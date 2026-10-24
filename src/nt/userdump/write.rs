//! Writes a user-mode minidump (`MDMP`) of one process (`.dump /u`): the
//! streams [`super::parse`] reads, in the layouts WinDbg reads too. The
//! memory goes in a `Memory64ListStream` whose data comes last, after every
//! other stream, so their 32-bit RVAs stay small however large the process
//! is; its ranges are decided before any byte of it is written.

use std::fs;
use std::io::{BufWriter, Write};
use std::ops::Range;
use std::path::Path;

use ntoseye_macros::record;

use crate::arch::Arch;
use crate::base::error::{Error, Result};
use crate::base::memory::PAGE_SIZE;
use crate::nt::dump_writer::{PartialDumpCleanup, create_temporary_file};

use super::parse::{
    MEMORY_INFO_LIST_STREAM, MEMORY64_LIST_STREAM, MINIDUMP_SIGNATURE, MINIDUMP_VERSION,
    MISC_INFO_STREAM, MISC1_PROCESS_ID, MISC1_PROCESS_TIMES, MODULE_LIST_STREAM, PLATFORM_WIN32_NT,
    PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64, SYSTEM_INFO_STREAM,
    THREAD_INFO_LIST_STREAM, THREAD_LIST_STREAM,
};

/// `MINIDUMP_TYPE`: all of the process's memory, every region's state, and
/// each thread's times and start address.
const MINIDUMP_WITH_FULL_MEMORY: u64 = 0x2;
const MINIDUMP_WITH_FULL_MEMORY_INFO: u64 = 0x800;
const MINIDUMP_WITH_THREAD_INFO: u64 = 0x1000;

const HEADER_SIZE: usize = 32;
const DIRECTORY_ENTRY_SIZE: usize = 12;
const STREAM_COUNT: usize = 7;
/// `MINIDUMP_THREAD_INFO_LIST` and `MINIDUMP_MEMORY_INFO_LIST` headers and
/// entries.
const THREAD_INFO_HEADER_SIZE: u32 = 12;
const THREAD_INFO_ENTRY_SIZE: u32 = 64;
const MEMORY_INFO_HEADER_SIZE: u32 = 16;
const MEMORY_INFO_ENTRY_SIZE: u32 = 48;
/// `MINIDUMP_MISC_INFO`, the first version: process ID and times.
const MISC_INFO_SIZE: u32 = 24;

/// A user-mode minidump that `.dump /u` wrote.
#[record]
pub struct MinidumpWrite {
    pub path: String,
    pub process: String,
    pub pid: u64,
    pub threads: usize,
    /// The threads whose user-mode registers their stacks did not give.
    pub threads_without_context: usize,
    pub modules: usize,
    pub regions: usize,
    /// The bytes of memory the minidump holds.
    pub captured_bytes: u64,
    /// Of those, the bytes of committed pages never touched, which are
    /// zeros.
    pub demand_zero_bytes: u64,
    /// The pages that translated but could not be read, written as zeros.
    pub unreadable_pages: u64,
}

/// The system the process ran on (`SystemInfoStream`).
#[derive(Debug, Clone)]
pub struct MinidumpSystem {
    pub arch: Arch,
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub processors: u8,
    /// `VER_NT_WORKSTATION` (1), `VER_NT_DOMAIN_CONTROLLER` (2) or
    /// `VER_NT_SERVER` (3).
    pub product_type: u8,
}

/// A thread of the process.
#[derive(Debug, Clone)]
pub struct MinidumpThread {
    pub tid: u32,
    pub teb: u64,
    pub priority: u32,
    pub priority_class: u32,
    pub suspend_count: u32,
    /// Its user-mode `CONTEXT`, `None` when it cannot be recovered.
    pub context: Option<Vec<u8>>,
    /// The used part of its user stack, from its stack pointer to its base.
    pub stack: Option<Range<u64>>,
    /// FILETIMEs, and 100 ns counts for the CPU times; 0 when unknown.
    pub create_time: u64,
    pub exit_time: u64,
    pub kernel_time: u64,
    pub user_time: u64,
    pub start_address: u64,
}

/// A module the process's loader lists hold.
#[derive(Debug, Clone)]
pub struct MinidumpModule {
    pub base: u64,
    pub size: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub path: String,
    /// The image's CodeView record, as its debug directory holds it.
    pub codeview: Option<Vec<u8>>,
}

/// A region of the address space (`MINIDUMP_MEMORY_INFO`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinidumpRegion {
    pub base: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub size: u64,
    pub state: u32,
    pub protect: u32,
    pub kind: u32,
}

/// What a minidump of one process holds.
#[derive(Debug, Clone)]
pub struct MinidumpProcess {
    pub system: MinidumpSystem,
    /// When the dump was taken, in seconds since 1970.
    pub time_date_stamp: u32,
    pub pid: u32,
    /// Seconds since 1970, and seconds of CPU time, when known.
    pub times: Option<(u32, u32, u32)>,
    pub threads: Vec<MinidumpThread>,
    pub modules: Vec<MinidumpModule>,
    pub regions: Vec<MinidumpRegion>,
    /// The memory to capture: page-aligned, ascending, not overlapping.
    pub memory: Vec<Range<u64>>,
    /// The pages of `memory` that were never touched (demand-zero): written
    /// as zeros, not read. Ascending, not overlapping.
    pub zero: Vec<Range<u64>>,
}

/// The streams before the memory data, laid out in one buffer whose first
/// byte is at file offset `base`.
struct Streams {
    base: usize,
    bytes: Vec<u8>,
}

impl Streams {
    fn rva(&self) -> u32 {
        (self.base + self.bytes.len()) as u32
    }

    fn align(&mut self, to: usize) {
        while !(self.base + self.bytes.len()).is_multiple_of(to) {
            self.bytes.push(0);
        }
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// A `MINIDUMP_STRING`: its length in bytes, UTF-16LE, and a NUL.
    fn string(&mut self, text: &str) -> u32 {
        self.align(4);
        let rva = self.rva();
        let units: Vec<u16> = text.encode_utf16().collect();
        self.u32((units.len() * 2) as u32);
        for unit in units {
            self.u16(unit);
        }
        self.u16(0);
        rva
    }

    /// `bytes` as a blob: its location descriptor.
    fn blob(&mut self, bytes: &[u8]) -> (u32, u32) {
        self.align(16);
        let rva = self.rva();
        self.bytes.extend_from_slice(bytes);
        (bytes.len() as u32, rva)
    }

    /// Patch a `u32` written earlier at file offset `rva`.
    fn patch_u32(&mut self, rva: u32, value: u32) {
        let at = rva as usize - self.base;
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
}

/// The file offset of the captured copy of `range`, when the dump captures
/// all of it in one of `memory`'s ranges, whose data starts at `data_base`.
fn captured_offset(memory: &[Range<u64>], data_base: u64, range: &Range<u64>) -> Option<u64> {
    let mut offset = data_base;
    for captured in memory {
        if captured.start <= range.start && range.end <= captured.end {
            return Some(offset + (range.start - captured.start));
        }
        offset += captured.end - captured.start;
    }
    None
}

/// Write the minidump of `process` to `path`. `read_page(address, page)`
/// fills one page of `process.memory`; a page it cannot read is written as
/// zeros and counted, which is the count returned. The file appears at
/// `path` only once it is complete.
pub fn write_minidump(
    path: &Path,
    process: &MinidumpProcess,
    mut read_page: impl FnMut(u64, &mut [u8]) -> bool,
    mut should_cancel: impl FnMut() -> bool,
    mut on_page: impl FnMut(),
) -> Result<u64> {
    let arch = match process.system.arch {
        Arch::Amd64 => PROCESSOR_ARCHITECTURE_AMD64,
        Arch::Arm64 => PROCESSOR_ARCHITECTURE_ARM64,
    };
    let page = PAGE_SIZE as u64;
    if let Some(range) = process
        .memory
        .iter()
        .find(|range| !range.start.is_multiple_of(page) || !range.end.is_multiple_of(page))
    {
        return Err(Error::InvalidArgument(format!(
            "memory range {:#x}-{:#x} is not page-aligned",
            range.start, range.end
        )));
    }

    let directory_size = STREAM_COUNT * DIRECTORY_ENTRY_SIZE;
    let mut streams = Streams {
        base: HEADER_SIZE + directory_size,
        bytes: Vec::new(),
    };
    let mut directory: Vec<(u32, u32, u32)> = Vec::with_capacity(STREAM_COUNT);

    // SystemInfoStream: MINIDUMP_SYSTEM_INFO and its (empty) CSD version.
    let system_rva = streams.rva();
    streams.u16(arch);
    streams.u16(0); // ProcessorLevel
    streams.u16(0); // ProcessorRevision
    streams.bytes.push(process.system.processors);
    streams.bytes.push(process.system.product_type);
    streams.u32(process.system.major);
    streams.u32(process.system.minor);
    streams.u32(process.system.build);
    streams.u32(PLATFORM_WIN32_NT);
    let csd_at = streams.rva();
    streams.u32(0); // CSDVersionRva, patched below
    streams.u16(0); // SuiteMask
    streams.u16(0); // Reserved2
    streams.bytes.extend_from_slice(&[0; 24]); // CPU_INFORMATION
    directory.push((SYSTEM_INFO_STREAM, streams.rva() - system_rva, system_rva));
    let csd = streams.string("");
    streams.patch_u32(csd_at, csd);

    // MiscInfoStream: MINIDUMP_MISC_INFO.
    streams.align(4);
    let misc_rva = streams.rva();
    let (create, user, kernel) = process.times.unwrap_or((0, 0, 0));
    streams.u32(MISC_INFO_SIZE);
    streams.u32(
        MISC1_PROCESS_ID
            | if process.times.is_some() {
                MISC1_PROCESS_TIMES
            } else {
                0
            },
    );
    streams.u32(process.pid);
    streams.u32(create);
    streams.u32(user);
    streams.u32(kernel);
    directory.push((MISC_INFO_STREAM, MISC_INFO_SIZE, misc_rva));

    // The memory data starts where the streams end, which is not known
    // until they are laid out, and threads point into it; the stack
    // descriptors are patched once it is.
    let contexts: Vec<Option<(u32, u32)>> = process
        .threads
        .iter()
        .map(|thread| {
            thread
                .context
                .as_deref()
                .map(|context| streams.blob(context))
        })
        .collect();

    // ThreadListStream: MINIDUMP_THREAD_LIST.
    streams.align(4);
    let threads_rva = streams.rva();
    streams.u32(process.threads.len() as u32);
    let mut stack_patches = Vec::new();
    for (thread, context) in process.threads.iter().zip(&contexts) {
        streams.u32(thread.tid);
        streams.u32(thread.suspend_count);
        streams.u32(thread.priority_class);
        streams.u32(thread.priority);
        streams.u64(thread.teb);
        streams.u64(thread.stack.as_ref().map_or(0, |stack| stack.start));
        stack_patches.push((streams.rva(), thread.stack.clone()));
        streams.u32(0); // Stack.Memory.DataSize
        streams.u32(0); // Stack.Memory.Rva
        let (size, rva) = context.unwrap_or((0, 0));
        streams.u32(size);
        streams.u32(rva);
    }
    directory.push((THREAD_LIST_STREAM, streams.rva() - threads_rva, threads_rva));

    // ThreadInfoListStream: MINIDUMP_THREAD_INFO_LIST.
    let thread_info_rva = streams.rva();
    streams.u32(THREAD_INFO_HEADER_SIZE);
    streams.u32(THREAD_INFO_ENTRY_SIZE);
    streams.u32(process.threads.len() as u32);
    for thread in &process.threads {
        streams.u32(thread.tid);
        streams.u32(0); // DumpFlags
        streams.u32(0); // DumpError
        streams.u32(0); // ExitStatus
        streams.u64(thread.create_time);
        streams.u64(thread.exit_time);
        streams.u64(thread.kernel_time);
        streams.u64(thread.user_time);
        streams.u64(thread.start_address);
        streams.u64(0); // Affinity
    }
    directory.push((
        THREAD_INFO_LIST_STREAM,
        streams.rva() - thread_info_rva,
        thread_info_rva,
    ));

    // ModuleListStream: MINIDUMP_MODULE_LIST, then the names and CodeView
    // records the modules point at.
    let names: Vec<u32> = process
        .modules
        .iter()
        .map(|module| streams.string(&module.path))
        .collect();
    let codeviews: Vec<(u32, u32)> = process
        .modules
        .iter()
        .map(|module| {
            module
                .codeview
                .as_deref()
                .map_or((0, 0), |cv| streams.blob(cv))
        })
        .collect();
    streams.align(4);
    let modules_rva = streams.rva();
    streams.u32(process.modules.len() as u32);
    for ((module, name), (cv_size, cv_rva)) in process.modules.iter().zip(names).zip(codeviews) {
        streams.u64(module.base);
        streams.u32(module.size);
        streams.u32(module.checksum);
        streams.u32(module.time_date_stamp);
        streams.u32(name);
        streams.bytes.extend_from_slice(&[0; 52]); // VS_FIXEDFILEINFO
        streams.u32(cv_size);
        streams.u32(cv_rva);
        streams.u64(0); // MiscRecord
        streams.u64(0); // Reserved0
        streams.u64(0); // Reserved1
    }
    directory.push((MODULE_LIST_STREAM, streams.rva() - modules_rva, modules_rva));

    // MemoryInfoListStream: MINIDUMP_MEMORY_INFO_LIST.
    streams.align(8);
    let regions_rva = streams.rva();
    streams.u32(MEMORY_INFO_HEADER_SIZE);
    streams.u32(MEMORY_INFO_ENTRY_SIZE);
    streams.u64(process.regions.len() as u64);
    for region in &process.regions {
        streams.u64(region.base);
        streams.u64(region.allocation_base);
        streams.u32(region.allocation_protect);
        streams.u32(0);
        streams.u64(region.size);
        streams.u32(region.state);
        streams.u32(region.protect);
        streams.u32(region.kind);
        streams.u32(0);
    }
    directory.push((
        MEMORY_INFO_LIST_STREAM,
        streams.rva() - regions_rva,
        regions_rva,
    ));

    // Memory64ListStream: MINIDUMP_MEMORY64_LIST, whose data follows it.
    let memory_rva = streams.rva();
    let memory_size = 16 + 16 * process.memory.len();
    let data_base = (streams.base + streams.bytes.len() + memory_size) as u64;
    streams.u64(process.memory.len() as u64);
    streams.u64(data_base);
    for range in &process.memory {
        streams.u64(range.start);
        streams.u64(range.end - range.start);
    }
    directory.push((MEMORY64_LIST_STREAM, memory_size as u32, memory_rva));
    if data_base > u64::from(u32::MAX) {
        return Err(Error::DebugInfo(
            "the process's streams do not fit in the first 4 GiB of a minidump".into(),
        ));
    }

    // A stack the dump captures whole points at its copy, when the copy is
    // within the 32-bit reach of a location descriptor.
    for (at, stack) in stack_patches {
        let Some(stack) = stack else { continue };
        let Some(offset) = captured_offset(&process.memory, data_base, &stack) else {
            continue;
        };
        let (Ok(size), Ok(rva)) = (
            u32::try_from(stack.end - stack.start),
            u32::try_from(offset),
        ) else {
            continue;
        };
        streams.patch_u32(at, size);
        streams.patch_u32(at + 4, rva);
    }

    let mut header = Vec::with_capacity(HEADER_SIZE + directory_size);
    header.extend_from_slice(&MINIDUMP_SIGNATURE.to_le_bytes());
    header.extend_from_slice(&u32::from(MINIDUMP_VERSION).to_le_bytes());
    header.extend_from_slice(&(STREAM_COUNT as u32).to_le_bytes());
    header.extend_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
    header.extend_from_slice(&process.time_date_stamp.to_le_bytes());
    header.extend_from_slice(
        &(MINIDUMP_WITH_FULL_MEMORY | MINIDUMP_WITH_FULL_MEMORY_INFO | MINIDUMP_WITH_THREAD_INFO)
            .to_le_bytes(),
    );
    debug_assert_eq!(directory.len(), STREAM_COUNT);
    for (stream_type, size, rva) in directory {
        header.extend_from_slice(&stream_type.to_le_bytes());
        header.extend_from_slice(&size.to_le_bytes());
        header.extend_from_slice(&rva.to_le_bytes());
    }

    let (temporary_path, file) = create_temporary_file(path)?;
    let mut cleanup = PartialDumpCleanup {
        path: &temporary_path,
        keep: false,
    };
    let mut writer = BufWriter::new(file);
    writer.write_all(&header)?;
    writer.write_all(&streams.bytes)?;
    let mut buffer = vec![0u8; PAGE_SIZE];
    let mut unreadable = 0;
    let mut zero = process.zero.iter().peekable();
    for range in &process.memory {
        for address in (range.start..range.end).step_by(PAGE_SIZE) {
            if should_cancel() {
                return Err(Error::DebugInfo("dump canceled".into()));
            }
            while zero.next_if(|zero| zero.end <= address).is_some() {}
            if zero.peek().is_some_and(|zero| zero.start <= address) {
                buffer.fill(0);
            } else if !read_page(address, &mut buffer) {
                buffer.fill(0);
                unreadable += 1;
            }
            writer.write_all(&buffer)?;
            on_page();
        }
    }
    drop(writer.into_inner().map_err(|error| error.into_error())?);
    fs::rename(&temporary_path, path)?;
    cleanup.keep = true;
    Ok(unreadable)
}
