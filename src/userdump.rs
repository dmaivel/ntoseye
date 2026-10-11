//! Windows user-mode minidumps (`MDMP`), as `MiniDumpWriteDump`, Windows
//! Error Reporting, Task Manager, and procdump write them: one process's
//! threads, modules, and the parts of its address space the dump captured.
//!
//! A user dump has no kernel, no physical memory, and no page tables. Its
//! memory is a set of captured virtual ranges, served to the address space
//! directly (see [`UserDump::read_virtual`]); the target built over it lists
//! the dump's own modules and threads rather than discovering a kernel.

use std::collections::HashMap;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use memmap2::Mmap;

use crate::bytes::get_u32;
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::guest::ModuleInfo;
use crate::kd::{context, context_arm64};
use crate::pe::headers::CodeView;
use crate::types::{Arch, VirtAddr};

pub mod backend;
pub mod parse;
#[cfg(test)]
mod tests;

pub use backend::UserDumpBackend;
pub use parse::is_minidump;

/// `SystemInfoStream`: the machine and Windows version the process ran on.
#[derive(Debug, Clone)]
pub struct UserSystemInfo {
    pub processor_level: u16,
    pub processor_revision: u16,
    pub number_of_processors: u8,
    /// `VER_NT_WORKSTATION` (1), `VER_NT_DOMAIN_CONTROLLER` (2),
    /// `VER_NT_SERVER` (3).
    pub product_type: u8,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    /// The service-pack string (`CSDVersionRva`), when one is recorded.
    pub service_pack: Option<String>,
}

/// `ThreadInfoListStream` entry: what the kernel knew of the thread.
#[derive(Debug, Clone)]
pub struct UserThreadInfo {
    pub dump_flags: u32,
    pub dump_error: u32,
    pub exit_status: u32,
    pub create_time: u64,
    pub exit_time: u64,
    pub kernel_time: u64,
    pub user_time: u64,
    pub start_address: u64,
    pub affinity: u64,
}

/// A thread of the captured process (`MINIDUMP_THREAD`), with what the
/// thread-info and thread-name streams add, matched by thread id.
#[derive(Debug, Clone)]
pub struct UserThread {
    pub tid: u32,
    pub suspend_count: u32,
    pub priority_class: u32,
    pub priority: u32,
    pub teb: u64,
    /// The captured stack as `(start, size)`, `None` when the dump holds
    /// none of it.
    pub stack: Option<(u64, u64)>,
    /// The thread's raw CONTEXT at the dump, or why it is unusable.
    pub context: std::result::Result<Vec<u8>, String>,
    pub name: Option<String>,
    pub info: Option<UserThreadInfo>,
}

/// A loaded module (`MINIDUMP_MODULE`).
#[derive(Debug, Clone)]
pub struct UserModule {
    pub base: u64,
    pub size: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    /// The full path the loader recorded.
    pub path: String,
    /// File and product version from the module's `VS_FIXEDFILEINFO`.
    pub version: Option<(String, String)>,
    /// The module's CodeView record, which names its PDB whether or not the
    /// image's own pages are in the dump.
    pub codeview: Option<CodeView>,
}

/// A module the process had unloaded (`MINIDUMP_UNLOADED_MODULE`).
#[derive(Debug, Clone)]
pub struct UnloadedModule {
    pub base: u64,
    pub size: u32,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub name: String,
}

/// `ExceptionStream`: the exception the dump was written for.
#[derive(Debug, Clone)]
pub struct UserException {
    pub thread_id: u32,
    pub code: u32,
    pub flags: u32,
    /// `ExceptionRecord`: the address of a chained record, 0 for none.
    pub record: u64,
    pub address: u64,
    pub parameters: Vec<u64>,
    /// The raw CONTEXT at the exception, or why it is unusable. It is stored
    /// in the dump file, not in the process's memory.
    pub context: std::result::Result<Vec<u8>, String>,
}

/// What a user dump records besides its memory.
#[derive(Debug, Clone)]
pub struct UserDumpInfo {
    /// `MINIDUMP_HEADER.TimeDateStamp`: when the dump was written, in
    /// seconds since 1970 (UTC).
    pub time_date_stamp: u32,
    /// `MINIDUMP_TYPE` flags the dump was written with.
    pub flags: u64,
    pub arch: Arch,
    pub system: UserSystemInfo,
    pub process_id: Option<u32>,
    /// Process creation, in seconds since 1970 (UTC).
    pub process_create_time: Option<u32>,
    /// User-mode and kernel-mode time the process had run, in seconds, as
    /// `(user, kernel)`.
    pub process_cpu_times: Option<(u32, u32)>,
    /// The time zone the system was in when the dump was written.
    pub time_zone: Option<UserTimeZone>,
    /// `MINIDUMP_MISC_INFO_4.BuildString`.
    pub build_string: Option<String>,
    pub threads: Vec<UserThread>,
    pub modules: Vec<UserModule>,
    pub unloaded_modules: Vec<UnloadedModule>,
    pub exception: Option<UserException>,
    /// `HandleDataStream`, `None` when the dump has none.
    pub handles: Option<Vec<UserHandle>>,
    /// `MemoryInfoListStream`, sorted by base, `None` when the dump has none.
    pub regions: Option<Vec<MemoryRegion>>,
    /// `FunctionTableStream`: the dynamic function tables (code no module
    /// holds, such as JIT-compiled code) the process had registered.
    pub function_tables: Vec<FunctionTable>,
    /// What was dropped or cut short while parsing, and why.
    pub notes: Vec<String>,
}

/// `MINIDUMP_MISC_INFO_3.TimeZone`, with `TimeZoneId` choosing the bias in
/// effect when the dump was written.
#[derive(Debug, Clone)]
pub struct UserTimeZone {
    /// Minutes to add to local time to get UTC, daylight saving included
    /// when it was in effect.
    pub bias: i32,
    /// The zone's name for the period in effect (`StandardName` or
    /// `DaylightName`).
    pub name: String,
}

/// A handle the process held (`MINIDUMP_HANDLE_DESCRIPTOR` or
/// `MINIDUMP_HANDLE_DESCRIPTOR_2`), as the dump records it.
#[derive(Debug, Clone)]
pub struct UserHandle {
    pub handle: u64,
    pub type_name: Option<String>,
    pub object_name: Option<String>,
    pub attributes: u32,
    pub granted_access: u32,
    pub handle_count: u32,
    pub pointer_count: u32,
}

/// `MINIDUMP_MEMORY_INFO`: one region of the address space, as
/// `VirtualQueryEx` reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: u64,
    pub allocation_base: u64,
    pub allocation_protect: u32,
    pub size: u64,
    /// `MEM_COMMIT`, `MEM_RESERVE`, or `MEM_FREE`.
    pub state: u32,
    pub protect: u32,
    /// `MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`, or 0 for a free region.
    pub kind: u32,
}

/// A dynamic function table (`MINIDUMP_FUNCTION_TABLE_DESCRIPTOR`): the
/// unwind entries for code at `minimum..maximum`, relative to `base`. The
/// entries' unwind data is in process memory, not in the stream.
#[derive(Debug, Clone)]
pub struct FunctionTable {
    pub minimum: u64,
    pub maximum: u64,
    pub base: u64,
    /// Sorted by `begin`.
    pub entries: Vec<DynamicFunction>,
}

/// An AMD64 `RUNTIME_FUNCTION` of a dynamic function table: offsets from
/// the table's base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DynamicFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind_data: u32,
}

/// A captured range of process memory and where its bytes are in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRange {
    pub start: u64,
    pub length: u64,
    pub offset: u64,
}

impl UserModule {
    /// The image's file name, the last component of its path.
    pub fn file_name(&self) -> &str {
        self.path.rsplit(['\\', '/']).next().unwrap_or(&self.path)
    }

    /// The module as the target lists it: named by its file name, with its
    /// path, timestamp, checksum, version, and CodeView record.
    pub fn to_module_info(&self) -> ModuleInfo {
        let mut info =
            ModuleInfo::new(self.file_name().to_string(), VirtAddr(self.base), self.size)
                .with_time_date_stamp(self.time_date_stamp)
                .with_checksum(self.checksum);
        info.path = Some(self.path.clone());
        if let Some((file, product)) = &self.version {
            info = info.with_version_info(file.clone(), product.clone());
        }
        info.codeview = self.codeview.clone();
        info
    }
}

impl UserDumpInfo {
    /// The process's image name, from the first module the dump lists (the
    /// executable).
    pub fn process_name(&self) -> Option<&str> {
        self.modules.first().map(UserModule::file_name)
    }

    /// `charmap.exe (pid 1234)`, as far as the dump records it.
    pub fn process_label(&self) -> String {
        let name = self.process_name().unwrap_or("process");
        match self.process_id {
            Some(pid) => format!("{name} (pid {pid})"),
            None => name.to_string(),
        }
    }

    pub fn thread(&self, tid: u32) -> Option<&UserThread> {
        self.threads.iter().find(|thread| thread.tid == tid)
    }

    /// The dynamic function covering `address`, with the base of its table:
    /// what unwinds code no module holds.
    pub fn dynamic_function(&self, address: u64) -> Option<(u64, DynamicFunction)> {
        self.function_tables
            .iter()
            .filter(|table| (table.minimum..table.maximum).contains(&address))
            .find_map(|table| {
                let offset = u32::try_from(address.checked_sub(table.base)?).ok()?;
                let index = table.entries.partition_point(|entry| entry.begin <= offset);
                let entry = table.entries.get(index.checked_sub(1)?)?;
                (offset < entry.end).then_some((table.base, *entry))
            })
    }

    /// The region of the memory-info list holding `address`.
    pub fn region(&self, address: u64) -> Option<&MemoryRegion> {
        let regions = self.regions.as_deref()?;
        let index = regions.partition_point(|region| region.base <= address);
        let region = regions.get(index.checked_sub(1)?)?;
        (address - region.base < region.size).then_some(region)
    }

    /// The index `~` lists `tid` at.
    pub fn thread_index(&self, tid: u32) -> Option<usize> {
        self.threads.iter().position(|thread| thread.tid == tid)
    }

    pub fn module_infos(&self) -> Vec<ModuleInfo> {
        self.modules
            .iter()
            .map(UserModule::to_module_info)
            .collect()
    }

    /// The backend's id for thread `tid`: `<pid>.<tid>` in hex, as WinDbg
    /// writes a user-mode thread id.
    pub fn backend_thread_id(&self, tid: u32) -> String {
        match self.process_id {
            Some(pid) => format!("{pid:x}.{tid:x}"),
            None => format!("{tid:x}"),
        }
    }

    /// The thread a backend id names (see [`Self::backend_thread_id`]).
    pub fn thread_for_backend_id(&self, id: &str) -> Option<&UserThread> {
        self.threads
            .iter()
            .find(|thread| self.backend_thread_id(thread.tid).eq_ignore_ascii_case(id))
    }
}

/// The register buffer the architecture's register map reads, holding a raw
/// CONTEXT. The slots past the CONTEXT (control registers, page-table roots)
/// stay zero: a user dump records none.
pub fn register_buffer(arch: Arch, raw_context: &[u8]) -> Vec<u8> {
    let (context_size, buffer_size) = match arch {
        Arch::Amd64 => (context::CONTEXT_SIZE, context::REGISTER_BUFFER_SIZE),
        Arch::Arm64 => (
            context_arm64::CONTEXT_SIZE,
            context_arm64::REGISTER_BUFFER_SIZE,
        ),
    };
    let mut buffer = vec![0u8; buffer_size];
    let length = raw_context.len().min(context_size);
    buffer[..length].copy_from_slice(&raw_context[..length]);
    buffer
}

/// The registers a raw CONTEXT records, named as the architecture's
/// register map names them: the CONTEXT's own fields only (none of the
/// control-register or descriptor slots past it), and of those only the
/// groups its `ContextFlags` mark present, so an unrecorded register is
/// unknown rather than whatever the structure holds there.
pub fn context_registers(
    arch: Arch,
    register_map: &RegisterMap,
    raw_context: &[u8],
) -> HashMap<String, u64> {
    let (size, flags_offset) = match arch {
        Arch::Amd64 => (context::CONTEXT_SIZE, context::OFFSET_CONTEXT_FLAGS),
        Arch::Arm64 => (
            context_arm64::CONTEXT_SIZE,
            context_arm64::OFFSET_CONTEXT_FLAGS,
        ),
    };
    let raw_context = &raw_context[..raw_context.len().min(size)];
    let flags = get_u32(raw_context, flags_offset).unwrap_or(0);
    let has = |group: u32| flags & group == group;
    let mut values = register_map.to_hashmap(raw_context);
    values.retain(|name, _| {
        let numbered = |prefix: &str| {
            name.strip_prefix(prefix)
                .and_then(|rest| rest.chars().next())
                .is_some_and(|ch| ch.is_ascii_digit())
        };
        match arch {
            Arch::Amd64 => {
                (has(context::CONTEXT_SEGMENTS)
                    || !["ds", "es", "fs", "gs"].contains(&name.as_str()))
                    && (has(context::CONTEXT_DEBUG_REGISTERS) || !numbered("dr"))
                    && (has(context::CONTEXT_FLOATING_POINT)
                        || !(numbered("xmm") || name == "mxcsr"))
            }
            Arch::Arm64 => {
                (has(context_arm64::CONTEXT_FLOATING_POINT)
                    || !(numbered("v") || name == "fpcr" || name == "fpsr"))
                    && (has(context_arm64::CONTEXT_DEBUG_REGISTERS)
                        || !["bcr", "bvr", "wcr", "wvr"]
                            .iter()
                            .any(|prefix| numbered(prefix)))
            }
        }
    });
    values
}

/// A user-mode minidump: the parsed streams and the file holding the
/// captured memory.
pub struct UserDump {
    mmap: Mmap,
    info: UserDumpInfo,
    /// Disjoint and sorted by start.
    memory: Vec<MemoryRange>,
}

/// Whether the file at `path` starts with the minidump signature. A kernel
/// dump (`PAGEDU64`) or a file shorter than the signature is not one.
pub fn file_is_minidump(path: &Path) -> Result<bool> {
    let mut signature = [0u8; 4];
    match File::open(path)?.read_exact(&mut signature) {
        Ok(()) => Ok(is_minidump(&signature)),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

impl UserDump {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        // SAFETY: the file is opened read-only and the mapping is never
        // written; a dump changed underneath a session is not supported, as
        // for kernel dumps.
        let mmap = unsafe { Mmap::map(&file)? };
        Self::from_mmap(mmap)
    }

    pub fn from_mmap(mmap: Mmap) -> Result<Self> {
        let parsed = parse::parse(&mmap)?;
        Ok(Self {
            info: parsed.info,
            memory: parsed.memory,
            mmap,
        })
    }

    pub fn info(&self) -> &UserDumpInfo {
        &self.info
    }

    pub fn memory_ranges(&self) -> &[MemoryRange] {
        &self.memory
    }

    /// The captured range holding `address`.
    fn range_containing(&self, address: u64) -> Option<&MemoryRange> {
        let index = self.memory.partition_point(|range| range.start <= address);
        let range = self.memory.get(index.checked_sub(1)?)?;
        (address - range.start < range.length).then_some(range)
    }

    /// The start of the first captured range above `address`.
    fn next_range_after(&self, address: u64) -> Option<u64> {
        let index = self.memory.partition_point(|range| range.start <= address);
        self.memory.get(index).map(|range| range.start)
    }

    /// Read process memory at `address`. A read that reaches memory the dump
    /// did not capture fails with [`Error::NotCaptured`], naming the first
    /// missing address and where captured memory resumes; the bytes before
    /// the hole are in `buf`.
    pub fn read_virtual(&self, address: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let Some(at) = address.0.checked_add(done as u64) else {
                return Err(Error::NotCaptured {
                    address,
                    resumes: None,
                });
            };
            let missing = || Error::NotCaptured {
                address: VirtAddr(at),
                resumes: self.next_range_after(at).map(VirtAddr),
            };
            let range = self.range_containing(at).ok_or_else(missing)?;
            let within = at - range.start;
            let take = usize::try_from(range.length - within)
                .unwrap_or(usize::MAX)
                .min(buf.len() - done);
            let bytes = usize::try_from(range.offset + within)
                .ok()
                .and_then(|start| self.mmap.get(start..start.checked_add(take)?))
                .ok_or_else(missing)?;
            buf[done..done + take].copy_from_slice(bytes);
            done += take;
        }
        Ok(())
    }
}
