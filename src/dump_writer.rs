//! `.dump`: write a WinDbg-loadable kernel memory dump (`PAGEDU64` full dump)
//! from a live target's physical memory.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::{offset_of, size_of};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::dmp::structs::{ExceptionRecord64, Header64};

use crate::backend::MemoryOps;
use crate::bugchecks::current_bugcheck;
use crate::cpu_state::MAX_PROCESSORS;
use crate::dmp::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64};
use crate::error::{Error, Result};
use crate::gdb::registers::RegisterMap;
use crate::kd::context;
use crate::kd::context_arm64;
use crate::kd::wire::{write_u32, write_u64};
use crate::layout::{FieldInfo, ParsedType};
use crate::memory::PAGE_SIZE;
use crate::session::Session;
use crate::target::Target;
use crate::types::{Arch, PhysAddr, VirtAddr};

const FULL_DUMP_TYPE: u32 = 1;
/// `_DUMP_HEADER64.PhysicalMemoryBlock` has room for at most 42 sixteen-byte
/// `PHYSICAL_MEMORY_RUN64` entries after its sixteen-byte descriptor prefix.
pub const MAX_PHYSICAL_MEMORY_RUNS: usize = 42;
const TEMP_CREATE_RETRIES: usize = 16;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn machine_image_type(arch: Arch) -> u32 {
    match arch {
        Arch::Amd64 => IMAGE_FILE_MACHINE_AMD64,
        Arch::Arm64 => IMAGE_FILE_MACHINE_ARM64,
    }
}

/// Rebuild a `CONTEXT` from a register file in another layout (a GDB stub's),
/// register by register. Registers the source lacks stay zero, and
/// `ContextFlags` claims the control and integer state (and segments on
/// AMD64) that every stub reports.
fn context_from_registers(arch: Arch, source: &RegisterMap, registers: &[u8]) -> Vec<u8> {
    let (layout, flags_offset, flags) = match arch {
        Arch::Amd64 => (
            context::build_register_map(),
            context::OFFSET_CONTEXT_FLAGS,
            context::CONTEXT_CONTROL | context::CONTEXT_INTEGER | context::CONTEXT_SEGMENTS,
        ),
        Arch::Arm64 => (
            context_arm64::build_register_map(),
            context_arm64::OFFSET_CONTEXT_FLAGS,
            context_arm64::CONTEXT_CONTROL | context_arm64::CONTEXT_INTEGER,
        ),
    };
    let mut context = vec![0u8; context_size(arch)];
    for register in layout.registers() {
        let end = register.offset + register.size;
        // The layout's synthetic slots (control registers, descriptor
        // tables) sit past the CONTEXT proper.
        if end > context.len() {
            continue;
        }
        if let Ok(value) = source.read_u128(&register.name, registers) {
            context[register.offset..end].copy_from_slice(&value.to_le_bytes()[..register.size]);
        }
    }
    write_u32(&mut context, flags_offset, flags);
    context
}

fn context_size(arch: Arch) -> usize {
    match arch {
        Arch::Amd64 => context::CONTEXT_SIZE,
        Arch::Arm64 => context_arm64::CONTEXT_SIZE,
    }
}

#[repr(C)]
struct PhysicalMemoryDescriptor64 {
    number_of_runs: u32,
    _padding: u32,
    number_of_pages: u64,
    run: [PhysicalMemoryRun64; 1],
}

#[repr(C)]
struct PhysicalMemoryRun64 {
    base_page: u64,
    page_count: u64,
}

/// A stop exception record copied into the dump header. Kernel bugchecks
/// generally carry no CPU exception record, so callers may leave this `None`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DumpException {
    pub code: u32,
    pub flags: u32,
    pub address: u64,
    pub parameters: [u64; 15],
    pub parameter_count: u32,
}

/// Metadata needed to build the fixed `_DUMP_HEADER64` prefix. The writer
/// deliberately accepts this separately from `Target`: it keeps byte layout
/// and physical-page streaming testable with a synthetic memory source and
/// lets the command degrade individual discovery fields to zero.
#[derive(Debug, Clone)]
pub struct DumpMetadata {
    /// Guest architecture. Selects the header's `MachineImageType` and how
    /// much of `context` is a `CONTEXT` record.
    pub arch: Arch,
    pub major_version: u32,
    pub minor_version: u32,
    pub directory_table_base: u64,
    pub pfn_database: u64,
    pub ps_loaded_module_list: u64,
    pub ps_active_process_head: u64,
    pub number_processors: u32,
    pub bug_check_code: u32,
    pub bug_check_parameters: [u64; 4],
    pub kd_debugger_data_block: u64,
    /// A KD register buffer. The writer takes the leading `CONTEXT` record for
    /// `arch` -- the buffer's synthetic control/system-register slots sit past
    /// it -- and leaves the rest of the header's context bytes zero.
    pub context: Vec<u8>,
    pub exception: Option<DumpException>,
    /// Physical RAM runs as `(base_page, page_count)`, in the order in which
    /// their page contents are streamed after the header.
    pub runs: Vec<(u64, u64)>,
}

struct PartialDumpCleanup<'a> {
    path: &'a Path,
    keep: bool,
}

impl Drop for PartialDumpCleanup<'_> {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(self.path);
        }
    }
}

impl DumpMetadata {
    /// Validate the run table and context, returning the dump's total page
    /// count.
    pub fn total_pages(&self) -> Result<u64> {
        if self.runs.len() > MAX_PHYSICAL_MEMORY_RUNS {
            return Err(Error::DebugInfo(format!(
                "physical dump has {} runs, but the header supports at most {}",
                self.runs.len(),
                MAX_PHYSICAL_MEMORY_RUNS
            )));
        }
        let context_size = context_size(self.arch);
        if self.context.len() < context_size {
            return Err(Error::DebugInfo(format!(
                "KD CONTEXT is too short: {} bytes, expected at least {context_size}",
                self.context.len(),
            )));
        }
        let mut pages = 0u64;
        for (run_index, &(base_page, page_count)) in self.runs.iter().enumerate() {
            if page_count == 0 {
                return Err(Error::DebugInfo(format!(
                    "physical dump run {run_index} has no pages"
                )));
            }
            base_page
                .checked_add(page_count)
                .ok_or_else(|| Error::DebugInfo("physical dump run overflows u64".into()))?;
            pages = pages
                .checked_add(page_count)
                .ok_or_else(|| Error::DebugInfo("physical dump page count overflows u64".into()))?;
        }
        if pages == 0 {
            return Err(Error::DebugInfo(
                "target exposes no guest RAM to dump".into(),
            ));
        }
        if self.number_processors == 0 || self.number_processors > u32::from(MAX_PROCESSORS) {
            return Err(Error::DebugInfo(format!(
                "invalid processor count {} (expected 1..={})",
                self.number_processors, MAX_PROCESSORS
            )));
        }
        Ok(pages)
    }
}

fn create_temporary_file(destination: &Path) -> Result<(PathBuf, File)> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination.file_name().ok_or_else(|| {
        Error::DebugInfo(format!(
            "dump destination has no file name: {}",
            destination.display()
        ))
    })?;
    for _ in 0..TEMP_CREATE_RETRIES {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temporary_name = OsString::from(".");
        temporary_name.push(name);
        temporary_name.push(format!(".ntoseye.tmp-{}-{sequence}", std::process::id()));
        let temporary = parent.join(temporary_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            // Replacing a private dump must not expose its memory through
            // the temporary file or a more permissive replacement inode.
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => return Ok((temporary, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "failed to create a unique temporary dump file",
    )
    .into())
}

fn build_header(metadata: &DumpMetadata, pages: u64) -> Result<Vec<u8>> {
    let header_size = size_of::<Header64>();
    debug_assert_eq!(header_size, 0x2000);
    let page_bytes = pages
        .checked_mul(PAGE_SIZE as u64)
        .ok_or_else(|| Error::DebugInfo("dump size overflows u64".into()))?;
    let required_space = (header_size as u64)
        .checked_add(page_bytes)
        .ok_or_else(|| Error::DebugInfo("required dump space overflows u64".into()))?;
    let required_space = i64::try_from(required_space)
        .map_err(|_| Error::DebugInfo("required dump space exceeds signed 64-bit range".into()))?;

    let mut header = vec![0u8; header_size];
    write_u32(
        &mut header,
        offset_of!(Header64, signature),
        u32::from_le_bytes(*b"PAGE"),
    );
    write_u32(
        &mut header,
        offset_of!(Header64, valid_dump),
        u32::from_le_bytes(*b"DU64"),
    );
    write_u32(
        &mut header,
        offset_of!(Header64, major_version),
        metadata.major_version,
    );
    write_u32(
        &mut header,
        offset_of!(Header64, minor_version),
        metadata.minor_version,
    );
    write_u64(
        &mut header,
        offset_of!(Header64, directory_table_base),
        metadata.directory_table_base,
    );
    write_u64(
        &mut header,
        offset_of!(Header64, pfn_database),
        metadata.pfn_database,
    );
    write_u64(
        &mut header,
        offset_of!(Header64, ps_loaded_module_list),
        metadata.ps_loaded_module_list,
    );
    write_u64(
        &mut header,
        offset_of!(Header64, ps_active_process_head),
        metadata.ps_active_process_head,
    );
    write_u32(
        &mut header,
        offset_of!(Header64, machine_image_type),
        machine_image_type(metadata.arch),
    );
    write_u32(
        &mut header,
        offset_of!(Header64, number_processors),
        metadata.number_processors,
    );
    write_u32(
        &mut header,
        offset_of!(Header64, bug_check_code),
        metadata.bug_check_code,
    );
    let bugcheck_params = offset_of!(Header64, bug_check_code_parameters);
    for (index, value) in metadata.bug_check_parameters.iter().copied().enumerate() {
        write_u64(&mut header, bugcheck_params + index * 8, value);
    }
    write_u64(
        &mut header,
        offset_of!(Header64, kd_debugger_data_block),
        metadata.kd_debugger_data_block,
    );

    // PHYSICAL_MEMORY_DESCRIPTOR64: NumberOfRuns, padding, NumberOfPages,
    // followed by PHYSICAL_MEMORY_RUN64 (BasePage, PageCount) entries.
    let physical = offset_of!(Header64, physical_memory_block_buffer);
    let runs = metadata.runs.iter();
    write_u32(
        &mut header,
        physical + offset_of!(PhysicalMemoryDescriptor64, number_of_runs),
        metadata.runs.len() as u32,
    );
    write_u64(
        &mut header,
        physical + offset_of!(PhysicalMemoryDescriptor64, number_of_pages),
        pages,
    );
    for (index, &(base_page, page_count)) in runs.enumerate() {
        let run_offset = physical
            + offset_of!(PhysicalMemoryDescriptor64, run)
            + index * size_of::<PhysicalMemoryRun64>();
        write_u64(
            &mut header,
            run_offset + offset_of!(PhysicalMemoryRun64, base_page),
            base_page,
        );
        write_u64(
            &mut header,
            run_offset + offset_of!(PhysicalMemoryRun64, page_count),
            page_count,
        );
    }

    let context_offset = offset_of!(Header64, context_record_buffer);
    let context_size = context_size(metadata.arch);
    header[context_offset..context_offset + context_size]
        .copy_from_slice(&metadata.context[..context_size]);

    if let Some(exception) = metadata.exception {
        let exception_offset = offset_of!(Header64, exception);
        write_u32(
            &mut header,
            exception_offset + offset_of!(ExceptionRecord64, exception_code),
            exception.code,
        );
        write_u32(
            &mut header,
            exception_offset + offset_of!(ExceptionRecord64, exception_flags),
            exception.flags,
        );
        write_u64(
            &mut header,
            exception_offset + offset_of!(ExceptionRecord64, exception_record),
            0,
        );
        write_u64(
            &mut header,
            exception_offset + offset_of!(ExceptionRecord64, exception_address),
            exception.address,
        );
        write_u32(
            &mut header,
            exception_offset + offset_of!(ExceptionRecord64, number_parameters),
            exception
                .parameter_count
                .min(exception.parameters.len() as u32),
        );
        for (index, value) in exception.parameters.iter().copied().enumerate() {
            write_u64(
                &mut header,
                exception_offset
                    + offset_of!(ExceptionRecord64, exception_information)
                    + index * size_of::<u64>(),
                value,
            );
        }
    }

    write_u32(&mut header, offset_of!(Header64, dump_type), FULL_DUMP_TYPE);
    write_u64(
        &mut header,
        offset_of!(Header64, required_dump_space),
        required_space as u64,
    );
    Ok(header)
}

/// Write a `PAGEDU64` full dump to `path`, streaming one physical page at a
/// time from `memory` in the run order supplied by [`DumpMetadata`].
///
/// `should_cancel` is checked before each page and `on_page` is called after
/// each page has been written to the temporary file. The destination is
/// replaced only after the complete file has been flushed and closed. Returns
/// the number of unreadable pages that were zero-filled.
pub fn write_kernel_dump<P, C, O>(
    path: impl AsRef<Path>,
    memory: &P,
    metadata: &DumpMetadata,
    mut should_cancel: C,
    mut on_page: O,
) -> Result<u64>
where
    P: MemoryOps<PhysAddr>,
    C: FnMut() -> bool,
    O: FnMut(),
{
    let path = path.as_ref();
    let pages = metadata.total_pages()?;
    let header = build_header(metadata, pages)?;
    let (temporary_path, file) = create_temporary_file(path)?;
    let mut cleanup = PartialDumpCleanup {
        path: &temporary_path,
        keep: false,
    };
    let mut writer = BufWriter::new(file);
    writer.write_all(&header)?;

    let mut page = [0u8; PAGE_SIZE];
    let mut unreadable_pages = 0u64;
    for &(base_page, page_count) in &metadata.runs {
        for page_index in 0..page_count {
            if should_cancel() {
                return Err(Error::DebugInfo("dump canceled".into()));
            }
            let page_number = base_page
                .checked_add(page_index)
                .ok_or_else(|| Error::DebugInfo("physical dump address overflows u64".into()))?;
            let address = page_number
                .checked_mul(PAGE_SIZE as u64)
                .ok_or_else(|| Error::DebugInfo("physical dump address overflows u64".into()))?;
            if memory.read_bytes(address, &mut page).is_err() {
                page.fill(0);
                unreadable_pages += 1;
            }
            writer.write_all(&page)?;
            on_page();
        }
    }
    // Close the complete file before publishing it under the destination name.
    drop(writer.into_inner().map_err(|error| error.into_error())?);
    fs::rename(&temporary_path, path)?;
    cleanup.keep = true;
    Ok(unreadable_pages)
}

const WINDOWS_MAJOR_VERSION: u32 = 0xf;

fn symbol_address(target: &Target, name: &str) -> u64 {
    target
        .guest()
        .ok()
        .and_then(|guest| guest.ntoskrnl.symbol(name).ok())
        .map(|symbol| symbol.address().0)
        .unwrap_or(0)
}

fn read_kernel_build_number(target: &Target) -> u32 {
    target
        .guest()
        .ok()
        .and_then(|guest| guest.ntoskrnl.symbol("NtBuildNumber").ok())
        .and_then(|symbol| symbol.read::<u16>().ok())
        .map(u32::from)
        .unwrap_or(0)
}

fn physical_runs_from_symbol(target: &Target) -> Result<Option<Vec<(u64, u64)>>> {
    let guest = match target.guest() {
        Ok(guest) => guest,
        Err(Error::NtoskrnlNotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    let symbol = match guest.ntoskrnl.symbol("MmPhysicalMemoryBlock") {
        Ok(symbol) => symbol,
        Err(Error::SymbolNotFound(_)) | Err(Error::ExpectedSymbols) => return Ok(None),
        Err(error) => return Err(error),
    };
    let descriptor_address: VirtAddr = symbol.read()?;
    if descriptor_address.is_zero() {
        return Err(Error::DebugInfo("nt!MmPhysicalMemoryBlock is null".into()));
    }

    let types = guest.ntoskrnl.types();
    let layout = types.layout("_PHYSICAL_MEMORY_DESCRIPTOR")?;
    let number_of_runs = layout.field("NumberOfRuns")?;
    let run = layout.field("Run")?;

    let element_type = match &run.type_data {
        ParsedType::Array(inner, _) => inner.as_ref(),
        element => element,
    };
    let element_name = match element_type {
        ParsedType::Struct(name) | ParsedType::Union(name) => name,
        _ => {
            return Err(Error::DebugInfo(
                "physical descriptor Run element has no struct layout".into(),
            ));
        }
    };
    let run_layout = types.layout(element_name)?;
    let base_page = run_layout.field("BasePage")?;
    let page_count = run_layout.field("PageCount")?;
    let run_stride = run_layout.size;
    if run_stride == 0 {
        return Err(Error::DebugInfo(
            "physical descriptor Run element has zero size".into(),
        ));
    }
    let (base_page_offset, base_page_size, page_count_offset, page_count_size) = (
        usize::try_from(base_page.offset)
            .map_err(|_| Error::DebugInfo("physical run BasePage offset overflows usize".into()))?,
        usize::try_from(base_page.size)
            .map_err(|_| Error::DebugInfo("physical run BasePage size overflows usize".into()))?,
        usize::try_from(page_count.offset).map_err(|_| {
            Error::DebugInfo("physical run PageCount offset overflows usize".into())
        })?,
        usize::try_from(page_count.size)
            .map_err(|_| Error::DebugInfo("physical run PageCount size overflows usize".into()))?,
    );
    for (name, offset, size) in [
        ("BasePage", base_page_offset, base_page_size),
        ("PageCount", page_count_offset, page_count_size),
    ] {
        let end = offset.checked_add(size).ok_or_else(|| {
            Error::DebugInfo(format!("physical run {name} field range overflows usize"))
        })?;
        if end > run_stride || !matches!(size, 1 | 2 | 4 | 8) {
            return Err(Error::DebugInfo(format!(
                "invalid physical run {name} field layout (offset={offset}, size={size}, stride={run_stride})"
            )));
        }
    }

    let field_end = |field: &FieldInfo| -> Result<usize> {
        let offset = usize::try_from(field.offset).map_err(|_| {
            Error::DebugInfo("physical descriptor field offset overflows usize".into())
        })?;
        let size = usize::try_from(field.size).map_err(|_| {
            Error::DebugInfo("physical descriptor field size overflows usize".into())
        })?;
        offset.checked_add(size).ok_or_else(|| {
            Error::DebugInfo("physical descriptor field range overflows usize".into())
        })
    };
    let read_integer = |bytes: &[u8], offset: usize, size: usize, name: &str| {
        let end = offset
            .checked_add(size)
            .ok_or_else(|| Error::DebugInfo(format!("{name} field range overflows usize")))?;
        let value = bytes.get(offset..end).ok_or_else(|| {
            Error::DebugInfo(format!("{name} field exceeds physical descriptor prefix"))
        })?;
        match size {
            1 => Ok(u64::from(value[0])),
            2 => Ok(u64::from(u16::from_le_bytes(value.try_into().unwrap()))),
            4 => Ok(u64::from(u32::from_le_bytes(value.try_into().unwrap()))),
            8 => Ok(u64::from_le_bytes(value.try_into().unwrap())),
            _ => Err(Error::DebugInfo(format!(
                "unsupported {name} field size {size}"
            ))),
        }
    };

    let run_offset = usize::try_from(run.offset)
        .map_err(|_| Error::DebugInfo("physical descriptor run offset overflows usize".into()))?;
    let prefix_len = run_offset.max(field_end(number_of_runs)?);
    let mut prefix = vec![0u8; prefix_len];
    target
        .kernel_address_space()
        .read_bytes(descriptor_address, &mut prefix)?;
    let run_count = read_integer(
        &prefix,
        usize::try_from(number_of_runs.offset)
            .map_err(|_| Error::DebugInfo("NumberOfRuns offset overflows usize".into()))?,
        usize::try_from(number_of_runs.size)
            .map_err(|_| Error::DebugInfo("NumberOfRuns size overflows usize".into()))?,
        "NumberOfRuns",
    )?;
    let run_count = usize::try_from(run_count).unwrap_or(usize::MAX);
    // Rejected rather than truncated: a dump missing runs would still claim
    // to be complete.
    if run_count > MAX_PHYSICAL_MEMORY_RUNS {
        return Err(Error::DebugInfo(format!(
            "physical descriptor reports {run_count} runs, but the dump header supports at most {MAX_PHYSICAL_MEMORY_RUNS}"
        )));
    }
    let runs_len = run_count
        .checked_mul(run_stride)
        .and_then(|size| run_offset.checked_add(size))
        .ok_or_else(|| Error::DebugInfo("physical descriptor run list overflows usize".into()))?;
    let mut bytes = prefix;
    if bytes.len() < runs_len {
        bytes.resize(runs_len, 0);
        target
            .kernel_address_space()
            .read_bytes(descriptor_address, &mut bytes)?;
    }

    let mut runs = Vec::with_capacity(run_count);
    for index in 0..run_count {
        let offset = run_offset + index * run_stride;
        let run_bytes = &bytes[offset..offset + run_stride];
        let base_page = read_integer(run_bytes, base_page_offset, base_page_size, "BasePage")?;
        let page_count = read_integer(run_bytes, page_count_offset, page_count_size, "PageCount")?;
        runs.push((base_page, page_count));
    }
    Ok(Some(runs))
}

fn physical_runs(target: &Target) -> Result<Vec<(u64, u64)>> {
    if let Some(runs) = physical_runs_from_symbol(target)? {
        return Ok(runs);
    }

    // A live VM exposes its hypervisor's RAM mapping, including the 32-bit PCI
    // hole, through this accessor. KD has no equivalent host map, so an absent
    // symbol there remains an actionable discovery error below.
    let runs = target.phys.ram_runs();
    let page_size = PAGE_SIZE as u64;
    if !runs.is_empty() {
        return runs
            .into_iter()
            .map(|(base, length)| {
                if !base.is_multiple_of(page_size) || !length.is_multiple_of(page_size) {
                    return Err(Error::DebugInfo(format!(
                        "physical RAM run is not page-aligned (base={base:#x}, size={length:#x})"
                    )));
                }
                let page_count = length / page_size;
                (page_count != 0)
                    .then_some((base / page_size, page_count))
                    .ok_or_else(|| Error::DebugInfo("physical RAM run has no pages".into()))
            })
            .collect();
    }

    let base = target.phys.ram_base();
    let length = target.phys.ram_size();
    if !base.is_multiple_of(page_size) || !length.is_multiple_of(page_size) {
        return Err(Error::DebugInfo(format!(
            "physical RAM range is not page-aligned (base={base:#x}, size={length:#x})"
        )));
    }
    let page_count = length / page_size;
    if page_count == 0 {
        return Err(Error::DebugInfo(
            "target did not expose physical memory runs".into(),
        ));
    }
    Ok(vec![(base / page_size, page_count)])
}

/// Gather the header metadata for a full kernel dump of the halted target:
/// the current CONTEXT, processor count, physical runs, kernel globals, and
/// the bugcheck/exception of the last stop when there is one.
pub fn collect_dump_metadata(session: &mut Session) -> Result<DumpMetadata> {
    let registers = session.read_registers()?;
    let context = if session.backend.registers_are_context() {
        registers
    } else {
        context_from_registers(session.target.arch(), &session.register_map, &registers)
    };
    let processor_count = session
        .backend
        .thread_list()
        .map(|threads| threads.len().clamp(1, usize::from(MAX_PROCESSORS)) as u32)
        .unwrap_or(1);
    let runs = physical_runs(&session.target)?;
    let major_version = WINDOWS_MAJOR_VERSION;
    let minor_version = read_kernel_build_number(&session.target);

    let debugger_data = session.target.debugger_data();
    let ps_loaded_module_list = debugger_data
        .and_then(|data| data.ps_loaded_module_list())
        .map(|value| value.value.0)
        .filter(|&address| address != 0)
        .unwrap_or_else(|| symbol_address(&session.target, "PsLoadedModuleList"));
    let ps_active_process_head = debugger_data
        .and_then(|data| data.ps_active_process_head())
        .map(|value| value.value.0)
        .filter(|&address| address != 0)
        .unwrap_or_else(|| symbol_address(&session.target, "PsActiveProcessHead"));
    let pfn_database = symbol_address(&session.target, "MmPfnDatabase");
    let kd_debugger_data_block = debugger_data.map(|data| data.address.0).unwrap_or(0);

    let mut bug_check_code = 0;
    let mut bug_check_parameters = [0u64; 4];
    let mut exception = None;
    if let Some(stop) = session.last_event.as_ref().map(|event| &event.stop) {
        if stop.is_bugcheck
            && let Some(info) = &stop.bugcheck
        {
            bug_check_code = info.code;
            bug_check_parameters = info.parameters;
        } else if stop.is_bugcheck
            && let Some(analysis) = current_bugcheck(&session.target)
        {
            bug_check_code = analysis.code;
            for (index, argument) in analysis.args.iter().take(4).enumerate() {
                bug_check_parameters[index] = argument.value;
            }
        }
        if let Some(code) = stop.exception_code {
            exception = Some(DumpException {
                code,
                flags: 0,
                address: stop.exception_address.or(stop.program_counter).unwrap_or(0),
                ..DumpException::default()
            });
        }
    }

    Ok(DumpMetadata {
        arch: session.target.arch(),
        major_version,
        minor_version,
        directory_table_base: session.target.kernel_dtb(),
        pfn_database,
        ps_loaded_module_list,
        ps_active_process_head,
        number_processors: processor_count,
        bug_check_code,
        bug_check_parameters,
        kd_debugger_data_block,
        context,
        exception,
        runs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmp::DmpMem;
    use crate::gdb::registers::RegisterInfo;
    use crate::kd::wire::write_u64;
    use std::cell::Cell;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[test]
    fn a_stub_register_file_becomes_a_context_by_register_name() {
        // A GDB-style layout: packed, in its own order, and without the
        // debug registers a CONTEXT has room for.
        let register = |name: &str, offset, size| RegisterInfo {
            name: name.to_string(),
            offset,
            size,
            regnum: offset,
        };
        let stub = RegisterMap::from_registers(vec![
            register("rip", 0, 8),
            register("rsp", 8, 8),
            register("eflags", 16, 4),
            register("cs", 20, 4),
            register("xmm1", 24, 16),
        ]);
        let mut registers = vec![0u8; 40];
        stub.write_u64("rip", &mut registers, 0xffff_f805_aed1_950f)
            .unwrap();
        stub.write_u64("rsp", &mut registers, 0xffff_f805_40ea_0968)
            .unwrap();
        stub.write_u64("eflags", &mut registers, 0x40282).unwrap();
        stub.write_u64("cs", &mut registers, 0x10).unwrap();
        registers[24..40]
            .copy_from_slice(&0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00u128.to_le_bytes());

        let converted = context_from_registers(Arch::Amd64, &stub, &registers);

        assert_eq!(converted.len(), context::CONTEXT_SIZE);
        let layout = context::build_register_map();
        assert_eq!(
            layout.read_u64("rip", &converted).unwrap(),
            0xffff_f805_aed1_950f
        );
        assert_eq!(
            layout.read_u64("rsp", &converted).unwrap(),
            0xffff_f805_40ea_0968
        );
        assert_eq!(layout.read_u64("eflags", &converted).unwrap(), 0x40282);
        assert_eq!(layout.read_u64("cs", &converted).unwrap(), 0x10);
        assert_eq!(
            layout.read_u128("xmm1", &converted).unwrap(),
            0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00
        );
        assert_eq!(layout.read_u64("dr7", &converted).unwrap(), 0);
        let flags = u32::from_le_bytes(
            converted[context::OFFSET_CONTEXT_FLAGS..context::OFFSET_CONTEXT_FLAGS + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            flags,
            context::CONTEXT_CONTROL | context::CONTEXT_INTEGER | context::CONTEXT_SEGMENTS
        );
    }

    struct SyntheticMemory {
        bytes: Vec<u8>,
    }

    impl MemoryOps<PhysAddr> for SyntheticMemory {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let start = usize::try_from(addr).map_err(|_| Error::BadPhysicalAddress(addr))?;
            let end = start
                .checked_add(buf.len())
                .ok_or(Error::BadPhysicalAddress(addr))?;
            let source = self
                .bytes
                .get(start..end)
                .ok_or(Error::BadPhysicalAddress(addr))?;
            buf.copy_from_slice(source);
            Ok(())
        }

        fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            Err(Error::ReadOnlyDump)
        }
    }

    fn test_metadata(runs: Vec<(u64, u64)>) -> DumpMetadata {
        DumpMetadata {
            arch: Arch::Amd64,
            major_version: 0xf,
            minor_version: 19_041,
            directory_table_base: 0x1234_5000,
            pfn_database: 0xffff_f800_1111_0000,
            ps_loaded_module_list: 0xffff_f800_2222_0000,
            ps_active_process_head: 0xffff_f800_3333_0000,
            number_processors: 1,
            bug_check_code: 0,
            bug_check_parameters: [0; 4],
            kd_debugger_data_block: 0,
            context: vec![0u8; context::CONTEXT_SIZE],
            exception: None,
            runs,
        }
    }

    fn temporary_paths(path: &Path) -> Vec<PathBuf> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let prefix = format!(
            ".{}.ntoseye.tmp-",
            path.file_name().unwrap().to_string_lossy()
        );
        fs::read_dir(parent)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|candidate| {
                candidate
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
            })
            .collect()
    }

    #[test]
    fn synthetic_multi_run_dump_round_trips_through_dmpmem() {
        let runs = vec![(0u64, 2u64), (4u64, 1u64)];
        let highest_page = runs
            .iter()
            .map(|(base_page, page_count)| base_page + page_count)
            .max()
            .unwrap();
        let mut bytes = vec![0u8; highest_page as usize * PAGE_SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(37).wrapping_add(11);
        }
        let memory = SyntheticMemory { bytes };
        let mut context = vec![0u8; context::CONTEXT_SIZE];
        write_u64(&mut context, context::OFFSET_RIP, 0xffff_f800_1234_5678);
        let metadata = DumpMetadata {
            arch: Arch::Amd64,
            major_version: 0xf,
            minor_version: 19_041,
            directory_table_base: 0x1234_5000,
            pfn_database: 0xffff_f800_1111_0000,
            ps_loaded_module_list: 0xffff_f800_2222_0000,
            ps_active_process_head: 0xffff_f800_3333_0000,
            number_processors: 1,
            bug_check_code: 0,
            bug_check_parameters: [0; 4],
            kd_debugger_data_block: 0,
            context,
            exception: None,
            runs: runs.clone(),
        };
        let path = std::env::temp_dir().join(format!(
            "ntoseye-dump-writer-{}-{}.dmp",
            std::process::id(),
            runs.len()
        ));

        let unreadable = write_kernel_dump(&path, &memory, &metadata, || false, || {}).unwrap();
        assert_eq!(unreadable, 0);
        let dump = DmpMem::open(&path).unwrap();
        let info = dump.info();
        assert_eq!(info.directory_table_base, metadata.directory_table_base);
        assert_eq!(info.number_processors, 1);
        assert_eq!(info.context.rip, 0xffff_f800_1234_5678);
        let system_info = info.system_info.as_ref().unwrap();
        assert_eq!(system_info.major_version, metadata.major_version);
        assert_eq!(system_info.minor_version, metadata.minor_version);
        let physical = offset_of!(Header64, physical_memory_block_buffer);
        let raw = fs::read(&path).unwrap();
        assert_eq!(
            u32::from_le_bytes(raw[physical..physical + 4].try_into().unwrap()),
            runs.len() as u32
        );
        assert_eq!(
            u64::from_le_bytes(raw[physical + 8..physical + 16].try_into().unwrap()),
            3
        );
        for (index, (base_page, page_count)) in runs.iter().copied().enumerate() {
            let run_offset = physical + 16 + index * 16;
            assert_eq!(
                u64::from_le_bytes(raw[run_offset..run_offset + 8].try_into().unwrap()),
                base_page
            );
            assert_eq!(
                u64::from_le_bytes(raw[run_offset + 8..run_offset + 16].try_into().unwrap()),
                page_count
            );
        }
        for page in [0u64, 1, 4] {
            let mut actual = [0u8; PAGE_SIZE];
            dump.read_bytes(page * PAGE_SIZE as u64, &mut actual)
                .unwrap();
            assert_eq!(
                &actual,
                &memory.bytes[page as usize * PAGE_SIZE..(page as usize + 1) * PAGE_SIZE]
            );
        }

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn arm64_dump_round_trips_with_an_arm64_header_and_context() {
        let runs = vec![(0u64, 2u64)];
        let mut bytes = vec![0u8; 2 * PAGE_SIZE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(59).wrapping_add(7);
        }
        let memory = SyntheticMemory { bytes };

        let mut context = vec![0u8; context_arm64::REGISTER_BUFFER_SIZE];
        write_u32(
            &mut context,
            context_arm64::OFFSET_CONTEXT_FLAGS,
            context_arm64::CONTEXT_ALL,
        );
        write_u64(
            &mut context,
            context_arm64::OFFSET_PC,
            0xffff_8000_dead_0000,
        );
        write_u64(
            &mut context,
            context_arm64::OFFSET_SP,
            0xffff_8000_beef_1000,
        );
        write_u64(&mut context, context_arm64::OFFSET_X0, 0x5a5a_5a5a);
        // Past the CONTEXT record: must not leak into the dump header.
        write_u64(
            &mut context,
            context_arm64::OFFSET_CR3,
            0xdead_dead_dead_dead,
        );

        let metadata = DumpMetadata {
            arch: Arch::Arm64,
            context,
            directory_table_base: 0x4321_0000,
            ..test_metadata(runs.clone())
        };
        let path = std::env::temp_dir().join(format!(
            "ntoseye-dump-writer-{}-arm64.dmp",
            std::process::id()
        ));

        let unreadable = write_kernel_dump(&path, &memory, &metadata, || false, || {}).unwrap();
        assert_eq!(unreadable, 0);

        let raw = fs::read(&path).unwrap();
        let machine = offset_of!(Header64, machine_image_type);
        assert_eq!(
            u32::from_le_bytes(raw[machine..machine + 4].try_into().unwrap()),
            IMAGE_FILE_MACHINE_ARM64,
            "the header must declare ARM64, not AMD64"
        );
        let ctx = offset_of!(Header64, context_record_buffer);
        let flags_at = ctx + context_arm64::OFFSET_CONTEXT_FLAGS;
        assert_eq!(
            u32::from_le_bytes(raw[flags_at..flags_at + 4].try_into().unwrap()),
            context_arm64::CONTEXT_ALL,
        );
        assert!(
            raw[ctx + context_arm64::CONTEXT_SIZE..ctx + context::CONTEXT_SIZE]
                .iter()
                .all(|&b| b == 0),
            "only the ARM64 CONTEXT prefix belongs in the header"
        );

        let dump = DmpMem::open(&path).unwrap();
        let info = dump.info();
        let arm = info
            .context
            .arm64
            .as_ref()
            .expect("reopened ARM64 dump must decode an ARM64 context");
        assert_eq!(arm.pc, 0xffff_8000_dead_0000);
        assert_eq!(arm.sp, 0xffff_8000_beef_1000);
        assert_eq!(arm.x[0], 0x5a5a_5a5a);
        assert_eq!(info.directory_table_base, 0x4321_0000);

        let mut actual = [0u8; PAGE_SIZE];
        dump.read_bytes(PAGE_SIZE as u64, &mut actual).unwrap();
        assert_eq!(&actual, &memory.bytes[PAGE_SIZE..2 * PAGE_SIZE]);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn too_many_runs_reject_without_replacing_destination() {
        let path = std::env::temp_dir().join(format!(
            "ntoseye-dump-writer-{}-too-many-runs.dmp",
            std::process::id()
        ));
        let original = b"previous dump";
        fs::write(&path, original).unwrap();
        let runs = (0..=MAX_PHYSICAL_MEMORY_RUNS)
            .map(|index| (index as u64 * 2, 1))
            .collect();
        let metadata = test_metadata(runs);
        let memory = SyntheticMemory { bytes: Vec::new() };

        let result = write_kernel_dump(&path, &memory, &metadata, || false, || {});
        assert!(result.is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(temporary_paths(&path).is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn cancellation_preserves_destination_and_cleans_temporary_file() {
        let path = std::env::temp_dir().join(format!(
            "ntoseye-dump-writer-{}-canceled.dmp",
            std::process::id()
        ));
        let original = b"previous dump";
        fs::write(&path, original).unwrap();
        let metadata = test_metadata(vec![(0, 2)]);
        let memory = SyntheticMemory {
            bytes: vec![0u8; 2 * PAGE_SIZE],
        };
        let written_pages = Cell::new(0u64);

        let result = write_kernel_dump(
            &path,
            &memory,
            &metadata,
            || written_pages.get() >= 1,
            || written_pages.set(written_pages.get() + 1),
        );
        assert!(result.unwrap_err().to_string().contains("canceled"));
        assert_eq!(written_pages.get(), 1);
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(temporary_paths(&path).is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rename_failure_preserves_destination_and_cleans_temporary_file() {
        let path = std::env::temp_dir().join(format!(
            "ntoseye-dump-writer-{}-rename-failure",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        let marker = path.join("marker");
        let original = b"existing destination";
        fs::write(&marker, original).unwrap();
        let metadata = test_metadata(vec![(0, 1)]);
        let memory = SyntheticMemory {
            bytes: vec![0u8; PAGE_SIZE],
        };

        let result = write_kernel_dump(&path, &memory, &metadata, || false, || {});
        assert!(result.is_err());
        assert!(path.is_dir());
        assert_eq!(fs::read(&marker).unwrap(), original);
        assert!(temporary_paths(&path).is_empty());
        fs::remove_file(marker).unwrap();
        fs::remove_dir(path).unwrap();
    }
}
