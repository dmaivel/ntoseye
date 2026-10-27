//! `.dump`: write a WinDbg-loadable kernel memory dump (`PAGEDU64` full dump)
//! from a live target's physical memory.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::{offset_of, size_of};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ntoseye_macros::record;

use crate::arch::{Arch, RegisterMap};
use crate::base::bytes::{write_u32, write_u64};
use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::types::{MAX_PROCESSORS, PhysAddr};
use crate::nt::dmp::structs::{ExceptionRecord64, Header64};
use crate::nt::layout::{FieldInfo, ParsedType};
use crate::nt::target::Target;

const FULL_DUMP_TYPE: u32 = 1;
/// `_DUMP_HEADER64.PhysicalMemoryBlock` has room for at most 42 sixteen-byte
/// `PHYSICAL_MEMORY_RUN64` entries after its sixteen-byte descriptor prefix.
pub const MAX_PHYSICAL_MEMORY_RUNS: usize = 42;
const TEMP_CREATE_RETRIES: usize = 16;

/// A kernel dump that `.dump` wrote.
#[record]
pub struct DumpWrite {
    pub path: String,
    /// The pages that could not be read, written as zeros.
    pub unreadable_pages: u64,
}

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Rebuild a `CONTEXT` from a register file in another layout (a GDB stub's),
/// register by register. Registers the source lacks stay zero, and
/// `ContextFlags` claims the control and integer state (and segments on
/// AMD64) that every stub reports.
pub fn context_from_registers(arch: Arch, source: &RegisterMap, registers: &[u8]) -> Vec<u8> {
    let mut context = vec![0u8; arch.context_size()];
    // The layout's synthetic slots (control registers, descriptor tables)
    // sit past the CONTEXT proper, so the copy leaves them out.
    arch.register_map()
        .copy_from(&mut context, source, registers);
    let flags = arch.context_flags();
    write_u32(
        &mut context,
        flags.offset,
        flags.control | flags.integer | flags.segments,
    );
    context
}

/// A `CONTEXT` from registers known by name (a stack walk's, or the state
/// the Windows hypervisor saved), claiming the control and integer state.
/// Registers the map lacks stay zero. AMD64's segments are a 64-bit user
/// thread's when `registers` does not hold them.
pub fn context_from_named_registers(arch: Arch, registers: &HashMap<String, u64>) -> Vec<u8> {
    let map = arch.register_map();
    let mut context = vec![0u8; arch.context_size()];
    for (name, value) in registers {
        if map.contains(name) {
            let _ = map.write_u64(name, &mut context, *value);
        }
    }
    let flags = arch.context_flags();
    let mut claimed = flags.control | flags.integer;
    if arch == Arch::Amd64 {
        for (segment, selector) in [("cs", 0x33), ("ss", 0x2b)] {
            if !registers.contains_key(segment) {
                let _ = map.write_u64(segment, &mut context, selector);
            }
        }
        claimed |= flags.segments;
    }
    write_u32(&mut context, flags.offset, claimed);
    context
}

/// A processor's `CONTEXT` as NT sees it. When its live registers are not
/// NT's (it is halted in the Windows hypervisor, or runs VTL1), that is
/// `vtl0`, the VTL0 state the hypervisor saved; otherwise its live
/// `registers`, in the `source` layout, or a KD register buffer (a
/// `CONTEXT` first) when `source` is `None`.
pub fn nt_context(
    arch: Arch,
    source: Option<&RegisterMap>,
    registers: &[u8],
    vtl0: Option<&HashMap<String, u64>>,
) -> Vec<u8> {
    match (vtl0, source) {
        (Some(vtl0), _) => context_from_named_registers(arch, vtl0),
        (None, Some(source)) => context_from_registers(arch, source, registers),
        (None, None) => registers.to_vec(),
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

/// A processor's NT `CONTEXT`, and where its `_KPRCB` keeps the context the
/// kernel saves when it stops the processor, which a dump's reader takes
/// the processor's registers from. A live target's processors were stopped
/// from outside, so RAM there holds whatever the kernel last saved.
#[derive(Debug, Clone)]
pub struct ProcessorContext {
    /// A `CONTEXT` first, as [`DumpMetadata::context`] is.
    pub context: Vec<u8>,
    /// The guest-physical pieces of the saved context, in order, each its
    /// address and length; together they are a `CONTEXT` long.
    pub saved_at: Vec<(PhysAddr, u64)>,
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
    /// `VER_NT_*` (`KUSER_SHARED_DATA.NtProductType`): 1 workstation,
    /// 2 domain controller, 3 server; 0 when unknown.
    pub product_type: u32,
    pub number_processors: u32,
    pub bug_check_code: u32,
    pub bug_check_parameters: [u64; 4],
    pub kd_debugger_data_block: u64,
    /// The current processor's NT `CONTEXT`, as in [`Self::processors`]: a
    /// KD register buffer, of which the writer takes the leading `CONTEXT`
    /// record for `arch` -- the buffer's synthetic control/system-register
    /// slots sit past it -- and leaves the rest of the header's context
    /// bytes zero.
    pub context: Vec<u8>,
    /// Each processor's NT context, written where its `_KPRCB` keeps it in
    /// place of what RAM holds there.
    pub processors: Vec<ProcessorContext>,
    pub exception: Option<DumpException>,
    /// Physical RAM runs as `(base_page, page_count)`, in the order in which
    /// their page contents are streamed after the header.
    pub runs: Vec<(u64, u64)>,
    /// The debugger's own breakpoints in guest RAM: each site's
    /// guest-physical address and the bytes it displaced, which the dump
    /// holds in its place.
    pub displaced: Vec<(PhysAddr, Vec<u8>)>,
}

/// Removes a dump's temporary file unless the dump completed.
pub struct PartialDumpCleanup<'a> {
    pub path: &'a Path,
    pub keep: bool,
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
        let context_size = self.arch.context_size();
        if self.context.len() < context_size {
            return Err(Error::DebugInfo(format!(
                "KD CONTEXT is too short: {} bytes, expected at least {context_size}",
                self.context.len(),
            )));
        }
        for (index, processor) in self.processors.iter().enumerate() {
            if processor.context.len() < context_size {
                return Err(Error::DebugInfo(format!(
                    "processor {index}'s CONTEXT is too short: {} bytes, expected at least {context_size}",
                    processor.context.len(),
                )));
            }
            let saved: u64 = processor.saved_at.iter().map(|&(_, length)| length).sum();
            if saved != context_size as u64 {
                return Err(Error::DebugInfo(format!(
                    "processor {index}'s saved context spans {saved:#x} bytes, not a CONTEXT's {context_size:#x}"
                )));
            }
        }
        let mut pages = 0u64;
        for (run_index, &(base_page, page_count)) in self.runs.iter().enumerate() {
            if page_count == 0 {
                return Err(Error::DebugInfo(format!(
                    "physical dump run {run_index} has no pages"
                )));
            }
            let run_end = base_page
                .checked_add(page_count)
                .ok_or_else(|| Error::DebugInfo("physical dump run overflows u64".into()))?;
            for (previous_index, &(previous_base, previous_count)) in
                self.runs[..run_index].iter().enumerate()
            {
                let previous_end = previous_base
                    .checked_add(previous_count)
                    .ok_or_else(|| Error::DebugInfo("physical dump run overflows u64".into()))?;
                if base_page < previous_end && previous_base < run_end {
                    return Err(Error::DebugInfo(format!(
                        "physical dump runs {previous_index} and {run_index} overlap"
                    )));
                }
            }
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

/// A new file, private to the user, beside `destination`, for a dump to be
/// written to and then renamed into place.
pub fn create_temporary_file(destination: &Path) -> Result<(PathBuf, File)> {
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
        u32::from(metadata.arch.machine_type()),
    );
    write_u32(
        &mut header,
        offset_of!(Header64, product_type),
        metadata.product_type,
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
    let context_size = metadata.arch.context_size();
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

    // The bytes the dump holds in place of RAM's -- the debugger's
    // breakpoints' displaced bytes, and each processor's NT context where
    // its `_KPRCB` keeps it -- one by one, in address order, so each page
    // finds its own with a search rather than a pass over every site.
    let mut replaced: Vec<(PhysAddr, u8)> = metadata
        .displaced
        .iter()
        .flat_map(|(address, bytes)| {
            (0..)
                .map(move |index| address + index)
                .zip(bytes.iter().copied())
        })
        .collect();
    let context_size = metadata.arch.context_size();
    for processor in &metadata.processors {
        let mut context = processor.context[..context_size].iter().copied();
        for &(address, length) in &processor.saved_at {
            replaced.extend(
                (0..length)
                    .map(|offset| address + offset)
                    .zip(context.by_ref()),
            );
        }
    }
    replaced.sort_unstable_by_key(|&(address, _)| address);

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
            let first = replaced.partition_point(|&(site, _)| site < address);
            for &(site, byte) in replaced[first..]
                .iter()
                .take_while(|&&(site, _)| site - address < PAGE_SIZE as u64)
            {
                page[(site - address) as usize] = byte;
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
    let descriptor_address = symbol.read_pointer()?;
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

/// The guest's physical memory as `(first PFN, page count)` runs: the kernel's
/// `MmPhysicalMemoryBlock`, else the hypervisor's RAM layout, else the
/// backend's one RAM range.
pub fn physical_runs(target: &Target) -> Result<Vec<(u64, u64)>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{RegisterInfo, amd64, arm64};
    use crate::backend::dbg_backend::DebugBackend;
    use crate::base::bytes::write_u64;
    use crate::nt::dmp::{DmpBackend, DmpMem};
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

        assert_eq!(converted.len(), amd64::CONTEXT_SIZE);
        let layout = Arch::Amd64.register_map();
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
            converted[amd64::OFFSET_CONTEXT_FLAGS..amd64::OFFSET_CONTEXT_FLAGS + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            flags,
            amd64::CONTEXT_CONTROL | amd64::CONTEXT_INTEGER | amd64::CONTEXT_SEGMENTS
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
            context: vec![0u8; amd64::CONTEXT_SIZE],
            processors: Vec::new(),
            exception: None,
            runs,
            product_type: 1,
            displaced: Vec::new(),
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
        let mut context = vec![0u8; amd64::CONTEXT_SIZE];
        write_u64(&mut context, amd64::OFFSET_RIP, 0xffff_f800_1234_5678);
        // Breakpoints in the first page, across the first two, and in the
        // last, which the dump must hold the displaced bytes of instead.
        let displaced = vec![
            (0x4000 + 0x123, vec![0x48]),
            (0x10, vec![0x4c]),
            (0xffe, vec![0x11, 0x22, 0x33, 0x44]),
        ];
        let mut expected = memory.bytes.clone();
        for (address, bytes) in &displaced {
            let start = *address as usize;
            expected[start..start + bytes.len()].copy_from_slice(bytes);
        }
        let metadata = DumpMetadata {
            arch: Arch::Amd64,
            major_version: 0xf,
            minor_version: 19_041,
            directory_table_base: 0x1234_5000,
            pfn_database: 0xffff_f800_1111_0000,
            ps_loaded_module_list: 0xffff_f800_2222_0000,
            ps_active_process_head: 0xffff_f800_3333_0000,
            product_type: 1,
            number_processors: 1,
            bug_check_code: 0,
            bug_check_parameters: [0; 4],
            kd_debugger_data_block: 0,
            context,
            processors: Vec::new(),
            exception: None,
            runs: runs.clone(),
            displaced,
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
        assert_eq!(info.context.instruction_pointer(), 0xffff_f800_1234_5678);
        let system_info = info.system_info.as_ref().unwrap();
        assert_eq!(system_info.major_version, metadata.major_version);
        assert_eq!(system_info.minor_version, metadata.minor_version);
        assert_eq!(system_info.product_type, 1);
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
                &expected[page as usize * PAGE_SIZE..(page as usize + 1) * PAGE_SIZE]
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

        let mut context = vec![0u8; arm64::REGISTER_BUFFER_SIZE];
        write_u32(
            &mut context,
            arm64::OFFSET_CONTEXT_FLAGS,
            arm64::CONTEXT_ALL,
        );
        write_u64(&mut context, arm64::OFFSET_PC, 0xffff_8000_dead_0000);
        write_u64(&mut context, arm64::OFFSET_SP, 0xffff_8000_beef_1000);
        write_u64(&mut context, arm64::OFFSET_X0, 0x5a5a_5a5a);
        // Past the CONTEXT record: must not leak into the dump header.
        write_u64(&mut context, arm64::OFFSET_CR3, 0xdead_dead_dead_dead);

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
            u32::from(Arch::Arm64.machine_type()),
            "the header must declare ARM64, not AMD64"
        );
        let ctx = offset_of!(Header64, context_record_buffer);
        let flags_at = ctx + arm64::OFFSET_CONTEXT_FLAGS;
        assert_eq!(
            u32::from_le_bytes(raw[flags_at..flags_at + 4].try_into().unwrap()),
            arm64::CONTEXT_ALL,
        );
        assert!(
            raw[ctx + arm64::CONTEXT_SIZE..ctx + amd64::CONTEXT_SIZE]
                .iter()
                .all(|&b| b == 0),
            "only the ARM64 CONTEXT prefix belongs in the header"
        );

        let dump = DmpMem::open(&path).unwrap();
        let info = dump.info();
        assert_eq!(info.context.arch(), Arch::Arm64);
        assert_eq!(info.context.instruction_pointer(), 0xffff_8000_dead_0000);
        assert_eq!(info.context.stack_pointer(), 0xffff_8000_beef_1000);
        assert_eq!(info.context.read("x0"), Some(0x5a5a_5a5a));
        assert_eq!(info.directory_table_base, 0x4321_0000);

        let mut actual = [0u8; PAGE_SIZE];
        dump.read_bytes(PAGE_SIZE as u64, &mut actual).unwrap();
        assert_eq!(&actual, &memory.bytes[PAGE_SIZE..2 * PAGE_SIZE]);

        fs::remove_file(path).unwrap();
    }

    /// A GDB-style register file of a vCPU at `rip` and `rsp` on root `cr3`.
    fn stub_registers(rip: u64, rsp: u64, cr3: u64) -> (RegisterMap, Vec<u8>) {
        let register = |name: &str, offset, size| RegisterInfo {
            name: name.to_string(),
            offset,
            size,
            regnum: offset,
        };
        let stub = RegisterMap::from_registers(vec![
            register("rip", 0, 8),
            register("rsp", 8, 8),
            register("cs", 16, 4),
            register("cr3", 20, 8),
        ]);
        let mut registers = vec![0u8; 28];
        stub.write_u64("rip", &mut registers, rip).unwrap();
        stub.write_u64("rsp", &mut registers, rsp).unwrap();
        stub.write_u64("cs", &mut registers, 0x10).unwrap();
        stub.write_u64("cr3", &mut registers, cr3).unwrap();
        (stub, registers)
    }

    /// A vCPU halted in the Windows hypervisor (win11.dmp's processor 0 at
    /// `fffff83e453a6c0e`) is written with where NT left off, not with the
    /// hypervisor's registers, which no NT stack walk can place.
    #[test]
    fn a_processor_outside_nt_gets_the_saved_vtl0_context() {
        let (stub, hypervisor) =
            stub_registers(0xffff_f83e_453a_6c0e, 0xffff_e700_0000_59e8, 0x1ae000);
        let vtl0 = HashMap::from([
            ("rip".to_string(), 0xffff_f805_a2a2_c7cf),
            ("rsp".to_string(), 0xffff_f805_34b6_39a8),
            ("eflags".to_string(), 0x40246),
            ("cs".to_string(), 0x10),
            ("ss".to_string(), 0x18),
            ("cr3".to_string(), 0x1ad000),
        ]);
        let layout = Arch::Amd64.register_map();

        let saved = nt_context(Arch::Amd64, Some(&stub), &hypervisor, Some(&vtl0));
        assert_eq!(saved.len(), amd64::CONTEXT_SIZE);
        assert_eq!(
            layout.read_u64("rip", &saved).unwrap(),
            0xffff_f805_a2a2_c7cf
        );
        assert_eq!(
            layout.read_u64("rsp", &saved).unwrap(),
            0xffff_f805_34b6_39a8
        );
        assert_eq!(layout.read_u64("ss", &saved).unwrap(), 0x18);
        assert_eq!(layout.read_u64("eflags", &saved).unwrap(), 0x40246);

        let live = nt_context(Arch::Amd64, Some(&stub), &hypervisor, None);
        assert_eq!(
            layout.read_u64("rip", &live).unwrap(),
            0xffff_f83e_453a_6c0e
        );
    }

    /// Every processor's NT context lands where its `_KPRCB` keeps it, over
    /// the stale or zero context RAM held there, including one split across
    /// two physical pages; the header holds the current processor's, so a
    /// reader taking the contexts from the PRCBs selects that processor and
    /// gives each one NT's registers.
    #[test]
    fn every_processor_gets_its_nt_context_where_its_prcb_keeps_it() {
        let layout = Arch::Amd64.register_map();
        let context = |rip: u64, rsp: u64| {
            let mut context = vec![0u8; amd64::CONTEXT_SIZE];
            layout.write_u64("rip", &mut context, rip).unwrap();
            layout.write_u64("rsp", &mut context, rsp).unwrap();
            context
        };
        // RAM holds a stale context for processor 0, and none (zeros) for
        // processor 2, as the kernel saved them when it last stopped them.
        let mut bytes = vec![0u8; 4 * PAGE_SIZE];
        let stale = context(0xffff_f805_a287_e535, 0xffff_f805_34b6_3de8);
        bytes[0x340..0x340 + amd64::CONTEXT_SIZE].copy_from_slice(&stale);
        let memory = SyntheticMemory { bytes };

        let (stub, hypervisor) =
            stub_registers(0xffff_f83e_453a_6c0e, 0xffff_e700_0000_59e8, 0x1ae000);
        let vtl0 = HashMap::from([
            ("rip".to_string(), 0xffff_f805_a2a2_c7cf),
            ("rsp".to_string(), 0xffff_f28e_9684_5b68),
            ("cs".to_string(), 0x10),
        ]);
        let (_, nt_live) = stub_registers(0xffff_f805_a2a2_c7cf, 0xffff_f805_34b6_39a8, 0x1ad000);
        let (_, nt_live_2) = stub_registers(0xffff_f805_a2a2_d000, 0xffff_f28e_9687_d9a8, 0x1ad000);
        // Processor 1, halted in the hypervisor, is the current one.
        let contexts = [
            nt_context(Arch::Amd64, Some(&stub), &nt_live, None),
            nt_context(Arch::Amd64, Some(&stub), &hypervisor, Some(&vtl0)),
            nt_context(Arch::Amd64, Some(&stub), &nt_live_2, None),
        ];
        let split = 0x100u64;
        let sites = [
            vec![(0x340, amd64::CONTEXT_SIZE as u64)],
            vec![(PAGE_SIZE as u64 + 0x340, amd64::CONTEXT_SIZE as u64)],
            vec![
                (2 * PAGE_SIZE as u64 - split, split),
                (3 * PAGE_SIZE as u64, amd64::CONTEXT_SIZE as u64 - split),
            ],
        ];
        let metadata = DumpMetadata {
            number_processors: 3,
            context: contexts[1].clone(),
            processors: contexts
                .iter()
                .zip(&sites)
                .map(|(context, saved_at)| ProcessorContext {
                    context: context.clone(),
                    saved_at: saved_at.clone(),
                })
                .collect(),
            ..test_metadata(vec![(0, 4)])
        };
        let path = std::env::temp_dir().join(format!(
            "ntoseye-dump-writer-{}-processor-contexts.dmp",
            std::process::id()
        ));

        write_kernel_dump(&path, &memory, &metadata, || false, || {}).unwrap();
        let dump = DmpMem::open(&path).unwrap();
        let saved: Vec<Option<Vec<u8>>> = sites
            .iter()
            .map(|site| {
                let mut context = Vec::new();
                for &(address, length) in site {
                    let mut piece = vec![0u8; length as usize];
                    dump.read_bytes(address, &mut piece).unwrap();
                    context.extend(piece);
                }
                Some(context)
            })
            .collect();
        for (saved, expected) in saved.iter().zip(&contexts) {
            assert_eq!(saved.as_deref(), Some(&expected[..]));
        }
        let mut backend = DmpBackend::new(dump.info());
        backend.set_processor_contexts(saved, vec![Vec::new(); 3], Vec::new());

        assert_eq!(backend.stopped_thread_id().unwrap(), "p1.2");
        for (processor, rip) in [
            (1, 0xffff_f805_a2a2_c7cf),
            (2, 0xffff_f805_a2a2_c7cf),
            (3, 0xffff_f805_a2a2_d000),
        ] {
            backend
                .set_current_thread(&format!("p1.{processor}"))
                .unwrap();
            let registers = backend.read_registers().unwrap();
            assert_eq!(
                backend.register_map().read_u64("rip", &registers).unwrap(),
                rip
            );
        }

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
    fn overlapping_runs_are_rejected_and_adjacent_runs_are_written() {
        let path = std::env::temp_dir().join(format!(
            "ntoseye-dump-writer-{}-overlapping-runs.dmp",
            std::process::id()
        ));
        let original = b"previous dump";
        fs::write(&path, original).unwrap();
        let mut bytes = vec![0; 3 * PAGE_SIZE];
        bytes[PAGE_SIZE..2 * PAGE_SIZE].fill(0x11);
        bytes[2 * PAGE_SIZE..].fill(0x22);
        let memory = SyntheticMemory { bytes };

        let overlapping = test_metadata(vec![(1, 2), (2, 1)]);
        assert!(write_kernel_dump(&path, &memory, &overlapping, || false, || {}).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(temporary_paths(&path).is_empty());

        let adjacent = test_metadata(vec![(1, 1), (2, 1)]);
        write_kernel_dump(&path, &memory, &adjacent, || false, || {}).unwrap();
        let dump = DmpMem::open(&path).unwrap();
        for (page, expected) in [(1, 0x11), (2, 0x22)] {
            let mut actual = [0; PAGE_SIZE];
            dump.read_bytes(page * PAGE_SIZE as u64, &mut actual)
                .unwrap();
            assert!(actual.iter().all(|&byte| byte == expected));
        }

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
