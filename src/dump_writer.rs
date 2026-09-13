//! `.dump`: write a WinDbg-loadable kernel memory dump (`PAGEDU64` full dump)
//! from a live target's physical memory.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::mem::{offset_of, size_of};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kdmp_parser::structs::{ExceptionRecord64, Header64};

use crate::backend::MemoryOps;
use crate::cpu_state::MAX_PROCESSORS;
use crate::dmp::IMAGE_FILE_MACHINE_AMD64;
use crate::error::{Error, Result};
use crate::kd::context;
use crate::kd::wire::{write_u32, write_u64};
use crate::memory::PAGE_SIZE;
use crate::types::PhysAddr;

const FULL_DUMP_TYPE: u32 = 1;
/// `_DUMP_HEADER64.PhysicalMemoryBlock` has room for at most 42 sixteen-byte
/// `PHYSICAL_MEMORY_RUN64` entries after its sixteen-byte descriptor prefix.
pub const MAX_PHYSICAL_MEMORY_RUNS: usize = 42;
const TEMP_CREATE_RETRIES: usize = 16;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    /// A KD `CONTEXT` record. The writer takes the first AMD64 CONTEXT-sized
    /// prefix and leaves the rest of the header's reserved context bytes zero.
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
        if self.context.len() < context::CONTEXT_SIZE {
            return Err(Error::DebugInfo(format!(
                "KD CONTEXT is too short: {} bytes, expected at least {}",
                self.context.len(),
                context::CONTEXT_SIZE
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
        IMAGE_FILE_MACHINE_AMD64,
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
    header[context_offset..context_offset + context::CONTEXT_SIZE]
        .copy_from_slice(&metadata.context[..context::CONTEXT_SIZE]);

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
                return Err(Error::DebugInfo("dump cancelled".into()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmp::DmpMem;
    use crate::kd::wire::write_u64;
    use std::cell::Cell;
    use std::fs;
    use std::path::{Path, PathBuf};

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
            "ntoseye-dump-writer-{}-cancelled.dmp",
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
        assert!(result.unwrap_err().to_string().contains("cancelled"));
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
