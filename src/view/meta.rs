//! `View` builders for the metadata inspectors.

use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use super::list::{ListEnd, list_termination};
use crate::target::ListTermination;
use crate::target::meta::{
    ErrorCodeDetail, TargetDumpMetadata, TargetKernelDetail, TargetTimeDetail,
    TargetUserDumpDetail, TargetVersionDetail, UserDumpTimeDetail, VerifierDetail,
    VerifierDriverDetail, VerifierDriverSummary as DriverSummaryDetail,
    VerifierStatistics as StatisticsDetail, VerifierSuspectDriver as SuspectDriverDetail,
};
use crate::types::VirtAddr;

/// A driver that Driver Verifier verifies, from the `!verifier` list.
#[record]
pub struct VerifierDriverSummary {
    /// The verifier entry of the driver.
    pub entry: VirtAddr,
    /// The state of the entry (`Loaded`).
    pub state: String,
    /// The nonpaged pool that the driver holds, in bytes.
    pub nonpaged_bytes: u64,
    /// The paged pool that the driver holds, in bytes.
    pub paged_bytes: u64,
    /// The module name of the driver.
    pub module: String,
}

/// A driver that is configured for verification, from the verifier
/// suspect list.
#[record]
pub struct VerifierSuspectDriver {
    /// The suspect-list entry.
    pub address: VirtAddr,
    pub full_name: String,
    pub base_name: String,
    /// The number of times that the driver loaded.
    pub loads: u64,
    /// The number of times that the driver unloaded.
    pub unloads: u64,
}

/// The aggregate counters of Driver Verifier. ntoseye reads each counter
/// separately, and each read can fail.
#[record]
pub struct VerifierStatistics {
    pub raise_irqls: DiagnosticValue<u64>,
    pub acquire_spin_locks: DiagnosticValue<u64>,
    pub synchronize_executions: DiagnosticValue<u64>,
    pub trims: DiagnosticValue<u64>,
    pub allocations_attempted: DiagnosticValue<u64>,
    pub allocations_succeeded: DiagnosticValue<u64>,
    pub allocations_succeeded_special_pool: DiagnosticValue<u64>,
    pub allocations_with_no_tag: DiagnosticValue<u64>,
    pub allocations_failed: DiagnosticValue<u64>,
    pub current_paged_pool_allocations: DiagnosticValue<u64>,
    pub paged_bytes: DiagnosticValue<u64>,
    pub peak_paged_pool_allocations: DiagnosticValue<u64>,
    pub peak_paged_bytes: DiagnosticValue<u64>,
    pub current_nonpaged_pool_allocations: DiagnosticValue<u64>,
    pub nonpaged_bytes: DiagnosticValue<u64>,
    pub peak_nonpaged_pool_allocations: DiagnosticValue<u64>,
    pub peak_nonpaged_bytes: DiagnosticValue<u64>,
    pub loads: DiagnosticValue<u64>,
    pub unloads: DiagnosticValue<u64>,
}

/// The Driver Verifier configuration, statistics, and drivers
/// (`!verifier`). The drivers are the verified drivers and the configured
/// suspect drivers that are not loaded.
#[record]
pub struct Verifier {
    /// The verification level (`MmVerifierData.Level`).
    #[record(hex)]
    pub level: DiagnosticValue<u64>,
    /// The option flags (`VerifierOptionFlags`).
    #[record(hex)]
    pub option_flags: DiagnosticValue<u64>,
    pub verify_mode: DiagnosticValue<u64>,
    /// The names of the checks that `level` enables.
    pub level_options: DiagnosticValue<Vec<String>>,
    pub statistics: VerifierStatistics,
    /// The verified drivers.
    pub drivers: DiagnosticValue<Vec<VerifierDriverSummary>>,
    /// Whether the driver table gives a smaller entry count than the
    /// number of linked entries, which means that the walk stopped before
    /// it reached all drivers.
    pub drivers_truncated: bool,
    /// The suspect drivers that are configured for verification but are
    /// not loaded.
    pub configured_but_unloaded: DiagnosticValue<Vec<VerifierSuspectDriver>>,
    /// How the suspect-list walk ended.
    pub suspect_list_termination: ListEnd,
}

/// The image, signing level, and counters of one verified driver
/// (`!verifier <module>`).
#[record]
pub struct VerifierDriver {
    pub module: String,
    pub image_base: VirtAddr,
    /// The image size in bytes.
    pub image_size: u64,
    /// The `_DRIVER_OBJECT` of the driver.
    pub driver_object: VirtAddr,
    /// The signing level of the image (`SE_SIGNING_LEVEL`).
    #[record(hex)]
    pub se_signing_level: u64,
    pub raise_irqls: u64,
    pub acquire_spin_locks: u64,
    pub synchronize_executions: u64,
    pub allocations_with_no_tag: u64,
    pub allocations_failed: u64,
    /// The number of allocations that the verifier failed on purpose
    /// (fault injection).
    pub allocations_failed_deliberately: u64,
    pub current_paged_pool_allocations: u64,
    pub paged_bytes: u64,
    pub peak_paged_pool_allocations: u64,
    pub peak_paged_bytes: u64,
    pub current_nonpaged_pool_allocations: u64,
    pub nonpaged_bytes: u64,
    pub peak_nonpaged_pool_allocations: u64,
    pub peak_nonpaged_bytes: u64,
    pub locked_bytes: u64,
    pub peak_locked_bytes: u64,
    pub mapped_locked_bytes: u64,
    pub peak_mapped_locked_bytes: u64,
    pub mapped_io_space_bytes: u64,
    pub peak_mapped_io_space_bytes: u64,
    pub pages_for_mdl_bytes: u64,
    pub peak_pages_for_mdl_bytes: u64,
    pub contiguous_memory_bytes: u64,
    pub peak_contiguous_memory_bytes: u64,
    /// The suspect-list entry of the driver, with its load history.
    /// `None` if the driver has no entry.
    pub suspect: Option<VerifierSuspectDriver>,
}

/// The identity of the kernel image.
#[record]
pub struct TargetKernel {
    /// The file name of the image.
    pub name: String,
    /// The module name (`nt`).
    pub short_name: String,
    pub base: VirtAddr,
    /// The image size in bytes.
    pub size: Option<u64>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    /// The GUID of the PDB, which identifies the symbols.
    pub pdb_guid: Option<String>,
    /// The age of the PDB.
    pub pdb_age: Option<u32>,
}

/// The data that a crash dump header records.
#[record]
pub struct TargetDump {
    /// Whether the dump is a triage (minidump-style) dump.
    pub is_triage: bool,
    /// The kernel page-table root that the dump records.
    pub directory_table_base: VirtAddr,
    #[record(hex)]
    pub bugcheck_code: u32,
    #[record(hex)]
    pub bugcheck_parameters: Vec<u64>,
    pub number_processors: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub product_type: u32,
    /// The machine type (`IMAGE_FILE_MACHINE_*`).
    pub machine_image_type: u32,
    pub service_pack_build: u32,
    /// The time when the dump was taken (FILETIME).
    #[record(hex)]
    pub system_time: Option<u64>,
    /// The system uptime in seconds.
    pub uptime_seconds: Option<u64>,
    /// The exception code that the dump records.
    #[record(hex)]
    pub exception_code: Option<u32>,
    /// Whether the triage data of the dump overflowed.
    pub triage_overflowed: bool,
    pub kernel_base: Option<VirtAddr>,
    /// The blocks that bugcheck callbacks added to the dump (`.enumtag`);
    /// `Inspect.read_tagged` reads one.
    pub tagged_blocks: Vec<TaggedBlock>,
}

/// A tagged data block of a crash dump.
#[record]
pub struct TaggedBlock {
    /// The GUID tag, `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub tag: String,
    /// The data's size in bytes.
    pub size: u64,
    /// For a tag Windows writes, the global that holds it, such as
    /// `nt!PopBlackBoxPnpGuid`.
    pub owner: Option<&'static str>,
    /// For a tag Windows writes, what the block holds.
    pub holds: Option<&'static str>,
}

/// The version data of the target (`vertarget`), with the build,
/// architecture, kernel, symbols, debugger version, time, and dump
/// metadata.
#[record]
pub struct TargetVersion {
    pub major_version: Option<u64>,
    pub minor_version: Option<u64>,
    pub build_number: Option<u64>,
    /// The build lab string.
    pub build_lab: Option<String>,
    pub architecture: String,
    /// The number of processors in the target.
    pub processors: Option<u16>,
    /// The product name.
    pub product: String,
    /// The kernel image. `None` if ntoseye did not find it.
    pub kernel: Option<TargetKernel>,
    /// The symbol status label of the kernel. `None` if ntoseye did not
    /// find the kernel.
    pub symbol_status: Option<String>,
    pub debugger_version: String,
    pub symbol_path: String,
    pub time: TargetTime,
    /// The backend attached to the target.
    pub backend: Option<String>,
    /// The crash dump header. `None` for a live target.
    pub dump: Option<TargetDump>,
    /// What a user-mode minidump records of its process and how it was
    /// written. `None` for a kernel target.
    pub user_dump: Option<TargetUserDump>,
}

/// A user-mode minidump's process and header.
#[record]
pub struct TargetUserDump {
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    /// `ProcessorLevel`: on AMD64, the processor family.
    pub processor_level: u16,
    /// `ProcessorRevision`: on AMD64, the model (high byte) and stepping
    /// (low byte).
    #[record(hex)]
    pub processor_revision: u16,
    pub service_pack: Option<String>,
    /// The `MINIDUMP_TYPE` flags the dump was written with.
    #[record(hex)]
    pub flags: u64,
    /// `flags` as `MINIDUMP_TYPE` names (`MiniDumpWithFullMemory`, ...).
    pub flag_names: Vec<String>,
    pub threads: usize,
    pub modules: usize,
    /// The code of the exception the dump was written for.
    #[record(hex)]
    pub exception_code: Option<u32>,
}

/// The UTC time and uptime of the target (`.time`). A user-mode minidump
/// records neither: its `user_dump` says when it was written instead.
#[record]
pub struct TargetTime {
    /// The UTC time of the target (FILETIME).
    #[record(hex)]
    pub system_time: Option<u64>,
    /// `system_time` as ISO 8601.
    pub system_time_iso: Option<String>,
    /// `KUSER_SHARED_DATA.InterruptTime`: the time since boot, in 100 ns
    /// units. The `due_time` of clock timers uses this clock.
    #[record(hex)]
    pub interrupt_time: Option<u64>,
    /// Seconds since boot.
    pub uptime_seconds: Option<u64>,
    /// The uptime as formatted text.
    pub uptime: Option<String>,
    /// When a user-mode minidump was written, and its process's times.
    /// `None` for a kernel target.
    pub user_dump: Option<UserDumpTime>,
}

/// When a user-mode minidump was written (its header), and how long its
/// process had run (`MiscInfoStream`), where it records them.
#[record]
pub struct UserDumpTime {
    /// When the dump was written, in seconds since 1970 (UTC).
    pub written: u32,
    /// `written` as ISO 8601 UTC.
    pub written_iso: Option<String>,
    /// `written` in the system's time zone.
    pub written_local: Option<String>,
    /// The name of that zone's period in effect.
    pub time_zone: Option<String>,
    /// When the process started, in seconds since 1970 (UTC).
    pub process_created: Option<u32>,
    /// `process_created` as ISO 8601 UTC.
    pub process_created_iso: Option<String>,
    /// From the process's start to the dump, in seconds.
    pub process_uptime_seconds: Option<u64>,
    /// `process_uptime_seconds` as formatted text.
    pub process_uptime: Option<String>,
    /// User-mode time the process had run, in seconds.
    pub user_time_seconds: Option<u32>,
    /// Kernel-mode time the process had run, in seconds.
    pub kernel_time_seconds: Option<u32>,
}

/// A decoded NTSTATUS, Win32, or HRESULT code (`!error`).
#[record]
pub struct ErrorCode {
    #[record(hex)]
    pub code: u64,
    /// `NTSTATUS`, `HRESULT`, `Win32`, or `unknown`.
    pub kind: String,
    /// The symbolic name of the code.
    pub name: String,
    pub description: String,
    /// `success`, `informational`, `warning`, or `error`. `None` for a
    /// Win32 code.
    pub severity: Option<String>,
    /// The facility that the code encodes.
    pub facility: Option<u32>,
    /// Whether the code is customer-defined (its C bit).
    pub customer: Option<bool>,
    /// The Win32 error: the code itself, or the Win32 error that a
    /// `HRESULT_FROM_WIN32` code wraps.
    #[record(hex)]
    pub win32_code: Option<u32>,
    /// The name of that Win32 error.
    pub win32_name: Option<String>,
}

fn verifier_summary(driver: &DriverSummaryDetail) -> VerifierDriverSummary {
    VerifierDriverSummary {
        entry: driver.entry,
        state: driver.state.clone(),
        nonpaged_bytes: driver.nonpaged_bytes,
        paged_bytes: driver.paged_bytes,
        module: driver.module_name.clone(),
    }
}

fn suspect_driver(driver: &SuspectDriverDetail) -> VerifierSuspectDriver {
    VerifierSuspectDriver {
        address: driver.address,
        full_name: driver.full_name.clone(),
        base_name: driver.base_name.clone(),
        loads: driver.loads,
        unloads: driver.unloads,
    }
}

fn verifier_statistics(stats: &StatisticsDetail) -> VerifierStatistics {
    VerifierStatistics {
        raise_irqls: stats.raise_irqls.clone(),
        acquire_spin_locks: stats.acquire_spin_locks.clone(),
        synchronize_executions: stats.synchronize_executions.clone(),
        trims: stats.trims.clone(),
        allocations_attempted: stats.allocations_attempted.clone(),
        allocations_succeeded: stats.allocations_succeeded.clone(),
        allocations_succeeded_special_pool: stats.allocations_succeeded_special_pool.clone(),
        allocations_with_no_tag: stats.allocations_with_no_tag.clone(),
        allocations_failed: stats.allocations_failed.clone(),
        current_paged_pool_allocations: stats.current_paged_pool_allocations.clone(),
        paged_bytes: stats.paged_bytes.clone(),
        peak_paged_pool_allocations: stats.peak_paged_pool_allocations.clone(),
        peak_paged_bytes: stats.peak_paged_bytes.clone(),
        current_nonpaged_pool_allocations: stats.current_nonpaged_pool_allocations.clone(),
        nonpaged_bytes: stats.nonpaged_bytes.clone(),
        peak_nonpaged_pool_allocations: stats.peak_nonpaged_pool_allocations.clone(),
        peak_nonpaged_bytes: stats.peak_nonpaged_bytes.clone(),
        loads: stats.loads.clone(),
        unloads: stats.unloads.clone(),
    }
}

/// How the verifier's suspect-list walk ended: as the shared
/// [`list_termination`], but every end except the list head carries an error.
fn suspect_list_end(termination: &ListTermination) -> ListEnd {
    let error = match termination {
        ListTermination::Null => Some("null link".to_string()),
        ListTermination::Cycle(address) => Some(format!("non-head cycle at {:#x}", address.0)),
        ListTermination::Bound => Some("entry bound reached".to_string()),
        ListTermination::Head | ListTermination::Corrupt(_) => None,
    };
    let end = list_termination(termination);
    ListEnd {
        error: end.error.or(error),
        ..end
    }
}

/// Driver Verifier global level/options, aggregate statistics, loaded drivers,
/// and configured-but-unloaded suspect drivers.
pub fn verifier(detail: &VerifierDetail) -> Verifier {
    Verifier {
        level: detail.level.clone(),
        option_flags: detail.option_flags.clone(),
        verify_mode: detail.verify_mode.clone(),
        level_options: detail.level_options.clone(),
        statistics: verifier_statistics(&detail.statistics),
        drivers: detail
            .drivers
            .map(|drivers| drivers.iter().map(verifier_summary).collect()),
        drivers_truncated: detail.drivers_truncated,
        configured_but_unloaded: detail
            .configured_but_unloaded
            .map(|drivers| drivers.iter().map(suspect_driver).collect()),
        suspect_list_termination: suspect_list_end(&detail.suspect_list_termination),
    }
}

/// One Driver Verifier entry's image, signing, counters, and load history.
pub fn verifier_driver(detail: &VerifierDriverDetail) -> VerifierDriver {
    VerifierDriver {
        module: detail.module_name.clone(),
        image_base: detail.image_base,
        image_size: detail.image_size,
        driver_object: detail.driver_object,
        se_signing_level: detail.se_signing_level,
        raise_irqls: detail.raise_irqls,
        acquire_spin_locks: detail.acquire_spin_locks,
        synchronize_executions: detail.synchronize_executions,
        allocations_with_no_tag: detail.allocations_with_no_tag,
        allocations_failed: detail.allocations_failed,
        allocations_failed_deliberately: detail.allocations_failed_deliberately,
        current_paged_pool_allocations: detail.current_paged_pool_allocations,
        paged_bytes: detail.paged_bytes,
        peak_paged_pool_allocations: detail.peak_paged_pool_allocations,
        peak_paged_bytes: detail.peak_paged_bytes,
        current_nonpaged_pool_allocations: detail.current_nonpaged_pool_allocations,
        nonpaged_bytes: detail.nonpaged_bytes,
        peak_nonpaged_pool_allocations: detail.peak_nonpaged_pool_allocations,
        peak_nonpaged_bytes: detail.peak_nonpaged_bytes,
        locked_bytes: detail.locked_bytes,
        peak_locked_bytes: detail.peak_locked_bytes,
        mapped_locked_bytes: detail.mapped_locked_bytes,
        peak_mapped_locked_bytes: detail.peak_mapped_locked_bytes,
        mapped_io_space_bytes: detail.mapped_io_space_bytes,
        peak_mapped_io_space_bytes: detail.peak_mapped_io_space_bytes,
        pages_for_mdl_bytes: detail.pages_for_mdl_bytes,
        peak_pages_for_mdl_bytes: detail.peak_pages_for_mdl_bytes,
        contiguous_memory_bytes: detail.contiguous_memory_bytes,
        peak_contiguous_memory_bytes: detail.peak_contiguous_memory_bytes,
        suspect: detail.suspect.as_ref().map(suspect_driver),
    }
}

fn target_kernel(kernel: &TargetKernelDetail) -> TargetKernel {
    TargetKernel {
        name: kernel.name.clone(),
        short_name: kernel.short_name.clone(),
        base: kernel.base,
        size: kernel.size,
        file_version: kernel.file_version.clone(),
        product_version: kernel.product_version.clone(),
        pdb_guid: kernel.pdb_guid.clone(),
        pdb_age: kernel.pdb_age,
    }
}

fn target_dump(dump: &TargetDumpMetadata) -> TargetDump {
    TargetDump {
        is_triage: dump.is_triage,
        directory_table_base: dump.directory_table_base,
        bugcheck_code: dump.bugcheck_code,
        bugcheck_parameters: dump.bugcheck_parameters.to_vec(),
        number_processors: dump.number_processors,
        major_version: dump.major_version,
        minor_version: dump.minor_version,
        product_type: dump.product_type,
        machine_image_type: dump.machine_image_type,
        service_pack_build: dump.service_pack_build,
        system_time: dump.system_time,
        uptime_seconds: dump.uptime_seconds,
        exception_code: dump.exception_code,
        triage_overflowed: dump.triage_overflowed,
        kernel_base: dump.kernel_base,
        tagged_blocks: dump
            .tagged_blocks
            .iter()
            .map(|block| TaggedBlock {
                tag: block.tag.clone(),
                size: block.size,
                owner: block.owner,
                holds: block.holds,
            })
            .collect(),
    }
}

/// Target/kernel build identity, architecture, processor count, symbols,
/// debugger version, time, and dump metadata.
pub fn target_version(detail: &TargetVersionDetail) -> TargetVersion {
    TargetVersion {
        major_version: detail.major_version,
        minor_version: detail.minor_version,
        build_number: detail.build_number,
        build_lab: detail.build_lab.clone(),
        architecture: detail.architecture.clone(),
        processors: detail.processors,
        product: detail.product.clone(),
        kernel: detail.kernel.as_ref().map(target_kernel),
        symbol_status: detail.symbol_status.clone(),
        debugger_version: detail.debugger_version.clone(),
        symbol_path: detail.symbol_path.clone(),
        time: target_time(&detail.time),
        backend: detail.backend.clone(),
        dump: detail.dump.as_ref().map(target_dump),
        user_dump: detail.user_dump.as_ref().map(target_user_dump),
    }
}

fn target_user_dump(detail: &TargetUserDumpDetail) -> TargetUserDump {
    TargetUserDump {
        process_name: detail.process_name.clone(),
        process_id: detail.process_id,
        processor_level: detail.processor_level,
        processor_revision: detail.processor_revision,
        service_pack: detail.service_pack.clone(),
        flags: detail.flags,
        flag_names: detail.flag_names.clone(),
        threads: detail.threads,
        modules: detail.modules,
        exception_code: detail.exception_code,
    }
}

fn user_dump_time(detail: &UserDumpTimeDetail) -> UserDumpTime {
    UserDumpTime {
        written: detail.written,
        written_iso: detail.written_iso.clone(),
        written_local: detail.written_local.clone(),
        time_zone: detail.time_zone.clone(),
        process_created: detail.process_created,
        process_created_iso: detail.process_created_iso.clone(),
        process_uptime_seconds: detail.process_uptime_seconds,
        process_uptime: detail.process_uptime.clone(),
        user_time_seconds: detail.user_time_seconds,
        kernel_time_seconds: detail.kernel_time_seconds,
    }
}

/// Target UTC FILETIME/ISO time and uptime in seconds/formatted form.
pub fn target_time(detail: &TargetTimeDetail) -> TargetTime {
    TargetTime {
        system_time: detail.system_time,
        system_time_iso: detail.system_time_iso.clone(),
        interrupt_time: detail.interrupt_time,
        uptime_seconds: detail.uptime_seconds,
        uptime: detail.uptime.clone(),
        user_dump: detail.user_dump.as_ref().map(user_dump_time),
    }
}

/// Decoded NTSTATUS, Win32, or HRESULT metadata.
pub fn error_code(detail: &ErrorCodeDetail) -> ErrorCode {
    ErrorCode {
        code: detail.code,
        kind: detail.kind.clone(),
        name: detail.name.clone(),
        description: detail.description.clone(),
        severity: detail.severity.clone(),
        facility: detail.facility,
        customer: detail.customer,
        win32_code: detail.win32_code,
        win32_name: detail.win32_name.clone(),
    }
}
