//! `View` builders for the metadata inspectors.

use super::shape::{Diag, Hex, shapes};
use super::list::{ListEnd, list_termination};
use crate::types::VirtAddr;
use crate::target::ListTermination;
use crate::target::meta::{
    ErrorCodeDetail, TargetDumpMetadata, TargetKernelDetail, TargetTimeDetail, TargetVersionDetail,
    VerifierDetail, VerifierDriverDetail, VerifierDriverSummary as DriverSummaryDetail,
    VerifierStatistics as StatisticsDetail, VerifierSuspectDriver as SuspectDriverDetail,
};

shapes! {
    /// A driver that Driver Verifier verifies, from the `!verifier` list.
    VerifierDriverSummary {
        /// The verifier entry of the driver.
        entry: VirtAddr,
        /// The state of the entry (`Loaded`).
        state: String,
        /// The nonpaged pool that the driver holds, in bytes.
        nonpaged_bytes: u64,
        /// The paged pool that the driver holds, in bytes.
        paged_bytes: u64,
        /// The module name of the driver.
        module: String,
    }

    /// A driver that is configured for verification, from the verifier
    /// suspect list.
    VerifierSuspectDriver {
        /// The suspect-list entry.
        address: VirtAddr,
        full_name: String,
        base_name: String,
        /// The number of times that the driver loaded.
        loads: u64,
        /// The number of times that the driver unloaded.
        unloads: u64,
    }

    /// The aggregate counters of Driver Verifier. ntoseye reads each counter
    /// separately, and each read can fail.
    VerifierStatistics {
        raise_irqls: Diag<u64>,
        acquire_spin_locks: Diag<u64>,
        synchronize_executions: Diag<u64>,
        trims: Diag<u64>,
        allocations_attempted: Diag<u64>,
        allocations_succeeded: Diag<u64>,
        allocations_succeeded_special_pool: Diag<u64>,
        allocations_with_no_tag: Diag<u64>,
        allocations_failed: Diag<u64>,
        current_paged_pool_allocations: Diag<u64>,
        paged_bytes: Diag<u64>,
        peak_paged_pool_allocations: Diag<u64>,
        peak_paged_bytes: Diag<u64>,
        current_nonpaged_pool_allocations: Diag<u64>,
        nonpaged_bytes: Diag<u64>,
        peak_nonpaged_pool_allocations: Diag<u64>,
        peak_nonpaged_bytes: Diag<u64>,
        loads: Diag<u64>,
        unloads: Diag<u64>,
    }

    /// The Driver Verifier configuration, statistics, and drivers
    /// (`!verifier`). The drivers are the verified drivers and the configured
    /// suspect drivers that are not loaded.
    Verifier {
        /// The verification level (`MmVerifierData.Level`).
        level: Diag<Hex>,
        /// The option flags (`VerifierOptionFlags`).
        option_flags: Diag<Hex>,
        verify_mode: Diag<u64>,
        /// The names of the checks that `level` enables.
        level_options: Diag<Vec<String>>,
        statistics: VerifierStatistics,
        /// The verified drivers.
        drivers: Diag<Vec<VerifierDriverSummary>>,
        /// Whether the driver table gives a smaller entry count than the
        /// number of linked entries. In that case, the walk stopped before it
        /// got to all drivers.
        drivers_truncated: bool,
        /// The suspect drivers that are configured for verification but are
        /// not loaded.
        configured_but_unloaded: Diag<Vec<VerifierSuspectDriver>>,
        /// How the suspect-list walk ended.
        suspect_list_termination: ListEnd,
    }

    /// The image, signing level, and counters of one verified driver
    /// (`!verifier <module>`).
    VerifierDriver {
        module: String,
        image_base: VirtAddr,
        /// The image size in bytes.
        image_size: u64,
        /// The `_DRIVER_OBJECT` of the driver.
        driver_object: VirtAddr,
        /// The signing level of the image (`SE_SIGNING_LEVEL`).
        se_signing_level: Hex,
        raise_irqls: u64,
        acquire_spin_locks: u64,
        synchronize_executions: u64,
        allocations_with_no_tag: u64,
        allocations_failed: u64,
        /// The number of allocations that the verifier failed on purpose
        /// (fault injection).
        allocations_failed_deliberately: u64,
        current_paged_pool_allocations: u64,
        paged_bytes: u64,
        peak_paged_pool_allocations: u64,
        peak_paged_bytes: u64,
        current_nonpaged_pool_allocations: u64,
        nonpaged_bytes: u64,
        peak_nonpaged_pool_allocations: u64,
        peak_nonpaged_bytes: u64,
        locked_bytes: u64,
        peak_locked_bytes: u64,
        mapped_locked_bytes: u64,
        peak_mapped_locked_bytes: u64,
        mapped_io_space_bytes: u64,
        peak_mapped_io_space_bytes: u64,
        pages_for_mdl_bytes: u64,
        peak_pages_for_mdl_bytes: u64,
        contiguous_memory_bytes: u64,
        peak_contiguous_memory_bytes: u64,
        /// The suspect-list entry of the driver, with its load history.
        /// `None` if the driver has no entry.
        suspect: Option<VerifierSuspectDriver>,
    }

    /// The identity of the kernel image.
    TargetKernel {
        /// The file name of the image.
        name: String,
        /// The module name (`nt`).
        short_name: String,
        base: VirtAddr,
        /// The image size in bytes.
        size: Option<u64>,
        file_version: Option<String>,
        product_version: Option<String>,
        /// The GUID of the PDB. It identifies the symbols.
        pdb_guid: Option<String>,
        /// The age of the PDB.
        pdb_age: Option<u32>,
    }

    /// The data that a crash dump header records.
    TargetDump {
        /// Whether the dump is a triage (minidump-style) dump.
        is_triage: bool,
        /// The kernel page-table root that the dump records.
        directory_table_base: VirtAddr,
        bugcheck_code: Hex<u32>,
        bugcheck_parameters: Vec<Hex>,
        number_processors: u32,
        major_version: u32,
        minor_version: u32,
        product_type: u32,
        /// The machine type (`IMAGE_FILE_MACHINE_*`).
        machine_image_type: u32,
        service_pack_build: u32,
        /// The time when the system made the dump (FILETIME).
        system_time: Option<Hex>,
        /// The system uptime in seconds.
        uptime_seconds: Option<u64>,
        /// The exception code that the dump records.
        exception_code: Option<Hex<u32>>,
        /// Whether the triage data of the dump overflowed.
        triage_overflowed: bool,
        kernel_base: Option<VirtAddr>,
    }

    /// The version data of the target (`vertarget`). It contains the build,
    /// architecture, kernel, symbols, debugger version, time, and dump
    /// metadata.
    TargetVersion {
        major_version: Option<u64>,
        minor_version: Option<u64>,
        build_number: Option<u64>,
        /// The build lab string.
        build_lab: Option<String>,
        architecture: String,
        /// The number of processors in the target.
        processors: Option<u16>,
        /// The product name.
        product: String,
        /// The kernel image. `None` if ntoseye did not find it.
        kernel: Option<TargetKernel>,
        /// The symbol status label of the kernel. `None` if ntoseye did not
        /// find the kernel.
        symbol_status: Option<String>,
        debugger_version: String,
        symbol_path: String,
        time: TargetTime,
        /// The backend attached to the target.
        backend: Option<String>,
        /// The crash dump header. `None` for a live target.
        dump: Option<TargetDump>,
    }

    /// The UTC time and uptime of the target (`.time`).
    TargetTime {
        /// The UTC time of the target (FILETIME).
        system_time: Option<Hex>,
        /// `system_time` as ISO 8601.
        system_time_iso: Option<String>,
        /// `KUSER_SHARED_DATA.InterruptTime`: the time since boot, in 100 ns
        /// units. The `due_time` of clock timers uses this clock.
        interrupt_time: Option<Hex>,
        /// Seconds since boot.
        uptime_seconds: Option<u64>,
        /// The uptime as formatted text.
        uptime: Option<String>,
    }

    /// A decoded NTSTATUS, Win32, or HRESULT code (`!error`).
    ErrorCode {
        code: Hex,
        /// `NTSTATUS`, `HRESULT`, `Win32`, or `unknown`.
        kind: String,
        /// The symbolic name of the code.
        name: String,
        description: String,
        /// `success`, `informational`, `warning`, or `error`. `None` for a
        /// Win32 code.
        severity: Option<String>,
        /// The facility that the code encodes.
        facility: Option<u32>,
        /// Whether the code is customer-defined (its C bit).
        customer: Option<bool>,
        /// The Win32 error. This is the code itself, or the Win32 error that
        /// a `HRESULT_FROM_WIN32` code wraps.
        win32_code: Option<Hex<u32>>,
        /// The name of that Win32 error.
        win32_name: Option<String>,
    }
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
        drivers: detail.drivers.map(|drivers| {
            drivers.iter().map(verifier_summary).collect()
        }),
        drivers_truncated: detail.drivers_truncated,
        configured_but_unloaded: detail.configured_but_unloaded.map(|drivers| {
            drivers.iter().map(suspect_driver).collect()
        }),
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
