//! `View` builders for the metadata inspectors.

use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use crate::target::ListTermination;
use crate::target::meta::{
    VerifierDetail, VerifierDriverDetail, VerifierDriverSummary as DriverSummaryDetail,
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
    pub suspect_list_termination: ListTermination,
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
        suspect_list_termination: detail.suspect_list_termination.clone(),
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
