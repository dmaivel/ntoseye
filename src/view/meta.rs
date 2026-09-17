//! `View` builders for the metadata inspectors.

use super::{View, diagnostic};
use crate::target::ListTermination;
use crate::target::meta::{
    ErrorCodeDetail, TargetDumpMetadata, TargetKernelDetail, TargetTimeDetail, TargetVersionDetail,
    VerifierDetail, VerifierDriverDetail, VerifierDriverSummary, VerifierStatistics,
    VerifierSuspectDriver,
};

fn verifier_summary(driver: &VerifierDriverSummary) -> View {
    View::Object(vec![
        ("entry", View::Hex(driver.entry.0)),
        ("state", View::Str(driver.state.clone())),
        ("nonpaged_bytes", View::Num(driver.nonpaged_bytes)),
        ("paged_bytes", View::Num(driver.paged_bytes)),
        ("module", View::Str(driver.module_name.clone())),
    ])
}

fn suspect_driver(driver: &VerifierSuspectDriver) -> View {
    View::Object(vec![
        ("address", View::Hex(driver.address.0)),
        ("full_name", View::Str(driver.full_name.clone())),
        ("base_name", View::Str(driver.base_name.clone())),
        ("loads", View::Num(driver.loads)),
        ("unloads", View::Num(driver.unloads)),
    ])
}

fn verifier_statistics(stats: &VerifierStatistics) -> View {
    View::Object(vec![
        (
            "raise_irqls",
            diagnostic(&stats.raise_irqls, |value| View::Num(*value)),
        ),
        (
            "acquire_spin_locks",
            diagnostic(&stats.acquire_spin_locks, |value| View::Num(*value)),
        ),
        (
            "synchronize_executions",
            diagnostic(&stats.synchronize_executions, |value| View::Num(*value)),
        ),
        ("trims", diagnostic(&stats.trims, |value| View::Num(*value))),
        (
            "allocations_attempted",
            diagnostic(&stats.allocations_attempted, |value| View::Num(*value)),
        ),
        (
            "allocations_succeeded",
            diagnostic(&stats.allocations_succeeded, |value| View::Num(*value)),
        ),
        (
            "allocations_succeeded_special_pool",
            diagnostic(&stats.allocations_succeeded_special_pool, |value| {
                View::Num(*value)
            }),
        ),
        (
            "allocations_with_no_tag",
            diagnostic(&stats.allocations_with_no_tag, |value| View::Num(*value)),
        ),
        (
            "allocations_failed",
            diagnostic(&stats.allocations_failed, |value| View::Num(*value)),
        ),
        (
            "current_paged_pool_allocations",
            diagnostic(&stats.current_paged_pool_allocations, |value| {
                View::Num(*value)
            }),
        ),
        (
            "paged_bytes",
            diagnostic(&stats.paged_bytes, |value| View::Num(*value)),
        ),
        (
            "peak_paged_pool_allocations",
            diagnostic(&stats.peak_paged_pool_allocations, |value| {
                View::Num(*value)
            }),
        ),
        (
            "peak_paged_bytes",
            diagnostic(&stats.peak_paged_bytes, |value| View::Num(*value)),
        ),
        (
            "current_nonpaged_pool_allocations",
            diagnostic(&stats.current_nonpaged_pool_allocations, |value| {
                View::Num(*value)
            }),
        ),
        (
            "nonpaged_bytes",
            diagnostic(&stats.nonpaged_bytes, |value| View::Num(*value)),
        ),
        (
            "peak_nonpaged_pool_allocations",
            diagnostic(&stats.peak_nonpaged_pool_allocations, |value| {
                View::Num(*value)
            }),
        ),
        (
            "peak_nonpaged_bytes",
            diagnostic(&stats.peak_nonpaged_bytes, |value| View::Num(*value)),
        ),
        ("loads", diagnostic(&stats.loads, |value| View::Num(*value))),
        (
            "unloads",
            diagnostic(&stats.unloads, |value| View::Num(*value)),
        ),
    ])
}

fn list_termination(termination: &ListTermination) -> View {
    match termination {
        ListTermination::Head => View::Object(vec![
            ("kind", View::Str("head".to_string())),
            ("address", View::Null),
            ("error", View::Null),
        ]),
        ListTermination::Null => View::Object(vec![
            ("kind", View::Str("null".to_string())),
            ("address", View::Null),
            ("error", View::Str("null link".to_string())),
        ]),
        ListTermination::Cycle(address) => View::Object(vec![
            ("kind", View::Str("cycle".to_string())),
            ("address", View::Hex(address.0)),
            (
                "error",
                View::Str(format!("non-head cycle at {:#x}", address.0)),
            ),
        ]),
        ListTermination::Bound => View::Object(vec![
            ("kind", View::Str("bound".to_string())),
            ("address", View::Null),
            ("error", View::Str("entry bound reached".to_string())),
        ]),
        ListTermination::Corrupt(error) => View::Object(vec![
            ("kind", View::Str("corrupt".to_string())),
            ("address", View::Null),
            ("error", View::Str(error.clone())),
        ]),
    }
}

/// Driver Verifier global level/options, aggregate statistics, loaded drivers,
/// and configured-but-unloaded suspect drivers. Top-level keys: `level`,
/// `option_flags`, `verify_mode`, `level_options`, `statistics`, `drivers`,
/// `drivers_truncated`, `configured_but_unloaded`, `suspect_list_termination`.
pub fn verifier(detail: &VerifierDetail) -> View {
    View::Object(vec![
        (
            "level",
            diagnostic(&detail.level, |value| View::Hex(*value)),
        ),
        (
            "option_flags",
            diagnostic(&detail.option_flags, |value| View::Hex(*value)),
        ),
        (
            "verify_mode",
            diagnostic(&detail.verify_mode, |value| View::Num(*value)),
        ),
        (
            "level_options",
            diagnostic(&detail.level_options, |options| {
                View::List(options.iter().cloned().map(View::Str).collect())
            }),
        ),
        ("statistics", verifier_statistics(&detail.statistics)),
        (
            "drivers",
            diagnostic(&detail.drivers, |drivers| {
                View::List(drivers.iter().map(verifier_summary).collect())
            }),
        ),
        ("drivers_truncated", View::Bool(detail.drivers_truncated)),
        (
            "configured_but_unloaded",
            diagnostic(&detail.configured_but_unloaded, |drivers| {
                View::List(drivers.iter().map(suspect_driver).collect())
            }),
        ),
        (
            "suspect_list_termination",
            list_termination(&detail.suspect_list_termination),
        ),
    ])
}

/// One Driver Verifier entry's image, signing, counters, and load history.
/// Top-level keys: `module`, `image_base`, `image_size`, `driver_object`,
/// `se_signing_level`, `raise_irqls`, `acquire_spin_locks`,
/// `synchronize_executions`, `allocations_with_no_tag`, `allocations_failed`,
/// `allocations_failed_deliberately`, `current_paged_pool_allocations`,
/// `paged_bytes`, `peak_paged_pool_allocations`, `peak_paged_bytes`,
/// `current_nonpaged_pool_allocations`, `nonpaged_bytes`,
/// `peak_nonpaged_pool_allocations`, `peak_nonpaged_bytes`, `locked_bytes`,
/// `peak_locked_bytes`, `mapped_locked_bytes`, `peak_mapped_locked_bytes`,
/// `mapped_io_space_bytes`, `peak_mapped_io_space_bytes`, `pages_for_mdl_bytes`,
/// `peak_pages_for_mdl_bytes`, `contiguous_memory_bytes`,
/// `peak_contiguous_memory_bytes`, `suspect`.
pub fn verifier_driver(detail: &VerifierDriverDetail) -> View {
    let suspect = detail
        .suspect
        .as_ref()
        .map(suspect_driver)
        .unwrap_or(View::Null);
    View::Object(vec![
        ("module", View::Str(detail.module_name.clone())),
        ("image_base", View::Hex(detail.image_base.0)),
        ("image_size", View::Num(detail.image_size)),
        ("driver_object", View::Hex(detail.driver_object.0)),
        ("se_signing_level", View::Hex(detail.se_signing_level)),
        ("raise_irqls", View::Num(detail.raise_irqls)),
        ("acquire_spin_locks", View::Num(detail.acquire_spin_locks)),
        (
            "synchronize_executions",
            View::Num(detail.synchronize_executions),
        ),
        (
            "allocations_with_no_tag",
            View::Num(detail.allocations_with_no_tag),
        ),
        ("allocations_failed", View::Num(detail.allocations_failed)),
        (
            "allocations_failed_deliberately",
            View::Num(detail.allocations_failed_deliberately),
        ),
        (
            "current_paged_pool_allocations",
            View::Num(detail.current_paged_pool_allocations),
        ),
        ("paged_bytes", View::Num(detail.paged_bytes)),
        (
            "peak_paged_pool_allocations",
            View::Num(detail.peak_paged_pool_allocations),
        ),
        ("peak_paged_bytes", View::Num(detail.peak_paged_bytes)),
        (
            "current_nonpaged_pool_allocations",
            View::Num(detail.current_nonpaged_pool_allocations),
        ),
        ("nonpaged_bytes", View::Num(detail.nonpaged_bytes)),
        (
            "peak_nonpaged_pool_allocations",
            View::Num(detail.peak_nonpaged_pool_allocations),
        ),
        ("peak_nonpaged_bytes", View::Num(detail.peak_nonpaged_bytes)),
        ("locked_bytes", View::Num(detail.locked_bytes)),
        ("peak_locked_bytes", View::Num(detail.peak_locked_bytes)),
        ("mapped_locked_bytes", View::Num(detail.mapped_locked_bytes)),
        (
            "peak_mapped_locked_bytes",
            View::Num(detail.peak_mapped_locked_bytes),
        ),
        (
            "mapped_io_space_bytes",
            View::Num(detail.mapped_io_space_bytes),
        ),
        (
            "peak_mapped_io_space_bytes",
            View::Num(detail.peak_mapped_io_space_bytes),
        ),
        ("pages_for_mdl_bytes", View::Num(detail.pages_for_mdl_bytes)),
        (
            "peak_pages_for_mdl_bytes",
            View::Num(detail.peak_pages_for_mdl_bytes),
        ),
        (
            "contiguous_memory_bytes",
            View::Num(detail.contiguous_memory_bytes),
        ),
        (
            "peak_contiguous_memory_bytes",
            View::Num(detail.peak_contiguous_memory_bytes),
        ),
        ("suspect", suspect),
    ])
}

fn target_kernel(kernel: &TargetKernelDetail) -> View {
    View::Object(vec![
        ("name", View::Str(kernel.name.clone())),
        ("short_name", View::Str(kernel.short_name.clone())),
        ("base", View::Hex(kernel.base.0)),
        ("size", View::OptNum(kernel.size)),
        ("file_version", View::OptStr(kernel.file_version.clone())),
        (
            "product_version",
            View::OptStr(kernel.product_version.clone()),
        ),
        ("pdb_guid", View::OptStr(kernel.pdb_guid.clone())),
        ("pdb_age", View::OptNum(kernel.pdb_age.map(u64::from))),
    ])
}

fn target_dump(dump: &TargetDumpMetadata) -> View {
    View::Object(vec![
        ("is_triage", View::Bool(dump.is_triage)),
        (
            "directory_table_base",
            View::Hex(dump.directory_table_base.0),
        ),
        ("bugcheck_code", View::Hex(dump.bugcheck_code.into())),
        (
            "bugcheck_parameters",
            View::List(
                dump.bugcheck_parameters
                    .iter()
                    .copied()
                    .map(View::Hex)
                    .collect(),
            ),
        ),
        (
            "number_processors",
            View::Num(dump.number_processors.into()),
        ),
        ("major_version", View::Num(dump.major_version.into())),
        ("minor_version", View::Num(dump.minor_version.into())),
        ("product_type", View::Num(dump.product_type.into())),
        (
            "machine_image_type",
            View::Num(dump.machine_image_type.into()),
        ),
        (
            "service_pack_build",
            View::Num(dump.service_pack_build.into()),
        ),
        ("system_time", View::OptHex(dump.system_time)),
        ("uptime_seconds", View::OptNum(dump.uptime_seconds)),
        (
            "exception_code",
            View::OptHex(dump.exception_code.map(u64::from)),
        ),
        ("triage_overflowed", View::Bool(dump.triage_overflowed)),
        (
            "kernel_base",
            View::OptHex(dump.kernel_base.map(|base| base.0)),
        ),
    ])
}

/// Target/kernel build identity, architecture, processor count, symbols,
/// debugger version, time, and dump metadata. Top-level keys: `major_version`,
/// `minor_version`, `build_number`, `build_lab`, `architecture`, `processors`,
/// `product`, `kernel`, `symbol_status`, `debugger_version`, `symbol_path`,
/// `system_time`, `system_time_iso`, `uptime_seconds`, `uptime`, `backend`,
/// `dump`.
pub fn target_version(detail: &TargetVersionDetail) -> View {
    View::Object(vec![
        ("major_version", View::OptNum(detail.major_version)),
        ("minor_version", View::OptNum(detail.minor_version)),
        ("build_number", View::OptNum(detail.build_number)),
        ("build_lab", View::OptStr(detail.build_lab.clone())),
        ("architecture", View::Str(detail.architecture.clone())),
        ("processors", View::OptNum(detail.processors.map(u64::from))),
        ("product", View::Str(detail.product.clone())),
        (
            "kernel",
            detail
                .kernel
                .as_ref()
                .map(target_kernel)
                .unwrap_or(View::Null),
        ),
        ("symbol_status", View::OptStr(detail.symbol_status.clone())),
        (
            "debugger_version",
            View::Str(detail.debugger_version.clone()),
        ),
        ("symbol_path", View::Str(detail.symbol_path.clone())),
        ("system_time", View::OptHex(detail.system_time)),
        (
            "system_time_iso",
            View::OptStr(detail.system_time_iso.clone()),
        ),
        ("uptime_seconds", View::OptNum(detail.uptime_seconds)),
        ("uptime", View::OptStr(detail.uptime.clone())),
        ("backend", View::OptStr(detail.backend.clone())),
        (
            "dump",
            detail.dump.as_ref().map(target_dump).unwrap_or(View::Null),
        ),
    ])
}

/// Target UTC FILETIME/ISO time and uptime in seconds/formatted form. Top-level
/// keys: `system_time`, `system_time_iso`, `uptime_seconds`, `uptime`.
pub fn target_time(detail: &TargetTimeDetail) -> View {
    View::Object(vec![
        ("system_time", View::OptHex(detail.system_time)),
        (
            "system_time_iso",
            View::OptStr(detail.system_time_iso.clone()),
        ),
        ("uptime_seconds", View::OptNum(detail.uptime_seconds)),
        ("uptime", View::OptStr(detail.uptime.clone())),
    ])
}

/// Decoded NTSTATUS, Win32, or HRESULT metadata. Top-level keys: `code`,
/// `kind`, `name`, `description`, `severity`, `facility`, `customer`,
/// `win32_code`, `win32_name`.
pub fn error_code(detail: &ErrorCodeDetail) -> View {
    View::Object(vec![
        ("code", View::Hex(detail.code)),
        ("kind", View::Str(detail.kind.clone())),
        ("name", View::Str(detail.name.clone())),
        ("description", View::Str(detail.description.clone())),
        ("severity", View::OptStr(detail.severity.clone())),
        ("facility", View::OptNum(detail.facility.map(u64::from))),
        ("customer", View::OptBool(detail.customer)),
        ("win32_code", View::OptHex(detail.win32_code.map(u64::from))),
        ("win32_name", View::OptStr(detail.win32_name.clone())),
    ])
}
