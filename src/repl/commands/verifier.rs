use crate::error::Result;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::ListTermination;
use crate::target::meta::{
    VerifierDetail, VerifierDriverDetail, VerifierDriverSummary, VerifierStatistics,
    VerifierSuspectDriver,
};
use crate::ui;

repl_command! {
    cmd_verifier;
    names: ["!verifier", "verifier"],
    usage: "!verifier [module]",
    summary: "Display Driver Verifier status, statistics, and verified drivers.",
    details: "Without a module, display the verifier level, aggregate counters, and the configured driver list. With a module, display its verified-driver counters and image details.",
}

fn diagnostic_error<T>(value: &DiagnosticValue<T>) -> Option<&str> {
    match value {
        DiagnosticValue::Available(_) => None,
        DiagnosticValue::Unavailable(error) => Some(error),
    }
}

fn print_hex_stat(label: &str, value: &DiagnosticValue<u64>) {
    match value {
        DiagnosticValue::Available(value) => outln!("  {label:<40}{value:#x}"),
        DiagnosticValue::Unavailable(error) => {
            outln!("  {label:<40}<unavailable>");
            outln!("    reason: {error}");
        }
    }
}

fn print_value(label: &str, value: &str) {
    outln!("  {label:<40}{value}");
}

fn print_pool_stat(label: &str, allocations: &DiagnosticValue<u64>, bytes: &DiagnosticValue<u64>) {
    let allocations_text = match allocations {
        DiagnosticValue::Available(value) => format!("{value:#x}"),
        DiagnosticValue::Unavailable(_) => "<unavailable>".to_string(),
    };
    let bytes_text = match bytes {
        DiagnosticValue::Available(value) => format!("{value:#x}"),
        DiagnosticValue::Unavailable(_) => "<unavailable>".to_string(),
    };
    outln!("  {label:<40}{allocations_text} for {bytes_text} bytes");
    if let Some(error) = diagnostic_error(allocations) {
        outln!("    allocations reason: {error}");
    }
    if let Some(error) = diagnostic_error(bytes) {
        outln!("    bytes reason: {error}");
    }
}

fn print_level(detail: &VerifierDetail) -> bool {
    let DiagnosticValue::Available(level) = &detail.level else {
        if let DiagnosticValue::Unavailable(error) = &detail.level {
            outln!("Verify Level unavailable: {error}");
        }
        return false;
    };
    outln!("Verify Level {level:x}  enabled options are:");
    if *level == 0 {
        outln!("Driver Verifier is not enabled");
        return false;
    }
    match &detail.level_options {
        DiagnosticValue::Available(options) => {
            for option in options {
                outln!("        {option}");
            }
        }
        DiagnosticValue::Unavailable(error) => outln!("        options unavailable: {error}"),
    }
    match &detail.option_flags {
        DiagnosticValue::Available(flags) => out!("  option flags {flags:#x}"),
        DiagnosticValue::Unavailable(error) => out!("  option flags <unavailable> ({error})"),
    }
    match &detail.verify_mode {
        DiagnosticValue::Available(mode) => outln!("  verify mode {mode}"),
        DiagnosticValue::Unavailable(error) => outln!("  verify mode <unavailable> ({error})"),
    }
    true
}

fn print_summary(stats: &VerifierStatistics) {
    outln!();
    outln!("Summary of All Verifier Statistics");
    print_hex_stat("RaiseIrqls", &stats.raise_irqls);
    print_hex_stat("AcquireSpinLocks", &stats.acquire_spin_locks);
    print_hex_stat("Synch Executions", &stats.synchronize_executions);
    print_hex_stat("Trims", &stats.trims);
    print_hex_stat("Pool Allocations Attempted", &stats.allocations_attempted);
    print_hex_stat("Pool Allocations Succeeded", &stats.allocations_succeeded);
    print_hex_stat(
        "Pool Allocations Succeeded SpecialPool",
        &stats.allocations_succeeded_special_pool,
    );
    print_hex_stat(
        "Pool Allocations With NO TAG",
        &stats.allocations_with_no_tag,
    );
    print_hex_stat("Pool Allocations Failed", &stats.allocations_failed);
    print_pool_stat(
        "Current paged pool allocations",
        &stats.current_paged_pool_allocations,
        &stats.paged_bytes,
    );
    print_pool_stat(
        "Peak paged pool allocations",
        &stats.peak_paged_pool_allocations,
        &stats.peak_paged_bytes,
    );
    print_pool_stat(
        "Current nonpaged pool allocations",
        &stats.current_nonpaged_pool_allocations,
        &stats.nonpaged_bytes,
    );
    print_pool_stat(
        "Peak nonpaged pool allocations",
        &stats.peak_nonpaged_pool_allocations,
        &stats.peak_nonpaged_bytes,
    );
    print_hex_stat("Loads", &stats.loads);
    print_hex_stat("Unloads", &stats.unloads);
}

fn print_driver_list(detail: &VerifierDetail) {
    outln!();
    outln!("Driver Verification List");
    outln!("  Entry             State       NonPagedPool  PagedPool  Module");
    match &detail.drivers {
        DiagnosticValue::Available(drivers) => {
            for driver in drivers {
                print_driver_summary(driver);
            }
        }
        DiagnosticValue::Unavailable(error) => {
            outln!("  <unavailable>     {error}");
        }
    }
    if detail.drivers_truncated {
        outln!("  <verified-driver AVL walk truncated>");
    }
    match &detail.configured_but_unloaded {
        DiagnosticValue::Available(suspects) => {
            for suspect in suspects {
                print_suspect_driver(suspect);
            }
        }
        DiagnosticValue::Unavailable(error) => {
            outln!("  <suspect list unavailable> {error}");
        }
    }
    match &detail.suspect_list_termination {
        ListTermination::Head => {}
        ListTermination::Null => {
            outln!("  <suspect list terminated at a null link>");
        }
        ListTermination::Cycle(address) => {
            outln!("  <suspect list cycle at {}>", ui::addr(address.0));
        }
        ListTermination::Bound => {
            outln!("  <suspect list truncated at 1000 entries>");
        }
        ListTermination::Corrupt(error) => {
            outln!("  <suspect list unreadable: {error}>");
        }
    }
}

fn print_driver_summary(driver: &VerifierDriverSummary) {
    outln!(
        "  {:<18}{:<12}{:<14}{:<11}{}",
        ui::addr(driver.entry.0),
        driver.state,
        format!("{:#x}", driver.nonpaged_bytes),
        format!("{:#x}", driver.paged_bytes),
        driver.module_name
    );
}

fn print_suspect_driver(suspect: &VerifierSuspectDriver) {
    let module = if suspect.base_name.is_empty() {
        suspect.full_name.as_str()
    } else {
        suspect.base_name.as_str()
    };
    outln!(
        "  {:<18}{:<12}{:<14}{:<11}{}",
        ui::addr(suspect.address.0),
        "Not loaded",
        "0x0",
        "0x0",
        module
    );
}

fn print_driver_details(driver: &VerifierDriverDetail) {
    outln!("Verifier driver {}", driver.module_name);
    print_value("Image base", &ui::addr(driver.image_base.0));
    print_hex_stat("Image size", &DiagnosticValue::Available(driver.image_size));
    print_value("DriverObject", &ui::addr(driver.driver_object.0));
    print_hex_stat(
        "SeSigningLevel",
        &DiagnosticValue::Available(driver.se_signing_level),
    );
    print_hex_stat(
        "RaiseIrqls",
        &DiagnosticValue::Available(driver.raise_irqls),
    );
    print_hex_stat(
        "AcquireSpinLocks",
        &DiagnosticValue::Available(driver.acquire_spin_locks),
    );
    print_hex_stat(
        "Synch Executions",
        &DiagnosticValue::Available(driver.synchronize_executions),
    );
    print_hex_stat(
        "Pool Allocations With NO TAG",
        &DiagnosticValue::Available(driver.allocations_with_no_tag),
    );
    print_hex_stat(
        "Pool Allocations Failed",
        &DiagnosticValue::Available(driver.allocations_failed),
    );
    print_hex_stat(
        "Pool Allocations Failed Deliberately",
        &DiagnosticValue::Available(driver.allocations_failed_deliberately),
    );
    print_pool_stat(
        "Current paged pool allocations",
        &DiagnosticValue::Available(driver.current_paged_pool_allocations),
        &DiagnosticValue::Available(driver.paged_bytes),
    );
    print_pool_stat(
        "Peak paged pool allocations",
        &DiagnosticValue::Available(driver.peak_paged_pool_allocations),
        &DiagnosticValue::Available(driver.peak_paged_bytes),
    );
    print_pool_stat(
        "Current nonpaged pool allocations",
        &DiagnosticValue::Available(driver.current_nonpaged_pool_allocations),
        &DiagnosticValue::Available(driver.nonpaged_bytes),
    );
    print_pool_stat(
        "Peak nonpaged pool allocations",
        &DiagnosticValue::Available(driver.peak_nonpaged_pool_allocations),
        &DiagnosticValue::Available(driver.peak_nonpaged_bytes),
    );
    print_hex_stat(
        "Locked bytes",
        &DiagnosticValue::Available(driver.locked_bytes),
    );
    print_hex_stat(
        "Peak locked bytes",
        &DiagnosticValue::Available(driver.peak_locked_bytes),
    );
    print_hex_stat(
        "Mapped locked bytes",
        &DiagnosticValue::Available(driver.mapped_locked_bytes),
    );
    print_hex_stat(
        "Peak mapped locked bytes",
        &DiagnosticValue::Available(driver.peak_mapped_locked_bytes),
    );
    print_hex_stat(
        "Mapped I/O space bytes",
        &DiagnosticValue::Available(driver.mapped_io_space_bytes),
    );
    print_hex_stat(
        "Peak mapped I/O space bytes",
        &DiagnosticValue::Available(driver.peak_mapped_io_space_bytes),
    );
    print_hex_stat(
        "Pages for MDL bytes",
        &DiagnosticValue::Available(driver.pages_for_mdl_bytes),
    );
    print_hex_stat(
        "Peak pages for MDL bytes",
        &DiagnosticValue::Available(driver.peak_pages_for_mdl_bytes),
    );
    print_hex_stat(
        "Contiguous memory bytes",
        &DiagnosticValue::Available(driver.contiguous_memory_bytes),
    );
    print_hex_stat(
        "Peak contiguous memory bytes",
        &DiagnosticValue::Available(driver.peak_contiguous_memory_bytes),
    );
    if let Some(suspect) = &driver.suspect {
        print_value("SuspectDriver FullName", &suspect.full_name);
        print_hex_stat(
            "SuspectDriver Loads",
            &DiagnosticValue::Available(suspect.loads),
        );
        print_hex_stat(
            "SuspectDriver Unloads",
            &DiagnosticValue::Available(suspect.unloads),
        );
    } else {
        print_value("SuspectDriver FullName", "-");
        print_value("SuspectDriver Loads", "-");
        print_value("SuspectDriver Unloads", "-");
    }
}

impl ReplState<'_> {
    fn cmd_verifier(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("!verifier"));
            return Ok(());
        }
        if let Some(module) = invocation.arg(0) {
            match self.ctx.target.verifier_driver(module) {
                Ok(driver) => print_driver_details(&driver),
                Err(error) => error!("{error}"),
            }
            return Ok(());
        }

        let detail = match self.ctx.target.verifier_status() {
            Ok(detail) => detail,
            Err(error) => {
                error!("verifier data unavailable: {error}");
                return Ok(());
            }
        };
        if !print_level(&detail) {
            return Ok(());
        }
        print_summary(&detail.statistics);
        print_driver_list(&detail);
        Ok(())
    }
}
