use crate::analysis::triage_report::{
    BlackboxState, CodeOwner, CulpritAttribution, CulpritSubject, FailureSignatureSource,
    KmdfLogFinding, POWER_THREAD_STACK_LIMIT, PowerFailureFinding, PowerThreadRole,
    TRIAGE_BACKTRACE_LIMIT, TriageReport, UserDumpTriage, UserExceptionFinding, UserProcessSummary,
    UserStackSource, UserStackThread, WheaRecordState, power_failure_finding,
};
use crate::backend::dbg_backend::BugcheckInfo;
use crate::base::error::{Error, Result};
use crate::base::ntstatus::exception_code_name;
use crate::base::time::{filetime_to_iso, unix_time_to_iso};
use crate::hosts::ui;
use crate::nt::bugchecks::{BugcheckAnalysis, analyze_bugcheck};
use crate::nt::expr::{Expr, NumberRadix};
use crate::nt::guest::ModuleInfo;
use crate::nt::pe::headers::CodeView;
use crate::nt::target::{Target, wait_reason_name};
use crate::nt::unwind::FrameSource;

use super::power::{
    duration_text, holder_text, print_power_irp_list, print_power_worker_list, request_text,
};
use crate::analysis::triage_report::hang::{
    ANALYZE_HANG_STACK_LIMIT, BugcheckDecoding, HangReport, HangThread, gather_hang_report,
};
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::bugcheck::print_bugcheck_analysis;
use crate::hosts::repl::*;
use crate::session::Session;
use ntoseye_macros::{command, grammar};

pub const ANALYZE_STACK_LIMIT: usize = 16;
pub const ANALYZE_MODULE_LIMIT: usize = 16;
pub const ANALYZE_UNLOADED_LIMIT: usize = 12;
pub const ANALYZE_VERBOSE_MODULE_LIMIT: usize = 4096;
pub const ANALYZE_VERBOSE_UNLOADED_LIMIT: usize = 4096;

/// The text `source:` of a failure signature.
pub fn signature_source(source: FailureSignatureSource) -> &'static str {
    match source {
        FailureSignatureSource::BugcheckFault => "bugcheck fault",
        FailureSignatureSource::ExceptionAddress => "exception address",
        FailureSignatureSource::CurrentInstruction => "current instruction",
        FailureSignatureSource::TopFrame => "top frame",
        FailureSignatureSource::PowerFailureDriver => "driver the 0x9F names",
        FailureSignatureSource::FirstNonSystemFrame => "first frame outside system modules",
        FailureSignatureSource::CodeOnly => "code only",
    }
}

pub fn product_name(product_type: u32) -> &'static str {
    match product_type {
        1 => "Workstation",
        2 => "DomainController",
        3 => "Server",
        _ => "Unknown",
    }
}

/// What `!analyze`'s line asks for.
#[derive(Default)]
pub struct AnalyzeOptions {
    verbose: bool,
    hang: bool,
    show: Option<BugcheckInfo>,
}

/// `!analyze`'s options: `-v`, `-hang` and `-show <code> [p1 p2 p3 p4]`, in
/// any order; a bad one shows the help, then the error.
#[grammar(
    usage = "[-v] [-show <bugcheck-code> [p1 p2 p3 p4]] [-hang]",
    complete = Expression
)]
fn analyze_options(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AnalyzeOptions, ArgError> {
    let argv: Vec<String> = cursor.words().map(str::to_string).collect();
    while cursor.word().is_some() {}
    parse_analyze_options(&argv, &cx.state.ctx.target, cx.state.radix).map_err(|error| {
        outln!("{}\n", command_help(cx.name));
        ArgError::Message(error.to_string())
    })
}

fn parse_analyze_options(
    argv: &[String],
    target: &Target,
    radix: NumberRadix,
) -> Result<AnalyzeOptions> {
    let arg = |index: usize| argv.get(index).map(String::as_str);
    let mut options = AnalyzeOptions::default();
    let mut index = 0;
    while index < argv.len() {
        match arg(index).unwrap_or_default() {
            "-v" | "/v" => options.verbose = true,
            "-hang" | "/hang" => options.hang = true,
            "-show" | "/show" => {
                let code_text = arg(index + 1).ok_or_else(|| {
                    Error::InvalidArgument("-show requires a bugcheck code".into())
                })?;
                let code = Expr::eval_with_radix(code_text, target, radix)
                    .map(|value| value.0)
                    .map_err(|_| {
                        Error::InvalidArgument(format!("invalid bugcheck code '{code_text}'"))
                    })?;
                let code = u32::try_from(code).map_err(|_| {
                    Error::InvalidArgument(format!("bugcheck code '{code_text}' exceeds 32 bits"))
                })?;
                let mut parameters = [0u64; 4];
                let mut consumed = 2;
                for (slot, parameter) in parameters.iter_mut().enumerate() {
                    let Some(text) = arg(index + 2 + slot) else {
                        break;
                    };
                    if text.starts_with('-') || text.starts_with('/') {
                        break;
                    }
                    *parameter = Expr::eval_with_radix(text, target, radix)
                        .map(|value| value.0)
                        .map_err(|_| {
                            Error::InvalidArgument(format!("invalid bugcheck parameter '{text}'"))
                        })?;
                    consumed += 1;
                }
                options.show = Some(BugcheckInfo {
                    code,
                    parameters,
                    driver: None,
                });
                index += consumed;
                continue;
            }
            other => {
                return Err(Error::InvalidArgument(format!(
                    "unknown !analyze option '{other}'"
                )));
            }
        }
        index += 1;
    }
    Ok(options)
}

fn print_bugcheck_header(analysis: &BugcheckAnalysis) {
    match analysis.driver.as_deref() {
        Some(driver) => outln!(
            "bugcheck {:#010x} {}  driver {}",
            analysis.code,
            analysis.name,
            ui::symbol(driver)
        ),
        None => outln!("bugcheck {:#010x} {}", analysis.code, analysis.name),
    }
}

fn print_hang_report(report: &HangReport) {
    print_section("hang analysis");
    if report.processors.is_empty() {
        outln!("  {}", ui::muted("processor count unavailable"));
    }
    for entry in &report.processors {
        let processor = entry.processor;
        match &entry.current {
            Ok(HangThread { thread, stack }) => {
                outln!(
                    "  cpu {}  {}  tid {} pid {}  {}",
                    processor,
                    ui::addr(thread.ethread.0),
                    thread
                        .tid
                        .map(|tid| tid.to_string())
                        .unwrap_or_else(|| "?".into()),
                    thread
                        .pid
                        .map(|pid| pid.to_string())
                        .unwrap_or_else(|| "?".into()),
                    thread.process_name.as_deref().unwrap_or("unknown")
                );
                match stack {
                    Ok(trace) => print_stacktrace_data(trace, ANALYZE_HANG_STACK_LIMIT, true),
                    Err(error) => {
                        outln!("    {}", ui::muted(&format!("stack unavailable: {error}")))
                    }
                }
            }
            Err(error) => outln!(
                "  cpu {}  {}",
                processor,
                ui::muted(&format!("current thread unavailable: {error}"))
            ),
        }
    }

    print_section("waiting threads by pending I/O");
    let threads = match &report.waiting {
        Ok(threads) => threads,
        Err(error) => {
            outln!(
                "  {}",
                ui::muted(&format!("thread list unavailable: {error}"))
            );
            return;
        }
    };
    for thread in threads {
        outln!(
            "  {} tid {} pid {} wait {} ({}) irps {}",
            ui::addr(thread.ethread.0),
            thread
                .tid
                .map(|tid| tid.to_string())
                .unwrap_or_else(|| "?".into()),
            thread
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "?".into()),
            thread.wait_reason.unwrap_or(0),
            wait_reason_name(thread.wait_reason.unwrap_or(0)),
            thread.pending_irps.as_ref().map_or(0, Vec::len)
        );
    }
}

fn print_triage_report(report: &TriageReport, verbose: bool) {
    if let Some(user) = &report.user {
        print_user_triage_report(report, user, verbose);
        return;
    }
    outln!("{}", ui::label("crash analysis"));

    match &report.bugcheck {
        Some(analysis) => {
            outln!();
            if verbose {
                print_bugcheck_analysis(analysis);
            } else {
                print_bugcheck_header(analysis);
            }
        }
        None => outln!("{}", ui::muted("no recorded bugcheck")),
    }

    if verbose {
        if let Some(exception) = &report.exception {
            print_section("exception");
            outln!(
                "  {} {} ({:#010x})",
                ui::muted("code   "),
                exception_code_name(exception.code),
                exception.code
            );
            outln!("  {} {}", ui::muted("address"), ui::addr(exception.address));
            outln!("  {} {:#x}", ui::muted("flags  "), exception.flags);
            for (index, parameter) in exception.parameters.iter().enumerate() {
                outln!(
                    "  {} {}",
                    ui::muted(&format!("param {} ", index + 1)),
                    ui::addr(*parameter)
                );
            }
        }

        print_section("faulting context");
        outln!(
            "  {} {}",
            ui::muted("state  "),
            if report.status.running {
                "running"
            } else {
                "halted"
            }
        );
        outln!(
            "  {} {}",
            ui::muted("context"),
            ui::thread(&report.status.current_thread)
        );
        // Where the fault happened, from its trap frame, rather than where
        // the processor stopped (the debugger break the bugcheck ended in).
        let trap = report.bugcheck.as_ref().and_then(|analysis| {
            analysis
                .trap_frames
                .iter()
                .find_map(|trap| Some((trap, trap.frame.as_ref()?)))
        });
        if let Some((trap, frame)) = trap {
            let symbol = trap
                .rip_symbol
                .as_deref()
                .map(|symbol| format!("  {}", ui::symbol(symbol)))
                .unwrap_or_default();
            outln!(
                "  {} {}{}",
                ui::muted("rip    "),
                ui::addr(frame.instruction_pointer()),
                symbol
            );
            outln!(
                "  {} {}  {}",
                ui::muted("trap   "),
                ui::addr(trap.address),
                ui::muted("(.trap selects it)")
            );
        } else if let Some(rip) = report.status.rip {
            let symbol = report
                .status
                .symbol
                .as_deref()
                .map(|symbol| format!("  {}", ui::symbol(symbol)))
                .unwrap_or_default();
            outln!("  {} {}{}", ui::muted("rip    "), ui::addr(rip), symbol);
        }
        if let Some(process) = &report.status.attached_process {
            outln!(
                "  {} {} (pid {}, eprocess {})",
                ui::muted("scope  "),
                process.name,
                process.pid,
                ui::addr(process.eprocess.0)
            );
        }
        if !report.status.coherent {
            outln!(
                "  {}",
                ui::muted("target metadata is still being rebuilt after reload")
            );
        }
        if let Some(context) = &report.crash_context {
            let process = context.process_name.as_deref().unwrap_or("unknown");
            let pid = context
                .process_id
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "unknown".into());
            let tid = context
                .thread_id
                .map(|tid| tid.to_string())
                .unwrap_or_else(|| "unknown".into());
            outln!(
                "  {} {} (pid {}, tid {})",
                ui::muted("crash  "),
                process,
                pid,
                tid
            );
            if let Some(parent) = context.parent_process_id {
                outln!("  {} {}", ui::muted("parent "), parent);
            }
            if let Some(status) = context.exit_status {
                outln!("  {} {:#x}", ui::muted("process exit"), status as u32);
            }
            if let Some(status) = context.thread_exit_status {
                outln!("  {} {:#x}", ui::muted("thread exit "), status as u32);
            }
            if let Some(time) = context.create_time
                && let Some(time) = filetime_to_iso(time)
            {
                outln!("  {} {}", ui::muted("created"), time);
            }
        }
        if let Some(prcb) = &report.prcb {
            outln!(
                "  {} #{} thread {}  {} MHz  {}",
                ui::muted("processor"),
                prcb.processor_number,
                ui::addr(prcb.current_thread),
                prcb.mhz,
                prcb.vendor_string
            );
        }

        match &report.backtrace {
            Some(trace) => print_stacktrace_data(
                trace,
                if verbose {
                    TRIAGE_BACKTRACE_LIMIT
                } else {
                    ANALYZE_STACK_LIMIT
                },
                true,
            ),
            None if report.status.running => {
                print_section("stack");
                outln!("  {}", ui::muted("unavailable while target is running"));
            }
            None => {
                print_section("stack");
                outln!("  {}", ui::muted("unavailable from captured context"));
            }
        }
    }
    if !report.warnings.is_empty() {
        print_section("warnings");
        for warning in &report.warnings {
            outln!("  {}", ui::muted(warning));
        }
    }

    print_crash_intelligence(report);
    print_report_modules(report, verbose);
    print_dump_metadata(report);
}

fn print_crash_intelligence(report: &TriageReport) {
    if let Some(signature) = &report.failure_signature {
        print_section("failure signature");
        outln!("  {}", signature.bucket);
        let source = signature_source(signature.source);
        outln!("  {}", ui::muted(&format!("source: {source}")));
    }

    if let Some(culprit) = &report.culprit {
        print_section("culprit attribution");
        let subject = match &culprit.subject {
            CulpritSubject::Module(module) => ui::symbol(module),
            CulpritSubject::DynamicCode(_) => culprit_label(culprit),
        };
        outln!(
            "  {}  {}",
            subject,
            ui::muted(&format!("{:?} confidence", culprit.confidence).to_ascii_lowercase())
        );
        if let Some(caller) = culprit_caller_text(culprit) {
            outln!("  {caller}");
        }
        for evidence in &culprit.evidence {
            match evidence.address {
                Some(address) => outln!(
                    "  {} {}  {}",
                    ui::muted(&format!("{:?}", evidence.kind)),
                    ui::addr(address),
                    evidence.detail
                ),
                None => outln!(
                    "  {}  {}",
                    ui::muted(&format!("{:?}", evidence.kind)),
                    evidence.detail
                ),
            }
        }
    }

    if let Some(verifier) = &report.verifier {
        print_section("driver verifier");
        outln!(
            "  {} ({:#x}) subcode {:#x}: {}",
            verifier.bugcheck_name,
            verifier.bugcheck_code,
            verifier.subcode,
            verifier.subcode_description
        );
        if let Some(driver) = &verifier.associated_driver {
            outln!("  {} {}", ui::muted("driver"), ui::symbol(driver));
        }
        for address in &verifier.addresses {
            outln!(
                "  {} {}",
                ui::muted(&address.role),
                ui::addr(address.address)
            );
        }
        for argument in &verifier.arguments {
            outln!("  {}  {}", ui::addr(argument.value), argument.description);
        }
    }

    if let Some(whea) = &report.whea {
        print_section("WHEA");
        if let Some(address) = whea.record_address {
            outln!("  {} {}", ui::muted("record"), ui::addr(address));
        }
        match &whea.state {
            WheaRecordState::Decoded(record) => {
                outln!(
                    "  revision {:#x}, severity {:#x}, length {:#x}, {} sections",
                    record.revision,
                    record.severity,
                    record.length,
                    record.sections.len()
                );
                for section in &record.sections {
                    outln!(
                        "  +{:#x} len {:#x} severity {:#x}  {}",
                        section.offset,
                        section.length,
                        section.severity,
                        section.section_type
                    );
                }
            }
            WheaRecordState::Unavailable { reason } => {
                outln!("  {}", ui::muted(&format!("unavailable: {reason}")));
            }
        }
    }

    if !report.blackboxes.is_empty() {
        print_section("blackbox streams");
        for blackbox in &report.blackboxes {
            match &blackbox.state {
                BlackboxState::Decoded { summary } => outln!(
                    "  {:<9} {summary}  {}",
                    blackbox.name,
                    ui::muted(&format!("({})", blackbox.command))
                ),
                BlackboxState::Malformed { reason } => {
                    outln!("  {:<9} {}", blackbox.name, ui::muted(reason));
                }
                BlackboxState::Absent => {
                    outln!("  {:<9} {}", blackbox.name, ui::muted("not in this dump"));
                }
            }
        }
    }

    if let Some(log) = &report.kmdf_log {
        print_section("KMDF log");
        outln!(
            "  {}  {}",
            kmdf_log_summary(log),
            ui::muted("(!wdfkd.wdfcrashdump)")
        );
    }

    if let Some(power) = &report.power {
        print_power_failure(power);
    }
}

/// The 0x9F section of `!analyze`: what is stuck, and the threads involved.
fn print_power_failure(finding: &PowerFailureFinding) {
    let failure = &finding.failure;
    print_section("power failure");
    outln!("  subtype {:#x}: {}", failure.subtype, failure.description);
    if let Some(culprit) = &failure.culprit {
        outln!(
            "  {} {} {}",
            ui::muted("driver     "),
            ui::symbol(&culprit.driver.label()),
            culprit.reason
        );
    }
    if let Some(blocked) = &failure.blocked_irp {
        outln!(
            "  {} {}  {}",
            ui::muted("blocked IRP"),
            ui::addr(blocked.irp.0),
            ui::muted("(!irp)")
        );
        match blocked.holder.as_result() {
            Ok(holder) => {
                outln!(
                    "  {} {}",
                    ui::muted("request    "),
                    request_text(
                        holder.major_function,
                        holder.minor_function,
                        holder.state.as_ref()
                    )
                );
                outln!("  {} {}", ui::muted("pending in "), holder_text(holder));
            }
            Err(error) => outln!(
                "  {} {}",
                ui::muted("pending in "),
                ui::muted(&format!("unknown: {error}"))
            ),
        }
        if let Some(data) = &blocked.data {
            let pending = data.pending.map_or_else(
                || format!("watchdog {}", data.watchdog.label()),
                |pending| format!("{} since the watchdog was armed", duration_text(pending)),
            );
            outln!(
                "  {} {}  {}",
                ui::muted("pending for"),
                pending,
                ui::muted(&format!("POP_IRP_DATA {}", ui::addr(data.data.0)))
            );
        }
    }
    if let Some(device) = failure.device {
        outln!(
            "  {} {}  {}",
            ui::muted("device     "),
            ui::addr(device.0),
            ui::muted("(!devstack, !podev)")
        );
    }
    match &failure.stack {
        Some(Ok(stack)) => {
            let holder = failure
                .blocked_irp
                .as_ref()
                .and_then(|blocked| blocked.holder.as_result().ok())
                .map(|holder| holder.device);
            for entry in &stack.entries {
                let marker = if Some(entry.device_object) == holder {
                    ">"
                } else {
                    " "
                };
                outln!(
                    "   {marker} {}  {:<20} {}",
                    ui::addr(entry.device_object.0),
                    entry.driver_name,
                    entry.object_name
                );
            }
            if holder.is_some() {
                outln!("  {}", ui::muted("> holds the blocked IRP"));
            }
        }
        Some(Err(error)) => outln!(
            "  {} {}",
            ui::muted("stack      "),
            ui::muted(&format!("unavailable: {error}"))
        ),
        None => {}
    }
    if let Some(seconds) = failure.timeout_seconds {
        outln!("  {} {} s", ui::muted("timeout    "), seconds);
    }
    if let Some(owner) = failure.pnp_lock_owner {
        outln!(
            "  {} {}  {}",
            ui::muted("PnP lock   "),
            ui::addr(owner.0),
            ui::muted("thread holding it (!thread)")
        );
    }
    if let Some(irps) = &failure.irps {
        print_power_irp_list(irps, "  ");
    }
    if let Some(workers) = &failure.workers {
        print_power_worker_list(workers, "  ");
    }
    for thread in &finding.threads {
        let role = match thread.role {
            PowerThreadRole::PnpLockOwner => "PnP lock owner".to_string(),
            PowerThreadRole::IrpWorker { irp, .. } if irp.is_zero() => {
                "IRP worker, waiting for work".to_string()
            }
            PowerThreadRole::IrpWorker { irp, device } => format!(
                "IRP worker, IRP {} device {}",
                ui::addr(irp.0),
                ui::addr(device.0)
            ),
        };
        outln!("  thread {}  {}", ui::addr(thread.thread.0), role);
        match &thread.stack {
            Ok(trace) => print_stacktrace_data(trace, POWER_THREAD_STACK_LIMIT, false),
            Err(error) => outln!("  {}", ui::muted(&format!("stack unavailable: {error}"))),
        }
    }
    for note in &failure.notes {
        outln!("  {}", ui::muted(note));
    }
}

/// `wtd's In-Flight Recorder log, 1 record`.
pub fn kmdf_log_summary(log: &KmdfLogFinding) -> String {
    format!(
        "{}'s In-Flight Recorder log, {} record{}",
        log.driver,
        log.records,
        if log.records == 1 { "" } else { "s" }
    )
}

fn print_report_modules(report: &TriageReport, verbose: bool) {
    print_section("loaded modules");
    let relevant_count = report
        .modules
        .iter()
        .filter(|module| report.loaded_module_is_relevant(module))
        .count();
    if !verbose && relevant_count == 0 {
        outln!(
            "  {}",
            ui::muted(&format!(
                "{} loaded; none contain a recorded fault or stack address",
                report.modules.len()
            ))
        );
    } else {
        for module in report
            .modules
            .iter()
            .filter(|module| verbose || report.loaded_module_is_relevant(module))
            .take(if verbose {
                ANALYZE_VERBOSE_MODULE_LIMIT
            } else {
                ANALYZE_MODULE_LIMIT
            })
        {
            outln!(
                "  {:<24} {}-{}  {:#x} bytes",
                module.name,
                ui::addr(module.base_address.0),
                ui::addr(module.end_address().0),
                module.size
            );
        }
        if !verbose && relevant_count > ANALYZE_MODULE_LIMIT {
            outln!(
                "  {}",
                ui::muted(&format!(
                    "... {} more address-matched modules",
                    relevant_count - ANALYZE_MODULE_LIMIT
                ))
            );
        }
        outln!(
            "  {}",
            ui::muted(&format!("{} loaded modules total", report.modules.len()))
        );
    }

    if report.unloaded_drivers.is_empty() {
        return;
    }
    print_section("unloaded modules");
    let relevant_count = report
        .unloaded_drivers
        .iter()
        .filter(|driver| report.unloaded_driver_is_relevant(driver))
        .count();
    if !verbose && relevant_count == 0 {
        outln!("  {}", ui::muted("no relevant unloaded modules"));
        return;
    }
    let mut shown = 0;
    for driver in report
        .unloaded_drivers
        .iter()
        .filter(|driver| verbose || report.unloaded_driver_is_relevant(driver))
        .take(if verbose {
            ANALYZE_VERBOSE_UNLOADED_LIMIT
        } else {
            ANALYZE_UNLOADED_LIMIT
        })
    {
        outln!(
            "  {:<24} {}-{}  {}",
            driver.name,
            ui::addr(driver.start_address),
            ui::addr(driver.end_address),
            ui::muted("recorded address/name match")
        );
        shown += 1;
    }
    if verbose {
        if report.unloaded_drivers.len() > shown {
            outln!(
                "  {}",
                ui::muted(&format!(
                    "... {} more unloaded modules",
                    report.unloaded_drivers.len() - shown
                ))
            );
        }
        return;
    }
    if relevant_count > shown {
        outln!(
            "  {}",
            ui::muted(&format!(
                "... {} more relevant unloaded modules",
                relevant_count - shown
            ))
        );
    }
}

fn print_dump_metadata(report: &TriageReport) {
    if report.system_info.is_none()
        && report.broken_driver.is_none()
        && report.triage_overflowed.is_none()
    {
        return;
    }

    print_section("dump metadata");
    if let Some(info) = &report.system_info {
        let machine = info.machine();
        outln!(
            "  {} Windows {}.{}  {}  service-pack build {}",
            ui::muted("system "),
            info.major_version,
            info.minor_version,
            machine,
            info.service_pack_build
        );
        if info.system_up_time > 0 {
            outln!(
                "  {} {} seconds",
                ui::muted("uptime "),
                info.system_up_time / 10_000_000
            );
        }
        if info.system_time > 0
            && let Some(time) = filetime_to_iso(info.system_time as u64)
        {
            outln!("  {} {}", ui::muted("time   "), time);
        }
        outln!(
            "  {} {}  suite {:#x}",
            ui::muted("product"),
            product_name(info.product_type),
            info.suite_mask
        );
    }
    if let Some(driver) = &report.broken_driver {
        outln!("  {} {}", ui::muted("recorded broken driver"), driver);
    }
    if let Some(overflowed) = report.triage_overflowed {
        outln!(
            "  {} {}",
            ui::muted("triage overflow"),
            if overflowed { "yes" } else { "no" }
        );
    }
}

/// The one-line verdict of a user dump's exception: `exception 0xc0000005 at
/// app!Parse+0x12 on thread 1f40.1a2c: STATUS_ACCESS_VIOLATION`.
pub fn user_exception_verdict(exception: &UserExceptionFinding) -> String {
    format!(
        "exception {:#010x} at {} on thread {}: {}",
        exception.code, exception.symbol, exception.thread, exception.name
    )
}

/// What holds a code address, in words: a module (marked when it is a
/// system one), or why no module does.
pub fn code_owner_text(owner: &CodeOwner) -> String {
    match owner {
        CodeOwner::Module { name, system: true } => format!("{name} (system module)"),
        CodeOwner::Module { name, .. } => name.clone(),
        CodeOwner::DynamicCode {
            table_start,
            table_end,
        } => format!(
            "JIT-compiled or generated code in no module (dynamic function table \
             {table_start:#x}-{table_end:#x})"
        ),
        CodeOwner::Unowned {
            region: Some(region),
        } => format!("code in no module ({region})"),
        CodeOwner::Unowned { region: None } => "code in no module".into(),
    }
}

/// What a culprit attribution names: a module, or `JIT-compiled code at
/// 0x7ff89b6c6a48 (dynamic function table 0x7ff89b6c0020-0x7ff89b740000, no
/// module)`.
pub fn culprit_label(culprit: &CulpritAttribution) -> String {
    match &culprit.subject {
        CulpritSubject::Module(module) => module.clone(),
        CulpritSubject::DynamicCode(code) => format!(
            "JIT-compiled code at {:#x} (dynamic function table {:#x}-{:#x}, no module)",
            code.address, code.table_start, code.table_end
        ),
    }
}

/// For a culprit in generated code, the module code that called into it:
/// `called from #4 system.core.ni+0x5ecdfa (System.Core.ni.dll)`.
pub fn culprit_caller_text(culprit: &CulpritAttribution) -> Option<String> {
    let CulpritSubject::DynamicCode(code) = &culprit.subject else {
        return None;
    };
    Some(match &code.caller {
        Some(caller) => match &caller.owner {
            CodeOwner::Module { name, .. } => {
                format!("called from #{} {} ({name})", caller.index, caller.symbol)
            }
            _ => format!("called from #{} {}", caller.index, caller.symbol),
        },
        None => "called from no frame a module holds".into(),
    })
}

/// `exception context of thread 10f4.cc4 (Main)`, the heading of a user
/// dump report's stack.
pub fn user_stack_heading(thread: &UserStackThread) -> String {
    let context = match thread.source {
        UserStackSource::ExceptionContext => "exception context of thread",
        UserStackSource::ThreadContext => "thread",
    };
    match &thread.name {
        Some(name) => format!("{context} {} ({name})", thread.id),
        None => format!("{context} {}", thread.id),
    }
}

/// `Windows 10.0.26200 AMD64 (26100.1.amd64fre...)`.
pub fn user_system_text(process: &UserProcessSummary) -> String {
    let mut text = format!(
        "Windows {}.{}.{} {}",
        process.major_version,
        process.minor_version,
        process.build_number,
        process.arch.label()
    );
    if let Some(build) = &process.build_string {
        text.push_str(&format!(" ({build})"));
    }
    text
}

/// `20 threads, 91 modules, 3 unloaded modules, 512 handles`.
pub fn user_captured_text(process: &UserProcessSummary) -> String {
    let mut text = format!(
        "{} threads, {} modules, {} unloaded modules",
        process.threads, process.modules, process.unloaded_modules
    );
    match process.handles {
        Some(handles) => text.push_str(&format!(", {handles} handles")),
        None => text.push_str(", no handle data"),
    }
    text
}

/// `powershell.exe (pid 4340)`.
pub fn user_process_label(process: &UserProcessSummary) -> String {
    let name = process.name.as_deref().unwrap_or("unknown process");
    match process.pid {
        Some(pid) => format!("{name} (pid {pid})"),
        None => name.to_string(),
    }
}

/// What `-v` leaves out of a user dump report, because a user dump has no
/// kernel to read it from.
pub const USER_DUMP_NOT_APPLICABLE: &str = "not in a user-mode minidump: bugcheck, trap frame, processor, verifier, WHEA, power, blackbox, and KMDF findings (they need a kernel)";

fn print_user_triage_report(report: &TriageReport, user: &UserDumpTriage, verbose: bool) {
    outln!("{}", ui::label("crash analysis"));
    match &user.exception {
        Some(exception) => print_user_exception(report, exception, verbose),
        None => outln!(
            "{}",
            ui::muted("no exception: the dump records none (it was not written for a crash)")
        ),
    }

    print_user_process(&user.process);

    if user.exception.is_none() || verbose {
        match &user.stack_thread {
            Some(thread) => print_section(&format!("stack, {}", user_stack_heading(thread))),
            None => print_section("stack"),
        }
        match &report.backtrace {
            Some(trace) => {
                let limit = if verbose {
                    TRIAGE_BACKTRACE_LIMIT
                } else {
                    ANALYZE_STACK_LIMIT
                };
                for (number, frame) in trace.frames.iter().take(limit).enumerate() {
                    outln!(
                        "  {}",
                        format_stack_frame(Some(number), frame, false, false)
                    );
                }
                let hidden = trace.frames.len().saturating_sub(limit) + trace.truncated;
                if hidden > 0 {
                    outln!("  {}", more_frames(hidden));
                }
            }
            None => outln!("  {}", ui::muted("unavailable")),
        }
    }
    if verbose && !user.exception_registers.is_empty() {
        print_section("exception registers");
        for row in user.exception_registers.chunks(3) {
            let cells: Vec<String> = row
                .iter()
                .map(|register| {
                    format!(
                        "{} {}",
                        ui::muted(&format!("{:<6}", register.name)),
                        ui::addr(register.value)
                    )
                })
                .collect();
            outln!("  {}", cells.join("   "));
        }
    }

    if !report.warnings.is_empty() {
        print_section("warnings");
        for warning in &report.warnings {
            outln!("  {}", ui::muted(warning));
        }
    }

    print_crash_intelligence(report);
    if let Some(exception) = &user.exception
        && report.culprit.is_none()
    {
        print_section("culprit attribution");
        outln!("  {}", ui::muted(&user_no_culprit_text(exception)));
    }
    if verbose {
        print_user_module_details(report, user);
    }
    print_report_modules(report, verbose);
    if verbose {
        outln!();
        outln!("{}", ui::muted(USER_DUMP_NOT_APPLICABLE));
    }
}

/// Why a user dump report names no culprit.
pub fn user_no_culprit_text(exception: &UserExceptionFinding) -> String {
    match &exception.blamed_frame {
        Some(frame) => format!(
            "none: frame #{} ({:#x}) is the first outside the system modules: {}",
            frame.index,
            frame.ip,
            code_owner_text(&frame.owner)
        ),
        None => "none: every frame of the faulting stack is in a system module".into(),
    }
}

fn print_user_exception(report: &TriageReport, exception: &UserExceptionFinding, verbose: bool) {
    outln!("{}", user_exception_verdict(exception));
    print_section("exception");
    outln!(
        "  {} {:#010x}  {}",
        ui::muted("code   "),
        exception.code,
        exception.name
    );
    let flags = if exception.flag_names.is_empty() {
        String::new()
    } else {
        format!("  {}", exception.flag_names.join(" | "))
    };
    outln!("  {} {:#x}{flags}", ui::muted("flags  "), exception.flags);
    outln!(
        "  {} {}  {}",
        ui::muted("address"),
        ui::addr(exception.address),
        ui::symbol(&exception.symbol)
    );
    outln!(
        "  {} {}",
        ui::muted("module "),
        code_owner_text(&exception.address_owner)
    );
    let thread_name = exception
        .thread_name
        .as_deref()
        .map(|name| format!(" ({name})"))
        .unwrap_or_default();
    outln!(
        "  {} {}{thread_name}",
        ui::muted("thread "),
        ui::thread_id(&exception.thread)
    );
    if let Some(summary) = &exception.summary {
        outln!("  {} {}", ui::muted("meaning"), summary);
    }
    if exception.parameters.is_empty() {
        outln!("  {} {}", ui::muted("params "), ui::muted("none"));
    }
    for (index, parameter) in exception.parameters.iter().enumerate() {
        let label = parameter
            .label
            .map(|label| format!("  {label}"))
            .unwrap_or_default();
        let meaning = parameter
            .meaning
            .as_deref()
            .map(|meaning| format!(": {meaning}"))
            .unwrap_or_default();
        outln!(
            "  {} {}{label}{meaning}",
            ui::muted(&format!("param {}", index + 1)),
            ui::addr(parameter.value)
        );
    }
    if exception.record != 0 {
        outln!(
            "  {} {}  {}",
            ui::muted("chained"),
            ui::addr(exception.record),
            ui::muted("(.exr reads it)")
        );
    }

    if verbose {
        return;
    }
    // The frames from the fault to the code it is blamed on; -v shows the
    // whole stack instead.
    let Some(trace) = &report.backtrace else {
        return;
    };
    print_section("faulting frames");
    let start = exception.faulting_frame.unwrap_or(0);
    let end = exception
        .blamed_frame
        .as_ref()
        .map_or(start, |frame| frame.index);
    for (index, frame) in trace.frames.iter().enumerate().take(end + 1).skip(start) {
        let source = if frame.source == FrameSource::Scan {
            format!("  {}", ui::muted("[scan]"))
        } else {
            String::new()
        };
        outln!(
            "  #{index:<2} {}  {}{source}",
            ui::addr(frame.ip),
            ui::symbol(&frame.symbol)
        );
    }
    match &exception.blamed_frame {
        Some(frame) => outln!(
            "  {}",
            ui::muted(&format!(
                "#{} is the first frame outside the system modules: {}",
                frame.index,
                code_owner_text(&frame.owner)
            ))
        ),
        None => outln!(
            "  {}",
            ui::muted("every frame of the stack is in a system module")
        ),
    }
}

fn print_user_process(process: &UserProcessSummary) {
    print_section("process");
    outln!(
        "  {} {}",
        ui::muted("process "),
        user_process_label(process)
    );
    outln!("  {} {}", ui::muted("system  "), user_system_text(process));
    if let Some(time) = unix_time_to_iso(u64::from(process.dump_time)) {
        outln!("  {} {}", ui::muted("written "), time);
    }
    if let Some(time) = process
        .create_time
        .and_then(|time| unix_time_to_iso(u64::from(time)))
    {
        outln!("  {} {}", ui::muted("created "), time);
    }
    if let Some((user, kernel)) = process.cpu_times {
        outln!(
            "  {} {user} s user, {kernel} s kernel",
            ui::muted("cpu time")
        );
    }
    outln!(
        "  {} {}",
        ui::muted("captured"),
        user_captured_text(process)
    );
}

/// The modules whose details `-v` shows on a user dump: the faulting
/// module, then the culprit's when it is another (for a culprit in
/// generated code, the module that called into it).
pub fn user_detail_modules<'a>(
    report: &'a TriageReport,
    user: &UserDumpTriage,
) -> Vec<&'a ModuleInfo> {
    let mut names: Vec<&str> = Vec::new();
    if let Some(CodeOwner::Module { name, .. }) = user
        .exception
        .as_ref()
        .map(|exception| &exception.address_owner)
    {
        names.push(name);
    }
    let culprit_modules = report.culprit.iter().flat_map(|culprit| {
        let caller = match &culprit.subject {
            CulpritSubject::DynamicCode(code) => {
                code.caller.as_ref().and_then(|caller| match &caller.owner {
                    CodeOwner::Module { name, .. } => Some(name.as_str()),
                    _ => None,
                })
            }
            CulpritSubject::Module(_) => None,
        };
        culprit.module().into_iter().chain(caller)
    });
    for name in culprit_modules {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
        .iter()
        .filter_map(|name| report.modules.iter().find(|module| module.name == *name))
        .collect()
}

/// The details of the faulting module and the culprit's (`-v`): path,
/// version, timestamp, checksum, and PDB.
fn print_user_module_details(report: &TriageReport, user: &UserDumpTriage) {
    for module in user_detail_modules(report, user) {
        print_section(&format!("module {}", module.name));
        outln!(
            "  {} {}-{}",
            ui::muted("range   "),
            ui::addr(module.base_address.0),
            ui::addr(module.end_address().0)
        );
        if let Some(path) = &module.path {
            outln!("  {} {}", ui::muted("path    "), path);
        }
        if let Some(version) = &module.file_version {
            outln!("  {} {}", ui::muted("version "), version);
        }
        if let Some(stamp) = module.time_date_stamp {
            outln!("  {} {stamp:#x}", ui::muted("time    "));
        }
        if let Some(checksum) = module.checksum {
            outln!("  {} {checksum:#x}", ui::muted("checksum"));
        }
        if let Some(pdb) = module.codeview.as_ref().map(codeview_path) {
            outln!("  {} {}", ui::muted("pdb     "), pdb);
        }
    }
}

/// The PDB path a CodeView record names.
pub fn codeview_path(codeview: &CodeView) -> &str {
    match codeview {
        CodeView::Rsds { path, .. } | CodeView::Nb10 { path, .. } => path,
    }
}

/// Show the bugcheck code and its four parameters.
///
/// Uses the bugcheck that the stop reported. If there is none, it uses the
/// bugcheck in nt!KiBugCheckData, as $bug_code and $bug_param1-4 do, and if
/// there is none there, the bugcheck in the crash dump header. !analyze uses
/// the same order.
#[command(
    names = [".bugcheck"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn bugcheck(session: &Session) -> Result<Option<BugcheckAnalysis>> {
    Ok(session.bugcheck())
}

impl Render for Option<BugcheckAnalysis> {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let Some(analysis) = self else {
            outln!(
                "{}\n",
                ui::muted("no bugcheck: the target has not bugchecked")
            );
            return;
        };
        outln!("Bugcheck code {:08x} ({})", analysis.code, analysis.name);
        let arguments: Vec<String> = analysis
            .args
            .iter()
            .map(|arg| ui::addr(arg.value))
            .collect();
        outln!("Arguments {}", arguments.join(" "));
        if let Some(source) = &analysis.source {
            outln!("{}", ui::muted(&format!("from {source}")));
        }
        outln!();
    }
}

/// Show a first-pass crash triage report.
///
/// Without -v, the command shows the short verdict: the bugcheck line, the
/// failure signature, the culprit, the verifier and WHEA findings, and the
/// relevant modules. -v adds the full bugcheck arguments, the faulting
/// context, the stack, and all modules. For a DRIVER_POWER_STATE_FAILURE
/// (0x9F), the report names what is stuck: for subtype 0x3, the blocked IRP,
/// the driver whose stack location it is pending in, which becomes the
/// culprit, the device stack of the PDO, and the power IRP worker threads with
/// their stacks; for 0x4, the thread that holds the PnP lock and its stack;
/// for 0x1, 0x2, and 0x500, the driver of the device or driver object in the
/// parameters. -show decodes a bugcheck code when there is no crash, and for a
/// 0x9F reads what its parameters point to in the target. -hang triages the
/// waits on each processor. On a user-mode minidump, the report is the
/// exception the dump was written for: its code, flags, and decoded
/// parameters, the faulting thread and module, the stack from the exception's
/// context, and the first frame outside the system modules (ntdll, kernelbase,
/// the C++ and .NET runtimes), which the signature and the culprit name; -v
/// adds the whole stack, the exception's registers, the faulting and culprit
/// modules' details, and all modules. -show and -hang need a kernel.
#[command(
    names = ["!analyze", "analyze"],
    category = "analysis",
    kind = Query,
    target = Nt,
    forms = [triage, hang, decode_bugcheck],
)]
fn analyze(
    session: &mut Session,
    #[arg(parse = analyze_options)] options: AnalyzeOptions,
    #[arg(invoked)] name: &str,
) -> Result<Analysis> {
    // -show and -hang read kernel structures; the report itself does not.
    let kernel_option = if options.show.is_some() {
        Some("-show")
    } else {
        options.hang.then_some("-hang")
    };
    if let Some(option) = kernel_option {
        session
            .target
            .require_kernel()
            .map_err(|error| Error::DebugInfo(format!("{name} {option}: {error}")))?;
    }
    let show = options
        .show
        .map(|info| decode_bugcheck(session, info.code, info.parameters.to_vec()));
    let body = if options.hang {
        Some(AnalysisBody::Hang(hang(session)?))
    } else if show.is_none() || options.verbose {
        Some(AnalysisBody::Report(triage(session)?))
    } else {
        None
    };
    Ok(Analysis {
        show: show.transpose()?,
        body,
        verbose: options.verbose,
    })
}

/// Make the structured one-shot crash and debug report (`!analyze`).
#[command(form_of = analyze, python = Inspect)]
fn triage(session: &mut Session) -> Result<TriageReport> {
    Ok(TriageReport::build(session))
}

/// Find what a hung system is doing (`!analyze -hang`): the thread on each
/// processor with its stack, and the waiting threads with the most pending
/// IRPs. The target must be a kernel.
#[command(form_of = analyze, python = Inspect, target = Kernel)]
fn hang(session: &mut Session) -> Result<HangReport> {
    Ok(gather_hang_report(session))
}

/// Decode a bugcheck code and its parameters as if the target had stopped
/// with it (`!analyze -show`), and for a DRIVER_POWER_STATE_FAILURE (0x9F),
/// read what its parameters point to. The target must be a kernel.
#[command(form_of = analyze, python = Inspect, target = Kernel)]
fn decode_bugcheck(
    session: &mut Session,
    code: u32,
    #[arg(sdk, default = Vec::new(), positional)] parameters: Vec<u64>,
) -> Result<BugcheckDecoding> {
    let mut slots = [0u64; 4];
    for (slot, value) in slots.iter_mut().zip(&parameters) {
        *slot = *value;
    }
    let info = BugcheckInfo {
        code,
        parameters: slots,
        driver: None,
    };
    Ok(BugcheckDecoding {
        analysis: analyze_bugcheck(&session.target, &info),
        // The structures a 0x9F's parameters point to, read from the target
        // as for a real stop.
        power: power_failure_finding(session, code, &slots),
    })
}

/// What `!analyze` read: the decoded `-show` bugcheck, then the report or
/// the hang analysis.
pub struct Analysis {
    show: Option<BugcheckDecoding>,
    body: Option<AnalysisBody>,
    verbose: bool,
}

enum AnalysisBody {
    Report(TriageReport),
    Hang(HangReport),
}

impl Render for Analysis {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        if let Some(show) = &self.show {
            print_bugcheck_analysis(&show.analysis);
            if let Some(finding) = &show.power {
                print_power_failure(finding);
            }
        }
        match &self.body {
            Some(AnalysisBody::Hang(report)) => {
                print_hang_report(report);
            }
            Some(AnalysisBody::Report(report)) => {
                let verbose = self.verbose;
                print_triage_report(report, verbose);
            }
            None => {}
        }
        outln!();
    }
}
