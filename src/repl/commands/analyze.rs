use crate::bugchecks::BugcheckAnalysis;
use crate::cpu_state;
use crate::dbg_backend::BugcheckInfo;
use crate::error::{Error, Result};
use crate::expr::{Expr, NumberRadix};
use crate::target::{Target, ThreadInfo, wait_reason_name};
use crate::triage_report::{
    BlackboxState, FailureSignatureSource, KmdfLogFinding, TRIAGE_BACKTRACE_LIMIT, TriageReport,
    WheaRecordState, exception_code_name, time::filetime_to_iso,
};
use crate::ui;
use crate::unwind::StackTrace;

use crate::repl::*;

repl_command! {
    cmd_analyze;
    names: ["!analyze", "analyze"],
    usage: "!analyze [-v] [-show <bugcheck-code> [p1 p2 p3 p4]] [-hang]",
    summary: "Show a first-pass crash triage report.",
    details: "Without -v, the command shows the short verdict: the bugcheck line, the failure signature, the culprit, the verifier and WHEA findings, and the relevant modules. -v adds the full bugcheck arguments, the faulting context, the stack, and all modules. -show decodes a bugcheck code when there is no crash, and -hang triages the waits on each processor.",
    completion: Expression,
}

repl_command! {
    cmd_bugcheck();
    names: [".bugcheck"],
    usage: ".bugcheck",
    summary: "Show the bugcheck code and its four parameters.",
    details: "Uses the bugcheck that the stop reported. If there is none, it uses the bugcheck in nt!KiBugCheckData, as $bug_code and $bug_param1-4 do, and if there is none there, the bugcheck in the crash dump header. !analyze uses the same order.",
}

pub const ANALYZE_STACK_LIMIT: usize = 16;
pub const ANALYZE_MODULE_LIMIT: usize = 16;
pub const ANALYZE_UNLOADED_LIMIT: usize = 12;
pub const ANALYZE_VERBOSE_MODULE_LIMIT: usize = 4096;
pub const ANALYZE_VERBOSE_UNLOADED_LIMIT: usize = 4096;
const ANALYZE_HANG_PROCESSOR_LIMIT: u16 = 256;
const ANALYZE_HANG_THREAD_LIMIT: usize = 32;
/// Frames shown per processor in `!analyze -hang`.
pub const ANALYZE_HANG_STACK_LIMIT: usize = 8;
const KTHREAD_STATE_WAITING: u8 = 5;

/// What `!analyze -hang` found, gathered once for both renderers.
pub struct HangReport {
    /// One entry per processor, in order; empty when the count is unknown.
    pub processors: Vec<HangProcessor>,
    /// The waiting threads, most pending IRPs first, or why there are none.
    pub waiting: std::result::Result<Vec<ThreadInfo>, String>,
}

pub struct HangProcessor {
    pub processor: u16,
    /// The thread running on it, or why it is unknown.
    pub current: std::result::Result<HangThread, String>,
}

pub struct HangThread {
    pub thread: ThreadInfo,
    pub stack: std::result::Result<StackTrace, String>,
}

/// The text `source:` of a failure signature.
pub fn signature_source(source: FailureSignatureSource) -> &'static str {
    match source {
        FailureSignatureSource::BugcheckFault => "bugcheck fault",
        FailureSignatureSource::ExceptionAddress => "exception address",
        FailureSignatureSource::CurrentInstruction => "current instruction",
        FailureSignatureSource::TopFrame => "top frame",
        FailureSignatureSource::CodeOnly => "code only",
    }
}

pub fn machine_name(machine_image_type: u32) -> &'static str {
    match machine_image_type {
        0x014c => "I386",
        0x8664 => "AMD64",
        0xAA64 => "ARM64",
        _ => "Unknown",
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

#[derive(Default)]
struct AnalyzeOptions {
    verbose: bool,
    hang: bool,
    show: Option<BugcheckInfo>,
}

fn parse_analyze_options(
    invocation: &CommandInvocation<'_>,
    target: &Target,
    radix: NumberRadix,
) -> Result<AnalyzeOptions> {
    let mut options = AnalyzeOptions::default();
    let mut index = 0;
    while index < invocation.argv.len() {
        match invocation.arg(index).unwrap_or_default() {
            "-v" | "/v" => options.verbose = true,
            "-hang" | "/hang" => options.hang = true,
            "-show" | "/show" => {
                let code_text = invocation.arg(index + 1).ok_or_else(|| {
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
                    let Some(text) = invocation.arg(index + 2 + slot) else {
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

fn gather_hang_report(state: &mut ReplState<'_>) -> HangReport {
    let processor_count = cpu_state::processor_count(&state.ctx.target)
        .ok()
        .or_else(|| {
            state
                .ctx
                .backend
                .thread_list()
                .ok()
                .map(|threads| threads.len() as u16)
        })
        .unwrap_or(0)
        .min(ANALYZE_HANG_PROCESSOR_LIMIT);
    let vcpus = state.ctx.processor_vcpus();
    let mut processors = Vec::with_capacity(usize::from(processor_count));
    for processor in 0..processor_count {
        let current = match state
            .ctx
            .target
            .current_windows_thread_for_processor(processor)
        {
            Ok(thread) => {
                let vcpu = vcpus.get(&processor).map(String::as_str);
                let stack = state
                    .ctx
                    .backtrace_thread(&thread, vcpu, ANALYZE_HANG_STACK_LIMIT)
                    .map(|trace| trace.stacktrace)
                    .map_err(|error| error.to_string());
                Ok(HangThread { thread, stack })
            }
            Err(error) => Err(error.to_string()),
        };
        processors.push(HangProcessor { processor, current });
    }

    let waiting = state
        .ctx
        .target
        .enumerate_threads()
        .map(|mut threads| {
            threads.retain(|thread| thread.state == Some(KTHREAD_STATE_WAITING));
            threads.sort_by_key(|thread| {
                (
                    std::cmp::Reverse(thread.pending_irps.as_ref().map_or(0, Vec::len)),
                    std::cmp::Reverse(thread.wait_reason.unwrap_or(0)),
                    thread.ethread.0,
                )
            });
            threads.truncate(ANALYZE_HANG_THREAD_LIMIT);
            threads
        })
        .map_err(|error| error.to_string());
    HangReport {
        processors,
        waiting,
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
            ui::muted("thread "),
            ui::thread_id(&report.status.current_thread)
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
                ui::addr(process.eprocess_va.0)
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
        outln!(
            "  {}  {}",
            ui::symbol(&culprit.module),
            ui::muted(&format!("{:?} confidence", culprit.confidence).to_ascii_lowercase())
        );
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
        let machine = machine_name(info.machine_image_type);
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

impl ReplState<'_> {
    fn cmd_bugcheck(&mut self) -> Result<()> {
        let Some(analysis) = self.ctx.bugcheck() else {
            outln!(
                "{}\n",
                ui::muted("no bugcheck: the target has not bugchecked")
            );
            return Ok(());
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
        Ok(())
    }

    fn cmd_analyze(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let options = match parse_analyze_options(&invocation, &self.ctx.target, self.radix) {
            Ok(options) => options,
            Err(error) => {
                outln!("{}\n", command_help(invocation.name));
                error!("{error}");
                return Ok(());
            }
        };
        if let Some(info) = &options.show {
            print_bugcheck_info(&self.ctx.target, info);
            if !options.verbose && !options.hang {
                outln!();
                return Ok(());
            }
        }
        if options.hang {
            let report = gather_hang_report(self);
            #[cfg(feature = "cli")]
            native::render(
                || native::analyze::hang(&report),
                || print_hang_report(&report),
            );
            #[cfg(not(feature = "cli"))]
            print_hang_report(&report);
        } else {
            let report = TriageReport::build(self.ctx);
            #[cfg(feature = "cli")]
            native::render(
                || native::analyze::triage(&report, options.verbose),
                || print_triage_report(&report, options.verbose),
            );
            #[cfg(not(feature = "cli"))]
            print_triage_report(&report, options.verbose);
        }
        outln!();
        Ok(())
    }
}
