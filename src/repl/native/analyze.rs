//! `!analyze` as one card: its ring says what failed (an error for a
//! bugcheck, a warning for an exception), the verdict sits open at the top,
//! and the report's other parts follow as sections, the verbose-only detail
//! folded.

use tern_sdk::ui::{self, Column, Section, Span, TableRow, TextAlign, Tone, Truncate, Wrap};
use tern_sdk::{Node, View};

use super::{MUTED, NUMBER, STRONG, SYMBOL, addr, bugcheck, span, stack, symbol};
use crate::repl::StackColumns;
use crate::repl::commands::analyze::{
    ANALYZE_HANG_STACK_LIMIT, ANALYZE_MODULE_LIMIT, ANALYZE_UNLOADED_LIMIT,
    ANALYZE_VERBOSE_MODULE_LIMIT, ANALYZE_VERBOSE_UNLOADED_LIMIT, HangReport, HangThread,
    kmdf_log_summary, machine_name, product_name, signature_source,
};
use crate::repl::commands::power::{duration_text, request_text};
use crate::target::power::power_minor_name;
use crate::target::{ThreadInfo, wait_reason_name};
use crate::triage_report::{
    BlackboxState, POWER_THREAD_STACK_LIMIT, PowerFailureFinding, PowerThreadRole,
    TRIAGE_BACKTRACE_LIMIT, TriageReport, WheaRecordState, exception_code_name,
    time::filetime_to_iso,
};

fn section(title: &str, collapsed: bool) -> Section<()> {
    ui::section()
        .head(title)
        .collapsible(true)
        .collapsed(collapsed)
}

fn note(text: impl Into<String>) -> Node {
    ui::text([span(text, MUTED)]).wrap(Wrap::Word).into()
}

/// The triage report, `!analyze [-v]`.
pub fn triage(report: &TriageReport, verbose: bool) -> View {
    let tone = if report.bugcheck.is_some() {
        Tone::Error
    } else if report.exception.is_some() {
        Tone::Warning
    } else {
        Tone::Neutral
    };
    let mut head = vec![span("crash analysis  ", MUTED)];
    match &report.bugcheck {
        Some(analysis) => head.extend(bugcheck::head(analysis)),
        None => head.push(span("no recorded bugcheck", MUTED)),
    }
    let mut card = ui::card().head(head).tone(tone).role("ntoseye.analyze");

    if let Some(summary) = summary(report) {
        card = card.child(section("summary", false).child(summary));
    }

    if verbose && let Some(analysis) = &report.bugcheck {
        let mut bugcheck_section = section("bugcheck", false);
        for child in bugcheck::details(analysis) {
            bugcheck_section = bugcheck_section.child(child);
        }
        card = card.child(bugcheck_section);
    }

    if let Some(culprit) = &report.culprit
        && !culprit.evidence.is_empty()
    {
        let mut table = ui::table()
            .col(Column::new("kind", "Evidence").priority(3.0))
            .col(Column::new("address", "Address").priority(2.0))
            .col(
                Column::new("detail", "Detail")
                    .grow(1.0)
                    .truncate(Truncate::End)
                    .priority(4.0),
            );
        for (index, evidence) in culprit.evidence.iter().enumerate() {
            table = table.row(
                TableRow::new(index.to_string())
                    .cell("kind", span(format!("{:?}", evidence.kind), MUTED))
                    .cell(
                        "address",
                        evidence.address.map_or_else(|| span("", ""), addr),
                    )
                    .cell("detail", span(&evidence.detail, "")),
            );
        }
        card = card.child(section("culprit evidence", false).child(table));
    }

    if verbose {
        if let Some(exception) = &report.exception {
            let mut kv = ui::kv()
                .item(
                    "code",
                    [
                        span(exception_code_name(exception.code), STRONG),
                        span(" ", ""),
                        span(format!("({:#010x})", exception.code), NUMBER),
                    ],
                )
                .item("address", addr(exception.address))
                .item("flags", span(format!("{:#x}", exception.flags), NUMBER));
            for (index, parameter) in exception.parameters.iter().enumerate() {
                kv = kv.item(format!("param {}", index + 1), addr(*parameter));
            }
            card = card.child(section("exception", false).child(kv));
        }

        card = card.child(faulting_context(report));

        let stack_section = section("stack", false);
        card = card.child(match &report.backtrace {
            Some(trace) => stack_section.child(stack::table(
                trace,
                TRIAGE_BACKTRACE_LIMIT,
                false,
                StackColumns::default(),
            )),
            None if report.status.running => {
                stack_section.child(note("unavailable while target is running"))
            }
            None => stack_section.child(note("unavailable from captured context")),
        });
    }

    if !report.warnings.is_empty() {
        let mut warnings = section("warnings", false);
        for warning in &report.warnings {
            warnings = warnings.child(ui::text([span(warning, "warning")]).wrap(Wrap::Word));
        }
        card = card.child(warnings);
    }

    if let Some(verifier) = &report.verifier {
        let mut kv = ui::kv().item(
            "bugcheck",
            [
                span(&verifier.bugcheck_name, STRONG),
                span(" ", ""),
                span(format!("({:#x})", verifier.bugcheck_code), NUMBER),
            ],
        );
        kv = kv.item(
            "subcode",
            [
                span(format!("{:#x}", verifier.subcode), NUMBER),
                span(format!("  {}", verifier.subcode_description), ""),
            ],
        );
        if let Some(driver) = &verifier.associated_driver {
            kv = kv.item("driver", symbol(driver));
        }
        for address in &verifier.addresses {
            kv = kv.item(address.role.as_str(), addr(address.address));
        }
        for (index, argument) in verifier.arguments.iter().enumerate() {
            kv = kv.item(
                format!("arg{}", index + 1),
                [
                    addr(argument.value),
                    span(format!("  {}", argument.description), MUTED),
                ],
            );
        }
        card = card.child(section("driver verifier", false).child(kv));
    }

    if let Some(whea) = &report.whea {
        let mut whea_section = section("WHEA", false);
        if let Some(address) = whea.record_address {
            whea_section = whea_section.child(ui::kv().item("record", addr(address)));
        }
        match &whea.state {
            WheaRecordState::Decoded(record) => {
                whea_section = whea_section.child(
                    ui::kv()
                        .item("revision", span(format!("{:#x}", record.revision), NUMBER))
                        .item("severity", span(format!("{:#x}", record.severity), NUMBER))
                        .item("length", span(format!("{:#x}", record.length), NUMBER))
                        .item("sections", span(record.sections.len().to_string(), NUMBER)),
                );
                if !record.sections.is_empty() {
                    let mut table = ui::table()
                        .col(
                            Column::new("offset", "Offset")
                                .align(TextAlign::End)
                                .priority(3.0),
                        )
                        .col(
                            Column::new("length", "Length")
                                .align(TextAlign::End)
                                .priority(2.0),
                        )
                        .col(
                            Column::new("severity", "Severity")
                                .align(TextAlign::End)
                                .priority(2.0),
                        )
                        .col(
                            Column::new("type", "Type")
                                .grow(1.0)
                                .truncate(Truncate::End)
                                .priority(4.0),
                        );
                    for section in &record.sections {
                        table = table.row(
                            TableRow::new(section.offset.to_string())
                                .cell("offset", span(format!("+{:#x}", section.offset), NUMBER))
                                .cell("length", span(format!("{:#x}", section.length), NUMBER))
                                .cell("severity", span(format!("{:#x}", section.severity), NUMBER))
                                .cell("type", span(&section.section_type, "")),
                        );
                    }
                    whea_section = whea_section.child(table);
                }
            }
            WheaRecordState::Unavailable { reason } => {
                whea_section = whea_section.child(note(format!("unavailable: {reason}")));
            }
        }
        card = card.child(whea_section);
    }

    if !report.blackboxes.is_empty() {
        let mut table = ui::table()
            .col(
                Column::new("name", "Stream")
                    .grow(1.0)
                    .truncate(Truncate::End)
                    .priority(4.0),
            )
            .col(
                Column::new("size", "Size")
                    .align(TextAlign::End)
                    .priority(2.0),
            )
            .col(Column::new("state", "Holds").grow(2.0).priority(3.0))
            .col(Column::new("command", "Command").priority(1.0));
        for (index, blackbox) in report.blackboxes.iter().enumerate() {
            let (state, style) = match &blackbox.state {
                BlackboxState::Decoded { summary } => (summary.as_str(), ""),
                BlackboxState::Malformed { reason } => (reason.as_str(), MUTED),
                BlackboxState::Absent => ("not in this dump", MUTED),
            };
            table = table.row(
                TableRow::new(index.to_string())
                    .cell("name", span(&blackbox.name, ""))
                    .cell(
                        "size",
                        blackbox.size.map_or_else(
                            || span("", ""),
                            |size| span(format!("{size:#x} bytes"), NUMBER),
                        ),
                    )
                    .cell("state", span(state, style))
                    .cell("command", span(blackbox.command, MUTED)),
            );
        }
        card = card.child(section("blackbox streams", false).child(table));
    }

    if let Some(log) = &report.kmdf_log {
        card = card.child(section("KMDF log", false).child(ui::text([
            span(kmdf_log_summary(log), ""),
            span("  !wdfkd.wdfcrashdump", MUTED),
        ])));
    }

    if let Some(power) = &report.power {
        card = card.child(power_section(power));
    }

    card = card.child(loaded_modules(report, verbose));
    if let Some(unloaded) = unloaded_modules(report, verbose) {
        card = card.child(unloaded);
    }
    if let Some(metadata) = dump_metadata(report) {
        card = card.child(metadata);
    }

    View::new().main([card])
}

/// The verdict: the bugcheck and its driver, the failure signature and the
/// culprit. `None` when the report has none of them.
fn summary(report: &TriageReport) -> Option<Node> {
    let mut kv = ui::kv();
    let mut any = false;
    if let Some(analysis) = &report.bugcheck {
        kv = kv.item("bugcheck", bugcheck::head(analysis));
        if let Some(driver) = &analysis.driver {
            kv = kv.item("driver", symbol(driver));
        }
        any = true;
    }
    if let Some(signature) = &report.failure_signature {
        kv = kv
            .item("failure signature", span(&signature.bucket, STRONG))
            .item(
                "signature source",
                span(signature_source(signature.source), MUTED),
            );
        any = true;
    }
    if let Some(culprit) = &report.culprit {
        let mut value = symbol(&culprit.module);
        value.push(span(
            format!("  {:?} confidence", culprit.confidence).to_ascii_lowercase(),
            MUTED,
        ));
        kv = kv.item("culprit", value);
        any = true;
    }
    any.then(|| kv.into())
}

/// Where the fault happened and in what context (`-v`): the fault's trap
/// frame rather than where the processor stopped, the scope, the crashing
/// process and the processor.
fn faulting_context(report: &TriageReport) -> Section<()> {
    let status = &report.status;
    let mut kv = ui::kv()
        .item(
            "state",
            span(if status.running { "running" } else { "halted" }, ""),
        )
        .item("thread", span(&status.current_thread, "info"));
    let trap = report.bugcheck.as_ref().and_then(|analysis| {
        analysis
            .trap_frames
            .iter()
            .find_map(|trap| Some((trap, trap.frame.as_ref()?)))
    });
    if let Some((trap, frame)) = trap {
        let mut rip = vec![addr(frame.instruction_pointer())];
        if let Some(name) = trap.rip_symbol.as_deref() {
            rip.push(span("  ", ""));
            rip.extend(symbol(name));
        }
        kv = kv.item("rip", rip).item(
            "trap",
            [addr(trap.address), span("  (.trap selects it)", MUTED)],
        );
    } else if let Some(rip) = status.rip {
        let mut value = vec![addr(rip)];
        if let Some(name) = status.symbol.as_deref() {
            value.push(span("  ", ""));
            value.extend(symbol(name));
        }
        kv = kv.item("rip", value);
    }
    if let Some(process) = &status.attached_process {
        kv = kv.item(
            "scope",
            [
                span(&process.name, STRONG),
                span(format!(" (pid {}, eprocess ", process.pid), MUTED),
                addr(process.eprocess_va.0),
                span(")", MUTED),
            ],
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
        kv = kv.item(
            "crash",
            [
                span(process, STRONG),
                span(format!(" (pid {pid}, tid {tid})"), MUTED),
            ],
        );
        if let Some(parent) = context.parent_process_id {
            kv = kv.item("parent", span(parent.to_string(), NUMBER));
        }
        if let Some(status) = context.exit_status {
            kv = kv.item(
                "process exit",
                span(format!("{:#x}", status as u32), NUMBER),
            );
        }
        if let Some(status) = context.thread_exit_status {
            kv = kv.item("thread exit", span(format!("{:#x}", status as u32), NUMBER));
        }
        if let Some(time) = context.create_time
            && let Some(time) = filetime_to_iso(time)
        {
            kv = kv.item("created", span(time, ""));
        }
    }
    if let Some(prcb) = &report.prcb {
        kv = kv.item(
            "processor",
            [
                span(format!("#{}", prcb.processor_number), "info"),
                span(" thread ", MUTED),
                addr(prcb.current_thread),
                span(format!("  {} MHz  {}", prcb.mhz, prcb.vendor_string), ""),
            ],
        );
    }
    let mut context = section("faulting context", true).child(kv);
    if !status.coherent {
        context = context.child(note("target metadata is still being rebuilt after reload"));
    }
    context
}

fn module_table(name_head: &str) -> tern_sdk::ui::Table<()> {
    ui::table()
        .col(
            Column::new("name", name_head)
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(5.0),
        )
        .col(Column::new("start", "Start").priority(3.0))
        .col(Column::new("end", "End").priority(2.0))
}

fn loaded_modules(report: &TriageReport, verbose: bool) -> Section<()> {
    let mut modules = section("loaded modules", true);
    let relevant_count = report
        .modules
        .iter()
        .filter(|module| report.loaded_module_is_relevant(module))
        .count();
    if !verbose && relevant_count == 0 {
        return modules.child(note(format!(
            "{} loaded; none contain a recorded fault or stack address",
            report.modules.len()
        )));
    }
    let mut table = module_table("Module").col(
        Column::new("size", "Size")
            .align(TextAlign::End)
            .priority(1.0),
    );
    for (index, module) in report
        .modules
        .iter()
        .filter(|module| verbose || report.loaded_module_is_relevant(module))
        .take(if verbose {
            ANALYZE_VERBOSE_MODULE_LIMIT
        } else {
            ANALYZE_MODULE_LIMIT
        })
        .enumerate()
    {
        table = table.row(
            TableRow::new(index.to_string())
                .cell("name", span(&module.name, STRONG))
                .cell("start", addr(module.base_address.0))
                .cell("end", addr(module.end_address().0))
                .cell("size", span(format!("{:#x} bytes", module.size), NUMBER)),
        );
    }
    modules = modules.child(table);
    if !verbose && relevant_count > ANALYZE_MODULE_LIMIT {
        modules = modules.child(note(format!(
            "... {} more address-matched modules",
            relevant_count - ANALYZE_MODULE_LIMIT
        )));
    }
    modules.child(note(format!(
        "{} loaded modules total",
        report.modules.len()
    )))
}

fn unloaded_modules(report: &TriageReport, verbose: bool) -> Option<Section<()>> {
    if report.unloaded_drivers.is_empty() {
        return None;
    }
    let mut unloaded = section("unloaded modules", true);
    let relevant_count = report
        .unloaded_drivers
        .iter()
        .filter(|driver| report.unloaded_driver_is_relevant(driver))
        .count();
    if !verbose && relevant_count == 0 {
        return Some(unloaded.child(note("no relevant unloaded modules")));
    }
    let mut table = module_table("Driver").col(Column::new("match", "").priority(1.0));
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
        table = table.row(
            TableRow::new(shown.to_string())
                .cell("name", span(&driver.name, STRONG))
                .cell("start", addr(driver.start_address))
                .cell("end", addr(driver.end_address))
                .cell("match", span("recorded address/name match", MUTED)),
        );
        shown += 1;
    }
    unloaded = unloaded.child(table);
    if verbose {
        if report.unloaded_drivers.len() > shown {
            unloaded = unloaded.child(note(format!(
                "... {} more unloaded modules",
                report.unloaded_drivers.len() - shown
            )));
        }
    } else if relevant_count > shown {
        unloaded = unloaded.child(note(format!(
            "... {} more relevant unloaded modules",
            relevant_count - shown
        )));
    }
    Some(unloaded)
}

fn dump_metadata(report: &TriageReport) -> Option<Section<()>> {
    if report.system_info.is_none()
        && report.broken_driver.is_none()
        && report.triage_overflowed.is_none()
    {
        return None;
    }
    let mut kv = ui::kv();
    if let Some(info) = &report.system_info {
        kv = kv.item(
            "system",
            [
                span(
                    format!(
                        "Windows {}.{}  {}",
                        info.major_version,
                        info.minor_version,
                        machine_name(info.machine_image_type)
                    ),
                    "",
                ),
                span(
                    format!("  service-pack build {}", info.service_pack_build),
                    MUTED,
                ),
            ],
        );
        if info.system_up_time > 0 {
            kv = kv.item(
                "uptime",
                span(
                    format!("{} seconds", info.system_up_time / 10_000_000),
                    NUMBER,
                ),
            );
        }
        if info.system_time > 0
            && let Some(time) = filetime_to_iso(info.system_time as u64)
        {
            kv = kv.item("time", span(time, ""));
        }
        kv = kv.item(
            "product",
            [
                span(product_name(info.product_type), ""),
                span(format!("  suite {:#x}", info.suite_mask), MUTED),
            ],
        );
    }
    if let Some(driver) = &report.broken_driver {
        kv = kv.item("recorded broken driver", span(driver, "error"));
    }
    if let Some(overflowed) = report.triage_overflowed {
        kv = kv.item(
            "triage overflow",
            span(if overflowed { "yes" } else { "no" }, ""),
        );
    }
    Some(section("dump metadata", true).child(kv))
}

/// `!analyze -hang`: each processor's running thread with its stack, then
/// the waiting threads, most pending I/O first.
pub fn hang(report: &HangReport) -> View {
    let mut card = ui::card()
        .head([span("hang analysis", STRONG)])
        .tone(Tone::Neutral)
        .role("ntoseye.analyze");

    if report.processors.is_empty() {
        card = card.child(note("processor count unavailable"));
    }
    for entry in &report.processors {
        let cpu = span(format!("cpu {}", entry.processor), "info");
        let processor = match &entry.current {
            Ok(HangThread { thread, stack }) => {
                let mut head = vec![cpu, span("  ", "")];
                head.extend(thread_spans(thread));
                head.push(span(
                    format!("  {}", thread.process_name.as_deref().unwrap_or("unknown")),
                    STRONG,
                ));
                let processor = ui::section().head(head).collapsible(true);
                match stack {
                    Ok(trace) => processor.child(stack::table(
                        trace,
                        ANALYZE_HANG_STACK_LIMIT,
                        false,
                        StackColumns::default(),
                    )),
                    Err(error) => processor.child(note(format!("stack unavailable: {error}"))),
                }
            }
            Err(error) => ui::section()
                .head([
                    cpu,
                    span(format!("  current thread unavailable: {error}"), MUTED),
                ])
                .collapsible(true),
        };
        card = card.child(processor);
    }

    let waiting = section("waiting threads by pending I/O", false);
    card = card.child(match &report.waiting {
        Ok(threads) => {
            let mut table = ui::table()
                .col(Column::new("ethread", "ETHREAD").priority(3.0))
                .col(
                    Column::new("tid", "TID")
                        .align(TextAlign::End)
                        .priority(4.0),
                )
                .col(
                    Column::new("pid", "PID")
                        .align(TextAlign::End)
                        .priority(4.0),
                )
                .col(
                    Column::new("wait", "Wait reason")
                        .grow(1.0)
                        .truncate(Truncate::End)
                        .priority(5.0),
                )
                .col(
                    Column::new("irps", "IRPs")
                        .align(TextAlign::End)
                        .priority(5.0),
                );
            for thread in threads {
                let reason = thread.wait_reason.unwrap_or(0);
                table = table.row(
                    TableRow::new(format!("{:x}", thread.ethread.0))
                        .cell("ethread", addr(thread.ethread.0))
                        .cell("tid", span(optional(thread.tid), NUMBER))
                        .cell("pid", span(optional(thread.pid), NUMBER))
                        .cell(
                            "wait",
                            [
                                span(format!("{reason} "), NUMBER),
                                span(format!("({})", wait_reason_name(reason)), ""),
                            ],
                        )
                        .cell(
                            "irps",
                            span(
                                thread.pending_irps.as_ref().map_or(0, Vec::len).to_string(),
                                NUMBER,
                            ),
                        ),
                );
            }
            waiting.child(table)
        }
        Err(error) => waiting.child(note(format!("thread list unavailable: {error}"))),
    });

    View::new().main([card])
}

/// `ffff…  tid 4 pid 4`.
fn thread_spans(thread: &ThreadInfo) -> Vec<Span> {
    vec![
        addr(thread.ethread.0),
        span("  tid ", MUTED),
        span(optional(thread.tid), NUMBER),
        span(" pid ", MUTED),
        span(optional(thread.pid), NUMBER),
    ]
}

fn optional(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".into())
}

/// `!analyze -show 9f ...`: what the parameters of a 0x9F point to.
pub fn power_failure(finding: &PowerFailureFinding) -> View {
    let card = ui::card()
        .head([span("DRIVER_POWER_STATE_FAILURE", STRONG)])
        .tone(Tone::Error)
        .role("ntoseye.analyze")
        .child(power_section(finding));
    View::new().main([card])
}

/// What a DRIVER_POWER_STATE_FAILURE names as stuck, and the threads
/// involved with their stacks.
fn power_section(finding: &PowerFailureFinding) -> Section<()> {
    let failure = &finding.failure;
    let mut kv = ui::kv().item(
        "subtype",
        [
            span(format!("{:#x}", failure.subtype), NUMBER),
            span(format!("  {}", failure.description), ""),
        ],
    );
    if let Some(culprit) = &failure.culprit {
        kv = kv.item(
            "driver",
            [
                span(culprit.driver.label(), SYMBOL),
                span(format!("  {}", culprit.reason), ""),
            ],
        );
    }
    let holder_device = failure
        .blocked_irp
        .as_ref()
        .and_then(|blocked| blocked.holder.as_ref().ok())
        .map(|holder| holder.device);
    if let Some(blocked) = &failure.blocked_irp {
        kv = kv.item("blocked IRP", addr(blocked.irp.0));
        match &blocked.holder {
            Ok(holder) => {
                kv = kv.item(
                    "request",
                    span(
                        request_text(
                            holder.major_function,
                            holder.minor_function,
                            holder.state.as_ref(),
                        ),
                        "",
                    ),
                );
                let driver = match &holder.driver {
                    Ok(driver) => span(driver.label(), SYMBOL),
                    Err(error) => span(format!("driver unreadable: {error}"), MUTED),
                };
                kv = kv.item(
                    "pending in",
                    [
                        driver,
                        span("  device ", MUTED),
                        addr(holder.device.0),
                        span(
                            format!(
                                "  stack location {} of {}",
                                holder.location, holder.stack_count
                            ),
                            "",
                        ),
                    ],
                );
            }
            Err(error) => kv = kv.item("pending in", span(format!("unknown: {error}"), MUTED)),
        }
        if let Some(data) = &blocked.data {
            let pending = data.pending.map_or_else(
                || format!("watchdog {}", data.watchdog.label()),
                |pending| format!("{} since the watchdog was armed", duration_text(pending)),
            );
            kv = kv.item("pending for", span(pending, ""));
        }
    }
    if let Some(device) = failure.device {
        kv = kv.item("device", addr(device.0));
    }
    if let Some(seconds) = failure.timeout_seconds {
        kv = kv.item("timeout", span(format!("{seconds} s"), NUMBER));
    }
    if let Some(owner) = failure.pnp_lock_owner {
        kv = kv.item(
            "PnP lock",
            [addr(owner.0), span("  thread holding it", MUTED)],
        );
    }
    let mut power = section("power failure", false).child(kv);

    match &failure.stack {
        Some(Ok(stack)) => {
            let mut table = ui::table()
                .col(Column::new("device", "Device").priority(4.0))
                .col(Column::new("driver", "Driver").priority(3.0))
                .col(
                    Column::new("name", "Name")
                        .grow(1.0)
                        .truncate(Truncate::End)
                        .priority(2.0),
                )
                .col(Column::new("holds", "").priority(1.0));
            for entry in &stack.entries {
                let holds = Some(entry.device_object) == holder_device;
                table = table.row(
                    TableRow::new(entry.device_object.0.to_string())
                        .cell("device", addr(entry.device_object.0))
                        .cell("driver", span(&entry.driver_name, SYMBOL))
                        .cell("name", span(&entry.object_name, ""))
                        .cell(
                            "holds",
                            span(if holds { "holds the IRP" } else { "" }, STRONG),
                        ),
                );
            }
            power = power.child(table);
        }
        Some(Err(error)) => power = power.child(note(format!("device stack unavailable: {error}"))),
        None => {}
    }

    if let Some(irps) = &failure.irps
        && !irps.entries.is_empty()
    {
        let mut table = ui::table()
            .col(Column::new("irp", "IRP").priority(4.0))
            .col(Column::new("request", "Request").priority(3.0))
            .col(Column::new("pdo", "PDO").priority(2.0))
            .col(
                Column::new("holder", "Pending in")
                    .grow(1.0)
                    .truncate(Truncate::End)
                    .priority(3.0),
            );
        for entry in &irps.entries {
            let row = TableRow::new(entry.data.0.to_string());
            table = table.row(match &entry.irp {
                Ok(irp) => row
                    .cell("irp", addr(irp.irp.0))
                    .cell(
                        "request",
                        span(
                            format!(
                                "{} {}",
                                power_minor_name(irp.minor_function).unwrap_or("?"),
                                irp.state.label()
                            ),
                            "",
                        ),
                    )
                    .cell("pdo", addr(irp.pdo.0))
                    .cell(
                        "holder",
                        match &irp.holder {
                            Ok(holder) => span(
                                holder
                                    .driver
                                    .as_ref()
                                    .map_or_else(|error| error.clone(), |driver| driver.label()),
                                SYMBOL,
                            ),
                            Err(error) => span(error, MUTED),
                        },
                    ),
                Err(error) => row
                    .cell("irp", addr(entry.data.0))
                    .cell("holder", span(error, MUTED)),
            });
        }
        power = power.child(table);
    }

    if let Some(workers) = &failure.workers {
        let mut table = ui::table()
            .col(Column::new("thread", "Worker thread").priority(4.0))
            .col(Column::new("kind", "Kind").priority(2.0))
            .col(Column::new("irp", "IRP").priority(3.0))
            .col(
                Column::new("device", "Device")
                    .grow(1.0)
                    .truncate(Truncate::End)
                    .priority(3.0),
            );
        for entry in &workers.entries {
            let row = TableRow::new(entry.entry.0.to_string());
            table = table.row(match &entry.worker {
                Ok(worker) => row
                    .cell("thread", addr(worker.thread.0))
                    .cell(
                        "kind",
                        span(
                            if worker.is_static {
                                "static"
                            } else {
                                "dynamic"
                            },
                            MUTED,
                        ),
                    )
                    .cell(
                        "irp",
                        if worker.irp.is_zero() {
                            span("waiting", MUTED)
                        } else {
                            addr(worker.irp.0)
                        },
                    )
                    .cell(
                        "device",
                        span(worker.driver.clone().unwrap_or_default(), SYMBOL),
                    ),
                Err(error) => row
                    .cell("thread", addr(entry.entry.0))
                    .cell("device", span(error, MUTED)),
            });
        }
        power = power.child(table);
    }

    for thread in &finding.threads {
        let role = match thread.role {
            PowerThreadRole::PnpLockOwner => "  holds the PnP lock".to_string(),
            PowerThreadRole::IrpWorker { irp, .. } if irp.is_zero() => {
                "  IRP worker, waiting for work".to_string()
            }
            PowerThreadRole::IrpWorker { irp, device } => {
                format!("  IRP worker, IRP {:016x} device {:016x}", irp.0, device.0)
            }
        };
        power = power.child(ui::text([
            span("thread ", MUTED),
            addr(thread.thread.0),
            span(role, ""),
        ]));
        power = match &thread.stack {
            Ok(trace) => power.child(stack::table(
                trace,
                POWER_THREAD_STACK_LIMIT,
                false,
                StackColumns::default(),
            )),
            Err(error) => power.child(note(format!("stack unavailable: {error}"))),
        };
    }
    for text in &failure.notes {
        power = power.child(note(text.clone()));
    }
    power
}
