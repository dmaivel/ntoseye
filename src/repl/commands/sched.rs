use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::repl::*;
use crate::target::sched::{
    ApcDetail, ApcListDetail, ApcSelector, ReadyQueuesDetail, StackFrameDetail, StacksDetail,
    ThreadSummary, TimerDetail, TimerListDetail,
};
use crate::target::{DiagnosticValue, ListTermination, kthread_state_name, wait_reason_name};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_running;
    names: ["!running", "running"],
    usage: "!running [-i] [-t]",
    summary: "Show the thread running on each processor.",
    details: "-i includes idle threads. -t appends a bounded short kernel stack for each processor.",
    completion: None,
}

repl_command! {
    cmd_ready;
    names: ["!ready", "ready"],
    usage: "!ready [processor]",
    summary: "List bounded dispatcher-ready queues, optionally for one processor.",
    details: "Reads DispatcherReadyListHead (or ReadyListHead on newer builds) from each _KPRCB.",
    completion: Expression,
}

repl_command! {
    cmd_dpcs;
    names: ["!dpcs", "dpcs"],
    usage: "!dpcs",
    summary: "List deferred procedure calls queued on each processor.",
    details: "Walks the two _KPRCB DpcData queues with cycle and entry bounds.",
    completion: None,
}

repl_command! {
    cmd_timer;
    names: ["!timer", "timer"],
    usage: "!timer [address-expression]",
    summary: "List kernel timers or decode one _KTIMER.",
    details: "The list form walks _KPRCB.TimerTable.TimerEntries; the address form decodes one timer and its DPC.",
    completion: Expression,
}

repl_command! {
    cmd_apc;
    names: ["!apc", "apc"],
    usage: "!apc [process|thread]",
    summary: "List kernel and user APCs for the selected thread, process, or all threads.",
    details: "With no argument the current Windows thread is used; * enumerates all threads within a bounded walk.",
    completion: [Expression],
}

repl_command! {
    cmd_stacks;
    names: ["!stacks", "stacks"],
    usage: "!stacks [0|1|2] [filter]",
    summary: "Show every thread's state, wait reason, and top stack symbol.",
    details: "Level 0 shows one frame; levels 1 and 2 append bounded full stacks. The optional filter matches process or stack symbols.",
    completion: [None, Process],
}

fn diagnostic_cell<T: std::fmt::Display>(value: &DiagnosticValue<T>) -> String {
    match value {
        DiagnosticValue::Available(value) => value.to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn diagnostic_address_cell(value: &DiagnosticValue<VirtAddr>) -> String {
    match value {
        DiagnosticValue::Available(address) => ui::addr(address.0).to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn diagnostic_option_cell<T>(
    value: &DiagnosticValue<Option<T>>,
    render: impl FnOnce(&T) -> String,
    none: &str,
) -> String {
    match value {
        DiagnosticValue::Available(Some(value)) => render(value),
        DiagnosticValue::Available(None) => none.to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn thread_tid(thread: &ThreadSummary) -> String {
    diagnostic_option_cell(
        &thread.tid,
        |tid| tid.to_string(),
        &ui::addr(thread.ethread.0).to_string(),
    )
}

fn thread_pid(thread: &ThreadSummary) -> String {
    diagnostic_option_cell(&thread.pid, |pid| pid.to_string(), "<unavailable>")
}

fn thread_process(thread: &ThreadSummary) -> String {
    diagnostic_option_cell(&thread.process_name, |name| name.clone(), "<unknown>")
}

fn thread_priority(thread: &ThreadSummary) -> String {
    diagnostic_option_cell(
        &thread.priority,
        |priority| priority.to_string(),
        "<unavailable>",
    )
}

fn thread_state(thread: &ThreadSummary) -> String {
    diagnostic_option_cell(
        &thread.state,
        |state| format!("{} ({state})", kthread_state_name(*state)),
        "<unavailable>",
    )
}

fn thread_wait_reason(thread: &ThreadSummary) -> String {
    diagnostic_option_cell(
        &thread.wait_reason,
        |reason| format!("{} ({reason})", wait_reason_name(*reason)),
        "<unavailable>",
    )
}

fn running_thread_kthread(value: &DiagnosticValue<Option<ThreadSummary>>) -> String {
    diagnostic_option_cell(value, |thread| ui::addr(thread.kthread.0).to_string(), "-")
}

fn running_thread_detail(value: &DiagnosticValue<Option<ThreadSummary>>) -> String {
    diagnostic_option_cell(
        value,
        |thread| {
            format!(
                "{} {} (pid {})",
                ui::addr(thread.kthread.0),
                thread_process(thread),
                thread_pid(thread)
            )
        },
        "-",
    )
}

fn short_stack_cell(value: Option<&DiagnosticValue<Vec<StackFrameDetail>>>) -> String {
    let Some(value) = value else {
        return "-".to_string();
    };
    match value {
        DiagnosticValue::Available(frames) if frames.is_empty() => "<no frames>".to_string(),
        DiagnosticValue::Available(frames) => frames
            .iter()
            .map(|frame| frame.symbol.as_str())
            .collect::<Vec<_>>()
            .join(" <- "),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn termination_message(termination: &ListTermination) -> Option<String> {
    termination.diagnostic()
}

impl ReplState<'_> {
    fn cmd_running(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut include_idle = false;
        let mut include_stacks = false;
        for argument in &invocation.argv {
            match argument.as_ref() {
                "-i" => include_idle = true,
                "-t" => include_stacks = true,
                other => {
                    outln!("{}\n", command_help("!running"));
                    error!("unknown !running option '{other}'");
                    return Ok(());
                }
            }
        }
        let detail = match self.ctx.inspect_running(include_idle, include_stacks) {
            Ok(detail) => detail,
            Err(error) => {
                error!("failed to inspect running threads: {error}");
                return Ok(());
            }
        };
        if detail.processors.is_empty() {
            outln!("no non-idle running threads\n");
            return Ok(());
        }
        let mut builder = tabled::builder::Builder::default();
        builder.push_record([
            "CPU", "KPCR", "KPRCB", "KTHREAD", "TID", "Process", "Priority", "Next", "Idle",
            "Stack",
        ]);
        for processor in &detail.processors {
            let current = match &processor.current_thread {
                DiagnosticValue::Available(Some(thread)) => thread,
                _ => {
                    builder.push_record([
                        processor.index.to_string(),
                        diagnostic_address_cell(&processor.kpcr),
                        diagnostic_address_cell(&processor.prcb),
                        running_thread_kthread(&processor.current_thread),
                        "-".to_string(),
                        "<unavailable>".to_string(),
                        "<unavailable>".to_string(),
                        running_thread_detail(&processor.next_thread),
                        running_thread_detail(&processor.idle_thread),
                        short_stack_cell(processor.short_stack.as_ref()),
                    ]);
                    continue;
                }
            };
            builder.push_record([
                processor.index.to_string(),
                diagnostic_address_cell(&processor.kpcr),
                diagnostic_address_cell(&processor.prcb),
                ui::addr(current.kthread.0).to_string(),
                thread_tid(current),
                thread_process(current),
                thread_priority(current),
                running_thread_detail(&processor.next_thread),
                running_thread_detail(&processor.idle_thread),
                short_stack_cell(processor.short_stack.as_ref()),
            ]);
        }
        print_padded_table(builder);
        Ok(())
    }

    fn cmd_ready(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.is_empty() {
            let detail = match self.ctx.target.inspect_ready_queues(None) {
                Ok(detail) => detail,
                Err(error) => {
                    error!("failed to inspect ready queues: {error}");
                    return Ok(());
                }
            };
            print_ready_queues(&detail);
            return Ok(());
        }
        let processor_text = invocation.join_args(0);
        let processor = match Expr::eval_with_radix(&processor_text, &self.ctx.target, self.radix) {
            Ok(value) => match u16::try_from(value.0) {
                Ok(index) => Some(index),
                Err(_) => {
                    error!("processor index out of range: {:#x}", value.0);
                    return Ok(());
                }
            },
            Err(error) => {
                error!("invalid processor '{processor_text}': {error}");
                return Ok(());
            }
        };
        let detail = match self.ctx.target.inspect_ready_queues(processor) {
            Ok(detail) => detail,
            Err(error) => {
                error!("failed to inspect ready queues: {error}");
                return Ok(());
            }
        };
        print_ready_queues(&detail);
        Ok(())
    }

    fn cmd_dpcs(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help("!dpcs"));
            return Ok(());
        }
        let detail = match self.ctx.target.inspect_dpc_queues() {
            Ok(detail) => detail,
            Err(error) => {
                error!("failed to inspect DPC queues: {error}");
                return Ok(());
            }
        };
        let mut builder = tabled::builder::Builder::default();
        builder.push_record([
            "CPU",
            "Queue",
            "KDPC",
            "DeferredRoutine",
            "Context",
            "Importance",
        ]);
        for queue in &detail.queues {
            for entry in &queue.entries {
                builder.push_record([
                    queue.processor.to_string(),
                    queue.queue.to_string(),
                    ui::addr(entry.address.0).to_string(),
                    routine_cell(&entry.deferred_routine, &entry.deferred_routine_symbol),
                    diagnostic_option_cell(
                        &entry.context,
                        |address| ui::addr(address.0).to_string(),
                        "0x0",
                    ),
                    diagnostic_option_cell(
                        &entry.importance,
                        |value| value.to_string(),
                        "<unavailable: field not present>",
                    ),
                ]);
            }
            if let Some(stop) = termination_message(&queue.termination) {
                outln!(
                    "CPU {} queue {}: list walk stopped: {}",
                    queue.processor,
                    queue.queue,
                    stop
                );
            }
        }
        for error in &detail.errors {
            outln!(
                "CPU {}: <unavailable: {}>",
                error
                    .processor
                    .map_or_else(|| "?".to_string(), |value| value.to_string()),
                error.message
            );
        }
        if detail.total == 0 {
            outln!("DPC queues are empty or unavailable\n");
        } else {
            print_padded_table(builder);
        }
        if detail.truncated {
            outln!("DPC output bounded at 4096 entries\n");
        }
        Ok(())
    }

    fn cmd_timer(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            let expression = invocation.join_args(0);
            let address = match Expr::eval_with_radix(&expression, &self.ctx.target, self.radix) {
                Ok(address) => address,
                Err(error) => {
                    error!("invalid timer address '{expression}': {error}");
                    return Ok(());
                }
            };
            let detail = match self.ctx.target.inspect_timer(address) {
                Ok(detail) => detail,
                Err(error) => {
                    error!("failed to inspect timer {}: {error}", ui::addr(address.0));
                    return Ok(());
                }
            };
            print_timer_detail(&detail);
            return Ok(());
        }
        let detail = match self.ctx.target.timer_list() {
            Ok(detail) => detail,
            Err(error) => {
                error!("failed to enumerate timers: {error}");
                return Ok(());
            }
        };
        print_timer_list(&detail);
        Ok(())
    }

    fn cmd_apc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let argument = (!invocation.argv.is_empty()).then(|| invocation.join_args(0));
        let selector = match self.parse_apc_selector(argument.as_deref()) {
            Ok(selector) => selector,
            Err(error) => {
                error!("failed to select APC threads: {error}");
                return Ok(());
            }
        };
        let detail = match self.ctx.inspect_apcs(selector) {
            Ok(detail) => detail,
            Err(error) => {
                error!("failed to inspect APCs: {error}");
                return Ok(());
            }
        };
        print_apcs(&detail);
        Ok(())
    }

    fn parse_apc_selector(&self, argument: Option<&str>) -> Result<ApcSelector> {
        let Some(argument) = argument else {
            return Ok(ApcSelector::CurrentThread);
        };
        if argument == "." {
            return Ok(ApcSelector::CurrentThread);
        }
        if argument == "*" {
            return Ok(ApcSelector::All);
        }
        let value =
            Expr::eval_with_radix(argument, &self.ctx.target, self.radix).map(|value| value.0);
        if let Ok(value) = value {
            let threads = self.ctx.target.enumerate_threads().unwrap_or_default();
            if threads.iter().any(|thread| {
                thread.ethread.0 == value || thread.kthread.0 == value || thread.tid == Some(value)
            }) {
                return Ok(ApcSelector::Thread(VirtAddr(value)));
            }
            if threads.iter().any(|thread| {
                thread.pid == Some(value)
                    || thread.eprocess.is_some_and(|address| address.0 == value)
            }) {
                return Ok(ApcSelector::Process(value));
            }
            return Ok(ApcSelector::Process(value));
        }
        let needle = argument.to_ascii_lowercase();
        let processes = self.ctx.target.guest()?.enumerate_processes()?;
        let process = processes
            .iter()
            .find(|process| process.name.to_ascii_lowercase().contains(&needle))
            .ok_or_else(|| {
                Error::DebugInfo(format!("no process or thread matches '{argument}'"))
            })?;
        Ok(ApcSelector::Process(process.pid))
    }

    fn cmd_stacks(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (level, filter_start) = match invocation.arg(0) {
            None => (0, 0),
            Some("0") => (0, 1),
            Some("1") => (1, 1),
            Some("2") => (2, 1),
            Some(_) => (0, 0),
        };
        let filter =
            (invocation.argv.len() > filter_start).then(|| invocation.join_args(filter_start));
        let detail = match self.ctx.inspect_stacks(level, filter.as_deref()) {
            Ok(detail) => detail,
            Err(error) => {
                error!("failed to inspect thread stacks: {error}");
                return Ok(());
            }
        };
        print_stacks(&detail);
        Ok(())
    }
}

fn print_ready_queues(detail: &ReadyQueuesDetail) {
    let mut builder = tabled::builder::Builder::default();
    builder.push_record([
        "CPU",
        "Priority",
        "KTHREAD",
        "TID",
        "Process",
        "ThreadPriority",
        "State",
    ]);
    for queue in &detail.queues {
        for entry in &queue.entries {
            let (tid, process, priority, state) = match &entry.thread {
                DiagnosticValue::Available(Some(thread)) => (
                    thread_tid(thread),
                    thread_process(thread),
                    thread_priority(thread),
                    thread_state(thread),
                ),
                DiagnosticValue::Available(None) => (
                    "<unavailable>".to_string(),
                    "<unavailable>".to_string(),
                    "<unavailable>".to_string(),
                    "<unavailable>".to_string(),
                ),
                DiagnosticValue::Unavailable(error) => (
                    "<unavailable>".to_string(),
                    format!("<unavailable: {error}>"),
                    "<unavailable>".to_string(),
                    "<unavailable>".to_string(),
                ),
            };
            builder.push_record([
                queue.processor.to_string(),
                queue.priority.to_string(),
                ui::addr(entry.kthread.0).to_string(),
                tid,
                process,
                priority,
                state,
            ]);
        }
        if let Some(stop) = termination_message(&queue.termination) {
            outln!(
                "CPU {} priority {}: list walk stopped: {}",
                queue.processor,
                queue.priority,
                stop
            );
        }
    }
    for error in &detail.errors {
        outln!(
            "CPU {}: <unavailable: {}>",
            error
                .processor
                .map_or_else(|| "?".to_string(), |value| value.to_string()),
            error.message
        );
    }
    if detail.total == 0 {
        outln!("ready lists are empty or unavailable\n");
    } else {
        print_padded_table(builder);
    }
    if detail.truncated {
        outln!("ready-list output bounded at 4096 entries\n");
    }
}

fn routine_cell(
    pointer: &DiagnosticValue<Option<VirtAddr>>,
    symbol: &DiagnosticValue<Option<String>>,
) -> String {
    match pointer {
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
        DiagnosticValue::Available(None) => "null".to_string(),
        DiagnosticValue::Available(Some(address)) => match symbol {
            DiagnosticValue::Available(Some(symbol)) => symbol.clone(),
            DiagnosticValue::Available(None) => ui::addr(address.0).to_string(),
            DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
        },
    }
}

fn interrupt_value(detail: &TimerDetail) -> Option<u64> {
    match &detail.interrupt_time {
        DiagnosticValue::Available(Some(value)) => Some(*value),
        _ => None,
    }
}

fn format_due_time(detail: &TimerDetail) -> String {
    let DiagnosticValue::Available(raw) = &detail.due_time else {
        return diagnostic_cell(&detail.due_time);
    };
    let raw = *raw;
    let Some(now) = interrupt_value(detail) else {
        return format!("{raw:#x}");
    };
    let (future, delta) = if raw >= now {
        (true, raw - now)
    } else {
        (false, now - raw)
    };
    if delta >= 1_000_000_000_000 {
        return format!("{raw:#x}");
    }
    let millis = delta / 10_000;
    if future {
        format!("{raw:#x} (+{millis} ms)")
    } else {
        format!("{raw:#x} (-{millis} ms, expired)")
    }
}

fn timer_dpc_cell(detail: &TimerDetail) -> String {
    if let DiagnosticValue::Unavailable(error) = &detail.dpc {
        if let DiagnosticValue::Available(Some(encoded)) = &detail.dpc_encoded {
            return format!("<encoded> {:#x}", encoded.0);
        }
        return format!("<unavailable: {error}>");
    }
    routine_cell(&detail.dpc_routine, &detail.dpc_routine_symbol)
}

fn print_timer_detail(detail: &TimerDetail) {
    outln!("timer {}", ui::addr(detail.address.0));
    outln!("  DueTime : {}", format_due_time(detail));
    outln!("  Period  : {}", diagnostic_cell(&detail.period));
    outln!("  DPC     : {}", timer_dpc_cell(detail));
    outln!();
}

fn print_timer_list(detail: &TimerListDetail) {
    outln!(
        "interrupt time {}",
        match &detail.interrupt_time {
            DiagnosticValue::Available(Some(value)) => format!(
                "{value:#x} [{}]",
                detail.interrupt_time_source.as_deref().unwrap_or("unknown")
            ),
            DiagnosticValue::Available(None) => "<unavailable>".to_string(),
            DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
        }
    );
    let mut builder = tabled::builder::Builder::default();
    builder.push_record(["CPU", "Bucket", "KTIMER", "DueTime", "Period", "DPC"]);
    for entry in &detail.entries {
        builder.push_record([
            entry.processor.to_string(),
            entry.bucket.to_string(),
            ui::addr(entry.timer.address.0).to_string(),
            format_due_time(&entry.timer),
            diagnostic_cell(&entry.timer.period),
            timer_dpc_cell(&entry.timer),
        ]);
    }
    for bucket in &detail.terminations {
        if let Some(stop) = termination_message(&bucket.termination) {
            outln!(
                "CPU {} bucket {}: list walk stopped: {}",
                bucket.processor,
                bucket.bucket,
                stop
            );
        }
    }
    for error in &detail.errors {
        outln!(
            "CPU {}: <unavailable: {}>",
            error
                .processor
                .map_or_else(|| "?".to_string(), |value| value.to_string()),
            error.message
        );
    }
    if detail.total == 0 {
        outln!("timer table is empty or unavailable\n");
    } else {
        print_padded_table(builder);
    }
    if detail.truncated {
        outln!("timer output bounded at 4096 entries\n");
    }
}

fn print_apc_detail(label: &str, detail: &ApcDetail) {
    outln!(
        "  {label:<6} APC {}  KernelRoutine {}  NormalRoutine {}",
        ui::addr(detail.address.0),
        routine_cell(&detail.kernel_routine, &detail.kernel_routine_symbol),
        routine_cell(&detail.normal_routine, &detail.normal_routine_symbol),
    );
}

fn print_apcs(detail: &ApcListDetail) {
    if let Some(error) = &detail.layout_error {
        outln!("APC layout: <unavailable: {error}>\n");
    }
    if detail.threads.is_empty() {
        outln!("no matching Windows threads\n");
        return;
    }
    for thread in &detail.threads {
        outln!(
            "thread {}  ETHREAD {}  process {} (pid {})",
            thread_tid(&thread.thread),
            ui::addr(thread.thread.ethread.0),
            thread_process(&thread.thread),
            thread_pid(&thread.thread)
        );
        for apc in &thread.kernel {
            print_apc_detail("kernel", apc);
        }
        for apc in &thread.user {
            print_apc_detail("user", apc);
        }
        if let Some(error) = &thread.state_error {
            outln!("  APC state: <unavailable: {error}>");
        }
        if let Some(stop) = termination_message(&thread.kernel_termination) {
            outln!("  kernel APC list stopped: {stop}");
        }
        if let Some(stop) = termination_message(&thread.user_termination) {
            outln!("  user APC list stopped: {stop}");
        }
    }
    if detail.truncated {
        outln!("APC output bounded at 4096 entries\n");
    } else {
        outln!();
    }
}

fn print_stacks(detail: &StacksDetail) {
    let frame_bound = match detail.level {
        1 => 32,
        2 => 64,
        _ => 1,
    };
    outln!(
        "{} thread(s), level {}, frame bound {}{}",
        detail.scanned_threads,
        detail.level,
        frame_bound,
        detail
            .filter
            .as_deref()
            .map(|value| format!(", filter '{value}'"))
            .unwrap_or_default()
    );
    for thread in &detail.threads {
        outln!(
            "{}  {:<16}  {:<8}  {:<24}  {:<20}  {}",
            thread_tid(&thread.thread),
            thread_process(&thread.thread),
            thread_pid(&thread.thread),
            thread_state(&thread.thread),
            thread_wait_reason(&thread.thread),
            diagnostic_option_cell(&thread.top_symbol, |symbol| symbol.clone(), "<unavailable>"),
        );
        if detail.level > 0 {
            for (index, frame) in thread.frames.iter().enumerate() {
                outln!("    #{index:<2} {}", frame.symbol);
            }
        }
        if detail.level > 0 && thread.truncated != 0 {
            outln!("    <{} additional frame(s) omitted>", thread.truncated);
        }
        if let Some(error) = &thread.error
            && detail.level == 0
        {
            outln!("    <unavailable: {error}>");
        }
    }
    if detail.interrupted {
        outln!(
            "interrupted after {} displayed thread(s)\n",
            detail.displayed_threads
        );
    } else if detail.displayed_threads == 0 {
        outln!("no matching thread stacks\n");
    } else {
        outln!();
    }
}
