use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::repl::disasm::{format_stack_frame, more_frames};
use crate::repl::*;
use crate::target::sched::{
    ApcDetail, ApcListDetail, ApcSelector, FindStackDetail, ReadyQueuesDetail, StacksDetail,
    TimerDetail, TimerListDetail, UniqStackDetail, UniqStackOptions, UniqStackScope,
    UnwalkedThread, findstack_level,
};
use crate::target::workqueue::{ExQueueDetail, WorkItemDetail};
use crate::target::{
    DiagnosticValue, ListTermination, ThreadInfo, kthread_state_name, wait_reason_name,
};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::StackFrame;

use super::diagnostics::{diagnostic_addr, diagnostic_cell};

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
    details: "Reads DispatcherReadyListHead (or ReadyListHead on newer builds) from each _KPRCB. Each queue walk reports null links, cycles, unreadable links, and reaching its entry bound, as `dt -l` does.",
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
    cmd_exqueue;
    names: ["!exqueue", "exqueue"],
    usage: "!exqueue [flags]",
    summary: "Show the executive worker queues, their pending work items, and worker threads.",
    details: "Windows 10 and later keep one _EX_WORK_QUEUE per partition, NUMA node, and queue index (_EXQUEUEINDEX: ExPoolUntrusted, IoPoolUntrusted, ...), reached from each _EPARTITION's ExPartition. For each queue: its thread count and limits, concurrency (_KPRIQUEUE.MaximumCount), work items processed, and every pending _WORK_QUEUE_ITEM by priority with its routine symbolized (an IoQueueWorkItem item also by its I/O routine, object, and context), then the threads serving it with their state and wait reason. A priority shows the WORK_QUEUE_TYPEs that map to it (CriticalWorkQueue is 13, DelayedWorkQueue 12, HyperCriticalWorkQueue 15, read from nt!ExpBuiltinPriorities) and its running threads against the concurrency. Flags follow WinDbg: 0x4 adds each worker thread's stack (32 frames); 0x10, 0x20, and 0x40 restrict the listed items to the critical, delayed, and hypercritical priorities; 0x1 and 0x2 are accepted (threads are always listed). Lists are walked with cycle and entry bounds (1,024 items per priority, 4,096 threads per queue).",
    completion: Expression,
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

repl_command! {
    cmd_findstack;
    names: ["!findstack", "findstack"],
    usage: "!findstack <symbol|module> [0|1|2]",
    summary: "List the threads whose stack has a frame matching a symbol or module.",
    details: "Walks every Windows thread's stack, up to 64 frames, as !stacks 2 does. `module!name` matches frames in that module whose function starts with name, as WinDbg's does (`nt!KeWait` matches KeWaitForSingleObject and KeWaitForMultipleObjects; `nt!` any frame in nt); a bare word matches a module by name or a function by prefix; with * or ? the module and function are globs (`nt!*Wait*`). Case is ignored. Display level 0 lists the matching threads and how many frames matched; 1 (the default) adds the matching frames; 2 the whole stack, matching frames marked with *. A thread whose stack does not walk (one running on a processor while the target runs) cannot be searched and is listed after the matches.",
    completion: [Symbol, None],
}

repl_command! {
    cmd_uniqstack;
    names: ["!uniqstack", "uniqstack"],
    usage: "!uniqstack [-v] [-n] [*|process]",
    summary: "Group threads by identical call stacks, showing each distinct stack once.",
    details: "WinDbg's !uniqstack groups the user-mode stacks of the current process's threads; this one groups the threads the kernel schedules, by their stacks as !stacks 2 walks them (up to 64 frames: the kernel frames, then the user-mode frames below a system call): the threads of the .process selection, or of every process when none is selected (the default in a kernel session), * for every thread, or one process by PID, EPROCESS address, or name. Threads whose frames have the same instruction pointers (and the same truncation) share a group. Each distinct stack is shown once, from its first thread, with the number of threads sharing it and their thread IDs by process; totals follow. -n numbers the frames; -v shows how each frame was recovered (current, seed, unwind, or scan), as kv does, in place of WinDbg's x86 FPO data. WinDbg's -b and -p are refused: x64 passes the first arguments in registers, which a saved stack does not keep, and -p needs private-symbol parameters per frame (use .thread and kp on one thread). A thread whose stack does not walk (one running on a processor while the target runs) is listed apart.",
    completion: Process,
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

fn option_cell<T>(value: Option<&T>, render: impl FnOnce(&T) -> String, none: &str) -> String {
    value.map_or_else(|| none.to_string(), render)
}

fn thread_tid(thread: &ThreadInfo) -> String {
    option_cell(
        thread.tid.as_ref(),
        |tid| tid.to_string(),
        &ui::addr(thread.ethread.0).to_string(),
    )
}

fn thread_pid(thread: &ThreadInfo) -> String {
    option_cell(thread.pid.as_ref(), |pid| pid.to_string(), "<unavailable>")
}

fn thread_process(thread: &ThreadInfo) -> String {
    option_cell(thread.process_name.as_ref(), Clone::clone, "<unknown>")
}

fn thread_priority(thread: &ThreadInfo) -> String {
    option_cell(
        thread.priority.as_ref(),
        |priority| priority.to_string(),
        "<unavailable>",
    )
}

fn thread_state(thread: &ThreadInfo) -> String {
    option_cell(
        thread.state.as_ref(),
        |state| format!("{} ({state})", kthread_state_name(*state)),
        "<unavailable>",
    )
}

fn thread_wait_reason(thread: &ThreadInfo) -> String {
    option_cell(
        thread.wait_reason.as_ref(),
        |reason| format!("{} ({reason})", wait_reason_name(*reason)),
        "<unavailable>",
    )
}

fn running_thread_kthread(value: &DiagnosticValue<Option<ThreadInfo>>) -> String {
    diagnostic_option_cell(value, |thread| ui::addr(thread.kthread.0).to_string(), "-")
}

fn running_thread_detail(value: &DiagnosticValue<Option<ThreadInfo>>) -> String {
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

fn short_stack_cell(value: Option<&DiagnosticValue<Vec<StackFrame>>>) -> String {
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
                        diagnostic_addr(&processor.kpcr),
                        diagnostic_addr(&processor.prcb),
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
                diagnostic_addr(&processor.kpcr),
                diagnostic_addr(&processor.prcb),
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
                    diagnostic_cell(&entry.importance),
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

    fn cmd_exqueue(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let flags = match invocation.arg(0) {
            Some(arg) => match self.eval_or_report(arg) {
                Some(VirtAddr(flags)) => flags,
                None => return Ok(()),
            },
            None => 0,
        };
        match self.ctx.inspect_work_queues(flags) {
            Ok(detail) => print_work_queues(&detail),
            Err(error) => error!("{error}"),
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
            print_timer_detail(&detail, interrupt_value(&self.ctx.target.interrupt_time()));
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
            return Ok(ApcSelector::Number(value));
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

    fn cmd_findstack(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (pattern, level) = match (invocation.arg(0), invocation.arg(1), invocation.arg(2)) {
            (None | Some("-?"), _, _) => {
                outln!("{}\n", command_help("!findstack"));
                return Ok(());
            }
            (Some(pattern), level, None) => match findstack_level(level) {
                Ok(level) => (pattern.to_string(), level),
                Err(error) => {
                    error!("!findstack: {error}");
                    return Ok(());
                }
            },
            (Some(_), _, Some(extra)) => {
                error!("!findstack: unexpected argument '{extra}'");
                return Ok(());
            }
        };
        match self.ctx.inspect_findstack(&pattern, level) {
            Ok(detail) => print_findstack(&detail),
            Err(error) => error!("!findstack: {error}"),
        }
        Ok(())
    }

    fn cmd_uniqstack(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
        let result = UniqStackOptions::parse(&args).and_then(|(options, scope)| {
            let scope = self.uniqstack_scope(scope)?;
            Ok((options, self.ctx.inspect_uniqstack(scope)?))
        });
        match result {
            Ok((options, detail)) => print_uniqstack(&detail, options),
            Err(error) => error!("!uniqstack: {error}"),
        }
        Ok(())
    }

    /// The threads `!uniqstack` groups: `*` for every thread, one process
    /// named as `.process` names it or by name (see
    /// [`Self::process_for_selector_or_name`]), and by default the `.process`
    /// selection, or every thread when none is selected.
    pub fn uniqstack_scope(&self, argument: Option<&str>) -> Result<UniqStackScope> {
        let process = match argument {
            Some("*") => return Ok(UniqStackScope::AllThreads),
            None => match self.ctx.target.attached_process() {
                Some(process) => process.clone(),
                None => return Ok(UniqStackScope::AllThreads),
            },
            Some(selector) => {
                let processes = self.ctx.target.matching_processes(None)?;
                self.process_for_selector_or_name(selector, &processes)?
            }
        };
        Ok(UniqStackScope::Process {
            pid: process.pid,
            name: process.name,
        })
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
                DiagnosticValue::Available(thread) => (
                    thread_tid(thread),
                    thread_process(thread),
                    thread_priority(thread),
                    thread_state(thread),
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

fn interrupt_value(interrupt_time: &DiagnosticValue<u64>) -> Option<u64> {
    match interrupt_time {
        DiagnosticValue::Available(value) => Some(*value),
        DiagnosticValue::Unavailable(_) => None,
    }
}

/// `detail`'s due time, and how far it is from `now` (the interrupt time).
fn format_due_time(detail: &TimerDetail, now: Option<u64>) -> String {
    let DiagnosticValue::Available(raw) = &detail.due_time else {
        return diagnostic_cell(&detail.due_time);
    };
    let raw = *raw;
    let Some(now) = now else {
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

fn print_timer_detail(detail: &TimerDetail, now: Option<u64>) {
    outln!("timer {}", ui::addr(detail.address.0));
    outln!("  DueTime : {}", format_due_time(detail, now));
    outln!("  Period  : {}", diagnostic_cell(&detail.period));
    outln!("  DPC     : {}", timer_dpc_cell(detail));
    outln!();
}

fn print_timer_list(detail: &TimerListDetail) {
    outln!(
        "interrupt time {}",
        match &detail.interrupt_time {
            DiagnosticValue::Available(value) =>
                format!("{value:#x} [KUSER_SHARED_DATA.InterruptTime]"),
            DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
        }
    );
    let now = interrupt_value(&detail.interrupt_time);
    let mut builder = tabled::builder::Builder::default();
    builder.push_record(["CPU", "Bucket", "KTIMER", "DueTime", "Period", "DPC"]);
    for entry in &detail.entries {
        builder.push_record([
            entry.processor.to_string(),
            entry.bucket.to_string(),
            ui::addr(entry.timer.address.0).to_string(),
            format_due_time(&entry.timer, now),
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

fn print_work_item(item: &WorkItemDetail) {
    let routine = |address: VirtAddr, symbol: &Option<String>| match symbol {
        Some(symbol) => format!("{} ({})", ui::symbol(symbol), ui::addr(address.0)),
        None => ui::addr(address.0).to_string(),
    };
    match &item.io {
        Some(io) => outln!(
            "    IoWorkItem ({})  Routine {}  IoObject ({})  Context ({})",
            ui::addr(io.address.0),
            routine(io.routine, &io.routine_symbol),
            ui::addr(io.io_object.0),
            ui::addr(io.context.0)
        ),
        None => outln!(
            "    ExWorkItem ({})  Routine {}  Parameter ({})",
            ui::addr(item.address.0),
            routine(item.routine, &item.routine_symbol),
            ui::addr(item.parameter.0)
        ),
    }
}

fn print_work_queues(detail: &ExQueueDetail) {
    if let Some(selected) = &detail.priority_filter {
        let list: Vec<String> = selected.iter().map(u8::to_string).collect();
        outln!("items listed for priorities {} only", list.join(", "));
    }
    for queue in &detail.queues {
        outln!(
            "**** Partition {}  NUMA Node {}  {} queue {} ****",
            ui::addr(queue.partition.0),
            queue.node,
            queue
                .queue_index_name
                .clone()
                .unwrap_or_else(|| format!("index {}", queue.queue_index)),
            ui::addr(queue.address.0)
        );
        outln!(
            "  Threads: {} (min {}, max {})   Concurrency: {}   Pending: {}   Processed: {} ({} at last pass)",
            queue.thread_count,
            queue.min_threads,
            queue.max_threads,
            queue.concurrency,
            queue.pending,
            queue.items_processed,
            queue.items_processed_last_pass
        );
        for priority in &queue.priorities {
            let types = if priority.queue_types.is_empty() {
                String::new()
            } else {
                format!(" ({})", priority.queue_types.join(", "))
            };
            outln!(
                " -> Priority {}{} - ( Concurrency: {}/{} )  {} pending",
                priority.priority,
                types,
                priority.current_count,
                queue.concurrency,
                priority.items.len()
            );
            for item in &priority.items {
                print_work_item(item);
            }
            if let Some(stop) = termination_message(&priority.termination) {
                outln!("    list walk stopped: {stop}");
            }
        }
        outln!(" -> Associated Threads ({})", queue.threads.len());
        for worker in &queue.threads {
            match &worker.thread {
                DiagnosticValue::Available(info) => {
                    let thread = info;
                    outln!(
                        "    THREAD {}  Cid {}.{}  {}  {}  Priority {}",
                        ui::addr(thread.ethread.0),
                        thread_pid(thread),
                        thread_tid(thread),
                        thread_state(thread),
                        thread_wait_reason(thread),
                        thread_priority(thread)
                    );
                }
                DiagnosticValue::Unavailable(error) => outln!(
                    "    KTHREAD {}  <unavailable: {error}>",
                    ui::addr(worker.kthread.0)
                ),
            }
            match &worker.stack {
                Some(DiagnosticValue::Available(frames)) => {
                    for (index, frame) in frames.iter().enumerate() {
                        outln!("      #{index:<2} {}", frame.symbol);
                    }
                }
                Some(DiagnosticValue::Unavailable(error)) => {
                    outln!("      <stack unavailable: {error}>")
                }
                None => {}
            }
        }
        if let Some(stop) = termination_message(&queue.threads_termination) {
            outln!("    thread list walk stopped: {stop}");
        }
        outln!();
    }
    for error in &detail.errors {
        outln!("<unavailable: {error}>");
    }
    if detail.queues.is_empty() {
        outln!("no executive work queues found\n");
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

fn thread_label(thread: &ThreadInfo) -> String {
    format!(
        "{} {} ({})  {}  {}",
        thread_tid(thread),
        thread_process(thread),
        thread_pid(thread),
        thread_state(thread),
        thread_wait_reason(thread)
    )
}

fn print_unwalked(unwalked: &[UnwalkedThread]) {
    if unwalked.is_empty() {
        return;
    }
    outln!("{} thread stack(s) could not be walked:", unwalked.len());
    let mut by_error: Vec<(&str, Vec<ThreadInfo>)> = Vec::new();
    for thread in unwalked {
        match by_error
            .iter_mut()
            .find(|(error, _)| *error == thread.error)
        {
            Some((_, threads)) => threads.push(thread.thread.clone()),
            None => by_error.push((&thread.error, vec![thread.thread.clone()])),
        }
    }
    for (error, threads) in by_error {
        outln!("    {} thread(s): {error}", threads.len());
        outln!("        {}", thread_ids_by_process(&threads));
    }
}

fn print_findstack(detail: &FindStackDetail) {
    for thread in &detail.threads {
        outln!(
            "Thread {}, {} frame(s) match",
            thread_label(&thread.thread),
            thread.matches.len()
        );
        let frames = &thread.stack.frames;
        match detail.level {
            0 => {}
            1 => {
                for &index in &thread.matches {
                    outln!(
                        "    * {}",
                        format_stack_frame(Some(index), &frames[index], true, false)
                    );
                }
            }
            _ => {
                for (index, frame) in frames.iter().enumerate() {
                    let mark = if thread.matches.contains(&index) {
                        '*'
                    } else {
                        ' '
                    };
                    outln!(
                        "    {mark} {}",
                        format_stack_frame(Some(index), frame, true, false)
                    );
                }
                if thread.stack.truncated != 0 {
                    outln!("      {}", more_frames(thread.stack.truncated));
                }
            }
        }
        if detail.level > 0 {
            outln!();
        }
    }
    outln!(
        "{} of {} thread(s) have a frame matching '{}'{}",
        detail.threads.len(),
        detail.scanned_threads,
        detail.pattern,
        if detail.interrupted {
            " (interrupted: not every thread was searched)"
        } else {
            ""
        }
    );
    print_unwalked(&detail.unwalked);
    outln!();
}

fn print_uniqstack(detail: &UniqStackDetail, options: UniqStackOptions) {
    match &detail.scope {
        UniqStackScope::AllThreads => {
            outln!("{} thread(s) of every process\n", detail.scanned_threads)
        }
        UniqStackScope::Process { pid, name } => {
            outln!("{} thread(s) of {name} ({pid})\n", detail.scanned_threads)
        }
    }
    let mut sharing = 0;
    for group in &detail.groups {
        let first = &group.threads[0];
        outln!(
            ". {}  -- {} thread(s) with this stack",
            thread_label(first),
            group.threads.len()
        );
        sharing += group.threads.len() - 1;
        for (index, frame) in group.stack.frames.iter().enumerate() {
            outln!(
                "    {}",
                format_stack_frame(
                    options.frame_numbers.then_some(index),
                    frame,
                    true,
                    options.provenance
                )
            );
        }
        if group.stack.truncated != 0 {
            outln!("    {}", more_frames(group.stack.truncated));
        }
        if group.threads.len() > 1 {
            outln!("    Threads: {}", thread_ids_by_process(&group.threads));
        }
        outln!();
    }
    outln!(
        "Total threads: {}, walked: {}, unique stacks: {}, threads sharing an earlier stack: {sharing}{}",
        detail.scanned_threads,
        detail.walked_threads(),
        detail.groups.len(),
        if detail.interrupted {
            " (interrupted: not every thread was walked)"
        } else {
            ""
        }
    );
    print_unwalked(&detail.unwalked);
    outln!();
}

/// `System (4): 12 16 20; smss.exe (544): 548`, in the threads' order.
fn thread_ids_by_process(threads: &[ThreadInfo]) -> String {
    let mut runs: Vec<(String, Vec<String>)> = Vec::new();
    for thread in threads {
        let process = format!("{} ({})", thread_process(thread), thread_pid(thread));
        match runs.last_mut() {
            Some((last, tids)) if *last == process => tids.push(thread_tid(thread)),
            _ => runs.push((process, vec![thread_tid(thread)])),
        }
    }
    runs.into_iter()
        .map(|(process, tids)| format!("{process}: {}", tids.join(" ")))
        .collect::<Vec<_>>()
        .join("; ")
}
