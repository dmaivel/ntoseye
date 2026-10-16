use ntoseye_macros::command;

use super::hardware::ready_processor;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::ProcessInfo;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::disasm::{format_stack_frame, more_frames};
use crate::repl::*;
use crate::session::Session;
use crate::target::sched::{
    Apc, ApcQueues, ApcSelector, DpcQueues, FindStack, KernelTimer, ReadyQueues, RunningProcessors,
    ThreadStacks, TimerTable, UniqStackOptions, UniqStackScope, UniqStacks, UnwalkedThread,
    findstack_level,
};
use crate::target::workqueue::{WorkItem, WorkQueueTypes, WorkQueues};
use crate::target::{
    DiagnosticValue, ListTermination, ThreadInfo, kthread_state_name, wait_reason_name,
};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::StackFrame;

use super::diagnostics::{diagnostic_addr, diagnostic_cell};

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

/// Show the thread that runs on each processor.
///
/// -i includes idle threads, and -t adds a short kernel stack, with a frame
/// limit, for each processor.
#[command(
    names = ["!running", "running"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!running [-i] [-t]",
    completion = [None]
)]
fn running(
    session: &mut Session,
    #[arg(switch = "-i")] include_idle: bool,
    #[arg(switch = "-t")] include_stacks: bool,
) -> Result<RunningProcessors> {
    session
        .inspect_running(include_idle, include_stacks)
        .map_err(|error| Error::DebugInfo(format!("failed to inspect running threads: {error}")))
}

impl Render for RunningProcessors {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        if self.processors.is_empty() {
            outln!("no non-idle running threads\n");
            return;
        }
        let mut builder = tabled::builder::Builder::default();
        builder.push_record([
            "CPU", "KPCR", "KPRCB", "KTHREAD", "TID", "Process", "Priority", "Next", "Idle",
            "Stack",
        ]);
        for processor in &self.processors {
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
    }
}

/// List the dispatcher ready queues of all processors or of one processor.
///
/// The command reads DispatcherReadyListHead from each _KPRCB, or ReadyListHead
/// on newer builds. Each queue walk has an entry limit and, like `dt -l`,
/// reports null links, cycles, unreadable links, and when it reaches its entry
/// limit.
#[command(
    names = ["!ready", "ready"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!ready [processor]",
    completion = [Expression]
)]
fn ready(
    session: &mut Session,
    #[arg(parse = ready_processor, positional)] processor: Option<u16>,
) -> Result<ReadyQueues> {
    session
        .target
        .inspect_ready_queues(processor)
        .map_err(|error| Error::DebugInfo(format!("failed to inspect ready queues: {error}")))
}

impl Render for ReadyQueues {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_ready_queues(self);
    }
}

/// List the deferred procedure calls that are queued on each processor.
///
/// The command walks the two _KPRCB DpcData queues. Each walk detects cycles
/// and has an entry limit.
#[command(
    names = ["!dpcs", "dpcs"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!dpcs",
    completion = [None]
)]
fn dpcs(session: &mut Session) -> Result<DpcQueues> {
    session
        .target
        .inspect_dpc_queues()
        .map_err(|error| Error::DebugInfo(format!("failed to inspect DPC queues: {error}")))
}

impl Render for DpcQueues {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let mut builder = tabled::builder::Builder::default();
        builder.push_record([
            "CPU",
            "Queue",
            "KDPC",
            "DeferredRoutine",
            "Context",
            "Importance",
        ]);
        for queue in &self.queues {
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
        for error in &self.errors {
            outln!(
                "CPU {}: <unavailable: {}>",
                error
                    .processor
                    .map_or_else(|| "?".to_string(), |value| value.to_string()),
                error.message
            );
        }
        if self.total == 0 {
            outln!("DPC queues are empty or unavailable\n");
        } else {
            print_padded_table(builder);
        }
        if self.truncated {
            outln!("DPC output bounded at 4096 entries\n");
        }
    }
}

/// Show the executive worker queues with their pending work items and worker
/// threads.
///
/// Windows 10 and later keep one _EX_WORK_QUEUE for each partition, NUMA node,
/// and queue index (_EXQUEUEINDEX: ExPoolUntrusted, IoPoolUntrusted, ...). The
/// command finds the queues from the ExPartition of each _EPARTITION. For each
/// queue, it shows the thread count and limits, the concurrency
/// (_KPRIQUEUE.MaximumCount), and the number of work items processed. Then it
/// shows each pending _WORK_QUEUE_ITEM by priority, with its routine as a
/// symbol and, for an IoQueueWorkItem item, the I/O routine, object, and
/// context. After the items come the threads that serve the queue, with their
/// state and wait reason. Each priority shows the WORK_QUEUE_TYPEs that map to
/// it, and its running threads against the concurrency. The command reads these
/// priorities from nt!ExpBuiltinPriorities (CriticalWorkQueue is 13,
/// DelayedWorkQueue is 12, HyperCriticalWorkQueue is 15). The flags are the
/// same as in WinDbg. 0x4 adds the stack of each worker thread (32 frames).
/// 0x10, 0x20, and 0x40 show only the items of the critical, delayed, and
/// hypercritical priorities. The command accepts 0x1 and 0x2, but it always
/// lists the threads. Each list walk detects cycles and has an entry limit:
/// 1,024 items for each priority and 4,096 threads for each queue.
#[command(
    names = ["!exqueue", "exqueue"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    forms = [work_queues],
    usage = "!exqueue [flags]"
)]
fn exqueue(session: &mut Session, #[arg(default = 0)] flags: u64) -> Result<WorkQueues> {
    session.inspect_work_queues(flags)
}

/// Get the executive worker queues, their pending work items, and their
/// worker threads (`!exqueue`). `include_stacks` adds the stack of each
/// worker, and `queue_types` (`"critical"`, `"delayed"`, `"hypercritical"`)
/// limits the listed items to the priorities of those types.
#[command(form_of = exqueue, python = Inspect, sdk)]
fn work_queues(
    session: &mut Session,
    #[arg(default = false)] include_stacks: bool,
    queue_types: Option<WorkQueueTypes>,
) -> Result<WorkQueues> {
    let stacks = if include_stacks { 0x4 } else { 0 };
    session.inspect_work_queues(stacks | queue_types.map_or(0, |types| types.0))
}

impl Render for WorkQueues {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_work_queues(self);
    }
}

/// `!timer`'s address: an expression over the rest of the line.
fn timer_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    if cursor.remaining() == 0 {
        return Ok(None);
    }
    let expression = cursor.rest();
    Expr::eval_with_radix(&expression, &cx.state.ctx.target, cx.state.radix)
        .map(Some)
        .map_err(|error| {
            ArgError::Message(format!("invalid timer address '{expression}': {error}"))
        })
}

/// What `!timer` shows: the timer tables, or one timer.
pub enum Timers {
    Table(TimerTable),
    /// One `_KTIMER`, and the interrupt time its due time is read against.
    Timer(KernelTimer, DiagnosticValue<u64>),
}

/// List the kernel timers or decode one _KTIMER.
///
/// Without an address, the command walks _KPRCB.TimerTable.TimerEntries. With
/// an address, it decodes one timer and its DPC.
#[command(
    names = ["!timer", "timer"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    forms = [timers, timer],
    usage = "!timer [address-expression]",
    completion = [Expression]
)]
fn timer_command(
    session: &mut Session,
    #[arg(parse = timer_address)] address: Option<VirtAddr>,
) -> Result<Timers> {
    match address {
        Some(address) => {
            let timer = timer(session, address).map_err(|error| {
                Error::DebugInfo(format!(
                    "failed to inspect timer {}: {error}",
                    ui::addr(address.0)
                ))
            })?;
            Ok(Timers::Timer(timer, session.target.interrupt_time()))
        }
        None => timers(session)
            .map(Timers::Table)
            .map_err(|error| Error::DebugInfo(format!("failed to enumerate timers: {error}"))),
    }
}

/// Read the kernel timer-table entries, up to a limit, and their DPCs
/// (`!timer`).
#[command(form_of = timer_command, python = Inspect)]
fn timers(session: &Session) -> Result<TimerTable> {
    session.target.timer_list()
}

/// Decode a `_KTIMER` and its DPC (`!timer address`).
#[command(form_of = timer_command, python = Inspect)]
fn timer(
    session: &Session,
    #[arg(name = "address-expression", complete = Expression)] address: VirtAddr,
) -> Result<KernelTimer> {
    session.target.inspect_timer(address)
}

impl Render for Timers {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Table(table) => print_timer_list(table),
            Self::Timer(timer, now) => print_timer_detail(timer, interrupt_value(now)),
        }
    }
}

/// `!apc`'s selection: `.` or nothing for the current thread, `*` for every
/// thread, a number for a thread or process, or part of a process name.
fn apc_selector(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<ApcSelector, ArgError> {
    let argument = (cursor.remaining() != 0).then(|| cursor.rest());
    let select = || -> Result<ApcSelector> {
        let Some(argument) = argument.as_deref() else {
            return Ok(ApcSelector::CurrentThread);
        };
        if argument == "." {
            return Ok(ApcSelector::CurrentThread);
        }
        if argument == "*" {
            return Ok(ApcSelector::All);
        }
        let target = &cx.state.ctx.target;
        if let Ok(value) = Expr::eval_with_radix(argument, target, cx.state.radix) {
            return Ok(ApcSelector::Number(value.0));
        }
        let needle = argument.to_ascii_lowercase();
        let processes = target.guest()?.enumerate_processes()?;
        let process = processes
            .iter()
            .find(|process| process.name.to_ascii_lowercase().contains(&needle))
            .ok_or_else(|| {
                Error::DebugInfo(format!("no process or thread matches '{argument}'"))
            })?;
        Ok(ApcSelector::Process(process.pid))
    };
    select().map_err(|error| ArgError::Message(format!("failed to select APC threads: {error}")))
}

/// List the kernel and user APCs of the selected thread, a process, or all
/// threads.
///
/// With no argument, the command uses the current Windows thread. With *, it
/// lists the APCs of all threads, in a walk that has a limit.
#[command(
    names = ["!apc", "apc"],
    category = "execution and stack",
    kind = Query,
    target = Kernel,
    forms = [apcs, process_apcs, thread_apcs],
    usage = "!apc [process|thread]",
    completion = [Expression]
)]
fn apc(
    session: &mut Session,
    #[arg(parse = apc_selector)] selector: ApcSelector,
) -> Result<ApcQueues> {
    apcs(session, selector)
        .map_err(|error| Error::DebugInfo(format!("failed to inspect APCs: {error}")))
}

/// Decode the kernel and user APC queues of all threads, of a process, or
/// of a thread (`!apc`): `target` is a `Process`, a `Thread`, or an
/// `_ETHREAD` address, and all threads by default.
#[command(form_of = apc, python = Inspect)]
fn apcs(
    session: &mut Session,
    #[arg(default = None, name = "process|thread", complete = Expression, positional)]
    target: ApcSelector,
) -> Result<ApcQueues> {
    session.inspect_apcs(target)
}

/// Decode the kernel and user APC queues of this process (`!apc`).
#[command(form_of = apc, python = Process, python_name = "apcs", sdk)]
fn process_apcs(session: &mut Session, #[arg(receiver)] process: ProcessInfo) -> Result<ApcQueues> {
    session.inspect_apcs(ApcSelector::Process(process.pid))
}

/// Decode the APC lists of this thread (`!apc`).
#[command(form_of = apc, python = Thread, python_name = "apcs", sdk)]
fn thread_apcs(session: &mut Session, #[arg(receiver)] thread: ThreadInfo) -> Result<ApcQueues> {
    session.inspect_apcs(ApcSelector::Thread(thread.ethread))
}

impl Render for ApcQueues {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_apcs(self);
    }
}

/// `!stacks`' level: a leading 0, 1, or 2; anything else is the filter.
fn stacks_level(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u8, ArgError> {
    let level = match cursor.peek() {
        Some("0") => 0,
        Some("1") => 1,
        Some("2") => 2,
        _ => return Ok(0),
    };
    cursor.word();
    Ok(level)
}

/// The words left, joined, or `None` when there are none.
fn rest_of_line(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<String>, ArgError> {
    Ok((cursor.remaining() != 0).then(|| cursor.rest()))
}

/// Show the state, wait reason, and top stack symbol of each thread.
///
/// Level 0 shows one frame. Levels 1 and 2 add the full stacks, with a frame
/// limit. The optional filter matches process or stack symbols.
#[command(
    names = ["!stacks", "stacks"],
    category = "execution and stack",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!stacks [0|1|2] [filter]",
    completion = [None, Process]
)]
fn stacks(
    session: &mut Session,
    #[arg(parse = stacks_level, default = 0)] level: u8,
    #[arg(parse = rest_of_line)] filter: Option<String>,
) -> Result<ThreadStacks> {
    session
        .inspect_stacks(level, filter.as_deref())
        .map_err(|error| Error::DebugInfo(format!("failed to inspect thread stacks: {error}")))
}

impl Render for ThreadStacks {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_stacks(self);
    }
}

/// `!findstack`'s pattern; `-?` asks for the help.
fn findstack_pattern(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<String, ArgError> {
    match cursor.word() {
        None => Err(ArgError::Missing),
        Some(word) if word == "-?" => Err(ArgError::Missing),
        Some(word) => Ok(word.into_owned()),
    }
}

/// `!findstack`'s display level: 0, 1 (the default), or 2.
fn findstack_display_level(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u8, ArgError> {
    let level = cursor.word();
    // A word past the level is refused before the level is read.
    if let Some(extra) = cursor.peek() {
        return Err(ArgError::Message(format!(
            "!findstack: unexpected argument '{extra}'"
        )));
    }
    findstack_level(level.as_deref())
        .map_err(|error| ArgError::Message(format!("!findstack: {error}")))
}

/// List the threads with a stack frame that matches a symbol or module.
///
/// The command walks the stack of each Windows thread, up to 64 frames, as
/// !stacks 2 does. `module!name` matches frames in that module whose function
/// starts with name, as in WinDbg, so `nt!KeWait` matches KeWaitForSingleObject
/// and KeWaitForMultipleObjects, and `nt!` matches all frames in nt. A bare
/// word matches a module by name or a function by prefix. With * or ?, the
/// module and function are globs (`nt!*Wait*`). Matches ignore case. Display
/// level 0 lists the matching threads and the number of frames that match,
/// level 1 (the default) adds the matching frames, and level 2 shows the whole
/// stack and marks the matching frames with *. The command cannot search a
/// thread whose stack does not walk, such as a thread that runs on a processor
/// while the target runs, and lists these threads after the matches.
#[command(
    names = ["!findstack", "findstack"],
    category = "execution and stack",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!findstack <symbol|module> [0|1|2]",
    completion = [Symbol, None]
)]
fn findstack(
    session: &mut Session,
    #[arg(parse = findstack_pattern)] symbol: String,
    #[arg(parse = findstack_display_level, default = 1)] level: u8,
) -> Result<FindStack> {
    session
        .inspect_findstack(&symbol, level)
        .map_err(|error| Error::DebugInfo(format!("!findstack: {error}")))
}

impl Render for FindStack {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_findstack(self);
    }
}

/// `!uniqstack`'s `-v`/`-n` words, wherever they are.
fn uniqstack_options(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<UniqStackOptions, ArgError> {
    let words = cursor.take_all(|word| word.len() > 1 && word.starts_with('-'));
    let words: Vec<&str> = words.iter().map(AsRef::as_ref).collect();
    UniqStackOptions::parse(&words)
        .map(|(options, _)| options)
        .map_err(|error| ArgError::Message(format!("!uniqstack: {error}")))
}

/// The threads `!uniqstack` groups: `*` for every thread, one process
/// named as `.process` names it or by name (see
/// [`ReplState::process_for_selector_or_name`]), and by default the
/// `.process` selection, or every thread when none is selected.
fn uniqstack_scope(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<UniqStackScope, ArgError> {
    let argument = cursor.word();
    if let (Some(first), Some(second)) = (&argument, cursor.peek()) {
        return Err(ArgError::Message(format!(
            "!uniqstack: {}",
            Error::InvalidArgument(format!(
                "!uniqstack takes one process or *, got '{first}' and '{second}'"
            ))
        )));
    }
    let state = &*cx.state;
    let select = || -> Result<UniqStackScope> {
        let process = match argument.as_deref() {
            Some("*") => return Ok(UniqStackScope::AllThreads),
            None => match state.ctx.target.attached_process() {
                Some(process) => process.clone(),
                None => return Ok(UniqStackScope::AllThreads),
            },
            Some(selector) => {
                let processes = state.ctx.target.matching_processes(None)?;
                state.process_for_selector_or_name(selector, &processes)?
            }
        };
        Ok(UniqStackScope::Process {
            pid: process.pid,
            name: process.name,
        })
    };
    select().map_err(|error| ArgError::Message(format!("!uniqstack: {error}")))
}

/// Group the threads by identical call stacks and show each unique stack once.
///
/// WinDbg's !uniqstack groups the user-mode stacks of the threads of the
/// current process. This command groups the threads that the kernel schedules,
/// using their stacks as !stacks 2 walks them: up to 64 frames, with the kernel
/// frames first and then the user-mode frames below a system call. With no
/// argument, the command uses the threads of the .process selection or, if no
/// process is selected, the threads of all processes, which is the default in a
/// kernel session. * selects all threads, and a PID, EPROCESS address, or name
/// selects one process. Threads share a group when their frames have the same
/// instruction pointers and the same truncation. The command shows each unique
/// stack once, from its first thread, with the number of threads that share it
/// and their thread IDs by process. The totals come after the groups. -n
/// numbers the frames. -v shows how ntoseye recovered each frame (current,
/// seed, unwind, or scan), as kv does, and this output replaces the x86 FPO
/// data that WinDbg shows. The command does not accept the -b and -p options of
/// WinDbg, because on x64 the first arguments go in registers, which a saved
/// stack does not keep, and -p also needs private-symbol parameters for each
/// frame. For one thread, use .thread and kp. Some stacks do not walk, such as
/// the stack of a thread that runs on a processor while the target runs, and
/// the command shows these threads in a separate list.
#[command(
    names = ["!uniqstack", "uniqstack"],
    category = "execution and stack",
    kind = Query,
    target = Kernel,
    forms = [uniqstack],
    usage = "!uniqstack [-v] [-n] [*|process]",
    completion = [Process]
)]
fn uniqstack_command(
    session: &mut Session,
    #[arg(render, parse = uniqstack_options)] options: UniqStackOptions,
    #[arg(parse = uniqstack_scope)] scope: UniqStackScope,
) -> Result<UniqStacks> {
    uniqstack(session, scope).map_err(|error| Error::DebugInfo(format!("!uniqstack: {error}")))
}

/// Group threads by identical call stacks (`!uniqstack`), using all threads
/// unless `process` limits it to the threads of one process.
#[command(form_of = uniqstack_command, python = Inspect)]
fn uniqstack(
    session: &mut Session,
    #[arg(default = None, name = "*|process", complete = Process, positional)]
    process: UniqStackScope,
) -> Result<UniqStacks> {
    session.inspect_uniqstack(process)
}

impl Render<UniqStackOptions> for UniqStacks {
    fn render(&self, _: &mut ReplState<'_>, options: UniqStackOptions) {
        print_uniqstack(self, options);
    }
}

fn print_ready_queues(detail: &ReadyQueues) {
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
fn format_due_time(detail: &KernelTimer, now: Option<u64>) -> String {
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

fn timer_dpc_cell(detail: &KernelTimer) -> String {
    if let DiagnosticValue::Unavailable(error) = &detail.dpc {
        if let DiagnosticValue::Available(Some(encoded)) = &detail.dpc_encoded {
            return format!("<encoded> {:#x}", encoded.0);
        }
        return format!("<unavailable: {error}>");
    }
    routine_cell(&detail.dpc_routine, &detail.dpc_routine_symbol)
}

fn print_timer_detail(detail: &KernelTimer, now: Option<u64>) {
    outln!("timer {}", ui::addr(detail.address.0));
    outln!("  DueTime : {}", format_due_time(detail, now));
    outln!("  Period  : {}", diagnostic_cell(&detail.period));
    outln!("  DPC     : {}", timer_dpc_cell(detail));
    outln!();
}

fn print_timer_list(detail: &TimerTable) {
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

fn print_apc_detail(label: &str, detail: &Apc) {
    outln!(
        "  {label:<6} APC {}  KernelRoutine {}  NormalRoutine {}",
        ui::addr(detail.address.0),
        routine_cell(&detail.kernel_routine, &detail.kernel_routine_symbol),
        routine_cell(&detail.normal_routine, &detail.normal_routine_symbol),
    );
}

fn print_apcs(detail: &ApcQueues) {
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

fn print_work_item(item: &WorkItem) {
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

fn print_work_queues(detail: &WorkQueues) {
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
                priority.work_items.len()
            );
            for item in &priority.work_items {
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

fn print_stacks(detail: &ThreadStacks) {
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

fn print_findstack(detail: &FindStack) {
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

fn print_uniqstack(detail: &UniqStacks, options: UniqStackOptions) {
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
