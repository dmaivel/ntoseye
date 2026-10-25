use ntoseye_macros::{command, grammar};

use super::hardware::ready_processor;
use crate::base::diagnostics::print_warning;
use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::disasm::{format_stack_frame, more_frames};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::expr::Expr;
use crate::nt::guest::ProcessInfo;
use crate::nt::target::sched::{
    Apc, ApcQueues, ApcSelector, DpcQueues, FindStack, KernelTimer, ReadyQueues, RunningProcessors,
    SchedulerError, ThreadStack, ThreadStacks, TimerTable, UniqStackOptions, UniqStackScope,
    UniqStacks, UnwalkedThread, findstack_level,
};
use crate::nt::target::workqueue::{WorkItem, WorkQueueTypes, WorkQueues};
use crate::nt::target::{
    DiagnosticValue, ListTermination, ThreadInfo, kthread_state_name, wait_reason_name,
};
use crate::nt::unwind::StackFrame;
use crate::session::Session;

/// The values a block could not read. Each shows `-` in its cell, and the
/// reasons print once after the block, one warning for each distinct reason
/// naming the values it hid.
#[derive(Default)]
struct Unread(Vec<(String, Vec<String>)>);

impl Unread {
    fn note(&mut self, what: String, error: &str) {
        match self.0.iter_mut().find(|(reason, _)| reason == error) {
            Some((_, whats)) => whats.push(what),
            None => self.0.push((error.to_string(), vec![what])),
        }
    }

    /// `value` rendered, or `-` with its reason noted under `what`.
    fn cell<T>(
        &mut self,
        value: &DiagnosticValue<T>,
        what: impl FnOnce() -> String,
        render: impl FnOnce(&T) -> String,
    ) -> String {
        match value {
            DiagnosticValue::Available(value) => render(value),
            DiagnosticValue::Unavailable(error) => {
                self.note(what(), error);
                "-".to_string()
            }
        }
    }

    fn print(&self) {
        // A reason shared by many rows names a few of them, not thousands.
        const NAMED: usize = 3;
        for (error, whats) in &self.0 {
            let mut named = whats[..whats.len().min(NAMED)].join(", ");
            if whats.len() > NAMED {
                named.push_str(&format!(" and {} more", whats.len() - NAMED));
            }
            print_warning(format!("{named}: {error}"));
        }
    }
}

/// `count` with `noun`, plural unless it is 1: `1 thread`, `2 threads`.
fn count_of(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn option_cell<T>(value: Option<&T>, render: impl FnOnce(&T) -> String, none: &str) -> String {
    value.map_or_else(|| none.to_string(), render)
}

fn thread_tid(thread: &ThreadInfo) -> String {
    option_cell(thread.tid.as_ref(), |tid| tid.to_string(), "-")
}

fn thread_pid(thread: &ThreadInfo) -> String {
    option_cell(thread.pid.as_ref(), |pid| pid.to_string(), "-")
}

fn thread_process(thread: &ThreadInfo) -> String {
    option_cell(thread.process_name.as_ref(), Clone::clone, "-")
}

fn thread_priority(thread: &ThreadInfo) -> String {
    option_cell(
        thread.priority.as_ref(),
        |priority| priority.to_string(),
        "-",
    )
}

fn thread_state(thread: &ThreadInfo) -> String {
    option_cell(
        thread.state.as_ref(),
        |state| format!("{} ({state:#x})", kthread_state_name(*state)),
        "-",
    )
}

fn thread_wait_reason(thread: &ThreadInfo) -> String {
    option_cell(
        thread.wait_reason.as_ref(),
        |reason| format!("{} ({reason:#x})", wait_reason_name(*reason)),
        "-",
    )
}

/// The `THREAD <addr>  TID n  PID n  process <name>` heading of a thread.
fn thread_heading(thread: &ThreadInfo) -> String {
    format!(
        "THREAD {}  TID {}  PID {}  process {}",
        ui::addr(thread.ethread.0),
        thread_tid(thread),
        thread_pid(thread),
        thread_process(thread)
    )
}

/// A processor's next or idle thread as its KTHREAD, or `-` when there is
/// none or it is the `current` thread the row already shows.
fn other_thread_cell(
    value: &DiagnosticValue<Option<ThreadInfo>>,
    current: Option<VirtAddr>,
    unread: &mut Unread,
    what: impl FnOnce() -> String,
) -> String {
    unread.cell(value, what, |thread| match thread {
        Some(thread) if Some(thread.kthread) != current => ui::addr(thread.kthread.0).to_string(),
        _ => "-".to_string(),
    })
}

fn short_stack_cell(
    value: Option<&DiagnosticValue<Vec<StackFrame>>>,
    unread: &mut Unread,
    what: impl FnOnce() -> String,
) -> String {
    let Some(value) = value else {
        return "-".to_string();
    };
    unread.cell(value, what, |frames| {
        if frames.is_empty() {
            return "-".to_string();
        }
        frames
            .iter()
            .map(|frame| frame.symbol.as_str())
            .collect::<Vec<_>>()
            .join(" <- ")
    })
}

fn termination_message(termination: &ListTermination) -> Option<String> {
    termination.diagnostic()
}

/// One warning for each processor whose queues could not be read.
fn print_scheduler_errors(errors: &[SchedulerError]) {
    for error in errors {
        match error.processor {
            Some(processor) => print_warning(format!("CPU {processor}: {}", error.message)),
            None => print_warning(&error.message),
        }
    }
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
            outln!("{}", ui::muted("no non-idle running threads"));
            return;
        }
        let mut builder = tabled::builder::Builder::default();
        builder.push_record([
            "CPU", "KPCR", "KPRCB", "KTHREAD", "TID", "PID", "Process", "Priority", "Next", "Idle",
            "Stack",
        ]);
        let mut unread = Unread::default();
        for processor in &self.processors {
            let cpu = processor.index;
            let current = match &processor.current_thread {
                DiagnosticValue::Available(thread) => thread.as_ref(),
                DiagnosticValue::Unavailable(error) => {
                    unread.note(format!("CPU {cpu} thread"), error);
                    None
                }
            };
            let current_kthread = current.map(|thread| thread.kthread);
            let address = |address: &VirtAddr| ui::addr(address.0).to_string();
            builder.push_record([
                cpu.to_string(),
                unread.cell(&processor.kpcr, || format!("CPU {cpu} KPCR"), address),
                unread.cell(&processor.prcb, || format!("CPU {cpu} KPRCB"), address),
                current.map_or_else(|| "-".to_string(), |thread| address(&thread.kthread)),
                current.map_or_else(|| "-".to_string(), thread_tid),
                current.map_or_else(|| "-".to_string(), thread_pid),
                current.map_or_else(|| "-".to_string(), thread_process),
                current.map_or_else(|| "-".to_string(), thread_priority),
                other_thread_cell(&processor.next_thread, current_kthread, &mut unread, || {
                    format!("CPU {cpu} next thread")
                }),
                other_thread_cell(&processor.idle_thread, current_kthread, &mut unread, || {
                    format!("CPU {cpu} idle thread")
                }),
                short_stack_cell(processor.short_stack.as_ref(), &mut unread, || {
                    format!("CPU {cpu} stack")
                }),
            ]);
        }
        print_padded_table(builder);
        unread.print();
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
            "Deferred routine",
            "Context",
            "Importance",
        ]);
        let mut unread = Unread::default();
        let mut stops = Vec::new();
        for queue in &self.queues {
            for entry in &queue.entries {
                let what = || format!("KDPC {:#x}", entry.address.0);
                builder.push_record([
                    queue.processor.to_string(),
                    queue.queue.to_string(),
                    ui::addr(entry.address.0).to_string(),
                    routine_cell(
                        &entry.deferred_routine,
                        &entry.deferred_routine_symbol,
                        &mut unread,
                        what,
                    ),
                    unread.cell(&entry.context, what, |context| {
                        context.map_or_else(
                            || "-".to_string(),
                            |address| ui::addr(address.0).to_string(),
                        )
                    }),
                    unread.cell(&entry.importance, what, u8::to_string),
                ]);
            }
            if let Some(stop) = termination_message(&queue.termination) {
                stops.push(format!(
                    "CPU {} queue {}: list walk stopped: {stop}",
                    queue.processor, queue.queue
                ));
            }
        }
        if self.total != 0 {
            print_padded_table(builder);
        } else if self.errors.is_empty() {
            outln!("{}", ui::muted("no queued DPCs"));
        }
        unread.print();
        for stop in &stops {
            print_warning(stop);
        }
        print_scheduler_errors(&self.errors);
        if self.truncated {
            outln!("DPC output bounded at 4096 entries");
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
)]
fn exqueue(session: &mut Session, #[arg(default = 0)] flags: u64) -> Result<WorkQueues> {
    session.inspect_work_queues(flags)
}

/// Get the executive worker queues, their pending work items, and their
/// worker threads (`!exqueue`). `include_stacks` adds the stack of each
/// worker, and `queue_types` (`"critical"`, `"delayed"`, `"hypercritical"`)
/// limits the listed items to the priorities of those types.
#[command(form_of = exqueue, python = Inspect)]
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
#[grammar(usage = "[{}]", complete = [Expression])]
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
fn timer(session: &Session, address: VirtAddr) -> Result<KernelTimer> {
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
#[grammar(usage = "[.|*|thread|process]", complete = [Expression])]
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
    #[arg(default = None, positional)] target: ApcSelector,
) -> Result<ApcQueues> {
    session.inspect_apcs(target)
}

/// Decode the kernel and user APC queues of this process (`!apc`).
#[command(form_of = apc, python = Process, python_name = "apcs")]
fn process_apcs(session: &mut Session, #[arg(receiver)] process: ProcessInfo) -> Result<ApcQueues> {
    session.inspect_apcs(ApcSelector::Process(process.pid))
}

/// Decode the APC lists of this thread (`!apc`).
#[command(form_of = apc, python = Thread, python_name = "apcs")]
fn thread_apcs(session: &mut Session, #[arg(receiver)] thread: ThreadInfo) -> Result<ApcQueues> {
    session.inspect_apcs(ApcSelector::Thread(thread.ethread))
}

impl Render for ApcQueues {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_apcs(self);
    }
}

/// `!stacks`' level: a leading 0, 1, or 2; anything else is the filter.
#[grammar(usage = "[0|1|2]", complete = [None])]
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
#[grammar(usage = "[{}]", complete = Process)]
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
#[grammar(usage = "<symbol|module>", complete = [Symbol])]
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
#[grammar(usage = "[0|1|2]", complete = [None])]
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
#[grammar(usage = "[-v] [-n]")]
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
#[grammar(usage = "[*|process]", complete = [Process])]
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
    #[arg(default = None, positional)] process: UniqStackScope,
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
        "PID",
        "Process",
        "Thread priority",
        "State",
    ]);
    let mut unread = Unread::default();
    let mut stops = Vec::new();
    for queue in &detail.queues {
        for entry in &queue.entries {
            let thread = match &entry.thread {
                DiagnosticValue::Available(thread) => Some(thread),
                DiagnosticValue::Unavailable(error) => {
                    unread.note(format!("KTHREAD {:#x}", entry.kthread.0), error);
                    None
                }
            };
            let field =
                |render: fn(&ThreadInfo) -> String| thread.map_or_else(|| "-".to_string(), render);
            builder.push_record([
                queue.processor.to_string(),
                queue.priority.to_string(),
                ui::addr(entry.kthread.0).to_string(),
                field(thread_tid),
                field(thread_pid),
                field(thread_process),
                field(thread_priority),
                field(thread_state),
            ]);
        }
        if let Some(stop) = termination_message(&queue.termination) {
            stops.push(format!(
                "CPU {} priority {}: list walk stopped: {stop}",
                queue.processor, queue.priority
            ));
        }
    }
    if detail.total != 0 {
        print_padded_table(builder);
    } else if detail.errors.is_empty() {
        outln!("{}", ui::muted("no ready threads"));
    }
    unread.print();
    for stop in &stops {
        print_warning(stop);
    }
    print_scheduler_errors(&detail.errors);
    if detail.truncated {
        outln!("ready-list output bounded at 4096 entries");
    }
}

/// A routine as its symbol, or its address when no symbol resolves; `-`
/// when there is none.
fn routine_cell(
    pointer: &DiagnosticValue<Option<VirtAddr>>,
    symbol: &DiagnosticValue<Option<String>>,
    unread: &mut Unread,
    what: impl FnOnce() -> String,
) -> String {
    match (pointer, symbol) {
        (DiagnosticValue::Unavailable(error), _) => {
            unread.note(what(), error);
            "-".to_string()
        }
        (DiagnosticValue::Available(None), _) => "-".to_string(),
        (DiagnosticValue::Available(Some(_)), DiagnosticValue::Available(Some(symbol))) => {
            symbol.clone()
        }
        (DiagnosticValue::Available(Some(address)), DiagnosticValue::Available(None)) => {
            format!("{:#x}", address.0)
        }
        // The address is known even when its symbol lookup failed, so the
        // cell shows it and the failure goes in the block's warning.
        (DiagnosticValue::Available(Some(address)), DiagnosticValue::Unavailable(error)) => {
            unread.note(what(), error);
            format!("{:#x}", address.0)
        }
    }
}

fn interrupt_value(interrupt_time: &DiagnosticValue<u64>) -> Option<u64> {
    match interrupt_time {
        DiagnosticValue::Available(value) => Some(*value),
        DiagnosticValue::Unavailable(_) => None,
    }
}

/// `raw`, a due time, and how far it is from `now` (the interrupt time).
fn format_due_time(raw: u64, now: Option<u64>) -> String {
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

fn timer_dpc_cell(detail: &KernelTimer, unread: &mut Unread) -> String {
    let what = || format!("KTIMER {:#x} DPC", detail.address.0);
    if let DiagnosticValue::Unavailable(error) = &detail.dpc {
        match &detail.dpc_encoded {
            DiagnosticValue::Available(Some(encoded)) => {
                unread.note(what(), &format!("{error} (encoded Dpc {:#x})", encoded.0))
            }
            _ => unread.note(what(), error),
        }
        return "-".to_string();
    }
    routine_cell(
        &detail.dpc_routine,
        &detail.dpc_routine_symbol,
        unread,
        what,
    )
}

/// The cells of a timer: its due time, period, and DPC routine.
fn timer_cells(timer: &KernelTimer, now: Option<u64>, unread: &mut Unread) -> [String; 3] {
    let what = || format!("KTIMER {:#x}", timer.address.0);
    [
        unread.cell(&timer.due_time, what, |raw| format_due_time(*raw, now)),
        unread.cell(&timer.period, what, u32::to_string),
        timer_dpc_cell(timer, unread),
    ]
}

fn print_timer_detail(detail: &KernelTimer, now: Option<u64>) {
    let mut unread = Unread::default();
    let [due_time, period, dpc] = timer_cells(detail, now, &mut unread);
    outln!("KTIMER {}", ui::addr(detail.address.0));
    outln!("  DueTime : {due_time}");
    outln!("  Period  : {period}");
    outln!("  DPC     : {dpc}");
    unread.print();
}

fn print_timer_list(detail: &TimerTable) {
    let mut unread = Unread::default();
    let interrupt_time = unread.cell(
        &detail.interrupt_time,
        || "interrupt time".to_string(),
        |value| format!("{value:#x} [KUSER_SHARED_DATA.InterruptTime]"),
    );
    outln!("interrupt time {interrupt_time}");
    let now = interrupt_value(&detail.interrupt_time);
    let mut builder = tabled::builder::Builder::default();
    builder.push_record(["CPU", "Bucket", "KTIMER", "Due time", "Period", "DPC"]);
    for entry in &detail.entries {
        let [due_time, period, dpc] = timer_cells(&entry.timer, now, &mut unread);
        builder.push_record([
            entry
                .processor
                .map_or_else(|| "-".to_string(), |processor| processor.to_string()),
            entry.bucket.to_string(),
            ui::addr(entry.timer.address.0).to_string(),
            due_time,
            period,
            dpc,
        ]);
    }
    if detail.total != 0 {
        print_padded_table(builder);
    } else if detail.errors.is_empty() {
        outln!("{}", ui::muted("no timers"));
    }
    unread.print();
    for bucket in &detail.terminations {
        if let Some(stop) = termination_message(&bucket.termination) {
            let table = bucket.processor.map_or_else(
                || "shared table".to_string(),
                |processor| format!("CPU {processor}"),
            );
            print_warning(format!(
                "{table} bucket {}: list walk stopped: {stop}",
                bucket.bucket
            ));
        }
    }
    print_scheduler_errors(&detail.errors);
    if detail.truncated {
        outln!("timer output bounded at 4096 entries");
    }
}

fn print_apc_detail(label: &str, detail: &Apc, unread: &mut Unread) {
    let what = || format!("APC {:#x}", detail.address.0);
    let kernel = routine_cell(
        &detail.kernel_routine,
        &detail.kernel_routine_symbol,
        unread,
        what,
    );
    let normal = routine_cell(
        &detail.normal_routine,
        &detail.normal_routine_symbol,
        unread,
        what,
    );
    outln!(
        "  {label:<6} APC {}  KernelRoutine {kernel}  NormalRoutine {normal}",
        ui::addr(detail.address.0),
    );
}

fn print_apcs(detail: &ApcQueues) {
    if let Some(error) = &detail.layout_error {
        print_warning(format!("APC layout unavailable: {error}"));
    }
    if detail.threads.is_empty() {
        outln!("{}", ui::muted("no matching Windows threads"));
        return;
    }
    let mut unread = Unread::default();
    for (index, thread) in detail.threads.iter().enumerate() {
        if index > 0 {
            outln!();
        }
        outln!("{}", thread_heading(&thread.thread));
        for apc in &thread.kernel {
            print_apc_detail("kernel", apc, &mut unread);
        }
        for apc in &thread.user {
            print_apc_detail("user", apc, &mut unread);
        }
        if let Some(error) = &thread.state_error {
            outln!("  APC state unavailable: {error}");
        } else if thread.kernel.is_empty() && thread.user.is_empty() {
            outln!("  {}", ui::muted("no queued APCs"));
        }
        if let Some(stop) = termination_message(&thread.kernel_termination) {
            outln!("  kernel APC list stopped: {stop}");
        }
        if let Some(stop) = termination_message(&thread.user_termination) {
            outln!("  user APC list stopped: {stop}");
        }
    }
    unread.print();
    if detail.truncated {
        outln!("APC output bounded at 4096 entries");
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
    let mut unread = Unread::default();
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
                DiagnosticValue::Available(thread) => outln!(
                    "    THREAD {}  TID {}  PID {}  {}  {}  Priority {}",
                    ui::addr(thread.ethread.0),
                    thread_tid(thread),
                    thread_pid(thread),
                    thread_state(thread),
                    thread_wait_reason(thread),
                    thread_priority(thread)
                ),
                DiagnosticValue::Unavailable(error) => {
                    outln!("    KTHREAD {}", ui::addr(worker.kthread.0));
                    unread.note(format!("KTHREAD {:#x}", worker.kthread.0), error);
                }
            }
            match &worker.stack {
                Some(DiagnosticValue::Available(frames)) => {
                    for (index, frame) in frames.iter().enumerate() {
                        outln!(
                            "      {}",
                            format_stack_frame(Some(index), frame, true, false)
                        );
                    }
                }
                Some(DiagnosticValue::Unavailable(error)) => {
                    outln!("      {}", ui::muted(error))
                }
                None => {}
            }
        }
        if let Some(stop) = termination_message(&queue.threads_termination) {
            outln!("    thread list walk stopped: {stop}");
        }
        outln!();
    }
    unread.print();
    for error in &detail.errors {
        print_warning(error);
    }
    if detail.queues.is_empty() && detail.errors.is_empty() {
        outln!("{}", ui::muted("no executive work queues"));
    }
}

/// The stack error of a thread, from the walk or from its top frame.
fn stack_error(thread: &ThreadStack) -> Option<&str> {
    match (&thread.error, &thread.top_symbol) {
        (Some(error), _) => Some(error.as_str()),
        (None, DiagnosticValue::Unavailable(error)) => Some(error.as_str()),
        (None, DiagnosticValue::Available(_)) => None,
    }
}

fn print_stacks(detail: &ThreadStacks) {
    let frame_bound = match detail.level {
        1 => 32,
        2 => 64,
        _ => 1,
    };
    outln!(
        "{}, level {}, frame bound {}{}",
        count_of(detail.scanned_threads, "thread"),
        detail.level,
        frame_bound,
        detail
            .filter
            .as_deref()
            .map(|value| format!(", filter '{value}'"))
            .unwrap_or_default()
    );
    if detail.level == 0 {
        if !detail.threads.is_empty() {
            let mut builder = tabled::builder::Builder::default();
            builder.push_record(["TID", "PID", "Process", "State", "Wait reason", "Top frame"]);
            for thread in &detail.threads {
                let top = match &thread.top_symbol {
                    DiagnosticValue::Available(Some(symbol)) => symbol.clone(),
                    _ => "-".to_string(),
                };
                builder.push_record([
                    thread_tid(&thread.thread),
                    thread_pid(&thread.thread),
                    thread_process(&thread.thread),
                    thread_state(&thread.thread),
                    thread_wait_reason(&thread.thread),
                    top,
                ]);
            }
            print_padded_table(builder);
        }
        print_unwalked(
            detail
                .threads
                .iter()
                .filter_map(|thread| Some((&thread.thread, stack_error(thread)?)))
                .collect(),
        );
    } else {
        for (index, thread) in detail.threads.iter().enumerate() {
            if index > 0 {
                outln!();
            }
            outln!("{}", thread_label(&thread.thread));
            for (index, frame) in thread.frames.iter().enumerate() {
                outln!(
                    "    {}",
                    format_stack_frame(Some(index), frame, true, false)
                );
            }
            if thread.truncated != 0 {
                outln!("    {}", more_frames(thread.truncated));
            }
            if let Some(error) = stack_error(thread) {
                outln!("    {}", ui::muted(error));
            }
        }
    }
    if detail.interrupted {
        outln!(
            "interrupted after {}",
            count_of(detail.displayed_threads, "displayed thread")
        );
    } else if detail.displayed_threads == 0 {
        let none = match &detail.filter {
            Some(filter) => format!("no threads matching '{filter}'"),
            None => "no threads".to_string(),
        };
        outln!("{}", ui::muted(&none));
    }
}

/// A thread's heading with its state and wait reason.
fn thread_label(thread: &ThreadInfo) -> String {
    format!(
        "{}  {}  {}",
        thread_heading(thread),
        thread_state(thread),
        thread_wait_reason(thread)
    )
}

/// The threads whose stacks did not walk, grouped by the reason.
fn print_unwalked(unwalked: Vec<(&ThreadInfo, &str)>) {
    if unwalked.is_empty() {
        return;
    }
    outln!(
        "{} could not be walked:",
        count_of(unwalked.len(), "thread stack")
    );
    let mut by_error: Vec<(&str, Vec<&ThreadInfo>)> = Vec::new();
    for (thread, error) in unwalked {
        match by_error.iter_mut().find(|(reason, _)| *reason == error) {
            Some((_, threads)) => threads.push(thread),
            None => by_error.push((error, vec![thread])),
        }
    }
    for (error, threads) in by_error {
        outln!("    {}: {error}", count_of(threads.len(), "thread"));
        outln!("        {}", thread_ids_by_process(threads));
    }
}

fn unwalked_threads(unwalked: &[UnwalkedThread]) -> Vec<(&ThreadInfo, &str)> {
    unwalked
        .iter()
        .map(|thread| (&thread.thread, thread.error.as_str()))
        .collect()
}

fn print_findstack(detail: &FindStack) {
    for (index, thread) in detail.threads.iter().enumerate() {
        if index > 0 && detail.level > 0 {
            outln!();
        }
        outln!(
            "{}: {}",
            thread_label(&thread.thread),
            count_of(thread.matches.len(), "matching frame")
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
    }
    if detail.level > 0 && !detail.threads.is_empty() {
        outln!();
    }
    let interrupted = if detail.interrupted {
        " (interrupted: not every thread was searched)"
    } else {
        ""
    };
    if detail.threads.is_empty() {
        outln!(
            "{}",
            ui::muted(&format!(
                "no threads with a frame matching '{}' ({} searched){interrupted}",
                detail.pattern, detail.scanned_threads
            ))
        );
    } else {
        outln!(
            "{} of {} {} a frame matching '{}'{interrupted}",
            detail.threads.len(),
            count_of(detail.scanned_threads, "thread"),
            if detail.threads.len() == 1 {
                "has"
            } else {
                "have"
            },
            detail.pattern,
        );
    }
    print_unwalked(unwalked_threads(&detail.unwalked));
}

fn print_uniqstack(detail: &UniqStacks, options: UniqStackOptions) {
    let threads = count_of(detail.scanned_threads, "thread");
    match &detail.scope {
        UniqStackScope::AllThreads => outln!("{threads} of every process"),
        UniqStackScope::Process { pid, name } => outln!("{threads} of {name} (PID {pid})"),
    }
    outln!();
    let mut sharing = 0;
    for group in &detail.groups {
        let first = &group.threads[0];
        outln!(
            ". {}  -- {} with this stack",
            thread_label(first),
            count_of(group.threads.len(), "thread")
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
            outln!("    threads: {}", thread_ids_by_process(&group.threads));
        }
        outln!();
    }
    outln!(
        "total threads: {}, walked: {}, unique stacks: {}, threads sharing an earlier stack: {sharing}{}",
        detail.scanned_threads,
        detail.walked_threads(),
        detail.groups.len(),
        if detail.interrupted {
            " (interrupted: not every thread was walked)"
        } else {
            ""
        }
    );
    print_unwalked(unwalked_threads(&detail.unwalked));
}

/// `System (PID 4): 12 16 20; smss.exe (PID 540): 544`, in the threads'
/// order.
fn thread_ids_by_process<'a>(threads: impl IntoIterator<Item = &'a ThreadInfo>) -> String {
    let mut runs: Vec<(String, Vec<String>)> = Vec::new();
    for thread in threads {
        let process = format!("{} (PID {})", thread_process(thread), thread_pid(thread));
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
