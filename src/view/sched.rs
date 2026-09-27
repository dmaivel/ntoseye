//! sched: [`View`] builders for the structured inspectors.

#[cfg(feature = "python-stubs")]
use pyo3::type_hint_union;

use super::execution::{numbered_stack_frame, stack_frame};
use super::shape::{Diag, Hex, Omit, ViewValue, shapes};
use super::{ListEnd, View, list_termination};
use crate::target::sched::{self as detail, ApcSelector};
use crate::target::workqueue::{self, ExQueueDetail};
use crate::target::{DiagnosticValue, kthread_state_name, wait_reason_name};
use crate::types::VirtAddr;
use crate::unwind::StackFrame;

shapes! {
    /// A thread's identity and scheduling state, each read on its own.
    ThreadSummary {
        ethread: Hex,
        kthread: Hex,
        /// Thread id.
        tid: Diag<Option<u64>>,
        /// Owning process's id.
        pid: Diag<Option<u64>>,
        /// Owning process's image name.
        process_name: Diag<Option<String>>,
        /// `_KTHREAD.State`.
        state: Diag<Option<u8>>,
        /// `state` by name (`Running`, `Waiting`, ...).
        state_name: Diag<Option<&'static str>>,
        /// `_KTHREAD.WaitReason`.
        wait_reason: Diag<Option<u8>>,
        /// `wait_reason` by name (`Executive`, `UserRequest`, ...).
        wait_reason_name: Diag<Option<&'static str>>,
        /// Current scheduling priority.
        priority: Diag<Option<u8>>,
    }

    /// A processor's running, next, and idle threads (`!running`).
    RunningProcessor {
        /// Processor number.
        index: u16,
        kpcr: Diag<Hex>,
        prcb: Diag<Hex>,
        /// The thread running on it; `None` inside when there is none.
        current_thread: Diag<Option<ThreadSummary>>,
        /// The thread selected to run next; `None` inside when there is none.
        next_thread: Diag<Option<ThreadSummary>>,
        /// The processor's idle thread.
        idle_thread: Diag<Option<ThreadSummary>>,
        /// The running thread's first frames; absent unless stacks were
        /// requested.
        short_stack: Omit<Diag<Vec<View>>>,
    }

    /// Every processor's running threads (`!running`).
    RunningProcessors {
        processors: Vec<RunningProcessor>,
    }

    /// A thread on a dispatcher ready queue.
    ReadyThread {
        /// The `_KTHREAD` linked on the queue.
        kthread: Hex,
        /// The thread decoded; `None` inside when it could not be.
        thread: Diag<Option<ThreadSummary>>,
    }

    /// One processor's ready list for one priority.
    ReadyQueue {
        processor: u16,
        priority: u8,
        entries: Vec<ReadyThread>,
        /// How the list walk ended.
        termination: ListEnd,
    }

    /// A per-processor or per-queue read that failed during a scheduler walk.
    SchedulerError {
        /// The processor it concerns, if any.
        processor: Option<u16>,
        /// The queue it concerns, if any.
        queue: Option<u16>,
        message: String,
    }

    /// The dispatcher ready queues (`!ready`).
    ReadyQueues {
        /// Non-empty queues.
        queues: Vec<ReadyQueue>,
        /// Threads listed across `queues`.
        total: usize,
        /// Whether the walk stopped at its entry bound.
        truncated: bool,
        errors: Vec<SchedulerError>,
    }

    /// A queued `_KDPC`.
    Dpc {
        address: Hex,
        /// `DeferredRoutine`.
        deferred_routine: Diag<Option<Hex>>,
        /// `deferred_routine` as a symbol, when one resolves.
        deferred_routine_symbol: Diag<Option<String>>,
        /// `DeferredContext`.
        context: Diag<Option<Hex>>,
        /// `Importance`.
        importance: Diag<Option<u8>>,
    }

    /// One of a processor's DPC queues.
    DpcQueue {
        processor: u16,
        /// 0 for the normal queue, 1 for the threaded one.
        queue: u8,
        entries: Vec<Dpc>,
        /// How the list walk ended.
        termination: ListEnd,
    }

    /// Every processor's queued DPCs (`!dpcs`).
    DpcQueues {
        /// Non-empty queues.
        queues: Vec<DpcQueue>,
        /// DPCs listed across `queues`.
        total: usize,
        /// Whether the walk stopped at its entry bound.
        truncated: bool,
        errors: Vec<SchedulerError>,
    }

    /// A `_KTIMER` and its decoded DPC.
    KernelTimer {
        address: Hex,
        /// `DueTime`: the interrupt time it expires at.
        due_time: Diag<Hex>,
        /// `Period` in milliseconds; 0 for a one-shot timer.
        period: Diag<u32>,
        /// `Dpc` as stored, encoded by the kernel.
        dpc_encoded: Diag<Option<Hex>>,
        /// The decoded `_KDPC` address; `None` inside when the timer has none.
        dpc: Diag<Option<Hex>>,
        /// The DPC's `DeferredRoutine`.
        dpc_routine: Diag<Option<Hex>>,
        /// `dpc_routine` as a symbol, when one resolves.
        dpc_routine_symbol: Diag<Option<String>>,
        /// The current interrupt time, to compare `due_time` against.
        interrupt_time: Diag<Option<Hex>>,
    }

    /// A timer found in a processor's timer table.
    TimerTableEntry {
        processor: u16,
        /// Timer-table bucket index.
        bucket: u16,
        timer: KernelTimer,
    }

    /// A timer-table bucket whose list walk did not end back at its head.
    TimerBucketEnd {
        processor: u16,
        bucket: u16,
        termination: ListEnd,
    }

    /// Every processor's timer table (`!timer`).
    TimerTable {
        /// The current interrupt time.
        interrupt_time: Diag<Option<Hex>>,
        /// Where `interrupt_time` was read from.
        interrupt_time_source: Option<String>,
        entries: Vec<TimerTableEntry>,
        /// Buckets whose walk ended abnormally.
        terminations: Vec<TimerBucketEnd>,
        /// Timers listed in `entries`.
        total: usize,
        /// Whether the walk stopped at its entry bound.
        truncated: bool,
        errors: Vec<SchedulerError>,
    }

    /// The thread or process `!apc` was pointed at.
    ApcSelection {
        /// `thread`, `process`, or `number` (not yet resolved to either).
        kind: &'static str,
        /// The ETHREAD/KTHREAD/TID, or PID/EPROCESS, given.
        value: Hex,
    }

    /// A queued `_KAPC`.
    Apc {
        address: Hex,
        /// `KernelRoutine`.
        kernel_routine: Diag<Option<Hex>>,
        /// `kernel_routine` as a symbol, when one resolves.
        kernel_routine_symbol: Diag<Option<String>>,
        /// `NormalRoutine`; `None` inside for a special kernel APC.
        normal_routine: Diag<Option<Hex>>,
        /// `normal_routine` as a symbol, when one resolves.
        normal_routine_symbol: Diag<Option<String>>,
    }

    /// A thread's kernel-mode and user-mode APC queues.
    ApcThread {
        thread: ThreadSummary,
        kernel: Vec<Apc>,
        user: Vec<Apc>,
        /// How the kernel-mode list walk ended.
        kernel_termination: ListEnd,
        /// How the user-mode list walk ended.
        user_termination: ListEnd,
        /// Why the thread's APC state could not be read, if it could not.
        state_error: Option<String>,
    }

    /// APC queues of every thread, a process's, or one thread's (`!apc`).
    ApcQueues {
        /// `all`, `current_thread`, or the thread or process selected.
        selector: ApcSelectorValue,
        threads: Vec<ApcThread>,
        /// APCs listed across `threads`.
        total: usize,
        /// Whether the walk stopped at its entry bound.
        truncated: bool,
        /// Why the APC layout could not be resolved, if it could not.
        layout_error: Option<String>,
    }

    /// A thread's state and walked stack (`!stacks`).
    ThreadStack {
        thread: ThreadSummary,
        /// The vCPU running the thread, when it is running.
        active: Option<String>,
        /// The top frame's symbol.
        top_symbol: Diag<Option<String>>,
        /// Frames, innermost first: the top one at level 0, up to 32 at
        /// level 1, up to 64 at level 2.
        frames: Vec<View>,
        /// Frames past the walk bound, not listed.
        truncated: usize,
        /// Why the stack could not be walked, if it could not.
        error: Option<String>,
    }

    /// Threads with their states and stacks (`!stacks`).
    ThreadStacks {
        /// Detail level (0, 1, or 2), which bounds the frames walked.
        level: u8,
        /// The symbol or module filter, if one was given.
        filter: Option<String>,
        scanned_threads: usize,
        displayed_threads: usize,
        /// Whether the walk was interrupted before it finished.
        interrupted: bool,
        threads: Vec<ThreadStack>,
    }

    /// A thread whose stack could not be walked, so it could not be searched
    /// or grouped.
    UnwalkedThread {
        thread: ThreadSummary,
        /// Why the walk failed.
        error: String,
    }

    /// A thread whose stack has a frame matching `!findstack`'s pattern.
    FindStackThread {
        thread: ThreadSummary,
        /// The vCPU running the thread, when it is running.
        active: Option<String>,
        /// Frames that matched.
        match_count: usize,
        /// The frames that matched, each with its `index` in the stack;
        /// absent at level 0.
        matching_frames: Omit<Vec<View>>,
        /// The whole walked stack, innermost first; present at level 2.
        frames: Omit<Vec<View>>,
        /// Frames past the walk bound, not searched; present at level 2.
        truncated: Omit<usize>,
    }

    /// Threads whose stack has a frame matching a symbol or module
    /// (`!findstack`).
    FindStack {
        pattern: String,
        /// Detail level: 0 counts matches, 1 lists them, 2 adds whole stacks.
        level: u8,
        scanned_threads: usize,
        /// Whether the walk was interrupted before it finished.
        interrupted: bool,
        threads: Vec<FindStackThread>,
        unwalked: Vec<UnwalkedThread>,
    }

    /// An `_IO_WORKITEM` queued through `IoQueueWorkItem`, whose work item
    /// runs `nt!IopProcessWorkItem` to call `routine`.
    IoWorkItem {
        /// The `_IO_WORKITEM` holding the queued `_WORK_QUEUE_ITEM`.
        address: Hex,
        routine: Hex,
        /// `routine` as a symbol, when one resolves.
        routine_symbol: Option<String>,
        /// The device or driver object it was allocated for.
        io_object: Hex,
        context: Hex,
    }

    /// A pending `_WORK_QUEUE_ITEM`.
    WorkItem {
        address: Hex,
        /// `WorkerRoutine`.
        routine: Hex,
        /// `routine` as a symbol, when one resolves.
        routine_symbol: Option<String>,
        parameter: Hex,
        /// The I/O work item it belongs to, when queued by `IoQueueWorkItem`.
        io_work_item: Option<IoWorkItem>,
    }

    /// One of a work queue's 32 priority lists.
    WorkQueuePriority {
        priority: u8,
        /// The `WORK_QUEUE_TYPE`s `ExQueueWorkItem` maps to this priority.
        queue_types: Vec<&'static str>,
        /// `CurrentCount[priority]`: threads running an item of this priority.
        current_count: i64,
        /// The pending work items (key `items`).
        work_items: Vec<WorkItem> => "items",
        /// How the list walk ended.
        termination: ListEnd,
    }

    /// A thread serving a work queue.
    WorkerThread {
        kthread: Hex,
        thread: Diag<ThreadSummary>,
        /// The thread's stack; `None` unless stacks were requested and the
        /// thread decoded.
        stack: Option<Diag<Vec<View>>>,
    }

    /// An `_EX_WORK_QUEUE`.
    WorkQueue {
        address: Hex,
        /// The `_EPARTITION` it belongs to.
        partition: Hex,
        /// NUMA node.
        node: u16,
        queue_index: u32,
        /// `queue_index` by name, when it is a known one.
        queue_index_name: Option<String>,
        items_processed: u32,
        items_processed_last_pass: u32,
        thread_count: i64,
        min_threads: u64,
        max_threads: i64,
        /// `_KPRIQUEUE.MaximumCount`: how many threads may run items at once.
        concurrency: u32,
        /// Items on all 32 priority lists, listed or not.
        pending: u64,
        /// The priority lists holding items or running threads, restricted to
        /// the requested priorities.
        priorities: Vec<WorkQueuePriority>,
        threads: Vec<WorkerThread>,
        /// How the worker-thread list walk ended.
        threads_termination: ListEnd,
    }

    /// Every executive worker queue (`!exqueue`).
    WorkQueues {
        /// The `!exqueue` flags.
        flags: Hex,
        /// The priorities flags 0x10/0x20/0x40 selected; `None` lists all.
        priority_filter: Option<Vec<u8>>,
        queues: Vec<WorkQueue>,
        /// Partitions or queues that could not be decoded.
        errors: Vec<String>,
    }

    /// Threads whose walked stacks have the same frames and truncation.
    UniqStackGroup {
        thread_count: usize,
        threads: Vec<ThreadSummary>,
        /// The first thread's frames, innermost first; the others share its
        /// instruction pointers, not its stack pointers.
        frames: Vec<View>,
        /// Frames past the walk bound, not compared.
        truncated: usize,
    }

    /// Which threads `!uniqstack` grouped.
    UniqStackScope {
        /// `all` or `process`.
        kind: &'static str,
        /// The process's id; `None` for `all`.
        pid: Option<u64>,
        /// The process's image name; `None` for `all`.
        name: Option<String>,
    }

    /// Threads grouped by identical call stacks (`!uniqstack`).
    UniqStacks {
        scope: UniqStackScope,
        scanned_threads: usize,
        /// Threads whose stacks were walked and grouped.
        walked_threads: usize,
        /// Whether the walk was interrupted before it finished.
        interrupted: bool,
        /// In the order their first thread was walked.
        groups: Vec<UniqStackGroup>,
        unwalked: Vec<UnwalkedThread>,
    }
}

/// `!apc`'s selector: a name for the whole-walk selections, an
/// [`ApcSelection`] for a thread or process.
pub enum ApcSelectorValue {
    Name(&'static str),
    Selection(ApcSelection),
}

impl ViewValue for ApcSelectorValue {
    fn into_view(self) -> View {
        match self {
            Self::Name(name) => name.into_view(),
            Self::Selection(selection) => selection.into_view(),
        }
    }
    #[cfg(feature = "python-stubs")]
    const HINT: pyo3::inspect::PyStaticExpr = type_hint_union!(
        pyo3::type_hint_identifier!("builtins", "str"),
        <py::ApcSelection as pyo3::PyTypeInfo>::TYPE_HINT
    );
}

fn thread_summary(thread: &detail::ThreadSummary) -> ThreadSummary {
    ThreadSummary {
        ethread: Hex(thread.ethread.0),
        kthread: Hex(thread.kthread.0),
        tid: Diag::of(&thread.tid, |value| *value),
        pid: Diag::of(&thread.pid, |value| *value),
        process_name: Diag::of(&thread.process_name, Clone::clone),
        state: Diag::of(&thread.state, |value| *value),
        state_name: Diag::of(&thread.state, |value| value.map(kthread_state_name)),
        wait_reason: Diag::of(&thread.wait_reason, |value| *value),
        wait_reason_name: Diag::of(&thread.wait_reason, |value| value.map(wait_reason_name)),
        priority: Diag::of(&thread.priority, |value| *value),
    }
}

fn optional_thread(
    value: &DiagnosticValue<Option<detail::ThreadSummary>>,
) -> Diag<Option<ThreadSummary>> {
    Diag::of(value, |thread| thread.as_ref().map(thread_summary))
}

fn scheduler_error(error: &detail::SchedulerError) -> SchedulerError {
    SchedulerError {
        processor: error.processor,
        queue: error.queue,
        message: error.message.clone(),
    }
}

fn scheduler_errors(errors: &[detail::SchedulerError]) -> Vec<SchedulerError> {
    errors.iter().map(scheduler_error).collect()
}

fn frames(frames: &[StackFrame]) -> Vec<View> {
    frames
        .iter()
        .map(|frame| stack_frame(frame).into_view())
        .collect()
}

fn opt_hex(address: &Option<VirtAddr>) -> Option<Hex> {
    address.map(|address| Hex(address.0))
}

pub fn running(detail: &detail::RunningDetail) -> View {
    RunningProcessors {
        processors: detail
            .processors
            .iter()
            .map(|processor| RunningProcessor {
                index: processor.index,
                kpcr: Diag::of(&processor.kpcr, |address| Hex(address.0)),
                prcb: Diag::of(&processor.prcb, |address| Hex(address.0)),
                current_thread: optional_thread(&processor.current_thread),
                next_thread: optional_thread(&processor.next_thread),
                idle_thread: optional_thread(&processor.idle_thread),
                short_stack: Omit(
                    processor
                        .short_stack
                        .as_ref()
                        .map(|stack| Diag::of(stack, |stack| frames(stack))),
                ),
            })
            .collect(),
    }
    .into_view()
}

pub fn ready_queues(detail: &detail::ReadyQueuesDetail) -> View {
    ReadyQueues {
        queues: detail
            .queues
            .iter()
            .map(|queue| ReadyQueue {
                processor: queue.processor,
                priority: queue.priority,
                entries: queue
                    .entries
                    .iter()
                    .map(|entry| ReadyThread {
                        kthread: Hex(entry.kthread.0),
                        thread: optional_thread(&entry.thread),
                    })
                    .collect(),
                termination: list_termination(&queue.termination),
            })
            .collect(),
        total: detail.total,
        truncated: detail.truncated,
        errors: scheduler_errors(&detail.errors),
    }
    .into_view()
}

fn dpc(dpc: &detail::DpcDetail) -> Dpc {
    Dpc {
        address: Hex(dpc.address.0),
        deferred_routine: Diag::of(&dpc.deferred_routine, opt_hex),
        deferred_routine_symbol: Diag::of(&dpc.deferred_routine_symbol, Clone::clone),
        context: Diag::of(&dpc.context, opt_hex),
        importance: Diag::of(&dpc.importance, |importance| *importance),
    }
}

pub fn dpc_queues(detail: &detail::DpcQueuesDetail) -> View {
    DpcQueues {
        queues: detail
            .queues
            .iter()
            .map(|queue| DpcQueue {
                processor: queue.processor,
                queue: queue.queue,
                entries: queue.entries.iter().map(dpc).collect(),
                termination: list_termination(&queue.termination),
            })
            .collect(),
        total: detail.total,
        truncated: detail.truncated,
        errors: scheduler_errors(&detail.errors),
    }
    .into_view()
}

fn kernel_timer(timer: &detail::TimerDetail) -> KernelTimer {
    KernelTimer {
        address: Hex(timer.address.0),
        due_time: Diag::of(&timer.due_time, |value| Hex(*value)),
        period: Diag::of(&timer.period, |value| *value),
        dpc_encoded: Diag::of(&timer.dpc_encoded, opt_hex),
        dpc: Diag::of(&timer.dpc, opt_hex),
        dpc_routine: Diag::of(&timer.dpc_routine, opt_hex),
        dpc_routine_symbol: Diag::of(&timer.dpc_routine_symbol, Clone::clone),
        interrupt_time: Diag::of(&timer.interrupt_time, |value| value.map(Hex)),
    }
}

pub fn timer_list(detail: &detail::TimerListDetail) -> View {
    TimerTable {
        interrupt_time: Diag::of(&detail.interrupt_time, |value| value.map(Hex)),
        interrupt_time_source: detail.interrupt_time_source.clone(),
        entries: detail
            .entries
            .iter()
            .map(|entry| TimerTableEntry {
                processor: entry.processor,
                bucket: entry.bucket,
                timer: kernel_timer(&entry.timer),
            })
            .collect(),
        terminations: detail
            .terminations
            .iter()
            .map(|entry| TimerBucketEnd {
                processor: entry.processor,
                bucket: entry.bucket,
                termination: list_termination(&entry.termination),
            })
            .collect(),
        total: detail.total,
        truncated: detail.truncated,
        errors: scheduler_errors(&detail.errors),
    }
    .into_view()
}

pub fn timer(detail: &detail::TimerDetail) -> View {
    kernel_timer(detail).into_view()
}

fn apc_selector(selector: ApcSelector) -> ApcSelectorValue {
    let (kind, value) = match selector {
        ApcSelector::CurrentThread => return ApcSelectorValue::Name("current_thread"),
        ApcSelector::All => return ApcSelectorValue::Name("all"),
        ApcSelector::Thread(address) => ("thread", address.0),
        ApcSelector::Process(value) => ("process", value),
        ApcSelector::Number(value) => ("number", value),
    };
    ApcSelectorValue::Selection(ApcSelection {
        kind,
        value: Hex(value),
    })
}

fn apc(apc: &detail::ApcDetail) -> Apc {
    Apc {
        address: Hex(apc.address.0),
        kernel_routine: Diag::of(&apc.kernel_routine, opt_hex),
        kernel_routine_symbol: Diag::of(&apc.kernel_routine_symbol, Clone::clone),
        normal_routine: Diag::of(&apc.normal_routine, opt_hex),
        normal_routine_symbol: Diag::of(&apc.normal_routine_symbol, Clone::clone),
    }
}

pub fn apcs(detail: &detail::ApcListDetail) -> View {
    ApcQueues {
        selector: apc_selector(detail.selector),
        threads: detail
            .threads
            .iter()
            .map(|thread| ApcThread {
                thread: thread_summary(&thread.thread),
                kernel: thread.kernel.iter().map(apc).collect(),
                user: thread.user.iter().map(apc).collect(),
                kernel_termination: list_termination(&thread.kernel_termination),
                user_termination: list_termination(&thread.user_termination),
                state_error: thread.state_error.clone(),
            })
            .collect(),
        total: detail.total,
        truncated: detail.truncated,
        layout_error: detail.layout_error.clone(),
    }
    .into_view()
}

pub fn stacks(detail: &detail::StacksDetail) -> View {
    ThreadStacks {
        level: detail.level,
        filter: detail.filter.clone(),
        scanned_threads: detail.scanned_threads,
        displayed_threads: detail.displayed_threads,
        interrupted: detail.interrupted,
        threads: detail
            .threads
            .iter()
            .map(|thread| ThreadStack {
                thread: thread_summary(&thread.thread),
                active: thread.active_vcpu.clone(),
                top_symbol: Diag::of(&thread.top_symbol, Clone::clone),
                frames: frames(&thread.frames),
                truncated: thread.truncated,
                error: thread.error.clone(),
            })
            .collect(),
    }
    .into_view()
}

fn unwalked_threads(threads: &[detail::UnwalkedThread]) -> Vec<UnwalkedThread> {
    threads
        .iter()
        .map(|thread| UnwalkedThread {
            thread: thread_summary(&thread.thread),
            error: thread.error.clone(),
        })
        .collect()
}

fn findstack_thread(thread: &detail::FindStackThread, level: u8) -> FindStackThread {
    let whole = level >= 2;
    FindStackThread {
        thread: thread_summary(&thread.thread),
        active: thread.active_vcpu.clone(),
        match_count: thread.matches.len(),
        matching_frames: Omit((level >= 1).then(|| {
            thread
                .matches
                .iter()
                .map(|&index| numbered_stack_frame(index, &thread.stack.frames[index]).into_view())
                .collect()
        })),
        frames: Omit(whole.then(|| frames(&thread.stack.frames))),
        truncated: Omit(whole.then_some(thread.stack.truncated)),
    }
}

pub fn findstack(detail: &detail::FindStackDetail) -> View {
    FindStack {
        pattern: detail.pattern.clone(),
        level: detail.level,
        scanned_threads: detail.scanned_threads,
        interrupted: detail.interrupted,
        threads: detail
            .threads
            .iter()
            .map(|thread| findstack_thread(thread, detail.level))
            .collect(),
        unwalked: unwalked_threads(&detail.unwalked),
    }
    .into_view()
}

fn work_item(item: &workqueue::WorkItemDetail) -> WorkItem {
    WorkItem {
        address: Hex(item.address.0),
        routine: Hex(item.routine.0),
        routine_symbol: item.routine_symbol.clone(),
        parameter: Hex(item.parameter.0),
        io_work_item: item.io.as_ref().map(|io| IoWorkItem {
            address: Hex(io.address.0),
            routine: Hex(io.routine.0),
            routine_symbol: io.routine_symbol.clone(),
            io_object: Hex(io.io_object.0),
            context: Hex(io.context.0),
        }),
    }
}

fn work_queue_priority(priority: &workqueue::WorkQueuePriority) -> WorkQueuePriority {
    WorkQueuePriority {
        priority: priority.priority,
        queue_types: priority.queue_types.clone(),
        current_count: priority.current_count.into(),
        work_items: priority.items.iter().map(work_item).collect(),
        termination: list_termination(&priority.termination),
    }
}

fn work_queue(queue: &workqueue::WorkQueueDetail) -> WorkQueue {
    WorkQueue {
        address: Hex(queue.address.0),
        partition: Hex(queue.partition.0),
        node: queue.node,
        queue_index: queue.queue_index,
        queue_index_name: queue.queue_index_name.clone(),
        items_processed: queue.items_processed,
        items_processed_last_pass: queue.items_processed_last_pass,
        thread_count: queue.thread_count.into(),
        min_threads: queue.min_threads,
        max_threads: queue.max_threads.into(),
        concurrency: queue.concurrency,
        pending: queue.pending,
        priorities: queue.priorities.iter().map(work_queue_priority).collect(),
        threads: queue
            .threads
            .iter()
            .map(|worker| WorkerThread {
                kthread: Hex(worker.kthread.0),
                thread: Diag::of(&worker.thread, |info| {
                    thread_summary(&detail::thread_summary(info))
                }),
                stack: worker
                    .stack
                    .as_ref()
                    .map(|stack| Diag::of(stack, |stack| frames(stack))),
            })
            .collect(),
        threads_termination: list_termination(&queue.threads_termination),
    }
}

pub fn work_queues(detail: &ExQueueDetail) -> View {
    WorkQueues {
        flags: Hex(detail.flags),
        priority_filter: detail.priority_filter.clone(),
        queues: detail.queues.iter().map(work_queue).collect(),
        errors: detail.errors.clone(),
    }
    .into_view()
}

pub fn uniqstack(detail: &detail::UniqStackDetail) -> View {
    let scope = match &detail.scope {
        detail::UniqStackScope::AllThreads => UniqStackScope {
            kind: "all",
            pid: None,
            name: None,
        },
        detail::UniqStackScope::Process { pid, name } => UniqStackScope {
            kind: "process",
            pid: Some(*pid),
            name: Some(name.clone()),
        },
    };
    UniqStacks {
        scope,
        scanned_threads: detail.scanned_threads,
        walked_threads: detail.walked_threads(),
        interrupted: detail.interrupted,
        groups: detail
            .groups
            .iter()
            .map(|group| UniqStackGroup {
                thread_count: group.threads.len(),
                threads: group.threads.iter().map(thread_summary).collect(),
                frames: frames(&group.stack.frames),
                truncated: group.stack.truncated,
            })
            .collect(),
        unwalked: unwalked_threads(&detail.unwalked),
    }
    .into_view()
}
