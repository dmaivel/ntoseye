//! sched: [`View`] builders for the structured inspectors.

use super::execution::{self, stack_frame, stack_frames};
use super::shape::{Diag, Hex, shapes, unions};
use super::list::{ListEnd, list_termination};
use crate::target::sched::{self as detail, ApcSelector};
use crate::target::workqueue::{self, ExQueueDetail};
use super::process::{ThreadSummary, thread_summary};
use crate::target::{DiagnosticValue, ThreadInfo};
use crate::types::VirtAddr;

shapes! {
    /// A processor's running, next, and idle threads (`!running`).
    RunningProcessor {
        /// The processor number.
        index: u16,
        kpcr: Diag<VirtAddr>,
        prcb: Diag<VirtAddr>,
        /// The thread that runs on the processor. The value inside is `None` if
        /// no thread runs.
        current_thread: Diag<Option<ThreadSummary>>,
        /// The thread selected to run next. The value inside is `None` if there
        /// is no next thread.
        next_thread: Diag<Option<ThreadSummary>>,
        /// The processor's idle thread.
        idle_thread: Diag<Option<ThreadSummary>>,
        /// The first frames of the running thread. `None` if stacks were not
        /// requested.
        short_stack: Option<Diag<Vec<execution::StackFrame>>>,
    }

    /// The running threads of all processors (`!running`).
    RunningProcessors {
        processors: Vec<RunningProcessor>,
    }

    /// A thread on a dispatcher ready queue.
    ReadyThread {
        /// The `_KTHREAD` linked on the queue.
        kthread: VirtAddr,
        /// The decoded thread.
        thread: Diag<ThreadSummary>,
    }

    /// The ready list of one processor for one priority.
    ReadyQueue {
        processor: u16,
        priority: u8,
        entries: Vec<ReadyThread>,
        /// How the list walk ended.
        termination: ListEnd,
    }

    /// A processor or queue read that failed during a scheduler walk.
    SchedulerError {
        /// The processor of the error, if there is one.
        processor: Option<u16>,
        /// The queue of the error, if there is one.
        queue: Option<u16>,
        message: String,
    }

    /// The dispatcher ready queues (`!ready`).
    ReadyQueues {
        /// The queues that are not empty.
        queues: Vec<ReadyQueue>,
        /// The total number of threads in `queues`.
        total: usize,
        /// Whether the walk stopped at its entry limit.
        truncated: bool,
        errors: Vec<SchedulerError>,
    }

    /// A queued `_KDPC`.
    Dpc {
        address: VirtAddr,
        /// `DeferredRoutine`.
        deferred_routine: Diag<Option<VirtAddr>>,
        /// `deferred_routine` as a symbol, if it resolves to one.
        deferred_routine_symbol: Diag<Option<String>>,
        /// `DeferredContext`.
        context: Diag<Option<VirtAddr>>,
        /// `Importance`.
        importance: Diag<u8>,
    }

    /// One of a processor's DPC queues.
    DpcQueue {
        processor: u16,
        /// 0 for the normal queue, 1 for the threaded queue.
        queue: u8,
        entries: Vec<Dpc>,
        /// How the list walk ended.
        termination: ListEnd,
    }

    /// The queued DPCs of all processors (`!dpcs`).
    DpcQueues {
        /// The queues that are not empty.
        queues: Vec<DpcQueue>,
        /// The total number of DPCs in `queues`.
        total: usize,
        /// Whether the walk stopped at its entry limit.
        truncated: bool,
        errors: Vec<SchedulerError>,
    }

    /// A `_KTIMER` and its decoded DPC.
    KernelTimer {
        address: VirtAddr,
        /// `DueTime`, the interrupt time when the timer expires (see
        /// `TargetTime.interrupt_time`).
        due_time: Diag<Hex>,
        /// `Period` in milliseconds. 0 for a one-shot timer.
        period: Diag<u32>,
        /// `Dpc` in the encoded form that the kernel stores.
        dpc_encoded: Diag<Option<VirtAddr>>,
        /// The decoded `_KDPC` address. The value inside is `None` if the timer
        /// has no DPC.
        dpc: Diag<Option<VirtAddr>>,
        /// The DPC's `DeferredRoutine`.
        dpc_routine: Diag<Option<VirtAddr>>,
        /// `dpc_routine` as a symbol, if it resolves to one.
        dpc_routine_symbol: Diag<Option<String>>,
    }

    /// A timer in the timer table of a processor.
    TimerTableEntry {
        processor: u16,
        /// The index of the timer-table bucket.
        bucket: u16,
        timer: KernelTimer,
    }

    /// A timer-table bucket whose list walk did not end at its head.
    TimerBucketEnd {
        processor: u16,
        bucket: u16,
        termination: ListEnd,
    }

    /// The timer tables of all processors (`!timer`).
    TimerTable {
        /// The interrupt time (`KUSER_SHARED_DATA.InterruptTime`) when ntoseye
        /// read the tables. The `due_time` of each entry uses this time scale.
        interrupt_time: Diag<Hex>,
        entries: Vec<TimerTableEntry>,
        /// The buckets whose walk did not end normally.
        terminations: Vec<TimerBucketEnd>,
        /// The number of timers in `entries`.
        total: usize,
        /// Whether the walk stopped at its entry limit.
        truncated: bool,
        errors: Vec<SchedulerError>,
    }

    /// The thread or process that `!apc` inspects.
    ApcSelection {
        /// `thread`, `process`, or `number`. A `number` is not yet resolved to
        /// a thread or a process.
        kind: &'static str,
        /// The given value: an ETHREAD, KTHREAD, or TID, or a PID or EPROCESS.
        value: Hex,
    }

    /// A queued `_KAPC`.
    Apc {
        address: VirtAddr,
        /// `KernelRoutine`.
        kernel_routine: Diag<Option<VirtAddr>>,
        /// `kernel_routine` as a symbol, if it resolves to one.
        kernel_routine_symbol: Diag<Option<String>>,
        /// `NormalRoutine`. The value inside is `None` for a special kernel APC.
        normal_routine: Diag<Option<VirtAddr>>,
        /// `normal_routine` as a symbol, if it resolves to one.
        normal_routine_symbol: Diag<Option<String>>,
    }

    /// The kernel-mode and user-mode APC queues of a thread.
    ApcThread {
        thread: ThreadSummary,
        kernel: Vec<Apc>,
        user: Vec<Apc>,
        /// How the kernel-mode list walk ended.
        kernel_termination: ListEnd,
        /// How the user-mode list walk ended.
        user_termination: ListEnd,
        /// The error, if ntoseye could not read the APC state of the thread.
        state_error: Option<String>,
    }

    /// The APC queues of all threads, of one process, or of one thread
    /// (`!apc`).
    ApcQueues {
        /// `all`, `current_thread`, or the selected thread or process.
        selector: ApcSelectorValue,
        threads: Vec<ApcThread>,
        /// The total number of APCs in `threads`.
        total: usize,
        /// Whether the walk stopped at its entry limit.
        truncated: bool,
        /// The error, if ntoseye could not resolve the APC layout.
        layout_error: Option<String>,
    }

    /// The state and walked stack of a thread (`!stacks`).
    ThreadStack {
        thread: ThreadSummary,
        /// The symbol of the top frame.
        top_symbol: Diag<Option<String>>,
        /// The frames, innermost first. Level 0 has the top frame, level 1 has
        /// up to 32 frames, and level 2 has up to 64 frames.
        frames: Vec<execution::StackFrame>,
        /// The number of frames past the walk limit, which are not listed.
        truncated: usize,
        /// The error, if the stack walk failed.
        error: Option<String>,
    }

    /// Threads with their states and stacks (`!stacks`).
    ThreadStacks {
        /// The detail level (0, 1, or 2), which sets the frame limit of the
        /// walk.
        level: u8,
        /// The symbol or module filter, if you gave one.
        filter: Option<String>,
        scanned_threads: usize,
        displayed_threads: usize,
        /// Whether an interrupt stopped the walk before it finished.
        interrupted: bool,
        threads: Vec<ThreadStack>,
    }

    /// A thread whose stack walk failed, so ntoseye could not search or group
    /// it.
    UnwalkedThread {
        thread: ThreadSummary,
        /// The reason the walk failed.
        error: String,
    }

    /// A thread with a stack frame that matches the `!findstack` pattern.
    FindStackThread {
        thread: ThreadSummary,
        /// The number of frames that matched.
        match_count: usize,
        /// The frames that matched. `None` at level 0.
        matching_frames: Option<Vec<execution::StackFrame>>,
        /// The whole walked stack, innermost first. `None` below level 2.
        frames: Option<Vec<execution::StackFrame>>,
        /// The number of frames past the walk limit, which ntoseye did not
        /// search. `None` below level 2.
        truncated: Option<usize>,
    }

    /// Threads with a stack frame that matches a symbol or module
    /// (`!findstack`).
    FindStack {
        pattern: String,
        /// The detail level. 0 counts the matches, 1 lists them, and 2 adds the
        /// whole stacks.
        level: u8,
        scanned_threads: usize,
        /// Whether an interrupt stopped the walk before it finished.
        interrupted: bool,
        threads: Vec<FindStackThread>,
        unwalked: Vec<UnwalkedThread>,
    }

    /// An `_IO_WORKITEM` that `IoQueueWorkItem` queued. Its work item runs
    /// `nt!IopProcessWorkItem`, which calls `routine`.
    IoWorkItem {
        /// The `_IO_WORKITEM` that holds the queued `_WORK_QUEUE_ITEM`.
        address: VirtAddr,
        routine: VirtAddr,
        /// `routine` as a symbol, when one resolves.
        routine_symbol: Option<String>,
        /// The device or driver object that the item was allocated for.
        io_object: VirtAddr,
        context: VirtAddr,
    }

    /// A pending `_WORK_QUEUE_ITEM`.
    WorkItem {
        address: VirtAddr,
        /// `WorkerRoutine`.
        routine: VirtAddr,
        /// `routine` as a symbol, when one resolves.
        routine_symbol: Option<String>,
        parameter: VirtAddr,
        /// The I/O work item that owns this item, if `IoQueueWorkItem` queued
        /// it.
        io_work_item: Option<IoWorkItem>,
    }

    /// One of the 32 priority lists of a work queue.
    WorkQueuePriority {
        priority: u8,
        /// The `WORK_QUEUE_TYPE`s that `ExQueueWorkItem` maps to this priority.
        queue_types: Vec<&'static str>,
        /// `CurrentCount[priority]`, the number of threads that run an item of
        /// this priority.
        current_count: i32,
        /// The pending work items (key `items`).
        work_items: Vec<WorkItem> => "items",
        /// How the list walk ended.
        termination: ListEnd,
    }

    /// A thread that serves a work queue.
    WorkerThread {
        kthread: VirtAddr,
        thread: Diag<ThreadSummary>,
        /// The stack of the thread. `None` if stacks were not requested or the
        /// thread did not decode.
        stack: Option<Diag<Vec<execution::StackFrame>>>,
    }

    /// An `_EX_WORK_QUEUE`.
    WorkQueue {
        address: VirtAddr,
        /// The `_EPARTITION` it belongs to.
        partition: VirtAddr,
        /// The NUMA node.
        node: u16,
        queue_index: u32,
        /// The name of `queue_index`, if it is a known index.
        queue_index_name: Option<String>,
        items_processed: u32,
        items_processed_last_pass: u32,
        thread_count: i32,
        min_threads: u64,
        max_threads: i32,
        /// `_KPRIQUEUE.MaximumCount`, the maximum number of threads that can run
        /// items at the same time.
        concurrency: u32,
        /// The number of items on all 32 priority lists, including items that
        /// are not listed.
        pending: u64,
        /// The priority lists that hold items or have running threads, limited
        /// to the requested priorities.
        priorities: Vec<WorkQueuePriority>,
        threads: Vec<WorkerThread>,
        /// How the worker-thread list walk ended.
        threads_termination: ListEnd,
    }

    /// All executive worker queues (`!exqueue`).
    WorkQueues {
        /// The `!exqueue` flags.
        flags: Hex,
        /// The priorities that flags 0x10, 0x20, and 0x40 selected. `None` means
        /// all priorities.
        priority_filter: Option<Vec<u8>>,
        queues: Vec<WorkQueue>,
        /// The partitions or queues that ntoseye could not decode.
        errors: Vec<String>,
    }

    /// Threads whose walked stacks have the same frames and truncation.
    UniqStackGroup {
        thread_count: usize,
        threads: Vec<ThreadSummary>,
        /// The frames of the first thread, innermost first. The other threads
        /// have the same instruction pointers, but their stack pointers can
        /// differ.
        frames: Vec<execution::StackFrame>,
        /// The number of frames past the walk limit, which ntoseye did not
        /// compare.
        truncated: usize,
    }

    /// The threads that `!uniqstack` grouped.
    UniqStackScope {
        /// `all` or `process`.
        kind: &'static str,
        /// The process ID. `None` for `all`.
        pid: Option<u64>,
        /// The image name of the process. `None` for `all`.
        name: Option<String>,
    }

    /// Threads grouped by identical call stacks (`!uniqstack`).
    UniqStacks {
        scope: UniqStackScope,
        scanned_threads: usize,
        /// The number of threads whose stacks ntoseye walked and grouped.
        walked_threads: usize,
        /// Whether an interrupt stopped the walk before it finished.
        interrupted: bool,
        /// The groups, in the order that ntoseye walked their first threads.
        groups: Vec<UniqStackGroup>,
        unwalked: Vec<UnwalkedThread>,
    }
}

unions! {
    /// `!apc`'s selector: a name for the whole-walk selections, an
    /// [`ApcSelection`] for a thread or process.
    ApcSelectorValue {
        Name(&'static str),
        Selection(ApcSelection),
    }
}

fn optional_thread(value: &DiagnosticValue<Option<ThreadInfo>>) -> DiagnosticValue<Option<ThreadSummary>> {
    value.map(|thread| thread.as_ref().map(|thread| thread_summary(thread, None)))
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

pub fn running(detail: &detail::RunningDetail) -> RunningProcessors {
    RunningProcessors {
        processors: detail
            .processors
            .iter()
            .map(|processor| RunningProcessor {
                index: processor.index,
                kpcr: processor.kpcr.clone(),
                prcb: processor.prcb.clone(),
                current_thread: optional_thread(&processor.current_thread),
                next_thread: optional_thread(&processor.next_thread),
                idle_thread: optional_thread(&processor.idle_thread),
                short_stack: processor
                        .short_stack
                        .as_ref()
                        .map(|stack| stack.map(|stack| stack_frames(stack))),
            })
            .collect(),
    }
}

pub fn ready_queues(detail: &detail::ReadyQueuesDetail) -> ReadyQueues {
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
                        kthread: entry.kthread,
                        thread: entry.thread.map(|thread| thread_summary(thread, None)),
                    })
                    .collect(),
                termination: list_termination(&queue.termination),
            })
            .collect(),
        total: detail.total,
        truncated: detail.truncated,
        errors: scheduler_errors(&detail.errors),
    }
}

fn dpc(dpc: &detail::DpcDetail) -> Dpc {
    Dpc {
        address: dpc.address,
        deferred_routine: dpc.deferred_routine.clone(),
        deferred_routine_symbol: dpc.deferred_routine_symbol.clone(),
        context: dpc.context.clone(),
        importance: dpc.importance.clone(),
    }
}

pub fn dpc_queues(detail: &detail::DpcQueuesDetail) -> DpcQueues {
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
}

pub fn timer(timer: &detail::TimerDetail) -> KernelTimer {
    KernelTimer {
        address: timer.address,
        due_time: timer.due_time.clone(),
        period: timer.period.clone(),
        dpc_encoded: timer.dpc_encoded.clone(),
        dpc: timer.dpc.clone(),
        dpc_routine: timer.dpc_routine.clone(),
        dpc_routine_symbol: timer.dpc_routine_symbol.clone(),
    }
}

pub fn timer_list(detail: &detail::TimerListDetail) -> TimerTable {
    TimerTable {
        interrupt_time: detail.interrupt_time.clone(),
        entries: detail
            .entries
            .iter()
            .map(|entry| TimerTableEntry {
                processor: entry.processor,
                bucket: entry.bucket,
                timer: timer(&entry.timer),
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
        value,
    })
}

fn apc(apc: &detail::ApcDetail) -> Apc {
    Apc {
        address: apc.address,
        kernel_routine: apc.kernel_routine.clone(),
        kernel_routine_symbol: apc.kernel_routine_symbol.clone(),
        normal_routine: apc.normal_routine.clone(),
        normal_routine_symbol: apc.normal_routine_symbol.clone(),
    }
}

pub fn apcs(detail: &detail::ApcListDetail) -> ApcQueues {
    ApcQueues {
        selector: apc_selector(detail.selector),
        threads: detail
            .threads
            .iter()
            .map(|thread| ApcThread {
                thread: thread_summary(&thread.thread, None),
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
}

pub fn stacks(detail: &detail::StacksDetail) -> ThreadStacks {
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
                thread: thread_summary(&thread.thread, thread.active_vcpu.as_deref()),
                top_symbol: thread.top_symbol.clone(),
                frames: stack_frames(&thread.frames),
                truncated: thread.truncated,
                error: thread.error.clone(),
            })
            .collect(),
    }
}

fn unwalked_threads(threads: &[detail::UnwalkedThread]) -> Vec<UnwalkedThread> {
    threads
        .iter()
        .map(|thread| UnwalkedThread {
            thread: thread_summary(&thread.thread, None),
            error: thread.error.clone(),
        })
        .collect()
}

fn findstack_thread(thread: &detail::FindStackThread, level: u8) -> FindStackThread {
    let whole = level >= 2;
    FindStackThread {
        thread: thread_summary(&thread.thread, thread.active_vcpu.as_deref()),
        match_count: thread.matches.len(),
        matching_frames: (level >= 1).then(|| {
            thread
                .matches
                .iter()
                .map(|&index| stack_frame(index, &thread.stack.frames[index]))
                .collect()
        }),
        frames: whole.then(|| stack_frames(&thread.stack.frames)),
        truncated: whole.then_some(thread.stack.truncated),
    }
}

pub fn findstack(detail: &detail::FindStackDetail) -> FindStack {
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
}

fn work_item(item: &workqueue::WorkItemDetail) -> WorkItem {
    WorkItem {
        address: item.address,
        routine: item.routine,
        routine_symbol: item.routine_symbol.clone(),
        parameter: item.parameter,
        io_work_item: item.io.as_ref().map(|io| IoWorkItem {
            address: io.address,
            routine: io.routine,
            routine_symbol: io.routine_symbol.clone(),
            io_object: io.io_object,
            context: io.context,
        }),
    }
}

fn work_queue_priority(priority: &workqueue::WorkQueuePriority) -> WorkQueuePriority {
    WorkQueuePriority {
        priority: priority.priority,
        queue_types: priority.queue_types.clone(),
        current_count: priority.current_count,
        work_items: priority.items.iter().map(work_item).collect(),
        termination: list_termination(&priority.termination),
    }
}

fn work_queue(queue: &workqueue::WorkQueueDetail) -> WorkQueue {
    WorkQueue {
        address: queue.address,
        partition: queue.partition,
        node: queue.node,
        queue_index: queue.queue_index,
        queue_index_name: queue.queue_index_name.clone(),
        items_processed: queue.items_processed,
        items_processed_last_pass: queue.items_processed_last_pass,
        thread_count: queue.thread_count,
        min_threads: queue.min_threads,
        max_threads: queue.max_threads,
        concurrency: queue.concurrency,
        pending: queue.pending,
        priorities: queue.priorities.iter().map(work_queue_priority).collect(),
        threads: queue
            .threads
            .iter()
            .map(|worker| WorkerThread {
                kthread: worker.kthread,
                thread: worker.thread.map(|info| thread_summary(info, None)),
                stack: worker
                    .stack
                    .as_ref()
                    .map(|stack| stack.map(|stack| stack_frames(stack))),
            })
            .collect(),
        threads_termination: list_termination(&queue.threads_termination),
    }
}

pub fn work_queues(detail: &ExQueueDetail) -> WorkQueues {
    WorkQueues {
        flags: detail.flags,
        priority_filter: detail.priority_filter.clone(),
        queues: detail.queues.iter().map(work_queue).collect(),
        errors: detail.errors.clone(),
    }
}

pub fn uniqstack(detail: &detail::UniqStackDetail) -> UniqStacks {
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
                threads: group
                    .threads
                    .iter()
                    .map(|thread| thread_summary(thread, None))
                    .collect(),
                frames: stack_frames(&group.stack.frames),
                truncated: group.stack.truncated,
            })
            .collect(),
        unwalked: unwalked_threads(&detail.unwalked),
    }
}
