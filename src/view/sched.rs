//! sched: [`View`] builders for the structured inspectors.

use ntoseye_macros::record;

use super::execution::{self, stack_frame, stack_frames};
use super::list::{ListEnd, list_termination};
use super::process::{ThreadSummary, thread_summary};
use crate::target::sched::{self as detail, ApcSelector};
use crate::target::workqueue::{self, ExQueueDetail};
use crate::target::{DiagnosticValue, ThreadInfo};
use crate::types::VirtAddr;

/// A processor's running, next, and idle threads (`!running`).
#[record]
pub struct RunningProcessor {
    /// The processor number.
    pub index: u16,
    pub kpcr: DiagnosticValue<VirtAddr>,
    pub prcb: DiagnosticValue<VirtAddr>,
    /// The thread that runs on the processor. The value inside is `None` if
    /// no thread runs.
    pub current_thread: DiagnosticValue<Option<ThreadSummary>>,
    /// The thread selected to run next. The value inside is `None` if there
    /// is no next thread.
    pub next_thread: DiagnosticValue<Option<ThreadSummary>>,
    /// The processor's idle thread.
    pub idle_thread: DiagnosticValue<Option<ThreadSummary>>,
    /// The first frames of the running thread. `None` if stacks were not
    /// requested.
    pub short_stack: Option<DiagnosticValue<Vec<execution::StackFrame>>>,
}

/// The running threads of all processors (`!running`).
#[record]
pub struct RunningProcessors {
    pub processors: Vec<RunningProcessor>,
}

/// A thread on a dispatcher ready queue.
#[record]
pub struct ReadyThread {
    /// The `_KTHREAD` linked on the queue.
    pub kthread: VirtAddr,
    /// The decoded thread.
    pub thread: DiagnosticValue<ThreadSummary>,
}

/// The ready list of one processor for one priority.
#[record]
pub struct ReadyQueue {
    pub processor: u16,
    pub priority: u8,
    pub entries: Vec<ReadyThread>,
    /// How the list walk ended.
    pub termination: ListEnd,
}

/// A processor or queue read that failed during a scheduler walk.
#[record]
pub struct SchedulerError {
    /// The processor of the error, if there is one.
    pub processor: Option<u16>,
    /// The queue of the error, if there is one.
    pub queue: Option<u16>,
    pub message: String,
}

/// The dispatcher ready queues (`!ready`).
#[record]
pub struct ReadyQueues {
    /// The queues that are not empty.
    pub queues: Vec<ReadyQueue>,
    /// The total number of threads in `queues`.
    pub total: usize,
    /// Whether the walk stopped at its entry limit.
    pub truncated: bool,
    pub errors: Vec<SchedulerError>,
}

/// A queued `_KDPC`.
#[record]
pub struct Dpc {
    pub address: VirtAddr,
    /// `DeferredRoutine`.
    pub deferred_routine: DiagnosticValue<Option<VirtAddr>>,
    /// `deferred_routine` as a symbol, if it resolves to one.
    pub deferred_routine_symbol: DiagnosticValue<Option<String>>,
    /// `DeferredContext`.
    pub context: DiagnosticValue<Option<VirtAddr>>,
    /// `Importance`.
    pub importance: DiagnosticValue<u8>,
}

/// One of a processor's DPC queues.
#[record]
pub struct DpcQueue {
    pub processor: u16,
    /// 0 for the normal queue, 1 for the threaded queue.
    pub queue: u8,
    pub entries: Vec<Dpc>,
    /// How the list walk ended.
    pub termination: ListEnd,
}

/// The queued DPCs of all processors (`!dpcs`).
#[record]
pub struct DpcQueues {
    /// The queues that are not empty.
    pub queues: Vec<DpcQueue>,
    /// The total number of DPCs in `queues`.
    pub total: usize,
    /// Whether the walk stopped at its entry limit.
    pub truncated: bool,
    pub errors: Vec<SchedulerError>,
}

/// A `_KTIMER` and its decoded DPC.
#[record]
pub struct KernelTimer {
    pub address: VirtAddr,
    /// `DueTime`, the interrupt time when the timer expires (see
    /// `TargetTime.interrupt_time`).
    #[record(hex)]
    pub due_time: DiagnosticValue<u64>,
    /// `Period` in milliseconds. 0 for a one-shot timer.
    pub period: DiagnosticValue<u32>,
    /// `Dpc` in the encoded form that the kernel stores.
    pub dpc_encoded: DiagnosticValue<Option<VirtAddr>>,
    /// The decoded `_KDPC` address. The value inside is `None` if the timer
    /// has no DPC.
    pub dpc: DiagnosticValue<Option<VirtAddr>>,
    /// The DPC's `DeferredRoutine`.
    pub dpc_routine: DiagnosticValue<Option<VirtAddr>>,
    /// `dpc_routine` as a symbol, if it resolves to one.
    pub dpc_routine_symbol: DiagnosticValue<Option<String>>,
}

/// A timer in the timer table of a processor.
#[record]
pub struct TimerTableEntry {
    pub processor: u16,
    /// The index of the timer-table bucket.
    pub bucket: u16,
    pub timer: KernelTimer,
}

/// A timer-table bucket whose list walk did not end at its head.
#[record]
pub struct TimerBucketEnd {
    pub processor: u16,
    pub bucket: u16,
    pub termination: ListEnd,
}

/// The timer tables of all processors (`!timer`).
#[record]
pub struct TimerTable {
    /// The interrupt time (`KUSER_SHARED_DATA.InterruptTime`) when ntoseye
    /// read the tables. The `due_time` of each entry uses this time scale.
    #[record(hex)]
    pub interrupt_time: DiagnosticValue<u64>,
    pub entries: Vec<TimerTableEntry>,
    /// The buckets whose walk did not end normally.
    pub terminations: Vec<TimerBucketEnd>,
    /// The number of timers in `entries`.
    pub total: usize,
    /// Whether the walk stopped at its entry limit.
    pub truncated: bool,
    pub errors: Vec<SchedulerError>,
}

/// The thread or process that `!apc` inspects.
#[record]
pub struct ApcSelection {
    /// `thread`, `process`, or `number`. A `number` is not yet resolved to
    /// a thread or a process.
    pub kind: &'static str,
    /// The given value: an ETHREAD, KTHREAD, or TID, or a PID or EPROCESS.
    #[record(hex)]
    pub value: u64,
}

/// A queued `_KAPC`.
#[record]
pub struct Apc {
    pub address: VirtAddr,
    /// `KernelRoutine`.
    pub kernel_routine: DiagnosticValue<Option<VirtAddr>>,
    /// `kernel_routine` as a symbol, if it resolves to one.
    pub kernel_routine_symbol: DiagnosticValue<Option<String>>,
    /// `NormalRoutine`. The value inside is `None` for a special kernel APC.
    pub normal_routine: DiagnosticValue<Option<VirtAddr>>,
    /// `normal_routine` as a symbol, if it resolves to one.
    pub normal_routine_symbol: DiagnosticValue<Option<String>>,
}

/// The kernel-mode and user-mode APC queues of a thread.
#[record]
pub struct ApcThread {
    pub thread: ThreadSummary,
    pub kernel: Vec<Apc>,
    pub user: Vec<Apc>,
    /// How the kernel-mode list walk ended.
    pub kernel_termination: ListEnd,
    /// How the user-mode list walk ended.
    pub user_termination: ListEnd,
    /// The error, if ntoseye could not read the APC state of the thread.
    pub state_error: Option<String>,
}

/// The APC queues of all threads, of one process, or of one thread
/// (`!apc`).
#[record]
pub struct ApcQueues {
    /// `all`, `current_thread`, or the selected thread or process.
    pub selector: ApcSelectorValue,
    pub threads: Vec<ApcThread>,
    /// The total number of APCs in `threads`.
    pub total: usize,
    /// Whether the walk stopped at its entry limit.
    pub truncated: bool,
    /// The error, if ntoseye could not resolve the APC layout.
    pub layout_error: Option<String>,
}

/// The state and walked stack of a thread (`!stacks`).
#[record]
pub struct ThreadStack {
    pub thread: ThreadSummary,
    /// The symbol of the top frame.
    pub top_symbol: DiagnosticValue<Option<String>>,
    /// The frames, innermost first. Level 0 has the top frame, level 1 has
    /// up to 32 frames, and level 2 has up to 64 frames.
    pub frames: Vec<execution::StackFrame>,
    /// The number of frames past the walk limit, which are not listed.
    pub truncated: usize,
    /// The error, if the stack walk failed.
    pub error: Option<String>,
}

/// Threads with their states and stacks (`!stacks`).
#[record]
pub struct ThreadStacks {
    /// The detail level (0, 1, or 2), which sets the frame limit of the
    /// walk.
    pub level: u8,
    /// The symbol or module filter, if you gave one.
    pub filter: Option<String>,
    pub scanned_threads: usize,
    pub displayed_threads: usize,
    /// Whether an interrupt stopped the walk before it finished.
    pub interrupted: bool,
    pub threads: Vec<ThreadStack>,
}

/// A thread whose stack walk failed, so ntoseye could not search or group
/// it.
#[record]
pub struct UnwalkedThread {
    pub thread: ThreadSummary,
    /// The reason the walk failed.
    pub error: String,
}

/// A thread with a stack frame that matches the `!findstack` pattern.
#[record]
pub struct FindStackThread {
    pub thread: ThreadSummary,
    /// The number of frames that matched.
    pub match_count: usize,
    /// The frames that matched. `None` at level 0.
    pub matching_frames: Option<Vec<execution::StackFrame>>,
    /// The whole walked stack, innermost first. `None` below level 2.
    pub frames: Option<Vec<execution::StackFrame>>,
    /// The number of frames past the walk limit, which ntoseye did not
    /// search. `None` below level 2.
    pub truncated: Option<usize>,
}

/// Threads with a stack frame that matches a symbol or module
/// (`!findstack`).
#[record]
pub struct FindStack {
    pub pattern: String,
    /// The detail level. 0 counts the matches, 1 lists them, and 2 adds the
    /// whole stacks.
    pub level: u8,
    pub scanned_threads: usize,
    /// Whether an interrupt stopped the walk before it finished.
    pub interrupted: bool,
    pub threads: Vec<FindStackThread>,
    pub unwalked: Vec<UnwalkedThread>,
}

/// An `_IO_WORKITEM` that `IoQueueWorkItem` queued. Its work item runs
/// `nt!IopProcessWorkItem`, which calls `routine`.
#[record]
pub struct IoWorkItem {
    /// The `_IO_WORKITEM` that holds the queued `_WORK_QUEUE_ITEM`.
    pub address: VirtAddr,
    pub routine: VirtAddr,
    /// `routine` as a symbol, when one resolves.
    pub routine_symbol: Option<String>,
    /// The device or driver object that the item was allocated for.
    pub io_object: VirtAddr,
    pub context: VirtAddr,
}

/// A pending `_WORK_QUEUE_ITEM`.
#[record]
pub struct WorkItem {
    pub address: VirtAddr,
    /// `WorkerRoutine`.
    pub routine: VirtAddr,
    /// `routine` as a symbol, when one resolves.
    pub routine_symbol: Option<String>,
    pub parameter: VirtAddr,
    /// The I/O work item that owns this item, if `IoQueueWorkItem` queued
    /// it.
    pub io_work_item: Option<IoWorkItem>,
}

/// One of the 32 priority lists of a work queue.
#[record]
pub struct WorkQueuePriority {
    pub priority: u8,
    /// The `WORK_QUEUE_TYPE`s that `ExQueueWorkItem` maps to this priority.
    pub queue_types: Vec<&'static str>,
    /// `CurrentCount[priority]`, the number of threads that run an item of
    /// this priority.
    pub current_count: i32,
    /// The pending work items (key `items`).
    #[record(rename = "items")]
    pub work_items: Vec<WorkItem>,
    /// How the list walk ended.
    pub termination: ListEnd,
}

/// A thread that serves a work queue.
#[record]
pub struct WorkerThread {
    pub kthread: VirtAddr,
    pub thread: DiagnosticValue<ThreadSummary>,
    /// The stack of the thread. `None` if stacks were not requested or the
    /// thread did not decode.
    pub stack: Option<DiagnosticValue<Vec<execution::StackFrame>>>,
}

/// An `_EX_WORK_QUEUE`.
#[record]
pub struct WorkQueue {
    pub address: VirtAddr,
    /// The `_EPARTITION` it belongs to.
    pub partition: VirtAddr,
    /// The NUMA node.
    pub node: u16,
    pub queue_index: u32,
    /// The name of `queue_index`, if it is a known index.
    pub queue_index_name: Option<String>,
    pub items_processed: u32,
    pub items_processed_last_pass: u32,
    pub thread_count: i32,
    pub min_threads: u64,
    pub max_threads: i32,
    /// `_KPRIQUEUE.MaximumCount`, the maximum number of threads that can run
    /// items at the same time.
    pub concurrency: u32,
    /// The number of items on all 32 priority lists, including items that
    /// are not listed.
    pub pending: u64,
    /// The priority lists that hold items or have running threads, limited
    /// to the requested priorities.
    pub priorities: Vec<WorkQueuePriority>,
    pub threads: Vec<WorkerThread>,
    /// How the worker-thread list walk ended.
    pub threads_termination: ListEnd,
}

/// All executive worker queues (`!exqueue`).
#[record]
pub struct WorkQueues {
    /// The `!exqueue` flags.
    #[record(hex)]
    pub flags: u64,
    /// The priorities that flags 0x10, 0x20, and 0x40 selected. `None` means
    /// all priorities.
    pub priority_filter: Option<Vec<u8>>,
    pub queues: Vec<WorkQueue>,
    /// The partitions or queues that ntoseye could not decode.
    pub errors: Vec<String>,
}

/// Threads whose walked stacks have the same frames and truncation.
#[record]
pub struct UniqStackGroup {
    pub thread_count: usize,
    pub threads: Vec<ThreadSummary>,
    /// The frames of the first thread, innermost first. The other threads
    /// have the same instruction pointers, but their stack pointers can
    /// differ.
    pub frames: Vec<execution::StackFrame>,
    /// The number of frames past the walk limit, which ntoseye did not
    /// compare.
    pub truncated: usize,
}

/// The threads that `!uniqstack` grouped.
#[record]
pub struct UniqStackScope {
    /// `all` or `process`.
    pub kind: &'static str,
    /// The process ID. `None` for `all`.
    pub pid: Option<u64>,
    /// The image name of the process. `None` for `all`.
    pub name: Option<String>,
}

/// Threads grouped by identical call stacks (`!uniqstack`).
#[record]
pub struct UniqStacks {
    pub scope: UniqStackScope,
    pub scanned_threads: usize,
    /// The number of threads whose stacks ntoseye walked and grouped.
    pub walked_threads: usize,
    /// Whether an interrupt stopped the walk before it finished.
    pub interrupted: bool,
    /// The groups, in the order that ntoseye walked their first threads.
    pub groups: Vec<UniqStackGroup>,
    pub unwalked: Vec<UnwalkedThread>,
}

/// `!apc`'s selector: a name for the whole-walk selections, an
/// [`ApcSelection`] for a thread or process.
#[record]
pub enum ApcSelectorValue {
    Name(&'static str),
    Selection(ApcSelection),
}

fn optional_thread(
    value: &DiagnosticValue<Option<ThreadInfo>>,
) -> DiagnosticValue<Option<ThreadSummary>> {
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
    ApcSelectorValue::Selection(ApcSelection { kind, value })
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
