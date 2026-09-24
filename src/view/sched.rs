//! sched: [`View`] builders for the structured inspectors.

use super::{View, diagnostic, list_termination};
use crate::target::sched::{
    ApcDetail, ApcListDetail, ApcSelector, ApcThread, DpcDetail, DpcQueue, DpcQueuesDetail,
    ReadyQueue, ReadyQueueEntry, ReadyQueuesDetail, RunningDetail, RunningProcessor,
    SchedulerError, StackFrameDetail, StackThreadDetail, StacksDetail, ThreadSummary,
    TimerBucketTermination, TimerDetail, TimerListDetail, TimerListEntry,
};
use crate::target::{DiagnosticValue, kthread_state_name, wait_reason_name};

fn thread_summary(thread: &ThreadSummary) -> View {
    View::Object(vec![
        ("ethread", View::Hex(thread.ethread.0)),
        ("kthread", View::Hex(thread.kthread.0)),
        ("tid", diagnostic(&thread.tid, |value| View::OptNum(*value))),
        ("pid", diagnostic(&thread.pid, |value| View::OptNum(*value))),
        (
            "process_name",
            diagnostic(&thread.process_name, |value| View::OptStr(value.clone())),
        ),
        (
            "state",
            diagnostic(&thread.state, |value| View::OptNum(value.map(u64::from))),
        ),
        (
            "state_name",
            diagnostic(&thread.state, |value| {
                View::OptStr(value.map(|state| kthread_state_name(state).to_string()))
            }),
        ),
        (
            "wait_reason",
            diagnostic(&thread.wait_reason, |value| {
                View::OptNum(value.map(u64::from))
            }),
        ),
        (
            "wait_reason_name",
            diagnostic(&thread.wait_reason, |value| {
                View::OptStr(value.map(|reason| wait_reason_name(reason).to_string()))
            }),
        ),
        (
            "priority",
            diagnostic(&thread.priority, |value| View::OptNum(value.map(u64::from))),
        ),
    ])
}

fn frame(frame: &StackFrameDetail) -> View {
    View::Object(vec![
        ("sp", View::Hex(frame.sp.0)),
        ("ip", View::Hex(frame.ip.0)),
        ("symbol", View::Str(frame.symbol.clone())),
    ])
}

fn running_thread(value: &DiagnosticValue<Option<ThreadSummary>>) -> View {
    diagnostic(value, |thread| {
        thread.as_ref().map_or(View::Null, thread_summary)
    })
}

fn running_processor(processor: &RunningProcessor) -> View {
    let mut fields = vec![
        ("index", View::Num(processor.index.into())),
        (
            "kpcr",
            diagnostic(&processor.kpcr, |address| View::Hex(address.0)),
        ),
        (
            "prcb",
            diagnostic(&processor.prcb, |address| View::Hex(address.0)),
        ),
        ("current_thread", running_thread(&processor.current_thread)),
        ("next_thread", running_thread(&processor.next_thread)),
        ("idle_thread", running_thread(&processor.idle_thread)),
    ];
    if let Some(stack) = &processor.short_stack {
        fields.push((
            "short_stack",
            diagnostic(stack, |frames| {
                View::List(frames.iter().map(frame).collect())
            }),
        ));
    }
    View::Object(fields)
}

/// Running processor rows; top-level key: `processors`.
pub fn running(detail: &RunningDetail) -> View {
    View::Object(vec![(
        "processors",
        View::List(detail.processors.iter().map(running_processor).collect()),
    )])
}

fn ready_entry(entry: &ReadyQueueEntry) -> View {
    View::Object(vec![
        ("kthread", View::Hex(entry.kthread.0)),
        (
            "thread",
            diagnostic(&entry.thread, |thread| {
                thread.as_ref().map_or(View::Null, thread_summary)
            }),
        ),
    ])
}

fn ready_queue(queue: &ReadyQueue) -> View {
    View::Object(vec![
        ("processor", View::Num(queue.processor.into())),
        ("priority", View::Num(queue.priority.into())),
        (
            "entries",
            View::List(queue.entries.iter().map(ready_entry).collect()),
        ),
        ("termination", list_termination(&queue.termination)),
    ])
}

fn scheduler_error(error: &SchedulerError) -> View {
    View::Object(vec![
        ("processor", View::OptNum(error.processor.map(u64::from))),
        ("queue", View::OptNum(error.queue.map(u64::from))),
        ("message", View::Str(error.message.clone())),
    ])
}

/// Dispatcher ready queues; top-level keys: `queues`, `total`, `truncated`, `errors`.
pub fn ready_queues(detail: &ReadyQueuesDetail) -> View {
    View::Object(vec![
        (
            "queues",
            View::List(detail.queues.iter().map(ready_queue).collect()),
        ),
        ("total", View::Num(detail.total as u64)),
        ("truncated", View::Bool(detail.truncated)),
        (
            "errors",
            View::List(detail.errors.iter().map(scheduler_error).collect()),
        ),
    ])
}

fn dpc(dpc: &DpcDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(dpc.address.0)),
        (
            "deferred_routine",
            diagnostic(&dpc.deferred_routine, |address| {
                View::OptHex(address.map(|address| address.0))
            }),
        ),
        (
            "deferred_routine_symbol",
            diagnostic(&dpc.deferred_routine_symbol, |symbol| {
                View::OptStr(symbol.clone())
            }),
        ),
        (
            "context",
            diagnostic(&dpc.context, |address| {
                View::OptHex(address.map(|address| address.0))
            }),
        ),
        (
            "importance",
            diagnostic(&dpc.importance, |importance| {
                View::OptNum(importance.map(u64::from))
            }),
        ),
    ])
}

fn dpc_queue(queue: &DpcQueue) -> View {
    View::Object(vec![
        ("processor", View::Num(queue.processor.into())),
        ("queue", View::Num(queue.queue.into())),
        (
            "entries",
            View::List(queue.entries.iter().map(dpc).collect()),
        ),
        ("termination", list_termination(&queue.termination)),
    ])
}

/// Deferred-procedure-call queues; top-level keys: `queues`, `total`, `truncated`, `errors`.
pub fn dpc_queues(detail: &DpcQueuesDetail) -> View {
    View::Object(vec![
        (
            "queues",
            View::List(detail.queues.iter().map(dpc_queue).collect()),
        ),
        ("total", View::Num(detail.total as u64)),
        ("truncated", View::Bool(detail.truncated)),
        (
            "errors",
            View::List(detail.errors.iter().map(scheduler_error).collect()),
        ),
    ])
}

fn timer_view(timer: &TimerDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(timer.address.0)),
        (
            "due_time",
            diagnostic(&timer.due_time, |value| View::Hex(*value)),
        ),
        (
            "period",
            diagnostic(&timer.period, |value| View::Num((*value).into())),
        ),
        (
            "dpc_encoded",
            diagnostic(&timer.dpc_encoded, |value| {
                View::OptHex(value.map(|address| address.0))
            }),
        ),
        (
            "dpc",
            diagnostic(&timer.dpc, |value| {
                View::OptHex(value.map(|address| address.0))
            }),
        ),
        (
            "dpc_routine",
            diagnostic(&timer.dpc_routine, |value| {
                View::OptHex(value.map(|address| address.0))
            }),
        ),
        (
            "dpc_routine_symbol",
            diagnostic(&timer.dpc_routine_symbol, |value| {
                View::OptStr(value.clone())
            }),
        ),
        (
            "interrupt_time",
            diagnostic(&timer.interrupt_time, |value| View::OptHex(*value)),
        ),
    ])
}

fn timer_entry(entry: &TimerListEntry) -> View {
    View::Object(vec![
        ("processor", View::Num(entry.processor.into())),
        ("bucket", View::Num(entry.bucket.into())),
        ("timer", timer_view(&entry.timer)),
    ])
}

fn timer_bucket_termination(entry: &TimerBucketTermination) -> View {
    View::Object(vec![
        ("processor", View::Num(entry.processor.into())),
        ("bucket", View::Num(entry.bucket.into())),
        ("termination", list_termination(&entry.termination)),
    ])
}

/// Kernel timer table rows; top-level keys: `interrupt_time`, `interrupt_time_source`, `entries`, `terminations`, `total`, `truncated`, `errors`.
pub fn timer_list(detail: &TimerListDetail) -> View {
    View::Object(vec![
        (
            "interrupt_time",
            diagnostic(&detail.interrupt_time, |value| View::OptHex(*value)),
        ),
        (
            "interrupt_time_source",
            View::OptStr(detail.interrupt_time_source.clone()),
        ),
        (
            "entries",
            View::List(detail.entries.iter().map(timer_entry).collect()),
        ),
        (
            "terminations",
            View::List(
                detail
                    .terminations
                    .iter()
                    .map(timer_bucket_termination)
                    .collect(),
            ),
        ),
        ("total", View::Num(detail.total as u64)),
        ("truncated", View::Bool(detail.truncated)),
        (
            "errors",
            View::List(detail.errors.iter().map(scheduler_error).collect()),
        ),
    ])
}

/// One `_KTIMER` plus its decoded DPC; top-level keys: `address`, `due_time`, `period`, `dpc_encoded`, `dpc`, `dpc_routine`, `dpc_routine_symbol`, `interrupt_time`.
pub fn timer(detail: &TimerDetail) -> View {
    timer_view(detail)
}

fn apc_selector(selector: ApcSelector) -> View {
    match selector {
        ApcSelector::CurrentThread => View::Str("current_thread".to_string()),
        ApcSelector::Thread(address) => View::Object(vec![
            ("kind", View::Str("thread".to_string())),
            ("value", View::Hex(address.0)),
        ]),
        ApcSelector::Process(value) => View::Object(vec![
            ("kind", View::Str("process".to_string())),
            ("value", View::Hex(value)),
        ]),
        ApcSelector::Number(value) => View::Object(vec![
            ("kind", View::Str("number".to_string())),
            ("value", View::Hex(value)),
        ]),
        ApcSelector::All => View::Str("all".to_string()),
    }
}

fn apc_detail(apc: &ApcDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(apc.address.0)),
        (
            "kernel_routine",
            diagnostic(&apc.kernel_routine, |address| {
                View::OptHex(address.map(|address| address.0))
            }),
        ),
        (
            "kernel_routine_symbol",
            diagnostic(&apc.kernel_routine_symbol, |symbol| {
                View::OptStr(symbol.clone())
            }),
        ),
        (
            "normal_routine",
            diagnostic(&apc.normal_routine, |address| {
                View::OptHex(address.map(|address| address.0))
            }),
        ),
        (
            "normal_routine_symbol",
            diagnostic(&apc.normal_routine_symbol, |symbol| {
                View::OptStr(symbol.clone())
            }),
        ),
    ])
}

fn apc_thread(thread: &ApcThread) -> View {
    View::Object(vec![
        ("thread", thread_summary(&thread.thread)),
        (
            "kernel",
            View::List(thread.kernel.iter().map(apc_detail).collect()),
        ),
        (
            "user",
            View::List(thread.user.iter().map(apc_detail).collect()),
        ),
        (
            "kernel_termination",
            list_termination(&thread.kernel_termination),
        ),
        (
            "user_termination",
            list_termination(&thread.user_termination),
        ),
        ("state_error", View::OptStr(thread.state_error.clone())),
    ])
}

/// APC lists; top-level keys: `selector`, `threads`, `total`, `truncated`, `layout_error`.
pub fn apcs(detail: &ApcListDetail) -> View {
    View::Object(vec![
        ("selector", apc_selector(detail.selector)),
        (
            "threads",
            View::List(detail.threads.iter().map(apc_thread).collect()),
        ),
        ("total", View::Num(detail.total as u64)),
        ("truncated", View::Bool(detail.truncated)),
        ("layout_error", View::OptStr(detail.layout_error.clone())),
    ])
}

fn stack_thread(thread: &StackThreadDetail) -> View {
    View::Object(vec![
        ("thread", thread_summary(&thread.thread)),
        ("active", View::OptStr(thread.active_vcpu.clone())),
        (
            "top_symbol",
            diagnostic(&thread.top_symbol, |symbol| View::OptStr(symbol.clone())),
        ),
        (
            "frames",
            View::List(thread.frames.iter().map(frame).collect()),
        ),
        ("truncated", View::Num(thread.truncated as u64)),
        ("error", View::OptStr(thread.error.clone())),
    ])
}

/// Thread stack rows; top-level keys: `level`, `filter`, `scanned_threads`, `displayed_threads`, `interrupted`, `threads`.
pub fn stacks(detail: &StacksDetail) -> View {
    View::Object(vec![
        ("level", View::Num(detail.level.into())),
        ("filter", View::OptStr(detail.filter.clone())),
        ("scanned_threads", View::Num(detail.scanned_threads as u64)),
        (
            "displayed_threads",
            View::Num(detail.displayed_threads as u64),
        ),
        ("interrupted", View::Bool(detail.interrupted)),
        (
            "threads",
            View::List(detail.threads.iter().map(stack_thread).collect()),
        ),
    ])
}
