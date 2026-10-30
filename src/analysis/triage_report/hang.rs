//! `!analyze -hang`: the thread on each processor with its stack, and the
//! threads that wait, most pending IRPs first.

use ntoseye_macros::record;

use crate::nt::bugchecks::BugcheckAnalysis;
use crate::nt::cpu_state;
use crate::nt::target::{DiagnosticValue, KTHREAD_STATE_WAITING, ThreadInfo};
use crate::nt::unwind::{StackFrame, StackTrace};
use crate::session::Session;

use super::PowerFailureFinding;

pub const ANALYZE_HANG_PROCESSOR_LIMIT: u16 = 256;
pub const ANALYZE_HANG_THREAD_LIMIT: usize = 32;
/// Frames shown per processor in `!analyze -hang`.
pub const ANALYZE_HANG_STACK_LIMIT: usize = 8;

/// What `!analyze -hang` found: the thread on each processor with its
/// stack, and the waiting threads.
#[record(impl)]
pub struct HangReport {
    /// One entry per processor, in order; empty when the count is unknown.
    pub processors: Vec<HangProcessor>,
    /// The waiting threads, most pending IRPs first, or why there are none
    /// (see the `waiting` property).
    #[record(skip)]
    pub waiting: std::result::Result<Vec<ThreadInfo>, String>,
}

#[record]
impl HangReport {
    /// The waiting threads, most pending IRPs first (at most 32), or why
    /// there are none.
    #[record(getter, rename = "waiting")]
    pub fn waiting_threads(&self) -> DiagnosticValue<Vec<ThreadInfo>> {
        diagnostic(&self.waiting)
    }
}

/// A processor in `!analyze -hang`, and the thread running on it.
#[record(impl)]
pub struct HangProcessor {
    pub processor: u16,
    /// The thread running on it, or why it is unknown (see the `current`
    /// property).
    #[record(skip)]
    pub current: std::result::Result<HangThread, String>,
}

#[record]
impl HangProcessor {
    /// The thread running on the processor, or why it is unknown.
    #[record(getter, rename = "current")]
    pub fn current_thread(&self) -> DiagnosticValue<HangThread> {
        diagnostic(&self.current)
    }
}

/// A thread running on a processor, with its stack.
#[record(impl)]
#[derive(Clone)]
pub struct HangThread {
    pub thread: ThreadInfo,
    /// The thread's stack, or why it did not unwind (see the `stack`
    /// property).
    #[record(skip)]
    pub stack: std::result::Result<StackTrace, String>,
}

#[record]
impl HangThread {
    /// The thread's innermost frames (at most 8), or why it did not unwind.
    #[record(getter, rename = "stack")]
    pub fn stack_frames(&self) -> DiagnosticValue<Vec<StackFrame>> {
        match &self.stack {
            Ok(trace) => DiagnosticValue::Available(trace.frames.clone()),
            Err(error) => DiagnosticValue::unavailable(error.clone()),
        }
    }
}

/// A result kept as text for the REPL, as the SDK's `Diagnostic`.
fn diagnostic<T: Clone>(value: &std::result::Result<T, String>) -> DiagnosticValue<T> {
    match value {
        Ok(value) => DiagnosticValue::Available(value.clone()),
        Err(error) => DiagnosticValue::unavailable(error.clone()),
    }
}

/// A bugcheck code and parameters decoded (`!analyze -show`).
#[record]
pub struct BugcheckDecoding {
    pub analysis: BugcheckAnalysis,
    /// What a DRIVER_POWER_STATE_FAILURE (0x9F) names as stuck.
    pub power: Option<PowerFailureFinding>,
}

pub fn gather_hang_report(session: &mut Session) -> HangReport {
    let processor_count = cpu_state::processor_count(&session.target)
        .ok()
        .or_else(|| {
            session
                .backend
                .thread_list()
                .ok()
                .map(|threads| threads.len() as u16)
        })
        .unwrap_or(0)
        .min(ANALYZE_HANG_PROCESSOR_LIMIT);
    let vcpus = session.processor_vcpus();
    let mut processors = Vec::with_capacity(usize::from(processor_count));
    for processor in 0..processor_count {
        let current = match session
            .target
            .current_windows_thread_for_processor(processor)
        {
            Ok(thread) => {
                let vcpu = vcpus.get(&processor).map(String::as_str);
                let stack = session
                    .backtrace_thread(&thread, vcpu, ANALYZE_HANG_STACK_LIMIT)
                    .map(|trace| trace.stacktrace)
                    .map_err(|error| error.to_string());
                Ok(HangThread { thread, stack })
            }
            Err(error) => Err(error.to_string()),
        };
        processors.push(HangProcessor { processor, current });
    }

    let waiting = session
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
