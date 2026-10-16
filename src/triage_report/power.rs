//! DRIVER_POWER_STATE_FAILURE (0x9F): what the bugcheck names as stuck (see
//! [`Target::power_failure`](crate::target::Target::power_failure)), with
//! the stacks of the threads it names: each power IRP worker thread for
//! subtype 0x3, and the thread that holds the PnP lock for 0x4.

use std::collections::HashMap;

use crate::session::Session;
use crate::target::DiagnosticValue;
use crate::target::power::{PowerFailure, power_failure_description};
use crate::types::VirtAddr;
use crate::unwind::{StackFrame, StackTrace};
use ntoseye_macros::record;

/// Frames walked of each thread a 0x9F names.
pub const POWER_THREAD_STACK_LIMIT: usize = 16;
/// Threads whose stacks a 0x9F report walks.
const POWER_THREAD_LIMIT: usize = 16;

/// Why a DRIVER_POWER_STATE_FAILURE names a thread: `kind` `irp_worker`
/// (a power IRP worker thread, passing `irp` to `device`, or waiting for
/// work when both are 0) or `pnp_lock_owner` (the thread that holds the PnP
/// lock, 0x4).
#[record(tagged)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PowerThreadRole {
    /// A power IRP worker thread, passing `irp` to `device`, or waiting for
    /// work when both are 0.
    IrpWorker { irp: VirtAddr, device: VirtAddr },
    /// The thread that holds the PnP lock (0x4).
    PnpLockOwner,
}

/// A thread that a DRIVER_POWER_STATE_FAILURE names, with its stack.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct PowerFailureThread {
    pub role: PowerThreadRole,
    /// The `_ETHREAD`.
    pub thread: VirtAddr,
    /// The thread's stack, or why it did not unwind (see the `stack`
    /// property).
    #[record(skip)]
    pub stack: std::result::Result<StackTrace, String>,
}

#[record]
impl PowerFailureThread {
    /// The thread's stack, or why it did not unwind.
    #[record(getter, rename = "stack")]
    pub fn stack_frames(&self) -> DiagnosticValue<Vec<StackFrame>> {
        match &self.stack {
            Ok(trace) => DiagnosticValue::Available(trace.frames.clone()),
            Err(error) => DiagnosticValue::unavailable(error.clone()),
        }
    }
}

/// What a DRIVER_POWER_STATE_FAILURE (0x9F) names, read from the target,
/// and the stacks of the threads involved.
#[record]
#[derive(Debug, Clone)]
pub struct PowerFailureFinding {
    #[record(rename = "record")]
    pub failure: PowerFailure,
    pub threads: Vec<PowerFailureThread>,
}

/// The finding for a bugcheck `code` with `parameters`; `None` unless it is
/// a 0x9F of a documented subtype.
pub fn power_failure_finding(
    session: &mut Session,
    code: u32,
    parameters: &[u64],
) -> Option<PowerFailureFinding> {
    if code != 0x9f {
        return None;
    }
    let parameters: [u64; 4] = parameters.get(..4)?.try_into().ok()?;
    power_failure_description(parameters[0])?;
    let failure = session.target.power_failure(parameters);

    let mut wanted = Vec::new();
    if let Some(owner) = failure.pnp_lock_owner.filter(|owner| !owner.is_zero()) {
        wanted.push((PowerThreadRole::PnpLockOwner, owner));
    }
    if let Some(workers) = &failure.workers {
        // Workers passing an IRP to a driver first: one of them may be
        // stuck in it.
        let mut listed: Vec<_> = workers
            .entries
            .iter()
            .filter_map(|entry| entry.worker.as_result().ok())
            .filter(|worker| !worker.thread.is_zero())
            .collect();
        listed.sort_by_key(|worker| worker.irp.is_zero());
        wanted.extend(listed.into_iter().map(|worker| {
            (
                PowerThreadRole::IrpWorker {
                    irp: worker.irp,
                    device: worker.device,
                },
                worker.thread,
            )
        }));
    }
    wanted.truncate(POWER_THREAD_LIMIT);
    let active = if wanted.is_empty() {
        HashMap::new()
    } else {
        session.active_thread_map()
    };
    let threads = wanted
        .into_iter()
        .map(|(role, thread)| {
            let stack = session
                .target
                .thread_info_from_ethread(thread)
                .map_err(|error| error.to_string())
                .and_then(|info| {
                    let vcpu = active.get(&thread.0).map(|(vcpu, _)| vcpu.clone());
                    session
                        .backtrace_thread(&info, vcpu.as_deref(), POWER_THREAD_STACK_LIMIT)
                        .map(|trace| trace.stacktrace)
                        .map_err(|error| error.to_string())
                });
            PowerFailureThread {
                role,
                thread,
                stack,
            }
        })
        .collect();
    Some(PowerFailureFinding { failure, threads })
}
