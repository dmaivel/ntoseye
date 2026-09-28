//! Run control for `Debugger`: resuming, waiting, stepping, and the Python
//! `when=` breakpoint conditions that decide whether a hit surfaces.

use std::cell::Cell;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pyo3::prelude::*;

use super::args::UntilFlow;
use super::handle::{Debugger, require_halted};
use super::stop::{Stop, from_outcome};
use super::symbols::Location;
use super::{err, raise, timeout_arg};
use crate::breakpoints::StepFrame;
use crate::dbg_backend::ContinueDisposition;
use crate::disasm::ControlFlow;
use crate::error::Result as CoreResult;
use crate::session::{ContinueOutcome, STEP_UNTIL_LIMIT, Session, StepKind, StepMode, StepStack};
use crate::types::VirtAddr;
use crate::view;
use crate::view::shape::Typed;

thread_local! {
    static IN_CONDITION: Cell<bool> = const { Cell::new(false) };
}

/// Reject run-control or breakpoint mutation while a Python `when=` callback
/// is deciding whether its stop should surface.
pub fn reject_condition_mutation() -> PyResult<()> {
    if IN_CONDITION.get() {
        Err(raise(
            "breakpoint conditions may not resume, step, or change breakpoints",
        ))
    } else {
        Ok(())
    }
}

struct ConditionGuard(bool);

impl ConditionGuard {
    fn enter() -> Self {
        Self(IN_CONDITION.replace(true))
    }
}

impl Drop for ConditionGuard {
    fn drop(&mut self) {
        IN_CONDITION.set(self.0);
    }
}

/// The stop the target is halted at, or `None` while it runs. Reading it
/// consumes nothing: a stop parked while idle is still delivered to the next
/// wait (and rendered by the next `command()`).
pub fn current_stop(dbg: &Bound<'_, Debugger>) -> PyResult<Option<Py<Stop>>> {
    let outcome = dbg.get().with_session(|session| {
        // A caught-but-undrained stop leaves the backend looking like it runs.
        session.settle_pending_stop().map_err(err)?;
        Ok((!session.backend.is_running()).then(|| session.halted_outcome()))
    })?;
    match outcome {
        Some(outcome) => from_outcome(dbg.py(), dbg.as_unbound(), outcome),
        None => Ok(None),
    }
}

/// The typed stop for a halting outcome (never `Running`).
fn stop_for(dbg: &Bound<'_, Debugger>, outcome: ContinueOutcome) -> PyResult<Py<Stop>> {
    from_outcome(dbg.py(), dbg.as_unbound(), outcome)?.ok_or_else(no_stop)
}

fn no_stop() -> PyErr {
    raise("the target is running; no stop to report")
}

/// The stop for `outcome`, first asking its breakpoint's `when=` callback.
/// `None` means the callback declined the hit; the caller decides how to go
/// on (resume, or keep stepping). A callback that raises surfaces the hit
/// with `condition_error`.
fn surface(dbg: &Bound<'_, Debugger>, mut outcome: ContinueOutcome) -> PyResult<Option<Py<Stop>>> {
    let py = dbg.py();
    let condition = match &outcome {
        ContinueOutcome::Breakpoint { id, .. } => dbg
            .get()
            .conditions
            .lock()
            .get(id)
            .map(|callable| callable.clone_ref(py)),
        _ => None,
    };
    let Some(condition) = condition else {
        return stop_for(dbg, outcome).map(Some);
    };
    let stop = stop_for(dbg, outcome.clone())?;
    let verdict = {
        let _guard = ConditionGuard::enter();
        condition
            .bind(py)
            .call1((stop.bind(py),))
            .and_then(|value| value.is_truthy())
    };
    match verdict {
        Ok(true) => Ok(Some(stop)),
        Ok(false) => Ok(None),
        Err(error) => {
            if let ContinueOutcome::Breakpoint {
                condition_error, ..
            } = &mut outcome
            {
                *condition_error = Some(error.to_string());
            }
            dbg.get().with_session(|session| {
                session.note_stop(&outcome);
                Ok(())
            })?;
            stop_for(dbg, outcome).map(Some)
        }
    }
}

pub fn cont(dbg: &Bound<'_, Debugger>, disposition: ContinueDisposition) -> PyResult<()> {
    reject_condition_mutation()?;
    dbg.get()
        .with_session(|session| session.resume_with_disposition(disposition).map_err(err))?;
    prune_conditions(dbg)
}

pub fn run(
    dbg: &Bound<'_, Debugger>,
    timeout: Option<f64>,
    mut disposition: ContinueDisposition,
) -> PyResult<Option<Py<Stop>>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    settle(dbg, timeout, None, move |session, remaining| {
        let cancel = Arc::clone(&session.target.interrupt);
        let outcome = session.continue_until_break(remaining, &cancel, disposition);
        // Past a declined hit, which the guest raised for us, not an exception.
        disposition = ContinueDisposition::Handled;
        outcome
    })
}

pub fn wait(dbg: &Bound<'_, Debugger>, timeout: Option<f64>) -> PyResult<Option<Py<Stop>>> {
    let timeout = timeout_arg(timeout)?;
    let mut declined = false;
    settle(dbg, timeout, None, move |session, remaining| {
        let cancel = Arc::clone(&session.target.interrupt);
        if declined {
            session.continue_until_break(remaining, &cancel, ContinueDisposition::Handled)
        } else if !session.backend.is_running() || session.backend.has_pending_stop() {
            declined = true;
            session.interrupt_outcome()
        } else {
            declined = true;
            session.wait_for_stop_bounded(remaining, &cancel)
        }
    })
}

/// Run `attempt` on the session until its stop surfaces, the one loop every
/// run and step goes through. A breakpoint hit whose `when=` callback
/// declines it is passed by attempting again: a run resumes from the hit, a
/// run-to re-arms the same target, a step walk keeps stepping. A step names
/// its vCPU (`stepping`), which a hit on another vCPU is stepped past and
/// handed back to (see [`Session::pass_declined_hit`]). `None`: the target
/// is still running when `timeout` ran out.
fn settle(
    dbg: &Bound<'_, Debugger>,
    timeout: Option<Duration>,
    stepping: Option<String>,
    mut attempt: impl FnMut(&mut Session, Option<Duration>) -> CoreResult<ContinueOutcome> + Send,
) -> PyResult<Option<Py<Stop>>> {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    loop {
        let remaining = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        let outcome = dbg
            .get()
            .with_session(|session| attempt(session, remaining).map_err(err))?;
        prune_conditions(dbg)?;
        if matches!(outcome, ContinueOutcome::Running) {
            return Ok(None);
        }
        if let Some(stop) = surface(dbg, outcome)? {
            return Ok(Some(stop));
        }
        if let Some(stepping) = &stepping {
            dbg.get()
                .with_session(|session| session.pass_declined_hit(stepping).map_err(err))?;
        }
    }
}

/// [`settle`] for a call that always ends on a stop (a step): one that
/// `timeout` cuts short is halted where it is.
fn settle_stop(
    dbg: &Bound<'_, Debugger>,
    timeout: Option<Duration>,
    attempt: impl FnMut(&mut Session, Option<Duration>) -> CoreResult<ContinueOutcome> + Send,
) -> PyResult<Py<Stop>> {
    let stepping = dbg
        .get()
        .with_session(|session| Ok(session.current_thread.clone()))?;
    settle(dbg, timeout, Some(stepping), attempt)?.ok_or_else(no_stop)
}

/// Drop `when=` callbacks of breakpoints that no longer exist (a one-shot
/// that fired, a reload that cleared them).
fn prune_conditions(dbg: &Bound<'_, Debugger>) -> PyResult<()> {
    let live = dbg.get().with_session(|session| {
        Ok(session
            .breakpoints
            .managed_ids()
            .into_iter()
            .collect::<HashSet<_>>())
    })?;
    dbg.get()
        .conditions
        .lock()
        .retain(|id, _| live.contains(id));
    Ok(())
}

pub fn run_to(
    dbg: &Bound<'_, Debugger>,
    location: Location,
    timeout: Option<f64>,
    step: Option<StepMode>,
) -> PyResult<Option<Py<Stop>>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    let address = dbg.get().with_session(|session| {
        require_halted(session, "run_to")?;
        location.resolve(session, session.target.current_dtb())
    })?;
    let stepping = match step {
        Some(_) => Some(
            dbg.get()
                .with_session(|session| Ok(session.current_thread.clone()))?,
        ),
        None => None,
    };
    settle(
        dbg,
        timeout,
        stepping,
        move |session, remaining| match step {
            None => run_to_address(session, VirtAddr(address), None, remaining),
            Some(mode) => {
                session.step_until(mode, STEP_UNTIL_LIMIT, remaining, |ip, _| ip == address)
            }
        },
    )
}

/// [`Session::run_to`], reporting a timeout or cancel that halted the target
/// short of `address` as a plain stop where it is.
fn run_to_address(
    session: &mut Session,
    address: VirtAddr,
    frame: Option<StepFrame>,
    timeout: Option<Duration>,
) -> CoreResult<ContinueOutcome> {
    let cancel = Arc::clone(&session.target.interrupt);
    match session.run_to(address, frame, timeout, &cancel)? {
        ContinueOutcome::Running if !session.backend.is_running() => Ok(ContinueOutcome::Halted {
            rip: session.current_rip(),
        }),
        outcome => Ok(outcome),
    }
}

pub fn step(
    dbg: &Bound<'_, Debugger>,
    until: Option<UntilFlow>,
    timeout: Option<f64>,
) -> PyResult<Py<Stop>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    dbg.get()
        .with_session(|session| require_halted(session, "step"))?;
    match until {
        None => settle_stop(dbg, None, single_step),
        Some(kind) => step_to_flow(dbg, StepMode::Into, kind, timeout),
    }
}

pub fn step_over(
    dbg: &Bound<'_, Debugger>,
    until: Option<UntilFlow>,
    timeout: Option<f64>,
) -> PyResult<Py<Stop>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    let plan = dbg.get().with_session(|session| {
        require_halted(session, "step_over")?;
        match until {
            Some(_) => Ok(None),
            None => match session.step_over_target().map_err(err)? {
                StepKind::RunTo(next) => {
                    let frame = session.step_frame(StepStack::CallReturn).map_err(err)?;
                    Ok(Some((next, frame)))
                }
                StepKind::Single => Ok(None),
            },
        }
    })?;
    match (until, plan) {
        (Some(kind), _) => step_to_flow(dbg, StepMode::Over, kind, timeout),
        (None, Some((next, frame))) => {
            // A call: run to the instruction after it, again past declined hits.
            settle_stop(dbg, timeout, move |session, remaining| {
                run_to_address(session, next, frame.clone(), remaining)
            })
        }
        (None, _) => settle_stop(dbg, None, single_step),
    }
}

fn single_step(session: &mut Session, _: Option<Duration>) -> CoreResult<ContinueOutcome> {
    Ok(ContinueOutcome::Step {
        rip: session.step()?,
    })
}

/// Step into or over calls per `mode` until the next instruction of `kind`.
fn step_to_flow(
    dbg: &Bound<'_, Debugger>,
    mode: StepMode,
    kind: UntilFlow,
    timeout: Option<Duration>,
) -> PyResult<Py<Stop>> {
    settle_stop(dbg, timeout, move |session, remaining| {
        session.step_until(mode, STEP_UNTIL_LIMIT, remaining, |_, flow| {
            kind.matches(flow)
        })
    })
}

pub fn step_out(dbg: &Bound<'_, Debugger>, timeout: Option<f64>) -> PyResult<Py<Stop>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    let (target, frame) = dbg.get().with_session(|session| {
        require_halted(session, "step_out")?;
        let target = session.step_out_target().map_err(err)?;
        let frame = session.step_frame(StepStack::FunctionReturn).map_err(err)?;
        Ok((target, frame))
    })?;
    settle_stop(dbg, timeout, move |session, remaining| {
        run_to_address(session, target, frame.clone(), remaining)
    })
}

impl UntilFlow {
    fn matches(self, flow: ControlFlow) -> bool {
        match self {
            UntilFlow::Call => flow == ControlFlow::Call,
            UntilFlow::Return => flow == ControlFlow::Ret,
            UntilFlow::Branch => matches!(
                flow,
                ControlFlow::Branch | ControlFlow::Call | ControlFlow::Ret
            ),
        }
    }
}

pub fn trace_calls<'py>(
    dbg: &Bound<'py, Debugger>,
    limit: usize,
) -> PyResult<Typed<'py, view::execution::CallTrace>> {
    reject_condition_mutation()?;
    let trace = dbg.get().with_session(|session| {
        require_halted(session, "trace_calls")?;
        session.trace_calls(limit).map_err(err)
    })?;
    prune_conditions(dbg)?;
    Typed::new(dbg.py(), view::execution::call_trace(&trace))
}

pub fn interrupt(dbg: &Bound<'_, Debugger>) -> PyResult<Py<Stop>> {
    reject_condition_mutation()?;
    let outcome = dbg
        .get()
        .with_session(|session| session.interrupt_requested().map_err(err))?;
    stop_for(dbg, outcome)
}

pub fn reboot(dbg: &Bound<'_, Debugger>) -> PyResult<()> {
    reject_condition_mutation()?;
    dbg.get().with_session(|session| {
        require_halted(session, "reboot")?;
        session.request_reboot().map_err(err)
    })?;
    prune_conditions(dbg)
}

pub fn crash(dbg: &Bound<'_, Debugger>) -> PyResult<()> {
    reject_condition_mutation()?;
    dbg.get().with_session(|session| {
        require_halted(session, "crash")?;
        session.request_crash().map_err(err)
    })?;
    prune_conditions(dbg)
}
