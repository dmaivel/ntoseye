//! Run control for `Debugger` on the session's driver ([`Session::run`]):
//! resuming, waiting, stepping, and the Python `when=` breakpoint
//! conditions that decide whether a hit surfaces.

use std::cell::Cell;
use std::collections::HashSet;
use std::time::{Duration, Instant};

use pyo3::prelude::*;

use super::handle::{Debugger, require_halted};
use super::symbols::Location;
use super::{err, raise, timeout_arg};
use crate::dbg_backend::ContinueDisposition;
use crate::output;
use crate::session::{
    Cancel, CancelBehavior, Motion, RunOutcome, Session, StepMode, Stop, StopKind, WalkUntil,
};
use crate::types::VirtAddr;
use crate::view;
use crate::view::record::Typed;

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
/// consumes nothing: a stop caught while idle is still delivered to the next
/// wait (and its action run there).
pub fn current_stop<'py>(dbg: &Bound<'py, Debugger>) -> PyResult<Typed<'py, Option<Stop>>> {
    let stop = dbg
        .get()
        .with_session(|session| session.halted_stop().map_err(err))?;
    Typed::new(dbg.py(), stop)
}

/// Run `motion` once on the session, writing what breakpoint actions and
/// filter commands printed meanwhile to `sys.stdout`.
fn drive(
    dbg: &Bound<'_, Debugger>,
    motion: Motion,
    deadline: Option<Instant>,
    behavior: CancelBehavior,
) -> PyResult<RunOutcome> {
    let (outcome, printed) = dbg.get().with_session(move |session| {
        let cancel = Cancel {
            flag: None,
            deadline,
            behavior,
            tick: None,
        };
        let (outcome, printed) = output::capture(|| session.run(motion, &cancel));
        Ok((outcome, printed))
    })?;
    if !printed.is_empty() {
        let py = dbg.py();
        py.import("sys")?
            .getattr("stdout")?
            .call_method1("write", (printed,))?;
    }
    prune_conditions(dbg)?;
    outcome.map_err(err)
}

/// Run `motion` until its stop surfaces, the one loop every run and step
/// goes through. A breakpoint hit whose `when=` callback declines it is
/// passed by going on with the same motion ([`Session::decline`]). `None`:
/// the target is still running when `timeout` ran out (`ReturnRunning`).
fn settle<'py>(
    dbg: &Bound<'py, Debugger>,
    motion: Motion,
    timeout: Option<Duration>,
    behavior: CancelBehavior,
) -> PyResult<Option<Typed<'py, Stop>>> {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let (mut motion, stepping) = dbg.get().with_session(|session| {
        let stepping = session.current_thread.clone();
        Ok((session.plan(motion).map_err(err)?, stepping))
    })?;
    loop {
        let RunOutcome::Stopped(stop) = drive(dbg, motion.clone(), deadline, behavior)? else {
            return Ok(None);
        };
        if let Some(stop) = surface(dbg, stop)? {
            return Ok(Some(stop));
        }
        let declined = motion;
        motion = dbg
            .get()
            .with_session(|session| session.decline(declined, &stepping).map_err(err))?;
    }
}

/// [`settle`] for a motion that always ends on a stop: one that `timeout`
/// cuts short is halted where it is.
fn settle_stop<'py>(
    dbg: &Bound<'py, Debugger>,
    motion: Motion,
    timeout: Option<Duration>,
) -> PyResult<Typed<'py, Stop>> {
    settle(dbg, motion, timeout, CancelBehavior::Halt)?
        .ok_or_else(|| raise("the target is running; no stop to report"))
}

/// The SDK's `stop`, first asking its breakpoint's `when=` callback.
/// `None` means the callback declined the hit; a callback that raises
/// surfaces the hit with `condition_error`, as a failed `condition=` does.
fn surface<'py>(dbg: &Bound<'py, Debugger>, stop: Stop) -> PyResult<Option<Typed<'py, Stop>>> {
    let py = dbg.py();
    let condition = stop
        .breakpoint
        .as_ref()
        .filter(|_| stop.kind == StopKind::Breakpoint)
        .and_then(|hit| {
            dbg.get()
                .conditions
                .lock()
                .get(&hit.id)
                .map(|callable| callable.clone_ref(py))
        });
    let object = Typed::<Stop>::of(py, &stop)?.into_bound();
    let Some(condition) = condition else {
        return Ok(Some(Typed::converted(object)));
    };
    let verdict = {
        let _guard = ConditionGuard::enter();
        condition
            .bind(py)
            .call1((object.clone(),))
            .and_then(|value| value.is_truthy())
    };
    match verdict {
        Ok(true) => Ok(Some(Typed::converted(object))),
        Ok(false) => Ok(None),
        Err(error) => {
            let error = error.to_string();
            let failed = dbg
                .get()
                .with_session(|session| Ok(session.fail_stop_condition(error)))?;
            Typed::new(py, failed.unwrap_or(stop)).map(Some)
        }
    }
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

/// Resume without waiting. A stop already waiting surfaces (its action runs)
/// and stays the current stop, which the next wait reports.
pub fn cont(dbg: &Bound<'_, Debugger>, disposition: ContinueDisposition) -> PyResult<()> {
    reject_condition_mutation()?;
    drive(
        dbg,
        Motion::Continue { disposition },
        Some(Instant::now()),
        CancelBehavior::ReturnRunning,
    )
    .map(drop)
}

pub fn run<'py>(
    dbg: &Bound<'py, Debugger>,
    timeout: Option<f64>,
    disposition: ContinueDisposition,
) -> PyResult<Option<Typed<'py, Stop>>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    settle(
        dbg,
        Motion::Continue { disposition },
        timeout,
        CancelBehavior::ReturnRunning,
    )
}

pub fn wait<'py>(
    dbg: &Bound<'py, Debugger>,
    timeout: Option<f64>,
) -> PyResult<Option<Typed<'py, Stop>>> {
    let timeout = timeout_arg(timeout)?;
    settle(dbg, Motion::Wait, timeout, CancelBehavior::ReturnRunning)
}

pub fn run_to<'py>(
    dbg: &Bound<'py, Debugger>,
    location: Location,
    timeout: Option<f64>,
    step: Option<StepMode>,
) -> PyResult<Option<Typed<'py, Stop>>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    let address = dbg.get().with_session(|session| {
        require_halted(session, "run_to")?;
        location
            .resolve(session, session.target.current_dtb())
            .map(VirtAddr)
    })?;
    let motion = match step {
        None => Motion::RunTo {
            address,
            frame: None,
            disposition: ContinueDisposition::Handled,
        },
        Some(mode) => Motion::walk(mode, WalkUntil::Address(address)),
    };
    settle_stop(dbg, motion, timeout).map(Some)
}

pub fn step<'py>(
    dbg: &Bound<'py, Debugger>,
    until: Option<WalkUntil>,
    timeout: Option<f64>,
) -> PyResult<Typed<'py, Stop>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    dbg.get()
        .with_session(|session| require_halted(session, "step"))?;
    let motion = until.map_or(Motion::Step, |until| Motion::walk(StepMode::Into, until));
    settle_stop(dbg, motion, timeout)
}

pub fn step_over<'py>(
    dbg: &Bound<'py, Debugger>,
    until: Option<WalkUntil>,
    timeout: Option<f64>,
) -> PyResult<Typed<'py, Stop>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    dbg.get()
        .with_session(|session| require_halted(session, "step_over"))?;
    let motion = until.map_or(Motion::StepOver, |until| {
        Motion::walk(StepMode::Over, until)
    });
    settle_stop(dbg, motion, timeout)
}

pub fn step_out<'py>(
    dbg: &Bound<'py, Debugger>,
    timeout: Option<f64>,
) -> PyResult<Typed<'py, Stop>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    dbg.get()
        .with_session(|session| require_halted(session, "step_out"))?;
    settle_stop(dbg, Motion::StepOut, timeout)
}

pub fn trace_calls<'py>(
    dbg: &Bound<'py, Debugger>,
    limit: usize,
    timeout: Option<f64>,
) -> PyResult<Typed<'py, view::execution::CallTrace>> {
    reject_condition_mutation()?;
    let timeout = timeout_arg(timeout)?;
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let trace = dbg.get().with_session(move |session: &mut Session| {
        require_halted(session, "trace_calls")?;
        let cancel = Cancel {
            flag: None,
            deadline,
            behavior: CancelBehavior::Halt,
            tick: None,
        };
        session.trace_calls(limit, &cancel).map_err(err)
    })?;
    prune_conditions(dbg)?;
    Typed::new(dbg.py(), view::execution::call_trace(&trace))
}

pub fn interrupt<'py>(dbg: &Bound<'py, Debugger>) -> PyResult<Typed<'py, Stop>> {
    reject_condition_mutation()?;
    match drive(dbg, Motion::Break, None, CancelBehavior::Halt)? {
        RunOutcome::Stopped(stop) => Typed::new(dbg.py(), stop),
        RunOutcome::Running => Err(raise("the target is running; no stop to report")),
    }
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
