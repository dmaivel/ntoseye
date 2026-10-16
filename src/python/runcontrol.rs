//! The SDK half of `#[command(kind = Run)]`: driving a run command's motion
//! on the session's driver ([`Session::run`]) for `Debugger`'s generated
//! run methods (`run`, `step`, `step_over`, `step_out`, `trace_calls`,
//! `reboot`, `crash`), plus `wait` and `interrupt`, and the Python `when=`
//! breakpoint conditions that decide whether a hit surfaces.

use std::cell::Cell;
use std::collections::HashSet;
use std::time::{Duration, Instant};

use pyo3::prelude::*;

use super::command::admit;
use super::handle::Debugger;
use super::record::{ToValue, Typed};
use super::{err, raise, timeout_arg};
use crate::error::Result;
use crate::output;
use crate::session::effects::Effects;
use crate::session::{Cancel, CancelBehavior, Motion, RunOutcome, Session, Stop, StopKind};

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
pub fn current_stop<'py>(py: Python<'py>, dbg: &Debugger) -> PyResult<Typed<'py, Option<Stop>>> {
    let stop = dbg.with_session(|session| session.halted_stop().map_err(err))?;
    Typed::new(py, stop)
}

/// Write what the session printed meanwhile (breakpoint actions, filter
/// commands, a command's own lines) to `sys.stdout`.
fn forward(py: Python<'_>, printed: String) -> PyResult<()> {
    if !printed.is_empty() {
        py.import("sys")?
            .getattr("stdout")?
            .call_method1("write", (printed,))?;
    }
    Ok(())
}

/// Run `motion` once on the session, forwarding what it printed.
fn drive(
    py: Python<'_>,
    dbg: &Debugger,
    motion: Motion,
    deadline: Option<Instant>,
    behavior: CancelBehavior,
) -> PyResult<RunOutcome> {
    let (outcome, printed) = dbg.with_session(move |session| {
        let cancel = Cancel {
            flag: None,
            deadline,
            behavior,
            tick: None,
        };
        Ok(output::capture(|| session.run(motion, &cancel)))
    })?;
    forward(py, printed)?;
    prune_conditions(dbg)?;
    outcome.map_err(err)
}

/// Run `motion` until its stop surfaces, the one loop every run and step
/// goes through. A breakpoint hit whose `when=` callback declines it is
/// passed by going on with the same motion ([`Session::decline`]). `None`:
/// the target is still running when `timeout` ran out (`ReturnRunning`).
fn settle<'py>(
    py: Python<'py>,
    dbg: &Debugger,
    motion: Motion,
    timeout: Option<Duration>,
    behavior: CancelBehavior,
) -> PyResult<Option<Typed<'py, Stop>>> {
    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    let (mut motion, stepping) = dbg.with_session(|session| {
        let stepping = session.current_thread.clone();
        Ok((session.plan(motion).map_err(err)?, stepping))
    })?;
    loop {
        let RunOutcome::Stopped(stop) = drive(py, dbg, motion.clone(), deadline, behavior)? else {
            return Ok(None);
        };
        if let Some(stop) = surface(py, dbg, stop)? {
            return Ok(Some(stop));
        }
        let declined = motion;
        motion = dbg.with_session(|session| session.decline(declined, &stepping).map_err(err))?;
    }
}

/// The SDK's `stop`, first asking its breakpoint's `when=` callback.
/// `None` means the callback declined the hit; a callback that raises
/// surfaces the hit with `condition_error`, as a failed `condition=` does.
fn surface<'py>(py: Python<'py>, dbg: &Debugger, stop: Stop) -> PyResult<Option<Typed<'py, Stop>>> {
    let condition = stop
        .breakpoint
        .as_ref()
        .filter(|_| stop.kind == StopKind::Breakpoint)
        .and_then(|hit| {
            dbg.conditions
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
            let failed = dbg.with_session(|session| Ok(session.fail_stop_condition(error)))?;
            Typed::new(py, failed.unwrap_or(stop)).map(Some)
        }
    }
}

/// Drop `when=` callbacks of breakpoints that no longer exist (a one-shot
/// that fired, a reload that cleared them).
pub fn prune_conditions(dbg: &Debugger) -> PyResult<()> {
    let live = dbg.with_session(|session| {
        Ok(session
            .breakpoints
            .managed_ids()
            .into_iter()
            .collect::<HashSet<_>>())
    })?;
    dbg.conditions.lock().retain(|id, _| live.contains(id));
    Ok(())
}

/// Admit a run command and run its operation for the motion it plans,
/// forwarding what the operation printed (`.reboot`'s announcement).
fn plan_run(
    py: Python<'_>,
    dbg: &Debugger,
    operation: &str,
    effects: &Effects,
    f: impl FnOnce(&mut Session) -> Result<Motion> + Send,
) -> PyResult<Motion> {
    reject_condition_mutation()?;
    let (motion, printed) = dbg.with_session(|session| {
        admit(session, effects, operation)?;
        Ok(output::capture(|| f(session)))
    })?;
    forward(py, printed)?;
    motion.map_err(err)
}

/// A run or wait hands back a running target when the timeout ends; any
/// other motion is halted where it got to.
fn timeout_behavior(motion: &Motion) -> CancelBehavior {
    match motion {
        Motion::Continue { .. } | Motion::Wait => CancelBehavior::ReturnRunning,
        _ => CancelBehavior::Halt,
    }
}

/// A `#[command(kind = Run)]` method admitted on a running target (`run`):
/// the stop its motion ends on, or `None` if the target is still running
/// when `timeout` (seconds) ran out.
pub fn run_motion<'py>(
    py: Python<'py>,
    dbg: &Debugger,
    operation: &str,
    effects: &Effects,
    timeout: Option<f64>,
    f: impl FnOnce(&mut Session) -> Result<Motion> + Send,
) -> PyResult<Typed<'py, Option<Stop>>> {
    let timeout = timeout_arg(timeout)?;
    let motion = plan_run(py, dbg, operation, effects, f)?;
    let behavior = timeout_behavior(&motion);
    let stop = settle(py, dbg, motion, timeout, behavior)?;
    Ok(optional(py, stop))
}

/// A `#[command(kind = Run)]` method on a halted target (`step`): the stop
/// its motion ends on; a `timeout` (seconds) halts it where it got to.
pub fn run_motion_to_stop<'py>(
    py: Python<'py>,
    dbg: &Debugger,
    operation: &str,
    effects: &Effects,
    timeout: Option<f64>,
    f: impl FnOnce(&mut Session) -> Result<Motion> + Send,
) -> PyResult<Typed<'py, Stop>> {
    let timeout = timeout_arg(timeout)?;
    let motion = plan_run(py, dbg, operation, effects, f)?;
    let behavior = timeout_behavior(&motion);
    settle(py, dbg, motion, timeout, behavior)?
        .ok_or_else(|| raise("the target is running; no stop to report"))
}

/// A `#[command(kind = Run)]` method whose operation drives the run itself
/// (`trace_calls`): `timeout` (seconds) halts it where it got to.
pub fn run_cancellable<'py, T: ToValue + Send>(
    py: Python<'py>,
    dbg: &Debugger,
    operation: &str,
    effects: &Effects,
    timeout: Option<f64>,
    f: impl FnOnce(&mut Session, &Cancel<'_>) -> Result<T> + Send,
) -> PyResult<Typed<'py, T>> {
    reject_condition_mutation()?;
    let deadline = timeout_arg(timeout)?.map(|timeout| Instant::now() + timeout);
    let (value, printed) = dbg.with_session(move |session| {
        admit(session, effects, operation)?;
        let cancel = Cancel {
            flag: None,
            deadline,
            behavior: CancelBehavior::Halt,
            tick: None,
        };
        Ok(output::capture(|| f(session, &cancel)))
    })?;
    forward(py, printed)?;
    prune_conditions(dbg)?;
    Typed::new(py, value.map_err(err)?)
}

/// A stop that may not have come, typed as `Stop | None`.
fn optional<'py>(py: Python<'py>, stop: Option<Typed<'py, Stop>>) -> Typed<'py, Option<Stop>> {
    Typed::converted(stop.map_or_else(|| py.None().into_bound(py), Typed::into_bound))
}

/// `Debugger.wait`: the next stop without resuming, or `None` if the target
/// is still running after `timeout` seconds.
pub fn wait<'py>(
    py: Python<'py>,
    dbg: &Debugger,
    timeout: Option<f64>,
) -> PyResult<Typed<'py, Option<Stop>>> {
    let timeout = timeout_arg(timeout)?;
    let stop = settle(
        py,
        dbg,
        Motion::Wait,
        timeout,
        CancelBehavior::ReturnRunning,
    )?;
    Ok(optional(py, stop))
}

/// `Debugger.interrupt`: break into a running target, or report the stop a
/// halted one is at.
pub fn interrupt<'py>(py: Python<'py>, dbg: &Debugger) -> PyResult<Typed<'py, Stop>> {
    reject_condition_mutation()?;
    match drive(py, dbg, Motion::Break, None, CancelBehavior::Halt)? {
        RunOutcome::Stopped(stop) => Typed::new(py, stop),
        RunOutcome::Running => Err(raise("the target is running; no stop to report")),
    }
}
