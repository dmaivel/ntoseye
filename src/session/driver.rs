//! The run driver: [`Session::run`], the one resume, step and wait entry
//! point every host uses, and the [`Stop`] it reports.
//!
//! The driver owns polling, absorbing debugger noise, the exception and
//! module-event policies (`notify` included, reported as a notice), surfacing
//! a stop parked while the host was idle, and running breakpoint `do` actions
//! and policy commands through the session's [`ActionRunner`]. Hosts only map
//! a [`Stop`] to their own rendering or protocol.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ntoseye_macros::record;

use crate::backend::dbg_backend::{
    BugcheckInfo, ContinueDisposition, HwBreakpointAccess, ModuleEvent,
    processor_index_from_backend_thread_id,
};
use crate::backend::kd::trace_enabled;
use crate::base::disasm::ControlFlow;
use crate::base::error::Result;
use crate::base::notice::Notice;
use crate::base::types::VirtAddr;
use crate::nt::breakpoints::{BreakpointInfo, StepFrame};
use crate::nt::guest::{ModuleInfo, ProcessInfo};
use crate::nt::target::ThreadInfo;
use crate::nt::unwind::try_format_symbol_at;
use crate::session::context::windows_thread_on_backend_thread;
use crate::session::exception_policy::ExceptionPolicyAction;
use crate::session::{
    ContinueOutcome, STEP_UNTIL_LIMIT, Session, StepKind, StepMode, StepStack, StopResolution,
};

/// How often a wait wakes to check the host's cancellation, the session's
/// interrupt request, and its deadline.
pub const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How many times a requested halt breaks in again past an exception its
/// policy continues, before the last stop surfaces as it is.
const HALT_ATTEMPTS: usize = 8;

/// What [`Session::run`] does with the target.
#[derive(Debug, Clone)]
pub enum Motion {
    /// Resume with `disposition` (unless the target already runs) and wait
    /// for the next stop.
    Continue { disposition: ContinueDisposition },
    /// Wait for the next stop without resuming. A stop parked while the host
    /// was idle surfaces first; a halted target reports the stop it is
    /// halted at.
    Wait,
    /// Halt the target: a parked or pending stop surfaces as itself,
    /// otherwise the debugger breaks in, which is an
    /// [`StopKind::Interrupt`]. A halted target reports the stop it is
    /// halted at.
    Break,
    /// Single-step one instruction on the current thread.
    Step,
    /// Step over the current instruction: a single step, or a run to the
    /// instruction after a call, by the stepping thread returning from it.
    StepOver,
    /// Run until the current function returns to its caller.
    StepOut,
    /// Run to `address`, by the execution `frame` names when given; reaching
    /// it is a [`StopKind::Step`].
    RunTo {
        address: VirtAddr,
        frame: Option<StepFrame>,
        disposition: ContinueDisposition,
    },
    /// Step into or over calls (`mode`) until `until` holds for the
    /// instruction about to run, at most `limit` instructions.
    /// `resume` goes on with the walk a stop ended, after the host passed it
    /// (see [`Session::decline`]).
    Walk {
        mode: StepMode,
        until: WalkUntil,
        limit: usize,
        resume: bool,
    },
}

impl Motion {
    /// A walk to `until`, with the session's default instruction cap.
    pub fn walk(mode: StepMode, until: WalkUntil) -> Self {
        Motion::Walk {
            mode,
            until,
            limit: STEP_UNTIL_LIMIT,
            resume: false,
        }
    }
}

/// Where a [`Motion::Walk`] ends: the instruction about to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkUntil {
    /// The instruction at this address.
    Address(VirtAddr),
    /// A call.
    Call,
    /// A return.
    Return,
    /// Any branching instruction, calls and returns included (WinDbg's `ph`).
    Branch,
}

impl WalkUntil {
    fn holds(self, ip: u64, flow: ControlFlow) -> bool {
        match self {
            WalkUntil::Address(address) => ip == address.0,
            WalkUntil::Call => flow == ControlFlow::Call,
            WalkUntil::Return => flow == ControlFlow::Ret,
            WalkUntil::Branch => matches!(
                flow,
                ControlFlow::Branch | ControlFlow::Call | ControlFlow::Ret
            ),
        }
    }
}

/// How a [`Session::run`] ended.
#[derive(Debug, Clone)]
pub enum RunOutcome {
    /// The target is halted at this stop.
    Stopped(Stop),
    /// The host's cancellation or deadline ended the wait under
    /// [`CancelBehavior::ReturnRunning`], with the target still running.
    Running,
}

/// What a host's cancellation or deadline does to a run in progress. The
/// session's interrupt request ([`crate::nt::target::Target::interrupt`], raised
/// by Ctrl+C, a DAP `pause`, a Python `KeyboardInterrupt`) always halts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelBehavior {
    /// Hand control back with the target still running
    /// ([`RunOutcome::Running`]). A run to an address leaves its temporary
    /// sites armed, so a later wait stops there.
    ReturnRunning,
    /// Halt the target where it is, which ends on a stop
    /// ([`StopKind::Interrupt`] unless a stop raced the break-in).
    Halt,
}

/// A host's cancellation of a [`Session::run`]: a flag another thread
/// raises, a deadline, what either does, and a hook the wait calls between
/// polls (a host's live output, such as guest prints and notices). A step
/// or an instruction walk is always halted where it is, whatever
/// `behavior` says: no run is left to hand back.
#[derive(Clone, Copy)]
pub struct Cancel<'a> {
    pub flag: Option<&'a AtomicBool>,
    pub deadline: Option<Instant>,
    pub behavior: CancelBehavior,
    pub tick: Option<&'a dyn Fn(&mut Session)>,
}

impl Cancel<'static> {
    /// No cancellation of the host's own: the run ends on a stop, or on the
    /// session's interrupt request.
    pub const NEVER: Cancel<'static> = Cancel {
        flag: None,
        deadline: None,
        behavior: CancelBehavior::Halt,
        tick: None,
    };

    /// A wait of at most `timeout` that hands back a running target.
    pub fn within(timeout: Duration) -> Self {
        Cancel {
            flag: None,
            deadline: Some(Instant::now() + timeout),
            behavior: CancelBehavior::ReturnRunning,
            tick: None,
        }
    }

    /// A check for a stop that does not wait: a parked or pending stop
    /// surfaces, a running target is handed back running.
    pub fn poll() -> Self {
        Cancel {
            flag: None,
            deadline: Some(Instant::now()),
            behavior: CancelBehavior::ReturnRunning,
            tick: None,
        }
    }
}

impl<'a> Cancel<'a> {
    /// Whether the host's flag is raised or its deadline has passed.
    pub fn fired(&self) -> bool {
        self.flag.is_some_and(|flag| flag.load(Ordering::SeqCst))
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Time left before the deadline, `None` without one.
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// This cancellation with `behavior` instead.
    pub fn with_behavior(self, behavior: CancelBehavior) -> Self {
        Cancel { behavior, ..self }
    }

    /// This cancellation, also ending at `deadline` if that is sooner.
    pub fn until(self, deadline: Instant) -> Self {
        Cancel {
            deadline: Some(self.deadline.map_or(deadline, |own| own.min(deadline))),
            ..self
        }
    }

    pub fn tick(&self, session: &mut Session) {
        if let Some(tick) = self.tick {
            tick(session);
        }
    }
}

/// Runs the commands a stop carries: a breakpoint's `do` action, and the
/// `-c` command of the exception or module-event filter that stopped it.
/// The REPL's dispatcher is the one implementation; every host installs it
/// ([`Session::set_action_runner`]) on the sessions it opens, so every host
/// runs them the same way. Output goes to whatever the host captures or
/// prints at the time.
pub trait ActionRunner {
    /// Run a breakpoint's action. `true` when it asks to resume (`gc`, or a
    /// plain `g`), which passes the hit as a false condition would.
    fn breakpoint_action(&mut self, session: &mut Session, action: &str) -> bool;
    /// Run a filter's command, which may not move the target.
    fn event_command(&mut self, session: &mut Session, command: &str);
}

/// Why the target stopped, with the context it stopped in, snapshotted at
/// the stop. Each kind is a subclass with that kind's own parts:
/// `Stop.Breakpoint` (`breakpoint`), `Stop.Exception` (`exception`),
/// `Stop.ModuleLoad` and `Stop.ModuleUnload` (`module`), `Stop.Bugcheck`
/// (`bugcheck`), `Stop.Reload` (`reload`), `Stop.Step`, `Stop.Interrupt`
/// and `Stop.Entry`; `isinstance` and `match` tell them apart, as `kind`
/// does.
///
/// The parts are records, not live handles; the collections take them as
/// keys: `dbg.threads[stop.thread]`, `dbg.processes[stop.process]`,
/// `dbg.modules[stop.module]`; `dbg.cpus[stop.cpu]` is the processor.
#[record]
pub struct Stop {
    /// The kind of stop, in snake case.
    #[record(flatten)]
    pub kind: StopKind,
    /// The zero-based number of the processor that stopped, as `dbg.cpus`
    /// numbers them in the current view; `None` on a user-mode minidump,
    /// whose threads are no processors.
    pub cpu: Option<u16>,
    /// Where it stopped. A bugcheck's fault site is in `bugcheck`, a
    /// breakpoint's address in `breakpoint`, an exception's in `exception`.
    #[record(hex)]
    pub rip: Option<u64>,
    /// The nearest symbol to `rip`, named in the stopped vCPU's own address
    /// space.
    pub symbol: Option<String>,
    /// The process whose page tables the stopped vCPU has loaded (its CR3).
    pub process: Option<ProcessInfo>,
    /// The Windows thread the stopped vCPU runs.
    pub thread: Option<ThreadInfo>,
    /// The `.process` inspection scope at the stop, which can differ from
    /// `process`.
    pub inspection_process: Option<ProcessInfo>,
    /// The VTL the stopped vCPU runs in (1: the secure kernel); `None` for a
    /// user dump.
    pub vtl: Option<u8>,
    /// The hypervisor partition whose view (`.partition`) shows the stop.
    pub partition: Option<u64>,
}

impl Stop {
    /// The breakpoint hit, for a breakpoint stop.
    pub fn breakpoint(&self) -> Option<&BreakpointHit> {
        match &self.kind {
            StopKind::Breakpoint { breakpoint } => Some(breakpoint),
            _ => None,
        }
    }

    /// The exception, for an exception stop.
    pub fn exception(&self) -> Option<&ExceptionStop> {
        match &self.kind {
            StopKind::Exception { exception } => Some(exception),
            _ => None,
        }
    }

    /// The module, for a module load or unload stop.
    pub fn module(&self) -> Option<&ModuleInfo> {
        match &self.kind {
            StopKind::ModuleLoad { module } | StopKind::ModuleUnload { module } => Some(module),
            _ => None,
        }
    }

    /// The bugcheck code and parameters, for a bugcheck stop whose transport
    /// decoded them.
    pub fn bugcheck(&self) -> Option<&BugcheckInfo> {
        match &self.kind {
            StopKind::Bugcheck { bugcheck } => bugcheck.as_ref(),
            _ => None,
        }
    }

    /// The reload, for a reboot the debugger rebuilt its state for.
    pub fn reload(&self) -> Option<&ReloadStop> {
        match &self.kind {
            StopKind::Reload { reload } => Some(reload),
            _ => None,
        }
    }
}

/// Why a [`Stop`] stopped: its kind (in Python, its subclass of `Stop`) and
/// that kind's parts.
#[record(tagged, base = Stop)]
pub enum StopKind {
    /// A breakpoint or watchpoint hit.
    Breakpoint { breakpoint: BreakpointHit },
    /// A Windows exception.
    Exception { exception: ExceptionStop },
    /// A requested break-in, or a stop with no exception code.
    Interrupt,
    /// A completed step, or a run to an address that reached it.
    Step,
    /// A kernel image loaded, and a `ld` filter set to `break` names it
    /// (`dbg.exceptions.set_module_event("ld", ...)`, `sxe ld`). The module
    /// is listed with its symbols and breakpoints, and its entry point has
    /// not run.
    ModuleLoad { module: ModuleInfo },
    /// A kernel image is unloading, and a `ud` filter set to `break` names
    /// it (`sxe ud`). Its unload routine has run, and it is still listed.
    ModuleUnload { module: ModuleInfo },
    /// The guest is in a bugcheck. `bugcheck` is the code and parameters
    /// when the transport decoded them (`None` otherwise);
    /// `dbg.inspect.bugcheck()` reads and analyzes the bugcheck from guest
    /// memory (`!analyze`).
    Bugcheck { bugcheck: Option<BugcheckInfo> },
    /// The guest rebooted and the debugger rebuilt its state; earlier
    /// handles are stale.
    Reload { reload: ReloadStop },
    /// Nothing stopped the target since the debugger attached: it was found
    /// halted (a dump, a target attached halted).
    Entry,
}

/// A breakpoint hit that stopped the target.
#[record]
pub struct BreakpointHit {
    pub id: u32,
    /// Which breakpoint this is among every one created in this process: a
    /// later breakpoint that reuses `id`, or another debugger's, has
    /// another.
    pub serial: u64,
    pub kind: HitKind,
    /// The planted or watched address, not necessarily where it stopped.
    #[record(hex)]
    pub address: u64,
    /// A debug-register breakpoint's access and length.
    pub access: Option<HwBreakpointAccess>,
    pub length: Option<u8>,
    /// A VM-exit breakpoint's exit reason.
    pub exit_reason: Option<String>,
    pub symbol: Option<String>,
    pub temporary: bool,
    pub action: Option<String>,
    /// Why its condition failed to evaluate; the hit is surfaced instead.
    pub condition_error: Option<String>,
}

/// What a breakpoint watches, named in snake case.
#[record]
#[derive(Copy, PartialEq, Eq)]
pub enum HitKind {
    /// A patched (software) code breakpoint.
    Code,
    /// A debug-register execute breakpoint.
    Hardware,
    /// A debug-register data watch.
    Watch,
    /// A hypercall breakpoint (`!hvbp`).
    Hypercall,
    /// A VM-exit breakpoint (`!hvexit`).
    VmExit,
}

/// A Windows exception that stopped the target.
#[record]
#[derive(Copy, PartialEq, Eq)]
pub struct ExceptionStop {
    /// The NTSTATUS code.
    #[record(hex)]
    pub code: u32,
    /// Whether this is the first chance; `None` when the transport does not
    /// say.
    pub first_chance: Option<bool>,
    /// The exception record's address, when the transport gives one.
    #[record(hex)]
    pub address: Option<u64>,
}

/// A reboot the debugger rebuilt its state for.
#[record]
#[derive(Copy, PartialEq, Eq)]
pub struct ReloadStop {
    /// The new kernel's base.
    #[record(hex)]
    pub kernel_base: Option<u64>,
    /// Whether the kernel's module list exists yet.
    pub coherent: bool,
}

impl BreakpointHit {
    fn new(breakpoint: &BreakpointInfo, condition_error: Option<String>) -> Self {
        let kind = match (
            breakpoint.hypercall,
            breakpoint.vm_exit,
            breakpoint.hardware,
        ) {
            (Some(_), _, _) => HitKind::Hypercall,
            (None, Some(_), _) => HitKind::VmExit,
            (None, None, Some(hardware)) if hardware.access == HwBreakpointAccess::Execute => {
                HitKind::Hardware
            }
            (None, None, Some(_)) => HitKind::Watch,
            (None, None, None) => HitKind::Code,
        };
        BreakpointHit {
            id: breakpoint.id,
            serial: breakpoint.serial,
            kind,
            address: breakpoint.address.0,
            access: breakpoint.hardware.map(|hardware| hardware.access),
            length: breakpoint.hardware.map(|hardware| hardware.len),
            exit_reason: breakpoint.vm_exit.map(|filter| filter.label().to_string()),
            symbol: breakpoint.symbol.clone(),
            temporary: breakpoint.temporary,
            action: breakpoint.action.clone(),
            condition_error,
        }
    }
}

/// The notice for an exception a `notify` policy continued past.
fn notify_line(code: u32, first_chance: Option<bool>, address: Option<u64>) -> String {
    let chance = match first_chance {
        Some(true) => "first chance",
        Some(false) => "second chance",
        None => "unknown chance",
    };
    let location = address
        .map(|address| format!(" at {address:#x}"))
        .unwrap_or_default();
    format!("Exception {code:#010x} ({chance}){location}; continuing")
}

impl Session {
    /// Move the target per `motion` and report where it stopped, the one
    /// run-control entry point for every host. Every breakpoint stop runs
    /// its action; a hit whose action asks to resume is passed as a declined
    /// hit is ([`Self::decline`]), unless a halt was asked for (a
    /// `Motion::Break`, a cancellation that halts) or the session's
    /// interrupt request arrived meanwhile: halt wins.
    pub fn run(&mut self, motion: Motion, cancel: &Cancel<'_>) -> Result<RunOutcome> {
        let stepping = self.current_thread.clone();
        let mut motion = self.plan(motion)?;
        loop {
            self.halt_requested = false;
            let (outcome, fresh) = self.advance(&motion, cancel)?;
            if matches!(outcome, ContinueOutcome::Running) {
                return Ok(RunOutcome::Running);
            }
            if !fresh {
                return Ok(RunOutcome::Stopped(self.current_snapshot(outcome)));
            }
            self.note_stop(&outcome);
            let stop = self.current_snapshot(outcome);
            // The action runs for every breakpoint stop. A halt that was
            // asked for (`Motion::Break`, a cancellation that halts, Ctrl+C)
            // wins over a resume the action asks for: the target stays at
            // the hit.
            if let Some(action) = stop.breakpoint().and_then(|hit| hit.action.clone())
                && self.run_breakpoint_action(&action)
                && !self.halt_requested
                // A Ctrl+C taken meanwhile breaks in at the hit instead of
                // being lost to the action's resume.
                && !self.target.interrupt.swap(false, Ordering::SeqCst)
            {
                cancel.tick(self);
                motion = self.decline(motion, &stepping)?;
                continue;
            }
            return Ok(RunOutcome::Stopped(stop));
        }
    }

    /// `motion` made concrete where the target is now: a step over becomes
    /// a single step or a run to the call's return site, a step out a run to
    /// the caller. A host that goes on past a declined stop
    /// ([`Self::decline`]) plans first, so the motion it repeats is the one
    /// that ran.
    pub fn plan(&mut self, motion: Motion) -> Result<Motion> {
        Ok(match motion {
            Motion::StepOver => match self.step_over_target()? {
                StepKind::Single => Motion::Step,
                StepKind::RunTo(address) => Motion::RunTo {
                    address,
                    frame: self.step_frame(StepStack::CallReturn)?,
                    disposition: ContinueDisposition::Handled,
                },
            },
            Motion::StepOut => {
                let address = self.step_out_target()?;
                Motion::RunTo {
                    address,
                    frame: self.step_frame(StepStack::FunctionReturn)?,
                    disposition: ContinueDisposition::Handled,
                }
            }
            motion => motion,
        })
    }

    /// The motion that goes on past the stop a planned `motion` ended on,
    /// which the host declined (a Python `when=` callback, or an action's
    /// `gc`): a run resumes from the hit, a run to an address re-arms its
    /// sites, a walk goes on from where its thread is, and a single step
    /// that a hit on another vCPU than `stepping` interrupted steps that
    /// vCPU past it and steps `stepping` again.
    pub fn decline(&mut self, motion: Motion, stepping: &str) -> Result<Motion> {
        Ok(match motion {
            Motion::Continue { .. } | Motion::Wait => Motion::Continue {
                disposition: ContinueDisposition::Handled,
            },
            Motion::RunTo { address, frame, .. } => Motion::RunTo {
                address,
                frame,
                disposition: ContinueDisposition::Handled,
            },
            Motion::Walk {
                mode, until, limit, ..
            } => Motion::Walk {
                mode,
                until,
                limit,
                resume: true,
            },
            Motion::Step => {
                self.pass_declined_hit(stepping)?;
                Motion::Step
            }
            motion @ (Motion::Break | Motion::StepOver | Motion::StepOut) => motion,
        })
    }

    /// One attempt at a planned `motion`, and whether its stop is new (not
    /// the one the target was already halted at, whose action already ran).
    /// A motion that would resume a halted target first surfaces a stop
    /// parked while the host was idle, one the backend holds, or a reload
    /// owed to the host, as that motion's stop: resuming would lose it.
    fn advance(&mut self, motion: &Motion, cancel: &Cancel<'_>) -> Result<(ContinueOutcome, bool)> {
        if !matches!(motion, Motion::Wait | Motion::Break)
            && !self.backend.is_running()
            && !self.halted_with_nothing_pending()
        {
            match self.wait_stop(cancel, true)? {
                ContinueOutcome::Halted { .. } => {}
                outcome => return Ok((outcome, true)),
            }
        }
        Ok(match motion {
            Motion::Continue { disposition } => (self.continue_stop(*disposition, cancel)?, true),
            Motion::Wait => {
                if self.halted_with_nothing_pending() {
                    return Ok((self.halted_outcome(), false));
                }
                match self.wait_stop(cancel, true)? {
                    ContinueOutcome::Halted { .. } => (self.halted_outcome(), false),
                    outcome => (outcome, true),
                }
            }
            Motion::Break => {
                if self.halted_with_nothing_pending() {
                    return Ok((self.halted_outcome(), false));
                }
                (self.halt()?, true)
            }
            Motion::Step => (self.step()?, true),
            Motion::RunTo {
                address,
                frame,
                disposition,
            } => (
                self.run_to_any(&[(*address, frame.clone())], *disposition, cancel)?,
                true,
            ),
            Motion::Walk {
                mode,
                until,
                limit,
                resume,
            } => {
                let until = *until;
                let holds = move |ip, flow| until.holds(ip, flow);
                let outcome = if *resume {
                    self.resume_step_until(*mode, *limit, cancel, holds)?
                } else {
                    self.step_until(*mode, *limit, cancel, holds)?
                };
                (outcome, true)
            }
            Motion::StepOver | Motion::StepOut => unreachable!("planned away"),
        })
    }

    /// Halted, with no parked, pending, or owed stop to surface.
    fn halted_with_nothing_pending(&self) -> bool {
        !self.backend.is_running()
            && !self.backend.has_pending_stop()
            && self.parked_stop.is_none()
            && !self.reload_surface_pending
    }

    /// Resume with `disposition` unless the target already runs, then wait
    /// for the next stop.
    pub fn continue_stop(
        &mut self,
        disposition: ContinueDisposition,
        cancel: &Cancel<'_>,
    ) -> Result<ContinueOutcome> {
        if !self.backend.is_running() {
            self.resume_with_disposition(disposition)?;
        }
        self.wait_stop(cancel, true)
    }

    /// Break in for a requested halt and return the stop it ends on: the
    /// break-in itself is a stop without an exception code; a stop it
    /// collected instead (a pending hit, a guest exception) keeps its own.
    /// An exception whose policy continues is continued and broken into
    /// again. A parked stop surfaces as itself.
    pub fn halt(&mut self) -> Result<ContinueOutcome> {
        self.halt_requested = true;
        if let Some(parked) = self.parked_stop.take()
            && !self.surface_policy(&parked, true)?
        {
            return Ok(parked);
        }
        let mut attempts = 0;
        loop {
            attempts += 1;
            let (resolution, candidate) = self.interrupt_classified()?;
            let own = self.is_own_breakin(&resolution, candidate);
            let mut outcome = self.continue_outcome_from_resolution(resolution);
            if own {
                if let ContinueOutcome::Stopped {
                    exception_code,
                    first_chance,
                    exception_address,
                    ..
                } = &mut outcome
                {
                    *exception_code = None;
                    *first_chance = None;
                    *exception_address = None;
                }
                return Ok(outcome);
            }
            if attempts < HALT_ATTEMPTS && self.surface_policy(&outcome, true)? {
                continue;
            }
            return Ok(outcome);
        }
    }

    /// What the host's cancellation does to a wait in progress.
    fn cancelled(&mut self, cancel: &Cancel<'_>) -> Result<ContinueOutcome> {
        match cancel.behavior {
            CancelBehavior::ReturnRunning => Ok(ContinueOutcome::Running),
            CancelBehavior::Halt => self.halt(),
        }
    }

    /// Wait for the next stop worth surfacing **without resuming**: a stop
    /// parked while the host was idle comes first; debugger noise is
    /// absorbed; exceptions and module events get their policies. `hosted`
    /// is false for idle servicing, which runs no commands (a stop whose
    /// policy has one surfaces, parked, for the next hosted wait) and leaves
    /// the interrupt request alone. A halted target with nothing pending is
    /// [`ContinueOutcome::Halted`]; a reload owed to the host surfaces
    /// first.
    pub fn wait_stop(&mut self, cancel: &Cancel<'_>, hosted: bool) -> Result<ContinueOutcome> {
        if let Some(parked) = self.parked_stop.take()
            && !self.surface_policy(&parked, hosted)?
        {
            return Ok(parked);
        }
        loop {
            if hosted && self.target.interrupt.swap(false, Ordering::SeqCst) {
                return self.halt();
            }
            if hosted {
                cancel.tick(self);
            }
            if cancel.flag.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
                return self.cancelled(cancel);
            }
            // A deadline already reached still polls once, without waiting:
            // a stop the backend holds surfaces.
            let poll = cancel
                .remaining()
                .map_or(POLL_INTERVAL, |remaining| remaining.min(POLL_INTERVAL));
            let Some(event) = self.backend.try_wait_for_stop(poll)? else {
                if !self.backend.is_running() {
                    // Flush a reload nobody surfaced before reporting a plain halt.
                    if self.reload_surface_pending {
                        self.reload_surface_pending = false;
                        return Ok(ContinueOutcome::TargetReloaded {
                            rip: self
                                .last_event
                                .as_ref()
                                .and_then(|last| last.stop.program_counter),
                            kernel_base: self.target.kernel_base().map(|a| a.0),
                            coherent: self.kernel_coherent(),
                        });
                    }
                    let rip = self.current_rip();
                    return Ok(ContinueOutcome::Halted { rip });
                }
                if cancel.fired() {
                    return self.cancelled(cancel);
                }
                continue;
            };
            let resolution = self.classify_stop_event(event)?;
            if let StopResolution::TargetReloaded { coherent, .. } = &resolution {
                reload_trace!(
                    "continue: SURFACE target_reloaded base={} coherent={}",
                    self.target
                        .kernel_base()
                        .map_or_else(|| "none".to_string(), |address| format!("{:#x}", address.0)),
                    coherent,
                );
            }
            if !matches!(
                resolution,
                StopResolution::Resumed | StopResolution::ModulesChanged
            ) {
                let outcome = self.continue_outcome_from_resolution(resolution);
                if !self.surface_policy(&outcome, hosted)? {
                    return Ok(outcome);
                }
            }
            // Absorbed, and the target runs on. A hot site whose condition
            // stays false keeps the backend reporting stops, so the poll
            // above never comes back empty: the deadline is checked here too.
            if cancel.fired() {
                return self.cancelled(cancel);
            }
        }
    }

    /// Apply the exception or module-event policy to the stop just
    /// classified, `outcome`: run its command (`hosted` only), say so for
    /// `notify`, and continue it when the policy does. `true` when the target
    /// was continued; a policy with a command an idle (not `hosted`) wait
    /// cannot run leaves the stop to surface, parked.
    fn surface_policy(&mut self, outcome: &ContinueOutcome, hosted: bool) -> Result<bool> {
        match outcome {
            ContinueOutcome::Stopped {
                exception_code: Some(code),
                first_chance,
                exception_address,
                rip,
            } => {
                let Some(event) = self.last_event.as_ref().map(|last| last.stop.clone()) else {
                    return Ok(false);
                };
                match self.exception_policies.action_for(&event) {
                    ExceptionPolicyAction::Surface { command } => {
                        if hosted && let Some(command) = command {
                            self.run_event_command(&command);
                        }
                        Ok(false)
                    }
                    ExceptionPolicyAction::Continue {
                        command: Some(_), ..
                    } if !hosted => Ok(false),
                    ExceptionPolicyAction::Continue {
                        notify,
                        disposition,
                        command,
                    } => {
                        if let Some(command) = command {
                            self.run_event_command(&command);
                        }
                        if notify {
                            self.notices.push(Notice::info(notify_line(
                                *code,
                                *first_chance,
                                exception_address.or(Some(*rip)),
                            )));
                        }
                        self.continue_backend(disposition)?;
                        self.record_continuation_disposition(disposition);
                        Ok(true)
                    }
                }
            }
            ContinueOutcome::ModuleLoad { module, .. } if hosted => {
                self.run_module_event_command(ModuleEvent::Load, module);
                Ok(false)
            }
            ContinueOutcome::ModuleUnload { module, .. } if hosted => {
                self.run_module_event_command(ModuleEvent::Unload, module);
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Run the `-c` command of the `sxe ld` or `sxe ud` filter that stopped
    /// for `module`.
    fn run_module_event_command(&mut self, event: ModuleEvent, module: &ModuleInfo) {
        if let Some(command) = self
            .exception_policies
            .module_event_policy(event, &module.name)
            .and_then(|policy| policy.command.clone())
        {
            self.run_event_command(&command);
        }
    }

    fn run_event_command(&mut self, command: &str) {
        if let Some(mut runner) = self.action_runner.take() {
            runner.event_command(self, command);
            self.action_runner = Some(runner);
        }
    }

    /// Install the host's [`ActionRunner`], which runs every later stop's
    /// breakpoint action and filter command.
    pub fn set_action_runner(&mut self, runner: Box<dyn ActionRunner>) {
        self.action_runner = Some(runner);
    }

    /// Run a breakpoint's action; whether it asked to resume. A session
    /// without a runner (no host installed one), or one already running an
    /// action, runs none.
    pub(super) fn run_breakpoint_action(&mut self, action: &str) -> bool {
        let Some(mut runner) = self.action_runner.take() else {
            return false;
        };
        let resume = runner.breakpoint_action(self, action);
        self.action_runner = Some(runner);
        resume
    }

    /// The stop the target is halted at, snapshotted when it surfaced; a
    /// [`StopKind::Entry`] when nothing stopped it since the debugger
    /// attached. `None` while it runs. A stop the backend caught but no host
    /// surfaced yet is classified and parked first, so the next wait still
    /// delivers it (and runs its action).
    pub fn halted_stop(&mut self) -> Result<Option<Stop>> {
        self.settle_pending_stop()?;
        if self.backend.is_running() {
            return Ok(None);
        }
        let outcome = self.halted_outcome();
        Ok(Some(self.current_snapshot(outcome)))
    }

    /// Record that the host's own condition for the breakpoint hit the target
    /// is halted at failed to evaluate (a Python `when=` callback that
    /// raised): the hit surfaces with `error`, as a failed `condition=` does.
    /// The stop as it now reads; `None` when no stop was snapshotted.
    pub fn fail_stop_condition(&mut self, error: String) -> Option<Stop> {
        if let Some(ContinueOutcome::Breakpoint {
            condition_error, ..
        }) = &mut self.current_stop
        {
            *condition_error = Some(error.clone());
        }
        let stop = self.stop_snapshot.as_mut()?;
        if let StopKind::Breakpoint { breakpoint } = &mut stop.kind {
            breakpoint.condition_error = Some(error);
        }
        Some(stop.clone())
    }

    /// A stop for a run whose end the backend never reported (its wait
    /// failed): a host that must tell its client the run ended reports this,
    /// at wherever the stopped vCPU's registers say.
    pub fn unreported_stop(&mut self) -> Stop {
        let rip = self.current_rip();
        self.snapshot(ContinueOutcome::Halted { rip })
    }

    /// The snapshot of the stop the target is halted at, `outcome`, taken
    /// once: later reads keep what the stop showed, whatever the inspection
    /// context became.
    fn current_snapshot(&mut self, outcome: ContinueOutcome) -> Stop {
        if let Some(stop) = &self.stop_snapshot {
            return stop.clone();
        }
        let stop = self.snapshot(outcome);
        self.stop_snapshot = Some(stop.clone());
        stop
    }

    /// The [`Stop`] for a classified halt, read from the stopped vCPU now.
    fn snapshot(&mut self, outcome: ContinueOutcome) -> Stop {
        let registers = self.backend.read_registers().ok();
        let read = |name: &str| {
            registers
                .as_ref()
                .and_then(|registers| self.register_map.read_u64(name, registers).ok())
        };
        let cr3 = read(self.target.arch().dtb_register());
        let register_rip = read(self.target.arch().pc_register());
        let mask = self.target.arch().dtb_page_mask();
        let secure = cr3.is_some_and(|cr3| self.target.recognize_secure_root(cr3 & mask));
        let user_dump = self.target.user_dump_info().is_some();
        let process = cr3
            .filter(|_| !secure && !user_dump)
            .and_then(|cr3| self.target.process_for_cr3(cr3 & mask));
        let thread = windows_thread_on_backend_thread(&self.target, &self.current_thread);
        let mut stop = Stop {
            kind: StopKind::Entry,
            cpu: (!user_dump)
                .then(|| processor_index_from_backend_thread_id(&self.current_thread))
                .flatten(),
            rip: register_rip,
            symbol: None,
            process,
            thread,
            inspection_process: self.target.attached_process().cloned(),
            vtl: (!user_dump).then_some(if secure { 1 } else { 0 }),
            partition: self.partition(),
        };
        let rip = match outcome {
            ContinueOutcome::Breakpoint {
                id,
                rip,
                temporary,
                condition_error,
                ..
            } => {
                // A run to an address reaching its own site is a step's end,
                // whichever wait saw it. A hit breakpoint is kept until the
                // next resume, so it is still there to describe.
                stop.kind = match self.breakpoints.get(id) {
                    _ if temporary => StopKind::Step,
                    Some(breakpoint) => StopKind::Breakpoint {
                        breakpoint: BreakpointHit::new(breakpoint, condition_error),
                    },
                    None => StopKind::Interrupt,
                };
                Some(rip)
            }
            ContinueOutcome::Bugcheck { rip, info } => {
                stop.kind = StopKind::Bugcheck { bugcheck: info };
                rip
            }
            ContinueOutcome::Stopped {
                rip,
                exception_code,
                first_chance,
                exception_address,
            } => {
                match exception_code {
                    Some(code) => {
                        stop.kind = StopKind::Exception {
                            exception: ExceptionStop {
                                code,
                                first_chance,
                                address: exception_address,
                            },
                        };
                    }
                    None => stop.kind = StopKind::Interrupt,
                }
                Some(rip)
            }
            ContinueOutcome::Step { rip } => {
                stop.kind = StopKind::Step;
                Some(rip)
            }
            ContinueOutcome::ModuleLoad { module, rip } => {
                stop.kind = StopKind::ModuleLoad { module: *module };
                Some(rip)
            }
            ContinueOutcome::ModuleUnload { module, rip } => {
                stop.kind = StopKind::ModuleUnload { module: *module };
                Some(rip)
            }
            ContinueOutcome::TargetReloaded {
                rip,
                kernel_base,
                coherent,
            } => {
                stop.kind = StopKind::Reload {
                    reload: ReloadStop {
                        kernel_base,
                        coherent,
                    },
                };
                rip
            }
            ContinueOutcome::Halted { rip } => Some(rip),
            ContinueOutcome::Running => unreachable!("a running target has no stop"),
        };
        stop.rip = rip.filter(|rip| *rip != 0).or(stop.rip);
        stop.symbol = stop
            .rip
            .and_then(|rip| try_format_symbol_at(&self.target, cr3.unwrap_or(0), rip));
        stop
    }
}
