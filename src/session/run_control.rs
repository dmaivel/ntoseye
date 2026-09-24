//! Resuming the target and breaking in: the resume prologue, exception
//! dispositions, interrupts, and edits made with the target briefly halted.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::dbg_backend::{ContinueDisposition, DebugCapability, StopEvent};
use crate::error::{Error, Result};
use crate::session::stepping::step_over_current_breakpoint;
use crate::session::{ContinueOutcome, STATUS_BREAKPOINT, Session, StopResolution};

/// How many noise stops [`Session::interrupt`] resumes past before surfacing
/// whatever the target is doing.
const INTERRUPT_MAX_RESUMES: usize = 8;

impl Session {
    fn interrupt_classified(&mut self) -> Result<(StopResolution, bool)> {
        let mut resumed = 0;
        loop {
            let stop_was_pending = self.backend.has_pending_stop();
            let event = self.backend.interrupt()?;
            let resolution = self.classify_stop_event(event)?;
            match resolution {
                StopResolution::Resumed => {
                    resumed += 1;
                    if resumed < INTERRUPT_MAX_RESUMES {
                        continue;
                    }
                    // Surface a generic stop after the bounded noise budget.
                    let stop_was_pending = self.backend.has_pending_stop();
                    let event = self.backend.interrupt()?;
                    let resolution = StopResolution::Stopped {
                        rip: event.program_counter.unwrap_or(0),
                        event,
                    };
                    return Ok((resolution, !stop_was_pending));
                }
                StopResolution::ModulesChanged => continue,
                resolution => return Ok((resolution, !stop_was_pending)),
            }
        }
    }

    /// Pause the VM and return the first meaningful stop. Every raw event routes
    /// through [`Self::classify_stop_event`], so an interrupt that races with a
    /// filtered breakpoint or reconnect-assist stop cannot bypass core state.
    ///
    /// Bounded: while the guest is rebooting (reconnect assist) or hammering a
    /// wrong-process breakpoint, every break-in can classify as noise and be
    /// resumed; after [`INTERRUPT_MAX_RESUMES`] of those the last stop is
    /// surfaced as-is rather than spinning forever (the ^D exit path lives on
    /// this).
    pub fn interrupt(&mut self) -> Result<StopEvent> {
        self.interrupt_classified()
            .map(|(resolution, _)| match resolution {
                StopResolution::Breakpoint { event, .. }
                | StopResolution::Bugcheck { event }
                | StopResolution::TargetReloaded { event, .. }
                | StopResolution::Stopped { event, .. } => event,
                StopResolution::Resumed | StopResolution::ModulesChanged => {
                    unreachable!("absorbed stop cannot be returned")
                }
            })
    }

    /// [`Self::interrupt`] keeping the classification: a breakpoint hit that
    /// races the break-in is reported as that breakpoint (with its action and
    /// condition result) rather than as a bare `STATUS_BREAKPOINT` stop. A
    /// target that is not running is not broken into (KD would wait out its
    /// break-in timeout): a stop parked by [`Self::with_target_halted`] or
    /// [`Self::service_idle`] is surfaced, and a halted target reports the
    /// stop it is halted at ([`Self::current_stop`]), or its pc.
    pub fn interrupt_outcome(&mut self) -> Result<ContinueOutcome> {
        if let Some(stop) = self.stop_without_breakin() {
            return Ok(stop);
        }
        self.interrupt_classified()
            .map(|(resolution, _)| self.continue_outcome_from_resolution(resolution))
    }

    /// [`Self::interrupt_outcome`] for a host that asked for the break-in and
    /// reports it as such: the break-in the interrupt itself caused comes back
    /// as a `Stopped` without an exception code. A parked stop, or a pending
    /// guest exception (a real `int 3`) the break-in collected, keeps its code.
    pub fn interrupt_requested(&mut self) -> Result<ContinueOutcome> {
        if let Some(stop) = self.stop_without_breakin() {
            return Ok(stop);
        }
        let (resolution, own_breakin_candidate) = self.interrupt_classified()?;
        let own_breakin = self.is_own_breakin(&resolution, own_breakin_candidate);
        let mut outcome = self.continue_outcome_from_resolution(resolution);
        if own_breakin
            && let ContinueOutcome::Stopped {
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
        self.note_stop(&outcome);
        Ok(outcome)
    }

    /// The stop an interrupt reports without breaking in: a parked stop, or
    /// the one a halted target is at. `None` when the target must be broken
    /// into.
    fn stop_without_breakin(&mut self) -> Option<ContinueOutcome> {
        if let Some(parked) = self.parked_stop.take() {
            return Some(parked);
        }
        (!self.backend.is_running() && !self.backend.has_pending_stop())
            .then(|| self.halted_outcome())
    }

    /// The stop a halted target is at, or a bare halt at its pc when it has
    /// not stopped since it last moved (attached halted).
    pub fn halted_outcome(&mut self) -> ContinueOutcome {
        match &self.current_stop {
            Some(stop) => stop.clone(),
            None => ContinueOutcome::Halted {
                rip: self.current_rip(),
            },
        }
    }

    /// Whether an interrupt's stop is the break-in it requested. The KD rule
    /// is the same status/non-managed-address split used by
    /// `stop_is_assisted_refresh_breakin`: a STATUS_BREAKPOINT that classified
    /// as an ordinary stop and is not on one of our sites. A stop the backend
    /// already had pending (`candidate` false) wins even with the same status.
    fn is_own_breakin(&self, resolution: &StopResolution, candidate: bool) -> bool {
        let StopResolution::Stopped { event, .. } = resolution else {
            return false;
        };
        candidate
            && event.exception_code == Some(STATUS_BREAKPOINT)
            && event
                .program_counter
                .is_none_or(|pc| self.breakpoints.breakpoint_id_at_address(pc).is_none())
    }

    /// Run `edit` with the target halted, restoring the previous run state.
    /// If the target is already halted, `edit` runs directly and neither
    /// interrupts nor resumes the backend. If it is running, this method breaks
    /// in, runs `edit`, and resumes afterward unless the interrupt exposed a
    /// genuine pending stop. Such a stop is left halted and parked for the next
    /// [`Self::wait_for_stop_bounded`], while an edit error still resumes an
    /// otherwise ordinary break-in before returning the error. This primitive is
    /// shared by hosts that edit breakpoint state; it emits no notifications.
    pub fn with_target_halted<T>(
        &mut self,
        edit: impl FnOnce(&mut Session) -> Result<T>,
    ) -> Result<T> {
        let interrupt_supported = self.backend.capabilities().iter().any(|capability| {
            capability.capability == DebugCapability::InterruptTarget && capability.supported
        });
        if !self.backend.is_running() || !interrupt_supported {
            return edit(self);
        }

        let (resolution, own_breakin_candidate) = self.interrupt_classified()?;
        if !self.is_own_breakin(&resolution, own_breakin_candidate) {
            self.parked_stop = Some(self.continue_outcome_from_resolution(resolution));
            return edit(self);
        }

        let result = edit(self);
        let resume = self.resume();
        match (result, resume) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(edit_error), Err(resume_error)) => Err(Error::DebugInfo(format!(
                "{edit_error}; failed to resume target: {resume_error}"
            ))),
        }
    }

    /// Resume the VM. If sitting on one of our breakpoints, step past it first
    /// (otherwise the `int3` at RIP re-fires immediately), re-arm enabled
    /// breakpoints, then continue and drop the now-stale inspection caches.
    /// The canonical resume prologue, shared by the REPL and the SDK.
    ///
    /// Does not poll for Ctrl+C or handle KD target-reload/reconnect the way the
    /// REPL's continue loop does; those remain REPL concerns.
    pub fn resume(&mut self) -> Result<()> {
        self.resume_with_disposition(ContinueDisposition::Handled)
    }

    /// Clear every inspection cache that cannot survive a crash/reboot command
    /// before the shared wait loop re-establishes the next stop.
    pub fn clear_resume_state(&mut self) {
        self.target.selected_frame = None;
        self.target.registers = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        self.target.last_exception_code = None;
        self.parked_windows_thread = None;
        self.parked_stop = None;
        self.current_stop = None;
        self.module_refresh_report = None;
    }

    /// Request a target reboot and clear register/context state before its
    /// reload stop is collected.
    pub fn request_reboot(&mut self) -> Result<()> {
        self.backend.reboot_target()?;
        self.clear_resume_state();
        Ok(())
    }

    /// Request a target bugcheck and clear register/context state before the
    /// resulting stop is collected.
    pub fn request_crash(&mut self) -> Result<()> {
        self.backend.cause_bugcheck()?;
        self.clear_resume_state();
        Ok(())
    }

    /// Resume with an explicit exception acknowledgment while preserving the
    /// same breakpoint step-over and cache invalidation prologue as [`Self::resume`].
    pub fn resume_with_disposition(&mut self, disposition: ContinueDisposition) -> Result<()> {
        self.target.selected_frame = None;
        self.module_refresh_report = None;
        // A bugcheck can only happen while the guest runs, so the trap has to
        // be in place before it does. Arming on stop alone would miss a crash
        // provoked immediately after attach.
        self.arm_bugcheck_trap();
        if self.parked_windows_thread().is_some() {
            self.parked_windows_thread = None;
            self.target.clear_current_windows_thread_context();
            self.refresh_context_for_current_thread();
        }
        // The VM is moving on, so any stop `service_idle` parked for the host to
        // observe is now spent; drop it so a later `wait_for_stop` doesn't replay
        // a stale event.
        self.parked_stop = None;
        self.current_stop = None;
        // If a post-reboot rediscovery is still pending only because the module
        // list wasn't up yet, finish it from memory before continuing. We are
        // halted, so the next `continue` starts the pump with the reconnect-assist
        // poking already off, instead of resuming into another forced break-in.
        self.try_finish_rediscovery_from_memory();
        if self.breakpoints.has_enabled_breakpoints() {
            self.backend.set_current_thread(&self.current_thread)?;
            step_over_current_breakpoint(
                self.backend.as_mut(),
                &self.register_map,
                &self.target,
                &mut self.breakpoints,
            )?;
        }
        for id in self.breakpoints.one_shot_hit_ids() {
            self.breakpoints
                .remove(self.backend.as_mut(), &self.target, id)?;
        }

        self.breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.continue_backend(disposition)?;
        self.record_continuation_disposition(disposition);

        Ok(())
    }

    /// Continue without user-command preparation (breakpoint refresh/step-over),
    /// but with the same inspection lifetime as an explicit resume.
    pub(super) fn continue_backend(&mut self, disposition: ContinueDisposition) -> Result<()> {
        self.backend
            .continue_execution_with_disposition(disposition)?;
        self.invalidate_running_context();
        Ok(())
    }

    /// No stopped inspection view survives a successful continuation, including
    /// one performed internally while absorbing a breakpoint or notification.
    pub(super) fn invalidate_running_context(&mut self) {
        self.target.selected_frame = None;
        self.target.registers = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        self.parked_windows_thread = None;
    }

    /// Resume the VM (unless already running, in which case no exception
    /// acknowledgment is sent) with `disposition`, then wait up to `timeout`
    /// for a meaningful stop; wrong-process int3 hits and false conditional
    /// breakpoints are stepped over silently. `None` waits indefinitely;
    /// `cancel` or an elapsed timeout returns [`ContinueOutcome::Running`]
    /// with the VM left running. Non-resuming observation is
    /// [`Self::wait_for_stop_bounded`].
    pub fn continue_until_break(
        &mut self,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
        disposition: ContinueDisposition,
    ) -> Result<ContinueOutcome> {
        if !self.backend.is_running() {
            self.resume_with_disposition(disposition)?;
        }
        self.wait_for_stop_bounded(timeout, cancel)
    }
}
