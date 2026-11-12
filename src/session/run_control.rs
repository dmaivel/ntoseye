//! Resuming the target and breaking in: the resume prologue, exception
//! dispositions, interrupts, and edits made with the target briefly halted.

use crate::backend::dbg_backend::{ContinueDisposition, DebugCapability, StopEvent};
use crate::base::error::{Error, Result};
use crate::session::{ContinueOutcome, STATUS_BREAKPOINT, Session, StopResolution};

/// How many noise stops [`Session::interrupt`] resumes past before surfacing
/// whatever the target is doing.
const INTERRUPT_MAX_RESUMES: usize = 8;

impl Session {
    /// Break in and classify the stop, breaking in again past one that is
    /// resumed (a hit a filter declines), up to [`INTERRUPT_MAX_RESUMES`]
    /// times; the last try holds a declined hit as the pause, and a stop
    /// still resumed then surfaces as a plain one. With it, whether
    /// the stop is the break-in itself rather than one already pending.
    pub fn interrupt_classified(&mut self) -> Result<(StopResolution, bool)> {
        let mut resumed = 0;
        loop {
            let stop_was_pending = self.backend.has_pending_stop();
            let event = self.backend.interrupt()?;
            step_trace!(
                "break-in on {:?} at {:x?} (a stop was pending: {stop_was_pending})",
                event.thread_id,
                event.program_counter
            );
            // The last try holds a hit a filter declines as the pause: hits
            // that come faster than the target polls for the break-in would
            // otherwise be all a break-in ever collects.
            self.hold_declined_hits = resumed + 1 >= INTERRUPT_MAX_RESUMES;
            let resolution = self.classify_stop_event(event);
            self.hold_declined_hits = false;
            match resolution? {
                StopResolution::Resumed => {
                    resumed += 1;
                    step_trace!("break-in resumed past a declined stop ({resumed})");
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
    /// resumed; after `INTERRUPT_MAX_RESUMES` of those the last stop is
    /// surfaced as-is rather than spinning forever (the ^D exit path lives on
    /// this).
    pub fn interrupt(&mut self) -> Result<StopEvent> {
        self.interrupt_classified()
            .map(|(resolution, _)| match resolution {
                StopResolution::Breakpoint { event, .. }
                | StopResolution::Bugcheck { event }
                | StopResolution::ModuleLoad { event, .. }
                | StopResolution::ModuleUnload { event, .. }
                | StopResolution::TargetReloaded { event, .. }
                | StopResolution::Stopped { event, .. } => event,
                StopResolution::Resumed | StopResolution::ModulesChanged => {
                    unreachable!("absorbed stop cannot be returned")
                }
            })
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

    /// Whether an interrupt's stop is the break-in it requested. A backend
    /// that tells break-ins apart (gdb's `SIGINT`) reports `break_in`. KD
    /// reports a break-in as a STATUS_BREAKPOINT, so there the rule is the
    /// same status/non-managed-address split used by
    /// `stop_is_assisted_refresh_breakin`: a STATUS_BREAKPOINT that classified
    /// as an ordinary stop and is not on one of our sites. A stop the backend
    /// already had pending (`candidate` false) wins even with the same status.
    pub fn is_own_breakin(&self, resolution: &StopResolution, candidate: bool) -> bool {
        let StopResolution::Stopped { event, .. } = resolution else {
            return false;
        };
        candidate
            && (event.break_in
                || (event.exception_code == Some(STATUS_BREAKPOINT)
                    && event
                        .program_counter
                        .is_none_or(|pc| self.breakpoints.breakpoint_id_at_address(pc).is_none())))
    }

    /// Run `edit` with the target halted, restoring the previous run state.
    /// If the target is already halted, `edit` runs directly and neither
    /// interrupts nor resumes the backend. If it is running, this method breaks
    /// in, runs `edit`, and resumes afterward unless the interrupt exposed a
    /// genuine pending stop. Such a stop is left halted and parked for the next
    /// wait ([`Self::run`]), while an edit error still resumes an
    /// otherwise ordinary break-in before returning the error. This primitive is
    /// shared by hosts that edit breakpoint state; it emits no notifications.
    pub fn with_target_halted<T>(
        &mut self,
        edit: impl FnOnce(&mut Session) -> Result<T>,
    ) -> Result<T> {
        let interrupt_supported = self.backend.supports(DebugCapability::InterruptTarget);
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
    /// It waits for nothing: a run that ends on a stop goes through
    /// [`Self::run`]. Only a resume that reports no stop calls it directly:
    /// [`Self::with_target_halted`]'s own break-in, and gdbserver's detach.
    pub fn resume(&mut self) -> Result<()> {
        self.resume_with_disposition(ContinueDisposition::Handled)
    }

    /// Clear every inspection cache that cannot survive a crash/reboot command
    /// before the shared wait loop re-establishes the next stop.
    pub fn clear_resume_state(&mut self) {
        // The target runs into the crash, which ends a `.process` context
        // as any run does.
        self.target.end_process_context_on_run();
        self.target.selected_frame = None;
        self.target.registers = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        self.target.last_exception_code = None;
        self.target.breakpoint_stop = None;
        self.parked_windows_thread = None;
        self.parked_stop = None;
        self.set_current_stop(None);
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
        // A partition view shows the partition as the target halted; the
        // target is what runs, so a resume leaves the view before anything
        // a run prepares (traps, parked stops) is touched, as that state is
        // the target's. A hit of the partition's breakpoints shows it again.
        self.leave_partition();
        self.target.selected_frame = None;
        self.module_refresh_report = None;
        // A bugcheck or module event can only happen while the guest runs, so
        // the traps have to be in place before it does. Arming on stop alone
        // would miss a crash or load provoked immediately after attach.
        self.arm_traps();
        if self.parked_windows_thread().is_some() {
            self.parked_windows_thread = None;
            self.target.clear_current_windows_thread_context();
            self.refresh_context_for_current_thread();
        }
        // The VM is moving on, so any stop `service_idle` parked for the host to
        // observe is now spent; drop it so a later `wait_stop` doesn't replay
        // a stale event.
        self.parked_stop = None;
        self.set_current_stop(None);
        // If a post-reboot rediscovery is still pending only because the module
        // list wasn't up yet, finish it from memory before continuing. We are
        // halted, so the next `continue` starts the pump with the reconnect-assist
        // poking already off, instead of resuming into another forced break-in.
        self.try_finish_rediscovery_from_memory();
        // A kept stop is this resume's (see `DebugBackend::keep_last_stop`):
        // nothing runs before the wait reports it, so no vCPU steps off a
        // site, which would take that stop for its own.
        if (self.breakpoints.has_enabled_breakpoints()
            || !self.module_traps.is_empty()
            || self.bugcheck_trap.is_some())
            && !self.backend.stop_kept()
        {
            self.backend.set_current_thread(&self.current_thread)?;
            self.step_over_site_at_pc()?;
        }
        for id in self.breakpoints.one_shot_hit_ids() {
            self.breakpoints
                .edit()
                .remove(self.backend.as_mut(), &self.target, id)?;
        }

        self.breakpoints
            .edit()
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
        self.step_in_flight = None;
        self.target.end_process_context_on_run();
        self.target.selected_frame = None;
        self.target.registers = None;
        self.target.breakpoint_stop = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        self.parked_windows_thread = None;
    }
}
