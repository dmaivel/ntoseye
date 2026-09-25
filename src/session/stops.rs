//! Stop ingestion: classifying raw backend stops, waiting for the next
//! meaningful one, and tracking the stop the target is halted at.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::breakpoints::BreakpointManager;
use crate::dbg_backend::{
    ContinueDisposition, DebugBackend, LastEvent, StopEvent, clear_trap_flag,
};
use crate::error::Result;
use crate::exception_policy::ExceptionPolicyAction;
use crate::guest::ProcessInfo;
use crate::kd::trace_enabled;
use crate::session::context::{
    refresh_windows_thread_context_for_backend_thread, update_target_context_from_registers,
};
use crate::session::hits::{resolve_watchpoint_stop, rewind_thread_off_breakpoint};
use crate::session::reload::ReloadDisposition;
use crate::session::{
    BreakpointStopAction, ContinueOutcome, RunStatus, STATUS_BREAKPOINT, STATUS_SINGLE_STEP,
    Session, StopResolution, WatchpointStopAction,
};
use crate::target::ThreadInfo;
use crate::types::VirtAddr;

/// The low bits of a CR3/DTB that select the page-directory base physical
/// frame (PCID and reserved/canonical bits masked out), for comparing the
/// address space a vCPU runs in against a process's DTB.
/// How often the run-control poll loop wakes to check for a stop.
const CONTINUE_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How long a background `service_idle` pass spends absorbing caught stops before
/// returning to the actor's job queue. Small so a real tool call is never held off
/// for long; one buffered stop is drained immediately regardless, this only bounds
/// the brief wait for any follow-on hit in a burst.
const SERVICE_IDLE_BUDGET: Duration = Duration::from_millis(5);

impl Session {
    /// Record a raw backend stop for `.lastevent` and typed hosts. REPL paths
    /// that own their richer wait loop call this at the same boundary as the
    /// session wait helpers.
    pub fn record_stop_event(&mut self, event: &StopEvent) {
        self.last_event = Some(LastEvent::new(event.clone()));
    }

    fn record_visible_stop(&mut self, resolution: &StopResolution) {
        let event = match resolution {
            StopResolution::Breakpoint { event, .. }
            | StopResolution::Bugcheck { event }
            | StopResolution::TargetReloaded { event, .. }
            | StopResolution::Stopped { event, .. } => event,
            StopResolution::Resumed | StopResolution::ModulesChanged => return,
        };
        // `$exr_code` follows the same boundary as host-visible stop events;
        // absorbed transport noise must not overwrite it.
        self.target.last_exception_code = event.exception_code;
        // Every host inspects the thread the stop landed on: `!thread`,
        // `.thread` and `$thread` read this selection, and resuming cleared it.
        refresh_windows_thread_context_for_backend_thread(&mut self.target, &self.current_thread);
        self.current_stop = Some(self.continue_outcome_from_resolution(resolution.clone()));
    }

    /// The stop the target is halted at, if it has stopped since it last
    /// moved; see [`Self::note_stop`].
    pub fn current_stop(&self) -> Option<&ContinueOutcome> {
        self.current_stop.as_ref()
    }

    /// Record `outcome` as the stop the target is halted at, for a host that
    /// reports a stop differently from its classification (a temporary
    /// breakpoint reached is a `Step`; a requested break-in is an interrupt).
    /// `Running` and `Halted` carry no stop and leave it alone.
    pub fn note_stop(&mut self, outcome: &ContinueOutcome) {
        if !matches!(
            outcome,
            ContinueOutcome::Running | ContinueOutcome::Halted { .. }
        ) {
            self.current_stop = Some(outcome.clone());
        }
    }

    /// Attach the acknowledgment chosen for the current stop. A successful
    /// continuation calls this after the backend accepts the request.
    pub fn record_continuation_disposition(&mut self, disposition: ContinueDisposition) {
        if let Some(last_event) = &mut self.last_event {
            last_event.disposition = Some(disposition);
        }
        self.current_stop = None;
    }

    pub(super) fn continue_outcome_from_resolution(
        &self,
        resolution: StopResolution,
    ) -> ContinueOutcome {
        match resolution {
            StopResolution::Breakpoint {
                breakpoint,
                rip,
                condition_error,
                ..
            } => ContinueOutcome::breakpoint_hit(&breakpoint, rip, condition_error),
            StopResolution::Bugcheck { event } => ContinueOutcome::Bugcheck {
                rip: event.program_counter,
                info: event.bugcheck,
            },
            StopResolution::TargetReloaded { event, coherent } => ContinueOutcome::TargetReloaded {
                rip: event.program_counter,
                kernel_base: self.target.kernel_base().map(|address| address.0),
                coherent,
            },
            StopResolution::Stopped { event, rip } => ContinueOutcome::Stopped {
                rip,
                exception_code: event.exception_code,
                first_chance: event.first_chance,
                exception_address: event.exception_address,
            },
            StopResolution::Resumed | StopResolution::ModulesChanged => {
                unreachable!("absorbed stop cannot be parked")
            }
        }
    }

    /// Drain a stop the background servicer has already caught without advancing
    /// to a later event. This makes a physically halted VM visible even while
    /// `is_running()` still holds stale running state.
    ///
    /// Debugger-generated noise is still absorbed so read/status surfaces match
    /// normal run control. Reload stops keep their deferred `TargetReloaded`
    /// notification for the next wait surface.
    pub fn settle_pending_stop(&mut self) -> Result<()> {
        if !self.backend.has_pending_stop() {
            return Ok(());
        }
        let event = self.backend.wait_for_stop()?;
        if matches!(
            self.classify_stop_event(event)?,
            StopResolution::TargetReloaded { .. }
        ) {
            // Settling is intentionally non-surfacing. Preserve the single
            // reboot notification for the next explicit wait.
            self.reload_surface_pending = true;
        }
        Ok(())
    }

    /// Service the guest while the host is otherwise idle: absorb a stop the
    /// background servicer caught but no tool call has drained (chiefly a
    /// wrong-process hit on a shared-page breakpoint), so the guest is not left
    /// frozen between tool calls. Noise is resumed; a real stop, a reboot
    /// included, is parked for the next `wait_for_stop`.
    pub fn service_idle(&mut self) {
        if self.parked_stop.is_some() || !self.backend.has_pending_stop() {
            return;
        }
        let never_cancel = AtomicBool::new(false);
        match self.wait_for_stop_bounded(Some(SERVICE_IDLE_BUDGET), &never_cancel) {
            Ok(ContinueOutcome::Running) | Err(_) => {}
            Ok(outcome) => {
                self.parked_stop = Some(outcome);
            }
        }
    }

    /// Hand over a stop [`Self::service_idle`] parked while the host was idle,
    /// for hosts that render stops themselves rather than through
    /// [`Self::wait_for_stop_bounded`]. The VM is halted at it.
    pub fn take_parked_stop(&mut self) -> Option<ContinueOutcome> {
        self.parked_stop.take()
    }

    /// Resolve the stopped vCPU's process and Windows thread from the target.
    /// Select that thread for inspection. The attached process scope is separate
    /// and persists across resumes.
    pub fn stopped_context(&mut self) -> (Option<ProcessInfo>, Option<ThreadInfo>) {
        let mask = self.target.arch().dtb_page_mask();
        let dtb_register = self.target.arch().dtb_register();
        let stopped_process = self
            .backend
            .read_registers()
            .ok()
            .and_then(|regs| self.register_map.read_u64(dtb_register, &regs).ok())
            .and_then(|cr3| self.target.process_for_cr3(cr3 & mask));
        let current_thread = self.current_thread.clone();
        let stopped_thread =
            refresh_windows_thread_context_for_backend_thread(&mut self.target, &current_thread);
        (stopped_process, stopped_thread)
    }

    /// A read-only run-control snapshot for the "where am I" surface (see
    /// [`RunStatus`]). When halted, selects the current thread and resolves
    /// rip+symbol (best-effort); while running, leaves those None. Reports
    /// `coherent: false` while a post-reboot rediscovery is still pending so a
    /// host waits instead of enumerating stale state.
    pub fn run_status(&mut self) -> RunStatus {
        // On failure `has_pending_stop` stays true and the snapshot reports
        // halted with no location.
        let _ = self.settle_pending_stop();
        self.try_finish_rediscovery_from_memory();
        // The snapshot carries `kernel_base` + `coherent`, so it is the reload
        // notification.
        self.clear_deferred_reload_surface();
        let pending_stop = self.backend.has_pending_stop();
        let running = self.backend.is_running() && !pending_stop;
        let (rip, symbol, stopped_process, stopped_thread) = if running || pending_stop {
            (None, None, None, None)
        } else {
            let _ = self.backend.set_current_thread(&self.current_thread);
            let registers = self.backend.read_registers().ok();
            let rip = registers
                .as_ref()
                .and_then(|regs| self.register_map.read_u64("rip", regs).ok());
            let symbol = rip.and_then(|r| self.target.closest_symbol_current_context(VirtAddr(r)));
            let (stopped_process, stopped_thread) = self.stopped_context();
            (rip, symbol, stopped_process, stopped_thread)
        };
        RunStatus {
            running,
            current_thread: self.current_thread.clone(),
            rip,
            symbol,
            attached_process: self.target.attached_process().cloned(),
            stopped_process,
            stopped_thread,
            coherent: self.kernel_coherent(),
            kernel_base: self.target.kernel_base().map(|a| a.0).unwrap_or(0),
        }
    }

    /// Classify one raw backend stop and perform every core-owned transition.
    ///
    /// This is the only stop-ingestion state machine. REPL, MCP, Python, and
    /// idle servicing may differ in polling and presentation, but must route
    /// raw events here so reload handling, DR acknowledgment, scope checks,
    /// `int3` rewind, conditions, and auto-resume behavior cannot drift.
    pub fn classify_stop_event(&mut self, mut event: StopEvent) -> Result<StopResolution> {
        self.target.selected_frame = None;
        set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);
        // A GDB stop reply names the thread but not its PC. Without one the
        // reboot heuristic cannot tell a stop in a relocated kernel from an
        // ordinary one, so read it from the thread the stop selected.
        if event.program_counter.is_none() {
            event.program_counter = self
                .backend
                .read_registers()
                .ok()
                .and_then(|regs| self.register_map.read_u64("rip", &regs).ok());
        }
        self.record_stop_event(&event);

        if event.is_bugcheck && !event.target_reloaded {
            self.target.registers = None;
            let resolution = StopResolution::Bugcheck { event };
            self.record_visible_stop(&resolution);
            return Ok(resolution);
        }

        match self.classify_reload_stop(&mut event)? {
            disposition @ (ReloadDisposition::Reloaded { .. }
            | ReloadDisposition::ReloadCompleted) => {
                let coherent =
                    !matches!(disposition, ReloadDisposition::Reloaded { coherent: false });
                self.refresh_context_for_current_thread();
                let resolution = StopResolution::TargetReloaded { event, coherent };
                self.record_visible_stop(&resolution);
                return Ok(resolution);
            }
            ReloadDisposition::PendingRediscovery | ReloadDisposition::ResumePastAssist => {
                self.continue_backend(ContinueDisposition::Handled)?;
                return Ok(StopResolution::Resumed);
            }
            ReloadDisposition::Ordinary => {}
        }

        if event.modules_changed {
            self.unreported_module_change = self.refresh_modules_on_stop();
            self.continue_backend(ContinueDisposition::Handled)?;
            return Ok(StopResolution::ModulesChanged);
        }

        match resolve_watchpoint_stop(
            self.backend.as_mut(),
            &self.register_map,
            &mut self.breakpoints,
            &mut self.target,
            &mut self.current_thread,
            &event,
        )? {
            WatchpointStopAction::Hit {
                breakpoint,
                condition_error,
            } => {
                let rip = self
                    .target
                    .registers
                    .as_ref()
                    .and_then(|registers| registers.get("rip").copied())
                    .unwrap_or(0);
                let resolution = StopResolution::Breakpoint {
                    breakpoint: Box::new(breakpoint),
                    event,
                    rip,
                    condition_error,
                };
                self.record_visible_stop(&resolution);
                return Ok(resolution);
            }
            WatchpointStopAction::Resumed => {
                self.invalidate_running_context();
                return Ok(StopResolution::Resumed);
            }
            WatchpointStopAction::NotBreakpoint => {}
        }

        if stop_is_stray_single_step(&event, &self.breakpoints) {
            let _ = clear_trap_flag(self.backend.as_mut(), &self.register_map);
            self.continue_backend(ContinueDisposition::Handled)?;
            return Ok(StopResolution::Resumed);
        }

        if event.exception_code == Some(STATUS_BREAKPOINT)
            && self.breakpoints.has_enabled_breakpoints()
        {
            rewind_thread_off_breakpoint(
                self.backend.as_mut(),
                &self.register_map,
                &self.breakpoints,
                self.target.arch(),
            );
        }

        let registers = self.backend.read_registers()?;
        let rip = self.register_map.read_u64("rip", &registers).unwrap_or(0);
        let cr3 = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &registers)
            .unwrap_or(0);
        update_target_context_from_registers(&mut self.target, &self.register_map, Ok(registers));

        if self.bugcheck_trap == Some(VirtAddr(rip)) {
            event.is_bugcheck = true;
            event.bugcheck = self.bugcheck_from_trap();
            // Re-record: the event was stored before the trap enriched it,
            // and `.lastevent` and `!analyze` both read it back.
            self.record_stop_event(&event);
            let resolution = StopResolution::Bugcheck { event };
            self.record_visible_stop(&resolution);
            return Ok(resolution);
        }

        let resolution = match self.resolve_breakpoint_stop(rip, cr3)? {
            BreakpointStopAction::Hit {
                breakpoint,
                condition_error,
            } => StopResolution::Breakpoint {
                breakpoint: Box::new(breakpoint),
                event,
                rip,
                condition_error,
            },
            BreakpointStopAction::Resumed => StopResolution::Resumed,
            BreakpointStopAction::NotBreakpoint => StopResolution::Stopped { event, rip },
        };
        self.record_visible_stop(&resolution);
        Ok(resolution)
    }

    /// Wait up to `timeout` for the next meaningful stop **without resuming**:
    /// drains a held stop, drives the reboot / breakpoint classification, absorbs
    /// debugger noise (assist break-ins, stray single-steps, wrong-process and
    /// false-condition hits), and returns the stop worth surfacing (or
    /// [`ContinueOutcome::Running`] on timeout/cancel). Because it never resumes, a
    /// caller already halted at an interesting site (e.g. the early-boot reload)
    /// observes it in place instead of blowing past it; that separation is why
    /// the MCP surface splits resume from wait.
    pub fn wait_for_stop_bounded(
        &mut self,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        // A stop `service_idle` caught and parked while the host was idle is
        // the proper event for this wait: surface it before waiting for a new
        // one, so every host (not just one) sees it as its real event.
        if let Some(parked) = self.parked_stop.take() {
            return Ok(parked);
        }
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Ok(ContinueOutcome::Running);
            }
            // Wait one poll interval at a time so `cancel` and the deadline stay
            // responsive; an indefinite wait (`deadline == None`) just keeps going.
            let poll = match deadline {
                Some(dl) => {
                    let remaining = dl.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(ContinueOutcome::Running);
                    }
                    remaining.min(CONTINUE_POLL_INTERVAL)
                }
                None => CONTINUE_POLL_INTERVAL,
            };

            let event = match self.backend.try_wait_for_stop(poll)? {
                Some(event) => event,
                None => {
                    // Halted with nothing pending: report the park instead of
                    // spinning out the timeout.
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
                        let rip = self
                            .backend
                            .read_registers()
                            .ok()
                            .and_then(|regs| self.register_map.read_u64("rip", &regs).ok())
                            .unwrap_or(0);
                        return Ok(ContinueOutcome::Halted { rip });
                    }
                    continue;
                }
            };
            match self.classify_stop_event(event)? {
                StopResolution::Resumed | StopResolution::ModulesChanged => continue,
                resolution @ StopResolution::TargetReloaded { coherent, .. } => {
                    reload_trace!(
                        "continue: SURFACE target_reloaded base={} coherent={}",
                        self.target.kernel_base().map_or_else(
                            || "none".to_string(),
                            |address| format!("{:#x}", address.0)
                        ),
                        coherent,
                    );
                    return Ok(self.continue_outcome_from_resolution(resolution));
                }
                StopResolution::Stopped { event, .. }
                    if let ExceptionPolicyAction::Continue {
                        disposition,
                        command: None,
                        ..
                    } = self.exception_policies.action_for(&event) =>
                {
                    // A policy with a command needs the REPL to run it, so it
                    // surfaces here; the command-free ones are pure run control.
                    self.continue_backend(disposition)?;
                    self.record_continuation_disposition(disposition);
                    continue;
                }
                resolution => return Ok(self.continue_outcome_from_resolution(resolution)),
            }
        }
    }

    /// Block until the backend produces a meaningful stop, routing every raw
    /// event through [`Self::classify_stop_event`]. Filtered breakpoint hits and
    /// debugger noise are resumed internally.
    pub fn wait_for_stop(&mut self) -> Result<StopEvent> {
        loop {
            let event = self.backend.wait_for_stop()?;
            match self.classify_stop_event(event)? {
                StopResolution::Resumed | StopResolution::ModulesChanged => continue,
                StopResolution::Breakpoint { event, .. }
                | StopResolution::Bugcheck { event }
                | StopResolution::TargetReloaded { event, .. }
                | StopResolution::Stopped { event, .. } => return Ok(event),
            }
        }
    }
}

/// Whether `event` is a *stray* single-step: a `STATUS_SINGLE_STEP` trap that
/// isn't sitting on a user breakpoint. In a run-control loop (continue / run-to)
/// nobody is intentionally single-stepping, so this is a debugger artifact; a
/// managed step-over's single-step that leaked out because KD single-steps the
/// whole machine and another processor's break was reported first. The loop
/// absorbs it (clear `TF`, resume) rather than surfacing it as a stop. Used by
/// [`Session::continue_until_break`] and the REPL's continue loop.
pub fn stop_is_stray_single_step(event: &StopEvent, breakpoints: &BreakpointManager) -> bool {
    event.exception_code == Some(STATUS_SINGLE_STEP)
        && !event.is_bugcheck
        && event
            .program_counter
            .is_none_or(|pc| breakpoints.breakpoint_id_at_address(pc).is_none())
}

/// Adopt the thread reported by a stop event (falling back to the backend's
/// stopped-thread query) as the current thread, and select it on the backend.
pub fn set_current_thread_from_stop(
    backend: &mut dyn DebugBackend,
    event: &StopEvent,
    current: &mut String,
) {
    let stopped_tid = event
        .thread_id
        .clone()
        .or_else(|| backend.stopped_thread_id().ok());
    if let Some(tid) = stopped_tid {
        *current = tid;
        let _ = backend.set_current_thread(current);
    }
}
