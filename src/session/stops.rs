//! Stop ingestion: classifying raw backend stops, waiting for the next
//! meaningful one, and tracking the stop the target is halted at.

use std::time::Duration;

use crate::backend::dbg_backend::{
    ContinueDisposition, DebugBackend, LastEvent, ModuleEvent, StopEvent, clear_trap_flag,
    processor_index_from_backend_thread_id,
};
use crate::base::bytes::utf16le_lossy;
use crate::base::error::Result;
use crate::base::memory::MemoryOps;
use crate::base::notice::Notice;
use crate::base::types::VirtAddr;
use crate::nt::breakpoints::{BreakpointInfo, BreakpointManager, BreakpointScope, BreakpointSpec};
use crate::nt::guest::{ModuleInfo, ProcessInfo};
use crate::nt::pe::headers::decode_headers;
use crate::nt::pe::read_pe_header_page;
use crate::nt::symbols::ModuleSymbolStatus;
use crate::nt::target::{BreakpointStop, HYPERVISOR_CONTEXT, ThreadInfo};
use crate::nt::unwind::{UNKNOWN_CONTEXT, thread_root, try_format_symbol_at};
use crate::session::context::{
    refresh_windows_thread_context_for_backend_thread, update_target_context_from_registers,
    windows_thread_on_backend_thread,
};
use crate::session::exception_policy::ExceptionPolicyMode;
use crate::session::hits::{resolve_watchpoint_stop, rewind_thread_off_breakpoint};
use crate::session::reload::ReloadDisposition;
use crate::session::{
    BreakpointStopAction, Cancel, ContinueOutcome, RunStatus, STATUS_BREAKPOINT,
    STATUS_SINGLE_STEP, Session, StopResolution, WatchpointStopAction,
};

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

    /// Record a finished single step at `rip` as the last event, as WinDbg's
    /// `.lastevent` reports one. Most ways a step runs (past a site, without
    /// the trap flag) see no stop of their own, so the event is made here.
    pub fn record_step_event(&mut self, rip: u64) {
        self.record_stop_event(&StopEvent {
            thread_id: Some(self.current_thread.clone()),
            exception_code: Some(STATUS_SINGLE_STEP),
            first_chance: None,
            exception_address: None,
            program_counter: Some(rip),
            watchpoint_address: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            target_kernel_base_hint: None,
            modules_changed: false,
            module_event: None,
            assisted_breakin: false,
            break_in: false,
        });
    }

    fn record_visible_stop(&mut self, resolution: &StopResolution) {
        let event = match resolution {
            StopResolution::Breakpoint { event, .. }
            | StopResolution::Bugcheck { event }
            | StopResolution::ModuleLoad { event, .. }
            | StopResolution::ModuleUnload { event, .. }
            | StopResolution::TargetReloaded { event, .. }
            | StopResolution::Stopped { event, .. } => event,
            StopResolution::Resumed | StopResolution::ModulesChanged => return,
        };
        // `$exr_code` follows the same boundary as host-visible stop events;
        // absorbed transport noise must not overwrite it.
        self.target.last_exception_code = event.exception_code;
        // A stop installs the halted vCPU's register context. Leaving a
        // secure root in place would render that stop through VTL1 tables.
        self.target.leave_secure_scope();
        if let Some(process) = self.target.end_exited_process_context() {
            self.notices.push(Notice::warning(format!(
                "{} (PID {}) has exited; its process context ended",
                process.name, process.pid
            )));
        }
        // Every host inspects the thread the stop landed on: `!thread`,
        // `.thread` and `$thread` read this selection, and resuming cleared it.
        refresh_windows_thread_context_for_backend_thread(&mut self.target, &self.current_thread);
        // An instruction breakpoint's trap on the Windows hypervisor's VM-exit
        // entry fires after KVM wrote the exit's eVMCS, so its saved state is
        // current. A break-in that merely lands on that address proves nothing.
        self.target.breakpoint_stop = match resolution {
            StopResolution::Breakpoint {
                breakpoint, rip, ..
            } if breakpoint.address.0 == *rip && !event.break_in => {
                self.target.registers.as_ref().and_then(|registers| {
                    BreakpointStop::new(&self.current_thread, *rip, registers)
                })
            }
            _ => None,
        };
        self.select_stop_context_default();
        let outcome = self.continue_outcome_from_resolution(resolution.clone());
        self.set_current_stop(Some(outcome));
    }

    /// Record `stop` as the stop the target is halted at (`None`: it moved),
    /// dropping the snapshot of the one before.
    pub fn set_current_stop(&mut self, stop: Option<ContinueOutcome>) {
        self.current_stop = stop;
        self.stop_snapshot = None;
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
            self.set_current_stop(Some(outcome.clone()));
        }
    }

    /// Attach the acknowledgment chosen for the current stop. A successful
    /// continuation calls this after the backend accepts the request.
    pub fn record_continuation_disposition(&mut self, disposition: ContinueDisposition) {
        if let Some(last_event) = &mut self.last_event {
            last_event.disposition = Some(disposition);
        }
        self.set_current_stop(None);
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
            StopResolution::ModuleLoad { module, rip, .. } => {
                ContinueOutcome::ModuleLoad { module, rip }
            }
            StopResolution::ModuleUnload { module, rip, .. } => {
                ContinueOutcome::ModuleUnload { module, rip }
            }
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
    /// normal run control. A real stop is parked, so the next wait surfaces it
    /// (and runs its action); a reload keeps its deferred notification.
    pub fn settle_pending_stop(&mut self) -> Result<()> {
        if !self.backend.has_pending_stop() {
            return Ok(());
        }
        let event = self.backend.wait_for_stop()?;
        match self.classify_stop_event(event)? {
            StopResolution::Resumed | StopResolution::ModulesChanged => {}
            // Settling is intentionally non-surfacing. Preserve the single
            // reboot notification for the next explicit wait.
            StopResolution::TargetReloaded { .. } => self.reload_surface_pending = true,
            resolution => {
                self.parked_stop = Some(self.continue_outcome_from_resolution(resolution));
            }
        }
        Ok(())
    }

    /// Service the guest while the host is otherwise idle: absorb a stop the
    /// background servicer caught but no tool call has drained (chiefly a
    /// wrong-process hit on a shared-page breakpoint), so the guest is not left
    /// frozen between tool calls. Noise is resumed; a real stop, a reboot
    /// included, is parked for the next wait, which runs its action and its
    /// filter's command; this runs none.
    pub fn service_idle(&mut self) {
        if self.parked_stop.is_some() || !self.backend.has_pending_stop() {
            return;
        }
        match self.wait_stop(&Cancel::within(SERVICE_IDLE_BUDGET), false) {
            Ok(ContinueOutcome::Running | ContinueOutcome::Halted { .. }) | Err(_) => {}
            Ok(outcome) => {
                self.parked_stop = Some(outcome);
            }
        }
    }

    /// Whether a stop waits to surface: one parked while the host was idle,
    /// or one the backend caught and no wait drained yet.
    pub fn stop_pending(&self) -> bool {
        self.parked_stop.is_some() || self.backend.has_pending_stop()
    }

    /// Resolve the stopped vCPU's process and Windows thread from the target,
    /// leaving the inspection context (the selected thread, frame, and
    /// process scope) as it is: a stop selected that thread already, and the
    /// user may have moved on since.
    pub fn stopped_context(&mut self) -> (Option<ProcessInfo>, Option<ThreadInfo>) {
        let mask = self.target.arch().dtb_page_mask();
        let dtb_register = self.target.arch().dtb_register();
        let stopped_thread = windows_thread_on_backend_thread(&self.target, &self.current_thread);
        // The stopped thread's owner, whichever thread the user selected.
        let stopped_process = self
            .backend
            .read_registers()
            .ok()
            .and_then(|regs| self.register_map.read_u64(dtb_register, &regs).ok())
            .filter(|cr3| !self.target.recognize_secure_root(*cr3))
            .and_then(|cr3| {
                self.target
                    .process_for_thread_cr3(cr3 & mask, stopped_thread.as_ref())
            });
        (stopped_process, stopped_thread)
    }

    /// A read-only run-control snapshot for the "where am I" surface (see
    /// [`RunStatus`]). When halted, resolves the current vCPU's rip+symbol and
    /// thread (best-effort) without changing the inspection context; while
    /// running, leaves those None. Reports
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
        let (rip, symbol, saved_vtl, serving, running_vp, stopped_process, stopped_thread) =
            if running || pending_stop {
                (None, None, Vec::new(), None, None, None, None)
            } else {
                let _ = self.backend.set_current_thread(&self.current_thread);
                let registers = self.backend.read_registers().ok();
                let rip = registers.as_ref().and_then(|regs| {
                    self.register_map
                        .read_u64(self.target.arch().pc_register(), regs)
                        .ok()
                });
                let cr3 = registers.as_ref().and_then(|regs| {
                    self.register_map
                        .read_u64(self.target.arch().dtb_register(), regs)
                        .ok()
                });
                // Named in the vCPU's own address space, as the stop header names
                // it, not the inspection scope (`.process`, a parked `.thread`),
                // and code outside NT (the Windows hypervisor, VTL1) for what it
                // is.
                let symbol =
                    rip.and_then(|rip| try_format_symbol_at(&self.target, cr3.unwrap_or(0), rip));
                // Where the hypervisor's VTLs left off, for a vCPU halted in it,
                // and the guest partition's VP whose exit it handles.
                let vcpu = registers
                    .as_ref()
                    .map(|regs| self.describe_vcpu(&self.current_thread, regs));
                let serving = match (&vcpu, cr3, rip) {
                    (Some(vcpu), Some(cr3), Some(rip)) if vcpu.context == HYPERVISOR_CONTEXT => {
                        processor_index_from_backend_thread_id(&self.current_thread)
                            .and_then(|number| self.target.served_guest_vp(cr3, rip, number))
                    }
                    _ => None,
                };
                // A vCPU in code no root of NT's maps runs a guest partition's
                // VP, as the stop header names it.
                let running_vp = match &vcpu {
                    Some(vcpu) if vcpu.context == UNKNOWN_CONTEXT => {
                        processor_index_from_backend_thread_id(&self.current_thread)
                            .and_then(|number| self.target.guest_vp_label(number))
                    }
                    _ => None,
                };
                let saved_vtl = vcpu.map(|vcpu| vcpu.saved_vtl).unwrap_or_default();
                let (stopped_process, stopped_thread) = self.stopped_context();
                (
                    rip,
                    symbol,
                    saved_vtl,
                    serving,
                    running_vp,
                    stopped_process,
                    stopped_thread,
                )
            };
        RunStatus {
            running,
            current_thread: self.current_thread.clone(),
            rip,
            symbol,
            saved_vtl,
            serving,
            running_vp,
            attached_process: self.target.attached_process().cloned(),
            stopped_process,
            stopped_thread,
            coherent: self.kernel_coherent(),
            kernel_base: self.target.kernel_base().map(|a| a.0).unwrap_or(0),
            partition: self.partition(),
        }
    }

    /// The stop of `breakpoint`'s watchpoint hit, reported by `event`,
    /// recorded as the stop the target is halted at.
    pub(super) fn watchpoint_hit(
        &mut self,
        breakpoint: BreakpointInfo,
        event: StopEvent,
        condition_error: Option<String>,
    ) -> StopResolution {
        let rip = self
            .target
            .registers
            .as_ref()
            .and_then(|registers| registers.get(self.target.arch().pc_register()).copied())
            .unwrap_or(0);
        let resolution = StopResolution::Breakpoint {
            breakpoint: Box::new(breakpoint),
            event,
            rip,
            condition_error,
        };
        self.record_visible_stop(&resolution);
        resolution
    }

    /// The watchpoint hit a run past kept for the next wait (see
    /// [`DebugBackend::keep_last_stop`]) as the stop a step ends on: the
    /// hit, on whichever vCPU made it, when its watchpoint takes it. `None`
    /// when no stop is kept, or the watchpoint declines the hit, with the
    /// step's vCPU selected again: a step does not resume past a hit as a run
    /// does, it ends where its vCPU is.
    pub fn kept_watch_hit(&mut self) -> Result<Option<ContinueOutcome>> {
        if !self.backend.stop_kept() {
            return Ok(None);
        }
        let stepping = self.current_thread.clone();
        let mut event = self.backend.wait_for_stop()?;
        set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);
        if event.program_counter.is_none() {
            event.program_counter = self.backend.read_registers().ok().and_then(|regs| {
                self.register_map
                    .read_u64(self.target.arch().pc_register(), &regs)
                    .ok()
            });
        }
        self.record_stop_event(&event);
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
                let resolution = self.watchpoint_hit(breakpoint, event, condition_error);
                Ok(Some(self.continue_outcome_from_resolution(resolution)))
            }
            WatchpointStopAction::PartitionHit {
                breakpoint,
                partition,
                vp,
            } => match self.partition_hit(breakpoint, partition, vp, event)? {
                Some(resolution) => Ok(Some(self.continue_outcome_from_resolution(resolution))),
                None => {
                    self.current_thread = stepping;
                    self.backend.set_current_thread(&self.current_thread)?;
                    Ok(None)
                }
            },
            WatchpointStopAction::Declined | WatchpointStopAction::NotBreakpoint => {
                self.current_thread = stepping;
                self.backend.set_current_thread(&self.current_thread)?;
                Ok(None)
            }
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
        // Conditions and stop presentation use the CPU that actually stopped,
        // not a read-only memory scope selected before execution resumed.
        self.target.leave_secure_scope();
        set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);
        // A GDB stop reply names the thread but not its PC. Without one the
        // reboot heuristic cannot tell a stop in a relocated kernel from an
        // ordinary one, so read it from the thread the stop selected.
        if event.program_counter.is_none() {
            event.program_counter = self.backend.read_registers().ok().and_then(|regs| {
                self.register_map
                    .read_u64(self.target.arch().pc_register(), &regs)
                    .ok()
            });
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

        if event.modules_changed || event.module_event.is_some() {
            let surfaced = match event.module_event.clone() {
                // A user-mode image changes no kernel module list.
                // While the user-image trap is planted it reports every
                // mapping, this one too.
                Some(notification) if notification.process.is_some() => {
                    if self.user_image_trap_planted() {
                        None
                    } else {
                        notification.path.as_deref().and_then(|path| {
                            self.user_module_event(
                                notification.kind,
                                notification.base,
                                notification.size,
                                path,
                                notification.process.map(ImageProcess::Eprocess32),
                            )
                        })
                    }
                    .map(|module| (notification.kind, module))
                }
                notification => {
                    self.unreported_module_change = self.refresh_modules_on_stop();
                    notification.and_then(|notification| {
                        self.kernel_module_at(notification.base)
                            .and_then(|module| {
                                self.module_event_to_surface(notification.kind, module)
                            })
                            .map(|module| (notification.kind, module))
                    })
                }
            };
            if let Some((kind, module)) = surfaced {
                let registers = self.backend.read_registers()?;
                let rip = self
                    .register_map
                    .read_u64(self.target.arch().pc_register(), &registers)
                    .unwrap_or(0);
                update_target_context_from_registers(
                    &mut self.target,
                    &self.register_map,
                    Ok(registers),
                );
                let resolution = module_event_resolution(kind, module, event, rip);
                self.record_visible_stop(&resolution);
                return Ok(resolution);
            }
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
                return Ok(self.watchpoint_hit(breakpoint, event, condition_error));
            }
            WatchpointStopAction::PartitionHit {
                breakpoint,
                partition,
                vp,
            } => {
                if let Some(resolution) = self.partition_hit(breakpoint, partition, vp, event)? {
                    return Ok(resolution);
                }
                self.continue_backend(ContinueDisposition::Handled)?;
                return Ok(StopResolution::Resumed);
            }
            WatchpointStopAction::Declined if self.hold_declined_hits => {
                let rip = event.program_counter.unwrap_or(0);
                let resolution = StopResolution::Stopped {
                    event: held_pause(event),
                    rip,
                };
                self.record_visible_stop(&resolution);
                return Ok(resolution);
            }
            WatchpointStopAction::Declined => {
                self.continue_backend(ContinueDisposition::Handled)?;
                return Ok(StopResolution::Resumed);
            }
            WatchpointStopAction::NotBreakpoint => {}
        }

        if stop_is_stray_single_step(&event, &self.breakpoints) {
            let _ = clear_trap_flag(
                self.target.arch(),
                self.backend.as_mut(),
                &self.register_map,
            );
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
        let rip = self
            .register_map
            .read_u64(self.target.arch().pc_register(), &registers)
            .unwrap_or(0);
        let cr3 = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &registers)
            .unwrap_or(0);
        update_target_context_from_registers(&mut self.target, &self.register_map, Ok(registers));

        if self
            .bugcheck_trap
            .as_ref()
            .is_some_and(|trap| trap.address.0 == rip)
        {
            event.is_bugcheck = true;
            event.bugcheck = self.bugcheck_from_trap();
            // Re-record: the event was stored before the trap enriched it,
            // and `.lastevent` and `!analyze` both read it back.
            self.record_stop_event(&event);
            let resolution = StopResolution::Bugcheck { event };
            self.record_visible_stop(&resolution);
            return Ok(resolution);
        }

        if let Some((kind, user)) = self
            .module_traps
            .iter()
            .find(|trap| trap.site.address.0 == rip)
            .map(|trap| (trap.event, trap.user))
        {
            return if user {
                self.classify_user_image_trap_hit(event, rip, cr3)
            } else {
                self.classify_module_trap_hit(kind, event, rip, cr3)
            };
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
            BreakpointStopAction::Held => StopResolution::Stopped {
                event: held_pause(event),
                rip,
            },
            BreakpointStopAction::NotBreakpoint
                if self.is_stale_breakpoint_hit(&event, rip, cr3) =>
            {
                self.continue_backend(ContinueDisposition::Handled)?;
                StopResolution::Resumed
            }
            BreakpointStopAction::NotBreakpoint => StopResolution::Stopped { event, rip },
        };
        self.record_visible_stop(&resolution);
        Ok(resolution)
    }

    /// Whether `event` is a breakpoint trap on a site that was lifted while
    /// the target ran: another processor executed the `int3` just before the
    /// debugger took it out, and the kernel, whose breakpoint table no longer
    /// has the site, reports the trap as an exception at `rip`, where the
    /// displaced instruction is back. Resumed, the processor runs that
    /// instruction; a hard-coded `int3` (a break-in) is still there to tell
    /// it apart. Only where the kernel dispatches the traps (KD): a stub's
    /// breakpoints never reach it.
    fn is_stale_breakpoint_hit(&self, event: &StopEvent, rip: u64, cr3: u64) -> bool {
        if event.exception_code != Some(STATUS_BREAKPOINT)
            || !self.backend.debug_traps_reach_target()
        {
            return false;
        }
        let opcode = self.target.arch().breakpoint_instruction();
        let mut bytes = [0u8; 4];
        let bytes = &mut bytes[..opcode.len()];
        self.target
            .address_space(thread_root(&self.target, cr3))
            .read_bytes(VirtAddr(rip), bytes)
            .is_ok_and(|()| bytes != opcode)
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
                | StopResolution::ModuleLoad { event, .. }
                | StopResolution::ModuleUnload { event, .. }
                | StopResolution::TargetReloaded { event, .. }
                | StopResolution::Stopped { event, .. } => return Ok(event),
            }
        }
    }

    /// A stop on a module trap for `kind` ([`Self::sync_module_traps`]), at
    /// the first instruction of the kernel function that reports it, with
    /// the image base in its second argument. The event is a module change
    /// like KD's notification: the module list is refreshed and deferred
    /// breakpoints reconciled. A `sxe ld`/`sxe ud` filter naming the image
    /// surfaces the stop; otherwise a breakpoint of the manager's at the same
    /// address takes the hit as usual, and without one the thread is stepped
    /// past the trap and resumed. A thread returning to the trap after an
    /// interrupt diverted it is the same event, resumed again.
    fn classify_module_trap_hit(
        &mut self,
        kind: ModuleEvent,
        event: StopEvent,
        rip: u64,
        cr3: u64,
    ) -> Result<StopResolution> {
        let stack = self.target.register_value(self.target.arch().sp_register());
        let repeated = self
            .module_trap_interrupted
            .take_if(|(event, interrupted)| *event == kind && Some(*interrupted) == stack)
            .is_some();
        self.unreported_module_change = self.refresh_modules_on_stop();
        let module = self
            .argument_on_entry(1, |name| self.target.register_value(name))
            .filter(|_| !repeated)
            .and_then(|base| self.kernel_module_at(VirtAddr(base)))
            .and_then(|module| self.module_event_to_surface(kind, module));
        if let Some(module) = module {
            let resolution = module_event_resolution(kind, module, event, rip);
            self.record_visible_stop(&resolution);
            return Ok(resolution);
        }
        self.resume_past_module_trap(event, rip, cr3)
    }

    /// A stop on the user-image trap
    /// ([`USER_IMAGE_TRAP`](crate::session::breakpoints::USER_IMAGE_TRAP)): a user-mode
    /// image was mapped into a process. Its deferred breakpoints are armed
    /// and the `sx ld` filters applied as for KD's report of one (see
    /// [`Self::user_module_event`]); a kernel image, which the trap sees
    /// too, is reported the way the backend reports kernel images.
    fn classify_user_image_trap_hit(
        &mut self,
        event: StopEvent,
        rip: u64,
        cr3: u64,
    ) -> Result<StopResolution> {
        let stack = self.target.register_value(self.target.arch().sp_register());
        let repeated = self
            .module_trap_interrupted
            .take_if(|(event, interrupted)| {
                *event == ModuleEvent::Load && Some(*interrupted) == stack
            })
            .is_some();
        let module = (!repeated)
            .then(|| self.user_image_at_trap(cr3))
            .flatten()
            .and_then(|(base, size, path, process)| {
                self.user_module_event(
                    ModuleEvent::Load,
                    base,
                    size,
                    &path,
                    Some(ImageProcess::IdOrObject(process)),
                )
            });
        if let Some(module) = module {
            let resolution = module_event_resolution(ModuleEvent::Load, module, event, rip);
            self.record_visible_stop(&resolution);
            return Ok(resolution);
        }
        self.resume_past_module_trap(event, rip, cr3)
    }

    /// What the call the user-image trap stopped at reports: the image's
    /// base, size and name, and the mapping process (its ID or its
    /// `EPROCESS`: builds pass either), from its first three arguments. The
    /// third points at the `IMAGE_INFO`, or at a wrapper that holds it 8
    /// bytes in, as current builds pass it; the one whose base holds a PE
    /// header of its size in the mapping address space (`dtb`) is it. `None`
    /// for a kernel image (`IMAGE_INFO.SystemModeImage`) or when neither
    /// layout holds an image.
    fn user_image_at_trap(&self, dtb: u64) -> Option<(VirtAddr, u32, String, u64)> {
        let argument =
            |index| self.argument_on_entry(index, |name| self.target.register_value(name));
        let (name, process, info) = (argument(0)?, argument(1)?, argument(2)?);
        let kernel = self.target.kernel_address_space();
        let pointer = kernel.arch().pointer_size();
        let user = self
            .target
            .address_space(dtb & self.target.arch().dtb_page_mask());
        let image = [info, info + IMAGE_INFO_EX_IMAGE_INFO_SLOT * pointer]
            .into_iter()
            .find_map(|at| {
                let properties: u32 = kernel.read(VirtAddr(at)).ok()?;
                let base = kernel
                    .read_pointer(VirtAddr(at + IMAGE_INFO_IMAGE_BASE_SLOT * pointer))
                    .ok()?
                    .0;
                // `SIZE_T`, pointer-wide.
                let size = kernel
                    .read_pointer(VirtAddr(at + IMAGE_INFO_IMAGE_SIZE_SLOT * pointer))
                    .ok()?
                    .0;
                let headers = read_pe_header_page(VirtAddr(base), &user).ok()?;
                let headers = decode_headers(&headers[..]).ok()?;
                (u64::from(headers.optional.size_of_image) == size)
                    .then_some((properties, base, size))
            });
        let (properties, base, size) = image?;
        if properties & IMAGE_INFO_SYSTEM_MODE_IMAGE != 0 {
            return None;
        }
        // `UNICODE_STRING`: its `Buffer` follows the lengths, a pointer in.
        let length: u16 = kernel.read(VirtAddr(name)).ok()?;
        let buffer = kernel.read_pointer(VirtAddr(name + pointer)).ok()?;
        let mut bytes = vec![0u8; usize::from(length)];
        kernel.read_bytes(buffer, &mut bytes).ok()?;
        Some((
            VirtAddr(base),
            u32::try_from(size).unwrap_or(u32::MAX),
            utf16le_lossy(&bytes),
            process,
        ))
    }

    /// Resume past a module trap no filter stopped at: a breakpoint of the
    /// manager's at the same address takes the hit as usual; otherwise the
    /// thread is stepped past the trap, the traps and breakpoints are synced
    /// (a load may have resolved the last breakpoint waiting on one), and
    /// the target resumed.
    fn resume_past_module_trap(
        &mut self,
        event: StopEvent,
        rip: u64,
        cr3: u64,
    ) -> Result<StopResolution> {
        if self.breakpoints.breakpoint_id_at_address(rip).is_some() {
            // A load may have resolved the last breakpoint waiting on one.
            self.arm_traps();
            match self.resolve_breakpoint_stop(rip, cr3)? {
                BreakpointStopAction::Hit {
                    breakpoint,
                    condition_error,
                } => {
                    let resolution = StopResolution::Breakpoint {
                        breakpoint: Box::new(breakpoint),
                        event,
                        rip,
                        condition_error,
                    };
                    self.record_visible_stop(&resolution);
                    return Ok(resolution);
                }
                BreakpointStopAction::Resumed => return Ok(StopResolution::ModulesChanged),
                BreakpointStopAction::Held => {
                    let resolution = StopResolution::Stopped {
                        event: held_pause(event),
                        rip,
                    };
                    self.record_visible_stop(&resolution);
                    return Ok(resolution);
                }
                BreakpointStopAction::NotBreakpoint => {}
            }
        }
        self.backend.set_current_thread(&self.current_thread)?;
        self.step_over_site_at_pc()?;
        // A load may have resolved the last breakpoint waiting on one.
        self.arm_traps();
        self.breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.continue_backend(ContinueDisposition::Handled)?;
        Ok(StopResolution::ModulesChanged)
    }

    /// The kernel image at `base`, from the module list as last refreshed;
    /// an unloading image is still in the list.
    fn kernel_module_at(&self, base: VirtAddr) -> Option<ModuleInfo> {
        self.target
            .kernel_modules()
            .ok()?
            .into_iter()
            .find(|module| module.base_address == base)
    }

    /// Apply the `sx* ld` or `sx* ud` filters to `kind` for `module`: the
    /// module to stop for (`sxe`), else `None`, with its
    /// [`module_event_line`] queued as a notice for `sxn`.
    fn module_event_to_surface(
        &mut self,
        kind: ModuleEvent,
        module: ModuleInfo,
    ) -> Option<ModuleInfo> {
        match self
            .exception_policies
            .module_event_policy(kind, &module.name)?
            .mode
        {
            ExceptionPolicyMode::Break => Some(module),
            ExceptionPolicyMode::Notify => {
                self.notices
                    .push(crate::base::notice::Notice::info(module_event_line(
                        kind, &module,
                    )));
                None
            }
            ExceptionPolicyMode::SecondChance | ExceptionPolicyMode::Ignore => None,
        }
    }

    /// A user-mode image mapped into or unmapped from `process`, as KD
    /// reports with `!gflag +ksl` or the user-image trap sees: on a load,
    /// the deferred breakpoints that wait on it in that process are armed
    /// in it before it runs; then the `sx* ld`/`sx* ud` filters apply, as
    /// for a kernel image. The report comes as the image is mapped, before
    /// the loader lists hold it, so the module is what the report says.
    fn user_module_event(
        &mut self,
        kind: ModuleEvent,
        base: VirtAddr,
        size: u32,
        path: &str,
        process: Option<ImageProcess>,
    ) -> Option<ModuleInfo> {
        let name = path.rsplit(['\\', '/']).next().unwrap_or(path).to_string();
        let mut module = ModuleInfo {
            short_name: ModuleInfo::derive_short_name(&name),
            name,
            path: Some(path.to_string()),
            base_address: base,
            size,
            is_32bit: false,
            entry_point: None,
            time_date_stamp: None,
            checksum: None,
            file_version: None,
            product_version: None,
            codeview: None,
        };
        if kind == ModuleEvent::Load
            && let Some(process) = process
        {
            if let Some(waiting) = self.deferred_process_for_module(process, &module.short_name) {
                self.arm_deferred_in_user_module(&waiting, &mut module);
            } else if self.module_event_stops(kind, &module.name)
                && let Some(mapping) = self.image_process(process)
                && let Some(failure) = self.load_user_module_symbols(&mapping, &mut module)
            {
                // The stop is where `x` and `ln` look for the image's
                // symbols, and the loader lists do not name it yet.
                self.notices.push(Notice::warning(format!(
                    "{} loaded in {} (PID {}), but its symbols did not ({failure})",
                    module.name, mapping.name, mapping.pid
                )));
            }
        }
        self.module_event_to_surface(kind, module)
    }

    /// Whether the `sx* ld`/`sx* ud` filters stop at `kind` of the image
    /// `name` (see [`Self::module_event_to_surface`]).
    fn module_event_stops(&self, kind: ModuleEvent, name: &str) -> bool {
        self.exception_policies
            .module_event_policy(kind, name)
            .is_some_and(|policy| policy.mode == ExceptionPolicyMode::Break)
    }

    /// The process a user-mode image report names.
    fn image_process(&self, process: ImageProcess) -> Option<ProcessInfo> {
        self.target
            .guest
            .as_ref()?
            .enumerate_processes()
            .ok()?
            .into_iter()
            .find(|candidate| process.names(candidate))
    }

    /// The process `process` names, when a deferred breakpoint scoped to it
    /// names the module `short_name`. An `ntdll32!` breakpoint waits on an
    /// image named ntdll too: only its header tells the WOW64 copy from the
    /// native one. Processes are only walked when some deferred breakpoint
    /// names the module.
    fn deferred_process_for_module(
        &self,
        process: ImageProcess,
        short_name: &str,
    ) -> Option<ProcessInfo> {
        let waiting: Vec<u64> = self
            .breakpoints
            .list()
            .iter()
            .filter(|bp| !bp.resolved)
            .filter_map(|bp| match (&bp.scope, &bp.spec) {
                (
                    BreakpointScope::Process { pid, .. },
                    Some(BreakpointSpec::Symbol { name, .. }),
                ) => {
                    let module = name.split_once('!')?.0.trim();
                    let names_it = module.eq_ignore_ascii_case(short_name)
                        || (short_name == "ntdll" && module.eq_ignore_ascii_case("ntdll32"));
                    names_it.then_some(*pid)
                }
                _ => None,
            })
            .collect();
        if waiting.is_empty() {
            return None;
        }
        self.target
            .guest
            .as_ref()?
            .enumerate_processes()
            .ok()?
            .into_iter()
            .find(|candidate| waiting.contains(&candidate.pid) && process.names(candidate))
    }

    /// Load the symbols of `module`, just mapped into `process` (see
    /// [`Self::load_user_module_symbols`]), and arm the deferred breakpoints
    /// they resolve.
    fn arm_deferred_in_user_module(&mut self, process: &ProcessInfo, module: &mut ModuleInfo) {
        if let Some(failure) = self.load_user_module_symbols(process, module) {
            self.notices.push(Notice::warning(format!(
                "{} loaded in {} (PID {}), but its symbols did not ({failure}); the breakpoints \
                 waiting on it stay deferred",
                module.name, process.name, process.pid
            )));
            return;
        }
        self.reconcile_deferred_breakpoints();
    }

    /// Load the symbols of `module`, just mapped into `process`, saying why
    /// they did not load. Its header gives its bitness first: a WOW64 ntdll
    /// is `ntdll32`. The stopped processor's registers are read too: whether
    /// the target can owe a site in a page not yet faulted in depends on
    /// which address space it stopped in.
    fn load_user_module_symbols(
        &mut self,
        process: &ProcessInfo,
        module: &mut ModuleInfo,
    ) -> Option<String> {
        let registers = self.backend.read_registers();
        update_target_context_from_registers(&mut self.target, &self.register_map, registers);
        let memory = self.target.address_space(process.dtb);
        module.is_32bit = read_pe_header_page(module.base_address, &memory)
            .ok()
            .and_then(|headers| decode_headers(&headers[..]).ok())
            .is_some_and(|headers| !headers.is_pe32_plus());
        if module.is_32bit && module.short_name == "ntdll" {
            module.short_name.push_str("32");
        }
        match self
            .target
            .load_mapped_module_symbols(process.dtb, module.clone())
        {
            Ok(Some(report)) if report.loaded == 0 => Some(
                match self
                    .target
                    .symbols
                    .module_symbol_status(process.dtb, module.base_address)
                {
                    Some(ModuleSymbolStatus::Failed(reason)) => reason,
                    Some(ModuleSymbolStatus::MissingDebugInfo) => {
                        "neither its image in memory nor the symbol server names a PDB".into()
                    }
                    status => report.diagnostics.first().map_or_else(
                        || {
                            status
                                .map_or("no PDB was found", |status| status.label())
                                .to_string()
                        },
                        |diagnostic| format!("{}: {}", diagnostic.phase, diagnostic.message),
                    ),
                },
            ),
            Ok(_) => None,
            Err(error) => Some(error.to_string()),
        }
    }
}

/// A hit held as a break-in's pause: the stop is the pause the host asked
/// for, not the exception the hit raised.
fn held_pause(event: StopEvent) -> StopEvent {
    StopEvent {
        exception_code: None,
        first_chance: None,
        exception_address: None,
        break_in: true,
        ..event
    }
}

/// `IMAGE_INFO.SystemModeImage`: the image is a kernel image.
const IMAGE_INFO_SYSTEM_MODE_IMAGE: u32 = 1 << 8;
/// `IMAGE_INFO.ImageBase` and `ImageSize`, in pointers from its start: the
/// `Properties` before each is padded to one.
const IMAGE_INFO_IMAGE_BASE_SLOT: u64 = 1;
const IMAGE_INFO_IMAGE_SIZE_SLOT: u64 = 3;
/// Where the wrapper current builds pass the notify call holds its
/// `IMAGE_INFO` (`IMAGE_INFO_EX.ImageInfo`, after its pointer-wide `Size`),
/// in pointers.
const IMAGE_INFO_EX_IMAGE_INFO_SLOT: u64 = 1;

/// The process a user-mode image report names.
#[derive(Debug, Clone, Copy)]
enum ImageProcess {
    /// KD's `DBGKD_LOAD_SYMBOLS64.ProcessId`: the low 32 bits of the
    /// mapping process's `EPROCESS`.
    Eprocess32(u64),
    /// Its process ID or its `EPROCESS`, as the user-image trap's call
    /// passes it.
    IdOrObject(u64),
}

impl ImageProcess {
    fn names(self, process: &ProcessInfo) -> bool {
        match self {
            Self::Eprocess32(bits) => process.eprocess.0 & 0xffff_ffff == bits,
            Self::IdOrObject(value) => process.pid == value || process.eprocess.0 == value,
        }
    }
}

/// The resolution of a stop that a `sxe ld` or `sxe ud` filter surfaces.
fn module_event_resolution(
    kind: ModuleEvent,
    module: ModuleInfo,
    event: StopEvent,
    rip: u64,
) -> StopResolution {
    let module = Box::new(module);
    match kind {
        ModuleEvent::Load => StopResolution::ModuleLoad { module, event, rip },
        ModuleEvent::Unload => StopResolution::ModuleUnload { module, event, rip },
    }
}

/// WinDbg's line for a module event: `ModLoad: <base> <end>   <image>` for
/// a load, `Unload module <image> at <base>` for an unload.
pub fn module_event_line(kind: ModuleEvent, module: &ModuleInfo) -> String {
    let image = module
        .name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&module.name);
    match kind {
        ModuleEvent::Load => format!(
            "ModLoad: {:016x} {:016x}   {image}",
            module.base_address.0,
            module.end_address().0
        ),
        ModuleEvent::Unload => {
            format!("Unload module {image} at {:016x}", module.base_address.0)
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
