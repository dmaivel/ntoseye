//! Attributing a stop to a breakpoint or watchpoint, and absorbing hits
//! that thread, processor, hypercall-caller, pass-count, or condition
//! filters reject.

use crate::arch::{Arch, Family, HardwareWatch, HwBreakpointAccess, RegisterMap};
use crate::backend::dbg_backend::{
    ContinueDisposition, DebugBackend, StopEvent, processor_index_from_backend_thread_id,
};
use crate::base::error::{Error, Result};
use crate::base::notice::Notice;
use crate::nt::breakpoints::{
    BreakpointHitDisposition, BreakpointHitResult, BreakpointInfo, BreakpointManager, ThreadScope,
};
use crate::nt::guest::hypercalls::HypercallCallerInfo;
use crate::nt::target::{BreakpointStop, ExpressionScope, Target};
use crate::session::context::{
    refresh_windows_thread_context_for_backend_thread, update_target_context_from_registers,
};
use crate::session::stops::set_current_thread_from_stop;
use crate::session::{
    BreakpointStopAction, STATUS_SINGLE_STEP, Session, WatchpointStopAction, step_trace_enabled,
};

impl Session {
    /// Classify a freshly observed stop at (`rip`, `cr3`) against our breakpoints,
    /// performing the absorb actions the caller shouldn't have to: a false
    /// conditional breakpoint or a wrong-process hit on a shared-page int3 is
    /// stepped over and resumed, returning [`BreakpointStopAction::Resumed`]. A
    /// real hit re-arms enabled breakpoints (the stub can drop non-hit ones on a
    /// stop) and returns its details. The caller must have read registers and
    /// established (`rip`, `cr3`) for the stopped thread first.
    ///
    /// Shared by [`Self::continue_until_break`] and the REPL's continue loop so
    /// they can't drift on which int3 hits surface and which are silently resumed.
    pub fn resolve_breakpoint_stop(&mut self, rip: u64, cr3: u64) -> Result<BreakpointStopAction> {
        if self.returned_to_interrupted_hit(rip)? {
            return self.decline_hit();
        }
        match self
            .breakpoints
            .check_breakpoint_hit(rip, cr3, self.target.arch())
        {
            BreakpointHitResult::Hit(bp) => {
                // A thread filter is resolved here rather than in the hit
                // predicate: the predicate matches on the address space,
                // which is known from the registers, while the Windows thread
                // costs a KPRCB walk that only a filtered breakpoint owes.
                if !self.stopped_thread_matches(bp.thread.as_ref())
                    || !stopped_processor_matches(bp.processor, &self.current_thread)
                    || !self.stopped_stack_reaches(bp.min_stack_pointer)
                {
                    return self.decline_hit();
                }
                let (caller_matches, caller) =
                    stopped_caller_matches(&mut self.target, &bp, &self.current_thread, cr3, rip);
                if !caller_matches {
                    return self.decline_hit();
                }
                // Count every scoped physical hit before pass-count and
                // condition evaluation. A pass skip uses the same canonical
                // step-over/resume path as a false condition.
                if self.breakpoints.edit().record_hit(bp.id)? == BreakpointHitDisposition::SkipPass
                {
                    return self.decline_hit();
                }
                // A false condition is absorbed. Evaluation errors fail safe:
                // surface the stop and carry the error to every host.
                // A condition may name the stopped thread (`$tid`, `$proc`),
                // which the stop selects only once it surfaces.
                if bp.condition_expr.is_some() {
                    refresh_windows_thread_context_for_backend_thread(
                        &mut self.target,
                        &self.current_thread,
                    );
                }
                let condition_error =
                    match evaluate_hit_condition(&mut self.target, &bp, caller.as_ref()) {
                        Ok(false) => {
                            return self.decline_hit();
                        }
                        Ok(true) => None,
                        Err(error) => Some(error.to_string()),
                    };

                // The stub can drop non-hit breakpoints when the VM stops; re-arm
                // so they survive the next resume.
                if let Err(error) = self
                    .breakpoints
                    .edit()
                    .refresh_enabled(self.backend.as_mut(), &self.target)
                {
                    self.notices.push(Notice::warning(format!(
                        "failed to re-arm breakpoints at this stop: {error}"
                    )));
                }

                self.breakpoints.edit().mark_one_shot_hit(bp.id)?;
                Ok(BreakpointStopAction::Hit {
                    breakpoint: bp,
                    condition_error,
                })
            }
            BreakpointHitResult::NotBreakpoint => {
                // Wrong-process hit on a shared-page int3 (the BP is scoped to a
                // different address space): silently step over so the wrong
                // process keeps running, then resume waiting for the right one.
                if self.breakpoints.breakpoint_id_at_address(rip).is_some() {
                    return self.decline_hit();
                }

                Ok(BreakpointStopAction::NotBreakpoint)
            }
        }
    }

    /// Whether the thread this stop belongs to is the one a `/t` breakpoint
    /// was restricted to. Unfiltered breakpoints always match.
    fn stopped_thread_matches(&mut self, thread: Option<&ThreadScope>) -> bool {
        let Some(scope) = thread else {
            return true;
        };
        let current = self.current_thread.clone();
        let stopped = refresh_windows_thread_context_for_backend_thread(&mut self.target, &current);
        scope.matches(stopped.as_ref())
    }

    /// Whether the stopped stack pointer is at least `min`, the floor of a
    /// step's run-to breakpoint. An unreadable one matches, as an
    /// unresolved thread does.
    fn stopped_stack_reaches(&mut self, min: Option<u64>) -> bool {
        let Some(min) = min else {
            return true;
        };
        self.backend
            .read_registers()
            .ok()
            .and_then(|registers| stack_pointer(self.target.arch(), &self.register_map, &registers))
            .is_none_or(|sp| sp >= min)
    }

    /// Silently continue past the breakpoint at the PC: step over it, rewrite
    /// whatever sites the stop dropped, and resume without surfacing anything.
    /// Pass a hit no filter accepts: step over its site and resume; or,
    /// while a break-in's last try holds declined hits, stay on it.
    fn decline_hit(&mut self) -> Result<BreakpointStopAction> {
        if self.hold_declined_hits {
            return Ok(BreakpointStopAction::Held);
        }
        self.step_over_and_resume()?;
        Ok(BreakpointStopAction::Resumed)
    }

    fn step_over_and_resume(&mut self) -> Result<()> {
        self.step_over_site_at_pc()?;
        self.breakpoints
            .edit()
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.continue_backend(ContinueDisposition::Handled)
    }

    /// Leave a hit a host declined (the SDK's `when=` callback) on another
    /// vCPU than `stepping`, whose step it interrupted: step that vCPU past
    /// its site and select `stepping` again, so the step goes on from where
    /// it was rather than from the hit.
    pub fn pass_declined_hit(&mut self, stepping: &str) -> Result<()> {
        if self.current_thread == stepping {
            return Ok(());
        }
        self.step_over_site_at_pc()?;
        self.breakpoints
            .edit()
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.set_current_thread(stepping)
    }

    /// Whether a stop at `rip` is an execution returning to the breakpoint
    /// site it was interrupted on while running past the hit it reported
    /// there: the same execution, not a new hit.
    fn returned_to_interrupted_hit(&mut self, rip: u64) -> Result<bool> {
        if !self.breakpoints.has_interrupted_hits() {
            return Ok(false);
        }
        let regs = self.backend.read_registers()?;
        let rsp = self
            .register_map
            .read_u64(self.target.arch().sp_register(), &regs)?;
        Ok(self.breakpoints.edit().take_interrupted_hit(rip, rsp))
    }
}

/// Parse a backend vCPU/thread id into a zero-based processor index. Returns
/// `None` for ids that aren't processor contexts. Shared by the REPL
/// (re-exported from `repl::stop`) and `Session`.
///
/// KD synthesizes its ids as `p1.<one-based-hex>`. A GDB stub prints its own,
/// and QEMU pads both fields: its first vCPU is `p01.01`. Both are the same
/// `p<pid>.<tid>` syntax, so the process field is skipped rather than matched
/// against a literal. The qualifier is still required: an unqualified id is
/// bare hex, which would make any hex-shaped string name a processor.
/// Whether a hit reported on `stopped` belongs to the processor a `/c`
/// breakpoint names.
///
/// Like the thread filter, this cannot be programmed into the target: a
/// breakpoint site is memory or a per-processor debug register that any
/// thread can reach, so every processor executing it traps and the filter is
/// applied to the one that reported. A stop whose processor cannot be
/// resolved matches, so a filter never loses a hit silently.
pub fn stopped_processor_matches(processor: Option<u16>, stopped: &str) -> bool {
    let Some(processor) = processor else {
        return true;
    };
    processor_index_from_backend_thread_id(stopped).is_none_or(|stopped| stopped == processor)
}

/// The guest partition's VP, as its partition's ID and its index, that the
/// processor a stop was reported on (`stopped`) runs, or `None` when it runs
/// the target's own: what the hypervisor's processor block names current.
/// An error when the hypervisor's partitions cannot be walked.
pub fn stopped_guest_vp(target: &Target, stopped: &str) -> Result<Option<(u64, u32)>> {
    let number = processor_index_from_backend_thread_id(stopped)
        .ok_or_else(|| Error::Hypervisor(format!("{stopped} names no processor")))?;
    target.processor_running_vp(number)
}

/// Whether a hit reported on `stopped`, at `rip` on root `cr3`, is the
/// hypercall or VM exit from the caller a hypervisor breakpoint names (see
/// [`crate::nt::breakpoints::HypercallFilter::matches`] and
/// [`crate::nt::guest::vm_exits::ExitFilter::matches`]), with the
/// caller found, whose registers the breakpoint's condition sees (see
/// [`evaluate_hit_condition`]). Resolved only for such a breakpoint. A stop
/// whose processor cannot be resolved has an unknown caller, so it matches.
pub fn stopped_caller_matches(
    target: &mut Target,
    breakpoint: &BreakpointInfo,
    stopped: &str,
    cr3: u64,
    rip: u64,
) -> (bool, Option<HypercallCallerInfo>) {
    if breakpoint.hypercall.is_none() && breakpoint.vm_exit.is_none() {
        return (true, None);
    }
    // A hit on the VM-exit entry itself is before the hypervisor stored the
    // caller's registers: they are still the vCPU's own. The stop records
    // that only once it surfaces, after this decides whether it does.
    if rip == breakpoint.address.0 {
        target.breakpoint_stop = target
            .registers
            .as_ref()
            .and_then(|registers| BreakpointStop::new(stopped, rip, registers));
    }
    let caller = processor_index_from_backend_thread_id(stopped)
        .and_then(|number| target.hypercall_caller(cr3, rip, number));

    let matches = breakpoint
        .hypercall
        .is_none_or(|filter| filter.matches(caller.as_ref()))
        && breakpoint
            .vm_exit
            .is_none_or(|filter| filter.matches(caller.as_ref()));
    (matches, caller)
}

/// Evaluate `breakpoint`'s condition at a hit. A hypercall or VM-exit
/// breakpoint's sees its `caller`'s registers at its exit, the ones `!hvcall` decodes
/// from, and reads its memory, as `!hvcall` reads a slow call's input,
/// rather than the hypervisor's registers and memory at the handler, which
/// hold none of the call's (see [`ExpressionScope::HypercallCaller`]). With
/// the caller unknown, the condition cannot be evaluated, which surfaces
/// the hit with the error.
pub fn evaluate_hit_condition(
    target: &mut Target,
    breakpoint: &BreakpointInfo,
    caller: Option<&HypercallCallerInfo>,
) -> Result<bool> {
    if (breakpoint.hypercall.is_none() && breakpoint.vm_exit.is_none())
        || breakpoint.condition_expr.is_none()
    {
        return breakpoint.evaluate_condition(target);
    }
    let caller = caller.ok_or_else(|| {
        Error::Hypervisor(
            "the hypercall's caller is not known, so neither are the registers the condition reads"
                .to_string(),
        )
    })?;
    let live = target.registers.replace(caller.registers.clone());
    target.expression_scope = ExpressionScope::HypercallCaller(caller.state);

    let held = breakpoint.evaluate_condition(target);
    target.expression_scope = ExpressionScope::Context;
    target.registers = live;
    held
}

/// The stack pointer in `registers`, `arch`'s [`Arch::sp_register`].
pub fn stack_pointer(arch: Arch, register_map: &RegisterMap, registers: &[u8]) -> Option<u64> {
    register_map.read_u64(arch.sp_register(), registers).ok()
}

/// If `event` is a hardware-debug stop, return the breakpoint that fired.
///
/// Which evidence says so depends on what the transport exposes. A stop that
/// names a data address an armed watchpoint covers answers directly; one no
/// watchpoint covers says nothing, as QEMU reports a vCPU's watchpoint hit
/// with its next stop, whatever made it, when another vCPU's stop was
/// reported instead. That stale address can fall in a watchpoint still armed
/// too, so a stop at an armed execute site (the stop's PC, which
/// [`Session::classify_stop_event`] fills in) is the site's: taken for the
/// watchpoint, the site's hit is lost, and a walk waiting there for its
/// thread waits on after the thread has passed. A write trapped by the
/// instruction just before a site is lost to it instead, rarer and only one
/// hit. Otherwise AMD64 maps DR6 status bits and clears them,
/// and ARM64 uses the stopped PC/FAR together with BCR/WCR enable and
/// address-select fields. A transport with neither (a GDB stub owns the
/// debug registers and does not show them) is left with the PC, which is an
/// execute breakpoint's address because x86 and ARM64 both fault before the
/// instruction runs.
///
/// `None` means a plain single-step or no hardware stop. Must run before
/// [`stop_is_stray_single_step`](super::stops::stop_is_stray_single_step).
pub fn hardware_breakpoint_hit(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    event: &StopEvent,
    arch: Arch,
) -> Result<Option<BreakpointInfo>> {
    if event.is_bugcheck || !breakpoints.has_enabled_hardware_breakpoints() {
        return Ok(None);
    }
    let slots = backend.hardware_breakpoint_slots();

    if let Some(hit) = reported_watch_hit(
        breakpoints,
        slots,
        event.watchpoint_address,
        event.program_counter,
    ) {
        return Ok(Some(hit));
    }

    // Debug-register evidence only means anything on the debug exception, and
    // checking that here is what keeps an ordinary stop from fetching
    // registers. A transport that exposes no debug registers (a GDB stub owns
    // them) reports no exception code either, so it has no such gate to pass.
    let debug_registers = arch.debug_registers();
    let exposed = debug_registers.exposed_in(register_map);
    if exposed && event.exception_code != Some(STATUS_SINGLE_STEP) {
        return Ok(None);
    }

    let mut regs = backend.read_registers()?;
    if !exposed {
        return execute_breakpoint_at_pc(
            backend,
            register_map,
            breakpoints,
            slots,
            event,
            &mut regs,
            arch,
        );
    }
    let pc = register_map
        .read_u64(arch.pc_register(), &regs)
        .unwrap_or_else(|_| event.program_counter.unwrap_or(0));
    let armed = |slot| {
        let bp = breakpoints.hardware_breakpoint_for_slot(slot)?;
        bp.hardware.map(|hw| HardwareWatch {
            address: bp.address.0,
            access: hw.access,
            len: hw.len,
        })
    };
    let hit = debug_registers
        .fired_slot(register_map, &regs, pc, &armed)
        .and_then(|slot| breakpoints.hardware_breakpoint_for_slot(slot));

    let mut dirty = debug_registers.clear_status(register_map, &mut regs);
    if hit
        .as_ref()
        .and_then(|bp| bp.hardware)
        .is_some_and(|hw| hw.access == HwBreakpointAccess::Execute)
    {
        dirty |= debug_registers.resume_past_execute(register_map, &mut regs);
    }
    if dirty {
        backend.write_registers(&regs)?;
    }

    Ok(hit)
}

/// The watchpoint whose hit a stop at `pc` reports with `watch`, the data
/// address a transport sends: the armed watchpoint covering it, unless the
/// stop is at an armed execute site, whose hit it is (see
/// [`hardware_breakpoint_hit`]).
pub fn reported_watch_hit(
    breakpoints: &BreakpointManager,
    slots: usize,
    watch: Option<u64>,
    pc: Option<u64>,
) -> Option<BreakpointInfo> {
    let hit = watchpoint_covering(breakpoints, slots, watch?)?;
    (!pc.is_some_and(|pc| execute_site_at(breakpoints, slots, pc))).then_some(hit)
}

/// The data watchpoint covering `address`, which is what a transport-reported
/// trap address names: the byte touched, not the watchpoint's base.
fn watchpoint_covering(
    breakpoints: &BreakpointManager,
    slots: usize,
    address: u64,
) -> Option<BreakpointInfo> {
    (0..slots)
        .filter_map(|slot| breakpoints.hardware_breakpoint_for_slot(slot))
        .find(|bp| {
            bp.hardware.is_some_and(|hw| {
                hw.access != HwBreakpointAccess::Execute
                    && bp
                        .address
                        .0
                        .checked_add(u64::from(hw.len))
                        .is_some_and(|end| address >= bp.address.0 && address < end)
            })
        })
}

/// Whether an armed breakpoint executes at `pc`: a planted software site, or
/// a hardware execute breakpoint.
fn execute_site_at(breakpoints: &BreakpointManager, slots: usize, pc: u64) -> bool {
    breakpoints.breakpoint_id_at_address(pc).is_some()
        || (0..slots)
            .filter_map(|slot| breakpoints.hardware_breakpoint_for_slot(slot))
            .any(|bp| {
                bp.address.0 == pc
                    && bp
                        .hardware
                        .is_some_and(|hw| hw.access == HwBreakpointAccess::Execute)
            })
}

/// The hardware execute breakpoint parked at the stopped PC, with `RF` set so
/// the resume gets past it.
///
/// An x86 execute breakpoint is a fault, not a trap: it fires before the
/// instruction runs, so resuming re-enters the same instruction and faults
/// again. `RF` suppresses it for exactly one instruction. A stub programs the
/// debug registers rather than exposing them, but the flag still lives in the
/// guest's `RFLAGS`, so writing it there is what breaks the loop.
fn execute_breakpoint_at_pc(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    slots: usize,
    event: &StopEvent,
    regs: &mut [u8],
    arch: Arch,
) -> Result<Option<BreakpointInfo>> {
    let Some(pc) = register_map
        .read_u64(arch.pc_register(), regs)
        .ok()
        .or(event.program_counter)
    else {
        return Ok(None);
    };
    let hit = (0..slots)
        .filter_map(|slot| breakpoints.hardware_breakpoint_for_slot(slot))
        .find(|bp| {
            bp.address.0 == pc
                && bp
                    .hardware
                    .is_some_and(|hw| hw.access == HwBreakpointAccess::Execute)
        });

    if hit.is_some()
        && arch
            .debug_registers()
            .resume_past_execute(register_map, regs)
    {
        backend.write_registers(regs)?;
    }

    Ok(hit)
}

/// Resolve one stop against the watchpoint manager. This owns the behavior
/// common to every host: claim and acknowledge backend status, adopt the
/// stopped thread, refresh register/CR3 context before condition evaluation,
/// and decline a hit the filters, pass count or condition reject, leaving
/// the caller to resume past it. Condition errors fail safe by surfacing
/// the hit with error metadata.
pub fn resolve_watchpoint_stop(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &mut BreakpointManager,
    target: &mut Target,
    current_thread: &mut String,
    event: &StopEvent,
) -> Result<WatchpointStopAction> {
    let arch = target.arch();
    let Some(breakpoint) =
        hardware_breakpoint_hit(backend, register_map, breakpoints, event, arch)?
    else {
        if step_trace_enabled() && breakpoints.has_enabled_hardware_breakpoints() {
            let pc = backend
                .read_registers()
                .ok()
                .and_then(|registers| register_map.read_u64(arch.pc_register(), &registers).ok());
            // What the match was made against: an armed site at `pc` should
            // have been found, so a stop here with one names the gap.
            let armed = breakpoints
                .managed_ids()
                .into_iter()
                .filter_map(|id| breakpoints.get(id))
                .filter(|bp| bp.enabled)
                .filter_map(|bp| {
                    bp.hardware
                        .map(|hw| format!("#{}@{:#x}/{}", bp.id, bp.address.0, hw.slot))
                })
                .collect::<Vec<_>>()
                .join(" ");
            step_trace!(
                "stop on {:?} (current {current_thread}) at {pc:x?} is no hardware breakpoint's \
                 (reported at {:x?}, break-in {}, watch {:x?}; armed {armed})",
                event.thread_id,
                event.program_counter,
                event.break_in,
                event.watchpoint_address
            );
        }
        return Ok(WatchpointStopAction::NotBreakpoint);
    };

    set_current_thread_from_stop(backend, event, current_thread);
    let registers = backend.read_registers()?;
    let scope_dtb = register_map
        .read_u64(arch.dtb_register(), &registers)
        .unwrap_or(0);
    let rip = register_map
        .read_u64(arch.pc_register(), &registers)
        .unwrap_or(0);
    let sp = stack_pointer(arch, register_map, &registers);
    step_trace!(
        "hardware breakpoint #{} at {:#x} hit on {current_thread} at {rip:#x}",
        breakpoint.id,
        breakpoint.address.0
    );
    let declined = |reason: &str| step_trace!("#{} declined: {reason}", breakpoint.id);
    update_target_context_from_registers(target, register_map, Ok(registers));
    if !breakpoint.scope.matches_dtb(scope_dtb, arch) {
        declined("another address space");
        return Ok(WatchpointStopAction::Declined);
    }
    if let Some(filter) = breakpoint.partition {
        // The stopped vCPU runs the guest's VP, so its stack is the VP's.
        if breakpoint
            .min_stack_pointer
            .is_some_and(|min| sp.is_some_and(|sp| sp < min))
        {
            declined("the stack is not deep enough");
            return Ok(WatchpointStopAction::Declined);
        }
        let vp = match stopped_guest_vp(target, current_thread) {
            Ok(running) if !filter.matches(running) => {
                declined(&format!("another partition or VP ({running:x?})"));
                return Ok(WatchpointStopAction::Declined);
            }
            Ok(running) => running.map(|(_, vp)| vp),
            // As for a hypercall breakpoint's unknown caller, a hit that
            // cannot be told apart surfaces rather than being lost.
            Err(error) => {
                step_trace!("#{}: the stopped VP is unknown: {error}", breakpoint.id);
                None
            }
        };
        return Ok(WatchpointStopAction::PartitionHit {
            breakpoint,
            partition: filter.partition,
            vp,
        });
    }
    if let Some(thread) = breakpoint.thread.as_ref() {
        let stopped = refresh_windows_thread_context_for_backend_thread(target, current_thread);
        if !thread.matches(stopped.as_ref()) {
            declined("another thread");
            return Ok(WatchpointStopAction::Declined);
        }
    }
    if !stopped_processor_matches(breakpoint.processor, current_thread)
        || breakpoint
            .min_stack_pointer
            .is_some_and(|min| sp.is_some_and(|sp| sp < min))
    {
        declined("another processor, or the stack is not deep enough");
        return Ok(WatchpointStopAction::Declined);
    }
    let (caller_matches, caller) =
        stopped_caller_matches(target, &breakpoint, current_thread, scope_dtb, rip);
    if !caller_matches {
        // Which caller the hit resolved to tells a filter that never matches
        // from a caller that never comes.
        if step_trace_enabled() {
            let found = caller.as_ref().map_or_else(
                || "caller unknown".to_string(),
                |caller| {
                    format!(
                        "partition {:#x} VP {} VTL{}, exit {}",
                        caller.partition,
                        caller.vp,
                        caller.vtl,
                        caller
                            .state
                            .map_or_else(|| "?".to_string(), |state| state.exit_reason.to_string())
                    )
                },
            );
            declined(&format!("another hypercall, VM exit or caller ({found})"));
        }
        return Ok(WatchpointStopAction::Declined);
    }
    if breakpoints.record_hit(breakpoint.id)? == BreakpointHitDisposition::SkipPass {
        declined("pass count");
        return Ok(WatchpointStopAction::Declined);
    }

    // A condition may name the stopped thread, as at a breakpoint's hit.
    if breakpoint.condition_expr.is_some() {
        refresh_windows_thread_context_for_backend_thread(target, current_thread);
    }
    let condition_error = match evaluate_hit_condition(target, &breakpoint, caller.as_ref()) {
        Ok(false) => {
            declined("condition false");
            return Ok(WatchpointStopAction::Declined);
        }
        Ok(true) => None,
        Err(error) => Some(error.to_string()),
    };
    if breakpoint.one_shot {
        // Kept, hidden, until the next resume removes it, so the stop can
        // still describe it (its kind, action and `when=`).
        breakpoints.mark_one_shot_hit(breakpoint.id)?;
    }

    Ok(WatchpointStopAction::Hit {
        breakpoint,
        condition_error,
    })
}

/// Rewind the reporting thread back onto the breakpoint address when it is
/// parked one byte past one of ours.
///
/// An `int3` advances RIP by one when it executes, so a thread that hit a
/// breakpoint the target does not own reports `addr + 1`; the breakpoint-hit
/// check matches on the exact address, so this realignment must happen first.
///
/// Only the thread that reported the stop is touched, and only for a
/// breakpoint exception. Every other vCPU is frozen wherever it happened to
/// be, which may legitimately be one byte past a breakpoint, and moving a PC
/// back there would re-execute a byte that already ran. A thread that did hit
/// the same `int3` reports it as its own stop later, and is realigned then.
/// Best-effort: a backend that cannot read or write the context is left alone.
pub fn rewind_thread_off_breakpoint(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    arch: Arch,
) {
    // Only x86's `int3` leaves the program counter past the breakpoint.
    match arch.family() {
        Family::X86 => {}
        Family::Arm => return,
    }
    let Ok(regs) = backend.read_registers() else {
        return;
    };
    let rip = register_map
        .read_u64(arch.pc_register(), &regs)
        .unwrap_or(0);
    let cr3 = register_map
        .read_u64(arch.dtb_register(), &regs)
        .unwrap_or(0);
    let Some(prev) = rip.checked_sub(u64::from(arch.breakpoint_size())) else {
        return;
    };
    if !matches!(
        breakpoints.check_breakpoint_hit(prev, cr3, arch),
        BreakpointHitResult::Hit(_)
    ) {
        return;
    }
    let mut adjusted = regs.clone();
    if register_map
        .write_u64(arch.pc_register(), &mut adjusted, prev)
        .is_err()
    {
        return;
    }
    let _ = backend.write_registers(&adjusted);
}
