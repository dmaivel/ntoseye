//! Attributing a stop to a breakpoint or watchpoint, and absorbing hits
//! that thread, processor, pass-count, or condition filters reject.

use crate::breakpoints::{
    Breakpoint, BreakpointHitDisposition, BreakpointHitResult, BreakpointManager, ThreadScope,
};
use crate::dbg_backend::{
    ContinueDisposition, DebugBackend, HW_BREAKPOINT_SLOTS, HwBreakpointAccess, StopEvent,
    processor_index_from_backend_thread_id,
};
use crate::error::Result;
use crate::gdb::RegisterMap;
use crate::kd::hwbp;
use crate::session::context::{
    refresh_windows_thread_context_for_backend_thread, update_target_context_from_registers,
};
use crate::session::stepping::step_over_current_breakpoint;
use crate::session::stops::set_current_thread_from_stop;
use crate::session::{BreakpointStopAction, STATUS_SINGLE_STEP, Session, WatchpointStopAction};
use crate::target::Target;
use crate::types::Arch;

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
                {
                    self.step_over_and_resume()?;
                    return Ok(BreakpointStopAction::Resumed);
                }
                // Count every scoped physical hit before pass-count and
                // condition evaluation. A pass skip uses the same canonical
                // step-over/resume path as a false condition.
                if self.breakpoints.record_hit(bp.id)? == BreakpointHitDisposition::SkipPass {
                    self.step_over_and_resume()?;
                    return Ok(BreakpointStopAction::Resumed);
                }
                // A false condition is absorbed. Evaluation errors fail safe:
                // surface the stop and carry the error to every host.
                let condition_error = match bp.evaluate_condition(&self.target) {
                    Ok(false) => {
                        self.step_over_and_resume()?;
                        return Ok(BreakpointStopAction::Resumed);
                    }
                    Ok(true) => None,
                    Err(error) => Some(error.to_string()),
                };

                // The stub can drop non-hit breakpoints when the VM stops; re-arm
                // so they survive the next resume.
                if let Err(error) = self
                    .breakpoints
                    .refresh_enabled(self.backend.as_mut(), &self.target)
                {
                    self.notices.push(format!(
                        "failed to re-arm breakpoints at this stop: {error}"
                    ));
                }

                self.breakpoints.mark_one_shot_hit(bp.id)?;
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
                    self.step_over_and_resume()?;
                    return Ok(BreakpointStopAction::Resumed);
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

    /// Silently continue past the breakpoint at the PC: step over it, rewrite
    /// whatever sites the stop dropped, and resume without surfacing anything.
    fn step_over_and_resume(&mut self) -> Result<()> {
        step_over_current_breakpoint(
            self.backend.as_mut(),
            &self.register_map,
            &self.target,
            &mut self.breakpoints,
        )?;
        self.breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.continue_backend(ContinueDisposition::Handled)
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

/// If `event` is a hardware-debug stop, return the breakpoint that fired.
///
/// Which evidence says so depends on what the transport exposes. A stop that
/// names the trapping data address answers directly. Otherwise AMD64 maps DR6
/// status bits and clears them, and ARM64 uses the stopped PC/FAR together
/// with BCR/WCR enable and address-select fields. A transport with neither
/// (a GDB stub owns the debug registers and does not show them) is left with
/// the PC, which is an execute breakpoint's address because x86 and ARM64
/// both fault before the instruction runs.
///
/// `None` means a plain single-step or no hardware stop. Must run before
/// [`stop_is_stray_single_step`](super::stops::stop_is_stray_single_step).
pub fn hardware_breakpoint_hit(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    event: &StopEvent,
) -> Result<Option<Breakpoint>> {
    if event.is_bugcheck || !breakpoints.has_enabled_hardware_breakpoints() {
        return Ok(None);
    }
    let slots = backend.hardware_breakpoint_slots();

    if let Some(address) = event.watchpoint_address {
        return Ok(watchpoint_covering(breakpoints, slots, address));
    }

    // Debug-register evidence only means anything on the debug exception, and
    // checking that here is what keeps an ordinary stop from fetching
    // registers. A transport that exposes no debug registers reports no
    // exception code either, so it has no such gate to pass.
    let debug_registers = register_map.contains("dr6") || register_map.contains("bcr0");
    if debug_registers && event.exception_code != Some(STATUS_SINGLE_STEP) {
        return Ok(None);
    }

    let mut regs = backend.read_registers()?;
    let Ok(dr6) = register_map.read_u64("dr6", &regs) else {
        if !debug_registers {
            return execute_breakpoint_at_pc(
                backend,
                register_map,
                breakpoints,
                slots,
                event,
                &mut regs,
            );
        }
        return arm64_hardware_breakpoint_hit(register_map, breakpoints, event, &regs);
    };

    let hit = (0..HW_BREAKPOINT_SLOTS)
        .filter(|slot| dr6 & (1u64 << slot) != 0)
        .find_map(|slot| breakpoints.hardware_breakpoint_for_slot(slot));

    let mut dirty = false;
    // Clear the B0-B3 status bits so the next single-step is unambiguous; the
    // CPU never clears them itself, but leave the rest of DR6 intact.
    let cleared = dr6 & !0b1111u64;
    if cleared != dr6 {
        register_map.write_u64("dr6", &mut regs, cleared)?;
        dirty = true;
    }
    if hit
        .as_ref()
        .and_then(|bp| bp.hardware)
        .is_some_and(|hw| hw.access == HwBreakpointAccess::Execute)
    {
        let eflags = register_map.read_u64("eflags", &regs)?;
        const RF: u64 = 1 << 16;
        if eflags & RF == 0 {
            register_map.write_u64("eflags", &mut regs, eflags | RF)?;
            dirty = true;
        }
    }

    if dirty {
        backend.write_registers(&regs)?;
    }

    Ok(hit)
}

/// The data watchpoint covering `address`, which is what a transport-reported
/// trap address names: the byte touched, not the watchpoint's base.
fn watchpoint_covering(
    breakpoints: &BreakpointManager,
    slots: u8,
    address: u64,
) -> Option<Breakpoint> {
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
    slots: u8,
    event: &StopEvent,
    regs: &mut [u8],
) -> Result<Option<Breakpoint>> {
    let Some(pc) = register_map
        .read_u64("rip", regs)
        .or_else(|_| register_map.read_u64("pc", regs))
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
        && let Ok(eflags) = register_map.read_u64("eflags", regs)
    {
        const RF: u64 = 1 << 16;
        if eflags & RF == 0 {
            register_map.write_u64("eflags", regs, eflags | RF)?;
            backend.write_registers(regs)?;
        }
    }

    Ok(hit)
}

fn arm64_hardware_breakpoint_hit(
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    event: &StopEvent,
    regs: &[u8],
) -> Result<Option<Breakpoint>> {
    let pc = register_map
        .read_u64("pc", regs)
        .or_else(|_| register_map.read_u64("rip", regs))
        .unwrap_or_else(|_| event.program_counter.unwrap_or(0));
    let far = register_map.read_u64("far", regs).unwrap_or(0);
    let mut hit = None;

    // ARM64 WVR values are granule-aligned and WCR.BAS identifies the bytes
    // that caused the data watchpoint. Require FAR as evidence: without it a
    // plain single-step must not be mistaken for a data breakpoint.
    if far != 0 {
        for slot in hwbp::ARM64_WATCHPOINT_SLOTS {
            let Some(bp) = breakpoints.hardware_breakpoint_for_slot(slot) else {
                continue;
            };
            let Some(hw) = bp.hardware else { continue };
            if hw.access == HwBreakpointAccess::Execute {
                continue;
            }
            let control = register_map
                .read_u64(format!("wcr{slot}"), regs)
                .unwrap_or(0);
            let value = register_map
                .read_u64(format!("wvr{slot}"), regs)
                .unwrap_or(0);
            if control & 1 == 0 || value != far & !7 {
                continue;
            }
            let bas = ((control >> 5) & 0xff) as u8;
            let far_bit = 1u8 << (far & 7);
            let in_requested_range = bp
                .address
                .0
                .checked_add(hw.len as u64)
                .is_some_and(|end| far >= bp.address.0 && far < end);
            if bas & far_bit != 0 && in_requested_range {
                hit = Some(bp);
                break;
            }
        }
    }

    if hit.is_none() {
        for slot in hwbp::ARM64_BREAKPOINT_SLOTS {
            let Some(bp) = breakpoints.hardware_breakpoint_for_slot(slot) else {
                continue;
            };
            let Some(hw) = bp.hardware else { continue };
            if hw.access != HwBreakpointAccess::Execute {
                continue;
            }
            let index = slot - hwbp::ARM64_BREAKPOINT_SLOTS.start;
            let control = register_map
                .read_u64(format!("bcr{index}"), regs)
                .unwrap_or(0);
            let value = register_map
                .read_u64(format!("bvr{index}"), regs)
                .unwrap_or(0);
            if control & 1 != 0 && value == pc & !3 && bp.address.0 == pc {
                hit = Some(bp);
                break;
            }
        }
    }

    Ok(hit)
}

/// Resolve one stop against the watchpoint manager. This owns the behavior
/// common to every host: claim and acknowledge backend status, adopt the
/// stopped thread, refresh register/CR3 context before condition evaluation,
/// and resume a pass-count or false conditional hit. Condition errors fail
/// safe by surfacing the hit with error metadata.
pub fn resolve_watchpoint_stop(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &mut BreakpointManager,
    target: &mut Target,
    current_thread: &mut String,
    event: &StopEvent,
) -> Result<WatchpointStopAction> {
    let Some(breakpoint) = hardware_breakpoint_hit(backend, register_map, breakpoints, event)?
    else {
        return Ok(WatchpointStopAction::NotBreakpoint);
    };

    set_current_thread_from_stop(backend, event, current_thread);
    let registers = backend.read_registers()?;
    let scope_dtb = register_map
        .read_u64(target.arch().dtb_register(), &registers)
        .unwrap_or(0);
    update_target_context_from_registers(target, register_map, Ok(registers));
    if !breakpoint.scope.matches_dtb(scope_dtb, target.arch()) {
        backend.continue_execution()?;
        return Ok(WatchpointStopAction::Resumed);
    }
    if let Some(thread) = breakpoint.thread.as_ref() {
        let stopped = refresh_windows_thread_context_for_backend_thread(target, current_thread);
        if !thread.matches(stopped.as_ref()) {
            backend.continue_execution()?;
            return Ok(WatchpointStopAction::Resumed);
        }
    }
    if !stopped_processor_matches(breakpoint.processor, current_thread) {
        backend.continue_execution()?;
        return Ok(WatchpointStopAction::Resumed);
    }
    if breakpoints.record_hit(breakpoint.id)? == BreakpointHitDisposition::SkipPass {
        backend.continue_execution()?;
        return Ok(WatchpointStopAction::Resumed);
    }

    let condition_error = match breakpoint.evaluate_condition(target) {
        Ok(false) => {
            backend.continue_execution()?;
            return Ok(WatchpointStopAction::Resumed);
        }
        Ok(true) => None,
        Err(error) => Some(error.to_string()),
    };
    if breakpoint.one_shot {
        breakpoints.remove(backend, target, breakpoint.id)?;
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
    if arch == Arch::Arm64 {
        return;
    }
    let Ok(regs) = backend.read_registers() else {
        return;
    };
    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
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
    if register_map.write_u64("rip", &mut adjusted, prev).is_err() {
        return;
    }
    let _ = backend.write_registers(&adjusted);
}
