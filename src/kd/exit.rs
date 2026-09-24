//! Detaching from the target: stopping the pump, releasing the breakpoints
//! the host left installed, and resuming the target when asked.

use std::collections::HashSet;
use std::mem::take;
use std::time::Duration;

use crate::dbg_backend::{DebugBackend, StopEvent, clear_trap_flag};
use crate::error::{Error, Result};

use super::{
    KD_REQUEST_TIMEOUT, KdBackend, Link, STATUS_SINGLE_STEP, api, with_framing_read_timeout,
};

const KD_EXIT_STOP_POLL: Duration = Duration::from_secs(1);
const KD_EXIT_MAX_CONTINUES: u32 = 8;
/// Module loads to continue through at exit; a full boot loads a few hundred.
const KD_EXIT_MAX_NOTIFICATIONS: u32 = 4096;

/// Whether a stop seen during exit is a stray single-step: `STATUS_SINGLE_STEP`
/// away from any int3 we installed (and not a bugcheck). The backend-layer twin
/// of [`crate::session::stops::stop_is_stray_single_step`]; `managed_bp_addresses` is
/// our installed-int3 set, standing in for the session's breakpoint manager.
pub(super) fn exit_stop_is_stray_single_step(
    stop: &StopEvent,
    managed_bp_addresses: &HashSet<u64>,
) -> bool {
    stop.exception_code == Some(STATUS_SINGLE_STEP)
        && !stop.is_bugcheck
        && stop
            .program_counter
            .is_none_or(|pc| !managed_bp_addresses.contains(&pc))
}

impl KdBackend {
    fn continue_stopped_for_exit(&mut self) -> Result<()> {
        let processor = self.last_stop_processor;
        self.skip_hardcoded_breakpoint(processor)?;
        self.continue_preserving_dr7(processor, api::DBG_CONTINUE, false)?;
        self.record_running();
        Ok(())
    }

    /// Hand every breakpoint site the host did not clear back to the target.
    ///
    /// A host that exits through its own teardown removes breakpoints through
    /// the manager and leaves nothing here. Abnormal exits (a termination
    /// signal, an I/O error unwinding past the REPL's cleanup) skip that path,
    /// and what is left behind is not just an `int3` in guest code: each site
    /// also holds one of the 32 entries in the target's `KdpBreakpointTable`
    /// for the rest of the boot, because only the debugger that owns a handle
    /// can release it. Best effort by construction: this runs while the
    /// process is already going away.
    fn restore_tracked_breakpoints(&mut self) {
        // Requests are only answered while the target is halted, and a pending
        // install owns the next reply on the wire.
        if self.bp_handles.is_empty()
            || self.link.is_running()
            || self.pending_write_breakpoint.is_some()
        {
            return;
        }
        let processor = self.current_processor;
        self.virtual_lines.clear();
        for (addr, handle) in take(&mut self.bp_handles) {
            let Ok(framing) = self.framing() else { return };
            match with_framing_read_timeout(framing, KD_REQUEST_TIMEOUT, |framing| {
                api::restore_breakpoint(framing, processor, handle)
            }) {
                Ok(()) => {
                    self.managed_bp_addresses.remove(&addr);
                }
                // The transport is going away with the process; a stranded
                // entry is better than blocking teardown on a retry.
                Err(error) => kd_trace!(
                    "kd: exit: restoring breakpoint handle {handle} at {addr:#x} failed: {error}"
                ),
            }
        }
    }

    /// Exit absorbs stray single-steps the same way run-control does: clear TF
    /// on the stopped vCPU, then continue. Otherwise a leaked TF can retrigger
    /// until exit gives up.
    fn absorb_stray_single_step_for_exit(&mut self, stop: &StopEvent) {
        if exit_stop_is_stray_single_step(stop, &self.managed_bp_addresses) {
            // record_stop selected the stop's processor, so this clears TF on the
            // offending vCPU. Clone the map to avoid borrowing self twice.
            let register_map = self.register_map.clone();
            let _ = clear_trap_flag(self, &register_map);
        }
    }

    pub(super) fn finish_for_exit(&mut self, leave_running: bool) -> Result<()> {
        if let Some(stop) = self.shutdown_pump_with_stop()? {
            self.record_stop(&stop);
        }
        self.restore_tracked_breakpoints();
        if !leave_running {
            return Ok(());
        }

        // A booting target stops on every image it loads, one after another,
        // so module-load notifications are progress and only other stops
        // count toward giving up. The notification cap only bounds the loop.
        let mut stops = 0;
        for _ in 0..KD_EXIT_MAX_NOTIFICATIONS {
            if !self.link.is_running() {
                self.continue_stopped_for_exit()?;
            }
            let Some(stop) = self.try_wait_for_stop(KD_EXIT_STOP_POLL)? else {
                return Ok(());
            };
            if stop.modules_changed {
                continue;
            }
            self.absorb_stray_single_step_for_exit(&stop);
            stops += 1;
            if stops == KD_EXIT_MAX_CONTINUES {
                break;
            }
        }

        Err(Error::Kd(if stops == KD_EXIT_MAX_CONTINUES {
            format!("target kept stopping during debugger exit after {stops} continues")
        } else {
            format!(
                "target was still loading modules during debugger exit after \
                 {KD_EXIT_MAX_NOTIFICATIONS} notifications"
            )
        }))
    }

    pub(super) fn needs_drop_cleanup(&self) -> bool {
        !self.exit_prepared && matches!(self.link, Link::Halted(_) | Link::RunningPumped(_))
    }
}

/// Best-effort resume during normal teardown
impl Drop for KdBackend {
    fn drop(&mut self) {
        if self.needs_drop_cleanup() {
            let _ = self.finish_for_exit(true);
        }
    }
}
