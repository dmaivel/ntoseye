//! Guest reboot detection, and the target rebuild and module-list
//! rediscovery that follow it.

use crate::bugchecks::looks_like_kernel_pointer;
use crate::dbg_backend::StopEvent;
use crate::error::Result;
use crate::gdb::BreakpointManager;
use crate::kd::{kd_files, trace_enabled};
use crate::session::{STATUS_BREAKPOINT, Session, TargetReloadOutcome};
use crate::target::{ReloadReport, Target};
use crate::types::VirtAddr;

/// How [`Session::classify_reload_stop`] classified a freshly observed stop:
/// real stop, reboot artifact, or transport noise.
/// [`Session::classify_stop_event`] turns the reboot cases into
/// [`StopResolution::TargetReloaded`](super::StopResolution::TargetReloaded)
/// and resumes past the noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReloadDisposition {
    /// Not reboot/assist related; handle it as an ordinary stop (breakpoint,
    /// exception, manual pause).
    Ordinary,
    /// The guest rebooted and guest state was rebuilt. `coherent` is true once
    /// the loaded-module list is available (introspection usable); false means
    /// the reload happened but the system is still very early in boot (module
    /// and process enumeration unavailable until a later stop completes
    /// rediscovery). Hosts surface both: this is the earliest meaningful
    /// post-reboot stop.
    Reloaded { coherent: bool },
    /// Rediscovery completed for a reload that was never surfaced (the rebuild
    /// failed at the detection stop, so the host has not been told the guest
    /// rebooted). Surface it as the reload notification, the fallback that
    /// guarantees one notification per reboot. When the reload *was* surfaced
    /// at detection, completion is silent instead: noise stops classify as
    /// [`Self::ResumePastAssist`], real stops as [`Self::Ordinary`].
    ReloadCompleted,
    /// A reboot was observed but the kernel image isn't discoverable yet; resume
    /// and keep retrying (the assist break-ins retry the reload until it lands,
    /// which then surfaces as [`Self::Reloaded`]).
    PendingRediscovery,
    /// A debugger-induced KD reconnect/refresh break-in (or any mid-reboot stop
    /// before the module list is available): resume past it, don't surface.
    ResumePastAssist,
}

impl Session {
    /// Whether kernel structures are safe to read: the loaded-module list is
    /// populated (not early boot / mid-rediscovery) and the kernel base still
    /// reads `MZ` (no undetected reboot).
    pub fn kernel_coherent(&self) -> bool {
        !self.reload_module_list_pending && self.target.current_kernel_mapping_is_valid()
    }

    /// Rebuild guest state, auto-discovering the kernel base.
    pub fn reload(&mut self) -> Result<()> {
        self.target.last_exception_code = None;
        self.module_refresh_report = None;
        let outcome = self.perform_target_reload(None);
        if let Some(error) = outcome.breakpoint_error {
            return Err(error);
        }
        outcome.report.map(|_| ())
    }

    /// If a module-list reload is pending and the loaded-module list has now
    /// appeared, finish rediscovery: reload the kernel module symbols, tell the
    /// backend rediscovery completed (stopping its reconnect-assist poking), and
    /// clear the pending flag. Returns whether it completed on this call.
    fn try_complete_pending_reload(&mut self) -> Result<bool> {
        if !self.reload_module_list_pending {
            return Ok(false);
        }
        let startup = match self.target.startup_message_data() {
            Ok(startup) => startup,
            Err(error) => {
                reload_trace!("try_complete: startup read failed: {error}");
                return Ok(false);
            }
        };
        reload_trace!("try_complete: psmods={:#x}", startup.loaded_module_list.0);
        if startup.loaded_module_list.is_zero() {
            return Ok(false);
        }
        self.target.refresh_kernel_module_symbols()?;
        self.breakpoints
            .resolve_symbolic(self.backend.as_mut(), &self.target)?;
        self.backend.note_target_rediscovery_complete();
        self.reload_module_list_pending = false;
        Ok(true)
    }

    /// Try to finish module-list rediscovery by reading `PsLoadedModuleList` from
    /// guest memory instead of forcing a stop. Skips while a reload notification
    /// is still owed, so completion cannot silently swallow the one
    /// `TargetReloaded` event.
    pub(super) fn try_finish_rediscovery_from_memory(&mut self) {
        if !self.reload_surface_pending {
            let _ = self.try_complete_pending_reload();
        }
    }

    /// Clear a deferred reboot notification once the host has already observed
    /// or acted on the rebuilt target. Leave it pending if the current kernel
    /// mapping still looks stale, so a later wait can surface the real reload.
    pub(super) fn clear_deferred_reload_surface(&mut self) {
        if self.target.current_kernel_mapping_is_valid() {
            self.reload_surface_pending = false;
        }
    }

    /// Advance the reboot / KD-reconnect state machine for a freshly observed
    /// `event`, returning how a host should treat it (see [`ReloadDisposition`]).
    /// On a detected reload it drops stale breakpoints, rebuilds guest state, and
    /// records whether the module list is available yet (setting
    /// [`Self::reload_module_list_pending`]); on a later stop it tries to complete
    /// a pending rediscovery; otherwise it recognizes transport assist break-ins.
    /// Mutates `event.target_reloaded` to match. Called only from
    /// [`Self::classify_stop_event`].
    pub(super) fn classify_reload_stop(
        &mut self,
        event: &mut StopEvent,
    ) -> Result<ReloadDisposition> {
        reload_trace!(
            "classify: pc={} exc={} assisted={} reloaded={} bugcheck={} pending={}",
            event
                .program_counter
                .map_or_else(|| "none".to_string(), |p| format!("{p:#x}")),
            event
                .exception_code
                .map_or_else(|| "none".to_string(), |c| format!("{c:#x}")),
            event.assisted_breakin,
            event.target_reloaded,
            event.is_bugcheck,
            self.reload_module_list_pending,
        );

        if stop_event_requires_target_reload(&self.target, event) {
            event.target_reloaded = true;
            // The reboot invalidates the site: the kernel is re-based and
            // the target's breakpoint is gone. The next resume re-arms it.
            self.bugcheck_trap = None;
            let TargetReloadOutcome {
                report,
                hint,
                breakpoint_error,
            } = self.perform_target_reload(event.target_kernel_base_hint);
            if let Some(error) = breakpoint_error {
                return Err(error);
            }
            return Ok(match report {
                Ok(report) => {
                    let coherent = reload_report_has_loaded_module_list(&report);
                    // The host surfaces this verdict, so the reboot has been
                    // reported; the eventual completion stays silent.
                    self.reload_surface_pending = false;
                    reload_trace!(
                        "classify: reload ok hint={} new_base={} psmods={} coherent={}",
                        hint.map_or_else(|| "none".to_string(), |value| format!("{:#x}", value.0)),
                        self.target.kernel_base().map_or_else(
                            || "none".to_string(),
                            |address| format!("{:#x}", address.0)
                        ),
                        report.startup.as_ref().map_or_else(
                            || "none".to_string(),
                            |startup| format!("{:#x}", startup.loaded_module_list.0),
                        ),
                        coherent,
                    );
                    ReloadDisposition::Reloaded { coherent }
                }
                Err(error) => {
                    self.reload_surface_pending = true;
                    reload_trace!("classify: reload err={error} -> pending_rediscovery");
                    ReloadDisposition::PendingRediscovery
                }
            });
        }

        // A pending reload whose module list just became available completes here
        // (and turns off the reconnect-assist poking). If the reload itself was
        // never surfaced (the rebuild failed at the detection stop), surface the
        // completion as the one reload notification for this reboot; otherwise
        // the completion is silent; absorb debugger noise, and let a real stop
        // (e.g. an early-boot breakpoint hit) be handled normally below.
        if self.try_complete_pending_reload()? {
            if self.reload_surface_pending {
                self.reload_surface_pending = false;
                reload_trace!(
                    "classify: pending reload COMPLETED (unsurfaced) -> reload_completed"
                );
                return Ok(ReloadDisposition::ReloadCompleted);
            }
            if stop_is_assisted_refresh_breakin(&self.breakpoints, event) {
                reload_trace!("classify: pending reload COMPLETED silently -> resume_past_assist");
                return Ok(ReloadDisposition::ResumePastAssist);
            }
            reload_trace!("classify: pending reload COMPLETED silently at a real stop");
            return Ok(ReloadDisposition::Ordinary);
        }

        // KD refresh/reconnect/debugger break-in (including the boot-time assist
        // pokes while a reload is still pending): resume past it. Real stops,
        // notably hits on breakpoints set at the early-boot reload stop, fall
        // through and surface even while the module list is still pending.
        if stop_is_assisted_refresh_breakin(&self.breakpoints, event) {
            reload_trace!("classify: assisted refresh break-in -> resume_past_assist");
            return Ok(ReloadDisposition::ResumePastAssist);
        }

        reload_trace!("classify: ordinary");
        Ok(ReloadDisposition::Ordinary)
    }

    /// Rebuild guest state after a detected reboot: drop the now-stale
    /// breakpoints, resolve a kernel-base hint (preferring the stop event's,
    /// else the backend's), reload the guest image, and tell the backend
    /// whether rediscovery completed so it stops (or keeps) its
    /// reconnect-assist poking. The reload *action* behind
    /// [`Self::classify_reload_stop`] and [`Self::reload`]; callers
    /// layer their own state on top of the returned outcome.
    fn perform_target_reload(&mut self, event_hint: Option<VirtAddr>) -> TargetReloadOutcome {
        let backend = self.backend.as_mut();
        let target = &mut self.target;
        let breakpoints = &mut self.breakpoints;
        // Target-specific numeric breakpoints and hardware slots cannot survive a
        // rebuild. Symbolic code breakpoints retain identity and become deferred.
        breakpoints.prepare_target_reload(backend);
        // Release file handles owned by the previous target.
        kd_files().reset_handles();
        // A load-symbols stop's hint is the loading image's base, which is the
        // kernel only for the first; the transport's own answer wins.
        let location = backend.target_kernel_location().ok().flatten();
        let hint = location.map(|location| location.base).or(event_hint);
        let report = target.reload_guest(location, event_hint);
        self.reload_module_list_pending = !report
            .as_ref()
            .is_ok_and(reload_report_has_loaded_module_list);
        // The attach-time identity check only proved the host mapping matched the
        // kernel that was running then. Re-check it against the rebuilt target
        // before anything reads through it again.
        if report.is_ok()
            && let Err(error) = backend.revalidate_host_memory(&target.phys)
        {
            self.notices.push(format!(
                "host memory no longer matches the target after the reload ({error}); every \
                 read through it is now suspect - reattach with --memory-source kd"
            ));
        }
        let breakpoint_error = if report.is_ok() {
            let debugger_data_hint = backend.target_debugger_data_hint().ok().flatten();
            target.refresh_debugger_data(debugger_data_hint);
            breakpoints.resolve_symbolic(backend, target).err()
        } else {
            None
        };
        match &report {
            // Once the kernel image is rediscovered, stop reconnect-assist pokes. The
            // remaining module-list completion is polled from live memory; forced
            // break-ins here would freeze early boot and delay the list we're waiting on.
            Ok(_) => backend.note_target_rediscovery_complete(),
            // Kernel not discoverable at all (no base to read): the assist poke is the
            // only way to force a stop where the rebuild can be retried, so keep it.
            Err(_) => backend.note_target_rediscovery_pending(),
        }
        TargetReloadOutcome {
            report,
            hint,
            breakpoint_error,
        }
    }
}

/// Whether a guest-reload report found the loaded-module list (i.e. kernel
/// rediscovery completed). Single definition shared with the REPL.
pub fn reload_report_has_loaded_module_list(report: &ReloadReport) -> bool {
    report
        .startup
        .as_ref()
        .is_some_and(|startup| !startup.loaded_module_list.is_zero())
}

/// How close to the current kernel base a stop PC must be to be treated as the
/// *same* kernel image rather than a reboot into a relocated one.
const CURRENT_KERNEL_RELOAD_WINDOW: u64 = 0x1000_0000;

/// Whether `event` reflects a guest reboot into a new kernel image (so debugger
/// state must be rebuilt), rather than an ordinary stop in the current one.
/// Trusts the transport's explicit reload flag, then falls back to heuristics:
/// an invalidated current-kernel mapping (whatever the PC), a kernel-space PC
/// that lands in no known module, or a rediscovered kernel whose identity
/// changed, while treating a near-base non-bugcheck stop as the *same* image.
fn stop_event_requires_target_reload(debugger: &Target, event: &StopEvent) -> bool {
    if event.target_reloaded {
        return true;
    }

    // Wherever the stop landed, a kernel image that no longer reads back
    // through its own page tables means the guest rebooted.
    if !debugger.current_kernel_mapping_is_valid() {
        return true;
    }

    let Some(pc) = event.program_counter else {
        return false;
    };
    if !looks_like_kernel_pointer(pc) {
        return false;
    }

    let current_dtb = debugger.kernel_dtb();
    if debugger
        .symbols
        .find_module_for_address(current_dtb, VirtAddr(pc))
        .is_some()
    {
        return false;
    }

    if !event.is_bugcheck
        && debugger
            .kernel_base()
            .is_some_and(|base| pc.abs_diff(base.0) < CURRENT_KERNEL_RELOAD_WINDOW)
    {
        return false;
    }

    debugger
        .rediscovered_kernel_identity_changed()
        .unwrap_or(false)
}

/// Whether `event` is a debugger-generated KD refresh/reconnect break-in
/// rather than a user break or genuine target exception, i.e. a stop to resume
/// past, not surface. KD marks reconnect-assist break-ins explicitly via the
/// `assisted_breakin` flag; user-initiated break-ins (e.g. via Ctrl+C) always
/// surface as real stops regardless of where the kernel hits. Used by
/// [`Session::classify_reload_stop`].
pub fn stop_is_assisted_refresh_breakin(
    breakpoints: &BreakpointManager,
    event: &StopEvent,
) -> bool {
    if event.bugcheck.is_some() || event.exception_code != Some(STATUS_BREAKPOINT) {
        return false;
    }

    if event
        .program_counter
        .is_some_and(|pc| breakpoints.breakpoint_id_at_address(pc).is_some())
    {
        return false;
    }

    event.assisted_breakin
}
