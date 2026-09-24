//! Run control: resuming, stepping and interrupting the target, and
//! recording and classifying the stops it reports.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::bytes;
use crate::dbg_backend::{ContinueDisposition, StopEvent};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::types::Arch;

use super::breakpoints::{
    breakpoint_instruction_at, reclaimed_breakpoints_notice, restore_unowned_breakpoint_handles,
};
use super::registers::KSPECIAL_REGISTERS_DR7_OFFSET;
use super::{
    AwaitStateOptions, ContinueDrain, ControlReport, DBG_KD_EXCEPTION_STATE_CHANGE,
    DBG_KD_LOAD_SYMBOLS_STATE_CHANGE, KD_REQUEST_TIMEOUT, KdBackend, Link, STATUS_BREAKPOINT,
    StateChange, StateChangeFilter, advance_pc_past_breakpoint, api, await_state_change,
    blocking_read_timeout, breakin_and_wait, read_program_counter, thread_id_for,
    with_framing_read_timeout,
};

const POST_BUGCHECK_RECONNECT_ASSIST_DELAY: Duration = Duration::from_secs(20);

pub(super) fn stop_event(stop: StateChange) -> StopEvent {
    StopEvent {
        thread_id: Some(thread_id_for(stop.processor)),
        exception_code: (stop.new_state == DBG_KD_EXCEPTION_STATE_CHANGE)
            .then_some(stop.exception_code),
        first_chance: stop.exception_first_chance,
        exception_address: stop.exception_address,
        program_counter: Some(stop.program_counter),
        watchpoint_address: None,
        is_bugcheck: stop.is_bugcheck,
        bugcheck: stop.bugcheck,
        target_reloaded: stop.target_reloaded,
        target_kernel_base_hint: stop.kernel_base_hint,
        modules_changed: stop.new_state == DBG_KD_LOAD_SYMBOLS_STATE_CHANGE,
        assisted_breakin: stop.assisted_breakin,
    }
}

impl KdBackend {
    fn known_breakin_stop(&self, stop: &StateChange) -> bool {
        self.unmanaged_breakpoint_stop(stop)
            && (self.late_breakin || self.breakin_addresses.contains(&stop.program_counter))
            // A break the host asked for is not assist noise, even though the
            // guest signals it from the same address our break-ins land on.
            && self.surface_break_at != Some(stop.program_counter)
    }

    /// A `STATUS_BREAKPOINT` exception on none of our breakpoints: how the
    /// target reports a break-in.
    fn unmanaged_breakpoint_stop(&self, stop: &StateChange) -> bool {
        stop.new_state == DBG_KD_EXCEPTION_STATE_CHANGE
            && stop.exception_code == STATUS_BREAKPOINT
            && !self.managed_bp_addresses.contains(&stop.program_counter)
    }

    pub(super) fn mark_known_breakin_stop(&self, mut stop: StateChange) -> StateChange {
        if self.known_breakin_stop(&stop) {
            stop.assisted_breakin = true;
        }
        stop
    }

    pub(super) fn record_stop(&mut self, stop: &StateChange) {
        if self.unmanaged_breakpoint_stop(stop) {
            self.late_breakin = false;
        }
        if stop.target_reloaded {
            kd_trace!("kd: target reload detected; clearing target-owned breakpoint state");
            self.bp_handles.clear();
            self.managed_bp_addresses.clear();
            self.breakin_addresses.clear();
            self.late_breakin = false;
            self.pending_write_breakpoint = None;
        } else if stop.is_bugcheck {
            self.reconnect_assist_after_continue = Some(POST_BUGCHECK_RECONNECT_ASSIST_DELAY);
        }
        let managed_breakpoint_stop = stop.exception_code == STATUS_BREAKPOINT
            && self.managed_bp_addresses.contains(&stop.program_counter);
        if stop.assisted_breakin
            && stop.exception_code == STATUS_BREAKPOINT
            && !managed_breakpoint_stop
        {
            self.breakin_addresses.insert(stop.program_counter);
        }
        kd_trace!(
            "kd: stop on p{}, new_state={:#x}, exception_code={:#x}, rip={:#x}, managed_bp={}",
            stop.processor + 1,
            stop.new_state,
            stop.exception_code,
            stop.program_counter,
            managed_breakpoint_stop
        );
        self.current_processor = stop.processor;
        // A rebooted target reports its real count; between reboots the count
        // never shrinks (no hot-unplug), so keep the high-water mark.
        self.processor_count = if stop.target_reloaded {
            stop.number_processors.max(1)
        } else {
            self.processor_count.max(stop.number_processors.max(1))
        };
        self.last_stop_processor = stop.processor;
        self.last_exception_code = stop.exception_code;
        self.last_rip = stop.program_counter;
        self.registers
            .stopped(stop.processor, stop.control_report.clone());
        self.stop_was_managed_breakpoint = managed_breakpoint_stop;
        if self.surface_break_at == Some(stop.program_counter) {
            self.surface_break_at = None;
        }
        // EFER survives: the guest sets it once entering long mode and a
        // reload is the only way a processor's value can differ from the one
        // we read. Re-reading it per stop costs an MSR round trip in every
        // absorbed breakpoint hit.
        if stop.target_reloaded {
            self.efer_cache.clear();
        }
        self.link.halt();
    }

    pub(super) fn record_running(&mut self) {
        self.link.resume(&mut self.registers);
        self.stop_was_managed_breakpoint = false;
        self.virtual_lines.clear();
        self.table_lines.clear();
        self.translations.resume();
    }

    /// Step the resume PC past a hard-coded `int3`, when that is genuinely what
    /// is at the PC.
    ///
    /// An `int3` that is really part of the guest's code has already executed
    /// by the time the kernel reports the stop with the PC back on it, so
    /// resuming in place would trap on it forever and the PC has to move past
    /// it. Every other `int3` at a stop PC is a *displaced* byte standing in
    /// for a real instruction, and moving the PC past one of those resumes
    /// inside that instruction: `48 8b c4` (`mov rax,rsp`) entered at its
    /// second byte is `8b c4` (`mov eax,esp`), which truncates the register the
    /// next instruction dereferences, and the guest faults three bytes into the
    /// function it was entering. So a displaced byte is never stepped over:
    ///
    /// * One of ours is left alone; the host's step-over owns removing and
    ///   restoring it.
    /// * A table entry a dead session stranded is released, which makes the
    ///   target restore the byte it displaced. Attach clears the table, but a
    ///   target reload drops our handles while the entries survive.
    /// * A PC that cannot be read resumes in place. Failing that way costs a
    ///   repeated stop; failing the other way corrupts the guest.
    ///
    /// The PC comes from the register cache rather than the recorded stop:
    /// hosts rewind and rewrite it between a stop and the resume, and a write
    /// invalidates that cache, so the cached value is always what is about to
    /// execute. It is already warm whenever the host classified the stop,
    /// which makes the common path free.
    pub(super) fn skip_hardcoded_breakpoint(&mut self, processor: u16) -> Result<()> {
        if self.last_exception_code != STATUS_BREAKPOINT {
            return Ok(());
        }
        self.require_no_pending_write_breakpoint()?;
        let arch = self.arch;
        let register_map = self.register_map.clone();
        let pc = self.resume_program_counter(processor, &register_map)?;
        // Our own site, disabled by the host's step-over between the stop and
        // this resume. Reading memory here would find the restored original
        // byte and prove only what the stop already said.
        if self.stop_was_managed_breakpoint && pc == self.last_rip {
            return Ok(());
        }
        if self.managed_bp_addresses.contains(&pc) {
            return Ok(());
        }
        if !breakpoint_instruction_at(self.link.framing(self.running_reason)?, arch, processor, pc)
        {
            kd_trace!(
                "kd: stop at {pc:#x} reported a breakpoint but memory holds none; resuming in place"
            );
            return Ok(());
        }

        let owned: HashSet<u32> = self.bp_handles.values().copied().collect();
        let reclaimed = restore_unowned_breakpoint_handles(
            self.link.framing(self.running_reason)?,
            processor,
            &owned,
            &mut self.released_handles,
        );
        self.notices.extend(reclaimed_breakpoints_notice(reclaimed));
        if reclaimed != 0
            && !breakpoint_instruction_at(
                self.link.framing(self.running_reason)?,
                arch,
                processor,
                pc,
            )
        {
            kd_trace!("kd: released a stranded breakpoint at {pc:#x}; resuming in place");
            return Ok(());
        }

        kd_trace!(
            "kd: advancing p{} past a hard-coded int3 at {pc:#x}",
            processor + 1
        );
        // The PC goes straight through the context API, behind
        // `write_registers` and its cache invalidation.
        self.registers.invalidate(processor);
        advance_pc_past_breakpoint(
            self.link.framing(self.running_reason)?,
            &register_map,
            arch,
            processor,
            pc,
        )
    }

    /// The program counter `processor` resumes from, served from the halt's
    /// register cache when it already holds that processor.
    ///
    /// Only a warm cache is consulted. Filling it would fetch the control
    /// registers and EFER alongside the context, which costs more than the
    /// bare context request this replaces.
    fn resume_program_counter(
        &mut self,
        processor: u16,
        register_map: &RegisterMap,
    ) -> Result<u64> {
        if let Some(context) = self.registers.context(processor)
            && let Ok(pc) = register_map.read_u64("rip", context)
        {
            return Ok(pc);
        }
        let arch = self.arch;
        read_program_counter(
            self.link.framing(self.running_reason)?,
            register_map,
            arch,
            processor,
        )
    }

    pub(super) fn continue_preserving_dr7(
        &mut self,
        processor: u16,
        status: u32,
        trace: bool,
    ) -> Result<()> {
        match self.arch {
            Arch::Amd64 => {
                // The stop reported DR7, so a resume that read no special
                // registers needs none: only a host write can have changed
                // it, and that drops the report along with the rest of the
                // processor's halt state.
                let reported_dr7 = self
                    .registers
                    .report(processor)
                    .and_then(ControlReport::amd64_dr7);
                if reported_dr7.is_none() && self.registers.special(processor).is_none() {
                    let special = self.read_special_registers_uncached(processor)?;
                    self.registers.set_special(processor, special);
                }
                let dr7 = match self.registers.special(processor) {
                    // A `ba` installed during this halt wrote the cache; it
                    // is newer than the report.
                    Some(special) => bytes::read_u64(special, KSPECIAL_REGISTERS_DR7_OFFSET),
                    None => reported_dr7.expect("read the registers when no report offered DR7"),
                };
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::continue_api2(framing, processor, status, trace, dr7)
                })
            }
            Arch::Arm64 => {
                // ARM64_DBGKD_CONTROL_SET has no Dr7 field; the kernel
                // single-steps via MDSCR when TraceFlag is set.
                with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
                    api::continue_api2_arm64(framing, processor, status, trace)
                })
            }
        }
    }

    pub(super) fn request_reboot(&mut self) -> Result<()> {
        let processor = self.current_processor;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::reboot(framing, processor)
        })?;
        // Reboot has no manipulate-state reply: after the transport ACK the
        // kernel resets the KD stream and eventually emits a fresh state
        // change. Keep the backend visibly running and let the pump perform
        // the existing reconnect/reload detection dance.
        self.record_running();
        self.start_pump(Some(Duration::ZERO), None)
    }

    pub(super) fn request_bugcheck(&mut self) -> Result<()> {
        let processor = self.current_processor;
        with_framing_read_timeout(self.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::cause_bugcheck(framing, processor)
        })?;
        // KeBugCheck2 skips the fatal print and the first debugger break for
        // MANUALLY_INITIATED_CRASH: the target writes its dump (tens of seconds,
        // interrupts off, break-ins ignored) and then reboots, or breaks in
        // afterwards when automatic restart is disabled. Treat it like a reboot,
        // but do not poke immediately: the kernel still polls for break-ins on
        // its way into KeBugCheck2 and an early poke detours it into a stop.
        self.record_running();
        self.start_pump(Some(POST_BUGCHECK_RECONNECT_ASSIST_DELAY), None)
    }

    pub(super) fn resume_with(&mut self, disposition: ContinueDisposition) -> Result<()> {
        let resume_processor = self.last_stop_processor;
        self.skip_hardcoded_breakpoint(resume_processor)?;
        // The pump absorbs the re-break a stale break-in byte causes right
        // after resume; it needs to know where we resumed from and which
        // breakpoints are real. Nothing can change either while the VM runs.
        let drain = ContinueDrain::new(
            self.last_rip,
            self.managed_bp_addresses.clone(),
            self.breakin_addresses.clone(),
            self.register_map.clone(),
            self.surface_break_at,
        );
        let reconnect_assist_after_continue = self.reconnect_assist_after_continue;
        kd_trace!(
            "kd: continue: sending ContinueApi2 on p{}",
            resume_processor + 1
        );
        self.continue_preserving_dr7(
            resume_processor,
            api::status_for_disposition(disposition),
            false,
        )?;
        kd_trace!("kd: continue: ContinueApi2 ACKed, VM should resume");
        self.record_running();
        // Hand the socket to the background pump so prints keep getting ACKed
        // (and the debugger stays "present") until the next stop.
        self.start_pump(reconnect_assist_after_continue, Some(drain))
    }

    pub(super) fn single_step(&mut self) -> Result<()> {
        // Managed BP step-over needs to execute the original instruction. A
        // single step stops almost immediately, so the caller's wait_for_stop
        // reads it synchronously; no pump needed
        let processor = self.current_processor;
        // A raw int3 stop still points at the int3; stepping from there would
        // only execute it again and report the same stop.
        if processor == self.last_stop_processor {
            self.skip_hardcoded_breakpoint(processor)?;
        }
        self.continue_preserving_dr7(processor, api::DBG_CONTINUE, true)?;
        self.record_running();
        Ok(())
    }

    pub(super) fn break_in(&mut self) -> Result<StopEvent> {
        let stop = if let Link::RunningPumped(pump) = &self.link {
            // Pump owns the socket; poke the kernel with a break-in over the
            // cloned fd, then collect the state-change the pump reports back.
            // Flag it first: the stop lands at the KD break-in instruction,
            // where the pump would otherwise absorb it as post-continue noise.
            pump.breakin_requested.store(true, Ordering::SeqCst);
            self.send_raw_breakin()?;
            match self.take_pump_stop(Some(Duration::from_secs(10)))? {
                Some(stop) => stop,
                None => {
                    self.shutdown_pump();
                    return Err(Error::Kd("no break-in response within 10s".into()));
                }
            }
        } else {
            // Stopped, or running via a bare step: drive the break-in inline
            let arch = self.arch;
            breakin_and_wait(self.framing()?, arch, Duration::from_secs(10))?
        };
        self.late_breakin = !self.unmanaged_breakpoint_stop(&stop);
        self.record_stop(&stop);
        Ok(stop_event(stop))
    }

    pub(super) fn await_stop(&mut self) -> Result<StopEvent> {
        if matches!(self.link, Link::RunningPumped(_)) {
            let stop = self
                .take_pump_stop(None)?
                .ok_or_else(|| Error::Kd("KD pump returned no stop".into()))?;
            let stop = self.mark_known_breakin_stop(stop);
            self.record_stop(&stop);
            return Ok(stop_event(stop));
        }
        let debug_log = self.debug_log.clone();
        let arch = self.arch;
        // Request paths leave shorter timeouts in place; a blocking wait needs a long one.
        let _ = self
            .framing()?
            .transport_mut()
            .set_read_timeout(Some(blocking_read_timeout()));
        let stop = await_state_change(
            self.framing()?,
            AwaitStateOptions {
                arch,
                saw_kd_refresh: None,
                filter: StateChangeFilter::Runtime,
                bugcheck: None,
                bugcheck_capture: None,
                deadline: None,
                debug_log: Some(&debug_log),
            },
        )?;
        let stop = self.mark_known_breakin_stop(stop);
        self.record_stop(&stop);
        Ok(stop_event(stop))
    }

    pub(super) fn poll_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        // Pump path: the background thread already services the socket and
        // detects stops, so just poll it. This is the common case while running
        if matches!(self.link, Link::RunningPumped(_)) {
            return match self.take_pump_stop(Some(timeout))? {
                Some(stop) => {
                    let stop = self.mark_known_breakin_stop(stop);
                    kd_trace!(
                        "kd: try_wait: pump reported stop rip={:#x} exc={:#x}",
                        stop.program_counter,
                        stop.exception_code
                    );
                    self.record_stop(&stop);
                    Ok(Some(stop_event(stop)))
                }
                None => Ok(None),
            };
        }
        // Synchronous fallback (no pump, e.g. polling after a bare step)
        self.framing()?
            .transport_mut()
            .set_read_timeout(Some(timeout))?;
        let mut saw_kd_refresh = false;
        let debug_log = self.debug_log.clone();
        let arch = self.arch;
        let result = await_state_change(
            self.framing()?,
            AwaitStateOptions {
                arch,
                saw_kd_refresh: Some(&mut saw_kd_refresh),
                filter: StateChangeFilter::Runtime,
                bugcheck: None,
                bugcheck_capture: None,
                deadline: Some(Instant::now() + timeout),
                debug_log: Some(&debug_log),
            },
        );

        let stop = match result {
            Ok(stop) => stop,
            Err(Error::Io(e))
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                if saw_kd_refresh {
                    kd_trace!("kd: try_wait: KD refresh observed while polling");
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        let stop = self.mark_known_breakin_stop(stop);
        kd_trace!(
            "kd: try_wait: stop rip={:#x} exc={:#x} in_managed={}",
            stop.program_counter,
            stop.exception_code,
            self.managed_bp_addresses.contains(&stop.program_counter)
        );

        self.record_stop(&stop);
        Ok(Some(stop_event(stop)))
    }
}
