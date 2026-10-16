//! Resuming, stepping, and waiting on the target, and translating each
//! stop into the reply a client expects.

use std::io;
use std::mem::take;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gdbstub::common::{Signal, Tid};
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::MultiThreadStopReason;
use gdbstub::target::ext::base::multithread::{
    MultiThreadResume, MultiThreadSchedulerLocking, MultiThreadSchedulerLockingOps,
    MultiThreadSingleStep, MultiThreadSingleStepOps,
};

use crate::dbg_backend::{ContinueDisposition, ModuleEvent};
use crate::gdb::trace_packet;
use crate::output;
use crate::repl::STATUS_BREAKPOINT;
use crate::session::stops::module_event_line;
use crate::session::{Cancel, Motion, RunOutcome, Stop, StopKind};
use crate::triage_report::exception_code_name;

use super::connection::Client;
use super::{GdbTarget, PlantedKind};

/// How long each wait for a stop runs before checking the client socket.
const RUN_POLL: Duration = Duration::from_millis(50);
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xC000_008E;
const STATUS_FLOAT_INVALID_OPERATION: u32 = 0xC000_0090;
const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC000_0096;

/// What a wait for the target produced.
pub(super) enum Wait {
    Stopped(MultiThreadStopReason<u64>),
    /// The client sent something (typically the `0x03` interrupt byte).
    Data(u8),
    Terminating,
}

impl GdbTarget<'_> {
    pub(super) fn note(&mut self, text: impl Into<String>) {
        self.notes.push(text.into());
    }

    /// Send queued notes, guest `DbgPrint` output, and session notices to the
    /// client's console.
    fn flush_console(&mut self, client: &mut Client) -> io::Result<()> {
        let mut text = String::new();
        for notice in self.session.take_notices() {
            text.push_str(match notice.level {
                crate::notice::NoticeLevel::Warning => "warning: ",
                crate::notice::NoticeLevel::Info => "note: ",
            });
            text.push_str(&notice.text);
            text.push('\n');
        }
        let page = self.session.read_debug_output(self.debug_seq);
        self.debug_seq = page.next_seq;
        if page.dropped {
            text.push_str("guest debug output overflowed; lines were dropped\n");
        }
        for line in page.lines {
            text.push_str(&line.text);
            text.push('\n');
        }
        for note in self.notes.drain(..) {
            text.push_str("ntoseye: ");
            text.push_str(&note);
            text.push('\n');
        }
        if text.is_empty() {
            return Ok(());
        }
        client.console(&text)
    }

    /// Run `motion` on the session, queueing what breakpoint actions print
    /// for the client's console. A run that fails is reported as a stop, so
    /// the client sees why instead of waiting on a run that can never end.
    fn drive(&mut self, motion: Motion, cancel: &Cancel<'_>) -> Option<Stop> {
        let (outcome, text) = output::capture(|| self.session.run(motion, cancel));
        if !text.is_empty() {
            self.note(text.trim_end().to_string());
        }
        match outcome {
            Ok(RunOutcome::Stopped(stop)) => Some(stop),
            Ok(RunOutcome::Running) => None,
            Err(error) => {
                self.note(format!("the target cannot run: {error}"));
                self.resume_refused = true;
                Some(self.session.unreported_stop())
            }
        }
    }

    /// Wait for the resumed target to stop, for the client to send
    /// something, or for a termination signal.
    pub(super) fn wait(&mut self, client: &mut Client) -> io::Result<Wait> {
        loop {
            if let Some(stop) = self.pending.take() {
                let refused = take(&mut self.resume_refused);
                let reason = self.stop_reason(stop, refused);
                self.flush_console(client)?;
                return Ok(Wait::Stopped(reason));
            }
            if self.terminating() {
                return Ok(Wait::Terminating);
            }
            if let Some(byte) = client.peek()? {
                client.next += 1;
                trace_packet("client", "<-", &[byte]);
                return Ok(Wait::Data(byte));
            }
            self.pending = self.drive(Motion::Wait, &Cancel::within(RUN_POLL));
            self.flush_console(client)?;
        }
    }

    /// Break in for the client's interrupt.
    pub(super) fn interrupt(&mut self) -> Option<MultiThreadStopReason<u64>> {
        self.cancel.store(false, Ordering::SeqCst);
        let stop = self
            .drive(Motion::Break, &Cancel::NEVER)
            .unwrap_or_else(|| self.session.unreported_stop());
        self.resume_refused = false;
        Some(self.stop_reason(stop, true))
    }

    /// Translate a session stop into a stop reply. `interrupted` marks the
    /// break-in the client asked for, which gdb expects as `SIGINT`, and a
    /// resume that failed, which must not look like a finished step.
    fn stop_reason(&mut self, stop: Stop, interrupted: bool) -> MultiThreadStopReason<u64> {
        let rip = stop.rip.unwrap_or(0);
        let signal = match stop.kind {
            StopKind::Breakpoint { breakpoint: hit } => {
                if let Some(error) = &hit.condition_error {
                    self.note(format!("breakpoint {} condition failed: {error}", hit.id));
                }
                self.sync_threads();
                let tid = self.current_tid();
                if let Some(planted) = self.planted.iter().find(|planted| planted.id == hit.id) {
                    return match planted.kind {
                        PlantedKind::Software => MultiThreadStopReason::SwBreak(tid),
                        PlantedKind::Hardware => MultiThreadStopReason::HwBreak(tid),
                        PlantedKind::Watch { kind, .. } => MultiThreadStopReason::Watch {
                            tid,
                            kind,
                            addr: planted.address,
                        },
                    };
                }
                // Set with `monitor bp`: the client has no record of it.
                let place = hit.symbol.unwrap_or_else(|| format!("{rip:#x}"));
                self.note(format!("breakpoint {} hit at {place}", hit.id));
                Signal::SIGTRAP
            }
            StopKind::Step => Signal::SIGTRAP,
            StopKind::ModuleLoad { module } => {
                self.note(module_event_line(ModuleEvent::Load, &module));
                Signal::SIGTRAP
            }
            StopKind::ModuleUnload { module } => {
                self.note(module_event_line(ModuleEvent::Unload, &module));
                Signal::SIGTRAP
            }
            StopKind::Entry | StopKind::Interrupt if interrupted => Signal::SIGINT,
            StopKind::Entry | StopKind::Interrupt => Signal::SIGTRAP,
            StopKind::Exception { exception }
                if interrupted && exception.code == STATUS_BREAKPOINT =>
            {
                Signal::SIGINT
            }
            StopKind::Exception { exception } => {
                let code = exception.code;
                let chance = match exception.first_chance {
                    Some(true) => " (first chance)",
                    Some(false) => " (second chance)",
                    None => "",
                };
                let name = exception_code_name(code);
                self.note(format!("{name} ({code:#010x}){chance} at {rip:#x}"));
                exception_signal(code)
            }
            StopKind::Bugcheck { bugcheck } => {
                let detail = match bugcheck {
                    Some(info) => format!(
                        "bugcheck {:#x} ({:#x}, {:#x}, {:#x}, {:#x})",
                        info.code,
                        info.parameters[0],
                        info.parameters[1],
                        info.parameters[2],
                        info.parameters[3]
                    ),
                    None => "bugcheck (code unavailable from the transport)".to_string(),
                };
                match stop.rip {
                    Some(rip) => self.note(format!("{detail} at {rip:#x}")),
                    None => self.note(detail),
                }
                self.note("run `monitor !analyze -v` for the full triage");
                Signal::SIGABRT
            }
            StopKind::Reload { reload } => {
                let base = reload
                    .kernel_base
                    .map(|base| format!("{base:#x}"))
                    .unwrap_or_else(|| "unknown".to_string());
                let early = if reload.coherent {
                    ""
                } else {
                    " (early boot: modules and processes are not available yet)"
                };
                self.note(format!("target rebooted; nt base {base}{early}"));
                // Every breakpoint the client planted belonged to the old boot.
                self.planted.clear();
                Signal::SIGTRAP
            }
        };
        self.signal(signal)
    }

    /// `signal` on the thread that stopped.
    fn signal(&mut self, signal: Signal) -> MultiThreadStopReason<u64> {
        self.sync_threads();
        MultiThreadStopReason::SignalWithThread {
            tid: self.current_tid(),
            signal,
        }
    }
}

/// The signal gdb shows for a Windows exception. Anything without a closer
/// POSIX match is a trap; the console note names the real status.
fn exception_signal(code: u32) -> Signal {
    match code {
        STATUS_BREAKPOINT | STATUS_SINGLE_STEP => Signal::SIGTRAP,
        STATUS_ACCESS_VIOLATION | STATUS_IN_PAGE_ERROR => Signal::SIGSEGV,
        STATUS_ILLEGAL_INSTRUCTION | STATUS_PRIVILEGED_INSTRUCTION => Signal::SIGILL,
        STATUS_FLOAT_DIVIDE_BY_ZERO
        | STATUS_FLOAT_INVALID_OPERATION
        | STATUS_INTEGER_DIVIDE_BY_ZERO
        | STATUS_INTEGER_OVERFLOW => Signal::SIGFPE,
        _ => Signal::SIGTRAP,
    }
}

impl MultiThreadResume for GdbTarget<'_> {
    fn resume(&mut self) -> std::result::Result<(), Self::Error> {
        self.cancel.store(false, Ordering::SeqCst);
        // A failed resume is reported as a stop, so the client sees the
        // reason instead of waiting forever or dropping the connection.
        self.pending = match self.step_thread.take() {
            Some(tid) => match self.select(tid) {
                Ok(()) => self.drive(Motion::Step, &Cancel::NEVER),
                Err(error) => {
                    self.note(format!("the target cannot run: {error}"));
                    self.resume_refused = true;
                    Some(self.session.unreported_stop())
                }
            },
            // Resume and take a stop already waiting; the wait takes the rest.
            None => self.drive(
                Motion::Continue {
                    disposition: ContinueDisposition::Handled,
                },
                &Cancel::poll(),
            ),
        };
        Ok(())
    }

    fn clear_resume_actions(&mut self) -> std::result::Result<(), Self::Error> {
        self.step_thread = None;
        Ok(())
    }

    /// All-stop: a continue resumes every vCPU, whichever thread it names.
    fn set_resume_action_continue(
        &mut self,
        _tid: Tid,
        _signal: Option<Signal>,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }

    fn support_scheduler_locking(&mut self) -> Option<MultiThreadSchedulerLockingOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadSingleStep for GdbTarget<'_> {
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        _signal: Option<Signal>,
    ) -> std::result::Result<(), Self::Error> {
        self.step_thread = Some(tid);
        Ok(())
    }
}

/// A step already runs one vCPU with the others frozen, so locking the
/// scheduler to the stepped thread is what happens anyway.
impl MultiThreadSchedulerLocking for GdbTarget<'_> {
    fn set_resume_action_scheduler_lock(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}
