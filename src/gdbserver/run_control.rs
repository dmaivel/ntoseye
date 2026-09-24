//! Resuming, stepping, and waiting on the target, and translating each
//! stop into the reply a client expects.

use std::io;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gdbstub::common::{Signal, Tid};
use gdbstub::conn::ConnectionExt;
use gdbstub::stub::MultiThreadStopReason;
use gdbstub::target::ext::base::multithread::{
    MultiThreadResume, MultiThreadSchedulerLocking, MultiThreadSchedulerLockingOps,
    MultiThreadSingleStep, MultiThreadSingleStepOps,
};

use crate::gdb::trace_packet;
use crate::repl::STATUS_BREAKPOINT;
use crate::session::ContinueOutcome;
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
            text.push_str(&notice);
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

    /// Wait for the resumed target to stop, for the client to send
    /// something, or for a termination signal.
    pub(super) fn wait(&mut self, client: &mut Client) -> io::Result<Wait> {
        loop {
            if let Some(outcome) = self.pending.take()
                && let Some(reason) = self.stop_reason(outcome, false)
            {
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
            let outcome = self
                .session
                .wait_for_stop_bounded(Some(RUN_POLL), &self.cancel);
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => {
                    // Report a stop rather than leave the client waiting on a
                    // run that can never end.
                    self.note(format!("target wait failed: {error}"));
                    ContinueOutcome::Halted { rip: 0 }
                }
            };
            self.flush_console(client)?;
            if let Some(reason) = self.stop_reason(outcome, false) {
                self.flush_console(client)?;
                return Ok(Wait::Stopped(reason));
            }
        }
    }

    /// Break in for the client's interrupt.
    pub(super) fn interrupt(&mut self) -> Option<MultiThreadStopReason<u64>> {
        self.cancel.store(false, Ordering::SeqCst);
        let outcome = self.session.interrupt_outcome().unwrap_or_else(|error| {
            self.note(format!("break-in failed: {error}"));
            ContinueOutcome::Halted { rip: 0 }
        });
        // Nothing to report if the target kept running; the client keeps
        // waiting and may interrupt again.
        self.stop_reason(outcome, true)
    }

    /// Translate a session stop into a stop reply, or `None` when the target
    /// is still running (a breakpoint action resumed it). `interrupted` marks
    /// the break-in the client asked for, which gdb expects as `SIGINT`.
    fn stop_reason(
        &mut self,
        outcome: ContinueOutcome,
        interrupted: bool,
    ) -> Option<MultiThreadStopReason<u64>> {
        let signal = match outcome {
            ContinueOutcome::Running => return None,
            ContinueOutcome::Breakpoint {
                id,
                symbol,
                rip,
                action,
                condition_error,
                ..
            } => {
                if let Some(error) = condition_error {
                    self.note(format!("breakpoint {id} condition failed: {error}"));
                }
                if let Some(action) = action
                    && self.run_breakpoint_action(&action)
                {
                    return None;
                }
                self.sync_threads();
                let tid = self.current_tid();
                if let Some(planted) = self.planted.iter().find(|planted| planted.id == id) {
                    return Some(match planted.kind {
                        PlantedKind::Software => MultiThreadStopReason::SwBreak(tid),
                        PlantedKind::Hardware => MultiThreadStopReason::HwBreak(tid),
                        PlantedKind::Watch { kind, .. } => MultiThreadStopReason::Watch {
                            tid,
                            kind,
                            addr: planted.address,
                        },
                    });
                }
                // Set with `monitor bp`: the client has no record of it.
                let place = symbol.unwrap_or_else(|| format!("{rip:#x}"));
                self.note(format!("breakpoint {id} hit at {place}"));
                Signal::SIGTRAP
            }
            ContinueOutcome::Step { .. } => Signal::SIGTRAP,
            ContinueOutcome::Halted { .. } if interrupted => Signal::SIGINT,
            ContinueOutcome::Halted { .. } => Signal::SIGTRAP,
            ContinueOutcome::Stopped {
                rip,
                exception_code,
                first_chance,
                ..
            } => match exception_code {
                None | Some(STATUS_BREAKPOINT) if interrupted => Signal::SIGINT,
                None => Signal::SIGTRAP,
                Some(code) => {
                    let chance = match first_chance {
                        Some(true) => " (first chance)",
                        Some(false) => " (second chance)",
                        None => "",
                    };
                    let name = exception_code_name(code);
                    self.note(format!("{name} ({code:#010x}){chance} at {rip:#x}"));
                    exception_signal(code)
                }
            },
            ContinueOutcome::Bugcheck { rip, info } => {
                let detail = match info {
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
                match rip {
                    Some(rip) => self.note(format!("{detail} at {rip:#x}")),
                    None => self.note(detail),
                }
                self.note("run `monitor !analyze -v` for the full triage");
                Signal::SIGABRT
            }
            ContinueOutcome::TargetReloaded {
                kernel_base,
                coherent,
                ..
            } => {
                let base = kernel_base
                    .map(|base| format!("{base:#x}"))
                    .unwrap_or_else(|| "unknown".to_string());
                let early = if coherent {
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
        self.sync_threads();
        Some(MultiThreadStopReason::SignalWithThread {
            tid: self.current_tid(),
            signal,
        })
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
        let outcome = match self.step_thread.take() {
            Some(tid) => self
                .select(tid)
                .and_then(|()| self.session.step())
                .map(|rip| Some(ContinueOutcome::Step { rip })),
            None => self.session.resume().map(|()| None),
        };
        self.pending = match outcome {
            Ok(pending) => pending,
            Err(error) => {
                self.note(format!("the target cannot run: {error}"));
                Some(ContinueOutcome::Halted { rip: 0 })
            }
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
