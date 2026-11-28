//! Resuming, stepping, and waiting on the target, and translating each
//! stop into the reply a client expects.

use std::io;
use std::mem::take;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gdb_remote::request::{Action, BreakpointType, ThreadAction};
use gdb_remote::stop::{Reason, Signalled, StopReply};

use crate::backend::dbg_backend::{ContinueDisposition, DebugCapability, ModuleEvent};
use crate::base::notice::NoticeLevel;
use crate::base::ntstatus::{
    STATUS_ACCESS_VIOLATION, STATUS_BREAKPOINT, STATUS_FLOAT_DIVIDE_BY_ZERO,
    STATUS_FLOAT_INVALID_OPERATION, STATUS_ILLEGAL_INSTRUCTION, STATUS_IN_PAGE_ERROR,
    STATUS_INTEGER_DIVIDE_BY_ZERO, STATUS_INTEGER_OVERFLOW, STATUS_PRIVILEGED_INSTRUCTION,
    STATUS_SINGLE_STEP,
};
use crate::base::output;
use crate::session::driver::describe_bugcheck;
use crate::session::stops::module_event_line;
use crate::session::{Cancel, Motion, RunOutcome, Stop, StopKind};

use super::Server;
use super::connection::Connection;

/// How long each wait for a stop runs before checking the client socket.
const RUN_POLL: Duration = Duration::from_millis(50);

/// The signals stops are reported as, by GDB's numbers.
const SIGINT: u8 = 2;
const SIGILL: u8 = 4;
const SIGTRAP: u8 = 5;
const SIGABRT: u8 = 6;
const SIGFPE: u8 = 8;
const SIGSEGV: u8 = 11;

/// What a wait for the resumed target produced.
pub(super) enum Wait {
    /// The target stopped: the stop reply.
    Stopped(Vec<u8>),
    /// The client sent the interrupt byte.
    Interrupted,
    Terminating,
}

/// What a resume does: step one thread (by index), or continue them all.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Resume {
    Step(usize),
    Continue,
}

impl Server<'_> {
    pub(super) fn note(&mut self, text: impl Into<String>) {
        self.notes.push(text.into());
    }

    /// Send queued notes, guest `DbgPrint` output, and session notices to the
    /// client's console.
    pub(super) fn flush_console(&mut self, connection: &mut Connection) -> io::Result<()> {
        let mut text = String::new();
        for notice in self.session.take_notices() {
            text.push_str(match notice.level {
                NoticeLevel::Warning => "warning: ",
                NoticeLevel::Info => "note: ",
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
        connection.console(&text)
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
            Err(error) => Some(self.refused(&error)),
        }
    }

    /// The stop to report for a resume that could not run.
    fn refused(&mut self, error: &dyn std::fmt::Display) -> Stop {
        self.note(format!("the target cannot run: {error}"));
        self.resume_refused = true;
        self.session.unreported_stop()
    }

    /// What `vCont` with `actions` does. All-stop: a step steps one vCPU
    /// with the others stopped, and a continue resumes them all, whatever
    /// threads it names. A step naming no thread (Binary Ninja's) steps
    /// the thread `Hc` chose, else the stopped vCPU. `None` for an action
    /// the server does not take (`t`, `r`, which `vCont?` does not offer),
    /// or a thread that does not exist.
    pub(super) fn resume_for(&self, actions: &[ThreadAction]) -> Option<Resume> {
        let mut resume = Resume::Continue;
        for action in actions {
            match action.action {
                Action::Continue | Action::ContinueSignal(_) => {}
                Action::Step | Action::StepSignal(_) => {
                    if resume == Resume::Continue {
                        let thread = match action.thread {
                            Some(thread) => self.resolve(thread)?,
                            None => None,
                        };
                        resume = Resume::Step(self.resume_index(thread));
                    }
                }
                Action::Stop | Action::RangeStep { .. } => return None,
            }
        }
        Some(resume)
    }

    /// The thread a step steps: `thread`, else the `Hc` thread, else the
    /// stopped vCPU.
    pub(super) fn resume_index(&self, thread: Option<usize>) -> usize {
        thread
            .or(self.resume_thread)
            .unwrap_or_else(|| self.current_index())
    }

    /// Start `resume`. A failed resume is reported as a stop, so the client
    /// sees the reason instead of waiting forever.
    pub(super) fn resume(&mut self, resume: Resume) {
        self.cancel.store(false, Ordering::SeqCst);
        self.pending = match resume {
            Resume::Step(index) => match self.select(index) {
                Ok(()) => self.drive(Motion::Step, &Cancel::NEVER),
                Err(error) => Some(self.refused(&error)),
            },
            // Resume and take a stop already waiting; the wait takes the rest.
            Resume::Continue => self.drive(
                Motion::Continue {
                    disposition: ContinueDisposition::Handled,
                },
                &Cancel::poll(),
            ),
        };
    }

    /// Wait for the resumed target to stop, for the client's interrupt, or
    /// for a termination signal.
    pub(super) fn wait(&mut self, connection: &mut Connection) -> io::Result<Wait> {
        loop {
            if let Some(stop) = self.pending.take() {
                let refused = take(&mut self.resume_refused);
                return Ok(Wait::Stopped(self.stop_reply(stop, refused)));
            }
            if self.terminating() {
                return Ok(Wait::Terminating);
            }
            if connection.interrupted()? {
                return Ok(Wait::Interrupted);
            }
            self.pending = self.drive(Motion::Wait, &Cancel::within(RUN_POLL));
            self.flush_console(connection)?;
        }
    }

    /// Break in for the client's interrupt: the stop reply.
    pub(super) fn interrupt(&mut self) -> Vec<u8> {
        self.cancel.store(false, Ordering::SeqCst);
        let stop = self
            .drive(Motion::Break, &Cancel::NEVER)
            .unwrap_or_else(|| self.session.unreported_stop());
        self.resume_refused = false;
        self.stop_reply(stop, true)
    }

    /// The stop reply for `stop`, which `?` and `qThreadStopInfo` repeat.
    /// `interrupted` marks the break-in the client asked for, which gdb
    /// expects as `SIGINT`, and a resume that failed, which must not look
    /// like a finished step. The thread it names becomes the one registers
    /// are read from, as gdb assumes of every stop reply (it sends `Hg`
    /// only for another thread).
    fn stop_reply(&mut self, stop: Stop, interrupted: bool) -> Vec<u8> {
        if let Some(exit_code) = stop.exit_code() {
            self.note(format!("process exited ({exit_code:#x})"));
            let mut reply = Vec::new();
            StopReply::Exited {
                status: (exit_code & 0xff) as u8,
                process: None,
            }
            .write(&mut reply);
            return reply;
        }
        let mut signalled = self.signalled(stop, interrupted);
        self.sync_threads();
        let index = self.current_index();
        signalled.thread = Some(self.thread_id(index));
        self.general_thread = Some(index);
        let mut reply = Vec::new();
        StopReply::Signal(signalled.clone()).write(&mut reply);
        self.last_stop = Some((index, signalled));
        reply
    }

    /// The `?` reply: the last stop this client saw; on a user-mode
    /// minidump that records an exception, the exception's signal on the
    /// thread that raised it; else, on a target that runs, an interrupt on
    /// the stopped vCPU: the client found it halted (the server broke in
    /// for it, or for an attach), which IDA expects as a pause, not as a
    /// trap it did not cause; and a trap on a dump, which never ran.
    pub(super) fn halt_reply(&mut self) -> Vec<u8> {
        self.sync_threads();
        let (index, mut signalled) = self.last_stop.clone().unwrap_or_else(|| {
            let exception = self.session.target.user_dump_info().and_then(|info| {
                let exception = info.exception.as_ref()?;
                Some((
                    exception_signal(exception.code),
                    info.backend_thread_id(exception.thread_id),
                ))
            });
            match exception {
                Some((signal, thread)) => (self.index_of(&thread), signal_only(signal)),
                None if self
                    .session
                    .backend
                    .supports(DebugCapability::InterruptTarget) =>
                {
                    (self.current_index(), signal_only(SIGINT))
                }
                None => (self.current_index(), signal_only(SIGTRAP)),
            }
        });
        // The pid may have changed since (an attach).
        signalled.thread = Some(self.thread_id(index));
        self.general_thread = Some(index);
        let mut reply = Vec::new();
        StopReply::Signal(signalled).write(&mut reply);
        reply
    }

    /// lldb's `qThreadStopInfo`: the last stop on the thread that stopped,
    /// and no signal on the others, which were only halted with it.
    pub(super) fn thread_stop_reply(&mut self, thread: u64) -> Option<Vec<u8>> {
        let index = usize::try_from(thread).ok()?.checked_sub(1)?;
        if index >= self.threads.len() {
            return None;
        }
        let signalled = match &self.last_stop {
            Some((stopped, signalled)) if *stopped == index => signalled.clone(),
            _ => signal_only(0),
        };
        let mut reply = Vec::new();
        StopReply::Signal(Signalled {
            thread: Some(self.thread_id(index)),
            ..signalled
        })
        .write(&mut reply);
        Some(reply)
    }

    /// Why `stop` stopped, as a signal and, for the client's own
    /// breakpoints, the reason; the thread is filled in by the caller.
    fn signalled(&mut self, stop: Stop, interrupted: bool) -> Signalled<'static> {
        let rip = stop.rip.unwrap_or(0);
        let signal = match stop.kind {
            StopKind::Breakpoint { breakpoint: hit } => {
                if let Some(error) = &hit.condition_error {
                    self.note(format!("breakpoint {} condition failed: {error}", hit.id));
                }
                if let Some(planted) = self
                    .planted
                    .iter()
                    .find(|planted| planted.id == hit.id && planted.serial == hit.serial)
                {
                    let reason = match planted.kind {
                        BreakpointType::Software => Reason::SoftwareBreak,
                        BreakpointType::Hardware => Reason::HardwareBreak,
                        BreakpointType::WriteWatch => Reason::Watch(planted.address),
                        BreakpointType::ReadWatch => Reason::ReadWatch(planted.address),
                        BreakpointType::AccessWatch => Reason::AccessWatch(planted.address),
                    };
                    return Signalled {
                        reason: Some(reason),
                        ..signal_only(SIGTRAP)
                    };
                }
                // Set with `monitor bp`: the client has no record of it.
                let place = hit.symbol.unwrap_or_else(|| format!("{rip:#x}"));
                self.note(format!("breakpoint {} hit at {place}", hit.id));
                SIGTRAP
            }
            StopKind::Step => SIGTRAP,
            StopKind::ModuleLoad { module } => {
                self.note(module_event_line(ModuleEvent::Load, &module));
                SIGTRAP
            }
            StopKind::ModuleUnload { module } => {
                self.note(module_event_line(ModuleEvent::Unload, &module));
                SIGTRAP
            }
            StopKind::Entry | StopKind::Interrupt if interrupted => SIGINT,
            StopKind::Entry | StopKind::Interrupt => SIGTRAP,
            StopKind::Exception { exception }
                if interrupted && exception.code == STATUS_BREAKPOINT =>
            {
                SIGINT
            }
            StopKind::Exception { exception } => {
                self.note(exception.describe(rip));
                exception_signal(exception.code)
            }
            StopKind::Bugcheck { bugcheck } => {
                let detail = describe_bugcheck(bugcheck.as_ref());
                match stop.rip {
                    Some(rip) => self.note(format!("{detail} at {rip:#x}")),
                    None => self.note(detail),
                }
                self.note("run `monitor !analyze -v` for the full triage");
                SIGABRT
            }
            StopKind::Reload { reload } => {
                self.note(reload.describe());
                // Every breakpoint the client planted belonged to the old boot.
                self.planted.clear();
                SIGTRAP
            }
            StopKind::ProcessExited { exit_code } => {
                self.note(format!("process exited ({exit_code:#x})"));
                SIGTRAP
            }
        };
        signal_only(signal)
    }
}

/// A stop reply's signal, with nothing more said.
fn signal_only(signal: u8) -> Signalled<'static> {
    Signalled {
        signal,
        ..Signalled::default()
    }
}

/// The signal gdb shows for a Windows exception. Anything without a closer
/// POSIX match is a trap; the console note names the real status.
fn exception_signal(code: u32) -> u8 {
    match code {
        STATUS_BREAKPOINT | STATUS_SINGLE_STEP => SIGTRAP,
        STATUS_ACCESS_VIOLATION | STATUS_IN_PAGE_ERROR => SIGSEGV,
        STATUS_ILLEGAL_INSTRUCTION | STATUS_PRIVILEGED_INSTRUCTION => SIGILL,
        STATUS_FLOAT_DIVIDE_BY_ZERO
        | STATUS_FLOAT_INVALID_OPERATION
        | STATUS_INTEGER_DIVIDE_BY_ZERO
        | STATUS_INTEGER_OVERFLOW => SIGFPE,
        _ => SIGTRAP,
    }
}
