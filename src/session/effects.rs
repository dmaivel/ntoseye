//! What an operation needs of the target and what it changes, declared once
//! per command (`#[command(target = ..., state = ...)]`, `repl_command!`) and
//! enforced by [`Session::admit`], which the REPL dispatcher and the Python
//! SDK both call before running it. Each host words a [`Refusal`] its own way
//! (the REPL prefixes the typed name, the SDK raises a typed exception), so
//! the decision is shared and the messages stay the hosts'.

use crate::dbg_backend::{DebugCapability, halt_unreachable_reason};
use crate::error::Error;
use crate::session::Session;

/// Everything admission checks about one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effects {
    pub target: TargetScope,
    pub state: RunState,
    pub run: RunEffect,
    /// The state the operation changes besides execution.
    pub writes: &'static [Writes],
    /// Refused on a crash dump or user-mode minidump, which never change.
    pub live_only: bool,
    /// A backend capability the operation needs.
    pub capability: Option<DebugCapability>,
}

impl Effects {
    /// Runs on any target in any state and changes nothing.
    pub const NONE: Effects = Effects {
        target: TargetScope::Any,
        state: RunState::Any,
        run: RunEffect::None,
        writes: &[],
        live_only: false,
        capability: None,
    };

    /// Reads registers or patches state: needs the target halted.
    pub const HALTED: Effects = Effects {
        state: RunState::Halted,
        ..Effects::NONE
    };

    /// Reads kernel structures: refused on a user-mode minidump.
    pub const KERNEL: Effects = Effects {
        target: TargetScope::Kernel,
        ..Effects::NONE
    };

    /// Both [`Self::KERNEL`] and [`Self::HALTED`].
    pub const KERNEL_HALTED: Effects = Effects {
        target: TargetScope::Kernel,
        state: RunState::Halted,
        ..Effects::NONE
    };

    /// Whether the operation needs the target halted now: a
    /// [`RunState::HaltedOrParkedThread`] operation does not while a parked
    /// thread is the context.
    pub fn needs_halt(&self, session: &Session) -> bool {
        match self.state {
            RunState::Halted => true,
            RunState::HaltedOrParkedThread => session.parked_windows_thread().is_none(),
            RunState::Running | RunState::Any => false,
        }
    }
}

/// What a command needs of the target besides its run state. A halted
/// user-mode minidump passes every run-state check, so a command that reads
/// kernel structures says so here and is refused there with one message,
/// whatever name or alias runs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetScope {
    Any,
    /// A Windows kernel: a live target or a kernel dump.
    Kernel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Any,
    Halted,
    /// Halted, unless the context is a parked Windows thread (`.thread`)
    /// and no vCPU's registers: its stack, frames, and their recovered
    /// registers are read from memory, which a running target (and the
    /// memory backend, which always runs) serves live.
    HaltedOrParkedThread,
    Running,
}

/// What a command does to target execution, so dispatch contexts that must
/// not let a command move the target (breakpoint actions, exception
/// commands, a remote host with its own run-control) can refuse it by
/// metadata rather than by a name list that aliases can bypass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunEffect {
    /// Leaves execution state alone (or only pauses it).
    None,
    /// Executes one instruction and returns promptly.
    Step,
    /// Resumes until the next stop; may block indefinitely.
    Run,
}

/// State an operation changes besides execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writes {
    Memory,
    Registers,
    Breakpoints,
    Symbols,
    Files,
}

/// Why [`Session::admit`] refused an operation.
#[derive(Debug)]
pub enum Refusal {
    /// The target is a user-mode minidump; the error says so.
    KernelRequired(Error),
    /// The operation needs a halted target and it runs.
    Running {
        /// Why `break` cannot halt it, when it cannot.
        unreachable: Option<String>,
        /// A parked thread (`.thread`) would also do.
        or_parked_thread: bool,
    },
    /// A `RunState::Running` operation (`break`) on a halted target: there
    /// is nothing to do, which is what was asked.
    AlreadyHalted,
    /// The operation runs or steps a static snapshot (a crash dump).
    NoExecutionControl { backend: &'static str },
    /// A `live_only` operation on a crash dump or minidump.
    StaticDump,
    /// The backend lacks the declared capability.
    Unsupported {
        capability: DebugCapability,
        backend: &'static str,
    },
    /// A writing operation in the `.vtl 1` memory view, which is read-only.
    ReadOnlyVtl1,
}

impl Session {
    /// Whether `effects` may run now. Checked in a fixed order (target kind,
    /// run state, execution control, static dump, capability, VTL1 view),
    /// so every host refuses the same operation for the same reason.
    pub fn admit(&self, effects: &Effects) -> Result<(), Refusal> {
        if effects.target == TargetScope::Kernel
            && let Err(error) = self.target.require_kernel()
        {
            return Err(Refusal::KernelRequired(error));
        }
        let running = self.backend.is_running();
        if running && effects.needs_halt(self) {
            return Err(Refusal::Running {
                unreachable: halt_unreachable_reason(&*self.backend),
                or_parked_thread: effects.state == RunState::HaltedOrParkedThread,
            });
        }
        if effects.state == RunState::Running && !running {
            return Err(Refusal::AlreadyHalted);
        }
        // Halted without execution control is a static snapshot (a crash
        // dump): a command that would run or step it could only fail on the
        // way, or report a stop that never happened.
        if effects.run != RunEffect::None
            && !running
            && !self.supports(DebugCapability::ExecutionControl)
        {
            return Err(Refusal::NoExecutionControl {
                backend: self.backend.name(),
            });
        }
        if effects.live_only && self.target.phys.is_dump() {
            return Err(Refusal::StaticDump);
        }
        if let Some(capability) = effects.capability
            && !self.supports(capability)
        {
            return Err(Refusal::Unsupported {
                capability,
                backend: self.backend.name(),
            });
        }
        if !effects.writes.is_empty() && self.target.in_secure_scope() {
            return Err(Refusal::ReadOnlyVtl1);
        }
        Ok(())
    }

    fn supports(&self, capability: DebugCapability) -> bool {
        self.capabilities()
            .iter()
            .any(|entry| entry.capability == capability && entry.supported)
    }
}
