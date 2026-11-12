//! What an operation needs of the target and what it changes, declared once
//! per command (`#[command(target = ..., state = ...)]`) and
//! enforced by [`Session::admit`], which the REPL dispatcher and the Python
//! SDK both call before running it. Each host words a [`Refusal`] its own way
//! (the REPL prefixes the typed name, the SDK raises a typed exception), so
//! the decision is shared and the messages stay the hosts'.

use crate::backend::dbg_backend::{DebugCapability, halt_unreachable_reason};
use crate::base::error::Error;
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
    /// Writing guest state (`Writes::{Memory, Registers, Hardware}`)
    /// implies it.
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

    /// Reads a halted kernel target's machine state (its vCPUs), which a
    /// VTL1 address space has too.
    pub const MACHINE_HALTED: Effects = Effects {
        target: TargetScope::Machine,
        state: RunState::Halted,
        ..Effects::NONE
    };

    /// Whether the operation writes the guest's memory, registers or
    /// devices, which a dump does not have and VTL0 cannot write in VTL1.
    pub fn writes_guest(&self) -> bool {
        self.writes
            .iter()
            .any(|write| matches!(write, Writes::Memory | Writes::Registers | Writes::Hardware))
    }

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
    /// A Windows kernel: a live target or a kernel dump. Reads NT's
    /// structures, so a VTL1 address space refuses it.
    Kernel,
    /// A Windows kernel target's machine rather than NT's structures:
    /// processors, MSRs, page tables, the hypervisor, the VTLs, and the
    /// selection of a VTL0 context. A VTL1 address space admits it.
    Machine,
    /// NT's own state about an address space: a kernel target or a
    /// user-mode minidump (both are NT's), but not VTL1 or a root outside
    /// NT. Admission refuses it in a VTL1 address space and otherwise
    /// treats it as `Any`; an SDK `Memory` over such a space refuses it
    /// (`!address`).
    Nt,
}

impl TargetScope {
    /// Refused on a user-mode minidump.
    pub fn needs_kernel(self) -> bool {
        matches!(self, TargetScope::Kernel | TargetScope::Machine)
    }

    /// Reads NT's structures, which a VTL1 address space does not have.
    pub fn reads_nt(self) -> bool {
        matches!(self, TargetScope::Kernel | TargetScope::Nt)
    }
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
    /// Device state: I/O ports, configuration space.
    Hardware,
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
    /// A `live_only` operation, or one that writes guest state, on a crash
    /// dump or minidump.
    StaticDump,
    /// The backend lacks the declared capability.
    Unsupported {
        capability: DebugCapability,
        backend: &'static str,
    },
    /// The current VTL1 address space refuses the operation.
    Vtl1(Vtl1Refusal),
}

/// Why a VTL1 address space refuses an operation. The secure kernel's
/// state is not laid out as NT's, VTL0 cannot write VTL1's memory,
/// registers or code, and the `.vtl 1` view is memory alone, with no vCPU
/// behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vtl1Refusal {
    /// In the explicit `.vtl 1` memory view: it reads NT, writes, or needs
    /// a vCPU's state.
    MemoryView,
    /// At a live VTL1 stop with a saved VTL1 context selected (`.vtlcxr`),
    /// which is read-only.
    SelectedContext,
    /// At a live VTL1 stop: it reads NT or writes.
    LiveStop,
}

impl Vtl1Refusal {
    /// The refusal of `operation`, worded the same for every host.
    pub fn message(self, operation: &str) -> String {
        match self {
            Vtl1Refusal::MemoryView => format!(
                "'{operation}' is unavailable in the .vtl 1 memory view (reads, `ba e1`, and plain \
                 g only); use .vtl 0 first"
            ),
            Vtl1Refusal::SelectedContext => format!(
                "'{operation}' is unavailable while a VTL1 context is selected, which is \
                 read-only; .vtlcxr goes back to VTL0's"
            ),
            Vtl1Refusal::LiveStop => format!(
                "'{operation}' is unavailable while the vCPU is stopped in VTL1: it needs NT \
                 state, or writes VTL1 memory, registers, or code"
            ),
        }
    }
}

impl Session {
    /// Whether `effects` may run now. Checked in a fixed order (target kind,
    /// VTL1 address space, run state, execution control, static dump,
    /// capability), so every host refuses the same operation for the same
    /// reason.
    pub fn admit(&self, effects: &Effects) -> Result<(), Refusal> {
        if effects.target.needs_kernel()
            && let Err(error) = self.target.require_kernel()
        {
            return Err(Refusal::KernelRequired(error));
        }
        if let Some(refusal) = self.vtl1_refusal(effects) {
            return Err(Refusal::Vtl1(refusal));
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
        // way, or report a stop that never happened. A partition view's
        // backend runs nothing: a run there runs the target, through the
        // target's backend, which the view keeps aside.
        let runner = self.run_backend();
        if effects.run != RunEffect::None
            && !running
            && !runner.supports(DebugCapability::ExecutionControl)
        {
            return Err(Refusal::NoExecutionControl {
                backend: runner.name(),
            });
        }
        if (effects.live_only || effects.writes_guest()) && self.target.phys.is_dump() {
            return Err(Refusal::StaticDump);
        }
        if let Some(capability) = effects.capability
            && !self.backend.supports(capability)
        {
            return Err(Refusal::Unsupported {
                capability,
                backend: self.backend.name(),
            });
        }
        Ok(())
    }

    /// Why the current VTL1 address space (the `.vtl 1` view, or the root of
    /// a live VTL1 stop) refuses `effects`, if it does.
    ///
    /// NT's structures are not the secure kernel's, and VTL0 cannot write
    /// VTL1's memory, registers or devices. A file the debugger writes on
    /// the host, its symbol state (`.reload` of the secure kernel's
    /// modules) and the breakpoint table are the debugger's: `ba e1` is how
    /// a VTL1 stop is reached, and the breakpoint core refuses a site that
    /// would patch VTL1 code, as runs and steps take debug-register sites
    /// there. The `.vtl 1` view is memory alone: it also refuses what needs
    /// a vCPU's state (any operation that needs the target halted, but
    /// breakpoint bookkeeping), and a resume leaves it first.
    fn vtl1_refusal(&self, effects: &Effects) -> Option<Vtl1Refusal> {
        let target = &self.target;
        if !target.in_secure_address_space() {
            return None;
        }
        let refused = effects.target.reads_nt() || effects.writes_guest();
        if target.in_secure_scope() {
            let needs_vcpu =
                effects.state != RunState::Any && effects.writes != [Writes::Breakpoints];
            return (refused || needs_vcpu).then_some(Vtl1Refusal::MemoryView);
        }
        if !refused {
            return None;
        }
        let context_selected = target
            .selected_frame
            .as_ref()
            .is_some_and(|frame| !frame.is_live());
        Some(if context_selected {
            Vtl1Refusal::SelectedContext
        } else {
            Vtl1Refusal::LiveStop
        })
    }
}
