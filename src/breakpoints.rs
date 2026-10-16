//! The backend-neutral breakpoint model every frontend drives: breakpoint
//! identities and configuration, and the manager that installs them through
//! a [`DebugBackend`](crate::dbg_backend::DebugBackend).

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::dbg_backend::{HwBreakpointAccess, WatchpointAccess};
use crate::expr::Expr;
use crate::guest::hypercalls::tlfs_hypercall;
use crate::guest::vm_exits::ExitFilter;
use crate::types::{Dtb, VirtAddr};
use ntoseye_macros::record;

mod config;
mod hardware;
mod hits;
mod install;
mod journal;
mod manager;
mod resolve;
mod spec;
#[cfg(test)]
mod test_backend;

use install::BreakpointBackend;
pub use install::{breakpoint_opcode, lift_target_site, plant_target_site};
pub use journal::{Repair, SiteJournal};

/// A hardware (debug-register) breakpoint's parameters: the access it traps on,
/// the watch width in bytes, and which physical debug slot it occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareBreakpoint {
    pub access: HwBreakpointAccess,
    pub len: u8,
    pub slot: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointSpec {
    Symbol {
        name: String,
        /// Resolve past the function's prologue, so the incoming arguments are
        /// already stored where the PDB says they live. Set by hosts whose
        /// clients expect a function breakpoint to expose arguments (DAP);
        /// WinDbg's `bu <symbol>` breaks at the symbol itself and leaves this
        /// clear.
        skip_prologue: bool,
    },
    Source {
        raw: String,
        file: String,
        line: u32,
        address_index: usize,
    },
}

/// A code breakpoint or data watchpoint (`bl`), as the debugger keeps it.
#[record(impl)]
pub struct BreakpointInfo {
    pub id: u32,
    /// Identity the manager never reuses, unlike `id`, which is handed out
    /// again once the table empties. Handles that outlive their breakpoint
    /// compare it to tell a new breakpoint with the same id from theirs.
    #[record(skip)]
    pub serial: u64,
    /// Last resolved address. Use [`Self::resolved_address`] when deciding
    /// whether a backend breakpoint is currently installed.
    #[record(skip)]
    pub address: VirtAddr,
    pub enabled: bool,
    /// The display name of the current resolution.
    pub symbol: Option<String>,
    /// Original deferred specification (`bu`/`bm`), kept across re-resolution.
    #[record(skip)]
    pub spec: Option<BreakpointSpec>,
    /// Whether the breakpoint resolved to an address. Use it to tell a
    /// deferred breakpoint from a disabled one.
    pub resolved: bool,
    #[record(skip)]
    pub scope: BreakpointScope,
    /// Which Windows thread may surface a hit (`/t`), if restricted.
    #[record(skip)]
    pub thread: Option<ThreadScope>,
    /// The only processor that can report a hit (`/c`). None if there is no
    /// processor restriction.
    pub processor: Option<u16>,
    /// Lowest stack pointer a hit may have, if restricted: a step's run-to
    /// breakpoint (see [`StepFrame`]).
    #[record(skip)]
    pub min_stack_pointer: Option<u64>,
    /// The hypercall a hit must be handling, and from which caller, for a
    /// hypercall breakpoint (`!hvbp`). None for any other breakpoint.
    pub hypercall: Option<HypercallFilter>,
    /// The VM exit a hit must be handling, and from which caller, for a
    /// VM-exit breakpoint (`!hvexit`). None for any other breakpoint.
    pub vm_exit: Option<ExitFilter>,
    /// The guest partition of the Windows hypervisor whose VPs a hit must be
    /// on, for a breakpoint set in its view (`.partition`). None for the
    /// target's own breakpoints.
    pub partition: Option<PartitionFilter>,
    /// Whether `scope` was inferred from the resolved address and the process
    /// selected when this breakpoint was created. Explicit `/p` scopes remain
    /// fixed across symbol re-resolution.
    #[record(skip)]
    automatic_scope: bool,
    /// The condition expression that a hit must satisfy.
    pub condition: Option<String>,
    #[record(skip)]
    pub condition_expr: Option<Arc<Expr>>,
    /// The requested hit number. Both 0 and 1 break on the first hit.
    pub pass_count: u64,
    pub hit_count: u64,
    /// The number of hits that remain before the breakpoint breaks.
    pub remaining_pass_count: u64,
    /// Whether ntoseye removes the breakpoint after its first break.
    pub one_shot: bool,
    /// The commands that run when the breakpoint breaks.
    pub action: Option<String>,
    /// Whether this is a temporary run-to breakpoint.
    pub temporary: bool,
    /// Set with `bp /a` or `bu /a`: without confirming that an instruction
    /// starts at the address.
    pub unchecked: bool,
    /// Transport-specific breakpoint state; hosts use [`Self::watchpoint`] for
    /// the semantic data-watch metadata.
    #[record(skip)]
    pub hardware: Option<HardwareBreakpoint>,
    #[record(skip)]
    backend: BreakpointBackend,
}

#[record]
impl BreakpointInfo {
    /// The resolved address; None while a symbolic or source breakpoint is
    /// deferred.
    #[record(getter, rename = "address")]
    pub fn resolved_address(&self) -> Option<VirtAddr> {
        self.resolved.then_some(self.address)
    }

    /// Whether a symbolic or source specification waits for resolution.
    #[record(getter)]
    pub fn deferred(&self) -> bool {
        self.spec.is_some() && !self.resolved
    }

    /// The symbolic or source specification (`bu`/`bm`), which ntoseye
    /// keeps when it resolves the breakpoint again.
    #[record(getter, rename = "specification")]
    pub fn specification_text(&self) -> Option<String> {
        self.specification().map(str::to_string)
    }

    /// `global`, or the process that the breakpoint is limited to
    /// (`name (pid)`).
    #[record(getter, rename = "scope")]
    pub fn scope_name(&self) -> String {
        self.scope.label()
    }

    /// The only thread that can report a hit (`/t`: `tid N` or
    /// `ethread 0x...`). None if there is no thread restriction.
    #[record(getter, rename = "thread")]
    pub fn thread_name(&self) -> Option<String> {
        self.thread.as_ref().map(ThreadScope::label)
    }

    /// `write` or `read_write` for a data watchpoint. None for a code
    /// breakpoint.
    #[record(getter)]
    pub fn watch_access(&self) -> Option<WatchpointAccess> {
        self.watchpoint().map(|(access, _)| access)
    }

    /// The watched width in bytes. None for a code breakpoint.
    #[record(getter)]
    pub fn watch_length(&self) -> Option<u8> {
        self.watchpoint().map(|(_, length)| length)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointScope {
    Kernel,
    Process { pid: u64, dtb: Dtb, name: String },
}

/// A breakpoint's thread filter (`/t`).
///
/// No target can program this: a software site is one byte in a page every
/// thread executing that code shares, and a debug register belongs to a
/// processor that any thread may be scheduled on. The trap fires for
/// whoever runs it, so the filter is applied to the stopped thread when the
/// hit arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadScope {
    pub ethread: VirtAddr,
    pub tid: Option<u64>,
}

/// The execution a step's run-to breakpoint (`p` over a call, `gu`) belongs
/// to. A hit by another thread, or by the same thread with its stack below
/// `min_stack_pointer` (a deeper call of the same code), is stepped past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepFrame {
    pub thread: ThreadScope,
    pub min_stack_pointer: Option<u64>,
}

/// A hypercall breakpoint's filter (`!hvbp`): the call code a hit's caller
/// made, and the partition, and VP index in it, the caller must be.
///
/// The breakpoint is on the call's handler, which the hypervisor runs for
/// every caller and, for a handler several codes share, for each of them.
/// Like the thread filter, the caller is known only once the hit arrives:
/// the VP whose exit the processor handles, and the code in its RCX.
#[record(impl)]
#[derive(Copy, PartialEq, Eq)]
pub struct HypercallFilter {
    /// The call code: the low 16 bits of the caller's RCX.
    #[record(hex)]
    pub code: u16,
    /// The caller's partition ID. None for any caller.
    pub partition: Option<u64>,
    /// The caller's VP index in `partition`. None for any VP. Set only with
    /// `partition`: a VP index names a VP of one partition.
    pub vp: Option<u32>,
}

#[record]
impl HypercallFilter {
    /// The TLFS name, or None for a code that the TLFS does not list.
    #[record(getter)]
    pub fn name(&self) -> Option<&'static str> {
        tlfs_hypercall(self.code).map(|(name, _)| name)
    }
}

/// A partition breakpoint's filter: the guest partition of the Windows
/// hypervisor (a Windows Sandbox, a Hyper-V VM) a hit must be on, and the VP
/// index in it, if restricted.
///
/// The breakpoint is a debug register of the target's processors, which
/// traps whatever code a processor runs at its address: the partition's, or
/// another partition's or the target's own mapped there. Which VP ran it is
/// known only once the hit arrives, from the processor's current VP.
#[record]
#[derive(Copy, PartialEq, Eq)]
pub struct PartitionFilter {
    /// The partition ID.
    #[record(rename = "id")]
    pub partition: u64,
    /// The VP index a hit must be on (`/c` in the view). None for any of
    /// the partition's VPs.
    pub vp: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointHitDisposition {
    SkipPass,
    Evaluate,
}

#[derive(Debug, Clone, Default)]
pub struct BreakpointConfig {
    pub condition: Option<String>,
    pub condition_expr: Option<Arc<Expr>>,
    pub pass_count: u64,
    pub one_shot: bool,
    pub action: Option<String>,
    pub scope: Option<BreakpointScope>,
    /// Restrict hits to one Windows thread (`/t`). Independent of `scope`:
    /// the address space decides where a site is written, the thread only
    /// decides which hits are surfaced.
    pub thread: Option<ThreadScope>,
    /// Restrict hits to the processor a stop is reported on (`/c`). Filtered
    /// the same way and for the same reason as `thread`.
    pub processor: Option<u16>,
    /// Restrict hits to a hypercall and its caller. See [`HypercallFilter`].
    pub hypercall: Option<HypercallFilter>,
    /// Restrict hits to a VM-exit reason and its caller. See [`ExitFilter`].
    pub vm_exit: Option<ExitFilter>,
    /// Make this a guest partition's breakpoint. See [`PartitionFilter`].
    pub partition: Option<PartitionFilter>,
    /// Resolve a symbol breakpoint past the function's prologue. See
    /// [`BreakpointSpec::Symbol`].
    pub skip_prologue: bool,
    /// The address was not confirmed to start an instruction (`bp /a`,
    /// `bu /a`). Kept so `.bpcmds` can set the breakpoint again.
    pub unchecked: bool,
}

#[derive(Default)]
pub struct BreakpointManager {
    breakpoints: HashMap<u32, BreakpointInfo>,
    one_shot_hits: HashSet<u32>,
    next_id: u32,
    /// Executions interrupted on a breakpoint's site while running past it,
    /// as `(id, stack pointer)`: returning to the site, they hit it again,
    /// and that hit is the one already reported.
    interrupted_hits: Vec<(u32, u64)>,
}

#[derive(Debug)]
pub enum BreakpointHitResult {
    /// Breakpoint hit
    Hit(BreakpointInfo),
    /// Program counter does not match any breakpoint.
    NotBreakpoint,
}

/// The commands that set the current breakpoints again (`.bpcmds`).
#[record]
pub struct BreakpointCommands {
    /// One command line per breakpoint, in ID order.
    pub commands: Vec<String>,
}

/// A breakpoint ID as a command names it (`bpc <id>`): a decimal number,
/// whatever the radix, as `bl` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakpointId(pub u32);
