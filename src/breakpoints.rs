//! The backend-neutral breakpoint model every frontend drives: breakpoint
//! identities and configuration, and the manager that installs them through
//! a [`DebugBackend`](crate::dbg_backend::DebugBackend).

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::dbg_backend::HwBreakpointAccess;
use crate::expr::Expr;
use crate::types::{Dtb, VirtAddr};

mod config;
mod hardware;
mod hits;
mod install;
mod manager;
mod resolve;
mod spec;
#[cfg(test)]
mod test_backend;

use install::BreakpointBackend;

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

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: u32,
    /// Last resolved address. Use [`Self::resolved_address`] when deciding
    /// whether a backend breakpoint is currently installed.
    pub address: VirtAddr,
    pub enabled: bool,
    /// Display name for the current resolution.
    pub symbol: Option<String>,
    /// Original deferred specification (`bu`/`bm`), kept across re-resolution.
    pub spec: Option<BreakpointSpec>,
    pub resolved: bool,
    pub scope: BreakpointScope,
    /// Which Windows thread may surface a hit (`/t`), if restricted.
    pub thread: Option<ThreadScope>,
    /// Which processor may surface a hit (`/c`), if restricted.
    pub processor: Option<u16>,
    /// Whether `scope` was inferred from the resolved address and the process
    /// selected when this breakpoint was created. Explicit `/p` scopes remain
    /// fixed across symbol re-resolution.
    automatic_scope: bool,
    pub condition: Option<String>,
    pub condition_expr: Option<Arc<Expr>>,
    /// Requested hit number. Zero and one both mean "break on the first hit".
    pub pass_count: u64,
    pub hit_count: u64,
    pub remaining_pass_count: u64,
    pub one_shot: bool,
    pub action: Option<String>,
    pub temporary: bool,
    /// Transport-specific breakpoint state; hosts use [`Self::watchpoint`] for
    /// the semantic data-watch metadata.
    pub hardware: Option<HardwareBreakpoint>,
    backend: BreakpointBackend,
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
    /// Resolve a symbol breakpoint past the function's prologue. See
    /// [`BreakpointSpec::Symbol`].
    pub skip_prologue: bool,
}

#[derive(Default)]
pub struct BreakpointManager {
    breakpoints: HashMap<u32, Breakpoint>,
    one_shot_hits: HashSet<u32>,
    next_id: u32,
}

#[derive(Debug)]
pub enum BreakpointHitResult {
    /// Breakpoint hit
    Hit(Breakpoint),
    /// Program counter does not match any breakpoint.
    NotBreakpoint,
}
