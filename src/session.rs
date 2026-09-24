use std::collections::HashMap;
#[cfg(test)]
use std::env::temp_dir;
use std::fmt::Write as _;
#[cfg(test)]
use std::fs::{remove_file, write};
#[cfg(test)]
use std::mem::take;
#[cfg(test)]
use std::process::id;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use crate::TargetSpec;
use crate::dbg_backend::{
    BackendCapability, BugcheckInfo, DebugBackend, DebugOutputPage, LastEvent, StopEvent,
};
use crate::disasm::ControlFlow;
use crate::error::{Error, Result};
use crate::exception_policy::ExceptionPolicyTable;
use crate::gdb::breakpoints::Breakpoint;
use crate::gdb::{BreakpointManager, RegisterMap};
use crate::guest::{ModuleSymbolLoadReport, ProcessInfo};
use crate::session::lifecycle::InstanceGuard;
use crate::target::{ReloadReport, Target, TargetSelection, ThreadInfo};
#[cfg(test)]
use crate::triage::{TriageBlock, make_triage_dump};
use crate::types::VirtAddr;

/// Trace reload classification (lines prefixed `reload:`), gated on
/// `NTOSEYE_KD_TRACE` like the KD packet trace so one capture correlates both.
/// Off by default; pure output.
macro_rules! reload_trace {
    ($($arg:tt)*) => {
        if trace_enabled() {
            eprintln!("reload: {}", format_args!($($arg)*));
        }
    };
}

pub mod breakpoints;
pub mod context;
pub mod hits;
pub mod inspection;
pub mod lifecycle;
pub mod reload;
pub mod run_control;
pub mod scheduler;
pub mod stepping;
pub mod stops;

/// How [`Session::continue_until_break`] returned: a stop worth surfacing, or a
/// timeout with the VM still running (the caller polls again). Hosts render it.
#[derive(Debug, Clone)]
pub enum ContinueOutcome {
    /// A scoped breakpoint hit (its condition, if any, held).
    Breakpoint {
        id: u32,
        address: u64,
        symbol: Option<String>,
        temporary: bool,
        /// Optional frontend command action attached to the breakpoint.
        action: Option<String>,
        rip: u64,
        /// Runtime condition failure. The stop is surfaced rather than skipped.
        condition_error: Option<String>,
    },
    /// The guest is processing a bugcheck (BSOD). `info` carries the code +
    /// parameters when the backend decoded them from the KD stream; otherwise
    /// read `nt!KiBugCheckData` from memory with
    /// [`crate::bugchecks::current_bugcheck`].
    Bugcheck {
        rip: Option<u64>,
        info: Option<BugcheckInfo>,
    },
    /// A non-breakpoint stop (exception, or a manual interrupt).
    Stopped {
        rip: u64,
        exception_code: Option<u32>,
        first_chance: Option<bool>,
        exception_address: Option<u64>,
    },
    /// A single-step / step-over / step-out completed and landed at `rip`
    /// (no user breakpoint was hit en route).
    Step { rip: u64 },
    /// The guest rebooted (KD stream reset) and debugger state was rebuilt.
    /// Surfaced exactly once per reboot, as early as possible: normally at the
    /// earliest post-reboot stop where the new kernel is discoverable
    /// (`coherent: false`, matching the REPL's early-boot break; process/module
    /// enumeration unavailable, and the later rediscovery completion is silent).
    /// If the rebuild failed at that detection stop, the notification falls back
    /// to the completion instead (`coherent: true`, system already up).
    /// `kernel_base` is the rediscovered `nt` base and `rip` where the stop
    /// landed. All prior addresses are stale and must be re-queried either way.
    TargetReloaded {
        rip: Option<u64>,
        kernel_base: Option<u64>,
        coherent: bool,
    },
    /// The timeout elapsed and the VM is still running; call again to keep
    /// waiting.
    Running,
    /// A non-resuming wait found the VM already halted with nothing pending: it
    /// is parked at `rip` and no new stop can arrive without a resume. Returned
    /// only by [`Session::wait_for_stop_bounded`] (the run-and-wait helpers resume
    /// first, so they never see it); lets a caller distinguish "still stopped
    /// where you left it" from "running" instead of spinning the whole timeout.
    Halted { rip: u64 },
}

/// The readable contents of a NUL-terminated string, without the terminator.
pub struct TerminatedRead {
    /// Readable bytes before the terminator or the first unreadable page.
    pub bytes: Vec<u8>,
    /// The string ran into an unreadable page before its terminator.
    pub unreadable: bool,
}

impl ContinueOutcome {
    /// A hit on `breakpoint` at `rip`.
    fn breakpoint_hit(breakpoint: &Breakpoint, rip: u64, condition_error: Option<String>) -> Self {
        ContinueOutcome::Breakpoint {
            id: breakpoint.id,
            address: breakpoint.address.0,
            symbol: breakpoint.symbol.clone(),
            temporary: breakpoint.temporary,
            action: breakpoint.action.clone(),
            rip,
            condition_error,
        }
    }
}

/// A "where am I" snapshot for the read-only status surface: whether the guest
/// is running, and if halted, the current stop site and inspection scope.
/// `coherent` is false after a reboot until the kernel's loaded-module list
/// exists, so a host knows process/module enumeration is not yet meaningful.
/// Halted there, kernel symbols work and resuming lets boot build the list;
/// running, the host waits rather than reading stale state.
#[derive(Debug, Clone)]
pub struct RunStatus {
    pub running: bool,
    pub current_thread: String,
    /// Current instruction pointer when halted (None while running).
    pub rip: Option<u64>,
    /// Nearest symbol to `rip` when halted.
    pub symbol: Option<String>,
    /// Attached process inspection scope, if any. This is where `dt`, `dq` and
    /// friends read from; it is chosen with `.process` and survives resumes,
    /// so it is not necessarily what the guest is executing.
    pub attached_process: Option<ProcessInfo>,
    /// The process whose page tables the stopped vCPU has loaded (from CR3).
    /// Refreshed at every stop.
    pub stopped_process: Option<ProcessInfo>,
    /// The Windows thread the stopped vCPU is running, walked from its KPRCB
    /// at this stop. Its owner can differ from `stopped_process`: a thread
    /// attached to another address space with `KeStackAttachProcess` runs on
    /// borrowed page tables.
    pub stopped_thread: Option<ThreadInfo>,
    pub coherent: bool,
    /// Rediscovered `nt` base. A host caches it to detect a reboot (the base
    /// changes) and invalidate stale addresses without parsing prose.
    pub kernel_base: u64,
}

/// The fields decoded from a 64-bit Windows `EXCEPTION_RECORD` by `.exr`.
#[derive(Debug, Clone)]
pub struct ExceptionRecord {
    pub code: u32,
    pub flags: u32,
    pub nested: u64,
    pub address: u64,
    pub parameters: Vec<u64>,
}

/// One call-tree node of a [`CallTrace`].
#[derive(Debug, Clone)]
pub struct CallTraceFrame {
    pub name: String,
    pub instructions: usize,
    pub children: Vec<CallTraceFrame>,
}

/// The call tree `wt` collected ([`Session::trace_calls`]), how many
/// instructions it single-stepped, and why it stopped.
#[derive(Debug, Clone)]
pub struct CallTrace {
    pub root: CallTraceFrame,
    pub instructions: usize,
    pub end: CallTraceEnd,
}

/// Why [`Session::trace_calls`] stopped tracing. Anything but `Returned`
/// leaves a partial tree whose open frames are folded into their callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallTraceEnd {
    /// The traced function returned to its caller.
    Returned,
    /// The instruction limit ran out first.
    Limit,
    /// An interrupt request ([`Target::interrupt`]) ended the trace.
    Interrupted,
    /// A step landed on an enabled code breakpoint.
    Breakpoint,
    /// A step or register/instruction read failed.
    Failed(String),
}

/// The halted vCPU's instruction and stack pointers, page-table root, and the
/// control flow of the instruction at the IP: what stepping loops decide on.
#[derive(Debug, Clone, Copy)]
pub struct ControlState {
    pub ip: u64,
    pub sp: u64,
    pub dtb: u64,
    pub flow: ControlFlow,
}

/// Instruction cap for a step-until walk (`pc`/`tc`/`pa`/..., and the SDK's
/// `step(until=)`/`run_to(step=)`) that never finds its target.
pub const STEP_UNTIL_LIMIT: usize = 100_000;

/// The plan for a step-over of the current instruction: either a plain
/// single-step, or run to an address (the instruction after a `call`).
#[derive(Debug, Clone, Copy)]
pub enum StepKind {
    /// The current instruction isn't a call; just single-step it.
    Single,
    /// Run to this address (the return site of a `call`, or a caller frame).
    RunTo(VirtAddr),
}

/// Whether a multi-instruction step follows calls or runs over them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepMode {
    /// Single-step into calls.
    Into,
    /// Run each call to its return site as one step.
    Over,
}

/// Architecture-neutral summary of the instruction at the program counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentInstruction {
    /// Whether the instruction is a call (`call` on AMD64, `bl`/`blr` on ARM64).
    pub is_call: bool,
    /// Address of the following instruction.
    pub next_ip: u64,
}

/// How a stop landed relative to our breakpoints, decided by
/// [`Session::resolve_breakpoint_stop`]. Cases a host shouldn't surface (a
/// wrong-process hit on a shared-page int3, or a false conditional breakpoint)
/// are stepped over and resumed inside the resolver; the host only reacts to the
/// verdict. Shared by the core loop and the REPL so the two can't drift.
#[derive(Debug, Clone)]
pub enum BreakpointStopAction {
    /// A breakpoint the caller should surface (its condition, if any, held).
    /// Enabled breakpoints have already been re-armed.
    Hit {
        breakpoint: Breakpoint,
        /// Runtime condition failure. The stop is surfaced rather than skipped.
        condition_error: Option<String>,
    },
    /// The stop was absorbed: a wrong-process shared-page int3 or a false
    /// conditional breakpoint. It has been stepped over and the VM resumed, so
    /// the caller should keep waiting.
    Resumed,
    /// `rip` is not one of our breakpoints (a genuine exception or manual pause).
    NotBreakpoint,
}

/// Disposition of a data-watch stop after backend status, inspection context,
/// and an optional condition have been handled.
#[derive(Debug, Clone)]
pub enum WatchpointStopAction {
    /// A watchpoint whose condition held or failed to evaluate.
    Hit {
        breakpoint: Breakpoint,
        condition_error: Option<String>,
    },
    /// A false conditional hit was resumed in place.
    Resumed,
    /// The stop was not raised by one of our watchpoints.
    NotBreakpoint,
}

/// Complete core classification of one raw backend stop. Frontends render
/// surfaced stops and execute frontend-owned breakpoint/exception commands;
/// they never repeat backend acknowledgment, reload, scope, or trap handling.
#[derive(Debug, Clone)]
pub enum StopResolution {
    /// Debugger noise or a filtered breakpoint was handled and execution resumed.
    Resumed,
    /// A kernel module load/unload notification was reconciled and resumed.
    ModulesChanged,
    /// A software or hardware breakpoint worth surfacing.
    Breakpoint {
        breakpoint: Box<Breakpoint>,
        event: StopEvent,
        rip: u64,
        condition_error: Option<String>,
    },
    /// The guest entered a bugcheck.
    Bugcheck { event: StopEvent },
    /// The guest rebooted and target state was rebuilt.
    TargetReloaded { event: StopEvent, coherent: bool },
    /// A genuine non-breakpoint stop, including a user interrupt.
    Stopped { event: StopEvent, rip: u64 },
}

/// A backend execution context (vCPU) and the guest code it is currently
/// running. `symbol` is `None` when nothing resolves (render the raw `rip`);
/// `error` is set when the vCPU's register context couldn't be read at all.
#[derive(Debug, Clone)]
pub struct VcpuInfo {
    /// Backend thread/vCPU id (e.g. `p1.1`).
    pub id: String,
    /// Instruction pointer, or `None` if the register context was unreadable.
    pub rip: Option<u64>,
    /// The address space the vCPU is executing in: `"kernel"`, a process name,
    /// or `"unknown"`. Empty when the context could not be determined.
    pub context: String,
    /// Nearest symbol to `rip` (`module!name+0x..`), if one resolved.
    pub symbol: Option<String>,
    /// Why the vCPU context was unavailable, if it was.
    pub error: Option<String>,
}

impl VcpuInfo {
    /// One line naming the vCPU and what it runs: `p1.1 [notepad.exe]
    /// ntdll!NtWaitForSingleObject+0x14`, as client thread lists show it.
    pub fn label(&self) -> String {
        let mut label = self.id.clone();
        if !self.context.is_empty() {
            let _ = write!(label, " [{}]", self.context);
        }
        let _ = match (&self.symbol, self.rip, &self.error) {
            (Some(symbol), _, _) => write!(label, " {symbol}"),
            (None, Some(rip), _) => write!(label, " {rip:#x}"),
            (None, None, Some(error)) => write!(label, " <{error}>"),
            _ => Ok(()),
        };
        label
    }
}

/// `STATUS_BREAKPOINT`, the NTSTATUS an `int3` raises (e.g. `nt!DbgBreakPoint`).
const STATUS_BREAKPOINT: u32 = 0x8000_0003;

/// What [`Session::page_in`] observed once the target came back.
#[derive(Debug, Clone, Copy)]
pub struct PageInReport {
    /// The stop was the worker's completion break, not something else the
    /// target hit while running.
    pub from_worker: bool,
    /// The requested address reads back in the current context.
    pub resident: bool,
}

/// `STATUS_SINGLE_STEP`, the NTSTATUS a trap-flag single-step raises. During a
/// run-control loop (continue / run-to) nobody is intentionally single-stepping;
/// `si` steps via [`stepping::step_one_and_clear_tf`] directly, not the loop,
/// so a single-step that isn't at a user breakpoint is a debugger artifact
/// (see [`stops::stop_is_stray_single_step`]).
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;

/// A session's inspection selection, moved out by [`Session::take_selection`].
pub struct Selection {
    target: TargetSelection,
    current_thread: String,
    parked_windows_thread: Option<VirtAddr>,
}

impl Selection {
    /// Move out the cached register file when it is the current vCPU's live
    /// one (no parked thread, no `.frame`/`.cxr` context), so a scoped
    /// operation on the same vCPU uses it instead of reading the registers
    /// again. Hand it back with [`Self::put_live_registers`].
    pub fn take_live_registers(&mut self) -> Option<HashMap<String, u64>> {
        if self.parked_windows_thread.is_some() {
            return None;
        }
        self.target.take_live_registers()
    }

    /// Return the live register file taken with [`Self::take_live_registers`],
    /// as the scoped operation left it (refreshed, or cleared by a resume).
    pub fn put_live_registers(&mut self, registers: Option<HashMap<String, u64>>) {
        if self.parked_windows_thread.is_none() {
            self.target.put_live_registers(registers);
        }
    }
}

/// The root owner of a live debugging session: the introspection context, the
/// backend that drives the target, and the session state layered on top.
pub struct Session {
    /// Process-unique session id, assigned at construction from a monotonic
    /// counter. Hosts use it as a stable identity token for handles they hand
    /// out (e.g. the Python `Breakpoint`/`StopOutcome` session guard) without
    /// reasoning about pointer reuse across reattach.
    id: usize,
    pub target: Target,
    pub backend: Box<dyn DebugBackend>,
    pub breakpoints: BreakpointManager,
    pub register_map: RegisterMap,
    pub current_thread: String,
    /// Per-exception-code stop policy (`sxe`/`sxd`/`sxn`/`sxi`). Session state
    /// so every host shares one table: the REPL loop applies it (including
    /// its `-c` commands), and the shared [`Self::wait_for_stop_bounded`]
    /// auto-continues the command-free `Continue` policies for the SDK/MCP.
    pub exception_policies: ExceptionPolicyTable,
    /// ETHREAD selected for stack-only inspection while the backend remains on
    /// `current_thread`. Its register file does not exist as a coherent snapshot.
    parked_windows_thread: Option<VirtAddr>,
    /// Whether a guest reload is mid-flight with the loaded-module list not yet
    /// available (very early boot). Carried across `continue_until_break` calls
    /// so the post-reboot KD-reconnect dance runs to completion; when the list
    /// appears, [`Self::try_complete_pending_reload`] finishes rediscovery and
    /// stops the backend's reconnect-assist poking. Seeded at attach, which
    /// may land mid-boot; hosts read it through [`Self::kernel_coherent`].
    reload_module_list_pending: bool,
    /// Address of the automatic `nt!KeBugCheckEx` breakpoint, once armed,
    /// and the instruction bytes it displaced. Only backends that cannot
    /// report a bugcheck themselves get one; see [`Self::arm_bugcheck_trap`].
    /// The bytes are kept for the same reason the breakpoint manager keeps
    /// its own: a read of that address must show the guest's code, not our
    /// trap.
    bugcheck_trap: Option<VirtAddr>,
    bugcheck_trap_original: Vec<u8>,
    /// Whether a detected reload has not yet been surfaced to the host: the
    /// guest-state rebuild failed at the detection stop, so no
    /// [`ContinueOutcome::TargetReloaded`] went out. While set, the eventual
    /// rediscovery completion is surfaced in its place (the fallback "the guest
    /// rebooted" notification); once a reload has been surfaced, the completion
    /// is silent. Guarantees exactly one reload notification per reboot.
    reload_surface_pending: bool,
    /// A real execution stop the background `service_idle` caught and processed
    /// while the host was idle (a breakpoint/non-bp stop/bugcheck the host didn't
    /// actively `wait_for_stop` for). The VM is halted at it; the next
    /// `wait_for_stop` returns this as the proper event instead of a bare
    /// "halted", and `resume` clears it. `None` whenever the host is up to date.
    parked_stop: Option<ContinueOutcome>,
    /// The stop the target is halted at, as it was surfaced: set by every
    /// visible classification and every host-facing run/step result, cleared
    /// when the target moves. Unlike `parked_stop` it is not consumed by
    /// reading it, so any host can ask "where are we stopped, and why".
    current_stop: Option<ContinueOutcome>,
    /// The most recent per-stop module refresh report, retained so the REPL can
    /// render its existing module-symbol summary after the core reconciles
    /// breakpoints. Other hosts simply leave it unconsumed.
    module_refresh_report: Option<ModuleSymbolLoadReport>,
    /// Diagnostics the core raised while acting on the host's behalf (a
    /// breakpoint that failed to re-arm at a stop, host memory that stopped
    /// matching the guest after a reload). Core never prints; the host drains
    /// these at its next output boundary via [`Self::take_notices`].
    notices: Vec<String>,
    /// The symbol store's load generation as of the last deferred-breakpoint
    /// reconcile, so a load this session did not perform itself (a background
    /// fetch, a lazy frame load, a process attach) still re-resolves `bu`
    /// specifications at the next opportunity.
    symbols_reconciled_at: u64,
    /// A module load/unload was absorbed while running (breakpoints already
    /// reconciled, target resumed). Reported by the next
    /// [`Self::refresh_modules_on_stop`] so hosts refresh module-derived state
    /// without halting the target on every load.
    unreported_module_change: bool,
    /// Most recently observed backend stop and the disposition used when it was
    /// subsequently continued.
    pub last_event: Option<LastEvent>,
    /// Per-target single-instance lock, held for the session's lifetime so a
    /// second ntoseye can't attach to the same backend resource. `Some` via
    /// [`Self::connect`] (every host's attach path), `None` via the unguarded
    /// [`Self::new`].
    _instance_guard: Option<InstanceGuard>,
}

impl Session {
    /// The backend's capability matrix (what the current transport supports), so
    /// a host can report unsupported operations up front instead of by failure.
    pub fn capabilities(&self) -> Vec<BackendCapability> {
        self.backend.capabilities()
    }

    /// Read captured guest debug output (DbgPrint) at or after `since_seq`.
    /// Snapshot+cursor: pass the previous page's `next_seq` to poll only new
    /// lines. Empty on backends without a native debug stream (gdb/memory); see
    /// [`DebugCapability::DebugOutput`](crate::dbg_backend::DebugCapability::DebugOutput).
    pub fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.backend.read_debug_output(since_seq)
    }

    /// This session's process-unique identity (see the `id` field).
    pub fn id(&self) -> usize {
        self.id
    }

    /// Drain the diagnostics core and backend raised since the last drain, in
    /// the order they happened. Hosts call this at each output boundary.
    pub fn take_notices(&mut self) -> Vec<String> {
        let mut notices = std::mem::take(&mut self.target.notices);
        notices.extend(self.target.symbols.take_notices());
        notices.append(&mut self.notices);
        notices.extend(self.backend.take_notices());
        notices
    }
}

/// The result of `Session::perform_target_reload`: the guest-reload outcome plus the
/// resolved kernel-base hint the reload was guided by. `report` is `Ok` when the
/// new kernel image was rediscovered (possibly before its module list is up;
/// check [`reload::reload_report_has_loaded_module_list`]) and `Err` when it
/// isn't discoverable yet (very early boot). `hint` is the base used (from the
/// stop event, else queried from the backend), which the REPL rebases symbols
/// against while rediscovery is pending.
pub struct TargetReloadOutcome {
    pub report: Result<ReloadReport>,
    pub hint: Option<VirtAddr>,
    /// Symbolic breakpoint re-resolution failed after the target itself reloaded.
    pub breakpoint_error: Option<Error>,
}

/// Open a session over a synthetic triage dump whose only memory region is
/// `memory`, mapped at `base`.
#[cfg(test)]
pub fn session_over_memory(base: u64, memory: &[u8]) -> Session {
    let block = TriageBlock {
        address: base,
        offset: 0,
        size: memory.len() as u32,
    };
    let dump = make_triage_dump(&[block], &[(base, memory)]);
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = temp_dir().join(format!("ntoseye-session-{sequence}-{}.dmp", id(),));
    write(&path, dump).unwrap();
    let session = Session::open(&TargetSpec::Dump(path.clone())).unwrap();
    remove_file(path).unwrap();
    session
}

#[cfg(test)]
pub mod tests;
