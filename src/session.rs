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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic};
use single_instance::SingleInstance;

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::bugchecks::{looks_like_kernel_pointer, plausible_bugcheck_code};
use crate::dbg_backend::{
    BackendCapability, BugcheckInfo, ContinueDisposition, DebugBackend, DebugCapability,
    DebugOutputPage, HW_BREAKPOINT_SLOTS, HwBreakpointAccess, LastEvent, StopEvent,
    WatchpointAccess,
};
use crate::disasm::{
    ControlFlow, DisasmRow, classify, decode_preceding, decode_rows, decode_rows_arm64,
    disasm_formatter, max_instruction_bytes,
};
use crate::dmp::DmpBackend;
use crate::error::{Error, Result};
use crate::exception_policy::{ExceptionPolicyAction, ExceptionPolicyTable};
use crate::expr::Expr;
use crate::gdb::breakpoints::{Breakpoint, BreakpointConfig, BreakpointScope, ThreadScope};
use crate::gdb::{
    BreakpointHitDisposition, BreakpointHitResult, BreakpointManager, GdbClient, RegisterMap,
};
use crate::guest::{ModuleSymbolLoadReport, ProcessInfo};
use crate::kd::{KdBackend, KdMemorySource, context, context_arm64, hwbp, kd_files, trace_enabled};
use crate::memory::{DTB_IDENTITY, PAGE_SIZE, read_page_chunks};
use crate::memory_backend::MemoryBackend;
use crate::phys::PhysMem;
use crate::target::{ReloadReport, SelectedFrame, Target, TargetSelection, ThreadInfo};
#[cfg(test)]
use crate::triage::{TriageBlock, make_triage_dump};
use crate::types::{Arch, VirtAddr};
use crate::unwind::{
    RecoveredStackTrace, StackTrace, ThreadStackTrace, build_parked_thread_recovered_stack,
    build_parked_thread_stack, build_stacktrace, build_stacktrace_with_context,
    build_stacktrace_with_register_values, format_symbol, function_range, preferred_code_dtb,
    resolve_thread_trace_context,
};
use crate::{Backend, TargetSpec};
#[cfg(test)]
use std::sync::atomic::AtomicU64;

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
    /// only by [`Self::wait_for_stop_bounded`] (the run-and-wait helpers resume
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

/// How [`Session::classify_reload_stop`] classified a freshly observed stop:
/// real stop, reboot artifact, or transport noise.
/// [`Session::classify_stop_event`] turns the reboot cases into
/// [`StopResolution::TargetReloaded`] and resumes past the noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadDisposition {
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

/// The plan for a step-over of the current instruction: either a plain
/// single-step, or run to an address (the instruction after a `call`).
#[derive(Debug, Clone, Copy)]
pub enum StepKind {
    /// The current instruction isn't a call; just single-step it.
    Single,
    /// Run to this address (the return site of a `call`, or a caller frame).
    RunTo(VirtAddr),
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

fn update_target_context_from_registers(
    target: &mut Target,
    register_map: &RegisterMap,
    registers: Result<Vec<u8>>,
) {
    target.selected_frame = None;
    let Ok(registers) = registers else {
        target.registers = None;
        target.clear_context_dtb_override();
        return;
    };
    target.registers = Some(register_map.to_hashmap(&registers));
    match register_map.read_u64(target.arch().dtb_register(), &registers) {
        // For triage dumps all modules are loaded with DTB_IDENTITY and
        // memory reads use identity mapping, so the context DTB from the
        // CONTEXT
        // record is meaningless.  Setting it here would cause a DTB
        // mismatch that makes symbol lookup, type resolution, and eval
        // fail.
        Ok(dtb) if dtb != 0 && target.guest.is_some() && target.kernel_dtb() != DTB_IDENTITY => {
            target.set_context_dtb_override(dtb)
        }
        _ => target.clear_context_dtb_override(),
    }
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

/// The low bits of a CR3/DTB that select the page-directory base physical
/// frame (PCID and reserved/canonical bits masked out), for comparing the
/// address space a vCPU runs in against a process's DTB.
/// How often the run-control poll loop wakes to check for a stop.
const CONTINUE_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How many noise stops [`Session::interrupt`] resumes past before surfacing
/// whatever the target is doing.
const INTERRUPT_MAX_RESUMES: usize = 8;

/// How long [`Session::halt_for_exit`] gives an already-pending stop to land
/// before breaking in.
const EXIT_STOP_POLL: Duration = Duration::from_millis(200);

/// How long a background `service_idle` pass spends absorbing caught stops before
/// returning to the actor's job queue. Small so a real tool call is never held off
/// for long; one buffered stop is drained immediately regardless, this only bounds
/// the brief wait for any follow-on hit in a burst.
const SERVICE_IDLE_BUDGET: Duration = Duration::from_millis(5);

/// `STATUS_BREAKPOINT`, the NTSTATUS an `int3` raises (e.g. `nt!DbgBreakPoint`).
const STATUS_BREAKPOINT: u32 = 0x8000_0003;

/// `DBG_STATUS_WORKER`, the status the kernel's debugger worker passes to
/// `DbgBreakPointWithStatus` when it has finished a [`Session::page_in`].
const DBG_STATUS_WORKER: u64 = 7;

/// How long [`Session::page_in`] lets the target run before giving up on the
/// worker. The work is a DPC and a work item behind one resume; a second is
/// already generous, and the guest may be busy.
const PAGE_IN_TIMEOUT: Duration = Duration::from_secs(10);

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
/// `si` steps via [`step_one_and_clear_tf`] directly, not the loop, so a
/// single-step that isn't at a user breakpoint is a debugger artifact (see
/// [`stop_is_stray_single_step`]).
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;

/// [`Error::TargetRunning`] payload for the live register file.
const REGISTERS_NEED_HALT: &str = "Registers belong to the halted context.";

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

fn prepare_backend_after_cleanup(
    backend: &mut dyn DebugBackend,
    cleanup: Result<()>,
) -> Result<()> {
    match cleanup {
        Ok(()) => backend.prepare_for_exit(true),
        Err(cleanup_error) => match backend.prepare_for_exit(false) {
            Ok(()) => Err(cleanup_error),
            Err(teardown_error) => Err(Error::DebugInfo(format!(
                "{cleanup_error}; backend teardown also failed: {teardown_error}"
            ))),
        },
    }
}

impl Session {
    /// Attach per `spec`: open a dump, or connect the chosen live backend.
    /// The one construction path shared by the CLI, MCP, and Python hosts, so
    /// backend selection, endpoint defaults, and instance locking cannot
    /// drift between them.
    ///
    /// kd/kdnet/gdb take a per-target instance lock before building the
    /// backend, so a second attach against the same resource fails fast rather
    /// than racing on the handshake; dumps and passive memory are read-only
    /// and coexist with anything.
    pub fn open(spec: &TargetSpec) -> Result<Self> {
        Self::open_with_progress(spec, &mut |_| {})
    }

    /// [`Self::open`], reporting connection progress (transport banners, the
    /// KD wait for a target, the memory-source decision) through `progress`
    /// one line at a time. Only live KD attaches report anything.
    pub fn open_with_progress(spec: &TargetSpec, progress: &mut dyn FnMut(&str)) -> Result<Self> {
        spec.validate().map_err(Error::DebugInfo)?;
        match spec {
            TargetSpec::Dump(path) => {
                let phys = Arc::new(PhysMem::dmp(path)?);
                let info = phys
                    .dmp_info()
                    .expect("dmp_info must be Some for DMP backend")
                    .clone();
                Self::connect(phys, None, || Ok(Box::new(DmpBackend::new(&info))))
            }
            TargetSpec::Live {
                backend: backend @ (Backend::Kd | Backend::KdNet),
                kdnet_key,
                memory_source,
                ..
            } => {
                let endpoint = spec.endpoint().expect("KD/KDNET always have an endpoint");
                Self::connect_kd(
                    endpoint,
                    *memory_source,
                    progress,
                    |progress| match backend {
                        Backend::Kd => KdBackend::connect(endpoint, progress),
                        Backend::KdNet => {
                            let key = kdnet_key.as_deref().expect("validated above");
                            KdBackend::connect_net(endpoint, key, progress)
                        }
                        Backend::Gdb | Backend::Memory => unreachable!("matched KD above"),
                    },
                )
            }
            TargetSpec::Live { backend, .. } => {
                let phys = Arc::new(PhysMem::live()?);
                let endpoint = spec.endpoint();
                Self::connect(phys, endpoint, || {
                    Ok(match backend {
                        Backend::Gdb => Box::new(GdbClient::connect(
                            endpoint.expect("gdb always has an endpoint"),
                        )?),
                        Backend::Memory => Box::new(MemoryBackend::new()),
                        Backend::Kd | Backend::KdNet => unreachable!("matched above"),
                    })
                })
            }
        }
    }

    /// Acquire the single-instance lock for `target` (`None` for read-only
    /// backends that are safe to share), then connect a backend via
    /// `make_backend` and build the owned session.
    pub fn connect<F>(phys: Arc<PhysMem>, target: Option<&str>, make_backend: F) -> Result<Self>
    where
        F: FnOnce() -> Result<Box<dyn DebugBackend>>,
    {
        let guard = target.map(acquire_instance_guard).transpose()?;
        let backend = make_backend()?;
        let mut session = Self::new(phys, backend)?;
        session._instance_guard = guard;
        Ok(session)
    }

    /// Connect KD/KDNET, select a validated memory source, and build the
    /// session. `Auto` prefers matching host VM memory and safely falls back to
    /// target-mediated KD physical-memory requests. Connection progress and
    /// the memory-source decision are reported through `progress`.
    pub fn connect_kd<F>(
        resource: &str,
        memory_source: KdMemorySource,
        progress: &mut dyn FnMut(&str),
        make_backend: F,
    ) -> Result<Self>
    where
        F: FnOnce(&mut dyn FnMut(&str)) -> Result<KdBackend>,
    {
        let guard = Some(acquire_instance_guard(resource)?);
        let mut backend = make_backend(progress)?;
        let hints = backend.target_hints()?;

        let host_phys: Option<PhysMem> = match memory_source {
            KdMemorySource::Kd => None,
            KdMemorySource::Host => {
                let phys = PhysMem::live().map_err(|error| {
                    Error::Kd(format!("host memory source unavailable: {error}"))
                })?;
                backend.validate_host_memory(&phys, hints)?;
                Some(phys)
            }
            KdMemorySource::Auto => match PhysMem::live() {
                Ok(phys) => match backend.validate_host_memory(&phys, hints) {
                    Ok(()) => Some(phys),
                    Err(error) => {
                        progress(&format!(
                            "{}: host memory rejected ({error}); falling back to KD memory",
                            backend.name()
                        ));
                        backend.note_host_memory_unavailable();
                        None
                    }
                },
                Err(error) => {
                    progress(&format!(
                        "{}: host memory unavailable ({error}); falling back to KD memory",
                        backend.name()
                    ));
                    backend.note_host_memory_unavailable();
                    None
                }
            },
        };

        let backend_name = backend.name();
        let (target, backend): (Target, Box<dyn DebugBackend>) = match host_phys {
            Some(host) => {
                progress(&format!(
                    "{backend_name}: memory source host (validated VM-process memory)"
                ));
                // Host reads can bypass KD, but writes must preserve guest protection,
                // copy-on-write, and residency handling.
                let (backend, memory) = backend.into_remote_memory();
                let phys = Arc::new(host.with_mediated_writes(memory));
                (
                    Target::with_remote_phys(
                        phys,
                        hints.kernel_dtb,
                        hints.kernel_base,
                        hints.arch,
                    )?,
                    Box::new(backend),
                )
            }
            None => {
                let (backend, memory) = backend.into_remote_memory();
                progress(&kd_memory_source_notice(backend_name));
                let phys = Arc::new(PhysMem::remote(memory));
                (
                    Target::with_remote_phys(
                        phys,
                        hints.kernel_dtb,
                        hints.kernel_base,
                        hints.arch,
                    )?,
                    Box::new(backend),
                )
            }
        };
        let mut session = Self::new_with_target(target, backend)?;
        session._instance_guard = guard;
        Ok(session)
    }

    /// Build a session around an already-connected backend and physical-memory
    /// source. Hosts normally use [`Self::connect`] or [`Self::connect_kd`].
    pub fn new(phys: Arc<PhysMem>, backend: Box<dyn DebugBackend>) -> Result<Self> {
        let target = Target::with_phys(phys)?;
        Self::new_with_target(target, backend)
    }

    fn new_with_target(mut target: Target, mut backend: Box<dyn DebugBackend>) -> Result<Self> {
        let debugger_data_hint = backend.target_debugger_data_hint().ok().flatten();
        target.refresh_debugger_data(debugger_data_hint);
        backend.initialize_from_target(&target);
        // ARM64 register snapshots expose TTBR1 via the synthetic `cr3` slot;
        // hand the resolved kernel root to the backend so it can fill it.
        backend.set_kernel_dtb(target.kernel_dtb());
        let register_map = backend.register_map().clone();

        // Seed the selected thread from the backend when it exposes register
        // context; otherwise default to the first processor.
        let has_register_context = backend
            .capabilities()
            .iter()
            .any(|c| c.capability == DebugCapability::ReadRegisters && c.supported);
        let current_thread = if has_register_context {
            backend
                .stopped_thread_id()
                .unwrap_or_else(|_| "1".to_string())
        } else {
            "1".to_string()
        };

        static NEXT_SESSION_ID: AtomicUsize = AtomicUsize::new(1);

        // An empty module list means the attach landed mid-boot, before
        // rediscovery could complete.
        let reload_module_list_pending = target
            .startup_message_data()
            .is_ok_and(|startup| startup.loaded_module_list.is_zero());
        let mut session = Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            target,
            backend,
            breakpoints: BreakpointManager::new(),
            register_map,
            current_thread,
            exception_policies: ExceptionPolicyTable::default(),
            parked_windows_thread: None,
            reload_module_list_pending,
            bugcheck_trap: None,
            bugcheck_trap_original: Vec::new(),
            reload_surface_pending: false,
            parked_stop: None,
            current_stop: None,
            module_refresh_report: None,
            notices: Vec::new(),
            symbols_reconciled_at: 0,
            unreported_module_change: false,
            last_event: None,
            _instance_guard: None,
        };

        // Populate target.registers so register names resolve in expressions
        // (important for dump sessions where no stop event fires).
        if has_register_context {
            session.refresh_context_for_current_thread();
        }

        // Arm here rather than at the first resume, so the operator reads
        // about it in the attach output alongside the capability warning that
        // explains why it is needed, instead of beside an unrelated stop.
        session.arm_bugcheck_trap();

        // A crash dump sits at its bugcheck: that is the stop it is halted at.
        if let Some(dump) = session.target.phys.dmp_info()
            && plausible_bugcheck_code(u64::from(dump.bug_check_code))
        {
            let info = BugcheckInfo {
                code: dump.bug_check_code,
                parameters: dump.bug_check_parameters,
                driver: None,
            };
            session.current_stop = Some(ContinueOutcome::Bugcheck {
                rip: Some(session.current_rip()).filter(|&rip| rip != 0),
                info: Some(info),
            });
        }

        Ok(session)
    }

    /// Single-step one instruction on the currently selected thread. If RIP sits
    /// on one of our breakpoints, do the disable/step/enable dance; otherwise
    /// plain step + trap-flag clear. Afterward re-arm enabled breakpoints (the
    /// stub can drop non-hit ones on a stop) and re-select the landed-on thread.
    /// The full "step one instruction", shared by the REPL (`si`) and the SDK.
    pub fn step(&mut self) -> Result<u64> {
        self.require_live_register_context()?;
        self.target.selected_frame = None;
        // Advancing the VM spends any stop `service_idle` parked, so drop it (the
        // other advance paths clear it via `resume`; a bare single-step doesn't).
        self.parked_stop = None;
        self.current_stop = None;
        self.backend.set_current_thread(&self.current_thread)?;
        if !step_over_current_breakpoint(
            self.backend.as_mut(),
            &self.register_map,
            &self.target,
            &mut self.breakpoints,
        )? {
            step_one_and_clear_tf(self.backend.as_mut(), &self.register_map)?;
        }
        for id in self.breakpoints.one_shot_hit_ids() {
            self.breakpoints
                .remove(self.backend.as_mut(), &self.target, id)?;
        }

        // Re-arm breakpoints the stub may have lost when the VM stopped, then
        // adopt whatever thread we ended up on.
        if let Err(error) = self
            .breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)
        {
            self.notices.push(format!(
                "failed to re-arm breakpoints after the step: {error}"
            ));
        }
        if let Ok(tid) = self.backend.stopped_thread_id() {
            self.current_thread = tid;
        }
        self.refresh_context_for_current_thread();
        let rip = self.current_rip();
        self.current_stop = Some(ContinueOutcome::Step { rip });
        Ok(rip)
    }

    /// Select `id` as the current inspection thread (e.g. a vCPU id), so
    /// registers/backtrace/step operate on it. Validates the id against the
    /// backend. Shared by the REPL's `thread`/`vcpu` commands and the SDKs.
    pub fn set_current_thread(&mut self, id: &str) -> Result<()> {
        self.backend.set_current_thread(id)?;
        self.target.selected_frame = None;
        self.current_thread = id.to_string();
        self.parked_windows_thread = None;
        self.target.clear_current_windows_thread_context();
        self.refresh_context_for_current_thread();
        Ok(())
    }

    /// Select a non-running Windows thread for metadata and stack inspection
    /// without changing the backend vCPU. This deliberately does not attempt to
    /// manufacture a register context for the parked thread.
    pub fn select_parked_windows_thread(&mut self, thread: &ThreadInfo) {
        self.target.selected_frame = None;
        self.parked_windows_thread = Some(thread.ethread);
        self.target.set_parked_windows_thread(thread.clone());
    }

    /// Install a debugger-selected frame/context as the inspection context:
    /// its recovered registers shadow the live ones and its address space
    /// becomes the expression/memory scope. Shared by the REPL's `.frame` /
    /// `.cxr` / `.trap` and the DAP frame selection so the two can't drift.
    pub fn select_frame(&mut self, selected: SelectedFrame) {
        self.target.registers = Some(selected.registers.clone());
        if let Some(cr3) = selected.registers.get("cr3").copied()
            && cr3 != 0
            && self.target.guest.is_some()
            && self.target.kernel_dtb() != DTB_IDENTITY
        {
            self.target.set_context_dtb_override(cr3);
        } else {
            self.target.clear_context_dtb_override();
        }
        self.target.selected_frame = Some(selected);
    }

    pub fn parked_windows_thread(&self) -> Option<&ThreadInfo> {
        let ethread = self.parked_windows_thread?;
        self.target
            .windows_thread_selection
            .as_ref()
            .filter(|thread| thread.ethread == ethread)
    }

    /// Every Windows thread the target knows plus the ones currently on a
    /// vCPU (which a mid-creation walk may not list yet). The candidate set
    /// for selecting a thread by tid/ETHREAD/KTHREAD.
    pub fn windows_thread_candidates(&mut self) -> Result<Vec<ThreadInfo>> {
        let mut threads = self.target.enumerate_threads()?;
        let active = self.active_thread_map();
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        if threads.is_empty()
            && let Some(thread) = self.target.windows_thread_selection.clone()
        {
            threads.push(thread);
        }
        Ok(threads)
    }

    /// The one Windows thread `value` names: a thread id, an ETHREAD, or a
    /// KTHREAD address. Ambiguity (a tid colliding with an address) is an
    /// error rather than a guess.
    pub fn find_windows_thread(&mut self, value: u64) -> Result<ThreadInfo> {
        let matches: Vec<ThreadInfo> = self
            .windows_thread_candidates()?
            .into_iter()
            .filter(|thread| {
                thread.tid == Some(value) || thread.ethread.0 == value || thread.kthread.0 == value
            })
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().unwrap()),
            0 => Err(Error::DebugInfo(format!(
                "no Windows thread matches {value:#x} (tid, ETHREAD, or KTHREAD)"
            ))),
            many => Err(Error::DebugInfo(format!(
                "ambiguous Windows thread {value:#x}: {many} matches"
            ))),
        }
    }

    /// Make `thread` the inspection context (`.thread`): a thread that is on
    /// a vCPU switches the live register context to that vCPU; any other
    /// thread is parked (stack-only, no coherent register file). Returns the
    /// vCPU id when the selection is live.
    pub fn select_windows_thread(&mut self, thread: &ThreadInfo) -> Result<Option<String>> {
        let active = self.active_thread_map();
        match active.get(&thread.ethread.0) {
            Some((vcpu, _)) => {
                let vcpu = vcpu.clone();
                self.set_current_thread(&vcpu)?;
                self.target.selected_frame = None;
                self.target
                    .set_current_windows_thread_context(thread.clone());
                Ok(Some(vcpu))
            }
            None => {
                self.select_parked_windows_thread(thread);
                Ok(None)
            }
        }
    }

    /// Drop any Windows-thread selection and return to the backend's current
    /// vCPU context (`.thread` with no argument).
    pub fn reset_windows_thread(&mut self) -> Result<()> {
        let current = self.current_thread.clone();
        self.set_current_thread(&current)?;
        self.target.selected_frame = None;
        self.target.clear_current_windows_thread_context();
        Ok(())
    }

    /// Move the whole inspection selection out (process scope, frame, parked
    /// thread, vCPU), leaving the session detached on the same vCPU. A host
    /// that scopes one operation itself (the Python SDK binds every handle to
    /// its own address space) runs it between this and
    /// [`Self::restore_selection`], so the user's `.process`/`.thread`/`.frame`
    /// choice survives untouched.
    pub fn take_selection(&mut self) -> Selection {
        Selection {
            target: self.target.take_selection(),
            current_thread: self.current_thread.clone(),
            parked_windows_thread: self.parked_windows_thread.take(),
        }
    }

    /// Put back a selection taken with [`Self::take_selection`], switching the
    /// backend back to its vCPU if the operation moved it.
    pub fn restore_selection(&mut self, selection: Selection) -> Result<()> {
        let switched = if self.current_thread != selection.current_thread {
            self.backend.set_current_thread(&selection.current_thread)
        } else {
            Ok(())
        };
        self.current_thread = selection.current_thread;
        self.parked_windows_thread = selection.parked_windows_thread;
        self.target.restore_selection(selection.target);
        switched
    }

    /// Select stack frame `index` (`.frame N`) of the current live thread as
    /// the inspection context, so registers, locals, and expressions see that
    /// frame's recovered register file. Returns the frame. A parked thread has
    /// no register file to unwind from and is refused.
    pub fn select_frame_index(&mut self, index: usize) -> Result<SelectedFrame> {
        const MAX_FRAME_INDEX: usize = 4096;
        if index > MAX_FRAME_INDEX {
            return Err(Error::InvalidArgument("frame index is too large".into()));
        }
        let (trace, seed, live) = self.recovered_live_trace(index.saturating_add(1))?;
        let frame = trace
            .frames
            .get(index)
            .ok_or_else(|| Error::DebugInfo(format!("frame {index} is unavailable")))?;
        let selected = SelectedFrame::from_recovered(frame, index, Some(&seed), live);
        self.select_frame(selected.clone());
        Ok(selected)
    }

    /// Refill the target's register cache from the live backend context, or
    /// clear it while the VM runs or a parked thread is selected, so
    /// expression evaluation follows the current thread's address space.
    pub fn restore_live_register_cache(&mut self) {
        let registers = if self.backend.is_running() || self.parked_windows_thread().is_some() {
            Err(Error::TargetRunning(REGISTERS_NEED_HALT))
        } else {
            self.read_registers()
        };
        update_target_context_from_registers(&mut self.target, &self.register_map, registers);
    }

    /// Forget a selected frame/context and go back to the live register file
    /// (`.frame` reset / `.cxr` with no argument).
    pub fn clear_selected_frame(&mut self) {
        if self.target.selected_frame.take().is_some() {
            self.restore_live_register_cache();
        }
    }

    /// Unwind `limit` frames from the current context: the selected frame's
    /// seed registers when one is selected, else the live vCPU file. Returns
    /// the trace, the seed register values, and whether that seed is the
    /// vCPU's own register file (a `.cxr`/`.trap` context is not).
    pub fn recovered_live_trace(
        &mut self,
        limit: usize,
    ) -> Result<(RecoveredStackTrace, HashMap<String, u64>, bool)> {
        if let Some(selected) = self.target.selected_frame.as_ref() {
            let seed = if selected.seed_registers.is_empty() {
                &selected.registers
            } else {
                &selected.seed_registers
            };
            let seed = seed.clone();
            let trace = build_stacktrace_with_register_values(
                &self.target,
                &self.register_map,
                &seed,
                limit,
            );
            return Ok((trace, seed, selected.seed_live));
        }
        if self.parked_windows_thread().is_some() {
            return Err(Error::DebugInfo(
                "frame selection requires a live register context; use `vcpu <id>`".into(),
            ));
        }
        let registers = self.read_registers()?;
        let seed = self.register_map.to_hashmap(&registers);
        let trace =
            build_stacktrace_with_context(&self.target, &self.register_map, &registers, limit);
        Ok((trace, seed, true))
    }

    fn require_live_register_context(&self) -> Result<()> {
        if self.parked_windows_thread().is_some() {
            return Err(Error::DebugInfo(
                "selected Windows thread is parked; registers and execution control require a live vCPU context (use `vcpu <id>`)".into(),
            ));
        }
        Ok(())
    }

    /// Record a raw backend stop for `.lastevent` and typed hosts. REPL paths
    /// that own their richer wait loop call this at the same boundary as the
    /// session wait helpers.
    pub fn record_stop_event(&mut self, event: &StopEvent) {
        self.last_event = Some(LastEvent::new(event.clone()));
    }

    fn record_visible_stop(&mut self, resolution: &StopResolution) {
        let event = match resolution {
            StopResolution::Breakpoint { event, .. }
            | StopResolution::Bugcheck { event }
            | StopResolution::TargetReloaded { event, .. }
            | StopResolution::Stopped { event, .. } => event,
            StopResolution::Resumed | StopResolution::ModulesChanged => return,
        };
        // `$exr_code` follows the same boundary as host-visible stop events;
        // absorbed transport noise must not overwrite it.
        self.target.last_exception_code = event.exception_code;
        self.current_stop = Some(self.continue_outcome_from_resolution(resolution.clone()));
    }

    /// The stop the target is halted at, if it has stopped since it last
    /// moved; see [`Self::note_stop`].
    pub fn current_stop(&self) -> Option<&ContinueOutcome> {
        self.current_stop.as_ref()
    }

    /// Record `outcome` as the stop the target is halted at, for a host that
    /// reports a stop differently from its classification (a temporary
    /// breakpoint reached is a `Step`; a requested break-in is an interrupt).
    /// `Running` and `Halted` carry no stop and leave it alone.
    pub fn note_stop(&mut self, outcome: &ContinueOutcome) {
        if !matches!(
            outcome,
            ContinueOutcome::Running | ContinueOutcome::Halted { .. }
        ) {
            self.current_stop = Some(outcome.clone());
        }
    }

    /// Attach the acknowledgment chosen for the current stop. A successful
    /// continuation calls this after the backend accepts the request.
    pub fn record_continuation_disposition(&mut self, disposition: ContinueDisposition) {
        if let Some(last_event) = &mut self.last_event {
            last_event.disposition = Some(disposition);
        }
        self.current_stop = None;
    }

    fn continue_outcome_from_resolution(&self, resolution: StopResolution) -> ContinueOutcome {
        match resolution {
            StopResolution::Breakpoint {
                breakpoint,
                rip,
                condition_error,
                ..
            } => ContinueOutcome::breakpoint_hit(&breakpoint, rip, condition_error),
            StopResolution::Bugcheck { event } => ContinueOutcome::Bugcheck {
                rip: event.program_counter,
                info: event.bugcheck,
            },
            StopResolution::TargetReloaded { event, coherent } => ContinueOutcome::TargetReloaded {
                rip: event.program_counter,
                kernel_base: self.target.kernel_base().map(|address| address.0),
                coherent,
            },
            StopResolution::Stopped { event, rip } => ContinueOutcome::Stopped {
                rip,
                exception_code: event.exception_code,
                first_chance: event.first_chance,
                exception_address: event.exception_address,
            },
            StopResolution::Resumed | StopResolution::ModulesChanged => {
                unreachable!("absorbed stop cannot be parked")
            }
        }
    }

    fn interrupt_classified(&mut self) -> Result<(StopResolution, bool)> {
        let mut resumed = 0;
        loop {
            let stop_was_pending = self.backend.has_pending_stop();
            let event = self.backend.interrupt()?;
            let resolution = self.classify_stop_event(event)?;
            match resolution {
                StopResolution::Resumed => {
                    resumed += 1;
                    if resumed < INTERRUPT_MAX_RESUMES {
                        continue;
                    }
                    // Surface a generic stop after the bounded noise budget.
                    let stop_was_pending = self.backend.has_pending_stop();
                    let event = self.backend.interrupt()?;
                    let resolution = StopResolution::Stopped {
                        rip: event.program_counter.unwrap_or(0),
                        event,
                    };
                    return Ok((resolution, !stop_was_pending));
                }
                StopResolution::ModulesChanged => continue,
                resolution => return Ok((resolution, !stop_was_pending)),
            }
        }
    }

    /// Pause the VM and return the first meaningful stop. Every raw event routes
    /// through [`Self::classify_stop_event`], so an interrupt that races with a
    /// filtered breakpoint or reconnect-assist stop cannot bypass core state.
    ///
    /// Bounded: while the guest is rebooting (reconnect assist) or hammering a
    /// wrong-process breakpoint, every break-in can classify as noise and be
    /// resumed; after [`INTERRUPT_MAX_RESUMES`] of those the last stop is
    /// surfaced as-is rather than spinning forever (the ^D exit path lives on
    /// this).
    pub fn interrupt(&mut self) -> Result<StopEvent> {
        self.interrupt_classified()
            .map(|(resolution, _)| match resolution {
                StopResolution::Breakpoint { event, .. }
                | StopResolution::Bugcheck { event }
                | StopResolution::TargetReloaded { event, .. }
                | StopResolution::Stopped { event, .. } => event,
                StopResolution::Resumed | StopResolution::ModulesChanged => {
                    unreachable!("absorbed stop cannot be returned")
                }
            })
    }

    /// [`Self::interrupt`] keeping the classification: a breakpoint hit that
    /// races the break-in is reported as that breakpoint (with its action and
    /// condition result) rather than as a bare `STATUS_BREAKPOINT` stop. A
    /// target that is not running is not broken into (KD would wait out its
    /// break-in timeout): a stop parked by [`Self::with_target_halted`] or
    /// [`Self::service_idle`] is surfaced, and a halted target reports the
    /// stop it is halted at ([`Self::current_stop`]), or its pc.
    pub fn interrupt_outcome(&mut self) -> Result<ContinueOutcome> {
        if let Some(stop) = self.stop_without_breakin() {
            return Ok(stop);
        }
        self.interrupt_classified()
            .map(|(resolution, _)| self.continue_outcome_from_resolution(resolution))
    }

    /// [`Self::interrupt_outcome`] for a host that asked for the break-in and
    /// reports it as such: the break-in the interrupt itself caused comes back
    /// as a `Stopped` without an exception code. A parked stop, or a pending
    /// guest exception (a real `int 3`) the break-in collected, keeps its code.
    pub fn interrupt_requested(&mut self) -> Result<ContinueOutcome> {
        if let Some(stop) = self.stop_without_breakin() {
            return Ok(stop);
        }
        let (resolution, own_breakin_candidate) = self.interrupt_classified()?;
        let own_breakin = self.is_own_breakin(&resolution, own_breakin_candidate);
        let mut outcome = self.continue_outcome_from_resolution(resolution);
        if own_breakin
            && let ContinueOutcome::Stopped {
                exception_code,
                first_chance,
                exception_address,
                ..
            } = &mut outcome
        {
            *exception_code = None;
            *first_chance = None;
            *exception_address = None;
        }
        self.note_stop(&outcome);
        Ok(outcome)
    }

    /// The stop an interrupt reports without breaking in: a parked stop, or
    /// the one a halted target is at. `None` when the target must be broken
    /// into.
    fn stop_without_breakin(&mut self) -> Option<ContinueOutcome> {
        if let Some(parked) = self.parked_stop.take() {
            return Some(parked);
        }
        (!self.backend.is_running() && !self.backend.has_pending_stop())
            .then(|| self.halted_outcome())
    }

    /// The stop a halted target is at, or a bare halt at its pc when it has
    /// not stopped since it last moved (attached halted).
    pub fn halted_outcome(&mut self) -> ContinueOutcome {
        match &self.current_stop {
            Some(stop) => stop.clone(),
            None => ContinueOutcome::Halted {
                rip: self.current_rip(),
            },
        }
    }

    /// Whether an interrupt's stop is the break-in it requested. The KD rule
    /// is the same status/non-managed-address split used by
    /// `stop_is_assisted_refresh_breakin`: a STATUS_BREAKPOINT that classified
    /// as an ordinary stop and is not on one of our sites. A stop the backend
    /// already had pending (`candidate` false) wins even with the same status.
    fn is_own_breakin(&self, resolution: &StopResolution, candidate: bool) -> bool {
        let StopResolution::Stopped { event, .. } = resolution else {
            return false;
        };
        candidate
            && event.exception_code == Some(STATUS_BREAKPOINT)
            && event
                .program_counter
                .is_none_or(|pc| self.breakpoints.breakpoint_id_at_address(pc).is_none())
    }

    /// Run `edit` with the target halted, restoring the previous run state.
    /// If the target is already halted, `edit` runs directly and neither
    /// interrupts nor resumes the backend. If it is running, this method breaks
    /// in, runs `edit`, and resumes afterward unless the interrupt exposed a
    /// genuine pending stop. Such a stop is left halted and parked for the next
    /// [`Self::wait_for_stop_bounded`], while an edit error still resumes an
    /// otherwise ordinary break-in before returning the error. This primitive is
    /// shared by hosts that edit breakpoint state; it emits no notifications.
    pub fn with_target_halted<T>(
        &mut self,
        edit: impl FnOnce(&mut Session) -> Result<T>,
    ) -> Result<T> {
        let interrupt_supported = self.backend.capabilities().iter().any(|capability| {
            capability.capability == DebugCapability::InterruptTarget && capability.supported
        });
        if !self.backend.is_running() || !interrupt_supported {
            return edit(self);
        }

        let (resolution, own_breakin_candidate) = self.interrupt_classified()?;
        if !self.is_own_breakin(&resolution, own_breakin_candidate) {
            self.parked_stop = Some(self.continue_outcome_from_resolution(resolution));
            return edit(self);
        }

        let result = edit(self);
        let resume = self.resume();
        match (result, resume) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(edit_error), Err(resume_error)) => Err(Error::DebugInfo(format!(
                "{edit_error}; failed to resume target: {resume_error}"
            ))),
        }
    }
    /// Bring the target to a real halt before teardown: consume a stop that is
    /// already pending if it is meaningful, else break in. The REPL's ^D path.
    pub fn halt_for_exit(&mut self) -> Result<()> {
        if let Some(event) = self.backend.try_wait_for_stop(EXIT_STOP_POLL)?
            && !matches!(
                self.classify_stop_event(event)?,
                StopResolution::Resumed | StopResolution::ModulesChanged
            )
        {
            return Ok(());
        }
        self.interrupt().map(drop)
    }

    /// Align the inspection context to the currently selected thread's address
    /// space: when halted, read that thread's registers and set
    /// `target.registers` and `context_dtb_override` from its CR3 (or ARM64
    /// TTBR0), so reads,
    /// steps, and breakpoint installs scope to the focused thread rather than
    /// an earlier stop on another thread. Called from the thread-selection entry
    /// points; `continue_until_break` establishes the same context inline. Best-
    /// effort and a no-op while the guest runs (no coherent register file).
    fn refresh_context_for_current_thread(&mut self) {
        self.parked_windows_thread = None;
        if self.backend.is_running() {
            return;
        }
        let registers = self
            .backend
            .set_current_thread(&self.current_thread)
            .and_then(|_| self.backend.read_registers());
        update_target_context_from_registers(&mut self.target, &self.register_map, registers);
    }

    /// Decode the instruction at the current thread's program counter, masking
    /// any software-breakpoint patch and reading through the thread's preferred
    /// code DTB. Selects the current thread first; the VM must be halted.
    pub fn current_instruction(&mut self) -> Result<CurrentInstruction> {
        self.require_live_register_context()?;
        self.backend.set_current_thread(&self.current_thread)?;
        let regs = self.backend.read_registers()?;
        self.target.registers = Some(self.register_map.to_hashmap(&regs));
        let pc = self.register_map.read_u64("rip", &regs)?;
        let dtb = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &regs)
            .unwrap_or(0);
        let trace = resolve_thread_trace_context(&self.target, dtb);
        let code_dtb = preferred_code_dtb(&trace, pc);
        let memory = self.target.address_space(code_dtb);
        let mut bytes = [0u8; 16];
        memory.read_bytes(VirtAddr(pc), &mut bytes)?;
        self.breakpoints.mask_breakpoint_bytes(
            &self.target,
            VirtAddr(pc),
            &mut bytes,
            trace.active_dtb,
        );
        self.mask_bugcheck_trap(VirtAddr(pc), &mut bytes);

        if self.target.arch() == Arch::Arm64 {
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let Ok(instruction) = bad64::decode(word, pc) else {
                return Err(Error::DebugInfo(format!(
                    "failed to decode instruction at {pc:#x}"
                )));
            };
            let mnem = instruction.op().mnem();
            // `bl`/`blr` are the call forms; AArch64 instructions are 4 bytes.
            return Ok(CurrentInstruction {
                is_call: mnem == "bl" || mnem == "blr",
                next_ip: pc.wrapping_add(4),
            });
        }

        let bitness = self.target.code_bitness(VirtAddr(pc));
        let mut decoder = Decoder::with_ip(bitness, &bytes, pc, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.code() == Code::INVALID {
            return Err(Error::DebugInfo(format!(
                "failed to decode instruction at {pc:#x}"
            )));
        }
        let next_ip = if bitness == 32 {
            instruction.next_ip() & u64::from(u32::MAX)
        } else {
            instruction.next_ip()
        };
        Ok(CurrentInstruction {
            is_call: instruction.mnemonic() == Mnemonic::Call,
            next_ip,
        })
    }

    /// Compute the step-over plan for the current instruction: run to the
    /// instruction *after* a `call`, otherwise a plain single-step. The shared
    /// decision used by the REPL `p` and [`Self::step_over`].
    pub fn step_over_target(&mut self) -> Result<StepKind> {
        let instruction = self.current_instruction()?;
        if instruction.is_call {
            Ok(StepKind::RunTo(VirtAddr(instruction.next_ip)))
        } else {
            Ok(StepKind::Single)
        }
    }

    /// The current frame's caller return address (the step-out target). Walks a
    /// few frames of the current thread's stack and returns the second frame's
    /// IP. Shared by the REPL `gu` and [`Self::step_out`].
    pub fn step_out_target(&mut self) -> Result<VirtAddr> {
        self.require_live_register_context()?;
        self.backend.set_current_thread(&self.current_thread)?;
        let regs = self.backend.read_registers()?;
        let trace = build_stacktrace(&self.target, &self.register_map, &regs, 4);
        let caller = trace
            .frames
            .get(1)
            .ok_or_else(|| Error::DebugInfo("could not find caller return address".to_string()))?;
        if caller.ip == 0 {
            return Err(Error::DebugInfo(
                "caller return address is null".to_string(),
            ));
        }
        Ok(VirtAddr(caller.ip))
    }

    /// The halted vCPU's [`ControlState`]: IP, SP, page-table root, and the
    /// control flow of the instruction at the IP (read breakpoint-masked).
    pub fn control_state(&mut self) -> Result<ControlState> {
        let registers = self.read_registers()?;
        let ip = self
            .register_map
            .read_u64("rip", &registers)
            .or_else(|_| self.register_map.read_u64("pc", &registers))?;
        let sp = self
            .register_map
            .read_u64("rsp", &registers)
            .or_else(|_| self.register_map.read_u64("sp", &registers))?;
        let dtb = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &registers)
            .unwrap_or(0);
        let mut bytes = [0u8; 16];
        let length = if self.target.arch() == Arch::Arm64 {
            4
        } else {
            bytes.len()
        };
        self.read_masked(VirtAddr(ip), &mut bytes[..length])?;
        Ok(ControlState {
            ip,
            sp,
            dtb,
            flow: classify(&bytes[..length], self.target.arch()),
        })
    }

    /// The enabled code breakpoint (in the current context) that a step from
    /// `previous_ip` landed on: one at `ip`, or one just before it when the
    /// trap reported the IP past the breakpoint byte. A step that started on
    /// a breakpoint does not count the one it left.
    pub fn code_breakpoint_after_step(&self, previous_ip: u64, ip: u64) -> Option<u32> {
        let at = |address: u64| {
            self.breakpoints
                .enabled_breakpoint_id_for_current_context(&self.target, VirtAddr(address))
        };
        if let Some(id) = at(ip) {
            return Some(id);
        }
        let step = u64::from(self.register_map.breakpoint_step_size());
        if at(previous_ip).is_some() || ip < step {
            return None;
        }
        at(ip - step)
    }

    /// Step until `stop` accepts the instruction about to execute, into calls
    /// or `over` them: the SDK's `step(until=)` and `run_to(step=)`. Returns
    /// the `Step` there; a breakpoint, exception, or other stop met on the way
    /// is returned as is. An interrupt request ([`Target::interrupt`]) or an
    /// elapsed `timeout` ends the walk where it is, as a `Step`; `limit`
    /// instructions without a match is an error.
    pub fn step_until(
        &mut self,
        over: bool,
        limit: usize,
        timeout: Option<Duration>,
        stop: impl Fn(u64, ControlFlow) -> bool,
    ) -> Result<ContinueOutcome> {
        self.require_live_register_context()?;
        self.clear_selected_frame();
        let deadline = timeout.map(|timeout| Instant::now() + timeout);
        let cancel = Arc::clone(&self.target.interrupt);
        for _ in 0..limit {
            if cancel.swap(false, Ordering::SeqCst) {
                let outcome = ContinueOutcome::Step {
                    rip: self.current_rip(),
                };
                self.note_stop(&outcome);
                return Ok(outcome);
            }
            let state = self.control_state()?;
            if stop(state.ip, state.flow)
                || deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                let outcome = ContinueOutcome::Step { rip: state.ip };
                self.note_stop(&outcome);
                return Ok(outcome);
            }
            let step = match self.step_over_target()? {
                StepKind::RunTo(next) if over => {
                    let remaining =
                        deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
                    self.run_to(next, remaining, &cancel)?
                }
                _ => ContinueOutcome::Step { rip: self.step()? },
            };
            let rip = match step {
                ContinueOutcome::Step { rip } => rip,
                // `run_to` was cancelled or timed out and halted the target.
                ContinueOutcome::Running => {
                    let outcome = ContinueOutcome::Step {
                        rip: self.current_rip(),
                    };
                    self.note_stop(&outcome);
                    return Ok(outcome);
                }
                other => return Ok(other),
            };
            if let Some(outcome) = self
                .code_breakpoint_after_step(state.ip, rip)
                .and_then(|id| self.breakpoint_outcome(id, rip))
            {
                self.note_stop(&outcome);
                return Ok(outcome);
            }
        }
        Err(Error::StepLimit(limit))
    }

    fn breakpoint_outcome(&self, id: u32, rip: u64) -> Option<ContinueOutcome> {
        let breakpoint = self.breakpoints.get(id)?;
        Some(ContinueOutcome::breakpoint_hit(breakpoint, rip, None))
    }

    /// Single-step the current function and collect its call tree (`wt`), up
    /// to `limit` instructions. A frame closes on a `ret` that moves the stack
    /// pointer above the one it was entered with, so a `ret` that does not
    /// leave the frame (a retpoline) is not taken for a return. An interrupt
    /// request ([`Target::interrupt`]), a breakpoint, or a failed step ends
    /// the trace early; [`CallTrace::end`] says which.
    pub fn trace_calls(&mut self, limit: usize) -> Result<CallTrace> {
        if limit == 0 {
            return Err(Error::InvalidArgument(
                "the instruction limit must be greater than zero".into(),
            ));
        }
        let name = |target: &Target, state: &ControlState| {
            let trace = resolve_thread_trace_context(target, state.dtb);
            format_symbol(target, &trace, state.ip)
        };
        let frame = |name| CallTraceFrame {
            name,
            instructions: 0,
            children: Vec::new(),
        };
        let mut current = self.control_state()?;
        // Each open frame with the stack pointer it was entered with.
        let mut stack = vec![(frame(name(&self.target, &current)), current.sp)];
        let mut instructions = 0usize;
        let arm64 = self.target.arch() == Arch::Arm64;
        let end = loop {
            if instructions >= limit {
                break CallTraceEnd::Limit;
            }
            if self.target.interrupt.swap(false, Ordering::SeqCst) {
                break CallTraceEnd::Interrupted;
            }
            if let Err(error) = self.step() {
                break CallTraceEnd::Failed(error.to_string());
            }
            instructions += 1;
            let next = match self.control_state() {
                Ok(state) => state,
                Err(error) => break CallTraceEnd::Failed(error.to_string()),
            };
            if self
                .code_breakpoint_after_step(current.ip, next.ip)
                .is_some()
            {
                break CallTraceEnd::Breakpoint;
            }
            let (open, entry_sp) = stack.last_mut().expect("the traced function's frame");
            open.instructions += 1;
            if current.flow == ControlFlow::Call {
                stack.push((frame(name(&self.target, &next)), next.sp));
            } else if current.flow == ControlFlow::Ret
                && (next.sp > *entry_sp || (arm64 && next.sp >= *entry_sp))
            {
                let (completed, _) = stack.pop().expect("an open frame");
                match stack.last_mut() {
                    Some((parent, _)) => parent.children.push(completed),
                    None => {
                        stack.push((completed, 0));
                        break CallTraceEnd::Returned;
                    }
                }
            }
            current = next;
        };

        let (mut root, _) = stack.remove(0);
        // Fold frames still open when the trace ended into their callers.
        let mut open: Vec<CallTraceFrame> = stack.into_iter().map(|(frame, _)| frame).collect();
        while let Some(completed) = open.pop() {
            open.last_mut()
                .unwrap_or(&mut root)
                .children
                .push(completed);
        }
        Ok(CallTrace {
            root,
            instructions,
            end,
        })
    }

    /// Run until `address` is reached. If a breakpoint is already set there in
    /// the current context this is a plain [`Self::continue_until_break`];
    /// otherwise it installs a temporary breakpoint, runs to it, removes it, and
    /// reports reaching it as [`ContinueOutcome::Step`]. A *different* breakpoint,
    /// bugcheck, or exception en route is surfaced as-is. Blocks until a stop,
    /// `timeout`, or `cancel` (checked between polls); the last two halt the
    /// target where it is, remove the temp breakpoint, and return
    /// [`ContinueOutcome::Running`]. The run-to-address primitive behind
    /// [`Self::step_over`] / [`Self::step_out`].
    pub fn run_to(
        &mut self,
        address: VirtAddr,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        // Already breakpointed here → just continue; the existing bp will report.
        let temp_id = if self
            .breakpoints
            .enabled_breakpoint_id_for_current_context(&self.target, address)
            .is_some()
        {
            None
        } else {
            Some(self.breakpoints.add_temporary_code(
                self.backend.as_mut(),
                &self.target,
                address,
            )?)
        };
        let outcome = self.continue_until_break(timeout, cancel, ContinueDisposition::Handled);

        // A cancel or timeout leaves the VM running; halt it where it is (the
        // temp breakpoint's removal writes guest memory anyway). A target
        // reload already cleared the manager, so the remove may be a no-op;
        // ignore its error.
        if self.backend.is_running() {
            let _ = self.interrupt();
        }
        if let Some(temp_id) = temp_id {
            let _ = self
                .breakpoints
                .remove(self.backend.as_mut(), &self.target, temp_id);
        }

        let outcome = match outcome? {
            ContinueOutcome::Breakpoint { id, rip, .. } if Some(id) == temp_id => {
                ContinueOutcome::Step { rip }
            }
            other => other,
        };
        self.note_stop(&outcome);
        Ok(outcome)
    }

    /// Step over the current instruction: single-step it, or, if it's a `call`,
    /// run to the instruction after it ([`ContinueOutcome::Step`] on completion).
    /// Shared by the REPL `p` (target only) and the SDKs.
    pub fn step_over(&mut self, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        match self.step_over_target()? {
            StepKind::Single => Ok(ContinueOutcome::Step { rip: self.step()? }),
            StepKind::RunTo(addr) => self.run_to(addr, None, cancel),
        }
    }

    /// Step out of the current function: run to the caller's return address.
    pub fn step_out(&mut self, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        let target = self.step_out_target()?;
        self.run_to(target, None, cancel)
    }

    /// Best-effort current RIP of the selected thread (0 if unreadable).
    pub fn current_rip(&mut self) -> u64 {
        self.backend
            .read_registers()
            .ok()
            .and_then(|r| {
                self.register_map
                    .read_u64("rip", &r)
                    .or_else(|_| self.register_map.read_u64("pc", &r))
                    .ok()
            })
            .unwrap_or(0)
    }

    /// Read the selected live vCPU register file. A parked Windows thread is a
    /// stack-only inspection target and must never fall through to the backend's
    /// unrelated live register context.
    pub fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.require_live_register_context()?;
        if self.backend.is_running() {
            return Err(Error::TargetRunning(REGISTERS_NEED_HALT));
        }
        self.backend.set_current_thread(&self.current_thread)?;
        self.backend.read_registers()
    }

    /// Set a single register on the current thread by name, as a read-modify-
    /// write of the register file (read all, patch the one, write back).
    pub fn write_register(&mut self, name: &str, value: u64) -> Result<()> {
        self.patch_registers(|map, regs| map.write_u64(name, regs, value))
    }

    /// Read-modify-write the current thread's register file: `patch` edits the
    /// raw file laid out by [`Self::register_map`], which is written back and
    /// becomes the live frame's register view.
    pub fn patch_registers(
        &mut self,
        patch: impl FnOnce(&RegisterMap, &mut [u8]) -> Result<()>,
    ) -> Result<()> {
        self.require_live_register_context()?;
        if self.backend.is_running() {
            return Err(Error::TargetRunning(REGISTERS_NEED_HALT));
        }
        if !self
            .backend
            .capabilities()
            .iter()
            .any(|entry| entry.capability == DebugCapability::WriteRegisters && entry.supported)
        {
            return Err(Error::RegisterWriteUnsupported);
        }
        let mut regs = self.read_registers()?;
        patch(&self.register_map, &mut regs)?;
        self.backend.write_registers(&regs)?;
        let values = self.register_map.to_hashmap(&regs);
        // A live frame 0 selection is this register file; keep it, and the
        // seed a `.frame N` walk starts from, in step with the write.
        if let Some(frame) = self
            .target
            .selected_frame
            .as_mut()
            .filter(|frame| frame.is_live())
        {
            frame.registers.clone_from(&values);
            frame.seed_registers.clone_from(&values);
        }
        self.target.registers = Some(values);
        Ok(())
    }

    /// The backend's capability matrix (what the current transport supports), so
    /// a host can report unsupported operations up front instead of by failure.
    pub fn capabilities(&self) -> Vec<BackendCapability> {
        self.backend.capabilities()
    }

    /// Read captured guest debug output (DbgPrint) at or after `since_seq`.
    /// Snapshot+cursor: pass the previous page's `next_seq` to poll only new
    /// lines. Empty on backends without a native debug stream (gdb/memory); see
    /// [`DebugCapability::DebugOutput`].
    pub fn read_debug_output(&self, since_seq: u64) -> DebugOutputPage {
        self.backend.read_debug_output(since_seq)
    }

    /// Whether kernel structures are safe to read: the loaded-module list is
    /// populated (not early boot / mid-rediscovery) and the kernel base still
    /// reads `MZ` (no undetected reboot).
    pub fn kernel_coherent(&self) -> bool {
        !self.reload_module_list_pending && self.target.current_kernel_mapping_is_valid()
    }

    /// Drain a stop the background servicer has already caught without advancing
    /// to a later event. This makes a physically halted VM visible even while
    /// `is_running()` still holds stale running state.
    ///
    /// Debugger-generated noise is still absorbed so read/status surfaces match
    /// normal run control. Reload stops keep their deferred `TargetReloaded`
    /// notification for the next wait surface.
    pub fn settle_pending_stop(&mut self) -> Result<()> {
        if !self.backend.has_pending_stop() {
            return Ok(());
        }
        let event = self.backend.wait_for_stop()?;
        if matches!(
            self.classify_stop_event(event)?,
            StopResolution::TargetReloaded { .. }
        ) {
            // Settling is intentionally non-surfacing. Preserve the single
            // reboot notification for the next explicit wait.
            self.reload_surface_pending = true;
        }
        Ok(())
    }

    /// Service the guest while the host is otherwise idle: absorb a stop the
    /// background servicer caught but no tool call has drained (chiefly a
    /// wrong-process hit on a shared-page breakpoint), so the guest is not left
    /// frozen between tool calls. Noise is resumed; a real stop, a reboot
    /// included, is parked for the next `wait_for_stop`.
    pub fn service_idle(&mut self) {
        if self.parked_stop.is_some() || !self.backend.has_pending_stop() {
            return;
        }
        let never_cancel = AtomicBool::new(false);
        match self.wait_for_stop_bounded(Some(SERVICE_IDLE_BUDGET), &never_cancel) {
            Ok(ContinueOutcome::Running) | Err(_) => {}
            Ok(outcome) => {
                self.parked_stop = Some(outcome);
            }
        }
    }

    /// Hand over a stop [`Self::service_idle`] parked while the host was idle,
    /// for hosts that render stops themselves rather than through
    /// [`Self::wait_for_stop_bounded`]. The VM is halted at it.
    pub fn take_parked_stop(&mut self) -> Option<ContinueOutcome> {
        self.parked_stop.take()
    }

    /// Resolve the stopped vCPU's process and Windows thread from the target.
    /// Select that thread for inspection. The attached process scope is separate
    /// and persists across resumes.
    pub fn stopped_context(&mut self) -> (Option<ProcessInfo>, Option<ThreadInfo>) {
        let mask = self.target.arch().dtb_page_mask();
        let dtb_register = self.target.arch().dtb_register();
        let stopped_process = self
            .backend
            .read_registers()
            .ok()
            .and_then(|regs| self.register_map.read_u64(dtb_register, &regs).ok())
            .and_then(|cr3| self.target.process_for_cr3(cr3 & mask));
        let current_thread = self.current_thread.clone();
        let stopped_thread =
            refresh_windows_thread_context_for_backend_thread(&mut self.target, &current_thread);
        (stopped_process, stopped_thread)
    }

    /// Read `buf` at `address` in the current inspection space, falling back
    /// to the kernel's: a record a trap or bugcheck saved lives in either.
    /// The error is the current space's.
    fn read_record_bytes(&self, address: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let current = self.target.context_memory().read_bytes(address, buf);
        if current.is_err()
            && self
                .target
                .kernel_address_space()
                .read_bytes(address, buf)
                .is_ok()
        {
            return Ok(());
        }
        current
    }

    /// Decode an `EXCEPTION_RECORD64` at `address` (`.exr`).
    pub fn read_exception_record(&self, address: VirtAddr) -> Result<ExceptionRecord> {
        const SIZE: usize = 0x98;
        let mut bytes = [0u8; SIZE];
        self.read_record_bytes(address, &mut bytes)?;
        let read_u32 = |offset: usize| {
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("record field"))
        };
        let read_u64 = |offset: usize| {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("record field"))
        };
        let count = (read_u32(24) as usize).min(15);
        let parameters = (0..count).map(|index| read_u64(32 + index * 8)).collect();
        Ok(ExceptionRecord {
            code: read_u32(0),
            flags: read_u32(4),
            nested: read_u64(8),
            address: read_u64(16),
            parameters,
        })
    }

    /// Decode the `CONTEXT` record at `address` into a register map, without
    /// changing the selected backend context (`.cxr`).
    pub fn read_context_record(&self, address: VirtAddr) -> Result<HashMap<String, u64>> {
        let (size, map) = match self.target.arch() {
            Arch::Amd64 => (context::CONTEXT_SIZE, context::build_register_map()),
            Arch::Arm64 => (
                context_arm64::CONTEXT_SIZE,
                context_arm64::build_register_map(),
            ),
        };
        let mut bytes = vec![0u8; size];
        self.read_record_bytes(address, &mut bytes)?;
        Ok(map.to_hashmap(&bytes))
    }

    /// The current `.exr -1` view, when the last event contains exception
    /// metadata or the attached dump carries a saved exception record.
    pub fn current_exception_record(&self) -> Option<ExceptionRecord> {
        if let Some(event) = &self.last_event {
            let stop = &event.stop;
            let code = stop
                .exception_code
                .or_else(|| stop.bugcheck.as_ref().map(|info| info.code))?;
            return Some(ExceptionRecord {
                code,
                flags: 0,
                nested: 0,
                address: stop.exception_address.or(stop.program_counter).unwrap_or(0),
                parameters: Vec::new(),
            });
        }
        let exception = self.target.phys.dmp_info()?.exception.as_ref()?;
        Some(ExceptionRecord {
            code: exception.code,
            flags: exception.flags,
            nested: 0,
            address: exception.address,
            parameters: exception.parameters.clone(),
        })
    }

    /// A read-only run-control snapshot for the "where am I" surface (see
    /// [`RunStatus`]). When halted, selects the current thread and resolves
    /// rip+symbol (best-effort); while running, leaves those None. Reports
    /// `coherent: false` while a post-reboot rediscovery is still pending so a
    /// host waits instead of enumerating stale state.
    pub fn run_status(&mut self) -> RunStatus {
        // On failure `has_pending_stop` stays true and the snapshot reports
        // halted with no location.
        let _ = self.settle_pending_stop();
        self.try_finish_rediscovery_from_memory();
        // The snapshot carries `kernel_base` + `coherent`, so it is the reload
        // notification.
        self.clear_deferred_reload_surface();
        let pending_stop = self.backend.has_pending_stop();
        let running = self.backend.is_running() && !pending_stop;
        let (rip, symbol, stopped_process, stopped_thread) = if running || pending_stop {
            (None, None, None, None)
        } else {
            let _ = self.backend.set_current_thread(&self.current_thread);
            let registers = self.backend.read_registers().ok();
            let rip = registers
                .as_ref()
                .and_then(|regs| self.register_map.read_u64("rip", regs).ok());
            let symbol = rip.and_then(|r| self.target.closest_symbol_current_context(VirtAddr(r)));
            let (stopped_process, stopped_thread) = self.stopped_context();
            (rip, symbol, stopped_process, stopped_thread)
        };
        RunStatus {
            running,
            current_thread: self.current_thread.clone(),
            rip,
            symbol,
            attached_process: self.target.attached_process().cloned(),
            stopped_process,
            stopped_thread,
            coherent: self.kernel_coherent(),
            kernel_base: self.target.kernel_base().map(|a| a.0).unwrap_or(0),
        }
    }

    /// Set a code breakpoint at `addr` with an optional display `symbol` and
    /// its configuration (condition, pass count, one-shot, command action;
    /// `BreakpointConfig::default()` for a plain one). The breakpoint's scope
    /// is derived from the current inspection context at install time.
    /// Returns the breakpoint id.
    pub fn add_breakpoint(
        &mut self,
        addr: VirtAddr,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        self.breakpoints
            .add_configured(self.backend.as_mut(), &self.target, addr, symbol, config)
    }

    /// Set a symbol-identity breakpoint: it survives module unload/reload and
    /// may remain deferred until matching symbols are loaded.
    pub fn add_symbol_breakpoint(
        &mut self,
        symbol: String,
        config: BreakpointConfig,
    ) -> Result<u32> {
        self.breakpoints
            .add_symbolic(self.backend.as_mut(), &self.target, symbol, config)
    }

    /// Set one source identity for every address matching `file:line`, or one
    /// deferred identity when no matching module is currently loaded. Returns
    /// one id per matching address (or the single deferred id).
    pub fn add_source_breakpoint(
        &mut self,
        source: String,
        config: BreakpointConfig,
    ) -> Result<Vec<u32>> {
        self.breakpoints
            .add_source(self.backend.as_mut(), &self.target, source, config)
    }

    /// Set one symbol-identity breakpoint per symbol matching `pattern`
    /// (`bm`): `*`/`?` globs, optionally `module!`-qualified; at most `limit`
    /// matches. Returns the ids created, and the count of matches that
    /// failed to install (already reported through `errors`).
    pub fn add_pattern_breakpoints(
        &mut self,
        pattern: &str,
        config: BreakpointConfig,
        limit: usize,
    ) -> Result<(Vec<u32>, Vec<Error>)> {
        let dtb = self.target.current_dtb();
        let names: Vec<String> = match pattern.split_once('!') {
            Some((module, query)) => self
                .target
                .symbols
                .search_symbols_in_module(dtb, module, query, limit)
                .into_iter()
                .map(|name| format!("{module}!{name}"))
                .collect(),
            None => self.target.current_symbol_index().search(pattern, limit),
        };
        let mut ids = Vec::new();
        let mut errors = Vec::new();
        for name in names.into_iter().take(limit) {
            let canonical = self
                .target
                .symbols
                .find_symbol_with_module(dtb, &name)?
                .map(|(_, module)| {
                    let bare = name
                        .rsplit_once('!')
                        .map_or(name.as_str(), |(_, bare)| bare);
                    format!("{module}!{bare}")
                })
                .unwrap_or_else(|| name.clone());
            match self.add_symbol_breakpoint(canonical, config.clone()) {
                Ok(id) => ids.push(id),
                Err(error) => errors.push(error),
            }
        }
        Ok((ids, errors))
    }

    /// The `/p <pid>` breakpoint scope: hits are reported only from that
    /// process's address space.
    pub fn breakpoint_scope_for_pid(&self, pid: u64) -> Result<BreakpointScope> {
        let process = self
            .target
            .guest
            .as_ref()
            .ok_or(Error::NtoskrnlNotFound)?
            .enumerate_processes()?
            .into_iter()
            .find(|process| process.pid == pid)
            .ok_or_else(|| Error::InvalidArgument(format!("process {pid} not found")))?;
        Ok(BreakpointScope::process(&process))
    }

    /// Arm an automatic breakpoint on `nt!KeBugCheckEx` when the backend
    /// cannot recognize a bugcheck on its own.
    ///
    /// KD learns of a crash from the target itself; a hypervisor stub never
    /// does, so the crash is only observable by stopping the guest as it
    /// enters the bugcheck. Armed at attach, where the operator can see it
    /// reported, and retried on every resume: the site needs kernel symbols,
    /// which can arrive late and move across a reboot.
    fn arm_bugcheck_trap(&mut self) {
        let capabilities = self.backend.capabilities();
        let supports = |capability| {
            capabilities
                .iter()
                .any(|entry| entry.capability == capability && entry.supported)
        };
        // A target that reports its own bugchecks needs no trap, and one that
        // cannot hold a breakpoint cannot be given one.
        if self.bugcheck_trap.is_some()
            || supports(DebugCapability::BugcheckDetection)
            || !supports(DebugCapability::KernelBreakpoints)
        {
            return;
        }
        let Some(guest) = self.target.guest.as_ref() else {
            return;
        };
        let kernel_dtb = guest.ntoskrnl.dtb();
        let Ok(Some(address)) = self
            .target
            .symbols
            .find_symbol_across_modules(kernel_dtb, "nt!KeBugCheckEx")
        else {
            return;
        };
        // Read the code before the trap displaces it: the stub writes the
        // breakpoint into guest memory, and memory here is read out of band
        // through the host mapping, so nothing else would ever see the
        // original instruction again.
        let mut original = vec![0u8; usize::from(self.register_map.breakpoint_step_size())];
        if self
            .target
            .address_space(kernel_dtb)
            .read_bytes(address, &mut original)
            .is_err()
        {
            original.clear();
        }

        match self.backend.set_breakpoint(address.0) {
            Ok(()) => {
                self.bugcheck_trap = Some(address);
                self.bugcheck_trap_original = original;
                self.notices.push(format!(
                    "armed a bugcheck trap at nt!KeBugCheckEx ({:#x}); the {} backend cannot detect a bugcheck by itself",
                    address.0,
                    self.backend.name()
                ));
            }
            Err(error) => self.notices.push(format!(
                "failed to arm a bugcheck trap at nt!KeBugCheckEx: {error}"
            )),
        }
    }

    /// The bugcheck a [`Self::arm_bugcheck_trap`] stop is reporting, read
    /// from the arguments of the `KeBugCheckEx` call we stopped at.
    ///
    /// `nt!KiBugCheckData` is empty at the function's first instruction: the
    /// code that fills it has not run. The arguments have not been spilled
    /// yet either, so they are still in registers, the fifth on the stack
    /// above the shadow space.
    fn bugcheck_from_trap(&mut self) -> Option<BugcheckInfo> {
        let registers = self.backend.read_registers().ok()?;
        let read = |name: &str| self.register_map.read_u64(name, &registers).ok();
        let (code, p1, p2, p3, p4) = match self.target.arch() {
            Arch::Amd64 => {
                let stack = read("rsp")?;
                let fourth = self
                    .target
                    .address_space(self.target.current_dtb())
                    .read::<u64>(VirtAddr(stack.wrapping_add(0x28)))
                    .ok();
                (read("rcx")?, read("rdx")?, read("r8")?, read("r9")?, fourth)
            }
            Arch::Arm64 => (
                read("x0")?,
                read("x1")?,
                read("x2")?,
                read("x3")?,
                read("x4"),
            ),
        };
        Some(BugcheckInfo {
            code: code as u32,
            parameters: [p1, p2, p3, p4.unwrap_or(0)],
            driver: None,
        })
    }

    /// The `/t` filter for an `ETHREAD`, for hosts that name a thread by
    /// address rather than by the REPL's selector grammar.
    pub fn breakpoint_thread_for_ethread(&self, ethread: u64) -> Result<ThreadScope> {
        let thread = self.target.thread_info_from_ethread(VirtAddr(ethread))?;
        Ok(ThreadScope::new(&thread))
    }

    /// Replace (or clear) a breakpoint's condition, compiling it with the
    /// default expression grammar.
    pub fn set_breakpoint_condition(&mut self, id: u32, condition: Option<String>) -> Result<()> {
        let compiled = condition
            .as_deref()
            .map(Expr::parse)
            .transpose()?
            .map(Arc::new);
        self.breakpoints.set_condition(id, condition, compiled)
    }

    /// Watch data accesses at `addr` (global across guest address spaces),
    /// with an optional host-resolved display symbol. Hosts choose write or
    /// read/write behavior while the backend implementation remains private.
    /// Returns the stop-point id.
    pub fn add_watchpoint(
        &mut self,
        addr: VirtAddr,
        access: WatchpointAccess,
        len: u8,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        self.breakpoints.add_hardware_configured(
            self.backend.as_mut(),
            &self.target,
            addr,
            access.into(),
            len,
            symbol,
            config,
        )
    }

    /// Remove a breakpoint by id.
    pub fn remove_breakpoint(&mut self, id: u32) -> Result<()> {
        self.breakpoints
            .remove(self.backend.as_mut(), &self.target, id)
    }

    /// Re-arm a disabled breakpoint (re-patch its `int3`).
    pub fn enable_breakpoint(&mut self, id: u32) -> Result<()> {
        self.breakpoints
            .enable(self.backend.as_mut(), &self.target, id)
    }

    /// Disable a breakpoint (restore the original byte) without forgetting it,
    /// so it can be re-enabled later.
    pub fn disable_breakpoint(&mut self, id: u32) -> Result<()> {
        self.breakpoints
            .disable(self.backend.as_mut(), &self.target, id)
    }

    /// List all breakpoints.
    pub fn list_breakpoints(&self) -> Vec<&Breakpoint> {
        self.breakpoints.list()
    }

    /// This session's process-unique identity (see the `id` field).
    pub fn id(&self) -> usize {
        self.id
    }

    /// Return one breakpoint by id.
    pub fn breakpoint(&self, id: u32) -> Option<&Breakpoint> {
        self.breakpoints.list().into_iter().find(|bp| bp.id == id)
    }

    /// Inspect every backend execution context (vCPU): its RIP, the address space
    /// it is running in (kernel / a process / unknown), and the nearest symbol.
    /// Selects each vCPU in turn to read its register file, then restores the
    /// originally-stopped one. The VM must be halted.
    pub fn vcpus(&mut self) -> Result<Vec<VcpuInfo>> {
        let original = self.backend.stopped_thread_id()?;
        let threads = self.backend.thread_list()?;
        let processes = self
            .target
            .guest
            .as_ref()
            .and_then(|g| g.enumerate_processes().ok())
            .unwrap_or_default();
        let dtb_mask = self.target.arch().dtb_page_mask();
        let kernel_dtb_masked = self
            .target
            .guest
            .as_ref()
            .map(|g| g.ntoskrnl.dtb() & dtb_mask);

        let mut out = Vec::with_capacity(threads.len());
        for thread in &threads {
            let regs = self
                .backend
                .set_current_thread(thread)
                .and_then(|_| self.backend.read_registers());
            let regs = match regs {
                Ok(regs) => regs,
                Err(e) => {
                    out.push(VcpuInfo {
                        id: thread.clone(),
                        rip: None,
                        context: String::new(),
                        symbol: None,
                        error: Some(e.to_string()),
                    });
                    continue;
                }
            };
            let (Ok(rip), Ok(dtb)) = (
                self.register_map.read_u64("rip", &regs),
                self.register_map
                    .read_u64(self.target.arch().dtb_register(), &regs),
            ) else {
                out.push(VcpuInfo {
                    id: thread.clone(),
                    rip: None,
                    context: String::new(),
                    symbol: None,
                    error: None,
                });
                continue;
            };

            // RIP=0 means the dump did not capture this CPU's context
            if rip == 0 {
                out.push(VcpuInfo {
                    id: thread.clone(),
                    rip: Some(0),
                    context: "no context".to_string(),
                    symbol: None,
                    error: None,
                });
                continue;
            }

            let dtb_masked = dtb & dtb_mask;
            let (context, symbol) = if kernel_dtb_masked.is_some_and(|k| dtb_masked == k) {
                let sym = self
                    .target
                    .guest
                    .as_ref()
                    .and_then(|g| g.ntoskrnl.closest_symbol(VirtAddr(rip)).ok())
                    .map(|(s, o)| format!("{s}+{o:#x}"));
                ("kernel".to_string(), sym)
            } else {
                match processes.iter().find(|p| (p.dtb & dtb_mask) == dtb_masked) {
                    Some(proc) => {
                        let sym = self
                            .target
                            .symbols
                            .format_closest_symbol_for_address(proc.dtb, VirtAddr(rip));
                        (proc.name.clone(), sym)
                    }
                    None => {
                        let sym = self.target.closest_symbol_current_context(VirtAddr(rip));
                        let ctx = if sym.is_some() { "kernel" } else { "unknown" };
                        (ctx.to_string(), sym)
                    }
                }
            };

            out.push(VcpuInfo {
                id: thread.clone(),
                rip: Some(rip),
                context,
                symbol,
                error: None,
            });
        }

        let _ = self.backend.set_current_thread(&original);
        Ok(out)
    }

    /// Map each *active* Windows thread (one currently scheduled on a vCPU) to
    /// the vCPU running it and its [`ThreadInfo`], keyed by `ETHREAD` address.
    /// Walks every backend vCPU, resolves the Windows thread it is executing,
    /// and restores the originally-stopped vCPU. Best-effort (empty map if the
    /// backend can't enumerate vCPUs).
    pub fn active_thread_map(&mut self) -> HashMap<u64, (String, ThreadInfo)> {
        let Ok(original) = self.backend.stopped_thread_id() else {
            return HashMap::new();
        };
        let Ok(vcpus) = self.backend.thread_list() else {
            return HashMap::new();
        };

        let mut active = HashMap::new();
        for vcpu in &vcpus {
            if self.backend.set_current_thread(vcpu).is_err() {
                continue;
            }
            let Some(processor) = processor_index_from_backend_thread_id(vcpu) else {
                continue;
            };
            if let Ok(thread) = self.target.current_windows_thread_for_processor(processor) {
                active.insert(thread.ethread.0, (vcpu.clone(), thread));
            }
        }

        let _ = self.backend.set_current_thread(&original);
        active
    }

    /// Enumerate all Windows threads, merged with the currently-active threads
    /// (so a thread scheduled on a vCPU but absent from the walk is still
    /// included), sorted by `(pid, tid)`. Returns the threads plus a map of
    /// `ETHREAD -> vCPU id` for those currently running; hosts apply their own
    /// filtering/rendering.
    pub fn windows_threads(&mut self) -> Result<(Vec<ThreadInfo>, HashMap<u64, String>)> {
        let active = self.active_thread_map();
        let mut threads = self.target.enumerate_threads()?;
        for (_, thread) in active.values() {
            if !threads.iter().any(|known| known.ethread == thread.ethread) {
                threads.push(thread.clone());
            }
        }
        threads.sort_by_key(|thread| (thread.pid.unwrap_or(u64::MAX), thread.tid));
        let active_vcpus = active
            .into_iter()
            .map(|(ethread, (vcpu, _))| (ethread, vcpu))
            .collect();
        Ok((threads, active_vcpus))
    }

    /// Read guest virtual memory in the inspection address space
    /// ([`Target::current_dtb`]) with our own breakpoint patch bytes masked
    /// back to the original code, so every host (REPL, MCP, SDK) sees the same
    /// bytes the guest would run.
    pub fn read_masked(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let dtb = self.target.current_dtb();
        self.target.address_space(dtb).read_bytes(addr, buf)?;
        self.breakpoints
            .mask_breakpoint_bytes(&self.target, addr, buf, dtb);
        self.mask_bugcheck_trap(addr, buf);
        Ok(())
    }

    /// Read up to `max_units` NUL-terminated 1- or 2-byte units. The returned
    /// bytes exclude the terminator; a later unreadable page is reported with
    /// the readable prefix, while a failure at the start remains an error.
    pub fn read_terminated(
        &mut self,
        addr: VirtAddr,
        max_units: usize,
        unit: usize,
    ) -> Result<TerminatedRead> {
        if !matches!(unit, 1 | 2) {
            return Err(Error::InvalidArgument(
                "string unit size must be 1 or 2 bytes".to_string(),
            ));
        }
        let max_bytes = max_units
            .checked_mul(unit)
            .ok_or_else(|| Error::InvalidArgument("string length overflows".to_string()))?;
        let mut bytes = Vec::with_capacity(max_bytes.min(PAGE_SIZE));
        let mut unreadable = false;
        while bytes.len() < max_bytes {
            let offset = u64::try_from(bytes.len())
                .map_err(|_| Error::InvalidArgument("string address overflows".to_string()))?;
            let current = addr
                .0
                .checked_add(offset)
                .ok_or_else(|| Error::InvalidArgument("string address overflows".to_string()))?;
            let page_remaining = PAGE_SIZE - VirtAddr(current).page_offset() as usize;
            let chunk_len = page_remaining.min(max_bytes - bytes.len());
            let mut page = [0u8; PAGE_SIZE];
            if let Err(error) = self.read_masked(VirtAddr(current), &mut page[..chunk_len]) {
                if matches!(&error, Error::TargetRunning(_)) {
                    return Err(error);
                }
                if bytes.is_empty() {
                    return Err(error);
                }
                unreadable = true;
                break;
            }

            let first_new_unit = bytes.len() / unit;
            bytes.extend_from_slice(&page[..chunk_len]);
            let complete_units = bytes.len() / unit;
            if let Some(index) = (first_new_unit..complete_units).find(|&index| {
                let start = index * unit;
                bytes[start..start + unit].iter().all(|byte| *byte == 0)
            }) {
                bytes.truncate(index * unit);
                return Ok(TerminatedRead {
                    bytes,
                    unreadable: false,
                });
            }
        }
        bytes.truncate(bytes.len() - bytes.len() % unit);
        Ok(TerminatedRead { bytes, unreadable })
    }

    /// Read as much of `buf` as the guest will give with [`Self::read_masked`],
    /// one page-sized chunk at a time, returning how many leading bytes are
    /// valid. Chunks are relative to `addr`, so an unmapped page truncates the
    /// read at the request's own granularity rather than at a page boundary.
    pub fn read_masked_partial(&self, addr: VirtAddr, buf: &mut [u8]) -> usize {
        if self.read_masked(addr, buf).is_ok() {
            return buf.len();
        }
        const CHUNK: usize = 0x1000;
        let mut read = 0;
        while read < buf.len() {
            let end = (read + CHUNK).min(buf.len());
            let chunk_address = VirtAddr(addr.0.wrapping_add(read as u64));
            if self
                .read_masked(chunk_address, &mut buf[read..end])
                .is_err()
            {
                break;
            }
            read = end;
        }
        read
    }

    /// Put the bugcheck trap's displaced instruction back into a read that
    /// covers it. The trap is not one of the manager's breakpoints, so the
    /// manager cannot mask it, and without this `u nt!KeBugCheckEx` shows the
    /// debugger's own trap instead of the guest's code.
    fn mask_bugcheck_trap(&self, start: VirtAddr, buf: &mut [u8]) {
        let Some(address) = self.bugcheck_trap else {
            return;
        };
        if self.bugcheck_trap_original.is_empty() || address.0 < start.0 {
            return;
        }
        let offset = (address.0 - start.0) as usize;
        let end = offset + self.bugcheck_trap_original.len();
        if end <= buf.len() {
            buf[offset..end].copy_from_slice(&self.bugcheck_trap_original);
        }
    }

    /// Disassemble `count` instructions starting at `addr` in the current
    /// address space. Our own breakpoint `int3` bytes are masked back to the
    /// original opcode, and branch / rip-relative targets get symbol comments.
    pub fn disassemble(&self, addr: VirtAddr, count: usize) -> Result<Vec<DisasmRow>> {
        let dtb = self.target.current_dtb();

        // x86-64 instructions are at most 15 bytes; ARM64 is fixed 4 bytes.
        // Over-read so `count` decode.
        let overread = match self.target.arch() {
            Arch::Amd64 => count * 16,
            Arch::Arm64 => count * 4,
        };
        let mut buf = vec![0u8; overread];
        self.read_masked(addr, &mut buf)?;

        let symbols = &self.target.symbols;
        let resolve = |target: u64| {
            symbols
                .format_closest_symbol_for_address(dtb, VirtAddr(target))
                .unwrap_or_default()
        };
        let bitness = self.target.code_bitness(addr);
        match self.target.arch() {
            Arch::Amd64 => {
                let mut formatter = disasm_formatter();
                Ok(decode_rows(
                    &buf,
                    addr.0,
                    Some(count),
                    bitness,
                    &mut formatter,
                    resolve,
                ))
            }
            Arch::Arm64 => Ok(decode_rows_arm64(&buf, addr.0, Some(count), resolve)),
        }
    }

    /// Disassemble the runtime function containing `addr`. Returns its start
    /// symbol, byte length, and decoded rows.
    pub fn disassemble_function(&self, addr: VirtAddr) -> Result<(String, usize, Vec<DisasmRow>)> {
        let dtb = self.target.current_dtb();
        let trace = resolve_thread_trace_context(&self.target, dtb);
        let Some((start, end)) = function_range(&self.target, &trace, addr.0) else {
            return Err(Error::DebugInfo(format!(
                "no runtime-function entry contains {:#x}",
                addr.0
            )));
        };
        let len = end
            .checked_sub(start)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or_else(|| {
                Error::DebugInfo(format!("invalid function range {start:#x}..{end:#x}"))
            })?;
        const MAX_FUNCTION_BYTES: usize = 1024 * 1024;
        if len == 0 || len > MAX_FUNCTION_BYTES {
            return Err(Error::DebugInfo(format!(
                "refusing invalid function size {len:#x} bytes"
            )));
        }

        let mut bytes = vec![0u8; len];
        self.read_masked(VirtAddr(start), &mut bytes)?;
        let resolve = |target| format_symbol(&self.target, &trace, target);
        let bitness = self.target.code_bitness(VirtAddr(start));
        let rows = match self.target.arch() {
            Arch::Amd64 => {
                let mut formatter = disasm_formatter();
                decode_rows(&bytes, start, None, bitness, &mut formatter, resolve)
            }
            Arch::Arm64 => decode_rows_arm64(&bytes, start, None, resolve),
        };
        Ok((format_symbol(&self.target, &trace, start), len, rows))
    }

    /// Disassemble the instructions ending at `addr`. Missing pages before
    /// the readable suffix are skipped.
    pub fn disassemble_back(&self, addr: VirtAddr, count: usize) -> Result<Vec<DisasmRow>> {
        if count == 0 {
            return Err(Error::InvalidArgument(
                "instruction count must be greater than zero".to_string(),
            ));
        }
        let arch = self.target.arch();
        let max_bytes = count.saturating_mul(max_instruction_bytes(arch));
        let start = VirtAddr(addr.0.saturating_sub(max_bytes as u64));
        let length = usize::try_from(addr.0 - start.0).unwrap_or(max_bytes);
        let (data, valid) =
            read_page_chunks(start, length, |address, buf| self.read_masked(address, buf))?;
        let readable_suffix_start = valid
            .iter()
            .rposition(|readable| !readable)
            .map_or(0, |last_unreadable| last_unreadable + 1);
        let mut suffix_len = length - readable_suffix_start;
        if arch == Arch::Arm64 {
            suffix_len -= suffix_len % 4;
        }
        let suffix_offset = length.saturating_sub(suffix_len);
        let read_start = start.0 + suffix_offset as u64;
        let bytes = &data[suffix_offset..];
        if bytes.is_empty() {
            return Err(Error::DebugInfo(format!(
                "could not read memory before {:#x}",
                addr.0
            )));
        }

        let dtb = self.target.current_dtb();
        let trace = resolve_thread_trace_context(&self.target, dtb);
        let bitness = self.target.code_bitness(addr);
        decode_preceding(arch, bytes, read_start, addr.0, count, bitness, |target| {
            format_symbol(&self.target, &trace, target)
        })
        .ok_or_else(|| {
            Error::DebugInfo(format!(
                "could not decode instructions ending at {:#x}",
                addr.0
            ))
        })
    }

    /// The current backend context's call stack with the sparse registers
    /// recovered for every frame, plus the seed register file the walk started
    /// from. A parked Windows thread is walked from its saved context without
    /// touching the backend vCPU.
    pub fn recovered_backtrace(
        &mut self,
        limit: usize,
    ) -> Result<(RecoveredStackTrace, HashMap<String, u64>)> {
        if let Some(thread) = self.parked_windows_thread() {
            let recovered = build_parked_thread_recovered_stack(&self.target, thread, limit)?;
            // The walk's own first frame is the only register context a parked
            // thread has; there is no live file to seed from.
            let seed = recovered
                .stacktrace
                .frames
                .first()
                .map(|frame| frame.registers.clone())
                .unwrap_or_default();
            return Ok((recovered.stacktrace, seed));
        }

        let registers = self.read_registers()?;
        let seed = self.register_map.to_hashmap(&registers);
        let recovered =
            build_stacktrace_with_context(&self.target, &self.register_map, &registers, limit);
        Ok((recovered, seed))
    }

    /// Walk the currently selected backend context's call stack, returning up to
    /// `limit` frames. A parked Windows thread uses stack-only recovery without
    /// touching the backend vCPU.
    pub fn backtrace(&mut self, limit: usize) -> Result<StackTrace> {
        let (recovered, _) = self.recovered_backtrace(limit)?;
        Ok(StackTrace {
            frames: recovered
                .frames
                .into_iter()
                .map(|frame| frame.frame)
                .collect(),
            truncated: recovered.truncated,
        })
    }

    /// Unwind a specified non-running Windows thread in its owning process
    /// address space without selecting it or mutating the backend vCPU.
    pub fn backtrace_thread(&self, thread: &ThreadInfo, limit: usize) -> Result<ThreadStackTrace> {
        build_parked_thread_stack(&self.target, thread, limit)
    }

    /// Uninstall every breakpoint. Successful removals are forgotten; failed
    /// removals remain managed so callers can retry and must not resume the
    /// target as if cleanup had succeeded.
    pub fn remove_all_breakpoints(&mut self) -> Result<()> {
        self.breakpoints
            .remove_all(self.backend.as_mut(), &self.target)
    }

    /// Whether any debugger-owned site is installed in the guest. The
    /// bugcheck trap is not one of the manager's breakpoints, so a caller
    /// asking whether there is anything to restore has to ask for both.
    pub fn has_installed_sites(&self) -> bool {
        !self.breakpoints.list().is_empty() || self.bugcheck_trap.is_some()
    }

    /// Take the automatic bugcheck trap back out of the guest.
    ///
    /// Nothing else does: it is not one of the manager's breakpoints, and a
    /// GDB stub leaves the `int3` it wrote in guest memory when the
    /// connection closes. Left behind, it is executed by the next thread to
    /// reach `nt!KeBugCheckEx` with no debugger attached.
    pub fn disarm_bugcheck_trap(&mut self) -> Result<()> {
        let Some(address) = self.bugcheck_trap else {
            return Ok(());
        };
        self.backend.remove_breakpoint(address.0)?;
        self.bugcheck_trap = None;
        self.bugcheck_trap_original.clear();
        Ok(())
    }

    /// Leave the target in a usable state when a frontend exits: halt first if
    /// needed, restore every debugger-owned breakpoint site, and resume only
    /// when both operations succeed. Any failure explicitly prepares the
    /// backend to leave the target halted.
    pub fn cleanup_for_exit(&mut self) -> Result<()> {
        // Halting is only for restoring sites; with none to restore a passive
        // backend (which cannot interrupt) exits cleanly too.
        let halted = if self.backend.is_running() && self.has_installed_sites() {
            self.interrupt().map(|_| ())
        } else {
            Ok(())
        };
        if halted.is_err() {
            return prepare_backend_after_cleanup(self.backend.as_mut(), halted);
        }

        let cleanup = self
            .remove_all_breakpoints()
            .and_then(|()| self.disarm_bugcheck_trap());
        prepare_backend_after_cleanup(self.backend.as_mut(), cleanup)
    }

    /// Resume the VM. If sitting on one of our breakpoints, step past it first
    /// (otherwise the `int3` at RIP re-fires immediately), re-arm enabled
    /// breakpoints, then continue and drop the now-stale inspection caches.
    /// The canonical resume prologue, shared by the REPL and the SDK.
    ///
    /// Does not poll for Ctrl+C or handle KD target-reload/reconnect the way the
    /// REPL's continue loop does; those remain REPL concerns.
    pub fn resume(&mut self) -> Result<()> {
        self.resume_with_disposition(ContinueDisposition::Handled)
    }

    /// Ask the guest's own debugger worker to fault a page in, and wait for it
    /// to report back.
    ///
    /// The kernel exposes this as three globals plus a flag. `KdExitDebugger`
    /// runs on our own resume and calls `ExQueueDebuggerWorker`, which
    /// compare-exchanges `ExpDebuggerWork` from 1 to 2 and queues a DPC; the
    /// resulting work item runs `ExpDebuggerWorker`, which attaches to
    /// `ExpDebuggerProcessAttach`, calls `MmPrefetchVirtualMemory` on
    /// `ExpDebuggerPageIn`, and breaks in with `DbgBreakPointWithStatus(7)`
    /// (`DBG_STATUS_WORKER`).
    ///
    /// Two consequences the caller cannot be shielded from: the target has to
    /// **run** for the worker thread to be scheduled, and it comes back halted
    /// at the worker rather than wherever it was. The worker zeroes all three
    /// globals before doing any of the work, so an abandoned request leaves
    /// nothing armed.
    pub fn page_in(&mut self, address: VirtAddr, process: Option<u64>) -> Result<PageInReport> {
        let worker_break = self.page_in_globals(address, process)?;
        // The worker signals completion at the same address KD break-ins land
        // on, which the transport would otherwise dismiss as its own noise.
        self.backend.surface_next_break_at(Some(worker_break.0));
        self.resume()?;
        let cancel = AtomicBool::new(false);
        let outcome = self.wait_for_stop_bounded(Some(PAGE_IN_TIMEOUT), &cancel);
        self.backend.surface_next_break_at(None);
        match outcome? {
            ContinueOutcome::Running => Err(Error::DebugInfo(format!(
                "the debugger worker did not report within {}s; the target is still running",
                PAGE_IN_TIMEOUT.as_secs()
            ))),
            _ => Ok(self.page_in_result(address, worker_break)),
        }
    }

    /// Arm the worker request. Every global is kernel data, so a mediated
    /// virtual write reaches it under any process context.
    fn page_in_globals(&mut self, address: VirtAddr, process: Option<u64>) -> Result<VirtAddr> {
        let dtb = self.target.kernel_dtb();
        let symbol = |name: &str| -> Result<VirtAddr> {
            self.target
                .symbols
                .find_symbol_with_module(dtb, name)?
                .map(|(address, _)| address)
                .ok_or_else(|| {
                    Error::DebugInfo(format!(
                        "{name} is not in the kernel's symbols; .pagein needs ntoskrnl symbols"
                    ))
                })
        };
        let attach_global = symbol("nt!ExpDebuggerProcessAttach")?;
        let page_in_global = symbol("nt!ExpDebuggerPageIn")?;
        let work_global = symbol("nt!ExpDebuggerWork")?;
        let worker_break = symbol("nt!DbgBreakPointWithStatus")?;

        let memory = self.target.kernel_address_space();
        memory.write_bytes(attach_global, &process.unwrap_or(0).to_le_bytes())?;
        memory.write_bytes(page_in_global, &address.0.to_le_bytes())?;
        // Exactly 1: `ExQueueDebuggerWorker` compare-exchanges 1 to 2, so any
        // other non-zero value is ignored and the worker never runs.
        memory.write_bytes(work_global, &1u32.to_le_bytes())?;
        Ok(worker_break)
    }

    /// Classify the stop the wait produced and probe the requested page.
    fn page_in_result(&mut self, address: VirtAddr, worker_break: VirtAddr) -> PageInReport {
        let registers = self.backend.read_registers().ok();
        let pc = registers
            .as_ref()
            .and_then(|regs| self.register_map.read_u64("rip", regs).ok());
        let first_argument = match self.target.arch() {
            Arch::Amd64 => "rcx",
            Arch::Arm64 => "x0",
        };
        let status = registers
            .as_ref()
            .and_then(|regs| self.register_map.read_u64(first_argument, regs).ok());
        // `DbgBreakPointWithStatus` takes its status in the first argument
        // register, so a worker break is distinguishable from any other
        // hard-coded break at the same address.
        let from_worker = pc == Some(worker_break.0) && status == Some(DBG_STATUS_WORKER);
        let mut probe = [0u8; 1];
        let resident = self
            .target
            .address_space(self.target.current_dtb())
            .read_bytes(address, &mut probe)
            .is_ok();
        PageInReport {
            from_worker,
            resident,
        }
    }

    /// Clear every inspection cache that cannot survive a crash/reboot command
    /// before the shared wait loop re-establishes the next stop.
    pub fn clear_resume_state(&mut self) {
        self.target.selected_frame = None;
        self.target.registers = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        self.target.last_exception_code = None;
        self.parked_windows_thread = None;
        self.parked_stop = None;
        self.current_stop = None;
        self.module_refresh_report = None;
    }

    /// Request a target reboot and clear register/context state before its
    /// reload stop is collected.
    pub fn request_reboot(&mut self) -> Result<()> {
        self.backend.reboot_target()?;
        self.clear_resume_state();
        Ok(())
    }

    /// Request a target bugcheck and clear register/context state before the
    /// resulting stop is collected.
    pub fn request_crash(&mut self) -> Result<()> {
        self.backend.cause_bugcheck()?;
        self.clear_resume_state();
        Ok(())
    }

    /// Resume with an explicit exception acknowledgment while preserving the
    /// same breakpoint step-over and cache invalidation prologue as [`Self::resume`].
    pub fn resume_with_disposition(&mut self, disposition: ContinueDisposition) -> Result<()> {
        self.target.selected_frame = None;
        self.module_refresh_report = None;
        // A bugcheck can only happen while the guest runs, so the trap has to
        // be in place before it does. Arming on stop alone would miss a crash
        // provoked immediately after attach.
        self.arm_bugcheck_trap();
        if self.parked_windows_thread().is_some() {
            self.parked_windows_thread = None;
            self.target.clear_current_windows_thread_context();
            self.refresh_context_for_current_thread();
        }
        // The VM is moving on, so any stop `service_idle` parked for the host to
        // observe is now spent; drop it so a later `wait_for_stop` doesn't replay
        // a stale event.
        self.parked_stop = None;
        self.current_stop = None;
        // If a post-reboot rediscovery is still pending only because the module
        // list wasn't up yet, finish it from memory before continuing. We are
        // halted, so the next `continue` starts the pump with the reconnect-assist
        // poking already off, instead of resuming into another forced break-in.
        self.try_finish_rediscovery_from_memory();
        if self.breakpoints.has_enabled_breakpoints() {
            self.backend.set_current_thread(&self.current_thread)?;
            step_over_current_breakpoint(
                self.backend.as_mut(),
                &self.register_map,
                &self.target,
                &mut self.breakpoints,
            )?;
        }
        for id in self.breakpoints.one_shot_hit_ids() {
            self.breakpoints
                .remove(self.backend.as_mut(), &self.target, id)?;
        }

        self.breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.continue_backend(disposition)?;
        self.record_continuation_disposition(disposition);

        Ok(())
    }

    /// Continue without user-command preparation (breakpoint refresh/step-over),
    /// but with the same inspection lifetime as an explicit resume.
    fn continue_backend(&mut self, disposition: ContinueDisposition) -> Result<()> {
        self.backend
            .continue_execution_with_disposition(disposition)?;
        self.invalidate_running_context();
        Ok(())
    }

    /// No stopped inspection view survives a successful continuation, including
    /// one performed internally while absorbing a breakpoint or notification.
    fn invalidate_running_context(&mut self) {
        self.target.selected_frame = None;
        self.target.registers = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        self.parked_windows_thread = None;
    }

    /// Classify a freshly observed stop at (`rip`, `cr3`) against our breakpoints,
    /// performing the absorb actions the caller shouldn't have to: a false
    /// conditional breakpoint or a wrong-process hit on a shared-page int3 is
    /// stepped over and resumed, returning [`BreakpointStopAction::Resumed`]. A
    /// real hit re-arms enabled breakpoints (the stub can drop non-hit ones on a
    /// stop) and returns its details. The caller must have read registers and
    /// established (`rip`, `cr3`) for the stopped thread first.
    ///
    /// Shared by [`Self::continue_until_break`] and the REPL's continue loop so
    /// they can't drift on which int3 hits surface and which are silently resumed.
    pub fn resolve_breakpoint_stop(&mut self, rip: u64, cr3: u64) -> Result<BreakpointStopAction> {
        match self
            .breakpoints
            .check_breakpoint_hit(rip, cr3, self.target.arch())
        {
            BreakpointHitResult::Hit(bp) => {
                // A thread filter is resolved here rather than in the hit
                // predicate: the predicate matches on the address space,
                // which is known from the registers, while the Windows thread
                // costs a KPRCB walk that only a filtered breakpoint owes.
                if !self.stopped_thread_matches(bp.thread.as_ref())
                    || !stopped_processor_matches(bp.processor, &self.current_thread)
                {
                    self.step_over_and_resume()?;
                    return Ok(BreakpointStopAction::Resumed);
                }
                // Count every scoped physical hit before pass-count and
                // condition evaluation. A pass skip uses the same canonical
                // step-over/resume path as a false condition.
                if self.breakpoints.record_hit(bp.id)? == BreakpointHitDisposition::SkipPass {
                    self.step_over_and_resume()?;
                    return Ok(BreakpointStopAction::Resumed);
                }
                // A false condition is absorbed. Evaluation errors fail safe:
                // surface the stop and carry the error to every host.
                let condition_error = match bp.evaluate_condition(&self.target) {
                    Ok(false) => {
                        self.step_over_and_resume()?;
                        return Ok(BreakpointStopAction::Resumed);
                    }
                    Ok(true) => None,
                    Err(error) => Some(error.to_string()),
                };

                // The stub can drop non-hit breakpoints when the VM stops; re-arm
                // so they survive the next resume.
                if let Err(error) = self
                    .breakpoints
                    .refresh_enabled(self.backend.as_mut(), &self.target)
                {
                    self.notices.push(format!(
                        "failed to re-arm breakpoints at this stop: {error}"
                    ));
                }

                self.breakpoints.mark_one_shot_hit(bp.id)?;
                Ok(BreakpointStopAction::Hit {
                    breakpoint: bp,
                    condition_error,
                })
            }
            BreakpointHitResult::NotBreakpoint => {
                // Wrong-process hit on a shared-page int3 (the BP is scoped to a
                // different address space): silently step over so the wrong
                // process keeps running, then resume waiting for the right one.
                if self.breakpoints.breakpoint_id_at_address(rip).is_some() {
                    self.step_over_and_resume()?;
                    return Ok(BreakpointStopAction::Resumed);
                }

                Ok(BreakpointStopAction::NotBreakpoint)
            }
        }
    }

    /// Whether the thread this stop belongs to is the one a `/t` breakpoint
    /// was restricted to. Unfiltered breakpoints always match.
    fn stopped_thread_matches(&mut self, thread: Option<&ThreadScope>) -> bool {
        let Some(scope) = thread else {
            return true;
        };
        let current = self.current_thread.clone();
        let stopped = refresh_windows_thread_context_for_backend_thread(&mut self.target, &current);
        scope.matches(stopped.as_ref())
    }

    /// Silently continue past the breakpoint at the PC: step over it, rewrite
    /// whatever sites the stop dropped, and resume without surfacing anything.
    fn step_over_and_resume(&mut self) -> Result<()> {
        step_over_current_breakpoint(
            self.backend.as_mut(),
            &self.register_map,
            &self.target,
            &mut self.breakpoints,
        )?;
        self.breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.continue_backend(ContinueDisposition::Handled)
    }

    /// Consult and clear the module-change signals, reconciling symbolic
    /// breakpoints when the module set moved. Returns whether it moved. The KD
    /// event signal and the per-stop module-list refresh are joined here so all
    /// hosts share the same deferred-breakpoint behavior; refresh and
    /// reconciliation failures are logged and do not discard the stop.
    pub fn refresh_modules_on_stop(&mut self) -> bool {
        let event_changed = self.backend.take_modules_changed()
            | std::mem::take(&mut self.unreported_module_change);
        let symbols_changed = match self.target.refresh_kernel_module_symbols() {
            Ok(report) => {
                let changed = report.loaded != 0 || report.unloaded != 0;
                if changed {
                    self.module_refresh_report = Some(report);
                }
                changed
            }
            Err(error) => {
                self.notices.push(format!(
                    "failed to refresh module symbols after module change: {error}"
                ));
                false
            }
        };
        let modules_changed = event_changed || symbols_changed;
        if modules_changed {
            self.reconcile_deferred_breakpoints();
        } else {
            self.reconcile_breakpoints_if_symbols_changed();
        }
        modules_changed
    }

    /// Re-resolve deferred (`bu`/source) breakpoints if any module's symbols
    /// became available since the last reconcile, whoever loaded them: a
    /// background fetch started by a stop render, a lazy frame load, or a
    /// process attach. Installing a site needs the target halted, so a running
    /// target waits for its next stop. Hosts call this after a command that
    /// may have loaded symbols; the stop path calls it on every stop.
    pub fn reconcile_breakpoints_if_symbols_changed(&mut self) {
        if self.target.symbols.load_generation() == self.symbols_reconciled_at
            || self.backend.is_running()
        {
            return;
        }
        self.reconcile_deferred_breakpoints();
    }

    fn reconcile_deferred_breakpoints(&mut self) {
        // Read before reconciling: a fetch landing mid-reconcile is caught
        // next time rather than missed.
        self.symbols_reconciled_at = self.target.symbols.load_generation();
        if let Err(error) = self
            .breakpoints
            .reconcile_symbolic_after_module_refresh(self.backend.as_mut(), &self.target)
        {
            self.notices.push(format!(
                "failed to reconcile breakpoints after module refresh: {error}"
            ));
        }
    }

    /// Take the latest module-symbol report for the REPL's existing summary.
    /// The report is private to the REPL's summary path.
    pub fn take_module_refresh_report(&mut self) -> Option<ModuleSymbolLoadReport> {
        self.module_refresh_report.take()
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

    /// Classify one raw backend stop and perform every core-owned transition.
    ///
    /// This is the only stop-ingestion state machine. REPL, MCP, Python, and
    /// idle servicing may differ in polling and presentation, but must route
    /// raw events here so reload handling, DR acknowledgment, scope checks,
    /// `int3` rewind, conditions, and auto-resume behavior cannot drift.
    pub fn classify_stop_event(&mut self, mut event: StopEvent) -> Result<StopResolution> {
        self.target.selected_frame = None;
        set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);
        // A GDB stop reply names the thread but not its PC. Without one the
        // reboot heuristic cannot tell a stop in a relocated kernel from an
        // ordinary one, so read it from the thread the stop selected.
        if event.program_counter.is_none() {
            event.program_counter = self
                .backend
                .read_registers()
                .ok()
                .and_then(|regs| self.register_map.read_u64("rip", &regs).ok());
        }
        self.record_stop_event(&event);

        if event.is_bugcheck && !event.target_reloaded {
            self.target.registers = None;
            let resolution = StopResolution::Bugcheck { event };
            self.record_visible_stop(&resolution);
            return Ok(resolution);
        }

        match self.classify_reload_stop(&mut event)? {
            disposition @ (ReloadDisposition::Reloaded { .. }
            | ReloadDisposition::ReloadCompleted) => {
                let coherent =
                    !matches!(disposition, ReloadDisposition::Reloaded { coherent: false });
                self.refresh_context_for_current_thread();
                let resolution = StopResolution::TargetReloaded { event, coherent };
                self.record_visible_stop(&resolution);
                return Ok(resolution);
            }
            ReloadDisposition::PendingRediscovery | ReloadDisposition::ResumePastAssist => {
                self.continue_backend(ContinueDisposition::Handled)?;
                return Ok(StopResolution::Resumed);
            }
            ReloadDisposition::Ordinary => {}
        }

        if event.modules_changed {
            self.unreported_module_change = self.refresh_modules_on_stop();
            self.continue_backend(ContinueDisposition::Handled)?;
            return Ok(StopResolution::ModulesChanged);
        }

        match resolve_watchpoint_stop(
            self.backend.as_mut(),
            &self.register_map,
            &mut self.breakpoints,
            &mut self.target,
            &mut self.current_thread,
            &event,
        )? {
            WatchpointStopAction::Hit {
                breakpoint,
                condition_error,
            } => {
                let rip = self
                    .target
                    .registers
                    .as_ref()
                    .and_then(|registers| registers.get("rip").copied())
                    .unwrap_or(0);
                let resolution = StopResolution::Breakpoint {
                    breakpoint: Box::new(breakpoint),
                    event,
                    rip,
                    condition_error,
                };
                self.record_visible_stop(&resolution);
                return Ok(resolution);
            }
            WatchpointStopAction::Resumed => {
                self.invalidate_running_context();
                return Ok(StopResolution::Resumed);
            }
            WatchpointStopAction::NotBreakpoint => {}
        }

        if stop_is_stray_single_step(&event, &self.breakpoints) {
            let _ = clear_trap_flag(self.backend.as_mut(), &self.register_map);
            self.continue_backend(ContinueDisposition::Handled)?;
            return Ok(StopResolution::Resumed);
        }

        if event.exception_code == Some(STATUS_BREAKPOINT)
            && self.breakpoints.has_enabled_breakpoints()
        {
            rewind_thread_off_breakpoint(
                self.backend.as_mut(),
                &self.register_map,
                &self.breakpoints,
                self.target.arch(),
            );
        }

        let registers = self.backend.read_registers()?;
        let rip = self.register_map.read_u64("rip", &registers).unwrap_or(0);
        let cr3 = self
            .register_map
            .read_u64(self.target.arch().dtb_register(), &registers)
            .unwrap_or(0);
        update_target_context_from_registers(&mut self.target, &self.register_map, Ok(registers));

        if self.bugcheck_trap == Some(VirtAddr(rip)) {
            event.is_bugcheck = true;
            event.bugcheck = self.bugcheck_from_trap();
            // Re-record: the event was stored before the trap enriched it,
            // and `.lastevent` and `!analyze` both read it back.
            self.record_stop_event(&event);
            let resolution = StopResolution::Bugcheck { event };
            self.record_visible_stop(&resolution);
            return Ok(resolution);
        }

        let resolution = match self.resolve_breakpoint_stop(rip, cr3)? {
            BreakpointStopAction::Hit {
                breakpoint,
                condition_error,
            } => StopResolution::Breakpoint {
                breakpoint: Box::new(breakpoint),
                event,
                rip,
                condition_error,
            },
            BreakpointStopAction::Resumed => StopResolution::Resumed,
            BreakpointStopAction::NotBreakpoint => StopResolution::Stopped { event, rip },
        };
        self.record_visible_stop(&resolution);
        Ok(resolution)
    }

    /// Resume the VM (unless already running, in which case no exception
    /// acknowledgment is sent) with `disposition`, then wait up to `timeout`
    /// for a meaningful stop; wrong-process int3 hits and false conditional
    /// breakpoints are stepped over silently. `None` waits indefinitely;
    /// `cancel` or an elapsed timeout returns [`ContinueOutcome::Running`]
    /// with the VM left running. Non-resuming observation is
    /// [`Self::wait_for_stop_bounded`].
    pub fn continue_until_break(
        &mut self,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
        disposition: ContinueDisposition,
    ) -> Result<ContinueOutcome> {
        if !self.backend.is_running() {
            self.resume_with_disposition(disposition)?;
        }
        self.wait_for_stop_bounded(timeout, cancel)
    }

    /// Wait up to `timeout` for the next meaningful stop **without resuming**:
    /// drains a held stop, drives the reboot / breakpoint classification, absorbs
    /// debugger noise (assist break-ins, stray single-steps, wrong-process and
    /// false-condition hits), and returns the stop worth surfacing (or
    /// [`ContinueOutcome::Running`] on timeout/cancel). Because it never resumes, a
    /// caller already halted at an interesting site (e.g. the early-boot reload)
    /// observes it in place instead of blowing past it; that separation is why
    /// the MCP surface splits resume from wait.
    pub fn wait_for_stop_bounded(
        &mut self,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        // A stop `service_idle` caught and parked while the host was idle is
        // the proper event for this wait: surface it before waiting for a new
        // one, so every host (not just one) sees it as its real event.
        if let Some(parked) = self.parked_stop.take() {
            return Ok(parked);
        }
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Ok(ContinueOutcome::Running);
            }
            // Wait one poll interval at a time so `cancel` and the deadline stay
            // responsive; an indefinite wait (`deadline == None`) just keeps going.
            let poll = match deadline {
                Some(dl) => {
                    let remaining = dl.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(ContinueOutcome::Running);
                    }
                    remaining.min(CONTINUE_POLL_INTERVAL)
                }
                None => CONTINUE_POLL_INTERVAL,
            };

            let event = match self.backend.try_wait_for_stop(poll)? {
                Some(event) => event,
                None => {
                    // Halted with nothing pending: report the park instead of
                    // spinning out the timeout.
                    if !self.backend.is_running() {
                        // Flush a reload nobody surfaced before reporting a plain halt.
                        if self.reload_surface_pending {
                            self.reload_surface_pending = false;
                            return Ok(ContinueOutcome::TargetReloaded {
                                rip: self
                                    .last_event
                                    .as_ref()
                                    .and_then(|last| last.stop.program_counter),
                                kernel_base: self.target.kernel_base().map(|a| a.0),
                                coherent: self.kernel_coherent(),
                            });
                        }
                        let rip = self
                            .backend
                            .read_registers()
                            .ok()
                            .and_then(|regs| self.register_map.read_u64("rip", &regs).ok())
                            .unwrap_or(0);
                        return Ok(ContinueOutcome::Halted { rip });
                    }
                    continue;
                }
            };
            match self.classify_stop_event(event)? {
                StopResolution::Resumed | StopResolution::ModulesChanged => continue,
                resolution @ StopResolution::TargetReloaded { coherent, .. } => {
                    reload_trace!(
                        "continue: SURFACE target_reloaded base={} coherent={}",
                        self.target.kernel_base().map_or_else(
                            || "none".to_string(),
                            |address| format!("{:#x}", address.0)
                        ),
                        coherent,
                    );
                    return Ok(self.continue_outcome_from_resolution(resolution));
                }
                StopResolution::Stopped { event, .. }
                    if let ExceptionPolicyAction::Continue {
                        disposition,
                        command: None,
                        ..
                    } = self.exception_policies.action_for(&event) =>
                {
                    // A policy with a command needs the REPL to run it, so it
                    // surfaces here; the command-free ones are pure run control.
                    self.continue_backend(disposition)?;
                    self.record_continuation_disposition(disposition);
                    continue;
                }
                resolution => return Ok(self.continue_outcome_from_resolution(resolution)),
            }
        }
    }

    /// Block until the backend produces a meaningful stop, routing every raw
    /// event through [`Self::classify_stop_event`]. Filtered breakpoint hits and
    /// debugger noise are resumed internally.
    pub fn wait_for_stop(&mut self) -> Result<StopEvent> {
        loop {
            let event = self.backend.wait_for_stop()?;
            match self.classify_stop_event(event)? {
                StopResolution::Resumed | StopResolution::ModulesChanged => continue,
                StopResolution::Breakpoint { event, .. }
                | StopResolution::Bugcheck { event }
                | StopResolution::TargetReloaded { event, .. }
                | StopResolution::Stopped { event, .. } => return Ok(event),
            }
        }
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
    fn try_finish_rediscovery_from_memory(&mut self) {
        if !self.reload_surface_pending {
            let _ = self.try_complete_pending_reload();
        }
    }

    /// Clear a deferred reboot notification once the host has already observed
    /// or acted on the rebuilt target. Leave it pending if the current kernel
    /// mapping still looks stale, so a later wait can surface the real reload.
    fn clear_deferred_reload_surface(&mut self) {
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
    fn classify_reload_stop(&mut self, event: &mut StopEvent) -> Result<ReloadDisposition> {
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
}

/// Per-target guard that one ntoseye session owns a given backend resource at a
/// time; a second attach against the same target would corrupt both. Held
/// inside [`Session`] for its lifetime (see [`Session::connect`]); dropping it
/// releases the lock.
struct InstanceGuard(#[allow(dead_code)] SingleInstance);

/// Take the single-instance lock for `target`, or [`Error::AlreadyRunning`] if
/// another ntoseye already holds it. `target` is the backend resource identifier
/// (socket path, address, dump file) so instances on *different* targets can
/// coexist. Internal to [`Session::connect`], which calls it before connecting
/// a backend so a second instance fails fast rather than racing on the transport
/// handshake.
fn acquire_instance_guard(target: &str) -> Result<InstanceGuard> {
    let canonical = canonicalize_target(target);
    let key = format!("ntoseye-{:016x}", fnv1a_64(canonical.as_bytes()));
    // macOS backs the lock with a flock file at this path; keep it out of cwd.
    #[cfg(target_os = "macos")]
    let key = std::env::temp_dir().join(&key).display().to_string();
    let instance = SingleInstance::new(&key).map_err(|err| {
        Error::DebugInfo(format!("failed to create single-instance guard: {err:?}"))
    })?;
    if !instance.is_single() {
        return Err(Error::AlreadyRunning(canonical));
    }
    Ok(InstanceGuard(instance))
}

/// Normalize a target identifier for lock-key stability: equivalent targets
/// must produce the same canonical string. Existing filesystem entries
/// (sockets, files) are resolved first so that different relative paths to
/// the same socket produce the same key.
fn canonicalize_target(target: &str) -> String {
    if let Some(normalized) = normalize_host_port(target) {
        return normalized;
    }
    let path = std::path::Path::new(target);
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon.to_string_lossy().into_owned();
    }
    let full = if path.is_relative() {
        std::env::current_dir().unwrap_or_default().join(path)
    } else {
        path.to_path_buf()
    };
    let mut out = std::path::PathBuf::new();
    for component in full.components() {
        match component {
            std::path::Component::RootDir => out.push("/"),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(s) => out.push(s),
            _ => {}
        }
    }
    out.to_string_lossy().into_owned()
}

/// Detect `host:port` targets and normalize the host component so that
/// `localhost:1234` and `127.0.0.1:1234` map to the same lock key.
fn normalize_host_port(target: &str) -> Option<String> {
    let (host, port_str) = target.rsplit_once(':')?;
    if host.contains('/') {
        return None;
    }
    // Reject bare (unbracketed) IPv6 because the host part would contain extra
    // colons (e.g. "fe80:" from "fe80::5678").
    if host.contains(':') && !host.starts_with('[') {
        return None;
    }
    let _port: u16 = port_str.parse().ok()?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let host = match host.as_str() {
        "localhost" | "ip6-localhost" | "::1" => "127.0.0.1",
        other => other,
    };
    Some(format!("{host}:{port_str}"))
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// What to tell the operator when every memory access goes over KD. An
/// emulated UART hands the guest one byte per hypervisor main-loop iteration,
/// so every request costs milliseconds; KDNET has no such floor.
fn kd_memory_source_notice(backend_name: &str) -> String {
    match backend_name {
        "kdnet" => "kdnet: memory source kd; remote reads may be slow.".to_string(),
        name => format!(
            "{name}: memory source kd; prefer --memory-source host if the VM is local, or KDNET"
        ),
    }
}

/// Parse a backend vCPU/thread id into a zero-based processor index. Returns
/// `None` for ids that aren't processor contexts. Shared by the REPL
/// (re-exported from `repl::stop`) and `Session`.
///
/// KD synthesizes its ids as `p1.<one-based-hex>`. A GDB stub prints its own,
/// and QEMU pads both fields: its first vCPU is `p01.01`. Both are the same
/// `p<pid>.<tid>` syntax, so the process field is skipped rather than matched
/// against a literal. The qualifier is still required: an unqualified id is
/// bare hex, which would make any hex-shaped string name a processor.
/// Whether a hit reported on `stopped` belongs to the processor a `/c`
/// breakpoint names.
///
/// Like the thread filter, this cannot be programmed into the target: a
/// breakpoint site is memory or a per-processor debug register that any
/// thread can reach, so every processor executing it traps and the filter is
/// applied to the one that reported. A stop whose processor cannot be
/// resolved matches, so a filter never loses a hit silently.
pub fn stopped_processor_matches(processor: Option<u16>, stopped: &str) -> bool {
    let Some(processor) = processor else {
        return true;
    };
    processor_index_from_backend_thread_id(stopped).is_none_or(|stopped| stopped == processor)
}

pub fn processor_index_from_backend_thread_id(thread_id: &str) -> Option<u16> {
    let (_pid, tid) = thread_id.strip_prefix('p')?.split_once('.')?;
    u16::from_str_radix(tid, 16).ok()?.checked_sub(1)
}

/// Adopt the Windows thread a backend vCPU is running as the inspection
/// context, walked from that processor's KPRCB. Returns it, or `None` when the
/// id is not a processor context or the walk fails, clearing the stale
/// selection either way.
///
/// Every host has to do this at every stop: the selection is what `!thread`
/// reports and what the `$thread`/`$proc` pseudo-registers read, and a resume
/// clears it. Shared by the REPL (re-exported from `repl::stop`) and
/// [`Session::run_status`] so the two cannot report different threads.
pub fn refresh_windows_thread_context_for_backend_thread(
    debugger: &mut Target,
    thread_id: &str,
) -> Option<ThreadInfo> {
    let thread = processor_index_from_backend_thread_id(thread_id).and_then(|processor| {
        debugger
            .current_windows_thread_for_processor(processor)
            .ok()
    });
    match thread.clone() {
        Some(thread) => debugger.set_current_windows_thread_context(thread),
        None => debugger.clear_current_windows_thread_context(),
    }
    thread
}

/// Whether a guest-reload report found the loaded-module list (i.e. kernel
/// rediscovery completed). Single definition shared with the REPL.
pub fn reload_report_has_loaded_module_list(report: &ReloadReport) -> bool {
    report
        .startup
        .as_ref()
        .is_some_and(|startup| !startup.loaded_module_list.is_zero())
}

/// The result of [`perform_target_reload`]: the guest-reload outcome plus the
/// resolved kernel-base hint the reload was guided by. `report` is `Ok` when the
/// new kernel image was rediscovered (possibly before its module list is up;
/// check [`reload_report_has_loaded_module_list`]) and `Err` when it isn't
/// discoverable yet (very early boot). `hint` is the base used (from the stop
/// event, else queried from the backend), which the REPL rebases symbols against
/// while rediscovery is pending.
pub struct TargetReloadOutcome {
    pub report: Result<ReloadReport>,
    pub hint: Option<VirtAddr>,
    /// Symbolic breakpoint re-resolution failed after the target itself reloaded.
    pub breakpoint_error: Option<Error>,
}

impl Session {
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

/// Whether `event` is a *stray* single-step: a `STATUS_SINGLE_STEP` trap that
/// isn't sitting on a user breakpoint. In a run-control loop (continue / run-to)
/// nobody is intentionally single-stepping, so this is a debugger artifact; a
/// managed step-over's single-step that leaked out because KD single-steps the
/// whole machine and another processor's break was reported first. The loop
/// absorbs it (clear `TF`, resume) rather than surfacing it as a stop. Used by
/// [`Session::continue_until_break`] and the REPL's continue loop.
pub fn stop_is_stray_single_step(event: &StopEvent, breakpoints: &BreakpointManager) -> bool {
    event.exception_code == Some(STATUS_SINGLE_STEP)
        && !event.is_bugcheck
        && event
            .program_counter
            .is_none_or(|pc| breakpoints.breakpoint_id_at_address(pc).is_none())
}

/// If `event` is a hardware-debug stop, return the breakpoint that fired.
///
/// Which evidence says so depends on what the transport exposes. A stop that
/// names the trapping data address answers directly. Otherwise AMD64 maps DR6
/// status bits and clears them, and ARM64 uses the stopped PC/FAR together
/// with BCR/WCR enable and address-select fields. A transport with neither
/// (a GDB stub owns the debug registers and does not show them) is left with
/// the PC, which is an execute breakpoint's address because x86 and ARM64
/// both fault before the instruction runs.
///
/// `None` means a plain single-step or no hardware stop. Must run before
/// [`stop_is_stray_single_step`].
pub fn hardware_breakpoint_hit(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    event: &StopEvent,
) -> Result<Option<Breakpoint>> {
    if event.is_bugcheck || !breakpoints.has_enabled_hardware_breakpoints() {
        return Ok(None);
    }
    let slots = backend.hardware_breakpoint_slots();

    if let Some(address) = event.watchpoint_address {
        return Ok(watchpoint_covering(breakpoints, slots, address));
    }

    // Debug-register evidence only means anything on the debug exception, and
    // checking that here is what keeps an ordinary stop from fetching
    // registers. A transport that exposes no debug registers reports no
    // exception code either, so it has no such gate to pass.
    let debug_registers = register_map.contains("dr6") || register_map.contains("bcr0");
    if debug_registers && event.exception_code != Some(STATUS_SINGLE_STEP) {
        return Ok(None);
    }

    let mut regs = backend.read_registers()?;
    let Ok(dr6) = register_map.read_u64("dr6", &regs) else {
        if !debug_registers {
            return execute_breakpoint_at_pc(
                backend,
                register_map,
                breakpoints,
                slots,
                event,
                &mut regs,
            );
        }
        return arm64_hardware_breakpoint_hit(register_map, breakpoints, event, &regs);
    };

    let hit = (0..HW_BREAKPOINT_SLOTS)
        .filter(|slot| dr6 & (1u64 << slot) != 0)
        .find_map(|slot| breakpoints.hardware_breakpoint_for_slot(slot));

    let mut dirty = false;
    // Clear the B0-B3 status bits so the next single-step is unambiguous; the
    // CPU never clears them itself, but leave the rest of DR6 intact.
    let cleared = dr6 & !0b1111u64;
    if cleared != dr6 {
        register_map.write_u64("dr6", &mut regs, cleared)?;
        dirty = true;
    }
    if hit
        .as_ref()
        .and_then(|bp| bp.hardware)
        .is_some_and(|hw| hw.access == HwBreakpointAccess::Execute)
    {
        let eflags = register_map.read_u64("eflags", &regs)?;
        const RF: u64 = 1 << 16;
        if eflags & RF == 0 {
            register_map.write_u64("eflags", &mut regs, eflags | RF)?;
            dirty = true;
        }
    }

    if dirty {
        backend.write_registers(&regs)?;
    }

    Ok(hit)
}

/// The data watchpoint covering `address`, which is what a transport-reported
/// trap address names: the byte touched, not the watchpoint's base.
fn watchpoint_covering(
    breakpoints: &BreakpointManager,
    slots: u8,
    address: u64,
) -> Option<Breakpoint> {
    (0..slots)
        .filter_map(|slot| breakpoints.hardware_breakpoint_for_slot(slot))
        .find(|bp| {
            bp.hardware.is_some_and(|hw| {
                hw.access != HwBreakpointAccess::Execute
                    && bp
                        .address
                        .0
                        .checked_add(u64::from(hw.len))
                        .is_some_and(|end| address >= bp.address.0 && address < end)
            })
        })
}

/// The hardware execute breakpoint parked at the stopped PC, with `RF` set so
/// the resume gets past it.
///
/// An x86 execute breakpoint is a fault, not a trap: it fires before the
/// instruction runs, so resuming re-enters the same instruction and faults
/// again. `RF` suppresses it for exactly one instruction. A stub programs the
/// debug registers rather than exposing them, but the flag still lives in the
/// guest's `RFLAGS`, so writing it there is what breaks the loop.
fn execute_breakpoint_at_pc(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    slots: u8,
    event: &StopEvent,
    regs: &mut [u8],
) -> Result<Option<Breakpoint>> {
    let Some(pc) = register_map
        .read_u64("rip", regs)
        .or_else(|_| register_map.read_u64("pc", regs))
        .ok()
        .or(event.program_counter)
    else {
        return Ok(None);
    };
    let hit = (0..slots)
        .filter_map(|slot| breakpoints.hardware_breakpoint_for_slot(slot))
        .find(|bp| {
            bp.address.0 == pc
                && bp
                    .hardware
                    .is_some_and(|hw| hw.access == HwBreakpointAccess::Execute)
        });

    if hit.is_some()
        && let Ok(eflags) = register_map.read_u64("eflags", regs)
    {
        const RF: u64 = 1 << 16;
        if eflags & RF == 0 {
            register_map.write_u64("eflags", regs, eflags | RF)?;
            backend.write_registers(regs)?;
        }
    }

    Ok(hit)
}

fn arm64_hardware_breakpoint_hit(
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    event: &StopEvent,
    regs: &[u8],
) -> Result<Option<Breakpoint>> {
    let pc = register_map
        .read_u64("pc", regs)
        .or_else(|_| register_map.read_u64("rip", regs))
        .unwrap_or_else(|_| event.program_counter.unwrap_or(0));
    let far = register_map.read_u64("far", regs).unwrap_or(0);
    let mut hit = None;

    // ARM64 WVR values are granule-aligned and WCR.BAS identifies the bytes
    // that caused the data watchpoint. Require FAR as evidence: without it a
    // plain single-step must not be mistaken for a data breakpoint.
    if far != 0 {
        for slot in hwbp::ARM64_WATCHPOINT_SLOTS {
            let Some(bp) = breakpoints.hardware_breakpoint_for_slot(slot) else {
                continue;
            };
            let Some(hw) = bp.hardware else { continue };
            if hw.access == HwBreakpointAccess::Execute {
                continue;
            }
            let control = register_map
                .read_u64(format!("wcr{slot}"), regs)
                .unwrap_or(0);
            let value = register_map
                .read_u64(format!("wvr{slot}"), regs)
                .unwrap_or(0);
            if control & 1 == 0 || value != far & !7 {
                continue;
            }
            let bas = ((control >> 5) & 0xff) as u8;
            let far_bit = 1u8 << (far & 7);
            let in_requested_range = bp
                .address
                .0
                .checked_add(hw.len as u64)
                .is_some_and(|end| far >= bp.address.0 && far < end);
            if bas & far_bit != 0 && in_requested_range {
                hit = Some(bp);
                break;
            }
        }
    }

    if hit.is_none() {
        for slot in hwbp::ARM64_BREAKPOINT_SLOTS {
            let Some(bp) = breakpoints.hardware_breakpoint_for_slot(slot) else {
                continue;
            };
            let Some(hw) = bp.hardware else { continue };
            if hw.access != HwBreakpointAccess::Execute {
                continue;
            }
            let index = slot - hwbp::ARM64_BREAKPOINT_SLOTS.start;
            let control = register_map
                .read_u64(format!("bcr{index}"), regs)
                .unwrap_or(0);
            let value = register_map
                .read_u64(format!("bvr{index}"), regs)
                .unwrap_or(0);
            if control & 1 != 0 && value == pc & !3 && bp.address.0 == pc {
                hit = Some(bp);
                break;
            }
        }
    }

    Ok(hit)
}

/// Resolve one stop against the watchpoint manager. This owns the behavior
/// common to every host: claim and acknowledge backend status, adopt the
/// stopped thread, refresh register/CR3 context before condition evaluation,
/// and resume a pass-count or false conditional hit. Condition errors fail
/// safe by surfacing the hit with error metadata.
pub fn resolve_watchpoint_stop(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &mut BreakpointManager,
    target: &mut Target,
    current_thread: &mut String,
    event: &StopEvent,
) -> Result<WatchpointStopAction> {
    let Some(breakpoint) = hardware_breakpoint_hit(backend, register_map, breakpoints, event)?
    else {
        return Ok(WatchpointStopAction::NotBreakpoint);
    };

    set_current_thread_from_stop(backend, event, current_thread);
    let registers = backend.read_registers()?;
    let scope_dtb = register_map
        .read_u64(target.arch().dtb_register(), &registers)
        .unwrap_or(0);
    update_target_context_from_registers(target, register_map, Ok(registers));
    if !breakpoint.scope.matches_dtb(scope_dtb, target.arch()) {
        backend.continue_execution()?;
        return Ok(WatchpointStopAction::Resumed);
    }
    if let Some(thread) = breakpoint.thread.as_ref() {
        let stopped = refresh_windows_thread_context_for_backend_thread(target, current_thread);
        if !thread.matches(stopped.as_ref()) {
            backend.continue_execution()?;
            return Ok(WatchpointStopAction::Resumed);
        }
    }
    if !stopped_processor_matches(breakpoint.processor, current_thread) {
        backend.continue_execution()?;
        return Ok(WatchpointStopAction::Resumed);
    }
    if breakpoints.record_hit(breakpoint.id)? == BreakpointHitDisposition::SkipPass {
        backend.continue_execution()?;
        return Ok(WatchpointStopAction::Resumed);
    }

    let condition_error = match breakpoint.evaluate_condition(target) {
        Ok(false) => {
            backend.continue_execution()?;
            return Ok(WatchpointStopAction::Resumed);
        }
        Ok(true) => None,
        Err(error) => Some(error.to_string()),
    };
    if breakpoint.one_shot {
        breakpoints.remove(backend, target, breakpoint.id)?;
    }

    Ok(WatchpointStopAction::Hit {
        breakpoint,
        condition_error,
    })
}

/// Rewind the reporting thread back onto the breakpoint address when it is
/// parked one byte past one of ours.
///
/// An `int3` advances RIP by one when it executes, so a thread that hit a
/// breakpoint the target does not own reports `addr + 1`; the breakpoint-hit
/// check matches on the exact address, so this realignment must happen first.
///
/// Only the thread that reported the stop is touched, and only for a
/// breakpoint exception. Every other vCPU is frozen wherever it happened to
/// be, which may legitimately be one byte past a breakpoint, and moving a PC
/// back there would re-execute a byte that already ran. A thread that did hit
/// the same `int3` reports it as its own stop later, and is realigned then.
/// Best-effort: a backend that cannot read or write the context is left alone.
pub fn rewind_thread_off_breakpoint(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    arch: Arch,
) {
    if arch == Arch::Arm64 {
        return;
    }
    let Ok(regs) = backend.read_registers() else {
        return;
    };
    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
    let cr3 = register_map
        .read_u64(arch.dtb_register(), &regs)
        .unwrap_or(0);
    let Some(prev) = rip.checked_sub(register_map.breakpoint_step_size() as u64) else {
        return;
    };
    if !matches!(
        breakpoints.check_breakpoint_hit(prev, cr3, arch),
        BreakpointHitResult::Hit(_)
    ) {
        return;
    }
    let mut adjusted = regs.clone();
    if register_map.write_u64("rip", &mut adjusted, prev).is_err() {
        return;
    }
    let _ = backend.write_registers(&adjusted);
}

/// Adopt the thread reported by a stop event (falling back to the backend's
/// stopped-thread query) as the current thread, and select it on the backend.
pub fn set_current_thread_from_stop(
    backend: &mut dyn DebugBackend,
    event: &StopEvent,
    current: &mut String,
) {
    let stopped_tid = event
        .thread_id
        .clone()
        .or_else(|| backend.stopped_thread_id().ok());
    if let Some(tid) = stopped_tid {
        *current = tid;
        let _ = backend.set_current_thread(current);
    }
}

/// Single-step the current thread and clear `TF` afterward (KVM leaves it set).
/// A fault or bugcheck instead of the step trap is returned as an error.
pub fn step_one_and_clear_tf(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
) -> Result<()> {
    backend.step()?;
    let event = backend.wait_for_stop()?;
    clear_trap_flag(backend, register_map)?;
    if event.is_bugcheck {
        return Err(Error::DebugInfo(
            "target bugchecked while single-stepping".into(),
        ));
    }
    if let Some(code) = event
        .exception_code
        .filter(|&code| code != STATUS_SINGLE_STEP && code != STATUS_BREAKPOINT)
    {
        return Err(Error::DebugInfo(format!(
            "target raised exception {code:#x} while single-stepping"
        )));
    }
    Ok(())
}

/// Clear the trap flag (`TF`, RFLAGS bit 8) and DR6's B0-B3 status bits on the
/// currently selected thread, best-effort, so an absorbed single-step leaves
/// no residue for the next resume. ARM64 has neither x86 field, so its
/// single-step state is acknowledged by KD's ARM64 continue request instead.
/// A transport that reports TF and DR6 with the stop answers this without a
/// register fetch, which is what keeps an absorbed breakpoint hit cheap.
pub fn clear_trap_flag(backend: &mut dyn DebugBackend, register_map: &RegisterMap) -> Result<()> {
    if backend
        .stop_trap_state()
        .is_some_and(|state| state.is_clean())
    {
        return Ok(());
    }
    if let Ok(mut regs) = backend.read_registers() {
        let mut dirty = false;
        if let Ok(eflags) = register_map.read_u64("eflags", &regs) {
            let cleared = eflags & !(1u64 << 8);
            if cleared != eflags && register_map.write_u64("eflags", &mut regs, cleared).is_ok() {
                dirty = true;
            }
        }
        if let Ok(dr6) = register_map.read_u64("dr6", &regs) {
            let cleared = dr6 & !0b1111u64;
            if cleared != dr6 && register_map.write_u64("dr6", &mut regs, cleared).is_ok() {
                dirty = true;
            }
        }
        if dirty {
            backend.write_registers(&regs)?;
        }
    }

    Ok(())
}

/// If RIP sits on one of our enabled breakpoints, disable it, step the
/// underlying instruction, then re-enable; returns whether a step was
/// performed. A stale breakpoint (its address space gone) is silently
/// discarded. A target that owns its sites (KD) has already dropped the one
/// at the PC while reporting the stop, so the disable is a no-op there and
/// the re-enable is what writes it back. Callers must have selected the
/// desired thread first. Shared by the REPL and [`Session::step`].
pub fn step_over_current_breakpoint(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    breakpoints: &mut BreakpointManager,
) -> Result<bool> {
    let regs = backend.read_registers()?;
    let rip = register_map.read_u64("rip", &regs)?;
    // Only the shared-page fallback below needs the address space; a stub
    // without its DTB register still gets the plain step-over.
    let cr3 = register_map
        .read_u64(debugger.arch().dtb_register(), &regs)
        .ok();

    // Scope-agnostic: a wrong-process hit on a shared-page BP still needs the
    // disable/step/enable dance so the wrong process can make forward progress.
    let Some(bp_id) = breakpoints.breakpoint_id_at_address(rip) else {
        return Ok(false);
    };

    match (breakpoints.disable(backend, debugger, bp_id), cr3) {
        (Ok(()), _) => {}
        (Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)), Some(cr3)) => {
            breakpoints
                .disable_guest_memory_patch_in_address_space(backend, debugger, bp_id, cr3)?;
        }
        (Err(err), _) => return Err(err),
    }

    let stepped = step_one_and_clear_tf(backend, register_map);

    // Re-arm whether or not the step worked: a failed step must not leave the
    // site unpatched with the manager still believing it is enabled.
    match breakpoints.enable(backend, debugger, bp_id) {
        Ok(()) => {}
        Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)) => {
            // Address space no longer exists; drop the breakpoint and move on.
            breakpoints.discard(backend, bp_id)?;
        }
        Err(err) => return stepped.and(Err(err)),
    }
    stepped.map(|()| true)
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
