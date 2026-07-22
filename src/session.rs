use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};
use single_instance::SingleInstance;

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::bugchecks::{CURRENT_KERNEL_RELOAD_WINDOW, looks_like_kernel_pointer};
use crate::dbg_backend::{
    BackendCapability, BugcheckInfo, DebugBackend, DebugCapability, DebugOutputPage,
    HW_BREAKPOINT_SLOTS, HwBreakpointAccess, StopEvent, WatchpointAccess,
};
use crate::disasm::{DisasmRow, decode_rows, disasm_formatter};
use crate::error::{Error, Result};
use crate::gdb::breakpoints::Breakpoint;
use crate::gdb::{BreakpointHitResult, BreakpointManager, RegisterMap};
use crate::kd::trace_enabled;
use crate::memory::{AddressSpace, DTB_IDENTITY};
use crate::phys::PhysMem;
use crate::target::{ReloadReport, Target, ThreadInfo};
use crate::types::VirtAddr;
use crate::unwind::{
    StackTrace, build_stacktrace, preferred_code_dtb, resolve_thread_trace_context,
};

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
    /// `kernel_base` is the rediscovered `nt` base. All prior addresses are
    /// stale and must be re-queried either way.
    TargetReloaded {
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

/// A "where am I" snapshot for the read-only status surface: whether the guest
/// is running, and if halted, the current stop site and inspection scope.
/// `coherent` is false after a reboot until kernel rediscovery finishes (the
/// loaded-module list is up), so a host knows process/module enumeration is not
/// yet meaningful and it should keep waiting rather than read stale state.
#[derive(Debug, Clone)]
pub struct RunStatus {
    pub running: bool,
    pub current_thread: String,
    /// Current instruction pointer when halted (None while running).
    pub rip: Option<u64>,
    /// Nearest symbol to `rip` when halted.
    pub symbol: Option<String>,
    /// Attached process inspection scope as (pid, name, eprocess), if any.
    pub process: Option<(u64, String, u64)>,
    pub coherent: bool,
    /// Rediscovered `nt` base. A host caches it to detect a reboot (the base
    /// changes) and invalidate stale addresses without parsing prose.
    pub kernel_base: u64,
}

/// How [`Session::classify_reload_stop`] classified a freshly observed stop:
/// real stop, reboot artifact, or transport noise. A host decides whether to
/// surface or absorb each case (the REPL prints boot phases inline;
/// `continue_until_break` surfaces reload detection and completion as
/// [`ContinueOutcome::TargetReloaded`] and absorbs the noise in between).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadDisposition {
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
        id: u32,
        address: u64,
        symbol: Option<String>,
        temporary: bool,
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

fn update_target_context_from_registers(
    target: &mut Target,
    register_map: &RegisterMap,
    registers: Result<Vec<u8>>,
) {
    let Ok(registers) = registers else {
        target.registers = None;
        target.clear_context_dtb_override();
        return;
    };
    target.registers = Some(register_map.to_hashmap(&registers));
    match register_map.read_u64("cr3", &registers) {
        // For triage dumps all modules are loaded with DTB_IDENTITY and
        // memory reads use identity mapping, so the CR3 from the CONTEXT
        // record is meaningless.  Setting it here would cause a DTB
        // mismatch that makes symbol lookup, type resolution, and eval
        // fail.
        Ok(cr3) if cr3 != 0 && target.guest.is_some() && target.kernel_dtb() != DTB_IDENTITY => {
            target.set_context_dtb_override(cr3)
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

/// The low bits of a CR3/DTB that select the page-directory base physical
/// frame (PCID and reserved/canonical bits masked out), for comparing the
/// address space a vCPU runs in against a process's DTB.
const DTB_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// How often the run-control poll loop wakes to check for a stop.
const CONTINUE_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How long a background `service_idle` pass spends absorbing caught stops before
/// returning to the actor's job queue. Small so a real tool call is never held off
/// for long; one buffered stop is drained immediately regardless, this only bounds
/// the brief wait for any follow-on hit in a burst.
const SERVICE_IDLE_BUDGET: Duration = Duration::from_millis(5);

/// `STATUS_BREAKPOINT`, the NTSTATUS an `int3` raises (e.g. `nt!DbgBreakPoint`).
const STATUS_BREAKPOINT: u32 = 0x8000_0003;

/// `STATUS_SINGLE_STEP`, the NTSTATUS a trap-flag single-step raises. During a
/// run-control loop (continue / run-to) nobody is intentionally single-stepping;
/// `si` steps via [`step_one_and_clear_tf`] directly, not the loop, so a
/// single-step that isn't at a user breakpoint is a debugger artifact (see
/// [`stop_is_stray_single_step`]).
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;

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
    /// Whether a guest reload is mid-flight with the loaded-module list not yet
    /// available (very early boot). Carried across `continue_until_break` calls
    /// so the post-reboot KD-reconnect dance runs to completion; when the list
    /// appears, [`Self::try_complete_pending_reload`] finishes rediscovery and
    /// stops the backend's reconnect-assist poking. The single owner of that
    /// state; hosts read it rather than reimplement it.
    pub reload_module_list_pending: bool,
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
    /// Per-target single-instance lock, held for the session's lifetime so a
    /// second ntoseye can't attach to the same backend resource. `Some` via
    /// [`Self::connect`] (every host's attach path), `None` via the unguarded
    /// [`Self::new`].
    _instance_guard: Option<InstanceGuard>,
}

impl Session {
    /// Optionally acquire the single-instance lock for `target`, connect a
    /// backend via `make_backend`, and build the owned session; the guarded
    /// attach path every host uses.
    ///
    /// `target` identifies the backend resource (socket path, address) so that
    /// instances targeting *different* resources can coexist while two instances
    /// on the *same* resource still conflict. Pass `None` for read-only
    /// backends (crash dumps, passive memory) that are safe to share. The lock
    /// is taken *before* `make_backend` runs, so a second instance fails fast
    /// instead of racing on the transport handshake. Backend selection
    /// (gdb/kd/memory/dmp) stays a frontend concern, in the closure.
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

    /// Build a session around an already-connected `backend`, constructing the
    /// guest [`Target`] view internally. The lower-level, *unguarded* constructor
    /// (tests / embedders that manage their own locking); hosts attach via
    /// [`Self::connect`], which takes the single-instance lock first.
    pub fn new(phys: Arc<PhysMem>, mut backend: Box<dyn DebugBackend>) -> Result<Self> {
        let target = Target::with_phys(phys)?;
        backend.initialize_from_target(&target);
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

        let mut session = Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            target,
            backend,
            breakpoints: BreakpointManager::new(),
            register_map,
            current_thread,
            reload_module_list_pending: false,
            reload_surface_pending: false,
            parked_stop: None,
            _instance_guard: None,
        };

        // Populate target.registers so register names resolve in expressions
        // (important for dump sessions where no stop event fires).
        if has_register_context {
            session.refresh_context_for_current_thread();
        }

        Ok(session)
    }

    /// Single-step one instruction on the currently selected thread. If RIP sits
    /// on one of our breakpoints, do the disable/step/enable dance; otherwise
    /// plain step + trap-flag clear. Afterward re-arm enabled breakpoints (the
    /// stub can drop non-hit ones on a stop) and re-select the landed-on thread.
    /// The full "step one instruction", shared by the REPL (`si`) and the SDK.
    pub fn step(&mut self) -> Result<()> {
        // Advancing the VM spends any stop `service_idle` parked, so drop it (the
        // other advance paths clear it via `resume`; a bare single-step doesn't).
        self.parked_stop = None;
        self.backend.set_current_thread(&self.current_thread)?;
        if !step_over_current_breakpoint(
            self.backend.as_mut(),
            &self.register_map,
            &self.target,
            &mut self.breakpoints,
        )? {
            step_one_and_clear_tf(self.backend.as_mut(), &self.register_map)?;
        }

        // Re-arm breakpoints the stub may have lost when the VM stopped, then
        // adopt whatever thread we ended up on.
        let _ = self
            .breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target);
        if let Ok(tid) = self.backend.stopped_thread_id() {
            self.current_thread = tid;
        }
        self.refresh_context_for_current_thread();
        Ok(())
    }

    /// Select `id` as the current inspection thread (e.g. a vCPU id), so
    /// registers/backtrace/step operate on it. Validates the id against the
    /// backend. Shared by the REPL's `thread`/`vcpu` commands and the SDKs.
    pub fn set_current_thread(&mut self, id: &str) -> Result<()> {
        self.backend.set_current_thread(id)?;
        self.current_thread = id.to_string();
        self.refresh_context_for_current_thread();
        Ok(())
    }

    /// Pause the running VM and adopt the stopped thread. Returns the raw stop
    /// event. pyo3/MCP route here (rather than calling the backend raw) so the
    /// selected thread tracks the halt; the REPL layers richer surfacing on top.
    pub fn interrupt(&mut self) -> Result<StopEvent> {
        let event = self.backend.interrupt()?;
        // Interrupting can land on a freshly-rebooted guest (the pump surfaced a
        // peer-reset stop that this break-in consumed). Rebuild kernel state now so
        // inspection here isn't against the stale pre-reboot image, and flag the
        // reload as not-yet-surfaced so the next wait_for_stop still reports it
        // (interrupt's own result carries no reload notification). Without this,
        // an interrupt that swallows the reboot stop leaves the session pointed at
        // the old kernel base, with stale symbols and enumeration faults, until a wait
        // happens to classify it.
        if event.target_reloaded {
            let _ = self.reload_with_hint(event.target_kernel_base_hint);
            self.reload_surface_pending = true;
        }
        set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);
        self.refresh_context_for_current_thread();
        Ok(event)
    }

    /// Align the inspection context to the currently selected thread's address
    /// space: when halted, read that thread's registers and set
    /// `target.registers` and `context_dtb_override` from its CR3, so reads,
    /// steps, and breakpoint installs scope to the focused thread rather than
    /// an earlier stop on another thread. Called from the thread-selection entry
    /// points; `continue_until_break` establishes the same context inline. Best-
    /// effort and a no-op while the guest runs (no coherent register file).
    fn refresh_context_for_current_thread(&mut self) {
        if self.backend.is_running() {
            return;
        }
        let registers = self
            .backend
            .set_current_thread(&self.current_thread)
            .and_then(|_| self.backend.read_registers());
        update_target_context_from_registers(&mut self.target, &self.register_map, registers);
    }

    /// Decode the instruction at the current thread's RIP, masking our own
    /// breakpoint `int3` bytes and reading through the thread's *preferred code
    /// DTB* (so a user-mode RIP decodes from the process address space, not the
    /// kernel's). Selects the current thread first; the VM must be halted.
    pub fn current_instruction(&mut self) -> Result<Instruction> {
        self.backend.set_current_thread(&self.current_thread)?;
        let regs = self.backend.read_registers()?;
        let rip = self.register_map.read_u64("rip", &regs)?;
        let cr3 = self.register_map.read_u64("cr3", &regs).unwrap_or(0);
        let trace = resolve_thread_trace_context(&self.target, cr3);
        let code_dtb = preferred_code_dtb(&trace, rip);
        let memory = AddressSpace::new(&self.target.phys, code_dtb);
        let mut bytes = [0u8; 16];
        memory.read_bytes(VirtAddr(rip), &mut bytes)?;
        self.breakpoints
            .mask_breakpoint_bytes(VirtAddr(rip), &mut bytes, trace.active_dtb);

        let mut decoder = Decoder::with_ip(64, &bytes, rip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.code() == Code::INVALID {
            return Err(Error::DebugInfo(format!(
                "failed to decode instruction at {rip:#x}"
            )));
        }
        Ok(instruction)
    }

    /// Compute the step-over plan for the current instruction: run to the
    /// instruction *after* a `call`, otherwise a plain single-step. The shared
    /// decision used by the REPL `p` and [`Self::step_over`].
    pub fn step_over_target(&mut self) -> Result<StepKind> {
        let instruction = self.current_instruction()?;
        if instruction.mnemonic() == Mnemonic::Call {
            Ok(StepKind::RunTo(VirtAddr(instruction.next_ip())))
        } else {
            Ok(StepKind::Single)
        }
    }

    /// The current frame's caller return address (the step-out target). Walks a
    /// few frames of the current thread's stack and returns the second frame's
    /// IP. Shared by the REPL `gu` and [`Self::step_out`].
    pub fn step_out_target(&mut self) -> Result<VirtAddr> {
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

    /// Run until `address` is reached. If a breakpoint is already set there in
    /// the current context this is a plain [`Self::continue_until_break`];
    /// otherwise it installs a temporary breakpoint, runs to it, removes it, and
    /// reports reaching it as [`ContinueOutcome::Step`]. A *different* breakpoint,
    /// bugcheck, or exception en route is surfaced as-is. Blocks until a stop
    /// (checking `cancel` between polls); on cancel it halts, removes the temp
    /// breakpoint, and returns [`ContinueOutcome::Running`]. The run-to-address
    /// primitive behind [`Self::step_over`] / [`Self::step_out`].
    pub fn run_to(&mut self, address: VirtAddr, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        // Already breakpointed here → just continue; the existing bp will report.
        if self
            .breakpoints
            .enabled_breakpoint_id_for_current_context(&self.target, address)
            .is_some()
        {
            return self.continue_until_break(None, cancel);
        }

        let temp_id =
            self.breakpoints
                .add_temporary_code(self.backend.as_mut(), &self.target, address)?;
        let outcome = self.continue_until_break(None, cancel);

        // Removing a breakpoint writes guest memory, so halt first if a cancel
        // left the VM running. A target reload already cleared the manager, so
        // the remove may be a no-op, ignore its error.
        if self.backend.is_running() {
            let _ = self.backend.interrupt();
        }
        let _ = self
            .breakpoints
            .remove(self.backend.as_mut(), &self.target, temp_id);

        match outcome? {
            ContinueOutcome::Breakpoint { id, rip, .. } if id == temp_id => {
                Ok(ContinueOutcome::Step { rip })
            }
            other => Ok(other),
        }
    }

    /// Step over the current instruction: single-step it, or, if it's a `call`,
    /// run to the instruction after it ([`ContinueOutcome::Step`] on completion).
    /// Shared by the REPL `p` (target only) and the SDKs.
    pub fn step_over(&mut self, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        match self.step_over_target()? {
            StepKind::Single => {
                self.step()?;
                Ok(ContinueOutcome::Step {
                    rip: self.current_rip(),
                })
            }
            StepKind::RunTo(addr) => self.run_to(addr, cancel),
        }
    }

    /// Step out of the current function: run to the caller's return address.
    pub fn step_out(&mut self, cancel: &AtomicBool) -> Result<ContinueOutcome> {
        let target = self.step_out_target()?;
        self.run_to(target, cancel)
    }

    /// Best-effort current RIP of the selected thread (0 if unreadable).
    fn current_rip(&mut self) -> u64 {
        self.backend
            .read_registers()
            .ok()
            .and_then(|r| self.register_map.read_u64("rip", &r).ok())
            .unwrap_or(0)
    }

    /// Set a single register on the current thread by name, as a read-modify-
    /// write of the register file (read all, patch the one, write back). The
    /// caller is responsible for halting the VM first; a running guest has no
    /// coherent register file to patch.
    pub fn write_register(&mut self, name: &str, value: u64) -> Result<()> {
        let mut regs = self.backend.read_registers()?;
        self.register_map.write_u64(name, &mut regs, value)?;
        self.backend.write_registers(&regs)
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

    /// Whether kernel structures are safe to read: the loaded-module list (and
    /// thus process/module/thread walks) is populated AND the image we're mapped
    /// to still validates. Two distinct ways to be incoherent:
    /// - `reload_module_list_pending`: detected early boot / mid-rediscovery; the
    ///   kernel is loaded and executing, but its lists aren't built yet.
    /// - the kernel base no longer reads `MZ`: an *undetected* reboot; the guest
    ///   rebooted (new KASLR base) but no wait loop has classified it yet, so our
    ///   cached base/symbols are stale and reads land at garbage addresses.
    ///
    /// The first is the `coherent` flag the reload notification carries; the
    /// second is the cheap 2-byte guard that stops `status`/enumeration from
    /// reporting a stale base as usable (the early-boot case is unaffected; the
    /// new kernel's `MZ` is valid there, and `reload_module_list_pending` covers
    /// it).
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
        set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);

        if !event.target_reloaded && !event.is_bugcheck {
            let stray = stop_is_stray_single_step(&event, &self.breakpoints);
            if stray || stop_is_assisted_refresh_breakin(&self.target, &self.breakpoints, &event) {
                if stray {
                    let _ = clear_trap_flag(self.backend.as_mut(), &self.register_map);
                }
                // These assist break-ins are the reconnect-assist poking the
                // backend keeps up until rediscovery finishes. Finish it now from
                // a live memory read (we are halted, so the next `continue` picks
                // up the cleared assist), so the poking stops at the source rather
                // than this absorb just feeding the next spurious break.
                self.try_finish_rediscovery_from_memory();
                self.backend.continue_execution()?;
                return Ok(());
            }

            // A breakpoint int3 the servicer caught: rewind off it and classify
            // via the shared resolver (same tail as `wait_for_stop_bounded`, so
            // they can't drift). A wrong-process hit on a shared-page int3, e.g.
            // one we patched into a shared DLL like user32, tripped by a process
            // other than the one the breakpoint is scoped to, or a false
            // conditional is stepped over and resumed here too, so a read/halt
            // surface services that noise (and un-sticks a VM frozen on it) the
            // same way `wait_for_stop` does, instead of surfacing a halt in another
            // process's address space. A real hit falls through to surface in place.
            if self.breakpoints.has_enabled_breakpoints() {
                rewind_threads_off_breakpoints(
                    self.backend.as_mut(),
                    &self.register_map,
                    &self.breakpoints,
                    &self.current_thread,
                );
                if let Ok(regs) = self.backend.read_registers() {
                    let rip = self.register_map.read_u64("rip", &regs).unwrap_or(0);
                    let cr3 = self.register_map.read_u64("cr3", &regs).unwrap_or(0);
                    self.target.registers = Some(self.register_map.to_hashmap(&regs));
                    if cr3 != 0 {
                        self.target.set_context_dtb_override(cr3);
                    }
                    if matches!(
                        self.resolve_breakpoint_stop(rip, cr3),
                        Ok(BreakpointStopAction::Resumed)
                    ) {
                        return Ok(());
                    }
                }
            }
        }

        if event.target_reloaded {
            // Mirror `interrupt`: rebuild against the new kernel now, and flag the
            // reload as not-yet-surfaced so the next `wait_for_stop` still reports
            // the one `target_reloaded` notification (settling carries none).
            let _ = self.reload_with_hint(event.target_kernel_base_hint);
            self.reload_surface_pending = true;
        }
        self.refresh_context_for_current_thread();
        Ok(())
    }

    /// Service the guest while the host is otherwise idle: absorb a stop the
    /// background servicer caught but no tool call has drained, chiefly a
    /// wrong-process hit on a shared-page breakpoint (an `int3` we patched into a
    /// shared DLL, tripped by a process other than the one the breakpoint is
    /// scoped to), which would otherwise leave the guest frozen between tool
    /// calls. Called from the MCP actor on a periodic [`Command::Service`] nudge.
    ///
    /// Only acts when the servicer has actually caught a stop (otherwise a cheap
    /// no-op, the common idle case). It drives the stop through the same loop
    /// `wait_for_stop` uses, so noise is absorbed identically (no drift): a
    /// wrong-process shared-page hit, an assist break-in, or a stray single-step
    /// is stepped over and the guest resumes. A *real* stop (a right-process
    /// breakpoint hit, a reload, a bugcheck) is left halted in place; the outcome
    /// is dropped here, so the host observes it via `status`/`wait_for_stop`
    /// (surfacing it as a proper event on the next wait is handled in a later
    /// step). A small budget bounds how long the actor is held off real jobs.
    pub fn service_idle(&mut self) {
        // Already holding a real stop for the host to consume, or nothing caught:
        // a cheap no-op (the common idle case).
        if self.parked_stop.is_some() || !self.backend.has_pending_stop() {
            return;
        }
        let never_cancel = AtomicBool::new(false);
        match self.wait_for_stop_bounded(Some(SERVICE_IDLE_BUDGET), &never_cancel) {
            // Noise absorbed (wrong-process / assist / stray) or a transient error
            // The guest is running again, nothing to surface.
            Ok(ContinueOutcome::Running) | Err(_) => {}
            // A reboot caught while idle: route through the one-notification
            // deferral (status delivers + clears it, an idle wait surfaces it) so a
            // reload the host already observed via `status` isn't double-announced.
            Ok(ContinueOutcome::TargetReloaded { .. }) => {
                self.reload_surface_pending = true;
            }
            // A real execution stop the host didn't actively wait for (breakpoint /
            // non-bp stop / bugcheck): park it so the next `wait_for_stop` reports
            // the proper event instead of a bare "halted".
            Ok(outcome) => {
                self.parked_stop = Some(outcome);
            }
        }
    }

    /// Take the stop `service_idle` parked while the host was idle, if any (see
    /// [`Self::parked_stop`]). The MCP `wait_for_stop` returns this before waiting,
    /// so a stop caught between tool calls surfaces as its proper event.
    pub fn take_parked_stop(&mut self) -> Option<ContinueOutcome> {
        self.parked_stop.take()
    }

    /// A read-only run-control snapshot for the "where am I" surface (see
    /// [`RunStatus`]). When halted, selects the current thread and resolves
    /// rip+symbol (best-effort); while running, leaves those None. Reports
    /// `coherent: false` while a post-reboot rediscovery is still pending so a
    /// host waits instead of enumerating stale state.
    pub fn run_status(&mut self) -> RunStatus {
        // Ingest a stop the servicer caught but nothing has drained yet, so the
        // snapshot reflects the real halt (rip/symbol/process/coherent) instead
        // of the stale running value (it resumes only to absorb debugger-noise
        // break-ins, surfacing in place otherwise; a no-op when nothing is
        // pending). If it fails (transport error), `has_pending_stop` stays true
        // and we fall back to reporting halted-with-no-location rather than lying.
        let _ = self.settle_pending_stop();
        // Finish a module-list rediscovery from memory if it is just waiting on the
        // list to come up, so `coherent` flips as soon as it is ready and the
        // reconnect-assist poking winds down (rather than the status snapshot
        // perpetually reporting coherent:false while the poking keeps breaking in).
        self.try_finish_rediscovery_from_memory();
        // This snapshot carries the reload's whole payload (`kernel_base` +
        // `coherent`), so it *is* the host's notification that the guest rebooted:
        // stop deferring a now-redundant `target_reloaded`.
        self.clear_deferred_reload_surface();
        let pending_stop = self.backend.has_pending_stop();
        let running = self.backend.is_running() && !pending_stop;
        let (rip, symbol) = if running || pending_stop {
            (None, None)
        } else {
            // NOTE: not strictly read-only; re-selects the (already-current)
            // thread and reads its registers to resolve rip/symbol. Idempotent in
            // practice, but it is a backend round-trip, not a pure field read.
            let _ = self.backend.set_current_thread(&self.current_thread);
            let rip = self
                .backend
                .read_registers()
                .ok()
                .and_then(|regs| self.register_map.read_u64("rip", &regs).ok());
            let symbol = rip.and_then(|r| self.target.closest_symbol_current_context(VirtAddr(r)));
            (rip, symbol)
        };
        let process = self
            .target
            .current_process_info
            .as_ref()
            .map(|p| (p.pid, p.name.clone(), p.eprocess_va.0));
        RunStatus {
            running,
            current_thread: self.current_thread.clone(),
            rip,
            symbol,
            process,
            coherent: self.kernel_coherent(),
            kernel_base: self.target.kernel_base().map(|a| a.0).unwrap_or(0),
        }
    }

    /// Set a code breakpoint at `addr`. Returns the breakpoint id.
    pub fn add_breakpoint(&mut self, addr: VirtAddr) -> Result<u32> {
        self.add_breakpoint_with_condition(addr, None)
    }

    /// Set a code breakpoint at `addr` with an optional break condition
    /// (re-evaluated each hit; the run-control loop steps over and keeps running
    /// when it is false). The breakpoint's scope is derived from the current
    /// inspection context at install time. Returns the breakpoint id.
    pub fn add_breakpoint_with_condition(
        &mut self,
        addr: VirtAddr,
        condition: Option<String>,
    ) -> Result<u32> {
        self.add_breakpoint_with_symbol_condition(addr, None, condition)
    }

    /// Set a code breakpoint at `addr`, carrying an optional display `symbol`
    /// for hosts that created it from a user expression rather than a raw
    /// address.
    pub fn add_breakpoint_with_symbol_condition(
        &mut self,
        addr: VirtAddr,
        symbol: Option<String>,
        condition: Option<String>,
    ) -> Result<u32> {
        self.breakpoints
            .add(self.backend.as_mut(), &self.target, addr, symbol, condition)
    }

    /// Watch data accesses at `addr`. Watches are global across guest address
    /// spaces. Returns the stop-point id.
    pub fn add_watchpoint(
        &mut self,
        addr: VirtAddr,
        access: WatchpointAccess,
        len: u8,
    ) -> Result<u32> {
        self.add_watchpoint_with_condition(addr, access, len, None)
    }

    /// Watch data accesses with an optional condition evaluated on each hit.
    pub fn add_watchpoint_with_condition(
        &mut self,
        addr: VirtAddr,
        access: WatchpointAccess,
        len: u8,
        condition: Option<String>,
    ) -> Result<u32> {
        self.add_watchpoint_with_symbol_condition(addr, access, len, None, condition)
    }

    /// Watch data accesses while retaining a host-resolved display symbol. This
    /// is a semantic watchpoint API: hosts choose write or read/write behavior
    /// while the backend implementation remains private.
    pub fn add_watchpoint_with_symbol_condition(
        &mut self,
        addr: VirtAddr,
        access: WatchpointAccess,
        len: u8,
        symbol: Option<String>,
        condition: Option<String>,
    ) -> Result<u32> {
        self.breakpoints.add_hardware(
            self.backend.as_mut(),
            addr,
            access.into(),
            len,
            symbol,
            condition,
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
        let kernel_dtb_masked = self
            .target
            .guest
            .as_ref()
            .map(|g| g.ntoskrnl.dtb() & DTB_PAGE_MASK);

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
            let (Ok(rip), Ok(cr3)) = (
                self.register_map.read_u64("rip", &regs),
                self.register_map.read_u64("cr3", &regs),
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

            let cr3_masked = cr3 & DTB_PAGE_MASK;
            let (context, symbol) = if kernel_dtb_masked.is_some_and(|k| cr3_masked == k) {
                let sym = self
                    .target
                    .guest
                    .as_ref()
                    .and_then(|g| g.ntoskrnl.closest_symbol(VirtAddr(rip)).ok())
                    .map(|(s, o)| format!("{s}+{o:#x}"));
                ("kernel".to_string(), sym)
            } else {
                match processes
                    .iter()
                    .find(|p| (p.dtb & DTB_PAGE_MASK) == cr3_masked)
                {
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

    /// Disassemble `count` instructions starting at `addr` in the current
    /// address space. Our own breakpoint `int3` bytes are masked back to the
    /// original opcode, and branch / rip-relative targets get symbol comments.
    pub fn disassemble(&self, addr: VirtAddr, count: usize) -> Result<Vec<DisasmRow>> {
        let process = self.target.current_process()?;
        let dtb = process.dtb();

        // x86-64 instructions are at most 15 bytes; over-read so `count` decode.
        let mut buf = vec![0u8; count * 16];
        process.memory().read_bytes(addr, &mut buf)?;
        self.breakpoints.mask_breakpoint_bytes(addr, &mut buf, dtb);

        let symbols = &self.target.symbols;
        let resolve = |target: u64| {
            symbols
                .format_closest_symbol_for_address(dtb, VirtAddr(target))
                .unwrap_or_default()
        };
        let mut formatter = disasm_formatter();
        Ok(decode_rows(
            &buf,
            addr.0,
            Some(count),
            &mut formatter,
            resolve,
        ))
    }

    /// Walk the currently selected thread's call stack, returning up to `limit`
    /// frames. Reads the live register context and unwinds via
    /// [`build_stacktrace`], which resolves the per-frame DTB from CR3 and lazily
    /// loads the modules each frame lands in. Each frame carries its stack
    /// pointer, instruction pointer, resolved symbol, and how it was recovered
    /// (current RIP, unwind data, or heuristic stack scan).
    pub fn backtrace(&mut self, limit: usize) -> Result<StackTrace> {
        self.backend.set_current_thread(&self.current_thread)?;
        let regs = self.backend.read_registers()?;
        Ok(build_stacktrace(
            &self.target,
            &self.register_map,
            &regs,
            limit,
        ))
    }

    /// Uninstall every breakpoint (e.g. on shutdown, so no `int3` is left in
    /// the guest). Best-effort: removal errors are ignored.
    pub fn remove_all_breakpoints(&mut self) {
        let ids: Vec<u32> = self.breakpoints.list().iter().map(|b| b.id).collect();
        for id in ids {
            let _ = self
                .breakpoints
                .remove(self.backend.as_mut(), &self.target, id);
        }
    }

    /// Leave the target in a usable state when a frontend exits: halt first if
    /// needed so breakpoint removal can safely restore guest memory, then ask
    /// the backend to leave the VM running.
    pub fn cleanup_for_exit(&mut self) -> Result<()> {
        if self.backend.is_running() {
            let _ = self.backend.interrupt();
        }
        self.remove_all_breakpoints();
        self.backend.prepare_for_exit(true)
    }

    /// Resume the VM. If sitting on one of our breakpoints, step past it first
    /// (otherwise the `int3` at RIP re-fires immediately), re-arm enabled
    /// breakpoints, then continue and drop the now-stale inspection caches.
    /// The canonical resume prologue, shared by the REPL and the SDK.
    ///
    /// Does not poll for Ctrl+C or handle KD target-reload/reconnect the way the
    /// REPL's continue loop does; those remain REPL concerns.
    pub fn resume(&mut self) -> Result<()> {
        // The VM is moving on, so any stop `service_idle` parked for the host to
        // observe is now spent; drop it so a later `wait_for_stop` doesn't replay
        // a stale event.
        self.parked_stop = None;
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

        self.breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.backend.continue_execution()?;

        self.target.registers = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        Ok(())
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
        match self.breakpoints.check_breakpoint_hit(rip, cr3) {
            BreakpointHitResult::Hit(bp) => {
                // A false condition is absorbed. Evaluation errors fail safe:
                // surface the stop and carry the error to every host.
                let condition_error = match bp.evaluate_condition(&self.target) {
                    Ok(false) => {
                        step_over_current_breakpoint(
                            self.backend.as_mut(),
                            &self.register_map,
                            &self.target,
                            &mut self.breakpoints,
                        )?;
                        self.backend.continue_execution()?;
                        return Ok(BreakpointStopAction::Resumed);
                    }
                    Ok(true) => None,
                    Err(error) => Some(error.to_string()),
                };

                // The stub can drop non-hit breakpoints when the VM stops; re-arm
                // so they survive the next resume.
                let _ = self
                    .breakpoints
                    .refresh_enabled(self.backend.as_mut(), &self.target);

                Ok(BreakpointStopAction::Hit {
                    id: bp.id,
                    address: bp.address.0,
                    symbol: bp.symbol.clone(),
                    temporary: bp.temporary,
                    condition_error,
                })
            }
            BreakpointHitResult::NotBreakpoint => {
                // Wrong-process hit on a shared-page int3 (the BP is scoped to a
                // different address space): silently step over so the wrong
                // process keeps running, then resume waiting for the right one.
                if self.breakpoints.breakpoint_id_at_address(rip).is_some() {
                    step_over_current_breakpoint(
                        self.backend.as_mut(),
                        &self.register_map,
                        &self.target,
                        &mut self.breakpoints,
                    )?;
                    self.backend.continue_execution()?;
                    return Ok(BreakpointStopAction::Resumed);
                }

                Ok(BreakpointStopAction::NotBreakpoint)
            }
        }
    }

    /// Resume the VM and wait up to `timeout` for a *meaningful* stop, returning
    /// a [`ContinueOutcome`]. The scope-aware run-control loop shared by the REPL
    /// and the SDK/MCP: it silently steps over and resumes past wrong-process int3
    /// hits on shared pages and false conditional breakpoints, surfacing only a
    /// `Breakpoint` the caller actually cares about.
    ///
    /// `timeout` bounds the wait: `Some(d)` returns [`ContinueOutcome::Running`]
    /// (VM left running) if `d` elapses with no stop (robust against transport
    /// timeouts); `None` waits indefinitely. If the VM is already running on entry
    /// it keeps waiting without re-resuming; otherwise it resumes first via
    /// [`Self::resume`]. `cancel` interrupts the wait between polls (returns
    /// `Running`, VM left running); pass a never-set flag to disable.
    ///
    /// This is the shared resume-and-wait helper; surfaces that need non-resuming
    /// observation should call [`Self::wait_for_stop_bounded`] directly.
    pub fn continue_until_break(
        &mut self,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        if !self.backend.is_running() {
            self.resume()?;
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

            let mut event = match self.backend.try_wait_for_stop(poll)? {
                Some(event) => event,
                None => {
                    // The poll drained any pending stop; if it found nothing and
                    // the VM is halted, it is parked with no stop coming; report
                    // that instead of spinning the rest of the timeout (the
                    // GetState-first idiom; `run_status` is the richer view).
                    if !self.backend.is_running() {
                        // A reload that a non-surfacing consumer detected+rebuilt
                        // (e.g. `interrupt` landing on the reboot stop) but never
                        // reported to the host: flush it as the one reload
                        // notification now, before falling back to a plain halt, so
                        // interrupt-first and wait-first both surface the early-boot
                        // `target_reloaded`.
                        if self.reload_surface_pending {
                            self.reload_surface_pending = false;
                            return Ok(ContinueOutcome::TargetReloaded {
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

            set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);

            // A bugcheck surfaces immediately and must not be absorbed by the
            // reload machine below, *unless* the same stop also carries a target
            // reload. A post-bugcheck reboot latches the bugcheck flag while the
            // new kernel's KD resync arrives, so the stop reports both; a reboot
            // means the crash is over, so the reload takes priority and the
            // early-boot stop surfaces instead of a phantom second bugcheck.
            // Mirrors the REPL's `is_bugcheck = event.is_bugcheck && !target_reloaded`
            // so the two continue loops can't drift.
            if event.is_bugcheck && !event.target_reloaded {
                self.target.registers = None;
                return Ok(ContinueOutcome::Bugcheck {
                    rip: event.program_counter,
                    info: event.bugcheck.clone(),
                });
            }

            // Drive the reboot / KD-reconnect state machine: one TargetReloaded
            // per reboot, surfaced as early as possible: at detection when the
            // rebuild succeeds (even with the module list not up yet, matching
            // the REPL's early-boot break; the later completion is then silent),
            // or at the rediscovery completion as the fallback when it didn't.
            // Pending-rediscovery stops and assist break-ins are absorbed; real
            // stops (early-boot breakpoint hits) fall through as Ordinary even
            // mid-reload. Completing rediscovery is also what stops the backend's
            // reconnect-assist poking; a missed completion here is what used to
            // leave the VM resume-past-looping forever.
            match self.classify_reload_stop(&mut event) {
                disposition @ (ReloadDisposition::Reloaded { .. }
                | ReloadDisposition::ReloadCompleted) => {
                    let coherent =
                        !matches!(disposition, ReloadDisposition::Reloaded { coherent: false });
                    reload_trace!(
                        "continue: SURFACE target_reloaded base={} coherent={}",
                        self.target
                            .kernel_base()
                            .map_or_else(|| "none".to_string(), |a| format!("{:#x}", a.0),),
                        coherent,
                    );
                    // Establish register/DTB context at the surfaced stop (or
                    // drop the pre-reboot leftovers if the read fails) so
                    // inspection here doesn't see the old kernel's state
                    self.refresh_context_for_current_thread();
                    return Ok(ContinueOutcome::TargetReloaded {
                        kernel_base: self.target.kernel_base().map(|a| a.0),
                        coherent,
                    });
                }
                ReloadDisposition::PendingRediscovery | ReloadDisposition::ResumePastAssist => {
                    reload_trace!("continue: absorb -> resume + keep waiting");
                    self.backend.continue_execution()?;
                    continue;
                }
                ReloadDisposition::Ordinary => {}
            }

            // Claim watchpoint stops before the stray-single-step absorber. The
            // shared resolver refreshes target context, evaluates conditions,
            // and resumes false hits so the REPL and SDK/MCP cannot drift.
            match resolve_watchpoint_stop(
                self.backend.as_mut(),
                &self.register_map,
                &self.breakpoints,
                &mut self.target,
                &mut self.current_thread,
                &event,
            )? {
                WatchpointStopAction::Hit {
                    breakpoint: bp,
                    condition_error,
                } => {
                    // resolve_watchpoint_stop just refreshed target.registers;
                    // read RIP from there instead of a second register round-trip.
                    let rip = self
                        .target
                        .registers
                        .as_ref()
                        .and_then(|regs| regs.get("rip").copied())
                        .unwrap_or(0);
                    return Ok(ContinueOutcome::Breakpoint {
                        id: bp.id,
                        address: bp.address.0,
                        symbol: bp.symbol,
                        temporary: bp.temporary,
                        rip,
                        condition_error,
                    });
                }
                WatchpointStopAction::Resumed => continue,
                WatchpointStopAction::NotBreakpoint => {}
            }

            // A stray single-step (STATUS_SINGLE_STEP, not at a user breakpoint)
            // is a debugger artifact, not a stop to surface: a managed step-over's
            // single-step that leaked here because KD single-steps the whole
            // machine and another processor's break was reported first, possibly
            // leaving TF set on its processor. Clear TF and resume.
            if stop_is_stray_single_step(&event, &self.breakpoints) {
                let _ = clear_trap_flag(self.backend.as_mut(), &self.register_map);
                self.backend.continue_execution()?;
                continue;
            }

            // After an `int3` executes, RIP sits at the byte *after* the
            // breakpoint; rewind any thread parked there so the hit check below
            // sees the breakpoint address.
            if self.breakpoints.has_enabled_breakpoints() {
                rewind_threads_off_breakpoints(
                    self.backend.as_mut(),
                    &self.register_map,
                    &self.breakpoints,
                    &self.current_thread,
                );
            }

            let regs = self.backend.read_registers()?;
            self.target.registers = Some(self.register_map.to_hashmap(&regs));
            let rip = self.register_map.read_u64("rip", &regs).unwrap_or(0);
            let cr3 = self.register_map.read_u64("cr3", &regs).unwrap_or(0);
            if cr3 != 0 {
                self.target.set_context_dtb_override(cr3);
            }

            // The breakpoint-hit disposition (real hit, wrong-process shared-page
            // int3, false conditional, or genuine non-breakpoint stop) is shared
            // with the REPL's continue loop so they can't drift; the absorbed
            // cases step over and resume inside the resolver.
            match self.resolve_breakpoint_stop(rip, cr3)? {
                BreakpointStopAction::Hit {
                    id,
                    address,
                    symbol,
                    temporary,
                    condition_error,
                } => {
                    return Ok(ContinueOutcome::Breakpoint {
                        id,
                        address,
                        symbol,
                        temporary,
                        rip,
                        condition_error,
                    });
                }
                BreakpointStopAction::Resumed => continue,
                BreakpointStopAction::NotBreakpoint => {
                    return Ok(ContinueOutcome::Stopped {
                        rip,
                        exception_code: event.exception_code,
                    });
                }
            }
        }
    }

    /// Block until the VM stops, then select the stopped thread. If the backend
    /// reports the target was reloaded (e.g. a KD stream reset / guest reboot),
    /// rebuild guest state before returning. Returns the raw stop event.
    pub fn wait_for_stop(&mut self) -> Result<StopEvent> {
        let event = self.backend.wait_for_stop()?;
        if event.target_reloaded {
            // Best-effort: the kernel may not be discoverable yet mid-reboot.
            let _ = self.reload_with_hint(event.target_kernel_base_hint);
        }
        set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);
        self.refresh_context_for_current_thread();
        Ok(event)
    }

    /// Rebuild guest state after a target reload/reboot: drop stale breakpoints,
    /// rediscover the kernel (optionally guided by `hint`), and tell the backend
    /// whether to keep poking for it. Routes through the shared
    /// [`perform_target_reload`] action so the sync path (pyo3 `wait_for_stop`),
    /// the MCP/SDK classifier, and the REPL can't drift on reload behavior.
    pub fn reload_with_hint(&mut self, hint: Option<VirtAddr>) -> Result<()> {
        let outcome = perform_target_reload(
            self.backend.as_mut(),
            &mut self.target,
            &mut self.breakpoints,
            hint,
        );
        self.reload_module_list_pending = !outcome
            .report
            .as_ref()
            .map(reload_report_has_loaded_module_list)
            .unwrap_or(false);
        outcome.report.map(|_| ())
    }

    /// Rebuild guest state, auto-discovering the kernel base.
    pub fn reload(&mut self) -> Result<()> {
        self.reload_with_hint(None)
    }

    /// If a module-list reload is pending and the loaded-module list has now
    /// appeared, finish rediscovery: reload the kernel module symbols, tell the
    /// backend rediscovery completed (stopping its reconnect-assist poking), and
    /// clear the pending flag. Returns whether it completed on this call. The
    /// REPL layers cache refresh and progress printing on the same condition.
    pub fn try_complete_pending_reload(&mut self) -> bool {
        if !self.reload_module_list_pending {
            return false;
        }
        let startup = match self.target.startup_message_data() {
            Ok(startup) => startup,
            Err(e) => {
                reload_trace!("try_complete: startup read failed: {e}");
                return false;
            }
        };
        reload_trace!("try_complete: psmods={:#x}", startup.loaded_module_list.0);
        if startup.loaded_module_list.is_zero() {
            return false;
        }
        let _ = self.target.refresh_kernel_module_symbols();
        self.backend.note_target_rediscovery_complete();
        self.reload_module_list_pending = false;
        true
    }

    /// Try to finish module-list rediscovery by reading `PsLoadedModuleList` from
    /// guest memory instead of forcing a stop. Skips while a reload notification
    /// is still owed, so completion cannot silently swallow the one
    /// `TargetReloaded` event.
    pub fn try_finish_rediscovery_from_memory(&mut self) {
        if !self.reload_surface_pending {
            let _ = self.try_complete_pending_reload();
        }
    }

    /// Clear a deferred reboot notification once the host has already observed
    /// or acted on the rebuilt target. Leave it pending if the current kernel
    /// mapping still looks stale, so a later wait can surface the real reload.
    pub fn clear_deferred_reload_surface(&mut self) {
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
    /// Mutates `event.target_reloaded` to match. `continue_until_break` consumes
    /// it; the REPL shares its predicates so they can't drift.
    pub fn classify_reload_stop(&mut self, event: &mut StopEvent) -> ReloadDisposition {
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
            let outcome = perform_target_reload(
                self.backend.as_mut(),
                &mut self.target,
                &mut self.breakpoints,
                event.target_kernel_base_hint,
            );
            return match outcome.report {
                Ok(report) => {
                    let coherent = reload_report_has_loaded_module_list(&report);
                    self.reload_module_list_pending = !coherent;
                    // The host surfaces this verdict, so the reboot has been
                    // reported; the eventual completion stays silent
                    self.reload_surface_pending = false;
                    reload_trace!(
                        "classify: reload ok hint={} new_base={} psmods={} coherent={}",
                        outcome
                            .hint
                            .map_or_else(|| "none".to_string(), |h| format!("{:#x}", h.0)),
                        self.target
                            .kernel_base()
                            .map_or_else(|| "none".to_string(), |a| format!("{:#x}", a.0),),
                        report.startup.as_ref().map_or_else(
                            || "none".to_string(),
                            |s| format!("{:#x}", s.loaded_module_list.0),
                        ),
                        coherent,
                    );
                    ReloadDisposition::Reloaded { coherent }
                }
                Err(ref e) => {
                    self.reload_module_list_pending = true;
                    // Nothing surfaced for this reboot yet; the completion
                    // must be surfaced in its place or the host never learns
                    // the guest rebooted
                    self.reload_surface_pending = true;
                    reload_trace!("classify: reload err={e} -> pending_rediscovery");
                    ReloadDisposition::PendingRediscovery
                }
            };
        }

        // A pending reload whose module list just became available completes here
        // (and turns off the reconnect-assist poking). If the reload itself was
        // never surfaced (the rebuild failed at the detection stop), surface the
        // completion as the one reload notification for this reboot; otherwise
        // the completion is silent; absorb debugger noise, and let a real stop
        // (e.g. an early-boot breakpoint hit) be handled normally below.
        if self.try_complete_pending_reload() {
            if self.reload_surface_pending {
                self.reload_surface_pending = false;
                reload_trace!(
                    "classify: pending reload COMPLETED (unsurfaced) -> reload_completed"
                );
                return ReloadDisposition::ReloadCompleted;
            }
            if stop_is_assisted_refresh_breakin(&self.target, &self.breakpoints, event) {
                reload_trace!("classify: pending reload COMPLETED silently -> resume_past_assist");
                return ReloadDisposition::ResumePastAssist;
            }
            reload_trace!("classify: pending reload COMPLETED silently at a real stop");
            return ReloadDisposition::Ordinary;
        }

        // KD refresh/reconnect/debugger break-in (including the boot-time assist
        // pokes while a reload is still pending): resume past it. Real stops,
        // notably hits on breakpoints set at the early-boot reload stop, fall
        // through and surface even while the module list is still pending.
        if stop_is_assisted_refresh_breakin(&self.target, &self.breakpoints, event) {
            reload_trace!("classify: assisted refresh break-in -> resume_past_assist");
            return ReloadDisposition::ResumePastAssist;
        }

        reload_trace!("classify: ordinary");
        ReloadDisposition::Ordinary
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
    // Reject bare (unbracketed) IPv6 — the host part would contain extra
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

/// Parse a backend vCPU/thread id (`p1.<one-based-hex>`) into a zero-based
/// processor index. Returns `None` for ids that aren't processor contexts.
/// Shared by the REPL (re-exported from `repl::stop`) and `Session`.
pub fn processor_index_from_backend_thread_id(thread_id: &str) -> Option<u16> {
    let stripped = thread_id.strip_prefix("p1.")?;
    let one_based = u16::from_str_radix(stripped, 16).ok()?;
    one_based.checked_sub(1)
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
}

/// Rebuild guest state after a detected reboot: drop the now-stale breakpoints,
/// resolve a kernel-base hint (preferring the stop event's, else the backend's),
/// reload the guest image, and tell the backend whether rediscovery completed so
/// it stops (or keeps) its reconnect-assist poking. The shared reload *action*
/// behind [`Session::classify_reload_stop`] and the REPL's
/// `apply_target_reload_if_needed`; callers layer their own state/caches/output
/// on top of the returned outcome.
pub fn perform_target_reload(
    backend: &mut dyn DebugBackend,
    target: &mut Target,
    breakpoints: &mut BreakpointManager,
    event_hint: Option<VirtAddr>,
) -> TargetReloadOutcome {
    // Release DR slots before dropping the manager; see BreakpointManager::clear_hardware_slots.
    breakpoints.clear_hardware_slots(backend);
    *breakpoints = BreakpointManager::new();
    let hint = event_hint.or_else(|| backend.target_kernel_base_hint().ok().flatten());
    let report = target.reload_guest_with_kernel_base_hint(hint);
    match &report {
        // Once the kernel image is rediscovered, stop reconnect-assist pokes. The
        // remaining module-list completion is polled from live memory; forced
        // break-ins here would freeze early boot and delay the list we're waiting on.
        Ok(_) => backend.note_target_rediscovery_complete(),
        // Kernel not discoverable at all (no base to read): the assist poke is the
        // only way to force a stop where the rebuild can be retried, so keep it.
        Err(_) => backend.note_target_rediscovery_pending(),
    }
    TargetReloadOutcome { report, hint }
}

/// Whether `event` reflects a guest reboot into a new kernel image (so debugger
/// state must be rebuilt), rather than an ordinary stop in the current one.
/// Trusts the transport's explicit reload flag, then falls back to heuristics: a
/// kernel-space PC that lands in no known module, an invalidated current-kernel
/// mapping, or a rediscovered kernel whose identity changed, while treating a
/// near-base bugcheck as the *same* image. Used by
/// [`Session::classify_reload_stop`] and re-exported for the REPL.
pub fn stop_event_requires_target_reload(debugger: &Target, event: &StopEvent) -> bool {
    if event.target_reloaded {
        return true;
    }

    let Some(pc) = event.program_counter else {
        return false;
    };
    if !looks_like_kernel_pointer(pc) {
        return false;
    }

    if !debugger.current_kernel_mapping_is_valid() {
        return true;
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

/// Whether `event` is a debugger-generated KD refresh/reconnect/manual break-in
/// rather than a user break or genuine target exception, i.e. a stop to resume
/// past, not surface. KD usually marks reconnect-assist break-ins explicitly,
/// but queued break-in bytes can also surface later as an ordinary
/// `nt!DbgBreakPointWithStatus` stop; those are transparent too unless the user
/// owns a breakpoint at that address. Used by [`Session::classify_reload_stop`]
/// and the REPL's `should_resume_assisted_refresh_stop`.
pub fn stop_is_assisted_refresh_breakin(
    debugger: &Target,
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

    if event.assisted_breakin {
        return true;
    }

    let Some(pc) = event.program_counter else {
        return false;
    };

    debugger
        .closest_symbol_current_context(VirtAddr(pc))
        .as_deref()
        .is_some_and(|symbol| {
            symbol == "nt!DbgBreakPointWithStatus"
                || symbol.starts_with("nt!DbgBreakPointWithStatus+")
        })
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

/// If `event` is a `#DB` (`STATUS_SINGLE_STEP`) raised by a hardware
/// (debug-register) breakpoint, return the breakpoint that fired. Reads DR6 on
/// the stopped processor (KD adopts the stopping processor in `record_stop`,
/// so the selected context is the right one even before the caller adopts the
/// stopped thread), maps a set status bit (B0-B3) to a registered slot, and
/// clears the status bits so a later single-step can't re-report a stale hit —
/// even when no slot matched, since a stale bit from the guest's own DR usage
/// would wedge the same way. For an execute watch it also sets RF in RFLAGS:
/// an instruction breakpoint is a *fault* (RIP still points at the watched
/// instruction), so resuming without RF would re-raise the same `#DB` forever;
/// the CPU clears RF once that instruction retires. Returns `None` for a plain
/// trap-flag single-step or on a backend without DR support (its `RegisterMap`
/// has no `dr6`). Must run *before* [`stop_is_stray_single_step`], which would
/// otherwise absorb the same `#DB` as debugger noise.
pub fn hardware_breakpoint_hit(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    event: &StopEvent,
) -> Result<Option<Breakpoint>> {
    if event.exception_code != Some(STATUS_SINGLE_STEP)
        || event.is_bugcheck
        || !breakpoints.has_enabled_hardware_breakpoints()
    {
        return Ok(None);
    }

    let mut regs = backend.read_registers()?;
    let dr6 = register_map.read_u64("dr6", &regs)?;

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

/// Resolve one stop against the watchpoint manager. This owns the behavior
/// common to every host: claim and acknowledge backend status, adopt the
/// stopped thread, refresh register/CR3 context before condition evaluation,
/// and resume a false conditional hit. Condition errors fail safe by surfacing
/// the hit with error metadata.
pub fn resolve_watchpoint_stop(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    target: &mut Target,
    current_thread: &mut String,
    event: &StopEvent,
) -> Result<WatchpointStopAction> {
    let Some(breakpoint) = hardware_breakpoint_hit(backend, register_map, breakpoints, event)?
    else {
        return Ok(WatchpointStopAction::NotBreakpoint);
    };

    set_current_thread_from_stop(backend, event, current_thread);
    let registers = backend.read_registers();
    update_target_context_from_registers(target, register_map, registers);

    let condition_error = match breakpoint.evaluate_condition(target) {
        Ok(false) => {
            backend.continue_execution()?;
            return Ok(WatchpointStopAction::Resumed);
        }
        Ok(true) => None,
        Err(error) => Some(error.to_string()),
    };

    Ok(WatchpointStopAction::Hit {
        breakpoint,
        condition_error,
    })
}

/// Rewind every thread that is parked one byte past one of our breakpoints back
/// onto the breakpoint address. An `int3` advances RIP by one when it executes,
/// so a thread that hit a BP reports `addr + 1`; the breakpoint-hit check matches
/// on the exact address, so this realignment must happen first. Best-effort per
/// thread; restores `restore_thread` as the selected thread afterward. Shared by
/// the REPL and [`Session::continue_until_break`].
pub fn rewind_threads_off_breakpoints(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    breakpoints: &BreakpointManager,
    restore_thread: &str,
) {
    let threads = match backend.thread_list() {
        Ok(t) => t,
        Err(_) => return,
    };

    for tid in &threads {
        if backend.set_current_thread(tid).is_err() {
            continue;
        }
        let Ok(regs) = backend.read_registers() else {
            continue;
        };
        let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
        let cr3 = register_map.read_u64("cr3", &regs).unwrap_or(0);
        let Some(prev) = rip.checked_sub(1) else {
            continue;
        };
        if !matches!(
            breakpoints.check_breakpoint_hit(prev, cr3),
            BreakpointHitResult::Hit(_)
        ) {
            continue;
        }
        let mut adjusted = regs.clone();
        if register_map.write_u64("rip", &mut adjusted, prev).is_err() {
            continue;
        }
        let _ = backend.write_registers(&adjusted);
    }

    let _ = backend.set_current_thread(restore_thread);
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

/// Single-step the current thread and clear `TF` from its RFLAGS afterward.
/// KVM sets `TF` when enabling `KVM_GUESTDBG_SINGLESTEP` but doesn't clear it
/// when SINGLESTEP is removed; without this clear, the stepped thread keeps
/// trapping after every instruction on resume. `DebugBackend::step` only
/// *issues* the step, so it must be paired with a wait. Shared by the REPL and
/// [`Session::step`].
pub fn step_one_and_clear_tf(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
) -> Result<()> {
    backend.step()?;
    backend.wait_for_stop()?;
    clear_trap_flag(backend, register_map)
}

/// Clear the trap flag (`TF`, RFLAGS bit 8) on the currently selected thread,
/// best-effort. Factored out of [`step_one_and_clear_tf`] so the run-control
/// loop can also clear it when a *stray* single-step surfaces: KD single-steps
/// by resuming the whole machine, so a managed step-over's single-step can be
/// reported after a different processor's break and leak out with `TF` still set
/// on its processor (see [`stop_is_stray_single_step`]). Without clearing it,
/// that processor keeps trapping after every instruction on the next resume.
///
/// Also clears DR6's B0-B3 status bits when the backend exposes `dr6`: a step
/// over an instruction that touched a hardware watch sets them, the CPU never
/// clears them, and [`hardware_breakpoint_hit`] would misread the stale bits as
/// a fresh hit on the next continue. Both stray-single-step absorbers and the
/// step path funnel through here, so absorbed `#DB`s can't leave residue.
pub fn clear_trap_flag(backend: &mut dyn DebugBackend, register_map: &RegisterMap) -> Result<()> {
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
/// discarded. Callers must have selected the desired thread first. Shared by the
/// REPL and [`Session::step`].
pub fn step_over_current_breakpoint(
    backend: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    breakpoints: &mut BreakpointManager,
) -> Result<bool> {
    let regs = backend.read_registers()?;
    let rip = register_map.read_u64("rip", &regs)?;
    let cr3 = register_map.read_u64("cr3", &regs)?;

    // Scope-agnostic: a wrong-process hit on a shared-page BP still needs the
    // disable/step/enable dance so the wrong process can make forward progress.
    let Some(bp_id) = breakpoints.breakpoint_id_at_address(rip) else {
        return Ok(false);
    };

    if let Err(err) = breakpoints.disable(backend, debugger, bp_id) {
        if matches!(
            err,
            Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)
        ) {
            breakpoints
                .disable_guest_memory_patch_in_address_space(backend, debugger, bp_id, cr3)?;
        } else {
            return Err(err);
        }
    }

    step_one_and_clear_tf(backend, register_map)?;

    if let Err(err) = breakpoints.enable(backend, debugger, bp_id) {
        if matches!(
            err,
            Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)
        ) {
            // Address space no longer exists; drop the breakpoint and move on.
            breakpoints.discard(bp_id)?;
        } else {
            return Err(err);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdb::breakpoints::HardwareBreakpoint;
    use crate::kd::context::{REGISTER_BUFFER_SIZE, build_register_map};

    /// DR6.BS (bit 14): a status bit outside B0-B3 that the functions under
    /// test must leave untouched.
    const DR6_BS: u64 = 1 << 14;
    /// RFLAGS.RF (bit 16), the resume flag an execute hit must set.
    const RF: u64 = 1 << 16;
    /// RFLAGS.TF (bit 8), the trap flag `clear_trap_flag` clears.
    const TF: u64 = 1 << 8;
    /// An eflags value with a few innocent bits (IF | reserved bit 1) that
    /// must survive every rewrite.
    const EFLAGS_BASE: u64 = 0x202;

    /// Minimal register-file backend: a KD-layout register buffer the map's
    /// offsets index into, plus a write counter for no-op assertions. Every
    /// non-register operation is out of scope for these tests.
    struct MockBackend {
        register_map: RegisterMap,
        regs: Vec<u8>,
        writes: usize,
        fail_writes: bool,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                register_map: build_register_map(),
                regs: vec![0u8; REGISTER_BUFFER_SIZE],
                writes: 0,
                fail_writes: false,
            }
        }

        fn set(&mut self, name: &str, value: u64) {
            self.register_map
                .write_u64(name, &mut self.regs, value)
                .unwrap();
        }

        fn get(&self, name: &str) -> u64 {
            self.register_map.read_u64(name, &self.regs).unwrap()
        }
    }

    impl DebugBackend for MockBackend {
        fn register_map(&self) -> &RegisterMap {
            &self.register_map
        }
        fn read_registers(&mut self) -> Result<Vec<u8>> {
            Ok(self.regs.clone())
        }
        fn write_registers(&mut self, data: &[u8]) -> Result<()> {
            self.writes += 1;
            if self.fail_writes {
                return Err(Error::Kd("injected register write failure".into()));
            }
            self.regs = data.to_vec();
            Ok(())
        }
        fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn continue_execution(&mut self) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn step(&mut self) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn interrupt(&mut self) -> Result<StopEvent> {
            Err(Error::NotSupported)
        }
        fn wait_for_stop(&mut self) -> Result<StopEvent> {
            Err(Error::NotSupported)
        }
        fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
            Ok(None)
        }
        fn thread_list(&mut self) -> Result<Vec<String>> {
            Err(Error::NotSupported)
        }
        fn set_current_thread(&mut self, _thread_id: &str) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn stopped_thread_id(&mut self) -> Result<String> {
            Err(Error::NotSupported)
        }
        fn is_running(&self) -> bool {
            false
        }
    }

    fn single_step_event() -> StopEvent {
        StopEvent {
            thread_id: None,
            exception_code: Some(STATUS_SINGLE_STEP),
            program_counter: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            target_kernel_base_hint: None,
            assisted_breakin: false,
        }
    }

    fn manager_with_hw(slot: u8, access: HwBreakpointAccess, enabled: bool) -> BreakpointManager {
        let mut manager = BreakpointManager::new();
        let len = match access {
            HwBreakpointAccess::Execute => 1,
            _ => 4,
        };
        manager.insert_for_test(
            7,
            VirtAddr(0x1000),
            enabled,
            Some(HardwareBreakpoint { access, len, slot }),
        );
        manager
    }

    #[test]
    fn hardware_breakpoint_hit_claims_matching_dr6_bit_and_clears_status() {
        let manager = manager_with_hw(2, HwBreakpointAccess::Write, true);
        let mut backend = MockBackend::new();
        backend.set("dr6", (1 << 2) | DR6_BS);
        backend.set("eflags", EFLAGS_BASE);

        let map = build_register_map();
        let hit = hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event())
            .expect("register update must succeed")
            .expect("slot 2 #DB must be claimed by the registered watch");
        assert_eq!(hit.id, 7);
        assert_eq!(hit.hardware.expect("hw params").slot, 2);

        // B0-B3 are flushed in the written registers; BS survives.
        assert_eq!(backend.get("dr6"), DR6_BS);
        assert_eq!(backend.writes, 1);
        // A data watch is a trap (RIP already past the access): no RF.
        assert_eq!(backend.get("eflags"), EFLAGS_BASE);
    }

    #[test]
    fn hardware_breakpoint_hit_sets_resume_flag_only_for_execute_watches() {
        for (access, want_rf) in [
            (HwBreakpointAccess::Execute, true),
            (HwBreakpointAccess::Write, false),
            (HwBreakpointAccess::ReadWrite, false),
        ] {
            let manager = manager_with_hw(0, access, true);
            let mut backend = MockBackend::new();
            backend.set("dr6", 1);
            backend.set("eflags", EFLAGS_BASE);

            let map = build_register_map();
            let hit = hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event())
                .unwrap();
            assert!(hit.is_some(), "{access:?} hit must be claimed");

            let eflags = backend.get("eflags");
            assert_eq!(eflags & RF != 0, want_rf, "{access:?}: RF mismatch");
            // Everything but RF is preserved either way.
            assert_eq!(eflags & !RF, EFLAGS_BASE, "{access:?}: eflags clobbered");
            assert_eq!(backend.get("dr6"), 0, "{access:?}: B0 not cleared");
        }
    }

    #[test]
    fn hardware_breakpoint_hit_propagates_required_register_write_failure() {
        let manager = manager_with_hw(0, HwBreakpointAccess::Execute, true);
        let mut backend = MockBackend::new();
        backend.set("dr6", 1);
        backend.set("eflags", EFLAGS_BASE);
        backend.fail_writes = true;

        let map = build_register_map();
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event()).is_err()
        );
        assert_eq!(backend.get("dr6"), 1);
        assert_eq!(backend.get("eflags"), EFLAGS_BASE);
        assert_eq!(backend.writes, 1);
    }

    #[test]
    fn hardware_breakpoint_hit_ignores_non_single_step_stops() {
        let manager = manager_with_hw(0, HwBreakpointAccess::Write, true);
        let mut backend = MockBackend::new();
        backend.set("dr6", 1); // would match slot 0 if the gate were open
        let before = backend.regs.clone();
        let map = build_register_map();

        // A software breakpoint exception is not a #DB.
        let mut event = single_step_event();
        event.exception_code = Some(0x8000_0003);
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &event)
                .unwrap()
                .is_none()
        );

        // No exception code at all.
        event.exception_code = None;
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &event)
                .unwrap()
                .is_none()
        );

        // A bugcheck stop never resolves to a hardware hit.
        event.exception_code = Some(STATUS_SINGLE_STEP);
        event.is_bugcheck = true;
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &event)
                .unwrap()
                .is_none()
        );

        assert_eq!(backend.writes, 0);
        assert_eq!(backend.regs, before);
    }

    #[test]
    fn hardware_breakpoint_hit_requires_an_enabled_hardware_breakpoint() {
        let map = build_register_map();
        let mut backend = MockBackend::new();
        backend.set("dr6", 1);
        let before = backend.regs.clone();

        // No breakpoints at all: gate closed, registers untouched.
        let empty = BreakpointManager::new();
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &empty, &single_step_event())
                .unwrap()
                .is_none()
        );
        assert_eq!(backend.writes, 0);
        assert_eq!(backend.regs, before);

        // A disabled hardware breakpoint keeps the gate closed too.
        let manager = manager_with_hw(0, HwBreakpointAccess::Write, false);
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event())
                .unwrap()
                .is_none()
        );
        assert_eq!(backend.writes, 0);
        assert_eq!(backend.regs, before);
    }

    #[test]
    fn hardware_breakpoint_hit_clears_stale_dr6_bits_for_unregistered_slots() {
        // An enabled watch in slot 1 opens the gate, but the #DB reports
        // slot 3, which nothing occupies (e.g. the guest's own DR usage).
        let manager = manager_with_hw(1, HwBreakpointAccess::Write, true);
        let mut backend = MockBackend::new();
        backend.set("dr6", (1 << 3) | DR6_BS);

        let map = build_register_map();
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event())
                .unwrap()
                .is_none()
        );
        // The stale status bit is still flushed so it can't be misread as a
        // fresh hit on the next stop; BS survives.
        assert_eq!(backend.get("dr6"), DR6_BS);
        assert_eq!(backend.writes, 1);
    }

    #[test]
    fn clear_trap_flag_clears_tf_and_dr6_status_in_one_write() {
        let mut backend = MockBackend::new();
        backend.set("eflags", TF | EFLAGS_BASE);
        backend.set("dr6", 0b1011 | DR6_BS);

        let map = build_register_map();
        clear_trap_flag(&mut backend, &map).unwrap();

        // TF gone, innocent flags preserved.
        assert_eq!(backend.get("eflags"), EFLAGS_BASE);
        // B0-B3 gone, BS preserved.
        assert_eq!(backend.get("dr6"), DR6_BS);
        // Both fixes folded into a single register write.
        assert_eq!(backend.writes, 1);
    }

    #[test]
    fn clear_trap_flag_skips_the_write_when_nothing_is_set() {
        let mut backend = MockBackend::new();
        backend.set("eflags", EFLAGS_BASE);
        backend.set("dr6", DR6_BS);
        let before = backend.regs.clone();

        let map = build_register_map();
        clear_trap_flag(&mut backend, &map).unwrap();

        assert_eq!(backend.writes, 0);
        assert_eq!(backend.regs, before);
    }
}
