use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic};
use single_instance::SingleInstance;

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::bugchecks::{CURRENT_KERNEL_RELOAD_WINDOW, looks_like_kernel_pointer};
use crate::dbg_backend::{
    BackendCapability, BugcheckInfo, ContinueDisposition, DebugBackend, DebugCapability,
    DebugOutputPage, HW_BREAKPOINT_SLOTS, HwBreakpointAccess, LastEvent, StopEvent,
    WatchpointAccess,
};
use crate::disasm::{DisasmRow, decode_rows, decode_rows_arm64, disasm_formatter};
use crate::dmp::DmpBackend;
use crate::error::{Error, Result};
use crate::gdb::breakpoints::{Breakpoint, BreakpointConfig};
use crate::gdb::{
    BreakpointHitDisposition, BreakpointHitResult, BreakpointManager, GdbClient, RegisterMap,
};
use crate::guest::ProcessInfo;
use crate::kd::{KdBackend, KdMemorySource, hwbp, trace_enabled};
use crate::memory::DTB_IDENTITY;
use crate::memory_backend::MemoryBackend;
use crate::phys::PhysMem;
use crate::target::{ReloadReport, Target, ThreadInfo};
use crate::types::{Arch, VirtAddr};
use crate::unwind::{
    StackTrace, ThreadStackTrace, build_parked_thread_stack, build_stacktrace, preferred_code_dtb,
    resolve_thread_trace_context,
};
use crate::{Backend, TargetSpec};

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
    /// Attached process inspection scope, if any.
    pub process: Option<ProcessInfo>,
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
/// they never repeat backend acknowledgement, reload, scope, or trap handling.
#[derive(Debug, Clone)]
pub enum StopResolution {
    /// Debugger noise or a filtered breakpoint was handled and execution resumed.
    Resumed,
    /// A software or hardware breakpoint worth surfacing.
    Breakpoint {
        breakpoint: Breakpoint,
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
    /// ETHREAD selected for stack-only inspection while the backend remains on
    /// `current_thread`. Its register file does not exist as a coherent snapshot.
    parked_windows_thread: Option<VirtAddr>,
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
            Err(teardown_error) => Err(Error::Rsp(format!(
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
                Self::connect_kd(endpoint, *memory_source, || match backend {
                    Backend::Kd => KdBackend::connect(endpoint),
                    Backend::KdNet => {
                        let key = kdnet_key.as_deref().expect("validated above");
                        KdBackend::connect_net(endpoint, key)
                    }
                    Backend::Gdb | Backend::Memory => unreachable!("matched KD above"),
                })
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
    /// target-mediated KD physical-memory requests.
    pub fn connect_kd<F>(
        resource: &str,
        memory_source: KdMemorySource,
        make_backend: F,
    ) -> Result<Self>
    where
        F: FnOnce() -> Result<KdBackend>,
    {
        let guard = Some(acquire_instance_guard(resource)?);
        let mut backend = make_backend()?;
        let hints = backend.target_hints()?;

        let host_phys = match memory_source {
            KdMemorySource::Kd => None,
            KdMemorySource::Host => {
                let phys = Arc::new(PhysMem::live().map_err(|error| {
                    Error::Kd(format!("host memory source unavailable: {error}"))
                })?);
                backend.validate_host_memory(&*phys, hints)?;
                Some(phys)
            }
            KdMemorySource::Auto => match PhysMem::live() {
                Ok(phys) => {
                    let phys = Arc::new(phys);
                    match backend.validate_host_memory(&*phys, hints) {
                        Ok(()) => Some(phys),
                        Err(error) => {
                            eprintln!(
                                "{}: host memory rejected ({error}); falling back to KD memory",
                                backend.name()
                            );
                            None
                        }
                    }
                }
                Err(error) => {
                    eprintln!(
                        "{}: host memory unavailable ({error}); falling back to KD memory",
                        backend.name()
                    );
                    None
                }
            },
        };

        let (target, backend): (Target, Box<dyn DebugBackend>) = match host_phys {
            Some(phys) => {
                eprintln!(
                    "{}: memory source host (validated VM-process memory)",
                    backend.name()
                );
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

        let mut session = Self {
            id: NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed),
            target,
            backend,
            breakpoints: BreakpointManager::new(),
            register_map,
            current_thread,
            parked_windows_thread: None,
            reload_module_list_pending: false,
            reload_surface_pending: false,
            parked_stop: None,
            last_event: None,
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
        self.require_live_register_context()?;
        self.target.selected_frame = None;
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
        for id in self.breakpoints.one_shot_hit_ids() {
            self.breakpoints
                .remove(self.backend.as_mut(), &self.target, id)?;
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

    pub fn parked_windows_thread(&self) -> Option<&ThreadInfo> {
        let ethread = self.parked_windows_thread?;
        self.target
            .windows_thread_selection
            .as_ref()
            .filter(|thread| thread.ethread == ethread)
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

    /// Attach the acknowledgement chosen for the current stop. A successful
    /// continuation calls this after the backend accepts the request.
    pub fn record_continuation_disposition(&mut self, disposition: ContinueDisposition) {
        if let Some(last_event) = &mut self.last_event {
            last_event.disposition = Some(disposition);
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
        for _ in 0..INTERRUPT_MAX_RESUMES {
            let event = self.backend.interrupt()?;
            match self.classify_stop_event(event)? {
                StopResolution::Resumed => continue,
                StopResolution::Breakpoint { event, .. }
                | StopResolution::Bugcheck { event }
                | StopResolution::TargetReloaded { event, .. }
                | StopResolution::Stopped { event, .. } => return Ok(event),
            }
        }
        self.backend.interrupt()
    }

    /// Bring the target to a real halt before teardown: consume a stop that is
    /// already pending if it is meaningful, else break in. The REPL's ^D path.
    pub fn halt_for_exit(&mut self) -> Result<()> {
        if let Some(event) = self.backend.try_wait_for_stop(EXIT_STOP_POLL)?
            && !matches!(self.classify_stop_event(event)?, StopResolution::Resumed)
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
        self.breakpoints
            .mask_breakpoint_bytes(VirtAddr(pc), &mut bytes, trace.active_dtb);

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

        let mut decoder = Decoder::with_ip(64, &bytes, pc, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.code() == Code::INVALID {
            return Err(Error::DebugInfo(format!(
                "failed to decode instruction at {pc:#x}"
            )));
        }
        Ok(CurrentInstruction {
            is_call: instruction.mnemonic() == Mnemonic::Call,
            next_ip: instruction.next_ip(),
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
            let _ = self.interrupt();
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

    /// Read the selected live vCPU register file. A parked Windows thread is a
    /// stack-only inspection target and must never fall through to the backend's
    /// unrelated live register context.
    pub fn read_registers(&mut self) -> Result<Vec<u8>> {
        self.require_live_register_context()?;
        if self.backend.is_running() {
            return Err(Error::TargetRunning);
        }
        self.backend.set_current_thread(&self.current_thread)?;
        self.backend.read_registers()
    }

    /// Set a single register on the current thread by name, as a read-modify-
    /// write of the register file (read all, patch the one, write back).
    pub fn write_register(&mut self, name: &str, value: u64) -> Result<()> {
        self.require_live_register_context()?;
        if self.backend.is_running() {
            return Err(Error::TargetRunning);
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
        self.register_map.write_u64(name, &mut regs, value)?;
        self.backend.write_registers(&regs)?;
        self.target.registers = Some(self.register_map.to_hashmap(&regs));
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
    /// frozen between tool calls. Noise is resumed; a real stop is parked for
    /// the next `wait_for_stop`.
    pub fn service_idle(&mut self) {
        if self.parked_stop.is_some() || !self.backend.has_pending_stop() {
            return;
        }
        let never_cancel = AtomicBool::new(false);
        match self.wait_for_stop_bounded(Some(SERVICE_IDLE_BUDGET), &never_cancel) {
            Ok(ContinueOutcome::Running) | Err(_) => {}
            Ok(ContinueOutcome::TargetReloaded { .. }) => {
                self.reload_surface_pending = true;
            }
            Ok(outcome) => {
                self.parked_stop = Some(outcome);
            }
        }
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
        let (rip, symbol) = if running || pending_stop {
            (None, None)
        } else {
            let _ = self.backend.set_current_thread(&self.current_thread);
            let rip = self
                .backend
                .read_registers()
                .ok()
                .and_then(|regs| self.register_map.read_u64("rip", &regs).ok());
            let symbol = rip.and_then(|r| self.target.closest_symbol_current_context(VirtAddr(r)));
            (rip, symbol)
        };
        RunStatus {
            running,
            current_thread: self.current_thread.clone(),
            rip,
            symbol,
            process: self.target.current_process_info.clone(),
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

    /// Set a symbol-identity breakpoint that survives module unload/reload and
    /// may remain deferred until matching symbols are loaded.
    pub fn add_symbol_breakpoint(
        &mut self,
        symbol: String,
        condition: Option<String>,
    ) -> Result<u32> {
        self.breakpoints.add_symbolic(
            self.backend.as_mut(),
            &self.target,
            symbol,
            BreakpointConfig {
                condition,
                ..BreakpointConfig::default()
            },
        )
    }

    /// Set one source identity for every address matching `file:line`, or one
    /// deferred identity when no matching module is currently loaded.
    pub fn add_source_breakpoint(
        &mut self,
        source: String,
        condition: Option<String>,
    ) -> Result<Vec<u32>> {
        self.breakpoints.add_source(
            self.backend.as_mut(),
            &self.target,
            source,
            BreakpointConfig {
                condition,
                ..BreakpointConfig::default()
            },
        )
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
            &self.target,
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

    /// Read guest virtual memory in the current inspection context with our
    /// own breakpoint patch bytes masked back to the original code, so every
    /// host (REPL, MCP, SDK) sees the same bytes the guest would run.
    pub fn read_masked(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let process = self.target.current_process()?;
        process.memory().read_bytes(addr, buf)?;
        self.breakpoints
            .mask_breakpoint_bytes(addr, buf, process.dtb());
        Ok(())
    }

    /// Disassemble `count` instructions starting at `addr` in the current
    /// address space. Our own breakpoint `int3` bytes are masked back to the
    /// original opcode, and branch / rip-relative targets get symbol comments.
    pub fn disassemble(&self, addr: VirtAddr, count: usize) -> Result<Vec<DisasmRow>> {
        let process = self.target.current_process()?;
        let dtb = process.dtb();

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
        match self.target.arch() {
            Arch::Amd64 => {
                let mut formatter = disasm_formatter();
                Ok(decode_rows(
                    &buf,
                    addr.0,
                    Some(count),
                    &mut formatter,
                    resolve,
                ))
            }
            Arch::Arm64 => Ok(decode_rows_arm64(&buf, addr.0, Some(count), resolve)),
        }
    }

    /// Walk the currently selected inspection context's call stack, returning
    /// up to `limit` frames. A parked Windows thread uses stack-only recovery
    /// without touching the backend vCPU; otherwise this reads live registers.
    pub fn backtrace(&mut self, limit: usize) -> Result<StackTrace> {
        if let Some(thread) = self.parked_windows_thread() {
            return Ok(build_parked_thread_stack(&self.target, thread, limit)?.stacktrace);
        }

        self.backend.set_current_thread(&self.current_thread)?;
        let regs = self.backend.read_registers()?;
        Ok(build_stacktrace(
            &self.target,
            &self.register_map,
            &regs,
            limit,
        ))
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

    /// Leave the target in a usable state when a frontend exits: halt first if
    /// needed, restore every debugger-owned breakpoint site, and resume only
    /// when both operations succeed. Any failure explicitly prepares the
    /// backend to leave the target halted.
    pub fn cleanup_for_exit(&mut self) -> Result<()> {
        let halted = if self.backend.is_running() {
            self.interrupt().map(|_| ())
        } else {
            Ok(())
        };
        if halted.is_err() {
            return prepare_backend_after_cleanup(self.backend.as_mut(), halted);
        }

        let cleanup = self.remove_all_breakpoints();
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

    /// Clear every inspection cache that cannot survive a crash/reboot command
    /// before the shared wait loop re-establishes the next stop.
    pub fn clear_resume_state(&mut self) {
        self.target.selected_frame = None;
        self.target.registers = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        self.parked_windows_thread = None;
        self.parked_stop = None;
    }

    /// Resume with an explicit exception acknowledgement while preserving the
    /// same breakpoint step-over and cache invalidation prologue as [`Self::resume`].
    pub fn resume_with_disposition(&mut self, disposition: ContinueDisposition) -> Result<()> {
        self.target.selected_frame = None;
        if self.parked_windows_thread().is_some() {
            self.parked_windows_thread = None;
            self.target.clear_current_windows_thread_context();
            self.refresh_context_for_current_thread();
        }
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
        for id in self.breakpoints.one_shot_hit_ids() {
            self.breakpoints
                .remove(self.backend.as_mut(), &self.target, id)?;
        }

        self.breakpoints
            .refresh_enabled(self.backend.as_mut(), &self.target)?;
        self.backend
            .continue_execution_with_disposition(disposition)?;
        self.record_continuation_disposition(disposition);

        self.target.registers = None;
        self.target.clear_context_dtb_override();
        self.target.clear_current_windows_thread_context();
        self.parked_windows_thread = None;
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
                // Count every scoped physical hit before pass-count and
                // condition evaluation. A pass skip uses the same canonical
                // step-over/resume path as a false condition.
                if self.breakpoints.record_hit(bp.id)? == BreakpointHitDisposition::SkipPass {
                    step_over_current_breakpoint(
                        self.backend.as_mut(),
                        &self.register_map,
                        &self.target,
                        &mut self.breakpoints,
                    )?;
                    self.backend.continue_execution()?;
                    return Ok(BreakpointStopAction::Resumed);
                }
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

    /// Classify one raw backend stop and perform every core-owned transition.
    ///
    /// This is the only stop-ingestion state machine. REPL, MCP, Python, and
    /// idle servicing may differ in polling and presentation, but must route
    /// raw events here so reload handling, DR acknowledgement, scope checks,
    /// `int3` rewind, conditions, and auto-resume behavior cannot drift.
    pub fn classify_stop_event(&mut self, mut event: StopEvent) -> Result<StopResolution> {
        self.target.selected_frame = None;
        self.record_stop_event(&event);
        set_current_thread_from_stop(self.backend.as_mut(), &event, &mut self.current_thread);

        if event.is_bugcheck && !event.target_reloaded {
            self.target.registers = None;
            return Ok(StopResolution::Bugcheck { event });
        }

        match self.classify_reload_stop(&mut event)? {
            disposition @ (ReloadDisposition::Reloaded { .. }
            | ReloadDisposition::ReloadCompleted) => {
                let coherent =
                    !matches!(disposition, ReloadDisposition::Reloaded { coherent: false });
                self.refresh_context_for_current_thread();
                return Ok(StopResolution::TargetReloaded { event, coherent });
            }
            ReloadDisposition::PendingRediscovery | ReloadDisposition::ResumePastAssist => {
                self.backend.continue_execution()?;
                return Ok(StopResolution::Resumed);
            }
            ReloadDisposition::Ordinary => {}
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
                return Ok(StopResolution::Breakpoint {
                    breakpoint,
                    event,
                    rip,
                    condition_error,
                });
            }
            WatchpointStopAction::Resumed => return Ok(StopResolution::Resumed),
            WatchpointStopAction::NotBreakpoint => {}
        }

        if stop_is_stray_single_step(&event, &self.breakpoints) {
            let _ = clear_trap_flag(self.backend.as_mut(), &self.register_map);
            self.backend.continue_execution()?;
            return Ok(StopResolution::Resumed);
        }

        if self.breakpoints.has_enabled_breakpoints() {
            rewind_threads_off_breakpoints(
                self.backend.as_mut(),
                &self.register_map,
                &self.breakpoints,
                &self.current_thread,
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

        match self.resolve_breakpoint_stop(rip, cr3)? {
            BreakpointStopAction::Hit {
                breakpoint,
                condition_error,
            } => Ok(StopResolution::Breakpoint {
                breakpoint,
                event,
                rip,
                condition_error,
            }),
            BreakpointStopAction::Resumed => Ok(StopResolution::Resumed),
            BreakpointStopAction::NotBreakpoint => Ok(StopResolution::Stopped { event, rip }),
        }
    }

    /// Resume the VM (unless already running) and wait up to `timeout` for a
    /// meaningful stop; wrong-process int3 hits and false conditional
    /// breakpoints are stepped over silently. `None` waits indefinitely;
    /// `cancel` or an elapsed timeout returns [`ContinueOutcome::Running`] with
    /// the VM left running. Non-resuming observation is
    /// [`Self::wait_for_stop_bounded`].
    pub fn continue_until_break(
        &mut self,
        timeout: Option<Duration>,
        cancel: &AtomicBool,
    ) -> Result<ContinueOutcome> {
        self.continue_until_break_with_disposition(timeout, cancel, ContinueDisposition::Handled)
    }

    /// Resume with an explicit exception acknowledgement, then wait for a
    /// meaningful stop. When already running, no acknowledgement is sent.
    pub fn continue_until_break_with_disposition(
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
                StopResolution::Resumed => continue,
                StopResolution::Breakpoint {
                    breakpoint,
                    rip,
                    condition_error,
                    ..
                } => {
                    return Ok(ContinueOutcome::Breakpoint {
                        id: breakpoint.id,
                        address: breakpoint.address.0,
                        symbol: breakpoint.symbol,
                        temporary: breakpoint.temporary,
                        action: breakpoint.action,
                        rip,
                        condition_error,
                    });
                }
                StopResolution::Bugcheck { event } => {
                    return Ok(ContinueOutcome::Bugcheck {
                        rip: event.program_counter,
                        info: event.bugcheck,
                    });
                }
                StopResolution::TargetReloaded { coherent, .. } => {
                    reload_trace!(
                        "continue: SURFACE target_reloaded base={} coherent={}",
                        self.target.kernel_base().map_or_else(
                            || "none".to_string(),
                            |address| format!("{:#x}", address.0)
                        ),
                        coherent,
                    );
                    return Ok(ContinueOutcome::TargetReloaded {
                        kernel_base: self.target.kernel_base().map(|address| address.0),
                        coherent,
                    });
                }
                StopResolution::Stopped { event, rip } => {
                    return Ok(ContinueOutcome::Stopped {
                        rip,
                        exception_code: event.exception_code,
                        first_chance: event.first_chance,
                        exception_address: event.exception_address,
                    });
                }
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
                StopResolution::Resumed => continue,
                StopResolution::Breakpoint { event, .. }
                | StopResolution::Bugcheck { event }
                | StopResolution::TargetReloaded { event, .. }
                | StopResolution::Stopped { event, .. } => return Ok(event),
            }
        }
    }

    /// Rebuild guest state using an optional kernel-base hint through the shared
    /// [`perform_target_reload`] action.
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
        if let Some(error) = outcome.breakpoint_error {
            return Err(error);
        }
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
    pub fn try_complete_pending_reload(&mut self) -> Result<bool> {
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
    pub fn classify_reload_stop(&mut self, event: &mut StopEvent) -> Result<ReloadDisposition> {
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
            let TargetReloadOutcome {
                report,
                hint,
                breakpoint_error,
            } = perform_target_reload(
                self.backend.as_mut(),
                &mut self.target,
                &mut self.breakpoints,
                event.target_kernel_base_hint,
            );
            if let Some(error) = breakpoint_error {
                return Err(error);
            }
            return Ok(match report {
                Ok(report) => {
                    let coherent = reload_report_has_loaded_module_list(&report);
                    self.reload_module_list_pending = !coherent;
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
                    self.reload_module_list_pending = true;
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
    /// Symbolic breakpoint re-resolution failed after the target itself reloaded.
    pub breakpoint_error: Option<Error>,
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
    // Target-specific numeric breakpoints and hardware slots cannot survive a
    // rebuild. Symbolic code breakpoints retain identity and become deferred.
    breakpoints.prepare_target_reload(backend);
    let hint = event_hint.or_else(|| backend.target_kernel_base_hint().ok().flatten());
    let report = target.reload_guest_with_kernel_base_hint(hint);
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
/// AMD64 maps DR6 status bits and clears them; ARM64 uses the stopped PC/FAR
/// together with BCR/WCR enable and address-select fields. `None` means a
/// plain single-step or a backend without hardware-stop state. Must run before
/// [`stop_is_stray_single_step`].
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
    let Ok(dr6) = register_map.read_u64("dr6", &regs) else {
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
    if !breakpoint.scope.matches_cr3(scope_dtb) {
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
    arch: Arch,
) {
    if arch == Arch::Arm64 {
        return;
    }
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
        let cr3 = register_map
            .read_u64(arch.dtb_register(), &regs)
            .unwrap_or(0);
        let Some(prev) = rip.checked_sub(register_map.breakpoint_step_size() as u64) else {
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
        exit_requests: Vec<bool>,
        fail_exit: bool,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                register_map: build_register_map(),
                regs: vec![0u8; REGISTER_BUFFER_SIZE],
                writes: 0,
                fail_writes: false,
                exit_requests: Vec::new(),
                fail_exit: false,
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
        fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
            self.exit_requests.push(leave_running);
            if self.fail_exit {
                Err(Error::Kd("injected backend teardown failure".into()))
            } else {
                Ok(())
            }
        }
    }

    fn single_step_event() -> StopEvent {
        StopEvent {
            thread_id: None,
            exception_code: Some(STATUS_SINGLE_STEP),
            first_chance: Some(true),
            exception_address: None,
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
    fn backend_default_rejects_not_handled_continuation() {
        let mut backend = MockBackend::new();
        assert!(matches!(
            backend.continue_execution_with_disposition(ContinueDisposition::NotHandled),
            Err(Error::ExceptionDispositionUnsupported)
        ));
    }

    #[test]
    fn successful_breakpoint_cleanup_requests_running_exit() {
        let mut backend = MockBackend::new();

        prepare_backend_after_cleanup(&mut backend, Ok(())).unwrap();

        assert_eq!(backend.exit_requests, vec![true]);
    }

    #[test]
    fn failed_breakpoint_cleanup_requests_halted_exit() {
        let mut backend = MockBackend::new();

        let error = prepare_backend_after_cleanup(
            &mut backend,
            Err(Error::Kd("injected breakpoint removal failure".into())),
        )
        .unwrap_err();

        assert!(error.to_string().contains("breakpoint removal failure"));
        assert_eq!(backend.exit_requests, vec![false]);
    }

    #[test]
    fn cleanup_reports_breakpoint_and_backend_teardown_failures() {
        let mut backend = MockBackend::new();
        backend.fail_exit = true;

        let error = prepare_backend_after_cleanup(
            &mut backend,
            Err(Error::Kd("injected breakpoint removal failure".into())),
        )
        .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("breakpoint removal failure"));
        assert!(message.contains("backend teardown failure"));
        assert_eq!(backend.exit_requests, vec![false]);
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

        assert_eq!(backend.get("dr6"), DR6_BS);
        assert_eq!(backend.writes, 1);
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

        let mut event = single_step_event();
        event.exception_code = Some(0x8000_0003);
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &event)
                .unwrap()
                .is_none()
        );

        event.exception_code = None;
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &event)
                .unwrap()
                .is_none()
        );

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

        let empty = BreakpointManager::new();
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &empty, &single_step_event())
                .unwrap()
                .is_none()
        );
        assert_eq!(backend.writes, 0);
        assert_eq!(backend.regs, before);

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
        let manager = manager_with_hw(1, HwBreakpointAccess::Write, true);
        let mut backend = MockBackend::new();
        backend.set("dr6", (1 << 3) | DR6_BS);

        let map = build_register_map();
        assert!(
            hardware_breakpoint_hit(&mut backend, &map, &manager, &single_step_event())
                .unwrap()
                .is_none()
        );
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

        assert_eq!(backend.get("eflags"), EFLAGS_BASE);
        assert_eq!(backend.get("dr6"), DR6_BS);
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
