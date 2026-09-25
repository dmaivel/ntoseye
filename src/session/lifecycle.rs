//! Attaching a session to a backend (construction and the per-target
//! instance lock) and leaving the target usable when a frontend exits.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use single_instance::SingleInstance;

use crate::breakpoints::{BreakpointManager, SiteJournal, breakpoint_opcode};
use crate::bugchecks::plausible_bugcheck_code;
use crate::dbg_backend::{BugcheckInfo, DebugBackend, DebugCapability};
use crate::dmp::DmpBackend;
use crate::error::{Error, Result};
use crate::exception_policy::ExceptionPolicyTable;
use crate::gdb::GdbClient;
use crate::kd::{KdBackend, KdMemorySource};
use crate::memory_backend::MemoryBackend;
use crate::phys::PhysMem;
use crate::session::{ContinueOutcome, Session, StopResolution};
use crate::symbols::ntoseye_home;
use crate::target::Target;
use crate::{Backend, TargetSpec};

/// How long [`Session::halt_for_exit`] gives an already-pending stop to land
/// before breaking in.
const EXIT_STOP_POLL: Duration = Duration::from_millis(200);

pub(super) fn prepare_backend_after_cleanup(
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
        spec.validate()?;
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
        if let Some(target) = target {
            session.open_site_journal(target);
        }
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
        session.open_site_journal(resource);
        Ok(session)
    }

    /// Take over the breakpoint-site journal of `resource`, whose instance
    /// lock this session holds, and put back every breakpoint instruction a
    /// previous session left patched into guest memory in this boot.
    fn open_site_journal(&mut self, resource: &str) {
        let Some(kernel_base) = self.target.kernel_base() else {
            return;
        };
        let Some(dir) = ntoseye_home()
            .map(|home| home.join("sites"))
            .filter(|dir| std::fs::create_dir_all(dir).is_ok())
        else {
            return;
        };
        let journal = SiteJournal::open(&dir, &instance_key(resource), kernel_base.0);
        let opcode = breakpoint_opcode(self.target.arch());
        let repair = journal.repair(self.target.phys.as_ref(), opcode);
        if repair.restored != 0 {
            self.notices.push(format!(
                "restored {} breakpoint instruction(s) a previous session left in guest memory",
                repair.restored
            ));
        }
        if repair.failed != 0 {
            self.notices.push(format!(
                "{} breakpoint instruction(s) a previous session left in guest memory could not \
                 be restored; they are retried on the next attach",
                repair.failed
            ));
        }
        self.target.site_journal = Some(journal);
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
        backend.set_windows_hypervisor(target.windows_hypervisor_running());
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
}

/// Per-target guard that one ntoseye session owns a given backend resource at a
/// time; a second attach against the same target would corrupt both. Held
/// inside [`Session`] for its lifetime (see [`Session::connect`]); dropping it
/// releases the lock.
pub(super) struct InstanceGuard(#[allow(dead_code)] SingleInstance);

/// Take the single-instance lock for `target`, or [`Error::AlreadyRunning`] if
/// another ntoseye already holds it. `target` is the backend resource identifier
/// (socket path, address, dump file) so instances on *different* targets can
/// coexist. Internal to [`Session::connect`], which calls it before connecting
/// a backend so a second instance fails fast rather than racing on the transport
/// handshake.
fn acquire_instance_guard(target: &str) -> Result<InstanceGuard> {
    let canonical = canonicalize_target(target);
    let key = instance_key(target);
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

/// The name a target is known by across sessions: its instance lock, and
/// the file its breakpoint-site journal lives in.
fn instance_key(target: &str) -> String {
    format!(
        "ntoseye-{:016x}",
        fnv1a_64(canonicalize_target(target).as_bytes())
    )
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
