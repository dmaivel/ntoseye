use rmcp::{
    ErrorData as McpError, ServiceExt,
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use crate::backend::MemoryOps;
use crate::bugchecks::{analyze_bugcheck, current_bugcheck};
use crate::dbg_backend::DebugBackend;
use crate::dmp::DmpBackend;
use crate::error::Error;
use crate::expr::Expr;
use crate::gdb::GdbClient;
use crate::kd::KdBackend;
use crate::memory_backend::MemoryBackend;
use crate::phys::PhysMem;
use crate::session::{ContinueOutcome, RunStatus, Session};
use crate::symbols::{FieldValue, TypeInfo};
use crate::target::{kthread_state_name, wait_reason_name};
use crate::types::VirtAddr;
use crate::view;

// MCP handlers are async/Send, but `Session` is not. A dedicated actor thread
// owns the session; handlers send closures and await one reply.
/// A unit of work run on the actor thread that owns the (`!Send`) session.
/// Returns JSON on success or a display string on error.
type SessionJob = Box<dyn FnOnce(&mut Session) -> Result<Value, ToolError> + Send>;

/// What the async handlers ask the actor to do.
enum Command {
    /// Run a job against the session and reply with its result.
    Run {
        job: SessionJob,
        reply: oneshot::Sender<Result<Value, ToolError>>,
    },
    /// Clean up the session (remove our breakpoints, resume the VM) and stop the
    /// actor. `ack` fires once cleanup is done so the caller can exit knowing the
    /// guest isn't left frozen with `int3`s installed.
    Shutdown { ack: oneshot::Sender<()> },
    /// A periodic nudge (from the background ticker) for the actor to service the
    /// guest while otherwise idle; absorb wrong-process hits on a shared-page
    /// breakpoint so they don't leave it frozen between tool calls. Carries no
    /// reply; the actor just runs `Session::service_idle`.
    Service,
}

/// How often the background ticker nudges the actor to service the guest (see
/// [`Command::Service`]). Small enough that a wrong-process breakpoint hit is
/// absorbed within a frame, large enough that the idle no-op is negligible.
const SERVICE_TICK: Duration = Duration::from_millis(20);

/// Tear down so the guest isn't left frozen at a stop with our `int3`s patched
/// in: remove breakpoints and leave the VM running (the halt-then-resume detail
/// lives in `Session::cleanup_for_exit`).
fn cleanup_session(ctx: &mut Session) {
    let _ = ctx.cleanup_for_exit();
}

/// Spawn the actor thread that owns the (`!Send`) debugging session. The backend
/// is constructed *on this thread* so the non-`Send` state never crosses a
/// thread boundary. Returns the sender the MCP handlers use to reach it.
fn spawn_session(
    backend: String,
    connect: Option<String>,
    dump: Option<PathBuf>,
) -> anyhow::Result<(mpsc::UnboundedSender<Command>, Arc<AtomicBool>)> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (tx, mut rx) = mpsc::unbounded_channel::<Command>();

    // Coalesces the background `Service` nudges: the ticker only enqueues one when
    // this is false (and sets it), the actor clears it as it services. Caps queued
    // `Service` commands at one, so a long `wait_for_stop` can't let a burst of
    // them pile up in the unbounded channel and drain all at once afterward.
    let service_pending = Arc::new(AtomicBool::new(false));
    let service_pending_actor = service_pending.clone();

    std::thread::spawn(move || {
        let is_dump = dump.is_some();

        // `connect` takes the per-target instance lock (on this actor thread,
        // where the `!Send` session lives) before building the backend, so a
        // second ntoseye can't attach to the same resource. Dumps and passive
        // memory introspection pass `None` (no lock needed).
        let built = (|| {
            if let Some(dump_path) = &dump {
                let phys = Arc::new(PhysMem::dmp(dump_path)?);
                let info = phys
                    .dmp_info()
                    .expect("dmp_info must be Some for DMP backend")
                    .clone();
                Session::connect(
                    phys,
                    None,
                    || -> crate::error::Result<Box<dyn DebugBackend>> {
                        Ok(Box::new(DmpBackend::new(&info)))
                    },
                )
            } else {
                let target = crate::resolve_target(backend.as_str(), connect.as_deref());
                let phys = Arc::new(PhysMem::kvm()?);
                Session::connect(phys, target.as_deref(), || {
                    let backend: Box<dyn DebugBackend> = match backend.as_str() {
                        "gdb" => Box::new(GdbClient::connect(
                            target.as_deref().unwrap(),
                        )?),
                        "kd" => Box::new(KdBackend::connect(
                            target.as_deref().unwrap(),
                        )?),
                        "memory" => Box::new(MemoryBackend::new()),
                        other => {
                            return Err(Error::DebugInfo(format!("unknown backend '{other}'")))
                        }
                    };
                    Ok(backend)
                })
            }
        })()
        .map_err(|e| e.to_string());

        let mut ctx = match built {
            Ok(ctx) => {
                let _ = ready_tx.send(Ok(()));
                ctx
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };

        // For live targets the MCP keeps the guest running between tool calls;
        // tools that need a stopped target ask the client to call `interrupt`
        // first. Dumps are always halted — skip the resume.
        if !is_dump && !ctx.backend.is_running() {
            let _ = ctx.backend.continue_execution();
        }

        // Synchronous job loop. `blocking_recv` is valid here because this is a
        // plain std thread with no tokio runtime on it. We clean up on an explicit
        // `Shutdown` (Ctrl+C / client disconnect drives one) and also if the
        // channel closes outright, so the VM is never left frozen.
        loop {
            match rx.blocking_recv() {
                Some(Command::Run { job, reply }) => {
                    // DIAGNOSTIC: every tool call submits exactly one Run job, so
                    // this logs whether the actor runs anything while you believe
                    // the session is idle (e.g. a client auto-probing tools).
                    // Gated on the same env as the kd traces so it interleaves.
                    if std::env::var_os("NTOSEYE_KD_TRACE").is_some() {
                        eprintln!("mcp: actor: running a tool job");
                    }
                    let _ = reply.send(job(&mut ctx));
                }
                Some(Command::Service) => {
                    service_pending_actor.store(false, Ordering::Release);
                    ctx.service_idle();
                }
                Some(Command::Shutdown { ack }) => {
                    cleanup_session(&mut ctx);
                    drop(ctx);
                    let _ = ack.send(());
                    break;
                }
                None => {
                    cleanup_session(&mut ctx);
                    break;
                }
            }
        }
    });

    match ready_rx.recv() {
        Ok(Ok(())) => Ok((tx, service_pending)),
        Ok(Err(e)) => Err(anyhow::anyhow!("failed to attach: {e}")),
        Err(_) => Err(anyhow::anyhow!("session thread exited before attaching")),
    }
}

/// The one shared session slot all transports funnel into. `Opening(gen)`
/// reserves the slot while `open_dump`/`open` builds a session off-thread,
/// so a concurrent open can't race the vacancy check and leak a second
/// actor. The generation counter lets [`OpeningGuard`] detect when its
/// reservation has been cancelled by a concurrent `close`.
enum SessionSlot {
    Vacant,
    Opening(u64),
    Active(mpsc::UnboundedSender<Command>),
}

static OPENING_GENERATION: AtomicU64 = AtomicU64::new(0);

type SharedSession = Arc<std::sync::Mutex<SessionSlot>>;

/// RAII guard that rolls `SessionSlot` back to `Vacant` if the opening future
/// is cancelled (e.g. MCP client timeout). Call [`OpeningGuard::promote`] to
/// install the active sender and defuse the rollback. The generation counter
/// ensures promote/drop only act on the `Opening` this guard created, not one
/// set by a concurrent open after a close race.
struct OpeningGuard {
    session: SharedSession,
    generation: u64,
}

impl OpeningGuard {
    fn claim(session: &SharedSession) -> Result<Self, McpError> {
        let mut guard = session.lock().unwrap();
        match *guard {
            SessionSlot::Vacant => {
                let id = OPENING_GENERATION.fetch_add(1, Ordering::Relaxed);
                *guard = SessionSlot::Opening(id);
                Ok(Self {
                    session: session.clone(),
                    generation: id,
                })
            }
            _ => Err(McpError::invalid_request(
                "a debugger session is already active or opening",
                None,
            )),
        }
    }

    fn promote(self, tx: mpsc::UnboundedSender<Command>) -> Result<(), McpError> {
        let mut guard = self.session.lock().unwrap();
        match *guard {
            SessionSlot::Opening(id) if id == self.generation => {
                *guard = SessionSlot::Active(tx);
                Ok(())
            }
            _ => Err(McpError::internal_error(
                "session open was cancelled",
                None,
            )),
        }
    }
}

impl Drop for OpeningGuard {
    fn drop(&mut self) {
        let mut guard = self.session.lock().unwrap();
        if matches!(*guard, SessionSlot::Opening(id) if id == self.generation) {
            *guard = SessionSlot::Vacant;
        }
    }
}

struct InterruptResetGuard(Arc<AtomicBool>);

impl Drop for InterruptResetGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct NtoseyeMcp {
    session: SharedSession,
    tool_router: ToolRouter<Self>,
    /// Flipped on shutdown so an in-flight `wait_for_stop` bails out promptly and
    /// the actor can run cleanup (resume the VM) before exit.
    interrupt: Arc<AtomicBool>,
}

// --- argument schemas ---

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct AddressArgs {
    #[schemars(
        description = "Address as a debugger expression (symbol, register, hex, arithmetic)"
    )]
    address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadMemoryArgs {
    #[schemars(description = "Start address as a debugger expression")]
    address: String,
    #[schemars(
        range(min = 1, max = 4096),
        description = "Number of bytes to read (range 1-4096)"
    )]
    length: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadCStringArgs {
    #[schemars(
        description = "Address of the NUL-terminated CHAR* string as a debugger expression"
    )]
    address: String,
    #[schemars(
        range(min = 1, max = 4096),
        description = "Maximum bytes to scan for the NUL terminator (default 260, range 1-4096)"
    )]
    max_len: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DisassembleArgs {
    #[schemars(description = "Start address as a debugger expression")]
    address: String,
    #[schemars(
        range(min = 1, max = 128),
        description = "Number of instructions to decode (range 1-128)"
    )]
    count: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BacktraceArgs {
    #[schemars(
        range(min = 1, max = 256),
        description = "Maximum number of frames to walk (default 64, range 1-256)"
    )]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TypeArgs {
    #[serde(rename = "type")]
    #[schemars(description = "Type name to look up across loaded modules, e.g. _EPROCESS")]
    type_name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SymbolSearchArgs {
    #[schemars(
        description = "Fuzzy symbol query; `module!query` (e.g. `nt!KiSwap`) scopes to one module"
    )]
    query: String,
    #[schemars(range(min = 1, max = 500), description = "Max results (default 50)")]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TypeSearchArgs {
    #[schemars(description = "Fuzzy type-name query, e.g. `_EPROCESS` or `KTHREAD`")]
    query: String,
    #[schemars(range(min = 1, max = 500), description = "Max results (default 50)")]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EnumSearchArgs {
    #[schemars(description = "Fuzzy enum-name query, e.g. `_KWAIT_REASON` or `_POOL_TYPE`")]
    query: String,
    #[schemars(range(min = 1, max = 500), description = "Max results (default 50)")]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadStructArgs {
    #[serde(rename = "type")]
    #[schemars(description = "Type name, e.g. _EPROCESS")]
    type_name: String,
    #[schemars(description = "Address of the struct as a debugger expression")]
    address: String,
}

/// Shared paging+filter args for the naturally-bounded enumerations
/// (processes/modules/drivers). `offset`/`limit` window the list like reading a
/// file by line range; `filter` is the ergonomic win for finding one entry.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListArgs {
    #[schemars(
        description = "Case-insensitive substring matched against the name (find a specific entry instead of paging all)"
    )]
    filter: Option<String>,
    #[schemars(
        description = "0-based index to start at (default 0). To page, pass the previous page's `next_offset`; absent means done."
    )]
    offset: Option<usize>,
    #[schemars(
        range(min = 1, max = 500),
        description = "Window size: how many to return from offset (default 100, range 1-500)"
    )]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ThreadsArgs {
    #[schemars(description = "Only threads belonging to this process id")]
    pid: Option<u64>,
    #[schemars(
        description = "0-based index to start at (default 0). To page, pass the previous page's `next_offset`; absent means done."
    )]
    offset: Option<usize>,
    #[schemars(
        range(min = 1, max = 200),
        description = "Window size (default 50, range 1-200). A live system has 1000+ threads; filter by pid and/or page via offset."
    )]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct MemoryMapArgs {
    #[schemars(description = "Process id whose VAD tree to enumerate")]
    pid: u64,
    #[schemars(
        description = "0-based index to start at (default 0). To page, pass the previous page's `next_offset`; absent means done."
    )]
    offset: Option<usize>,
    #[schemars(
        range(min = 1, max = 500),
        description = "Window size (default 200, range 1-500)."
    )]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct PidArgs {
    #[schemars(description = "Process id to attach the inspection context to")]
    pid: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetBreakpointArgs {
    #[schemars(
        description = "Breakpoint address as a debugger expression, e.g. user32!PostQuitMessage"
    )]
    address: String,
    #[schemars(
        description = "Optional break condition, re-evaluated each hit; the breakpoint only surfaces when it holds (e.g. \"$rcx == 0x4\" or a bare expression treated as non-zero). Comparison ops: == != < <= > >="
    )]
    condition: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct BreakpointIdArgs {
    #[schemars(description = "Breakpoint id")]
    id: u32,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SearchArgs {
    #[schemars(description = "Start address as a debugger expression")]
    start: String,
    #[schemars(
        description = "Byte pattern to find, as contiguous lowercase hex, e.g. \"48895c24\""
    )]
    pattern: String,
    #[schemars(
        range(min = 1, max = 1048576),
        description = "How many bytes to scan from start (range 1-1048576)"
    )]
    length: usize,
    #[schemars(
        description = "0-based index into the match list to start at (default 0). To page, pass the previous page's `next_offset`; absent means done."
    )]
    offset: Option<usize>,
    #[schemars(
        range(min = 1, max = 500),
        description = "Max matches to return from offset (default 50, range 1-500). A short pattern over a dense region can match millions of times."
    )]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WalkListArgs {
    #[schemars(
        description = "List-head address as a debugger expression, e.g. PsLoadedModuleList"
    )]
    head: String,
    #[schemars(description = "Record struct type the list links into, e.g. _LDR_DATA_TABLE_ENTRY")]
    record_type: String,
    #[schemars(
        description = "Name of the _LIST_ENTRY field inside the record, e.g. InLoadOrderLinks"
    )]
    link_field: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteMemoryArgs {
    #[schemars(description = "Start address as a debugger expression")]
    address: String,
    #[schemars(
        description = "Bytes to write as contiguous lowercase hex (same form read_memory returns), e.g. \"90909090\". 1-4096 bytes."
    )]
    hex: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ThreadIdArgs {
    #[schemars(description = "Thread/vCPU id to select as the current inspection thread")]
    thread: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct SetRegisterArgs {
    #[schemars(description = "Register name, e.g. rip, rax, rflags")]
    name: String,
    #[schemars(
        description = "New value as a debugger expression (symbol, register, hex, arithmetic)"
    )]
    value: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OpenDumpArgs {
    #[schemars(description = "Absolute path to a Windows kernel crash dump (.dmp) file")]
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OpenArgs {
    #[schemars(description = "Backend to use: \"kd\" (KD over Unix socket), \"gdb\" (GDB remote stub), or \"memory\" (physical memory only, no debug transport)")]
    backend: String,
    #[schemars(
        description = "Connection target: Unix socket path for kd (default /tmp/ntoseye-kd.sock), host:port for gdb (default 127.0.0.1:1234). Ignored for memory backend."
    )]
    connect: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EvalArgs {
    #[schemars(
        description = "Debugger expression to evaluate (symbol name, hex address, register, arithmetic, or poi())"
    )]
    expression: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadPointerArgs {
    #[schemars(
        description = "Address expression to read a pointer-sized (8-byte) value from"
    )]
    address: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WaitArgs {
    #[schemars(
        range(min = 0, max = 20000),
        description = "How long to wait for a stop before returning {stop:\"running\"} (default 10000, max 20000; 0 means use the default). Bounded by design: poll by calling again while it returns running. There is no indefinite wait; your MCP client times out the request on its own, and a long wait blocks every other tool on the single debugger session."
    )]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DebugLogArgs {
    #[schemars(
        description = "Resume cursor: pass the previous call's `next_seq` to get only lines captured since then. Default 0 returns from the oldest retained line."
    )]
    since_seq: Option<u64>,
}

const LIST_DEFAULT_LIMIT: usize = 100;
const LIST_MAX_LIMIT: usize = 500;
const THREADS_DEFAULT_LIMIT: usize = 50;
const THREADS_MAX_LIMIT: usize = 200;
const MEMORY_MAP_DEFAULT_LIMIT: usize = 200;
const MEMORY_MAP_MAX_LIMIT: usize = 500;
const READ_MEMORY_MAX_LENGTH: usize = 4096;
const READ_C_STRING_MAX_LENGTH: usize = 4096;
const READ_C_STRING_DEFAULT_LENGTH: usize = 260; // MAX_PATH, the common case
const WRITE_MEMORY_MAX_LENGTH: usize = 4096;
const SEARCH_MAX_LENGTH: usize = 1 << 20; // 1 MiB scanned per call
const SEARCH_DEFAULT_LIMIT: usize = 50;
const SEARCH_MAX_LIMIT: usize = 500;

const DISASSEMBLE_MAX_COUNT: usize = 128;
const BACKTRACE_DEFAULT_LIMIT: usize = 64;
const BACKTRACE_MAX_LIMIT: usize = 256;
const CONTINUE_DEFAULT_TIMEOUT_MS: u64 = 10_000;
// Capped well under common MCP client request timeouts (e.g. oh-my-pi defaults to
// 30s) so a wait returns {stop:"running"} and frees the single-session actor
// before the client gives up. No indefinite wait is offered over MCP.
const CONTINUE_MAX_TIMEOUT_MS: u64 = 20_000;

/// A tool failure carrying enough structure to map to the right MCP error class.
/// Keeps guest memory faults distinguishable from bad arguments and internal bugs.
enum ToolError {
    /// A bad argument value (JSON-RPC invalid params).
    Params(String),
    /// Well-formed but not valid in the current state (invalid request).
    Request(String),
    /// A guest memory access fault (unmapped page, partial read, ...).
    Memory(String),
    /// Anything else (internal error).
    Internal(String),
}

impl From<Error> for ToolError {
    fn from(e: Error) -> Self {
        let msg = e.to_string();
        match e {
            Error::BadVirtualAddress(_)
            | Error::BadPhysicalAddress(_)
            | Error::PartialRead(_)
            | Error::PartialWrite(_)
            | Error::BufferNotEnough
            | Error::InvalidRange => ToolError::Memory(msg),
            _ => ToolError::Internal(msg),
        }
    }
}

impl ToolError {
    fn into_mcp(self) -> McpError {
        match self {
            ToolError::Params(m) => McpError::invalid_params(m, None),
            ToolError::Request(m) => McpError::invalid_request(m, None),
            // No dedicated JSON-RPC code for a guest fault; surface it as an
            // invalid request tagged with `kind` so a client can tell "this
            // address isn't readable" apart from an internal bug.
            ToolError::Memory(m) => {
                McpError::invalid_request(m, Some(serde_json::json!({ "kind": "memory_access" })))
            }
            ToolError::Internal(m) => McpError::internal_error(m, None),
        }
    }
}

fn invalid_params(message: impl Into<String>) -> McpError {
    McpError::invalid_params(message.into(), None)
}

fn invalid_request(message: impl Into<String>) -> ToolError {
    ToolError::Request(message.into())
}

/// Turn a kernel-enumeration failure into an actionable directive when the kernel
/// lists aren't up yet (early boot / mid-rediscovery): the process and module
/// lists don't exist, so the raw "bad virtual address" is noise. Only rewrites
/// when the target is known-incoherent, so a genuine bad address still surfaces
/// as itself (classified by `ToolError::from`).
fn enumeration_error(ctx: &Session, e: Error) -> ToolError {
    if !ctx.kernel_coherent() {
        invalid_request(
            "guest is rebooting or at early boot: kernel process/module lists are not up yet, \
             so enumeration is unavailable. resume, then wait_for_stop until status reports \
             coherent:true, then retry.",
        )
    } else {
        ToolError::from(e)
    }
}

fn required_range(name: &str, value: usize, max: usize) -> Result<usize, McpError> {
    if value == 0 || value > max {
        Err(invalid_params(format!("{name} must be in range 1..={max}")))
    } else {
        Ok(value)
    }
}

fn optional_limit(
    name: &str,
    value: Option<usize>,
    default: usize,
    max: usize,
) -> Result<usize, McpError> {
    match value {
        Some(v) => required_range(name, v, max),
        None => Ok(default),
    }
}

fn optional_timeout_ms(value: Option<u64>) -> Result<u64, McpError> {
    // 0 or omitted means "use the default". There is deliberately no indefinite
    // wait over MCP: the client owns the request timeout, and a long wait pins the
    // single-session actor, so callers poll instead (a bounded wait returns
    // {stop:"running"} and the caller calls again).
    let ms = match value {
        None | Some(0) => CONTINUE_DEFAULT_TIMEOUT_MS,
        Some(ms) => ms,
    };
    if ms > CONTINUE_MAX_TIMEOUT_MS {
        Err(invalid_params(format!(
            "timeout_ms must be 0 (use default) or in range 1..={CONTINUE_MAX_TIMEOUT_MS}"
        )))
    } else {
        Ok(ms)
    }
}

fn require_halted(ctx: &mut Session, tool: &str) -> Result<(), ToolError> {
    // A stop the servicer already caught (e.g. an early-boot break) leaves the VM
    // physically halted while `is_running()` still reads stale-true. Ingest it
    // first so a genuinely halted target isn't turned away with "call interrupt";
    // a debugger-noise break-in is absorbed (resume), so only a VM that is truly
    // running, or stopped on a real, inspectable site, reaches the guard.
    ctx.settle_pending_stop().map_err(ToolError::from)?;
    // This op runs against the (already-rebuilt) current kernel, so the host has
    // engaged the target post-reboot: finish any memory-completable rediscovery
    // and stop deferring the reboot notification, so a later `wait_for_stop`
    // doesn't flush a stale `target_reloaded` into the middle of the agent's flow
    // (e.g. right after it set a kernel breakpoint). Matches what `status` does.
    ctx.try_finish_rediscovery_from_memory();
    ctx.clear_deferred_reload_surface();
    if ctx.backend.is_running() {
        Err(invalid_request(format!(
            "{tool} requires the VM to be halted; call interrupt first (resume afterwards with resume)"
        )))
    } else {
        Ok(())
    }
}

/// Render a [`ContinueOutcome`] as JSON, enriching breakpoint/exception stops with
/// the current process and resolved symbol from `ctx`.
fn continue_outcome_json(ctx: &Session, outcome: ContinueOutcome) -> Value {
    let process = ctx
        .target
        .current_process_info
        .as_ref()
        .map(|p| serde_json::json!({ "pid": p.pid, "name": p.name }));
    let symbol_at = |rip: u64| ctx.target.closest_symbol_current_context(VirtAddr(rip));
    match outcome {
        ContinueOutcome::Breakpoint {
            id,
            address,
            symbol,
            temporary,
            rip,
        } => serde_json::json!({
            "stop": "breakpoint",
            "id": id,
            "address": hex(address),
            "symbol": symbol.or_else(|| symbol_at(rip)),
            "temporary": temporary,
            "rip": hex(rip),
            "process": process,
        }),
        ContinueOutcome::Bugcheck { rip, info } => {
            let analysis = info
                .map(|i| analyze_bugcheck(&ctx.target, &i))
                .or_else(|| current_bugcheck(&ctx.target));
            serde_json::json!({
                "stop": "bugcheck",
                "rip": rip.map(hex),
                "bugcheck": analysis.as_ref().map(|a| view::to_json(&view::bugcheck(a))),
            })
        }
        ContinueOutcome::Stopped {
            rip,
            exception_code,
        } => serde_json::json!({
            "stop": "exception",
            "rip": hex(rip),
            "exception_code": exception_code,
            "symbol": symbol_at(rip),
            "process": process,
        }),
        ContinueOutcome::Step { rip } => serde_json::json!({
            "stop": "step",
            "rip": hex(rip),
            "symbol": symbol_at(rip),
            "process": process,
        }),
        ContinueOutcome::TargetReloaded {
            kernel_base,
            coherent,
        } => {
            let note = if coherent {
                "The guest rebooted and debugger state is now fully rebuilt against \
                 the new kernel: the loaded-module list is available and the system \
                 is introspectable. The VM is halted at an internal KD break-in (an \
                 arbitrary landing site, not a meaningful location). Every prior \
                 address (eprocess, ethread/kthread, module base, dtb) from before \
                 the reboot is invalid; re-enumerate (processes/threads/modules) \
                 before acting."
            } else {
                "The guest rebooted and the VM is halted at the earliest post-reboot \
                 stop, before kernel initialization: kernel symbols are loaded, but \
                 the loaded-module list does not exist yet, so process, thread, and \
                 module enumeration are UNAVAILABLE at this stop and most reads will \
                 fail or mislead. Every prior address (eprocess, ethread/kthread, \
                 module base, dtb) is now invalid; do not reuse results from before \
                 the reload. Use this stop to debug early boot (e.g. set breakpoints \
                 on init paths; hits are reported even while the system is coming \
                 up). Otherwise to reach a usable system: resume, then poll \
                 wait_for_stop, and only enumerate once status reports \
                 coherent:true (rediscovery finishes silently as the system comes \
                 up; this is the only reload stop reported). Enumerating while \
                 coherent:false returns a directive error, not data."
            };
            serde_json::json!({
                "stop": "target_reloaded",
                "kernel_base": kernel_base.map(hex),
                "coherent": coherent,
                "note": note,
            })
        }
        ContinueOutcome::Running => serde_json::json!({ "stop": "running" }),
        ContinueOutcome::Halted { rip } => serde_json::json!({
            "stop": "halted",
            // Not a new event; the VM was already parked here, so don't treat it
            // like a fresh breakpoint/exception stop.
            "event": false,
            "rip": hex(rip),
            "symbol": symbol_at(rip),
            "process": process,
            "coherent": ctx.kernel_coherent(),
        }),
    }
}

// --- value decoding helpers (run on the actor thread) ---

/// Resolve an address-expression argument against the live session.
fn eval_addr(ctx: &Session, expr: &str) -> Result<u64, ToolError> {
    Expr::eval(expr, &ctx.target)
        .map(|v| v.0)
        .map_err(|e| ToolError::Params(e.to_string()))
}

/// Lowercase contiguous hex for a byte slice.
fn hex_of(slice: &[u8]) -> String {
    slice.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode contiguous hex (the form `hex_of`/`read_memory` emit) back to bytes.
/// Rejects odd length and non-hex digits as invalid params.
fn bytes_of_hex(s: &str) -> Result<Vec<u8>, ToolError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err(invalid_request("hex must have an even number of digits"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| invalid_request("hex contains non-hex digits"))
        })
        .collect()
}

/// Format an address/value as a `0x` hex string. JSON numbers are decimal-only,
/// so addresses (which debugger users always read in hex) are emitted as strings.
fn hex(v: u64) -> String {
    format!("{v:#x}")
}

/// Decode a struct's fields the same way the Python SDK does: scalars (1/2/4/8
/// bytes) and pointers become ints, bitfields are masked to their value, and
/// larger aggregates become a hex string. Nested-struct fields the PDB reports
/// with size 0 are omitted; read those separately with their own type.
fn decode_struct(info: &TypeInfo, buf: &[u8]) -> Value {
    let mut map = serde_json::Map::new();
    for (name, value) in info.decode_fields(buf) {
        // A struct dump renders every scalar in hex (WinDbg `dt` convention):
        // type-stable and predictable, so the same field never flips between
        // decimal and hex across instances. Most 8-byte fields are addresses
        // anyway (ULONG_PTR/ULONGLONG the PDB types as ints, e.g.
        // _LOADER_PARAMETER_BLOCK.KernelStack/Prcb/Process); counts, sizes and
        // versions read as hex too, which a consumer converts trivially.
        // Aggregates stay contiguous bytes.
        let v = match value {
            FieldValue::Int(n) | FieldValue::Bitfield(n) | FieldValue::Pointer(n) => {
                Value::from(hex(n))
            }
            FieldValue::Bytes(b) => Value::from(hex_of(&b)),
        };
        map.insert(name, v);
    }
    Value::Object(map)
}

/// Build a paged list envelope: `{total, offset, returned, has_more, next_offset?, <key>: [...]}`.
/// `next_offset` is the offset of the next page, present only when more pages remain.
/// `total` is the count after filtering; `items` is the windowed slice.
fn paged(total: usize, offset: usize, key: &str, items: Vec<Value>) -> Value {
    let returned = items.len();
    let end = offset.saturating_add(returned);
    let mut obj = serde_json::json!({
        "total": total,
        "offset": offset,
        "returned": returned,
        "has_more": end < total,
    });
    if end < total {
        obj["next_offset"] = end.into();
    }
    obj[key] = Value::Array(items);
    obj
}

/// Wrap a JSON value as a successful tool result (pretty-printed text content).
// Structured tool result. rmcp's `structured()` also embeds a compact-text copy
// in `content`, so clients that ignore structuredContent still get JSON.
fn json_result(v: Value) -> Result<CallToolResult, McpError> {
    Ok(CallToolResult::structured(v))
}

fn run_status_json(s: RunStatus) -> Value {
    let process = s.process.map(|(pid, name, eprocess)| {
        serde_json::json!({ "pid": pid, "name": name, "eprocess": hex(eprocess) })
    });
    serde_json::json!({
        "running": s.running,
        "current_thread": s.current_thread,
        "rip": s.rip.map(hex),
        "symbol": s.symbol,
        "process": process,
        "coherent": s.coherent,
        "kernel_base": hex(s.kernel_base),
    })
}

fn status_json(ctx: &mut Session) -> Value {
    run_status_json(ctx.run_status())
}

fn frame_json(f: &crate::unwind::StackFrame) -> Value {
    serde_json::json!({
        "ip": hex(f.ip),
        "sp": hex(f.sp),
        "symbol": f.symbol,
        "source": f.source.as_str(),
    })
}

fn module_json(m: &crate::guest::ModuleInfo) -> Value {
    serde_json::json!({
        "name": m.name,
        "short_name": m.short_name,
        "base": hex(m.base_address.0),
        "end": hex(m.end_address().0),
        "size": m.size,
    })
}

fn read_virt_bytes(ctx: &mut Session, addr: u64, buf: &mut [u8]) -> Result<(), ToolError> {
    let process = ctx.target.current_process();
    process
        .memory()
        .read_bytes(VirtAddr(addr), buf)
        .map_err(ToolError::from)?;
    ctx.breakpoints
        .mask_breakpoint_bytes(VirtAddr(addr), buf, process.dtb());
    Ok(())
}

#[tool_router]
impl NtoseyeMcp {
    fn new(session: SharedSession, interrupt: Arc<AtomicBool>) -> Self {
        let tool_router = Self::tool_router();
        Self {
            session,
            tool_router,
            interrupt,
        }
    }

    /// Ship a job to the session actor and await its JSON reply.
    async fn run<F>(&self, job: F) -> Result<Value, McpError>
    where
        F: FnOnce(&mut Session) -> Result<Value, ToolError> + Send + 'static,
    {
        let tx = {
            let guard = self.session.lock().unwrap();
            match &*guard {
                SessionSlot::Active(tx) => tx.clone(),
                SessionSlot::Opening(_) => {
                    return Err(McpError::invalid_request(
                        "a debugger session is still opening; retry shortly",
                        None,
                    ));
                }
                SessionSlot::Vacant => {
                    return Err(McpError::invalid_request(
                        "no debugger session is active; call open_dump or open to attach",
                        None,
                    ));
                }
            }
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(Command::Run {
            job: Box::new(job),
            reply: reply_tx,
        })
        .map_err(|_| McpError::internal_error("debugger session is gone", None))?;
        reply_rx
            .await
            .map_err(|_| McpError::internal_error("debugger session dropped the request", None))?
            .map_err(ToolError::into_mcp)
    }

    #[tool(
        description = "List running processes (optional name filter; paged via offset/limit) as {total, offset, returned, has_more, next_offset?, processes:[{pid, name, eprocess, dtb}]}"
    )]
    async fn processes(
        &self,
        Parameters(ListArgs {
            filter,
            offset,
            limit,
        }): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let offset = offset.unwrap_or(0);
        let limit = optional_limit("limit", limit, LIST_DEFAULT_LIMIT, LIST_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                let matched = ctx
                    .target
                    .matching_processes(filter.as_deref())
                    .map_err(|e| enumeration_error(ctx, e))?;
                let total = matched.len();
                let items: Vec<Value> = matched
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|p| {
                        serde_json::json!({
                            "pid": p.pid,
                            "name": p.name,
                            "eprocess": hex(p.eprocess_va.0),
                            "dtb": hex(p.dtb),
                        })
                    })
                    .collect();
                Ok(paged(total, offset, "processes", items))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "List loaded kernel modules (optional name filter; paged via offset/limit) as {total, offset, returned, has_more, next_offset?, modules:[{name, short_name, base, end, size}]}"
    )]
    async fn kernel_modules(
        &self,
        Parameters(ListArgs {
            filter,
            offset,
            limit,
        }): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let offset = offset.unwrap_or(0);
        let limit = optional_limit("limit", limit, LIST_DEFAULT_LIMIT, LIST_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                let mods = ctx
                    .target
                    .guest
                    .kernel_modules()
                    .map_err(|e| enumeration_error(ctx, e))?;
                let f = filter.as_deref().map(str::to_ascii_lowercase);
                let matched: Vec<_> = mods
                    .iter()
                    .filter(|m| {
                        f.as_deref().is_none_or(|f| {
                            m.name.to_ascii_lowercase().contains(f)
                                || m.short_name.to_ascii_lowercase().contains(f)
                        })
                    })
                    .collect();
                let total = matched.len();
                let items: Vec<Value> = matched
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|m| module_json(m))
                    .collect();
                Ok(paged(total, offset, "modules", items))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "List driver objects (optional name filter; paged via offset/limit) as {total, offset, returned, has_more, next_offset?, drivers:[{name, object, driver_start, driver_size, device_object, driver_unload}]}"
    )]
    async fn driver_objects(
        &self,
        Parameters(ListArgs {
            filter,
            offset,
            limit,
        }): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let offset = offset.unwrap_or(0);
        let limit = optional_limit("limit", limit, LIST_DEFAULT_LIMIT, LIST_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                let drivers = ctx
                    .target
                    .enumerate_driver_objects()
                    .map_err(|e| enumeration_error(ctx, e))?;
                let f = filter.as_deref().map(str::to_ascii_lowercase);
                let matched: Vec<_> = drivers
                    .iter()
                    .filter(|d| {
                        f.as_deref()
                            .is_none_or(|f| d.name.to_ascii_lowercase().contains(f))
                    })
                    .collect();
                let total = matched.len();
                let items: Vec<Value> = matched
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|d| {
                        serde_json::json!({
                            "name": d.name,
                            "object": hex(d.object.0),
                            "driver_start": hex(d.driver_start.0),
                            "driver_size": d.driver_size,
                            "device_object": hex(d.device_object.0),
                            "driver_unload": hex(d.driver_unload.0),
                        })
                    })
                    .collect();
                Ok(paged(total, offset, "drivers", items))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "List Windows threads (filter by pid; paged via offset/limit) as {total, offset, returned, has_more, next_offset?, threads:[{tid, pid, process_name, ethread, kthread, eprocess, state, state_name, wait_reason, wait_reason_name, active}]}. `active` is the vCPU id currently running the thread (only resolved when the VM is halted), else null. A live system has 1000+ threads; pass pid to scope to one process."
    )]
    async fn threads(
        &self,
        Parameters(ThreadsArgs { pid, offset, limit }): Parameters<ThreadsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let offset = offset.unwrap_or(0);
        let limit = optional_limit("limit", limit, THREADS_DEFAULT_LIMIT, THREADS_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                let (threads, active) = ctx
                    .windows_threads()
                    .map_err(|e| enumeration_error(ctx, e))?;
                let matched: Vec<_> = threads
                    .iter()
                    .filter(|t| pid.is_none_or(|p| t.pid == Some(p)))
                    .collect();
                let total = matched.len();
                let items: Vec<Value> = matched
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|t| {
                        serde_json::json!({
                            "tid": t.tid,
                            "pid": t.pid,
                            "process_name": t.process_name,
                            "ethread": hex(t.ethread.0),
                            "kthread": hex(t.kthread.0),
                            "eprocess": t.eprocess.map(|a| hex(a.0)),
                            "state": t.state,
                            "state_name": t.state.map(kthread_state_name),
                            "wait_reason": t.wait_reason,
                            "wait_reason_name": t.wait_reason.map(wait_reason_name),
                            "active": active.get(&t.ethread.0),
                        })
                    })
                    .collect();
                Ok(paged(total, offset, "threads", items))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Inspect every vCPU as {vcpus:[{id, rip, context, symbol, error}]}: the address space each is executing in (\"kernel\", a process name, or \"unknown\") and the nearest symbol. Requires the VM halted (call interrupt first, or be stopped at a breakpoint)."
    )]
    async fn vcpus(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                require_halted(ctx, "vcpus")?;
                let vcpus = ctx.vcpus().map_err(ToolError::from)?;
                let items: Vec<Value> = vcpus
                    .into_iter()
                    .map(|v| {
                        serde_json::json!({
                            "id": v.id,
                            "rip": v.rip.map(hex),
                            "context": v.context,
                            "symbol": v.symbol,
                            "error": v.error,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "vcpus": items }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Read all registers of the current thread as a {name: value} object. Requires the VM halted (call interrupt first, or be stopped at a breakpoint)."
    )]
    async fn registers(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                require_halted(ctx, "registers")?;
                let regs = ctx.backend.read_registers().map_err(ToolError::from)?;
                let map: serde_json::Map<String, Value> = ctx
                    .register_map
                    .to_hashmap(&regs)
                    .into_iter()
                    .map(|(name, value)| (name, Value::from(hex(value))))
                    .collect();
                Ok(Value::Object(map))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Read guest virtual memory in the current address space (attached process or kernel); length must be 1-4096. Returns {address, length, hex} (hex is contiguous bytes)"
    )]
    async fn read_memory(
        &self,
        Parameters(ReadMemoryArgs { address, length }): Parameters<ReadMemoryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let length = required_range("length", length, READ_MEMORY_MAX_LENGTH)?;
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let len = length;
                let mut buf = vec![0u8; len];
                read_virt_bytes(ctx, addr, &mut buf)?;
                Ok(serde_json::json!({
                    "address": hex(addr),
                    "length": len,
                    "hex": hex_of(&buf),
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Disassemble 1-128 instructions at an address in the current address space; returns {instructions:[{ip, hex, asm, comment}]}"
    )]
    async fn disassemble(
        &self,
        Parameters(DisassembleArgs { address, count }): Parameters<DisassembleArgs>,
    ) -> Result<CallToolResult, McpError> {
        let count = required_range("count", count, DISASSEMBLE_MAX_COUNT)?;
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let rows = ctx
                    .disassemble(VirtAddr(addr), count)
                    .map_err(ToolError::from)?;
                let arr: Vec<Value> = rows
                    .iter()
                    .map(|r| {
                        serde_json::json!({
                            "ip": hex(r.ip),
                            "hex": r.hex,
                            "asm": r.asm,
                            "comment": r.comment,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "instructions": arr }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Walk the current thread's call stack; limit default 64, range 1-256. Returns {frames:[{ip, sp, symbol, source}]} (source: current/unwind/scan). Requires the VM halted (call interrupt first, or be stopped at a breakpoint)."
    )]
    async fn backtrace(
        &self,
        Parameters(BacktraceArgs { limit }): Parameters<BacktraceArgs>,
    ) -> Result<CallToolResult, McpError> {
        let limit = optional_limit("limit", limit, BACKTRACE_DEFAULT_LIMIT, BACKTRACE_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                require_halted(ctx, "backtrace")?;
                let trace = ctx.backtrace(limit).map_err(ToolError::from)?;
                let arr: Vec<Value> = trace.frames.iter().map(frame_json).collect();
                Ok(serde_json::json!({ "frames": arr }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Walk the page tables for an address; returns {address, levels:[{level, address, value, pfn, present, large_page, writable, user, nx, flags}]}"
    )]
    async fn pte_walk(
        &self,
        Parameters(AddressArgs { address }): Parameters<AddressArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let t = ctx
                    .target
                    .pte_traverse(VirtAddr(addr))
                    .map_err(ToolError::from)?;
                let mut levels = vec![
                    view::to_json(&view::pte_level(&t.pxe)),
                    view::to_json(&view::pte_level(&t.ppe)),
                ];
                if let Some(pde) = &t.pde {
                    levels.push(view::to_json(&view::pte_level(pde)));
                }
                if let Some(pte) = &t.pte {
                    levels.push(view::to_json(&view::pte_level(pte)));
                }
                Ok(serde_json::json!({
                    "address": hex(t.address.0),
                    "dtb": hex(t.dtb),
                    "levels": levels,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Inspect an _IRP at an address (expression) in the current address space. Returns {address, type, size, stack_count, current_location, pending_returned, requestor_mode, io_status, user_event, user_buffer, mdl_address, thread, current_stack:{address, major_function, major_function_name, minor_function, device_object, file_object, completion_routine, context}|null}. current_stack is null when CurrentLocation is out of range or the slot is unreadable."
    )]
    async fn inspect_irp(
        &self,
        Parameters(AddressArgs { address }): Parameters<AddressArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let irp = ctx
                    .target
                    .inspect_irp(VirtAddr(addr))
                    .map_err(ToolError::from)?;
                Ok(view::to_json(&view::irp(&irp)))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Inspect a _DRIVER_OBJECT at an address (expression). Accepts a pointer to one. Returns {object, via_pointer, name, driver_start, driver_size, driver_section, driver_unload, devices:[{device, device_type, flags, characteristics, attached, next}], dispatch:[{index, name, routine, symbol}]} where dispatch is the 28-entry IRP_MJ_* table."
    )]
    async fn inspect_driver_object(
        &self,
        Parameters(AddressArgs { address }): Parameters<AddressArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let d = ctx
                    .target
                    .inspect_driver_object(VirtAddr(addr))
                    .map_err(ToolError::from)?;
                Ok(view::to_json(&view::driver_object(&ctx.target, &d)))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Inspect a _DEVICE_OBJECT at an address (expression). Accepts a pointer to one. Returns {object, via_pointer, device_type, flags, characteristics, driver_object, attached_device, next_device, current_irp, device_extension, attached_stack:[{device, driver_object, device_type, flags}]}."
    )]
    async fn inspect_device_object(
        &self,
        Parameters(AddressArgs { address }): Parameters<AddressArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let d = ctx
                    .target
                    .inspect_device_object(VirtAddr(addr))
                    .map_err(ToolError::from)?;
                Ok(view::to_json(&view::device_object(&d)))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Inspect an executive _OBJECT_HEADER for an address (expression), accepting either the object body or the header. Returns {input, mode, header, body, pointer_count, handle_count, type_index, type_object, type_name, info_mask, name_info, name}. mode is 'body' or 'header'; type_name/name are null when unresolved."
    )]
    async fn inspect_object_header(
        &self,
        Parameters(AddressArgs { address }): Parameters<AddressArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let o = ctx
                    .target
                    .inspect_object_header(VirtAddr(addr))
                    .map_err(ToolError::from)?;
                Ok(view::to_json(&view::object_header(&o)))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Enumerate process/thread/image notification callbacks (Psp*NotifyRoutine arrays). `filter` is a case-insensitive substring matched against the resolved routine symbol. Paged via offset/limit. Returns {total, offset, returned, has_more, next_offset?, callbacks:[{kind, index, function, symbol, block, raw, context}]}."
    )]
    async fn notify_callbacks(
        &self,
        Parameters(ListArgs {
            filter,
            offset,
            limit,
        }): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let offset = offset.unwrap_or(0);
        let limit = optional_limit("limit", limit, LIST_DEFAULT_LIMIT, LIST_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                let dtb = ctx.target.guest.ntoskrnl.dtb();
                let cbs = ctx
                    .target
                    .enumerate_notify_callbacks()
                    .map_err(ToolError::from)?;
                let f = filter.as_deref().map(str::to_ascii_lowercase);
                let rows: Vec<Value> = cbs
                    .iter()
                    .map(|c| {
                        let symbol = ctx
                            .target
                            .symbols
                            .format_closest_symbol_for_address(dtb, c.function);
                        (c, symbol)
                    })
                    .filter(|(_, symbol)| {
                        f.as_deref().is_none_or(|f| {
                            symbol
                                .as_deref()
                                .is_some_and(|s| s.to_ascii_lowercase().contains(f))
                        })
                    })
                    .map(|(c, symbol)| view::to_json(&view::notify_callback(c, symbol)))
                    .collect();
                let total = rows.len();
                let items: Vec<Value> = rows.into_iter().skip(offset).take(limit).collect();
                Ok(paged(total, offset, "callbacks", items))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Dump the kernel SSDT (KiServiceTable) and, when initialized, the win32k shadow table. Returns {tables:[{label, base, limit, entries:[{index, target, symbol, module}]}]}. An entry whose module differs from the expected owner (ntoskrnl/win32k) is a candidate hook."
    )]
    async fn ssdt(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let tables = ctx.target.dump_ssdt().map_err(ToolError::from)?;
                let tables: Vec<Value> = tables
                    .iter()
                    .map(|t| view::to_json(&view::ssdt_table(t)))
                    .collect();
                Ok(serde_json::json!({ "tables": tables }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Discover in-flight IRPs from each thread's _ETHREAD.IrpList and each device's _DEVICE_OBJECT.CurrentIrp. `filter` scopes processes (pid or name substring) and driver names; a numeric/pid filter skips the device sweep. Paged via offset/limit. Returns {total, offset, returned, has_more, next_offset?, irps:[{irp, source, stack_count, current_location, pid, tid, ethread, state, wait_reason, driver, device}]}."
    )]
    async fn discover_irps(
        &self,
        Parameters(ListArgs {
            filter,
            offset,
            limit,
        }): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let offset = offset.unwrap_or(0);
        let limit = optional_limit("limit", limit, LIST_DEFAULT_LIMIT, LIST_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                let hits = ctx
                    .target
                    .discover_irps(filter.as_deref())
                    .map_err(ToolError::from)?;
                let total = hits.len();
                let items: Vec<Value> = hits
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|h| view::to_json(&view::irp_hit(h)))
                    .collect();
                Ok(paged(total, offset, "irps", items))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Describe what an address belongs to (complements pte_walk's how-it's-mapped with where-it-lives). Returns {address, dtb, kind, module:{name, base, size, offset}|null, section|null, va_type|null, region:{start, end, protection, vad_type, private_memory, commit_charge, details}|null}. kind is kernel-module/user-image/kernel-region/private/mapped/unknown; section is the PE section for a module hit; va_type is the MM region name (e.g. KernelStacks, PagedPool, SystemPtes) for a kernel address; region is the VAD entry for a process address."
    )]
    async fn describe_address(
        &self,
        Parameters(AddressArgs { address }): Parameters<AddressArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let d = ctx
                    .target
                    .describe_address(VirtAddr(addr))
                    .map_err(ToolError::from)?;
                Ok(view::to_json(&view::address_description(&d)))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Resolve the nearest symbol to an address as module!name+0x..; returns {address, symbol}"
    )]
    async fn closest_symbol(
        &self,
        Parameters(AddressArgs { address }): Parameters<AddressArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let symbol = ctx.target.closest_symbol_current_context(VirtAddr(addr));
                Ok(serde_json::json!({ "address": hex(addr), "symbol": symbol }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Get a struct/class type's layout; returns {name, size, fields:[{name, offset, size, type}]} sorted by offset. Use enum_values for PDB enums."
    )]
    async fn type_layout(
        &self,
        Parameters(TypeArgs { type_name }): Parameters<TypeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let dtb = ctx.target.current_dtb();
                let info = ctx
                    .target
                    .symbols
                    .find_type_across_modules(dtb, &type_name)
                    .ok_or_else(|| {
                        ToolError::Request(ctx.target.symbols.unresolved_type_message(dtb, &type_name))
                    })?;
                let fields: Vec<Value> = {
                    let mut fields: Vec<_> = info.fields.iter().collect();
                    fields.sort_by_key(|(_, f)| f.offset);
                    fields
                }
                .into_iter()
                .map(|(n, f)| {
                    serde_json::json!({
                        "name": n,
                        "offset": hex(f.offset as u64),
                        "size": f.size,
                        "type": format!("{}", f.type_data),
                    })
                })
                .collect();
                Ok(serde_json::json!({
                    "name": type_name,
                    "size": info.size,
                    "fields": fields,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Fuzzy-search symbols by name (use `module!query` to scope to one module). Returns {query, total, symbols:[{name, address, module}]}; address/module are null when a name doesn't resolve in the current context."
    )]
    async fn search_symbols(
        &self,
        Parameters(SymbolSearchArgs { query, limit }): Parameters<SymbolSearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let limit = optional_limit("limit", limit, 50, 500)?;
        let v = self
            .run(move |ctx| {
                let dtb = ctx.target.current_dtb();
                let (module, names) = match query.split_once('!') {
                    Some((m, q)) => (
                        Some(m.to_string()),
                        ctx.target
                            .symbols
                            .search_symbols_in_module(dtb, m, q, limit),
                    ),
                    None => (
                        None,
                        ctx.target.current_symbol_index().search(&query, limit),
                    ),
                };
                let symbols: Vec<Value> = names
                    .iter()
                    .map(|name| {
                        let lookup = match &module {
                            Some(m) => format!("{m}!{name}"),
                            None => name.clone(),
                        };
                        let resolved = ctx.target.symbols.find_symbol_with_module(dtb, &lookup);
                        serde_json::json!({
                            "name": name,
                            "address": resolved.as_ref().map(|(a, _)| hex(a.0)),
                            "module": resolved.map(|(_, m)| m),
                        })
                    })
                    .collect();
                Ok(serde_json::json!({
                    "query": query,
                    "total": symbols.len(),
                    "symbols": symbols,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Fuzzy-search struct/class type names across loaded modules. Returns {query, total, types:[name]}; feed a name to type_layout for its fields. Use search_enums for PDB enums."
    )]
    async fn search_types(
        &self,
        Parameters(TypeSearchArgs { query, limit }): Parameters<TypeSearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let limit = optional_limit("limit", limit, 50, 500)?;
        let v = self
            .run(move |ctx| {
                let names = ctx.target.current_types_index().search(&query, limit);
                Ok(serde_json::json!({
                    "query": query,
                    "total": names.len(),
                    "types": names,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Fuzzy-search PDB enum names across loaded modules. Returns {query, total, enums:[name]}; feed a name to enum_values."
    )]
    async fn search_enums(
        &self,
        Parameters(EnumSearchArgs { query, limit }): Parameters<EnumSearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let limit = optional_limit("limit", limit, 50, 500)?;
        let v = self
            .run(move |ctx| {
                let names = ctx.target.current_enums_index().search(&query, limit);
                Ok(serde_json::json!({
                    "query": query,
                    "total": names.len(),
                    "enums": names,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "List a PDB enum's variants (in declaration order) as {name, values:[{name, value}]}. Enums aren't structs, so use this rather than type_layout (e.g. _MI_SYSTEM_VA_TYPE, _KWAIT_REASON, _POOL_TYPE)."
    )]
    async fn enum_values(
        &self,
        Parameters(TypeArgs { type_name }): Parameters<TypeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let variants = ctx
                    .target
                    .symbols
                    .find_enum_across_modules(ctx.target.current_dtb(), &type_name)
                    .ok_or_else(|| ToolError::Request(format!("unknown enum: {type_name}")))?;
                let values: Vec<Value> = variants
                    .into_iter()
                    .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                    .collect();
                Ok(serde_json::json!({ "name": type_name, "values": values }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Read a typed struct at an address in the current address space; returns {type, address, fields:{name: value}}. Nested structs are omitted; read them separately at their own address."
    )]
    async fn read_struct(
        &self,
        Parameters(ReadStructArgs { type_name, address }): Parameters<ReadStructArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let dtb = ctx.target.current_dtb();
                let info = ctx
                    .target
                    .symbols
                    .find_type_across_modules(dtb, &type_name)
                    .ok_or_else(|| {
                        ToolError::Request(ctx.target.symbols.unresolved_type_message(dtb, &type_name))
                    })?;
                let mut buf = vec![0u8; info.size];
                read_virt_bytes(ctx, addr, &mut buf)?;
                Ok(serde_json::json!({
                    "type": type_name,
                    "address": hex(addr),
                    "fields": decode_struct(&info, &buf),
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Enumerate a process's virtual address map (VAD tree) by pid, paged via offset/limit; returns {total, offset, returned, has_more, next_offset?, regions:[{start, end, size, protection, vad_type, private, commit, details}]}"
    )]
    async fn memory_map(
        &self,
        Parameters(MemoryMapArgs { pid, offset, limit }): Parameters<MemoryMapArgs>,
    ) -> Result<CallToolResult, McpError> {
        let offset = offset.unwrap_or(0);
        let limit = optional_limit(
            "limit",
            limit,
            MEMORY_MAP_DEFAULT_LIMIT,
            MEMORY_MAP_MAX_LIMIT,
        )?;
        let v = self
            .run(move |ctx| {
                let process = ctx
                    .target
                    .guest
                    .enumerate_processes()
                    .map_err(|e| enumeration_error(ctx, e))?
                    .into_iter()
                    .find(|p| p.pid == pid)
                    .ok_or_else(|| ToolError::Request(format!("no process with pid {pid}")))?;
                let all = ctx
                    .target
                    .enumerate_vad_regions_for_process_info(&process)
                    .map_err(ToolError::from)?;
                let total = all.len();
                let items: Vec<Value> = all
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|r| {
                        serde_json::json!({
                            "start": hex(r.start.0),
                            "end": hex(r.end.0),
                            "size": r.size(),
                            "protection": r.protection,
                            "vad_type": r.vad_type,
                            "private": r.private_memory,
                            "commit": r.commit_charge,
                            "details": r.details,
                        })
                    })
                    .collect();
                Ok(paged(total, offset, "regions", items))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Current inspection context: {dtb, current_thread, process:{pid, name, eprocess}|null}"
    )]
    async fn context(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                let process = ctx.target.current_process_info.as_ref().map(|p| {
                    serde_json::json!({
                        "pid": p.pid,
                        "name": p.name,
                        "eprocess": hex(p.eprocess_va.0),
                    })
                });
                Ok(serde_json::json!({
                    "dtb": hex(ctx.target.current_dtb()),
                    "current_thread": ctx.current_thread,
                    "process": process,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Analyze the current bugcheck (BSOD): {code, code_hex, name, description, driver, args:[{index, value, description}], fault:{ip, symbol, driver}, source}, or null if the guest is not bugchecking"
    )]
    async fn bugcheck(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                Ok(match current_bugcheck(&ctx.target) {
                    Some(analysis) => view::to_json(&view::bugcheck(&analysis)),
                    None => Value::Null,
                })
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Read captured guest debug output (DbgPrint, e.g. \"DriverEntry failed 0x...\"). Snapshot+cursor: pass since_seq (the prior call's next_seq) to poll only new lines; returns {lines:[{seq, timestamp_ms, text}], next_seq, dropped}. dropped=true means older lines were evicted before you read them (poll more often). Output is captured only while the target runs, so resume to let it accumulate; an empty result is not proof the guest is silent. Empty on backends without a debug stream."
    )]
    async fn debug_log(
        &self,
        Parameters(DebugLogArgs { since_seq }): Parameters<DebugLogArgs>,
    ) -> Result<CallToolResult, McpError> {
        let since = since_seq.unwrap_or(0);
        let v = self
            .run(move |ctx| {
                let page = ctx.read_debug_output(since);
                let lines: Vec<Value> = page
                    .lines
                    .iter()
                    .map(|l| {
                        serde_json::json!({
                            "seq": l.seq,
                            "timestamp_ms": l.timestamp_ms,
                            "text": l.text,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({
                    "lines": lines,
                    "next_seq": page.next_seq,
                    "dropped": page.dropped,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "List the backend's capability matrix - which debug operations the current transport (kd/gdb/memory/dump) supports - as {capabilities:[{capability, label, supported}]}. Check before a state-changing op (e.g. usermode breakpoints)."
    )]
    async fn capabilities(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                let arr: Vec<Value> = ctx
                    .capabilities()
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "capability": format!("{:?}", c.capability),
                            "label": c.capability.label(),
                            "supported": c.supported,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "capabilities": arr }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "List loaded modules for the current inspection scope: the attached process's user-mode modules when attached (attach_process), otherwise the kernel module list. Optional name filter; paged via offset/limit. Returns {total, offset, returned, has_more, next_offset?, modules:[{name, short_name, base, end, size}]}. Use kernel_modules to list kernel modules regardless of attach state."
    )]
    async fn modules(
        &self,
        Parameters(ListArgs {
            filter,
            offset,
            limit,
        }): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let offset = offset.unwrap_or(0);
        let limit = optional_limit("limit", limit, LIST_DEFAULT_LIMIT, LIST_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                let mods = ctx
                    .target
                    .modules()
                    .map_err(|e| enumeration_error(ctx, e))?;
                let f = filter.as_deref().map(str::to_ascii_lowercase);
                let matched: Vec<_> = mods
                    .iter()
                    .filter(|m| {
                        f.as_deref().is_none_or(|f| {
                            m.name.to_ascii_lowercase().contains(f)
                                || m.short_name.to_ascii_lowercase().contains(f)
                        })
                    })
                    .collect();
                let total = matched.len();
                let items: Vec<Value> = matched
                    .iter()
                    .skip(offset)
                    .take(limit)
                    .map(|m| module_json(m))
                    .collect();
                Ok(paged(total, offset, "modules", items))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Search guest memory in the current address space: scan `length` bytes from `start` for a byte `pattern` (contiguous lowercase hex). Returns {start, length, total, offset, returned, has_more, next_offset?, matches:[{address, offset, symbol, kind, module, section, va_type, region}]}; `total` is the full match count and `matches` is the offset/limit window."
    )]
    async fn search(
        &self,
        Parameters(SearchArgs {
            start,
            pattern,
            length,
            offset,
            limit,
        }): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let length = required_range("length", length, SEARCH_MAX_LENGTH)?;
        let offset = offset.unwrap_or(0);
        let limit = optional_limit("limit", limit, SEARCH_DEFAULT_LIMIT, SEARCH_MAX_LIMIT)?;
        let v = self
            .run(move |ctx| {
                let start_addr = eval_addr(ctx, &start)?;
                let needle = bytes_of_hex(&pattern)?;
                if needle.is_empty() {
                    return Err(invalid_request("pattern must be at least one byte"));
                }
                let matches = ctx
                    .target
                    .search(VirtAddr(start_addr), &needle, length)
                    .map_err(ToolError::from)?;
                let total = matches.len();
                let page: Vec<u64> = matches.into_iter().skip(offset).take(limit).collect();
                let items: Vec<Value> = ctx
                    .target
                    .describe_search_matches(VirtAddr(start_addr), &page)
                    .map_err(ToolError::from)?
                    .iter()
                    .map(|m| view::to_json(&view::memory_search_match(m)))
                    .collect();
                let mut out = paged(total, offset, "matches", items);
                out["start"] = Value::from(hex(start_addr));
                out["length"] = Value::from(length);
                Ok(out)
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Walk an intrusive _LIST_ENTRY list in the current address space. Given the list-head address, the record struct type, and the name of the _LIST_ENTRY field embedded in the record, returns each record's base address: {head, record_type, total, records:[addr...]}. Bounded to 1000 records. E.g. head=PsLoadedModuleList, record_type=_LDR_DATA_TABLE_ENTRY, link_field=InLoadOrderLinks."
    )]
    async fn walk_list(
        &self,
        Parameters(WalkListArgs {
            head,
            record_type,
            link_field,
        }): Parameters<WalkListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let head_addr = eval_addr(ctx, &head)?;
                let dtb = ctx.target.current_dtb();
                let info = ctx
                    .target
                    .symbols
                    .find_type_across_modules(dtb, &record_type)
                    .ok_or_else(|| invalid_request(format!("unknown type: {record_type}")))?;
                let link_offset = info.field_offset(&link_field).map_err(ToolError::from)?;
                let records = ctx
                    .target
                    .walk_list(VirtAddr(head_addr), link_offset)
                    .map_err(ToolError::from)?;
                Ok(serde_json::json!({
                    "head": hex(head_addr),
                    "record_type": record_type,
                    "total": records.len(),
                    "records": records.into_iter().map(hex).collect::<Vec<_>>(),
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Decode the _UNICODE_STRING at an address in the current address space to a string. Returns {address, value}."
    )]
    async fn read_unicode_string(
        &self,
        Parameters(AddressArgs { address }): Parameters<AddressArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let value = ctx
                    .target
                    .read_unicode_string(VirtAddr(addr))
                    .map_err(ToolError::from)?;
                Ok(serde_json::json!({ "address": hex(addr), "value": value }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Read a NUL-terminated CHAR* (ASCII/UTF-8) string at an address in the current address space, up to max_len bytes (default 260). Returns {address, value}. The CHAR* counterpart to read_unicode_string; use it for ARC paths, boot LoadOptions, and other plain C strings."
    )]
    async fn read_c_string(
        &self,
        Parameters(ReadCStringArgs { address, max_len }): Parameters<ReadCStringArgs>,
    ) -> Result<CallToolResult, McpError> {
        let max_len = optional_limit(
            "max_len",
            max_len,
            READ_C_STRING_DEFAULT_LENGTH,
            READ_C_STRING_MAX_LENGTH,
        )?;
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let value = ctx
                    .target
                    .read_c_string(VirtAddr(addr), max_len)
                    .map_err(ToolError::from)?;
                Ok(serde_json::json!({ "address": hex(addr), "value": value }))
            })
            .await?;
        json_result(v)
    }

    // --- context / run-control (state-changing) ---

    #[tool(
        description = "Switch the inspection context to a process by pid (scopes memory reads and breakpoints to it and loads its module symbols); returns {pid, name}"
    )]
    async fn attach_process(
        &self,
        Parameters(PidArgs { pid }): Parameters<PidArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let report = ctx.target.attach(pid).map_err(ToolError::from)?;
                Ok(serde_json::json!({ "pid": pid, "name": report.name }))
            })
            .await?;
        json_result(v)
    }

    #[tool(description = "Return the inspection context to the default kernel scope")]
    async fn detach(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                ctx.target.detach();
                Ok(serde_json::json!({ "detached": true }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Set a code breakpoint at an address (scoped to the attached process, or kernel-wide if not attached), with an optional break condition. Requires the VM halted (call interrupt first, or be stopped at a breakpoint); resume then wait_for_stop to run to a hit. Returns {id, address, condition}"
    )]
    async fn set_breakpoint(
        &self,
        Parameters(SetBreakpointArgs { address, condition }): Parameters<SetBreakpointArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                require_halted(ctx, "set_breakpoint")?;
                let addr = eval_addr(ctx, &address)?;
                let id = ctx
                    .add_breakpoint_with_condition(VirtAddr(addr), condition.clone())
                    .map_err(ToolError::from)?;
                Ok(serde_json::json!({ "id": id, "address": hex(addr), "condition": condition }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Remove a breakpoint by id. Requires the VM halted (call interrupt first, or be stopped at a breakpoint)."
    )]
    async fn clear_breakpoint(
        &self,
        Parameters(BreakpointIdArgs { id }): Parameters<BreakpointIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                require_halted(ctx, "clear_breakpoint")?;
                ctx.remove_breakpoint(id).map_err(ToolError::from)?;
                Ok(serde_json::json!({ "cleared": id }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Re-arm a disabled breakpoint by id (re-patch its int3). Requires the VM halted (call interrupt first, or be stopped at a breakpoint)."
    )]
    async fn enable_breakpoint(
        &self,
        Parameters(BreakpointIdArgs { id }): Parameters<BreakpointIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                require_halted(ctx, "enable_breakpoint")?;
                ctx.enable_breakpoint(id).map_err(ToolError::from)?;
                Ok(serde_json::json!({ "id": id, "enabled": true }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Disable a breakpoint by id (restore the original byte) without forgetting it, so it can be re-enabled later. Requires the VM halted (call interrupt first, or be stopped at a breakpoint)."
    )]
    async fn disable_breakpoint(
        &self,
        Parameters(BreakpointIdArgs { id }): Parameters<BreakpointIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                require_halted(ctx, "disable_breakpoint")?;
                ctx.disable_breakpoint(id).map_err(ToolError::from)?;
                Ok(serde_json::json!({ "id": id, "enabled": false }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "List breakpoints as {id, address, enabled, symbol, scope, condition, temporary} objects (scope is \"global\" for kernel-wide or \"name (pid)\" for a process-scoped breakpoint)"
    )]
    async fn list_breakpoints(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                let arr: Vec<Value> = ctx
                    .list_breakpoints()
                    .iter()
                    .map(|b| {
                        serde_json::json!({
                            "id": b.id,
                            "address": hex(b.address.0),
                            "enabled": b.enabled,
                            "symbol": b.symbol,
                            "scope": b.scope.label(),
                            "condition": b.condition,
                            "temporary": b.temporary,
                        })
                    })
                    .collect();
                Ok(serde_json::json!({ "breakpoints": arr }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Resume the VM (go). Non-blocking: returns immediately as {running:true, already_running:bool}. To wait for the next stop, call wait_for_stop; to see where it is now without resuming, call status."
    )]
    async fn resume(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                // Drain any stop the servicer caught so a real halt that already
                // surfaced is reflected as `already_running:false` and the resume
                // below actually advances past it, rather than the stale running
                // value reporting `already_running:true` and doing nothing. A
                // debugger-noise break-in is absorbed (already running, no-op).
                ctx.settle_pending_stop().map_err(ToolError::from)?;
                let already_running = ctx.backend.is_running();
                if !already_running {
                    ctx.resume().map_err(ToolError::from)?;
                }
                Ok(serde_json::json!({ "running": true, "already_running": already_running }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Wait up to timeout_ms for the next stop WITHOUT resuming (default 10000, max 20000; 0 = default). Returns {stop:\"breakpoint\"|\"exception\"|\"bugcheck\"|\"target_reloaded\"} with context, {stop:\"running\"} if the wait elapsed (call again to keep waiting; no stops lost between calls), or {stop:\"halted\"} immediately if the VM is already parked with nothing pending. Does not resume; call resume to advance. Use short timeouts and poll; there is no indefinite wait."
    )]
    async fn wait_for_stop(
        &self,
        Parameters(WaitArgs { timeout_ms }): Parameters<WaitArgs>,
        ct: CancellationToken,
    ) -> Result<CallToolResult, McpError> {
        let timeout_ms = optional_timeout_ms(timeout_ms)?;
        // Per-request cancel flag the actor's wait loop polls. Set when the
        // client cancels/times out this request (`ct`) or the server is shutting
        // down (`self.interrupt`), so an in-flight wait returns and frees the
        // single-threaded actor instead of pinning it for the whole timeout.
        let cancel = Arc::new(AtomicBool::new(false));
        let watcher = {
            let cancel = cancel.clone();
            let shutdown = self.interrupt.clone();
            tokio::spawn(async move {
                loop {
                    if shutdown.load(Ordering::Relaxed) {
                        cancel.store(true, Ordering::Relaxed);
                        return;
                    }
                    tokio::select! {
                        _ = ct.cancelled() => {
                            cancel.store(true, Ordering::Relaxed);
                            return;
                        }
                        _ = tokio::time::sleep(Duration::from_millis(200)) => {}
                    }
                }
            })
        };
        let result = self
            .run(move |ctx| {
                // A stop the background `service_idle` caught and parked while the
                // host was idle (e.g. a breakpoint that fired between tool calls)
                // is the proper event for this wait; return it before waiting for
                // a new one.
                if let Some(parked) = ctx.take_parked_stop() {
                    return Ok(continue_outcome_json(ctx, parked));
                }
                // Always bounded over MCP (see optional_timeout_ms): the caller
                // polls by calling again rather than waiting indefinitely. Never
                // resumes, so a held stop (e.g. the early-boot reload) surfaces in
                // place instead of being run past.
                let timeout = Some(Duration::from_millis(timeout_ms));
                let outcome = ctx
                    .wait_for_stop_bounded(timeout, &cancel)
                    .map_err(ToolError::from)?;
                Ok(continue_outcome_json(ctx, outcome))
            })
            .await;
        watcher.abort();
        let v = result?;
        json_result(v)
    }

    #[tool(
        description = "Read-only run-control state (where am I): {running, current_thread, rip, symbol, process:{pid,name,eprocess}|null, coherent}. rip/symbol are null while running. coherent=false means the guest rebooted and rediscovery is still in progress, so process/module enumeration is not yet meaningful; resume + wait_for_stop to advance rather than reading stale state."
    )]
    async fn status(&self) -> Result<CallToolResult, McpError> {
        let v = self.run(|ctx| Ok(status_json(ctx))).await?;
        json_result(v)
    }

    #[tool(
        description = "Pause a running VM (e.g. before reading registers/backtrace); returns {already_halted, rip}. If already halted, no action is taken. Resume with resume."
    )]
    async fn interrupt(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                // A stop the servicer already caught means the VM is halted now;
                // ingest it so `already_halted` is truthful at a real stop and we
                // don't send a redundant break-in over it (a debugger-noise break-in
                // is absorbed, so already_halted is false and we interrupt for real).
                ctx.settle_pending_stop().map_err(ToolError::from)?;
                let already_halted = !ctx.backend.is_running();
                let event_rip = if already_halted {
                    None
                } else {
                    // Route through the context so the selected thread tracks
                    // the halt (rather than calling the backend raw).
                    ctx.interrupt().map_err(ToolError::from)?.program_counter
                };
                let rip = event_rip.or_else(|| {
                    ctx.backend
                        .read_registers()
                        .ok()
                        .and_then(|r| ctx.register_map.read_u64("rip", &r).ok())
                });
                Ok(serde_json::json!({
                    "already_halted": already_halted,
                    "rip": rip.map(hex),
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Single-step one instruction on the current thread. Requires the VM halted (call interrupt first, or be stopped at a breakpoint). Returns {rip, symbol}"
    )]
    async fn step(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                require_halted(ctx, "step")?;
                ctx.step().map_err(ToolError::from)?;
                let regs = ctx.backend.read_registers().map_err(ToolError::from)?;
                let rip = ctx.register_map.read_u64("rip", &regs).unwrap_or(0);
                let symbol = ctx.target.closest_symbol_current_context(VirtAddr(rip));
                Ok(serde_json::json!({ "rip": hex(rip), "symbol": symbol }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Step over the current instruction on the current thread: if it's a call, run to its return site, otherwise single-step. Requires the VM halted (call interrupt first, or be stopped at a breakpoint). Returns the same shape as wait_for_stop ({stop:\"step\"} on completion, or breakpoint/bugcheck/exception if one is hit en route)."
    )]
    async fn step_over(&self) -> Result<CallToolResult, McpError> {
        let cancel = self.interrupt.clone();
        let v = self
            .run(move |ctx| {
                require_halted(ctx, "step_over")?;
                let outcome = ctx.step_over(&cancel).map_err(ToolError::from)?;
                Ok(continue_outcome_json(ctx, outcome))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Step out of the current function: run to the caller's return address. Requires the VM halted (call interrupt first, or be stopped at a breakpoint). Returns the same shape as wait_for_stop ({stop:\"step\"} on completion, or breakpoint/bugcheck/exception if one is hit en route)."
    )]
    async fn step_out(&self) -> Result<CallToolResult, McpError> {
        let cancel = self.interrupt.clone();
        let v = self
            .run(move |ctx| {
                require_halted(ctx, "step_out")?;
                let outcome = ctx.step_out(&cancel).map_err(ToolError::from)?;
                Ok(continue_outcome_json(ctx, outcome))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Select the current inspection thread (a vCPU id, as listed by vcpus or in threads' `active` field) so registers/backtrace/step operate on it. Returns {current_thread}."
    )]
    async fn set_current_thread(
        &self,
        Parameters(ThreadIdArgs { thread }): Parameters<ThreadIdArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                ctx.set_current_thread(&thread).map_err(ToolError::from)?;
                Ok(serde_json::json!({ "current_thread": thread }))
            })
            .await?;
        json_result(v)
    }

    // --- guest writes (state-changing) ---

    #[tool(
        description = "Write bytes to guest virtual memory (scoped to the attached process, or kernel-wide if not attached). `hex` is contiguous lowercase hex, 1-4096 bytes (the form read_memory returns). Works while the guest runs; if the guest may be concurrently touching the same bytes, interrupt first to avoid a torn write. Returns {address, length}."
    )]
    async fn write_memory(
        &self,
        Parameters(WriteMemoryArgs { address, hex: data }): Parameters<WriteMemoryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let bytes = bytes_of_hex(&data)?;
                if bytes.is_empty() || bytes.len() > WRITE_MEMORY_MAX_LENGTH {
                    return Err(invalid_request(format!(
                        "hex must decode to 1..={WRITE_MEMORY_MAX_LENGTH} bytes"
                    )));
                }
                let addr = eval_addr(ctx, &address)?;
                ctx.target
                    .current_process()
                    .memory()
                    .write_bytes(VirtAddr(addr), &bytes)
                    .map_err(ToolError::from)?;
                Ok(serde_json::json!({
                    "address": hex(addr),
                    "length": bytes.len(),
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Set a single register on the current thread. `value` is a debugger expression. Requires the VM halted (call interrupt first, or be stopped at a breakpoint). Returns {name, value}."
    )]
    async fn set_register(
        &self,
        Parameters(SetRegisterArgs { name, value }): Parameters<SetRegisterArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                require_halted(ctx, "set_register")?;
                let value = eval_addr(ctx, &value)?;
                ctx.write_register(&name, value)
                    .map_err(ToolError::from)?;
                Ok(serde_json::json!({ "name": name, "value": hex(value) }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Open a Windows kernel crash dump (.dmp) file for offline analysis. Must be called before any other tool when the server was started without --dump/--connect. Only one session can be active at a time. Returns status, path, processor count, and bugcheck analysis if applicable."
    )]
    async fn open_dump(
        &self,
        Parameters(OpenDumpArgs { path }): Parameters<OpenDumpArgs>,
    ) -> Result<CallToolResult, McpError> {
        let opening = OpeningGuard::claim(&self.session)?;

        let dump_path = PathBuf::from(&path);
        let (tx, _service_pending) = tokio::task::spawn_blocking(move || {
            spawn_session(String::new(), None, Some(dump_path))
        })
        .await
        .map_err(|e| McpError::internal_error(format!("spawn_blocking failed: {e}"), None))?
        .map_err(|e| McpError::internal_error(format!("failed to open dump: {e}"), None))?;

        opening.promote(tx)?;

        let v = self
            .run(move |ctx| {
                let processors = ctx.backend.thread_list().map(|t| t.len()).unwrap_or(1);
                let bc = current_bugcheck(&ctx.target);
                Ok(serde_json::json!({
                    "status": "opened",
                    "path": path,
                    "processors": processors,
                    "bugcheck": bc.map(|a| view::to_json(&view::bugcheck(&a))),
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Connect to a live Windows VM. Supported backends: \"kd\" (KD over Unix socket, default /tmp/ntoseye-kd.sock), \"gdb\" (GDB remote stub, default 127.0.0.1:1234), \"memory\" (physical memory only, no debug transport). Must be called before any other tool when the server was started without --backend/--connect/--dump. Only one session can be active at a time."
    )]
    async fn open(
        &self,
        Parameters(OpenArgs { backend, connect }): Parameters<OpenArgs>,
    ) -> Result<CallToolResult, McpError> {
        match backend.as_str() {
            "kd" | "gdb" => {}
            "memory" => {
                if connect.is_some() {
                    return Err(invalid_params(
                        "memory backend does not use 'connect'".to_string(),
                    ));
                }
            }
            other => {
                return Err(invalid_params(format!(
                    "unknown backend \"{other}\": must be \"kd\", \"gdb\", or \"memory\""
                )));
            }
        }

        let opening = OpeningGuard::claim(&self.session)?;

        let backend_name = backend.clone();
        let connect_str = connect.clone();
        let (tx, service_pending) = tokio::task::spawn_blocking(move || {
            spawn_session(backend_name, connect_str, None)
        })
        .await
        .map_err(|e| McpError::internal_error(format!("spawn_blocking failed: {e}"), None))?
        .map_err(|e| {
            McpError::internal_error(format!("failed to connect ({backend}): {e}"), None)
        })?;

        let tx_for_ticker = tx.clone();
        opening.promote(tx)?;
        if backend != "memory" {
            spawn_service_ticker(tx_for_ticker, service_pending);
        }

        let v = self
            .run(move |ctx| {
                let processors = ctx.backend.thread_list().map(|t| t.len()).unwrap_or(1);
                Ok(serde_json::json!({
                    "status": "connected",
                    "backend": backend,
                    "connect": connect,
                    "processors": processors,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "One-shot overview for crash/debug triage: bundles status, bugcheck analysis, backtrace, and loaded kernel modules into a single response. backtrace is null when the VM is running. Returns {status, bugcheck, backtrace, modules}."
    )]
    async fn triage(&self) -> Result<CallToolResult, McpError> {
        let v = self
            .run(|ctx| {
                let s = ctx.run_status();
                let running = s.running;
                let status = run_status_json(s);

                let bc = current_bugcheck(&ctx.target)
                    .map(|a| view::to_json(&view::bugcheck(&a)));

                let bt = if !running {
                    ctx.backtrace(BACKTRACE_DEFAULT_LIMIT)
                        .ok()
                        .map(|trace| {
                            Value::Array(trace.frames.iter().map(frame_json).collect())
                        })
                } else {
                    None
                };

                let all_mods = ctx.target.guest.kernel_modules().unwrap_or_default();
                let modules_total = all_mods.len();
                let mods: Vec<Value> = all_mods
                    .iter()
                    .take(200)
                    .map(module_json)
                    .collect();

                Ok(serde_json::json!({
                    "status": status,
                    "bugcheck": bc,
                    "backtrace": bt,
                    "modules": mods,
                    "modules_total": modules_total,
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Evaluate a debugger expression (symbol, hex address, register, arithmetic, poi()) and return its numeric result. Returns {expression, value}."
    )]
    async fn eval(
        &self,
        Parameters(EvalArgs { expression }): Parameters<EvalArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let result = eval_addr(ctx, &expression)?;
                Ok(serde_json::json!({
                    "expression": expression,
                    "value": hex(result),
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Read a pointer-sized (8-byte little-endian) value at the given address. Shorthand for read_memory + byte reversal. Returns {address, value}."
    )]
    async fn read_pointer(
        &self,
        Parameters(ReadPointerArgs { address }): Parameters<ReadPointerArgs>,
    ) -> Result<CallToolResult, McpError> {
        let v = self
            .run(move |ctx| {
                let addr = eval_addr(ctx, &address)?;
                let mut buf = [0u8; 8];
                read_virt_bytes(ctx, addr, &mut buf)?;
                let val = u64::from_le_bytes(buf);
                Ok(serde_json::json!({
                    "address": hex(addr),
                    "value": hex(val),
                }))
            })
            .await?;
        json_result(v)
    }

    #[tool(
        description = "Close the active debugger session so a new one can be opened with open_dump or open. Returns {status:\"closed\"} on clean shutdown, {status:\"closed\", warning:\"...\"} if the shutdown timed out. Cancels an in-progress open if one is pending."
    )]
    async fn close(&self) -> Result<CallToolResult, McpError> {
        let tx = {
            let mut guard = self.session.lock().unwrap();
            match &*guard {
                SessionSlot::Active(tx) => tx.clone(),
                SessionSlot::Opening(_) => {
                    *guard = SessionSlot::Vacant;
                    return json_result(serde_json::json!({
                        "status": "closed",
                        "note": "cancelled a pending open; the old connection may take a moment to release — retry if the next open reports AlreadyRunning",
                    }));
                }
                SessionSlot::Vacant => {
                    return Err(McpError::invalid_request(
                        "no debugger session is active; nothing to close",
                        None,
                    ));
                }
            }
        };

        self.interrupt.store(true, Ordering::Relaxed);
        let _interrupt_guard = InterruptResetGuard(self.interrupt.clone());

        let (ack_tx, ack_rx) = oneshot::channel();
        let clean = if tx.send(Command::Shutdown { ack: ack_tx }).is_ok() {
            tokio::time::timeout(Duration::from_secs(5), ack_rx)
                .await
                .is_ok_and(|r| r.is_ok())
        } else {
            true
        };
        drop(tx);

        if clean {
            // Vacate only after the actor has acked (and released its
            // InstanceGuard), so a subsequent open() can acquire the same
            // target.
            *self.session.lock().unwrap() = SessionSlot::Vacant;
            drop(_interrupt_guard);
            json_result(serde_json::json!({ "status": "closed" }))
        } else {
            // The actor is still running (and still holds the InstanceGuard),
            // so leave the slot as Active — vacating now would let a
            // concurrent open() past OpeningGuard::claim only to fail inside
            // acquire_instance_guard with AlreadyRunning.
            drop(_interrupt_guard);
            json_result(serde_json::json!({
                "status": "pending",
                "warning": "shutdown timed out; the session is still closing — retry close shortly",
            }))
        }
    }
}

#[tool_handler]
impl rmcp::ServerHandler for NtoseyeMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2025_06_18,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: Implementation {
                name: env!("CARGO_PKG_NAME").to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                ..Implementation::from_build_env()
            },
            instructions: Some(
                "ntoseye: introspect and control a live Windows kernel running under \
                 KVM/QEMU. Read-only tools for process/thread/module/driver \
                 enumeration, memory and struct reads, disassembly, backtraces, \
                 page-table walks, and symbol/type lookup. State-changing tools: \
                 attach_process/detach (scope the context to a process), \
                 set_breakpoint/clear_breakpoint/list_breakpoints, run-control \
                 (resume, wait_for_stop, interrupt, step, step_over, step_out, \
                 set_current_thread), and guest writes \
                 (write_memory, set_register). Run-control is split: resume goes \
                 (non-blocking), wait_for_stop polls for the next stop without \
                 resuming, status reports where it is now, interrupt pauses. \
                 Typical flow for a user-mode breakpoint: attach_process(pid) → \
                 interrupt → set_breakpoint(expr) → resume → wait_for_stop(timeout) \
                 (poll until stop:\"breakpoint\"). \
                 The guest runs freely by default (memory/process/struct reads work \
                 live). registers/backtrace need the CPU halted: call interrupt \
                 first (or be stopped at a breakpoint), inspect, then resume to let \
                 the guest run again. Breakpoint mutation, step, and set_register \
                 require the VM halted; write_memory works live. After a reboot, \
                 status reports coherent:false until rediscovery finishes; \
                 wait_for_stop for it rather than enumerating stale state. \
                 Tools that take an address accept a debugger expression (symbol, \
                 register, hex, arithmetic). Addresses in tool output are 0x hex \
                 strings (JSON has no hex numbers); ids/pids/sizes stay decimal."
                    .to_string(),
            ),
        }
    }
}

fn is_loopback_http_bind(addr: &str) -> bool {
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        return socket.ip().is_loopback();
    }

    let Some((host, _port)) = addr.rsplit_once(':') else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// Whether a browser `Origin` header (`scheme://host[:port]`, no path) names a
/// loopback host. Used to gate cross-origin access to the loopback HTTP bind so a
/// website the user merely visits can't reach the debugger via 127.0.0.1.
fn is_loopback_origin(origin: &str) -> bool {
    let Some((_scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    // host[:port]; a bracketed IPv6 literal ([::1]:port) keeps the colons inside
    // the brackets, so peel those off before splitting on the port colon.
    let host = if let Some(after_bracket) = rest.strip_prefix('[') {
        match after_bracket.split_once(']') {
            Some((host, _port)) => host,
            None => return false,
        }
    } else {
        rest.split(':').next().unwrap_or(rest)
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn check_http_bind_policy(addr: &str, unsafe_http: bool) -> anyhow::Result<()> {
    if is_loopback_http_bind(addr) {
        return Ok(());
    }
    if unsafe_http {
        eprintln!(
            "ntoseye-mcp: warning: HTTP bind {addr} is not loopback; debugger control tools are reachable by clients that can access this address"
        );
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "refusing non-loopback MCP HTTP bind {addr}; use 127.0.0.1:PORT for local browser clients or pass --unsafe-http to expose debugger control tools on the network"
        ))
    }
}

/// Attach (on a dedicated thread) and serve the MCP protocol until the client
/// disconnects. Synchronous entry point; it owns its own tokio runtime, so the
/// rest of the binary stays runtime-free.
///
/// `http` selects the transport: `None` serves over **stdio** (the client
/// launches this binary as a subprocess, e.g. Claude Desktop / Claude Code), while
/// `Some(addr)` serves the **Streamable HTTP** transport on `addr` (for web
/// clients like llama.cpp's webui that connect over the network and can't spawn a
/// subprocess). HTTP binds are loopback-only unless `unsafe_http` is set. Both
/// transports drive the same single session actor.
pub fn run(
    backend: String,
    connect: Option<String>,
    dump: Option<PathBuf>,
    http: Option<String>,
    unsafe_http: bool,
) -> anyhow::Result<()> {
    if let Some(addr) = http.as_deref() {
        check_http_bind_policy(addr, unsafe_http)?;
    }

    // The stdio transport speaks MCP on stdout, so all logging goes to stderr.
    let session: SharedSession = Arc::new(std::sync::Mutex::new(SessionSlot::Vacant));
    let eager = dump.is_some() || connect.is_some() || backend == "memory";

    if eager {
        let is_dump = dump.is_some();
        let needs_ticker = !is_dump && backend != "memory";
        let label = if is_dump { "dump" } else { &backend };
        eprintln!("ntoseye-mcp: attaching ({label})...");
        let (tx, service_pending) = spawn_session(backend, connect, dump)?;
        *session.lock().unwrap() = SessionSlot::Active(tx.clone());
        if needs_ticker {
            spawn_service_ticker(tx, service_pending);
        }
    } else {
        if backend == "kd" {
            eprintln!(
                "ntoseye-mcp: note: pass --connect {default_kd} to auto-attach at startup, \
                 or use the 'open' tool after launch",
                default_kd = crate::DEFAULT_KD_SOCKET,
            );
        } else {
            eprintln!(
                "ntoseye-mcp: note: --backend {backend} has no effect without --connect; \
                 use the 'open' tool to attach, or pass --connect to auto-attach at startup"
            );
        }
        eprintln!("ntoseye-mcp: starting without a session (use open_dump or open to attach)");
    }

    // Shared with the handlers so shutdown can interrupt an in-flight
    // `wait_for_stop` (otherwise the actor stays busy and never reaches
    // cleanup, leaving the VM frozen).
    let interrupt = Arc::new(AtomicBool::new(false));
    let interrupt_for_signal = interrupt.clone();
    // Slot kept aside so we can drive teardown of whichever session is active
    // by then (eager or opened later via open_dump/open).
    let session_for_shutdown = session.clone();

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let serve = async {
            match http {
                Some(addr) => {
                    eprintln!(
                        "ntoseye-mcp: serving Streamable HTTP at http://{addr}/mcp"
                    );
                    serve_http(session, addr, unsafe_http, interrupt).await
                }
                None => {
                    eprintln!("ntoseye-mcp: serving over stdio");
                    let service = NtoseyeMcp::new(session, interrupt).serve(stdio()).await?;
                    service.waiting().await?;
                    Ok(())
                }
            }
        };

        // Serve until the client disconnects (or the server errors), or until
        // Ctrl+C; either way fall through to teardown.
        let result = tokio::select! {
            r = serve => r,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("ntoseye-mcp: interrupted");
                Ok(())
            }
        };

        // Ask the actor to remove our breakpoints and resume the VM before we
        // exit, so Ctrl+C doesn't leave a live guest frozen with int3s
        // installed (a no-op for dumps). Set the interrupt first so any
        // in-flight wait returns and the actor is free to process the Shutdown.
        eprintln!("ntoseye-mcp: cleaning up...");
        interrupt_for_signal.store(true, Ordering::Relaxed);
        // Clone the sender out so the slot's mutex isn't held across the await
        let shutdown_tx = match &*session_for_shutdown.lock().unwrap() {
            SessionSlot::Active(tx) => Some(tx.clone()),
            _ => None,
        };
        if let Some(tx) = shutdown_tx {
            let (ack_tx, ack_rx) = oneshot::channel();
            if tx.send(Command::Shutdown { ack: ack_tx }).is_ok() {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), ack_rx).await;
            }
        }
        result
    })
}

/// Background servicing ticker: periodically nudge the actor to service the
/// guest while idle (see [`Command::Service`]), so a wrong-process hit on a
/// shared-page breakpoint doesn't leave it frozen between tool calls.
/// `service_pending` keeps at most one `Service` queued even if the actor is
/// busy in a long wait; the thread exits once the actor's channel closes
/// (send fails).
fn spawn_service_ticker(
    tx: mpsc::UnboundedSender<Command>,
    service_pending: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(SERVICE_TICK);
            if service_pending.swap(true, Ordering::AcqRel) {
                continue;
            }
            if tx.send(Command::Service).is_err() {
                break;
            }
        }
    });
}

/// Serve the Streamable HTTP transport on `addr`, mounting the MCP service at
/// `/mcp`. Every HTTP session gets a clone of the handler (cheap; it holds only
/// the actor's channel sender), so all connections funnel to the one live
/// debugger session.
async fn serve_http(
    session: SharedSession,
    addr: String,
    unsafe_http: bool,
    interrupt: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    use rmcp::transport::StreamableHttpService;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use tower_http::cors::{AllowOrigin, Any, CorsLayer};

    let template = NtoseyeMcp::new(session, interrupt);
    let service = StreamableHttpService::new(
        move || Ok(template.clone()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // Methods/headers stay permissive for the Streamable HTTP handshake. Origin
    // is the exposure that matters: loopback binds trust only loopback browser
    // origins, while `--unsafe-http` widens it to any origin.
    let allow_origin = if unsafe_http {
        AllowOrigin::any()
    } else {
        AllowOrigin::predicate(|origin, _parts| {
            origin.to_str().is_ok_and(is_loopback_origin)
        })
    };
    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    let router = axum::Router::new()
        .nest_service("/mcp", service)
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_mcp() -> NtoseyeMcp {
        NtoseyeMcp::new(
            Arc::new(std::sync::Mutex::new(SessionSlot::Vacant)),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn fake_active_mcp() -> NtoseyeMcp {
        let (tx, _rx) = mpsc::unbounded_channel::<Command>();
        NtoseyeMcp::new(
            Arc::new(std::sync::Mutex::new(SessionSlot::Active(tx))),
            Arc::new(AtomicBool::new(false)),
        )
    }

    #[test]
    fn loopback_origins_are_trusted() {
        assert!(is_loopback_origin("http://localhost"));
        assert!(is_loopback_origin("http://localhost:8080"));
        assert!(is_loopback_origin("http://127.0.0.1:3000"));
        assert!(is_loopback_origin("https://127.0.0.1"));
        assert!(is_loopback_origin("http://[::1]:9000"));
        assert!(is_loopback_origin("http://LOCALHOST:1234"));
    }

    #[test]
    fn non_loopback_origins_are_rejected() {
        assert!(!is_loopback_origin("http://meow.example.com"));
        assert!(!is_loopback_origin("https://meow.test:443"));
        assert!(!is_loopback_origin("http://10.0.0.5:8080"));
        // `null` (sandboxed iframes, file://) is not a loopback host.
        assert!(!is_loopback_origin("null"));
        // Malformed / no scheme.
        assert!(!is_loopback_origin("127.0.0.1"));
        assert!(!is_loopback_origin(""));
    }

    #[tokio::test]
    async fn open_dump_rejects_when_session_active() {
        let mcp = fake_active_mcp();
        let err = mcp
            .open_dump(Parameters(OpenDumpArgs {
                path: "/tmp/fake.dmp".into(),
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("already active"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn open_rejects_when_session_active() {
        let mcp = fake_active_mcp();
        let err = mcp
            .open(Parameters(OpenArgs {
                backend: "kd".into(),
                connect: None,
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("already active"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn open_rejects_unknown_backend() {
        let mcp = empty_mcp();
        let err = mcp
            .open(Parameters(OpenArgs {
                backend: "nope".into(),
                connect: None,
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("unknown backend"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn open_memory_rejects_connect() {
        let mcp = empty_mcp();
        let err = mcp
            .open(Parameters(OpenArgs {
                backend: "memory".into(),
                connect: Some("127.0.0.1:1234".into()),
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("does not use"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn open_dump_nonexistent_file() {
        let mcp = empty_mcp();
        let err = mcp
            .open_dump(Parameters(OpenDumpArgs {
                path: "/tmp/ntoseye-test-does-not-exist.dmp".into(),
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("failed to open dump"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn open_kd_nonexistent_socket() {
        let mcp = empty_mcp();
        let err = mcp
            .open(Parameters(OpenArgs {
                backend: "kd".into(),
                connect: Some("/tmp/ntoseye-test-does-not-exist.sock".into()),
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("failed to connect"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn open_kd_default_socket() {
        let mcp = empty_mcp();
        // Use a nonexistent socket so the test doesn't block on a real KD
        // handshake when /tmp/ntoseye-kd.sock exists.
        let err = mcp
            .open(Parameters(OpenArgs {
                backend: "kd".into(),
                connect: Some("/tmp/ntoseye-test-default-does-not-exist.sock".into()),
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("failed to connect"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn close_when_no_session() {
        let mcp = empty_mcp();
        let err = mcp.close().await.unwrap_err();
        assert!(
            err.message.contains("no debugger session"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn close_active_session() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
        let mcp = NtoseyeMcp::new(
            Arc::new(std::sync::Mutex::new(SessionSlot::Active(tx))),
            Arc::new(AtomicBool::new(false)),
        );

        // Simulate the actor: drain commands and ack shutdown.
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                if let Command::Shutdown { ack } = cmd {
                    let _ = ack.send(());
                    break;
                }
            }
        });

        let result = mcp.close().await.expect("close should succeed");
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or("");
        assert!(text.contains("closed"), "unexpected result: {text}");
        assert!(
            matches!(&*mcp.session.lock().unwrap(), SessionSlot::Vacant),
            "session should be vacant after close"
        );
        assert!(!mcp.interrupt.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn close_then_reopen_allowed() {
        let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
        let mcp = NtoseyeMcp::new(
            Arc::new(std::sync::Mutex::new(SessionSlot::Active(tx))),
            Arc::new(AtomicBool::new(false)),
        );

        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                if let Command::Shutdown { ack } = cmd {
                    let _ = ack.send(());
                    break;
                }
            }
        });

        mcp.close().await.expect("close should succeed");

        // After close, open should no longer reject with "already active".
        // Use a nonexistent socket so the test doesn't block on a real KD
        // handshake when /tmp/ntoseye-kd.sock exists.
        let err = mcp
            .open(Parameters(OpenArgs {
                backend: "kd".into(),
                connect: Some("/tmp/ntoseye-test-close-reopen-does-not-exist.sock".into()),
            }))
            .await
            .unwrap_err();
        assert!(
            !err.message.contains("already active"),
            "session should not be active after close: {err:?}"
        );
    }

    #[tokio::test]
    async fn close_cancels_opening_session() {
        let mcp = NtoseyeMcp::new(
            Arc::new(std::sync::Mutex::new(SessionSlot::Opening(0))),
            Arc::new(AtomicBool::new(false)),
        );

        let result = mcp.close().await.expect("close of Opening should succeed");
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.as_str())
            .unwrap_or("");
        assert!(text.contains("closed"), "unexpected result: {text}");
        assert!(
            matches!(&*mcp.session.lock().unwrap(), SessionSlot::Vacant),
            "session should be vacant after close"
        );
    }

    #[tokio::test]
    async fn triage_requires_session() {
        let mcp = empty_mcp();
        let err = mcp.triage().await.unwrap_err();
        assert!(
            err.message.contains("no debugger session"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn eval_requires_session() {
        let mcp = empty_mcp();
        let err = mcp
            .eval(Parameters(EvalArgs {
                expression: "0x1234".into(),
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("no debugger session"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn read_pointer_requires_session() {
        let mcp = empty_mcp();
        let err = mcp
            .read_pointer(Parameters(ReadPointerArgs {
                address: "0x1234".into(),
            }))
            .await
            .unwrap_err();
        assert!(
            err.message.contains("no debugger session"),
            "unexpected error: {err:?}"
        );
    }
}
