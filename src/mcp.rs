//! MCP server: the debugger's REPL command language over the Model Context
//! Protocol, for clients that cannot run Python themselves.
//!
//! One `command` tool runs a REPL line and returns its text; `resume`
//! (non-blocking), `wait_for_stop` (bounded), `interrupt`, and `status` cover
//! run control; `open`/`close` manage the single session slot.

use rmcp::{
    ErrorData as McpError, ServiceExt,
    handler::server::router::tool::ToolRouter,
    handler::server::wrapper::Parameters,
    model::{
        CallToolResult, ContentBlock, Implementation, ProtocolVersion, ServerCapabilities,
        ServerInfo,
    },
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

use crate::bugchecks::{analyze_bugcheck, bugcheck_from_dump_info, current_bugcheck};
use crate::dbg_backend::ContinueDisposition;
use crate::diagnostics;
use crate::error::Error;
use crate::kd::KdMemorySource;
use crate::output;
use crate::repl::{DispatchContext, Flow, ReplState, ReplStore};
use crate::session::{ContinueOutcome, Session};
use crate::types::VirtAddr;
use crate::view;
use crate::{Backend, TargetSpec};

/// The session actor's state: the (`!Send`) session plus the REPL state the
/// `command` tool keeps between calls (built on first use).
struct Actor {
    ctx: Session,
    repl: Option<ReplStore>,
}

/// A unit of work run on the actor thread. MCP handlers are async/`Send`
/// but `Session` is not, so a dedicated thread owns it; handlers send
/// closures and await one reply.
type Job = Box<dyn FnOnce(&mut Actor) -> Result<CallToolResult, ToolError> + Send>;

enum Command {
    Run {
        job: Job,
        reply: oneshot::Sender<Result<CallToolResult, ToolError>>,
    },
    /// Clean up the session and stop the actor. The guest resumes only after
    /// every debugger-owned breakpoint is restored; cleanup failure is reported
    /// and leaves the target halted rather than running with an orphaned int3.
    Shutdown { ack: oneshot::Sender<()> },
    /// A periodic nudge (from the background ticker) for the actor to service
    /// the guest while otherwise idle, absorbing wrong-process hits on a
    /// shared-page breakpoint so they don't leave it frozen between calls.
    Service,
}

/// How often the background ticker nudges the actor (see [`Command::Service`]).
const SERVICE_TICK: Duration = Duration::from_millis(20);

const CONTINUE_DEFAULT_TIMEOUT_MS: u64 = 10_000;
/// Capped well under common MCP client request timeouts (30 s is typical) so a
/// wait returns `{stop:"running"}` and frees the single-session actor before
/// the client gives up. No indefinite wait is offered over MCP.
const CONTINUE_MAX_TIMEOUT_MS: u64 = 20_000;

fn cleanup_session(ctx: &mut Session) {
    if let Err(error) = ctx.cleanup_for_exit() {
        diagnostics::eprint_warning(format!(
            "debugger cleanup failed; target was not resumed: {error}"
        ));
    }
}

/// Spawn the actor thread that owns the session. The backend is constructed
/// *on this thread* so the non-`Send` state never crosses a thread boundary.
/// Returns the sender the handlers use to reach it and the ticker's coalescing
/// flag.
fn spawn_session(
    spec: TargetSpec,
) -> anyhow::Result<(mpsc::UnboundedSender<Command>, Arc<AtomicBool>)> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let (tx, mut rx) = mpsc::unbounded_channel::<Command>();

    // Coalesces the background `Service` nudges: the ticker only enqueues one
    // when this is false (and sets it), the actor clears it as it services, so
    // a long wait can't let a burst of them pile up in the unbounded channel.
    let service_pending = Arc::new(AtomicBool::new(false));
    let service_pending_actor = service_pending.clone();

    std::thread::spawn(move || {
        let is_dump = matches!(spec, TargetSpec::Dump(_));
        let mut actor = match Session::open(&spec) {
            Ok(ctx) => {
                let _ = ready_tx.send(Ok(()));
                Actor { ctx, repl: None }
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
                return;
            }
        };

        // For live targets the MCP keeps the guest running between calls;
        // tools that need a stopped target ask the client to `interrupt`.
        // Dumps are always halted.
        if !is_dump && !actor.ctx.backend.is_running() {
            let _ = actor.ctx.backend.continue_execution();
        }

        // `blocking_recv` is valid here: a plain std thread, no runtime. Clean
        // up on an explicit `Shutdown` (Ctrl+C / client disconnect) and if the
        // channel closes outright, so the VM is never left frozen.
        loop {
            match rx.blocking_recv() {
                Some(Command::Run { job, reply }) => {
                    let _ = reply.send(job(&mut actor));
                }
                Some(Command::Service) => {
                    service_pending_actor.store(false, Ordering::Release);
                    actor.ctx.service_idle();
                }
                Some(Command::Shutdown { ack }) => {
                    cleanup_session(&mut actor.ctx);
                    drop(actor);
                    let _ = ack.send(());
                    break;
                }
                None => {
                    cleanup_session(&mut actor.ctx);
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
/// reserves the slot while `open` builds a session off-thread, so a concurrent
/// open can't race the vacancy check and leak a second actor. The generation
/// lets [`OpeningGuard`] detect that its reservation was cancelled by a
/// concurrent `close`.
enum SessionSlot {
    Vacant,
    Opening(u64),
    Active(mpsc::UnboundedSender<Command>),
}

static OPENING_GENERATION: AtomicU64 = AtomicU64::new(0);

type SharedSession = Arc<std::sync::Mutex<SessionSlot>>;

/// RAII guard that rolls `SessionSlot` back to `Vacant` if the opening future
/// is cancelled (e.g. MCP client timeout). [`OpeningGuard::promote`] installs
/// the active sender and defuses the rollback.
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
            _ => Err(McpError::internal_error("session open was cancelled", None)),
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
    /// Flipped on shutdown so an in-flight `wait_for_stop` bails out promptly
    /// and the actor can run cleanup (resume the VM) before exit.
    interrupt: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum BackendArg {
    Kd,
    #[serde(rename = "kdnet")]
    KdNet,
    Gdb,
    Memory,
    Dump,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct OpenArgs {
    #[schemars(
        description = "What to attach to: kd (KD over Unix socket), kdnet (KDNET over encrypted UDP), gdb (GDB remote stub), memory (physical memory only, no debug transport), or dump (a Windows kernel crash dump file)"
    )]
    backend: BackendArg,
    #[schemars(
        description = "Connection target: Unix socket path for kd (default /tmp/ntoseye-kd.sock), listen address for kdnet (default 0.0.0.0:50000), host:port for gdb (default 127.0.0.1:1234), absolute .dmp path for dump (required). Not used by memory."
    )]
    connect: Option<String>,
    #[schemars(
        description = "KDNET encryption key as four base-36 components. Required for kdnet only."
    )]
    key: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CommandArgs {
    #[schemars(
        description = "A REPL command line in ntoseye's WinDbg-style syntax, e.g. `!process 0 0`, `dt nt!_EPROCESS ffff...`, `k`, `bp nt!NtCreateFile`, `dq rsp l8`, `u rip`, `lm`. Several commands may be separated by `;`. Run `help` for the list and `help <cmd>` for one command."
    )]
    line: String,
}

#[derive(Clone, Copy, Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ContinueDispositionArg {
    Handled,
    NotHandled,
}

impl From<ContinueDispositionArg> for ContinueDisposition {
    fn from(disposition: ContinueDispositionArg) -> Self {
        match disposition {
            ContinueDispositionArg::Handled => Self::Handled,
            ContinueDispositionArg::NotHandled => Self::NotHandled,
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ResumeArgs {
    #[schemars(
        description = "Exception acknowledgement: handled (default) or not_handled. not_handled requires native transport support (currently KD) and otherwise returns an error."
    )]
    disposition: Option<ContinueDispositionArg>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WaitArgs {
    #[schemars(
        range(min = 0, max = 20000),
        description = "How long to wait for a stop before returning {stop:\"running\"} (default 10000, max 20000; 0 means the default). Bounded by design: poll by calling again while it returns running. A long wait blocks every other tool on the single debugger session."
    )]
    timeout_ms: Option<u64>,
}

/// A tool failure from the session, classified so a guest memory fault stays
/// distinguishable from an internal bug. Argument errors never reach the
/// actor; handlers reject them as `McpError` params before dispatch.
enum ToolError {
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
            | Error::AddressNotInDump(_)
            | Error::BadPhysicalAddress(_)
            | Error::PartialRead(_)
            | Error::PartialWrite(_)
            | Error::BufferNotEnough
            | Error::InvalidRange => ToolError::Memory(msg),
            _ => ToolError::Internal(msg),
        }
    }
}

impl From<ToolError> for McpError {
    fn from(e: ToolError) -> Self {
        match e {
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

fn optional_timeout_ms(value: Option<u64>) -> Result<u64, McpError> {
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

/// Structured tool result. rmcp's `structured()` also embeds a compact-text
/// copy in `content`, so clients that ignore `structuredContent` still get
/// the JSON.
fn json(v: Value) -> Result<CallToolResult, ToolError> {
    Ok(CallToolResult::structured(v))
}

/// Format an address/value as a `0x` hex string. JSON numbers are decimal-only,
/// so addresses (which debugger users always read in hex) are emitted as
/// strings.
fn hex(v: u64) -> String {
    format!("{v:#x}")
}

/// Render a [`ContinueOutcome`] as JSON, enriching breakpoint/exception stops
/// with the current process and resolved symbol from `ctx`.
fn continue_outcome_json(ctx: &Session, outcome: ContinueOutcome) -> Value {
    let process = ctx
        .target
        .current_process_info
        .as_ref()
        .map(|p| view::to_json(&view::process(p)));
    let symbol_at = |rip: u64| ctx.target.closest_symbol_current_context(VirtAddr(rip));
    match outcome {
        ContinueOutcome::Breakpoint {
            id,
            address,
            symbol,
            temporary,
            rip,
            condition_error,
            ..
        } => {
            let bp = ctx.breakpoint(id);
            let watch_access = bp.and_then(|bp| bp.watch_access_name());
            serde_json::json!({
                "stop": if watch_access.is_some() { "watchpoint" } else { "breakpoint" },
                "id": id,
                "address": hex(address),
                "symbol": symbol.or_else(|| symbol_at(rip)),
                "temporary": temporary,
                "rip": hex(rip),
                "process": process,
                "watch_access": watch_access,
                "watch_length": bp.and_then(|bp| bp.watch_length()),
                "condition_error": condition_error,
            })
        }
        ContinueOutcome::Bugcheck { rip, info } => {
            let analysis = info
                .map(|i| analyze_bugcheck(&ctx.target, &i))
                .or_else(|| current_bugcheck(&ctx.target))
                .or_else(|| bugcheck_from_dump_info(&ctx.target));
            serde_json::json!({
                "stop": "bugcheck",
                "rip": rip.map(hex),
                "bugcheck": analysis.as_ref().map(|a| view::to_json(&view::bugcheck(a))),
            })
        }
        ContinueOutcome::Stopped {
            rip,
            exception_code,
            first_chance,
            exception_address,
        } => serde_json::json!({
            "stop": "exception",
            "rip": hex(rip),
            "exception_code": exception_code,
            "first_chance": first_chance,
            "exception_address": exception_address.map(hex),
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
                 the new kernel. The VM is halted at an internal KD break-in (an \
                 arbitrary landing site). Every prior address (eprocess, ethread, \
                 module base, dtb) is invalid; re-enumerate before acting."
            } else {
                "The guest rebooted and the VM is halted at the earliest post-reboot \
                 stop, before kernel initialization: kernel symbols are loaded, but \
                 the loaded-module list does not exist yet, so process/thread/module \
                 enumeration is UNAVAILABLE at this stop. Every prior address is now \
                 invalid. Use this stop to debug early boot (breakpoints on init paths \
                 work); otherwise resume, poll wait_for_stop, and enumerate only once \
                 status reports coherent:true."
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
            // Not a new event; the VM was already parked here.
            "event": false,
            "rip": hex(rip),
            "symbol": symbol_at(rip),
            "process": process,
            "coherent": ctx.kernel_coherent(),
        }),
    }
}

#[tool_router]
impl NtoseyeMcp {
    fn new(session: SharedSession, interrupt: Arc<AtomicBool>) -> Self {
        Self {
            session,
            tool_router: Self::tool_router(),
            interrupt,
        }
    }

    /// Ship a job to the session actor and await its reply.
    async fn run<F>(&self, job: F) -> Result<CallToolResult, McpError>
    where
        F: FnOnce(&mut Actor) -> Result<CallToolResult, ToolError> + Send + 'static,
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
                        "no debugger session is active; call open to attach",
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
            .map_err(McpError::from)
    }

    #[tool(
        description = "Run one line of ntoseye's WinDbg-style REPL and return its text output (styling stripped). This is the whole debugger: `help` lists every command; `help <cmd>` explains one. Common: `!process 0 0` / `!process <pid|name>` (processes), `.attach <pid>` / `.detach` (address-space scope), `lm` (modules), `dt <type> [addr]` (struct layout/read), `x <mod>!<pat>` (symbols), `dq/dd/db <addr> [l<n>]` (memory), `u <addr>` (disassemble), `k` (backtrace; VM must be halted), `r` (registers; halted), `bp/bl/bc/bd/be` (breakpoints; halted), `!pte <addr>`, `!analyze`. Commands that resume until the next stop (g, gh, gn, p, gu) are refused here because they would block the session: use the resume tool then poll wait_for_stop. `t`/`si` (one instruction) is allowed. Addresses accept expressions (symbols, registers, hex, arithmetic, poi())."
    )]
    async fn command(
        &self,
        Parameters(CommandArgs { line }): Parameters<CommandArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(move |actor| {
            let store = actor
                .repl
                .take()
                .unwrap_or_else(|| ReplStore::new(&actor.ctx, DispatchContext::Remote));
            let mut state = ReplState::attach(&mut actor.ctx, store);
            state.line = line.trim().to_string();
            let (result, mut text) = output::capture(|| state.dispatch_line(&line));
            actor.repl = Some(state.detach());
            let ok = match result {
                Ok(Flow::Continue | Flow::Quit) => true,
                Ok(Flow::Denied) => false,
                Err(e) => {
                    text.push_str(&format!("error: {e}\n"));
                    false
                }
            };
            let content = vec![ContentBlock::text(text)];
            Ok(if ok {
                CallToolResult::success(content)
            } else {
                CallToolResult::error(content)
            })
        })
        .await
    }

    #[tool(
        description = "Read-only run-control state (where am I): {running, current_thread, rip, symbol, process:{pid,name,eprocess}|null, coherent, kernel_base}. rip/symbol are null while running. coherent=false means the guest rebooted and rediscovery is still in progress, so enumeration is not yet meaningful; resume + wait_for_stop rather than reading stale state."
    )]
    async fn status(&self) -> Result<CallToolResult, McpError> {
        self.run(|actor| json(view::to_json(&view::run_status(&actor.ctx.run_status()))))
            .await
    }

    #[tool(
        description = "Resume the VM with an optional exception acknowledgement (handled by default, or not_handled; KD only). Non-blocking: returns {running:true, already_running, disposition}. To wait for the next stop, call wait_for_stop."
    )]
    async fn resume(
        &self,
        Parameters(ResumeArgs { disposition }): Parameters<ResumeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let disposition =
            disposition.map_or(ContinueDisposition::Handled, ContinueDisposition::from);
        self.run(move |actor| {
            let ctx = &mut actor.ctx;
            // Drain any stop the servicer caught so a real halt that already
            // surfaced is reflected as `already_running:false` and the resume
            // actually advances past it.
            ctx.settle_pending_stop()?;
            let already_running = ctx.backend.is_running();
            if !already_running {
                ctx.resume_with_disposition(disposition)?;
            }
            json(serde_json::json!({
                "running": true,
                "already_running": already_running,
                "disposition": disposition.name(),
            }))
        })
        .await
    }

    #[tool(
        description = "Wait up to timeout_ms for the next stop WITHOUT resuming (default 10000, max 20000; 0 = default). Returns {stop:\"breakpoint\"|\"watchpoint\"|\"exception\"|\"bugcheck\"|\"step\"|\"target_reloaded\"} with context, {stop:\"running\"} if the wait elapsed (call again; no stops are lost between calls), or {stop:\"halted\"} immediately if the VM is already parked with nothing pending. Does not resume; call resume to advance. Poll with short timeouts; there is no indefinite wait."
    )]
    async fn wait_for_stop(
        &self,
        Parameters(WaitArgs { timeout_ms }): Parameters<WaitArgs>,
        ct: CancellationToken,
    ) -> Result<CallToolResult, McpError> {
        let timeout_ms = optional_timeout_ms(timeout_ms)?;
        // Per-request cancel flag the actor's wait loop polls. Set when the
        // client cancels this request (`ct`) or the server is shutting down
        // (`self.interrupt`), so an in-flight wait returns and frees the actor
        // instead of pinning it for the whole timeout.
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
            .run(move |actor| {
                let ctx = &mut actor.ctx;
                let outcome =
                    ctx.wait_for_stop_bounded(Some(Duration::from_millis(timeout_ms)), &cancel)?;
                json(continue_outcome_json(ctx, outcome))
            })
            .await;
        watcher.abort();
        result
    }

    #[tool(
        description = "Pause a running VM (needed before k, r, bp, t and other halted-only commands); returns {already_halted, rip}. If already halted, no action is taken. Resume with resume."
    )]
    async fn interrupt(&self) -> Result<CallToolResult, McpError> {
        self.run(|actor| {
            let ctx = &mut actor.ctx;
            // A stop the servicer already caught means the VM is halted now;
            // ingest it so `already_halted` is truthful and we don't send a
            // redundant break-in over it.
            ctx.settle_pending_stop()?;
            let already_halted = !ctx.backend.is_running();
            let event_rip = if already_halted {
                None
            } else {
                ctx.interrupt()?.program_counter
            };
            let rip = event_rip.or_else(|| {
                ctx.read_registers()
                    .ok()
                    .and_then(|r| ctx.register_map.read_u64("rip", &r).ok())
            });
            json(serde_json::json!({
                "already_halted": already_halted,
                "rip": rip.map(hex),
            }))
        })
        .await
    }

    #[tool(
        description = "Attach to a target: a live Windows VM over kd/kdnet/gdb/memory, or a crash dump (backend=dump, connect=<path>). Must be called before other tools when the server was started without --connect/--dump. Only one session can be active at a time. Returns {status:\"connected\", backend, connect, processors}."
    )]
    async fn open(
        &self,
        Parameters(OpenArgs {
            backend,
            connect,
            key,
        }): Parameters<OpenArgs>,
    ) -> Result<CallToolResult, McpError> {
        let spec = match backend {
            BackendArg::Dump => {
                if key.is_some() {
                    return Err(invalid_params("dump does not use 'key'"));
                }
                let path = connect
                    .clone()
                    .ok_or_else(|| invalid_params("dump requires 'connect' (the .dmp path)"))?;
                TargetSpec::Dump(PathBuf::from(path))
            }
            live => {
                // The memory source is the operator's call (`--memory-source`
                // on the CLI); `auto` validates host memory and falls back to
                // KD, which is right whenever nobody knows better.
                TargetSpec::Live {
                    backend: match live {
                        BackendArg::Kd => Backend::Kd,
                        BackendArg::KdNet => Backend::KdNet,
                        BackendArg::Gdb => Backend::Gdb,
                        BackendArg::Memory => Backend::Memory,
                        BackendArg::Dump => unreachable!("handled above"),
                    },
                    connect: connect.clone(),
                    kdnet_key: key,
                    memory_source: KdMemorySource::Auto,
                }
            }
        };
        spec.validate().map_err(invalid_params)?;
        let label = match &spec {
            TargetSpec::Dump(_) => "dump".to_string(),
            TargetSpec::Live { backend, .. } => backend.to_string(),
        };
        let needs_ticker = !matches!(
            spec,
            TargetSpec::Dump(_)
                | TargetSpec::Live {
                    backend: Backend::Memory,
                    ..
                }
        );

        let opening = OpeningGuard::claim(&self.session)?;
        let (tx, service_pending) = tokio::task::spawn_blocking(move || spawn_session(spec))
            .await
            .map_err(|e| McpError::internal_error(format!("spawn_blocking failed: {e}"), None))?
            .map_err(|e| {
                McpError::internal_error(format!("failed to open ({label}): {e}"), None)
            })?;
        let tx_for_ticker = tx.clone();
        opening.promote(tx)?;
        if needs_ticker {
            spawn_service_ticker(tx_for_ticker, service_pending);
        }

        self.run(move |actor| {
            let processors = actor
                .ctx
                .backend
                .thread_list()
                .map(|t| t.len())
                .unwrap_or(1);
            json(serde_json::json!({
                "status": "connected",
                "backend": label,
                "connect": connect,
                "processors": processors,
            }))
        })
        .await
    }

    #[tool(
        description = "Close the active debugger session (restores breakpoints and resumes the guest) so a new one can be opened. Returns {status:\"closed\"}, or {status:\"pending\", warning} if the shutdown timed out (retry shortly). Cancels an in-progress open if one is pending."
    )]
    async fn close(&self) -> Result<CallToolResult, McpError> {
        let tx = {
            let mut guard = self.session.lock().unwrap();
            match &*guard {
                SessionSlot::Active(tx) => tx.clone(),
                SessionSlot::Opening(_) => {
                    *guard = SessionSlot::Vacant;
                    return Ok(CallToolResult::structured(serde_json::json!({
                        "status": "closed",
                        "note": "cancelled a pending open; the old connection may take a moment to release — retry if the next open reports AlreadyRunning",
                    })));
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
        let _reset = InterruptResetGuard(self.interrupt.clone());

        let (ack_tx, ack_rx) = oneshot::channel();
        let clean = if tx.send(Command::Shutdown { ack: ack_tx }).is_ok() {
            tokio::time::timeout(Duration::from_secs(5), ack_rx)
                .await
                .is_ok_and(|r| r.is_ok())
        } else {
            true
        };
        drop(tx);

        Ok(CallToolResult::structured(if clean {
            // Vacate only after the actor has acked (and released its
            // instance lock), so a subsequent open() can acquire the same
            // target.
            *self.session.lock().unwrap() = SessionSlot::Vacant;
            serde_json::json!({ "status": "closed" })
        } else {
            // The actor is still running (and still holds the instance lock),
            // so leave the slot Active; vacating now would let a concurrent
            // open() past `claim` only to fail on the lock.
            serde_json::json!({
                "status": "pending",
                "warning": "shutdown timed out; the session is still closing — retry close shortly",
            })
        }))
    }
}

#[tool_handler(router = self.tool_router)]
impl rmcp::ServerHandler for NtoseyeMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "ntoseye: a WinDbg-like kernel debugger for a Windows VM (KVM/QEMU, \
                 VMware, UTM) or a crash dump. Drive it with the `command` tool, which \
                 runs one REPL line in WinDbg-style syntax and returns its text; `help` \
                 lists commands. The guest runs freely by default: memory, process, \
                 module, and struct commands work live, while registers, backtraces, \
                 stepping, and breakpoint changes need the VM halted (call `interrupt` \
                 first, or be stopped at a breakpoint). Run-control is split so no \
                 request blocks: `resume` returns immediately, `wait_for_stop` polls \
                 (bounded) for the next stop, `status` reports where the target is now. \
                 Typical breakpoint flow: interrupt → command(\"bp nt!NtCreateFile\") → \
                 resume → wait_for_stop until stop:\"breakpoint\" → command(\"k\"). \
                 After a reboot, status reports coherent:false until rediscovery \
                 finishes; wait for it rather than enumerating stale state. Addresses \
                 in JSON results are 0x hex strings. If no session is open and the \
                 user has not said how the VM is exposed (kd socket path, kdnet key, \
                 gdb address, or a dump file), ask them before calling `open` rather \
                 than guessing; the defaults only fit the documented QEMU setup.",
            )
    }
}

/// Whether a host string (`localhost`, an IP literal, optionally bracketed)
/// names the loopback interface.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn is_loopback_http_bind(addr: &str) -> bool {
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        return socket.ip().is_loopback();
    }
    addr.rsplit_once(':')
        .is_some_and(|(host, _port)| is_loopback_host(host))
}

/// Whether a browser `Origin` header (`scheme://host[:port]`, no path) names a
/// loopback host. Gates cross-origin access to the loopback HTTP bind so a
/// website the user merely visits can't reach the debugger via 127.0.0.1.
fn is_loopback_origin(origin: &str) -> bool {
    let Some((_scheme, rest)) = origin.split_once("://") else {
        return false;
    };
    // host[:port]; a bracketed IPv6 literal ([::1]:port) keeps the colons
    // inside the brackets, so peel those off before splitting on the port.
    let host = if let Some(after_bracket) = rest.strip_prefix('[') {
        match after_bracket.split_once(']') {
            Some((host, _port)) => host,
            None => return false,
        }
    } else {
        rest.split(':').next().unwrap_or(rest)
    };
    is_loopback_host(host)
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

/// Attach (on a dedicated thread) per `spec`, if given, and serve the MCP
/// protocol until the client disconnects. Synchronous entry point; it owns
/// its own tokio runtime, so the rest of the binary stays runtime-free.
///
/// `http` selects the transport: `None` serves over **stdio** (the client
/// launches this binary as a subprocess), `Some(addr)` serves **Streamable
/// HTTP** on `addr` for web clients. HTTP binds are loopback-only unless
/// `unsafe_http` is set. Both transports drive the same single session actor.
pub fn run(
    spec: Option<TargetSpec>,
    http: Option<String>,
    unsafe_http: bool,
) -> anyhow::Result<()> {
    if let Some(addr) = http.as_deref() {
        check_http_bind_policy(addr, unsafe_http)?;
    }

    // The stdio transport speaks MCP on stdout, so all logging goes to stderr.
    let session: SharedSession = Arc::new(std::sync::Mutex::new(SessionSlot::Vacant));
    match spec {
        Some(spec) => {
            let (label, needs_ticker) = match &spec {
                TargetSpec::Dump(_) => ("dump".to_string(), false),
                TargetSpec::Live { backend, .. } => {
                    (backend.to_string(), *backend != Backend::Memory)
                }
            };
            eprintln!("ntoseye-mcp: attaching ({label})...");
            let (tx, service_pending) = spawn_session(spec)?;
            *session.lock().unwrap() = SessionSlot::Active(tx.clone());
            if needs_ticker {
                spawn_service_ticker(tx, service_pending);
            }
        }
        None => eprintln!("ntoseye-mcp: starting without a session (use open to attach)"),
    }

    // Shared with the handlers so shutdown can interrupt an in-flight
    // `wait_for_stop` (otherwise the actor stays busy and never reaches
    // cleanup, leaving the VM frozen).
    let interrupt = Arc::new(AtomicBool::new(false));
    let interrupt_for_signal = interrupt.clone();
    let session_for_shutdown = session.clone();

    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(async move {
        let serve = async {
            match http {
                Some(addr) => {
                    eprintln!("ntoseye-mcp: serving Streamable HTTP at http://{addr}/mcp");
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
        // Clone the sender out so the slot's mutex isn't held across the await.
        let shutdown_tx = match &*session_for_shutdown.lock().unwrap() {
            SessionSlot::Active(tx) => Some(tx.clone()),
            _ => None,
        };
        if let Some(tx) = shutdown_tx {
            let (ack_tx, ack_rx) = oneshot::channel();
            if tx.send(Command::Shutdown { ack: ack_tx }).is_ok() {
                let _ = tokio::time::timeout(Duration::from_secs(5), ack_rx).await;
            }
        }
        result
    });
    runtime.shutdown_background();
    result
}

/// Background servicing ticker: periodically nudge the actor to service the
/// guest while idle (see [`Command::Service`]). `service_pending` keeps at
/// most one `Service` queued even if the actor is busy in a long wait; the
/// thread exits once the actor's channel closes (send fails).
fn spawn_service_ticker(tx: mpsc::UnboundedSender<Command>, service_pending: Arc<AtomicBool>) {
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
/// `/mcp`. Every HTTP session gets a clone of the handler (cheap; it holds
/// only the actor's channel sender), so all connections funnel to the one
/// live debugger session.
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

    // Methods/headers stay permissive for the Streamable HTTP handshake.
    // Origin is the exposure that matters: loopback binds trust only loopback
    // browser origins, while `--unsafe-http` widens it to any origin.
    let allow_origin = if unsafe_http {
        AllowOrigin::any()
    } else {
        AllowOrigin::predicate(|origin, _parts| origin.to_str().is_ok_and(is_loopback_origin))
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

    fn fake_active_mcp() -> (NtoseyeMcp, mpsc::UnboundedReceiver<Command>) {
        let (tx, rx) = mpsc::unbounded_channel::<Command>();
        let mcp = NtoseyeMcp::new(
            Arc::new(std::sync::Mutex::new(SessionSlot::Active(tx))),
            Arc::new(AtomicBool::new(false)),
        );
        (mcp, rx)
    }

    fn open_kd(
        mcp: &NtoseyeMcp,
        connect: &str,
    ) -> impl Future<Output = Result<CallToolResult, McpError>> {
        mcp.open(Parameters(OpenArgs {
            backend: BackendArg::Kd,
            connect: Some(connect.into()),
            key: None,
        }))
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
        assert!(!is_loopback_origin("null"));
        assert!(!is_loopback_origin("127.0.0.1"));
        assert!(!is_loopback_origin(""));
    }

    #[test]
    fn loopback_binds_are_recognized() {
        assert!(is_loopback_http_bind("127.0.0.1:8080"));
        assert!(is_loopback_http_bind("[::1]:8080"));
        assert!(is_loopback_http_bind("localhost:8080"));
        assert!(!is_loopback_http_bind("0.0.0.0:8080"));
        assert!(!is_loopback_http_bind("192.168.1.2:8080"));
    }

    #[tokio::test]
    async fn open_rejects_when_session_active() {
        let (mcp, _rx) = fake_active_mcp();
        let err = open_kd(&mcp, "/tmp/fake.sock").await.unwrap_err();
        assert!(
            err.message.contains("already active"),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn open_validates_backend_arguments() {
        let mcp = empty_mcp();
        let err = mcp
            .open(Parameters(OpenArgs {
                backend: BackendArg::KdNet,
                connect: None,
                key: None,
            }))
            .await
            .unwrap_err();
        assert!(err.message.contains("requires a key"), "{err:?}");

        let err = mcp
            .open(Parameters(OpenArgs {
                backend: BackendArg::Memory,
                connect: Some("127.0.0.1:1234".into()),
                key: None,
            }))
            .await
            .unwrap_err();
        assert!(err.message.contains("does not use"), "{err:?}");

        let err = mcp
            .open(Parameters(OpenArgs {
                backend: BackendArg::Dump,
                connect: None,
                key: None,
            }))
            .await
            .unwrap_err();
        assert!(err.message.contains("requires 'connect'"), "{err:?}");
    }

    #[tokio::test]
    async fn open_reports_connect_failure_and_frees_the_slot() {
        let mcp = empty_mcp();
        let err = open_kd(&mcp, "/tmp/ntoseye-test-does-not-exist.sock")
            .await
            .unwrap_err();
        assert!(err.message.contains("failed to open"), "{err:?}");
        assert!(matches!(&*mcp.session.lock().unwrap(), SessionSlot::Vacant));
    }

    #[tokio::test]
    async fn close_when_no_session() {
        let mcp = empty_mcp();
        let err = mcp.close().await.unwrap_err();
        assert!(err.message.contains("no debugger session"), "{err:?}");
    }

    #[tokio::test]
    async fn close_active_session_then_reopen_allowed() {
        let (mcp, mut rx) = fake_active_mcp();
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                if let Command::Shutdown { ack } = cmd {
                    let _ = ack.send(());
                    break;
                }
            }
        });

        let result = mcp.close().await.expect("close should succeed");
        assert_eq!(result.structured_content.unwrap()["status"], "closed");
        assert!(matches!(&*mcp.session.lock().unwrap(), SessionSlot::Vacant));
        assert!(!mcp.interrupt.load(Ordering::Relaxed));

        let err = open_kd(&mcp, "/tmp/ntoseye-test-close-reopen-does-not-exist.sock")
            .await
            .unwrap_err();
        assert!(!err.message.contains("already active"), "{err:?}");
    }

    #[tokio::test]
    async fn close_cancels_opening_session() {
        let mcp = NtoseyeMcp::new(
            Arc::new(std::sync::Mutex::new(SessionSlot::Opening(0))),
            Arc::new(AtomicBool::new(false)),
        );
        let result = mcp.close().await.expect("close of Opening should succeed");
        assert_eq!(result.structured_content.unwrap()["status"], "closed");
        assert!(matches!(&*mcp.session.lock().unwrap(), SessionSlot::Vacant));
    }

    #[tokio::test]
    async fn command_requires_session() {
        let mcp = empty_mcp();
        let err = mcp
            .command(Parameters(CommandArgs { line: "lm".into() }))
            .await
            .unwrap_err();
        assert!(err.message.contains("no debugger session"), "{err:?}");
    }
}
