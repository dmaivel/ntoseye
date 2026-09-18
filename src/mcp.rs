//! MCP server: the debugger's REPL command language over the Model Context
//! Protocol, for clients that cannot run Python themselves.
//!
//! One `command` tool runs a REPL line with REPL semantics, bounded: a
//! resuming command waits up to `timeout_ms` for the next stop and otherwise
//! hands control back with the target running, a halted-only command sent
//! while it runs waits for that stop first, `break` interrupts. Guest debug output and a run-state trailer
//! ride along with every result. `open`/`close` manage the single session slot.

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

use crate::diagnostics;
use crate::error::Error;
use crate::kd::KdMemorySource;
use crate::output;
use crate::repl::{
    DispatchContext, Flow, RemoteClient, ReplState, ReplStore, StopWaitBudget, command_registry,
    parse_command,
};
use crate::session::{RunStatus, Session};
use crate::structured;
use crate::view;
use crate::{Backend, TargetSpec};

/// The session actor's state: the (`!Send`) session plus the REPL state the
/// `command` tool keeps between calls (built on first use).
struct Actor {
    ctx: Session,
    repl: Option<ReplStore>,
    /// Cursor into the guest debug-output stream (DbgPrint); every `command`
    /// result carries the lines captured since the previous one.
    debug_seq: u64,
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
/// resuming command hands control back with the target running and frees the
/// single-session actor before the client gives up. No indefinite wait is
/// offered over MCP.
const CONTINUE_MAX_TIMEOUT_MS: u64 = 300_000;

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
        let mut actor = match Session::open_with_progress(&spec, &mut |line| eprintln!("{line}")) {
            Ok(ctx) => {
                let _ = ready_tx.send(Ok(()));
                Actor {
                    ctx,
                    repl: None,
                    debug_seq: 0,
                }
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
/// lets [`OpeningGuard`] detect that its reservation was canceled by a
/// concurrent `close`.
enum SessionSlot {
    Vacant,
    Opening(u64),
    Active(mpsc::UnboundedSender<Command>),
}

static OPENING_GENERATION: AtomicU64 = AtomicU64::new(0);

type SharedSession = Arc<std::sync::Mutex<SessionSlot>>;

/// RAII guard that rolls `SessionSlot` back to `Vacant` if the opening future
/// is canceled (e.g. MCP client timeout). [`OpeningGuard::promote`] installs
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
            _ => Err(McpError::internal_error("session open was canceled", None)),
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
    /// Flipped on shutdown so an in-flight bounded wait bails out promptly
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

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CommandArgs {
    #[schemars(
        description = "A REPL command line in ntoseye's WinDbg-style syntax, e.g. `!process 0 0`, `dt nt!_EPROCESS ffff...`, `k`, `bp nt!NtCreateFile`, `dq rsp l8`, `u rip`, `lm`, `g`, `p`, `break`. Several commands may be separated by `;`. Run `help` for the list and `help <cmd>` for one command."
    )]
    line: String,
    #[schemars(
        range(min = 0, max = 300000),
        description = "How long the call may wait for the target to stop before returning with it still running (default 10000, max 300000; 0 = default): a resuming command (g, p, gu, pa, ...) waits for the stop it causes, and a halted-only command (k, r, bp, ...) issued while the target runs waits for the stop before running. Commands that work on a running target ignore it."
    )]
    timeout_ms: Option<u64>,
    #[schemars(
        description = "text (default): the REPL's output with a one-line `[target ...]` trailer. json: a structured envelope {output, result, target, debug_output}; `result` is the typed decoding for commands that have one (the ! inspectors, lm, !process, k, bl, dt, ?, r, !analyze, ...) and null otherwise."
    )]
    format: Option<OutputFormat>,
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

/// One line of run state appended to every text result so a client always
/// knows whether the next call may inspect registers or must wait.
fn status_trailer(status: &RunStatus) -> String {
    if status.running {
        return "[target running]".to_string();
    }
    let mut line = format!("[target halted @ {}", status.current_thread);
    match (status.rip, status.symbol.as_deref()) {
        (Some(rip), Some(symbol)) => line.push_str(&format!(" {rip:#x} {symbol}")),
        (Some(rip), None) => line.push_str(&format!(" {rip:#x}")),
        (None, _) => {}
    }
    if let Some(process) = &status.stopped_process {
        line.push_str(&format!(" | process {} ({})", process.name, process.pid));
    }
    if let Some(scope) = &status.attached_process {
        line.push_str(&format!(" | scope {} ({})", scope.name, scope.pid));
    }
    if !status.coherent {
        line.push_str(" | rediscovery pending");
    }
    line.push(']');
    line
}

/// Everything one `command` call produced, before choosing a rendering.
struct CommandOutput {
    ok: bool,
    text: String,
    result: Option<serde_json::Value>,
    status: RunStatus,
    debug_output: Vec<serde_json::Value>,
}

impl CommandOutput {
    fn into_text(mut self) -> CallToolResult {
        for line in &self.debug_output {
            if let Some(text) = line.get("text").and_then(|t| t.as_str()) {
                self.text.push_str(&format!("[dbgprint] {text}\n"));
            }
        }
        if !self.text.is_empty() && !self.text.ends_with('\n') {
            self.text.push('\n');
        }
        self.text.push_str(&status_trailer(&self.status));
        let content = vec![ContentBlock::text(self.text)];
        if self.ok {
            CallToolResult::success(content)
        } else {
            CallToolResult::error(content)
        }
    }

    fn into_json(self) -> CallToolResult {
        let value = serde_json::json!({
            "ok": self.ok,
            "output": self.text,
            "result": self.result,
            "target": view::to_json(&view::run_status(&self.status)),
            "debug_output": self.debug_output,
        });
        let mut result = CallToolResult::structured(value);
        if !self.ok {
            result.is_error = Some(true);
        }
        result
    }
}

/// Run one REPL line on the actor with REPL semantics, bounded by `budget`.
///
/// [`ReplState::begin_remote_line`] renders a parked stop first; each command
/// on the line is then admitted by [`ReplState::gate_remote_command`] against
/// the target's state at that point, so `break; bp ...; g` is one call. Guest
/// debug output captured since the previous call and the run state are
/// gathered afterwards.
fn run_command(
    actor: &mut Actor,
    line: &str,
    budget: StopWaitBudget,
    format: OutputFormat,
) -> CommandOutput {
    let store = actor
        .repl
        .take()
        .unwrap_or_else(|| ReplStore::new(&actor.ctx, DispatchContext::Remote(RemoteClient::Mcp)));
    let mut state = ReplState::attach(&mut actor.ctx, store);
    state.stop_wait = Some(budget);
    state.line = line.trim().to_string();
    let mut result = None;
    let (flow, mut text) = output::capture(|| {
        let line = state.line.clone();
        if let Some(flow) = state.begin_remote_line(&line)? {
            return Ok(flow);
        }
        if format == OutputFormat::Json {
            // The structured decoders bypass `dispatch_one` and its gate, so
            // admit the (single) command here. A line without a decoding
            // falls through to `dispatch_line`, whose gate is then a no-op:
            // the target is already halted or the command never needed it.
            let spec = parse_command(&line)
                .ok()
                .flatten()
                .and_then(|parsed| command_registry().get(parsed.name));
            if let Some(spec) = spec
                && let Some(flow) = state.gate_remote_command(spec)?
            {
                return Ok(flow);
            }
            match structured::structured_command(&mut state, &line) {
                Some(Ok(view)) => {
                    result = Some(view::to_json(&view));
                    return Ok(Flow::Continue);
                }
                Some(Err(error)) => {
                    outln!("error: {error}");
                    return Ok(Flow::Denied);
                }
                None => {}
            }
        }
        state.dispatch_line(&line)
    });
    let ok = match flow {
        Ok(Flow::Continue | Flow::Quit) => true,
        Ok(Flow::Denied) => false,
        Err(e) => {
            text.push_str(&format!("error: {e}\n"));
            false
        }
    };
    let status = state.ctx.run_status();
    // `run_status` may have ingested a stop that arrived during the command;
    // show it now rather than on the next call.
    let (_, late) = output::capture(|| state.surface_parked_stop());
    text.push_str(&late);
    actor.repl = Some(state.detach());

    let page = actor.ctx.read_debug_output(actor.debug_seq);
    actor.debug_seq = page.next_seq;
    let debug_output = match view::to_json(&view::debug_log(&page)) {
        serde_json::Value::Object(mut map) => match map.remove("lines") {
            Some(serde_json::Value::Array(lines)) => lines,
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    CommandOutput {
        ok,
        text,
        result,
        status,
        debug_output,
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
        description = "Run one line of ntoseye's WinDbg-style REPL (`;` separates commands) and return its output (styling stripped) followed by a `[target ...]` trailer with the run state. This is the whole debugger: `help` lists every command; `help <cmd>` explains one. Common: `!process 0 0` / `!process <pid|name>` (processes), `.process /p <pid>` / `.process 0` (address-space scope), `lm` (modules), `dt <type> [addr]` (struct layout/read), `x <mod>!<pat>` (symbols), `dq/dd/db <addr> [l<n>]` (memory), `u <addr>` (disassemble), `k` (backtrace; halted), `r` (registers; halted), `bp/bl/bc/bd/be` (breakpoints; halted), `!analyze`. Run control has REPL semantics, bounded by timeout_ms: `g`/`p`/`t`/`gu`/`pa`... resume and wait for the next stop, which is rendered like the REPL renders it; if none arrives the result ends with `[target running]` and the target keeps running. Like typing at a running WinDbg, a halted-only command (`k`, `r`, `bp`, ...) or another resuming command sent while the target runs waits up to timeout_ms for the stop first, then runs (a resuming one is instead refused once, so the stop is seen before it is continued past); `break` interrupts. Each command on a `;` line is admitted against the target's state at that point, so to set a breakpoint on a freely running guest send `break; bp <addr>; g` as one line rather than waiting for a stop that will not come. A stop that happened between calls is rendered at the top of the next result. Guest DbgPrint lines captured since the previous call are appended as `[dbgprint] ...`. format=json returns {ok, output, result, target, debug_output} with a typed `result` for commands that have a structured decoding."
    )]
    async fn command(
        &self,
        Parameters(CommandArgs {
            line,
            timeout_ms,
            format,
        }): Parameters<CommandArgs>,
        ct: CancellationToken,
    ) -> Result<CallToolResult, McpError> {
        let timeout_ms = optional_timeout_ms(timeout_ms)?;
        let format = format.unwrap_or_default();
        // Per-request cancel flag the REPL's bounded wait polls. Set when the
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
                let budget = StopWaitBudget::new(Duration::from_millis(timeout_ms), cancel);
                let output = run_command(actor, &line, budget, format);
                Ok(match format {
                    OutputFormat::Text => output.into_text(),
                    OutputFormat::Json => output.into_json(),
                })
            })
            .await;
        watcher.abort();
        result
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
                        "note": "canceled a pending open; the old connection may take a moment to release, so retry if the next open reports AlreadyRunning",
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
                "warning": "shutdown timed out; the session is still closing. Retry close shortly",
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
                 runs one REPL line in WinDbg-style syntax and returns its text plus a \
                 `[target ...]` trailer; `help` lists commands. The guest runs freely by \
                 default: memory, process, module, and struct commands work live, while \
                 registers, backtraces, stepping, and breakpoint changes need the VM \
                 halted (`break` first, or be stopped at a breakpoint). Resuming commands \
                 (`g`, `p`, `t`, `gu`, ...) wait up to timeout_ms for the next stop and \
                 render it; if the trailer says running, the next halted-only command \
                 (`k`, `r`, ...) waits for the stop before running, so just carry on (no \
                 stop is lost between calls). To set a breakpoint on a freely running \
                 guest, halt it on the same line: `break; bp nt!NtCreateFile; g`, then \
                 `k` once it hits (a bare `bp` while the guest runs only waits for a \
                 stop that nothing will cause). A user-mode symbol like \
                 `user32!PeekMessageW` lives in a process, so name it: \
                 `break; bu /p <pid> user32!PeekMessageW; g` resolves the symbol in that \
                 process without a prior `.process /p`. A backtrace through a module \
                 whose PDB is not cached shows `module+offset` and fetches it in the \
                 background; run `k` again for the names. After a \
                 reboot the trailer says \
                 rediscovery pending until the kernel is rediscovered; wait rather than \
                 enumerating stale state. Use format=json when you need typed values \
                 instead of parsing text. If no session is open and the user has not said \
                 how the VM is exposed (kd socket path, kdnet key, gdb address, or a dump \
                 file), ask them before calling `open` rather than guessing; the defaults \
                 only fit the documented QEMU setup.",
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
            .command(
                Parameters(CommandArgs {
                    line: "lm".into(),
                    timeout_ms: None,
                    format: None,
                }),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(err.message.contains("no debugger session"), "{err:?}");
    }
}
