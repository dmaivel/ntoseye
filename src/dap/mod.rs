//! DAP server for a single kernel-debugging session.
//!
//! The `!Send` session stays on its owning thread; a reader thread queues client
//! messages and cancels blocking runs. Responses precede their stop events.
//! DAP threads are vCPUs, and stops halt the whole target.

mod breakpoints;
mod data_breakpoints;
mod evaluate;
mod memory;
mod run_control;
mod stack;
mod variables;
mod wire;

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{Value, json};

use crate::dbg_backend::DebugCapability;
use crate::error::{Error, Result};
use crate::kd::KdMemorySource;
use crate::layout::ParsedType;
use crate::repl::ReplStore;
use crate::session::{ContinueOutcome, Session, StepMode};
use crate::symbols::{SourceLocation, parse_source_paths, parse_symbol_sources};
use crate::termination;
use crate::types::{Dtb, VirtAddr};
use crate::typeview::Expand;
use crate::{Backend, TargetSpec};

use breakpoints::BreakpointState;
use run_control::StepRequest;
use wire::{ClientMessage, Request};

const IDLE_TICK: Duration = Duration::from_millis(20);
const RUN_POLL: Duration = Duration::from_millis(50);

/// Why a request that needs a target cannot be served.
const NO_TARGET: &str = "no target is attached; send a launch or attach request";

/// Whether the guest is running, halted, or the client has detached.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RunState {
    Halted,
    Running,
    /// The session was released: breakpoints removed and the guest resumed.
    /// The target is never touched again.
    Detached,
}

/// A frame handed to the client, plus the register context recovered for it.
/// Valid only for the stop it was built in; the table is cleared on resume.
struct FrameRef {
    thread: i64,
    index: usize,
    ip: u64,
    sp: u64,
    symbol: String,
    source_location: Option<SourceLocation>,
    frame_base: Option<u64>,
    registers: HashMap<String, u64>,
    seed_registers: HashMap<String, u64>,
    /// The address space the frame was recovered in, where its locals live.
    /// A parked thread's frames belong to its own process, whatever the
    /// console's inspection context is.
    dtb: Dtb,
}

/// What a `variablesReference` refers to: one of a frame's scopes, or an
/// aggregate the client opened inside one. The scopes are frame-scoped and the
/// aggregates address the guest directly, so both die with the stop that
/// produced them. An aggregate keeps the address space it was found in, so
/// a frame's locals open in that frame's process.
#[derive(Clone, PartialEq, Eq, Hash)]
enum VarRef {
    Locals(usize),
    Registers(usize),
    /// A struct or union layout at a guest address: a struct-typed local, a
    /// nested field, or what a pointer points at.
    Fields {
        type_name: String,
        address: VirtAddr,
        dtb: Dtb,
    },
    /// Bounded array elements of one element layout and stride.
    Elements {
        element: ParsedType,
        count: u32,
        element_size: usize,
        address: VirtAddr,
        dtb: Dtb,
    },
}

impl VarRef {
    /// The reference that opens `expand`, read in the address space `dtb`.
    fn aggregate(expand: Expand, dtb: Dtb) -> Self {
        match expand {
            Expand::Fields { type_name, address } => Self::Fields {
                type_name,
                address,
                dtb,
            },
            Expand::Elements {
                element,
                count,
                element_size,
                address,
            } => Self::Elements {
                element,
                count,
                element_size,
                address,
                dtb,
            },
        }
    }
}

/// The stop the client was last told about, for `exceptionInfo` and for
/// answering `threads` while the target is running again.
struct StopInfo {
    reason: &'static str,
    description: String,
    exception_id: Option<String>,
    detail: Option<String>,
    /// The breakpoint that caused the stop, reported as `hitBreakpointIds`
    /// so the client can highlight it.
    breakpoint_id: Option<u32>,
}

struct Server {
    session: Option<Session>,
    repl: Option<ReplStore>,
    out: Box<dyn Write>,
    rx: Receiver<ClientMessage>,
    seq: i64,
    state: RunState,
    /// Backend vCPU ids, indexed by `DAP thread id` minus one.
    threads: Vec<String>,
    frames: Vec<FrameRef>,
    vars: Vec<VarRef>,
    /// Reverse index over `vars`, so the same guest object asked about twice
    /// in one stop reuses its reference. A client re-reads the window it is
    /// rendering on every focus change, `setVariable`, and collapse/expand,
    /// and without this each repeat appended a fresh row per visible element.
    var_refs: HashMap<VarRef, i64>,
    /// ntoseye breakpoint ids owned by the client's `setBreakpoints` for one
    /// source path. Each DAP breakpoint can expand into several ids, because a
    /// source line may match several addresses (inlined or ICF'd code).
    source_breakpoints: HashMap<String, Vec<Vec<u32>>>,
    function_breakpoints: Vec<u32>,
    instruction_breakpoints: Vec<u32>,
    data_breakpoints: Vec<u32>,
    last_stop: Option<StopInfo>,
    /// Last state reported per installed breakpoint id, so a deferred
    /// breakpoint that arms (or a resolved one whose module unloads) produces
    /// exactly one `breakpoint` event instead of one per stop. The address is
    /// part of the state because a driver that reloads at a different base
    /// re-resolves to a new one, and a client holding the old address marks
    /// the wrong line and the wrong disassembly row.
    verified: HashMap<u32, BreakpointState>,
    /// Cursor into the guest debug-output stream (DbgPrint).
    debug_seq: u64,
    /// Raised by the reader thread on `pause`, `disconnect`, `terminate`, or
    /// end of stream, so a blocking run gives up promptly. Cleared only where
    /// the pause is consumed (`pause` itself and the stop report), never by
    /// run control: a `pause` read before a step began still cancels it.
    cancel: Arc<AtomicBool>,
    lines_start_at_1: bool,
    columns_start_at_1: bool,
    /// Set when a termination signal arrived; the loop detaches and exits.
    terminating: Arc<AtomicBool>,
    /// Whether the client accepts `invalidated` events, from its `initialize`
    /// arguments. Without it, a context change the console made can only be
    /// reported in the console itself.
    supports_invalidated: bool,
    configured: bool,
    done: bool,
}

/// Serve the Debug Adapter Protocol until the client disconnects.
///
/// `spec` attaches at startup (from the CLI flags); without it the adapter
/// waits for the `launch`/`attach` request to name a target. `port` serves one
/// TCP client on loopback instead of stdio, which is what editors configured
/// with a `debugServer` port expect.
pub fn run(spec: Option<TargetSpec>, port: Option<u16>) -> Result<()> {
    let (tx, rx) = mpsc::channel();
    // Shared with the reader thread so a `pause` can interrupt a run the loop
    // is already blocked in.
    let cancel = Arc::new(AtomicBool::new(false));
    let out: Box<dyn Write> = match port {
        Some(port) => {
            let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            let listener = TcpListener::bind(addr)
                .map_err(|error| Error::DebugInfo(format!("failed to bind {addr}: {error}")))?;
            let addr = listener
                .local_addr()
                .map_err(|error| Error::DebugInfo(error.to_string()))?;
            eprintln!("ntoseye-dap: listening on {addr}");
            let (stream, peer) = listener
                .accept()
                .map_err(|error| Error::DebugInfo(format!("accept failed: {error}")))?;
            eprintln!("ntoseye-dap: client connected from {peer}");
            let reader = stream
                .try_clone()
                .map_err(|error| Error::DebugInfo(error.to_string()))?;
            wire::spawn_reader(reader, tx, Arc::clone(&cancel));
            Box::new(stream)
        }
        None => {
            wire::spawn_reader(io::stdin(), tx, Arc::clone(&cancel));
            Box::new(io::stdout())
        }
    };

    let session = match spec {
        Some(spec) => Some(Session::open_with_progress(&spec, &mut |line| {
            eprintln!("{line}")
        })?),
        None => None,
    };

    let mut server = Server::new(session, out, rx, Arc::clone(&cancel));
    server.terminating = termination::install(&cancel);
    server.serve();
    if let Some(session) = server.session.as_mut()
        && let Err(error) = session.cleanup_for_exit()
    {
        eprintln!("ntoseye-dap: cleanup failed: {error}");
    }
    Ok(())
}

impl Server {
    fn new(
        session: Option<Session>,
        out: Box<dyn Write>,
        rx: Receiver<ClientMessage>,
        cancel: Arc<AtomicBool>,
    ) -> Self {
        Self {
            session,
            repl: None,
            out,
            rx,
            seq: 0,
            state: RunState::Halted,
            threads: Vec::new(),
            frames: Vec::new(),
            vars: Vec::new(),
            var_refs: HashMap::new(),
            source_breakpoints: HashMap::new(),
            function_breakpoints: Vec::new(),
            instruction_breakpoints: Vec::new(),
            data_breakpoints: Vec::new(),
            last_stop: None,
            verified: HashMap::new(),
            debug_seq: 0,
            cancel,
            lines_start_at_1: true,
            columns_start_at_1: true,
            terminating: Arc::new(AtomicBool::new(false)),
            supports_invalidated: false,
            configured: false,
            done: false,
        }
    }

    fn serve(&mut self) {
        while !self.done {
            if self.terminating.load(Ordering::SeqCst) {
                self.detach_on_signal();
                return;
            }
            match self.rx.recv_timeout(IDLE_TICK) {
                Ok(message) => self.consume(message),
                Err(mpsc::RecvTimeoutError::Timeout) => self.service(),
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
        // Drain anything the client sent before it stopped reading, so a
        // trailing `disconnect` still gets its response.
        while let Ok(message) = self.rx.try_recv() {
            if let ClientMessage::Message(message) = message
                && let Some(request) = Request::from_message(&message)
                && request.command == "disconnect"
            {
                self.respond(&request, Ok(None));
            }
        }
    }

    /// A termination signal arrived: release the target before the process
    /// dies, so no breakpoint byte is left behind and the guest keeps running.
    /// The client may already be gone, so the writes are best effort.
    fn detach_on_signal(&mut self) {
        eprintln!("ntoseye-dap: termination signal received; detaching");
        self.shutdown_session();
        self.send_event("terminated", json!({}));
        self.done = true;
    }

    fn consume(&mut self, message: ClientMessage) {
        match message {
            ClientMessage::Message(message) => {
                if let Some(request) = Request::from_message(&message) {
                    self.dispatch(request);
                }
            }
            ClientMessage::Eof => self.done = true,
            ClientMessage::Error(error) => {
                eprintln!("ntoseye-dap: {error}");
                self.done = true;
            }
        }
    }

    /// Between client messages: surface a stop the target reached on its own,
    /// keep a halted target's transport serviced, and forward guest debug
    /// output.
    fn service(&mut self) {
        if self.session.is_none() || !self.configured {
            return;
        }
        match self.state {
            RunState::Running => {
                let cancel = Arc::clone(&self.cancel);
                let outcome = self
                    .session
                    .as_mut()
                    .map(|session| session.wait_for_stop_bounded(Some(RUN_POLL), &cancel));
                match outcome {
                    Some(Ok(ContinueOutcome::Running)) | None => {}
                    Some(Ok(outcome)) => self.report_stop(outcome),
                    Some(Err(error)) => {
                        self.emit_output("stderr", format!("target wait failed: {error}\n"));
                        // Stop polling a transport that just failed, instead
                        // of repeating the same error every tick. The client
                        // is told the run ended even though the target never
                        // reported where: it last saw `continued`, so without
                        // a stop its view stays on a run that can never end,
                        // and `pause` would then answer from the halted
                        // shortcut without an event either.
                        let rip = self
                            .session
                            .as_mut()
                            .and_then(|session| session.run_status().rip)
                            .unwrap_or(0);
                        self.report_stop(ContinueOutcome::Halted { rip });
                    }
                }
            }
            RunState::Halted => {
                if let Some(session) = self.session.as_mut() {
                    session.service_idle();
                }
            }
            RunState::Detached => {}
        }
        self.drain_debug_output();
    }

    fn next_seq(&mut self) -> i64 {
        self.seq += 1;
        self.seq
    }

    fn send(&mut self, message: Value) {
        if wire::write_message(&mut self.out, &message).is_err() {
            self.done = true;
        }
    }

    fn send_event(&mut self, event: &str, body: Value) {
        let seq = self.next_seq();
        self.send(json!({"seq": seq, "type": "event", "event": event, "body": body}));
    }

    fn respond(&mut self, request: &Request, result: result::Result<Option<Value>, String>) {
        let seq = self.next_seq();
        let message = match result {
            Ok(body) => {
                let mut response = json!({
                    "seq": seq,
                    "type": "response",
                    "request_seq": request.seq,
                    "success": true,
                    "command": request.command,
                });
                if let Some(body) = body {
                    response["body"] = body;
                }
                response
            }
            Err(message) => json!({
                "seq": seq,
                "type": "response",
                "request_seq": request.seq,
                "success": false,
                "command": request.command,
                "message": message,
            }),
        };
        self.send(message);
    }

    fn emit_output(&mut self, category: &str, text: impl Into<String>) {
        self.send_event(
            "output",
            json!({"category": category, "output": text.into()}),
        );
    }

    fn drain_debug_output(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        for notice in session.take_notices() {
            self.emit_output("important", format!("{notice}\n"));
        }
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let page = session.read_debug_output(self.debug_seq);
        if page.lines.is_empty() && !page.dropped {
            return;
        }
        self.debug_seq = page.next_seq;
        if page.dropped {
            self.emit_output(
                "important",
                "guest debug output overflowed; lines were dropped\n",
            );
        }
        for line in page.lines {
            self.emit_output("stdout", format!("{}\n", line.text));
        }
    }

    /// Remove installed breakpoints and resume the guest before disconnecting.
    fn shutdown_session(&mut self) {
        let Some(mut session) = self.session.take() else {
            return;
        };
        // A dump or passive memory view was never halted, so nothing resumes.
        let resumable = session
            .capabilities()
            .iter()
            .any(|entry| entry.capability == DebugCapability::ExecutionControl && entry.supported);
        match session.cleanup_for_exit() {
            Ok(()) if resumable => {
                self.emit_output("console", "ntoseye: detached; guest resumed\n")
            }
            Ok(()) => self.emit_output("console", "ntoseye: detached\n"),
            Err(error) => {
                let message = format!("ntoseye: detach failed, guest may still be halted: {error}");
                eprintln!("{message}");
                self.emit_output("important", format!("{message}\n"));
            }
        }
        self.state = RunState::Detached;
    }

    fn session(&mut self) -> result::Result<&mut Session, String> {
        self.session.as_mut().ok_or_else(|| NO_TARGET.to_string())
    }

    fn dispatch(&mut self, request: Request) {
        let result = match request.command.as_str() {
            "initialize" => self.on_initialize(&request.arguments),
            "launch" | "attach" => self.on_attach(&request.arguments),
            "configurationDone" => self.on_configuration_done(&request),
            "disconnect" => {
                // Detach before replying: clients may kill the adapter on the response.
                let released = !matches!(self.state, RunState::Detached);
                self.shutdown_session();
                self.done = true;
                if released {
                    self.send_event("terminated", json!({}));
                }
                Ok(None)
            }
            "terminate" => {
                // The client follows `terminated` with a `disconnect` of its
                // own; stay up to answer it.
                self.shutdown_session();
                self.send_event("terminated", json!({}));
                Ok(None)
            }
            "threads" => self.on_threads(),
            "stackTrace" => self.on_stack_trace(&request.arguments),
            "scopes" => self.on_scopes(&request.arguments),
            "variables" => self.on_variables(&request.arguments),
            "setVariable" => self.on_set_variable(&request.arguments),
            "evaluate" => self.on_evaluate(&request.arguments),
            "continue" => self.on_continue(&request),
            "pause" => self.on_pause(&request),
            "next" => self.on_step(&request, StepRequest::Step(StepMode::Over)),
            "stepIn" => self.on_step(&request, StepRequest::Step(StepMode::Into)),
            "stepOut" => self.on_step(&request, StepRequest::Out),
            "setBreakpoints" => self.on_set_breakpoints(&request.arguments),
            "setFunctionBreakpoints" => self.on_set_function_breakpoints(&request.arguments),
            "setInstructionBreakpoints" => self.on_set_instruction_breakpoints(&request.arguments),
            "dataBreakpointInfo" => self.on_data_breakpoint_info(&request.arguments),
            "setDataBreakpoints" => self.on_set_data_breakpoints(&request.arguments),
            "setExceptionBreakpoints" => Self::on_set_exception_breakpoints(&request.arguments),
            "exceptionInfo" => self.on_exception_info(),
            "readMemory" => self.on_read_memory(&request.arguments),
            "writeMemory" => self.on_write_memory(&request.arguments),
            "disassemble" => self.on_disassemble(&request.arguments),
            "modules" => self.on_modules(&request.arguments),
            other => Err(format!("unsupported request '{other}'")),
        };
        // Run control answers its own request before emitting `stopped`, so
        // only a failure raised before it got that far is answered here.
        if matches!(
            request.command.as_str(),
            "configurationDone" | "continue" | "pause" | "next" | "stepIn" | "stepOut"
        ) {
            if let Err(message) = result {
                self.respond(&request, Err(message));
            }
            return;
        }
        self.respond(&request, result);
    }

    fn on_initialize(&mut self, args: &Value) -> Handled {
        self.lines_start_at_1 = arg_bool(args, "linesStartAt1").unwrap_or(true);
        self.columns_start_at_1 = arg_bool(args, "columnsStartAt1").unwrap_or(true);
        self.supports_invalidated = arg_bool(args, "supportsInvalidatedEvent").unwrap_or(false);
        Ok(Some(capabilities()))
    }

    fn on_attach(&mut self, args: &Value) -> Handled {
        if self.session.is_some() {
            self.apply_symbol_arguments(args)?;
            self.send_event("initialized", json!({}));
            self.emit_output(
                "console",
                "ntoseye: already attached from the command line; launch/attach arguments ignored\n",
            );
            return Ok(None);
        }
        let spec = target_spec(args)?;
        let session = Session::open_with_progress(&spec, &mut |line| eprintln!("{line}"))
            .map_err(|error| error.to_string())?;
        self.session = Some(session);
        self.repl = None;
        self.debug_seq = 0;
        self.apply_symbol_arguments(args)?;
        self.send_event("initialized", json!({}));
        Ok(None)
    }

    /// Append client paths and reload symbols at attach when paths were supplied.
    fn apply_symbol_arguments(&mut self, args: &Value) -> result::Result<(), String> {
        let symbol_paths = arg_strings(args, "symbolPath");
        let source_paths = arg_strings(args, "sourcePath");
        if symbol_paths.is_empty() && source_paths.is_empty() {
            return Ok(());
        }
        let session = self.session()?;
        for source in parse_symbol_sources(&symbol_paths) {
            session.target.symbols.append_symbol_source(source);
        }
        for mapping in parse_source_paths(&source_paths) {
            session.target.symbols.append_source_path(mapping);
        }
        if symbol_paths.is_empty() {
            return Ok(());
        }
        let report = session
            .target
            .reload_module_symbols(None)
            .map_err(|error| error.to_string())?;
        let message = format!(
            "ntoseye: symbols reloaded from the configured path: {}/{} modules loaded, {} failed\n",
            report.loaded, report.total, report.failed
        );
        self.emit_output("console", message);
        Ok(())
    }

    /// Frame ids, variable references and the selected frame are only valid
    /// within one stop.
    fn invalidate_stop_state(&mut self) {
        self.frames.clear();
        self.vars.clear();
        self.var_refs.clear();
        if let Some(session) = self.session.as_mut() {
            session.target.selected_frame = None;
        }
    }

    fn on_modules(&mut self, args: &Value) -> Handled {
        let start = arg_i64(args, "startModule").unwrap_or(0).max(0) as usize;
        let requested = arg_i64(args, "moduleCount").unwrap_or(0).max(0) as usize;
        let session = self.session()?;
        let modules = session
            .target
            .modules()
            .map_err(|error| error.to_string())?;
        let total = modules.len();
        let end = if requested == 0 {
            total
        } else {
            (start + requested).min(total)
        };
        let values = modules
            .get(start..end)
            .unwrap_or_default()
            .iter()
            .map(|module| {
                let mut value = json!({
                    "id": module.name,
                    "name": module.short_name,
                    "path": module.name,
                    "addressRange": format!("{:#x}", module.base_address.0),
                });
                if let Some(version) = &module.file_version {
                    value["version"] = json!(version);
                }
                value
            })
            .collect::<Vec<_>>();
        Ok(Some(
            json!({"modules": values, "totalModules": total as i64}),
        ))
    }

    fn to_client_line(&self, line: i64) -> i64 {
        if self.lines_start_at_1 {
            line
        } else {
            line.saturating_sub(1)
        }
    }

    /// The inverse of [`Self::to_client_line`]: a line number as the client
    /// counts it, back into the 1-based line the PDB records.
    fn to_source_line(&self, line: i64) -> u32 {
        let line = if self.lines_start_at_1 {
            line
        } else {
            line + 1
        };
        u32::try_from(line.max(0)).unwrap_or(0)
    }

    fn to_client_column(&self, column: i64) -> i64 {
        if self.columns_start_at_1 {
            column
        } else {
            column.saturating_sub(1)
        }
    }
}

/// Handler result: `Ok(None)` is a success with no body, `Err` becomes a
/// protocol error response with that message.
type Handled = result::Result<Option<Value>, String>;

/// DAP capabilities; backend-specific limitations are reported per request.
fn capabilities() -> Value {
    json!({
        "supportsConfigurationDoneRequest": true,
        "supportsFunctionBreakpoints": true,
        "supportsConditionalBreakpoints": true,
        "supportsHitConditionalBreakpoints": true,
        "supportsLogPoints": true,
        "supportsInstructionBreakpoints": true,
        "supportsDataBreakpoints": true,
        "supportsEvaluateForHovers": true,
        "supportsVariablePaging": true,
        "supportsDelayedStackTraceLoading": true,
        "supportsSetVariable": true,
        "supportsSteppingGranularity": true,
        "supportsDisassembleRequest": true,
        "supportsReadMemoryRequest": true,
        "supportsWriteMemoryRequest": true,
        "supportsModulesRequest": true,
        "supportsExceptionInfoRequest": true,
        "supportsTerminateRequest": true,
        "supportTerminateDebuggee": false,
        "supportsRestartRequest": false,
        "supportsStepBack": false,
    })
}

/// Build a target spec from `launch`/`attach` arguments. Kernel debugging has
/// no process to launch, so both requests mean the same thing.
fn target_spec(args: &Value) -> result::Result<TargetSpec, String> {
    if let Some(dump) = arg_str(args, "dump") {
        return Ok(TargetSpec::Dump(PathBuf::from(dump)));
    }
    let backend = match arg_str(args, "backend") {
        Some(name) => name.parse::<Backend>().map_err(|error| error.to_string())?,
        None => Backend::Kd,
    };
    let memory_source = match arg_str(args, "memorySource") {
        Some(source) => source.parse::<KdMemorySource>()?,
        None => KdMemorySource::Auto,
    };
    let spec = TargetSpec::Live {
        backend,
        connect: arg_str(args, "connect"),
        kdnet_key: arg_str(args, "kdnetKey"),
        memory_source,
    };
    spec.validate().map_err(|error| match error {
        Error::InvalidArgument(message) => message,
        other => other.to_string(),
    })?;
    Ok(spec)
}

fn source_value(location: &SourceLocation) -> Value {
    let name = file_stem_of(&location.file);
    let mut source = json!({"name": name});
    match location
        .local_path
        .as_ref()
        .filter(|_| location.local_exists)
    {
        Some(path) => source["path"] = json!(path.to_string_lossy()),
        // No local file: naming the recorded path lets the client show where
        // the source would come from without pretending it can open it.
        None => {
            source["origin"] = json!(format!("recorded as {}", location.file));
            source["presentationHint"] = json!("deemphasize");
        }
    }
    source
}

/// Last path component of a PDB-recorded source path. Recorded paths are
/// Windows paths, whose separator `Path` does not recognize on a Unix host.
fn file_stem_of(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(path)
        .to_string()
}

/// Parse a protocol address string. DAP memory references are opaque strings;
/// every one this adapter hands out is `0x`-prefixed hex.
fn parse_address(text: &str) -> result::Result<u64, String> {
    let trimmed = text.trim();
    let parsed = match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => trimmed.parse::<u64>(),
    };
    parsed.map_err(|_| format!("malformed address '{text}'"))
}

fn arg_str(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|text| !text.is_empty())
}

fn arg_i64(args: &Value, key: &str) -> Option<i64> {
    args.get(key).and_then(Value::as_i64)
}

fn arg_bool(args: &Value, key: &str) -> Option<bool> {
    args.get(key).and_then(Value::as_bool)
}

/// A repeatable string argument, accepted either as one string or as an array
/// of them, because a client's launch configuration may write either.
fn arg_strings(args: &Value, key: &str) -> Vec<String> {
    match args.get(key) {
        Some(Value::String(single)) => vec![single.clone()],
        Some(Value::Array(entries)) => entries
            .iter()
            .filter_map(|entry| entry.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
