//! DAP server for a single kernel-debugging session.
//!
//! The `!Send` session stays on its owning thread; a reader thread queues client
//! messages and cancels blocking runs. Responses precede their stop events.
//! DAP threads are vCPUs, and stops halt the whole target.

mod wire;

#[cfg(unix)]
use libc::{SIGHUP, SIGINT, SIGTERM, c_int, sighandler_t, signal as install_signal};
#[cfg(test)]
use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(test)]
use std::io::Cursor;
use std::io::{self, Write};
use std::mem::replace;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
#[cfg(test)]
use std::rc::Rc;
use std::result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{LazyLock, OnceLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Value, json};

use crate::backend::MemoryOps;
use crate::dbg_backend::{DebugCapability, WatchpointAccess, validate_hw_breakpoint};
use crate::disasm::{
    decode_preceding, fallthrough_run_end, instruction_length, max_instruction_bytes,
};
use crate::error::{Error, Result};
use crate::expr::{Expr, ExprType, ExprValue, NumberRadix};
use crate::gdb::BreakpointConfig;
use crate::gdb::breakpoints::Breakpoint;
use crate::kd::KdMemorySource;
use crate::output;
use crate::repl::{DispatchContext, Flow, RemoteClient, ReplState, ReplStore, supports_capability};
use crate::session::{ContinueOutcome, Session};
use crate::symbols::{
    FieldInfo, LocalVariableLocation, ParsedType, ProcedureLocal, SourceLocation,
    parse_source_paths, parse_symbol_sources,
};
use crate::target::{SelectedFrame, Target};
use crate::triage_report::exception_code_name;
use crate::types::VirtAddr;
use crate::typeview::{Expand, FieldView, TypeView, find_field};
use crate::{Backend, TargetSpec};

use wire::{ClientMessage, Request};

const IDLE_TICK: Duration = Duration::from_millis(20);
const RUN_POLL: Duration = Duration::from_millis(50);
/// Frames cached per stop; stackTrace paging slices this walk.
const STACK_FRAME_LIMIT: usize = 256;
/// Bound source stepping when execution does not reach another mapped line.
const STEP_LINE_BUDGET: usize = 4096;
/// Largest source-line range eligible for a temporary endpoint breakpoint.
const MAX_LINE_SPAN: usize = 4096;
/// Raised by a termination signal, so the loop can release the target before
/// the process dies. The handler only stores into it, and
/// [`install_termination_handler`] forces initialization before installing
/// the handler, so the store never allocates.
static TERMINATION: LazyLock<Arc<AtomicBool>> = LazyLock::new(|| Arc::new(AtomicBool::new(false)));

/// Raise the shared flags from a signal handler. Signal-handler safe: two
/// atomic stores through already-initialized statics, no allocation, no locks.
#[cfg(unix)]
extern "C" fn note_termination(_signal: c_int) {
    TERMINATION.store(true, Ordering::SeqCst);
    // Also cancel any run control the loop is blocked inside, so it reaches
    // the flag instead of waiting for the target to stop on its own.
    if let Some(cancel) = RUN_CANCEL.get() {
        cancel.store(true, Ordering::SeqCst);
    }
}

/// The run-control cancel flag, published for [`note_termination`]. Its value
/// only exists once a session is being served, so it cannot be a `LazyLock`.
static RUN_CANCEL: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Install detach handlers and return the flag polled by the server loop.
fn install_termination_handler(cancel: &Arc<AtomicBool>) -> Arc<AtomicBool> {
    // Initialize before the handler can run: a store into an initialized
    // `LazyLock` is a plain atomic write.
    let flag = Arc::clone(&TERMINATION);
    let _ = RUN_CANCEL.set(Arc::clone(cancel));
    #[cfg(unix)]
    for signal in [SIGTERM, SIGHUP, SIGINT] {
        // SAFETY: the handler only performs atomic stores.
        unsafe {
            install_signal(signal, note_termination as *const () as sighandler_t);
        }
    }
    flag
}

/// `variablesReference` values start here so they can never collide with a
/// frame id (both are plain integers in the protocol).
const VARIABLES_BASE: i64 = 1 << 20;
/// Largest single `readMemory` response, before the client's own chunking.
const MAX_READ_MEMORY: usize = 1024 * 1024;
/// Maximum array elements decoded per variables request.
const MAX_VARIABLE_PAGE: usize = 1024;

/// Bound client-controlled disassembly buffers, matching console `u`.
const MAX_DISASSEMBLE_INSTRUCTIONS: usize = 4096;

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
    frame_base: Option<u64>,
    registers: HashMap<String, u64>,
    seed_registers: HashMap<String, u64>,
}

/// What a `variablesReference` refers to: one of a frame's scopes, or an
/// aggregate the client opened inside one. The scopes are frame-scoped and the
/// aggregates address the guest directly, so both die with the stop that
/// produced them.
#[derive(Clone, PartialEq, Eq, Hash)]
enum VarRef {
    Locals(usize),
    Registers(usize),
    /// A struct or union layout at a guest address: a struct-typed local, a
    /// nested field, or what a pointer points at.
    Fields {
        type_name: String,
        address: VirtAddr,
    },
    /// Bounded array elements of one element layout and stride.
    Elements {
        element: ParsedType,
        count: u32,
        element_size: usize,
        address: VirtAddr,
    },
}

impl From<Expand> for VarRef {
    fn from(expand: Expand) -> Self {
        match expand {
            Expand::Fields { type_name, address } => Self::Fields { type_name, address },
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
        Some(spec) => Some(Session::open(&spec)?),
        None => None,
    };

    let mut server = Server::new(session, out, rx, Arc::clone(&cancel));
    server.terminating = install_termination_handler(&cancel);
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
        match session.cleanup_for_exit() {
            Ok(()) => self.emit_output("console", "ntoseye: detached; guest resumed\n"),
            Err(error) => {
                let message = format!("ntoseye: detach failed, guest may still be halted: {error}");
                eprintln!("{message}");
                self.emit_output("important", format!("{message}\n"));
            }
        }
        self.state = RunState::Detached;
    }

    fn session(&mut self) -> result::Result<&mut Session, String> {
        self.session
            .as_mut()
            .ok_or_else(|| "no target is attached; send a launch or attach request".to_string())
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
            "next" => self.on_step(&request, StepMode::Over),
            "stepIn" => self.on_step(&request, StepMode::Into),
            "stepOut" => self.on_step(&request, StepMode::Out),
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
        let session = Session::open(&spec).map_err(|error| error.to_string())?;
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

    /// Answers its own request, so the entry stop follows the response the
    /// way every other stop follows the run-control request that produced it.
    fn on_configuration_done(&mut self, request: &Request) -> Handled {
        self.configured = true;
        let status = self.session()?.run_status();
        let running = status.running;
        let rip = status.rip.unwrap_or(0);
        self.respond(request, Ok(None));
        if running {
            self.state = RunState::Running;
        } else {
            self.state = RunState::Halted;
            self.report_stop(ContinueOutcome::Halted { rip });
        }
        Ok(None)
    }

    fn on_continue(&mut self, request: &Request) -> Handled {
        let result = self.session()?.resume().map_err(|error| error.to_string());
        match result {
            Ok(()) => {
                self.invalidate_stop_state();
                self.state = RunState::Running;
                self.respond(request, Ok(Some(json!({"allThreadsContinued": true}))));
                self.send_event(
                    "continued",
                    json!({"threadId": 1, "allThreadsContinued": true}),
                );
            }
            Err(message) => self.respond(request, Err(message)),
        }
        Ok(None)
    }

    fn on_pause(&mut self, request: &Request) -> Handled {
        // The reader raised the flag for this request; it is consumed here.
        self.cancel.store(false, Ordering::Relaxed);
        // The client already holds the stop (a step this pause interrupted
        // reported where it ended), so there is nothing to interrupt.
        if matches!(self.state, RunState::Halted) {
            self.respond(request, Ok(None));
            return Ok(None);
        }
        let result = self
            .session()?
            .interrupt_outcome()
            .map_err(|error| error.to_string());
        match result {
            Ok(outcome) => {
                self.respond(request, Ok(None));
                // A break-in arrives as `STATUS_BREAKPOINT` and a target found
                // halted has no event; both are the pause the client asked
                // for (the exception detail stays for `exceptionInfo`). A
                // breakpoint, bugcheck, or reboot the break-in raced is
                // reported as itself.
                let forced = matches!(
                    outcome,
                    ContinueOutcome::Stopped { .. } | ContinueOutcome::Halted { .. }
                )
                .then_some("pause");
                self.report_stop_as(outcome, forced);
            }
            Err(message) => self.respond(request, Err(message)),
        }
        Ok(None)
    }

    fn on_step(&mut self, request: &Request, mode: StepMode) -> Handled {
        let instruction_granularity =
            arg_str(&request.arguments, "granularity").as_deref() == Some("instruction");
        if let Some(thread) = arg_i64(&request.arguments, "threadId")
            && let Err(message) = self.select_thread(thread)
        {
            self.respond(request, Err(message));
            return Ok(None);
        }
        self.invalidate_stop_state();
        let outcome = self.run_step(mode, instruction_granularity);
        match outcome {
            Ok(outcome) => {
                self.respond(request, Ok(None));
                self.report_stop(outcome);
            }
            Err(message) => {
                self.respond(request, Err(message));
                // The step failed with the target still halted where it was,
                // so re-announce that stop to keep the client's view live. A
                // target that reports no pc has no stop to re-announce, and
                // inventing one would park the client at 0x0.
                if let Some(rip) = self
                    .session
                    .as_mut()
                    .and_then(|session| session.run_status().rip)
                {
                    self.report_stop(ContinueOutcome::Halted { rip });
                }
            }
        }
        Ok(None)
    }

    /// Step by source line, or by instruction when requested or unmapped.
    fn run_step(
        &mut self,
        mode: StepMode,
        instruction_granularity: bool,
    ) -> result::Result<ContinueOutcome, String> {
        let cancel = Arc::clone(&self.cancel);
        if mode == StepMode::Out {
            let session = self.session()?;
            return session.step_out(&cancel).map_err(|error| error.to_string());
        }

        let (mut rip, start) = {
            let session = self.session()?;
            let rip = session.run_status().rip;
            let start = rip
                .and_then(|rip| session.target.source_location(VirtAddr(rip)))
                .map(|location| (location.file, location.line));
            (rip.unwrap_or(0), start)
        };
        if instruction_granularity || start.is_none() {
            return self.step_once(mode);
        }

        for _ in 0..STEP_LINE_BUDGET {
            let outcome = self.advance_within_line(mode, rip)?;
            if !matches!(outcome, ContinueOutcome::Step { .. }) {
                return Ok(outcome);
            }
            if self.cancel.load(Ordering::Relaxed) {
                return Ok(outcome);
            }
            let session = self.session()?;
            rip = session.run_status().rip.unwrap_or(0);
            match session.target.source_location(VirtAddr(rip)) {
                // Left line-mapped code (a call into a module without private
                // symbols): stop here rather than running on blindly.
                None => return Ok(outcome),
                Some(location) => {
                    if start
                        .as_ref()
                        .is_none_or(|(file, line)| location.line != *line || location.file != *file)
                    {
                        return Ok(outcome);
                    }
                }
            }
        }
        Ok(ContinueOutcome::Step { rip })
    }

    /// Run through a fall-through range, or single-step if no range can be used.
    fn advance_within_line(
        &mut self,
        mode: StepMode,
        rip: u64,
    ) -> result::Result<ContinueOutcome, String> {
        let Some(end) = self.coalescible_line_end(rip)? else {
            return self.step_once(mode);
        };
        let cancel = Arc::clone(&self.cancel);
        match self.session()?.run_to(end, &cancel) {
            Ok(outcome) => Ok(outcome),
            // The temporary breakpoint could not be written (a non-resident or
            // read-only page at that address). Stepping needs no breakpoint.
            Err(_) => self.step_once(mode),
        }
    }

    /// End of a readable fall-through range containing more than one instruction.
    /// `None` requires single-stepping instead.
    fn coalescible_line_end(&mut self, rip: u64) -> result::Result<Option<VirtAddr>, String> {
        let session = self.session()?;
        let Some(end) = session
            .target
            .source_line_extent(VirtAddr(rip))
            .and_then(|extent| extent.end)
            .filter(|end| end.0 > rip)
        else {
            return Ok(None);
        };
        let Some(span) = usize::try_from(end.0 - rip)
            .ok()
            .filter(|span| *span <= MAX_LINE_SPAN)
        else {
            return Ok(None);
        };
        // Masked: an injected breakpoint byte reads as `int3`, i.e. as control
        // flow, and would defeat the fall-through proof.
        let mut bytes = vec![0u8; span];
        if session.read_masked(VirtAddr(rip), &mut bytes).is_err() {
            return Ok(None);
        }
        let arch = session.target.arch();
        let Some(run_end) = fallthrough_run_end(&bytes, rip, end.0, arch) else {
            return Ok(None);
        };
        // One instruction: a single-step reaches it in one round trip, a run
        // needs a breakpoint write, a resume and a removal.
        if instruction_length(&bytes, arch) == Some(run_end.saturating_sub(rip) as usize) {
            return Ok(None);
        }
        Ok(Some(VirtAddr(run_end)))
    }

    fn step_once(&mut self, mode: StepMode) -> result::Result<ContinueOutcome, String> {
        let cancel = Arc::clone(&self.cancel);
        let session = self.session()?;
        match mode {
            StepMode::Into => {
                session.step().map_err(|error| error.to_string())?;
                Ok(ContinueOutcome::Step {
                    rip: session.run_status().rip.unwrap_or(0),
                })
            }
            StepMode::Over => session
                .step_over(&cancel)
                .map_err(|error| error.to_string()),
            StepMode::Out => session.step_out(&cancel).map_err(|error| error.to_string()),
        }
    }

    fn select_thread(&mut self, thread: i64) -> result::Result<(), String> {
        // Report a missing target before a missing thread: without a session
        // the thread table is empty for that reason, not because the client
        // named a stale id.
        self.session()?;
        if self.threads.is_empty() {
            self.sync_threads();
        }
        let Some(backend_id) = self.backend_thread_id(thread) else {
            return Err(format!("unknown thread id {thread}"));
        };
        let session = self.session()?;
        if session.current_thread == backend_id {
            return Ok(());
        }
        session
            .set_current_thread(&backend_id)
            .map_err(|error| error.to_string())
    }

    fn backend_thread_id(&self, thread: i64) -> Option<String> {
        usize::try_from(thread)
            .ok()
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| self.threads.get(index))
            .cloned()
    }

    fn dap_thread_id(&self, backend_id: &str) -> i64 {
        self.threads
            .iter()
            .position(|id| id == backend_id)
            .map(|index| index as i64 + 1)
            .unwrap_or(1)
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

    fn report_stop(&mut self, outcome: ContinueOutcome) {
        self.report_stop_as(outcome, None);
    }

    /// Reconcile symbolic breakpoints and report verification changes.
    ///
    /// Compare per-id state at every stop: module-load notifications may have
    /// already reconciled the breakpoint and consumed the module-change signal.
    fn reconcile_breakpoints(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        session.refresh_modules_on_stop();
        let tracked: Vec<u32> = self
            .source_breakpoints
            .values()
            .flatten()
            .flatten()
            .copied()
            .chain(self.function_breakpoints.iter().copied())
            .chain(self.instruction_breakpoints.iter().copied())
            .chain(self.data_breakpoints.iter().copied())
            .collect();
        for id in tracked {
            let Some(session) = self.session.as_ref() else {
                return;
            };
            let Some(breakpoint) = session.breakpoint(id) else {
                self.verified.remove(&id);
                continue;
            };
            let state = BreakpointState::from(breakpoint);
            if self.verified.insert(id, state) == Some(state) {
                continue;
            }
            let Some(breakpoint) = self.session.as_ref().and_then(|s| s.breakpoint(id)) else {
                continue;
            };
            let body = json!({"reason": "changed", "breakpoint": breakpoint_json(breakpoint, 1)});
            self.send_event("breakpoint", body);
        }
    }

    /// Report a stop to the client. `forced_reason` overrides the DAP stop
    /// reason without touching the description or exception detail, for stops
    /// whose transport encoding hides the real cause (a break-in is delivered
    /// as a breakpoint exception).
    fn report_stop_as(&mut self, outcome: ContinueOutcome, forced_reason: Option<&'static str>) {
        // A cancelled run: `run_to` halts the target to remove its temporary
        // breakpoint before reporting `Running`, so the client's `pause` has
        // its stop. Only a target still running (the halt failed) stays on
        // its run.
        let (outcome, forced_reason) = match outcome {
            ContinueOutcome::Running => {
                let halted_rip = self
                    .session
                    .as_mut()
                    .filter(|session| !session.backend.is_running())
                    .and_then(|session| session.run_status().rip);
                match halted_rip {
                    Some(rip) => (ContinueOutcome::Halted { rip }, Some("pause")),
                    None => {
                        self.invalidate_stop_state();
                        self.state = RunState::Running;
                        return;
                    }
                }
            }
            outcome => (outcome, forced_reason),
        };
        self.invalidate_stop_state();
        self.state = RunState::Halted;
        self.cancel.store(false, Ordering::Relaxed);
        self.drain_debug_output();
        self.reconcile_breakpoints();

        let mut action = None;
        let stop = match outcome {
            ContinueOutcome::Running => unreachable!("a running target was reported above"),
            ContinueOutcome::Breakpoint {
                id,
                address,
                symbol,
                rip,
                condition_error,
                action: breakpoint_action,
                ..
            } => {
                action = breakpoint_action;
                let where_ = symbol.unwrap_or_else(|| format!("{rip:#x}"));
                if let Some(error) = condition_error {
                    self.emit_output(
                        "important",
                        format!("breakpoint {id} condition failed: {error}\n"),
                    );
                }
                StopInfo {
                    reason: "breakpoint",
                    description: format!("breakpoint {id} at {where_}"),
                    exception_id: None,
                    detail: Some(format!("address {address:#x}")),
                }
            }
            ContinueOutcome::Step { rip } => StopInfo {
                reason: "step",
                description: format!("step to {rip:#x}"),
                exception_id: None,
                detail: None,
            },
            ContinueOutcome::Halted { rip } => StopInfo {
                reason: "entry",
                description: format!("halted at {rip:#x}"),
                exception_id: None,
                detail: None,
            },
            ContinueOutcome::Stopped {
                rip,
                exception_code,
                first_chance,
                exception_address,
            } => match exception_code {
                Some(code) => {
                    let name = exception_code_name(code);
                    let chance = match first_chance {
                        Some(true) => " (first chance)",
                        Some(false) => " (second chance)",
                        None => "",
                    };
                    StopInfo {
                        reason: "exception",
                        description: format!("{name} ({code:#x}){chance} at {rip:#x}"),
                        exception_id: Some(format!("{code:#010x}")),
                        detail: exception_address
                            .map(|address| format!("exception record address {address:#x}")),
                    }
                }
                None => StopInfo {
                    reason: "pause",
                    description: format!("halted at {rip:#x}"),
                    exception_id: None,
                    detail: None,
                },
            },
            ContinueOutcome::Bugcheck { rip, info } => {
                let detail = match &info {
                    Some(info) => format!(
                        "bugcheck {:#x} ({:#x}, {:#x}, {:#x}, {:#x})",
                        info.code,
                        info.parameters[0],
                        info.parameters[1],
                        info.parameters[2],
                        info.parameters[3]
                    ),
                    None => "bugcheck (code unavailable from the transport)".to_string(),
                };
                self.emit_output("important", format!("{detail}\n"));
                self.emit_output(
                    "console",
                    "run `!analyze -v` in the debug console for the full triage\n",
                );
                StopInfo {
                    reason: "exception",
                    description: match rip {
                        Some(rip) => format!("{detail} at {rip:#x}"),
                        None => detail.clone(),
                    },
                    exception_id: Some("bugcheck".to_string()),
                    detail: Some(detail),
                }
            }
            ContinueOutcome::TargetReloaded {
                kernel_base,
                coherent,
            } => {
                let base = kernel_base
                    .map(|base| format!("{base:#x}"))
                    .unwrap_or_else(|| "unknown".to_string());
                self.emit_output(
                    "important",
                    format!(
                        "target rebooted; nt base {base}{}\n",
                        if coherent {
                            ""
                        } else {
                            " (early boot: module and process enumeration not yet available)"
                        }
                    ),
                );
                StopInfo {
                    reason: "entry",
                    description: format!("target rebooted (nt {base})"),
                    exception_id: None,
                    detail: None,
                }
            }
        };

        // A breakpoint command action belongs to the frontend. Running it here
        // keeps `bp ... do "..."` (typed in the console) working, including a
        // trailing `gc` that resumes the target.
        if let Some(action) = action {
            self.run_breakpoint_action(&action);
            if self
                .session
                .as_ref()
                .is_some_and(|session| session.backend.is_running())
            {
                self.state = RunState::Running;
                self.last_stop = Some(stop);
                return;
            }
        }

        self.sync_threads();
        let thread_id = self
            .session
            .as_ref()
            .map(|session| session.current_thread.clone())
            .map(|id| self.dap_thread_id(&id))
            .unwrap_or(1);
        let mut body = json!({
            "reason": forced_reason.unwrap_or(stop.reason),
            "threadId": thread_id,
            "allThreadsStopped": true,
            "description": stop.description,
            "preserveFocusHint": false,
        });
        if stop.reason == "breakpoint"
            && let Some(detail) = &stop.detail
        {
            body["text"] = json!(detail);
        }
        self.last_stop = Some(stop);
        self.send_event("stopped", body);
    }

    /// Run the breakpoint command action, sending output to the Debug Console.
    /// A trailing `gc` resumes without reporting a stop.
    fn run_breakpoint_action(&mut self, action: &str) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let store = ReplStore::new(session, DispatchContext::BreakpointAction);
        let mut state = ReplState::attach(session, store);
        state.line = action.to_string();
        let (result, text) = output::capture(|| state.dispatch_breakpoint_action(action));
        drop(state.detach());
        if !text.is_empty() {
            self.emit_output("stdout", text);
        }
        match result {
            // The action asked to resume (`...; gc`). Nothing else will do it:
            // the client was never told the target stopped.
            Ok(true) => {
                if let Some(session) = self.session.as_mut()
                    && let Err(error) = session.resume()
                {
                    self.emit_output(
                        "stderr",
                        format!("breakpoint action could not resume the target: {error}\n"),
                    );
                }
            }
            Ok(false) => {}
            Err(error) => {
                self.emit_output("stderr", format!("breakpoint action failed: {error}\n"));
            }
        }
    }

    /// Rebuild the vCPU list, announcing additions and removals so a client's
    /// thread view survives a reboot changing the processor count.
    fn sync_threads(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let ids: Vec<String> = match session.vcpus() {
            Ok(vcpus) => vcpus.into_iter().map(|vcpu| vcpu.id).collect(),
            Err(_) => vec![session.current_thread.clone()],
        };
        self.set_threads(ids);
    }

    /// Install the vCPU list, announcing additions and removals.
    fn set_threads(&mut self, ids: Vec<String>) {
        if ids == self.threads {
            return;
        }
        let previous = replace(&mut self.threads, ids);
        for index in previous.len()..self.threads.len() {
            self.send_event(
                "thread",
                json!({"reason": "started", "threadId": index as i64 + 1}),
            );
        }
        for index in (self.threads.len()..previous.len()).rev() {
            self.send_event(
                "thread",
                json!({"reason": "exited", "threadId": index as i64 + 1}),
            );
        }
    }

    fn on_threads(&mut self) -> Handled {
        if matches!(self.state, RunState::Running) {
            // vCPU contexts can only be read while halted; report the last
            // known set so the client's thread view does not empty out.
            let threads = self
                .threads
                .iter()
                .enumerate()
                .map(|(index, id)| json!({"id": index as i64 + 1, "name": format!("{id} (running)")}))
                .collect::<Vec<_>>();
            return Ok(Some(json!({"threads": threads})));
        }
        let session = self.session()?;
        let vcpus = session.vcpus().map_err(|error| error.to_string())?;
        self.set_threads(vcpus.iter().map(|vcpu| vcpu.id.clone()).collect());
        let threads = vcpus
            .iter()
            .enumerate()
            .map(|(index, vcpu)| {
                let mut name = vcpu.id.clone();
                if !vcpu.context.is_empty() {
                    name.push_str(&format!(" [{}]", vcpu.context));
                }
                match (&vcpu.symbol, vcpu.rip, &vcpu.error) {
                    (Some(symbol), _, _) => name.push_str(&format!(" {symbol}")),
                    (None, Some(rip), _) => name.push_str(&format!(" {rip:#x}")),
                    (None, None, Some(error)) => name.push_str(&format!(" <{error}>")),
                    _ => {}
                }
                json!({"id": index as i64 + 1, "name": name})
            })
            .collect::<Vec<_>>();
        Ok(Some(json!({"threads": threads})))
    }

    fn on_stack_trace(&mut self, args: &Value) -> Handled {
        let thread = arg_i64(args, "threadId").unwrap_or(1);
        self.select_thread(thread)?;
        // Clients walk every stopped thread before asking for scopes, so a
        // thread already walked in this stop keeps the handles it was given.
        if !self.frames.iter().any(|frame| frame.thread == thread) {
            self.build_frames(thread)?;
        }

        let start = arg_i64(args, "startFrame").unwrap_or(0).max(0) as usize;
        let levels = arg_i64(args, "levels").unwrap_or(0).max(0) as usize;
        let own: Vec<usize> = self
            .frames
            .iter()
            .enumerate()
            .filter(|(_, frame)| frame.thread == thread)
            .map(|(handle, _)| handle)
            .collect();
        let total = own.len();
        let end = if levels == 0 {
            total
        } else {
            (start + levels).min(total)
        };
        let mut frames = Vec::new();
        for handle in own.iter().skip(start).take(end.saturating_sub(start)) {
            frames.push(self.frame_value(*handle));
        }
        Ok(Some(json!({"stackFrames": frames, "totalFrames": total})))
    }

    /// Walk the selected thread's stack and publish one handle per frame.
    fn build_frames(&mut self, thread: i64) -> result::Result<(), String> {
        let session = self.session()?;
        // Goes through the session so a Windows thread selected in the console
        // (`.thread`) is the stack the client sees, instead of whatever the
        // vCPU is running.
        let (recovered, seed) = session
            .recovered_backtrace(STACK_FRAME_LIMIT)
            .map_err(|error| error.to_string())?;
        for (index, frame) in recovered.frames.iter().enumerate() {
            self.frames.push(FrameRef {
                thread,
                index,
                ip: frame.frame.ip,
                sp: frame.frame.sp,
                frame_base: frame.frame_base,
                registers: frame.registers.clone(),
                seed_registers: seed.clone(),
            });
        }
        Ok(())
    }

    fn frame_value(&mut self, handle: usize) -> Value {
        let (ip, name) = {
            let session = self.session.as_ref();
            let frame = &self.frames[handle];
            let name = session
                .map(|session| {
                    session
                        .target
                        .closest_symbol_current_context(VirtAddr(frame.ip))
                })
                .unwrap_or(None)
                .unwrap_or_else(|| format!("{:#x}", frame.ip));
            (frame.ip, name)
        };
        let location = self
            .session
            .as_ref()
            .and_then(|session| session.target.source_location(VirtAddr(ip)));
        let mut value = json!({
            "id": handle as i64 + 1,
            "name": name,
            "line": 0,
            "column": 0,
            "instructionPointerReference": format!("{ip:#x}"),
        });
        if let Some(location) = &location {
            value["line"] = json!(self.to_client_line(location.line as i64));
            value["column"] = json!(
                location
                    .column
                    .map(|column| self.to_client_column(column as i64))
                    .unwrap_or(0)
            );
            value["source"] = source_value(location);
        }
        value
    }

    fn on_scopes(&mut self, args: &Value) -> Handled {
        let handle = self.frame_handle(args, "frameId")?;
        let locals = self.var_ref(VarRef::Locals(handle));
        let registers = self.var_ref(VarRef::Registers(handle));
        Ok(Some(json!({"scopes": [
            {
                "name": "Locals",
                "presentationHint": "locals",
                "variablesReference": locals,
                "expensive": false,
            },
            {
                "name": "Registers",
                "presentationHint": "registers",
                "variablesReference": registers,
                "expensive": false,
            }
        ]})))
    }

    fn frame_handle(&self, args: &Value, key: &str) -> result::Result<usize, String> {
        let id = arg_i64(args, key).ok_or_else(|| format!("missing {key}"))?;
        usize::try_from(id)
            .ok()
            .and_then(|id| id.checked_sub(1))
            .filter(|handle| *handle < self.frames.len())
            .ok_or_else(|| format!("stale frame id {id}; re-request the stack trace"))
    }

    /// Select the requested frame, or keep the current frame if none was supplied.
    /// Reject stale frame ids.
    fn select_named_frame(&mut self, args: &Value, key: &str) -> result::Result<(), String> {
        if args.get(key).is_none() {
            return Ok(());
        }
        let handle = self.frame_handle(args, key)?;
        self.select_frame(handle)
    }

    fn var_ref(&mut self, reference: VarRef) -> i64 {
        if let Some(existing) = self.var_refs.get(&reference) {
            return *existing;
        }
        self.vars.push(reference.clone());
        let id = VARIABLES_BASE + self.vars.len() as i64 - 1;
        self.var_refs.insert(reference, id);
        id
    }

    /// Resolve a client-supplied `variablesReference` into a live table slot.
    /// References are cleared at every stop, so a stale one is an error rather
    /// than a silent read of whatever now occupies that slot.
    fn var_index(&self, reference: i64) -> result::Result<usize, String> {
        reference
            .checked_sub(VARIABLES_BASE)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < self.vars.len())
            .ok_or_else(|| format!("stale variablesReference {reference}"))
    }

    fn on_variables(&mut self, args: &Value) -> Handled {
        let reference = arg_i64(args, "variablesReference")
            .ok_or_else(|| "missing variablesReference".to_string())?;
        let index = self.var_index(reference)?;
        // Respect both the requested child kind and the array paging window.
        let filter = arg_str(args, "filter").unwrap_or_default();
        let start = arg_i64(args, "start").unwrap_or(0).max(0) as usize;
        let requested = arg_i64(args, "count").unwrap_or(0).max(0) as usize;
        match self.vars[index].clone() {
            VarRef::Registers(handle) if filter != "indexed" => {
                let rows = self.register_variables(handle)?;
                Self::page_rows(rows, start, requested)
            }
            VarRef::Locals(handle) if filter != "indexed" => {
                let rows = self.local_variables(handle)?;
                Self::page_rows(rows, start, requested)
            }
            VarRef::Fields { type_name, address } if filter != "indexed" => {
                let rows = self.field_variables(&type_name, address)?;
                Self::page_rows(rows, start, requested)
            }
            VarRef::Elements {
                element,
                count,
                element_size,
                address,
            } if filter != "named" => {
                let window = match requested {
                    0 => MAX_VARIABLE_PAGE,
                    requested => requested.min(MAX_VARIABLE_PAGE),
                };
                self.element_variables(&element, count, element_size, address, start, window)
            }
            _ => Ok(Some(json!({"variables": []}))),
        }
    }

    /// Apply a client's `start`/`count` window to rows already produced.
    ///
    /// Array elements are windowed at the source, because reading a million of
    /// them to return ten would be the cost that paging exists to avoid. Named
    /// children are bounded by a type's field count, so slicing them here
    /// keeps one window rule for every reference kind.
    fn page_rows(body: Option<Value>, start: usize, count: usize) -> Handled {
        if start == 0 && count == 0 {
            return Ok(body);
        }
        let Some(mut body) = body else {
            return Ok(None);
        };
        let Some(rows) = body["variables"].as_array() else {
            return Ok(Some(body));
        };
        let windowed: Vec<Value> = match count {
            0 => rows.iter().skip(start).cloned().collect(),
            count => rows.iter().skip(start).take(count).cloned().collect(),
        };
        body["variables"] = Value::Array(windowed);
        Ok(Some(body))
    }

    fn register_variables(&mut self, handle: usize) -> Handled {
        self.select_frame(handle)?;
        let frame_index = self.frames[handle].index;
        let snapshot = self.frames[handle].registers.clone();
        let session = self.session()?;
        // Frame 0 is the live register file, so read it rather than the
        // snapshot taken when the stack was walked: a write (`setVariable`, or
        // `r rax=...` in the console) then shows up immediately. Caller frames
        // keep their recovered snapshot, which is all unwind metadata
        // justifies, and so does a parked Windows thread, which has no live
        // file at all.
        let live_context = frame_index == 0 && session.parked_windows_thread().is_none();
        let values = match live_context.then(|| session.read_registers()) {
            Some(Ok(registers)) => session.register_map.to_hashmap(&registers),
            _ => snapshot,
        };
        let mut variables = Vec::new();
        for name in session.register_map.names().iter() {
            let Some(value) = values.get(name.as_str()) else {
                continue;
            };
            variables.push(json!({
                "name": name,
                "value": format!("{value:#018x}"),
                "variablesReference": 0,
                "presentationHint": {"kind": "data", "attributes": ["rawString"]},
            }));
        }
        Ok(Some(json!({"variables": variables})))
    }

    fn local_variables(&mut self, handle: usize) -> Handled {
        let ip = self.frames[handle].ip;
        self.select_frame(handle)?;
        let views = {
            let session = self.session()?;
            let locals = session
                .target
                .procedure_locals(VirtAddr(ip))
                .map_err(|error| error.to_string())?;
            let Some(locals) = locals else {
                return Ok(Some(json!({"variables": []})));
            };
            let view = TypeView::new(session);
            locals
                .iter()
                .map(|local| {
                    let address = session.target.procedure_local_address(local).map(VirtAddr);
                    // Decode memory locals as fields, including aggregates.
                    let (value, expand) = match address {
                        Some(address) => {
                            let field = FieldInfo {
                                offset: 0,
                                size: local.byte_size.unwrap_or_default(),
                                type_data: local.type_data.clone(),
                            };
                            let (text, raw) = view.value_and_raw(address, &field);
                            (text, view.expand_for(&local.type_data, Some(address), raw))
                        }
                        None => {
                            let value = session
                                .target
                                .resolve_procedure_local_value(VirtAddr(ip), local);
                            let expand = view.expand_for(&local.type_data, None, value);
                            (local_value_text(local, value, expand.as_ref()), expand)
                        }
                    };
                    let field = FieldView {
                        name: local.name.clone(),
                        type_name: local.type_name.clone(),
                        address,
                        value,
                        expand,
                    };
                    (field, local.is_parameter)
                })
                .collect::<Vec<_>>()
        };
        let variables = self.variable_rows(views);
        Ok(Some(json!({"variables": variables})))
    }

    /// Open a struct or union: one row per field, each with the value `dt`
    /// would print and a reference of its own when it is expandable in turn.
    fn field_variables(&mut self, type_name: &str, address: VirtAddr) -> Handled {
        let views = {
            let session = self.session()?;
            let view = TypeView::new(session);
            let type_info = view
                .lookup_type(type_name)
                .ok_or_else(|| format!("type '{type_name}' is not in the loaded symbols"))?;
            view.fields(type_info.as_ref(), address)
                .into_iter()
                .map(|field| (field, false))
                .collect::<Vec<_>>()
        };
        let variables = self.variable_rows(views);
        Ok(Some(json!({"variables": variables})))
    }

    /// Open a bounded array. Only the shared element bound is materialized; a
    /// larger array is read past that point through the console (`dt -a`, `dq`).
    fn element_variables(
        &mut self,
        element: &ParsedType,
        count: u32,
        element_size: usize,
        address: VirtAddr,
        start: usize,
        window: usize,
    ) -> Handled {
        let views = {
            let session = self.session()?;
            let view = TypeView::new(session);
            view.elements_from(address, element, count, element_size, start, window)
                .into_iter()
                .map(|field| (field, false))
                .collect::<Vec<_>>()
        };
        let variables = self.variable_rows(views);
        Ok(Some(json!({"variables": variables})))
    }

    /// Turn neutral field views into `variables` rows, allocating a reference
    /// for every row the client may open. An aggregate has no scalar text, so
    /// it is labeled by what opening it yields.
    fn variable_rows(&mut self, views: Vec<(FieldView, bool)>) -> Vec<Value> {
        let mut variables = Vec::with_capacity(views.len());
        for (field, parameter) in views {
            let value = if field.value.is_empty() {
                match &field.expand {
                    Some(Expand::Fields { .. }) => "{...}".to_string(),
                    Some(Expand::Elements { count, .. }) => format!("[{count}]"),
                    None => String::new(),
                }
            } else {
                field.value
            };
            let indexed = match &field.expand {
                Some(Expand::Elements { count, .. }) => Some(*count),
                _ => None,
            };
            let reference = match field.expand {
                Some(expand) => self.var_ref(VarRef::from(expand)),
                None => 0,
            };
            let mut variable = json!({
                "name": field.name,
                "type": field.type_name,
                "value": value,
                "variablesReference": reference,
                "presentationHint": {
                    "kind": if parameter { "property" } else { "data" },
                },
            });
            if let Some(address) = field.address {
                variable["memoryReference"] = json!(format!("{:#x}", address.0));
            }
            if let Some(count) = indexed {
                variable["indexedVariables"] = json!(count);
            }
            variables.push(variable);
        }
        variables
    }

    /// Re-read the live register file into a frame-0 handle, so the frame
    /// context this adapter installs for locals and expressions matches the
    /// target after a write (`setVariable`, or `r rax=...` in the console).
    /// Caller frames keep their recovered snapshot, and so does a parked
    /// Windows thread, whose `read_registers` is refused.
    fn refresh_live_frame(&mut self, handle: usize) {
        if self.frames[handle].index != 0 {
            return;
        }
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let Ok(registers) = session.read_registers() else {
            return;
        };
        let values = session.register_map.to_hashmap(&registers);
        self.frames[handle].registers = values.clone();
        self.frames[handle].seed_registers = values;
    }

    /// Install the recovered register context for a frame in the session, the
    /// same way `.frame N` does, so locals and expressions resolve against the
    /// frame the client selected. Its thread also becomes the backend's
    /// current context, because handles outlive the client's last stack walk.
    fn select_frame(&mut self, handle: usize) -> result::Result<(), String> {
        self.select_thread(self.frames[handle].thread)?;
        self.refresh_live_frame(handle);
        let frame = &self.frames[handle];
        let selected = SelectedFrame {
            index: frame.index,
            ip: frame.ip,
            sp: frame.sp,
            frame_base: frame.frame_base,
            registers: frame.registers.clone(),
            seed_registers: frame.seed_registers.clone(),
        };
        if let Some(session) = self.session.as_mut() {
            session.select_frame(selected);
        }
        Ok(())
    }

    fn on_set_variable(&mut self, args: &Value) -> Handled {
        let reference = arg_i64(args, "variablesReference")
            .ok_or_else(|| "missing variablesReference".to_string())?;
        let name = arg_str(args, "name").ok_or_else(|| "missing name".to_string())?;
        let expression = arg_str(args, "value").ok_or_else(|| "missing value".to_string())?;
        let index = self.var_index(reference)?;
        let target = self.vars[index].clone();
        // A scope row's value expression (`index + 1`, `@rcx`) means what it
        // means in that row's frame, not in whichever frame the previous
        // request installed. Aggregates address the guest directly.
        if let VarRef::Locals(handle) | VarRef::Registers(handle) = target {
            self.select_frame(handle)?;
        }
        let value = self.evaluate_expression(&expression)?;
        match target {
            VarRef::Registers(handle) => {
                if self.frames[handle].index != 0 {
                    return Err(
                        "caller-frame registers are recovered from unwind metadata and are not writable"
                            .to_string(),
                    );
                }
                let session = self.session()?;
                if session.parked_windows_thread().is_some() {
                    return Err(
                        "a parked Windows thread's registers are recovered from its saved context \
                         and are not writable; select a vCPU with `.thread` first"
                            .to_string(),
                    );
                }
                session
                    .write_register(&name, value)
                    .map_err(|error| error.to_string())?;
                self.refresh_live_frame(handle);
                Ok(Some(json!({"value": format!("{value:#018x}")})))
            }
            VarRef::Locals(handle) => {
                let ip = self.frames[handle].ip;
                let live_frame = self.frames[handle].index == 0;
                let session = self.session()?;
                let locals = session
                    .target
                    .procedure_locals(VirtAddr(ip))
                    .map_err(|error| error.to_string())?
                    .unwrap_or_default();
                let local = locals
                    .iter()
                    .find(|local| local.name == name)
                    .ok_or_else(|| format!("no local named '{name}' in scope"))?;
                let size = local
                    .byte_size
                    .and_then(|size| usize::try_from(size).ok())
                    .filter(|size| *size > 0 && *size <= 8)
                    .ok_or_else(|| {
                        format!("'{name}' is not a scalar this adapter can write in place")
                    })?;
                match &local.location {
                    LocalVariableLocation::Register { register } => {
                        if !live_frame {
                            return Err(format!(
                                "'{name}' lives in a register recovered from unwind metadata for a \
                                 caller frame; writing it would change the live register instead"
                            ));
                        }
                        let register = register.clone();
                        session
                            .write_register(&register, value)
                            .map_err(|error| error.to_string())?;
                    }
                    _ => {
                        let address = session
                            .target
                            .procedure_local_address(local)
                            .ok_or_else(|| format!("'{name}' has no resolvable address"))?;
                        let bytes = value.to_le_bytes();
                        session
                            .target
                            .current_process()
                            .map_err(|error| error.to_string())?
                            .memory()
                            .write_bytes(VirtAddr(address), &bytes[..size])
                            .map_err(|error| error.to_string())?;
                    }
                }
                // A register-held local shares storage with the frame's
                // register cache, which `select_frame` reinstalls on the next
                // request; re-read it so the pane does not show the old value.
                self.refresh_live_frame(handle);
                let session = self.session()?;
                let refreshed = session
                    .target
                    .procedure_locals(VirtAddr(ip))
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let view = TypeView::new(session);
                let text = refreshed
                    .iter()
                    .find(|local| local.name == name)
                    .map(|local| {
                        // Read the written local back the way the variables
                        // view renders it, so the response and the next
                        // refresh cannot disagree.
                        match session.target.procedure_local_address(local).map(VirtAddr) {
                            Some(address) => {
                                let field = FieldInfo {
                                    offset: 0,
                                    size: local.byte_size.unwrap_or_default(),
                                    type_data: local.type_data.clone(),
                                };
                                view.value_text(address, &field)
                            }
                            None => {
                                let value = session
                                    .target
                                    .resolve_procedure_local_value(VirtAddr(ip), local);
                                let expand = view.expand_for(&local.type_data, None, value);
                                local_value_text(local, value, expand.as_ref())
                            }
                        }
                    })
                    .unwrap_or_else(|| format!("{value:#x}"));
                Ok(Some(json!({"value": text})))
            }
            VarRef::Fields { type_name, address } => {
                let (field_address, size, field) = {
                    let session = self.session()?;
                    let view = TypeView::new(session);
                    let type_info = view.lookup_type(&type_name).ok_or_else(|| {
                        format!("type '{type_name}' is not in the loaded symbols")
                    })?;
                    let (field_name, field) = find_field(type_info.as_ref(), &name)
                        .ok_or_else(|| format!("no field named '{name}' in {type_name}"))?;
                    if let ParsedType::Bitfield { .. } = field.type_data {
                        return Err(format!(
                            "'{field_name}' is a bitfield; set it with 'eb'/'ed' on the containing \
                             value in the console"
                        ));
                    }
                    let size = view.field_size(field);
                    if !(1..=8).contains(&size) {
                        return Err(format!(
                            "'{field_name}' is {size} bytes; write it with 'eb' in the console"
                        ));
                    }
                    let field_address = address + u64::from(field.offset);
                    (field_address, size, field.clone())
                };
                self.write_scalar(field_address, size, value)?;
                let session = self.session()?;
                let view = TypeView::new(session);
                Ok(Some(
                    json!({"value": view.value_text(field_address, &field)}),
                ))
            }
            VarRef::Elements {
                element,
                count,
                element_size,
                address,
            } => {
                let index = element_index(&name)?;
                if index >= count {
                    return Err(format!(
                        "element {index} is past the end of a [{count}] array"
                    ));
                }
                if !(1..=8).contains(&element_size) {
                    return Err(format!(
                        "elements are {element_size} bytes; write them with 'eb' in the console"
                    ));
                }
                let element_address =
                    address + u64::from(index) * u64::try_from(element_size).unwrap_or(1);
                self.write_scalar(element_address, element_size, value)?;
                let field = FieldInfo {
                    offset: 0,
                    size: element_size as u64,
                    type_data: element,
                };
                let session = self.session()?;
                let view = TypeView::new(session);
                Ok(Some(
                    json!({"value": view.value_text(element_address, &field)}),
                ))
            }
        }
    }

    /// Write `size` little-endian bytes into the guest in the current process
    /// context. The caller has already bounded `size` to a scalar width.
    fn write_scalar(
        &mut self,
        address: VirtAddr,
        size: usize,
        value: u64,
    ) -> result::Result<(), String> {
        let bytes = value.to_le_bytes();
        self.session()?
            .target
            .current_process()
            .map_err(|error| error.to_string())?
            .memory()
            .write_bytes(address, &bytes[..size])
            .map_err(|error| error.to_string())
    }

    fn on_evaluate(&mut self, args: &Value) -> Handled {
        let expression = arg_str(args, "expression").unwrap_or_default();
        if expression.trim().is_empty() {
            return Ok(Some(json!({"result": "", "variablesReference": 0})));
        }
        let context = arg_str(args, "context").unwrap_or_else(|| "repl".to_string());
        self.select_named_frame(args, "frameId")?;
        if context == "repl" {
            let before = self.inspection_context();
            let text = self.run_console_command(&expression)?;
            if self.inspection_context() != before {
                self.invalidate_context();
            }
            return Ok(Some(json!({
                "result": text,
                "variablesReference": 0,
            })));
        }
        let (expr, value) = self.parse_and_evaluate(&expression)?;
        let (result, type_name, memory_reference, expansion, indexed_variables) = {
            let session = self.session()?;
            let type_data = value.type_data().cloned();
            let byte_size = value.byte_size();
            let scalar = value.scalar(&session.target);
            let storage = value.address().ok();
            let register = direct_register_expression(&expr, &session.target);
            // A typed pointer rvalue has no storage of its own, but its scalar
            // is a pointee address clients can inspect or watch.
            let pointer_value = matches!(type_data, Some(ParsedType::Pointer(_)));
            let view = TypeView::new(session);
            let expansion = type_data.as_ref().and_then(|type_data| {
                view.expand_for_with_size(
                    type_data,
                    storage,
                    scalar.as_ref().ok().map(|value| value.0),
                    byte_size,
                )
            });
            let indexed_variables = match expansion.as_ref() {
                Some(Expand::Elements { count, .. }) => Some(*count),
                _ => None,
            };
            let result = match (&type_data, scalar.as_ref(), storage) {
                (Some(type_data), Ok(value), _) => view.scalar_text(value.0, type_data, byte_size),
                (Some(type_data), Err(_), Some(address)) => {
                    let field = FieldInfo {
                        offset: 0,
                        size: byte_size.unwrap_or_default(),
                        type_data: type_data.clone(),
                    };
                    view.value_text(address, &field)
                }
                (Some(_), Err(error), None) => format!("<unavailable: {error}>"),
                (None, Ok(value), _) => format!("{:#x} ({})", value.0, value.0),
                (None, Err(error), _) => return Err(error.to_string()),
            };
            let result = if result.is_empty() {
                match expansion.as_ref() {
                    Some(Expand::Fields { .. }) => "{...}".to_string(),
                    Some(Expand::Elements { count, .. }) => format!("[{count}]"),
                    None => result,
                }
            } else {
                result
            };
            let memory_reference = storage.or_else(|| {
                (!register && (type_data.is_none() || pointer_value))
                    .then(|| scalar.as_ref().ok().copied())
                    .flatten()
            });
            (
                result,
                type_data.map(|type_data| type_data.to_string()),
                memory_reference,
                expansion,
                indexed_variables,
            )
        };
        let reference = expansion
            .map(|expansion| self.var_ref(VarRef::from(expansion)))
            .unwrap_or(0);
        let mut response = json!({
            "result": result,
            "variablesReference": reference,
        });
        if let Some(type_name) = type_name {
            response["type"] = json!(type_name);
        }
        if let Some(memory_reference) = memory_reference {
            response["memoryReference"] = json!(format!("{:#x}", memory_reference.0));
        }
        if let Some(indexed_variables) = indexed_variables {
            response["indexedVariables"] = json!(indexed_variables);
        }
        Ok(Some(response))
    }

    /// Parse and evaluate one expression against the selected frame.  Keeping
    /// the parsed tree alongside the value lets DAP distinguish a raw register
    /// from a typed value when resolving data-breakpoint storage.
    fn parse_and_evaluate(
        &mut self,
        expression: &str,
    ) -> result::Result<(Expr, ExprValue), String> {
        let radix = self.repl_radix();
        let expr = Expr::parse_with_radix(expression, radix).map_err(|error| error.to_string())?;
        let session = self.session()?;
        let value = expr
            .evaluate(&session.target)
            .map_err(|error| error.to_string())?;
        Ok((expr, value))
    }

    fn evaluate_expression(&mut self, expression: &str) -> result::Result<u64, String> {
        let radix = self.repl_radix();
        let session = self.session()?;
        Expr::eval_with_radix(expression, &session.target, radix)
            .map(|address| address.0)
            .map_err(|error| error.to_string())
    }

    fn repl_radix(&mut self) -> NumberRadix {
        self.repl
            .as_ref()
            .map(ReplStore::radix)
            .unwrap_or(NumberRadix::Hexadecimal)
    }

    /// What the console can repoint underneath the client: the selected
    /// Windows thread, the address space, and the backend vCPU. `.thread`,
    /// `.process` and `.cxr` all move one of these.
    fn inspection_context(&mut self) -> (Option<u64>, u64, String) {
        let Some(session) = self.session.as_mut() else {
            return (None, 0, String::new());
        };
        (
            session
                .parked_windows_thread()
                .map(|thread| thread.ethread.0),
            session.target.current_dtb(),
            session.current_thread.clone(),
        )
    }

    /// Tell the client its frames and variables are stale after a console
    /// command moved the inspection context. Frame ids and variable references
    /// belong to the context they were built in, so they are dropped here too.
    fn invalidate_context(&mut self) {
        self.invalidate_stop_state();
        if self.supports_invalidated {
            self.send_event(
                "invalidated",
                json!({"areas": ["stacks", "variables", "registers"]}),
            );
            return;
        }
        self.emit_output(
            "console",
            "ntoseye: inspection context changed; this client does not support the invalidated \
             event, so the call stack and variables panes refresh at the next stop\n",
        );
    }

    /// Run one REPL command line for the Debug Console. Run-control commands
    /// are refused by [`DispatchContext::Remote`]; the client's step/continue
    /// buttons own the target.
    fn run_console_command(&mut self, line: &str) -> result::Result<String, String> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| "no target is attached".to_string())?;
        let store = self
            .repl
            .take()
            .unwrap_or_else(|| ReplStore::new(session, DispatchContext::Remote(RemoteClient::Dap)));
        let mut state = ReplState::attach(session, store);
        state.line = line.trim().to_string();
        let (result, text) = output::capture(|| state.dispatch_line(line));
        self.repl = Some(state.detach());
        match result {
            Ok(Flow::Continue | Flow::Quit) => Ok(text),
            Ok(Flow::Denied) => Err(if text.is_empty() {
                "the debug console cannot move the target; use the client's run controls"
                    .to_string()
            } else {
                text
            }),
            Err(error) => Err(if text.is_empty() {
                error.to_string()
            } else {
                format!("{text}{error}")
            }),
        }
    }

    fn on_set_breakpoints(&mut self, args: &Value) -> Handled {
        let source = args.get("source").cloned().unwrap_or_else(|| json!({}));
        let key = arg_str(&source, "path")
            .or_else(|| arg_str(&source, "name"))
            .ok_or_else(|| "source breakpoints need a path or name".to_string())?;
        let requested = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let lines: Vec<Option<i64>> = requested
            .iter()
            .map(|entry| arg_i64(entry, "line"))
            .collect();
        let plan = requested
            .iter()
            .zip(&lines)
            .map(|(entry, line)| {
                let line = line.ok_or_else(|| "breakpoint without a line".to_string())?;
                let config = breakpoint_config(entry)?;
                let spec = self.source_spec(&key, self.to_source_line(line));
                Ok(Install::Source(spec, config))
            })
            .collect();
        let previous: Vec<u32> = self
            .source_breakpoints
            .get(&key)
            .into_iter()
            .flatten()
            .flatten()
            .copied()
            .collect();
        let results = self.install_breakpoints(previous, plan)?;
        self.source_breakpoints.remove(&key);
        let mut installed = Vec::with_capacity(results.len());
        let mut response = Vec::with_capacity(results.len());
        for (result, line) in results.into_iter().zip(lines) {
            match result {
                Ok(ids) => {
                    response.push(self.breakpoint_value(&ids, line));
                    installed.push(ids);
                }
                Err(message) => response.push(refused_breakpoint(message, line)),
            }
        }
        self.source_breakpoints.insert(key, installed);
        Ok(Some(json!({"breakpoints": response})))
    }

    /// Choose the `file:line` identity ntoseye should resolve. The client's
    /// absolute path is tried first (it matches when `.srcpath` maps the PDB
    /// path onto it); otherwise the basename, which matches any recorded file
    /// with that name.
    fn source_spec(&mut self, path: &str, line: u32) -> String {
        let matched_full = self
            .session
            .as_ref()
            .is_some_and(|session| !session.target.source_addresses(path, line).is_empty());
        if matched_full {
            return format!("{path}:{line}");
        }
        let base = file_stem_of(path);
        format!("{base}:{line}")
    }

    fn on_set_function_breakpoints(&mut self, args: &Value) -> Handled {
        let requested = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let plan = requested
            .iter()
            .map(|entry| {
                let name = arg_str(entry, "name")
                    .ok_or_else(|| "breakpoint without a name".to_string())?;
                // Skip the prologue so arguments occupy their PDB locations.
                // Console `bu` still breaks at the symbol address.
                let config = BreakpointConfig {
                    skip_prologue: true,
                    ..breakpoint_config(entry)?
                };
                Ok(Install::Symbol(name, config))
            })
            .collect();
        self.replace_owned_set(OwnedSet::Function, plan)
    }

    fn on_set_instruction_breakpoints(&mut self, args: &Value) -> Handled {
        let requested = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let plan = requested
            .iter()
            .map(|entry| {
                let address = arg_str(entry, "instructionReference")
                    .ok_or_else(|| "breakpoint without an instructionReference".to_string())
                    .and_then(|reference| parse_address(&reference))?
                    .wrapping_add_signed(arg_i64(entry, "offset").unwrap_or(0));
                let config = breakpoint_config(entry)?;
                Ok(Install::Address(address, config))
            })
            .collect();
        self.replace_owned_set(OwnedSet::Instruction, plan)
    }

    fn on_data_breakpoint_info(&mut self, args: &Value) -> Handled {
        let name = arg_str(args, "name").ok_or_else(|| "missing name".to_string())?;
        let watchpoints = {
            let session = self.session()?;
            let capabilities = session.capabilities();
            supports_capability(&capabilities, DebugCapability::Watchpoints)
        };
        if !watchpoints {
            return Ok(Some(json!({
                "dataId": Value::Null,
                "description": "this backend does not support data watchpoints",
            })));
        }

        // A free-form `name` is evaluated in the frame the client names, the
        // way `evaluate` does: a local in an outer frame otherwise resolves
        // against whichever frame happens to be selected.
        self.select_named_frame(args, "frameId")?;
        // From the variables view the client passes the owning scope; anything
        // else is treated as an expression naming an address.
        let resolved = match arg_i64(args, "variablesReference") {
            Some(reference) if reference >= VARIABLES_BASE => self.data_target(reference, &name),
            _ => self.data_expression_target(&name),
        };
        let (address, size) = match resolved {
            Ok(resolved) => resolved,
            Err(message) => {
                return Ok(Some(json!({
                    "dataId": Value::Null,
                    "description": message,
                })));
            }
        };
        let len = watch_length(size);
        if let Err(error) = validate_hw_breakpoint(WatchpointAccess::Write.into(), len, address) {
            return Ok(Some(json!({
                "dataId": Value::Null,
                "description": error.to_string(),
            })));
        }
        Ok(Some(json!({
            "dataId": format!("{address:#x}:{len}"),
            "description": format!("{len} byte(s) at {address:#x}"),
            "accessTypes": ["write", "readWrite"],
            "canPersist": false,
        })))
    }

    /// Resolve a free-form watch expression once through the typed evaluator.
    /// Typed memory values watch their storage; raw address/u64 expressions
    /// retain the old numeric-address behavior. Registers and non-pointer
    /// typed immediate values are rejected because neither has writable
    /// storage.
    fn data_expression_target(&mut self, expression: &str) -> result::Result<(u64, usize), String> {
        let (expr, value) = self.parse_and_evaluate(expression)?;
        let session = self.session()?;
        match value.address() {
            Ok(address) => expression_watch_size(&value, session).map(|size| (address.0, size)),
            Err(_error) if direct_register_expression(&expr, &session.target) => {
                Err("registers cannot be watched; watch the memory they point at".to_string())
            }
            // A typed pointer rvalue has no storage address of its own, but
            // its scalar is an explicit pointee address a client can watch.
            Err(error) => match value.type_data() {
                Some(ParsedType::Pointer(pointee)) => {
                    let size = TypeView::new(session).parsed_type_size(pointee);
                    if size == 0 {
                        return Err("typed pointer has unknown pointee size".to_string());
                    }
                    value
                        .scalar(&session.target)
                        .map(|address| (address.0, size))
                        .map_err(|error| error.to_string())
                }
                Some(_) => Err(error.to_string()),
                None => {
                    let address = value
                        .scalar(&session.target)
                        .map_err(|error| error.to_string())?;
                    let size = expression_watch_size(&value, session)?;
                    Ok((address.0, size))
                }
            },
        }
    }

    /// Resolve the storage address and width to watch from the variable the
    /// client asked about. Register-held values and bitfields intentionally
    /// have no independently watchable address.
    fn data_target(&mut self, reference: i64, name: &str) -> result::Result<(u64, usize), String> {
        let index = self.var_index(reference)?;
        match self.vars[index].clone() {
            VarRef::Locals(handle) => {
                self.select_frame(handle)?;
                // The explicit local namespace avoids accidentally selecting
                // a same-named module symbol when a scope row is watched.
                let expression = Expr::Local(name.to_string());
                let session = self.session()?;
                let value = expression
                    .evaluate(&session.target)
                    .map_err(|error| error.to_string())?;
                let address = value.address().map_err(|error| error.to_string())?;
                let size = expression_watch_size(&value, session)?;
                Ok((address.0, size))
            }
            VarRef::Registers(_) => {
                Err("registers cannot be watched; watch the memory they point at".into())
            }
            VarRef::Fields { type_name, address } => {
                let field_name = {
                    let session = self.session()?;
                    let view = TypeView::new(session);
                    let type_info = view.lookup_type(&type_name).ok_or_else(|| {
                        format!("type '{type_name}' is not in the loaded symbols")
                    })?;
                    find_field(type_info.as_ref(), name)
                        .map(|(field_name, _)| field_name.clone())
                        .ok_or_else(|| format!("no field named '{name}' in {type_name}"))?
                };
                let expression = Expr::FieldAccess(
                    Box::new(Expr::Cast(
                        Box::new(Expr::Literal(address)),
                        ExprType::Pointer(Box::new(ExprType::Struct(type_name))),
                    )),
                    field_name,
                );
                self.data_value_target(&expression)
            }
            VarRef::Elements {
                count,
                element_size,
                address,
                element: element_type,
                ..
            } => {
                let index = element_index(name)?;
                if index >= count {
                    Err(format!(
                        "element {index} is past the end of a [{count}] array"
                    ))
                } else if matches!(&element_type, ParsedType::Bitfield { .. }) {
                    Err("bitfields have no independently addressable storage".to_string())
                } else if element_size == 0 {
                    Err("array element has no storage size".to_string())
                } else {
                    let offset = u64::from(index) * element_size as u64;
                    Ok((address.0.wrapping_add(offset), element_size))
                }
            }
        }
    }

    /// Resolve typed storage and width; reject registers, bitfields, and immediates.
    fn data_value_target(&mut self, expression: &Expr) -> result::Result<(u64, usize), String> {
        let value = {
            let session = self.session()?;
            expression
                .evaluate(&session.target)
                .map_err(|error| error.to_string())?
        };
        let session = self.session()?;
        let address = value.address().map_err(|error| error.to_string())?;
        let size = expression_watch_size(&value, session)?;
        Ok((address.0, size))
    }

    fn on_set_data_breakpoints(&mut self, args: &Value) -> Handled {
        let requested = args
            .get("breakpoints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let plan = requested
            .iter()
            .map(|entry| {
                let (address, len) = arg_str(entry, "dataId")
                    .ok_or_else(|| "breakpoint without a dataId".to_string())
                    .and_then(|id| parse_data_id(&id))?;
                let access = match arg_str(entry, "accessType").as_deref() {
                    Some("read") | Some("readWrite") => WatchpointAccess::ReadWrite,
                    _ => WatchpointAccess::Write,
                };
                let config = breakpoint_config(entry)?;
                Ok(Install::Watch {
                    address,
                    access,
                    len,
                    config,
                })
            })
            .collect();
        self.replace_owned_set(OwnedSet::Data, plan)
    }

    fn owned_set(&mut self, set: OwnedSet) -> &mut Vec<u32> {
        match set {
            OwnedSet::Function => &mut self.function_breakpoints,
            OwnedSet::Instruction => &mut self.instruction_breakpoints,
            OwnedSet::Data => &mut self.data_breakpoints,
        }
    }

    /// Answer a `set*Breakpoints` request for a set without source lines.
    fn replace_owned_set(
        &mut self,
        set: OwnedSet,
        plan: Vec<result::Result<Install, String>>,
    ) -> Handled {
        let previous = self.owned_set(set).clone();
        let results = self.install_breakpoints(previous, plan)?;
        self.owned_set(set).clear();
        let mut response = Vec::with_capacity(results.len());
        for result in results {
            match result {
                Ok(ids) => {
                    response.push(self.breakpoint_value(&ids, None));
                    self.owned_set(set).extend(ids);
                }
                Err(message) => response.push(refused_breakpoint(message, None)),
            }
        }
        Ok(Some(json!({"breakpoints": response})))
    }

    /// Replace one client-owned breakpoint set in a single halt/resume round
    /// trip: remove what the client last sent, install what it sends now.
    /// Results align with `plan`; a slot refused before the target was
    /// touched passes through.
    ///
    /// `Err` means the target could not be halted and nothing changed. A
    /// failure to resume afterwards is reported to the console instead: the
    /// edits stand, and the next service tick surfaces the halt.
    fn install_breakpoints(
        &mut self,
        remove: Vec<u32>,
        mut plan: Vec<result::Result<Install, String>>,
    ) -> result::Result<Vec<result::Result<Vec<u32>, String>>, String> {
        let session = self.session()?;
        let mut results = Vec::with_capacity(plan.len());
        let mut edited = false;
        let outcome = session.with_target_halted(|session| {
            edited = true;
            for id in &remove {
                let _ = session.remove_breakpoint(*id);
            }
            results.extend(plan.drain(..).map(|slot| {
                slot.and_then(|install| install.apply(session).map_err(|error| error.to_string()))
            }));
            Ok(())
        });
        match outcome {
            Ok(()) => {}
            Err(error) if !edited => {
                return Err(format!(
                    "breakpoints unchanged; the target could not be halted: {error}"
                ));
            }
            Err(error) => self.emit_output(
                "important",
                format!("ntoseye: breakpoints changed but the target did not resume: {error}\n"),
            ),
        }
        for id in &remove {
            self.verified.remove(id);
        }
        Ok(results)
    }

    /// Report one installed breakpoint: verified once an address is resolved,
    /// unverified (with the reason) while it stays deferred.
    fn breakpoint_value(&mut self, ids: &[u32], line: Option<i64>) -> Value {
        let Some(session) = self.session.as_ref() else {
            return json!({"verified": false, "message": "no target attached"});
        };
        let first = ids.first().and_then(|id| session.breakpoint(*id));
        // One client breakpoint can install several ids (a source line with
        // more than one address). `reconcile_breakpoints` walks all of them, so
        // all of them have to be seeded here or the ids the client never saw
        // each report a spurious change at the next stop.
        let states: Vec<(u32, BreakpointState)> = ids
            .iter()
            .filter_map(|id| {
                session
                    .breakpoint(*id)
                    .map(|breakpoint| (*id, BreakpointState::from(breakpoint)))
            })
            .collect();
        for (id, state) in states {
            self.verified.insert(id, state);
        }
        let mut value = match first {
            Some(breakpoint) => breakpoint_json(breakpoint, ids.len()),
            None => json!({"verified": false, "message": "breakpoint was not installed"}),
        };
        if let Some(line) = line {
            value["line"] = json!(line);
        }
        value
    }

    /// Accept an empty filter list; reject unsupported exception filters.
    fn on_set_exception_breakpoints(args: &Value) -> Handled {
        for field in ["filters", "filterOptions", "exceptionOptions"] {
            let requested = args
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(|entries| !entries.is_empty());
            if requested {
                return Err(format!(
                    "exception breakpoints are not supported; '{field}' cannot be honored. \
                     Use the REPL's `sx` commands for exception policy"
                ));
            }
        }
        Ok(Some(json!({"breakpoints": []})))
    }

    fn on_exception_info(&mut self) -> Handled {
        let Some(stop) = self.last_stop.as_ref() else {
            return Err("no stop has been reported yet".to_string());
        };
        let Some(exception_id) = stop.exception_id.clone() else {
            return Err("the last stop was not an exception".to_string());
        };
        let description = stop.description.clone();
        let detail = stop.detail.clone().unwrap_or_else(|| description.clone());
        Ok(Some(json!({
            "exceptionId": exception_id,
            "description": description,
            "breakMode": "always",
            "details": {"message": detail},
        })))
    }

    fn on_read_memory(&mut self, args: &Value) -> Handled {
        let reference = arg_str(args, "memoryReference")
            .ok_or_else(|| "missing memoryReference".to_string())?;
        let base = parse_address(&reference)?;
        let offset = arg_i64(args, "offset").unwrap_or(0);
        let address = base.wrapping_add_signed(offset);
        let count = arg_i64(args, "count").unwrap_or(0).max(0) as usize;
        let count = count.min(MAX_READ_MEMORY);
        if count == 0 {
            return Ok(Some(
                json!({"address": format!("{address:#x}"), "data": ""}),
            ));
        }

        let session = self.session()?;
        let mut buffer = vec![0u8; count];
        let read = match session.read_masked(VirtAddr(address), &mut buffer) {
            Ok(()) => count,
            Err(_) => partial_read(session, address, &mut buffer),
        };
        buffer.truncate(read);
        let mut body = json!({
            "address": format!("{address:#x}"),
            "data": BASE64.encode(&buffer),
        });
        if read < count {
            body["unreadableBytes"] = json!((count - read) as i64);
        }
        Ok(Some(body))
    }

    fn on_write_memory(&mut self, args: &Value) -> Handled {
        let reference = arg_str(args, "memoryReference")
            .ok_or_else(|| "missing memoryReference".to_string())?;
        let base = parse_address(&reference)?;
        let offset = arg_i64(args, "offset").unwrap_or(0);
        let address = base.wrapping_add_signed(offset);
        let data = arg_str(args, "data").ok_or_else(|| "missing data".to_string())?;
        let bytes = BASE64
            .decode(data.as_bytes())
            .map_err(|error| format!("invalid base64 payload: {error}"))?;
        if bytes.is_empty() {
            return Ok(Some(json!({"bytesWritten": 0})));
        }
        let allow_partial = arg_bool(args, "allowPartial").unwrap_or(false);
        let session = self.session()?;
        let written = session
            .target
            .current_process()
            .map_err(|error| error.to_string())?
            .memory()
            .write_bytes(VirtAddr(address), &bytes);
        let written = match written {
            Ok(()) => bytes.len(),
            // The write ran into an untranslatable page after committing a
            // prefix. The client decides whether that prefix stands.
            Err(Error::PartialWrite(committed)) if allow_partial => committed,
            Err(error) => return Err(error.to_string()),
        };
        Ok(Some(json!({"bytesWritten": written as i64})))
    }

    fn on_disassemble(&mut self, args: &Value) -> Handled {
        let reference = arg_str(args, "memoryReference")
            .ok_or_else(|| "missing memoryReference".to_string())?;
        let base = parse_address(&reference)?;
        let offset = arg_i64(args, "offset").unwrap_or(0);
        let address = base.wrapping_add_signed(offset);
        let instruction_offset = arg_i64(args, "instructionOffset").unwrap_or(0);
        let count = (arg_i64(args, "instructionCount").unwrap_or(0).max(0) as usize)
            .min(MAX_DISASSEMBLE_INSTRUCTIONS);
        if count == 0 {
            return Ok(Some(json!({"instructions": []})));
        }

        // Row `i` is instruction `instructionOffset + i` from the reference.
        // A client records the reference's address positionally and derives
        // instruction-breakpoint offsets from it, so a hole is an invalid
        // row, never a shifted one.
        let mut rows: Vec<Option<DisassembledRow>> = Vec::with_capacity(count);
        // Negative offsets ask for the instructions *before* the reference, so
        // decode backwards into the gap first; a short decode leaves its hole
        // at the far end.
        let backwards = usize::try_from(instruction_offset.min(0).saturating_neg())
            .unwrap_or(0)
            .min(MAX_DISASSEMBLE_INSTRUCTIONS);
        if backwards > 0 {
            let preceding = self.disassemble_preceding(address, backwards)?;
            rows.resize_with(backwards.saturating_sub(preceding.len()), || None);
            rows.extend(preceding.into_iter().map(Some));
        }
        let forward_start = if instruction_offset > 0 {
            // Skip forward by decoding and dropping instructions.
            let skip = (instruction_offset as usize).min(MAX_DISASSEMBLE_INSTRUCTIONS);
            let session = self.session()?;
            match session.disassemble(VirtAddr(address), skip + 1) {
                Ok(decoded) => decoded.get(skip).map(|row| row.ip).unwrap_or(address),
                Err(_) => address,
            }
        } else {
            address
        };
        let remaining = count.saturating_sub(rows.len());
        if remaining > 0 {
            let session = self.session()?;
            match session.disassemble(VirtAddr(forward_start), remaining) {
                Ok(decoded) => rows.extend(decoded.into_iter().map(|row| {
                    Some(DisassembledRow {
                        address: row.ip,
                        bytes: Some(row.hex.clone()),
                        text: row.asm(),
                    })
                })),
                Err(error) => rows.push(Some(DisassembledRow {
                    address: forward_start,
                    bytes: None,
                    text: format!("<{error}>"),
                })),
            }
        }

        // The protocol requires exactly `instructionCount` entries.
        rows.resize_with(count, || None);
        let instructions = self.disassembly_values(rows);
        Ok(Some(json!({"instructions": instructions})))
    }

    fn disassemble_preceding(
        &mut self,
        address: u64,
        count: usize,
    ) -> result::Result<Vec<DisassembledRow>, String> {
        let session = self.session()?;
        let arch = session.target.arch();
        let window = count.saturating_mul(max_instruction_bytes(arch));
        let start = address.saturating_sub(window as u64);
        let mut bytes = vec![0u8; (address - start) as usize];
        if bytes.is_empty() || session.read_masked(VirtAddr(start), &mut bytes).is_err() {
            return Ok(Vec::new());
        }
        let rows = decode_preceding(arch, &bytes, start, address, count, |target| {
            format!("{target:#x}")
        });
        Ok(rows
            .unwrap_or_default()
            .into_iter()
            .map(|row| DisassembledRow {
                address: row.ip,
                bytes: Some(row.hex.clone()),
                text: row.asm(),
            })
            .collect())
    }

    /// A `None` row is the invalid-instruction value. Its address is `-1`,
    /// which no instruction has, so a client keying rows by address (VS Code
    /// sorts and merges on it) drops it rather than filing it under 0.
    fn disassembly_values(&mut self, rows: Vec<Option<DisassembledRow>>) -> Vec<Value> {
        let mut instructions = Vec::with_capacity(rows.len());
        for row in rows {
            let Some(row) = row else {
                instructions.push(json!({
                    "address": "-1",
                    "instruction": "(unreadable)",
                    "presentationHint": "invalid",
                }));
                continue;
            };
            let symbol = self.session.as_ref().and_then(|session| {
                session
                    .target
                    .closest_symbol_current_context(VirtAddr(row.address))
            });
            let location = self
                .session
                .as_ref()
                .and_then(|session| session.target.source_location(VirtAddr(row.address)));
            let mut value = json!({
                "address": format!("{:#x}", row.address),
                "instruction": row.text,
            });
            if let Some(bytes) = row.bytes {
                value["instructionBytes"] = json!(bytes);
            }
            if let Some(symbol) = symbol {
                value["symbol"] = json!(symbol);
            }
            if let Some(location) = &location {
                value["location"] = source_value(location);
                value["line"] = json!(self.to_client_line(location.line as i64));
            }
            instructions.push(value);
        }
        instructions
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

/// A decoded instruction on its way to a `disassemble` response.
struct DisassembledRow {
    address: u64,
    bytes: Option<String>,
    text: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepMode {
    Over,
    Into,
    Out,
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
    spec.validate()?;
    Ok(spec)
}

/// Translate a DAP breakpoint's condition and hit condition into ntoseye's
/// breakpoint configuration. `hitCondition` is a plain pass count, matching
/// WinDbg's `bp <target> <passes>`.
fn breakpoint_config(entry: &Value) -> result::Result<BreakpointConfig, String> {
    let pass_count = match arg_str(entry, "hitCondition") {
        Some(text) => {
            let trimmed = text.trim();
            trimmed
                .parse::<u64>()
                .map_err(|_| format!("hit condition '{trimmed}' must be a decimal pass count"))?
        }
        None => 0,
    };
    Ok(BreakpointConfig {
        condition: arg_str(entry, "condition").filter(|text| !text.trim().is_empty()),
        pass_count,
        action: match arg_str(entry, "logMessage") {
            Some(message) => Some(log_point_action(&message)?),
            None => None,
        },
        ..BreakpointConfig::default()
    })
}

/// One breakpoint a `set*Breakpoints` request asks for, resolved as far as
/// possible before the target is halted for the batch.
enum Install {
    /// `bu file:line`; may resolve to several addresses.
    Source(String, BreakpointConfig),
    /// `bu symbol`, deferred until its module loads.
    Symbol(String, BreakpointConfig),
    /// `bp address` out of the disassembly view, with no symbol to re-resolve.
    Address(u64, BreakpointConfig),
    /// `ba` on storage a `dataId` already resolved, with no symbol to defer on.
    Watch {
        address: u64,
        access: WatchpointAccess,
        len: u8,
        config: BreakpointConfig,
    },
}

impl Install {
    fn apply(self, session: &mut Session) -> Result<Vec<u32>> {
        match self {
            Self::Source(spec, config) => session.add_source_breakpoint_with(spec, config),
            Self::Symbol(name, config) => session
                .add_symbol_breakpoint_with(name, config)
                .map(|id| vec![id]),
            Self::Address(address, config) => session
                .add_breakpoint_with(VirtAddr(address), None, config)
                .map(|id| vec![id]),
            Self::Watch {
                address,
                access,
                len,
                config,
            } => session
                .add_watchpoint_with(VirtAddr(address), access, len, None, config)
                .map(|id| vec![id]),
        }
    }
}

/// A breakpoint set the client replaces wholesale with one request.
#[derive(Clone, Copy)]
enum OwnedSet {
    Function,
    Instruction,
    Data,
}

/// A breakpoint row the request refused, with the client's line when it had one.
fn refused_breakpoint(message: String, line: Option<i64>) -> Value {
    let mut row = json!({"verified": false, "message": message});
    if let Some(line) = line {
        row["line"] = json!(line);
    }
    row
}

/// Compile log placeholders into a `.printf` action followed by `gc`.
fn log_point_action(message: &str) -> result::Result<String, String> {
    let mut format = String::new();
    let mut arguments: Vec<String> = Vec::new();
    let mut rest = message;
    while let Some(open) = rest.find('{') {
        format.push_str(&escape_printf(&rest[..open]));
        let tail = &rest[open + 1..];
        let close = tail
            .find('}')
            .ok_or_else(|| format!("log message has an unclosed '{{': {message}"))?;
        // `.printf` takes its arguments as whitespace-separated tokens, so an
        // expression cannot carry spaces. Removing them is safe: ntoseye
        // expressions never contain a significant space.
        let expression: String = tail[..close]
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if expression.is_empty() {
            return Err(format!("log message has an empty '{{}}': {message}"));
        }
        // Guard the command grammar: an expression carrying a quote or a
        // semicolon would end the action early.
        if expression.contains(['"', ';']) {
            return Err(format!(
                "log message expression '{expression}' cannot contain a quote or a semicolon"
            ));
        }
        format.push_str("%p");
        arguments.push(expression);
        rest = &tail[close + 1..];
    }
    format.push_str(&escape_printf(rest));
    // `.printf` arguments are whitespace-separated, not comma-separated, and
    // the console already terminates the line, so no trailing newline escape.
    let mut action = format!("\"{format}\"");
    for argument in arguments {
        action.push(' ');
        action.push_str(&argument);
    }
    Ok(format!(".printf {action}; gc"))
}

/// Escape the literal parts of a log message for `.printf`: the quote that
/// would end the format string, the backslash that introduces an escape, and
/// the `%` that would start a specifier.
fn escape_printf(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
}

/// What the client was last told about a breakpoint, for change detection.
#[derive(Clone, Copy, PartialEq, Eq)]
struct BreakpointState {
    resolved: bool,
    address: VirtAddr,
}

impl From<&Breakpoint> for BreakpointState {
    fn from(breakpoint: &Breakpoint) -> Self {
        Self {
            resolved: breakpoint.resolved,
            address: breakpoint.address,
        }
    }
}

fn breakpoint_json(breakpoint: &Breakpoint, matches: usize) -> Value {
    let mut value = json!({
        "id": breakpoint.id as i64,
        "verified": breakpoint.resolved,
    });
    if breakpoint.resolved {
        value["instructionReference"] = json!(format!("{:#x}", breakpoint.address.0));
    }
    let mut notes = Vec::new();
    if breakpoint.deferred() {
        notes.push(format!(
            "deferred: '{}' is not resolvable yet (it will arm when its module loads)",
            breakpoint.specification().unwrap_or("symbol")
        ));
    }
    if matches > 1 {
        notes.push(format!("{matches} addresses matched"));
    }
    if !notes.is_empty() {
        value["message"] = json!(notes.join("; "));
    }
    value
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

/// Render a local's value, or the reason it has none. A caller frame keeps
/// only the registers unwind metadata justifies, so "unavailable" is a real
/// answer rather than a failure.
fn local_value_text(local: &ProcedureLocal, value: Option<u64>, expand: Option<&Expand>) -> String {
    if let Some(value) = value {
        return match local.byte_size {
            Some(size) if size <= 8 => format!("{value:#x} ({value})"),
            _ => format!("{value:#x}"),
        };
    }
    // An aggregate has no scalar value to be missing, so it is not unavailable:
    // the caller labels it by what expanding it yields.
    if expand.is_some() {
        return String::new();
    }
    match &local.location {
        LocalVariableLocation::Unavailable { reason } => format!("<unavailable: {reason}>"),
        LocalVariableLocation::Register { register } => {
            format!("<in {register}, unavailable in this context>")
        }
        location => format!("<at {}, unreadable>", location.describe()),
    }
}

/// Whether an expression names an actual CPU register directly.  Result slots,
/// convenience variables, and builtins also use the sigiled AST form but are
/// numeric address/u64 values and remain usable as memory references.
fn direct_register_expression(expr: &Expr, target: &Target) -> bool {
    match expr {
        Expr::Register(name) => target.register_value(name).is_some(),
        Expr::Symbol(name) => {
            target
                .symbols
                .find_symbol_across_modules(target.current_dtb(), name)
                .ok()
                .flatten()
                .is_none()
                && target.register_value(name).is_some()
        }
        _ => false,
    }
}

/// Use the declared width or loaded layout. Untyped addresses default to eight bytes.
fn expression_watch_size(value: &ExprValue, session: &Session) -> result::Result<usize, String> {
    if let Some(size) = value
        .byte_size()
        .and_then(|size| usize::try_from(size).ok())
        .filter(|size| *size != 0)
    {
        return Ok(size);
    }
    if let Some(type_data) = value.type_data() {
        let size = TypeView::new(session).parsed_type_size(type_data);
        if size != 0 {
            return Ok(size);
        }
        return Err(format!(
            "typed value '{type_data}' has unknown storage size"
        ));
    }
    Ok(8)
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

/// Read as much of `buffer` as the guest will give us, one page-sized chunk at
/// a time, and report how many leading bytes are valid. Chunks are relative to
/// `address`, so an unmapped page truncates the read at the request's own
/// granularity rather than at a page boundary.
fn partial_read(session: &Session, address: u64, buffer: &mut [u8]) -> usize {
    const CHUNK: usize = 0x1000;
    let mut read = 0;
    while read < buffer.len() {
        let end = (read + CHUNK).min(buffer.len());
        let chunk_address = VirtAddr(address.wrapping_add(read as u64));
        if session
            .read_masked(chunk_address, &mut buffer[read..end])
            .is_err()
        {
            break;
        }
        read = end;
    }
    read
}

/// Round a variable's size down to a legal debug-register watch width.
fn watch_length(size: usize) -> u8 {
    match size {
        0 | 1 => 1,
        2 | 3 => 2,
        4..=7 => 4,
        _ => 8,
    }
}

/// The index in an array child's name (`[3]`), which is how a client names an
/// element back to the adapter.
fn element_index(name: &str) -> result::Result<u32, String> {
    name.trim()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|index| index.parse().ok())
        .ok_or_else(|| format!("'{name}' is not an array element"))
}

fn parse_data_id(id: &str) -> result::Result<(u64, u8), String> {
    let (address, len) = id
        .split_once(':')
        .ok_or_else(|| format!("malformed dataId '{id}'"))?;
    let address = parse_address(address)?;
    let len = len
        .parse::<u8>()
        .map_err(|_| format!("malformed dataId '{id}'"))?;
    Ok((address, len))
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
mod tests {
    use super::*;
    use crate::session::session_over_memory;
    use crate::symbols::TypeInfo;

    #[test]
    fn a_disassembly_request_cannot_ask_for_unbounded_work() {
        let session = session_over_memory(0x1000, &[0x90u8; 0x40]);
        let (_tx, rx) = mpsc::channel();
        let (mut server, _sink) = server_with_sink(Some(session), rx);

        let answer = server
            .on_disassemble(&json!({
                "memoryReference": "0x1000",
                "instructionCount": i64::MAX,
                "instructionOffset": i64::MIN,
            }))
            .expect("the request is answered, not refused")
            .expect("a body is returned");

        let instructions = answer["instructions"].as_array().expect("instructions");
        assert_eq!(instructions.len(), MAX_DISASSEMBLE_INSTRUCTIONS);
    }

    #[test]
    fn a_short_backward_decode_keeps_the_reference_at_its_offset() {
        // Nothing is mapped below 0x1000, so the eight instructions before
        // the reference cannot be decoded. The client takes the reference's
        // address from row `-instructionOffset`, so the hole goes in front.
        let session = session_over_memory(0x1000, &[0x90u8; 0x1000]);
        let (_tx, rx) = mpsc::channel();
        let (mut server, _sink) = server_with_sink(Some(session), rx);

        let answer = server
            .on_disassemble(&json!({
                "memoryReference": "0x1000",
                "instructionOffset": -8,
                "instructionCount": 16,
            }))
            .unwrap()
            .unwrap();

        let instructions = answer["instructions"].as_array().unwrap();
        assert_eq!(instructions.len(), 16);
        for row in &instructions[..8] {
            assert_eq!(row["address"], "-1", "{row}");
            assert_eq!(row["presentationHint"], "invalid");
        }
        assert_eq!(instructions[8]["address"], "0x1000");
        assert_eq!(instructions[9]["address"], "0x1001");
    }

    #[test]
    fn a_cancelled_run_that_left_the_target_halted_is_a_pause_stop() {
        // `run_to` halts the target to lift its temporary breakpoint before
        // reporting `Running` for a cancelled step; that halt is the stop the
        // client's `pause` asked for.
        let session = session_over_memory(0x1000, &[0x90u8; 0x40]);
        let (_tx, rx) = mpsc::channel();
        let (mut server, sink) = server_with_sink(Some(session), rx);
        server.state = RunState::Running;

        server.report_stop(ContinueOutcome::Running);

        assert!(matches!(server.state, RunState::Halted));
        let messages = decode_sink(&sink);
        let stopped = messages
            .iter()
            .find(|message| message["event"] == "stopped")
            .unwrap_or_else(|| panic!("no stopped event in {messages:?}"));
        assert_eq!(stopped["body"]["reason"], "pause");
    }

    #[test]
    fn terminate_keeps_serving_until_the_client_disconnects() {
        // The client follows `terminated` with its own `disconnect`.
        let session = session_over_memory(0x1000, &[0u8; 0x40]);
        let messages = serve_script_with(
            Some(session),
            &[
                request(1, "terminate"),
                request(2, "threads"),
                request(3, "disconnect"),
            ],
        );

        let responses: Vec<&Value> = messages
            .iter()
            .filter(|message| message["type"] == "response")
            .collect();
        assert_eq!(responses.len(), 3, "{messages:?}");
        assert_eq!(responses[0]["command"], "terminate");
        assert_eq!(responses[0]["success"], true);
        assert_eq!(responses[1]["command"], "threads");
        assert_eq!(responses[1]["success"], false, "the target was released");
        assert_eq!(responses[2]["command"], "disconnect");
        assert_eq!(
            messages
                .iter()
                .filter(|message| message["event"] == "terminated")
                .count(),
            1,
            "{messages:?}"
        );
    }

    #[test]
    fn one_object_keeps_one_reference_however_often_it_is_asked_for() {
        const COUNT: u32 = 2048;
        let mut memory = vec![0u8; COUNT as usize * 8];
        for index in 0..COUNT as usize {
            // Distinct pointees, so each row names a different guest object.
            memory[index * 8..index * 8 + 8]
                .copy_from_slice(&(0x1000u64 + index as u64 * 8).to_le_bytes());
        }
        let session = session_over_memory(0x1000, &memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session.target.symbols.inject_module_for_test(
            1,
            vec![TypeInfo {
                name: "_NODE".to_string(),
                size: 8,
                fields: HashMap::new(),
            }],
            &[],
        );
        let (_tx, rx) = mpsc::channel();
        let (mut server, _sink) = server_with_sink(Some(session), rx);
        let array = server.var_ref(VarRef::Elements {
            element: ParsedType::Pointer(Box::new(ParsedType::Struct("_NODE".to_string()))),
            count: COUNT,
            element_size: 8,
            address: VirtAddr(0x1000),
        });
        let page = |server: &mut Server| {
            let body = server
                .on_variables(&json!({
                    "variablesReference": array,
                    "filter": "indexed",
                    "start": 0,
                    "count": 64,
                }))
                .unwrap()
                .unwrap();
            body["variables"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["variablesReference"].as_i64().unwrap())
                .collect::<Vec<_>>()
        };

        let first = page(&mut server);
        assert_eq!(first.len(), 64);
        let after_first = server.vars.len();

        // The same 64 rows, asked for four more times.
        for _ in 0..4 {
            assert_eq!(page(&mut server), first, "a row changed reference");
        }
        assert_eq!(
            server.vars.len(),
            after_first,
            "re-reading one window grew the reference table"
        );

        server.invalidate_stop_state();
        assert!(server.vars.is_empty());
    }

    #[test]
    fn addresses_parse_from_hex_and_decimal() {
        assert_eq!(
            parse_address("0xfffff80012345678").unwrap(),
            0xfffff800_12345678
        );
        assert_eq!(parse_address(" 0X10 ").unwrap(), 0x10);
        assert_eq!(parse_address("4096").unwrap(), 4096);
        assert!(parse_address("nt!KeBugCheckEx").is_err());
    }

    #[test]
    fn data_ids_round_trip_through_the_client() {
        let (address, len) = parse_data_id("0x1000:4").unwrap();
        assert_eq!((address, len), (0x1000, 4));
        assert!(parse_data_id("0x1000").is_err());
        assert!(parse_data_id("0x1000:x").is_err());
    }

    #[test]
    fn watch_widths_round_down_to_legal_debug_register_sizes() {
        assert_eq!(watch_length(0), 1);
        assert_eq!(watch_length(3), 2);
        assert_eq!(watch_length(6), 4);
        assert_eq!(watch_length(16), 8);
    }

    #[test]
    fn log_points_become_printf_actions_that_resume() {
        let config = breakpoint_config(&json!({"logMessage": "irp {@rcx} status {@rax}"})).unwrap();
        assert_eq!(
            config.action.as_deref(),
            Some(r#".printf "irp %p status %p" @rcx @rax; gc"#)
        );

        // `.printf` splits its arguments on whitespace, so a spaced expression
        // is closed up rather than tokenized into pieces that cannot evaluate.
        let spaced = breakpoint_config(&json!({"logMessage": "at {poi(@rsp + 0x40)}"})).unwrap();
        assert_eq!(
            spaced.action.as_deref(),
            Some(r#".printf "at %p" poi(@rsp+0x40); gc"#)
        );

        // Literal text only: still a print-and-continue, no arguments.
        let plain = breakpoint_config(&json!({"logMessage": "reached unload"})).unwrap();
        assert_eq!(
            plain.action.as_deref(),
            Some(".printf \"reached unload\"; gc")
        );

        // A `%` in the text is a literal, not a format specifier.
        let percent = breakpoint_config(&json!({"logMessage": "100% done"})).unwrap();
        assert_eq!(
            percent.action.as_deref(),
            Some(".printf \"100%% done\"; gc")
        );

        // A placeholder that would break out of the action's quoting is
        // refused rather than silently changing what runs on each hit.
        for bad in [
            "unclosed {@rcx",
            "empty {}",
            "quote {\"}",
            "chain {@rcx; g}",
        ] {
            assert!(
                breakpoint_config(&json!({"logMessage": bad})).is_err(),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn blank_conditions_are_not_forwarded_as_expressions() {
        let config = breakpoint_config(&json!({"condition": "   "})).unwrap();
        assert!(config.condition.is_none());
    }

    #[test]
    fn source_without_a_local_file_is_not_advertised_as_openable() {
        let location = SourceLocation {
            file: "d:\\src\\driver.c".to_string(),
            line: 42,
            column: None,
            local_path: Some(PathBuf::from("/tmp/nonexistent/driver.c")),
            local_exists: false,
        };
        let value = source_value(&location);
        assert!(value.get("path").is_none());
        assert_eq!(value["name"], json!("driver.c"));
    }

    #[test]
    fn dump_targets_take_precedence_over_live_backend_arguments() {
        let spec = target_spec(&json!({"dump": "/tmp/crash.dmp", "backend": "gdb"})).unwrap();
        assert!(matches!(spec, TargetSpec::Dump(path) if path.ends_with("crash.dmp")));
    }

    /// A `Write` the loop can own while the test keeps reading what it wrote.
    struct Sink(Rc<RefCell<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Run the server loop over a scripted client with no target attached and
    /// return the messages it wrote back, decoded.
    fn serve_script(requests: &[Value]) -> Vec<Value> {
        serve_script_with(None, requests)
    }

    /// Run the server loop over a scripted client and return the messages it
    /// wrote back, decoded, in the order they were written.
    fn serve_script_with(session: Option<Session>, requests: &[Value]) -> Vec<Value> {
        let (tx, rx) = mpsc::channel();
        for request in requests {
            tx.send(ClientMessage::Message(request.clone())).unwrap();
        }
        tx.send(ClientMessage::Eof).unwrap();

        let (mut server, sink) = server_with_sink(session, rx);
        server.serve();
        decode_sink(&sink)
    }

    /// A server writing into a buffer the test can read, for handlers driven
    /// directly instead of through the loop.
    fn server_with_sink(
        session: Option<Session>,
        rx: Receiver<ClientMessage>,
    ) -> (Server, Rc<RefCell<Vec<u8>>>) {
        let sink = Rc::new(RefCell::new(Vec::new()));
        let server = Server::new(
            session,
            Box::new(Sink(Rc::clone(&sink))),
            rx,
            Arc::new(AtomicBool::new(false)),
        );
        (server, sink)
    }

    fn decode_sink(sink: &Rc<RefCell<Vec<u8>>>) -> Vec<Value> {
        let written = sink.borrow().clone();
        let mut input = Cursor::new(written);
        let mut messages = Vec::new();
        while let Some(message) = wire::read_message(&mut input).unwrap() {
            messages.push(message);
        }
        messages
    }

    fn request(seq: i64, command: &str) -> Value {
        json!({"seq": seq, "type": "request", "command": command})
    }

    #[test]
    fn a_termination_signal_releases_the_target_before_the_loop_exits() {
        // The loop must detach before exiting.
        let session = session_over_memory(0x1000, &[0u8; 0x40]);
        let (_tx, rx) = mpsc::channel();
        let (mut server, sink) = server_with_sink(Some(session), rx);
        server.terminating.store(true, Ordering::SeqCst);

        server.serve();

        assert!(server.session.is_none(), "the target was not released");
        let messages = decode_sink(&sink);
        assert!(
            messages.iter().any(|message| {
                message["event"] == "output"
                    && message["body"]["output"]
                        .as_str()
                        .is_some_and(|text| text.contains("detached"))
            }),
            "{messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message["event"] == "terminated"),
            "{messages:?}"
        );
    }

    #[test]
    fn a_console_context_change_invalidates_the_clients_view() {
        // `.thread` in the console repoints the stack and variables; frame ids
        // and variable references from the previous context must die with it.
        let (_tx, rx) = mpsc::channel();
        let (mut server, sink) = server_with_sink(None, rx);
        server.supports_invalidated = true;
        server.frames.push(FrameRef {
            thread: 1,
            index: 0,
            ip: 0x1000,
            sp: 0x2000,
            frame_base: None,
            registers: HashMap::new(),
            seed_registers: HashMap::new(),
        });
        server.vars.push(VarRef::Locals(0));

        server.invalidate_context();

        let messages = decode_sink(&sink);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert_eq!(messages[0]["event"], "invalidated");
        assert_eq!(
            messages[0]["body"]["areas"],
            json!(["stacks", "variables", "registers"])
        );
        assert!(server.frames.is_empty() && server.vars.is_empty());
    }

    #[test]
    fn requests_before_an_attach_fail_instead_of_going_unanswered() {
        // Every request must produce exactly one response, or the client hangs
        // waiting for one.
        let messages = serve_script(&[
            request(1, "initialize"),
            request(2, "threads"),
            request(3, "modules"),
            request(4, "restart"),
        ]);

        let responses: Vec<&Value> = messages
            .iter()
            .filter(|message| message["type"] == "response")
            .collect();
        assert_eq!(responses.len(), 4, "{messages:?}");
        assert_eq!(responses[1]["success"], false);
        assert!(
            responses[1]["message"].as_str().unwrap().contains("attach"),
            "{:?}",
            responses[1]
        );
        assert_eq!(responses[2]["success"], false);
        assert_eq!(responses[3]["success"], false);
        assert!(
            responses[3]["message"]
                .as_str()
                .unwrap()
                .contains("restart"),
            "{:?}",
            responses[3]
        );
    }

    #[test]
    fn disconnect_is_answered_before_the_loop_exits() {
        let messages = serve_script(&[request(1, "disconnect")]);

        assert!(
            messages
                .iter()
                .any(|message| message["event"] == "terminated"),
            "{messages:?}"
        );
        assert!(
            messages.iter().any(|message| message["type"] == "response"
                && message["command"] == "disconnect"
                && message["success"] == true),
            "{messages:?}"
        );
    }

    #[test]
    fn instruction_and_data_breakpoints_honor_hit_conditions() {
        let session = session_over_memory(0x1000, &[0u8; 0x40]);
        let (_tx, rx) = mpsc::channel();
        let (mut server, _sink) = server_with_sink(Some(session), rx);

        // Reject non-decimal pass counts for both breakpoint kinds.
        for (request, args) in [
            (
                "instruction",
                json!({"breakpoints": [{"instructionReference": "0x1000", "hitCondition": ">5"}]}),
            ),
            (
                "data",
                json!({"breakpoints": [{"dataId": "0x1000:4", "hitCondition": ">5"}]}),
            ),
        ] {
            let body = match request {
                "instruction" => server.on_set_instruction_breakpoints(&args),
                _ => server.on_set_data_breakpoints(&args),
            }
            .expect("handler answers")
            .expect("body");
            let entry = &body["breakpoints"][0];
            assert_eq!(entry["verified"], json!(false), "{request}: {body}");
            assert!(
                entry["message"]
                    .as_str()
                    .is_some_and(|text| text.contains("decimal pass count")),
                "{request} breakpoint ignored its hit condition: {body}"
            );
        }
    }

    #[test]
    fn disconnect_releases_the_target_before_answering() {
        // Detach must precede the disconnect response.
        let session = session_over_memory(0x1000, &[0u8; 0x40]);
        let messages = serve_script_with(Some(session), &[request(1, "disconnect")]);

        let detached = messages
            .iter()
            .position(|message| {
                message["event"] == "output"
                    && message["body"]["output"]
                        .as_str()
                        .is_some_and(|text| text.contains("detached"))
            })
            .unwrap_or_else(|| panic!("no detach notice in {messages:?}"));
        let answered = messages
            .iter()
            .position(|message| message["type"] == "response" && message["command"] == "disconnect")
            .unwrap_or_else(|| panic!("no disconnect response in {messages:?}"));

        assert!(
            detached < answered,
            "target was released after the response: {messages:?}"
        );
    }

    #[test]
    fn variable_windows_follow_the_requested_page_and_filter() {
        let memory: Vec<u8> = (0..64u8).collect();
        let session = session_over_memory(0x1000, &memory);
        let (_tx, rx) = mpsc::channel();
        let (mut server, _sink) = server_with_sink(Some(session), rx);
        let elements = server.var_ref(VarRef::Elements {
            element: ParsedType::Primitive("UCHAR".to_string()),
            count: 64,
            element_size: 1,
            address: VirtAddr(0x1000),
        });

        let page = |server: &mut Server, args: Value| -> Vec<(String, String)> {
            server
                .on_variables(&args)
                .expect("handler answers")
                .expect("body")["variables"]
                .as_array()
                .expect("variables array")
                .iter()
                .map(|row| {
                    (
                        row["name"].as_str().unwrap_or_default().to_string(),
                        row["value"].as_str().unwrap_or_default().to_string(),
                    )
                })
                .collect()
        };

        let second = page(
            &mut server,
            json!({"variablesReference": elements, "filter": "indexed", "start": 16, "count": 4}),
        );
        assert_eq!(
            second,
            vec![
                ("[16]".to_string(), "0x10".to_string()),
                ("[17]".to_string(), "0x11".to_string()),
                ("[18]".to_string(), "0x12".to_string()),
                ("[19]".to_string(), "0x13".to_string()),
            ]
        );

        // A window past the end is empty, not wrapped around to the start.
        assert!(
            page(
                &mut server,
                json!({"variablesReference": elements, "start": 64, "count": 4})
            )
            .is_empty()
        );

        // Array children are indexed, so a request for the named half of the
        // same reference has nothing to answer with.
        assert!(
            page(
                &mut server,
                json!({"variablesReference": elements, "filter": "named"})
            )
            .is_empty()
        );
    }

    #[test]
    fn named_children_honor_the_requested_window() {
        let mut server = server_with_node_layout();
        let fields = server.var_ref(VarRef::Fields {
            type_name: "_NODE".to_string(),
            address: VirtAddr(0x1000),
        });

        let all = rows(
            server
                .on_variables(&json!({"variablesReference": fields}))
                .unwrap(),
        );
        assert!(all.len() >= 3, "expected several fields, got {all:?}");

        let windowed = rows(
            server
                .on_variables(&json!({"variablesReference": fields, "start": 1, "count": 1}))
                .unwrap(),
        );
        assert_eq!(windowed.len(), 1);
        assert_eq!(windowed[0]["name"], all[1]["name"]);

        // An `indexed` request against named children answers empty rather
        // than handing back the fields again.
        assert!(
            rows(
                server
                    .on_variables(&json!({"variablesReference": fields, "filter": "indexed"}))
                    .unwrap()
            )
            .is_empty()
        );
    }

    /// A server over a synthetic dump target carrying one `_NODE` layout:
    /// `Value` = 0x2a, `Next` pointing back at the node, `Nil` null.
    fn server_with_node_layout() -> Server {
        let mut memory = [0u8; 0x40];
        memory[0..4].copy_from_slice(&0x2au32.to_le_bytes());
        memory[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        let session = session_over_memory(0x1000, &memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        let pointer = ParsedType::Pointer(Box::new(ParsedType::Struct("_NODE".to_string())));
        let fields = [
            (
                "Value".to_string(),
                FieldInfo {
                    offset: 0,
                    size: 4,
                    type_data: ParsedType::Primitive("ULONG".to_string()),
                },
            ),
            (
                "Next".to_string(),
                FieldInfo {
                    offset: 8,
                    size: 8,
                    type_data: pointer.clone(),
                },
            ),
            (
                "Nil".to_string(),
                FieldInfo {
                    offset: 16,
                    size: 8,
                    type_data: pointer,
                },
            ),
        ];
        session.target.symbols.inject_module_for_test(
            1,
            vec![TypeInfo {
                name: "_NODE".to_string(),
                size: 24,
                fields: fields.into_iter().collect(),
            }],
            &[],
        );

        let (_, rx) = mpsc::channel();
        Server::new(
            Some(session),
            Box::new(Sink(Rc::new(RefCell::new(Vec::new())))),
            rx,
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn rows(body: Option<Value>) -> Vec<Value> {
        body.unwrap()["variables"].as_array().unwrap().clone()
    }

    fn row<'a>(rows: &'a [Value], name: &str) -> &'a Value {
        rows.iter()
            .find(|row| row["name"] == name)
            .unwrap_or_else(|| panic!("no row named {name} in {rows:?}"))
    }

    #[test]
    fn structs_open_into_field_rows_with_decoded_values() {
        let mut server = server_with_node_layout();

        let fields = rows(server.field_variables("_NODE", VirtAddr(0x1000)).unwrap());

        assert_eq!(row(&fields, "Value")["value"], "0x2a");
        assert_eq!(row(&fields, "Value")["memoryReference"], "0x1000");
        // A scalar is a leaf: no expander arrow.
        assert_eq!(row(&fields, "Value")["variablesReference"], 0);
        assert_eq!(row(&fields, "Next")["value"], "0x1000");
    }

    #[test]
    fn evaluated_members_read_values_but_data_watches_select_storage() {
        let mut server = server_with_node_layout();
        let expression = "((_NODE*)0x1000)->Next->Value";
        let response = server
            .on_evaluate(&json!({
                "expression": expression,
                "context": "watch",
            }))
            .unwrap()
            .unwrap();
        assert_eq!(response["result"], "0x2a");
        assert_eq!(
            server.data_expression_target(expression).unwrap(),
            (0x1000, 4)
        );
        assert_eq!(
            server
                .data_expression_target("&((_NODE*)0x1000)->Value")
                .unwrap(),
            (0x1000, 4)
        );
        assert_eq!(
            server
                .data_expression_target("((_NODE*)0x1000)->Next")
                .unwrap(),
            (0x1008, 8)
        );
        let target = &server.session.as_ref().unwrap().target;
        assert_eq!(
            Expr::eval("((_NODE*)0x1000)->Value == 0n42", target)
                .unwrap()
                .0,
            1
        );
        assert!(Expr::eval("((_NODE*)0x1000).Value", target).is_err());
        assert!(Expr::eval("(*((_NODE*)0x1000))->Value", target).is_err());
        assert_eq!(
            Expr::eval("(*((_NODE*)0x1000)).Value", target).unwrap().0,
            42
        );
    }

    #[test]
    fn a_pointer_row_opens_its_pointee_and_a_null_one_does_not() {
        let mut server = server_with_node_layout();
        let fields = rows(server.field_variables("_NODE", VirtAddr(0x1000)).unwrap());

        // A null pointer has nothing to open: an expander arrow there would
        // lead to an empty list the user cannot tell from an empty struct.
        assert_eq!(row(&fields, "Nil")["variablesReference"], 0);

        let reference = row(&fields, "Next")["variablesReference"].as_i64().unwrap();
        assert!(reference >= VARIABLES_BASE);
        let pointee = rows(
            server
                .on_variables(&json!({"variablesReference": reference}))
                .unwrap(),
        );

        assert_eq!(row(&pointee, "Value")["value"], "0x2a");
    }

    #[test]
    fn stale_and_unknown_references_are_refused_rather_than_answered_empty() {
        let mut server = server_with_node_layout();

        assert!(
            server
                .on_variables(&json!({"variablesReference": VARIABLES_BASE + 7}))
                .is_err()
        );
        assert!(
            server
                .field_variables("_MISSING", VirtAddr(0x1000))
                .is_err()
        );
    }

    /// A server whose guest holds `code` at 0x1000, recorded by the PDB as one
    /// source line covering exactly those bytes.
    fn server_over_one_line(code: &[u8]) -> Server {
        let session = session_over_memory(0x1000, code);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session.target.symbols.inject_source_lines_for_test(
            1,
            dtb,
            VirtAddr(0x1000),
            0x1000,
            "driver.c",
            &[(0, Some(code.len() as u32), 42)],
        );

        let (_, rx) = mpsc::channel();
        Server::new(
            Some(session),
            Box::new(Sink(Rc::new(RefCell::new(Vec::new())))),
            rx,
            Arc::new(AtomicBool::new(false)),
        )
    }

    #[test]
    fn a_branch_free_line_is_covered_by_one_run_instead_of_many_steps() {
        // mov rax, rcx / add rax, 1 / mov rcx, rax / xor edx, edx
        let code = [
            0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01, 0x48, 0x89, 0xc1, 0x31, 0xd2,
        ];
        let mut server = server_over_one_line(&code);

        assert_eq!(
            server.coalescible_line_end(0x1000).unwrap(),
            Some(VirtAddr(0x1000 + code.len() as u64))
        );
        // From inside the line, only the remainder is covered.
        assert_eq!(
            server.coalescible_line_end(0x1003).unwrap(),
            Some(VirtAddr(0x1000 + code.len() as u64))
        );
    }

    #[test]
    fn a_line_is_only_covered_up_to_its_first_control_flow_instruction() {
        // mov rax, rcx / add rax, 1 / call rax / mov rcx, rax
        let code = [
            0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01, 0xff, 0xd0, 0x48, 0x89, 0xc1,
        ];
        let mut server = server_over_one_line(&code);

        // Running past the call would skip the callee the client may step into.
        assert_eq!(
            server.coalescible_line_end(0x1000).unwrap(),
            Some(VirtAddr(0x1007))
        );
        // Standing on the call itself: nothing to coalesce, so step it.
        assert_eq!(server.coalescible_line_end(0x1007).unwrap(), None);
    }

    #[test]
    fn one_instruction_and_unmapped_addresses_are_left_to_the_stepper() {
        let code = [0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01];
        let mut server = server_over_one_line(&code);

        // A single remaining instruction: a step costs less than planting and
        // removing a breakpoint.
        assert_eq!(server.coalescible_line_end(0x1003).unwrap(), None);
        // No line record covers this address at all.
        assert_eq!(server.coalescible_line_end(0x9000).unwrap(), None);
    }
}
