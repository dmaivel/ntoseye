#[cfg(all(feature = "cli", unix))]
use libc::{SIGHUP, SIGTERM, c_int, sigaction, sigemptyset, sighandler_t};
#[cfg(feature = "cli")]
use nu_ansi_term::{Color, Style};
#[cfg(feature = "cli")]
use reedline::{
    DescriptionMode, Emacs, FileBackedHistory, IdeMenu, KeyCode, KeyModifiers, MenuBuilder,
    ReedlineEvent, ReedlineMenu, default_emacs_keybindings,
};
#[cfg(feature = "cli")]
use reedline::{Reedline, Signal};
#[cfg(feature = "cli")]
use std::io;
#[cfg(feature = "cli")]
use std::io::{BufRead, Write};
#[cfg(all(feature = "cli", unix))]
use std::mem::zeroed;
use std::path::PathBuf;
#[cfg(all(feature = "cli", unix))]
use std::ptr::null_mut;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tabled::builder::Builder;
use tabled::settings::Padding;

use owo_colors::OwoColorize;

#[cfg(feature = "cli")]
use crate::dbg_backend::DebugBackend;
use crate::dbg_backend::{BackendCapability, DebugCapability};
use crate::diagnostics;
#[cfg(feature = "cli")]
use crate::error::Error;
use crate::error::Result;
use crate::expr::NumberRadix;
use crate::guest::ModuleSymbolLoadReport;
#[cfg(feature = "cli")]
use crate::output::log_input_line;
#[cfg(feature = "python")]
use crate::python::embed;
use crate::session::Session;
#[cfg(feature = "cli")]
use crate::symbols::ntoseye_home;
#[cfg(feature = "cli")]
use crate::target::Target;
use crate::ui;

/// Set by [`note_termination`]; polled by the prompt loops so a termination
/// signal leaves through the same teardown as `q`.
#[cfg(feature = "cli")]
static TERMINATION_REQUESTED: AtomicBool = AtomicBool::new(false);
pub const BREAK_STACKTRACE_DISPLAY_LIMIT: usize = 6;
pub const BREAK_STACKTRACE_PROBE_LIMIT: usize = 64;
#[cfg(feature = "cli")]
const REPL_HISTORY_SIZE: usize = 5000;
macro_rules! require_arg {
    ($invocation:expr, $idx:expr, $cmd:expr) => {
        match $invocation.arg($idx) {
            Some(a) => a,
            None => {
                outln!("{}\n", command_help($cmd));
                return Ok(());
            }
        }
    };
}

pub fn error(msg: &str) {
    diagnostics::print_error(msg);
}

macro_rules! error {
    ($($arg:tt)*) => {
        error(&format!($($arg)*))
    };
}

mod aliases;
mod bugcheck;
mod command;
mod commands;
mod completion;
mod disasm;
mod heap;
#[cfg(feature = "cli")]
mod line_editor;
mod memory_view;
mod stop;

pub use crate::exception_policy::*;
pub use crate::repl_command;
pub use aliases::*;
pub use bugcheck::*;
pub use command::*;
pub use completion::*;
pub use disasm::*;
pub use heap::*;
#[cfg(feature = "cli")]
use line_editor::{CustomPrompt, MyCompleter, TrackingHighlighter};
pub use memory_view::*;
pub use stop::*;

pub fn print_module_symbol_report(report: &ModuleSymbolLoadReport) {
    let mut summary = format!("loaded {}/{}", report.loaded, report.total);
    if report.failed_count() > 0 {
        summary.push_str(&format!(", {} failed", report.failed_count()));
    }
    if report.no_pdb > 0 {
        summary.push_str(&format!(", {} no-pdb", report.no_pdb));
    }
    if report.skipped > 0 {
        summary.push_str(&format!(", {} skipped", report.skipped));
    }
    if report.diagnostic_count > 0 {
        summary.push_str(&format!(
            ", {} PDB warning{}",
            report.diagnostic_count,
            if report.diagnostic_count == 1 {
                ""
            } else {
                "s"
            }
        ));
    }
    outln!("{} {summary}", ui::muted("symbols:"));
    const DISPLAY_LIMIT: usize = 8;
    for diagnostic in report.diagnostics.iter().take(DISPLAY_LIMIT) {
        let location = diagnostic
            .compiland
            .as_deref()
            .map(|compiland| format!("{} ({compiland})", diagnostic.module))
            .unwrap_or_else(|| diagnostic.module.clone());
        diagnostics::print_warning(format!(
            "{location}: {}: {}",
            diagnostic.phase, diagnostic.message
        ));
    }
    if report.diagnostic_count > DISPLAY_LIMIT {
        diagnostics::print_warning(format!(
            "{} additional PDB diagnostics omitted",
            report.diagnostic_count - DISPLAY_LIMIT
        ));
    }
}

pub fn print_backend_capabilities(capabilities: &[BackendCapability]) {
    const COLUMNS: usize = 4;

    outln!("{}", "capabilities".bold());

    let mut builder = Builder::default();
    for chunk in capabilities.chunks(COLUMNS) {
        let mut row = chunk
            .iter()
            .enumerate()
            .map(|(idx, capability)| {
                let marker = if capability.supported {
                    "+".green().to_string()
                } else {
                    "-".red().to_string()
                };
                let cell = format!("{} {}", marker, capability.capability.label());
                if idx + 1 == COLUMNS {
                    cell
                } else {
                    format!("{cell}  ")
                }
            })
            .collect::<Vec<_>>();
        row.resize(COLUMNS, String::new());
        builder.push_record(row);
    }

    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    for line in table.to_string().lines() {
        outln!("  {line}");
    }
    outln!();
}

pub fn supports_capability(
    capabilities: &[BackendCapability],
    capability: DebugCapability,
) -> bool {
    capabilities
        .iter()
        .any(|entry| entry.capability == capability && entry.supported)
}

pub fn print_backend_capability_warning(capabilities: &[BackendCapability]) {
    if capabilities.iter().all(|capability| capability.supported) {
        return;
    }

    diagnostics::print_warning(
        "selected backend has reduced capabilities; run `capabilities` for details",
    );
    outln!();
}

pub fn print_plain_table(builder: Builder) {
    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    outln!("{table}\n");
}

pub fn print_padded_table(builder: Builder) {
    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::new(0, 2, 0, 0));
    outln!("{table}\n");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
    /// The dispatch context refused a command's run effect (already reported);
    /// the rest of the command list is abandoned.
    Denied,
}

pub struct ReplState<'a> {
    pub ctx: &'a mut Session,
    pub caches: ReplCaches,
    pub aliases: UserAliases,
    /// Nested automatic exception-command executions. Bounded so an event
    /// command that resumes into the same exception cannot recurse forever.
    pub event_command_depth: usize,
    pub radix: NumberRadix,
    pub line: String,
    /// Who is dispatching; decides which [`RunEffect`]s a command may have.
    pub context: DispatchContext,
    /// Set while a multi-step command (`pa`, `pt`, `wt`...) drives the
    /// target: intermediate stops are not rendered, only the final one.
    pub quiet_stops: bool,
    /// Where `ls` continues: the file and the line after the last one listed.
    pub source_cursor: Option<(PathBuf, u32)>,
    /// How long a resuming command may wait for the next stop before handing
    /// control back with the target still running. `None` (the interactive
    /// prompt) waits until a stop or Ctrl+C. A request/response host sets it
    /// per dispatch so no call blocks past the client's patience; the target
    /// keeps running and the host collects the stop on a later call with
    /// [`ReplState::collect_stop`].
    pub stop_wait: Option<StopWaitBudget>,
}

/// Deadline for a bounded stop wait, plus a host-owned cancel flag (client
/// disconnect, server shutdown) that ends the wait early. Elapsing never
/// interrupts the target; it only returns control.
#[derive(Clone, Debug)]
pub struct StopWaitBudget {
    pub deadline: Instant,
    pub cancel: Arc<AtomicBool>,
}

impl StopWaitBudget {
    pub fn new(timeout: Duration, cancel: Arc<AtomicBool>) -> Self {
        Self {
            deadline: Instant::now() + timeout,
            cancel,
        }
    }

    pub fn exhausted(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
}

/// Where a command line comes from. Event-driven and remote contexts must not
/// let a command move the target on their own; see
/// [`ReplState::run_control_denial`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchContext {
    /// The user's prompt: anything goes.
    Interactive,
    /// A breakpoint's action string; only a trailing `gc` may resume.
    BreakpointAction,
    /// An exception policy's command; the policy's `-f` owns the disposition.
    ExceptionCommand,
    /// A request/response host that cannot block on a run, because its client
    /// owns run control; the variant names which controls to point at.
    Remote(RemoteClient),
}

/// The protocol server behind a [`DispatchContext::Remote`] session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteClient {
    /// The MCP `command` tool. Resumes are allowed but bounded by
    /// [`ReplState::stop_wait`]; `quit` is refused (the client closes).
    Mcp,
    /// The DAP Debug Console, alongside the client's own run-control buttons.
    Dap,
}

/// Everything a [`ReplState`] owns besides its session borrow. A host that
/// runs commands one at a time against a session it owns (the MCP `command`
/// tool) keeps one of these between calls, so completion caches, aliases,
/// exception policies, and the radix persist exactly as in the interactive
/// REPL, and rebuilds the borrowing `ReplState` per call with
/// [`ReplState::attach`].
pub struct ReplStore {
    caches: ReplCaches,
    aliases: UserAliases,
    radix: NumberRadix,
    context: DispatchContext,
    source_cursor: Option<(PathBuf, u32)>,
}

impl ReplStore {
    /// Fresh REPL state for `ctx`: caches seeded from the current symbol
    /// context, persisted aliases loaded, default exception policies and radix.
    pub fn new(ctx: &Session, context: DispatchContext) -> Self {
        let caches = ReplCaches {
            symbols: Arc::new(RwLock::new(ctx.target.current_symbol_index())),
            types: Arc::new(RwLock::new(ctx.target.current_types_index())),
            symbol_store: Arc::clone(&ctx.target.symbols),
            dtb: Arc::new(RwLock::new(ctx.target.current_dtb())),
            processes: Arc::new(RwLock::new(Vec::new())),
            threads: Arc::new(RwLock::new(Vec::new())),
            vcpus: Arc::new(RwLock::new(Vec::new())),
            breakpoints: Arc::new(RwLock::new(Vec::new())),
            drivers: Arc::new(RwLock::new(Vec::new())),
            registers: Arc::new(ctx.register_map.names()),
            expression_variables: Arc::new(RwLock::new(Vec::new())),
            user_commands: Arc::new(RwLock::new(initial_user_commands())),
            aliases: Arc::new(RwLock::new(Vec::new())),
        };
        caches.refresh_expression_context(&ctx.target);
        let aliases = UserAliases::load();
        *caches.aliases.write().unwrap() = aliases.entries();
        Self {
            caches,
            aliases,
            radix: NumberRadix::Hexadecimal,
            context,
            source_cursor: None,
        }
    }

    /// The session's current default radix. A host that evaluates expressions
    /// outside `dispatch_line` (DAP watch/hover requests) shares it so `n 10`
    /// typed in the console applies there too.
    pub fn radix(&self) -> NumberRadix {
        self.radix
    }
}

/// The user-command completion set: the registered Python commands when the
/// binary embeds Python (`python-embed`), else empty.
pub fn initial_user_commands() -> Vec<(String, String, Vec<CompletionStrategy>)> {
    #[cfg(feature = "python")]
    {
        embed::command_list()
    }
    #[cfg(not(feature = "python"))]
    {
        Vec::new()
    }
}

impl<'a> ReplState<'a> {
    /// Bind stored REPL state to a session for one dispatch; [`Self::detach`]
    /// hands the state back afterwards.
    pub fn attach(ctx: &'a mut Session, store: ReplStore) -> Self {
        ReplState {
            ctx,
            caches: store.caches,
            aliases: store.aliases,
            event_command_depth: 0,
            radix: store.radix,
            line: String::new(),
            context: store.context,
            quiet_stops: false,
            source_cursor: store.source_cursor,
            stop_wait: None,
        }
    }

    /// Release the session borrow, keeping the REPL state for the next
    /// [`Self::attach`].
    pub fn detach(self) -> ReplStore {
        ReplStore {
            caches: self.caches,
            aliases: self.aliases,
            radix: self.radix,
            context: self.context,
            source_cursor: self.source_cursor,
        }
    }

    /// Build a transient REPL state around an existing context for one-off
    /// command dispatch (e.g. the Python SDK's `run_command`). Completion caches
    /// start empty (no live REPL to populate them). Output goes to stdout unless
    /// the caller wraps dispatch in [`crate::output::capture`].
    pub fn for_oneshot(ctx: &'a mut Session) -> Self {
        if ctx.target.selected_frame.is_none() {
            ctx.restore_live_register_cache();
        }
        let store = ReplStore::new(ctx, DispatchContext::Interactive);
        Self::attach(ctx, store)
    }
}

#[cfg(feature = "cli")]
pub fn start_repl(ctx: &mut Session) -> Result<()> {
    start_repl_with_mode(ctx, false)
}

/// Signal-handler safe: one atomic store through an already-initialized static.
#[cfg(all(unix, feature = "cli"))]
extern "C" fn note_termination(_signal: c_int) {
    TERMINATION_REQUESTED.store(true, Ordering::SeqCst);
}

/// Turn a termination signal into an ordinary exit so the teardown below runs.
///
/// The default disposition kills the process outright, which leaves an `int3`
/// in guest code and holds one of the target's 32 breakpoint-table entries for
/// the rest of the boot, since only the debugger owning a handle can release
/// it.
/// `SIGINT` is left to the Ctrl+C handler, which means "interrupt the guest".
/// `SA_RESTART` is deliberately unset: the interrupted `read` is how a loop
/// blocked on input learns to stop waiting.
#[cfg(all(unix, feature = "cli"))]
fn install_termination_handler() {
    for signal in [SIGTERM, SIGHUP] {
        // SAFETY: the handler only performs one atomic store.
        unsafe {
            let mut action: sigaction = zeroed();
            action.sa_sigaction = note_termination as *const () as sighandler_t;
            sigemptyset(&mut action.sa_mask);
            sigaction(signal, &action, null_mut());
        }
    }
}

#[cfg(all(not(unix), feature = "cli"))]
fn install_termination_handler() {}

#[cfg(feature = "cli")]
fn termination_requested() -> bool {
    TERMINATION_REQUESTED.load(Ordering::SeqCst)
}

/// Read one line, noticing a termination signal that arrived mid-read.
///
/// `BufRead::read_line` retries `EINTR` internally, so a signal delivered while
/// the prompt waits for input stays invisible until the next keypress, leaving
/// the process alive with breakpoints still installed in the guest. Returns
/// `None` when termination was requested instead of a line.
#[cfg(feature = "cli")]
fn read_line_interruptible<R: BufRead>(
    input: &mut R,
    buffer: &mut String,
) -> io::Result<Option<usize>> {
    let mut line = Vec::new();
    loop {
        if termination_requested() {
            return Ok(None);
        }
        let available = match input.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            break;
        }
        let (chunk, complete) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (&available[..=index], true),
            None => (available, false),
        };
        // Decoded once at the end: a multi-byte character can straddle two
        // fills, and lossy-decoding each chunk would mangle it.
        line.extend_from_slice(chunk);
        let consumed = chunk.len();
        input.consume(consumed);
        if complete {
            break;
        }
    }
    buffer.push_str(&String::from_utf8_lossy(&line));
    Ok(Some(line.len()))
}

#[cfg(feature = "cli")]
pub fn start_plain_repl(ctx: &mut Session) -> Result<()> {
    start_repl_with_mode(ctx, true)
}

#[cfg(feature = "cli")]
fn start_repl_with_mode(ctx: &mut Session, plain: bool) -> Result<()> {
    // Warnings the attach raised (unreadable PRCB contexts, a corrupt triage
    // signature, kernel discovery falling back) precede the banner.
    for notice in ctx.take_notices() {
        diagnostics::print_warning(notice);
    }
    let debugger: &mut Target = &mut ctx.target;
    let client: &mut dyn DebugBackend = ctx.backend.as_mut();

    let interrupt = Arc::clone(&debugger.interrupt);
    ctrlc::set_handler(move || {
        interrupt.store(true, Ordering::SeqCst);
    })?;
    install_termination_handler();

    let backend_label = client.name();

    // Loaded up front so the summary prints with the transport banner and
    // the completion caches below see them.
    #[cfg(feature = "python")]
    let py_report = embed::load_commands_dir();
    let (aliases, alias_report) = UserAliases::load_with_report();
    let mut loaded_parts: Vec<String> = Vec::new();
    #[cfg(feature = "python")]
    if !py_report.loaded.is_empty() || !py_report.failed.is_empty() {
        let mut part = format!("{} python", py_report.loaded.len());
        if !py_report.failed.is_empty() {
            part.push_str(&format!(" ({} failed)", py_report.failed.len()));
        }
        loaded_parts.push(part);
    }
    if alias_report.loaded > 0 || !alias_report.failed.is_empty() {
        let n = alias_report.loaded;
        let mut part = format!("{n} alias{}", if n == 1 { "" } else { "es" });
        if !alias_report.failed.is_empty() {
            part.push_str(&format!(" ({} failed)", alias_report.failed.len()));
        }
        loaded_parts.push(part);
    }
    if !loaded_parts.is_empty() {
        outln!(
            "{}",
            ui::muted(&format!("loaded: {}", loaded_parts.join(", ")))
        );
    }
    #[cfg(feature = "python")]
    embed::print_script_load_failures(&py_report);
    print_alias_load_failures(&alias_report);

    // Triage dumps may lack the ntoskrnl PE header needed for full kernel
    // discovery; a missing kernel is non-fatal and commands that need it
    // fail individually.
    let reload_module_list_pending = match debugger.startup_message_data() {
        Ok(message_data) => {
            outln!("\n{}", ui::label("target"));
            outln!(
                "  {} Windows {}",
                ui::muted("kernel"),
                message_data.build_number.0
            );
            outln!(
                "  {} {}",
                ui::muted("base  "),
                ui::addr(message_data.base_address.0)
            );
            outln!(
                "  {} {}",
                ui::muted("psmods"),
                ui::addr_opt(message_data.loaded_module_list)
            );
            outln!();
            message_data.loaded_module_list.is_zero()
        }
        Err(Error::NtoskrnlNotFound) | Err(Error::AddressNotInDump(_)) => {
            outln!("\n{}", ui::label("target"));
            if let Some(base) = debugger.kernel_base() {
                outln!("  {} {}", ui::muted("base  "), ui::addr(base.0));
            } else {
                outln!(
                    "  {} {}",
                    ui::muted("kernel"),
                    ui::muted("unknown (ntoskrnl not found in dump)")
                );
            }
            outln!();
            false
        }
        Err(e) => return Err(e),
    };
    let capabilities = client.capabilities();
    print_backend_capability_warning(&capabilities);

    let has_register_context = supports_capability(&capabilities, DebugCapability::ReadRegisters);

    if has_register_context {
        print_break_context(
            &mut *client,
            &ctx.register_map,
            debugger,
            &ctx.breakpoints,
            &ctx.current_thread,
        );
    }

    let ide_menu = IdeMenu::default()
        .with_name("completion_menu")
        .with_max_completion_width(50)
        .with_max_completion_height(12)
        .with_padding(1)
        .with_description_mode(DescriptionMode::PreferRight)
        .with_min_description_width(0)
        .with_max_description_width(50)
        .with_description_offset(1)
        .with_correct_cursor_pos(false)
        .with_marker(" ")
        .with_text_style(Style::new().fg(Color::LightGray));
    let completion_menu = Box::new(ide_menu);

    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    keybindings.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuPrevious,
        ]),
    );
    keybindings.add_binding(KeyModifiers::NONE, KeyCode::Left, ReedlineEvent::Left);
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Right,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::HistoryHintComplete,
            ReedlineEvent::Right,
        ]),
    );

    let edit_mode = Box::new(Emacs::new(keybindings));

    let initial_vcpus = if supports_capability(&capabilities, DebugCapability::ThreadList) {
        client.thread_list().unwrap_or_default()
    } else {
        Vec::new()
    };

    // Process and driver lists are never walked ahead of use: completions
    // enumerate them on demand through the target loan below, and listing
    // commands refresh the fallback snapshots as a side effect.
    let caches = ReplCaches {
        symbols: Arc::new(RwLock::new(debugger.current_symbol_index())),
        types: Arc::new(RwLock::new(debugger.current_types_index())),
        symbol_store: Arc::clone(&debugger.symbols),
        dtb: Arc::new(RwLock::new(debugger.current_dtb())),
        processes: Arc::new(RwLock::new(Vec::new())),
        // populated on demand by the threads/thread commands
        threads: Arc::new(RwLock::new(Vec::new())),
        vcpus: Arc::new(RwLock::new(initial_vcpus)),
        breakpoints: Arc::new(RwLock::new(Vec::new())),
        drivers: Arc::new(RwLock::new(Vec::new())),
        registers: Arc::new(ctx.register_map.names()),
        expression_variables: Arc::new(RwLock::new(Vec::new())),
        user_commands: Arc::new(RwLock::new(initial_user_commands())),
        aliases: Arc::new(RwLock::new(aliases.entries())),
    };
    caches.refresh_expression_context(debugger);

    let target_loan = TargetLoan::default();
    let completor = Box::new(MyCompleter {
        caches: caches.clone(),
        target: target_loan.clone(),
    });

    let had_content = Arc::new(AtomicBool::new(false));
    let highlighter = TrackingHighlighter {
        had_content: Arc::clone(&had_content),
    };

    let mut line_editor = Reedline::create()
        .with_completer(completor)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode)
        .with_highlighter(Box::new(highlighter))
        .with_history_exclusion_prefix(Some(" ".to_string()));
    if let Some(history_path) = ntoseye_home().map(|root| root.join("history")) {
        match FileBackedHistory::with_file(REPL_HISTORY_SIZE, history_path.clone()) {
            Ok(history) => {
                line_editor = line_editor.with_history(Box::new(history));
            }
            Err(err) => diagnostics::print_warning(format!(
                "failed to load command history from {}: {}",
                history_path.display(),
                err
            )),
        }
    }

    let mut state = ReplState {
        ctx,
        caches,
        aliases,
        event_command_depth: 0,
        radix: NumberRadix::Hexadecimal,
        line: String::new(),
        context: DispatchContext::Interactive,
        quiet_stops: false,
        source_cursor: None,
        stop_wait: None,
    };
    // An empty module list at startup means we attached before rediscovery completed.
    state.ctx.reload_module_list_pending = reload_module_list_pending;

    if plain {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut buffer = String::new();

        loop {
            if termination_requested() {
                break;
            }
            let prompt = if state.ctx.current_thread.is_empty() {
                "ntoseye>".to_string()
            } else {
                format!("{backend_label}:{}>", state.ctx.current_thread)
            };
            outln!("{prompt}");
            io::stdout().flush()?;

            buffer.clear();
            match read_line_interruptible(&mut input, &mut buffer) {
                // A termination signal, or end of input.
                Ok(None) | Ok(Some(0)) => break,
                Ok(Some(_)) => {}
                Err(error) => return Err(error.into()),
            }
            let command = buffer.trim();
            if command.is_empty() {
                continue;
            }

            log_input_line(command);
            state.line = command.to_string();
            if state.dispatch_line(command)? == Flow::Quit {
                break;
            }
        }
    } else {
        loop {
            if termination_requested() {
                break;
            }
            let prompt = CustomPrompt::new(backend_label, &state.ctx.current_thread);
            let sig = match target_loan.lend(&state.ctx.target, || line_editor.read_line(&prompt)) {
                Ok(sig) => sig,
                Err(_) if termination_requested() => break,
                Err(error) => return Err(error.into()),
            };
            if termination_requested() {
                break;
            }
            match sig {
                Signal::Success(buffer) => {
                    if !buffer.trim().is_empty() {
                        log_input_line(buffer.trim());
                        state.line = buffer.trim().to_string();
                        match state.dispatch_line(&buffer)? {
                            Flow::Quit => break,
                            Flow::Continue | Flow::Denied => {}
                        }
                    }
                }
                Signal::CtrlD => {
                    break;
                }
                Signal::CtrlC => {
                    if had_content.load(Ordering::Relaxed) {
                        had_content.store(false, Ordering::Relaxed);
                        continue;
                    }

                    if state.ctx.backend.is_running() {
                        state.interrupt_running_vm()?;
                    } else {
                        error!("VM is already paused");
                    }
                }
                _ => {}
            }
        }
    }

    let was_running_on_exit = state.ctx.backend.is_running();
    let mut resume_on_exit = !was_running_on_exit;
    if was_running_on_exit && !state.ctx.breakpoints.list().is_empty() {
        match state.ctx.halt_for_exit() {
            Ok(()) => resume_on_exit = true,
            Err(error) => {
                error!("failed to halt cleanly during exit: {error}");
                resume_on_exit = false;
            }
        }
    }

    // Restore every debugger-owned site before allowing the guest to resume.
    // A failed removal remains managed and forces an explicitly halted exit;
    // resuming with an orphaned int3 would turn cleanup failure into a guest
    // crash after the debugger disconnects.
    let breakpoint_cleanup_succeeded = match state
        .ctx
        .breakpoints
        .remove_all(&mut *state.ctx.backend, &state.ctx.target)
    {
        Ok(()) => true,
        Err(error) => {
            error!("failed to uninstall breakpoints on exit: {error}");
            false
        }
    };

    let leave_running_on_exit =
        breakpoint_cleanup_succeeded && (resume_on_exit || state.ctx.backend.is_running());
    if let Err(e) = state.ctx.backend.prepare_for_exit(leave_running_on_exit) {
        error!("failed to prepare backend for exit: {:?}", e);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::dbg_backend::BugcheckInfo;
    use crate::output::capture;
    use crate::repl::{Flow, ReplState};
    use crate::session::tests::{MockBackend, breakpoint_event, session_with_mock};
    use crate::session::{Session, session_over_memory};
    use crate::symbols::{FieldInfo, ParsedType, TypeInfo};
    use crate::types::VirtAddr;

    use super::{
        bugcheck_fault_ip, looks_like_kernel_pointer, parse_byte_pattern, plausible_bugcheck_code,
        repeat_pattern, resolve_length_or_end,
    };

    #[test]
    fn parse_byte_pattern_accepts_contiguous_hex() {
        assert_eq!(
            parse_byte_pattern("4883792000740a"),
            Some(vec![0x48, 0x83, 0x79, 0x20, 0x00, 0x74, 0x0a])
        );
    }

    #[test]
    fn plausible_bugcheck_code_rejects_pointer_like_values() {
        assert!(plausible_bugcheck_code(0xe2));
        assert!(plausible_bugcheck_code(0x0000_0139));
        assert!(!plausible_bugcheck_code(0));
        assert!(!plausible_bugcheck_code(0xfffff8007f1afb50));
    }

    #[test]
    fn kernel_pointer_heuristic_accepts_canonical_kernel_addresses() {
        assert!(looks_like_kernel_pointer(0xfffff8007f1afb50));
        assert!(!looks_like_kernel_pointer(0x00000000000000e2));
    }

    #[test]
    fn bugcheck_fault_ip_uses_only_real_fault_instruction_arguments() {
        let mut info = BugcheckInfo {
            code: 0x50,
            parameters: [0x1, 0x2, 0xfffff804877d1805, 0x4],
            driver: None,
        };
        assert_eq!(bugcheck_fault_ip(&info), Some(0xfffff804877d1805));

        info.code = 0xd1;
        info.parameters = [0x1, 0x2, 0x0, 0xfffff804877d1730];
        assert_eq!(bugcheck_fault_ip(&info), Some(0xfffff804877d1730));

        info.code = 0x4a;
        info.parameters = [0x00007ffb32481d84, 0x2, 0x0, 0xffffdf8669067b20];
        assert_eq!(bugcheck_fault_ip(&info), None);
    }

    #[test]
    fn parse_byte_pattern_accepts_hex_escape_bytes() {
        assert_eq!(
            parse_byte_pattern(r"\x48\x83\x79\x20\x00\x74\x0a"),
            Some(vec![0x48, 0x83, 0x79, 0x20, 0x00, 0x74, 0x0a])
        );
    }

    #[test]
    fn parse_byte_pattern_rejects_odd_length_hex() {
        assert_eq!(parse_byte_pattern("488379200074a"), None);
    }

    #[test]
    fn resolve_length_or_end_treats_small_value_as_length() {
        assert_eq!(
            resolve_length_or_end(VirtAddr(0xfffff8075b471000), VirtAddr(0x20)),
            Some(0x20)
        );
    }

    #[test]
    fn resolve_length_or_end_treats_large_value_as_end() {
        assert_eq!(
            resolve_length_or_end(VirtAddr(0x1000), VirtAddr(0x1020)),
            Some(0x20)
        );
    }

    #[test]
    fn repeat_pattern_repeats_and_truncates() {
        assert_eq!(repeat_pattern(&[0x90], 4), vec![0x90, 0x90, 0x90, 0x90]);
        assert_eq!(
            repeat_pattern(&[0x48, 0x83, 0x79], 8),
            vec![0x48, 0x83, 0x79, 0x48, 0x83, 0x79, 0x48, 0x83]
        );
    }

    #[test]
    fn windbg_forms_produce_windbg_shaped_output() {
        let mut memory = [0u8; 0x40];
        memory[..4].copy_from_slice(&0x12345678u32.to_le_bytes());
        memory[0x10..0x14].copy_from_slice(b"abc\0");
        let mut session = session_over_memory(0x1000, &memory);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session.target.symbols.inject_module_for_test(
            1,
            vec![
                TypeInfo {
                    name: "_NODE".to_string(),
                    pointer_size: 8,
                    size: 0x10,
                    fields: [(
                        "Value".to_string(),
                        FieldInfo {
                            offset: 0,
                            size: 4,
                            type_data: ParsedType::Primitive("ULONG".to_string()),
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
                // A layout whose fields sit past 0xfff, where WinDbg's three-digit
                // offset pad gives way to the natural width.
                TypeInfo {
                    name: "_WIDE".to_string(),
                    pointer_size: 8,
                    size: 0x1160,
                    fields: [(
                        "Far".to_string(),
                        FieldInfo {
                            offset: 0x1150,
                            size: 4,
                            type_data: ParsedType::Primitive("ULONG".to_string()),
                        },
                    )]
                    .into_iter()
                    .collect(),
                },
            ],
            &[],
        );
        let mut state = ReplState::for_oneshot(&mut session);

        for (line, expected) in [
            // Hexadecimal default radix, `0n` decimal override.
            ("? 0n42", "000000000000002a"),
            ("? 1000 + 0n16", "0000000000001010"),
            // WinDbg prints every 64-bit address with a `\`` between its halves
            // and takes that spelling back, so a copied address must evaluate.
            ("? 00000000`00001000", "0000000000001000"),
            ("? fffff803`1a2b3c4d", "fffff8031a2b3c4d"),
            ("db 00000000`00001000 L4", "78 56 34 12"),
            // Memory dumps are address-prefixed rows of fixed-width units.
            ("db 1000 L4", "78 56 34 12"),
            ("dd 1000 L1", "12345678"),
            ("da 1010 4", "abc"),
            // `dt` rows: WinDbg's three-digit minimum offset, name, type, value.
            ("dt _NODE 1000", "+0x000 Value : ULONG = 0x12345678"),
            ("dt _WIDE 0", "+0x1150 Far : ULONG"),
            // `.formats` shows one value in every radix WinDbg lists.
            (".formats 0n42", "2a"),
        ] {
            let (result, text) = capture(|| state.dispatch_line(line));
            result.unwrap_or_else(|error| panic!("{line} failed: {error}"));
            if line.starts_with("dt ") {
                let expected_line = format!("  {expected}");
                assert!(
                    text.lines().any(|line| line == expected_line),
                    "{line} printed {text:?}"
                );
            } else {
                assert!(text.contains(expected), "{line} printed {text:?}");
            }
        }
    }

    #[test]
    fn session_radix_switch_applies_to_later_expressions() {
        let mut session = session_over_memory(0x1000, &[0u8; 8]);
        let mut state = ReplState::for_oneshot(&mut session);
        let (result, _) = capture(|| state.dispatch_line("n 10"));
        result.unwrap();
        let (result, text) = capture(|| state.dispatch_line("? 42"));
        result.unwrap();
        assert!(text.contains("000000000000002a"), "decimal radix: {text:?}");
        // A separated address is the debugger's own address spelling, so it stays
        // hexadecimal even while the session default is decimal.
        let (result, text) = capture(|| state.dispatch_line("? 00000000`00001000"));
        result.unwrap();
        assert!(
            text.contains("0000000000001000"),
            "separated address under decimal radix: {text:?}"
        );
        let (result, _) = capture(|| state.dispatch_line("n 16"));
        result.unwrap();
        let (result, text) = capture(|| state.dispatch_line("? 42"));
        result.unwrap();
        assert!(text.contains("0000000000000042"), "hex radix: {text:?}");
    }

    fn remote_state(session: &mut Session, budget_ms: u64) -> ReplState<'_> {
        let mut state = ReplState::for_oneshot(session);
        state.context = super::DispatchContext::Remote(super::RemoteClient::Mcp);
        state.stop_wait = Some(super::StopWaitBudget::new(
            std::time::Duration::from_millis(budget_ms),
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ));
        state
    }

    #[test]
    fn bounded_wait_hands_back_a_running_target_instead_of_blocking() {
        let mut session = session_with_mock(MockBackend::default().running());
        let mut state = remote_state(&mut session, 150);
        let started = std::time::Instant::now();
        let (result, text) = capture(|| state.collect_stop());
        result.unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(text.contains("target still running"), "{text:?}");
        assert!(state.ctx.backend.is_running());
    }

    #[test]
    fn bounded_wait_renders_the_stop_that_arrives_within_budget() {
        let mut backend = MockBackend::default().running();
        backend.queue_interrupt(breakpoint_event(0x1000));
        let mut session = session_with_mock(backend);
        let mut state = remote_state(&mut session, 5_000);
        let (result, text) = capture(|| state.collect_stop());
        result.unwrap();
        assert!(!state.ctx.backend.is_running());
        assert!(!text.contains("target still running"), "{text:?}");
    }

    #[test]
    fn halted_only_line_waits_for_the_stop_then_runs() {
        let mut backend = MockBackend::default().running();
        backend.queue_interrupt(breakpoint_event(0x1000));
        let mut session = session_with_mock(backend);
        let mut state = remote_state(&mut session, 5_000);
        let (result, _) = capture(|| state.gate_remote_line("k"));
        assert!(result.unwrap().is_none(), "k was not let through");
        assert!(!state.ctx.backend.is_running());
    }

    #[test]
    fn halted_only_line_is_not_run_on_a_target_still_running() {
        let mut session = session_with_mock(MockBackend::default().running());
        let mut state = remote_state(&mut session, 150);
        let (result, text) = capture(|| state.gate_remote_line("k"));
        assert_eq!(result.unwrap(), Some(Flow::Denied));
        assert!(text.contains("not run"), "{text:?}");
        assert!(state.ctx.backend.is_running());
    }

    #[test]
    fn resuming_line_is_refused_against_the_stop_it_waited_for() {
        let mut backend = MockBackend::default().running();
        backend.queue_interrupt(breakpoint_event(0x1000));
        let mut session = session_with_mock(backend);
        let mut state = remote_state(&mut session, 5_000);
        let (result, text) = capture(|| state.gate_remote_line("g"));
        assert_eq!(result.unwrap(), Some(Flow::Denied));
        assert!(text.contains("not run"), "{text:?}");
        assert!(
            !state.ctx.backend.is_running(),
            "the stop was continued past"
        );
    }

    #[test]
    fn running_safe_line_runs_without_waiting() {
        let mut session = session_with_mock(MockBackend::default().running());
        let mut state = remote_state(&mut session, 5_000);
        let started = std::time::Instant::now();
        let (result, _) = capture(|| state.gate_remote_line("help"));
        assert!(result.unwrap().is_none());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(state.ctx.backend.is_running());
    }

    #[test]
    fn resuming_line_is_recognized_through_aliases() {
        let mut session = session_over_memory(0x1000, &[0u8; 8]);
        let state = ReplState::for_oneshot(&mut session);
        assert!(state.line_moves_target("g"));
        assert!(state.line_moves_target("lm; p"));
        assert!(state.line_moves_target("t"));
        assert!(!state.line_moves_target("lm"));
        assert!(!state.line_moves_target(""));
        assert!(!state.line_moves_target("break"));
    }
}
