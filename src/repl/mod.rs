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
use std::io::{BufRead, Write};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;
#[cfg(feature = "cli")]
use std::sync::atomic::Ordering;

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
use crate::guest::ModuleSymbolLoadReport;
#[cfg(feature = "python")]
use crate::python::embed;
use crate::session::Session;
#[cfg(feature = "cli")]
use crate::session::StopResolution;
#[cfg(feature = "cli")]
use crate::symbols::ntoseye_home;
#[cfg(feature = "cli")]
use crate::target::Target;
use crate::ui;

pub static INTERRUPT_REQUESTED: AtomicBool = AtomicBool::new(false);
pub const BREAK_STACKTRACE_DISPLAY_LIMIT: usize = 6;
pub const BREAK_STACKTRACE_PROBE_LIMIT: usize = 64;
#[cfg(feature = "cli")]
const REPL_HISTORY_SIZE: usize = 5000;
macro_rules! require_arg {
    ($invocation:expr, $idx:expr, $cmd:expr) => {
        match $invocation.arg($idx) {
            Some(a) => a,
            None => {
                println!("{}\n", command_help($cmd));
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
mod exception_policy;
#[cfg(feature = "cli")]
mod line_editor;
mod memory_view;
mod pool;
mod stop;

pub use crate::repl_command;
pub use aliases::*;
pub use bugcheck::*;
pub use command::*;
pub use completion::*;
pub use disasm::*;
pub use exception_policy::*;
#[cfg(feature = "cli")]
use line_editor::{CustomPrompt, MyCompleter, TrackingHighlighter};
pub use memory_view::*;
pub use pool::*;
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
    println!("{} {summary}", ui::muted("symbols:"));
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

    println!("{}", "capabilities".bold());

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
        println!("  {line}");
    }
    println!();
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
    println!();
}

pub fn print_plain_table(builder: Builder) {
    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::zero());
    println!("{table}\n");
}

pub fn print_padded_table(builder: Builder) {
    let mut table = builder.build();
    table
        .with(tabled::settings::Style::empty())
        .with(Padding::new(0, 2, 0, 0));
    println!("{table}\n");
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

pub struct ReplState<'a> {
    pub ctx: &'a mut Session,
    pub caches: ReplCaches,
    pub aliases: UserAliases,
    pub exception_policies: ExceptionPolicyTable,
    /// Nested automatic exception-command executions. Bounded so an event
    /// command that resumes into the same exception cannot recurse forever.
    pub event_command_depth: usize,
    pub radix: crate::expr::NumberRadix,
    pub line: String,
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
    /// Build a transient REPL state around an existing context for one-off
    /// command dispatch (e.g. the Python SDK's `run_command`). Completion caches
    /// start empty (no live REPL to populate them). Output goes to stdout, as in
    /// the REPL.
    pub fn for_oneshot(ctx: &'a mut Session) -> Self {
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

        let state = ReplState {
            ctx,
            caches,
            aliases: UserAliases::load(),
            exception_policies: ExceptionPolicyTable::default(),
            event_command_depth: 0,
            radix: crate::expr::NumberRadix::Hexadecimal,
            line: String::new(),
        };
        state.caches.refresh_expression_context(&state.ctx.target);
        state.refresh_alias_cache();
        state
    }
}

#[cfg(feature = "cli")]
pub fn start_repl(ctx: &mut Session) -> Result<()> {
    start_repl_with_mode(ctx, false)
}

#[cfg(feature = "cli")]
pub fn start_plain_repl(ctx: &mut Session) -> Result<()> {
    start_repl_with_mode(ctx, true)
}

#[cfg(feature = "cli")]
fn start_repl_with_mode(ctx: &mut Session, plain: bool) -> Result<()> {
    // Borrow the two owned fields disjointly; the rest of this function (and
    // ReplState) consumes them exactly as before.
    let debugger: &mut Target = &mut ctx.target;
    let client: &mut dyn DebugBackend = ctx.backend.as_mut();

    ctrlc::set_handler(move || {
        INTERRUPT_REQUESTED.store(true, Ordering::SeqCst);
    })?;

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
        println!(
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
            println!("\n{}", ui::label("target"));
            println!(
                "  {} Windows {}",
                ui::muted("kernel"),
                message_data.build_number.0
            );
            println!(
                "  {} {}",
                ui::muted("base  "),
                ui::addr(message_data.base_address.0)
            );
            println!(
                "  {} {}",
                ui::muted("psmods"),
                ui::addr_opt(message_data.loaded_module_list)
            );
            println!();
            message_data.loaded_module_list.is_zero()
        }
        Err(Error::NtoskrnlNotFound) | Err(Error::AddressNotInDump(_)) => {
            println!("\n{}", ui::label("target"));
            if let Some(base) = debugger.kernel_base() {
                println!("  {} {}", ui::muted("base  "), ui::addr(base.0));
            } else {
                println!(
                    "  {} {}",
                    ui::muted("kernel"),
                    ui::muted("unknown (ntoskrnl not found in dump)")
                );
            }
            println!();
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

    let min_completion_width: u16 = 0;
    let max_completion_width: u16 = 50;
    let max_completion_height: u16 = 12;
    let padding: u16 = 0;
    let border: bool = true;
    let cursor_offset: i16 = 0;
    let description_mode: DescriptionMode = DescriptionMode::PreferRight;
    let min_description_width: u16 = 0;
    let max_description_width: u16 = 50;
    let description_offset: u16 = 1;
    let correct_cursor_pos: bool = false;

    let mut ide_menu = IdeMenu::default()
        .with_name("completion_menu")
        .with_min_completion_width(min_completion_width)
        .with_max_completion_width(max_completion_width)
        .with_max_completion_height(max_completion_height)
        .with_padding(padding)
        .with_cursor_offset(cursor_offset)
        .with_description_mode(description_mode)
        .with_min_description_width(min_description_width)
        .with_max_description_width(max_description_width)
        .with_description_offset(description_offset)
        .with_correct_cursor_pos(correct_cursor_pos)
        .with_marker(" ")
        .with_text_style(Style::new().fg(Color::LightGray));

    if border {
        ide_menu = ide_menu.with_default_border();
    }

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
    // The default Left/Right bindings route through MenuLeft/MenuRight first,
    // which the open completion menu swallows so the cursor never moves. The
    // IdeMenu is a single column (Up/Down navigate it), so drop the menu nav and
    // let the arrows always move the cursor; keep history-hint accept on Right.
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
        exception_policies: ExceptionPolicyTable::default(),
        event_command_depth: 0,
        radix: crate::expr::NumberRadix::Hexadecimal,
        line: String::new(),
    };
    // The reload state machine lives on the Session now; seed it from the
    // startup message (an empty module list means we attached very early in
    // boot, before rediscovery completed).
    state.ctx.reload_module_list_pending = reload_module_list_pending;

    if plain {
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        let mut buffer = String::new();

        loop {
            let prompt = if state.ctx.current_thread.is_empty() {
                "ntoseye>".to_string()
            } else {
                format!("{backend_label}:{}>", state.ctx.current_thread)
            };
            println!("{prompt}");
            std::io::stdout().flush()?;

            buffer.clear();
            if input.read_line(&mut buffer)? == 0 {
                break;
            }
            let command = buffer.trim();
            if command.is_empty() {
                continue;
            }

            state.line = command.to_string();
            if state.dispatch_line(command)? == Flow::Quit {
                break;
            }
        }
    } else {
        loop {
            let prompt = CustomPrompt::new(backend_label, &state.ctx.current_thread);
            let sig = target_loan.lend(&state.ctx.target, || line_editor.read_line(&prompt))?;
            match sig {
                Signal::Success(buffer) => {
                    if !buffer.trim().is_empty() {
                        state.line = buffer.trim().to_string();
                        match state.dispatch_line(&buffer)? {
                            Flow::Quit => break,
                            Flow::Continue => {}
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
        let settle = (|| -> Result<()> {
            let mut event = match state.ctx.backend.try_wait_for_stop(REPL_STOP_POLL)? {
                Some(event) => event,
                None => state.ctx.backend.interrupt()?,
            };
            loop {
                match state.ctx.classify_stop_event(event)? {
                    StopResolution::Resumed => {
                        event = state.ctx.backend.interrupt()?;
                    }
                    StopResolution::Breakpoint { .. }
                    | StopResolution::Bugcheck { .. }
                    | StopResolution::TargetReloaded { .. }
                    | StopResolution::Stopped { .. } => return Ok(()),
                }
            }
        })();
        match settle {
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
    fn repeat_pattern_allows_zero_length() {
        assert_eq!(repeat_pattern(&[0x90], 0), Vec::<u8>::new());
    }
}
