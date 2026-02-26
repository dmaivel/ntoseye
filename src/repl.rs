use indicatif::{ProgressBar, ProgressStyle};
use nu_ansi_term::{Color, Style};
use reedline::{
    Completer, Prompt, PromptEditMode, PromptHistorySearch, PromptHistorySearchStatus, Reedline,
    Signal, Span, Suggestion,
};
use reedline::{
    DescriptionMode, Emacs, Highlighter, IdeMenu, KeyCode, KeyModifiers, MenuBuilder,
    ReedlineEvent, ReedlineMenu, StyledText, default_emacs_keybindings,
};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use strum::EnumMessage;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumMessage, EnumString};
use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Padding, Panel};

use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, Instruction, MemorySizeOptions, NasmFormatter,
};
use owo_colors::OwoColorize;
use std::borrow::Cow;

use crate::backend::MemoryOps;
use crate::debugger::{DebuggerArgument, DebuggerContext};
use crate::error::{Error, Result};
use crate::gdb::{BreakpointHitResult, BreakpointManager, GdbClient, RegisterMap};
use crate::symbols::{ParsedType, SymbolIndex};
use crate::types::{Value, VirtAddr};

static INTERRUPT_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct CustomPrompt;
pub static DEFAULT_MULTILINE_INDICATOR: &str = "     ::: ";
impl Prompt for CustomPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Owned("ntoseye>".bright_black().to_string())
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Owned("".into())
    }

    fn render_prompt_indicator(&self, _edit_mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Owned(" ".to_string())
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed(DEFAULT_MULTILINE_INDICATOR)
    }

    fn render_prompt_history_search_indicator(
        &self,
        history_search: PromptHistorySearch,
    ) -> Cow<'_, str> {
        let prefix = match history_search.status {
            PromptHistorySearchStatus::Passing => "",
            PromptHistorySearchStatus::Failing => "failing ",
        };

        Cow::Owned(format!(
            "({}reverse-search: {}) ",
            prefix, history_search.term
        ))
    }
}

enum CompletionStrategy {
    None,
    Symbol,
    Type,
    Process,
    Thread,
    Breakpoint,
}

fn make_suggestions(
    names: Vec<String>,
    description: &str,
    arg_start: usize,
    prefix_offset: usize,
    pos: usize,
) -> Vec<Suggestion> {
    names
        .into_iter()
        .map(|name| Suggestion {
            value: name,
            description: Some(description.to_string()),
            style: None,
            extra: None,
            match_indices: None,
            span: Span::new(arg_start + prefix_offset, pos),
            append_whitespace: true,
        })
        .collect()
}

macro_rules! require_arg {
    ($parts:expr, $idx:expr, $cmd:expr) => {
        match $parts.get($idx) {
            Some(a) => *a,
            None => {
                println!("{}\n", $cmd.get_message().unwrap_or("invalid usage"));
                continue;
            }
        }
    };
}

struct AddressRange {
    start: VirtAddr,
    end: VirtAddr,
}

impl AddressRange {
    fn parse(parts: &[&str], debugger: &DebuggerContext, default_length: u64) -> Result<Self> {
        let start_arg = parts.get(1).ok_or(Error::InvalidRange)?;
        let start = DebuggerArgument::new(start_arg).try_resolve(debugger)?;

        let end = if let Some(end_arg) = parts.get(2) {
            let end = DebuggerArgument::new(end_arg).try_resolve(debugger)?;
            if end.0 < start.0 { end + start.0 } else { end }
        } else {
            start + default_length
        };

        if end.0 < start.0 {
            return Err(Error::InvalidRange);
        }

        Ok(AddressRange { start, end })
    }

    fn len(&self) -> usize {
        (self.end.0 - self.start.0) as usize
    }
}

// TODO
//
// Memory Display:
//   dd, dq       - Display as DWORDs/QWORDs
//   da, du       - Display ASCII/Unicode strings
//   dps          - Display pointers with symbol resolution
// Memory Write:
//   eb, ed, eq   - Edit byte/dword/qword
//   ea, eu       - Write ASCII/Unicode string
//   f            - Fill memory with pattern
// Execution Control:
//   t / si       - Single step (step into)
//   p / ni       - Step over
//   gu           - Go until return
//   st           - Switch threads/VCPU
// Breakpoints:
//   Conditional breakpoints
// Registers:
//   r            - Display/modify registers
//   context      - Auto-display regs/stack/disasm on break
// Stack Analysis:
//   k            - Stack backtrace
//   kv, kp       - Backtrace with locals/params
// Search:
//   s            - Search memory for bytes/string/pattern
//   x            - Search symbols by wildcard
//   ln           - List nearest symbols to address
// Expression Evaluation
// Misc:
//   vmmap        - Memory region map

#[derive(Debug, Clone, Copy, PartialEq, EnumIter, Display, EnumString, EnumMessage)]
#[strum(serialize_all = "kebab-case")]
enum ReplCommand {
    #[strum(
        message = "Display memory as bytes. Command accepts either just a symbol/address, or accepts an optional argument noting either the length or end address. The optional parameter is treated as an address if it's greater than the start address. By default, the optional parameter is 128.\n(usage: db <VirtualAddress or Symbol> [Length or EndAddress])"
    )]
    Db,

    #[strum(
        message = "Display type definition. Users may optionally supply a memory location, either as a symbol or address, and optionally provide a specific field to be printed.\n(usage: dt <Name> [VirtualAddress or Symbol] [Field])"
    )]
    Dt,

    #[strum(
        message = "Disassemble memory at a symbol or address.\n(usage: disasm <VirtualAddress or Symbol>)"
    )]
    Disasm,

    #[strum(
        message = "Resume VM execution. If breakpoints are set, waits for breakpoint hit or Ctrl+C.\n(usage: continue)"
    )]
    Continue,

    #[strum(
        message = "Display the page table entry (PTE) and page directory entry (PDE) for the specified address.\n(usage: pte <VirtualAddress or Symbol>)"
    )]
    Pte,

    #[strum(message = "List all threads and their RIP values.\n(usage: lt)")]
    Lt,

    #[strum(
        message = "List all running processes. Shows process name, PID, and CR3 (DirectoryTableBase).\n(usage: ps)"
    )]
    Ps,

    #[strum(
        message = "List all loaded modules in the current process. For kernel context, shows kernel modules.\n(usage: lm)"
    )]
    Lm,

    #[strum(
        message = "Attach to a process by PID. This sets the current process context for memory operations.\n(usage: attach <PID>)"
    )]
    Attach,

    #[strum(
        message = "Detach from the current process and return to kernel context.\n(usage: detach)"
    )]
    Detach,

    #[strum(message = "Display CPU registers (GPR, control, debug, segment).\n(usage: registers)")]
    Registers,

    #[strum(
        message = "Single step (step into). Waits for the next instruction to execute.\n(usage: si)"
    )]
    Si,

    #[strum(message = "Switch to a different thread/vCPU.\n(usage: thread <thread_id>)")]
    Thread,

    #[strum(
        message = "Set a breakpoint at address or symbol. If attached to a process, the breakpoint is process-specific.\n(usage: bp <VirtualAddress or Symbol>)"
    )]
    Bp,

    #[strum(message = "List all breakpoints.\n(usage: bl)")]
    Bl,

    #[strum(message = "Clear a breakpoint by ID.\n(usage: bc <ID>)")]
    Bc,

    #[strum(message = "Disable a breakpoint by ID.\n(usage: bd <ID>)")]
    Bd,

    #[strum(message = "Enable a previously disabled breakpoint by ID.\n(usage: be <ID>)")]
    Be,

    #[strum(
        message = "Display stack backtrace. Scans the stack for return addresses pointing into known modules.\n(usage: k [count])"
    )]
    K,

    #[strum(
        message = "Display current VM status. Shows break information if stopped, or indicates if running.\n(usage: status)"
    )]
    Status,

    #[strum(message = "Exit the application.")]
    Quit,
}

impl ReplCommand {
    pub fn completion_type(&self) -> CompletionStrategy {
        match self {
            Self::Quit => CompletionStrategy::None,
            Self::Pte => CompletionStrategy::Symbol,
            Self::Db => CompletionStrategy::Symbol,
            Self::Disasm => CompletionStrategy::Symbol,
            Self::Lt => CompletionStrategy::None,
            Self::Continue => CompletionStrategy::None,
            Self::Dt => CompletionStrategy::Type,
            Self::Ps => CompletionStrategy::None,
            Self::Lm => CompletionStrategy::None,
            Self::Attach => CompletionStrategy::Process,
            Self::Detach => CompletionStrategy::None,
            Self::Registers => CompletionStrategy::None,
            Self::Si => CompletionStrategy::None,
            Self::Thread => CompletionStrategy::Thread,
            Self::Bp => CompletionStrategy::Symbol,
            Self::Bl => CompletionStrategy::None,
            Self::Bc => CompletionStrategy::Breakpoint,
            Self::Bd => CompletionStrategy::Breakpoint,
            Self::Be => CompletionStrategy::Breakpoint,
            Self::K => CompletionStrategy::None,
            Self::Status => CompletionStrategy::None,
        }
    }
}

/// Cached process info for completion (name, PID)
type ProcessCache = Vec<(String, u64)>;

/// Cached thread IDs for completion
type ThreadCache = Vec<String>;

/// Cached breakpoint info for completion (id, enabled, address, symbol)
type BreakpointCache = Vec<(u32, bool, VirtAddr, Option<String>)>;

struct MyCompleter {
    symbols: Arc<RwLock<SymbolIndex>>,
    types: Arc<RwLock<SymbolIndex>>,
    processes: Arc<RwLock<ProcessCache>>,
    threads: Arc<RwLock<ThreadCache>>,
    breakpoints: Arc<RwLock<BreakpointCache>>,
}

impl Completer for MyCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let text_before_cursor = &line[..pos];
        let mut parts = text_before_cursor.split_whitespace();

        let command_str = parts.next().unwrap_or("");
        let is_command_context = !text_before_cursor.contains(' ');

        if is_command_context {
            return ReplCommand::iter()
                .filter_map(|cmd| {
                    let c_str = cmd.to_string();
                    if c_str.starts_with(command_str) {
                        Some(Suggestion {
                            value: c_str,
                            description: cmd.get_message().map(String::from),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(0, pos),
                            append_whitespace: true,
                        })
                    } else {
                        None
                    }
                })
                .collect();
        }

        if let Ok(cmd) = ReplCommand::from_str(command_str) {
            let arg_start = text_before_cursor.rfind(' ').map(|i| i + 1).unwrap_or(0);
            let raw_prefix = &text_before_cursor[arg_start..];

            let prefix = raw_prefix.strip_prefix('*').unwrap_or(raw_prefix);
            let prefix_offset = if raw_prefix.starts_with('*') { 1 } else { 0 };

            match cmd.completion_type() {
                CompletionStrategy::None => return vec![],

                CompletionStrategy::Symbol => {
                    let symbols = self.symbols.read().unwrap();
                    let results = symbols.search(prefix, 1024);
                    return make_suggestions(results, "Symbol", arg_start, prefix_offset, pos);
                }

                CompletionStrategy::Type => {
                    let mut arg_count = text_before_cursor.split_whitespace().count();
                    if text_before_cursor.ends_with(char::is_whitespace) {
                        arg_count += 1;
                    }

                    let results = if arg_count > 2 {
                        let symbols = self.symbols.read().unwrap();
                        symbols.search(prefix, 1024)
                    } else {
                        let types = self.types.read().unwrap();
                        types.search(prefix, 1024)
                    };

                    let description = if arg_count > 2 { "Symbol" } else { "Structure" };
                    return make_suggestions(results, description, arg_start, prefix_offset, pos);
                }

                CompletionStrategy::Process => {
                    let processes = self.processes.read().unwrap();
                    let prefix_lower = prefix.to_lowercase();
                    return processes
                        .iter()
                        .filter(|(name, pid)| {
                            name.to_lowercase().contains(&prefix_lower)
                                || pid.to_string().starts_with(prefix)
                        })
                        .map(|(name, pid)| Suggestion {
                            value: pid.to_string(),
                            description: Some(format!("{} (PID {})", name, pid)),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(arg_start + prefix_offset, pos),
                            append_whitespace: true,
                        })
                        .collect();
                }

                CompletionStrategy::Thread => {
                    let threads = self.threads.read().unwrap();
                    return threads
                        .iter()
                        .filter(|tid| tid.starts_with(prefix))
                        .map(|tid| Suggestion {
                            value: tid.clone(),
                            description: Some("Thread/vCPU".to_string()),
                            style: None,
                            extra: None,
                            match_indices: None,
                            span: Span::new(arg_start + prefix_offset, pos),
                            append_whitespace: true,
                        })
                        .collect();
                }

                CompletionStrategy::Breakpoint => {
                    let breakpoints = self.breakpoints.read().unwrap();
                    return breakpoints
                        .iter()
                        .filter(|(id, _, _, _)| id.to_string().starts_with(prefix))
                        .map(|(id, _, addr, symbol)| {
                            let sym_str = symbol.as_deref().unwrap_or("-");
                            Suggestion {
                                value: id.to_string(),
                                description: Some(format!("{} @ {:#x}", sym_str, addr.0)),
                                style: None,
                                extra: None,
                                match_indices: None,
                                span: Span::new(arg_start + prefix_offset, pos),
                                append_whitespace: true,
                            }
                        })
                        .collect();
                }
            }
        }

        vec![]
    }
}

fn error(msg: &str) {
    eprintln!("{} {}", "error:".red(), msg);
}

macro_rules! error {
    ($($arg:tt)*) => {
        error(&format!($($arg)*))
    };
}

macro_rules! update_breakpoint_cache {
    ($breakpoints:expr, $cache:expr) => {
        *$cache.write().unwrap() = $breakpoints
            .list()
            .iter()
            .map(|bp| (bp.id, bp.enabled, bp.address, bp.symbol.clone()))
            .collect();
    };
}

fn print_break_info(
    client: &mut GdbClient,
    register_map: &RegisterMap,
    debugger: &DebuggerContext,
    thread_id: &str,
) {
    let regs = match client.read_registers() {
        Ok(r) => r,
        Err(_) => {
            println!("{} thread {}\n", "break:".magenta(), thread_id);
            return;
        }
    };

    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
    let cr3 = register_map.read_u64("cr3", &regs).unwrap_or(0);
    let cr3_masked = cr3 & 0x000F_FFFF_FFFF_F000;
    let kernel_dtb_masked = debugger.guest.ntoskrnl.dtb() & 0x000F_FFFF_FFFF_F000;

    let (context, symbol) = if cr3_masked == kernel_dtb_masked {
        let sym = debugger
            .guest
            .ntoskrnl
            .closest_symbol(&debugger.symbols, VirtAddr(rip))
            .map(|(s, o)| if o == 0 { s } else { format!("{}+{:#x}", s, o) })
            .unwrap_or_else(|_| format!("{:#x}", rip));
        ("kernel".to_string(), sym)
    } else {
        let processes = debugger
            .guest
            .enumerate_processes(&debugger.kvm, &debugger.symbols)
            .unwrap_or_default();

        match processes
            .iter()
            .find(|p| (p.dtb & 0x000F_FFFF_FFFF_F000) == cr3_masked)
        {
            Some(proc) => {
                let sym = debugger
                    .symbols
                    .find_closest_symbol_for_address(proc.dtb, VirtAddr(rip))
                    .map(|(module, sym, offset)| {
                        if offset == 0 {
                            format!("{}!{}", module, sym)
                        } else {
                            format!("{}!{}+{:#x}", module, sym, offset)
                        }
                    })
                    .unwrap_or_else(|| format!("{:#x}", rip));
                (format!("{} ({})", proc.name.clone(), proc.pid), sym)
            }
            None => ("unknown".to_string(), format!("{:#x}", rip)),
        }
    };

    println!(
        "{} {} {} {} {} {}\n",
        "break:".magenta(),
        format!("thread {}", thread_id).bright_black(),
        "in".bright_black(),
        context.cyan(),
        "at".bright_black(),
        symbol.green()
    );
}

fn hexdump(start_address: VirtAddr, data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:08x}  ", start_address + ((i * 16) as u64));

        for byte in chunk {
            print!("{:02x} ", byte);
        }

        for _ in chunk.len()..16 {
            print!("   ");
        }

        print!(" ");

        // not the most efficient, FIXME?
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!("{}", ".".bright_black());
            }
        }

        println!();
    }

    println!();
}

struct TrackingHighlighter {
    had_content: Arc<AtomicBool>,
}

impl Highlighter for TrackingHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        self.had_content.store(!line.is_empty(), Ordering::Relaxed);

        let mut styled = StyledText::new();
        styled.push((Style::new(), line.to_string()));
        styled
    }
}

pub fn start_repl(debugger: &mut DebuggerContext) -> Result<()> {
    ctrlc::set_handler(move || {
        INTERRUPT_REQUESTED.store(true, Ordering::SeqCst);
    })?;

    let message_data = debugger.get_startup_message_data()?;

    let splash_text = format!(
        "{} {}\n{} Kernel version = {}\n{} Kernel base = {:#x}\n{} PsLoadedModuleList = {:#x}\n",
        "    ⢀⣴⠶⣶⡄⠀⠀⠀⠀".bright_blue(),
        format!(
            "Windows kernel debugger for Linux ({} {})",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )
        .bright_magenta()
        .bold(),
        "⢀⣴⣧⠀⠸⣿⣀⣸⡇⠀⢨⡦⣄".bright_blue(),
        message_data.build_number,
        "⠘⣿⣿⣄⠀⠈⠛⠉⠀⣠⣾⡿⠋".bright_blue(),
        message_data.base_address,
        "⠀⠀⠈⠛⠿⠶⣶⡶⠿⠟⠉⠀⠀".bright_blue(),
        message_data.loaded_module_list
    );

    println!("{}", splash_text);

    // TODO make this non-fatal
    let mut client = GdbClient::connect("127.1:1234")?;

    let register_map = client.get_register_map()?;

    let mut current_thread = client
        .get_stopped_thread_id()
        .unwrap_or_else(|_| "1".to_string());

    let mut breakpoints = BreakpointManager::new();

    print_break_info(&mut client, &register_map, debugger, &current_thread);

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

    let edit_mode = Box::new(Emacs::new(keybindings));

    let shared_symbols = Arc::new(RwLock::new(debugger.current_symbol_index()));
    let shared_types = Arc::new(RwLock::new(debugger.current_types_index()));

    let initial_processes = debugger
        .guest
        .enumerate_processes(&debugger.kvm, &debugger.symbols)
        .map(|procs| procs.into_iter().map(|p| (p.name, p.pid)).collect())
        .unwrap_or_default();
    let shared_processes: Arc<RwLock<ProcessCache>> = Arc::new(RwLock::new(initial_processes));

    let initial_threads = client.get_thread_list().unwrap_or_default();
    let shared_threads: Arc<RwLock<ThreadCache>> = Arc::new(RwLock::new(initial_threads));

    let shared_breakpoints: Arc<RwLock<BreakpointCache>> = Arc::new(RwLock::new(Vec::new()));

    let completor = Box::new(MyCompleter {
        symbols: Arc::clone(&shared_symbols),
        types: Arc::clone(&shared_types),
        processes: Arc::clone(&shared_processes),
        threads: Arc::clone(&shared_threads),
        breakpoints: Arc::clone(&shared_breakpoints),
    });

    let had_content = Arc::new(AtomicBool::new(false));
    let highlighter = TrackingHighlighter {
        had_content: Arc::clone(&had_content),
    };

    let mut line_editor = Reedline::create()
        .with_completer(completor)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode)
        .with_highlighter(Box::new(highlighter));
    let prompt = CustomPrompt {};

    loop {
        let sig = line_editor.read_line(&prompt)?;
        match sig {
            Signal::Success(buffer) => {
                let parts: Vec<&str> = buffer.split_whitespace().collect();
                if let Some(cmd_str) = parts.first() {
                    match ReplCommand::from_str(cmd_str) {
                        Ok(ReplCommand::Quit) => {
                            break;
                        }
                        Ok(ReplCommand::Pte) => {
                            let arg = require_arg!(parts, 1, ReplCommand::Pte);
                            let arg = DebuggerArgument::new(arg);
                            match debugger.pte_traverse(arg) {
                                Ok(result) => {
                                    let mut levels = vec![result.pxe, result.ppe];

                                    if let Some(x) = result.pde {
                                        levels.push(x);
                                    }

                                    if let Some(x) = result.pte {
                                        levels.push(x);
                                    }

                                    let header = format!("VA {:016x}", result.address);
                                    let mut builder = Builder::default();

                                    let row_strings: Vec<String> =
                                        levels.iter().map(|l| l.to_string()).collect();
                                    builder.push_record(row_strings);

                                    let mut table = builder.build();
                                    table
                                        .with(Panel::header(header))
                                        .with(Modify::new(Rows::first()).with(Alignment::center()))
                                        .with(tabled::settings::Style::empty());

                                    println!("{}\n", table);
                                }
                                Err(e) => {
                                    error!("{}\n", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Db) => {
                            let range = match AddressRange::parse(&parts, debugger, 128) {
                                Ok(r) => r,
                                Err(_) => {
                                    println!(
                                        "{}\n",
                                        ReplCommand::Db.get_message().unwrap_or("invalid usage")
                                    );
                                    continue;
                                }
                            };

                            let mut data: Vec<u8> = vec![0u8; range.len()];
                            if let Err(e) = debugger
                                .get_current_process()
                                .memory(&debugger.kvm)
                                .read_bytes(range.start, &mut data)
                            {
                                println!("{e}\n");
                                continue;
                            }

                            hexdump(range.start, &data);
                        }
                        Ok(ReplCommand::Disasm) => {
                            let range = match AddressRange::parse(&parts, debugger, 32) {
                                Ok(r) => r,
                                Err(_) => {
                                    println!(
                                        "{}\n",
                                        ReplCommand::Disasm
                                            .get_message()
                                            .unwrap_or("invalid usage")
                                    );
                                    continue;
                                }
                            };

                            let mut bytes: Vec<u8> = vec![0u8; range.len()];
                            if let Err(e) = debugger
                                .get_current_process()
                                .memory(&debugger.kvm)
                                .read_bytes(range.start, &mut bytes)
                            {
                                println!("{e}\n");
                                continue;
                            }

                            let mut decoder = Decoder::with_ip(
                                64, /* TODO dont hardcode for WOW64 process? */
                                &bytes,
                                range.start.0,
                                DecoderOptions::NONE,
                            );

                            // TODO support other formats?
                            let mut formatter = NasmFormatter::new();
                            let options = formatter.options_mut();
                            options.set_space_after_operand_separator(true);
                            options.set_hex_prefix("0x");
                            options.set_hex_suffix("");
                            options.set_first_operand_char_index(5);
                            options.set_memory_size_options(MemorySizeOptions::Always);
                            options.set_show_branch_size(false);
                            options.set_rip_relative_addresses(true);

                            let mut output = String::new();
                            let mut instruction = Instruction::default();

                            while decoder.can_decode() {
                                decoder.decode_out(&mut instruction);
                                if instruction.code() == Code::INVALID {
                                    continue;
                                }

                                output.clear();
                                formatter.format(&instruction, &mut output);

                                print!("{:016x} ", VirtAddr(instruction.ip()));
                                let start_index = (instruction.ip() - range.start.0) as usize;
                                let instr_bytes =
                                    &bytes[start_index..start_index + instruction.len()];
                                for b in instr_bytes.iter() {
                                    print!("{:02x}", Value(b));
                                }
                                if instr_bytes.len() < 12 {
                                    for _ in 0..12 - instr_bytes.len() {
                                        print!("  ");
                                    }
                                }
                                print!(" {}", output);

                                if instruction.is_ip_rel_memory_operand() {
                                    let target_address = instruction.ip_rel_memory_address();
                                    let sym = debugger
                                        .guest
                                        .ntoskrnl
                                        .closest_symbol(&debugger.symbols, VirtAddr(target_address))
                                        .map(|(s, o)| format!("{}+{:#x}", s, o))
                                        .unwrap_or_else(|_| format!("{:#X}", target_address));
                                    print!("{}", format!(" ; {}", sym).bright_black());
                                } else if instruction.is_call_near()
                                    || instruction.is_jmp_near()
                                    || instruction.is_jcc_near()
                                {
                                    let target_address = instruction.near_branch_target();
                                    let sym = debugger
                                        .guest
                                        .ntoskrnl
                                        .closest_symbol(&debugger.symbols, VirtAddr(target_address))
                                        .map(|(s, o)| format!("{}+{:#x}", s, o))
                                        .unwrap_or_else(|_| format!("{:#X}", target_address));
                                    print!("{}", format!(" ; {}", sym).bright_black());
                                }

                                println!();
                            }
                            println!();
                        }
                        Ok(ReplCommand::Lt) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            let pb = ProgressBar::new_spinner();
                            pb.set_style(
                                ProgressStyle::default_spinner()
                                    .template("{spinner:.black.bright} {msg}")
                                    .unwrap(),
                            );

                            pb.set_message(format!(
                                "{}",
                                owo_colors::OwoColorize::bright_black(&"Waiting on GDB...")
                            ));
                            pb.enable_steady_tick(Duration::from_millis(100));

                            let original_thread = client.get_stopped_thread_id()?;
                            let threads = client.get_thread_list()?;

                            let processes = debugger
                                .guest
                                .enumerate_processes(&debugger.kvm, &debugger.symbols)
                                .unwrap_or_default();
                            let kernel_dtb = debugger.guest.ntoskrnl.dtb();

                            let mut thread_data: Vec<(String, String, String, String)> = Vec::new();

                            for thread in &threads {
                                client.set_current_thread(thread)?;

                                let regs = client.read_registers()?;
                                let rip = register_map.read_u64("rip", &regs)?;
                                let cr3 = register_map.read_u64("cr3", &regs)?;

                                let cr3_masked = cr3 & 0x000F_FFFF_FFFF_F000;
                                let kernel_dtb_masked = kernel_dtb & 0x000F_FFFF_FFFF_F000;

                                let (context, symbol) = if cr3_masked == kernel_dtb_masked {
                                    let sym = debugger
                                        .guest
                                        .ntoskrnl
                                        .closest_symbol(&debugger.symbols, VirtAddr(rip))
                                        .map(|(s, o)| format!("{}+{:#x}", s, o))?;
                                    ("kernel".to_string(), sym)
                                } else {
                                    match processes
                                        .iter()
                                        .find(|p| (p.dtb & 0x000F_FFFF_FFFF_F000) == cr3_masked)
                                    {
                                        Some(proc) => {
                                            let sym = debugger
                                                .symbols
                                                .find_closest_symbol_for_address(
                                                    proc.dtb,
                                                    VirtAddr(rip),
                                                )
                                                .map(|(module, sym, offset)| {
                                                    if offset == 0 {
                                                        format!("{}!{}", module, sym)
                                                    } else {
                                                        format!("{}!{}+{:#x}", module, sym, offset)
                                                    }
                                                })
                                                .unwrap_or_else(|| format!("{:#x}", rip));
                                            (proc.name.clone(), sym)
                                        }
                                        None => ("unknown".to_string(), format!("{:#x}", rip)),
                                    }
                                };

                                thread_data.push((
                                    thread.clone(),
                                    format!("{:#018x}", VirtAddr(rip)),
                                    context,
                                    symbol,
                                ));
                            }

                            client.set_current_thread(&original_thread)?;

                            let mut builder = Builder::default();
                            builder.push_record(vec!["Thread", "RIP", "Context", "Symbol"]);
                            for (tid, rip, ctx, sym) in thread_data {
                                builder.push_record(vec![
                                    format!("{}  ", tid),
                                    format!("{}  ", rip),
                                    format!("{}  ", ctx),
                                    sym,
                                ]);
                            }

                            pb.finish_and_clear();

                            let mut table = builder.build();
                            table
                                .with(tabled::settings::Style::empty())
                                .with(Padding::zero());
                            println!("{}\n", table);
                        }
                        Ok(ReplCommand::Continue) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            if let Err(e) = breakpoints.refresh_enabled(&mut client) {
                                error!("failed to refresh breakpoints: {}", e);
                                continue;
                            }

                            if let Err(e) = client.continue_execution() {
                                error!("failed to continue: {:?}", e);
                                continue;
                            }

                            if breakpoints.has_enabled_breakpoints() {
                                println!(
                                    "{}",
                                    "VM running, waiting for breakpoint (Ctrl+C to pause)..."
                                        .bright_black()
                                );

                                INTERRUPT_REQUESTED.store(false, Ordering::SeqCst);
                                if let Err(e) =
                                    client.set_read_timeout(Some(Duration::from_millis(100)))
                                {
                                    error!("failed to set timeout: {:?}", e);
                                    continue;
                                }

                                loop {
                                    // if user pressed Ctrl+C
                                    if INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst) {
                                        // restore blocking mode before interrupt
                                        let _ = client.set_read_timeout(None);
                                        if let Err(e) = client.interrupt() {
                                            error!("failed to interrupt VM: {:?}", e);
                                            break;
                                        }

                                        if let Ok(tid) = client.get_stopped_thread_id() {
                                            current_thread = tid;
                                        }
                                        println!();
                                        print_break_info(
                                            &mut client,
                                            &register_map,
                                            debugger,
                                            &current_thread,
                                        );
                                        break;
                                    }

                                    match client.try_wait_for_stop() {
                                        Ok(Some(_)) => {
                                            // restore blocking mode for subsequent operations
                                            let _ = client.set_read_timeout(None);

                                            // VM stopped, check if it's our breakpoint
                                            let regs = match client.read_registers() {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    error!("failed to read registers: {:?}", e);
                                                    break;
                                                }
                                            };

                                            let rip =
                                                register_map.read_u64("rip", &regs).unwrap_or(0);
                                            let cr3 =
                                                register_map.read_u64("cr3", &regs).unwrap_or(0);

                                            match breakpoints.check_breakpoint_hit(rip, cr3) {
                                                BreakpointHitResult::Hit(bp) => {
                                                    if let Ok(tid) = client.get_stopped_thread_id()
                                                    {
                                                        current_thread = tid;
                                                    }
                                                    println!();
                                                    println!(
                                                        "{} {} {}",
                                                        "breakpoint".magenta(),
                                                        format!("#{}", bp.id).cyan(),
                                                        bp.symbol
                                                            .as_ref()
                                                            .map(|s| format!("({})", s))
                                                            .unwrap_or_default()
                                                            .green()
                                                    );
                                                    print_break_info(
                                                        &mut client,
                                                        &register_map,
                                                        debugger,
                                                        &current_thread,
                                                    );

                                                    // reset the breakpoint to ensure it's still active
                                                    let _ = client.set_breakpoint(bp.address.0, 1);

                                                    break;
                                                }
                                                BreakpointHitResult::WrongProcess(bp) => {
                                                    // temporarily disable the breakpoint to step over it
                                                    if let Err(e) =
                                                        breakpoints.disable(&mut client, bp.id)
                                                    {
                                                        error!(
                                                            "failed to disable breakpoint for step: {}",
                                                            e
                                                        );
                                                        break;
                                                    }

                                                    if let Err(e) = client.step() {
                                                        let _ =
                                                            breakpoints.enable(&mut client, bp.id);
                                                        error!("failed to step: {:?}", e);
                                                        break;
                                                    }
                                                    if let Err(e) = client.wait_for_stop() {
                                                        let _ =
                                                            breakpoints.enable(&mut client, bp.id);
                                                        error!(
                                                            "failed to wait after step: {:?}",
                                                            e
                                                        );
                                                        break;
                                                    }

                                                    // reenable the breakpoint after stepping
                                                    if let Err(e) =
                                                        breakpoints.enable(&mut client, bp.id)
                                                    {
                                                        error!(
                                                            "failed to re-enable breakpoint: {}",
                                                            e
                                                        );
                                                        break;
                                                    }

                                                    if let Err(e) =
                                                        breakpoints.refresh_enabled(&mut client)
                                                    {
                                                        error!(
                                                            "failed to refresh breakpoints after step: {}",
                                                            e
                                                        );
                                                        break;
                                                    }

                                                    if let Err(e) = client.continue_execution() {
                                                        error!("failed to continue: {:?}", e);
                                                        break;
                                                    }

                                                    let _ = client.set_read_timeout(Some(
                                                        Duration::from_millis(100),
                                                    ));
                                                }
                                                BreakpointHitResult::NotBreakpoint => {
                                                    if let Ok(tid) = client.get_stopped_thread_id()
                                                    {
                                                        current_thread = tid;
                                                    }

                                                    println!();
                                                    print_break_info(
                                                        &mut client,
                                                        &register_map,
                                                        debugger,
                                                        &current_thread,
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                        Ok(None) => {
                                            // timeout
                                        }
                                        Err(e) => {
                                            let _ = client.set_read_timeout(None);
                                            error!("error waiting for stop: {:?}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        Ok(ReplCommand::Dt) => {
                            let arg = require_arg!(parts, 1, ReplCommand::Dt);

                            let address = DebuggerArgument::new(parts.get(2).unwrap_or(&"0"))
                                .try_resolve(debugger)?;

                            let field_name = parts.get(3);

                            match debugger
                                .symbols
                                .find_type_across_modules(debugger.current_dtb(), arg)
                            {
                                Some(type_info) => {
                                    let mut builder = Builder::default();
                                    builder.push_record(vec![format!(
                                        "{} ({} bytes)",
                                        type_info.name,
                                        Value(type_info.size)
                                    )]);

                                    let mut sorted_fields: Vec<_> =
                                        type_info.fields.iter().collect();
                                    sorted_fields.sort_by_key(|(_, info)| {
                                        let bitfield_pos = match &info.type_data {
                                            ParsedType::Bitfield { pos, .. } => *pos,
                                            _ => 0,
                                        };
                                        (info.offset, bitfield_pos)
                                    });

                                    for (name, info) in sorted_fields {
                                        let value = if address.0 != 0 {
                                            let mem = debugger
                                                .get_current_process()
                                                .memory(&debugger.kvm);
                                            match &info.type_data {
                                                ParsedType::Primitive(p) => {
                                                    if p.contains("*") || p.contains("LONGLONG") {
                                                        let val: u64 =
                                                            mem.read(address + info.offset)?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("LONG") {
                                                        let val: u32 =
                                                            mem.read(address + info.offset)?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("SHORT")
                                                        || p.contains("WCHAR")
                                                    {
                                                        let val: u16 =
                                                            mem.read(address + info.offset)?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else if p.contains("CHAR") {
                                                        let val: u8 =
                                                            mem.read(address + info.offset)?;
                                                        format!(" = {:#x}", Value(val))
                                                    } else {
                                                        "".into()
                                                    }
                                                }
                                                ParsedType::Pointer(_) => {
                                                    let val: u64 =
                                                        mem.read(address + info.offset)?;
                                                    format!(" = {:#x}", Value(val))
                                                }
                                                ParsedType::Bitfield { pos, len, .. } => {
                                                    let val: u64 =
                                                        mem.read(address + info.offset)?;
                                                    let val = (val >> pos) & ((1u64 << len) - 1);

                                                    if *len == 1 {
                                                        if val == 1 {
                                                            format!(" = {}", "Y".green())
                                                        } else {
                                                            format!(" = {}", "N".red())
                                                        }
                                                    } else {
                                                        format!(" = {}", Value(val))
                                                    }
                                                }
                                                _ => "".into(),
                                            }
                                        } else {
                                            "".into()
                                        };

                                        if field_name.is_none() || field_name.unwrap() == name {
                                            builder.push_record(vec![
                                                format!(
                                                    "  + {:#06x} {:-12}",
                                                    VirtAddr(info.offset.into()),
                                                    name
                                                ),
                                                format!("  : {}", info.type_data.green()),
                                                format!("  {}", value),
                                            ]);
                                        }
                                    }

                                    let mut table = builder.build();
                                    table
                                        .with(tabled::settings::Style::empty())
                                        .with(Padding::zero());
                                    println!("{}\n", table);
                                }
                                None => {
                                    error!(
                                        "failed to get type information: type `{}` not found\n",
                                        arg
                                    );
                                }
                            }
                        }
                        Ok(ReplCommand::Ps) => {
                            match debugger
                                .guest
                                .enumerate_processes(&debugger.kvm, &debugger.symbols)
                            {
                                Ok(processes) => {
                                    *shared_processes.write().unwrap() =
                                        processes.iter().map(|p| (p.name.clone(), p.pid)).collect();

                                    let mut builder = Builder::default();
                                    builder.push_record(vec![
                                        "Name".to_string(),
                                        "PID".to_string(),
                                        "DTB".to_string(),
                                    ]);

                                    for proc in processes {
                                        builder.push_record(vec![
                                            format!("{}  ", proc.name),
                                            format!("{}  ", Value(proc.pid)),
                                            format!("{:#018x}", VirtAddr(proc.dtb)), // TODO technically is phys addr..
                                        ]);
                                    }

                                    let mut table = builder.build();
                                    table
                                        .with(tabled::settings::Style::empty())
                                        .with(Padding::zero());
                                    println!("{}\n", table);
                                }
                                Err(e) => {
                                    error!("failed to enumerate processes: {}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Lm) => {
                            let result = if let Some(process_info) = &debugger.current_process_info
                            {
                                debugger.guest.get_process_modules(
                                    &debugger.kvm,
                                    &debugger.symbols,
                                    process_info,
                                )
                            } else {
                                debugger
                                    .guest
                                    .get_kernel_modules(&debugger.kvm, &debugger.symbols)
                            };

                            match result {
                                Ok(modules) => {
                                    let mut builder = Builder::default();
                                    builder.push_record(vec![
                                        "Start".to_string(),
                                        "End".to_string(),
                                        "Module".to_string(),
                                        "Image".to_string(),
                                    ]);

                                    for module in modules {
                                        let end_address =
                                            module.base_address.0 + module.size as u64;
                                        builder.push_record(vec![
                                            format!("{:#018x}  ", module.base_address),
                                            format!("{:#018x}  ", VirtAddr(end_address)),
                                            format!("{}  ", module.short_name),
                                            module.name,
                                        ]);
                                    }

                                    let mut table = builder.build();
                                    table
                                        .with(tabled::settings::Style::empty())
                                        .with(Padding::zero());
                                    println!("{}\n", table);
                                }
                                Err(e) => {
                                    error!("failed to list modules: {}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Attach) => {
                            let pid_str = require_arg!(parts, 1, ReplCommand::Attach);
                            match pid_str.parse::<u64>() {
                                Ok(pid) => match debugger.attach(pid) {
                                    Ok(name) => {
                                        *shared_symbols.write().unwrap() =
                                            debugger.current_symbol_index();
                                        *shared_types.write().unwrap() =
                                            debugger.current_types_index();
                                        println!("attached to {} (PID {})\n", name, pid);
                                    }
                                    Err(e) => {
                                        error!("failed to attach: {}", e);
                                    }
                                },
                                Err(_) => {
                                    error!("invalid PID: {}", pid_str);
                                }
                            }
                        }
                        Ok(ReplCommand::Detach) => {
                            if debugger.current_process.is_none() {
                                error!("not attached to any process");
                            } else {
                                debugger.detach();
                                *shared_symbols.write().unwrap() = debugger.current_symbol_index();
                                *shared_types.write().unwrap() = debugger.current_types_index();
                                println!("detached, now in kernel context\n");
                            }
                        }
                        Ok(ReplCommand::Registers) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };

                            let read_reg = |name: &str| -> String {
                                register_map
                                    .read_u64(name, &regs)
                                    .map(|v| format!("{:#018x}", VirtAddr(v)))
                                    .unwrap_or_else(|_| "N/A".to_string())
                            };

                            println!(
                                "rax={}  rbx={}  rcx={}",
                                read_reg("rax"),
                                read_reg("rbx"),
                                read_reg("rcx")
                            );
                            println!(
                                "rdx={}  rsi={}  rdi={}",
                                read_reg("rdx"),
                                read_reg("rsi"),
                                read_reg("rdi")
                            );
                            println!(
                                "rsp={}  rbp={}  rip={}",
                                read_reg("rsp"),
                                read_reg("rbp"),
                                read_reg("rip")
                            );
                            println!(
                                "r8 ={}  r9 ={}  r10={}",
                                read_reg("r8"),
                                read_reg("r9"),
                                read_reg("r10")
                            );
                            println!(
                                "r11={}  r12={}  r13={}",
                                read_reg("r11"),
                                read_reg("r12"),
                                read_reg("r13")
                            );
                            println!(
                                "r14={}  r15={}  rflags={}",
                                read_reg("r14"),
                                read_reg("r15"),
                                read_reg("eflags")
                            );
                            println!();

                            println!(
                                "cr0={}  cr2={}  cr3={}",
                                read_reg("cr0"),
                                read_reg("cr2"),
                                read_reg("cr3")
                            );
                            println!("cr4={}  cr8={}", read_reg("cr4"), read_reg("cr8"));
                            println!();

                            // println!("dr0={}  dr1={}  dr2={}", read_reg("dr0"), read_reg("dr1"), read_reg("dr2"));
                            // println!("dr3={}  dr6={}  dr7={}", read_reg("dr3"), read_reg("dr6"), read_reg("dr7"));
                            // println!();

                            println!(
                                "cs={}  ds={}  es={}",
                                read_reg("cs"),
                                read_reg("ds"),
                                read_reg("es")
                            );
                            println!(
                                "fs={}  gs={}  ss={}",
                                read_reg("fs"),
                                read_reg("gs"),
                                read_reg("ss")
                            );
                            println!();
                        }
                        Ok(ReplCommand::Si) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            // check if we're at a breakpoint address and temporarily remove it
                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };
                            let rip = register_map.read_u64("rip", &regs).unwrap_or(0);

                            let bp_at_rip = breakpoints
                                .list()
                                .iter()
                                .find(|bp| bp.enabled && bp.address.0 == rip)
                                .map(|bp| bp.id);

                            // temporarily disable breakpoint at current rip if present
                            if let Some(bp_id) = bp_at_rip
                                && let Err(e) = breakpoints.disable(&mut client, bp_id)
                            {
                                error!("failed to disable breakpoint for step: {}", e);
                                continue;
                            }

                            if let Err(e) = client.step() {
                                // reenable breakpoint on error
                                if let Some(bp_id) = bp_at_rip {
                                    let _ = breakpoints.enable(&mut client, bp_id);
                                }
                                error!("failed to step: {:?}", e);
                                continue;
                            }

                            if let Err(e) = client.wait_for_stop() {
                                // reenable breakpoint on error
                                if let Some(bp_id) = bp_at_rip {
                                    let _ = breakpoints.enable(&mut client, bp_id);
                                }
                                error!("failed to wait after step: {:?}", e);
                                continue;
                            }

                            // reenable the breakpoint after stepping
                            if let Some(bp_id) = bp_at_rip
                                && let Err(e) = breakpoints.enable(&mut client, bp_id)
                            {
                                error!("failed to re-enable breakpoint after step: {}", e);
                            }

                            if let Err(e) = breakpoints.refresh_enabled(&mut client) {
                                error!("failed to refresh breakpoints after step: {}", e);
                            }

                            if let Ok(tid) = client.get_stopped_thread_id() {
                                current_thread = tid;
                            }

                            println!();
                            print_break_info(&mut client, &register_map, debugger, &current_thread);
                        }
                        Ok(ReplCommand::Thread) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            let thread_id = require_arg!(parts, 1, ReplCommand::Thread);

                            let threads = match client.get_thread_list() {
                                Ok(t) => t,
                                Err(e) => {
                                    error!("failed to get thread list: {:?}", e);
                                    continue;
                                }
                            };

                            if !threads.iter().any(|t| t == thread_id) {
                                error!(
                                    "thread '{}' not found (use 'lt' to list threads)",
                                    thread_id
                                );
                                continue;
                            }

                            if let Err(e) = client.set_current_thread(thread_id) {
                                error!("failed to switch thread: {:?}", e);
                                continue;
                            }

                            current_thread = thread_id.to_string();
                            println!("switched to thread {}\n", current_thread);
                        }
                        Ok(ReplCommand::Bp) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            let addr_str = require_arg!(parts, 1, ReplCommand::Bp);
                            let arg = DebuggerArgument::new(addr_str);
                            let address = match arg.try_resolve(debugger) {
                                Ok(a) => a,
                                Err(e) => {
                                    error!("{}", e);
                                    continue;
                                }
                            };

                            let symbol = debugger
                                .symbols
                                .find_closest_symbol_for_address(debugger.current_dtb(), address)
                                .map(|(module, sym, offset)| {
                                    if offset == 0 {
                                        format!("{}!{}", module, sym)
                                    } else {
                                        format!("{}!{}+{:#x}", module, sym, offset)
                                    }
                                });

                            let target_cr3 = debugger.current_process_info.as_ref().map(|p| p.dtb);

                            match breakpoints.add(&mut client, address, target_cr3, symbol.clone())
                            {
                                Ok(id) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    let scope = if let Some(target_cr3) = target_cr3 {
                                        format!(" (process-specific, CR3={:#x})", target_cr3)
                                    } else {
                                        " (global)".to_string()
                                    };
                                    println!(
                                        "breakpoint {} set at {}{}{}\n",
                                        format!("#{}", id).cyan(),
                                        format!("{:#x}", address).yellow(),
                                        symbol
                                            .map(|s| format!(" ({})", s))
                                            .unwrap_or_default()
                                            .green(),
                                        scope.bright_black()
                                    );
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Bl) => {
                            let bps = breakpoints.list();
                            if bps.is_empty() {
                                println!("no breakpoints set\n");
                            } else {
                                let mut builder = Builder::default();
                                builder.push_record(vec![
                                    "ID".to_string(),
                                    "Status".to_string(),
                                    "Address".to_string(),
                                    "Symbol".to_string(),
                                    "Scope".to_string(),
                                ]);

                                for bp in bps {
                                    let status = if bp.enabled { "enabled" } else { "disabled" };
                                    let scope = bp
                                        .target_cr3
                                        .map(|cr3| format!("CR3={:#x}", cr3))
                                        .unwrap_or_else(|| "global".to_string());

                                    builder.push_record(vec![
                                        format!("{}   ", bp.id),
                                        format!("{}  ", status),
                                        format!("{:#018x}  ", bp.address),
                                        format!("{}  ", bp.symbol.as_deref().unwrap_or("-")),
                                        scope,
                                    ]);
                                }

                                let mut table = builder.build();
                                table
                                    .with(tabled::settings::Style::empty())
                                    .with(Padding::zero());
                                println!("{}\n", table);
                            }
                        }
                        Ok(ReplCommand::Bc) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            let id_str = require_arg!(parts, 1, ReplCommand::Bc);
                            let id: u32 = match id_str.parse() {
                                Ok(i) => i,
                                Err(_) => {
                                    error!("invalid breakpoint ID: {}", id_str);
                                    continue;
                                }
                            };

                            match breakpoints.remove(&mut client, id) {
                                Ok(()) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    println!("breakpoint #{} cleared\n", id);
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Bd) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            let id_str = require_arg!(parts, 1, ReplCommand::Bd);
                            let id: u32 = match id_str.parse() {
                                Ok(i) => i,
                                Err(_) => {
                                    error!("invalid breakpoint ID: {}", id_str);
                                    continue;
                                }
                            };

                            match breakpoints.disable(&mut client, id) {
                                Ok(()) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    println!("breakpoint #{} disabled\n", id);
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        Ok(ReplCommand::Be) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            let id_str = require_arg!(parts, 1, ReplCommand::Be);
                            let id: u32 = match id_str.parse() {
                                Ok(i) => i,
                                Err(_) => {
                                    error!("invalid breakpoint ID: {}", id_str);
                                    continue;
                                }
                            };

                            match breakpoints.enable(&mut client, id) {
                                Ok(()) => {
                                    update_breakpoint_cache!(breakpoints, shared_breakpoints);
                                    println!("breakpoint #{} enabled\n", id);
                                }
                                Err(e) => {
                                    error!("{}", e);
                                }
                            }
                        }
                        // TODO look into using UNWIND info?
                        Ok(ReplCommand::K) => {
                            if client.is_running {
                                error!("VM is running");
                                continue;
                            }

                            let frame_limit: Option<usize> =
                                parts.get(1).and_then(|s| s.parse().ok());

                            if let Err(e) = client.set_current_thread(&current_thread) {
                                error!("failed to set thread context: {:?}", e);
                                continue;
                            }

                            let regs = match client.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    continue;
                                }
                            };

                            let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
                            let rsp = register_map.read_u64("rsp", &regs).unwrap_or(0);
                            let cr3 = register_map.read_u64("cr3", &regs).unwrap_or(0);

                            let cr3_masked = cr3 & 0x000F_FFFF_FFFF_F000;
                            let kernel_dtb_masked =
                                debugger.guest.ntoskrnl.dtb() & 0x000F_FFFF_FFFF_F000;
                            let is_kernel = cr3_masked == kernel_dtb_masked;

                            // get module ranges for validating return addresses
                            let modules = if is_kernel {
                                debugger
                                    .guest
                                    .get_kernel_modules(&debugger.kvm, &debugger.symbols)
                                    .unwrap_or_default()
                            } else if let Some(ref proc_info) = debugger.current_process_info {
                                debugger
                                    .guest
                                    .get_process_modules(
                                        &debugger.kvm,
                                        &debugger.symbols,
                                        proc_info,
                                    )
                                    .unwrap_or_default()
                            } else {
                                Vec::new()
                            };

                            let is_code_addr = |addr: u64| -> bool {
                                modules.iter().any(|m| {
                                    let start = m.base_address.0;
                                    let end = start + m.size as u64;
                                    addr >= start && addr < end
                                })
                            };

                            let mem = debugger.get_current_process().memory(&debugger.kvm);

                            let resolve_symbol = |addr: u64| -> String {
                                if is_kernel {
                                    debugger
                                        .guest
                                        .ntoskrnl
                                        .closest_symbol(&debugger.symbols, VirtAddr(addr))
                                        .map(
                                            |(s, o)| {
                                                if o == 0 { s } else { format!("{}+{:#x}", s, o) }
                                            },
                                        )
                                        .unwrap_or_else(|_| format!("{:#x}", addr))
                                } else {
                                    debugger
                                        .symbols
                                        .find_closest_symbol_for_address(
                                            debugger.current_dtb(),
                                            VirtAddr(addr),
                                        )
                                        .map(|(module, sym, offset)| {
                                            if offset == 0 {
                                                format!("{}!{}", module, sym)
                                            } else {
                                                format!("{}!{}+{:#x}", module, sym, offset)
                                            }
                                        })
                                        .unwrap_or_else(|| format!("{:#x}", addr))
                                }
                            };

                            let mut frames: Vec<(usize, u64, u64, String)> = Vec::new();
                            const MAX_FRAMES: usize = 64;
                            const STACK_SCAN_SIZE: usize = 0x1000;

                            // frame 0 is current RIP
                            frames.push((0, rsp, rip, resolve_symbol(rip)));

                            let mut stack_data = vec![0u8; STACK_SCAN_SIZE];
                            if mem.read_bytes(VirtAddr(rsp), &mut stack_data).is_ok() {
                                // scan for potential return addresses
                                for offset in (0..STACK_SCAN_SIZE - 8).step_by(8) {
                                    if frames.len() >= MAX_FRAMES {
                                        break;
                                    }

                                    let potential_addr = u64::from_le_bytes(
                                        stack_data[offset..offset + 8].try_into().unwrap(),
                                    );

                                    if potential_addr == rip {
                                        continue;
                                    }

                                    if is_code_addr(potential_addr) {
                                        let stack_addr = rsp + offset as u64;
                                        let symbol = resolve_symbol(potential_addr);
                                        frames.push((
                                            frames.len(),
                                            stack_addr,
                                            potential_addr,
                                            symbol,
                                        ));
                                    }
                                }
                            }

                            let total_frames = frames.len();
                            let display_count =
                                frame_limit.unwrap_or(total_frames).min(total_frames);
                            let remaining = total_frames.saturating_sub(display_count);

                            let mut builder = Builder::default();
                            builder.push_record(vec![
                                "#".to_string(),
                                "Child SP".to_string(),
                                "Return addr".to_string(),
                                "Symbol".to_string(),
                            ]);

                            for (num, sp, addr, sym) in frames.into_iter().take(display_count) {
                                builder.push_record(vec![
                                    format!("{:02}  ", num),
                                    format!("{:#018x}  ", VirtAddr(sp)),
                                    format!("{:#018x}  ", VirtAddr(addr)),
                                    sym,
                                ]);
                            }

                            let mut table = builder.build();
                            table
                                .with(tabled::settings::Style::empty())
                                .with(Padding::zero());
                            println!("{}", table);

                            if remaining > 0 {
                                println!("{}", format!("+{} more", remaining).bright_black());
                            }
                            println!();
                        }
                        Ok(ReplCommand::Status) => {
                            if client.is_running {
                                println!("VM is running\n");
                            } else {
                                if let Err(e) = client.set_current_thread(&current_thread) {
                                    error!("failed to set thread context: {:?}", e);
                                    continue;
                                }
                                print_break_info(
                                    &mut client,
                                    &register_map,
                                    debugger,
                                    &current_thread,
                                );
                            }
                        }
                        Err(_) => {
                            println!(
                                "unknown command: '{}' (try pressing tab to see available commands)\n",
                                cmd_str
                            );
                        }
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

                if client.is_running {
                    if let Err(e) = client.interrupt() {
                        error!("failed to interrupt: {:?}", e);
                        continue;
                    }

                    if let Ok(thread_id) = client.get_stopped_thread_id() {
                        current_thread = thread_id;
                    }
                    println!();
                    print_break_info(&mut client, &register_map, debugger, &current_thread);
                } else {
                    error!("VM is already paused");
                }
            }
        }
    }

    if !client.is_running {
        let _ = client.continue_execution();
    }

    Ok(())
}
