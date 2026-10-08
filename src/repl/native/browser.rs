//! The code and memory browser, `browse` or F2 at the prompt: a screen
//! surface over the pane that pages through disassembly and memory, follows
//! branches and pointers, finds bytes, and sets and clears breakpoints and
//! watchpoints, then leaves the pane as it was.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

mod typed;

use reedline::{Completer, Suggestion};
use tern_sdk::keys::Key;
use tern_sdk::ui::{self, Align, Gap, Mark, Span, TextNode, Wrap};
use tern_sdk::wire::{Event, RevealAt};
use tern_sdk::{Input, Node, Session, SurfaceOptions, View};

use super::completions::{Popup, PopupKey};
use super::frames::{ARM64_GRID, X64_GRID};
use super::memory::Runs;
use super::{
    DIM, MNEMONIC, MUTED, NUMBER, ROLE, STRING, STRONG, STYLESHEET, TYPE, addr, code, connect,
    span, symbol,
};
use crate::dbg_backend::DebugCapability;
use crate::disasm::{DisasmRow, OperandKind, decode_code, disasm_formatter};
use crate::expr::Expr;
use crate::memory::read_page_chunks;
use crate::output;
use crate::repl::{MyCompleter, ReplState, TargetLoan};
use crate::triage_report::time::filetime_to_iso;
use crate::types::VirtAddr;
use crate::unwind::{format_symbol, resolve_thread_trace_context, try_format_symbol};
use typed::{Kind, Typed};

/// What the browser shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    Code,
    Memory,
}

impl Pane {
    fn name(self) -> &'static str {
        match self {
            Pane::Code => "code",
            Pane::Memory => "memory",
        }
    }

    fn other(self) -> Self {
        match self {
            Pane::Code => Pane::Memory,
            Pane::Memory => Pane::Code,
        }
    }
}

/// How the memory pane lays a row out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    /// Sixteen bytes in hex and as text, with a byte cursor.
    Bytes,
    /// One pointer, its bytes as text and the symbol it points into.
    Pointers,
}

impl Layout {
    fn width(self) -> u64 {
        match self {
            Layout::Bytes => 16,
            Layout::Pointers => POINTER,
        }
    }
}

/// Instructions decoded at a time on each side of where the cursor goes.
const CODE_CHUNK: usize = 64;
/// Bytes of memory read at a time on each side of the cursor.
const MEMORY_CHUNK: u64 = 1024;
/// How close, in rows, the cursor comes to an end before more is read.
const MARGIN: usize = 16;
/// The most instructions kept; past it the end away from the cursor goes.
const ROW_LIMIT: usize = 768;
/// The most bytes of memory kept, likewise.
const MEMORY_LIMIT: u64 = 6144;
/// The widest byte column: eight bytes.
const HEX_WIDTH: usize = 8 * 3 - 1;
const POINTER: u64 = 8;
/// How far a find looks at a time; `n` goes on from where it stopped.
const FIND_RANGE: usize = 1 << 20;
/// How long a look for Escape between find steps waits: past the SDK's
/// 30 ms for a lone ESC byte to count as the key.
const ESCAPE_WAIT: Duration = Duration::from_millis(40);
/// How much of it a find reads between looks for Escape and redraws.
const FIND_STEP: usize = 64 << 10;
/// How many characters the inspector's strings show.
const STRING_PREVIEW: usize = 32;
/// The inspector's label column, and the column its numbers align right
/// in: as wide as the widest, `-9223372036854775808`.
const LABEL_WIDTH: usize = 6;
const VALUE_WIDTH: usize = 20;
/// The widest a typed view's name and type columns grow, so a long name
/// doesn't push every value off the pane.
const NAME_WIDTH: usize = 36;
const TYPE_WIDTH: usize = 28;
/// The frames the stack beside the code walks, and the widest its lines
/// grow.
const STACK_FRAMES: usize = 32;
const CONTEXT_WIDTH: usize = 44;
/// The key of the registers and stack beside the code.
const CONTEXT_KEY: &str = "context";
/// What a run from the browser changed: the warning color in a highlight,
/// so a changed number stands apart from the numbers around it, which
/// share the warning color's hue in a light theme.
const CHANGED_TINT: &str = "warning mark";
/// FILETIMEs from 1990 to 2100: a value in this range reads as a time.
const PLAUSIBLE_FILETIME: std::ops::Range<u64> = 122_756_256_000_000_000..157_469_184_000_000_000;
/// How long a rebuilt listing takes Tern to lay out.
const LAYOUT_WAIT: Duration = Duration::from_millis(60);
/// The keys of the row under `main`, the rows' column in it and the
/// inspector beside them.
const SPLIT_KEY: &str = "split";
const ROWS_KEY: &str = "rows";
const INSPECTOR_KEY: &str = "inspector";
/// The input field's key, and its id in the dock.
const FIELD_KEY: &str = "field";
const FIELD: &str = "dock.field";

impl Search {
    fn progress(&self) -> String {
        format!(
            "finding {} from {:#x}: {} of {} KiB, Esc stops",
            self.label,
            self.from,
            self.done >> 10,
            FIND_RANGE >> 10
        )
    }
}

/// What a click on a row reports: a code or memory row's address, or a
/// typed row's index.
#[derive(Clone)]
enum Msg {
    Select(u64),
    Follow(u64),
    SelectRow(usize),
    FollowRow(usize),
    /// A frame of the stack beside the code.
    Frame(usize),
    /// A register's value: browse where it points.
    Goto(u64),
}

thread_local! {
    /// The browser's session while it runs the target, for the REPL's wait
    /// for a stop to poll for the keys that break in: the terminal is raw,
    /// so Ctrl+C is a key, not a signal.
    static RUNNING: RefCell<Option<Session<Msg>>> = const { RefCell::new(None) };
}

/// Whether the browser is running the target: it says so itself.
pub fn running() -> bool {
    RUNNING.with(|running| running.borrow().is_some())
}

/// Whether Escape or Ctrl+C came in while the browser runs the target,
/// read without waiting; other keys meanwhile are dropped. False when the
/// browser isn't running it.
pub fn break_requested() -> bool {
    RUNNING.with(|running| {
        let mut running = running.borrow_mut();
        let Some(session) = running.as_mut() else {
            return false;
        };
        let mut requested = false;
        while let Ok(Some(input)) = session.next(Some(Duration::ZERO)) {
            if let Input::Key(key) = input {
                requested |= key.is("escape") || key.is("ctrl+c");
            }
        }
        requested
    })
}

/// What a browse leaves for the pane: what the breakpoint commands it ran
/// printed, and whether it ran the target, whose stop the pane then shows.
pub struct Record {
    pub lines: Vec<String>,
    pub ran: bool,
}

/// Browse from `address` in `pane`, or in the pane for its page: code when
/// it is executable. Returns what the pane should show, or why it could
/// not open.
pub fn run(state: &mut ReplState<'_>, address: u64, pane: Option<Pane>) -> Result<Record, String> {
    let mut browser = Browser::new(state);
    let pane = pane.unwrap_or_else(|| browser.pane_for(address));
    browser.go(pane, address)?;
    let mut session = Some(connect::<Msg>().ok_or("Tern did not open the browser")?);
    browse(&mut session, &mut browser);
    // Restores the terminal for the line editor whatever happened.
    if let Some(session) = session {
        let _ = session.close();
    }
    Ok(Record {
        lines: browser.record,
        ran: browser.ran,
    })
}

/// The browser's loop over `slot`'s session, which a run hands to the
/// REPL's wait for a stop and takes back after it.
fn browse(slot: &mut Option<Session<Msg>>, browser: &mut Browser<'_, '_>) -> Option<()> {
    let surface = slot
        .as_mut()?
        .open(
            SurfaceOptions::screen()
                .role(format!("{ROLE}.browser"))
                .keep(false),
        )
        .ok()?;
    let _ = slot.as_mut()?.stylesheet(surface, ROLE, Some(STYLESHEET));
    loop {
        let session = slot.as_mut()?;
        session.render(surface, browser.view()).ok()?;
        match browser.scroll.take() {
            Some(Scroll::Jump) => {
                // Tern lays out rebuilt rows before it can scroll to one
                // below the first screen; until then the reveal is lost.
                let _ = session.pump(LAYOUT_WAIT);
                // The cursor a third of the way down, its lead-in above it.
                let id = browser.cursor_row_id(page() / 3);
                let _ = session.reveal(surface, &id, RevealAt::Start);
            }
            Some(Scroll::Follow) => {
                let id = browser.cursor_row_id(0);
                let _ = session.reveal(surface, &id, RevealAt::Nearest);
            }
            None => {}
        }
        if browser.focus_field {
            browser.focus_field = false;
            let _ = session.focus(surface, Some(FIELD));
        }
        // A find goes a step at a time, each frame saying how far it got,
        // and Escape between steps stops it; other keys meanwhile are
        // dropped.
        if browser.search.is_some() {
            browser.search_step();
            if browser.search.is_some() && escape_pending(session) {
                browser.stop_search();
            }
            continue;
        }
        let outcome = match session.next(None).ok()?? {
            Input::Key(key) => browser.key(&key),
            Input::Msg(Msg::Select(address), _) => {
                browser.select(address);
                Outcome::Continue
            }
            Input::Msg(Msg::Follow(address), _) => {
                browser.select(address);
                browser.follow();
                Outcome::Continue
            }
            Input::Msg(Msg::SelectRow(index), _) => {
                browser.select_row(index);
                Outcome::Continue
            }
            Input::Msg(Msg::FollowRow(index), _) => {
                browser.select_row(index);
                browser.follow();
                Outcome::Continue
            }
            Input::Msg(Msg::Frame(index), _) => {
                browser.select_frame(index);
                Outcome::Continue
            }
            Input::Msg(Msg::Goto(address), _) => {
                browser.goto_value(address);
                Outcome::Continue
            }
            Input::Event(Event::Select(pick) | Event::Activate(pick)) => {
                browser.pick_completion(&pick.item);
                Outcome::Continue
            }
            Input::Event(_) => Outcome::Continue,
        };
        match outcome {
            Outcome::Continue => {}
            Outcome::Close => return Some(()),
            Outcome::Run(line) => {
                // Say it runs, then hand the keys to the wait for a stop.
                browser.note = Some("running: Esc or Ctrl+C breaks in".into());
                session.render(surface, browser.view()).ok()?;
                RUNNING.with(|running| *running.borrow_mut() = slot.take());
                browser.run_line(&line);
                *slot = RUNNING.with(|running| running.borrow_mut().take());
            }
        }
    }
}

/// Whether Escape (or Ctrl+C) came in since the last look; other input
/// meanwhile is dropped. A lone ESC byte stays undecided until a short
/// quiet tells it from the start of a sequence, so this waits that long.
fn escape_pending(session: &mut Session<Msg>) -> bool {
    let mut escape = false;
    while let Ok(Some(input)) = session.next(Some(ESCAPE_WAIT)) {
        if let Input::Key(key) = input {
            escape |= key.is("escape") || key.is("ctrl+c");
        }
    }
    escape
}

#[derive(PartialEq, Eq)]
enum Outcome {
    Continue,
    Close,
    /// Run the target with this command line: `p`, `t`, `gu`, `g`.
    Run(String),
}

/// How the next frame scrolls to the cursor.
enum Scroll {
    /// After a jump: the cursor a third of the way down.
    Jump,
    /// After a move: the least scrolling that shows it.
    Follow,
}

/// An instruction, with the symbol that starts at it.
struct CodeRow {
    row: DisasmRow,
    label: Option<String>,
}

/// The memory read around the cursor: the byte at `start + i` is
/// `data[i]`, read when `valid[i]`.
#[derive(Default)]
struct Memory {
    start: u64,
    data: Vec<u8>,
    valid: Vec<bool>,
    /// The symbol each read pointer-aligned value points into, by the
    /// value's address.
    symbols: HashMap<u64, String>,
    /// The byte under the cursor.
    cursor: u64,
}

impl Memory {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.data.len() as u64)
    }

    fn byte(&self, address: u64) -> Option<u8> {
        let index = usize::try_from(address.checked_sub(self.start)?).ok()?;
        self.valid.get(index).copied()?.then(|| self.data[index])
    }

    /// `N` bytes from `address`, when all were read.
    fn bytes<const N: usize>(&self, address: u64) -> Option<[u8; N]> {
        let mut bytes = [0; N];
        for (offset, byte) in bytes.iter_mut().enumerate() {
            *byte = self.byte(address.checked_add(offset as u64)?)?;
        }
        Some(bytes)
    }

    fn value(&self, address: u64) -> Option<u64> {
        self.bytes::<8>(address).map(u64::from_le_bytes)
    }
}

/// The field open in the dock, and the completions for what is typed.
struct Field {
    kind: FieldKind,
    draft: String,
    popup: Option<Popup>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Goto,
    Find,
    /// The type to read the memory at the cursor as.
    Type,
}

/// Where Backspace goes back to: a pane at an address, or a typed view as
/// it was left.
enum Place {
    At(Pane, u64),
    Typed {
        type_name: String,
        base: u64,
        open: std::collections::HashSet<String>,
        path: Option<String>,
    },
}

/// A find: what to look for, and where the next `n` starts.
struct Find {
    pattern: Vec<u8>,
    /// The pattern as typed, for notes.
    label: String,
    /// Where the last find left the cursor; `n` from there goes on at
    /// `from`, from anywhere else at the cursor.
    at: u64,
    from: u64,
}

/// A find under way, a step at a time.
struct Search {
    pattern: Vec<u8>,
    label: String,
    from: u64,
    /// How much of [`FIND_RANGE`] from `from` is searched.
    done: usize,
}

struct Browser<'s, 'a> {
    state: &'s mut ReplState<'a>,
    completer: MyCompleter,
    loan: TargetLoan,
    pane: Pane,
    layout: Layout,
    code: Vec<CodeRow>,
    /// The instruction under the cursor, an index into `code`.
    cursor: usize,
    memory: Memory,
    /// The memory read as a type, over the memory pane.
    typed: Option<Typed>,
    /// Where Backspace goes back to.
    history: Vec<Place>,
    field: Option<Field>,
    focus_field: bool,
    scroll: Option<Scroll>,
    find: Option<Find>,
    search: Option<Search>,
    /// The last thing said, under the rows.
    note: Option<String>,
    /// What the commands run printed, for the pane once the browser closes.
    record: Vec<String>,
    /// Breakpoint addresses, enabled or not.
    breakpoints: HashMap<u64, bool>,
    /// The ranges data breakpoints watch.
    watches: Vec<(u64, u64)>,
    /// The scope's instruction pointer.
    ip: Option<u64>,
    /// Whether the backend can run the target: not a dump's or `memory`'s.
    can_run: bool,
    /// The registers and stack beside the code; `r` hides them.
    context: Option<Context>,
    show_context: bool,
    /// The bytes the last run from the browser changed.
    changed_bytes: HashSet<u64>,
    /// Whether the browser ran the target, so the pane shows where it
    /// stopped once the browser closes.
    ran: bool,
}

/// The registers and stack beside the code, as the last stop left them.
struct Context {
    /// The frames, innermost first: where each one is, and its symbol.
    frames: Vec<(u64, String)>,
    /// Each frame's registers: the context's own for the first, what the
    /// walk recovered for the callers'.
    registers: Vec<HashMap<String, u64>>,
    /// The frame whose registers show, and which the code marks.
    frame: usize,
    /// The registers the last run from the browser changed.
    changed: HashSet<String>,
    /// Why the context could not be read.
    error: Option<String>,
}

impl<'s, 'a> Browser<'s, 'a> {
    fn new(state: &'s mut ReplState<'a>) -> Self {
        let ip = state.ctx.target.builtin_variable_value("ip");
        let can_run =
            state.ctx.backend.capabilities().iter().any(|entry| {
                entry.capability == DebugCapability::ExecutionControl && entry.supported
            });
        let completer = MyCompleter {
            caches: state.caches.clone(),
            target: TargetLoan::default(),
        };
        let loan = completer.target.clone();
        let mut browser = Self {
            state,
            completer,
            loan,
            pane: Pane::Code,
            layout: Layout::Bytes,
            code: Vec::new(),
            cursor: 0,
            memory: Memory::default(),
            typed: None,
            history: Vec::new(),
            field: None,
            focus_field: false,
            scroll: None,
            find: None,
            search: None,
            note: None,
            record: Vec::new(),
            breakpoints: HashMap::new(),
            watches: Vec::new(),
            ip,
            can_run,
            context: None,
            show_context: true,
            changed_bytes: HashSet::new(),
            ran: false,
        };
        browser.refresh_breakpoints();
        browser.read_context(None);
        browser
    }

    fn refresh_breakpoints(&mut self) {
        let list = self.state.ctx.breakpoints.list();
        self.breakpoints = list
            .iter()
            .map(|breakpoint| (breakpoint.address.0, breakpoint.enabled))
            .collect();
        self.watches = list
            .iter()
            .filter_map(|breakpoint| {
                let hardware = breakpoint.hardware.as_ref()?;
                Some((breakpoint.address.0, u64::from(hardware.len)))
            })
            .collect();
    }

    /// Read the registers and stack of the context, marking the registers
    /// that differ from `before`, the first frame's before a run.
    fn read_context(&mut self, before: Option<&HashMap<String, u64>>) {
        let context = match self.state.ctx.recovered_backtrace(STACK_FRAMES) {
            Ok((trace, seed, _)) => {
                let changed = before.map_or_else(HashSet::new, |before| {
                    seed.iter()
                        .filter(|(name, value)| before.get(*name).is_some_and(|was| was != *value))
                        .map(|(name, _)| name.clone())
                        .collect()
                });
                let frames = trace
                    .frames
                    .iter()
                    .map(|frame| (frame.frame.ip, frame.frame.symbol.clone()))
                    .collect();
                let mut registers: Vec<HashMap<String, u64>> = trace
                    .frames
                    .into_iter()
                    .map(|frame| frame.registers)
                    .collect();
                match registers.first_mut() {
                    Some(first) => *first = seed,
                    None => registers.push(seed),
                }
                Context {
                    frames,
                    registers,
                    frame: 0,
                    changed,
                    error: None,
                }
            }
            Err(error) => Context {
                frames: Vec::new(),
                registers: Vec::new(),
                frame: 0,
                changed: HashSet::new(),
                error: Some(error.to_string()),
            },
        };
        self.context = Some(context);
    }

    /// Show frame `index`'s registers, and its code with the cursor there.
    fn select_frame(&mut self, index: usize) {
        let Some(context) = &mut self.context else {
            return;
        };
        let Some(&(ip, _)) = context.frames.get(index) else {
            return;
        };
        context.frame = index;
        if self.pane == Pane::Code
            && let Some(row) = self.code.iter().position(|row| row.row.ip == ip)
        {
            self.cursor = row;
            self.scroll = Some(Scroll::Follow);
        } else {
            self.jump(Pane::Code, ip);
        }
    }

    /// A click on a register's value: browse where it points.
    fn goto_value(&mut self, value: u64) {
        if self.points_somewhere(value) {
            self.jump(self.pane_for(value), value);
        } else {
            self.note = Some(format!("{value:#x} points nowhere mapped"));
        }
    }

    /// The command a run key stands for, WinDbg's keys: F5 `g`, F10 `p`,
    /// F11 `t`, Shift+F11 `gu`, and F7 or Ctrl+F10 `g` to the cursor.
    fn run_key(&mut self, key: &Key) -> Option<Outcome> {
        let line = if key.is("f5") {
            "g".to_owned()
        } else if key.is("f10") {
            "p".to_owned()
        } else if key.is("f11") {
            "t".to_owned()
        } else if key.is("shift+f11") {
            "gu".to_owned()
        } else if key.is("f7") || key.is("ctrl+f10") {
            match (self.pane, self.here()) {
                (Pane::Code, Some(here)) => format!("g {here:#x}"),
                _ => {
                    self.note = Some("run to the cursor is for code".into());
                    return Some(Outcome::Continue);
                }
            }
        } else {
            return None;
        };
        if !self.can_run {
            self.note = Some(format!(
                "the {} backend cannot run the target",
                self.state.ctx.backend.name()
            ));
            return Some(Outcome::Continue);
        }
        Some(Outcome::Run(line))
    }

    /// Run `line` as the prompt would, then show where the target stopped:
    /// the code follows the instruction pointer, and the registers, bytes
    /// and fields the run changed are marked.
    fn run_line(&mut self, line: &str) {
        let before = self
            .context
            .as_ref()
            .and_then(|context| context.registers.first().cloned());
        let (result, text) = output::capture(|| self.state.dispatch_line(line));
        let text = text.trim().to_owned();
        self.ran = true;
        self.ip = self.state.ctx.target.builtin_variable_value("ip");
        self.refresh_breakpoints();
        self.read_context(before.as_ref());
        let session = &*self.state.ctx;
        if let Some(typed) = &mut self.typed {
            typed.read(session);
        }
        self.reread_memory();
        if self.pane == Pane::Code
            && let Some(ip) = self.ip
        {
            match self.code.iter().position(|row| row.row.ip == ip) {
                Some(row) => {
                    self.cursor = row;
                    self.scroll = Some(Scroll::Follow);
                }
                None => {
                    if let Err(error) = self.go(Pane::Code, ip) {
                        self.note = Some(error);
                    }
                }
            }
        }
        // An error, else the line saying why it stopped, else where.
        let said = text
            .lines()
            .map(str::trim)
            .find(|line| {
                line.starts_with("error")
                    || line.starts_with("Breakpoint")
                    || line.starts_with("Exception")
            })
            .map(str::to_owned);
        let ran = match line {
            "p" => "stepped over",
            "t" => "stepped into",
            "gu" => "stepped out",
            "g" => "ran",
            _ => "ran to the cursor",
        };
        self.note = match (result, said) {
            (Err(error), _) => Some(error.to_string()),
            (Ok(_), Some(said)) => Some(said),
            (Ok(_), None) => {
                let target = &self.state.ctx.target;
                let trace = resolve_thread_trace_context(target, target.current_dtb());
                self.ip.map(|ip| {
                    let at =
                        try_format_symbol(target, &trace, ip).unwrap_or_else(|| format!("{ip:#x}"));
                    format!("{ran}: now at {at}")
                })
            }
        };
    }

    /// Read the memory shown again, marking the bytes that changed.
    fn reread_memory(&mut self) {
        let (start, end, cursor) = (self.memory.start, self.memory.end(), self.memory.cursor);
        if end <= start {
            return;
        }
        let mut fresh = self.read_memory(start, end);
        fresh.cursor = cursor;
        self.changed_bytes = (start..end)
            .filter(|&address| {
                matches!(
                    (self.memory.byte(address), fresh.byte(address)),
                    (Some(was), Some(now)) if was != now
                )
            })
            .collect();
        self.memory = fresh;
    }

    /// The address under the cursor.
    fn here(&self) -> Option<u64> {
        match self.pane {
            Pane::Code => self.code.get(self.cursor).map(|row| row.row.ip),
            Pane::Memory if let Some(typed) = &self.typed => typed.row().map(|row| row.address),
            Pane::Memory => Some(self.memory.cursor),
        }
    }

    /// Show `pane` at `address`, leaving the view as it was when nothing
    /// there can be read. Memory shows as bytes or pointers: a typed view
    /// comes from [`go_typed`](Self::go_typed).
    fn go(&mut self, pane: Pane, address: u64) -> Result<(), String> {
        match pane {
            Pane::Code => {
                let after = self.decode_after(address, CODE_CHUNK * 2);
                if after.is_empty() {
                    return Err(format!("cannot read code at {address:#x}"));
                }
                let before = self.decode_before(address, CODE_CHUNK);
                self.cursor = before.len();
                self.code = before
                    .into_iter()
                    .chain(after)
                    .map(|row| self.code_row(row))
                    .collect();
            }
            Pane::Memory => {
                let row = address & !15;
                let start = row.saturating_sub(MEMORY_CHUNK);
                let memory = self.read_memory(start, row.saturating_add(MEMORY_CHUNK));
                if memory.byte(address).is_none() {
                    return Err(format!("cannot read memory at {address:#x}"));
                }
                self.memory = Memory {
                    cursor: self.align(address),
                    ..memory
                };
                self.typed = None;
                self.changed_bytes.clear();
            }
        }
        self.pane = pane;
        self.scroll = Some(Scroll::Jump);
        Ok(())
    }

    /// Show the memory at `base` as `type_name`, its fields in `open` open
    /// and the cursor on the field at `path`, or the first.
    fn go_typed(
        &mut self,
        type_name: &str,
        base: u64,
        open: std::collections::HashSet<String>,
        path: Option<&str>,
    ) -> Result<(), String> {
        let session = &*self.state.ctx;
        let mut typed = Typed::new(session, type_name, base)?;
        if !open.is_empty() {
            typed.open = open;
            typed.read(session);
        }
        if let Some(index) =
            path.and_then(|path| typed.rows.iter().position(|row| row.path == path))
        {
            typed.cursor = index;
        }
        self.typed = Some(typed);
        self.pane = Pane::Memory;
        self.load_typed_cursor();
        self.scroll = Some(Scroll::Jump);
        Ok(())
    }

    /// Keep the memory cursor on the typed field under the cursor, reading
    /// the memory around it when it is not read yet, so the inspector shows
    /// the field's bytes.
    fn load_typed_cursor(&mut self) {
        let Some(address) = self
            .typed
            .as_ref()
            .and_then(Typed::row)
            .map(|row| row.address)
        else {
            return;
        };
        if self.memory.byte(address).is_none() {
            let row = address & !15;
            self.memory = self.read_memory(
                row.saturating_sub(MEMORY_CHUNK),
                row.saturating_add(MEMORY_CHUNK),
            );
        }
        self.memory.cursor = address;
    }

    /// Where the cursor is, to come back to.
    fn place(&self) -> Option<Place> {
        match (&self.typed, self.pane) {
            (Some(typed), Pane::Memory) => Some(Place::Typed {
                type_name: typed.type_name.clone(),
                base: typed.base,
                open: typed.open.clone(),
                path: typed.row().map(|row| row.path.clone()),
            }),
            _ => self.here().map(|here| Place::At(self.pane, here)),
        }
    }

    fn restore(&mut self, place: Place) -> Result<(), String> {
        match place {
            Place::At(pane, address) => self.go(pane, address),
            Place::Typed {
                type_name,
                base,
                open,
                path,
            } => self.go_typed(&type_name, base, open, path.as_deref()),
        }
    }

    /// The cursor's address for the memory layout: a pointer's start in
    /// the pointer layout.
    fn align(&self, address: u64) -> u64 {
        match self.layout {
            Layout::Bytes => address,
            Layout::Pointers => address & !(POINTER - 1),
        }
    }

    /// [`go`](Self::go) somewhere new, remembering where the cursor was.
    fn jump(&mut self, pane: Pane, address: u64) {
        self.jump_to(Place::At(pane, address));
    }

    /// [`restore`](Self::restore) `place`, remembering where the cursor was.
    fn jump_to(&mut self, place: Place) {
        let from = self.place();
        match self.restore(place) {
            Ok(()) => {
                self.history.extend(from);
                self.note = None;
            }
            Err(error) => self.note = Some(error),
        }
    }

    fn back(&mut self) {
        let Some(place) = self.history.pop() else {
            self.note = Some("nothing to go back to".into());
            return;
        };
        if let Err(error) = self.restore(place) {
            self.note = Some(error);
        }
    }

    fn select(&mut self, address: u64) {
        match self.pane {
            Pane::Code => {
                if let Some(index) = self.code.iter().position(|row| row.row.ip == address) {
                    self.cursor = index;
                }
            }
            Pane::Memory => self.memory.cursor = address,
        }
    }

    /// A click on typed row `index`.
    fn select_row(&mut self, index: usize) {
        if let Some(typed) = &mut self.typed
            && index < typed.rows.len()
        {
            typed.cursor = index;
            self.load_typed_cursor();
        }
    }

    /// Move `rows` rows, or in memory also `bytes` bytes.
    fn move_by(&mut self, rows: isize, bytes: isize) {
        match self.pane {
            Pane::Code => {
                let last = self.code.len().saturating_sub(1);
                self.cursor = self.cursor.saturating_add_signed(rows).min(last);
            }
            Pane::Memory if let Some(typed) = &mut self.typed => {
                let last = typed.rows.len().saturating_sub(1);
                typed.cursor = typed.cursor.saturating_add_signed(rows).min(last);
                self.load_typed_cursor();
                self.scroll = Some(Scroll::Follow);
                return;
            }
            Pane::Memory => {
                let step = rows as i64 * self.layout.width() as i64 + bytes as i64;
                let cursor = self.memory.cursor.saturating_add_signed(step);
                self.memory.cursor = self.align(cursor);
            }
        }
        self.load_more();
        self.scroll = Some(Scroll::Follow);
    }

    /// Read on past an end the cursor nears, and drop the far end of a
    /// listing grown past the limit.
    fn load_more(&mut self) {
        match self.pane {
            Pane::Code => {
                if self.cursor + MARGIN >= self.code.len()
                    && let Some(last) = self.code.last()
                {
                    let next = last.row.ip.wrapping_add(last.row.length as u64);
                    let rows = self.decode_after(next, CODE_CHUNK);
                    let rows: Vec<CodeRow> =
                        rows.into_iter().map(|row| self.code_row(row)).collect();
                    self.code.extend(rows);
                }
                if self.cursor < MARGIN
                    && let Some(first) = self.code.first()
                {
                    let rows = self.decode_before(first.row.ip, CODE_CHUNK);
                    self.cursor += rows.len();
                    let rows: Vec<CodeRow> =
                        rows.into_iter().map(|row| self.code_row(row)).collect();
                    self.code.splice(0..0, rows);
                }
                self.cursor -= trim(&mut self.code, self.cursor);
            }
            Pane::Memory => {
                let margin = MARGIN as u64 * self.layout.width();
                let (start, end) = (self.memory.start, self.memory.end());
                if self.memory.cursor.saturating_add(margin) >= end {
                    let more = self.read_memory(end, end.saturating_add(MEMORY_CHUNK));
                    self.memory.data.extend(more.data);
                    self.memory.valid.extend(more.valid);
                    self.memory.symbols.extend(more.symbols);
                }
                if self.memory.cursor < start.saturating_add(margin) && start > 0 {
                    let mut more = self.read_memory(start.saturating_sub(MEMORY_CHUNK), start);
                    more.data.extend(std::mem::take(&mut self.memory.data));
                    more.valid.extend(std::mem::take(&mut self.memory.valid));
                    more.symbols
                        .extend(std::mem::take(&mut self.memory.symbols));
                    more.cursor = self.memory.cursor;
                    self.memory = more;
                }
                self.trim_memory();
                let last = self.memory.end().saturating_sub(1);
                self.memory.cursor = self.memory.cursor.clamp(self.memory.start, last);
            }
        }
    }

    /// Drop the end of memory away from the cursor past [`MEMORY_LIMIT`],
    /// keeping rows whole.
    fn trim_memory(&mut self) {
        let memory = &mut self.memory;
        let excess = (memory.data.len() as u64).saturating_sub(MEMORY_LIMIT);
        if excess == 0 {
            return;
        }
        let middle = memory.start + memory.data.len() as u64 / 2;
        if memory.cursor > middle {
            let drop = excess.next_multiple_of(16) as usize;
            memory.data.drain(..drop);
            memory.valid.drain(..drop);
            memory.start += drop as u64;
        } else {
            memory.data.truncate(MEMORY_LIMIT as usize);
            memory.valid.truncate(MEMORY_LIMIT as usize);
        }
        let (start, end) = (memory.start, memory.end());
        memory
            .symbols
            .retain(|&address, _| (start..end).contains(&address));
    }

    /// Up to `count` instructions from `address`, as far as memory reads.
    fn decode_after(&self, address: u64, count: usize) -> Vec<DisasmRow> {
        let session = &*self.state.ctx;
        let target = &session.target;
        let machine = target.code_machine(VirtAddr(address));
        let mut bytes = vec![0u8; count * machine.max_instruction_bytes()];
        let read = session.read_masked_partial(VirtAddr(address), &mut bytes);
        bytes.truncate(read);
        let trace = resolve_thread_trace_context(target, target.current_dtb());
        let mut rows = decode_code(&bytes, address, Some(count), machine, |to| {
            format_symbol(target, &trace, to)
        });
        // An instruction cut off where the read ended is not one.
        let end = address.wrapping_add(read as u64);
        rows.retain(|row| row.ip.wrapping_add(row.length as u64) <= end);
        rows
    }

    /// Up to `count` instructions ending at `address`.
    fn decode_before(&self, address: u64, count: usize) -> Vec<DisasmRow> {
        self.state
            .ctx
            .disassemble_back(VirtAddr(address), count)
            .unwrap_or_default()
    }

    fn code_row(&self, row: DisasmRow) -> CodeRow {
        let target = &self.state.ctx.target;
        let label = target
            .symbols
            .find_closest_symbol_for_address(target.current_dtb(), VirtAddr(row.ip))
            .filter(|(_, _, offset)| *offset == 0)
            .map(|(module, name, _)| format!("{module}!{name}"));
        CodeRow { row, label }
    }

    /// The memory from `start` to `end`, a page at a time so one missing
    /// page leaves the rest, with the symbols its pointers point into.
    fn read_memory(&self, start: u64, end: u64) -> Memory {
        let session = &*self.state.ctx;
        let target = &session.target;
        let length = usize::try_from(end.saturating_sub(start)).unwrap_or(0);
        let (data, valid) = read_page_chunks(VirtAddr(start), length, |at, buf| {
            session.read_masked(at, buf)
        })
        .unwrap_or_else(|_| (vec![0; length], vec![false; length]));
        let mut memory = Memory {
            start,
            data,
            valid,
            ..Memory::default()
        };
        let trace = resolve_thread_trace_context(target, target.current_dtb());
        let first = start.next_multiple_of(POINTER);
        for address in (first..end.saturating_sub(POINTER - 1)).step_by(POINTER as usize) {
            if let Some(value) = memory.value(address)
                && let Some(name) = try_format_symbol(target, &trace, value)
            {
                memory.symbols.insert(address, name);
            }
        }
        memory
    }

    /// Where Enter goes from the cursor: an instruction's branch target or
    /// the memory it addresses, or the address a pointer holds.
    fn target(&self) -> Option<(Pane, u64)> {
        match self.pane {
            Pane::Code => {
                let row = &self.code.get(self.cursor)?.row;
                let operands = row.operands(&mut disasm_formatter());
                if let Some(to) = operands
                    .iter()
                    .find(|operand| operand.kind == OperandKind::Branch)
                    .and_then(|operand| operand.immediate)
                {
                    return Some((Pane::Code, to as u64));
                }
                if let Some(displacement) = operands
                    .iter()
                    .find(|operand| {
                        operand.kind == OperandKind::Memory
                            && operand.base.as_deref() == Some("rip")
                            && operand.index.is_none()
                    })
                    .and_then(|operand| operand.displacement)
                {
                    let next = row.ip.wrapping_add(row.length as u64);
                    return Some((Pane::Memory, next.wrapping_add_signed(displacement)));
                }
                operands
                    .iter()
                    .filter(|operand| operand.kind == OperandKind::Immediate)
                    .filter_map(|operand| operand.immediate)
                    .map(|value| value as u64)
                    .find(|&value| self.points_somewhere(value))
                    .map(|value| (self.pane_for(value), value))
            }
            Pane::Memory => {
                let value = self.memory.value(self.memory.cursor)?;
                self.points_somewhere(value)
                    .then(|| (self.pane_for(value), value))
            }
        }
    }

    /// Whether `value` is an address the page tables map.
    fn points_somewhere(&self, value: u64) -> bool {
        let target = &self.state.ctx.target;
        matches!(
            target
                .address_space(target.current_dtb())
                .virt_to_phys(VirtAddr(value)),
            Ok(Some(_))
        )
    }

    /// Code for an executable page, memory otherwise.
    fn pane_for(&self, address: u64) -> Pane {
        let target = &self.state.ctx.target;
        match target
            .address_space(target.current_dtb())
            .virt_to_phys(VirtAddr(address))
        {
            Ok(Some(translation)) if !translation.nx => Pane::Code,
            _ => Pane::Memory,
        }
    }

    fn follow(&mut self) {
        if self.pane == Pane::Memory && self.typed.is_some() {
            self.follow_field();
            return;
        }
        match self.target() {
            Some((pane, address)) => self.jump(pane, address),
            None => self.note = Some("nothing to follow here".into()),
        }
    }

    /// Enter on a typed field: a structure or an array opens or closes, a
    /// list link goes to the next record of the same type (CONTAINING_RECORD
    /// of its Flink) with the same fields open, and a pointer goes to what
    /// it points to, as its type when the PDB has it.
    fn follow_field(&mut self) {
        let session = &*self.state.ctx;
        let Some(typed) = &mut self.typed else {
            return;
        };
        let Some(row) = typed.row() else {
            return;
        };
        let (kind, raw, pointee, path) = (row.kind, row.raw, row.pointee.clone(), row.path.clone());
        match kind {
            Kind::Aggregate | Kind::Array | Kind::Flags => {
                typed.toggle(session);
                self.load_typed_cursor();
            }
            Kind::Link => match typed.next_record() {
                Ok(next) => {
                    let place = Place::Typed {
                        type_name: typed.type_name.clone(),
                        base: next,
                        open: typed.open.clone(),
                        path: Some(path),
                    };
                    self.jump_to(place);
                }
                Err(error) => self.note = Some(error),
            },
            Kind::Pointer | Kind::Scalar => match (raw, pointee) {
                (Some(0), _) if kind == Kind::Pointer => {
                    self.note = Some("the pointer is null".into())
                }
                (Some(value), Some(type_name)) if kind == Kind::Pointer => {
                    self.jump_to(Place::Typed {
                        type_name,
                        base: value,
                        open: Default::default(),
                        path: None,
                    });
                }
                (Some(value), _) if self.points_somewhere(value) => {
                    self.jump(self.pane_for(value), value);
                }
                _ => self.note = Some("nothing to follow here".into()),
            },
            Kind::Note => {}
        }
    }

    /// In code, set a breakpoint at the instruction under the cursor or
    /// clear the one there; in memory, set a write watchpoint on the
    /// cursor or clear the one watching it. Both with the commands that do
    /// it at the prompt, so `bp` refuses a row decoded from inside an
    /// instruction (a go-to into its middle, or a backward decode that
    /// guessed wrong) as it refuses the address typed.
    fn toggle_breakpoint(&mut self) {
        let Some(here) = self.here() else {
            return;
        };
        let list = self.state.ctx.breakpoints.list();
        let line = match self.pane {
            Pane::Code => match list.iter().find(|breakpoint| breakpoint.address.0 == here) {
                Some(breakpoint) => format!("bc {}", breakpoint.id),
                None => format!("bp {here:#x}"),
            },
            Pane::Memory => {
                let watching = list.iter().find(|breakpoint| {
                    breakpoint.hardware.as_ref().is_some_and(|hardware| {
                        let start = breakpoint.address.0;
                        (start..start + u64::from(hardware.len)).contains(&here)
                    })
                });
                match watching {
                    Some(breakpoint) => format!("bc {}", breakpoint.id),
                    // A typed field's own size, else the widest size the
                    // address is aligned to.
                    None => {
                        let field = self
                            .typed
                            .as_ref()
                            .and_then(Typed::row)
                            .map(|row| row.size as u64)
                            .filter(|size| [1, 2, 4, 8].contains(size) && here % size == 0);
                        let size = field.unwrap_or_else(|| {
                            [8, 4, 2, 1]
                                .into_iter()
                                .find(|size| here % size == 0)
                                .unwrap_or(1)
                        });
                        format!("ba w{size} {here:#x}")
                    }
                }
            }
        };
        let (result, text) = output::capture(|| self.state.dispatch_line(&line));
        let mut text = text.trim().to_owned();
        if let Err(error) = result {
            text = error.to_string();
        }
        self.note = text.lines().next().map(str::to_owned);
        if !text.is_empty() {
            self.record.push(text);
        }
        self.refresh_breakpoints();
    }

    fn open_field(&mut self, kind: FieldKind) {
        self.open_field_with(kind, String::new());
    }

    fn open_field_with(&mut self, kind: FieldKind, draft: String) {
        self.field = Some(Field {
            kind,
            draft,
            popup: None,
        });
        self.focus_field = true;
    }

    /// The completions for `draft`: an expression the way `?` completes its
    /// argument, a type the way `dt` does.
    fn completions(&mut self, kind: FieldKind, draft: &str) -> Vec<Suggestion> {
        let prefix = match kind {
            FieldKind::Goto | FieldKind::Find => "? ",
            FieldKind::Type => "dt ",
        };
        let line = format!("{prefix}{draft}");
        let (loan, completer) = (&self.loan, &mut self.completer);
        let mut suggestions = loan.lend(&self.state.ctx.target, || {
            completer.complete(&line, line.len())
        });
        for suggestion in &mut suggestions {
            suggestion.span.start = suggestion.span.start.saturating_sub(prefix.len());
            suggestion.span.end = suggestion.span.end.saturating_sub(prefix.len());
        }
        suggestions
    }

    /// Refill the popup for the word the draft ends in: it follows typing,
    /// and closes once the word ends.
    fn refill(&mut self) {
        let Some(field) = &self.field else {
            return;
        };
        let kind = field.kind;
        let draft = field.draft.clone();
        let keep = field
            .popup
            .as_ref()
            .and_then(Popup::selected_value)
            .map(str::to_owned);
        let in_word = draft
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_whitespace());
        let popup = if in_word && completes(kind, &draft) {
            let suggestions = self.completions(kind, &draft);
            Popup::open(suggestions, &draft, keep.as_deref())
        } else {
            None
        };
        if let Some(field) = &mut self.field {
            field.popup = popup;
        }
    }

    fn apply(&mut self, suggestion: &Suggestion) {
        let Some(field) = &mut self.field else {
            return;
        };
        let end = suggestion.span.end.min(field.draft.len());
        let start = suggestion.span.start.min(end);
        field.draft.replace_range(start..end, &suggestion.value);
        field.draft.truncate(start + suggestion.value.len());
        field.popup = None;
    }

    /// A click on a completion takes it.
    fn pick_completion(&mut self, item: &str) {
        let suggestion = self
            .field
            .as_ref()
            .and_then(|field| field.popup.as_ref())
            .and_then(|popup| popup.clicked(item))
            .cloned();
        if let Some(suggestion) = suggestion {
            self.apply(&suggestion);
        }
    }

    fn field_key(&mut self, key: &Key) {
        let Some(field) = &mut self.field else {
            return;
        };
        if let Some(popup) = &mut field.popup {
            match popup.key(key) {
                PopupKey::Moved => return,
                PopupKey::Close => {
                    field.popup = None;
                    return;
                }
                PopupKey::Take(suggestion) => {
                    self.apply(&suggestion);
                    return;
                }
                // The fields have no palette: typing narrows the list.
                PopupKey::More => return,
                PopupKey::Ignored => {}
            }
        }
        if key.is("escape") || key.is("ctrl+c") {
            self.field = None;
            return;
        }
        if key.is("enter") {
            if let Some(field) = self.field.take() {
                self.submit(field.kind, field.draft.trim());
            }
            return;
        }
        if key.is("tab") {
            let draft = field.draft.clone();
            let kind = field.kind;
            if !completes(kind, &draft) {
                return;
            }
            let mut suggestions = self.completions(kind, &draft);
            if suggestions.len() == 1 {
                let only = suggestions.remove(0);
                self.apply(&only);
            } else if let Some(field) = &mut self.field
                && !suggestions.is_empty()
            {
                field.popup = Some(Popup::new(suggestions, &draft, None));
            }
            return;
        }
        if key.is("right") || key.is("end") {
            let ghost = field
                .popup
                .as_ref()
                .map(|popup| popup.ghost().to_owned())
                .unwrap_or_default();
            field.draft.push_str(&ghost);
            field.popup = None;
            return;
        }
        if key.is("backspace") {
            field.draft.pop();
        } else if key.is("ctrl+u") {
            field.draft.clear();
        } else if key.name == "paste" {
            let text = key.text.as_deref().unwrap_or_default();
            field
                .draft
                .push_str(text.lines().next().unwrap_or_default());
        } else if let Some(text) = key.typed() {
            field.draft.push_str(text);
        } else {
            return;
        }
        self.refill();
    }

    fn submit(&mut self, kind: FieldKind, text: &str) {
        if text.is_empty() {
            // No type: back to the memory as bytes or pointers.
            if kind == FieldKind::Type
                && self.typed.is_some()
                && let Some(here) = self.here()
            {
                self.jump(Pane::Memory, here);
            }
            return;
        }
        match kind {
            FieldKind::Goto => {
                match Expr::eval_with_radix(text, &self.state.ctx.target, self.state.radix) {
                    Ok(address) => self.jump(self.pane_for(address.0), address.0),
                    Err(error) => self.note = Some(error.to_string()),
                }
            }
            FieldKind::Find => match self.pattern(text) {
                Ok(pattern) => {
                    let from = self.here().map_or(0, |here| here.wrapping_add(1));
                    self.queue_search(pattern, text.to_owned(), from);
                }
                Err(error) => self.note = Some(error),
            },
            FieldKind::Type => self.view_as(text),
        }
    }

    /// Read the memory at the cursor as `text`: a type, or `Type.Field` for
    /// the record whose field the cursor is on, opened down to that field.
    fn view_as(&mut self, text: &str) {
        let Some(here) = self.here() else {
            return;
        };
        let (type_name, offset) = match typed::resolve(self.state.ctx, text) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.note = Some(error);
                return;
            }
        };
        let path = text.split_once('.').map(|(_, path)| path.to_owned());
        // The fields the path goes through, open so its row shows.
        let open = path
            .iter()
            .flat_map(|path| {
                path.match_indices('.')
                    .map(|(dot, _)| path[..dot].to_owned())
                    .collect::<Vec<_>>()
            })
            .collect();
        self.jump_to(Place::Typed {
            type_name,
            base: here.wrapping_sub(offset),
            open,
            path,
        });
    }

    /// What to find for `text`: `"text"` as ASCII, `u"text"` as UTF-16,
    /// hex byte pairs as bytes, else an expression's value as a pointer.
    fn pattern(&self, text: &str) -> Result<Vec<u8>, String> {
        if let Some(inner) = text.strip_prefix('u').and_then(quoted) {
            return Ok(inner.encode_utf16().flat_map(u16::to_le_bytes).collect());
        }
        if let Some(inner) = quoted(text) {
            return Ok(inner.as_bytes().to_vec());
        }
        if let Some(bytes) = hex_pairs(text) {
            return Ok(bytes);
        }
        Expr::eval_with_radix(text, &self.state.ctx.target, self.state.radix)
            .map(|value| value.0.to_le_bytes().to_vec())
            .map_err(|error| error.to_string())
    }

    fn queue_search(&mut self, pattern: Vec<u8>, label: String, from: u64) {
        let search = Search {
            pattern,
            label,
            from,
            done: 0,
        };
        self.note = Some(search.progress());
        self.search = Some(search);
    }

    /// `n`: the next match of the last find.
    fn find_next(&mut self) {
        let Some(find) = &self.find else {
            self.note = Some("nothing to find again: / finds".into());
            return;
        };
        let here = self.here().unwrap_or(0);
        let from = if here == find.at {
            find.from
        } else {
            here.wrapping_add(1)
        };
        self.queue_search(find.pattern.clone(), find.label.clone(), from);
    }

    /// One [`FIND_STEP`] of the find under way: the first match ends it,
    /// as does the end of [`FIND_RANGE`] with none.
    fn search_step(&mut self) {
        let Some(mut search) = self.search.take() else {
            return;
        };
        let start = search.from.wrapping_add(search.done as u64);
        let step = FIND_STEP.min(FIND_RANGE - search.done);
        // On past the step by the pattern less a byte: a match that starts
        // in it and ends past it is the step's.
        let length = step + search.pattern.len() - 1;
        let result = self
            .state
            .ctx
            .search(VirtAddr(start), &search.pattern, length);
        let found = match result {
            Ok(result) => result.matches.first().copied(),
            Err(error) => {
                self.note = Some(error.to_string());
                return;
            }
        };
        if let Some(found) = found {
            self.jump(self.pane, found);
            self.note = Some(format!("{} at {found:#x}", search.label));
            self.find = Some(Find {
                pattern: search.pattern,
                label: search.label,
                at: found,
                from: found.wrapping_add(1),
            });
            return;
        }
        search.done += step;
        if search.done < FIND_RANGE {
            self.note = Some(search.progress());
            self.search = Some(search);
            return;
        }
        let end = search.from.saturating_add(FIND_RANGE as u64);
        self.note = Some(format!(
            "no {} from {:#x} to {end:#x}; n looks further",
            search.label, search.from
        ));
        self.find = Some(Find {
            pattern: search.pattern,
            label: search.label,
            at: self.here().unwrap_or(0),
            from: end,
        });
    }

    /// Escape during a find: stop it where it got to, for `n` to go on.
    fn stop_search(&mut self) {
        let Some(search) = self.search.take() else {
            return;
        };
        let reached = search.from.wrapping_add(search.done as u64);
        self.note = Some(format!(
            "stopped finding {} at {reached:#x}; n goes on from there",
            search.label
        ));
        self.find = Some(Find {
            pattern: search.pattern,
            label: search.label,
            at: self.here().unwrap_or(0),
            from: reached,
        });
    }

    fn key(&mut self, key: &Key) -> Outcome {
        if self.field.is_some() {
            self.field_key(key);
            return Outcome::Continue;
        }
        let typed = key.typed().unwrap_or_default();
        if key.is("escape") || key.is("ctrl+c") || typed == "q" {
            return Outcome::Close;
        }
        if let Some(outcome) = self.run_key(key) {
            return outcome;
        }
        let page = page() as isize;
        let memory = self.pane == Pane::Memory;
        let fields = memory && self.typed.is_some();
        if key.is("up") || typed == "k" {
            self.move_by(-1, 0);
        } else if key.is("down") || typed == "j" {
            self.move_by(1, 0);
        } else if fields && (key.is("right") || typed == "l") {
            let session = &*self.state.ctx;
            if let Some(typed) = &mut self.typed {
                typed.open_row(session);
            }
            self.load_typed_cursor();
        } else if fields && (key.is("left") || typed == "h") {
            let session = &*self.state.ctx;
            if let Some(typed) = &mut self.typed {
                typed.close_row(session);
            }
            self.load_typed_cursor();
            self.scroll = Some(Scroll::Follow);
        } else if fields && (key.is("home") || key.is("end")) {
            if let Some(typed) = &mut self.typed {
                typed.cursor = if key.is("home") {
                    0
                } else {
                    typed.rows.len().saturating_sub(1)
                };
            }
            self.load_typed_cursor();
            self.scroll = Some(Scroll::Follow);
        } else if memory && (key.is("left") || typed == "h") {
            self.move_by(0, -1);
        } else if memory && (key.is("right") || typed == "l") {
            self.move_by(0, 1);
        } else if memory && key.is("home") {
            let row = self.memory.cursor & !(self.layout.width() - 1);
            self.memory.cursor = row;
            self.scroll = Some(Scroll::Follow);
        } else if memory && key.is("end") {
            let row = self.memory.cursor & !(self.layout.width() - 1);
            self.memory.cursor = self.align(row + self.layout.width() - 1);
            self.scroll = Some(Scroll::Follow);
        } else if key.is("shift+up") {
            self.move_by(-page, 0);
        } else if key.is("shift+down") || key.is("space") {
            self.move_by(page, 0);
        } else if key.is("enter") {
            self.follow();
        } else if key.is("backspace") {
            self.back();
        } else if key.is("tab") {
            if let Some(here) = self.here() {
                self.jump(self.pane.other(), here);
            }
        } else if fields && typed == "p" {
            // The field's memory as bytes or pointers; Backspace comes back.
            if let Some(here) = self.here() {
                self.jump(Pane::Memory, here);
            }
        } else if memory && typed == "p" {
            self.layout = match self.layout {
                Layout::Bytes => Layout::Pointers,
                Layout::Pointers => Layout::Bytes,
            };
            self.memory.cursor = self.align(self.memory.cursor);
            self.scroll = Some(Scroll::Jump);
        } else if memory && typed == "t" {
            // The type shown, else the object's whose body the cursor is at.
            let current = match &self.typed {
                Some(typed) => typed.type_name.clone(),
                None => typed::guess(self.state.ctx, self.memory.cursor)
                    .unwrap_or_default()
                    .to_owned(),
            };
            self.open_field_with(FieldKind::Type, current);
        } else if typed == "g" {
            self.open_field(FieldKind::Goto);
        } else if typed == "/" {
            self.open_field(FieldKind::Find);
        } else if typed == "n" {
            self.find_next();
        } else if typed == "b" {
            self.toggle_breakpoint();
        } else if !memory && (typed == "[" || typed == "]") {
            // Out to the caller's frame, or back in.
            let frame = self.context.as_ref().map_or(0, |context| context.frame);
            let next = if typed == "[" {
                frame + 1
            } else {
                frame.saturating_sub(1)
            };
            self.select_frame(next);
        } else if !memory && typed == "r" {
            self.show_context = !self.show_context;
        } else if typed == "." {
            match self.ip {
                Some(ip) => self.jump(Pane::Code, ip),
                None => self.note = Some("no instruction pointer here".into()),
            }
        }
        Outcome::Continue
    }

    /// The id of the row `above` rows above the cursor's.
    fn cursor_row_id(&self, above: usize) -> String {
        let key = match self.pane {
            Pane::Code => self
                .code
                .get(self.cursor.saturating_sub(above))
                .map_or_else(String::new, |row| code_key(row.row.ip)),
            Pane::Memory if let Some(typed) = &self.typed => {
                match typed.cursor.checked_sub(above) {
                    Some(index) => typed_key(index),
                    None => "th".to_owned(),
                }
            }
            Pane::Memory => {
                let width = self.layout.width();
                let row = self.memory.cursor & !(width - 1);
                let lead = row
                    .saturating_sub(above as u64 * width)
                    .max(self.memory.start);
                memory_key(lead)
            }
        };
        format!("main.{SPLIT_KEY}.{ROWS_KEY}.{key}")
    }

    fn view(&self) -> View<Msg> {
        let mut rows = ui::col().key(ROWS_KEY).role("ntoseye.browse");
        match self.pane {
            Pane::Code => {
                let width = self
                    .code
                    .iter()
                    .map(|row| row.row.hex.len())
                    .max()
                    .unwrap_or(0)
                    .min(HEX_WIDTH);
                for (index, row) in self.code.iter().enumerate() {
                    if let Some(label) = &row.label {
                        let mut spans = symbol(label);
                        spans.push(span(":", MUTED));
                        rows = rows.child(
                            ui::text(spans)
                                .wrap(Wrap::None)
                                .key(format!("l{:x}", row.row.ip)),
                        );
                    }
                    rows = rows.child(self.code_line(index, width));
                }
            }
            Pane::Memory => {
                if let Some(typed) = &self.typed {
                    for line in self.typed_lines(typed) {
                        rows = rows.child(line);
                    }
                } else {
                    let width = self.layout.width();
                    let first = self.memory.start & !(width - 1);
                    for row in (first..self.memory.end()).step_by(width as usize) {
                        rows = rows.child(self.memory_line(row));
                    }
                }
            }
        }
        let mut dock: Vec<Node<Msg>> = Vec::new();
        let mut view = View::new();
        if let Some(field) = &self.field {
            let (prompt, placeholder) = match field.kind {
                FieldKind::Goto => ("go to ", "address or expression"),
                FieldKind::Find => ("find ", "\"text\", u\"text\", hex bytes, or a pointer"),
                FieldKind::Type => (
                    "type ",
                    "a type such as nt!_EPROCESS, or Type.Field for the record this field is in; empty for bytes",
                ),
            };
            let ghost = field
                .popup
                .as_ref()
                .map(|popup| popup.ghost().to_owned())
                .unwrap_or_default();
            dock.push(
                ui::input()
                    .key(FIELD_KEY)
                    .text(field.draft.clone())
                    .cursor(field.draft.encode_utf16().count())
                    .prompt(vec![span(prompt, MUTED)])
                    .placeholder(placeholder.to_owned())
                    .ghost(ghost)
                    .into(),
            );
            if let Some(popup) = &field.popup {
                view = view.layer(vec![popup.overlay(FIELD, false)]);
            }
        }
        dock.push(self.location().into());
        dock.push(hints(self.pane, self.layout, self.typed.is_some(), self.can_run).into());
        // Beside memory's bytes and pointers, the inspector; code and typed
        // fields take the width, their values already decoded, so the
        // cursor's mark runs across the pane.
        let split = ui::row().key(SPLIT_KEY).gap(Gap::Lg).align(Align::Start);
        let split = match self.pane {
            Pane::Memory if self.typed.is_none() => split.child(rows).child(self.inspector()),
            Pane::Code
                if self.show_context
                    && let Some(panel) = self.context_panel() =>
            {
                split.child(rows.grow(1.0)).child(panel)
            }
            Pane::Memory | Pane::Code => split.child(rows.grow(1.0)),
        };
        // A child of `main`, not its root: the screen region is a fixed-height
        // column that would shrink every row to nothing.
        view.main(vec![Node::from(split)]).dock(dock)
    }

    /// A typed view's lines: its type and address, then a row per field,
    /// `dt`'s columns aligned: offset, name (indented by how deep it is,
    /// marked when it opens), type and value.
    fn typed_lines(&self, typed: &Typed) -> Vec<TextNode<Msg>> {
        let target = &self.state.ctx.target;
        let trace = resolve_thread_trace_context(target, target.current_dtb());
        let offset_width = typed
            .rows
            .iter()
            .map(|row| format!("{:x}", row.offset).len().max(3))
            .max()
            .unwrap_or(3);
        let name_width = typed
            .rows
            .iter()
            .filter(|row| row.kind != Kind::Note)
            .map(|row| row.depth * 2 + row.name.chars().count())
            .max()
            .unwrap_or(0)
            .min(NAME_WIDTH);
        let type_width = typed
            .rows
            .iter()
            .map(|row| row.type_name.chars().count())
            .max()
            .unwrap_or(0)
            .min(TYPE_WIDTH);

        let mut head = vec![span(typed.type_name.clone(), TYPE), span("  ", "")];
        head.push(addr(typed.base));
        head.push(span(format!("  {:#x} bytes", typed.size), MUTED));
        if let Some(name) = try_format_symbol(target, &trace, typed.base) {
            head.push(span("  ", ""));
            head.extend(symbol(&name));
        }
        let mut lines = vec![ui::text(head).wrap(Wrap::None).key("th")];

        for (index, row) in typed.rows.iter().enumerate() {
            let indent = "  ".repeat(row.depth);
            let mut spans = vec![span(format!("+0x{:0offset_width$x}  ", row.offset), MUTED)];
            if row.kind == Kind::Note {
                spans.push(span(format!("   {indent}{}", row.name), MUTED));
                lines.push(self.row_line(index, spans, index == typed.cursor));
                continue;
            }
            // ASCII markers, as in code: a fallback font's would shift the row.
            let marker = match (row.opens(), typed.open.contains(&row.path)) {
                (true, true) => "- ",
                (true, false) => "+ ",
                _ => "  ",
            };
            spans.push(span(format!("{indent}{marker}"), DIM));
            let name = clip(&row.name, name_width.saturating_sub(row.depth * 2));
            let pad = name_width.saturating_sub(row.depth * 2 + name.chars().count());
            spans.push(span(name, STRONG));
            spans.push(span(format!("{}  ", " ".repeat(pad)), ""));
            let type_name = clip(&row.type_name, type_width);
            let pad = type_width.saturating_sub(type_name.chars().count());
            spans.push(span(format!("{type_name}{}  ", " ".repeat(pad)), TYPE));
            let changed = typed.changed.contains(&row.path);
            spans.extend(self.field_value(row, changed, &trace));
            lines.push(self.row_line(index, spans, index == typed.cursor));
        }
        if typed.cut {
            lines.push(
                ui::text(vec![span(
                    "… rows past here are left out: close fields to see them",
                    MUTED,
                )])
                .wrap(Wrap::None)
                .key("tc"),
            );
        }
        lines
    }

    /// A typed field's value: a pointer as an address with the symbol it
    /// points into or the type it leads to, a number as a number, a string
    /// as a string; in the changed color when a run changed it.
    fn field_value(
        &self,
        row: &typed::Row,
        changed: bool,
        trace: &crate::unwind::ThreadTraceContext,
    ) -> Vec<Span> {
        let style = |default: &str| {
            if changed {
                CHANGED_TINT.to_owned()
            } else {
                default.to_owned()
            }
        };
        let target = &self.state.ctx.target;
        match row.kind {
            Kind::Aggregate | Kind::Array | Kind::Note => Vec::new(),
            Kind::Pointer => match row.raw {
                Some(0) => vec![span("null", &style(DIM))],
                Some(value) => {
                    let mut spans = vec![span(format!("{value:016x}"), &style(""))];
                    if let Some(name) = try_format_symbol(target, trace, value) {
                        spans.push(span("  ", ""));
                        spans.extend(symbol(&name));
                    } else if let Some(pointee) = &row.pointee {
                        spans.push(span(format!("  → {pointee}"), MUTED));
                    }
                    spans
                }
                None => vec![span(row.value.clone(), &style(MUTED))],
            },
            // The Flink, where Enter goes, and the symbol of a list head.
            Kind::Link => match row.raw {
                Some(flink) => {
                    let mut spans = vec![
                        span("\u{2192} ", MUTED),
                        span(format!("{flink:016x}"), &style("")),
                    ];
                    if let Some(name) = try_format_symbol(target, trace, flink) {
                        spans.push(span("  ", ""));
                        spans.extend(symbol(&name));
                    }
                    spans
                }
                None => vec![span(row.value.clone(), &style(MUTED))],
            },
            Kind::Flags => {
                let number = if row.raw == Some(0) { DIM } else { NUMBER };
                let mut spans = vec![span(row.value.clone(), &style(number))];
                if !row.set.is_empty() {
                    spans.push(span(format!("  {}", row.set), MUTED));
                }
                spans
            }
            Kind::Scalar if row.value.starts_with('"') => {
                vec![span(row.value.clone(), &style(STRING))]
            }
            // Zero dim, as the bytes show it, so the values that say
            // something stand out.
            Kind::Scalar if row.value == "0x0" || row.value == "N" => {
                vec![span(row.value.clone(), &style(DIM))]
            }
            Kind::Scalar if row.value.starts_with("0x") => {
                vec![span(row.value.clone(), &style(NUMBER))]
            }
            Kind::Scalar => vec![span(row.value.clone(), &style(""))],
        }
    }

    /// A typed row's line, clicked to put the cursor on it and double-clicked
    /// to follow it.
    fn row_line(&self, index: usize, spans: Vec<Span>, cursor: bool) -> TextNode<Msg> {
        let line = ui::text(spans)
            .wrap(Wrap::None)
            .key(typed_key(index))
            .on_click(Msg::SelectRow(index))
            .on_dblclick(Msg::FollowRow(index));
        if cursor { line.mark(Mark::Pick) } else { line }
    }

    /// Where the caller's frame the stack shows is, when it is not the
    /// innermost.
    fn frame_ip(&self) -> Option<u64> {
        let context = self.context.as_ref().filter(|context| context.frame > 0)?;
        context.frames.get(context.frame).map(|&(ip, _)| ip)
    }

    /// The registers and stack beside the code: the registers two a row,
    /// those the last run changed marked, a click on one browsing where it
    /// points; the frames under them, a click showing one. A caller's frame
    /// shows what the walk recovered of its registers, the rest dashed.
    fn context_panel(&self) -> Option<ui::Col<Msg>> {
        let context = self.context.as_ref()?;
        let mut panel = ui::col().key(CONTEXT_KEY).role("ntoseye.inspector");
        if let Some(error) = &context.error {
            return Some(
                panel
                    .child(ui::text(vec![span("registers", MUTED)]).key("rt"))
                    .child(
                        ui::text(vec![span(clip(error, CONTEXT_WIDTH), DIM)])
                            .wrap(Wrap::None)
                            .key("re"),
                    ),
            );
        }
        let registers = context.registers.get(context.frame)?;
        let arm = context
            .registers
            .first()
            .is_some_and(|first| first.contains_key("pc"));
        let names: &[&str] = if arm { &ARM64_GRID } else { &X64_GRID };
        let title = match context.frame {
            0 => "registers".to_owned(),
            frame => format!("registers of frame {frame}"),
        };
        panel = panel.child(ui::text(vec![span(title, MUTED)]).key("rt"));
        for (index, pair) in names.chunks(2).enumerate() {
            let mut row = ui::row().key(format!("r{index}")).gap(Gap::Md);
            for &name in pair {
                let label = match name {
                    "eflags" => "efl",
                    name => name,
                };
                let value = registers.get(name).copied();
                let style = match value {
                    _ if context.frame == 0 && context.changed.contains(name) => CHANGED_TINT,
                    Some(0) | None => DIM,
                    Some(_) => "",
                };
                let text = value.map_or_else(
                    || format!("{:<16}", "\u{2014}"),
                    |value| format!("{value:016x}"),
                );
                let mut cell =
                    ui::text(vec![span(format!("{label:<4}"), MUTED), span(text, style)])
                        .wrap(Wrap::None)
                        .key(name.to_owned());
                if let Some(value) = value {
                    cell = cell.on_click(Msg::Goto(value));
                }
                row = row.child(cell);
            }
            panel = panel.child(row);
        }
        if let Some(&flags) = registers.get("eflags") {
            panel = panel.child(
                ui::text(vec![
                    span(format!("{:<4}", ""), MUTED),
                    span(eflags_names(flags), MUTED),
                ])
                .wrap(Wrap::None)
                .key("rf"),
            );
        }
        panel = panel.child(ui::text(vec![span(" ", "")]).key("gap"));
        panel = panel.child(ui::text(vec![span("stack", MUTED)]).key("st"));
        for (index, (_, name)) in context.frames.iter().enumerate() {
            let mut spans = vec![
                if index == context.frame {
                    span("> ", "info")
                } else {
                    span("  ", "")
                },
                span(format!("{index:<3}"), MUTED),
            ];
            spans.extend(symbol(&clip(name, CONTEXT_WIDTH - 5)));
            panel = panel.child(
                ui::text(spans)
                    .wrap(Wrap::None)
                    .key(format!("s{index}"))
                    .on_click(Msg::Frame(index)),
            );
        }
        Some(panel)
    }

    fn code_line(&self, index: usize, width: usize) -> TextNode<Msg> {
        let row = &self.code[index].row;
        // ASCII markers: a shape the monospace font lacks comes from a
        // fallback font at another width and shifts the row.
        let mut spans = vec![
            match self.breakpoints.get(&row.ip) {
                Some(true) => span("* ", "error"),
                Some(false) => span("* ", MUTED),
                None => span("  ", ""),
            },
            if self.ip == Some(row.ip) {
                span("> ", "info")
            } else if self.frame_ip() == Some(row.ip) {
                span("> ", MUTED)
            } else {
                span("  ", "")
            },
            addr(row.ip),
            span(format!("  {:<width$}  ", hex_column(&row.hex)), DIM),
        ];
        spans.extend(code::asm(&row.tokens));
        if let Some(comment) = &row.comment {
            spans.push(span("  ; ", MUTED));
            spans.extend(symbol(comment));
        }
        self.line(code_key(row.ip), spans, row.ip, index == self.cursor)
    }

    /// A byte's color: red where a watchpoint watches it, else by what it
    /// is, as hexyl colors bytes: zero dim, printable ASCII as a string,
    /// other ASCII as a keyword, the rest plain, unread muted.
    fn byte_style(&self, address: u64) -> &'static str {
        if self.watched(address) {
            return "error";
        }
        if self.changed_bytes.contains(&address) {
            return CHANGED_TINT;
        }
        match self.memory.byte(address) {
            None => MUTED,
            Some(0) => DIM,
            Some(0x20..=0x7e) => STRING,
            Some(0x01..=0x1f | 0x7f) => MNEMONIC,
            Some(_) => "",
        }
    }

    fn watched(&self, address: u64) -> bool {
        self.watches
            .iter()
            .any(|&(start, len)| (start..start.saturating_add(len)).contains(&address))
    }

    fn memory_line(&self, row: u64) -> TextNode<Msg> {
        let memory = &self.memory;
        let width = self.layout.width();
        let cursor = memory.cursor;
        let mut runs = Runs::default();
        runs.push_span(addr(row));
        runs.push(MUTED, format_args!(" │ "));
        match self.layout {
            Layout::Bytes => {
                for offset in 0..width {
                    let address = row + offset;
                    let style = self.byte_style(address);
                    let gap = match offset {
                        0 => "",
                        8 => "  ",
                        _ => " ",
                    };
                    runs.push(style, format_args!("{gap}"));
                    let text = memory
                        .byte(address)
                        .map_or_else(|| "??".to_owned(), |byte| format!("{byte:02x}"));
                    if address == cursor {
                        runs.push_span(span(text, style).style("mark strong"));
                    } else {
                        runs.push(style, format_args!("{text}"));
                    }
                }
            }
            Layout::Pointers => {
                let style = if self.watched(row) {
                    "error"
                } else {
                    match memory.value(row) {
                        None => MUTED,
                        Some(0) => DIM,
                        Some(_) => "",
                    }
                };
                match memory.value(row) {
                    Some(value) => runs.push(style, format_args!("{value:016x}")),
                    None => runs.push(style, format_args!("????????????????")),
                }
            }
        }
        runs.push(MUTED, format_args!(" │ "));
        for offset in 0..width {
            let address = row + offset;
            let style = self.byte_style(address);
            let glyph = match memory.byte(address) {
                Some(byte @ 0x20..=0x7e) => byte as char,
                Some(_) => '·',
                None => ' ',
            };
            if address == cursor && self.layout == Layout::Bytes {
                runs.push_span(span(glyph.to_string(), style).style("mark strong"));
            } else {
                runs.push(style, format_args!("{glyph}"));
            }
        }
        let mut spans = runs.finish();
        if self.layout == Layout::Pointers
            && let Some(name) = memory.symbols.get(&row)
        {
            spans.push(span("  ", ""));
            spans.extend(symbol(name));
        }
        let at_cursor = (row..row + width).contains(&cursor);
        self.line(memory_key(row), spans, row, at_cursor)
    }

    fn line(&self, key: String, spans: Vec<Span>, address: u64, cursor: bool) -> TextNode<Msg> {
        let line = ui::text(spans)
            .wrap(Wrap::None)
            .key(key)
            .on_click(Msg::Select(address))
            .on_dblclick(Msg::Follow(address));
        if cursor { line.mark(Mark::Pick) } else { line }
    }

    /// The values the bytes at the cursor make, little-endian, as a column
    /// beside the memory rows, as ImHex's data inspector shows them: a row
    /// per reading, the label, the hex of an unsigned integer, and the value
    /// right-aligned to one edge, so moving the cursor changes the values and
    /// nothing moves. Then the symbol a pointer points into, a FILETIME, and
    /// the strings that start there.
    fn inspector(&self) -> ui::Col<Msg> {
        let memory = &self.memory;
        let at = memory.cursor;
        let byte = memory.bytes::<1>(at).map(|[byte]| u64::from(byte));
        let word = memory
            .bytes::<2>(at)
            .map(|bytes| u64::from(u16::from_le_bytes(bytes)));
        let dword = memory
            .bytes::<4>(at)
            .map(|bytes| u64::from(u32::from_le_bytes(bytes)));
        let quad = memory.value(at);

        let mut panel = ui::col().key(INSPECTOR_KEY).role("ntoseye.inspector");
        for (bits, value) in [(8, byte), (16, word), (32, dword), (64, quad)] {
            let hex = value.map(|value| format!("{value:#0width$x}", width = 2 + bits / 4));
            let unsigned = value.map(|value| value.to_string());
            // The value as the signed integer of its size.
            let signed = value.map(|value| {
                let shift = 64 - bits;
                (((value << shift) as i64) >> shift).to_string()
            });
            panel = panel
                .child(number_row(&format!("u{bits}"), hex, unsigned))
                .child(number_row(&format!("i{bits}"), None, signed));
        }
        let single = dword.map(|bits| float(f32::from_bits(bits as u32).into()));
        panel = panel
            .child(number_row("f32", None, single))
            .child(number_row(
                "f64",
                None,
                quad.map(|bits| float(f64::from_bits(bits))),
            ));

        let target = &self.state.ctx.target;
        let name = quad.and_then(|value| {
            let trace = resolve_thread_trace_context(target, target.current_dtb());
            try_format_symbol(target, &trace, value)
        });
        // Where Enter would go when the value has no symbol.
        let pointer = match (name, quad) {
            (Some(name), _) => symbol(&name),
            (None, Some(value)) if self.points_somewhere(value) => {
                vec![span(self.pane_for(value).name(), MUTED)]
            }
            _ => vec![span("—", DIM)],
        };
        let time = quad
            .filter(|value| PLAUSIBLE_FILETIME.contains(value))
            .and_then(filetime_to_iso);
        let ascii: String = (0..STRING_PREVIEW as u64)
            .map_while(|offset| memory.byte(at + offset))
            .take_while(|byte| (0x20..=0x7e).contains(byte))
            .map(char::from)
            .collect();
        // Printable ASCII only: UTF-16 of anything else is mostly pointer
        // bytes read as CJK.
        let utf16: String = (0..STRING_PREVIEW as u64)
            .map_while(|index| memory.bytes::<2>(at + index * 2).map(u16::from_le_bytes))
            .take_while(|unit| (0x20..=0x7e).contains(unit))
            .filter_map(|unit| char::from_u32(unit.into()))
            .collect();
        // One character is as likely chance as text.
        let string = |text: String| {
            if text.chars().count() < 2 {
                vec![span("—", DIM)]
            } else {
                vec![span(format!("\"{text}\""), STRING)]
            }
        };
        let none = || vec![span("—", DIM)];
        panel
            .child(text_row("ptr", pointer))
            .child(text_row(
                "time",
                time.map_or_else(none, |time| vec![span(time, "")]),
            ))
            .child(text_row("ascii", string(ascii)))
            .child(text_row("utf16", string(utf16)))
    }

    /// The pane, where the cursor is, and the last note.
    fn location(&self) -> TextNode<Msg> {
        let mut spans = vec![span(format!("{}  ", self.pane.name()), "info")];
        if self.pane == Pane::Memory
            && let Some(typed) = &self.typed
        {
            // `nt!_EPROCESS  ffff…7040  +0x448 ActiveProcessLinks.Flink`
            spans.push(span(format!("{}  ", typed.type_name), TYPE));
            spans.push(addr(typed.base));
            if let Some(row) = typed.row() {
                spans.push(span(format!("  +{:#x} ", row.offset), MUTED));
                spans.push(span(row.path.clone(), ""));
            }
        } else if let Some(here) = self.here() {
            spans.push(addr(here));
            let target = &self.state.ctx.target;
            let trace = resolve_thread_trace_context(target, target.current_dtb());
            if let Some(name) = try_format_symbol(target, &trace, here) {
                spans.push(span("  ", ""));
                spans.extend(symbol(&name));
            }
        }
        if let Some(note) = &self.note {
            spans.push(span(format!("   {note}"), MUTED));
        }
        ui::text(spans).wrap(Wrap::None)
    }
}

fn code_key(ip: u64) -> String {
    format!("c{ip:x}")
}

/// The text of a quoted string, without its closing quote when typed.
fn quoted(text: &str) -> Option<&str> {
    let inner = text.strip_prefix('"')?;
    Some(inner.strip_suffix('"').unwrap_or(inner))
}

/// Hex byte pairs, `48 8b 05`, as bytes.
fn hex_pairs(text: &str) -> Option<Vec<u8>> {
    let bytes: Option<Vec<u8>> = text
        .split_whitespace()
        .map(|pair| {
            (pair.len() == 2)
                .then(|| u8::from_str_radix(pair, 16).ok())
                .flatten()
        })
        .collect();
    bytes.filter(|bytes| !bytes.is_empty())
}

/// Whether a field's draft completes: an expression or a type does, a find
/// of text or bytes does not.
fn completes(kind: FieldKind, draft: &str) -> bool {
    kind != FieldKind::Find
        || !(draft.starts_with('"') || draft.starts_with("u\"") || hex_pairs(draft).is_some())
}

/// An inspector row for a number: the label, the hex of an unsigned
/// integer in a column as wide as a quadword's, and the value right-aligned
/// to [`VALUE_WIDTH`], or a dash where the bytes were not read.
fn number_row(label: &str, hex: Option<String>, value: Option<String>) -> TextNode<Msg> {
    let hex = hex.unwrap_or_default();
    let value = match value {
        Some(value) => span(format!("{value:>VALUE_WIDTH$}"), ""),
        None => span(format!("{:>VALUE_WIDTH$}", "—"), DIM),
    };
    ui::text(vec![
        span(format!("{label:<LABEL_WIDTH$}"), MUTED),
        span(format!("{hex:<18}  "), MUTED),
        value,
    ])
    .wrap(Wrap::None)
}

/// An inspector row for text: the label and the text as it is.
fn text_row(label: &str, value: Vec<Span>) -> TextNode<Msg> {
    let mut spans = vec![span(format!("{label:<LABEL_WIDTH$}"), MUTED)];
    spans.extend(value);
    ui::text(spans).wrap(Wrap::None)
}

/// A float as the inspector shows it: four decimals in a readable range,
/// else exponent form, never hundreds of digits.
fn float(value: f64) -> String {
    let magnitude = value.abs();
    if value == 0.0 || !value.is_finite() {
        format!("{value}")
    } else if (1e-3..1e7).contains(&magnitude) {
        format!("{value:.4}")
    } else {
        format!("{value:.4e}")
    }
}

fn memory_key(row: u64) -> String {
    format!("m{row:x}")
}

fn typed_key(index: usize) -> String {
    format!("t{index}")
}

/// The set flags of `eflags`, by their short names, highest first.
fn eflags_names(eflags: u64) -> String {
    const FLAGS: [(u32, &str); 9] = [
        (11, "of"),
        (10, "df"),
        (9, "if"),
        (8, "tf"),
        (7, "sf"),
        (6, "zf"),
        (4, "af"),
        (2, "pf"),
        (0, "cf"),
    ];
    FLAGS
        .iter()
        .filter(|(bit, _)| eflags >> bit & 1 != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(" ")
}

/// `text` cut to `width` characters with an ellipsis.
fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut clipped: String = text.chars().take(width.saturating_sub(1)).collect();
    clipped.push('…');
    clipped
}

/// The keys, as keycaps with what they do.
fn hints(pane: Pane, layout: Layout, typed: bool, can_run: bool) -> ui::Row<Msg> {
    if pane == Pane::Memory && typed {
        return keycaps(&[
            (&["↑", "↓"], "move"),
            (&["→", "←"], "open, close"),
            (&["Enter"], "follow"),
            (&["⌫"], "back"),
            (&["t"], "type"),
            (&["p"], "bytes"),
            (&["b"], "watch writes"),
            (&["Tab"], "to code"),
            (&["g"], "go to"),
            (&["/"], "find"),
            (&["Esc"], "close"),
        ]);
    }
    let other = format!("to {}", pane.other().name());
    let mut keys: Vec<(&[&str], &str)> = vec![(&["↑", "↓"], "move")];
    if pane == Pane::Memory {
        keys = vec![(&["↑", "↓", "←", "→"], "move")];
    }
    keys.extend([
        (&["⇧↑", "⇧↓"][..], "page"),
        (&["Enter"], "follow"),
        (&["⌫"], "back"),
        (&["Tab"], &other),
        (&["g"], "go to"),
        (&["/"], "find"),
        (&["n"], "next"),
    ]);
    match pane {
        Pane::Code => {
            keys.push((&["b"], "breakpoint"));
            keys.push((&["[", "]"], "frame"));
            keys.push((&["r"], "registers"));
        }
        Pane::Memory => {
            keys.push((&["b"], "watch writes"));
            keys.push((
                &["p"],
                match layout {
                    Layout::Bytes => "pointers",
                    Layout::Pointers => "bytes",
                },
            ));
            keys.push((&["t"], "as a type"));
        }
    }
    keys.push((&["."], "instruction pointer"));
    if can_run {
        keys.extend([
            (&["F10"][..], "step over"),
            (&["F11"], "into"),
            (&["\u{21e7}F11"], "out"),
            (&["F5"], "go"),
        ]);
        if pane == Pane::Code {
            keys.push((&["F7"], "to cursor"));
        }
    }
    keys.push((&["Esc"], "close"));
    keycaps(&keys)
}

/// Keys as keycaps, each with what it does.
fn keycaps(keys: &[(&[&str], &str)]) -> ui::Row<Msg> {
    let mut row = ui::row().gap(Gap::Sm).wrap(true);
    for (caps, what) in keys {
        row = row
            .child(ui::kbd(caps.iter().copied()))
            .child(ui::text(vec![span(format!("{what}  "), MUTED)]));
    }
    row
}

/// An instruction's bytes, cut to [`HEX_WIDTH`] with an ellipsis: most
/// instructions fit, and one of up to 15 bytes would push every row's
/// mnemonic far right.
fn hex_column(hex: &str) -> std::borrow::Cow<'_, str> {
    if hex.len() <= HEX_WIDTH {
        return hex.into();
    }
    // Seven whole bytes and the ellipsis.
    format!("{}…", &hex[..HEX_WIDTH - 3]).into()
}

/// Drop the end of `rows` away from `cursor` past [`ROW_LIMIT`]; how many
/// rows went from before the cursor.
fn trim<T>(rows: &mut Vec<T>, cursor: usize) -> usize {
    let excess = rows.len().saturating_sub(ROW_LIMIT);
    if excess == 0 {
        return 0;
    }
    if cursor > rows.len() / 2 {
        rows.drain(..excess);
        excess
    } else {
        rows.truncate(ROW_LIMIT);
        0
    }
}

/// Rows a page moves: the pane's height less the dock.
fn page() -> usize {
    terminal_size::terminal_size()
        .map_or(24, |(_, terminal_size::Height(height))| usize::from(height))
        .saturating_sub(6)
        .max(4)
}
