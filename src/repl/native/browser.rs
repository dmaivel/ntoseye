//! The code and memory browser, `browse` or F2 at the prompt: a screen
//! surface over the pane that pages through disassembly and memory, follows
//! branches and pointers, finds bytes, and sets and clears breakpoints and
//! watchpoints, then leaves the pane as it was.

use std::collections::HashMap;
use std::time::Duration;

use reedline::{Completer, Suggestion};
use tern_sdk::keys::Key;
use tern_sdk::ui::{self, Align, Gap, Mark, Span, TextNode, Wrap};
use tern_sdk::wire::{Event, RevealAt};
use tern_sdk::{Input, Node, Session, SurfaceOptions, View};

use super::completions::{POPUP_LIMIT, Popup, PopupKey};
use super::memory::Runs;
use super::{DIM, MNEMONIC, MUTED, ROLE, STRING, STYLESHEET, addr, code, connect, span, symbol};
use crate::disasm::{DisasmRow, OperandKind, decode_code, disasm_formatter};
use crate::expr::Expr;
use crate::memory::read_page_chunks;
use crate::output;
use crate::repl::{MyCompleter, ReplState, TargetLoan};
use crate::triage_report::time::filetime_to_iso;
use crate::types::VirtAddr;
use crate::unwind::{format_symbol, resolve_thread_trace_context, try_format_symbol};

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

/// What a click on a row reports: the row's address.
#[derive(Clone)]
enum Msg {
    Select(u64),
    Follow(u64),
}

/// Browse from `address` in `pane`, or in the pane for its page: code when
/// it is executable. Returns what the commands it ran printed, for the
/// pane's record, or why it could not open.
pub fn run(
    state: &mut ReplState<'_>,
    address: u64,
    pane: Option<Pane>,
) -> Result<Vec<String>, String> {
    let mut browser = Browser::new(state);
    let pane = pane.unwrap_or_else(|| browser.pane_for(address));
    browser.go(pane, address)?;
    let mut session = connect::<Msg>().ok_or("Tern did not open the browser")?;
    browse(&mut session, &mut browser);
    // Restores the terminal for the line editor whatever happened.
    let _ = session.close();
    Ok(browser.record)
}

fn browse(session: &mut Session<Msg>, browser: &mut Browser<'_, '_>) -> Option<()> {
    let surface = session
        .open(
            SurfaceOptions::screen()
                .role(format!("{ROLE}.browser"))
                .keep(false),
        )
        .ok()?;
    let _ = session.stylesheet(surface, ROLE, Some(STYLESHEET));
    loop {
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
            Input::Event(Event::Select(pick) | Event::Activate(pick)) => {
                browser.pick_completion(&pick.item);
                Outcome::Continue
            }
            Input::Event(_) => Outcome::Continue,
        };
        if outcome == Outcome::Close {
            return Some(());
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
    /// Where Backspace goes back to.
    history: Vec<(Pane, u64)>,
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
}

impl<'s, 'a> Browser<'s, 'a> {
    fn new(state: &'s mut ReplState<'a>) -> Self {
        let ip = state.ctx.target.builtin_variable_value("ip");
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
        };
        browser.refresh_breakpoints();
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

    /// The address under the cursor.
    fn here(&self) -> Option<u64> {
        match self.pane {
            Pane::Code => self.code.get(self.cursor).map(|row| row.row.ip),
            Pane::Memory => Some(self.memory.cursor),
        }
    }

    /// Show `pane` at `address`, leaving the view as it was when nothing
    /// there can be read.
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
            }
        }
        self.pane = pane;
        self.scroll = Some(Scroll::Jump);
        Ok(())
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
        let from = self.here().map(|here| (self.pane, here));
        match self.go(pane, address) {
            Ok(()) => {
                self.history.extend(from);
                self.note = None;
            }
            Err(error) => self.note = Some(error),
        }
    }

    fn back(&mut self) {
        let Some((pane, address)) = self.history.pop() else {
            self.note = Some("nothing to go back to".into());
            return;
        };
        if let Err(error) = self.go(pane, address) {
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

    /// Move `rows` rows, or in memory also `bytes` bytes.
    fn move_by(&mut self, rows: isize, bytes: isize) {
        match self.pane {
            Pane::Code => {
                let last = self.code.len().saturating_sub(1);
                self.cursor = self.cursor.saturating_add_signed(rows).min(last);
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
        match self.target() {
            Some((pane, address)) => self.jump(pane, address),
            None => self.note = Some("nothing to follow here".into()),
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
                    // The widest size the address is aligned to.
                    None => {
                        let size = [8, 4, 2, 1]
                            .into_iter()
                            .find(|size| here % size == 0)
                            .unwrap_or(1);
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
        self.field = Some(Field {
            kind,
            draft: String::new(),
            popup: None,
        });
        self.focus_field = true;
    }

    /// The completions for `draft` as an expression, the way `?` completes
    /// its argument.
    fn completions(&mut self, draft: &str) -> Vec<Suggestion> {
        const PREFIX: &str = "? ";
        let line = format!("{PREFIX}{draft}");
        let (loan, completer) = (&self.loan, &mut self.completer);
        let mut suggestions = loan.lend(&self.state.ctx.target, || {
            completer.complete(&line, line.len())
        });
        suggestions.truncate(POPUP_LIMIT);
        for suggestion in &mut suggestions {
            suggestion.span.start = suggestion.span.start.saturating_sub(PREFIX.len());
            suggestion.span.end = suggestion.span.end.saturating_sub(PREFIX.len());
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
            let suggestions = self.completions(&draft);
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
            if !completes(field.kind, &draft) {
                return;
            }
            let mut suggestions = self.completions(&draft);
            if suggestions.len() == 1 {
                let only = suggestions.remove(0);
                self.apply(&only);
            } else if let Some(field) = &mut self.field {
                field.popup = Popup::open(suggestions, &draft, None);
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
        }
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
        let page = page() as isize;
        let memory = self.pane == Pane::Memory;
        if key.is("up") || typed == "k" {
            self.move_by(-1, 0);
        } else if key.is("down") || typed == "j" {
            self.move_by(1, 0);
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
        } else if memory && typed == "p" {
            self.layout = match self.layout {
                Layout::Bytes => Layout::Pointers,
                Layout::Pointers => Layout::Bytes,
            };
            self.memory.cursor = self.align(self.memory.cursor);
            self.scroll = Some(Scroll::Jump);
        } else if typed == "g" {
            self.open_field(FieldKind::Goto);
        } else if typed == "/" {
            self.open_field(FieldKind::Find);
        } else if typed == "n" {
            self.find_next();
        } else if typed == "b" {
            self.toggle_breakpoint();
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
                let width = self.layout.width();
                let first = self.memory.start & !(width - 1);
                for row in (first..self.memory.end()).step_by(width as usize) {
                    rows = rows.child(self.memory_line(row));
                }
            }
        }
        let mut dock: Vec<Node<Msg>> = Vec::new();
        let mut view = View::new();
        if let Some(field) = &self.field {
            let (prompt, placeholder) = match field.kind {
                FieldKind::Goto => ("go to ", "address or expression"),
                FieldKind::Find => ("find ", "\"text\", u\"text\", hex bytes, or a pointer"),
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
                view = view.layer(vec![popup.overlay(FIELD)]);
            }
        }
        dock.push(self.location().into());
        dock.push(hints(self.pane, self.layout).into());
        // In memory, the inspector beside the rows; in code the rows take
        // the width, so the cursor's mark runs across the pane.
        let split = ui::row().key(SPLIT_KEY).gap(Gap::Lg).align(Align::Start);
        let split = match self.pane {
            Pane::Memory => split.child(rows).child(self.inspector()),
            Pane::Code => split.child(rows.grow(1.0)),
        };
        // A child of `main`, not its root: the screen region is a fixed-height
        // column that would shrink every row to nothing.
        view.main(vec![Node::from(split)]).dock(dock)
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
        if let Some(here) = self.here() {
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

/// Whether a field's draft is an expression, which completes: a find of
/// text or bytes does not.
fn completes(kind: FieldKind, draft: &str) -> bool {
    kind == FieldKind::Goto
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

/// The keys, as keycaps with what they do.
fn hints(pane: Pane, layout: Layout) -> ui::Row<Msg> {
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
        Pane::Code => keys.push((&["b"], "breakpoint")),
        Pane::Memory => {
            keys.push((&["b"], "watch writes"));
            keys.push((
                &["p"],
                match layout {
                    Layout::Bytes => "pointers",
                    Layout::Pointers => "bytes",
                },
            ));
        }
    }
    keys.push((&["."], "instruction pointer"));
    keys.push((&["Esc"], "close"));
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
