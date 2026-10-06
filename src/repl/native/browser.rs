//! The code and memory browser, `browse` or F2 at the prompt: a screen
//! surface over the pane that pages through disassembly and memory, follows
//! branches and pointers, and sets and clears breakpoints, then leaves the
//! pane as it was.

use std::collections::HashMap;

use tern_sdk::keys::Key;
use tern_sdk::ui::{self, Gap, Mark, Span, TextNode, Wrap};
use tern_sdk::wire::RevealAt;
use tern_sdk::{Input, Node, Session, SurfaceOptions, View};

use super::{DIM, MUTED, ROLE, STYLESHEET, addr, code, connect, span, symbol};
use crate::disasm::{DisasmRow, OperandKind, decode_code, disasm_formatter};
use crate::expr::Expr;
use crate::memory::read_page_chunks;
use crate::output;
use crate::repl::ReplState;
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

/// Instructions decoded at a time on each side of where the cursor goes.
const CODE_CHUNK: usize = 64;
/// Memory rows, a pointer each, read at a time on each side.
const MEMORY_CHUNK: usize = 128;
/// How close the cursor comes to an end of the rows before more are read.
const MARGIN: usize = 16;
/// The most rows kept; past it the end away from the cursor is dropped.
const ROW_LIMIT: usize = 768;
/// The widest byte column: eight bytes.
const HEX_WIDTH: usize = 8 * 3 - 1;
/// The width of a memory row: one pointer.
const POINTER: u64 = 8;
/// How long a rebuilt listing takes Tern to lay out.
const LAYOUT_WAIT: std::time::Duration = std::time::Duration::from_millis(60);
/// The rows' column's key under `main`.
const ROWS_KEY: &str = "rows";
/// The go-to field's key, and its id in the dock.
const GOTO_KEY: &str = "goto";
const GOTO: &str = "dock.goto";

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
                let lead = browser.cursor.saturating_sub(page() / 3);
                let _ = session.reveal(surface, &browser.row_id(lead), RevealAt::Start);
            }
            Some(Scroll::Follow) => {
                let _ = session.reveal(surface, &browser.row_id(browser.cursor), RevealAt::Nearest);
            }
            None => {}
        }
        if browser.focus_goto {
            browser.focus_goto = false;
            let _ = session.focus(surface, Some(GOTO));
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
            Input::Event(_) => Outcome::Continue,
        };
        if outcome == Outcome::Close {
            return Some(());
        }
    }
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

/// A pointer-sized row of memory.
struct MemoryRow {
    address: u64,
    bytes: [u8; POINTER as usize],
    /// Whether every byte was read.
    read: bool,
    /// The symbol the value points into.
    symbol: Option<String>,
}

impl MemoryRow {
    fn value(&self) -> Option<u64> {
        self.read.then(|| u64::from_le_bytes(self.bytes))
    }
}

struct Browser<'s, 'a> {
    state: &'s mut ReplState<'a>,
    pane: Pane,
    code: Vec<CodeRow>,
    memory: Vec<MemoryRow>,
    cursor: usize,
    /// Where Backspace goes back to.
    history: Vec<(Pane, u64)>,
    /// The go-to field's text while it is open.
    goto: Option<String>,
    focus_goto: bool,
    scroll: Option<Scroll>,
    /// The last thing said, under the rows.
    note: Option<String>,
    /// What the commands run printed, for the pane once the browser closes.
    record: Vec<String>,
    /// Breakpoint addresses, enabled or not.
    breakpoints: HashMap<u64, bool>,
    /// The scope's instruction pointer.
    ip: Option<u64>,
}

impl<'s, 'a> Browser<'s, 'a> {
    fn new(state: &'s mut ReplState<'a>) -> Self {
        let ip = state.ctx.target.builtin_variable_value("ip");
        let mut browser = Self {
            state,
            pane: Pane::Code,
            code: Vec::new(),
            memory: Vec::new(),
            cursor: 0,
            history: Vec::new(),
            goto: None,
            focus_goto: false,
            scroll: None,
            note: None,
            record: Vec::new(),
            breakpoints: HashMap::new(),
            ip,
        };
        browser.refresh_breakpoints();
        browser
    }

    fn refresh_breakpoints(&mut self) {
        self.breakpoints = self
            .state
            .ctx
            .breakpoints
            .list()
            .into_iter()
            .map(|breakpoint| (breakpoint.address.0, breakpoint.enabled))
            .collect();
    }

    /// The address under the cursor.
    fn here(&self) -> Option<u64> {
        match self.pane {
            Pane::Code => self.code.get(self.cursor).map(|row| row.row.ip),
            Pane::Memory => self.memory.get(self.cursor).map(|row| row.address),
        }
    }

    fn len(&self) -> usize {
        match self.pane {
            Pane::Code => self.code.len(),
            Pane::Memory => self.memory.len(),
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
                let address = address & !(POINTER - 1);
                let rows = self.read_rows(address, MEMORY_CHUNK * 2);
                if !rows.iter().any(|row| row.read) {
                    return Err(format!("cannot read memory at {address:#x}"));
                }
                let start = address.saturating_sub(MEMORY_CHUNK as u64 * POINTER);
                let before = self.read_rows(start, ((address - start) / POINTER) as usize);
                self.cursor = before.len();
                self.memory = before.into_iter().chain(rows).collect();
            }
        }
        self.pane = pane;
        self.scroll = Some(Scroll::Jump);
        Ok(())
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
        let index = match self.pane {
            Pane::Code => self.code.iter().position(|row| row.row.ip == address),
            Pane::Memory => self.memory.iter().position(|row| row.address == address),
        };
        if let Some(index) = index {
            self.cursor = index;
        }
    }

    fn move_by(&mut self, delta: isize) {
        let last = self.len().saturating_sub(1);
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
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
                if self.cursor + MARGIN >= self.memory.len()
                    && let Some(last) = self.memory.last()
                    && let Some(next) = last.address.checked_add(POINTER)
                {
                    let rows = self.read_rows(next, MEMORY_CHUNK);
                    self.memory.extend(rows);
                }
                if self.cursor < MARGIN
                    && let Some(first) = self.memory.first()
                {
                    let start = first.address.saturating_sub(MEMORY_CHUNK as u64 * POINTER);
                    let rows = self.read_rows(start, ((first.address - start) / POINTER) as usize);
                    self.cursor += rows.len();
                    self.memory.splice(0..0, rows);
                }
                self.cursor -= trim(&mut self.memory, self.cursor);
            }
        }
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

    /// `count` pointer rows from `address`, each marked read or not.
    fn read_rows(&self, address: u64, count: usize) -> Vec<MemoryRow> {
        let session = &*self.state.ctx;
        let target = &session.target;
        let length = count * POINTER as usize;
        let Ok((data, valid)) = read_page_chunks(VirtAddr(address), length, |at, buf| {
            session.read_masked(at, buf)
        }) else {
            return Vec::new();
        };
        let trace = resolve_thread_trace_context(target, target.current_dtb());
        const WIDTH: usize = POINTER as usize;
        data.as_chunks::<WIDTH>()
            .0
            .iter()
            .zip(valid.as_chunks::<WIDTH>().0)
            .enumerate()
            .map(|(index, (bytes, valid))| {
                let read = valid.iter().all(|&read| read);
                let symbol = read
                    .then(|| try_format_symbol(target, &trace, u64::from_le_bytes(*bytes)))
                    .flatten();
                MemoryRow {
                    address: address.wrapping_add(index as u64 * POINTER),
                    bytes: *bytes,
                    read,
                    symbol,
                }
            })
            .collect()
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
                let value = self.memory.get(self.cursor)?.value()?;
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

    /// Set a breakpoint at the instruction under the cursor, or clear the
    /// one there, with the commands that do it at the prompt.
    fn toggle_breakpoint(&mut self) {
        if self.pane != Pane::Code {
            self.note = Some("breakpoints go on code; Tab shows it".into());
            return;
        }
        let Some(ip) = self.here() else {
            return;
        };
        let existing = self
            .state
            .ctx
            .breakpoints
            .list()
            .into_iter()
            .find(|breakpoint| breakpoint.address.0 == ip)
            .map(|breakpoint| breakpoint.id);
        let line = match existing {
            Some(id) => format!("bc {id}"),
            None => format!("bp {ip:#x}"),
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

    fn goto_key(&mut self, key: &Key) -> Outcome {
        let Some(draft) = &mut self.goto else {
            return Outcome::Continue;
        };
        if key.is("escape") || key.is("ctrl+c") {
            self.goto = None;
        } else if key.is("enter") {
            let text = std::mem::take(draft);
            self.goto = None;
            if !text.trim().is_empty() {
                match Expr::eval_with_radix(&text, &self.state.ctx.target, self.state.radix) {
                    Ok(address) => self.jump(self.pane_for(address.0), address.0),
                    Err(error) => self.note = Some(error.to_string()),
                }
            }
        } else if key.is("backspace") {
            draft.pop();
        } else if key.is("ctrl+u") {
            draft.clear();
        } else if key.name == "paste" {
            let text = key.text.as_deref().unwrap_or_default();
            draft.push_str(text.lines().next().unwrap_or_default());
        } else if let Some(text) = key.typed() {
            draft.push_str(text);
        }
        Outcome::Continue
    }

    fn key(&mut self, key: &Key) -> Outcome {
        if self.goto.is_some() {
            return self.goto_key(key);
        }
        let typed = key.typed().unwrap_or_default();
        if key.is("escape") || key.is("ctrl+c") || typed == "q" {
            return Outcome::Close;
        }
        let page = page() as isize;
        if key.is("up") || typed == "k" {
            self.move_by(-1);
        } else if key.is("down") || typed == "j" {
            self.move_by(1);
        } else if key.is("shift+up") {
            self.move_by(-page);
        } else if key.is("shift+down") || key.is("space") {
            self.move_by(page);
        } else if key.is("enter") || key.is("right") {
            self.follow();
        } else if key.is("backspace") || key.is("left") {
            self.back();
        } else if key.is("tab") {
            if let Some(here) = self.here() {
                self.jump(self.pane.other(), here);
            }
        } else if typed == "g" {
            self.goto = Some(String::new());
            self.focus_goto = true;
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

    fn row_id(&self, index: usize) -> String {
        format!("main.{ROWS_KEY}.{}", self.row_key(index))
    }

    fn row_key(&self, index: usize) -> String {
        match self.pane {
            Pane::Code => self
                .code
                .get(index)
                .map_or_else(String::new, |row| format!("c{:x}", row.row.ip)),
            Pane::Memory => self
                .memory
                .get(index)
                .map_or_else(String::new, |row| format!("m{:x}", row.address)),
        }
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
                for index in 0..self.memory.len() {
                    rows = rows.child(self.memory_line(index));
                }
            }
        }
        let mut dock: Vec<Node<Msg>> = Vec::new();
        if let Some(draft) = &self.goto {
            dock.push(
                ui::input()
                    .key(GOTO_KEY)
                    .text(draft.clone())
                    .cursor(draft.encode_utf16().count())
                    .prompt(vec![span("go to ", MUTED)])
                    .placeholder("address or expression".to_owned())
                    .into(),
            );
        }
        dock.push(self.location().into());
        dock.push(hints(self.pane).into());
        // A child of `main`, not its root: the screen region is a fixed-height
        // column that would shrink every row to nothing.
        View::new().main(vec![Node::from(rows)]).dock(dock)
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
        self.line(index, spans, row.ip)
    }

    fn memory_line(&self, index: usize) -> TextNode<Msg> {
        let row = &self.memory[index];
        let mut spans = vec![addr(row.address), span("  ", "")];
        match row.value() {
            Some(value) => {
                spans.push(span(
                    format!("{value:016x}"),
                    if value == 0 { DIM } else { "" },
                ));
                let ascii: String = row
                    .bytes
                    .iter()
                    .map(|&byte| {
                        if byte.is_ascii_graphic() || byte == b' ' {
                            byte as char
                        } else {
                            '·'
                        }
                    })
                    .collect();
                spans.push(span(format!("  {ascii}"), MUTED));
                if let Some(name) = &row.symbol {
                    spans.push(span("  ", ""));
                    spans.extend(symbol(name));
                }
            }
            None => spans.push(span("????????????????", MUTED)),
        }
        self.line(index, spans, row.address)
    }

    fn line(&self, index: usize, spans: Vec<Span>, address: u64) -> TextNode<Msg> {
        let line = ui::text(spans)
            .wrap(Wrap::None)
            .key(self.row_key(index))
            .on_click(Msg::Select(address))
            .on_dblclick(Msg::Follow(address));
        if index == self.cursor {
            line.mark(Mark::Pick)
        } else {
            line
        }
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

/// The keys, as keycaps with what they do.
fn hints(pane: Pane) -> ui::Row<Msg> {
    let other = format!("to {}", pane.other().name());
    let mut keys: Vec<(&[&str], &str)> = vec![
        (&["↑", "↓"], "move"),
        (&["⇧↑", "⇧↓"], "page"),
        (&["Enter"], "follow"),
        (&["⌫"], "back"),
        (&["Tab"], &other),
        (&["g"], "go to"),
    ];
    if pane == Pane::Code {
        keys.push((&["b"], "breakpoint"));
    }
    keys.push((&["."], "instruction pointer"));
    keys.push((&["Esc"], "close"));
    let mut row = ui::row().gap(Gap::Sm);
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
        .saturating_sub(4)
        .max(4)
}
