use std::borrow::Cow;
use std::fs::File;
use std::io::{Read, Write};

use owo_colors::OwoColorize;

use ntoseye_macros::{command, grammar};

use crate::arch::Arch;
use crate::base::bytes::utf16le_lossy;
use crate::base::error::{Error, Result, best_effort};
use crate::base::memory::{
    MemoryOps, TerminatedRead, for_each_page_chunk, pattern_offsets, read_page_chunks,
};
use crate::base::time::days_to_ymd;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::expr::Expr;
use crate::nt::guest::ProcessInfo;
use crate::nt::target::memory::{MemorySearchMatch, SearchSpace};
use crate::nt::target::mm::AddressKind;
use crate::nt::target::{
    CODE_BITNESS_X86, CompareResult, MAX_SEARCH_BYTES, MAX_SEARCH_MATCHES, MemoryKind,
    SearchResult, SearchStop, StringDescriptor,
};
use crate::nt::unwind::{resolve_thread_trace_context, try_format_symbol};
use crate::session::Session;

pub const MAX_DISPLAY_BYTES: usize = 1024 * 1024;
pub const MAX_DISASSEMBLY_INSTRUCTIONS: usize = 4096;
const FILETIME_UNIX_MIN_SECONDS: i64 = -62_135_596_800;
const FILETIME_UNIX_MAX_SECONDS: i64 = 253_402_300_799;
/// Characters `d*a`/`d*u` show of each string, as `da`/`du` do by default.
const POINTER_STRING_CHARS: usize = 256;
/// Characters `da`/`du` show without a count.
const DEFAULT_STRING_CHARS: usize = 256;

/// What the `d*p`, `d*a`, and `d*u` commands show after each pointer.
#[derive(Clone, Copy)]
enum Pointee {
    /// The pointer-sized value it points to (`d*p`).
    Value,
    /// The NUL-terminated string it points to, in 1-byte (`d*a`) or 2-byte
    /// (`d*u`) units.
    String { char_size: usize },
}

impl Pointee {
    /// The pointer size, default count and pointee of the command `name`:
    /// `dd*` reads doublewords, `dq*` and `dp*` quadwords; the last letter
    /// says what follows each pointer.
    fn of(name: &str) -> (usize, u64, Self) {
        let (item_size, default_count) = if name.starts_with("dd") {
            (4, 16)
        } else {
            (8, 8)
        };
        let pointee = match name.as_bytes().get(2) {
            Some(b'a') => Pointee::String { char_size: 1 },
            Some(b'u') => Pointee::String { char_size: 2 },
            _ => Pointee::Value,
        };
        (item_size, default_count, pointee)
    }
}

/// A little-endian doubleword or quadword.
fn le_value(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

/// Read `range` a page at a time, so one missing page does not hide the
/// readable bytes before and after it: the bytes, and which of them were
/// read. Virtual memory is the inspection space as the guest runs it, with
/// this session's breakpoints masked.
fn read_best_effort(
    session: &Session,
    memory: MemoryKind,
    range: &AddressRange,
) -> Result<(Vec<u8>, Vec<bool>)> {
    read_page_chunks(range.start, range.len(), |address, buf| match memory {
        MemoryKind::Virtual => session.read_masked(address, buf),
        MemoryKind::Physical => session.target.read_physical(address.0, buf),
    })
}

/// Refuse a display range over [`MAX_DISPLAY_BYTES`].
fn require_display_range(range: &AddressRange) -> Result<()> {
    if range.len() > MAX_DISPLAY_BYTES {
        return Err(Error::DebugInfo(format!(
            "display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes"
        )));
    }
    Ok(())
}

/// `range`'s items of `item_size` bytes: each one's address, bytes (fewer at
/// the end of a range that ends inside an item), and whether all of them were
/// read.
fn items<'a>(
    range: &AddressRange,
    data: &'a [u8],
    valid: &'a [bool],
    item_size: usize,
) -> impl Iterator<Item = (VirtAddr, &'a [u8], bool)> {
    let start = range.start;
    data.chunks(item_size)
        .enumerate()
        .map(move |(index, chunk)| {
            let offset = index * item_size;
            let readable = chunk.len() == item_size
                && valid
                    .get(offset..offset + item_size)
                    .is_some_and(|bytes| bytes.iter().all(|ok| *ok));
            (start + offset as u64, chunk, readable)
        })
}

/// Memory a display command read, and how it shows it.
pub struct MemoryDump {
    pub start: VirtAddr,
    pub data: Vec<u8>,
    /// Which bytes of `data` were read.
    pub valid: Vec<bool>,
    pub mode: MemoryDisplayMode,
}

/// Read `range` of `memory` for display in `mode`.
pub(super) fn dump_memory(
    session: &Session,
    memory: MemoryKind,
    range: AddressRange,
    mode: MemoryDisplayMode,
) -> Result<MemoryDump> {
    require_display_range(&range)?;
    let (data, valid) = read_best_effort(session, memory, &range)?;
    Ok(MemoryDump {
        start: range.start,
        data,
        valid,
        mode,
    })
}

impl Render for MemoryDump {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        display_memory_with_validity(self.start, &self.data, Some(&self.valid), &self.mode);
    }
}

/// A display command's `<address> [L<count>|length|end]`, `COUNT` items of
/// `SIZE` bytes without an end.
#[grammar(usage = "<address> [L<count>|length|end]", complete = [Expression, Expression])]
fn display_range<const COUNT: u64, const SIZE: u64>(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AddressRange, ArgError> {
    AddressRange::from_args(cx, cursor, COUNT, SIZE)
}

/// Show memory as bytes.
#[command(
    names = ["db"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn db(
    session: &Session,
    #[arg(parse = display_range::<128, 1>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Virtual,
        range,
        MemoryDisplayMode::bytes(),
    )
}

/// Show memory as words (2 bytes).
#[command(
    names = ["dw"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dw(
    session: &Session,
    #[arg(parse = display_range::<32, 2>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Virtual,
        range,
        MemoryDisplayMode::words(),
    )
}

/// Show memory as words with an ASCII column.
#[command(
    names = ["dW"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dw_ascii(
    session: &Session,
    #[arg(parse = display_range::<32, 2>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Virtual,
        range,
        MemoryDisplayMode::words_ascii(),
    )
}

/// Show memory as doublewords with an ASCII column.
#[command(
    names = ["dc"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dc(
    session: &Session,
    #[arg(parse = display_range::<16, 4>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Virtual,
        range,
        MemoryDisplayMode::dwords_ascii(),
    )
}

/// Show memory as doublewords (4 bytes).
#[command(
    names = ["dd"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dd(
    session: &Session,
    #[arg(parse = display_range::<16, 4>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Virtual,
        range,
        MemoryDisplayMode::dwords(),
    )
}

/// Show memory as quadwords (8 bytes).
#[command(
    names = ["dq"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dq(
    session: &Session,
    #[arg(parse = display_range::<8, 8>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Virtual,
        range,
        MemoryDisplayMode::qwords(),
    )
}

/// Show memory as pointer-sized values.
#[command(
    names = ["dp"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dp(
    session: &Session,
    #[arg(parse = display_range::<8, 8>)] range: AddressRange,
) -> Result<MemoryDump> {
    // ntoseye supports only 64-bit Windows targets, so pointer-sized
    // display is a qword on both supported architectures.
    dump_memory(
        session,
        MemoryKind::Virtual,
        range,
        MemoryDisplayMode::qwords(),
    )
}

/// Show memory as binary values with their bytes.
#[command(
    names = ["dyb"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dyb(
    session: &Session,
    #[arg(parse = display_range::<128, 1>)] range: AddressRange,
) -> Result<MemoryDump> {
    dump_memory(
        session,
        MemoryKind::Virtual,
        range,
        MemoryDisplayMode::binary(),
    )
}

/// `df`'s range of four-byte floats, or `dD`'s of eight-byte doubles.
#[grammar(usage = "<address> [L<count>|length|end]", complete = [Expression, Expression])]
fn float_range(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AddressRange, ArgError> {
    if cx.name == "df" {
        AddressRange::from_args(cx, cursor, 16, 4)
    } else {
        AddressRange::from_args(cx, cursor, 6, 8)
    }
}

/// Show memory as single-precision (df, 4-byte) or double-precision (dD, 8-byte) floating-point numbers.
#[command(
    names = ["df", "dD"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn df(
    session: &Session,
    #[arg(parse = float_range)] range: AddressRange,
    #[arg(invoked)] name: &str,
) -> Result<MemoryDump> {
    let mode = if name == "df" {
        MemoryDisplayMode::floats()
    } else {
        MemoryDisplayMode::doubles()
    };
    dump_memory(session, MemoryKind::Virtual, range, mode)
}

/// What `dds`/`dqs` show of an item.
pub enum SymbolValue {
    /// The range ends inside the item.
    Partial,
    /// A byte of the item is unreadable.
    Unreadable,
    /// The value, and the symbol it resolves to.
    Value { value: u64, symbol: Option<String> },
}

/// A `dds`/`dqs` row: an item's address and what it holds.
pub struct SymbolValueRow {
    pub address: VirtAddr,
    pub value: SymbolValue,
}

/// `dds`/`dqs`: memory as `item_size`-byte values, and their symbols.
pub struct SymbolValues {
    pub item_size: usize,
    pub rows: Vec<SymbolValueRow>,
}

/// Read `range` as `item_size`-byte values and resolve each to the symbol it
/// points at, in the current thread's context.
fn symbol_values(
    session: &Session,
    range: &AddressRange,
    item_size: usize,
) -> Result<SymbolValues> {
    require_display_range(range)?;
    let (data, valid) = read_best_effort(session, MemoryKind::Virtual, range)?;
    let target = &session.target;
    let trace = resolve_thread_trace_context(target, target.current_dtb());
    let rows = items(range, &data, &valid, item_size)
        .filter_map(|(address, chunk, readable)| {
            let value = if chunk.len() != item_size {
                SymbolValue::Partial
            } else if !readable {
                SymbolValue::Unreadable
            } else {
                let value = le_value(chunk)?;
                SymbolValue::Value {
                    value,
                    symbol: try_format_symbol(target, &trace, value),
                }
            };
            Some(SymbolValueRow { address, value })
        })
        .collect();
    Ok(SymbolValues { item_size, rows })
}

impl SymbolValues {
    fn show(&self, session: &Session) {
        print_symbol_values(session, &self.rows, self.item_size);
    }
}

impl Render for SymbolValues {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        self.show(repl.ctx);
    }
}

/// `arch`'s registers whose values a `dqs` slot can hold the address of,
/// the stack and frame pointers first.
fn slot_registers(arch: Arch) -> impl Iterator<Item = &'static str> {
    let first = [arch.sp_register(), arch.frame_register()];
    let rest = arch
        .general_registers()
        .iter()
        .copied()
        .filter(move |name| !first.contains(name) && *name != arch.flags_register());
    first.into_iter().chain(rest)
}

/// `dds`/`dqs` as text, a line per item, values `item_size * 2` digits
/// wide, read as a stack: each slot a register points into named before it
/// (`rsp ▶`), and a value that is a return address (the code before it
/// ends in a call) marked `↩` before its symbol.
fn print_symbol_values(session: &Session, rows: &[SymbolValueRow], item_size: usize) {
    let target = &session.target;
    // The selected frame's registers, else the selected thread's.
    let registers = target
        .selected_frame
        .as_ref()
        .map(|frame| &frame.registers)
        .or(target.registers.as_ref());
    let pointing = |address: u64| -> Vec<&str> {
        let Some(registers) = registers else {
            return Vec::new();
        };
        let slot = address..address.saturating_add(item_size as u64);
        slot_registers(target.arch())
            .filter(|name| {
                registers
                    .get(*name)
                    .is_some_and(|value| slot.contains(value))
            })
            .collect()
    };
    let markers: Vec<String> = rows
        .iter()
        .map(|row| {
            let names = pointing(row.address.0);
            if names.is_empty() {
                String::new()
            } else {
                format!("{} \u{25b6}", names.join(" "))
            }
        })
        .collect();
    let marker_width = markers
        .iter()
        .map(|marker| marker.chars().count())
        .max()
        .unwrap_or(0);
    // A return address: the code before it, as the code there decodes,
    // ends in a call.
    let returns = |value: u64| {
        let mut before = [0u8; 8];
        value.checked_sub(before.len() as u64).is_some_and(|from| {
            session.read_masked(VirtAddr(from), &mut before).is_ok()
                && target
                    .code_machine(VirtAddr(value))
                    .instruction_set()
                    .ends_in_call(&before)
        })
    };
    let width = item_size * 2;
    for (row, marker) in rows.iter().zip(&markers) {
        let marker = match marker_width {
            0 => String::new(),
            width => format!("{} ", format!("{marker:>width$}").cyan()),
        };
        let address = ui::addr(row.address.0);
        match &row.value {
            SymbolValue::Partial => outln!("{marker}{address}  <partial>"),
            SymbolValue::Unreadable => outln!("{marker}{address}  <unreadable>"),
            SymbolValue::Value { value, symbol } => {
                let symbol = match symbol {
                    Some(symbol) if returns(*value) => {
                        format!("  \u{21a9} {}", ui::symbol(symbol))
                    }
                    Some(symbol) => format!("  {}", ui::symbol(symbol)),
                    None => String::new(),
                };
                outln!("{marker}{address}  {value:0width$x}{symbol}");
            }
        }
    }
    outln!();
}

impl ReplState<'_> {
    /// `dds`/`dqs` over `range`: each value, and the symbol it resolves to.
    pub fn display_symbol_range(&self, range: &AddressRange, item_size: usize) -> Result<()> {
        match symbol_values(self.ctx, range, item_size) {
            Ok(values) => values.show(self.ctx),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}

/// Show memory as doublewords, and the symbol of each value that resolves to one.
#[command(
    names = ["dds"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dds(
    session: &Session,
    #[arg(parse = display_range::<16, 4>)] range: AddressRange,
) -> Result<SymbolValues> {
    symbol_values(session, &range, 4)
}

/// Show memory as quadwords, and the symbol of each value that resolves to one.
///
/// Use it for raw stack triage. If the unwinder cannot find the return
/// addresses, dqs @rsp finds them in the raw stack.
#[command(
    names = ["dqs", "dps"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dqs(
    session: &Session,
    #[arg(parse = display_range::<16, 8>)] range: AddressRange,
) -> Result<SymbolValues> {
    symbol_values(session, &range, 8)
}

/// What a `d*p`/`d*a`/`d*u` pointer points to.
pub enum PointeeValue {
    /// The pointer-sized value there and its symbol; `None` when it is
    /// unreadable.
    Value(Option<(u64, Option<String>)>),
    /// The NUL-terminated string there.
    String {
        read: TerminatedRead,
        char_size: usize,
    },
}

/// What a `d*p`/`d*a`/`d*u` item holds.
pub enum PointerValue {
    /// The range ends inside the item.
    Partial,
    /// A byte of the item is unreadable.
    Unreadable,
    Pointer {
        pointer: u64,
        /// The symbol the pointer resolves to (`d*p` only).
        symbol: Option<String>,
        /// What it points to; `None` for a string that is null or
        /// unreadable, which shows nothing, as in WinDbg.
        pointee: Option<PointeeValue>,
    },
}

pub struct PointerRow {
    pub address: VirtAddr,
    pub value: PointerValue,
}

/// `d*p`, `d*a`, `d*u`: pointers, and what each points to.
pub struct Pointers {
    pub item_size: usize,
    pub rows: Vec<PointerRow>,
}

/// Read `range` as `item_size`-byte pointers, and what each points to.
fn pointers(
    session: &Session,
    range: &AddressRange,
    item_size: usize,
    pointee: Pointee,
) -> Result<Pointers> {
    require_display_range(range)?;
    let (data, valid) = read_best_effort(session, MemoryKind::Virtual, range)?;
    let target = &session.target;
    let trace = resolve_thread_trace_context(target, target.current_dtb());
    let rows = items(range, &data, &valid, item_size)
        .filter_map(|(address, chunk, readable)| {
            let value = if chunk.len() != item_size {
                PointerValue::Partial
            } else if !readable {
                PointerValue::Unreadable
            } else {
                let pointer = le_value(chunk)?;
                match pointee {
                    Pointee::Value => {
                        let pointed = if pointer == 0 {
                            Some((0, None))
                        } else {
                            let mut pointed = vec![0u8; item_size];
                            session
                                .read_masked(VirtAddr(pointer), &mut pointed)
                                .ok()
                                .and_then(|()| le_value(&pointed))
                                .map(|value| (value, try_format_symbol(target, &trace, value)))
                        };
                        PointerValue::Pointer {
                            pointer,
                            symbol: try_format_symbol(target, &trace, pointer),
                            pointee: Some(PointeeValue::Value(pointed)),
                        }
                    }
                    Pointee::String { char_size } => PointerValue::Pointer {
                        pointer,
                        symbol: None,
                        pointee: (pointer != 0)
                            .then(|| {
                                session
                                    .read_terminated(
                                        VirtAddr(pointer),
                                        POINTER_STRING_CHARS,
                                        char_size,
                                    )
                                    .ok()
                            })
                            .flatten()
                            .map(|read| PointeeValue::String { read, char_size }),
                    },
                }
            };
            Some(PointerRow { address, value })
        })
        .collect();
    Ok(Pointers { item_size, rows })
}

impl Render for Pointers {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let width = self.item_size * 2;
        for row in &self.rows {
            let address = ui::addr(row.address.0);
            let PointerValue::Pointer {
                pointer,
                symbol,
                pointee,
            } = &row.value
            else {
                let reason = match row.value {
                    PointerValue::Partial => "<partial>",
                    _ => "<unreadable>",
                };
                outln!("{address}  {reason}");
                continue;
            };
            let mut line = format!("{address}  {pointer:0width$x}");
            if let Some(symbol) = symbol {
                line.push_str(&format!("  {}", ui::symbol(symbol)));
            }
            match pointee {
                Some(PointeeValue::Value(Some((value, symbol)))) => {
                    line.push_str(&format!("  -> {value:0width$x}"));
                    if let Some(symbol) = symbol {
                        line.push_str(&format!("  {}", ui::symbol(symbol)));
                    }
                }
                Some(PointeeValue::Value(None)) => line.push_str("  -> <unreadable>"),
                Some(PointeeValue::String { read, char_size }) => {
                    line.push_str("  ");
                    line.push_str(&quote_terminated(read, POINTER_STRING_CHARS, *char_size));
                }
                None => {}
            }
            outln!("{}", line);
        }
        outln!();
    }
}

/// The range of the `d*p` family member typed: its pointer size decides the
/// default count and the size of an `L<count>` item.
#[grammar(usage = "<address> [L<count>|length|end]", complete = [Expression, Expression])]
fn pointer_range(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AddressRange, ArgError> {
    let (item_size, default_count, _) = Pointee::of(cx.name);
    AddressRange::from_args(cx, cursor, default_count, item_size as u64)
}

/// Show pointers and the data that each pointer points to.
///
/// After each pointer, d*p shows the value, d*a the ASCII string, and d*u
/// the UTF-16 string at that pointer. dd* reads doubleword pointers, and
/// dq* and its dp* aliases read quadwords. d*p also shows symbols.
#[command(
    names = ["dpp", "dqp", "ddp", "dqa", "dpa", "dda", "dqu", "dpu", "ddu"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn dpp(
    session: &Session,
    #[arg(parse = pointer_range)] range: AddressRange,
    #[arg(invoked)] name: &str,
) -> Result<Pointers> {
    let (item_size, _, pointee) = Pointee::of(name);
    pointers(session, &range, item_size, pointee)
}

/// The NUL-terminated string of `char_size`-wide units, quoted and escaped
/// as `da`/`du` show it, marked when it is cut short by `max_chars` or an
/// unreadable page.
fn quote_terminated(read: &TerminatedRead, max_chars: usize, char_size: usize) -> String {
    let text: String = if char_size == 1 {
        read.bytes.iter().map(|&byte| char::from(byte)).collect()
    } else {
        utf16le_lossy(&read.bytes)
    };
    let suffix = if read.unreadable {
        " <unreadable>".red().to_string()
    } else if read.bytes.len() / char_size == max_chars {
        "...".bright_black().to_string()
    } else {
        String::new()
    };
    format!("\"{}\"{}", text.escape_debug(), suffix)
}

/// A NUL-terminated string `da`/`du` read.
pub struct TerminatedString {
    pub address: VirtAddr,
    pub read: TerminatedRead,
    pub max_chars: usize,
    pub char_size: usize,
}

/// Read the NUL-terminated string of `char_size`-wide units at `address`,
/// up to `max_chars`. Reads stop at an unreadable page, so a string ending
/// near one still shows up to the readable part.
fn terminated_string(
    session: &Session,
    address: VirtAddr,
    max_chars: usize,
    char_size: usize,
) -> Result<TerminatedString> {
    let read = session
        .read_terminated(address, max_chars, char_size)
        .map_err(|error| {
            Error::DebugInfo(format!(
                "failed to read string at {:#x}: {}",
                address.0, error
            ))
        })?;
    Ok(TerminatedString {
        address,
        read,
        max_chars,
        char_size,
    })
}

impl Render for TerminatedString {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!(
            "{}  {}\n",
            ui::addr(self.address.0),
            quote_terminated(&self.read, self.max_chars, self.char_size)
        );
    }
}

/// `da`/`du`'s `[max-chars]`: a positive count of `CHAR_SIZE`-byte units
/// within [`MAX_DISPLAY_BYTES`].
#[grammar(usage = "[{}]", complete = [Expression])]
fn max_chars<const CHAR_SIZE: usize>(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<usize, ArgError> {
    let Some(text) = cursor.word() else {
        return Ok(DEFAULT_STRING_CHARS);
    };
    match cx.eval(&text)? {
        VirtAddr(0) => Err(ArgError::Message(format!("invalid max-chars: {text}"))),
        VirtAddr(count) => checked_display_string_count(count, CHAR_SIZE)
            .map_err(|error| ArgError::Message(error.to_string())),
    }
}

/// Show a NUL-terminated ASCII string.
#[command(
    names = ["da"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn da(
    session: &Session,
    address: VirtAddr,
    #[arg(parse = max_chars::<1>)] max_chars: usize,
) -> Result<TerminatedString> {
    terminated_string(session, address, max_chars, 1)
}

/// Show a NUL-terminated UTF-16 string (for example, a UNICODE_STRING Buffer).
#[command(
    names = ["du"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn du(
    session: &Session,
    address: VirtAddr,
    #[arg(parse = max_chars::<2>)] max_chars: usize,
) -> Result<TerminatedString> {
    terminated_string(session, address, max_chars, 2)
}

/// What a counted string's buffer holds.
pub enum CountedText {
    /// `Length` or `Buffer` is unreadable.
    Unreadable,
    /// No characters, or a null buffer.
    Empty,
    /// The characters, and whether all of them were read.
    Text { text: String, complete: bool },
}

/// An `ANSI_STRING`/`UNICODE_STRING` descriptor and its buffer (`ds`/`dS`).
pub struct CountedString {
    pub address: VirtAddr,
    pub length: Option<u16>,
    pub maximum_length: Option<u16>,
    pub buffer: Option<VirtAddr>,
    pub text: CountedText,
}

struct StringDescriptorFields {
    length: Option<u16>,
    maximum_length: Option<u16>,
    buffer: Option<VirtAddr>,
}

/// The fields of the string descriptor at `address`, each `None` when
/// unreadable.
fn string_descriptor_fields(
    session: &Session,
    address: VirtAddr,
    kind: StringDescriptor,
) -> Result<StringDescriptorFields> {
    let target = &session.target;
    // `.effmach x86` reads a WOW64 process's 32-bit descriptors.
    let bits = target.data_bitness();
    if let Ok(cursor) = target.string_descriptor(address, kind, bits) {
        let fields = StringDescriptorFields {
            length: best_effort(cursor.read_field::<u16>("Length"))?,
            maximum_length: best_effort(cursor.read_field::<u16>("MaximumLength"))?,
            buffer: best_effort(cursor.read_pointer("Buffer"))?,
        };
        if fields.length.is_some() || fields.maximum_length.is_some() || fields.buffer.is_some() {
            return Ok(fields);
        }
    }

    // These descriptors have a stable Windows layout at each width:
    // `Buffer` follows the two lengths at pointer alignment. Retaining it
    // keeps ds/dS useful in a dump whose PDB omits the tiny string type.
    let mem = target.context_memory();
    let buffer = if bits == CODE_BITNESS_X86 {
        best_effort(mem.read::<u32>(address + 4u64))?.map(VirtAddr::from)
    } else {
        best_effort(mem.read_pointer(address + mem.arch().pointer_size()))?
    };
    Ok(StringDescriptorFields {
        length: best_effort(mem.read(address))?,
        maximum_length: best_effort(mem.read(address + 2u64))?,
        buffer,
    })
}

/// Read the `kind` descriptor at `address` and its buffer; `command` names
/// it in an error.
fn counted_string(
    session: &Session,
    address: VirtAddr,
    kind: StringDescriptor,
    command: &str,
) -> Result<CountedString> {
    let StringDescriptorFields {
        length,
        maximum_length,
        buffer,
    } = string_descriptor_fields(session, address, kind).map_err(|error| {
        Error::DebugInfo(format!(
            "failed to read {} at {}: {}",
            command,
            ui::addr(address.0),
            error
        ))
    })?;
    let unit_size = match kind {
        StringDescriptor::Unicode => 2usize,
        StringDescriptor::Ansi => 1usize,
    };
    let text = match (length, buffer) {
        (Some(length), Some(buffer)) => {
            // A Length past MaximumLength is a corrupt or unrelated
            // descriptor; the buffer holds no more than MaximumLength bytes.
            let length = maximum_length.map_or(length, |maximum| length.min(maximum));
            let byte_len = (length as usize / unit_size) * unit_size;
            if byte_len == 0 || buffer.is_zero() {
                CountedText::Empty
            } else {
                let range = AddressRange {
                    start: buffer,
                    end: buffer + byte_len as u64,
                };
                let (data, valid) = read_best_effort(session, MemoryKind::Virtual, &range)?;
                let text = match kind {
                    StringDescriptor::Unicode => utf16le_lossy(&data),
                    StringDescriptor::Ansi => String::from_utf8_lossy(&data).into_owned(),
                };
                CountedText::Text {
                    text,
                    complete: valid.iter().all(|ok| *ok),
                }
            }
        }
        _ => CountedText::Unreadable,
    };
    Ok(CountedString {
        address,
        length,
        maximum_length,
        buffer,
        text,
    })
}

impl Render for CountedString {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let unreadable = || "<unreadable>".to_string();
        let length = self
            .length
            .map_or_else(unreadable, |value| value.to_string());
        let maximum_length = self
            .maximum_length
            .map_or_else(unreadable, |value| value.to_string());
        let buffer = self
            .buffer
            .map_or_else(unreadable, |value| ui::addr(value.0));
        let text = match &self.text {
            CountedText::Unreadable => "<unreadable>".to_string(),
            CountedText::Empty => "\"\"".to_string(),
            CountedText::Text { text, complete } => format!(
                "\"{}\"{}",
                text.escape_debug(),
                if *complete {
                    String::new()
                } else {
                    " <unreadable>".red().to_string()
                }
            ),
        };
        outln!(
            "{}  Length={} MaximumLength={} Buffer={}  {}\n",
            ui::addr(self.address.0),
            length,
            maximum_length,
            buffer,
            text
        );
    }
}

/// Show an ANSI_STRING descriptor and its buffer.
#[command(
    names = ["ds"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn ds(session: &Session, address: VirtAddr) -> Result<CountedString> {
    counted_string(session, address, StringDescriptor::Ansi, "ds")
}

/// Show a UNICODE_STRING descriptor and its buffer.
#[command(
    names = ["dS"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn ds_unicode(session: &Session, address: VirtAddr) -> Result<CountedString> {
    counted_string(session, address, StringDescriptor::Unicode, "dS")
}

/// What `.pagein` pages in: the address, in a process's space with `/p`.
struct PageInRequest {
    process: Option<ProcessInfo>,
    address: VirtAddr,
}

/// `.pagein [/p <pid|eprocess>] <address>`.
#[grammar(usage = "[/p <pid|eprocess>] <address>", complete = [None, Process, Expression])]
fn pagein_request(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<PageInRequest, ArgError> {
    let message = |text: String| ArgError::Message(text);
    let mut address_text: Option<Cow<'_, str>> = None;
    let mut process_text = None;
    while let Some(arg) = cursor.word() {
        if arg == "/p" {
            let Some(selector) = cursor.word() else {
                return Err(message("/p needs a PID or EPROCESS".to_string()));
            };
            process_text = Some(selector);
        } else if arg.starts_with('/') {
            return Err(ArgError::usage(
                cx.name,
                format!("unknown {} switch '{arg}'", cx.name),
            ));
        } else if address_text.replace(arg).is_some() {
            return Err(ArgError::usage(
                cx.name,
                format!("{} accepts one address", cx.name),
            ));
        }
    }
    let Some(address_text) = address_text else {
        return Err(ArgError::usage(
            cx.name,
            format!("{} needs an address", cx.name),
        ));
    };
    let address = cx.eval(&address_text)?;
    let process = match process_text {
        Some(selector) => {
            let state = &*cx.state;
            let processes = state
                .ctx
                .target
                .matching_processes(None)
                .map_err(|error| message(format!("failed to enumerate processes: {error}")))?;
            let process = state
                .process_for_selector(&selector, &processes)
                .ok_or_else(|| message(format!("no process matches '{selector}'")))?;
            Some(process)
        }
        None => None,
    };
    Ok(PageInRequest { process, address })
}

/// Make a paged-out address resident with the debugger worker in the guest.
///
/// Because the guest does the work, ntoseye resumes the target, which halts
/// again at nt!DbgBreakPointWithStatus and not at its earlier location. `/p`
/// attaches the worker to a process first, which user-space addresses need.
#[command(
    names = [".pagein"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    state = Halted,
    run = Run,
    writes = [Memory],
    forms = [page_in],
)]
fn pagein(
    state: &mut ReplState<'_>,
    #[arg(parse = pagein_request)] request: PageInRequest,
) -> Result<()> {
    let PageInRequest { process, address } = request;
    outln!("resuming the target so its debugger worker can run");
    state.clear_selected_frame();
    let report = state
        .ctx
        .page_in(address, process.map(|process| process.eprocess.0))?;
    if !report.from_worker {
        return Err(Error::DebugInfo(format!(
            "the target stopped for another reason before the worker reported; {} may still be \
             paged in",
            ui::addr(address.0)
        )));
    }
    if !report.resident {
        // MmPrefetchVirtualMemory declines addresses that are not backed
        // at all, and the worker reports completion either way.
        return Err(Error::DebugInfo(format!(
            "{} is still unreadable; it may be unmapped rather than paged out",
            ui::addr(address.0)
        )));
    }
    outln!("{} is resident", ui::addr(address.0));
    Ok(())
}

/// Make `address` resident with the guest debugger worker (`.pagein`), which
/// resumes the guest. When the worker completes, the guest stops and the
/// method returns, and `dbg.stop` shows that stop.
#[command(form_of = pagein, python = Memory)]
fn page_in(
    session: &mut Session,
    #[arg(receiver)] memory: MemoryKind,
    #[arg(receiver)] process: Option<ProcessInfo>,
    address: VirtAddr,
) -> Result<bool> {
    memory.require_virtual()?;
    let report = session.page_in(address, process.map(|process| process.eprocess.0))?;
    if !report.from_worker {
        return Err(Error::DebugInfo(
            "the target stopped for another reason before the worker reported".to_string(),
        ));
    }
    Ok(report.resident)
}

/// The width of the integers `eb`/`ew`/`ed`/`eq` (and `!eb`/`!ed`/`!eq`)
/// write.
#[derive(Clone, Copy)]
pub enum WriteUnit {
    Byte,
    Word,
    Dword,
    Qword,
}

impl WriteUnit {
    /// What an error calls a value.
    pub fn noun(self) -> &'static str {
        match self {
            Self::Byte => "byte",
            Self::Word => "word",
            Self::Dword => "dword",
            Self::Qword => "qword",
        }
    }

    /// `values`, truncated to this width, little-endian.
    pub fn encode(self, values: &[u64]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &value in values {
            match self {
                Self::Byte => bytes.push(value as u8),
                Self::Word => bytes.extend((value as u16).to_le_bytes()),
                Self::Dword => bytes.extend((value as u32).to_le_bytes()),
                Self::Qword => bytes.extend(value.to_le_bytes()),
            }
        }
        bytes
    }

    fn show(self, value: u64) -> String {
        match self {
            Self::Byte => format!("{:02x}", value as u8),
            Self::Word => format!("{:04x}", value as u16),
            Self::Dword => format!("{:#x}", value as u32),
            Self::Qword => format!("{value:#x}"),
        }
    }
}

/// The values an `e*` command wrote.
pub enum WrittenValues {
    Integers(WriteUnit, Vec<u64>),
    Floats(Vec<f32>),
    Doubles(Vec<f64>),
}

/// Values written to virtual memory.
pub struct ValuesWritten {
    pub address: VirtAddr,
    pub values: WrittenValues,
}

impl Render for ValuesWritten {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let shown: Vec<String> = match &self.values {
            WrittenValues::Integers(unit, values) => {
                values.iter().map(|&value| unit.show(value)).collect()
            }
            WrittenValues::Floats(values) => {
                values.iter().map(|&value| format_float(value)).collect()
            }
            WrittenValues::Doubles(values) => {
                values.iter().map(|&value| format_float(value)).collect()
            }
        };
        outln!(
            "{} {} -> {}\n",
            "wrote".green(),
            shown.join(" "),
            ui::addr(self.address.0)
        );
    }
}

/// Write `bytes` at `address` in `memory`: the inspection space's virtual
/// addresses, or guest-physical ones. `noun` names what they are in an
/// error. Every memory-writing command and SDK method writes through it.
pub fn write_memory(
    session: &Session,
    memory: MemoryKind,
    address: VirtAddr,
    bytes: &[u8],
    noun: &str,
) -> Result<()> {
    session
        .target
        .write_memory(memory, address.0, bytes)
        .map_err(|error| {
            let space = match memory {
                MemoryKind::Virtual => "",
                MemoryKind::Physical => "physical ",
            };
            Error::DebugInfo(format!("failed to write {space}{noun}: {error}"))
        })
}

/// Write `bytes` at `address` in the inspection space.
fn write_virtual(session: &Session, address: VirtAddr, bytes: &[u8], noun: &str) -> Result<()> {
    write_memory(session, MemoryKind::Virtual, address, bytes, noun)
}

/// Write `values` as `unit`s at `address`.
fn write_integers(
    session: &Session,
    address: VirtAddr,
    values: Vec<u64>,
    unit: WriteUnit,
) -> Result<ValuesWritten> {
    write_virtual(session, address, &unit.encode(&values), unit.noun())?;
    Ok(ValuesWritten {
        address,
        values: WrittenValues::Integers(unit, values),
    })
}

/// A write's `<address>`, which needs a value after it.
#[grammar(usage = "<{}>", complete = [Expression])]
pub fn write_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    if cursor.remaining() < 2 {
        return Err(ArgError::Missing);
    }
    let text = cursor.word().ok_or(ArgError::Missing)?;
    cx.eval(&text)
}

/// Every word left, in order.
fn words<'i>(cursor: &mut ArgCursor<'i>) -> Vec<Cow<'i, str>> {
    std::iter::from_fn(|| cursor.word()).collect()
}

/// A write's `<value>...`: each word an expression, or, when one of them is
/// not, all of them one expression (`eb @rsp 1 + 1`).
#[grammar(usage = "<value>...", complete = Expression)]
pub fn write_values(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Vec<u64>, ArgError> {
    let words = words(cursor);
    if words.is_empty() {
        return Err(ArgError::Missing);
    }
    match words
        .iter()
        .map(|word| cx.eval(word).map(|value| value.0))
        .collect()
    {
        Ok(values) => Ok(values),
        Err(_) => Ok(vec![cx.eval(&words.join(" "))?.0]),
    }
}

/// Write one or more bytes to memory.
#[command(
    names = ["eb"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    forms = [write_bytes, write_u8],
)]
fn eb(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(parse = write_values)] values: Vec<u64>,
) -> Result<ValuesWritten> {
    write_integers(session, address, values, WriteUnit::Byte)
}

/// Write bytes to this address space.
#[command(form_of = eb, python = Memory, python_name = "write")]
fn write_bytes(
    session: &Session,
    #[arg(receiver)] memory: MemoryKind,
    address: VirtAddr,
    data: Vec<u8>,
) -> Result<()> {
    write_memory(session, memory, address, &data, "bytes")
}

/// Write a little-endian byte.
#[command(form_of = eb, python = Memory)]
fn write_u8(
    session: &Session,
    #[arg(receiver)] memory: MemoryKind,
    address: VirtAddr,
    value: u8,
) -> Result<()> {
    write_memory(session, memory, address, &[value], WriteUnit::Byte.noun())
}

/// Write one or more words (2 bytes) to memory.
#[command(
    names = ["ew"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    forms = [write_u16],
)]
fn ew(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(parse = write_values)] values: Vec<u64>,
) -> Result<ValuesWritten> {
    write_integers(session, address, values, WriteUnit::Word)
}

/// Write a little-endian 16-bit integer.
#[command(form_of = ew, python = Memory)]
fn write_u16(
    session: &Session,
    #[arg(receiver)] memory: MemoryKind,
    address: VirtAddr,
    value: u16,
) -> Result<()> {
    let bytes = value.to_le_bytes();
    write_memory(session, memory, address, &bytes, WriteUnit::Word.noun())
}

/// Write one or more doublewords (4 bytes) to memory.
#[command(
    names = ["ed"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    forms = [write_u32],
)]
fn ed(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(parse = write_values)] values: Vec<u64>,
) -> Result<ValuesWritten> {
    write_integers(session, address, values, WriteUnit::Dword)
}

/// Write a little-endian 32-bit integer.
#[command(form_of = ed, python = Memory)]
fn write_u32(
    session: &Session,
    #[arg(receiver)] memory: MemoryKind,
    address: VirtAddr,
    value: u32,
) -> Result<()> {
    let bytes = value.to_le_bytes();
    write_memory(session, memory, address, &bytes, WriteUnit::Dword.noun())
}

/// Write one or more quadwords (8 bytes) to memory.
#[command(
    names = ["eq"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    forms = [write_u64],
)]
fn eq(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(parse = write_values)] values: Vec<u64>,
) -> Result<ValuesWritten> {
    write_integers(session, address, values, WriteUnit::Qword)
}

/// Write a little-endian 64-bit integer.
#[command(form_of = eq, python = Memory)]
fn write_u64(
    session: &Session,
    #[arg(receiver)] memory: MemoryKind,
    address: VirtAddr,
    value: u64,
) -> Result<()> {
    let bytes = value.to_le_bytes();
    write_memory(session, memory, address, &bytes, WriteUnit::Qword.noun())
}

/// `ef`/`eD`'s `<number>...`: decimal floating-point literals.
#[grammar(usage = "<number>...", complete = Expression)]
fn float_values(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Vec<f64>, ArgError> {
    let words = words(cursor);
    if words.is_empty() {
        return Err(ArgError::Missing);
    }
    words
        .iter()
        .map(|text| {
            text.parse::<f64>()
                .map_err(|_| ArgError::Message(format!("invalid floating-point number '{text}'")))
        })
        .collect()
}

/// Write single-precision (ef, 4-byte) or double-precision (eD, 8-byte) floating-point numbers to memory.
///
/// The numbers are decimal floating-point literals (`ef @rcx 1.5 -2 3e-4`),
/// whatever the radix setting.
#[command(
    names = ["ef", "eD"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    python = none,
)]
fn ef(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(parse = float_values)] numbers: Vec<f64>,
    #[arg(invoked)] name: &str,
) -> Result<ValuesWritten> {
    let values = if name == "ef" {
        let values: Vec<f32> = numbers.iter().map(|&value| value as f32).collect();
        let bytes: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        write_virtual(session, address, &bytes, "float")?;
        WrittenValues::Floats(values)
    } else {
        let bytes: Vec<u8> = numbers
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        write_virtual(session, address, &bytes, "double")?;
        WrittenValues::Doubles(numbers)
    };
    Ok(ValuesWritten { address, values })
}

/// A string written to memory.
pub struct StringWritten {
    pub address: VirtAddr,
    pub len: usize,
}

impl Render for StringWritten {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!(
            "{} {} bytes -> {}\n",
            "wrote".green(),
            self.len,
            ui::addr(self.address.0)
        );
    }
}

/// Write `text` at `address` as ANSI or UTF-16, NUL-terminated or not;
/// `command` names it in an error.
fn write_string(
    session: &Session,
    address: VirtAddr,
    text: &str,
    unicode: bool,
    nul_terminated: bool,
    command: &str,
) -> Result<StringWritten> {
    let mut bytes = if unicode {
        text.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    } else {
        text.as_bytes().to_vec()
    };
    if nul_terminated {
        bytes.extend_from_slice(if unicode { &[0, 0] } else { &[0] });
    }
    write_virtual(session, address, &bytes, command)?;
    Ok(StringWritten {
        address,
        len: bytes.len(),
    })
}

/// Write an ANSI string to memory.
#[command(
    names = ["ea"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    python = none,
)]
fn ea(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(rest, usage = "<text>", complete = None)] text: String,
) -> Result<StringWritten> {
    write_string(session, address, &text, false, false, "ea")
}

/// Write a UTF-16 string to memory.
#[command(
    names = ["eu"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    python = none,
)]
fn eu(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(rest, usage = "<text>", complete = None)] text: String,
) -> Result<StringWritten> {
    write_string(session, address, &text, true, false, "eu")
}

/// Write a NUL-terminated ANSI string to memory.
#[command(
    names = ["eza"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    python = none,
)]
fn eza(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(rest, usage = "<text>", complete = None)] text: String,
) -> Result<StringWritten> {
    write_string(session, address, &text, false, true, "eza")
}

/// Write a NUL-terminated UTF-16 string to memory.
#[command(
    names = ["ezu"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    python = none,
)]
fn ezu(
    session: &Session,
    #[arg(parse = write_address)] address: VirtAddr,
    #[arg(rest, usage = "<text>", complete = None)] text: String,
) -> Result<StringWritten> {
    write_string(session, address, &text, true, true, "ezu")
}

/// `.writemem`/`.readmem`'s `<address> <L<len>|end>`.
#[grammar(usage = "<address> <L<count>|length|end>", complete = [Expression, Expression])]
fn file_range(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AddressRange, ArgError> {
    AddressRange::required_from_args(cx, cursor)
}

/// A memory range `.writemem` saved.
pub struct MemoryToFile {
    pub path: String,
    pub len: usize,
    /// Bytes that could not be read, written as zero.
    pub unreadable: usize,
}

/// Write a virtual memory range to a file.
#[command(
    names = [".writemem"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Files],
    python = none,
)]
fn writemem(
    session: &Session,
    #[arg(name = "file")] path: String,
    #[arg(parse = file_range)] range: AddressRange,
) -> Result<MemoryToFile> {
    let mut file = File::create(&path)
        .map_err(|error| Error::DebugInfo(format!("failed to create '{path}': {error}")))?;
    let mut unreadable = 0usize;
    let mut write_error = None;
    for_each_page_chunk(range.start, range.len(), |_, address, len| {
        if write_error.is_some() {
            return;
        }
        let mut bytes = vec![0u8; len];
        if session.read_masked(address, &mut bytes).is_err() {
            bytes.fill(0);
            unreadable += len;
        }
        if let Err(error) = file.write_all(&bytes) {
            write_error = Some(error.to_string());
        }
    });
    if let Some(error) = write_error {
        return Err(Error::DebugInfo(format!(
            "failed to write '{path}': {error}"
        )));
    }
    Ok(MemoryToFile {
        path,
        len: range.len(),
        unreadable,
    })
}

impl Render for MemoryToFile {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        if self.unreadable == 0 {
            outln!("wrote {:#x} bytes to '{}'\n", self.len, self.path);
        } else {
            outln!(
                "wrote {:#x} bytes to '{}' ({} unreadable bytes written as zero)\n",
                self.len,
                self.path,
                self.unreadable
            );
        }
    }
}

/// A file `.readmem` loaded into memory.
pub struct FileToMemory {
    pub path: String,
    pub start: VirtAddr,
    pub len: usize,
    /// The pages that could not be written, and why.
    pub failed: Vec<(VirtAddr, Error)>,
    /// Bytes not written.
    pub unwritten: usize,
    /// Where the file ended or failed, which stopped the load there.
    pub read_error: Option<(usize, String)>,
}

/// Read a file into a virtual memory range.
#[command(
    names = [".readmem"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    python = none,
)]
fn readmem(
    session: &Session,
    #[arg(name = "file")] path: String,
    #[arg(parse = file_range)] range: AddressRange,
) -> Result<FileToMemory> {
    let mut file = File::open(&path)
        .map_err(|error| Error::DebugInfo(format!("failed to open '{path}': {error}")))?;
    let mut loaded = FileToMemory {
        path,
        start: range.start,
        len: range.len(),
        failed: Vec::new(),
        unwritten: 0,
        read_error: None,
    };
    for_each_page_chunk(range.start, range.len(), |offset, address, len| {
        if loaded.read_error.is_some() {
            return;
        }
        let mut bytes = vec![0u8; len];
        if let Err(error) = file.read_exact(&mut bytes) {
            loaded.read_error = Some((offset, error.to_string()));
            return;
        }
        if let Err(error) = session
            .target
            .write_memory(MemoryKind::Virtual, address.0, &bytes)
        {
            loaded.failed.push((address, error));
            loaded.unwritten += len;
        }
    });
    Ok(loaded)
}

impl Render for FileToMemory {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for (address, error) in &self.failed {
            error!(
                "failed to write memory at {}: {}",
                ui::addr(address.0),
                error
            );
        }
        if let Some((offset, error)) = &self.read_error {
            error!(
                "failed to read '{}' at file offset {:#x}: {}",
                self.path, offset, error
            );
            return;
        }
        if self.unwritten == 0 {
            outln!(
                "read {:#x} bytes from '{}' into {}\n",
                self.len,
                self.path,
                ui::addr(self.start.0)
            );
        } else {
            outln!(
                "read {:#x} bytes from '{}' ({} bytes not written)\n",
                self.len,
                self.path,
                self.unwritten
            );
        }
    }
}

/// `.formats`' expression: the rest of the line, unsplit.
#[grammar(usage = "<expression>", complete = Expression)]
fn formats_value(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u64, ArgError> {
    let expression = cursor.raw();
    let expression = expression.trim();
    if expression.is_empty() {
        return Err(ArgError::Missing);
    }
    Ok(cx.eval(expression)?.0)
}

/// A value `.formats` shows in common formats.
pub struct NumberFormats(pub u64);

/// Show an expression in common numeric formats.
#[command(
    names = [".formats"],
    category = "symbols, types, and expressions",
    kind = Query,
    python = none,
    style = ExpressionTail,
)]
fn formats(_session: &Session, #[arg(parse = formats_value)] value: u64) -> Result<NumberFormats> {
    Ok(NumberFormats(value))
}

impl Render for NumberFormats {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let value = self.0;
        outln!("hexadecimal: 0x{value:016x}");
        outln!("decimal: {value} (signed {})", value as i64);
        outln!("octal: 0o{value:o}");
        outln!("binary: 0b{value:064b}");
        outln!("characters: \"{}\"", format_characters(value));
        outln!("float: {}", format_float(f32::from_bits(value as u32)));
        outln!("double: {}", format_float(f64::from_bits(value)));

        const FILETIME_UNIX_OFFSET_SECONDS: i64 = 11_644_473_600;
        const FILETIME_MAX_TICKS: u64 = 265_046_774_400_000_000;
        let filetime_seconds = value / 10_000_000;
        let filetime_unix_seconds =
            (filetime_seconds as i64).saturating_sub(FILETIME_UNIX_OFFSET_SECONDS);
        if value <= FILETIME_MAX_TICKS
            && (FILETIME_UNIX_MIN_SECONDS..=FILETIME_UNIX_MAX_SECONDS)
                .contains(&filetime_unix_seconds)
        {
            let nanos = ((value % 10_000_000) * 100) as u32;
            outln!(
                "time (FILETIME): {} UTC",
                format_unix_timestamp(filetime_unix_seconds, nanos)
            );
        } else {
            outln!("time (FILETIME): out of range");
        }
        let unix_seconds = value as i64;
        if (FILETIME_UNIX_MIN_SECONDS..=FILETIME_UNIX_MAX_SECONDS).contains(&unix_seconds) {
            outln!(
                "time (Unix seconds): {} UTC",
                format_unix_timestamp(unix_seconds, 0)
            );
        } else {
            outln!("time (Unix seconds): out of range");
        }
        outln!();
    }
}

/// `<address> <L<count>|end>` of bytes before `extra` more words (`f`'s
/// pattern, `c`'s and `m`'s second address): fewer words show the help, as
/// does more than `exact` when it is given.
fn range_before(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
    item_size: u64,
) -> std::result::Result<AddressRange, ArgError> {
    let start = cursor.word().ok_or(ArgError::Missing)?;
    let start = cx.eval(&start)?;
    let end = cursor.word().ok_or(ArgError::Missing)?;
    eval_range_arg(cx, &end, start, item_size)
        .map_err(|error| ArgError::Message(format!("invalid range '{end}': {error}")))
}

/// `f`'s range: its pattern follows.
#[grammar(usage = "<address> <L<count>|length|end>", complete = [Expression, Expression])]
fn fill_range(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AddressRange, ArgError> {
    if cursor.remaining() < 3 {
        return Err(ArgError::Missing);
    }
    range_before(cx, cursor, 1)
}

/// The `kind` pattern in `words` (see [`SearchKind::pattern`]).
fn search_pattern(
    cx: &ArgCx<'_, '_>,
    kind: SearchKind,
    words: &[Cow<'_, str>],
) -> std::result::Result<Vec<u8>, ArgError> {
    let words: Vec<&str> = words.iter().map(AsRef::as_ref).collect();
    kind.pattern(&words, |value| {
        Expr::eval_with_radix(value, &cx.state.ctx.target, cx.state.radix).map(|value| value.0)
    })
    .map_err(|error| ArgError::Message(error.to_string()))
}

/// `f`'s byte pattern, in the format `s` takes.
#[grammar(usage = "<pattern>...", complete = None)]
fn fill_pattern(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Vec<u8>, ArgError> {
    let words = words(cursor);
    search_pattern(cx, SearchKind::Bytes, &words)
}

/// A range `f` filled.
pub struct MemoryFilled {
    pub address: VirtAddr,
    pub len: usize,
    pub pattern: Vec<u8>,
}

impl Render for MemoryFilled {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!(
            "{} {:#x} bytes at {} with {}\n",
            "filled".green(),
            self.len,
            ui::addr(self.address.0),
            format!("[{}]", hex::encode(&self.pattern)).green()
        );
    }
}

/// Fill memory with a repeated byte pattern.
///
/// The pattern is bytes, in the same format as for `s`: `90`, `48 89 5c`,
/// `48895c`, or `\x48\x89`. The command repeats the pattern to fill the
/// range (`f @rsp L20 cc`).
#[command(
    names = ["f"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    python = none,
)]
fn fill(
    session: &Session,
    #[arg(parse = fill_range)] range: AddressRange,
    #[arg(parse = fill_pattern)] pattern: Vec<u8>,
) -> Result<MemoryFilled> {
    let data = repeat_pattern(&pattern, range.len());
    session
        .target
        .write_memory(MemoryKind::Virtual, range.start.0, &data)
        .map_err(|error| Error::DebugInfo(format!("failed to fill memory: {error}")))?;
    Ok(MemoryFilled {
        address: range.start,
        len: range.len(),
        pattern,
    })
}

/// `c`'s and `m`'s range: exactly one address follows.
#[grammar(usage = "<address> <L<count>|length|end>", complete = [Expression, Expression])]
fn paired_range(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<AddressRange, ArgError> {
    if cursor.remaining() != 3 {
        return Err(ArgError::Missing);
    }
    range_before(cx, cursor, 1)
}

/// Compare two memory ranges byte by byte.
///
/// The command compares the range with the same number of bytes at
/// <address2>. It lists each byte that is different, as `<address> <byte> -
/// <address2> <byte>` (`c nt L1000 poi(@$t0)`). If an offset is unreadable in
/// one of the ranges, the command skips and counts it. It compares up to 1
/// GiB and stops after 4096 differences or when you press Ctrl+C.
#[command(
    names = ["c"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
)]
fn compare(
    session: &Session,
    #[arg(parse = paired_range)] range: AddressRange,
    #[arg(name = "address2")] other: VirtAddr,
) -> Result<CompareResult> {
    session
        .compare(range.start, other, range.len())
        .map_err(|error| Error::DebugInfo(format!("failed to compare memory: {error}")))
}

impl Render for CompareResult {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for &(offset, left, right) in &self.differences {
            outln!(
                "{}  {:02x} - {}  {:02x}",
                ui::addr(self.first.0.wrapping_add(offset as u64)),
                left,
                ui::addr(self.second.0.wrapping_add(offset as u64)),
                right
            );
        }
        match self.differences.len() {
            0 => outln!(
                "{} ({:#x} bytes compared)",
                "no differences".bright_black(),
                self.compared
            ),
            count => outln!(
                "\n{count} {} ({:#x} bytes compared)",
                if count == 1 {
                    "difference"
                } else {
                    "differences"
                },
                self.compared
            ),
        }
        if self.unreadable > 0 {
            outln!(
                "{}",
                format!("{:#x} unreadable bytes skipped", self.unreadable).bright_black()
            );
        }
        print_search_stop(self.stopped, "differences");
        outln!();
    }
}

/// Why a search or comparison stopped early, if it did.
pub fn print_search_stop(stopped: Option<SearchStop>, what: &str) {
    match stopped {
        Some(SearchStop::MatchLimit) => outln!(
            "{}",
            format!("stopped after {MAX_SEARCH_MATCHES} {what}").bright_black()
        ),
        Some(SearchStop::Interrupted) => outln!("{}", "interrupted".bright_black()),
        None => {}
    }
}

/// A range `m` copied.
pub struct MemoryCopied {
    pub source: VirtAddr,
    pub destination: VirtAddr,
    pub len: usize,
}

impl Render for MemoryCopied {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!(
            "copied {:#x} bytes from {} to {}\n",
            self.len,
            ui::addr(self.source.0),
            ui::addr(self.destination.0)
        );
    }
}

/// Copy a memory range to another address.
///
/// The command reads the full range before it writes, so overlapping ranges
/// copy as if through a buffer (`m @rsp L20 @rsp+8`). If this session set a
/// breakpoint in the range, the command copies the original byte that the
/// breakpoint replaced. It copies up to 16 MiB, and if a byte of the range is
/// unreadable, it writes nothing.
#[command(
    names = ["m"],
    category = "memory and disassembly",
    kind = Action,
    writes = [Memory],
    python = none,
)]
fn move_memory(
    session: &Session,
    #[arg(parse = paired_range)] range: AddressRange,
    destination: VirtAddr,
) -> Result<MemoryCopied> {
    /// A copy is buffered whole, so it is bounded.
    const MAX_MOVE_BYTES: usize = 16 << 20;
    if range.len() > MAX_MOVE_BYTES {
        return Err(Error::DebugInfo(format!(
            "cannot copy {:#x} bytes: at most {MAX_MOVE_BYTES:#x} are copied at once",
            range.len()
        )));
    }
    let (data, valid) =
        read_best_effort(session, MemoryKind::Virtual, &range).map_err(|error| {
            Error::DebugInfo(format!(
                "failed to read {}: {error}",
                ui::addr(range.start.0)
            ))
        })?;
    if let Some(offset) = valid.iter().position(|valid| !valid) {
        return Err(Error::DebugInfo(format!(
            "nothing copied: {} is unreadable",
            ui::addr(range.start.0.wrapping_add(offset as u64))
        )));
    }
    session
        .target
        .write_memory(MemoryKind::Virtual, destination.0, &data)
        .map_err(|error| {
            Error::DebugInfo(format!(
                "failed to write {}: {error}",
                ui::addr(destination.0)
            ))
        })?;
    Ok(MemoryCopied {
        source: range.start,
        destination,
        len: data.len(),
    })
}

/// What `s` searches for, and where.
pub struct SearchRequest {
    pub range: AddressRange,
    pub pattern: Vec<u8>,
}

/// `s [-b|-w|-d|-q|-a|-u] <address> <L<count>|end> <pattern>`: the flag
/// sets both the element an `L<count>` counts and how the pattern reads.
#[grammar(
    usage = "[-b|-w|-d|-q|-a|-u] <address> <L<count>|length|end> <pattern>...",
    complete = [None, Expression, Expression]
)]
fn search_request(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<SearchRequest, ArgError> {
    let mut first = cursor.word();
    let kind = match first.as_deref().and_then(SearchKind::from_flag) {
        Some(kind) => {
            first = cursor.word();
            kind
        }
        None => SearchKind::Bytes,
    };
    let Some(start) = first else {
        return Err(ArgError::Missing);
    };
    if cursor.remaining() < 2 {
        return Err(ArgError::Missing);
    }
    let start = cx.eval(&start)?;
    let end = cursor.word().ok_or(ArgError::Missing)?;
    let range = eval_range_arg(cx, &end, start, kind.element_size())
        .map_err(|error| ArgError::Message(format!("invalid range '{end}': {error}")))?;
    let words = words(cursor);
    let pattern = search_pattern(cx, kind, &words)?;
    Ok(SearchRequest { range, pattern })
}

/// Search memory for bytes, values, or a string.
///
/// -b (the default) searches for bytes: `4d 5a`, `4d5a`, or `\x4d\x5a`. -w,
/// -d, and -q search for 2-, 4-, and 8-byte values (`s -d @rsp L100 0 1`).
/// -a and -u search for an ASCII or UTF-16 string (`s -a nt L?1000000 "This
/// program"`). `L<count>` sets the number of elements of the search type. The
/// search skips unreadable pages, scans up to 1 GiB, and stops after 4096
/// matches or when you press Ctrl+C.
#[command(
    names = ["s"],
    category = "memory and disassembly",
    kind = Query,
    forms = [memory_search],
)]
fn search(
    session: &Session,
    #[arg(parse = search_request)] request: SearchRequest,
) -> Result<SearchResult> {
    let SearchRequest { range, pattern } = request;
    session
        .search(range.start, &pattern, range.len())
        .map_err(|error| Error::DebugInfo(format!("failed to search memory: {error}")))
}

/// Find matches, including overlapping ones, with symbol/module/VAD
/// context. In a virtual space, the search skips pages that it cannot read,
/// the breakpoints of this session read as the code that they replaced, and
/// the search returns a maximum of 4096 matches.
#[command(form_of = search, python = Memory, python_name = "search")]
fn memory_search(
    session: &Session,
    #[arg(receiver)] space: SearchSpace,
    pattern: Vec<u8>,
    start: VirtAddr,
    length: usize,
) -> Result<Vec<MemorySearchMatch>> {
    let VirtAddr(start) = start;
    if length > MAX_SEARCH_BYTES {
        return Err(Error::DebugInfo(format!(
            "search length {length} exceeds cap {MAX_SEARCH_BYTES} (0x{MAX_SEARCH_BYTES:x})"
        )));
    }
    if pattern.is_empty() || pattern.len() > length {
        return Ok(Vec::new());
    }
    let target = &session.target;
    let SearchSpace::Virtual(undescribed) = space else {
        // The range in one read, as `!search` does not chunk it.
        let mut bytes = vec![0; length];
        target.read_physical(start, &mut bytes)?;
        return Ok(pattern_offsets(&bytes, &pattern)
            .map(|offset| {
                MemorySearchMatch::undescribed(
                    start.wrapping_add(offset as u64),
                    offset as u64,
                    None,
                    AddressKind::Physical,
                )
            })
            .collect());
    };
    let hits = session.search(VirtAddr(start), &pattern, length)?.matches;
    match undescribed {
        Some(kind) => Ok(hits
            .into_iter()
            .map(|address| {
                MemorySearchMatch::undescribed(
                    address,
                    address.wrapping_sub(start),
                    target.closest_symbol_current_context(VirtAddr(address)),
                    kind,
                )
            })
            .collect()),
        None => target.describe_search_matches(VirtAddr(start), &hits),
    }
}

/// The matches with their symbols, which become `$0`.. (`.results`).
impl Render for SearchResult {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        let hits = &self.matches;
        for &address in hits {
            let symbol = repl
                .ctx
                .target
                .closest_symbol_current_context(VirtAddr(address))
                .unwrap_or_default();
            outln!("{}  {}", ui::addr(address), ui::symbol(&symbol));
        }
        if hits.is_empty() && self.length > 0 && self.unreadable >= self.length {
            // Nothing was searched, so "no matches" would claim too much.
            error!(
                "none of the {:#x} bytes at {:#x} can be read",
                self.length, self.start.0
            );
        } else if hits.is_empty() {
            outln!(
                "{} (searched {:#x} bytes at {})",
                "no matches found".bright_black(),
                self.length,
                ui::addr(self.start.0)
            );
        } else {
            outln!(
                "\n{} {} (in $0..${})",
                hits.len(),
                if hits.len() == 1 { "match" } else { "matches" },
                hits.len() - 1
            );
        }
        if self.unreadable > 0 && self.unreadable < self.length {
            outln!(
                "{}",
                format!("{:#x} unreadable bytes skipped", self.unreadable).bright_black()
            );
        }
        print_search_stop(self.stopped, "matches");
        let origin = repl.line.clone();
        repl.ctx.target.set_results(hits.clone(), origin);
        outln!();
    }
}

fn checked_display_string_count(max_chars: u64, char_size: usize) -> Result<usize> {
    let max_chars_by_bytes = u64::try_from(MAX_DISPLAY_BYTES / char_size).unwrap_or(u64::MAX);
    if max_chars > max_chars_by_bytes {
        return Err(Error::InvalidArgument(format!(
            "display range exceeds the maximum of {MAX_DISPLAY_BYTES:#x} bytes"
        )));
    }
    usize::try_from(max_chars)
        .map_err(|_| Error::InvalidArgument("string length exceeds the platform limit".into()))
}

fn format_characters(value: u64) -> String {
    value.to_le_bytes().into_iter().map(ascii_char).collect()
}

/// Format a proleptic-Gregorian UTC timestamp without pulling a date/time
/// dependency into the debugger. `seconds` is Unix time and `nanos` is the
/// fractional second component.
fn format_unix_timestamp(seconds: i64, nanos: u32) -> String {
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let (year, month, day) = days_to_ymd(days);
    if nanos == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}")
    } else {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_display_counts_are_limited_by_requested_bytes() {
        assert_eq!(
            checked_display_string_count(MAX_DISPLAY_BYTES as u64, 1).unwrap(),
            MAX_DISPLAY_BYTES
        );
        assert!(matches!(
            checked_display_string_count(MAX_DISPLAY_BYTES as u64 + 1, 1),
            Err(Error::InvalidArgument(_))
        ));
        assert_eq!(
            checked_display_string_count((MAX_DISPLAY_BYTES / 2) as u64, 2).unwrap(),
            MAX_DISPLAY_BYTES / 2
        );
        assert!(matches!(
            checked_display_string_count((MAX_DISPLAY_BYTES / 2) as u64 + 1, 2),
            Err(Error::InvalidArgument(_))
        ));
    }
}
