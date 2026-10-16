//! Disassembly: `u`, `uf`, `ub`, and the `#` search.

use owo_colors::OwoColorize;

use ntoseye_macros::command;

use crate::disasm::FunctionDisassembly;
use crate::error::{Error, Result};
use crate::memory::PAGE_SIZE;
#[cfg(feature = "python")]
use crate::python::command::PyArg;
use crate::session::Session;
use crate::symbols::glob_matches;
use crate::target::MemoryKind;
use crate::types::{CodeMachine, VirtAddr};
use crate::ui;
use crate::unwind::{format_symbol, resolve_thread_trace_context};

use crate::repl::args::{ArgCursor, ArgCx, ArgError, virtual_memory};
use crate::repl::*;

use super::memory::MAX_DISASSEMBLY_INSTRUCTIONS;

/// Instructions `u` and `ub` list without a count.
const DEFAULT_INSTRUCTIONS: u64 = 8;

/// How far `u` lists from its start.
#[derive(Clone, Copy, Debug)]
pub enum DisasmExtent {
    /// `L<count>` instructions.
    Count(u64),
    /// A WinDbg range end: an inclusive end address, through which every
    /// instruction that starts is listed, or a byte length when it is below
    /// the start, which no end address can be.
    Through(u64),
}

#[cfg(feature = "python")]
impl PyArg for DisasmExtent {
    type Py = u64;
    fn from_py(count: u64) -> Self {
        Self::Count(count)
    }
}

/// `count` as an instruction count `u` and `ub` take.
fn instruction_count(count: u64) -> Result<usize> {
    if (1..=MAX_DISASSEMBLY_INSTRUCTIONS as u64).contains(&count) {
        Ok(count as usize)
    } else {
        Err(Error::DebugInfo(format!(
            "instruction count must be 1..{MAX_DISASSEMBLY_INSTRUCTIONS}"
        )))
    }
}

/// Disassemble memory at a symbol or address.
///
/// `L<count>` sets the number of instructions, 8 by default. If you give an
/// end address, the command shows all instructions that start at or before
/// that address. If you do not give an address, the command continues after
/// the last instruction that the previous u showed. After the target runs or
/// steps, or when you select another frame, thread, or process, it starts at
/// the instruction pointer instead.
#[command(
    names = ["u", "disasm"],
    category = "memory and disassembly",
    kind = Query,
    python = Memory,
    usage = "u [address [L<count>|length|end]]",
    completion = [Expression, Expression]
)]
fn disassemble(
    session: &Session,
    #[arg(receiver, parse = virtual_memory)] memory: MemoryKind,
    #[arg(parse = listing_start)] addr: VirtAddr,
    #[arg(parse = listing_extent)] count: DisasmExtent,
    #[arg(render, parse = continues_listing)] continues: ContinuesListing,
) -> Result<Vec<DisasmRow>> {
    memory.require_virtual()?;
    // The window is sized for the machine at the start expression's
    // address, which is only known once it is evaluated: size it for the
    // longest instruction set, and decode what the address holds.
    let max_instruction_bytes = CodeMachine::Amd64.max_instruction_bytes() as u64;
    let (byte_len, instruction_limit, last_start) = match count {
        DisasmExtent::Count(count) => {
            let count = instruction_count(count)?;
            (count as u64 * max_instruction_bytes, Some(count), None)
        }
        DisasmExtent::Through(value) => {
            let end = if value < addr.0 {
                addr.0.checked_add(value)
            } else {
                value.checked_add(1)
            }
            .ok_or(Error::InvalidRange)?;
            // The last instruction may run past the end.
            (end - addr.0 + max_instruction_bytes - 1, None, Some(end))
        }
    };

    // An instruction window may run past the end of the mapped image;
    // keep what is readable up to the first unreadable page.
    let mut bytes: Vec<u8> = vec![0u8; byte_len as usize];
    if session.read_masked(addr, &mut bytes).is_err() {
        let page_end = addr
            .0
            .checked_add(PAGE_SIZE as u64 - addr.page_offset())
            .ok_or(Error::InvalidRange)?;
        let readable = page_end.saturating_sub(addr.0).min(byte_len) as usize;
        bytes.truncate(readable);
        session.read_masked(addr, &mut bytes)?;
    }

    let target = &session.target;
    let trace = resolve_thread_trace_context(target, target.current_dtb());
    let resolve = |address: u64| format_symbol(target, &trace, address);
    let machine = target.code_machine(addr);
    let mut rows = decode_code(&bytes, addr.0, instruction_limit, machine, resolve);
    if let Some(end) = last_start {
        rows.retain(|row| row.ip < end);
    }
    Ok(rows)
}

/// Where `u` starts: the address given, else where the previous `u` left
/// off while its scope holds, else the instruction pointer.
fn listing_start(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    match cursor.word() {
        Some(text) => cx.eval(&text),
        None => DisasmCursor::start(cx.state.disasm_cursor.as_ref(), &cx.state.ctx.target)
            .map_err(|error| ArgError::Message(error.to_string())),
    }
}

/// `u`'s `L<count>`, length, or end; 8 instructions without one.
fn listing_extent(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<DisasmExtent, ArgError> {
    let Some(text) = cursor.word() else {
        return Ok(DisasmExtent::Count(DEFAULT_INSTRUCTIONS));
    };
    match windbg_count_expression(&text) {
        Some(count) => cx.eval(count).map(|count| DisasmExtent::Count(count.0)),
        None => cx.eval(&text).map(|value| DisasmExtent::Through(value.0)),
    }
}

/// `u`'s listing moves the cursor a bare `u` continues from; `ub`'s does not.
pub struct ContinuesListing;

fn continues_listing(
    _: &mut ArgCx<'_, '_>,
    _: &mut ArgCursor<'_>,
) -> std::result::Result<ContinuesListing, ArgError> {
    Ok(ContinuesListing)
}

/// A plain listing, as `u` and `ub` show it.
fn show_listing(rows: &[DisasmRow], repl: &ReplState<'_>) {
    let print_text = || {
        render_rows(rows, |_| None);
        outln!();
    };
    #[cfg(feature = "cli")]
    native::render(
        || native::frames::disasm(rows, repl.ctx.target.builtin_variable_value("ip")),
        print_text,
    );
    #[cfg(not(feature = "cli"))]
    {
        let _ = repl;
        print_text();
    }
}

impl Render<ContinuesListing> for Vec<DisasmRow> {
    fn render(&self, repl: &mut ReplState<'_>, ContinuesListing: ContinuesListing) {
        show_listing(self, repl);
        repl.disasm_cursor = DisasmCursor::after(&repl.ctx.target, self);
    }
}

impl Render for Vec<DisasmRow> {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        show_listing(self, repl);
    }
}

/// Disassemble the function that contains an address.
///
/// The function's runtime function entry gives its extent. A leaf function
/// has none, so uf reads it from its symbol for as far as its control flow
/// reaches before the next symbol: it follows the branches inside the
/// function, and treats a branch past the next symbol as a tail call.
#[command(
    names = ["uf"],
    category = "memory and disassembly",
    kind = Query,
    python = Memory,
    usage = "uf [address]",
    completion = [Expression]
)]
fn disassemble_function(
    session: &Session,
    #[arg(receiver, parse = virtual_memory)] memory: MemoryKind,
    #[arg(parse = address_or_ip)] addr: VirtAddr,
) -> Result<FunctionDisassembly> {
    memory.require_virtual()?;
    session.disassemble_function(addr)
}

/// `uf`'s address, `@rip` without one.
fn address_or_ip(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    cx.eval(cursor.word().as_deref().unwrap_or("@rip"))
}

impl Render for FunctionDisassembly {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        let print_text = || {
            outln!("{}  {} bytes", ui::symbol(&self.symbol), self.length);
            render_rows(&self.rows, |_| None);
            outln!();
        };
        #[cfg(feature = "cli")]
        native::render(
            || {
                native::frames::function(
                    &self.symbol,
                    self.length,
                    &self.rows,
                    repl.ctx.target.builtin_variable_value("ip"),
                )
            },
            print_text,
        );
        #[cfg(not(feature = "cli"))]
        {
            let _ = repl;
            print_text();
        }
    }
}

/// Disassemble the instructions that end at an address.
#[command(
    names = ["ub"],
    category = "memory and disassembly",
    kind = Query,
    python = Memory,
    usage = "ub <address> [L<count>]",
    completion = [Expression, Expression]
)]
fn disassemble_back(
    session: &Session,
    #[arg(receiver, parse = virtual_memory)] memory: MemoryKind,
    addr: VirtAddr,
    #[arg(parse = back_count)] count: u64,
) -> Result<Vec<DisasmRow>> {
    memory.require_virtual()?;
    session.disassemble_back(addr, instruction_count(count)?)
}

/// `ub`'s count: `L<count>`, `L?<count>`, or a bare count; 8 without one.
fn back_count(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u64, ArgError> {
    let Some(arg) = cursor.word() else {
        return Ok(DEFAULT_INSTRUCTIONS);
    };
    let count = windbg_count_expression(&arg)
        .map(|count| count.strip_prefix('?').unwrap_or(count))
        .unwrap_or(&arg);
    let count = cx.eval(count)?.0;
    if instruction_count(count).is_err() {
        return Err(ArgError::Message(format!(
            "instruction count must be 1..{MAX_DISASSEMBLY_INSTRUCTIONS}: {arg}"
        )));
    }
    Ok(count)
}

/// Search the disassembly for the next instruction that matches a pattern.
///
/// The pattern can match any part of the address, bytes, or text of an
/// instruction, where the text is the mnemonic, the operands, and the
/// resolved symbol. The match is not case-sensitive, and you can use `*` and
/// `?` wildcards. To include spaces, put the pattern in quotes (`#
/// "mov*cr3" nt!KiSwapContext`). The command shows the first match. If you
/// do not give an address, the search continues after the last match, and
/// the first search starts at the instruction pointer. If you do not give a
/// pattern, the command uses the last pattern again, so a bare `#` finds the
/// next occurrence. `L<count>` sets the maximum number of instructions to
/// search. Without it, the search continues until it finds a match, reaches
/// an unreadable page, or searches 1,048,576 instructions, and you can also
/// stop it with Ctrl+C.
#[command(
    names = ["#"],
    category = "memory and disassembly",
    kind = Query,
    python = none,
    usage = "# [pattern] [address [L<count>]]",
    completion = [None, Expression]
)]
fn disasm_search(
    state: &mut ReplState<'_>,
    #[arg(parse = every_word)] args: Vec<String>,
) -> Result<()> {
    /// Instructions searched when no count bounds the search.
    const MAX_SEARCH_INSTRUCTIONS: u64 = 1 << 20;
    /// Code decoded per read.
    const CHUNK: usize = PAGE_SIZE;
    let count_arg = match args.get(2..).unwrap_or_default() {
        [] => None,
        [count] => match windbg_count_expression(count) {
            Some(count) => Some(count),
            None => {
                outln!("{}\n", command_help("#"));
                return Ok(());
            }
        },
        [l, count] if l.eq_ignore_ascii_case("l") => Some(count.as_str()),
        _ => {
            outln!("{}\n", command_help("#"));
            return Ok(());
        }
    };
    if let Some(pattern) = args.first() {
        state.disasm_search.pattern = Some(pattern.clone());
    }
    let Some(pattern) = state.disasm_search.pattern.clone() else {
        outln!("{}\n", command_help("#"));
        return Ok(());
    };
    let start = match args.get(1) {
        Some(address) => state.eval_or_report(address),
        None => state.disasm_search.next.or_else(|| {
            let ip = state.ctx.target.builtin_variable_value("ip");
            if ip.is_none() {
                error!("no address to search from: give one, or halt the target");
            }
            ip.map(VirtAddr)
        }),
    };
    let Some(start) = start else {
        return Ok(());
    };
    let budget = match count_arg {
        Some(count) => match state.eval_or_report(count) {
            Some(count) if (1..=MAX_SEARCH_INSTRUCTIONS).contains(&count.0) => count.0,
            Some(_) => {
                error!("instruction count must be 1..{MAX_SEARCH_INSTRUCTIONS:#x}");
                return Ok(());
            }
            None => return Ok(()),
        },
        None => MAX_SEARCH_INSTRUCTIONS,
    };

    let wildcard = format!("*{pattern}*");
    let matches = |row: &DisasmRow| {
        let bytes: String = row.hex.split_whitespace().collect();
        let text = match &row.comment {
            Some(comment) => format!("{} {comment}", row.asm()),
            None => row.asm(),
        };
        [format!("{:016x}", row.ip), bytes, text]
            .iter()
            .any(|part| glob_matches(&wildcard, part, true))
    };
    let session = &*state.ctx;
    let target = &session.target;
    let trace = resolve_thread_trace_context(target, target.current_dtb());
    let resolve = |address: u64| format_symbol(target, &trace, address);
    let machine = target.code_machine(start);
    let max_instruction_bytes = machine.max_instruction_bytes();
    let mut cursor = start.0;
    let mut searched = 0u64;
    let mut found = None;
    let mut stop = None;
    let mut buffer = vec![0u8; CHUNK + max_instruction_bytes];
    'search: while searched < budget {
        if target.interrupted() {
            stop = Some("interrupted".to_string());
            break;
        }
        let readable = session.read_masked_partial(VirtAddr(cursor), &mut buffer);
        let bytes = &buffer[..readable];
        // Instructions starting past the chunk are decoded again from the
        // next read, which has the bytes after them.
        let window_end = cursor.saturating_add(CHUNK.min(readable) as u64);
        let read_end = cursor.saturating_add(readable as u64);
        let mut next = cursor;
        for row in decode_code(bytes, cursor, None, machine, resolve) {
            let end = row
                .ip
                .saturating_add(row.hex.split_whitespace().count() as u64);
            if row.ip >= window_end || end > read_end {
                break;
            }
            searched += 1;
            next = end;
            if matches(&row) {
                found = Some(row);
                break 'search;
            }
            if searched == budget {
                break;
            }
        }
        if next == cursor {
            stop = Some(format!("{} is unreadable", ui::addr(read_end)));
            break;
        }
        cursor = next;
    }

    match found {
        Some(row) => {
            let len = row.hex.split_whitespace().count() as u64;
            state.disasm_search.next = Some(VirtAddr(row.ip.saturating_add(len)));
            render_rows(&[row], |_| None);
        }
        None => {
            state.disasm_search.next = Some(VirtAddr(cursor));
            outln!(
                "{} for '{pattern}' in {searched:#x} instructions from {}{}",
                "no match".bright_black(),
                ui::addr(start.0),
                stop.map(|stop| format!("; {stop}")).unwrap_or_default()
            );
        }
    }
    outln!();
    Ok(())
}

/// `#`'s words, which it reads by their count.
fn every_word(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Vec<String>, ArgError> {
    Ok(std::iter::from_fn(|| cursor.word().map(|word| word.into_owned())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::capture;
    use crate::session::session_over_memory;
    use std::collections::HashMap;

    /// The addresses a `u` line listed.
    fn listed(state: &mut ReplState<'_>, line: &str) -> Vec<u64> {
        let (result, text) = capture(|| state.dispatch_line(line));
        result.unwrap();
        text.lines()
            .filter_map(|row| u64::from_str_radix(row.split_whitespace().next()?, 16).ok())
            .collect()
    }

    /// A `u` given no address goes on after the previous one only while the
    /// scope stays where it was; at another instruction pointer (a stop, a
    /// step, another frame or thread) it starts there, as WinDbg's does.
    #[test]
    fn u_without_an_address_continues_only_in_the_same_scope() {
        let mut session = session_over_memory(0x1000, &[0x90; 0x1000]);
        let mut state = ReplState::for_oneshot(&mut session);
        state.ctx.target.registers = Some(HashMap::from([("rip".to_string(), 0x1000)]));

        assert_eq!(
            listed(&mut state, "u"),
            (0x1000..0x1008).collect::<Vec<_>>()
        );
        assert_eq!(
            listed(&mut state, "u"),
            (0x1008..0x1010).collect::<Vec<_>>()
        );
        assert_eq!(
            listed(&mut state, "u 1030"),
            (0x1030..0x1038).collect::<Vec<_>>()
        );
        assert_eq!(
            listed(&mut state, "u"),
            (0x1038..0x1040).collect::<Vec<_>>()
        );

        state.ctx.target.registers = Some(HashMap::from([("rip".to_string(), 0x1020)]));
        assert_eq!(
            listed(&mut state, "u"),
            (0x1020..0x1028).collect::<Vec<_>>()
        );
    }
}
