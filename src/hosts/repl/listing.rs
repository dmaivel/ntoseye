//! Disassembly as the stop and `u` show it: each row's offset in its
//! function, a direct branch's target named in place of its address, the
//! jumps between rows drawn as arrows in a gutter, and, at the instruction
//! the processor is at, whether its jump is taken and where its return goes.

use owo_colors::OwoColorize;

use crate::base::disasm::{
    AsmKind, DisasmRow, decode_code, decode_preceding, direct_branch_target,
};
use crate::base::memory::read_page_chunks;
use crate::base::output::strip_ansi;
use crate::base::types::VirtAddr;
use crate::hosts::repl::{disasm_context_rows, read_code};
use crate::hosts::ui;
use crate::nt::unwind::{SymbolName, ThreadTraceContext, format_symbol, symbol_name};
use crate::session::Session;

/// The widest the instruction column grows before its notes.
const MAX_ASM_WIDTH: usize = 44;
/// Decode from the function's start when it begins this close before the
/// instruction pointer, so the instructions before it are exact.
const MAX_FUNCTION_LEAD: u64 = 2048;
/// Otherwise, how far before the instruction pointer decoding starts.
const PRECEDING_BYTES: u64 = 96;
/// How far past the instruction pointer the code is read.
const FOLLOWING_BYTES: u64 = 192;

/// A disassembly listing and what its lines show.
pub struct Listing<'a> {
    pub rows: &'a [DisasmRow],
    /// The row of the instruction the processor is at, when listed.
    pub current: Option<usize>,
    /// Whether the jump at the current row goes, as the registers say.
    pub taken: Option<bool>,
    /// The symbol a return at the current row goes back to.
    pub returns_to: Option<&'a str>,
    /// Whether each row shows its bytes.
    pub bytes: bool,
    /// Jumps drawn side by side in the gutter; the ones past it name their
    /// target instead.
    pub lanes: usize,
    /// Whether the first row names its symbol even when every row stays in
    /// it: a listing with no heading of its own (`u`, `ub`, `#`) names where
    /// it is, one under a heading that names the function (`uf`, the stop)
    /// does not repeat it.
    pub named: bool,
}

/// The lines of a listing: a gutter with the jumps between its rows drawn
/// as arrows, a breakpoint's `●`, the current row's `>`, the address and its
/// offset from the symbol it is named after (as the stack and `ln` name
/// it), the bytes when asked for, and the instruction, a direct branch
/// naming its target (`je +0x33`, `call nt!Foo`) in place of the address.
/// Where the rows pass into another symbol, a line names it (`nt!Foo:`). A
/// jump out of the listing points up or down at its target; the current row
/// says whether its jump is taken and where its return goes.
pub fn listing_lines(
    session: &Session,
    trace: &ThreadTraceContext,
    listing: &Listing<'_>,
) -> Vec<String> {
    let rows = listing.rows;
    let taken = listing.taken;
    let index_of = |ip: u64| rows.iter().position(|row| row.ip == ip);
    let mut arcs = Vec::new();
    let mut away = vec![None; rows.len()];
    for (index, row) in rows.iter().enumerate() {
        let Some(jump) = row.jump() else {
            continue;
        };
        match index_of(jump.target) {
            Some(to) if to != index => arcs.push(Arc {
                from: index,
                to,
                lit: listing.current == Some(index) && taken == Some(true),
            }),
            _ => away[index] = Some(jump.target),
        }
    }
    let (gutter, between, unplaced) = gutter(&arcs, rows.len(), listing.lanes);
    for index in unplaced {
        away[arcs[index].from] = Some(rows[arcs[index].to].ip);
    }
    // What each row is named after: its offset counts from that symbol,
    // and a line names the symbol where the rows pass into it.
    let names: Vec<Option<SymbolName>> = rows
        .iter()
        .map(|row| symbol_name(&session.target, trace, row.ip))
        .collect();
    let same_symbol = |a: &SymbolName, b: &SymbolName| a.module == b.module && a.name == b.name;
    // A target under the jumping row's symbol is its offset there, which
    // the offset column and the arrow find; any other is its symbol, which
    // `u`, `bp` and `g` take as it is.
    let symbol = |target: u64| ui::symbol(&format_symbol(&session.target, trace, target));
    let name = |index: usize, target: u64| {
        let target_name = symbol_name(&session.target, trace, target);
        match (&names[index], &target_name) {
            (Some(from), Some(to)) if same_symbol(from, to) => {
                ui::muted(&format!("+{:#x}", to.offset))
            }
            _ => symbol(target),
        }
    };
    let arrow = |index: usize, target: u64| {
        let arrow = if target < rows[index].ip {
            "↑"
        } else {
            "↓"
        };
        if listing.current == Some(index) && taken == Some(true) {
            arrow.yellow().bold().to_string()
        } else {
            ui::muted(arrow)
        }
    };
    // Each instruction as text, a direct branch's target named in place of
    // its address, and the note after it.
    let texts: Vec<(String, Option<String>)> = rows
        .iter()
        .enumerate()
        .map(|(index, row)| {
            let away = away[index];
            match (direct_branch_target(&row.operands()), row.jump()) {
                (Some(target), Some(_)) => {
                    let label = match away {
                        Some(_) => format!("{} {}", arrow(index, target), symbol(target)),
                        None => name(index, target),
                    };
                    (format!("{}{label}", mnemonic_text(row)), None)
                }
                (Some(target), None) => (
                    format!("{}{}", mnemonic_text(row), name(index, target)),
                    None,
                ),
                (None, _) => (
                    ui::disasm_asm(&row.tokens),
                    match away {
                        Some(target) => {
                            Some(format!("{} {}", arrow(index, target), symbol(target)))
                        }
                        None => row.comment.as_deref().map(ui::symbol),
                    },
                ),
            }
        })
        .collect();
    let asm_width = texts
        .iter()
        .map(|(text, _)| visible(text))
        .max()
        .unwrap_or(0)
        .min(MAX_ASM_WIDTH);
    // Each row's offset from its symbol, as gdb and lldb show `<+29>` and
    // as the jump labels name their targets.
    let offsets: Vec<String> = names
        .iter()
        .map(|name| {
            name.as_ref()
                .map_or_else(String::new, |name| format!("+{:#x}", name.offset))
        })
        .collect();
    // Where a symbol starts after the first row, and then before the first
    // row too, so that every offset's symbol is named.
    let crosses: Vec<bool> = (0..rows.len())
        .map(|index| {
            index > 0
                && match (&names[index - 1], &names[index]) {
                    (Some(before), Some(here)) => !same_symbol(before, here),
                    (before, here) => before.is_some() != here.is_some(),
                }
        })
        .collect();
    let labeled =
        |index: usize| crosses[index] || (index == 0 && (listing.named || crosses.contains(&true)));
    let offset_width = offsets.iter().map(String::len).max().unwrap_or(0);
    let hex_width = if listing.bytes {
        rows.iter().map(|row| row.hex.len()).max().unwrap_or(0)
    } else {
        0
    };
    let mut lines = Vec::with_capacity(rows.len());
    for (index, (row, (asm, note))) in rows.iter().zip(texts).enumerate() {
        if labeled(index)
            && let Some(name) = &names[index]
        {
            let label = match &name.name {
                Some(symbol) => format!("{}!{symbol}", name.module),
                None => name.module.clone(),
            };
            lines.push(format!("{}{}:", between[index], ui::symbol(&label)));
        }
        lines.push({
            let current = listing.current == Some(index);
            let breakpoint = session
                .breakpoints
                .enabled_breakpoint_id_for_current_context(&session.target, VirtAddr(row.ip))
                .is_some();
            let bullet = if breakpoint {
                "●".red().to_string()
            } else {
                " ".to_string()
            };
            let marker = if current {
                ">".yellow().bold().to_string()
            } else {
                " ".to_string()
            };
            let quiet = |text: String| if current { text } else { ui::muted(&text) };
            let address = quiet(ui::addr(row.ip));
            let offset = match offset_width {
                0 => String::new(),
                width => quiet(format!(" {:<width$}", offsets[index])),
            };
            let bytes = match hex_width {
                0 => String::new(),
                width => format!("  {}", ui::muted(&format!("{:<width$}", row.hex))),
            };
            let pad = asm_width.saturating_sub(visible(&asm));
            let mut notes: Vec<String> = note.into_iter().collect();
            if current {
                match taken {
                    Some(true) if row.jump().is_some_and(|jump| jump.conditional) => {
                        notes.push("taken".yellow().to_string());
                    }
                    Some(false) => notes.push(ui::muted("not taken")),
                    _ => {}
                }
                if let Some(caller) = listing.returns_to
                    && matches!(row.mnemonic().as_str(), "ret" | "retf" | "iretq")
                {
                    notes.push(format!("{} {}", ui::muted("↩"), ui::symbol(caller)));
                }
            }
            let line = format!(
                "{}{bullet}{marker} {address}{offset}{bytes}  {asm}{}  {}",
                gutter[index],
                " ".repeat(pad),
                notes.join("  ")
            );
            line.trim_end().to_string()
        });
    }
    lines
}

/// Columns `text` takes on screen, its styling aside.
fn visible(text: &str) -> usize {
    strip_ansi(text).chars().count()
}

/// A jump from one row of a listing to another.
struct Arc {
    from: usize,
    to: usize,
    lit: bool,
}

// The arms of a box-drawing cell.
const UP: u8 = 1;
const DOWN: u8 = 2;
const LEFT: u8 = 4;
const RIGHT: u8 = 8;

fn glyph(arms: u8) -> char {
    match arms {
        0 => ' ',
        a if a == UP | DOWN => '│',
        a if a == DOWN | RIGHT => '╭',
        a if a == UP | RIGHT => '╰',
        a if a == DOWN | LEFT => '╮',
        a if a == UP | LEFT => '╯',
        a if a == UP | DOWN | RIGHT => '├',
        a if a == UP | DOWN | LEFT => '┤',
        a if a == LEFT | RIGHT | DOWN => '┬',
        a if a == LEFT | RIGHT | UP => '┴',
        a if a == UP | DOWN | LEFT | RIGHT => '┼',
        a if a & (UP | DOWN) != 0 && a & (LEFT | RIGHT) == 0 => '│',
        _ => '─',
    }
}

/// The gutter: each arc in a lane of its own, at most `max_lanes`, the
/// shortest nearest the code, as a corner at each end joined by a line, with
/// an arrowhead where it lands. Returns one string per row, one per gap
/// above a row (the arcs passing through it, for a line put there), and
/// which arcs found no lane.
fn gutter(arcs: &[Arc], rows: usize, max_lanes: usize) -> (Vec<String>, Vec<String>, Vec<usize>) {
    let mut order: Vec<usize> = (0..arcs.len()).collect();
    order.sort_by_key(|&index| arcs[index].from.abs_diff(arcs[index].to));
    let mut lanes: Vec<Vec<(usize, usize)>> = Vec::new();
    let mut lane_of = vec![None; arcs.len()];
    let mut unplaced = Vec::new();
    for index in order {
        let arc = &arcs[index];
        let span = (arc.from.min(arc.to), arc.from.max(arc.to));
        let free = lanes.iter().position(|taken| {
            taken
                .iter()
                .all(|&(top, bottom)| span.1 < top || span.0 > bottom)
        });
        match free {
            Some(lane) => {
                lanes[lane].push(span);
                lane_of[index] = Some(lane);
            }
            None if lanes.len() < max_lanes => {
                lanes.push(vec![span]);
                lane_of[index] = Some(lanes.len() - 1);
            }
            None => unplaced.push(index),
        }
    }
    if lanes.is_empty() {
        return (
            vec![String::new(); rows],
            vec![String::new(); rows],
            unplaced,
        );
    }
    let width = lanes.len();
    // Per row: each lane's arms and whether a lit arc drew them, then the
    // column joining the lanes to the code.
    let mut cells = vec![vec![(0u8, false); width]; rows];
    let mut gaps = vec![vec![(0u8, false); width]; rows];
    let mut heads = vec![(None::<char>, false); rows];
    for (index, arc) in arcs.iter().enumerate() {
        let Some(lane) = lane_of[index] else {
            continue;
        };
        let column = width - 1 - lane;
        let (top, bottom) = (arc.from.min(arc.to), arc.from.max(arc.to));
        for gap in &mut gaps[top + 1..=bottom] {
            gap[column] = (UP | DOWN, gap[column].1 || arc.lit);
        }
        for row in top..=bottom {
            let vertical = match (row == top, row == bottom) {
                (true, _) => DOWN | RIGHT,
                (_, true) => UP | RIGHT,
                _ => UP | DOWN,
            };
            let cell = &mut cells[row][column];
            cell.0 |= vertical;
            cell.1 |= arc.lit;
            if row == top || row == bottom {
                for cell in &mut cells[row][column + 1..] {
                    cell.0 |= LEFT | RIGHT;
                    cell.1 |= arc.lit;
                }
                let head = &mut heads[row];
                if row == arc.to {
                    head.0 = Some('▶');
                } else if head.0.is_none() {
                    head.0 = Some('─');
                }
                head.1 |= arc.lit;
            }
        }
    }
    let paint = |ch: char, lit: bool| {
        let text = ch.to_string();
        if lit {
            text.yellow().bold().to_string()
        } else {
            ui::muted(&text)
        }
    };
    let lanes_text = |row: &[(u8, bool)]| -> String {
        row.iter()
            .map(|&(arms, lit)| paint(glyph(arms), lit))
            .collect()
    };
    let lines = cells
        .iter()
        .zip(&heads)
        .map(|(row, head)| lanes_text(row) + &paint(head.0.unwrap_or(' '), head.1))
        .collect();
    let between = gaps.iter().map(|gap| lanes_text(gap) + " ").collect();
    (lines, between, unplaced)
}

/// The instruction's mnemonic and prefixes, styled, with the spacing before
/// its first operand.
fn mnemonic_text(row: &DisasmRow) -> String {
    let lead = row
        .tokens
        .iter()
        .take_while(|token| matches!(token.kind, AsmKind::Mnemonic) || token.text.trim().is_empty())
        .count();
    let text = ui::disasm_asm(&row.tokens[..lead]);
    if row.tokens[..lead]
        .last()
        .is_some_and(|token| token.text.ends_with(' '))
    {
        text
    } else {
        format!("{text} ")
    }
}

/// The instructions around the instruction pointer, within its function
/// when that is known.
pub struct CodeWindow {
    pub rows: Vec<DisasmRow>,
    /// The row of the instruction pointer.
    pub current: usize,
}

/// `height` instructions around `rip`, `lead` of them before it where the
/// function has them (more when it ends soon after), none outside the
/// function when its bounds are known. Where the code cannot be read, the
/// instructions from `rip` on as the classic reader decodes them, or its
/// note saying why there are none.
pub fn code_window(
    session: &Session,
    trace: &ThreadTraceContext,
    rip: u64,
    height: usize,
    lead: usize,
) -> Result<CodeWindow, String> {
    let debugger = &session.target;
    let machine = debugger.code_machine(VirtAddr(rip));
    let function = session.function_bounds(trace, VirtAddr(rip));
    let classic = || {
        disasm_context_rows(session, trace, rip).map(|mut rows| {
            rows.truncate(height);
            CodeWindow { rows, current: 0 }
        })
    };
    let from = match function {
        Some((start, _)) if rip - start <= MAX_FUNCTION_LEAD => start,
        _ => rip.saturating_sub(PRECEDING_BYTES),
    };
    let to = rip + FOLLOWING_BYTES;
    let Ok((bytes, valid)) =
        read_page_chunks(VirtAddr(from), (to - from) as usize, |address, buf| {
            read_code(debugger, trace, address, buf)
        })
    else {
        return classic();
    };
    let at = (rip - from) as usize;
    if !valid[at] {
        return classic();
    }
    let lo = valid[..at]
        .iter()
        .rposition(|valid| !valid)
        .map_or(0, |hole| hole + 1);
    let hi = valid[at..]
        .iter()
        .position(|valid| !valid)
        .map_or(bytes.len(), |hole| at + hole);
    let resolve = |target: u64| format_symbol(debugger, trace, target);

    let from_function = lo == 0 && function.is_some_and(|(start, _)| start == from);
    let mut rows = if from_function {
        decode_code(&bytes[..hi], from, None, machine, resolve)
    } else {
        Vec::new()
    };
    if !rows.iter().any(|row| row.ip == rip) {
        rows = decode_preceding(
            machine,
            &bytes[lo..at],
            from + lo as u64,
            rip,
            height,
            resolve,
        )
        .unwrap_or_default();
        rows.extend(decode_code(
            &bytes[at..hi],
            rip,
            Some(height),
            machine,
            resolve,
        ));
    }
    if let Some((start, end)) = function {
        rows.retain(|row| (start..end).contains(&row.ip));
    }
    let Some(current) = rows.iter().position(|row| row.ip == rip) else {
        return classic();
    };
    let after = rows.len() - current - 1;
    let before = current.min(lead.max((height - 1).saturating_sub(after)));
    let first = current - before;
    let last = rows.len().min(first + height);
    Ok(CodeWindow {
        rows: rows.drain(first..last).collect(),
        current: before,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nt::unwind::resolve_thread_trace_context;
    use crate::session::session_over_memory;

    /// The window holds `lead` instructions before the instruction pointer
    /// and the rest after it, takes fewer before where the code starts, and
    /// more where it ends soon after.
    #[test]
    fn code_window_leads_up_to_rip_and_fills_toward_the_end() {
        let base = 0x1000;
        // A page: memory is read a page at a time.
        let session = session_over_memory(base, &[0x90; 0x1000]);
        let trace = resolve_thread_trace_context(&session.target, session.target.current_dtb());
        let window = |rip: u64| {
            let window = code_window(&session, &trace, rip, 9, 3).unwrap();
            let ips: Vec<u64> = window.rows.iter().map(|row| row.ip).collect();
            (ips, window.current)
        };

        let rip = base + 0x80;
        assert_eq!(window(rip), ((rip - 3..rip + 6).collect(), 3));
        assert_eq!(window(base), ((base..base + 9).collect(), 0));
        // Two instructions left: the window takes seven before instead.
        let rip = base + 0xffe;
        assert_eq!(window(rip), ((rip - 7..rip + 2).collect(), 7));
    }
}
