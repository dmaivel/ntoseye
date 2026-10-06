//! The `k` family, the register grid and the `u` family as Tern views.

use tern_sdk::View;
use tern_sdk::ui::{self, Column, Span, Table, TableRow};

use super::{MUTED, addr, code, span, stack, symbol};
use crate::disasm::DisasmRow;
use crate::repl::{StackColumns, format_rflags};
use crate::unwind::StackTrace;

/// `k`, `kv`, `kf`, `kn`: the trace's first `limit` frames numbered from
/// `first`, the `selected` frame (`.frame`) marked, with the child SP.
pub fn stack(
    trace: &StackTrace,
    limit: usize,
    columns: StackColumns,
    first: usize,
    selected: Option<usize>,
) -> View {
    View::new().main([stack::numbered(
        trace, limit, true, columns, first, selected,
    )])
}

/// `u`, `ub`: the listing, the instruction pointer's row marked when the
/// listing holds it.
pub fn disasm(rows: &[DisasmRow], ip: Option<u64>) -> View {
    // A list, not the listing itself: a region root's own props (the role
    // the current-row mark is styled by) are dropped.
    View::new().main([code::listing(rows, ip)])
}

/// `uf`: the function and its size over its listing.
pub fn function(name: &str, len: usize, rows: &[DisasmRow], ip: Option<u64>) -> View {
    let mut head = symbol(name);
    head.push(span(format!("  {len} bytes"), MUTED));
    View::new().main(
        ui::col()
            .child(ui::text(head))
            .child(code::listing(rows, ip)),
    )
}

/// One register cell: the name, then the value (or quiet `N/A`) and any
/// trailing note.
type RegisterCell = (&'static str, Vec<Span>);

/// `r`: the general-purpose grid in the text grid's rows, as a header-less
/// table of (name, value) column pairs so the values line up in columns,
/// then the control and segment registers in a second such table.
/// `read` answers a register by name; `arm64` picks the trailer's layout as
/// the text renderer does (`Target::arch`), the grid's layout follows
/// whether the map has `pc`.
pub fn registers(read: &dyn Fn(&str) -> Option<u64>, arm64: bool) -> View {
    let value = |name: &str| -> Vec<Span> {
        match read(name) {
            Some(value) => vec![addr(value)],
            None => vec![span("N/A", MUTED)],
        }
    };
    let cell = |name: &'static str| -> RegisterCell { (name, value(name)) };
    let segment = |name: &'static str| -> RegisterCell {
        let value = match read(name) {
            Some(value) => span(format!("{value:04x}"), ""),
            None => span("N/A", MUTED),
        };
        (name, vec![value])
    };
    let trailer: Vec<Vec<RegisterCell>> = if arm64 {
        vec![
            vec![cell("ttbr0"), ("ttbr1", value("cr3"))],
            vec![cell("esr"), cell("far")],
        ]
    } else {
        vec![
            vec![cell("cr0"), cell("cr2"), cell("cr3")],
            vec![cell("cr4"), cell("cr8")],
            vec![segment("cs"), segment("ds"), segment("es")],
            vec![segment("fs"), segment("gs"), segment("ss")],
        ]
    };

    View::new().main([ui::col()
        .role("ntoseye.registers")
        .child(register_grid(read))
        .child(register_table(&trailer))])
}

/// The general-purpose registers in the text grid's rows, flags decoded:
/// `r`'s first table, and the registers a stop card shows.
pub fn register_grid(read: &dyn Fn(&str) -> Option<u64>) -> Table<()> {
    let value = |name: &str| -> Vec<Span> {
        match read(name) {
            Some(value) => vec![addr(value)],
            None => vec![span("N/A", MUTED)],
        }
    };
    let cell = |name: &'static str| -> RegisterCell { (name, value(name)) };
    let flags = |names: Vec<&str>| -> Option<Span> {
        (!names.is_empty()).then(|| span(format!("  {}", names.join(" ")), MUTED))
    };

    let grid: Vec<Vec<RegisterCell>> = if read("pc").is_some() {
        let mut rows: Vec<Vec<RegisterCell>> = [
            ["x0", "x1", "x2", "x3"],
            ["x4", "x5", "x6", "x7"],
            ["x8", "x9", "x10", "x11"],
            ["x12", "x13", "x14", "x15"],
            ["x16", "x17", "x18", "x19"],
            ["x20", "x21", "x22", "x23"],
            ["x24", "x25", "x26", "x27"],
            ["x28", "fp", "lr", "sp"],
        ]
        .into_iter()
        .map(|row| row.into_iter().map(cell).collect())
        .collect();
        let mut cpsr = value("cpsr");
        cpsr.extend(flags(cpsr_flags(read("cpsr").unwrap_or(0))));
        rows.push(vec![cell("pc"), ("cpsr", cpsr)]);
        rows
    } else {
        let mut rows: Vec<Vec<RegisterCell>> = [
            ["rax", "rbx", "rcx"],
            ["rdx", "rsi", "rdi"],
            ["rsp", "rbp", "rip"],
            ["r8", "r9", "r10"],
            ["r11", "r12", "r13"],
        ]
        .into_iter()
        .map(|row| row.into_iter().map(cell).collect())
        .collect();
        let rflags = format_rflags(read("eflags").unwrap_or(0));
        let names: Vec<&str> = rflags
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split_whitespace()
            .collect();
        let mut rfl = value("eflags");
        rfl.extend(flags(names));
        rows.push(vec![cell("r14"), cell("r15"), ("rfl", rfl)]);
        rows
    };
    register_table(&grid)
}

/// Rows of (name, value) cells as a table with no header: a name column
/// and a value column per pair, the rightmost pair hiding first.
fn register_table(rows: &[Vec<RegisterCell>]) -> Table<()> {
    let pairs = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut table = ui::table();
    for pair in 0..pairs {
        let priority = (pairs - pair) as f64;
        table = table
            .col(
                Column {
                    id: format!("k{pair}"),
                    ..Column::default()
                }
                .priority(priority),
            )
            .col(
                Column {
                    id: format!("v{pair}"),
                    ..Column::default()
                }
                .priority(priority),
            );
    }
    for (index, row) in rows.iter().enumerate() {
        let mut table_row = TableRow::new(index.to_string());
        for (pair, (name, value)) in row.iter().enumerate() {
            table_row = table_row
                .cell(format!("k{pair}"), span(*name, MUTED))
                .cell(format!("v{pair}"), value.clone());
        }
        table = table.row(table_row);
    }
    table
}

/// The set NZCV and DAIF bits of `cpsr`, by name.
fn cpsr_flags(cpsr: u64) -> Vec<&'static str> {
    [
        (31, "N"),
        (30, "Z"),
        (29, "C"),
        (28, "V"),
        (9, "D"),
        (8, "A"),
        (7, "I"),
        (6, "F"),
    ]
    .into_iter()
    .filter(|(bit, _)| cpsr & (1u64 << bit) != 0)
    .map(|(_, name)| name)
    .collect()
}
