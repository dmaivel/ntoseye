//! The `k` family, the register grid and the `u` family as Tern views.

use tern_sdk::View;
use tern_sdk::ui::{self, Align, Column, Gap, Node, Span, Table, TableRow, Wrap};

use super::{CHANGED, MUTED, addr, code, span, stack, symbol};
use crate::disasm::DisasmRow;
use crate::repl::{StackColumns, format_rflags};
use crate::trapframe::{KtrapFrame, KtrapFrameData, TrapKind};
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
        .child(register_grid(read, &|_| false))
        .child(register_table(&trailer))])
}

/// The general-purpose registers in the text grid's rows, flags decoded:
/// `r`'s first table, and the registers a stop card shows, those `changed`
/// since the last stop standing out.
pub fn register_grid(
    read: &dyn Fn(&str) -> Option<u64>,
    changed: &dyn Fn(&str) -> bool,
) -> Table<()> {
    let value = |name: &str| -> Vec<Span> {
        match read(name) {
            Some(value) if changed(name) => vec![addr(value).style(CHANGED)],
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

/// The general-purpose registers `changed` since the last stop, in the
/// grid's order.
pub fn changed_registers(
    read: &dyn Fn(&str) -> Option<u64>,
    changed: &dyn Fn(&str) -> bool,
) -> Vec<&'static str> {
    let names: &[&'static str] = if read("pc").is_some() {
        &ARM64_GRID
    } else {
        &X64_GRID
    };
    names.iter().copied().filter(|name| changed(name)).collect()
}

/// The registers of the grid, by architecture, in reading order.
const X64_GRID: [&str; 18] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15", "eflags",
];
const ARM64_GRID: [&str; 34] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "fp", "lr", "sp", "pc", "cpsr",
];

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

/// `.trap`: the frame's address and a chip for the kind of entry that built
/// it in the head, its registers, and what it ran.
pub fn trap(frame: &KtrapFrame, rip_symbol: Option<&str>, selected: u64) -> View {
    let mut head = ui::row()
        .key("head")
        .gap(Gap::Sm)
        .align(Align::Center)
        .child(
            ui::text([span("trap frame ", MUTED), addr(frame.address)])
                .wrap(Wrap::None)
                .grow(1.0),
        );
    if let Some(kind) = frame.amd64().and_then(|frame| frame.kind) {
        head = head.child(ui::badge(kind.as_str()).title(unsaved_note(kind)));
    }
    // The card's own key names its head child: `main.trap.head`.
    let mut card = ui::card()
        .key("trap")
        .head("main.trap.head")
        .role("ntoseye.trap")
        .child(head);
    for node in trap_frame(frame, rip_symbol) {
        card = card.child(node);
    }
    card = card.child(ui::text([
        span("selected trap context frame 00 at ", MUTED),
        addr(selected),
    ]));
    View::new().main([card])
}

/// A trap frame's registers as a table, a register its entry did not save
/// a quiet `-`, then the selectors, mode and IRQL, and the symbol of the
/// instruction it trapped at. `.trap` and the bugcheck card show it.
pub fn trap_frame(frame: &KtrapFrame, rip_symbol: Option<&str>) -> Vec<Node> {
    let saved = |value: Option<u64>| -> Vec<Span> {
        match value {
            Some(value) => vec![addr(value)],
            None => vec![span("-", MUTED)],
        }
    };
    let hex = |value: Option<u64>| -> Span {
        match value {
            Some(value) => span(format!("{value:#x}"), ""),
            None => span("-", MUTED),
        }
    };
    let mut nodes: Vec<Node> = Vec::new();
    let mut details: Vec<(&str, Span)> = Vec::new();
    let pc_name = match &frame.data {
        KtrapFrameData::Amd64(frame) => {
            let mut rfl = vec![addr(frame.eflags as u64)];
            let flags = format_rflags(frame.eflags as u64);
            let flags = flags.trim();
            if !flags.is_empty() {
                rfl.push(span(format!("  {flags}"), MUTED));
            }
            let rows: Vec<Vec<RegisterCell>> = vec![
                vec![
                    ("rax", saved(frame.rax)),
                    ("rbx", saved(frame.rbx)),
                    ("rcx", saved(frame.rcx)),
                ],
                vec![
                    ("rdx", saved(frame.rdx)),
                    ("rsi", saved(frame.rsi)),
                    ("rdi", saved(frame.rdi)),
                ],
                vec![
                    ("rsp", vec![addr(frame.rsp)]),
                    ("rbp", vec![addr(frame.rbp)]),
                    ("rip", vec![addr(frame.rip)]),
                ],
                vec![
                    ("r8", saved(frame.r8)),
                    ("r9", saved(frame.r9)),
                    ("r10", saved(frame.r10)),
                ],
                vec![("r11", saved(frame.r11)), ("rfl", rfl)],
            ];
            nodes.push(register_table(&rows).into());
            details.push(("cs", span(format!("{:04x}", frame.cs), "")));
            details.push((
                "ss",
                match frame.ss {
                    Some(ss) => span(format!("{ss:04x}"), ""),
                    None => span("-", MUTED),
                },
            ));
            if let Some(code) = frame.error_code {
                details.push(("error code", span(format!("{code:#x}"), "")));
            }
            if let Some(irql) = frame.previous_irql {
                details.push(("irql", span(irql.to_string(), "")));
            }
            details.push((
                "previous mode",
                span(
                    if frame.previous_mode == 0 {
                        "kernel"
                    } else {
                        "user"
                    },
                    "",
                ),
            ));
            "rip"
        }
        KtrapFrameData::Arm64(frame) => {
            let mut rows: Vec<Vec<RegisterCell>> = frame
                .x
                .chunks(3)
                .enumerate()
                .map(|(index, values)| {
                    values
                        .iter()
                        .enumerate()
                        .map(|(offset, value)| (X_NAMES[index * 3 + offset], vec![addr(*value)]))
                        .collect()
                })
                .collect();
            rows.push(vec![
                ("fp", vec![addr(frame.fp)]),
                ("lr", vec![addr(frame.lr)]),
                ("sp", vec![addr(frame.sp)]),
            ]);
            let mut cpsr = vec![hex(frame.cpsr)];
            if let Some(value) = frame.cpsr {
                let flags = cpsr_flags(value);
                if !flags.is_empty() {
                    cpsr.push(span(format!("  {}", flags.join(" ")), MUTED));
                }
            }
            rows.push(vec![("pc", vec![addr(frame.pc)]), ("cpsr", cpsr)]);
            nodes.push(register_table(&rows).into());
            let debug: Vec<Vec<RegisterCell>> = [
                ("bcr", &frame.bcr[..]),
                ("bvr", &frame.bvr[..]),
                ("wcr", &frame.wcr[..]),
                ("wvr", &frame.wvr[..]),
            ]
            .into_iter()
            .filter(|(_, values)| values.iter().any(Option::is_some))
            .flat_map(|(name, values)| {
                values
                    .chunks(4)
                    .enumerate()
                    .map(move |(chunk, values)| {
                        values
                            .iter()
                            .enumerate()
                            .map(|(offset, value)| {
                                (
                                    debug_register_name(name, chunk * 4 + offset),
                                    vec![hex(*value)],
                                )
                            })
                            .collect::<Vec<RegisterCell>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
            if !debug.is_empty() {
                nodes.push(
                    ui::section()
                        .head("debug registers")
                        .collapsible(true)
                        .collapsed(true)
                        .child(register_table(&debug))
                        .into(),
                );
            }
            details.push(("esr", hex(frame.esr)));
            details.push((
                "fault address",
                match frame.fault_address {
                    Some(address) => addr(address),
                    None => span("-", MUTED),
                },
            ));
            details.push((
                "irql",
                match frame.previous_irql {
                    Some(irql) => span(irql.to_string(), ""),
                    None => span("-", MUTED),
                },
            ));
            details.push((
                "previous mode",
                match frame.previous_mode {
                    Some(0) => span("kernel", ""),
                    Some(_) => span("user", ""),
                    None => span("-", MUTED),
                },
            ));
            "pc"
        }
    };
    let mut line = Vec::new();
    for (index, (key, value)) in details.into_iter().enumerate() {
        let gap = if index == 0 { "" } else { "  " };
        line.push(span(format!("{gap}{key} "), MUTED));
        line.push(value);
    }
    nodes.push(ui::text(line).wrap(Wrap::Word).into());
    if let Some(name) = rip_symbol {
        let mut line = vec![span(format!("{pc_name} \u{21d2} "), MUTED)];
        line.extend(symbol(name));
        nodes.push(ui::text(line).into());
    }
    nodes
}

/// `x0`..`x18` as static names for the register table.
const X_NAMES: [&str; 19] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18",
];

/// `bcr3`, `wvr1`: a debug register's name, static for the register table.
fn debug_register_name(kind: &str, index: usize) -> &'static str {
    const BCR: [&str; 8] = [
        "bcr0", "bcr1", "bcr2", "bcr3", "bcr4", "bcr5", "bcr6", "bcr7",
    ];
    const BVR: [&str; 8] = [
        "bvr0", "bvr1", "bvr2", "bvr3", "bvr4", "bvr5", "bvr6", "bvr7",
    ];
    const WCR: [&str; 2] = ["wcr0", "wcr1"];
    const WVR: [&str; 2] = ["wvr0", "wvr1"];
    let names: &[&'static str] = match kind {
        "bcr" => &BCR,
        "bvr" => &BVR,
        "wcr" => &WCR,
        _ => &WVR,
    };
    names[index]
}

/// Which registers the kind of entry that built a frame leaves unsaved, so
/// its `-` cells: the trap kind chip's tooltip.
fn unsaved_note(kind: TrapKind) -> &'static str {
    match kind {
        TrapKind::Interrupt => "An interrupt entry does not save rbx, rdi or an error code.",
        TrapKind::Exception => "An exception entry does not save rbx, rdi, rsi or the IRQL.",
        TrapKind::SystemCall => {
            "A system call does not save r11 (it holds the flags), an error code or the IRQL."
        }
        TrapKind::ZwCall => {
            "A Zw call saves only rbx, rdi and rsi besides the machine frame and rbp."
        }
    }
}
