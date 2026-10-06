//! The memory displays as Tern tables: `db` and its siblings a row per text
//! row, the values in the text's own spacing, and `dds`/`dqs` a row per
//! value with the symbol it resolves to. Zeros read quieter than data, and
//! unreadable memory quieter still than what was read.

use std::fmt::{self, Write as _};

use tern_sdk::View;
use tern_sdk::ui::{self, Column, Span, TableRow, Truncate};

use super::{DIM, MUTED, addr, span, symbol};
use crate::repl::commands::memory::{SymbolValue, SymbolValueRow};
use crate::repl::{AsciiCell, ItemKind, MemoryDisplayMode, row_ascii, row_items};
use crate::types::VirtAddr;

/// Spans built a run at a time: adjacent text in one style is one span, so
/// a uniform row is a single span however many items it holds.
#[derive(Default)]
pub struct Runs {
    spans: Vec<Span>,
    text: String,
    style: &'static str,
}

impl Runs {
    pub fn push(&mut self, style: &'static str, text: fmt::Arguments<'_>) {
        if style != self.style && !self.text.is_empty() {
            self.flush();
        }
        self.style = style;
        let _ = self.text.write_fmt(text);
    }

    fn flush(&mut self) {
        self.spans
            .push(span(std::mem::take(&mut self.text), self.style));
    }

    /// A span of its own, such as one carrying a second style token.
    pub fn push_span(&mut self, span: Span) {
        if !self.text.is_empty() {
            self.flush();
        }
        self.spans.push(span);
    }

    /// The spans, without the separator the last item ends in.
    pub fn finish(mut self) -> Vec<Span> {
        let end = self.text.trim_end().len();
        self.text.truncate(end);
        if !self.text.is_empty() {
            self.flush();
        }
        self.spans
    }
}

/// A header-less column.
fn column(id: &str, priority: f64) -> Column {
    Column {
        id: id.into(),
        ..Column::default()
    }
    .priority(priority)
}

/// `db`, `dw`, `dW`, `dc`, `dd`, `dq`, `dp`, `dyb`, `df`, `dD`: a row per
/// text row, the address, the values laid out as the text lays them out,
/// and the ASCII column when the mode has one. `validity` marks the bytes
/// read, one entry per byte of `data`.
pub fn dump(
    start: VirtAddr,
    data: &[u8],
    validity: Option<&[bool]>,
    mode: &MemoryDisplayMode,
) -> View {
    let mut table = ui::table()
        .col(column("addr", 3.0))
        .col(column("values", 2.0));
    if mode.show_ascii() {
        table = table.col(column("ascii", 1.0));
    }

    for (row, chunk) in data.chunks(mode.bytes_per_row()).enumerate() {
        let address = start + (row * mode.bytes_per_row()) as u64;
        let mut values = Runs::default();
        row_items(row, chunk, validity, mode, |kind, text| {
            let style = match kind {
                ItemKind::Value => "",
                ItemKind::Zero => DIM,
                ItemKind::Unreadable => MUTED,
                // The table's column keeps the ASCII column in line.
                ItemKind::Padding => return,
            };
            values.push(style, text);
        });
        let mut cells = TableRow::new(format!("{:x}", address.0))
            .cell("addr", addr(address.0))
            .cell("values", values.finish());
        if mode.show_ascii() {
            let mut ascii = Runs::default();
            row_ascii(row, chunk, validity, mode, |cell| match cell {
                AsciiCell::Unreadable => ascii.push(MUTED, format_args!("?")),
                AsciiCell::Char(character) => ascii.push(MUTED, format_args!("{character}")),
                // Not the text's `.`: Tern's font joins `...` into an
                // ellipsis, and a middle dot also tells a non-printable byte
                // from a real `.` (0x2e).
                AsciiCell::Dot => ascii.push(DIM, format_args!("\u{b7}")),
            });
            cells = cells.cell("ascii", ascii.finish());
        }
        table = table.row(cells);
    }

    View::new().main([table])
}

/// `dds`, `dqs`/`dps`: a row per value, `item_size * 2` digits wide, and
/// the symbol it resolves to carrying the table.
pub fn symbol_values(rows: &[SymbolValueRow], item_size: usize) -> View {
    let width = item_size * 2;
    let mut table = ui::table()
        .col(Column::new("addr", "Address").priority(3.0))
        .col(Column::new("value", "Value").priority(2.0))
        .col(
            Column::new("symbol", "Symbol")
                .grow(1.0)
                .truncate(Truncate::End)
                .priority(4.0),
        );
    for row in rows {
        let (value, resolved) = match &row.value {
            SymbolValue::Partial => (span("<partial>", MUTED), Vec::new()),
            SymbolValue::Unreadable => (span("<unreadable>", MUTED), Vec::new()),
            SymbolValue::Value {
                value,
                symbol: name,
            } => (
                span(
                    format!("{value:0width$x}"),
                    if *value == 0 { DIM } else { "" },
                ),
                name.as_deref().map(symbol).unwrap_or_default(),
            ),
        };
        table = table.row(
            TableRow::new(format!("{:x}", row.address.0))
                .cell("addr", addr(row.address.0))
                .cell("value", value)
                .cell("symbol", resolved),
        );
    }
    View::new().main([table])
}
