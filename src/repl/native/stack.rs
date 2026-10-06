//! A stack trace as a Tern table: the `k` family's columns, the call site
//! growing into the pane's width, and the quieter columns hiding first in a
//! narrow one.

use tern_sdk::ui::{self, Col, Column, Span, TableRow, TextAlign, Truncate};

use super::{MUTED, NUMBER, STRONG, addr, span, symbol};
use crate::repl::StackColumns;
use crate::symbols::{LocalSourceState, SourceLocation};
use crate::unwind::{FrameSource, StackFrame, StackTrace};

/// The first `limit` frames of `trace`, with the child SP when `with_sp`,
/// then a note for the frames not shown or not walked.
pub fn table(trace: &StackTrace, limit: usize, with_sp: bool, columns: StackColumns) -> Col<()> {
    numbered(trace, limit, with_sp, columns, 0, None)
}

/// [`table`] with the frames numbered from `first`, and the frame numbered
/// `selected` (the `.frame` one) marked.
pub fn numbered(
    trace: &StackTrace,
    limit: usize,
    with_sp: bool,
    columns: StackColumns,
    first: usize,
    selected: Option<usize>,
) -> Col<()> {
    let mut table = ui::table().col(Column::new("n", "#").align(TextAlign::End).priority(4.0));
    if columns.frame_size {
        table = table.col(
            Column::new("size", "Size")
                .align(TextAlign::End)
                .priority(1.0),
        );
    }
    if with_sp {
        table = table.col(Column::new("sp", "Child-SP").priority(2.0));
    }
    table = table.col(Column::new("ip", "Address").priority(3.0)).col(
        Column::new("site", "Call site")
            .grow(1.0)
            .truncate(Truncate::End)
            .priority(5.0),
    );

    let mut previous_sp = None;
    for (number, frame) in trace.frames.iter().take(limit).enumerate() {
        let number = first + number;
        let label = if selected == Some(number) {
            span(format!("▸ {number}"), STRONG)
        } else {
            span(number.to_string(), MUTED)
        };
        let mut row = TableRow::new(number.to_string())
            .cell("n", label)
            .cell("ip", addr(frame.ip))
            .cell("site", call_site(frame, columns.provenance));
        if with_sp {
            row = row.cell("sp", [span(format!("{:016x}", frame.sp), MUTED)]);
        }
        if columns.frame_size {
            let size = if frame.inline {
                None
            } else {
                previous_sp
                    .replace(frame.sp)
                    .and_then(|previous| frame.sp.checked_sub(previous))
            };
            if let Some(size) = size {
                row = row.cell("size", span(format!("{size:x}"), NUMBER));
            }
        }
        table = table.row(row);
    }

    let mut col = ui::col().child(table);
    let hidden = trace.frames.len().saturating_sub(limit) + trace.truncated;
    if hidden > 0 {
        col = col.child(ui::text([span(format!("… {hidden} more frames"), MUTED)]));
    }
    col
}

/// The symbol, then the tags the text renderer appends: inline, how the
/// frame was recovered (always with `provenance`, else only a guess), and
/// the source line, linked when the file is on this machine.
fn call_site(frame: &StackFrame, provenance: bool) -> Vec<Span> {
    let mut spans = if frame.symbol.starts_with("0x") {
        Vec::new()
    } else {
        symbol(&frame.symbol)
    };
    if frame.inline {
        spans.push(span("  [inline]", MUTED));
    }
    if provenance || matches!(frame.source, FrameSource::Scan | FrameSource::Prolog) {
        spans.push(span(format!("  [{}]", frame.source.as_str()), MUTED));
    }
    if let Some(location) = &frame.source_location {
        spans.push(span("  ", ""));
        spans.push(source(location));
    }
    spans
}

/// `[local path:line]`, a link Tern opens in a file block at the line when
/// the file is the one the PDB names.
fn source(location: &SourceLocation) -> Span {
    let line = match location.column {
        Some(column) => format!("{}:{column}", location.line),
        None => location.line.to_string(),
    };
    match &location.local {
        Some(local) => {
            let label = match local.state {
                LocalSourceState::Found => "local",
                LocalSourceState::Missing => "mapped",
                LocalSourceState::Differs => "differs",
            };
            let text = format!("[{label} {}:{line}]", local.path.display());
            let link = span(text, &format!("{MUTED} path"));
            if local.state == LocalSourceState::Found {
                link.href(format!("{}:{}", local.path.display(), location.line))
            } else {
                link
            }
        }
        None => span(format!("[recorded {}:{line}]", location.file), MUTED),
    }
}
