//! A stop as one card: where it stopped in the head, why under it, then the
//! registers (folded), the code at the stop and the stack. The ring's tone
//! says what kind of stop it is at a glance.

use tern_sdk::View;
use tern_sdk::ui::{self, Tone, Wrap};

use super::{MUTED, STRONG, block, code, source, span, spans, stack, symbol};
use crate::disasm::DisasmRow;
use crate::repl::StackColumns;
use crate::unwind::StackTrace;

/// What a stop shows, as the text renderer gathers it.
pub struct Stop<'a> {
    /// The backend thread, `p1.1`.
    pub thread: &'a str,
    /// The process context, `dwm.exe (3832)`, or `hypervisor`.
    pub context: &'a str,
    pub symbol: &'a str,
    /// The ring: what kind of stop this is.
    pub tone: Tone,
    /// Styled lines under the head: the cause first, then the thread and
    /// notes.
    pub details: &'a [String],
    /// The section's title and the styled register grid.
    pub registers: (&'a str, String),
    /// The code at `current`, or why it can't be shown.
    pub code: Result<&'a [DisasmRow], String>,
    pub current: u64,
    pub stack: &'a StackTrace,
    pub stack_limit: usize,
}

pub fn stop_card(stop: Stop<'_>) -> View {
    let mut head = vec![
        span(stop.thread, "info"),
        span(format!(" {} ", stop.context), STRONG),
        span("at ", MUTED),
    ];
    head.extend(symbol(stop.symbol));

    let mut card = ui::card().head(head).tone(stop.tone).role("ntoseye.stop");
    for line in stop.details {
        card = card.child(ui::text(spans(line)).wrap(Wrap::Word));
    }
    let (title, registers) = stop.registers;
    card = card.child(
        ui::section()
            .head(title)
            .collapsible(true)
            .collapsed(true)
            .child(block(&registers)),
    );
    let listing: tern_sdk::Node = match stop.code {
        Ok(rows) => code::listing(rows, Some(stop.current)).into(),
        Err(note) => ui::text([span(note, MUTED)]).into(),
    };
    // At a line of a file on this machine, the source leads and the
    // instructions fold under it.
    let lines = stop
        .stack
        .frames
        .first()
        .and_then(|frame| frame.source_location.as_ref())
        .and_then(source::around);
    let folded = lines.is_some();
    if let Some(lines) = lines {
        card = card.child(ui::section().head("source").collapsible(true).child(lines));
    }
    card = card.child(
        ui::section()
            .head("disassembly")
            .collapsible(true)
            .collapsed(folded)
            .child(listing),
    );
    card = card.child(
        ui::section()
            .head("stack")
            .collapsible(true)
            .child(stack::table(
                stop.stack,
                stop.stack_limit,
                false,
                StackColumns::default(),
            )),
    );
    View::new().main([card])
}

/// The ring for a stop: an error for a bugcheck, a warning for an
/// exception, the accent for a breakpoint or watchpoint, info for a module
/// event and the hypervisor, neutral for a step or a break-in.
pub fn tone(cause: Option<&str>, bugcheck: bool, hypervisor: bool) -> Tone {
    if bugcheck {
        return Tone::Error;
    }
    let cause = cause.map(|cause| {
        spans(cause)
            .into_iter()
            .map(|span| span.t)
            .collect::<String>()
    });
    match cause.as_deref() {
        Some(cause) if cause.starts_with("exception") => Tone::Warning,
        Some(cause) if cause.starts_with("module") => Tone::Info,
        Some(_) => Tone::Accent,
        None if hypervisor => Tone::Pending,
        None => Tone::Neutral,
    }
}
