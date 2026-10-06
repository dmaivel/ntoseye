//! A bugcheck as an error card: the name and code in the head, the module,
//! the fault and the four parameters with their meanings as properties, the
//! description under them, and the trap frames the parameters name folded
//! away.

use tern_sdk::ui::{self, Span, Tone, Wrap};
use tern_sdk::{Node, View};

use super::{MUTED, NUMBER, STRONG, addr, frames, span, spans, styled, symbol};
use crate::bugchecks::{
    BUGCHECK_DATA_SLOTS, BugcheckAnalysis, BugcheckFault, BugcheckTrapFrame, CurrentBugcheckFailure,
};
use crate::repl::print_bugcheck_trap_frame;

/// The summary a bugcheck stop prints, and `!analyze -show`.
pub fn card(analysis: &BugcheckAnalysis) -> View {
    let mut card = ui::card()
        .head(head(analysis))
        .tone(Tone::Error)
        .role("ntoseye.bugcheck");
    for child in details(analysis) {
        card = card.child(child);
    }
    View::new().main([card])
}

/// `NAME (0x000000d1)`.
pub fn head(analysis: &BugcheckAnalysis) -> Vec<Span> {
    vec![
        span(&analysis.name, STRONG),
        span(" ", ""),
        span(format!("({:#010x})", analysis.code), NUMBER),
    ]
}

/// Everything the text renderer shows under the banner: the properties
/// (module, fault, source, Arg1..Arg4 with their meanings), the
/// description, then each trap frame, folded.
pub fn details(analysis: &BugcheckAnalysis) -> Vec<Node> {
    let mut kv = ui::kv();
    if let Some(driver) = &analysis.driver {
        kv = kv.item("module", symbol(driver));
    }
    if let Some(fault) = &analysis.fault {
        kv = kv.item("fault", fault_spans(fault));
    }
    if let Some(source) = &analysis.source {
        kv = kv.item("source", span(source, MUTED));
    }
    for (index, arg) in analysis.args.iter().enumerate() {
        let mut value = vec![addr(arg.value)];
        if !arg.description.is_empty() {
            value.push(span(format!("  {}", arg.description), MUTED));
        }
        kv = kv.item(format!("Arg{}", index + 1).as_str(), value);
    }

    let mut nodes: Vec<Node> = vec![kv.into()];
    if let Some(description) = &analysis.description {
        nodes.push(ui::text([span(description, MUTED)]).wrap(Wrap::Word).into());
    }
    for trap_frame in &analysis.trap_frames {
        nodes.push(trap_frame_node(trap_frame));
    }
    nodes
}

/// The fault site: the address, then the symbol unless it is only the
/// address again.
fn fault_spans(fault: &BugcheckFault) -> Vec<Span> {
    let mut value = vec![addr(fault.ip)];
    if !fault.symbol.starts_with("0x") {
        value.push(span("  ", ""));
        value.extend(symbol(&fault.symbol));
    }
    value
}

/// A trap frame: `trap frame <address>  <kind>` as a folded section's head
/// over its registers, or the decode failure alone.
pub fn trap_frame_node(trap_frame: &BugcheckTrapFrame) -> Node {
    let Some(frame) = &trap_frame.frame else {
        let text = styled(|| print_bugcheck_trap_frame(trap_frame));
        return ui::text(spans(text.trim_end_matches('\n')))
            .wrap(Wrap::Word)
            .into();
    };
    let mut head = vec![span("trap frame ", ""), addr(trap_frame.address)];
    if let Some(kind) = frame.amd64().and_then(|frame| frame.kind) {
        head.push(span(format!("  {}", kind.as_str()), MUTED));
    }
    let mut section = ui::section().head(head).collapsible(true).collapsed(true);
    for node in frames::trap_frame(frame, trap_frame.rip_symbol.as_deref()) {
        section = section.child(node);
    }
    section.into()
}

/// The guest bugchecks, but `nt!KiBugCheckData` has no symbol.
pub fn symbol_unavailable() -> View {
    let card = ui::card()
        .head([span("guest is bugchecking", STRONG)])
        .tone(Tone::Error)
        .role("ntoseye.bugcheck")
        .child(ui::text([span(
            "symbol nt!KiBugCheckData unavailable",
            MUTED,
        )]));
    View::new().main([card])
}

/// `nt!KiBugCheckData` could not be read as a bugcheck: why, and the raw
/// slots that were there.
pub fn unresolved(failure: &CurrentBugcheckFailure) -> View {
    let mut kv = ui::kv().item("reason", span(&failure.reason, "error"));
    if let Some(data) = &failure.slots {
        kv = kv.item("raw slots", slots(data));
    }
    if let Some(data) = &failure.dereferenced_slots {
        kv = kv.item("dereferenced slots", slots(data));
    }
    let card = ui::card()
        .head([
            span("unable to resolve ", STRONG),
            span("nt!KiBugCheckData", STRONG),
            span(format!(" at {:#x}", failure.address), MUTED),
        ])
        .tone(Tone::Error)
        .role("ntoseye.bugcheck")
        .child(kv);
    View::new().main([card])
}

fn slots(data: &[u64; BUGCHECK_DATA_SLOTS]) -> Span {
    let values: Vec<String> = data.iter().map(|value| format!("{value:#x}")).collect();
    span(format!("[{}]", values.join(", ")), NUMBER)
}
