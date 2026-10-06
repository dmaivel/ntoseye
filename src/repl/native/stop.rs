//! A stop as one card. The head says where it stopped, a chip in the
//! card's tone why, and how long the target ran; under it the thread, then
//! the registers (folded), the source or code at the stop and the stack.

use std::time::Duration;

use tern_sdk::ui::{self, Align, Gap, Span, Tone, Wrap};
use tern_sdk::{Node, View};

use super::{MUTED, STRONG, addr, code, ran_row, source, span, spans, stack, symbol};
use crate::disasm::DisasmRow;
use crate::repl::StackColumns;
use crate::target::{ThreadInfo, kthread_state_name};
use crate::triage_report::exception_code_name;
use crate::unwind::StackTrace;

/// What a stop shows, as the text renderer gathers it.
pub struct Stop<'a> {
    /// The backend thread, `p1.1`.
    pub thread: &'a str,
    /// The process context, `dwm.exe (3832)`, or `hypervisor`.
    pub context: &'a str,
    pub symbol: &'a str,
    /// The ring and the chip: what kind of stop this is.
    pub tone: Tone,
    /// Why it stopped, styled: `breakpoint #3`, `exception 0x80000003 at
    /// …`. A bugcheck has none.
    pub cause: Option<&'a str>,
    pub bugcheck: bool,
    /// The Windows thread the stop is on.
    pub windows_thread: Option<&'a ThreadInfo>,
    /// Further styled lines: where a bugcheck stopped, the hypervisor's
    /// saved state.
    pub lines: &'a [String],
    /// The section's head and its registers.
    pub registers: (Vec<Span>, Node),
    /// The code at `current`, or why it can't be shown.
    pub code: Result<&'a [DisasmRow], String>,
    pub current: u64,
    pub stack: &'a StackTrace,
    pub stack_limit: usize,
    /// How long the target ran to reach the stop.
    pub ran: Option<Duration>,
}

pub fn stop_card(stop: Stop<'_>) -> View {
    let mut place = vec![
        span(stop.thread, "info"),
        span(format!(" {} ", stop.context), STRONG),
        span("at ", MUTED),
    ];
    place.extend(symbol(stop.symbol));

    let cause = stop.cause.map(spans).unwrap_or_default();
    let (chip, rest) = chip(&cause, stop.bugcheck);
    let mut head = ui::row()
        .key("head")
        .gap(Gap::Sm)
        .align(Align::Center)
        .child(ui::text(place).wrap(Wrap::None).grow(1.0));
    if let Some(chip) = chip {
        let mut badge = ui::badge(chip.as_str()).tone(stop.tone.clone());
        if let Some(name) = exception_name(&chip) {
            badge = badge.title(name);
        }
        head = head.child(badge);
    }
    if let Some(ran) = stop.ran {
        head = head.child(ran_row(ran));
    }

    // The card's own key names its head child: `main.stop.head`.
    let mut card = ui::card()
        .key("stop")
        .head("main.stop.head")
        .tone(stop.tone)
        .role("ntoseye.stop")
        .child(head);
    if !rest.is_empty() {
        card = card.child(ui::text(rest).wrap(Wrap::Word));
    }
    if let Some(thread) = stop.windows_thread {
        card = card.child(thread_line(thread));
    }
    for line in stop.lines {
        card = card.child(ui::text(spans(line)).wrap(Wrap::Word));
    }
    let (title, registers) = stop.registers;
    card = card.child(
        ui::section()
            .head(title)
            .collapsible(true)
            .collapsed(true)
            .child(registers),
    );
    let listing: Node = match stop.code {
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

/// `thread dwm.exe  state Running  ethread …  pid 3832  tid 3956`: muted
/// keys, evenly spaced, as the text renderer prints it.
fn thread_line(thread: &ThreadInfo) -> ui::TextNode<()> {
    let mut pairs = vec![(
        "thread",
        span(thread.process_name.as_deref().unwrap_or("unknown"), STRONG),
    )];
    if let Some(state) = thread.state {
        pairs.push(("state", span(kthread_state_name(state), "")));
    }
    pairs.push(("ethread", addr(thread.ethread.0)));
    if let Some(pid) = thread.pid {
        pairs.push(("pid", span(pid.to_string(), "")));
    }
    if let Some(tid) = thread.tid {
        pairs.push(("tid", span(tid.to_string(), "")));
    }
    let mut spans = Vec::new();
    for (index, (key, value)) in pairs.into_iter().enumerate() {
        let gap = if index == 0 { "" } else { "  " };
        spans.push(span(format!("{gap}{key} "), MUTED));
        spans.push(value);
    }
    ui::text(spans).wrap(Wrap::Word)
}

/// The chip for a stop's cause, and what the cause says beyond it:
/// `breakpoint #3` alone, `hardware breakpoint #0` then `e1 nt!NtClose`,
/// `exception 0x80000003` then `at fffff…`, `module load` then the module.
fn chip(cause: &[Span], bugcheck: bool) -> (Option<String>, Vec<Span>) {
    if cause.is_empty() {
        return (bugcheck.then(|| "bugcheck".to_owned()), Vec::new());
    }
    let plain: String = cause.iter().map(|span| span.t.as_str()).collect();
    let words: Vec<&str> = plain.split_whitespace().collect();
    let taken = match words.as_slice() {
        ["exception", _, ..] | ["module", "load" | "unload", ..] => 2,
        _ => match words.iter().position(|word| word.starts_with('#')) {
            Some(id) => id + 1,
            None => 1,
        },
    };
    let chip = words[..taken.min(words.len())].join(" ");
    // Drop the chip's words from the styled cause, keeping the rest's style.
    let mut skip = plain
        .split_whitespace()
        .take(taken)
        .map(|word| plain.find(word).map_or(0, |at| at + word.len()))
        .max()
        .unwrap_or(0);
    let mut rest = Vec::new();
    for span in cause {
        let text = &span.t;
        if skip >= text.len() {
            skip -= text.len();
            continue;
        }
        let mut kept = span.clone();
        kept.t = text[skip..].to_owned();
        skip = 0;
        rest.push(kept);
    }
    if let Some(first) = rest.first_mut() {
        first.t = first.t.trim_start().to_owned();
    }
    rest.retain(|span| !span.t.is_empty());
    (Some(chip), rest)
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

/// `STATUS_ACCESS_VIOLATION` for the chip `exception 0xc0000005`: the
/// chip's tooltip. `None` for any other chip, or a code with no name.
fn exception_name(chip: &str) -> Option<&'static str> {
    let code = chip.strip_prefix("exception 0x")?;
    let name = exception_code_name(u32::from_str_radix(code, 16).ok()?);
    (name != "unknown").then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(spans: &[Span]) -> String {
        spans.iter().map(|span| span.t.as_str()).collect()
    }

    #[test]
    fn the_chip_takes_the_kind_and_the_rest_keeps_the_detail() {
        let cases = [
            ("breakpoint #3", "breakpoint #3", ""),
            (
                "hardware breakpoint #0 e1  nt!NtClose",
                "hardware breakpoint #0",
                "e1  nt!NtClose",
            ),
            (
                "exception 0x80000003 at fffff804a115dfb0",
                "exception 0x80000003",
                "at fffff804a115dfb0",
            ),
            ("module load foo.sys", "module load", "foo.sys"),
        ];
        for (cause, want_chip, want_rest) in cases {
            let (chip, rest) = chip(&spans(cause), false);
            assert_eq!(chip.as_deref(), Some(want_chip), "{cause}");
            assert_eq!(plain(&rest), want_rest, "{cause}");
        }
        assert_eq!(chip(&[], true).0.as_deref(), Some("bugcheck"));
        assert_eq!(chip(&[], false).0, None);
    }
}
