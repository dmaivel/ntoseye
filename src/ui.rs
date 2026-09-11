//! The single presentation layer for terminal styling. Domain types (e.g.
//! `VirtAddr`) stay plain; everything that adds color goes through here, so the
//! palette lives in one place and stays consistent.

use owo_colors::OwoColorize;
use std::fmt::Display;

use crate::disasm::{AsmKind, AsmToken};
use crate::types::VirtAddr;

/// Absolute address: bare 16-digit, default foreground. Never format a
/// `VirtAddr` with `{:#x}` for display; route it through here so the styling
/// can't drift.
pub fn addr(value: u64) -> String {
    format!("{value:016x}")
}

/// An address, or a muted `unavailable` when null.
pub fn addr_opt(value: VirtAddr) -> String {
    if value.is_zero() {
        muted("unavailable")
    } else {
        addr(value.0)
    }
}

/// A resolved symbol: light-blue name (module prefix included), with any
/// trailing `+0x...` offset dimmed so the eye lands on the name. A raw
/// `0x...` fallback (nothing resolved) renders fully muted.
pub fn symbol(sym: &str) -> String {
    if sym.starts_with("0x") {
        return muted(sym);
    }
    let (body, offset) = match sym.rfind("+0x") {
        Some(idx) => (&sym[..idx], &sym[idx..]),
        None => (sym, ""),
    };
    let body = body.bright_blue().to_string();
    if offset.is_empty() {
        body
    } else {
        format!("{}{}", body, muted(offset))
    }
}

/// Secondary / de-emphasized text: scan tags, "N more", offsets, raw fallbacks.
pub fn muted(text: &str) -> String {
    text.bright_black().to_string()
}

/// A bold, uncolored label/header (e.g. `break:`, `breakpoint:`, section
/// titles). Color is reserved for content; labels are bold only.
pub fn label(text: &str) -> String {
    text.bold().to_string()
}

/// Style a disassembled instruction's [`AsmToken`](crate::disasm::AsmToken)s
/// for the listing: mnemonic as the anchor, registers and immediates in content
/// color, punctuation muted.
pub fn disasm_asm(tokens: &[AsmToken]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token.kind {
            AsmKind::Register => out.push_str(&token.text.cyan().to_string()),
            AsmKind::Number => out.push_str(&token.text.green().to_string()),
            AsmKind::Punctuation | AsmKind::Keyword => out.push_str(&muted(&token.text)),
            AsmKind::Mnemonic => out.push_str(&token.text.bright_magenta().to_string()),
            AsmKind::Text => out.push_str(&token.text),
        }
    }
    out
}

/// A breakpoint identifier accent, e.g. `#3` in cyan. Used consistently across
/// every breakpoint message (set/hit/cleared/disabled/enabled).
pub fn bp_id(id: impl Display) -> String {
    format!("#{id}").cyan().to_string()
}

/// Thread/processor id accent, e.g. `p1.1`, cyan like [`bp_id`]. Shared by
/// the prompt and break lines.
pub fn thread_id(id: &str) -> String {
    id.cyan().to_string()
}

/// An event badge like ` BREAK `: white on red, reserved for execution-stop
/// announcements.
pub fn badge(text: &str) -> String {
    format!(" {text} ").white().on_red().to_string()
}

/// Event-banner background: palette "black", which themes remap toward
/// their own background (near-black on dark themes, near-white on light
/// ones), so the plate adapts without terminal queries. Inner styles must
/// reset foreground only (`39`) and never carry a background.
pub fn plate(text: &str) -> String {
    text.on_black().to_string()
}
