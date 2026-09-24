//! The single presentation layer for terminal styling. Domain types (e.g.
//! `VirtAddr`) stay plain; everything that adds color goes through here, so the
//! palette lives in one place and stays consistent.

use owo_colors::OwoColorize;
use std::fmt::{self, Display, Write as _};

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
    muted_style(&text).to_string()
}

fn muted_style<T: Display>(text: &T) -> impl Display + '_ {
    text.bright_black()
}

/// A bold, uncolored label/header (e.g. `break:`, `breakpoint:`, section
/// titles). Color is reserved for content; labels are bold only.
pub fn label(text: &str) -> String {
    text.bold().to_string()
}

/// A numeric value in content color, styled under `{}`, `{:x}`, `{:X}` and
/// `{:b}` alike so width and padding flags still apply to the digits.
pub struct Value<T>(pub T);

macro_rules! impl_value_fmt {
    ($($trait:path),+) => {
        $(
            impl<T: $trait> $trait for Value<T> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    <_ as $trait>::fmt(&self.0.cyan(), f)
                }
            }
        )+
    };
}

impl_value_fmt!(fmt::Display, fmt::LowerHex, fmt::UpperHex, fmt::Binary);

/// Style a disassembled instruction's [`AsmToken`]s
/// for the listing: mnemonic as the anchor, registers and immediates in content
/// color, punctuation muted.
pub fn disasm_asm(tokens: &[AsmToken]) -> String {
    let mut out = String::new();
    for token in tokens {
        let text = &token.text;
        let _ = match token.kind {
            AsmKind::Register => write!(out, "{}", text.cyan()),
            AsmKind::Number => write!(out, "{}", text.green()),
            AsmKind::Punctuation | AsmKind::Keyword => write!(out, "{}", muted_style(text)),
            AsmKind::Mnemonic => write!(out, "{}", text.bright_magenta()),
            AsmKind::Text => out.write_str(text),
        };
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
