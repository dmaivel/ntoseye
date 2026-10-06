//! Disassembly as Tern rows: the text renderer's columns, colored with
//! Tern's syntax palette, and the instruction a thread stands on marked
//! across the row instead of by a `>` gutter.

use tern_sdk::ui::{self, Col, Mark, Span, Wrap};

use super::{DIM, IMMEDIATE, MNEMONIC, MUTED, REGISTER, addr, span, symbol};
use crate::disasm::{AsmKind, AsmToken, DisasmRow};

/// One row per instruction, the byte column as wide as the listing's
/// longest; `current` marks the instruction at that address.
pub fn listing(rows: &[DisasmRow], current: Option<u64>) -> Col<()> {
    let width = rows.iter().map(|row| row.hex.len()).max().unwrap_or(0);
    let mut listing = ui::col().role("ntoseye.disasm");
    for row in rows {
        let mut spans = vec![addr(row.ip), span(format!("  {:<width$}  ", row.hex), DIM)];
        spans.extend(asm(&row.tokens));
        if let Some(comment) = &row.comment {
            spans.push(span("  ; ", MUTED));
            spans.extend(symbol(comment));
        }
        let line = ui::text(spans).wrap(Wrap::None);
        listing = listing.child(if current == Some(row.ip) {
            line.mark(Mark::Pick)
        } else {
            line
        });
    }
    listing
}

/// An instruction's tokens, as `crate::ui::disasm_asm` colors them.
pub fn asm(tokens: &[AsmToken]) -> impl Iterator<Item = Span> + '_ {
    tokens.iter().map(|token| {
        let style = match token.kind {
            AsmKind::Mnemonic => MNEMONIC,
            AsmKind::Register => REGISTER,
            AsmKind::Number => IMMEDIATE,
            AsmKind::Punctuation | AsmKind::Keyword => MUTED,
            AsmKind::Text => "",
        };
        span(token.text.clone(), style)
    })
}
