//! Text rendering helpers for user-mode heap commands.
//!
//! Heap decoding is implemented in [`crate::target::heap`] so the same detail
//! structs serve the REPL, Python SDK, and MCP surfaces.

use crate::target::heap::HeapKind;

pub fn heap_kind_name(kind: HeapKind) -> String {
    match kind {
        HeapKind::Nt => "nt".into(),
        HeapKind::Segment => "segment".into(),
        HeapKind::Unknown(signature) => format!("unknown ({signature:#x})"),
    }
}
