//! Debug-backend [`View`] builders: the capability matrix and
//! captured guest debug output.

use super::View;
use crate::dbg_backend::{BackendCapability, DebugLine, DebugOutputPage};

/// A page of captured guest debug output plus the cursor for the next poll.
pub fn debug_log(page: &DebugOutputPage) -> View {
    View::Object(vec![
        (
            "lines",
            View::List(page.lines.iter().map(debug_log_line).collect()),
        ),
        ("next_seq", View::Num(page.next_seq)),
        ("dropped", View::Bool(page.dropped)),
    ])
}

/// One captured guest debug output line.
pub fn debug_log_line(line: &DebugLine) -> View {
    View::Object(vec![
        ("seq", View::Num(line.seq)),
        ("timestamp_ms", View::Num(line.timestamp_ms)),
        ("text", View::Str(line.text.clone())),
    ])
}

/// One row of a backend's capability matrix.
pub fn capability(capability: &BackendCapability) -> View {
    View::Object(vec![
        (
            "capability",
            View::Str(capability.capability.name().to_string()),
        ),
        (
            "label",
            View::Str(capability.capability.label().to_string()),
        ),
        ("supported", View::Bool(capability.supported)),
    ])
}
