//! Debug-backend [`View`] builders: the capability matrix and
//! captured guest debug output.

use super::View;
use super::shape::shapes;
use crate::dbg_backend::{self, DebugLine, DebugOutputPage};

shapes! {
    /// A captured line of guest debug output (DbgPrint, kernel printf).
    DebugLogLine {
        /// Monotonic sequence number, the read cursor.
        seq: u64,
        /// Host wall-clock time the line completed, in milliseconds since
        /// the Unix epoch.
        timestamp_ms: u64,
        text: String,
    }

    /// A page of captured guest debug output.
    DebugLog {
        lines: Vec<DebugLogLine>,
        /// The cursor to pass next time to resume after the last line.
        next_seq: u64,
        /// Whether lines the caller had not read were evicted from the
        /// bounded ring.
        dropped: bool,
    }

    /// A row of the backend's capability matrix.
    BackendCapability {
        /// Stable identifier (`memory_introspection`, ...).
        capability: &'static str,
        /// Human-readable name.
        label: &'static str,
        supported: bool,
    }
}

/// A page of captured guest debug output plus the cursor for the next poll.
pub fn debug_log(page: &DebugOutputPage) -> View {
    DebugLog {
        lines: page.lines.iter().map(debug_log_line).collect(),
        next_seq: page.next_seq,
        dropped: page.dropped,
    }
    .into_view()
}

/// One captured guest debug output line.
pub fn debug_log_line(line: &DebugLine) -> DebugLogLine {
    DebugLogLine {
        seq: line.seq,
        timestamp_ms: line.timestamp_ms,
        text: line.text.clone(),
    }
}

/// One row of a backend's capability matrix.
pub fn capability(capability: &dbg_backend::BackendCapability) -> BackendCapability {
    BackendCapability {
        capability: capability.capability.name(),
        label: capability.capability.label(),
        supported: capability.supported,
    }
}
