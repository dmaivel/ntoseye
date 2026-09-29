//! Debug-backend [`View`] builders: the capability matrix and
//! captured guest debug output.

use super::shape::shapes;
use crate::dbg_backend::{self, DebugLine, DebugOutputPage};

shapes! {
    /// A captured line of guest debug output (DbgPrint, kernel printf).
    DebugLogLine {
        /// A monotonic sequence number. It is the read cursor.
        seq: u64,
        /// The host wall-clock time when the line was complete, in milliseconds
        /// since the Unix epoch.
        timestamp_ms: u64,
        text: String,
    }

    /// A page of captured guest debug output.
    DebugLog {
        lines: Vec<DebugLogLine>,
        /// The cursor to give on the next call to continue after the last line.
        next_seq: u64,
        /// Whether the bounded ring removed lines that the caller did not read.
        dropped: bool,
    }

    /// A row of the capability matrix of the backend.
    BackendCapability {
        /// Stable identifier (`memory_introspection`, ...).
        capability: &'static str,
        /// Human-readable name.
        label: &'static str,
        supported: bool,
    }
}

/// A page of captured guest debug output plus the cursor for the next poll.
pub fn debug_log(page: &DebugOutputPage) -> DebugLog {
    DebugLog {
        lines: page.lines.iter().map(debug_log_line).collect(),
        next_seq: page.next_seq,
        dropped: page.dropped,
    }
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
