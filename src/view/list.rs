//! How a guest linked-list walk ended, shared by every decoding that walks
//! one.

use super::shape::shapes;
use crate::target::ListTermination;
use crate::types::VirtAddr;

shapes! {
    /// How a guest linked-list walk ended.
    ListEnd {
        /// `head` (back at the list head), `null`, `cycle` (a loop not
        /// through the head), `bound` (the walk's limit), or `corrupt`.
        kind: &'static str,
        /// Where a cycle closed.
        address: Option<VirtAddr>,
        /// What was wrong, for a corrupt (or, in some walks, null) link.
        error: Option<String>,
    }
}

/// How a guest linked-list walk ended.
pub fn list_termination(termination: &ListTermination) -> ListEnd {
    let (kind, address, error) = match termination {
        ListTermination::Head => ("head", None, None),
        ListTermination::Null => ("null", None, None),
        ListTermination::Cycle(address) => ("cycle", Some(*address), None),
        ListTermination::Bound => ("bound", None, None),
        ListTermination::Corrupt(error) => ("corrupt", None, Some(error.clone())),
    };
    ListEnd {
        kind,
        address,
        error,
    }
}
