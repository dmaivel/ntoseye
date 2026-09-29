//! How a guest linked-list walk ended, shared by every decoding that walks
//! one.

use super::shape::shapes;
use crate::target::ListTermination;
use crate::types::VirtAddr;

shapes! {
    /// The end condition of a guest linked-list walk.
    ListEnd {
        /// `head` (the walk came back to the list head), `null`, `cycle` (a
        /// loop that does not go through the head), `bound` (the walk reached
        /// its limit), or `corrupt`.
        kind: &'static str,
        /// The address where a cycle closed.
        address: Option<VirtAddr>,
        /// The problem with a corrupt link. Some walks also set this for a null
        /// link.
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
