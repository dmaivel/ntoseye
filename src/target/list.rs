//! Bounded, cycle-stopping walks of intrusive guest lists: the cursor the
//! typed walkers drive, and the untyped walks built on it.

use std::collections::HashSet;
use std::result;

use super::Target;
use crate::{backend::MemoryOps, error::Result, types::VirtAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListTermination {
    Head,
    Null,
    Cycle(VirtAddr),
    Bound,
    Corrupt(String),
}

impl ListTermination {
    pub fn diagnostic(&self) -> Option<String> {
        match self {
            Self::Head => None,
            Self::Null => Some("null link".to_string()),
            Self::Cycle(address) => Some(format!("non-head cycle at {:#x}", address.0)),
            Self::Bound => Some("entry bound reached".to_string()),
            Self::Corrupt(error) => Some(format!("unreadable link: {error}")),
        }
    }
}

/// Termination state for walking an intrusive list: bounded, stopping at the
/// head, a null link, or the first link seen twice. The caller supplies each
/// link read after consuming the current entry, so a typed walk can take the
/// next link from the record image it already prefetched.
pub struct ListCursor {
    head: VirtAddr,
    limit: usize,
    current: Option<VirtAddr>,
    visited: HashSet<u64>,
    yielded: usize,
    first_entry: bool,
    termination: Option<ListTermination>,
}

impl ListCursor {
    pub fn new(head: VirtAddr, limit: usize) -> Self {
        Self {
            head,
            limit,
            current: None,
            visited: HashSet::with_capacity(16),
            yielded: 0,
            first_entry: false,
            termination: None,
        }
    }

    /// Construct a cursor over a ring whose first element is `first` itself,
    /// rather than the link stored at a head. The walk ends when it returns
    /// to `first`; commands that treat their address argument as element one
    /// (`dt -l`, `!list`, `dl`) use this.
    pub fn from_first(first: VirtAddr, limit: usize) -> Self {
        Self {
            head: first,
            limit,
            current: Some(first),
            visited: HashSet::with_capacity(16),
            yielded: 0,
            first_entry: true,
            termination: None,
        }
    }

    pub fn take_current(&mut self) -> Option<VirtAddr> {
        if self.termination.is_some() {
            return None;
        }
        let current = self.current.take()?;
        if !self.first_entry && current == self.head {
            self.termination = Some(ListTermination::Head);
            return None;
        }
        if current.is_zero() {
            self.termination = Some(ListTermination::Null);
            return None;
        }
        if !self.visited.insert(current.0) {
            self.termination = Some(ListTermination::Cycle(current));
            return None;
        }
        if self.yielded >= self.limit {
            self.termination = Some(ListTermination::Bound);
            return None;
        }
        self.first_entry = false;
        self.yielded += 1;
        Some(current)
    }

    pub fn advance(&mut self, next: result::Result<VirtAddr, String>) {
        if self.termination.is_some() {
            return;
        }
        self.current = match next {
            Ok(next) => Some(next),
            Err(error) => {
                self.termination = Some(ListTermination::Corrupt(error));
                None
            }
        };
    }

    /// The termination reached; the walk must have been driven to `take_current()`
    /// returning `None`.
    pub fn finish(self) -> ListTermination {
        self.termination
            .expect("ListCursor::finish called before take_current() returned None")
    }
}

pub fn bounded_list_walk<F>(
    head: VirtAddr,
    limit: usize,
    mut read_next: F,
) -> (Vec<VirtAddr>, ListTermination)
where
    F: FnMut(VirtAddr) -> Result<VirtAddr>,
{
    let mut links = Vec::new();
    let mut cursor = ListCursor::new(head, limit);
    cursor.advance(read_next(head).map_err(|error| error.to_string()));
    while let Some(current) = cursor.take_current() {
        links.push(current);
        cursor.advance(read_next(current).map_err(|error| error.to_string()));
    }
    (links, cursor.finish())
}

impl Target {
    /// Walk an intrusive `_LIST_ENTRY` from `head` (the list-head address) in
    /// the current address space, returning each record's base
    /// (`link_addr - link_offset`). Bounded (max 1000) and cycle-stopping,
    /// mirroring the engine's `Types::list_at`; a bad link truncates the walk
    /// rather than discarding the records already collected. Shared by the SDK
    /// and MCP list walking; the typed cursor walk (`StructRef::list`) is the
    /// richer form.
    pub fn walk_list(&self, head: VirtAddr, link_offset: u64) -> Result<Vec<u64>> {
        const MAX: usize = 1000;
        let mem = self.context_memory();
        let mut cursor = ListCursor::new(head, MAX);
        cursor.advance(Ok(mem.read::<VirtAddr>(head)?));
        let mut out = Vec::new();
        while let Some(current) = cursor.take_current() {
            out.push(current.0.wrapping_sub(link_offset));
            cursor.advance(
                mem.read::<VirtAddr>(current)
                    .map_err(|error| error.to_string()),
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::{ListTermination, bounded_list_walk};
    use crate::error::Error;
    use crate::types::VirtAddr;

    #[test]
    fn diagnostic_list_walk_honors_bound() {
        let (links, termination) =
            bounded_list_walk(VirtAddr(0), 2, |address| Ok(VirtAddr(address.0 + 1)));
        assert_eq!(links, vec![VirtAddr(1), VirtAddr(2)]);
        assert_eq!(termination, ListTermination::Bound);
    }

    #[test]
    fn diagnostic_list_walk_flags_non_head_cycle() {
        let (links, termination) = bounded_list_walk(VirtAddr(0), 8, |address| {
            Ok(match address.0 {
                0 => VirtAddr(1),
                1 => VirtAddr(2),
                _ => VirtAddr(1),
            })
        });
        assert_eq!(links, vec![VirtAddr(1), VirtAddr(2)]);
        assert_eq!(termination, ListTermination::Cycle(VirtAddr(1)));
    }

    #[test]
    fn diagnostic_list_walk_preserves_corrupt_read_error() {
        let (links, termination) = bounded_list_walk(VirtAddr(0), 8, |address| match address.0 {
            0 => Ok(VirtAddr(1)),
            1 => Ok(VirtAddr(2)),
            _ => Err(Error::DebugInfo("synthetic bad flink".into())),
        });
        assert_eq!(links, vec![VirtAddr(1), VirtAddr(2)]);
        assert_eq!(
            termination,
            ListTermination::Corrupt("synthetic bad flink".into())
        );
    }
}
