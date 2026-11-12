//! The B+ trees the kernel's store manager keys pages with, read from a
//! node's bytes. A node starts with its entry count (u16), level (u8), leaf
//! flag (u8), 4 bytes of padding and its leftmost child (u64). Leaf entries
//! are a u32 key and a u32 value; inner entries are a u32 key, 4 bytes of
//! padding and the u64 child that holds keys from that key on.

use super::{MemoryOps, PAGE_SIZE};
use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;

/// Bytes of a node's header.
pub const HEADER: usize = 16;

/// Levels a search follows before giving up on a tree.
const MAX_DEPTH: usize = 8;

/// Where a key leads from one node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The key's value, in this leaf.
    Value(u32),
    /// The child node to search next.
    Child(u64),
    /// This leaf does not hold the key.
    Missing,
}

/// A node's entry count, and whether it is a leaf, from its header.
fn header(node: &[u8]) -> (usize, bool) {
    (
        usize::from(u16::from_le_bytes([node[0], node[1]])),
        node[3] != 0,
    )
}

/// The bytes of a node with `count` entries.
fn node_size(count: usize, leaf: bool) -> usize {
    HEADER + count * if leaf { 8 } else { 16 }
}

/// The step for `key` from `node`, whose bytes hold its header and every
/// entry its count says.
pub fn step(node: &[u8], key: u32) -> Step {
    let (count, leaf) = header(node);
    let u32_at = |at: usize| u32::from_le_bytes(node[at..at + 4].try_into().expect("4 bytes"));
    let u64_at = |at: usize| u64::from_le_bytes(node[at..at + 8].try_into().expect("8 bytes"));
    if leaf {
        return (0..count)
            .map(|index| HEADER + index * 8)
            .find(|&at| u32_at(at) == key)
            .map_or(Step::Missing, |at| Step::Value(u32_at(at + 4)));
    }
    let child = (0..count)
        .map(|index| HEADER + index * 16)
        .take_while(|&at| u32_at(at) <= key)
        .last()
        .map_or_else(|| u64_at(8), |at| u64_at(at + 8));
    Step::Child(child)
}

/// The value of `key` in the tree whose root node is at `root`; `None`
/// when the tree does not hold the key. A node is at most a page.
pub fn search(memory: &impl MemoryOps<VirtAddr>, root: u64, key: u32) -> Result<Option<u32>> {
    let mut node = [0u8; PAGE_SIZE];
    let mut address = root;
    for _ in 0..MAX_DEPTH {
        memory.read_bytes(VirtAddr(address), &mut node[..HEADER])?;
        let (count, leaf) = header(&node);
        let size = node_size(count, leaf);
        if size > PAGE_SIZE {
            return Err(Error::DebugInfo(format!(
                "store tree node {address:#x}: {count} entries"
            )));
        }
        memory.read_bytes(VirtAddr(address + HEADER as u64), &mut node[HEADER..size])?;
        match step(&node[..size], key) {
            Step::Value(value) => return Ok(Some(value)),
            Step::Missing => return Ok(None),
            Step::Child(child) => address = child,
        }
    }
    Err(Error::DebugInfo(format!(
        "store tree at {root:#x} is deeper than {MAX_DEPTH} levels"
    )))
}

/// A node's bytes: a leaf of `(key, value)` entries, or an inner node with
/// leftmost child `left` and `(key, child)` entries.
#[cfg(test)]
pub fn node(leaf: bool, left: u64, entries: &[(u32, u64)]) -> Vec<u8> {
    let mut bytes = vec![0u8; HEADER];
    bytes[..2].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    bytes[3] = u8::from(leaf);
    bytes[8..16].copy_from_slice(&left.to_le_bytes());
    for (key, value) in entries {
        bytes.extend_from_slice(&key.to_le_bytes());
        if leaf {
            bytes.extend_from_slice(&(*value as u32).to_le_bytes());
        } else {
            bytes.extend_from_slice(&[0; 4]);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::memory::store::fixture::Bytes;

    #[test]
    fn a_leaf_gives_the_value_of_its_key_only() {
        let leaf = node(true, 0, &[(10, 100), (20, 200)]);
        assert_eq!(step(&leaf, 20), Step::Value(200));
        assert_eq!(step(&leaf, 15), Step::Missing);
    }

    #[test]
    fn an_inner_node_leads_to_the_child_that_covers_the_key() {
        let inner = node(false, 0xa000, &[(10, 0xb000), (20, 0xc000)]);
        assert_eq!(step(&inner, 5), Step::Child(0xa000));
        assert_eq!(step(&inner, 10), Step::Child(0xb000));
        assert_eq!(step(&inner, 19), Step::Child(0xb000));
        assert_eq!(step(&inner, 25), Step::Child(0xc000));
    }

    #[test]
    fn a_search_descends_to_the_leaf_and_stops_at_cycles() {
        let memory = Bytes::new(&[
            (0x1000, node(false, 0x2000, &[(50, 0x3000)])),
            (0x2000, node(true, 0, &[(7, 70)])),
            (0x3000, node(true, 0, &[(50, 500), (60, 600)])),
            // A node that leads back to itself.
            (0x4000, node(false, 0x4000, &[])),
        ]);
        assert_eq!(search(&memory, 0x1000, 7).unwrap(), Some(70));
        assert_eq!(search(&memory, 0x1000, 60).unwrap(), Some(600));
        assert_eq!(search(&memory, 0x1000, 8).unwrap(), None);
        assert!(search(&memory, 0x4000, 1).is_err());
    }

    /// A count past what a page holds is refused before anything is read
    /// past the header.
    #[test]
    fn a_node_larger_than_a_page_is_refused() {
        let mut inner = node(false, 0, &[]);
        inner[..2].copy_from_slice(&300u16.to_le_bytes());
        assert!(search(&Bytes::new(&[(0x1000, inner)]), 0x1000, 1).is_err());
    }
}
