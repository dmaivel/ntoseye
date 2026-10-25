//! The B+ trees the kernel's store manager keys pages with, read from a
//! node's bytes. A node starts with its entry count (u16), level (u8), leaf
//! flag (u8), 4 bytes of padding and its leftmost child (u64). Leaf entries
//! are a u32 key and a u32 value; inner entries are a u32 key, 4 bytes of
//! padding and the u64 child that holds keys from that key on.

/// Bytes of a node's header.
pub const HEADER: usize = 16;

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

/// The step for `key` from the node in `node`, or `None` when the node's
/// bytes are too short for its entry count.
pub fn step(node: &[u8], key: u32) -> Option<Step> {
    let count = usize::from(u16::from_le_bytes(node.get(..2)?.try_into().ok()?));
    let leaf = *node.get(3)? != 0;
    let u32_at = |at: usize| Some(u32::from_le_bytes(node.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_le_bytes(node.get(at..at + 8)?.try_into().ok()?));
    if leaf {
        for index in 0..count {
            let at = HEADER + index * 8;
            if u32_at(at)? == key {
                return Some(Step::Value(u32_at(at + 4)?));
            }
        }
        return Some(Step::Missing);
    }
    let mut child = u64_at(8)?;
    for index in 0..count {
        let at = HEADER + index * 16;
        if u32_at(at)? > key {
            break;
        }
        child = u64_at(at + 8)?;
    }
    Some(Step::Child(child))
}

/// Levels a search follows before giving up on a tree.
const MAX_DEPTH: usize = 8;
/// The most entries a node holds: its 4 KiB filled with inner entries.
const MAX_ENTRIES: usize = (4096 - HEADER) / 8;

/// The value of `key` in the tree whose root node is at `root`, reading
/// nodes with `read`; `None` when the tree does not hold the key.
pub fn search(
    mut read: impl FnMut(u64, &mut [u8]) -> crate::base::error::Result<()>,
    root: u64,
    key: u32,
) -> crate::base::error::Result<Option<u32>> {
    use crate::base::error::Error;
    let mut address = root;
    for _ in 0..MAX_DEPTH {
        let mut header = [0u8; HEADER];
        read(address, &mut header)?;
        let count = usize::from(u16::from_le_bytes([header[0], header[1]]));
        if count > MAX_ENTRIES {
            return Err(Error::DebugInfo(format!(
                "store tree node {address:#x}: {count} entries"
            )));
        }
        let entry = if header[3] != 0 { 8 } else { 16 };
        let mut node = vec![0u8; HEADER + count * entry];
        read(address, &mut node)?;
        match step(&node, key) {
            Some(Step::Value(value)) => return Ok(Some(value)),
            Some(Step::Missing) => return Ok(None),
            Some(Step::Child(child)) => address = child,
            None => unreachable!("the node was read whole"),
        }
    }
    Err(Error::DebugInfo(format!(
        "store tree at {root:#x} is deeper than {MAX_DEPTH} levels"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(leaf: bool, left: u64, entries: &[(u32, u64)]) -> Vec<u8> {
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

    #[test]
    fn a_leaf_gives_the_value_of_its_key_only() {
        let leaf = node(true, 0, &[(10, 100), (20, 200)]);
        assert_eq!(step(&leaf, 20), Some(Step::Value(200)));
        assert_eq!(step(&leaf, 15), Some(Step::Missing));
    }

    #[test]
    fn an_inner_node_leads_to_the_child_that_covers_the_key() {
        let inner = node(false, 0xa000, &[(10, 0xb000), (20, 0xc000)]);
        assert_eq!(step(&inner, 5), Some(Step::Child(0xa000)));
        assert_eq!(step(&inner, 10), Some(Step::Child(0xb000)));
        assert_eq!(step(&inner, 19), Some(Step::Child(0xb000)));
        assert_eq!(step(&inner, 25), Some(Step::Child(0xc000)));
    }

    #[test]
    fn a_node_shorter_than_its_count_is_refused() {
        let mut leaf = node(true, 0, &[(10, 100)]);
        leaf[0] = 3;
        assert_eq!(step(&leaf, 99), None);
    }

    #[test]
    fn a_search_descends_to_the_leaf_and_stops_at_cycles() {
        let nodes: std::collections::HashMap<u64, Vec<u8>> = [
            (0x1000, node(false, 0x2000, &[(50, 0x3000)])),
            (0x2000, node(true, 0, &[(7, 70)])),
            (0x3000, node(true, 0, &[(50, 500), (60, 600)])),
            // A node that leads back to itself.
            (0x4000, node(false, 0x4000, &[])),
        ]
        .into();
        let read = |address: u64, out: &mut [u8]| {
            let bytes = &nodes[&address];
            out.copy_from_slice(&bytes[..out.len()]);
            Ok(())
        };
        assert_eq!(search(read, 0x1000, 7).unwrap(), Some(70));
        assert_eq!(search(read, 0x1000, 60).unwrap(), Some(600));
        assert_eq!(search(read, 0x1000, 8).unwrap(), None);
        assert!(search(read, 0x4000, 1).is_err());
    }
}
