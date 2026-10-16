//! Where a process's VAD tree keeps its links, for every walk that reads it.

use crate::base::error::Result;
use crate::base::types::VirtAddr;
use crate::nt::layout::{TypeInfo, Types};

/// What [`VadTreeOffsets::resolve`] does with an offset the PDB lacks.
#[derive(Clone, Copy, Debug)]
pub enum MissingOffset {
    /// Fail with the PDB's error.
    Fail,
    /// Take the x64 layout's: `VadNode` and `Left` at 0, `Right` at 8.
    Default,
}

/// The offsets a VAD tree walk follows: the `_RTL_BALANCED_NODE` inside a
/// VAD (`VadNode`) and that node's children.
#[derive(Clone, Copy, Debug)]
pub struct VadTreeOffsets {
    pub vad_node: u64,
    pub left: u64,
    pub right: u64,
}

impl VadTreeOffsets {
    /// The offsets for VADs laid out as `vad` (`_MMVAD_SHORT` or `_MMVAD`).
    /// A PDB without `_RTL_BALANCED_NODE` fails whatever `missing` says.
    pub fn resolve(types: Types<'_>, vad: &TypeInfo, missing: MissingOffset) -> Result<Self> {
        let node = types.layout("_RTL_BALANCED_NODE")?;
        Ok(match missing {
            MissingOffset::Fail => Self {
                vad_node: vad.field_offset("VadNode")?,
                left: node.field_offset("Left")?,
                right: node.field_offset("Right")?,
            },
            MissingOffset::Default => Self {
                vad_node: vad_node_offset(vad),
                left: node.field_offset("Left").unwrap_or(0),
                right: node.field_offset("Right").unwrap_or(8),
            },
        })
    }
}

/// `VadNode`'s offset in `vad`; 0 when the PDB lacks it.
pub fn vad_node_offset(vad: &TypeInfo) -> u64 {
    vad.field_offset("VadNode").unwrap_or(0)
}

/// The node a raw tree link points at: the links keep balance bits in their
/// low four bits.
pub fn vad_tree_link(raw: u64) -> VirtAddr {
    VirtAddr(raw & !0xf)
}
