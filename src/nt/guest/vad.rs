//! Where a process's VAD tree keeps its links, for every walk that reads it.

use std::sync::Arc;

use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::nt::layout::{ParsedType, TypeInfo, Types};

/// Where in `_EPROCESS` the pointer to the root VAD is. `VadRoot` is an
/// `_RTL_AVL_TREE`, whose `Root` it is; before Windows 8.1 an
/// `_MM_AVL_TABLE`, whose `BalancedRoot` is a sentinel node (an
/// `_MMADDRESS_NODE` on Windows 7, an `_MM_AVL_NODE` on 8) with the root as
/// its right child.
pub fn vad_root_offset(types: Types<'_>, eprocess: &TypeInfo) -> Result<u64> {
    root_offset(&|name| types.layout(name), eprocess)
}

/// A struct's layout by its bare name.
type LayoutOf<'a> = &'a dyn Fn(&str) -> Result<Arc<TypeInfo>>;

fn root_offset(layout: LayoutOf<'_>, eprocess: &TypeInfo) -> Result<u64> {
    let field = eprocess.field("VadRoot")?;
    let at = u64::from(field.offset);
    match &field.type_data {
        ParsedType::Struct(name) if bare(name) == "_MM_AVL_TABLE" => {
            let table = layout("_MM_AVL_TABLE")?;
            let (root, node) = embedded_layout(layout, &table, "BalancedRoot")?;
            Ok(at + root + node.field_offset("RightChild")?)
        }
        ParsedType::Struct(name) => Ok(at + layout(bare(name))?.field_offset("Root")?),
        _ => Ok(at),
    }
}

/// A type name without the module it may be qualified with
/// (`nt!_MM_AVL_TABLE`).
fn bare(name: &str) -> &str {
    name.rsplit('!').next().unwrap_or(name)
}

/// The offset of struct field `name` in `layout`, and the field's own layout.
fn embedded_layout(
    layout_of: LayoutOf<'_>,
    layout: &TypeInfo,
    name: &str,
) -> Result<(u64, Arc<TypeInfo>)> {
    let field = layout.field(name)?;
    let ParsedType::Struct(type_name) = &field.type_data else {
        return Err(Error::FieldTypeMismatch(
            name.to_string(),
            "embedded struct".to_string(),
        ));
    };
    Ok((u64::from(field.offset), layout_of(bare(type_name))?))
}

/// What [`VadTreeOffsets::resolve`] does with an offset the PDB lacks.
#[derive(Clone, Copy, Debug)]
pub enum MissingOffset {
    /// Fail with the PDB's error.
    Fail,
    /// Take the x64 layout's: `VadNode` and `Left` at 0, `Right` at 8.
    Default,
}

/// The offsets a VAD tree walk follows: the tree node inside a VAD
/// (`VadNode`, or the VAD itself before Windows 8) and that node's children.
#[derive(Clone, Copy, Debug)]
pub struct VadTreeOffsets {
    pub vad_node: u64,
    pub left: u64,
    pub right: u64,
}

impl VadTreeOffsets {
    /// The offsets for VADs laid out as `vad` (`_MMVAD_SHORT` or `_MMVAD`).
    pub fn resolve(types: Types<'_>, vad: &TypeInfo, missing: MissingOffset) -> Result<Self> {
        Self::resolve_with(&|name| types.layout(name), vad, missing)
    }

    fn resolve_with(layout: LayoutOf<'_>, vad: &TypeInfo, missing: MissingOffset) -> Result<Self> {
        // Before Windows 8 a VAD is the tree's node itself.
        if let (Ok(left), Ok(right)) = (
            vad.field_offset("LeftChild"),
            vad.field_offset("RightChild"),
        ) {
            return Ok(Self {
                vad_node: 0,
                left,
                right,
            });
        }
        // From Windows 8 its node is `VadNode`: an `_MM_AVL_NODE` on 8
        // (`LeftChild`, `RightChild`), an `_RTL_BALANCED_NODE` from 8.1
        // (`Left`, `Right`).
        let resolved = embedded_layout(layout, vad, "VadNode").and_then(|(vad_node, node)| {
            let (left, right) = match (node.field_offset("Left"), node.field_offset("Right")) {
                (Ok(left), Ok(right)) => (left, right),
                _ => (
                    node.field_offset("LeftChild")?,
                    node.field_offset("RightChild")?,
                ),
            };
            Ok(Self {
                vad_node,
                left,
                right,
            })
        });
        match (resolved, missing) {
            (Ok(offsets), _) => Ok(offsets),
            (Err(error), MissingOffset::Fail) => Err(error),
            (Err(_), MissingOffset::Default) => Ok(Self {
                vad_node: vad_node_offset(vad),
                left: 0,
                right: 8,
            }),
        }
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::{MissingOffset, VadTreeOffsets, root_offset};
    use crate::base::error::{Error, Result};
    use crate::nt::layout::{FieldInfo, ParsedType, TypeInfo};

    fn layout(name: &str, fields: &[(&str, u32, Option<&str>)]) -> TypeInfo {
        TypeInfo {
            name: name.to_string(),
            size: 0,
            fields: fields
                .iter()
                .map(|(field, offset, embedded)| {
                    let type_data = match embedded {
                        Some(name) => ParsedType::Struct(name.to_string()),
                        None => ParsedType::Pointer(Box::new(ParsedType::Primitive("void".into()))),
                    };
                    (
                        field.to_string(),
                        FieldInfo {
                            offset: *offset,
                            size: 8,
                            type_data,
                        },
                    )
                })
                .collect(),
            pointer_size: 8,
        }
    }

    /// The root VAD's slot in `_EPROCESS` and the links of a VAD, on each
    /// of the three tree layouts, from the offsets of their PDBs: on
    /// Windows 8 both the table's sentinel and a VAD's `VadNode` are
    /// `_MM_AVL_NODE`s, whose children follow a parent word.
    #[test]
    fn vad_links_follow_each_releases_node_type() {
        let avl_table = |node: &str| {
            layout(
                "_MM_AVL_TABLE",
                &[("BalancedRoot", 0, Some(node)), ("NodeHint", 0x20, None)],
            )
        };
        let releases = [
            (
                "Windows 7",
                vec![
                    avl_table("_MMADDRESS_NODE"),
                    layout(
                        "_MMADDRESS_NODE",
                        &[("LeftChild", 8, None), ("RightChild", 0x10, None)],
                    ),
                ],
                ("nt!_MM_AVL_TABLE", 0x448),
                layout(
                    "_MMVAD_SHORT",
                    &[("LeftChild", 8, None), ("RightChild", 0x10, None)],
                ),
                (0x458, (0, 8, 0x10)),
            ),
            (
                "Windows 8",
                vec![
                    avl_table("_MM_AVL_NODE"),
                    layout(
                        "_MM_AVL_NODE",
                        &[("LeftChild", 8, None), ("RightChild", 0x10, None)],
                    ),
                ],
                ("_MM_AVL_TABLE", 0x590),
                layout(
                    "_MMVAD_SHORT",
                    &[
                        ("VadNode", 0, Some("_MM_AVL_NODE")),
                        ("StartingVpn", 0x18, None),
                    ],
                ),
                (0x5a0, (0, 8, 0x10)),
            ),
            (
                "Windows 8.1",
                vec![
                    layout("_RTL_AVL_TREE", &[("Root", 0, None)]),
                    layout(
                        "_RTL_BALANCED_NODE",
                        &[("Left", 0, None), ("Right", 8, None)],
                    ),
                ],
                ("_RTL_AVL_TREE", 0x5d8),
                layout(
                    "_MMVAD_SHORT",
                    &[
                        ("VadNode", 0, Some("_RTL_BALANCED_NODE")),
                        ("StartingVpn", 0x18, None),
                    ],
                ),
                (0x5d8, (0, 0, 8)),
            ),
        ];
        for (release, types, (root_type, root_at), vad, (root, links)) in releases {
            let types: HashMap<String, Arc<TypeInfo>> = types
                .into_iter()
                .map(|layout| (layout.name.clone(), Arc::new(layout)))
                .collect();
            let lookup = |name: &str| -> Result<Arc<TypeInfo>> {
                types
                    .get(name)
                    .cloned()
                    .ok_or_else(|| Error::StructNotFound(name.to_string()))
            };
            let eprocess = layout("_EPROCESS", &[("VadRoot", root_at, Some(root_type))]);
            assert_eq!(root_offset(&lookup, &eprocess).unwrap(), root, "{release}");
            let offsets = VadTreeOffsets::resolve_with(&lookup, &vad, MissingOffset::Fail).unwrap();
            assert_eq!(
                (offsets.vad_node, offsets.left, offsets.right),
                links,
                "{release}"
            );
        }
    }
}
