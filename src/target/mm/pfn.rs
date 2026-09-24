//! PFN database inspection: decoding one `_MMPFN` record for `!pfn`.

use std::collections::HashSet;

use super::{PfnDetail, PfnSelector, diagnostic_unavailable, nested_type_name};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{TypeInfo, le_uint};
use crate::memory::PAGE_SIZE;
use crate::target::pool::{pool_field_from_buf, read_kernel_global_u64};
use crate::target::{DiagnosticValue, Target};
use crate::types::VirtAddr;

const MMPFN_U1_OFFSET: usize = 0;
const MMPFN_PTE_ADDRESS_OFFSET: usize = 8;
const MMPFN_ORIGINAL_PTE_OFFSET: usize = 16;
const MMPFN_U2_OFFSET: usize = 24;
const MMPFN_U3_OFFSET: usize = 32;
const MMPFN_U4_OFFSET: usize = 40;
const MMPFNENTRY1_FLAGS_OFFSET: usize = 2;
const MMPFNENTRY3_FLAGS_OFFSET: usize = 3;
const MMPTE_SOFTWARE_OFFSET: usize = 0;

impl Target {
    /// Decode an `_MMPFN` selected by PFN or physical address. The record and PFN
    /// database metadata are required; `pte_address`, `original_pte`, the derived
    /// `used_entry_count`/`page_color`/`pte_frame`, and flag fields carry an
    /// unavailable reason when their PDB leaf or fallback bytes cannot be decoded.
    /// Union-specific `flink`/`blink`/node links, `share_count`, `ws_index`, and
    /// `event` are absent when the record's page-location union does not select
    /// that view.
    pub fn inspect_pfn(&self, selector: PfnSelector) -> Result<PfnDetail> {
        let pfn = selector.pfn();
        if let Ok(highest) = read_kernel_global_u64(self, "MmHighestPhysicalPage")
            && pfn > highest
        {
            return Err(Error::DebugInfo(format!(
                "PFN {pfn:#x} exceeds MmHighestPhysicalPage {highest:#x}"
            )));
        }
        let database = read_kernel_global_u64(self, "MmPfnDatabase")
            .map_err(|error| Error::DebugInfo(format!("PFN database: {error}")))?;
        if database == 0 {
            return Err(Error::DebugInfo(
                "PFN database: null MmPfnDatabase".to_string(),
            ));
        }
        let ti = self
            .symbols
            .find_type_across_modules(self.kernel_dtb(), "_MMPFN")
            .ok_or_else(|| Error::StructNotFound("_MMPFN".to_string()))?;
        let record_size = u64::try_from(ti.size).unwrap_or(0);
        if record_size == 0 || ti.size > PAGE_SIZE {
            return Err(Error::DebugInfo(format!(
                "_MMPFN size {record_size:#x} is invalid"
            )));
        }
        let offset = pfn
            .checked_mul(record_size)
            .ok_or_else(|| Error::DebugInfo("PFN record address overflow".to_string()))?;
        let record = VirtAddr(database.checked_add(offset).ok_or_else(|| {
            Error::DebugInfo("PFN record address overflows the PFN database".to_string())
        })?);
        let memory = self.kernel_address_space();
        let mut buf = vec![0u8; ti.size];
        memory.read_bytes(record, &mut buf)?;
        let pte = pool_field_from_buf(&ti, &buf, "PteAddress")
            .or_else(|| pool_field_from_buf(&ti, &buf, "PteLong"))
            .or_else(|| {
                Some(member_raw(
                    &ti,
                    &buf,
                    "PteAddress",
                    MMPFN_PTE_ADDRESS_OFFSET,
                ))
            });
        let original_pte = pool_field_from_buf(&ti, &buf, "OriginalPte").or_else(|| {
            Some(member_raw(
                &ti,
                &buf,
                "OriginalPte",
                MMPFN_ORIGINAL_PTE_OFFSET,
            ))
        });
        let u1_raw = member_raw(&ti, &buf, "u1", MMPFN_U1_OFFSET);
        let u2_raw = member_raw(&ti, &buf, "u2", MMPFN_U2_OFFSET);
        let u3_raw = member_raw(&ti, &buf, "u3", MMPFN_U3_OFFSET);
        let u4_raw = member_raw(&ti, &buf, "u4", MMPFN_U4_OFFSET);
        let e1_raw = (u3_raw >> 16) as u8;
        let e3_raw = (u3_raw >> 24) as u8;
        let reference_count = scalar_from_pfn_member(self, &ti, &buf, "u3", "ReferenceCount")
            .or_else(|| pool_field_from_buf(&ti, &buf, "ReferenceCount"))
            .unwrap_or(u3_raw & 0xffff);
        let page_location = pool_field_from_buf(&ti, &buf, "PageLocation")
            .or_else(|| {
                scalar_from_named_type(
                    self,
                    "_MMPFNENTRY1",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY1_FLAGS_OFFSET,
                    "PageLocation",
                )
            })
            .unwrap_or(u64::from(e1_raw & 0x7));
        let modified = pool_field_from_buf(&ti, &buf, "Modified")
            .or_else(|| {
                scalar_from_named_type(
                    self,
                    "_MMPFNENTRY1",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY1_FLAGS_OFFSET,
                    "Modified",
                )
            })
            .map(|value| value != 0)
            .unwrap_or(e1_raw & 0x10 != 0);
        let cache_attribute = pool_field_from_buf(&ti, &buf, "CacheAttribute")
            .or_else(|| {
                scalar_from_named_type(
                    self,
                    "_MMPFNENTRY1",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY1_FLAGS_OFFSET,
                    "CacheAttribute",
                )
            })
            .unwrap_or(u64::from((e1_raw >> 6) & 0x3));
        let priority = pool_field_from_buf(&ti, &buf, "Priority")
            .or_else(|| {
                scalar_from_named_type(
                    self,
                    "_MMPFNENTRY3",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY3_FLAGS_OFFSET,
                    "Priority",
                )
            })
            .unwrap_or(u64::from(e3_raw & 0x7));
        let active_page = page_location == 6;
        let transition_page = page_location == 7;
        let list_page = !active_page && !transition_page;
        let share_count = if active_page || transition_page {
            scalar_from_pfn_member(self, &ti, &buf, "u2", "ShareCount")
                .or_else(|| pool_field_from_buf(&ti, &buf, "ShareCount"))
                .or(Some(u2_raw & ((1u64 << 62) - 1)))
        } else {
            None
        };
        let blink = if list_page {
            scalar_from_pfn_member(self, &ti, &buf, "u2", "Blink")
                .or(Some(u2_raw & ((1u64 << 40) - 1)))
        } else {
            None
        };
        let node_blink_low = if list_page {
            scalar_from_pfn_member(self, &ti, &buf, "u2", "NodeBlinkLow")
                .or(Some((u2_raw >> 40) & ((1u64 << 19) - 1)))
        } else {
            None
        };
        let flink = if list_page {
            scalar_from_pfn_member(self, &ti, &buf, "u1", "Flink")
                .or(Some(u1_raw & ((1u64 << 40) - 1)))
        } else {
            None
        };
        let node_flink_low = if list_page {
            scalar_from_pfn_member(self, &ti, &buf, "u1", "NodeFlinkLow")
        } else {
            None
        };
        let ws_index = if active_page {
            scalar_from_pfn_member(self, &ti, &buf, "u1", "WsIndex")
        } else {
            None
        };
        let event = if transition_page {
            scalar_from_pfn_member(self, &ti, &buf, "u1", "Event")
        } else {
            None
        };
        let pte_frame = scalar_from_pfn_member(self, &ti, &buf, "u4", "PteFrame")
            .or(Some(u4_raw & ((1u64 << 40) - 1)));
        let page_color = scalar_from_pfn_member(self, &ti, &buf, "u4", "PageColor").or_else(|| {
            scalar_from_named_type(
                self,
                "_MMPFNENTRY1",
                &u3_raw.to_le_bytes(),
                MMPFNENTRY1_FLAGS_OFFSET,
                "PageColor",
            )
        });
        let used_entry_count = original_pte
            .and_then(|value| {
                scalar_from_named_type(
                    self,
                    "_MMPTE_SOFTWARE",
                    &value.to_le_bytes(),
                    MMPTE_SOFTWARE_OFFSET,
                    "UsedPageTableEntries",
                )
            })
            .or_else(|| {
                scalar_from_pfn_member(self, &ti, &buf, "OriginalPte", "UsedPageTableEntries")
            })
            .or_else(|| original_pte.map(|value| (value >> 12) & 0x3ff));
        Ok(PfnDetail {
            selector,
            pfn,
            record,
            physical_address: selector.physical_address(),
            pte_address: pte.map_or_else(
                || diagnostic_unavailable("PteAddress"),
                |value| DiagnosticValue::Available(VirtAddr(value)),
            ),
            original_pte: original_pte.map_or_else(
                || diagnostic_unavailable("OriginalPte"),
                DiagnosticValue::Available,
            ),
            reference_count: DiagnosticValue::Available(reference_count),
            flink: flink.map(DiagnosticValue::Available),
            blink: blink.map(DiagnosticValue::Available),
            node_flink_low: node_flink_low.map(DiagnosticValue::Available),
            node_blink_low: node_blink_low.map(DiagnosticValue::Available),
            share_count: share_count.map(DiagnosticValue::Available),
            ws_index: ws_index.map(DiagnosticValue::Available),
            event: event.map(DiagnosticValue::Available),
            used_entry_count: used_entry_count.map_or_else(
                || diagnostic_unavailable("UsedPageTableEntries"),
                DiagnosticValue::Available,
            ),
            page_color: page_color.map_or_else(
                || diagnostic_unavailable("PageColor"),
                DiagnosticValue::Available,
            ),
            pte_frame: pte_frame.map_or_else(
                || diagnostic_unavailable("PteFrame"),
                DiagnosticValue::Available,
            ),
            page_location: DiagnosticValue::Available(page_location as u8),
            modified: DiagnosticValue::Available(modified),
            cache_attribute: DiagnosticValue::Available(cache_attribute as u8),
            priority: DiagnosticValue::Available(priority as u8),
        })
    }
}

fn member_raw(ti: &TypeInfo, buf: &[u8], member: &str, fallback_offset: usize) -> u64 {
    let (offset, size) = ti
        .fields
        .get(member)
        .map(|field| {
            (
                field.offset as usize,
                usize::try_from(field.size)
                    .ok()
                    .filter(|size| *size != 0)
                    .unwrap_or(8)
                    .clamp(1, 8),
            )
        })
        .unwrap_or((fallback_offset, 8));
    buf.get(offset..offset.saturating_add(size))
        .map(le_uint)
        .unwrap_or(0)
}

fn scalar_from_type_tree(
    target: &Target,
    ti: &TypeInfo,
    buf: &[u8],
    base: usize,
    field: &str,
    depth: usize,
    visited: &mut HashSet<String>,
) -> Option<u64> {
    if depth > 5 {
        return None;
    }
    let slice = buf.get(base..)?;
    if let Some(value) = pool_field_from_buf(ti, slice, field) {
        return Some(value);
    }
    let mut nested = ti
        .fields
        .iter()
        .filter_map(|(name, info)| {
            nested_type_name(&info.type_data).map(|nested| (name, info, nested))
        })
        .collect::<Vec<_>>();
    nested.sort_by_key(|(_, info, _)| info.offset);
    for (_, info, nested_name) in nested {
        let nested_base = base.checked_add(info.offset as usize)?;
        let key = format!("{nested_base}:{nested_name}:{field}");
        if !visited.insert(key) {
            continue;
        }
        let Some(nested_ti) = target
            .symbols
            .find_type_across_modules(target.kernel_dtb(), nested_name)
        else {
            continue;
        };
        if let Some(value) = scalar_from_type_tree(
            target,
            &nested_ti,
            buf,
            nested_base,
            field,
            depth + 1,
            visited,
        ) {
            return Some(value);
        }
    }
    None
}

fn scalar_from_pfn_member(
    target: &Target,
    pfn_ti: &TypeInfo,
    buf: &[u8],
    member: &str,
    field: &str,
) -> Option<u64> {
    if let Some(member_info) = pfn_ti.fields.get(member) {
        if let Some(nested_name) = nested_type_name(&member_info.type_data)
            && let Some(nested_ti) = target
                .symbols
                .find_type_across_modules(target.kernel_dtb(), nested_name)
        {
            let mut visited = HashSet::new();
            if let Some(value) = scalar_from_type_tree(
                target,
                &nested_ti,
                buf,
                member_info.offset as usize,
                field,
                0,
                &mut visited,
            ) {
                return Some(value);
            }
        }
        return pool_field_from_buf(pfn_ti, buf, field);
    }
    let mut visited = HashSet::new();
    scalar_from_type_tree(target, pfn_ti, buf, 0, field, 0, &mut visited)
}

fn scalar_from_named_type(
    target: &Target,
    name: &str,
    buf: &[u8],
    offset: usize,
    field: &str,
) -> Option<u64> {
    let ti = target
        .symbols
        .find_type_across_modules(target.kernel_dtb(), name)?;
    let mut visited = HashSet::new();
    scalar_from_type_tree(target, &ti, buf, offset, field, 0, &mut visited)
}
