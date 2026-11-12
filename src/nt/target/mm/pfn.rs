//! PFN database inspection: decoding one `_MMPFN` record for `!pfn`.

use std::collections::HashSet;

use super::{CacheAttribute, PageLocation, PfnDetail, PfnSelector, nested_type_name};
use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::types::VirtAddr;
use crate::nt::layout::TypeInfo;
use crate::nt::target::pool::{
    pool_field_from_buf, read_kernel_global_ptr, read_kernel_global_u64,
};
use crate::nt::target::{DiagnosticValue, Target};

impl Target {
    /// Decode an `_MMPFN` selected by PFN or physical address. Each member is
    /// found by name in the build's PDB layout, because the flags moved
    /// between builds (Windows Server 2003 packs `PageLocation` and
    /// `CacheAttribute` into a 16-bit `u3.e1` beside `PageColor`, later
    /// builds into a byte of their own), so a record whose layout lacks a
    /// member every build has is an error rather than a guess at its bits.
    /// Union-specific `flink`/`blink`/node links, `share_count`, `ws_index`, and
    /// `event` are absent when the record's page-location union does not select
    /// that view; `page_color` is unavailable on builds without one.
    pub fn inspect_pfn(&self, selector: PfnSelector) -> Result<PfnDetail> {
        let pfn = selector.pfn();
        if let Ok(highest) = read_kernel_global_u64(self, "MmHighestPhysicalPage")
            && pfn > highest
        {
            return Err(Error::DebugInfo(format!(
                "PFN {pfn:#x} exceeds MmHighestPhysicalPage {highest:#x}"
            )));
        }
        let database = read_kernel_global_ptr(self, "MmPfnDatabase")
            .map(|pointer| pointer.0)
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
        let leaf = |member: Option<&str>, field: &str| {
            scalar_from_pfn_member(self, &ti, &buf, member, field)
        };
        let required = |member: Option<&str>, field: &str| {
            leaf(member, field).ok_or_else(|| Error::FieldNotFound(format!("_MMPFN.{field}")))
        };
        let pte = pool_field_from_buf(&ti, &buf, "PteAddress")
            .ok_or_else(|| Error::FieldNotFound("_MMPFN.PteAddress".to_string()))?;
        let original_pte = pool_field_from_buf(&ti, &buf, "OriginalPte")
            .ok_or_else(|| Error::FieldNotFound("_MMPFN.OriginalPte".to_string()))?;
        let reference_count = required(Some("u3"), "ReferenceCount")?;
        let page_location = required(Some("u3"), "PageLocation")?;
        let modified = required(Some("u3"), "Modified")? != 0;
        let cache_attribute = required(Some("u3"), "CacheAttribute")?;
        // Priority is in u4 on Windows Server 2003 and in u3 on later builds.
        let priority = required(None, "Priority")?;
        let pte_frame = required(Some("u4"), "PteFrame")?;
        // Windows Server 2003 keeps the count in the record itself; later
        // builds keep it in the original PTE's software format.
        let used_entry_count = pool_field_from_buf(&ti, &buf, "UsedPageTableEntries")
            .map_or_else(|| required(Some("OriginalPte"), "UsedPageTableEntries"), Ok)?;
        let page_color = leaf(None, "PageColor");
        let active_page = page_location == 6;
        let transition_page = page_location == 7;
        let list_page = !active_page && !transition_page;
        let share_count = (active_page || transition_page)
            .then(|| leaf(Some("u2"), "ShareCount"))
            .flatten();
        let blink = list_page.then(|| leaf(Some("u2"), "Blink")).flatten();
        let node_blink_low = list_page
            .then(|| leaf(Some("u2"), "NodeBlinkLow"))
            .flatten();
        let flink = list_page.then(|| leaf(Some("u1"), "Flink")).flatten();
        let node_flink_low = list_page
            .then(|| leaf(Some("u1"), "NodeFlinkLow"))
            .flatten();
        let ws_index = active_page.then(|| leaf(Some("u1"), "WsIndex")).flatten();
        let event = transition_page.then(|| leaf(Some("u1"), "Event")).flatten();
        Ok(PfnDetail {
            selector,
            pfn,
            record,
            physical_address: selector.physical_address(),
            pte_address: VirtAddr(pte),
            original_pte,
            reference_count,
            flink,
            blink,
            node_flink_low,
            node_blink_low,
            share_count,
            ws_index,
            event,
            used_entry_count,
            page_color: page_color.map_or_else(
                || DiagnosticValue::unavailable("_MMPFN of this build has no PageColor"),
                DiagnosticValue::Available,
            ),
            pte_frame,
            page_location: PageLocation {
                value: page_location as u8,
            },
            modified,
            cache_attribute: CacheAttribute {
                value: cache_attribute as u8,
            },
            priority: priority as u8,
        })
    }
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

/// The leaf `field` of an `_MMPFN` in `buf`: looked for in `member` first,
/// where a name the record repeats elsewhere (`Flink` is also a page-table
/// link of the original PTE) must be read, or anywhere in the record.
fn scalar_from_pfn_member(
    target: &Target,
    pfn_ti: &TypeInfo,
    buf: &[u8],
    member: Option<&str>,
    field: &str,
) -> Option<u64> {
    if let Some(member_info) = member.and_then(|member| pfn_ti.fields.get(member)) {
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
