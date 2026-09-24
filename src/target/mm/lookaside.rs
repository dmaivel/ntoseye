//! `_GENERAL_LOOKASIDE` inspection: single records and the exported
//! nonpaged and paged lookaside-list roots.

use std::collections::HashSet;

use super::{LookasideDetail, LookasideListsDetail, diagnostic_unavailable};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::TypeInfo;
use crate::target::pool::{kernel_symbol_address, read_pool_field};
use crate::target::{DiagnosticValue, Target};
use crate::types::VirtAddr;

const MAX_LOOKASIDE_ENTRIES: usize = 256;

impl Target {
    /// Decode one `_GENERAL_LOOKASIDE` record. `tag`, `size`, `depth`,
    /// `total_allocates`, `total_frees`, and `allocate_misses` each retain the
    /// exact missing-layout/read reason instead of failing the whole record.
    pub fn inspect_lookaside(&self, address: VirtAddr) -> Result<LookasideDetail> {
        let ti = self
            .symbols
            .find_type_across_modules(self.kernel_dtb(), "_GENERAL_LOOKASIDE")
            .ok_or_else(|| Error::StructNotFound("_GENERAL_LOOKASIDE".to_string()))?;
        let memory = self.kernel_address_space();
        let field = |name: &str| match read_pool_field(&ti, &memory, address, name) {
            Some(value) => DiagnosticValue::Available(value),
            None => diagnostic_unavailable(format!("{name} unavailable")),
        };
        let tag = match field("Tag") {
            DiagnosticValue::Available(value) => DiagnosticValue::Available(value as u32),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error),
        };
        Ok(LookasideDetail {
            address,
            index: 0,
            tag,
            size: field("Size"),
            depth: field("Depth"),
            total_allocates: field("TotalAllocates"),
            total_frees: field("TotalFrees"),
            allocate_misses: field("AllocateMisses"),
        })
    }

    /// Walk the exported nonpaged and paged `_GENERAL_LOOKASIDE` roots with
    /// cycle/bound termination recorded in the returned detail.
    pub fn lookaside_lists(&self) -> Result<LookasideListsDetail> {
        let ti = self
            .symbols
            .find_type_across_modules(self.kernel_dtb(), "_GENERAL_LOOKASIDE")
            .ok_or_else(|| Error::StructNotFound("_GENERAL_LOOKASIDE".to_string()))?;
        let mut seen = HashSet::new();
        let (nonpaged, nonpaged_termination) = self.walk_lookaside_root(
            "ExNPagedLookasideListHead",
            &ti,
            0,
            MAX_LOOKASIDE_ENTRIES,
            &mut seen,
        );
        let nonpaged_count = nonpaged.len();
        let (paged, paged_termination) = self.walk_lookaside_root(
            "ExPagedLookasideListHead",
            &ti,
            nonpaged_count,
            MAX_LOOKASIDE_ENTRIES.saturating_sub(nonpaged_count),
            &mut seen,
        );
        let mut records = nonpaged;
        records.extend(paged);
        let interrupted = self.interrupted();
        let truncated = records.len() >= MAX_LOOKASIDE_ENTRIES;
        Ok(LookasideListsDetail {
            nonpaged_count,
            paged_count: records.len().saturating_sub(nonpaged_count),
            records,
            nonpaged_termination,
            paged_termination,
            interrupted,
            truncated,
        })
    }

    fn walk_lookaside_root(
        &self,
        symbol: &str,
        ti: &TypeInfo,
        start_index: usize,
        limit: usize,
        seen: &mut HashSet<u64>,
    ) -> (Vec<LookasideDetail>, String) {
        let Ok(symbol_address) = kernel_symbol_address(self, symbol) else {
            return (Vec::new(), format!("{symbol} unavailable"));
        };
        let memory = self.kernel_address_space();
        let Ok(first_link) = memory.read::<VirtAddr>(symbol_address) else {
            return (Vec::new(), format!("{symbol} unreadable"));
        };
        let Some(link_offset) = ti.fields.get("ListEntry").map(|field| field.offset as u64) else {
            return (Vec::new(), "ListEntry field unavailable".to_string());
        };
        let mut records = Vec::new();
        let mut current_link = first_link;
        let mut termination = "null link".to_string();
        while records.len() < limit && !current_link.is_zero() && !self.interrupted() {
            if current_link == symbol_address {
                termination = "head".to_string();
                break;
            }
            let Some(record_address) = current_link.0.checked_sub(link_offset).map(VirtAddr) else {
                termination = "corrupt link".to_string();
                break;
            };
            if !seen.insert(record_address.0) {
                termination = format!("cycle at {:#x}", record_address.0);
                break;
            }
            if read_pool_field(ti, &memory, record_address, "Size").is_none() {
                termination = "unreadable record".to_string();
                break;
            }
            let mut detail = match self.inspect_lookaside(record_address) {
                Ok(detail) => detail,
                Err(error) => {
                    termination = format!("unreadable record: {error}");
                    break;
                }
            };
            detail.index = start_index + records.len();
            records.push(detail);
            let Ok(next) = memory.read::<VirtAddr>(current_link) else {
                termination = "unreadable link".to_string();
                break;
            };
            current_link = next;
        }
        if records.len() >= MAX_LOOKASIDE_ENTRIES {
            termination = "bound".to_string();
        } else if self.interrupted() {
            termination = "interrupted".to_string();
        }
        (records, termination)
    }
}
