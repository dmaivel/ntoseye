//! Structured memory-manager inspectors shared by the REPL, Python SDK, and MCP.

use std::collections::HashSet;
use std::fmt;

use crate::backend::MemoryOps;
use crate::debugger_data::{
    DebuggerDataBlock, MetadataSource, MetadataValue, read_counter_from_getter,
};
use crate::error::{Error, Result};
use crate::guest::{ModuleInfo, section_name_at};
use crate::memory::{DTB_IDENTITY, PAGE_SIZE, PFN_MASK};
use crate::symbols::{ParsedType, TypeInfo, format_symbol_with_offset, glob_matches, le_uint};
use crate::target::pool::{
    BigPoolEntry, PoolHeader, PoolUsageRow, big_pool_layout, classify_pool_region,
    collect_pool_usage, find_big_pool, kernel_symbol_address, locate_pool_block_in_page,
    pool_block_state, pool_field_from_buf, pool_layout, read_kernel_global_u64, read_pool_field,
    scan_big_pool_entries, scan_pool_page_lax, tag_string,
};
use crate::types::{Arch, Dtb, PageTableEntry, Value, VirtAddr};

use super::{DiagnosticMetric, DiagnosticValue, Target};
use crate::guest::ProcessInfo;

const DEFAULT_MEMORY_PROCESS_LIMIT: usize = 64;
const MAX_MI_FIELDS: usize = 64;
const MAX_MI_STATE_FIELDS: usize = 16;
const MAX_LOOKASIDE_ENTRIES: usize = 256;
const MAX_POOLFIND_PAGES: u64 = 16 * 1024;
const MAX_POOLFIND_RESULTS: usize = 1024;
const MAX_POOLUSED_ROWS: usize = 256;
const MAX_PTOV_TABLE_PAGES: usize = 65_536;
const MAX_PTOV_RESULTS: usize = 32;
const LARGE_PAGE_1G: u64 = 1 << 30;
const LARGE_PAGE_2M: u64 = 1 << 21;
const MMPFN_U1_OFFSET: usize = 0;
const MMPFN_PTE_ADDRESS_OFFSET: usize = 8;
const MMPFN_ORIGINAL_PTE_OFFSET: usize = 16;
const MMPFN_U2_OFFSET: usize = 24;
const MMPFN_U3_OFFSET: usize = 32;
const MMPFN_U4_OFFSET: usize = 40;
const MMPFNENTRY1_FLAGS_OFFSET: usize = 2;
const MMPFNENTRY3_FLAGS_OFFSET: usize = 3;
const MMPTE_SOFTWARE_OFFSET: usize = 0;

/// A system-wide or page-file counter shown by `!vm`.
#[derive(Debug, Clone)]
pub struct VmCounter {
    pub name: String,
    pub value: DiagnosticMetric<u64>,
    pub unit: &'static str,
}

/// Pool counters and symbol-backed pool fields shown by `!vm`.
#[derive(Debug, Clone)]
pub struct VmPoolDetail {
    pub nonpaged_pool_bytes: DiagnosticMetric<u64>,
    pub nonpaged_pool_maximum: DiagnosticMetric<u64>,
    pub paged_pool_pages: DiagnosticMetric<u64>,
    pub fields: Vec<VmCounter>,
}

/// System PTE counters shown by `!vm`.
#[derive(Debug, Clone)]
pub struct VmPteDetail {
    pub counters: Vec<VmCounter>,
}

/// Paging-file counters shown by `!vm`.
#[derive(Debug, Clone)]
pub struct VmPageFileDetail {
    pub counters: Vec<VmCounter>,
}

/// Complete bounded `!vm` result. `system` retains the existing memory summary,
/// while pool/PTE/page-file counters carry their individual source and failure.
#[derive(Debug, Clone)]
pub struct VmDetail {
    pub system: SystemMemorySummary,
    pub pool: VmPoolDetail,
    pub pte: VmPteDetail,
    pub page_files: VmPageFileDetail,
    pub include_processes: bool,
}

/// `!pfn` input selector. A physical-address selector is shifted by the page
/// size before indexing the PFN database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfnSelector {
    Pfn(u64),
    PhysicalAddress(u64),
}

impl PfnSelector {
    pub fn pfn(self) -> u64 {
        match self {
            Self::Pfn(value) => value,
            Self::PhysicalAddress(value) => value / PAGE_SIZE as u64,
        }
    }

    pub fn physical_address(self) -> Option<u64> {
        match self {
            Self::Pfn(_) => None,
            Self::PhysicalAddress(value) => Some(value),
        }
    }
}

/// A decoded `_MMPFN` record. Fields represented by `DiagnosticValue` retain a
/// precise unavailable reason when a layout member or record read is missing.
#[derive(Debug, Clone)]
pub struct PfnDetail {
    pub selector: PfnSelector,
    pub pfn: u64,
    pub record: VirtAddr,
    pub physical_address: Option<u64>,
    pub pte_address: DiagnosticValue<VirtAddr>,
    pub original_pte: DiagnosticValue<u64>,
    pub reference_count: DiagnosticValue<u64>,
    pub flink: Option<DiagnosticValue<u64>>,
    pub blink: Option<DiagnosticValue<u64>>,
    pub node_flink_low: Option<DiagnosticValue<u64>>,
    pub node_blink_low: Option<DiagnosticValue<u64>>,
    pub share_count: Option<DiagnosticValue<u64>>,
    pub ws_index: Option<DiagnosticValue<u64>>,
    pub event: Option<DiagnosticValue<u64>>,
    pub used_entry_count: DiagnosticValue<u64>,
    pub page_color: DiagnosticValue<u64>,
    pub pte_frame: DiagnosticValue<u64>,
    pub page_location: DiagnosticValue<u8>,
    pub modified: DiagnosticValue<bool>,
    pub cache_attribute: DiagnosticValue<u8>,
    pub priority: DiagnosticValue<u8>,
}

/// One page-table level reached by [`Target::vtop`].
#[derive(Debug, Clone)]
pub struct VtopLevel {
    pub name: String,
    pub address: VirtAddr,
    pub value: u64,
}

/// Explicit page-table translation, including every readable level and the
/// final physical address (when present).
#[derive(Debug, Clone)]
pub struct VtopDetail {
    pub address: VirtAddr,
    pub dtb: Dtb,
    pub levels: Vec<VtopLevel>,
    pub physical: Option<u64>,
    pub large: bool,
    /// The leaf was a transition PTE: `physical` is a real frame the guest
    /// still holds, but nothing maps it here and it cannot be written.
    pub transition: bool,
}

/// One reverse page-table mapping found by `!ptov`.
#[derive(Debug, Clone)]
pub struct PtovMapping {
    pub virtual_address: VirtAddr,
    pub large: bool,
}

/// Bounded reverse page-table walk result.
#[derive(Debug, Clone)]
pub struct PtovDetail {
    pub physical: u64,
    pub dtb: Dtb,
    pub mappings: Vec<PtovMapping>,
    pub table_pages: usize,
    pub bounded: bool,
    pub interrupted: bool,
}

/// Classification used by `!poolfind` and pool-page results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    NonPaged,
    Paged,
}

impl PoolType {
    pub fn name(self) -> &'static str {
        match self {
            Self::NonPaged => "NonPagedPool",
            Self::Paged => "PagedPool",
        }
    }

    fn kind(self) -> u64 {
        match self {
            Self::NonPaged => 0,
            Self::Paged => 1,
        }
    }
}

/// A normal `_POOL_HEADER` block in a page.
#[derive(Debug, Clone)]
pub struct PoolBlockDetail {
    pub header: VirtAddr,
    pub body: VirtAddr,
    pub size: u64,
    pub previous_size: u64,
    pub pool_type: u8,
    pub tag: u32,
    pub tag_name: String,
    pub allocated: bool,
    pub marked: bool,
    pub state: String,
    pub target_offset: Option<u64>,
}

/// Large allocation represented by `PoolBigPageTable`.
#[derive(Debug, Clone)]
pub struct BigPoolDetail {
    pub address: VirtAddr,
    pub target: VirtAddr,
    pub size: u64,
    pub offset: u64,
    pub tag: u32,
    pub tag_name: String,
    pub entry: VirtAddr,
    pub index: u64,
    pub nonpaged: bool,
    pub pattern: u8,
    pub pool_flags: u16,
    pub slush_size: u16,
}

/// Bounded result for the pool page containing an address.
#[derive(Debug, Clone)]
pub struct PoolPageDetail {
    pub target: VirtAddr,
    pub page: VirtAddr,
    pub page_kind: String,
    pub region: Option<PoolRegionDetail>,
    pub blocks: Vec<PoolBlockDetail>,
    pub target_index: Option<usize>,
    pub big: Option<BigPoolDetail>,
    pub segment_heap_hint: Option<String>,
    pub near_symbol: Option<String>,
    pub message: Option<String>,
}

/// Virtual pool range metadata attached to a pool-page result.
#[derive(Debug, Clone)]
pub struct PoolRegionDetail {
    pub name: String,
    pub start: VirtAddr,
    pub end: VirtAddr,
}

/// Aggregated tracker rows returned by `!poolused`.
#[derive(Debug, Clone)]
pub struct PoolUsageDetail {
    pub rows: Vec<PoolUsageRow>,
    pub rows_truncated: bool,
    pub tracker_status: String,
    pub big_status: String,
    pub sort: PoolUsageSort,
    pub tag_filter: Option<String>,
    pub include_counts: bool,
}

/// Sort order for [`Target::pool_usage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolUsageSort {
    Tag,
    NonPagedBytes,
    PagedBytes,
}

impl PoolUsageSort {
    pub fn name(self) -> &'static str {
        match self {
            Self::Tag => "tag",
            Self::NonPagedBytes => "nonpaged_bytes",
            Self::PagedBytes => "paged_bytes",
        }
    }
}

/// One match found by the bounded `!poolfind` scan.
#[derive(Debug, Clone)]
pub struct PoolFindMatch {
    pub source: String,
    pub address: VirtAddr,
    pub size: u64,
    pub tag: u32,
    pub tag_name: String,
    pub allocated: bool,
    pub state: String,
    pub pool_type: Option<PoolType>,
    pub table_entry: Option<VirtAddr>,
    pub index: Option<u64>,
}

/// Bounded pool-tag scan result, including scan status rather than printing it.
#[derive(Debug, Clone)]
pub struct PoolFindDetail {
    pub tag: String,
    pub pool_type: Option<PoolType>,
    pub matches: Vec<PoolFindMatch>,
    pub found: usize,
    pub ranges: Vec<PoolFindRange>,
    pub big_status: Option<String>,
    pub truncated: bool,
    pub interrupted: bool,
}

/// One virtual pool range's scan status.
#[derive(Debug, Clone)]
pub struct PoolFindRange {
    pub name: String,
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub pages: u64,
    pub scanned_pages: u64,
    pub bounded: bool,
}

/// A decoded `_GENERAL_LOOKASIDE` record. Each counter is independently
/// diagnostic because stripped PDBs commonly omit one or more members.
#[derive(Debug, Clone)]
pub struct LookasideDetail {
    pub address: VirtAddr,
    pub index: usize,
    pub tag: DiagnosticValue<u32>,
    pub size: DiagnosticValue<u64>,
    pub depth: DiagnosticValue<u64>,
    pub total_allocates: DiagnosticValue<u64>,
    pub total_frees: DiagnosticValue<u64>,
    pub allocate_misses: DiagnosticValue<u64>,
}

/// Both exported lookaside-list roots and their bounded records.
#[derive(Debug, Clone)]
pub struct LookasideListsDetail {
    pub records: Vec<LookasideDetail>,
    pub nonpaged_count: usize,
    pub paged_count: usize,
    pub nonpaged_termination: String,
    pub paged_termination: String,
    pub interrupted: bool,
    pub truncated: bool,
}

fn available_metric(value: u64) -> DiagnosticMetric<u64> {
    DiagnosticMetric {
        value: DiagnosticValue::Available(value),
        source: Some(MetadataSource::KernelSymbol),
    }
}

fn unavailable_metric(error: impl std::fmt::Display) -> DiagnosticMetric<u64> {
    DiagnosticMetric {
        value: DiagnosticValue::Unavailable(error.to_string()),
        source: None,
    }
}

fn global_metric(target: &Target, symbol: &str) -> DiagnosticMetric<u64> {
    match read_kernel_global_u64(target, symbol) {
        Ok(value) => available_metric(value),
        Err(error) => unavailable_metric(error),
    }
}

fn named_counter(target: &Target, name: &str, unit: &'static str) -> VmCounter {
    VmCounter {
        name: name.to_string(),
        value: global_metric(target, name),
        unit,
    }
}

fn diagnostic_unavailable<T>(error: impl std::fmt::Display) -> DiagnosticValue<T> {
    DiagnosticValue::Unavailable(error.to_string())
}

fn nested_type_name(data: &ParsedType) -> Option<&str> {
    match data {
        ParsedType::Struct(name) | ParsedType::Union(name) => Some(name.as_str()),
        _ => None,
    }
}

fn nested_mi_state_fields(
    target: &Target,
    base: VirtAddr,
    ti: &TypeInfo,
    prefix: &str,
    predicates: &[String],
    depth: usize,
    visited: &mut HashSet<String>,
    output: &mut Vec<(String, u64)>,
) {
    if depth > 3 || output.len() >= MAX_MI_FIELDS {
        return;
    }
    let memory = target.kernel_address_space();
    let mut fields: Vec<_> = ti.fields.iter().collect();
    fields.sort_by_key(|(_, field)| field.offset);
    for (name, field) in fields {
        if output.len() >= MAX_MI_FIELDS {
            break;
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}.{name}")
        };
        if let Some(nested) = nested_type_name(&field.type_data)
            && depth < 3
            && visited.insert(format!("{path}:{nested}"))
            && let Some(nested_ti) = target
                .symbols
                .find_type_across_modules(target.kernel_dtb(), nested)
        {
            nested_mi_state_fields(
                target,
                base + field.offset as u64,
                &nested_ti,
                &path,
                predicates,
                depth + 1,
                visited,
                output,
            );
            continue;
        }
        let matches_predicate = predicates
            .iter()
            .any(|predicate| path.to_ascii_lowercase().contains(predicate));
        if matches_predicate
            && !matches!(&field.type_data, ParsedType::Array(_, _))
            && let Some(value) = read_pool_field(ti, &memory, base, name)
        {
            output.push((path, value));
        }
    }
}

fn find_mi_state_fields(target: &Target, predicates: &[&str]) -> Vec<(String, u64)> {
    let Ok(base) = kernel_symbol_address(target, "MiState") else {
        return Vec::new();
    };
    let Some(ti) = target
        .symbols
        .find_type_across_modules(target.kernel_dtb(), "_MI_SYSTEM_INFORMATION")
    else {
        return Vec::new();
    };
    let predicates = predicates
        .iter()
        .map(|predicate| predicate.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut fields = Vec::new();
    let mut visited = HashSet::new();
    nested_mi_state_fields(
        target,
        base,
        &ti,
        "",
        &predicates,
        0,
        &mut visited,
        &mut fields,
    );
    fields
}

fn mi_state_pool_field_unit(name: &str) -> &'static str {
    let leaf = name
        .to_ascii_lowercase()
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_string();
    if leaf == "maximumnonpagedpoolthreshold"
        || (leaf.contains("allocated")
            && (leaf.contains("nonpagedpool") || leaf.contains("pagedpool")))
    {
        "pages"
    } else {
        "bytes"
    }
}

fn curated_mi_state_pool_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let leaf = lower.rsplit('.').next().unwrap_or(&lower);
    (leaf == "allocatednonpagedpool")
        || (leaf == "allocatedpagedpool")
        || (leaf == "allocatedsecurenonpagedpool")
        || (leaf == "maximumnonpagedpoolthreshold")
        || (leaf.starts_with("total") && leaf.contains("poolquota"))
        || ((leaf.contains("nonpagedpool") || leaf.contains("pagedpool")) && leaf.contains("bytes"))
}

fn vm_processes(target: &Target, include: bool) -> Result<(Vec<ProcessMemoryUsage>, usize, bool)> {
    if !include {
        return Ok((Vec::new(), 0, false));
    }
    let all_processes = target.matching_processes(None)?;
    let process_count = all_processes.len();
    let process_limit = DEFAULT_MEMORY_PROCESS_LIMIT;
    let layouts = (|| -> Result<(std::sync::Arc<TypeInfo>, std::sync::Arc<TypeInfo>)> {
        let guest = target.guest()?;
        let types = guest.ntoskrnl.types();
        let eprocess_layout = types.layout("_EPROCESS")?;
        let vm_field = eprocess_layout
            .fields
            .get("Vm")
            .ok_or_else(|| Error::FieldNotFound("Vm".to_string()))?;
        let vm_name = match &vm_field.type_data {
            ParsedType::Struct(name) | ParsedType::Union(name) => name.clone(),
            _ => {
                return Err(Error::FieldTypeMismatch(
                    "Vm".to_string(),
                    "embedded struct".to_string(),
                ));
            }
        };
        Ok((eprocess_layout, types.layout(vm_name)?))
    })();
    let processes = all_processes
        .into_iter()
        .take(process_limit)
        .map(|process| {
            let unavailable = layouts.as_ref().err().map(ToString::to_string);
            let field = |name: &str| match &layouts {
                Ok((eprocess_layout, vm_layout)) => target.process_memory_counter(
                    eprocess_layout,
                    vm_layout,
                    process.eprocess_va,
                    name,
                ),
                Err(_) => diagnostic_unavailable(
                    unavailable.as_deref().unwrap_or("VM layout unavailable"),
                ),
            };
            ProcessMemoryUsage {
                virtual_size: field("VirtualSize"),
                peak_virtual_size: field("PeakVirtualSize"),
                working_set_size: field("WorkingSetSize"),
                peak_working_set_size: field("PeakWorkingSetSize"),
                pagefile_usage: field("PagefileUsage"),
                peak_pagefile_usage: field("PeakPagefileUsage"),
                private_usage: field("PrivateUsage"),
                process,
            }
        })
        .collect();
    Ok((processes, process_count, process_count > process_limit))
}

impl Target {
    /// Read guest-physical memory directly through the target's physical-memory
    /// backend without translating the supplied address.
    pub fn read_physical(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.phys.read_bytes(address, buf)
    }

    /// Write guest-physical memory directly through the target's physical-memory
    /// backend without translating the supplied address.
    pub fn write_physical(&self, address: u64, data: &[u8]) -> Result<()> {
        self.phys.write_bytes(address, data)
    }

    /// Translate `address` using `directory_base`, or the current inspection
    /// context when it is `None` (or explicitly zero). Returns `None` when no
    /// present mapping exists.
    pub fn virt_to_phys(
        &self,
        directory_base: Option<u64>,
        address: VirtAddr,
    ) -> Result<Option<u64>> {
        let dtb = directory_base
            .filter(|value| *value != 0)
            .map(|value| value & self.arch().dtb_page_mask())
            .unwrap_or_else(|| self.current_dtb());
        Ok(self
            .address_space(dtb)
            .virt_to_phys(address)?
            .map(|translation| translation.address))
    }

    /// Decode system memory, pool, PTE, page-file, and bounded per-process
    /// counters. Global `DiagnosticMetric` values report the kernel-symbol (or
    /// debugger-data fallback) read failure in their value/source; process fields
    /// report missing VM layouts or individual field-read failures independently.
    pub fn inspect_vm(&self, include_processes: bool) -> Result<VmDetail> {
        let debugger_data = self.debugger_data();
        let (processes, process_count, truncated) = vm_processes(self, include_processes)?;
        let system = SystemMemorySummary {
            physical_pages: self.global_memory_counter(
                "MmNumberOfPhysicalPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_number_of_physical_pages_address),
                ),
                Some("MmGetNumberOfPhysicalPages"),
            ),
            available_pages: self.global_memory_counter(
                "MmAvailablePages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_available_pages_address),
                ),
                Some("MmGetAvailablePages"),
            ),
            committed_pages: self.global_memory_counter(
                "MmTotalCommittedPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_committed_pages_address),
                ),
                Some("MmGetTotalCommittedPages"),
            ),
            commit_limit_pages: self.global_memory_counter(
                "MmTotalCommitLimit",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_commit_limit_address),
                ),
                Some("MmGetTotalCommitLimit"),
            ),
            paged_pool_pages: self.global_memory_counter("MmSizeOfPagedPoolInPages", None, None),
            nonpaged_pool_bytes: self.global_memory_counter(
                "MmSizeOfNonPagedPoolInBytes",
                None,
                None,
            ),
            processes,
            process_count,
            truncated,
        };
        let pool_fields = find_mi_state_fields(self, &["pool"])
            .into_iter()
            .filter(|(name, _)| curated_mi_state_pool_field(name))
            .take(MAX_MI_STATE_FIELDS)
            .map(|(name, value)| VmCounter {
                unit: mi_state_pool_field_unit(&name),
                name,
                value: available_metric(value),
            })
            .collect();
        let pool = VmPoolDetail {
            nonpaged_pool_bytes: global_metric(self, "MmSizeOfNonPagedPoolInBytes"),
            nonpaged_pool_maximum: global_metric(self, "MmMaximumNonPagedPoolInBytes"),
            paged_pool_pages: global_metric(self, "MmSizeOfPagedPoolInPages"),
            fields: pool_fields,
        };
        let pte = VmPteDetail {
            counters: [
                ("MmTotalSystemPtes", "total system PTEs"),
                ("MmTotalFreeSystemPtes", "free system PTEs"),
                ("MmTotalNonPagedPoolPtes", "nonpaged pool PTEs"),
                ("MmAvailableSystemPtes", "available system PTEs"),
            ]
            .into_iter()
            .map(|(symbol, name)| {
                let mut counter = named_counter(self, symbol, "");
                counter.name = name.to_string();
                counter
            })
            .collect(),
        };
        let page_files = VmPageFileDetail {
            counters: [
                ("MmNumberOfPagingFiles", "number of paging files", ""),
                (
                    "MmTotalPagesForPagingFile",
                    "pages for paging file",
                    "pages",
                ),
                ("MmFreePages", "free paging pages", "pages"),
            ]
            .into_iter()
            .map(|(symbol, name, unit)| {
                let mut counter = named_counter(self, symbol, unit);
                counter.name = name.to_string();
                counter
            })
            .collect(),
        };
        Ok(VmDetail {
            system,
            pool,
            pte,
            page_files,
            include_processes,
        })
    }

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

    /// Walk `directory_base` for `address`, reusing the existing current-context
    /// `PteWalk` decoder when the argument is zero. Explicit AMD64 walks retain
    /// each PML4/PDP/PDE/PTE entry; other architectures use the shared translator.
    pub fn vtop(&self, directory_base: u64, address: VirtAddr) -> Result<VtopDetail> {
        let dtb = if directory_base == 0 {
            self.current_dtb()
        } else {
            directory_base & self.arch().dtb_page_mask()
        };
        if directory_base == 0
            && let Ok(walk) = self.pte_traverse(address)
        {
            let physical = self
                .address_space(dtb)
                .virt_to_phys(address)?
                .map(|translation| translation.address);
            let walk_transition = walk
                .pte
                .as_ref()
                .is_some_and(|level| level.value.is_transition());
            let large_entry = walk
                .pde
                .as_ref()
                .or(Some(&walk.ppe))
                .is_some_and(|level| level.value.is_large_page());
            let large = physical.is_some() && large_entry;
            let levels = [Some(walk.pxe), Some(walk.ppe), walk.pde, walk.pte]
                .into_iter()
                .flatten()
                .map(|level| VtopLevel {
                    name: level.name,
                    address: level.address,
                    value: level.value.0,
                })
                .collect();
            return Ok(VtopDetail {
                address,
                dtb,
                levels,
                physical,
                large,
                transition: physical.is_some() && walk_transition,
            });
        }
        if self.arch() != Arch::Amd64 {
            let translation = self.address_space(dtb).virt_to_phys(address)?;
            return Ok(VtopDetail {
                address,
                dtb,
                levels: Vec::new(),
                physical: translation.map(|value| value.address),
                large: translation.is_some_and(|value| value.large),
                transition: translation.is_some_and(|value| value.transition),
            });
        }
        explicit_amd64_walk(self, dtb, address)
    }

    /// Reverse-walk the current AMD64 directory base for mappings of a physical
    /// page. The walk stops at 32 results or 65,536 table pages and records both
    /// bounds and Ctrl-C interruption state.
    pub fn ptov(&self, physical: u64) -> Result<PtovDetail> {
        let dtb = self.current_dtb();
        if dtb == DTB_IDENTITY {
            return Ok(PtovDetail {
                physical,
                dtb,
                mappings: vec![PtovMapping {
                    virtual_address: VirtAddr(physical),
                    large: false,
                }],
                table_pages: 0,
                bounded: false,
                interrupted: false,
            });
        }
        if self.arch() != Arch::Amd64 {
            return Err(Error::DebugInfo(
                "!ptov reverse walking is currently available for AMD64 targets only".to_string(),
            ));
        }
        let mut visited = HashSet::new();
        let mut table_pages = 0usize;
        let mut mappings = Vec::new();
        scan_ptov_table(
            self,
            dtb,
            0,
            [0; 4],
            physical & !(PAGE_SIZE as u64 - 1),
            &mut visited,
            &mut table_pages,
            &mut mappings,
        );
        let interrupted = self.interrupted();
        let bounded = table_pages >= MAX_PTOV_TABLE_PAGES || mappings.len() >= MAX_PTOV_RESULTS;
        Ok(PtovDetail {
            physical,
            dtb,
            mappings: mappings
                .into_iter()
                .map(|(address, large)| PtovMapping {
                    virtual_address: VirtAddr(
                        address.0.wrapping_add(physical & (PAGE_SIZE as u64 - 1)),
                    ),
                    large,
                })
                .collect(),
            table_pages,
            bounded,
            interrupted,
        })
    }

    /// Decode the pool page containing `address`, including every plausible
    /// block and the block containing the requested address. Big-page entries
    /// are retained separately when the address lies in one.
    pub fn inspect_pool(&self, address: VirtAddr) -> Result<PoolPageDetail> {
        let layout = pool_layout(self)?;
        if address.0 & (POOL_PAGE_SIZE - 1) == 0
            && let Some(big) = find_big_pool(self, &layout, address)
        {
            return Ok(PoolPageDetail {
                target: address,
                page: VirtAddr(address.0 & !(POOL_PAGE_SIZE - 1)),
                page_kind: "big".to_string(),
                region: None,
                blocks: Vec::new(),
                target_index: None,
                big: Some(big_pool_detail(address, &big)),
                segment_heap_hint: None,
                near_symbol: None,
                message: None,
            });
        }
        let region =
            classify_pool_region(self, address).map(|(name, start, end)| PoolRegionDetail {
                name: name.to_string(),
                start,
                end,
            });
        let (blocks, index, page) = locate_pool_block_in_page(self, &layout, address);
        let details = blocks
            .iter()
            .enumerate()
            .map(|(block_index, block)| {
                pool_block_detail(block, index == Some(block_index), address)
            })
            .collect::<Vec<_>>();
        let big = if index.is_none() {
            find_big_pool(self, &layout, address).map(|entry| big_pool_detail(address, &entry))
        } else {
            None
        };
        let message = if index.is_none() && big.is_none() {
            Some("address does not lie inside a recognizable _POOL_HEADER block".to_string())
        } else {
            None
        };
        let page_kind = if big.is_some() {
            "big"
        } else if index.is_some() {
            "pool"
        } else {
            "unknown"
        };
        Ok(PoolPageDetail {
            target: address,
            page,
            page_kind: page_kind.to_string(),
            region,
            blocks: details,
            target_index: index,
            big,
            segment_heap_hint: if message.is_some() {
                segment_heap_hint(self).map(str::to_string)
            } else {
                None
            },
            near_symbol: if message.is_some() {
                annotate_near_symbol(self, address)
            } else {
                None
            },
            message,
        })
    }

    /// Aggregate bounded pool tracker and big-page usage rows, filtering and
    /// sorting them before returning the neutral result.
    pub fn pool_usage(
        &self,
        sort: PoolUsageSort,
        tag_filter: Option<&str>,
        include_counts: bool,
    ) -> Result<PoolUsageDetail> {
        let summary = collect_pool_usage(self);
        let mut rows = summary
            .rows
            .into_iter()
            .filter(|row| {
                tag_filter
                    .map(|filter| glob_matches(filter, &tag_string(row.tag), false))
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        match sort {
            PoolUsageSort::NonPagedBytes => rows.sort_by(|a, b| {
                b.nonpaged_bytes
                    .cmp(&a.nonpaged_bytes)
                    .then_with(|| a.tag.cmp(&b.tag))
            }),
            PoolUsageSort::PagedBytes => rows.sort_by(|a, b| {
                b.paged_bytes
                    .cmp(&a.paged_bytes)
                    .then_with(|| a.tag.cmp(&b.tag))
            }),
            PoolUsageSort::Tag => rows.sort_by_key(|row| row.tag),
        }
        let rows_truncated = summary.rows_truncated || rows.len() > MAX_POOLUSED_ROWS;
        rows.truncate(MAX_POOLUSED_ROWS);
        Ok(PoolUsageDetail {
            rows,
            rows_truncated,
            tracker_status: summary.tracker_status,
            big_status: summary.big.status,
            sort,
            tag_filter: tag_filter.map(str::to_string),
            include_counts,
        })
    }

    /// Scan virtual pool ranges and `PoolBigPageTable` for a tag. The bounded
    /// result records whether the scan reached a limit or was interrupted by
    /// the host.
    pub fn pool_find(&self, tag: &str, pool_type: Option<PoolType>) -> Result<PoolFindDetail> {
        let layout = pool_layout(self).ok();
        let mut matches = Vec::new();
        let mut ranges = Vec::new();
        let mut truncated = false;
        if let Some(layout) = &layout {
            for range in resolve_pool_ranges(self) {
                if pool_type.is_some_and(|kind| range.kind != kind.kind()) {
                    continue;
                }
                let Some(start) = range
                    .start
                    .checked_add(PAGE_SIZE as u64 - 1)
                    .map(|value| value & !(PAGE_SIZE as u64 - 1))
                else {
                    continue;
                };
                let end = range.end & !(PAGE_SIZE as u64 - 1);
                let pages = end.saturating_sub(start) / PAGE_SIZE as u64;
                let scan_pages = pages.min(MAX_POOLFIND_PAGES);
                let mut scanned_pages = 0;
                for page in 0..scan_pages {
                    if self.interrupted() || matches.len() >= MAX_POOLFIND_RESULTS {
                        break;
                    }
                    let Some(base) = page
                        .checked_mul(PAGE_SIZE as u64)
                        .and_then(|offset| start.checked_add(offset))
                        .map(VirtAddr)
                    else {
                        break;
                    };
                    scanned_pages += 1;
                    for block in scan_pool_page_lax(self, layout, base) {
                        if block.synthetic_free || !glob_matches(tag, &tag_string(block.tag), false)
                        {
                            continue;
                        }
                        let kind = if block.pool_type == 1 {
                            PoolType::Paged
                        } else {
                            PoolType::NonPaged
                        };
                        matches.push(PoolFindMatch {
                            source: range.name.to_string(),
                            address: block.body,
                            size: block.size,
                            tag: block.tag,
                            tag_name: tag_string(block.tag),
                            allocated: pool_block_state(&block) != "Free",
                            state: pool_block_state(&block).to_string(),
                            pool_type: Some(kind),
                            table_entry: None,
                            index: None,
                        });
                        if matches.len() >= MAX_POOLFIND_RESULTS {
                            break;
                        }
                    }
                }
                let range_bounded = scan_pages < pages;
                truncated |= range_bounded;
                ranges.push(PoolFindRange {
                    name: range.name.to_string(),
                    start: VirtAddr(start),
                    end: VirtAddr(end),
                    pages,
                    scanned_pages,
                    bounded: range_bounded,
                });
                if self.interrupted() || matches.len() >= MAX_POOLFIND_RESULTS {
                    break;
                }
            }
        }
        let big_status = if let Some(layout) = layout.as_ref() {
            Some(
                scan_big_pool_entries(
                    self,
                    layout.big_pool_type.as_deref(),
                    layout.big_pool_uses_struct,
                    layout.big_pool_has_pool_type,
                    layout.big_pool_has_slush,
                    |entry| {
                        if matches.len() < MAX_POOLFIND_RESULTS
                            && pool_type
                                .is_none_or(|kind| entry.nonpaged == (kind == PoolType::NonPaged))
                            && glob_matches(tag, &tag_string(entry.tag), false)
                        {
                            matches.push(PoolFindMatch {
                                source: "BigPool".to_string(),
                                address: entry.va,
                                size: entry.size,
                                tag: entry.tag,
                                tag_name: tag_string(entry.tag),
                                allocated: true,
                                state: "Allocated".to_string(),
                                pool_type: Some(if entry.nonpaged {
                                    PoolType::NonPaged
                                } else {
                                    PoolType::Paged
                                }),
                                table_entry: Some(entry.entry),
                                index: Some(entry.index),
                            });
                        }
                        matches.len() >= MAX_POOLFIND_RESULTS
                    },
                )
                .status,
            )
        } else {
            match big_pool_layout(self) {
                Ok((big_pool_type, uses_struct, has_pool_type, has_slush)) => Some(
                    scan_big_pool_entries(
                        self,
                        Some(&big_pool_type),
                        uses_struct,
                        has_pool_type,
                        has_slush,
                        |entry| {
                            if matches.len() < MAX_POOLFIND_RESULTS
                                && pool_type.is_none_or(|kind| {
                                    entry.nonpaged == (kind == PoolType::NonPaged)
                                })
                                && glob_matches(tag, &tag_string(entry.tag), false)
                            {
                                matches.push(PoolFindMatch {
                                    source: "BigPool".to_string(),
                                    address: entry.va,
                                    size: entry.size,
                                    tag: entry.tag,
                                    tag_name: tag_string(entry.tag),
                                    allocated: true,
                                    state: "Allocated".to_string(),
                                    pool_type: Some(if entry.nonpaged {
                                        PoolType::NonPaged
                                    } else {
                                        PoolType::Paged
                                    }),
                                    table_entry: Some(entry.entry),
                                    index: Some(entry.index),
                                });
                            }
                            matches.len() >= MAX_POOLFIND_RESULTS
                        },
                    )
                    .status,
                ),
                Err(error) => Some(format!("big-page layout unavailable: {error}")),
            }
        };
        truncated |= matches.len() >= MAX_POOLFIND_RESULTS;
        let interrupted = self.interrupted();
        Ok(PoolFindDetail {
            tag: tag.to_string(),
            pool_type,
            found: matches.len(),
            matches,
            ranges,
            big_status,
            truncated,
            interrupted,
        })
    }

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

fn explicit_amd64_walk(target: &Target, dtb: Dtb, va: VirtAddr) -> Result<VtopDetail> {
    if dtb == DTB_IDENTITY {
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels: Vec::new(),
            physical: Some(va.0),
            large: false,
            transition: false,
        });
    }
    let root = dtb & PFN_MASK;
    let memory = &target.phys;
    let mut levels = Vec::with_capacity(4);
    let pml4_address = root
        .checked_add((va.pml4_index() as u64) * 8)
        .ok_or_else(|| Error::DebugInfo("PML4 address overflow".to_string()))?;
    let pml4e: PageTableEntry = memory.read(pml4_address)?;
    levels.push(VtopLevel {
        name: "PXE".to_string(),
        address: VirtAddr(pml4_address),
        value: pml4e.0,
    });
    if !pml4e.is_present() {
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: None,
            large: false,
            transition: false,
        });
    }
    let pdpt_address = pml4e
        .page_frame()
        .checked_add((va.pdpt_index() as u64) * 8)
        .ok_or_else(|| Error::DebugInfo("PDPT address overflow".to_string()))?;
    let pdpte: PageTableEntry = memory.read(pdpt_address)?;
    levels.push(VtopLevel {
        name: "PPE".to_string(),
        address: VirtAddr(pdpt_address),
        value: pdpte.0,
    });
    if !pdpte.is_present() {
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: None,
            large: false,
            transition: false,
        });
    }
    if pdpte.is_large_page() {
        let frame = pdpte.page_frame() & !(LARGE_PAGE_1G - 1);
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: frame.checked_add(va.huge_page_offset()),
            large: true,
            transition: false,
        });
    }
    let pde_address = pdpte
        .page_frame()
        .checked_add((va.pd_index() as u64) * 8)
        .ok_or_else(|| Error::DebugInfo("PD address overflow".to_string()))?;
    let pde: PageTableEntry = memory.read(pde_address)?;
    levels.push(VtopLevel {
        name: "PDE".to_string(),
        address: VirtAddr(pde_address),
        value: pde.0,
    });
    if !pde.is_present() {
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: None,
            large: false,
            transition: false,
        });
    }
    if pde.is_large_page() {
        let frame = pde.page_frame() & !(LARGE_PAGE_2M - 1);
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: frame.checked_add(va.large_page_offset()),
            transition: false,
            large: true,
        });
    }
    let pte_address = pde
        .page_frame()
        .checked_add((va.pt_index() as u64) * 8)
        .ok_or_else(|| Error::DebugInfo("PT address overflow".to_string()))?;
    let pte: PageTableEntry = memory.read(pte_address)?;
    levels.push(VtopLevel {
        name: "PTE".to_string(),
        address: VirtAddr(pte_address),
        value: pte.0,
    });
    // A transition leaf still names the frame the guest holds, and reads go
    // through it, so reporting it unmapped here would contradict them.
    let transition = pte.is_transition();
    Ok(VtopDetail {
        address: va,
        dtb,
        levels,
        physical: (pte.is_present() || transition).then(|| pte.page_frame() + va.page_offset()),
        large: false,
        transition,
    })
}

fn scan_ptov_table(
    target: &Target,
    table: u64,
    level: u8,
    prefix: [usize; 4],
    wanted_page: u64,
    visited: &mut HashSet<u64>,
    table_pages: &mut usize,
    results: &mut Vec<(VirtAddr, bool)>,
) {
    if *table_pages >= MAX_PTOV_TABLE_PAGES
        || results.len() >= MAX_PTOV_RESULTS
        || target.interrupted()
    {
        return;
    }
    let table = table & PFN_MASK;
    if !visited.insert(table) {
        return;
    }
    *table_pages += 1;
    let entries: [PageTableEntry; 512] = match target.phys.read(table) {
        Ok(entries) => entries,
        Err(_) => {
            visited.remove(&table);
            return;
        }
    };
    for (index, entry) in entries.into_iter().enumerate() {
        if !entry.is_present() || results.len() >= MAX_PTOV_RESULTS {
            continue;
        }
        let mut current = prefix;
        current[level as usize] = index;
        if level == 1 && entry.is_large_page() {
            let frame = entry.page_frame() & !(LARGE_PAGE_1G - 1);
            if (frame..frame.saturating_add(LARGE_PAGE_1G)).contains(&wanted_page) {
                let va = VirtAddr::construct(current[0], current[1], 0, 0) + (wanted_page - frame);
                results.push((va, true));
            }
            continue;
        }
        if level == 2 && entry.is_large_page() {
            let frame = entry.page_frame() & !(LARGE_PAGE_2M - 1);
            if (frame..frame.saturating_add(LARGE_PAGE_2M)).contains(&wanted_page) {
                let va = VirtAddr::construct(current[0], current[1], current[2], 0)
                    + (wanted_page - frame);
                results.push((va, true));
            }
            continue;
        }
        if level == 3 {
            if entry.page_frame() == wanted_page {
                results.push((
                    VirtAddr::construct(current[0], current[1], current[2], current[3]),
                    false,
                ));
            }
            continue;
        }
        scan_ptov_table(
            target,
            entry.page_frame(),
            level + 1,
            current,
            wanted_page,
            visited,
            table_pages,
            results,
        );
    }
    visited.remove(&table);
}

fn pool_block_detail(block: &PoolHeader, marked: bool, target: VirtAddr) -> PoolBlockDetail {
    let state = pool_block_state(block).to_string();
    PoolBlockDetail {
        header: block.header,
        body: block.body,
        size: block.size,
        previous_size: block.previous_size,
        pool_type: block.pool_type,
        tag: block.tag,
        tag_name: tag_string(block.tag),
        allocated: state != "Free",
        marked,
        state,
        target_offset: marked.then(|| target.0.saturating_sub(block.body.0)),
    }
}

fn big_pool_detail(target: VirtAddr, entry: &BigPoolEntry) -> BigPoolDetail {
    BigPoolDetail {
        address: entry.va,
        target,
        size: entry.size,
        offset: target.0.saturating_sub(entry.va.0),
        tag: entry.tag,
        tag_name: tag_string(entry.tag),
        entry: entry.entry,
        index: entry.index,
        nonpaged: entry.nonpaged,
        pattern: entry.pattern,
        pool_flags: entry.pool_flags,
        slush_size: entry.slush_size,
    }
}

fn resolve_pool_ranges(target: &Target) -> Vec<PoolFindRangeInternal> {
    let mut ranges = Vec::new();
    if let Some(range) = pool_range(
        target,
        "NonPagedPool",
        "MmNonPagedPoolStart",
        "MmNonPagedPoolEnd",
        0,
    ) {
        ranges.push(range);
    } else if let Some(range) =
        mi_state_pool_range(target, "nonpagedpoolstart", "nonpagedpoolend", 0)
    {
        ranges.push(range);
    }
    if let Some(range) = pool_range(target, "PagedPool", "MmPagedPoolStart", "MmPagedPoolEnd", 1) {
        ranges.push(range);
    } else if let Some(range) = mi_state_pool_range(target, "pagedpoolstart", "pagedpoolend", 1) {
        ranges.push(range);
    }
    ranges
}

#[derive(Clone, Copy)]
struct PoolFindRangeInternal {
    name: &'static str,
    start: u64,
    end: u64,
    kind: u64,
}

fn pool_range(
    target: &Target,
    name: &'static str,
    start_symbol: &str,
    end_symbol: &str,
    kind: u64,
) -> Option<PoolFindRangeInternal> {
    let start = read_kernel_global_u64(target, start_symbol).ok()?;
    let end = read_kernel_global_u64(target, end_symbol).ok()?;
    (start < end).then_some(PoolFindRangeInternal {
        name,
        start,
        end,
        kind,
    })
}

fn mi_state_pool_range(
    target: &Target,
    start_name: &str,
    end_name: &str,
    kind: u64,
) -> Option<PoolFindRangeInternal> {
    let fields = find_mi_state_fields(target, &["pool", "start", "end"]);
    let start = fields.iter().find_map(|(name, value)| {
        name.to_ascii_lowercase()
            .contains(&start_name.to_ascii_lowercase())
            .then_some(*value)
    });
    let end = fields.iter().find_map(|(name, value)| {
        name.to_ascii_lowercase()
            .contains(&end_name.to_ascii_lowercase())
            .then_some(*value)
    });
    Some(PoolFindRangeInternal {
        name: if kind == 0 {
            "NonPagedPool"
        } else {
            "PagedPool"
        },
        start: start?,
        end: end?,
        kind,
    })
    .filter(|range| range.start < range.end)
}

fn segment_heap_hint(target: &Target) -> Option<&'static str> {
    target
        .symbols
        .find_symbol_across_modules(target.current_dtb(), "nt!RtlpHpHeapGlobals")
        .ok()
        .flatten()?;
    Some(
        "kernel has RtlpHpHeapGlobals (segment heap is enabled); address may be a _HEAP_VS_CHUNK_HEADER / LFH chunk instead of a _POOL_HEADER",
    )
}

fn annotate_near_symbol(target: &Target, address: VirtAddr) -> Option<String> {
    let (module, name, offset) = target
        .symbols
        .find_closest_symbol_for_address(target.current_dtb(), address)?;
    (offset <= 0x1000).then(|| format_symbol_with_offset(&module, &name, offset))
}

const POOL_PAGE_SIZE: u64 = PAGE_SIZE as u64;

#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub node_address: VirtAddr,
    pub level: usize,
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub protection: Option<u64>,
    pub vad_type: Option<u64>,
    pub private_memory: Option<bool>,
    pub commit_charge: Option<u64>,
    pub details: Option<String>,
}

impl MemoryRegionInfo {
    pub fn size(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
}

#[derive(Debug, Clone)]
pub struct AddressModule {
    pub name: String,
    pub base: VirtAddr,
    pub size: u32,
    pub offset: u64,
}

/// What an address belongs to: a loaded module (and section), a process VAD
/// region, or nothing recognized. Complements `pte_traverse` (how it's mapped)
/// with where it lives.
#[derive(Debug, Clone)]
pub struct AddressDescription {
    pub address: VirtAddr,
    pub dtb: Dtb,
    /// "kernel-module", "user-image", "kernel-region", "private", "mapped", or
    /// "unknown".
    pub kind: &'static str,
    pub module: Option<AddressModule>,
    pub section: Option<String>,
    /// For a "kernel-region" hit: the `MI_SYSTEM_VA_TYPE` name (e.g.
    /// `KernelStacks`, `PagedPool`, `SystemPtes`).
    pub va_type: Option<String>,
    pub region: Option<MemoryRegionInfo>,
}

#[derive(Debug, Clone)]
pub struct ProcessMemoryUsage {
    pub process: ProcessInfo,
    pub virtual_size: DiagnosticValue<u64>,
    pub peak_virtual_size: DiagnosticValue<u64>,
    pub working_set_size: DiagnosticValue<u64>,
    pub peak_working_set_size: DiagnosticValue<u64>,
    pub pagefile_usage: DiagnosticValue<u64>,
    pub peak_pagefile_usage: DiagnosticValue<u64>,
    pub private_usage: DiagnosticValue<u64>,
}

#[derive(Debug, Clone)]
pub struct SystemMemorySummary {
    pub physical_pages: DiagnosticMetric<u64>,
    pub available_pages: DiagnosticMetric<u64>,
    pub committed_pages: DiagnosticMetric<u64>,
    pub commit_limit_pages: DiagnosticMetric<u64>,
    pub paged_pool_pages: DiagnosticMetric<u64>,
    pub nonpaged_pool_bytes: DiagnosticMetric<u64>,
    pub processes: Vec<ProcessMemoryUsage>,
    pub process_count: usize,
    pub truncated: bool,
}

pub struct PteLevel {
    pub name: String, // TODO maybe enum instead?
    pub address: VirtAddr,
    pub value: PageTableEntry,
}

pub struct PteWalk {
    pub address: VirtAddr,
    /// The address space the walk was performed in (the attached process DTB
    /// when attached, else the kernel), so callers know what was walked.
    pub dtb: Dtb,
    pub pxe: PteLevel,
    pub ppe: PteLevel,
    pub pde: Option<PteLevel>,
    pub pte: Option<PteLevel>,
}

impl Target {
    fn process_memory_counter(
        &self,
        eprocess_layout: &TypeInfo,
        vm_layout: &TypeInfo,
        eprocess: VirtAddr,
        field: &str,
    ) -> DiagnosticValue<u64> {
        DiagnosticValue::from_result((|| -> Result<u64> {
            let vm = eprocess + eprocess_layout.field_offset("Vm")?;

            if let Ok(value) = self.read_layout_field(vm_layout, vm, field) {
                return Ok(value);
            }
            if let Ok(value) = self.read_layout_field(eprocess_layout, eprocess, field) {
                return Ok(value);
            }

            let types = self.guest()?.ntoskrnl.types();
            for container in ["Instance", "Shared"] {
                let Some(container_field) = vm_layout.fields.get(container) else {
                    continue;
                };
                let (ParsedType::Struct(layout_name) | ParsedType::Union(layout_name)) =
                    &container_field.type_data
                else {
                    continue;
                };
                let Ok(layout) = types.layout(layout_name) else {
                    continue;
                };
                if let Ok(value) =
                    self.read_layout_field(&layout, vm + u64::from(container_field.offset), field)
                {
                    return Ok(value);
                }
            }

            let page_field = match field {
                "PagefileUsage" => Some("CommitCharge"),
                "PeakPagefileUsage" => Some("CommitChargePeak"),
                "PrivateUsage" => Some("NumberOfPrivatePages"),
                _ => None,
            };
            if let Some(page_field) = page_field {
                let pages: u64 = self.read_layout_field(eprocess_layout, eprocess, page_field)?;
                return pages.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
                    Error::DebugInfo(format!("_EPROCESS.{page_field} overflows a byte count"))
                });
            }

            Err(Error::FieldNotFound(field.to_string()))
        })())
    }

    fn debugger_data_counter(
        &self,
        address: Option<MetadataValue<VirtAddr>>,
    ) -> Option<Result<MetadataValue<u64>>> {
        address.map(|address| {
            self.context_memory()
                .read::<u64>(address.value)
                .map(|value| MetadataValue {
                    value,
                    source: address.source,
                })
        })
    }

    fn global_memory_counter(
        &self,
        symbol_name: &str,
        debugger_data_value: Option<Result<MetadataValue<u64>>>,
        getter_name: Option<&str>,
    ) -> DiagnosticMetric<u64> {
        let mut errors = Vec::new();
        match self
            .guest()
            .and_then(|guest| guest.ntoskrnl.symbol(symbol_name))
            .and_then(|symbol| symbol.read())
        {
            Ok(value) => {
                return DiagnosticMetric::available(MetadataValue {
                    value,
                    source: MetadataSource::KernelSymbol,
                });
            }
            Err(error) => errors.push(error.to_string()),
        }

        if let Some(value) = debugger_data_value {
            match value {
                Ok(value) if value.value != 0 => return DiagnosticMetric::available(value),
                Ok(_) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }

        if let Some(getter_name) = getter_name {
            match (|| -> Result<MetadataValue<u64>> {
                let guest = self.guest()?;
                let getter = guest.ntoskrnl.symbol(getter_name)?.address();
                let system_partition = guest.ntoskrnl.symbol("MiSystemPartition")?.address();
                read_counter_from_getter(&self.context_memory(), getter, system_partition)
            })() {
                Ok(value) => return DiagnosticMetric::available(value),
                Err(error) => errors.push(error.to_string()),
            }
        }

        DiagnosticMetric::unavailable(errors)
    }

    /// Build a bounded memory-use summary from exported memory-manager counters
    /// and per-process `_EPROCESS.Vm` fields.  It never scans physical memory or
    /// walks every VAD.
    pub fn memory_use_summary(&self, process_limit: usize) -> Result<SystemMemorySummary> {
        let process_limit = process_limit.clamp(1, 256);
        let all_processes = self.matching_processes(None)?;
        let process_count = all_processes.len();
        let guest = self.guest()?;
        let types = guest.ntoskrnl.types();
        let eprocess_layout = types.layout("_EPROCESS")?;
        let vm_field = eprocess_layout
            .fields
            .get("Vm")
            .ok_or_else(|| Error::FieldNotFound("Vm".to_string()))?;
        let vm_name = match &vm_field.type_data {
            ParsedType::Struct(name) | ParsedType::Union(name) => name,
            _ => {
                return Err(Error::FieldTypeMismatch(
                    "Vm".to_string(),
                    "embedded struct".to_string(),
                ));
            }
        };
        let vm_layout = types.layout(vm_name)?;
        let processes = all_processes
            .into_iter()
            .take(process_limit)
            .map(|process| ProcessMemoryUsage {
                virtual_size: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "VirtualSize",
                ),
                peak_virtual_size: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PeakVirtualSize",
                ),
                working_set_size: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "WorkingSetSize",
                ),
                peak_working_set_size: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PeakWorkingSetSize",
                ),
                pagefile_usage: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PagefileUsage",
                ),
                peak_pagefile_usage: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PeakPagefileUsage",
                ),
                private_usage: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PrivateUsage",
                ),
                process,
            })
            .collect();
        let debugger_data = self.debugger_data();
        Ok(SystemMemorySummary {
            physical_pages: self.global_memory_counter(
                "MmNumberOfPhysicalPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_number_of_physical_pages_address),
                ),
                Some("MmGetNumberOfPhysicalPages"),
            ),
            available_pages: self.global_memory_counter(
                "MmAvailablePages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_available_pages_address),
                ),
                Some("MmGetAvailablePages"),
            ),
            committed_pages: self.global_memory_counter(
                "MmTotalCommittedPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_committed_pages_address),
                ),
                Some("MmGetTotalCommittedPages"),
            ),
            commit_limit_pages: self.global_memory_counter(
                "MmTotalCommitLimit",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_commit_limit_address),
                ),
                Some("MmGetTotalCommitLimit"),
            ),
            // KDBG exposes the configured paged-pool virtual range, not current
            // usage, so it is intentionally not substituted here.
            paged_pool_pages: self.global_memory_counter("MmSizeOfPagedPoolInPages", None, None),
            // KDBG exposes the configured maximum nonpaged-pool size, not the
            // current usage requested here, so it is intentionally not substituted.
            nonpaged_pool_bytes: self.global_memory_counter(
                "MmSizeOfNonPagedPoolInBytes",
                None,
                None,
            ),
            processes,
            process_count,
            truncated: process_count > process_limit,
        })
    }

    /// Classify `address`: which loaded module (and PE section) it falls in, or
    /// which process VAD region, else unknown. The shared backend for the REPL
    /// `address` command, the MCP tool, and the SDK.
    pub fn describe_address(&self, address: VirtAddr) -> Result<AddressDescription> {
        let dtb = self.current_dtb();
        let is_kernel = address.0 >= 0xffff_0000_0000_0000;

        // 1. Loaded module containment (kernel list for kernel VAs, else the
        // current scope's user modules).
        let modules = if is_kernel {
            self.kernel_modules()
        } else {
            self.modules()
        };
        if let Ok(mods) = modules
            && let Some(m) = mods.into_iter().find(|m| {
                address.0 >= m.base_address.0 && address.0 < m.base_address.0 + m.size as u64
            })
        {
            let memory = self.current_process()?.memory();
            let section = section_name_at(&memory, m.base_address, address);
            return Ok(AddressDescription {
                address,
                dtb,
                kind: if is_kernel {
                    "kernel-module"
                } else {
                    "user-image"
                },
                module: Some(AddressModule {
                    name: m.name,
                    base: m.base_address,
                    size: m.size,
                    offset: address.0 - m.base_address.0,
                }),
                section,
                va_type: None,
                region: None,
            });
        }

        // 2. Kernel dynamic-VA region (pool, stacks, PTEs, cache, ...) via the
        // MM SystemVaType map.
        if is_kernel && let Some(va_type) = self.kernel_va_region(address) {
            return Ok(AddressDescription {
                address,
                dtb,
                kind: "kernel-region",
                module: None,
                section: None,
                va_type: Some(va_type),
                region: None,
            });
        }

        // 3. Process VAD region (when attached to a process).
        if let Some(p) = self.current_process_info.as_ref()
            && let Ok(regions) = self.enumerate_vad_regions_for_process_info(p)
            && let Some(r) = regions
                .into_iter()
                .find(|r| address.0 >= r.start.0 && address.0 < r.end.0)
        {
            let kind = match r.private_memory {
                Some(true) => "private",
                _ => "mapped",
            };
            return Ok(AddressDescription {
                address,
                dtb,
                kind,
                module: None,
                section: None,
                va_type: None,
                region: Some(r),
            });
        }

        Ok(AddressDescription {
            address,
            dtb,
            kind: "unknown",
            module: None,
            section: None,
            va_type: None,
            region: None,
        })
    }

    /// Classify a kernel dynamic-VA address via the MM `SystemVaType` map:
    /// `chunk = (va - MmSystemRangeStart) / granularity`, where the granularity
    /// is the kernel half divided into the 256-entry map. Returns the
    /// `MI_SYSTEM_VA_TYPE` name (sans `MiVa` prefix), read from the PDB enum so
    /// it adapts per build. `MiVisibleState` is a pointer to `_MI_VISIBLE_STATE`.
    fn kernel_va_region(&self, address: VirtAddr) -> Option<String> {
        let ntos = &self.guest.as_ref()?.ntoskrnl;
        let range_start: VirtAddr = ntos.symbol("MmSystemRangeStart").ok()?.read().ok()?;
        if address.0 < range_start.0 {
            return None;
        }
        // Kernel-half size / 256 (512GB on 4-level, 256TB on 5-level).
        let granularity = range_start.0.wrapping_neg() / 256;
        if granularity == 0 {
            return None;
        }
        let chunk = (address.0 - range_start.0) / granularity;
        if chunk >= 256 {
            return None;
        }

        let vs: VirtAddr = ntos.symbol("MiVisibleState").ok()?.read().ok()?;
        let type_off = ntos
            .types()
            .layout("_MI_VISIBLE_STATE")
            .ok()?
            .field_offset("SystemVaType")
            .ok()?;
        let type_byte: u8 = ntos.memory().read(vs + type_off + chunk).ok()?;

        let variants = self
            .symbols
            .find_enum_across_modules(ntos.dtb(), "_MI_SYSTEM_VA_TYPE")?;
        let name = variants
            .into_iter()
            .find(|(_, v)| *v == type_byte as i64)
            .map(|(n, _)| n)?;
        Some(name.strip_prefix("MiVa").unwrap_or(&name).to_string())
    }

    pub fn enumerate_vad_regions_for_process_info(
        &self,
        process: &ProcessInfo,
    ) -> Result<Vec<MemoryRegionInfo>> {
        let guest = self.guest()?;
        let memory = self.address_space(process.dtb);
        let types = guest.ntoskrnl.types_in(process.dtb);
        let eprocess_layout = guest.ntoskrnl.types().layout("_EPROCESS")?;
        let vad_root_base = process.eprocess_va + eprocess_layout.field_offset("VadRoot")?;
        let root = self.read_vad_root(process.dtb, vad_root_base)?;
        if root.is_zero() {
            return Ok(Vec::new());
        }

        let vad_layout = types
            .layout("_MMVAD_SHORT")
            .or_else(|_| types.layout("_MMVAD"))?;
        let vad_node_offset = vad_layout.field_offset("VadNode").unwrap_or(0);
        let node_layout = types.layout("_RTL_BALANCED_NODE")?;
        let left_offset = node_layout.field_offset("Left").unwrap_or(0);
        let right_offset = node_layout.field_offset("Right").unwrap_or(8);
        let flags_layout = types.layout("_MMVAD_FLAGS").ok();
        let modules = guest.process_modules(process).unwrap_or_default();

        let mut regions = Vec::new();
        let mut stack = vec![(root, 0usize)];
        let mut visited = HashSet::new();

        while let Some((node, level)) = stack.pop() {
            if node.is_zero() || !visited.insert(node.0) || visited.len() > 65536 {
                continue;
            }

            let left = Self::canonical_vad_link(memory.read::<VirtAddr>(node + left_offset)?);
            let right = Self::canonical_vad_link(memory.read::<VirtAddr>(node + right_offset)?);
            if !right.is_zero() {
                stack.push((right, level.saturating_add(1)));
            }
            if !left.is_zero() {
                stack.push((left, level.saturating_add(1)));
            }

            let vad = node - vad_node_offset;
            if let Some(region) = Self::read_vad_region(
                &memory,
                &vad_layout,
                flags_layout.as_deref(),
                node,
                level,
                vad,
                &modules,
            ) {
                regions.push(region);
            }
        }

        regions.sort_by_key(|region| region.start.0);
        Ok(regions)
    }

    fn read_vad_root(&self, dtb: Dtb, vad_root_base: VirtAddr) -> Result<VirtAddr> {
        let memory = self.address_space(dtb);
        let types = self.guest()?.ntoskrnl.types_in(dtb);

        if let Ok(tree_layout) = types.layout("_RTL_AVL_TREE")
            && let Ok(root_offset) = tree_layout.field_offset("Root")
        {
            let root: VirtAddr = memory.read(vad_root_base + root_offset)?;
            return Ok(Self::canonical_vad_link(root));
        }

        let root: VirtAddr = memory.read(vad_root_base)?;
        Ok(Self::canonical_vad_link(root))
    }

    fn canonical_vad_link(link: VirtAddr) -> VirtAddr {
        VirtAddr(link.0 & !0xf)
    }

    fn read_integer_field(
        memory: &impl MemoryOps<VirtAddr>,
        layout: &TypeInfo,
        base: VirtAddr,
        field: &str,
    ) -> Option<u64> {
        let info = layout.fields.get(field)?;
        let address = base + info.offset as u64;
        match info.size {
            1 => memory.read::<u8>(address).ok().map(u64::from),
            2 => memory.read::<u16>(address).ok().map(u64::from),
            4 => memory.read::<u32>(address).ok().map(u64::from),
            8 => memory.read::<u64>(address).ok(),
            _ => None,
        }
    }

    fn bitfield_value(layout: &TypeInfo, field: &str, raw: u64) -> Option<u64> {
        let info = layout.fields.get(field)?;
        let ParsedType::Bitfield { pos, len, .. } = info.type_data else {
            return None;
        };
        let mask = if len >= 64 {
            u64::MAX
        } else {
            (1u64 << len) - 1
        };
        Some((raw >> pos) & mask)
    }

    fn vad_flags_base_offset(vad_layout: &TypeInfo) -> Option<u64> {
        vad_layout
            .field_offset("u")
            .or_else(|_| vad_layout.field_offset("u1"))
            .or_else(|_| vad_layout.field_offset("VadFlags"))
            .ok()
    }

    fn read_vad_region(
        memory: &impl MemoryOps<VirtAddr>,
        vad_layout: &TypeInfo,
        flags_layout: Option<&TypeInfo>,
        node_address: VirtAddr,
        level: usize,
        vad: VirtAddr,
        modules: &[ModuleInfo],
    ) -> Option<MemoryRegionInfo> {
        let start_low = Self::read_integer_field(memory, vad_layout, vad, "StartingVpn")?;
        let end_low = Self::read_integer_field(memory, vad_layout, vad, "EndingVpn")?;
        let start_high =
            Self::read_integer_field(memory, vad_layout, vad, "StartingVpnHigh").unwrap_or(0);
        let end_high =
            Self::read_integer_field(memory, vad_layout, vad, "EndingVpnHigh").unwrap_or(0);
        let start_vpn = start_low | (start_high << 32);
        let end_vpn = end_low | (end_high << 32);
        let start = VirtAddr(start_vpn.checked_shl(12)?);
        let end = VirtAddr(end_vpn.checked_add(1)?.checked_shl(12)?);

        let flags = Self::vad_flags_base_offset(vad_layout)
            .and_then(|offset| memory.read::<u32>(vad + offset).ok())
            .map(u64::from);
        let protection = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "Protection", raw));
        let vad_type = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "VadType", raw));
        let private_memory = flags.zip(flags_layout).and_then(|(raw, layout)| {
            Self::bitfield_value(layout, "PrivateMemory", raw).map(|v| v != 0)
        });
        let commit_charge = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "CommitCharge", raw));
        let details = modules
            .iter()
            .find(|module| {
                module.base_address.0 >= start.0 && module.base_address.0 < end.0
                    || start.0 >= module.base_address.0 && start.0 < module.end_address().0
            })
            .map(|module| module.name.clone());

        Some(MemoryRegionInfo {
            node_address,
            level,
            start,
            end,
            protection,
            vad_type,
            private_memory,
            commit_charge,
            details,
        })
    }

    pub fn pte_traverse(&self, address: VirtAddr) -> Result<PteWalk> {
        // Walk through the current inspection address space so user VAs resolve
        // through the attached process's tables (not the kernel's). MmPteBase is
        // a kernel VA valid in any process context (the recursive PML4 slot).
        let memory = self.current_process()?.memory();
        let dtb = self.current_dtb();

        let pte_base: VirtAddr = self.guest()?.ntoskrnl.symbol("MmPteBase")?.read()?;
        let pde_base = pte_base + (pte_base.0 >> 9 & 0x7FFFFFFFFF);
        let ppe_base = pde_base + (pde_base.0 >> 9 & 0x3FFFFFFF);
        let pxe_base = ppe_base + (ppe_base.0 >> 9 & 0x1FFFFF);

        let pxe_address = VirtAddr(pxe_base.0 + (((address.0 >> 39) & 0x1FF) << 3));
        let ppe_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 30) << 3) + ppe_base.0);

        let pxe_value: PageTableEntry = memory.read(pxe_address)?;
        let ppe_value: PageTableEntry = memory.read(ppe_address)?;

        let pxe = PteLevel {
            name: "PXE".into(),
            address: pxe_address,
            value: pxe_value,
        };
        let ppe = PteLevel {
            name: "PPE".into(),
            address: ppe_address,
            value: ppe_value,
        };

        if ppe_value.is_large_page() {
            return Ok(PteWalk {
                address,
                dtb,
                pxe,
                ppe,
                pde: None,
                pte: None,
            });
        }

        let pde_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 21) << 3) + pde_base.0);
        let pde_value: PageTableEntry = memory.read(pde_address)?;
        let pde = PteLevel {
            name: "PDE".into(),
            address: pde_address,
            value: pde_value,
        };

        if pde_value.is_large_page() {
            return Ok(PteWalk {
                address,
                dtb,
                pxe,
                ppe,
                pde: Some(pde),
                pte: None,
            });
        }

        let pte_address = VirtAddr(((address.0 & 0xFFFFFFFFFFFF) >> 12) << 3) + pte_base.0;
        let pte_value: PageTableEntry = memory.read(pte_address)?;
        let pte = PteLevel {
            name: "PTE".into(),
            address: pte_address,
            value: pte_value,
        };

        Ok(PteWalk {
            address,
            dtb,
            pxe,
            ppe,
            pde: Some(pde),
            pte: Some(pte),
        })
    }
}

impl fmt::Display for PteLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = format!("pfn {:<5x} {:>11}", self.value.pfn(), self.value.flags());
        write!(
            f,
            "{} at {:X}\ncontains {:016X}\n{}",
            self.name,
            self.address,
            Value(self.value.0),
            flags
        )
    }
}
