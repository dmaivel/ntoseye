//! Structured memory-manager inspectors shared by the REPL, Python SDK, and MCP.
//!
//! The root holds the public result types; each submodule adds the `Target`
//! inspectors and private helpers for one area of the memory manager.

use std::collections::HashSet;

use super::{DiagnosticMetric, DiagnosticValue, Target};
use crate::guest::ProcessInfo;
use crate::layout::{ParsedType, TypeInfo};
use crate::memory::PAGE_SIZE;
use crate::target::pool::{PoolUsageRow, kernel_symbol_address, read_pool_field};
use crate::types::{Dtb, PageTableEntry, PageTableLevel, VirtAddr};

mod lookaside;
mod paging;
mod pfn;
mod pool;
mod vad;
mod vm;

const MAX_MI_FIELDS: usize = 64;

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
    pub level: PageTableLevel,
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
    for (name, field) in ti.fields_in_order() {
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

#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub node_address: VirtAddr,
    pub level: usize,
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub protection: Option<VadProtection>,
    pub vad_type: Option<VadType>,
    pub private_memory: Option<bool>,
    pub commit_charge: Option<u64>,
    pub details: Option<String>,
}

impl MemoryRegionInfo {
    pub fn size(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }
}

/// `_MMVAD_FLAGS.Protection`: an index into the memory manager's protection
/// table, not a `PAGE_*` mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadProtection {
    NoAccess,
    ReadOnly,
    Execute,
    ExecuteRead,
    ReadWrite,
    WriteCopy,
    ExecuteReadWrite,
    ExecuteWriteCopy,
    Unknown(u64),
}

impl VadProtection {
    pub fn from_raw(raw: u64) -> Self {
        match raw {
            0 => Self::NoAccess,
            1 => Self::ReadOnly,
            2 => Self::Execute,
            3 => Self::ExecuteRead,
            4 => Self::ReadWrite,
            5 => Self::WriteCopy,
            6 => Self::ExecuteReadWrite,
            7 => Self::ExecuteWriteCopy,
            other => Self::Unknown(other),
        }
    }

    pub fn raw(self) -> u64 {
        match self {
            Self::NoAccess => 0,
            Self::ReadOnly => 1,
            Self::Execute => 2,
            Self::ExecuteRead => 3,
            Self::ReadWrite => 4,
            Self::WriteCopy => 5,
            Self::ExecuteReadWrite => 6,
            Self::ExecuteWriteCopy => 7,
            Self::Unknown(raw) => raw,
        }
    }
}

/// `_MMVAD_FLAGS.VadType`, an `_MI_VAD_TYPE` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadType {
    None,
    DevicePhysicalMemory,
    ImageMap,
    Awe,
    WriteWatch,
    LargePages,
    RotatePhysical,
    LargePageSection,
    Unknown(u64),
}

impl VadType {
    pub fn from_raw(raw: u64) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::DevicePhysicalMemory,
            2 => Self::ImageMap,
            3 => Self::Awe,
            4 => Self::WriteWatch,
            5 => Self::LargePages,
            6 => Self::RotatePhysical,
            7 => Self::LargePageSection,
            other => Self::Unknown(other),
        }
    }

    pub fn raw(self) -> u64 {
        match self {
            Self::None => 0,
            Self::DevicePhysicalMemory => 1,
            Self::ImageMap => 2,
            Self::Awe => 3,
            Self::WriteWatch => 4,
            Self::LargePages => 5,
            Self::RotatePhysical => 6,
            Self::LargePageSection => 7,
            Self::Unknown(raw) => raw,
        }
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

impl ProcessMemoryUsage {
    fn from_counters(process: ProcessInfo, counter: impl Fn(&str) -> DiagnosticValue<u64>) -> Self {
        Self {
            virtual_size: counter("VirtualSize"),
            peak_virtual_size: counter("PeakVirtualSize"),
            working_set_size: counter("WorkingSetSize"),
            peak_working_set_size: counter("PeakWorkingSetSize"),
            pagefile_usage: counter("PagefileUsage"),
            peak_pagefile_usage: counter("PeakPagefileUsage"),
            private_usage: counter("PrivateUsage"),
            process,
        }
    }
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
    pub level: PageTableLevel,
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
