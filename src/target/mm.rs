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
use crate::types::{Dtb, PageTableEntry, PageTableLevel, PteAttributes, VirtAddr};

mod lookaside;
mod mdl;
mod paging;
mod pfn;
mod pool;
mod sysptes;
mod vad;
mod vm;
mod vprot;

pub use vprot::{memory_state_name, memory_type_name, page_protection_name};

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
    pub attributes: PteAttributes,
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
    /// Nothing maps the page here; `physical` is the frame its section PTE
    /// holds, a page of a shared image or file view the process has not
    /// touched. It cannot be written either.
    pub section: bool,
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

/// `!poolval`: the blocks of one pool page and the first inconsistency
/// among their headers, `None` when the page is consistent.
#[derive(Debug, Clone)]
pub struct PoolValidationDetail {
    pub address: VirtAddr,
    pub page: VirtAddr,
    pub region: Option<PoolRegionDetail>,
    /// `chained` (the classic pool) or `segment heap`.
    pub layout: String,
    pub blocks: Vec<PoolBlockDetail>,
    pub problem: Option<PoolProblem>,
}

/// A pool header inconsistency: the header it is found at and what is wrong.
#[derive(Debug, Clone)]
pub struct PoolProblem {
    pub header: VirtAddr,
    pub message: String,
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
    /// Pages the range spans, mapped or not.
    pub pages: u64,
    /// Mapped pages read.
    pub scanned_pages: u64,
    /// The mapped page the scan stopped at, unread, when the match bound or
    /// an interrupt ended it early.
    pub stopped_at: Option<VirtAddr>,
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

/// A decoded `_MDL` header and the page-frame array that follows it (`!mdl`).
#[derive(Debug, Clone)]
pub struct MdlDetail {
    pub address: VirtAddr,
    pub next: VirtAddr,
    /// `Size`: bytes of header plus PFN array the allocation holds.
    pub size: u16,
    pub flags: u16,
    /// `MDL_*` names of the set `flags` bits, low bit first.
    pub flag_names: Vec<&'static str>,
    pub process: VirtAddr,
    pub mapped_system_va: VirtAddr,
    pub start_va: VirtAddr,
    pub byte_count: u32,
    pub byte_offset: u32,
    /// Pages the described buffer spans (`ADDRESS_AND_SIZE_TO_SPAN_PAGES`).
    pub spanned_pages: u64,
    /// PFN slots `Size` leaves after the header.
    pub capacity: u64,
    /// Where the PFN array starts (just past the header).
    pub pfn_array: VirtAddr,
    pub pfns: Vec<u64>,
    /// Fewer PFNs are listed than the buffer spans: a smaller count was
    /// requested.
    pub truncated: bool,
}

/// A run of free system PTEs: clear bits in an allocation bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemPteRun {
    /// Address of the run's first PTE.
    pub pte: VirtAddr,
    /// Virtual address that PTE maps.
    pub va: Option<VirtAddr>,
    /// Length in PTEs.
    pub ptes: u64,
}

/// One `_MI_SYSTEM_PTE_TYPE` bitmap allocator (`!sysptes`). Counts are in
/// PTEs; the bitmap may cover several PTEs per bit (`ptes_per_bit`).
#[derive(Debug, Clone)]
pub struct SystemPteTypeDetail {
    /// The `MiState` path of the allocator, e.g. `Vs.SystemPteInfo`.
    pub name: String,
    pub address: VirtAddr,
    /// `VaType`'s `_MI_SYSTEM_VA_TYPE` name, without the `MiVa` prefix.
    pub va_type: Option<String>,
    pub flags: u32,
    pub ptes_per_bit: u64,
    pub base_pte: VirtAddr,
    /// Virtual address `base_pte` maps; `None` without `MmPteBase`.
    pub base_va: Option<VirtAddr>,
    pub bitmap: VirtAddr,
    pub bitmap_bits: u64,
    /// `TotalSystemPtes`: PTEs made available so far; the rest of the
    /// bitmap is reserved (its bits set) until the allocator expands.
    pub total: u64,
    /// `TotalFreeSystemPtes`.
    pub free: u64,
    pub failures: u32,
    /// Free PTEs counted from the bitmap's clear bits. It differs from
    /// `free` only when the target allocated between the two reads.
    pub bitmap_free: u64,
    /// Bitmap bytes that could not be read (counted as allocated).
    pub unreadable_bitmap_bytes: u64,
    /// Bits past the bound on how much of one bitmap is read (a corrupt
    /// `SizeOfBitMap`); they are left out of every count.
    pub unscanned_bitmap_bits: u64,
    pub free_run_count: u64,
    pub largest_free_run: u64,
    /// The free runs in address order, when listing was requested; bounded.
    pub free_runs: Vec<SystemPteRun>,
    pub free_runs_truncated: bool,
    /// `TrackingBitmap` is allocated: the kernel tracks which driver
    /// mapped each PTE (`TrackPtes`).
    pub tracking: bool,
}

/// Every system-PTE bitmap allocator in `MiState` (`!sysptes`).
#[derive(Debug, Clone)]
pub struct SystemPtesDetail {
    pub flags: u64,
    pub types: Vec<SystemPteTypeDetail>,
    pub total: u64,
    pub free: u64,
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

pub(crate) fn find_mi_state_fields(target: &Target, predicates: &[&str]) -> Vec<(String, u64)> {
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

/// `!vprot`: what `VirtualQuery` reports for an address. `state`, `protect`,
/// `allocation_protect`, and `kind` are the `MEM_*` and `PAGE_*` values.
#[derive(Debug, Clone)]
pub struct VprotDetail {
    pub process: ProcessInfo,
    pub address: VirtAddr,
    pub base_address: VirtAddr,
    /// The VAD's start; zero for free memory.
    pub allocation_base: VirtAddr,
    pub allocation_protect: u32,
    /// From `base_address` to the first page whose state or protection
    /// differs, or the end of the VAD.
    pub region_size: u64,
    pub state: u32,
    pub protect: u32,
    pub kind: u32,
    /// The VAD node, `None` for free memory.
    pub vad: Option<VirtAddr>,
    /// The scan stopped at its bound or an unreadable page table before the
    /// region ended, so `region_size` is a lower bound.
    pub truncated: bool,
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
    pub attributes: PteAttributes,
}

pub struct PteWalk {
    pub address: VirtAddr,
    /// The address space the walk was performed in (the attached process DTB
    /// when attached, else the kernel), so callers know what was walked.
    pub dtb: Dtb,
    pub pxe: PteLevel,
    /// The levels below the PXE, each present only when the one above it
    /// points at a table.
    pub ppe: Option<PteLevel>,
    pub pde: Option<PteLevel>,
    pub pte: Option<PteLevel>,
}

impl PteWalk {
    /// The levels reached, top down.
    pub fn levels(&self) -> impl Iterator<Item = &PteLevel> {
        [
            Some(&self.pxe),
            self.ppe.as_ref(),
            self.pde.as_ref(),
            self.pte.as_ref(),
        ]
        .into_iter()
        .flatten()
    }
}
