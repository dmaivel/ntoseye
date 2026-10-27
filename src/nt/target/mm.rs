//! Structured memory-manager inspectors shared by the REPL, Python SDK, and MCP.
//!
//! The root holds the public result types; each submodule adds the `Target`
//! inspectors and private helpers for one area of the memory manager.

use std::collections::HashSet;

use ntoseye_macros::record;

use super::{DiagnosticMetric, DiagnosticValue, Target};
use crate::base::memory::{NonResident, PAGE_SIZE};
use crate::base::types::{Dtb, PageTableLevel, PteAttributes, VirtAddr};
use crate::nt::guest::ProcessInfo;
use crate::nt::layout::{ParsedType, TypeInfo};
use crate::nt::target::pool::{PoolUsageRow, kernel_symbol_address, read_pool_field, tag_string};

mod lookaside;
mod mdl;
mod paging;
mod pfn;
mod pool;
mod sysptes;
mod vad;
mod vm;
mod vprot;

pub use paging::PteSelfMap;
pub use vprot::{
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEM_RESERVE, memory_state_name,
    memory_type_name, page_protection, page_protection_name,
};

const MAX_MI_FIELDS: usize = 64;

/// A named memory-manager counter (`!vm`).
#[record]
#[derive(Debug, Clone)]
pub struct VmCounter {
    pub name: String,
    pub value: DiagnosticMetric<u64>,
    /// The unit of `value`, or `None` for a plain count.
    pub unit: Option<VmUnit>,
}

/// Pool counters and the pool fields of `MiState` (`!vm`).
#[record]
#[derive(Debug, Clone)]
pub struct VmPoolDetail {
    pub nonpaged_pool_bytes: DiagnosticMetric<u64>,
    pub nonpaged_pool_maximum: DiagnosticMetric<u64>,
    pub paged_pool_pages: DiagnosticMetric<u64>,
    /// The symbol-backed pool fields of `MiState`.
    pub fields: Vec<VmCounter>,
}

/// System PTE counters (`!vm`).
#[record]
#[derive(Debug, Clone)]
pub struct VmPteDetail {
    pub counters: Vec<VmCounter>,
}

/// Virtual-memory statistics (`!vm`). Each counter carries its own source
/// and read failure, so one that cannot be read leaves the others.
#[record]
#[derive(Debug, Clone)]
pub struct VmDetail {
    /// The system memory counters and, when requested, per-process usage.
    pub system: SystemMemorySummary,
    pub pool: VmPoolDetail,
    pub pte: VmPteDetail,
    /// Paging-file counters.
    pub page_files: Vec<VmCounter>,
    /// Whether per-process usage was requested.
    pub include_processes: bool,
}

/// What `!pfn` decodes: a page-frame number, or the frame of a physical
/// address (shifted by the page size before indexing the PFN database).
#[record(tagged)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfnSelector {
    Pfn(
        /// The page-frame number or physical address given.
        #[record(hex, rename = "value")]
        u64,
    ),
    PhysicalAddress(
        /// The page-frame number or physical address given.
        #[record(hex, rename = "value")]
        u64,
    ),
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

/// The `PageLocation` of a PFN, which is the list that holds the page.
#[record(impl)]
#[derive(Debug, Clone, Copy)]
pub struct PageLocation {
    pub value: u8,
}

#[record]
impl PageLocation {
    /// The `_MMLISTS` name (`ActiveAndValid`, `StandbyPageList`, ...).
    #[record(getter)]
    pub fn name(&self) -> &'static str {
        match self.value & 0x7 {
            0 => "ZeroedPageList",
            1 => "FreePageList",
            2 => "StandbyPageList",
            3 => "ModifiedPageList",
            4 => "ModifiedNoWritePageList",
            5 => "BadPageList",
            6 => "ActiveAndValid",
            _ => "TransitionPage",
        }
    }
}

/// The `CacheAttribute` of a PFN.
#[record(impl)]
#[derive(Debug, Clone, Copy)]
pub struct CacheAttribute {
    pub value: u8,
}

#[record]
impl CacheAttribute {
    /// The `_MI_PFN_CACHE_ATTRIBUTE` name (`MmCached`, ...).
    #[record(getter)]
    pub fn name(&self) -> &'static str {
        match self.value & 0x3 {
            0 => "MmNonCached",
            1 => "MmCached",
            2 => "MmWriteCombined",
            _ => "MmNotMapped",
        }
    }
}

/// A decoded `_MMPFN` record (`!pfn`). A member the layout lacks is decoded
/// from the record's raw bits at its known offset, so only `page_color`,
/// which has no such fallback, can be unavailable. Union members that the
/// page state does not use are `None`: the list links when the page is not
/// on a list, `share_count` and `ws_index` when the page is not active, and
/// `event` when the page is not in transition.
#[record]
#[derive(Debug, Clone)]
pub struct PfnDetail {
    pub selector: PfnSelector,
    /// The page frame number.
    #[record(hex)]
    pub pfn: u64,
    /// The `_MMPFN` record's address.
    pub record: VirtAddr,
    /// The requested physical address, for a physical-address selector.
    #[record(hex)]
    pub physical_address: Option<u64>,
    pub pte_address: VirtAddr,
    #[record(hex)]
    pub original_pte: u64,
    pub reference_count: u64,
    #[record(hex)]
    pub flink: Option<u64>,
    #[record(hex)]
    pub blink: Option<u64>,
    #[record(hex)]
    pub node_flink_low: Option<u64>,
    #[record(hex)]
    pub node_blink_low: Option<u64>,
    pub share_count: Option<u64>,
    /// The working-set index.
    #[record(hex)]
    pub ws_index: Option<u64>,
    #[record(hex)]
    pub event: Option<u64>,
    pub used_entry_count: u64,
    /// Not available if the `_MMPFN` of this build has no `PageColor`.
    pub page_color: DiagnosticValue<u64>,
    /// The PFN of the page table that holds the PTE of the page.
    #[record(hex)]
    pub pte_frame: u64,
    pub page_location: PageLocation,
    pub modified: bool,
    pub cache_attribute: CacheAttribute,
    pub priority: u8,
}

/// One page-table level of a walk (`!pte`, `!vtop`): where its entry is,
/// the entry as read, and the entry decoded at its level.
#[record]
#[derive(Debug, Clone)]
pub struct PteLevel {
    pub level: PageTableLevel,
    /// The entry's address: virtual through NT's self-map, physical in an
    /// explicit walk.
    pub address: VirtAddr,
    /// The entry as read.
    #[record(hex)]
    pub value: u64,
    pub attributes: PteAttributes,
}

/// A virtual address translated through the page tables of a DTB
/// (`!vtop`), with every level read.
#[record]
#[derive(Debug, Clone)]
pub struct VtopDetail {
    pub address: VirtAddr,
    #[record(hex)]
    pub dtb: Dtb,
    /// The levels read, top down.
    pub levels: Vec<PteLevel>,
    /// Whether the levels' addresses are physical (a walk of the tables
    /// from the DTB) rather than virtual through NT's self-map.
    pub physical_walk: bool,
    /// The physical address; `None` when the address is not mapped.
    #[record(hex)]
    pub physical: Option<u64>,
    /// Whether a large page maps it.
    pub large: bool,
    /// Whether the leaf is a transition PTE. If true, `physical` is a frame
    /// that the guest still holds, but nothing maps it here and it cannot be
    /// written.
    pub transition: bool,
    /// Whether nothing maps the page here. If true, `physical` is the frame
    /// that the page's section PTE holds, for a page of a shared image or
    /// file view that is not touched yet. It cannot be written either.
    pub section: bool,
}

/// A virtual address that maps a physical page (`!ptov`).
#[record]
#[derive(Debug, Clone)]
pub struct PtovMapping {
    pub virtual_address: VirtAddr,
    /// Whether a large page maps it.
    pub large: bool,
}

/// The virtual addresses that map a physical address (`!ptov`).
#[record]
#[derive(Debug, Clone)]
pub struct PtovDetail {
    #[record(hex)]
    pub physical: u64,
    #[record(hex)]
    pub dtb: Dtb,
    pub mappings: Vec<PtovMapping>,
    /// The number of page-table pages that the walk read.
    pub table_pages: usize,
    /// Whether the walk stopped at its limit before the end.
    pub bounded: bool,
    /// Whether an interrupt request stopped the walk.
    pub interrupted: bool,
}

/// A pool: `nonpaged` (`NonPagedPool`) or `paged` (`PagedPool`).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    #[record(rename = "nonpaged", label = "NonPagedPool")]
    NonPaged,
    #[record(label = "PagedPool")]
    Paged,
}

/// The state of a pool block: `allocated`, `free`, or `allocated_unverified`
/// (allocated, but its tag is not printable).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolBlockState {
    #[record(label = "Allocated")]
    Allocated,
    #[record(label = "Free")]
    Free,
    #[record(label = "Allocated?")]
    AllocatedUnverified,
}

/// How a pool page lays its blocks out, which decides what a consistent page
/// looks like: `chained` or `segment_heap`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolPageLayout {
    /// The classic pool: headers chain from the page start to its end, each
    /// `PreviousSize` the `BlockSize` before it, `PoolType` the POOL_TYPE + 1.
    Chained,
    /// Segment heap (Windows 10 1903 and later): `PreviousSize` is unused,
    /// variable-size blocks sit behind a 16-byte chunk header, and free
    /// chunks have no `_POOL_HEADER`.
    #[record(label = "segment heap")]
    SegmentHeap,
}

/// The unit of a [`VmCounter`] value: `pages` or `bytes`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmUnit {
    Pages,
    Bytes,
}

/// What an address belongs to (`address`): `kernel_module`, `user_image`,
/// `kernel_region`, `private`, `mapped`, or `unknown`; a memory-search match
/// may also be `physical`, `vtl1`, or `foreign` (a root outside NT and VTL1).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    #[record(label = "kernel-module")]
    KernelModule,
    #[record(label = "user-image")]
    UserImage,
    #[record(label = "kernel-region")]
    KernelRegion,
    Private,
    Mapped,
    Unknown,
    Physical,
    Vtl1,
    Foreign,
}

/// A `_POOL_HEADER` block in a pool page.
#[record]
#[derive(Debug, Clone)]
pub struct PoolBlockDetail {
    /// The pool header's address.
    pub header: VirtAddr,
    /// The address of the allocation, immediately after the header.
    pub body: VirtAddr,
    /// The block size in bytes, with the header.
    pub size: u64,
    /// The previous block's size in bytes.
    pub previous_size: u64,
    /// The header's `PoolType` bits.
    pub pool_type: u8,
    #[record(hex)]
    pub tag: u32,
    /// The tag as its four characters.
    pub tag_name: String,
    pub allocated: bool,
    /// Whether the block holds the requested address.
    pub marked: bool,
    pub state: PoolBlockState,
    /// The offset of the requested address in the block, if the block holds it.
    #[record(hex)]
    pub target_offset: Option<u64>,
}

/// A large allocation from `PoolBigPageTable`.
#[record]
#[derive(Debug, Clone)]
pub struct BigPoolDetail {
    /// The allocation's address.
    pub address: VirtAddr,
    /// The requested address.
    pub target: VirtAddr,
    /// The allocation size in bytes.
    pub size: u64,
    /// The offset of the requested address in the allocation.
    #[record(hex)]
    pub offset: u64,
    #[record(hex)]
    pub tag: u32,
    /// The tag as its four characters.
    pub tag_name: String,
    /// The address of the `PoolBigPageTable` entry.
    pub entry: VirtAddr,
    /// The entry's index in `PoolBigPageTable`.
    pub index: u64,
    pub nonpaged: bool,
    #[record(hex)]
    pub pattern: u8,
    #[record(hex)]
    pub pool_flags: u16,
    pub slush_size: u16,
}

/// The pool page holding an address (`!pool`).
#[record]
#[derive(Debug, Clone)]
pub struct PoolPageDetail {
    /// The requested address.
    pub target: VirtAddr,
    /// The page's address.
    pub page: VirtAddr,
    /// The layout of the page: its pool kind, or the reason that the page
    /// could not be decoded.
    pub page_kind: String,
    /// The pool range holding the page, when known.
    pub region: Option<PoolRegionDetail>,
    pub blocks: Vec<PoolBlockDetail>,
    /// The index in `blocks` of the block that holds the requested address.
    pub target_index: Option<usize>,
    /// The large allocation that holds the address, if the address is in one.
    pub big: Option<BigPoolDetail>,
    /// Set if the page belongs to the segment heap, whose blocks have no
    /// pool headers.
    pub segment_heap_hint: Option<String>,
    /// The nearest symbol to the address, if one resolves.
    pub near_symbol: Option<String>,
    /// The reason that no blocks were decoded, if none were.
    pub message: Option<String>,
}

/// The blocks of the pool page that holds an address, with a check of
/// header consistency (`!poolval`).
#[record(impl)]
#[derive(Debug, Clone)]
pub struct PoolValidationDetail {
    pub address: VirtAddr,
    /// The page's address.
    pub page: VirtAddr,
    /// The pool range holding the page, when known.
    pub region: Option<PoolRegionDetail>,
    pub layout: PoolPageLayout,
    pub blocks: Vec<PoolBlockDetail>,
    /// The first inconsistency found.
    pub problem: Option<PoolProblem>,
}

#[record]
impl PoolValidationDetail {
    /// Whether the headers are consistent (`problem` is `None`).
    #[record(getter)]
    pub fn valid(&self) -> bool {
        self.problem.is_none()
    }
}

/// A pool header inconsistency.
#[record]
#[derive(Debug, Clone)]
pub struct PoolProblem {
    /// The header where the problem is.
    pub header: VirtAddr,
    /// What is wrong.
    pub message: String,
}

/// A virtual pool range.
#[record]
#[derive(Debug, Clone)]
pub struct PoolRegionDetail {
    pub name: String,
    pub start: VirtAddr,
    /// The end of the range (exclusive).
    pub end: VirtAddr,
}

/// Pool usage by tag, from the pool tracker (`!poolused`).
#[record]
#[derive(Debug, Clone)]
pub struct PoolUsageDetail {
    pub rows: Vec<PoolUsageRow>,
    /// Whether more tags matched than are listed.
    pub rows_truncated: bool,
    /// The read status of the pool tracker table.
    pub tracker_status: String,
    /// The read status of the big-pool table.
    pub big_status: String,
    pub sort: PoolUsageSort,
    /// The tag pattern that filters the rows, if any.
    pub tag_filter: Option<String>,
}

/// The order of `!poolused`'s rows: `tag`, or `nonpaged`/`paged` bytes
/// (largest first).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolUsageSort {
    Tag,
    #[record(rename = "nonpaged")]
    NonPagedBytes,
    #[record(rename = "paged")]
    PagedBytes,
}

/// A pool allocation with the search tag (`!poolfind`).
#[record]
#[derive(Debug, Clone)]
pub struct PoolFindMatch {
    /// Where the search found the allocation: a pool range scan or the big-pool
    /// table.
    pub source: String,
    pub address: VirtAddr,
    /// Size in bytes.
    pub size: u64,
    #[record(hex)]
    pub tag: u32,
    /// The tag as its four characters.
    pub tag_name: String,
    pub allocated: bool,
    pub state: PoolBlockState,
    /// The pool, when known.
    pub pool_type: Option<PoolType>,
    /// The `PoolBigPageTable` entry, for a big-pool match.
    pub table_entry: Option<VirtAddr>,
    /// The `PoolBigPageTable` index, for a big-pool match.
    pub index: Option<u64>,
}

/// A pool-tag search (`!poolfind`).
#[record]
#[derive(Debug, Clone)]
pub struct PoolFindDetail {
    /// The searched tag.
    pub tag: String,
    /// The pool that the search was limited to, if any.
    pub pool_type: Option<PoolType>,
    pub matches: Vec<PoolFindMatch>,
    /// The number of matches found, including those past the listing limit.
    pub found: usize,
    pub ranges: Vec<PoolFindRange>,
    /// The read status of the big-pool table, if the search included it.
    pub big_status: Option<String>,
    /// Whether more matches were found than are listed.
    pub truncated: bool,
    /// Whether an interrupt request stopped the search.
    pub interrupted: bool,
}

/// How far `!poolfind` scanned one virtual pool range.
#[record]
#[derive(Debug, Clone)]
pub struct PoolFindRange {
    pub name: String,
    pub start: VirtAddr,
    /// The end of the range (exclusive).
    pub end: VirtAddr,
    /// The number of pages in the range, mapped or not.
    pub pages: u64,
    /// The number of mapped pages that the scan read.
    pub scanned_pages: u64,
    /// The mapped page where the scan stopped, if the match limit or an
    /// interrupt stopped it early. The scan did not read this page.
    pub stopped_at: Option<VirtAddr>,
}

/// A pool tag.
#[record(impl)]
#[derive(Debug, Clone, Copy)]
pub struct PoolTag {
    #[record(hex)]
    pub value: u32,
}

#[record]
impl PoolTag {
    /// The tag as its four characters.
    #[record(getter)]
    pub fn name(&self) -> String {
        tag_string(self.value)
    }
}

/// A decoded `_GENERAL_LOOKASIDE` list (`!lookaside`). Each counter is
/// read on its own, because stripped PDBs often omit some members.
#[record]
#[derive(Debug, Clone)]
pub struct LookasideDetail {
    pub address: VirtAddr,
    /// The position in the list walk.
    pub index: usize,
    pub tag: DiagnosticValue<PoolTag>,
    /// The allocation size in bytes.
    pub size: DiagnosticValue<u64>,
    pub depth: DiagnosticValue<u64>,
    pub total_allocates: DiagnosticValue<u64>,
    pub total_frees: DiagnosticValue<u64>,
    pub allocate_misses: DiagnosticValue<u64>,
}

/// The system lookaside lists (`!lookaside`).
#[record]
#[derive(Debug, Clone)]
pub struct LookasideListsDetail {
    pub records: Vec<LookasideDetail>,
    pub nonpaged_count: usize,
    pub paged_count: usize,
    /// How the nonpaged list walk ended.
    pub nonpaged_termination: String,
    /// How the paged list walk ended.
    pub paged_termination: String,
    /// Whether an interrupt request stopped the walk.
    pub interrupted: bool,
    /// Whether the walk stopped at its limit before the end.
    pub truncated: bool,
}

/// A decoded `_MDL` header and the page-frame array that follows it
/// (`!mdl`).
#[record]
#[derive(Debug, Clone)]
pub struct MdlDetail {
    pub address: VirtAddr,
    pub next: VirtAddr,
    /// The size in bytes of the header and the PFN array in the allocation.
    pub size: u16,
    #[record(hex)]
    pub flags: u16,
    /// The `MDL_*` names of the set `flags` bits, low bit first.
    pub flag_names: Vec<&'static str>,
    pub process: VirtAddr,
    pub mapped_system_va: VirtAddr,
    pub start_va: VirtAddr,
    pub byte_count: u32,
    #[record(hex)]
    pub byte_offset: u32,
    /// The number of pages that the described buffer spans
    /// (`ADDRESS_AND_SIZE_TO_SPAN_PAGES`).
    pub spanned_pages: u64,
    /// The number of PFN slots that `size` leaves after the header.
    pub capacity: u64,
    /// The start of the PFN array, immediately after the header.
    pub pfn_array: VirtAddr,
    #[record(hex)]
    pub pfns: Vec<u64>,
    /// Whether the list has fewer PFNs than the buffer spans, which happens
    /// when a smaller count was requested.
    pub truncated: bool,
}

/// A run of free system PTEs, which is a sequence of clear bits in an
/// allocation bitmap.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemPteRun {
    /// The address of the first PTE in the run.
    pub pte: VirtAddr,
    /// The virtual address that this PTE maps, if `MmPteBase` is known.
    pub va: Option<VirtAddr>,
    /// The length in PTEs.
    pub ptes: u64,
}

/// One `_MI_SYSTEM_PTE_TYPE` bitmap allocator (`!sysptes`). Counts are in
/// PTEs; the bitmap may cover several PTEs per bit (`ptes_per_bit`).
#[record(impl)]
#[derive(Debug, Clone)]
pub struct SystemPteTypeDetail {
    /// The `MiState` path of the allocator, e.g. `Vs.SystemPteInfo`.
    pub name: String,
    pub address: VirtAddr,
    /// The `_MI_SYSTEM_VA_TYPE` name, without the `MiVa` prefix.
    pub va_type: Option<String>,
    #[record(hex)]
    pub flags: u32,
    /// The number of PTEs that each bitmap bit covers.
    pub ptes_per_bit: u64,
    pub base_pte: VirtAddr,
    /// The virtual address that `base_pte` maps. `None` without `MmPteBase`.
    pub base_va: Option<VirtAddr>,
    pub bitmap: VirtAddr,
    pub bitmap_bits: u64,
    /// `TotalSystemPtes`, the number of PTEs made available so far; the rest
    /// of the bitmap is reserved (its bits set) until the allocator expands.
    pub total: u64,
    /// `TotalFreeSystemPtes`.
    pub free: u64,
    pub failures: u32,
    /// The free PTEs, counted from the clear bits of the bitmap, which the
    /// allocator hands out from. It differs from `free` when the target
    /// allocated between the two reads, or where the counter does not hold:
    /// Windows 11 22631 ARM64 keeps one below zero.
    pub bitmap_free: u64,
    /// The bitmap bytes that could not be read, which count as allocated.
    pub unreadable_bitmap_bytes: u64,
    /// The bits past the read limit for one bitmap (a corrupt
    /// `SizeOfBitMap`), which no count includes.
    pub unscanned_bitmap_bits: u64,
    pub free_run_count: u64,
    pub largest_free_run: u64,
    /// The free runs in address order, if the list was requested; bounded.
    pub free_runs: Vec<SystemPteRun>,
    pub free_runs_truncated: bool,
    /// Whether the kernel tracks which driver mapped each PTE (`TrackPtes`).
    pub tracking: bool,
}

#[record]
impl SystemPteTypeDetail {
    /// `total` minus `free`.
    #[record(getter)]
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }
}

impl SystemPteTypeDetail {
    /// The free PTEs: counted from the bitmap where it was read whole, else
    /// `TotalFreeSystemPtes`.
    pub fn counted_free(&self) -> u64 {
        if self.unreadable_bitmap_bytes == 0 && self.unscanned_bitmap_bits == 0 {
            self.bitmap_free
        } else {
            self.free
        }
    }
}

/// Every system-PTE bitmap allocator in `MiState` (`!sysptes`). Counts
/// are in PTEs.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct SystemPtesDetail {
    pub types: Vec<SystemPteTypeDetail>,
    pub total: u64,
    /// The free PTEs of every allocator: counted from its bitmap where the
    /// bitmap was read whole, else its `TotalFreeSystemPtes`.
    pub free: u64,
}

#[record]
impl SystemPtesDetail {
    /// `total` minus `free`.
    #[record(getter)]
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }
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

/// One VAD region of a process (`!vad`, `proc.regions` items, address
/// context).
#[record(impl)]
pub struct MemoryRegionInfo {
    /// The VAD's node in the process's VAD tree.
    pub node_address: VirtAddr,
    /// The node's depth in the VAD tree.
    pub level: usize,
    /// The first address of the region.
    pub start: VirtAddr,
    /// The end of the region (exclusive).
    pub end: VirtAddr,
    #[record(skip)]
    pub protection: Option<VadProtection>,
    #[record(skip)]
    pub vad_type: Option<VadType>,
    /// Whether the region is private (not shared or mapped).
    pub private_memory: Option<bool>,
    /// The committed pages that are charged to the region.
    pub commit_charge: Option<u64>,
    /// A description: the mapped file.
    pub details: Option<String>,
}

#[record]
impl MemoryRegionInfo {
    /// Size in bytes.
    #[record(getter)]
    pub fn size(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }

    /// The VAD protection value, if known. It is an index into the memory
    /// manager's protection table, not a `PAGE_*` mask.
    #[record(getter, rename = "protection")]
    pub fn protection_value(&self) -> Option<u64> {
        self.protection.map(VadProtection::raw)
    }

    /// The VAD type (`_MI_VAD_TYPE`), when known.
    #[record(getter, rename = "vad_type")]
    pub fn vad_type_value(&self) -> Option<u64> {
        self.vad_type.map(VadType::raw)
    }
}

/// `_MMVAD_FLAGS.Protection`: a 5-bit MM protection value, whose low three
/// bits index the access and whose 0x8 and 0x10 bits add no caching, guard,
/// or (both) write combining; any value with no access bits is no access
/// (`MmProtectToValue`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VadProtection(u64);

impl VadProtection {
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub fn raw(self) -> u64 {
        self.0
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

/// The data that `VirtualQuery` reports for an address (`!vprot`). Each
/// `MEM_*`/`PAGE_*` value has its name next to it.
#[record(impl)]
pub struct MemoryBasicInformation {
    /// The process whose address space holds the address; `None` on a
    /// user-mode minidump, whose memory-info list gives the region.
    pub process: Option<ProcessInfo>,
    pub address: VirtAddr,
    pub base_address: VirtAddr,
    /// The VAD's start; zero for free memory.
    pub allocation_base: VirtAddr,
    #[record(hex)]
    pub allocation_protect: u32,
    /// The number of bytes from `base_address` to the first page with a
    /// different state or protection, or to the end of the VAD.
    #[record(hex)]
    pub region_size: u64,
    #[record(hex)]
    pub state: u32,
    #[record(hex)]
    pub protect: u32,
    /// The `MEM_*` type (`MEMORY_BASIC_INFORMATION.Type`).
    #[record(hex, rename = "type")]
    pub kind: u32,
    /// The VAD node; `None` for free memory.
    pub vad: Option<VirtAddr>,
    /// Whether the scan stopped before the end of the region, at its limit
    /// or at a page table that it cannot read. If true, `region_size` is a
    /// lower bound.
    pub truncated: bool,
}

#[record]
impl MemoryBasicInformation {
    #[record(getter)]
    pub fn allocation_protect_name(&self) -> String {
        page_protection_name(self.allocation_protect)
    }

    #[record(getter)]
    pub fn state_name(&self) -> &'static str {
        memory_state_name(self.state)
    }

    #[record(getter)]
    pub fn protect_name(&self) -> String {
        page_protection_name(self.protect)
    }

    #[record(getter)]
    pub fn type_name(&self) -> &'static str {
        memory_type_name(self.kind)
    }
}

/// The loaded module that contains an address.
#[record]
pub struct AddressModule {
    /// The module's image name.
    pub name: String,
    /// The module's base address.
    pub base: VirtAddr,
    /// The module's image size.
    pub size: u32,
    /// The offset of the address from `base`.
    #[record(hex)]
    pub offset: u64,
}

/// What an address belongs to: a loaded module (and section), a process VAD
/// region, a kernel region, or nothing that ntoseye recognizes. Complements
/// `pte_traverse` (how it's mapped) with where it lives.
#[record]
pub struct AddressDescription {
    pub address: VirtAddr,
    /// The address space of the lookup.
    #[record(hex)]
    pub dtb: Dtb,
    pub kind: AddressKind,
    /// The module containing the address, if any.
    pub module: Option<AddressModule>,
    /// The module section containing the address, if any.
    pub section: Option<String>,
    /// The `_MI_SYSTEM_VA_TYPE` name, for a kernel region (e.g.
    /// `KernelStacks`, `PagedPool`, `SystemPtes`).
    pub va_type: Option<String>,
    /// The VAD region containing the address, if any.
    pub region: Option<MemoryRegionInfo>,
}

/// One process's memory counters, in bytes.
#[record]
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

/// System memory counters and per-process usage (`!memusage`).
#[record]
pub struct SystemMemorySummary {
    pub physical_pages: DiagnosticMetric<u64>,
    pub available_pages: DiagnosticMetric<u64>,
    pub committed_pages: DiagnosticMetric<u64>,
    pub commit_limit_pages: DiagnosticMetric<u64>,
    pub paged_pool_pages: DiagnosticMetric<u64>,
    pub nonpaged_pool_bytes: DiagnosticMetric<u64>,
    pub processes: Vec<ProcessMemoryUsage>,
    /// The number of processes, including those past the listing limit.
    pub process_count: usize,
    /// Whether more processes exist than are listed.
    pub truncated: bool,
}

/// The page-table entries that map an address, read through NT's self-map
/// (`!pte`).
#[record]
pub struct PteWalk {
    pub address: VirtAddr,
    /// The address space the walk was performed in (the attached process DTB
    /// when attached, else the kernel), so callers know what was walked.
    #[record(hex)]
    pub dtb: Dtb,
    /// The entries read, root first: each below the root only when the one
    /// above it points at a table.
    pub levels: Vec<PteLevel>,
    /// Where the page is when it is not in memory, and whether reads still
    /// get it (from the memory-compression store); `None` when it is in
    /// memory.
    pub non_resident: Option<NonResident>,
}
