//! Neutral value-tree views for memory-manager inspectors.

use crate::guest::ProcessInfo;
use crate::target::DiagnosticMetric;
use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use crate::target::mm::{
    self as target_mm, BigPoolDetail, LookasideDetail, LookasideListsDetail, MdlDetail,
    MemoryRegionInfo, PfnDetail, PoolBlockDetail, PoolFindDetail, PoolFindMatch, PoolFindRange,
    PoolPageDetail, PoolRegionDetail, PoolType, PoolUsageDetail, PoolValidationDetail, PtovDetail,
    PtovMapping, SystemMemorySummary, SystemPteTypeDetail, SystemPtesDetail, VadProtection,
    VadType, VmDetail, VprotDetail, VtopDetail, VtopLevel, memory_state_name, memory_type_name,
    page_protection_name,
};
use crate::target::pool::{PoolUsageRow, tag_string};
use crate::target::{self};
use crate::types::{PageTableLevel, PteAttributes, VirtAddr};

/// A named memory-manager counter (`!vm`).
#[record]
pub struct VmCounter {
    pub name: String,
    pub value: DiagnosticMetric<u64>,
    /// The unit of `value`: `pages`, `bytes`, or empty for a plain count.
    pub unit: &'static str,
}

/// Pool counters and the pool fields of `MiState` (`!vm`).
#[record]
pub struct VmPool {
    pub nonpaged_pool_bytes: DiagnosticMetric<u64>,
    pub nonpaged_pool_maximum: DiagnosticMetric<u64>,
    pub paged_pool_pages: DiagnosticMetric<u64>,
    /// The symbol-backed pool fields of `MiState`.
    pub fields: Vec<VmCounter>,
}

/// System PTE counters (`!vm`).
#[record]
pub struct VmPte {
    pub counters: Vec<VmCounter>,
}

/// Virtual-memory statistics (`!vm`).
#[record]
pub struct VmStatistics {
    pub system: SystemMemoryUsage,
    pub pool: VmPool,
    pub pte: VmPte,
    /// Paging-file counters.
    pub page_files: Vec<VmCounter>,
    /// Whether per-process usage was requested.
    pub include_processes: bool,
}

/// The input to `!pfn`.
#[record]
pub struct PfnSelector {
    /// `pfn` or `physical_address`.
    pub kind: &'static str,
    #[record(hex)]
    pub value: u64,
}

/// The `PageLocation` of a PFN, which is the list that holds the page.
#[record]
pub struct PageLocation {
    pub value: u8,
    /// The `_MMLISTS` name (`ActiveAndValid`, `StandbyPageList`, ...).
    pub name: &'static str,
}

/// The `CacheAttribute` of a PFN.
#[record]
pub struct CacheAttribute {
    pub value: u8,
    /// The `_MI_PFN_CACHE_ATTRIBUTE` name (`MmCached`, ...).
    pub name: &'static str,
}

/// A decoded `_MMPFN` record (`!pfn`). Union members that the page state
/// does not use are `None`: the list links when the page is not on a list,
/// `share_count` and `ws_index` when the page is not active, and `event`
/// when the page is not in transition.
#[record]
pub struct Pfn {
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

/// One page-table level of a walk, with the entry decoded into WinDbg-style
/// flags. For an entry that points to a lower table, `writable`, `user`,
/// and `nx` are the restrictions that the entry puts on everything below
/// it.
#[record]
pub struct PageTableEntry {
    /// `PXE`, `PPE`, `PDE`, or `PTE`.
    pub level: &'static str,
    /// The entry's virtual address.
    pub address: VirtAddr,
    /// The entry as read.
    #[record(hex)]
    pub value: u64,
    /// The frame the entry points at.
    #[record(hex)]
    pub pfn: u64,
    pub present: bool,
    /// Whether the entry maps a large page instead of pointing to a lower
    /// table.
    pub large_page: bool,
    pub writable: bool,
    pub user: bool,
    pub nx: bool,
    /// WinDbg's flag string for the entry.
    pub flags: String,
}

/// A virtual address translated through the page tables of a DTB (`!vtop`).
#[record]
pub struct AddressTranslation {
    pub address: VirtAddr,
    #[record(hex)]
    pub dtb: u64,
    /// The levels read, top down.
    pub levels: Vec<PageTableEntry>,
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
    /// file view that is not touched yet.
    pub section: bool,
}

/// A virtual address that maps a physical page.
#[record]
pub struct PhysicalMapping {
    pub virtual_address: VirtAddr,
    /// Whether a large page maps it.
    pub large: bool,
}

/// The virtual addresses that map a physical address (`!ptov`).
#[record]
pub struct ReverseTranslation {
    #[record(hex)]
    pub physical: u64,
    #[record(hex)]
    pub dtb: u64,
    pub mappings: Vec<PhysicalMapping>,
    /// The number of page-table pages that the walk read.
    pub table_pages: usize,
    /// Whether the walk stopped at its limit before the end.
    pub bounded: bool,
    /// Whether an interrupt request stopped the walk.
    pub interrupted: bool,
}

/// A virtual pool range.
#[record]
pub struct PoolRegion {
    pub name: String,
    pub start: VirtAddr,
    /// The end of the range (exclusive).
    pub end: VirtAddr,
}

/// A `_POOL_HEADER` block in a pool page.
#[record]
pub struct PoolBlock {
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
    /// `allocated`, `free`, or a description of what is wrong.
    pub state: String,
    /// The offset of the requested address in the block, if the block holds it.
    #[record(hex)]
    pub target_offset: Option<u64>,
}

/// A large allocation from `PoolBigPageTable`.
#[record]
pub struct BigPoolAllocation {
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
pub struct PoolPage {
    /// The requested address.
    pub target: VirtAddr,
    /// The page's address.
    pub page: VirtAddr,
    /// The layout of the page: its pool kind, or the reason that the page
    /// could not be decoded.
    pub page_kind: String,
    /// The pool range holding the page, when known.
    pub region: Option<PoolRegion>,
    pub blocks: Vec<PoolBlock>,
    /// The index in `blocks` of the block that holds the requested address.
    pub target_index: Option<usize>,
    /// The large allocation that holds the address, if the address is in one.
    pub big: Option<BigPoolAllocation>,
    /// Set if the page belongs to the segment heap, whose blocks have no
    /// pool headers.
    pub segment_heap_hint: Option<String>,
    /// The nearest symbol to the address, if one resolves.
    pub near_symbol: Option<String>,
    /// The reason that no blocks were decoded, if none were.
    pub message: Option<String>,
}

/// A pool header inconsistency.
#[record]
pub struct PoolProblem {
    /// The header where the problem is.
    pub header: VirtAddr,
    /// What is wrong.
    pub message: String,
}

/// The blocks of the pool page that holds an address, with a check of
/// header consistency (`!poolval`).
#[record]
pub struct PoolValidation {
    pub address: VirtAddr,
    /// The page's address.
    pub page: VirtAddr,
    /// The pool range holding the page, when known.
    pub region: Option<PoolRegion>,
    /// `chained` (the classic pool) or `segment heap`.
    pub layout: String,
    /// Whether the headers are consistent (`problem` is `None`).
    pub valid: bool,
    /// The first inconsistency found.
    pub problem: Option<PoolProblem>,
    pub blocks: Vec<PoolBlock>,
}

/// The pool usage of one tag, in bytes (`!poolused`). A value is `None` if
/// the tracker has no entry for that pool.
#[record]
pub struct PoolTagUsage {
    #[record(hex)]
    pub tag: u32,
    /// The tag as its four characters.
    pub tag_name: String,
    pub nonpaged_bytes: Option<u64>,
    pub paged_bytes: Option<u64>,
    /// `None` unless allocation counts were requested.
    pub nonpaged_allocs: Option<u64>,
    /// `None` unless allocation counts were requested.
    pub nonpaged_frees: Option<u64>,
    /// `None` unless allocation counts were requested.
    pub paged_allocs: Option<u64>,
    /// `None` unless allocation counts were requested.
    pub paged_frees: Option<u64>,
}

/// Pool usage by tag, from the pool tracker (`!poolused`).
#[record]
pub struct PoolUsage {
    pub rows: Vec<PoolTagUsage>,
    /// Whether more tags matched than are listed.
    pub rows_truncated: bool,
    /// The read status of the pool tracker table.
    pub tracker_status: String,
    /// The read status of the big-pool table.
    pub big_status: String,
    /// The sort order: `tag`, `nonpaged_bytes`, or `paged_bytes`.
    pub sort: &'static str,
    /// The tag pattern that filters the rows, if any.
    pub tag_filter: Option<String>,
    /// Whether allocation and free counts were requested.
    pub include_counts: bool,
}

/// A pool allocation with the search tag (`!poolfind`).
#[record]
pub struct PoolMatch {
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
    pub state: String,
    /// `NonPagedPool` or `PagedPool`, when known.
    pub pool_type: Option<&'static str>,
    /// The `PoolBigPageTable` entry, for a big-pool match.
    pub table_entry: Option<VirtAddr>,
    /// The `PoolBigPageTable` index, for a big-pool match.
    pub index: Option<u64>,
}

/// How far `!poolfind` scanned one virtual pool range.
#[record]
pub struct PoolRangeScan {
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

/// A pool-tag search (`!poolfind`).
#[record]
pub struct PoolSearch {
    /// The searched tag.
    pub tag: String,
    /// The pool that the search was limited to, if any.
    pub pool_type: Option<&'static str>,
    pub matches: Vec<PoolMatch>,
    /// The number of matches found, including those past the listing limit.
    pub found: usize,
    pub ranges: Vec<PoolRangeScan>,
    /// The read status of the big-pool table, if the search included it.
    pub big_status: Option<String>,
    /// Whether more matches were found than are listed.
    pub truncated: bool,
    /// Whether an interrupt request stopped the search.
    pub interrupted: bool,
}

/// A pool tag.
#[record]
pub struct PoolTag {
    #[record(hex)]
    pub value: u32,
    /// The tag as its four characters.
    pub name: String,
}

/// A decoded `_GENERAL_LOOKASIDE` list (`!lookaside`).
#[record]
pub struct LookasideList {
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
pub struct LookasideLists {
    pub records: Vec<LookasideList>,
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
pub struct Mdl {
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
    /// The number of pages that the described buffer spans.
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
pub struct SystemPteRun {
    /// The address of the first PTE in the run.
    pub pte: VirtAddr,
    /// The virtual address that this PTE maps, if `MmPteBase` is known.
    pub va: Option<VirtAddr>,
    /// The length in PTEs.
    pub ptes: u64,
}

/// One `_MI_SYSTEM_PTE_TYPE` bitmap allocator (`!sysptes`). Counts are
/// in PTEs.
#[record]
pub struct SystemPteType {
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
    /// `TotalSystemPtes`, the number of PTEs made available so far.
    pub total: u64,
    /// `TotalFreeSystemPtes`.
    pub free: u64,
    /// `total` minus `free`.
    pub used: u64,
    pub failures: u32,
    /// The free PTEs, counted from the clear bits of the bitmap.
    pub bitmap_free: u64,
    /// The bitmap bytes that could not be read, which count as allocated.
    pub unreadable_bitmap_bytes: u64,
    /// The bits past the read limit for one bitmap, which no count
    /// includes.
    pub unscanned_bitmap_bits: u64,
    pub free_run_count: u64,
    pub largest_free_run: u64,
    /// The free runs in address order, if the list was requested.
    pub free_runs: Vec<SystemPteRun>,
    pub free_runs_truncated: bool,
    /// Whether the kernel tracks which driver mapped each PTE (`TrackPtes`).
    pub tracking: bool,
}

/// Every system-PTE bitmap allocator in `MiState` (`!sysptes`). Counts
/// are in PTEs.
#[record]
pub struct SystemPtes {
    /// The requested flags.
    #[record(hex)]
    pub flags: u64,
    pub types: Vec<SystemPteType>,
    pub total: u64,
    pub free: u64,
    pub used: u64,
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

/// One VAD or kernel region (`proc.regions` items, address context).
#[record]
pub struct MemoryRegion {
    /// The first address of the region.
    pub start: VirtAddr,
    /// The end of the region (exclusive).
    pub end: VirtAddr,
    /// Size in bytes.
    pub size: u64,
    /// The VAD protection value, if known. It is an index into the memory
    /// manager's protection table, not a `PAGE_*` mask.
    pub protection: Option<u64>,
    /// The VAD type (`_MI_VAD_TYPE`), when known.
    pub vad_type: Option<u64>,
    /// Whether the region is private (not shared or mapped).
    pub private_memory: Option<bool>,
    /// The committed pages that are charged to the region.
    pub commit_charge: Option<u64>,
    /// A description: the mapped file, or the kernel region kind.
    pub details: Option<String>,
}

/// The data that `VirtualQuery` reports for an address (`!vprot`). Each
/// `MEM_*`/`PAGE_*` value has its name next to it.
#[record]
pub struct MemoryBasicInformation {
    pub process: ProcessInfo,
    pub address: VirtAddr,
    pub base_address: VirtAddr,
    /// The VAD's start; zero for free memory.
    pub allocation_base: VirtAddr,
    #[record(hex)]
    pub allocation_protect: u32,
    pub allocation_protect_name: String,
    /// The number of bytes from `base_address` to the first page with a
    /// different state or protection, or to the end of the VAD.
    #[record(hex)]
    pub region_size: u64,
    #[record(hex)]
    pub state: u32,
    pub state_name: &'static str,
    #[record(hex)]
    pub protect: u32,
    pub protect_name: String,
    #[record(hex)]
    pub r#type: u32,
    pub type_name: &'static str,
    /// The VAD node; `None` for free memory.
    pub vad: Option<VirtAddr>,
    /// Whether the scan stopped before the end of the region, at its limit
    /// or at a page table that it cannot read. If true, `region_size` is a
    /// lower bound.
    pub truncated: bool,
}

/// What an address belongs to: a loaded module (and section), a process VAD
/// region, a kernel region, or nothing that ntoseye recognizes.
#[record]
pub struct AddressDescription {
    pub address: VirtAddr,
    /// The address space of the lookup.
    #[record(hex)]
    pub dtb: u64,
    /// `kernel-module`, `user-image`, `kernel-region`, `private`,
    /// `mapped`, or `unknown`.
    pub kind: &'static str,
    /// The module containing the address, if any.
    pub module: Option<AddressModule>,
    /// The module section containing the address, if any.
    pub section: Option<String>,
    /// The `_MI_SYSTEM_VA_TYPE` name, for a kernel region.
    pub va_type: Option<String>,
    /// The region containing the address, if any.
    pub region: Option<MemoryRegion>,
}

/// A memory-search hit, with its symbol and location data.
#[record]
pub struct MemorySearchMatch {
    /// The address of the match.
    pub address: VirtAddr,
    /// The offset of the match from the start of the search.
    #[record(hex)]
    pub offset: u64,
    /// The nearest symbol, if one resolves.
    pub symbol: Option<String>,
    /// The kind of address: `kernel-module`, `user-image`,
    /// `kernel-region`, `private`, `mapped`, `unknown`, `physical`,
    /// `vtl1`, or `foreign` (a root outside NT and VTL1).
    pub kind: &'static str,
    /// The module containing the match, if any.
    pub module: Option<AddressModule>,
    /// The module section containing the match, if any.
    pub section: Option<String>,
    /// The `_MI_SYSTEM_VA_TYPE` name, for a kernel-region match.
    pub va_type: Option<String>,
    /// The region containing the match, if any.
    pub region: Option<MemoryRegion>,
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

/// System memory counters and per-process usage (`!memusage`).
#[record]
pub struct SystemMemoryUsage {
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

fn vm_counter(counter: &target_mm::VmCounter) -> VmCounter {
    VmCounter {
        name: counter.name.clone(),
        value: counter.value.clone(),
        unit: counter.unit,
    }
}

/// `!vm`'s statistics.
pub fn vm(detail: &VmDetail) -> VmStatistics {
    VmStatistics {
        system: memory_usage(&detail.system),
        pool: VmPool {
            nonpaged_pool_bytes: detail.pool.nonpaged_pool_bytes.clone(),
            nonpaged_pool_maximum: detail.pool.nonpaged_pool_maximum.clone(),
            paged_pool_pages: detail.pool.paged_pool_pages.clone(),
            fields: detail.pool.fields.iter().map(vm_counter).collect(),
        },
        pte: VmPte {
            counters: detail.pte.counters.iter().map(vm_counter).collect(),
        },
        page_files: detail.page_files.counters.iter().map(vm_counter).collect(),
        include_processes: detail.include_processes,
    }
}

fn page_location_name(value: u8) -> &'static str {
    match value & 0x7 {
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

fn cache_attribute_name(value: u8) -> &'static str {
    match value & 0x3 {
        0 => "MmNonCached",
        1 => "MmCached",
        2 => "MmWriteCombined",
        _ => "MmNotMapped",
    }
}

/// One decoded `_MMPFN` (`!pfn`).
pub fn pfn(detail: &PfnDetail) -> Pfn {
    let selector = match detail.selector {
        target_mm::PfnSelector::Pfn(value) => PfnSelector { kind: "pfn", value },
        target_mm::PfnSelector::PhysicalAddress(value) => PfnSelector {
            kind: "physical_address",
            value,
        },
    };
    Pfn {
        selector,
        pfn: detail.pfn,
        record: detail.record,
        physical_address: detail.physical_address,
        pte_address: detail.pte_address,
        original_pte: detail.original_pte,
        reference_count: detail.reference_count,
        flink: detail.flink,
        blink: detail.blink,
        node_flink_low: detail.node_flink_low,
        node_blink_low: detail.node_blink_low,
        share_count: detail.share_count,
        ws_index: detail.ws_index,
        event: detail.event,
        used_entry_count: detail.used_entry_count,
        page_color: detail.page_color.clone(),
        pte_frame: detail.pte_frame,
        page_location: PageLocation {
            value: detail.page_location,
            name: page_location_name(detail.page_location),
        },
        modified: detail.modified,
        cache_attribute: CacheAttribute {
            value: detail.cache_attribute,
            name: cache_attribute_name(detail.cache_attribute),
        },
        priority: detail.priority,
    }
}

fn vtop_level(level: &VtopLevel) -> PageTableEntry {
    table_level(level.level, level.address, level.value, &level.attributes)
}

/// One page-table level (WinDbg-style flags), decoded for its architecture.
fn table_level(
    level: PageTableLevel,
    address: VirtAddr,
    value: u64,
    attributes: &PteAttributes,
) -> PageTableEntry {
    PageTableEntry {
        level: level.name(),
        address,
        value,
        pfn: attributes.pfn,
        present: attributes.present,
        large_page: attributes.large_page,
        writable: attributes.writable,
        user: attributes.user,
        nx: attributes.nx,
        flags: attributes.flags.clone(),
    }
}

/// `!vtop`'s translation.
pub fn vtop(detail: &VtopDetail) -> AddressTranslation {
    AddressTranslation {
        address: detail.address,
        dtb: detail.dtb,
        levels: detail.levels.iter().map(vtop_level).collect(),
        physical: detail.physical,
        large: detail.large,
        transition: detail.transition,
        section: detail.section,
    }
}

fn ptov_mapping(mapping: &PtovMapping) -> PhysicalMapping {
    PhysicalMapping {
        virtual_address: mapping.virtual_address,
        large: mapping.large,
    }
}

/// `!ptov`'s reverse mappings.
pub fn ptov(detail: &PtovDetail) -> ReverseTranslation {
    ReverseTranslation {
        physical: detail.physical,
        dtb: detail.dtb,
        mappings: detail.mappings.iter().map(ptov_mapping).collect(),
        table_pages: detail.table_pages,
        bounded: detail.bounded,
        interrupted: detail.interrupted,
    }
}

fn pool_region(region: &PoolRegionDetail) -> PoolRegion {
    PoolRegion {
        name: region.name.clone(),
        start: region.start,
        end: region.end,
    }
}

fn pool_block(block: &PoolBlockDetail) -> PoolBlock {
    PoolBlock {
        header: block.header,
        body: block.body,
        size: block.size,
        previous_size: block.previous_size,
        pool_type: block.pool_type,
        tag: block.tag,
        tag_name: block.tag_name.clone(),
        allocated: block.allocated,
        marked: block.marked,
        state: block.state.clone(),
        target_offset: block.target_offset,
    }
}

fn big_pool(big: &BigPoolDetail) -> BigPoolAllocation {
    BigPoolAllocation {
        address: big.address,
        target: big.target,
        size: big.size,
        offset: big.offset,
        tag: big.tag,
        tag_name: big.tag_name.clone(),
        entry: big.entry,
        index: big.index,
        nonpaged: big.nonpaged,
        pattern: big.pattern,
        pool_flags: big.pool_flags,
        slush_size: big.slush_size,
    }
}

/// `!pool`'s page.
pub fn pool_page(detail: &PoolPageDetail) -> PoolPage {
    PoolPage {
        target: detail.target,
        page: detail.page,
        page_kind: detail.page_kind.clone(),
        region: detail.region.as_ref().map(pool_region),
        blocks: detail.blocks.iter().map(pool_block).collect(),
        target_index: detail.target_index,
        big: detail.big.as_ref().map(big_pool),
        segment_heap_hint: detail.segment_heap_hint.clone(),
        near_symbol: detail.near_symbol.clone(),
        message: detail.message.clone(),
    }
}

/// `!poolval`'s check.
pub fn pool_validation(detail: &PoolValidationDetail) -> PoolValidation {
    PoolValidation {
        address: detail.address,
        page: detail.page,
        region: detail.region.as_ref().map(pool_region),
        layout: detail.layout.clone(),
        valid: detail.problem.is_none(),
        problem: detail.problem.as_ref().map(|problem| PoolProblem {
            header: problem.header,
            message: problem.message.clone(),
        }),
        blocks: detail.blocks.iter().map(pool_block).collect(),
    }
}

fn usage_row(row: &PoolUsageRow, include_counts: bool) -> PoolTagUsage {
    let bytes = |value: Option<i64>| value.map(|value| value.max(0) as u64);
    let count = |value: Option<i64>| bytes(value).filter(|_| include_counts);
    PoolTagUsage {
        tag: row.tag,
        tag_name: tag_string(row.tag),
        nonpaged_bytes: bytes(row.nonpaged_bytes),
        paged_bytes: bytes(row.paged_bytes),
        nonpaged_allocs: count(row.nonpaged_allocs),
        nonpaged_frees: count(row.nonpaged_frees),
        paged_allocs: count(row.paged_allocs),
        paged_frees: count(row.paged_frees),
    }
}

/// `!poolused`'s rows.
pub fn pool_usage(detail: &PoolUsageDetail) -> PoolUsage {
    PoolUsage {
        rows: detail
            .rows
            .iter()
            .map(|row| usage_row(row, detail.include_counts))
            .collect(),
        rows_truncated: detail.rows_truncated,
        tracker_status: detail.tracker_status.clone(),
        big_status: detail.big_status.clone(),
        sort: detail.sort.name(),
        tag_filter: detail.tag_filter.clone(),
        include_counts: detail.include_counts,
    }
}

fn pool_match(m: &PoolFindMatch) -> PoolMatch {
    PoolMatch {
        source: m.source.clone(),
        address: m.address,
        size: m.size,
        tag: m.tag,
        tag_name: m.tag_name.clone(),
        allocated: m.allocated,
        state: m.state.clone(),
        pool_type: m.pool_type.map(PoolType::name),
        table_entry: m.table_entry,
        index: m.index,
    }
}

fn pool_range_scan(range: &PoolFindRange) -> PoolRangeScan {
    PoolRangeScan {
        name: range.name.clone(),
        start: range.start,
        end: range.end,
        pages: range.pages,
        scanned_pages: range.scanned_pages,
        stopped_at: range.stopped_at,
    }
}

/// `!poolfind`'s matches.
pub fn pool_find(detail: &PoolFindDetail) -> PoolSearch {
    PoolSearch {
        tag: detail.tag.clone(),
        pool_type: detail.pool_type.map(PoolType::name),
        matches: detail.matches.iter().map(pool_match).collect(),
        found: detail.found,
        ranges: detail.ranges.iter().map(pool_range_scan).collect(),
        big_status: detail.big_status.clone(),
        truncated: detail.truncated,
        interrupted: detail.interrupted,
    }
}

/// One lookaside list (`!lookaside <address>`).
pub fn lookaside(detail: &LookasideDetail) -> LookasideList {
    LookasideList {
        address: detail.address,
        index: detail.index,
        tag: detail.tag.map(|value| PoolTag {
            value: (*value),
            name: tag_string(*value),
        }),
        size: detail.size.clone(),
        depth: detail.depth.clone(),
        total_allocates: detail.total_allocates.clone(),
        total_frees: detail.total_frees.clone(),
        allocate_misses: detail.allocate_misses.clone(),
    }
}

/// The system lookaside lists (`!lookaside`).
pub fn lookaside_lists(detail: &LookasideListsDetail) -> LookasideLists {
    LookasideLists {
        records: detail.records.iter().map(lookaside).collect(),
        nonpaged_count: detail.nonpaged_count,
        paged_count: detail.paged_count,
        nonpaged_termination: detail.nonpaged_termination.clone(),
        paged_termination: detail.paged_termination.clone(),
        interrupted: detail.interrupted,
        truncated: detail.truncated,
    }
}

/// `!mdl`'s header and PFNs.
pub fn mdl(detail: &MdlDetail) -> Mdl {
    Mdl {
        address: detail.address,
        next: detail.next,
        size: detail.size,
        flags: detail.flags,
        flag_names: detail.flag_names.clone(),
        process: detail.process,
        mapped_system_va: detail.mapped_system_va,
        start_va: detail.start_va,
        byte_count: detail.byte_count,
        byte_offset: detail.byte_offset,
        spanned_pages: detail.spanned_pages,
        capacity: detail.capacity,
        pfn_array: detail.pfn_array,
        pfns: detail.pfns.to_vec(),
        truncated: detail.truncated,
    }
}

fn system_pte_type(detail: &SystemPteTypeDetail) -> SystemPteType {
    SystemPteType {
        name: detail.name.clone(),
        address: detail.address,
        va_type: detail.va_type.clone(),
        flags: detail.flags,
        ptes_per_bit: detail.ptes_per_bit,
        base_pte: detail.base_pte,
        base_va: detail.base_va,
        bitmap: detail.bitmap,
        bitmap_bits: detail.bitmap_bits,
        total: detail.total,
        free: detail.free,
        used: detail.total.saturating_sub(detail.free),
        failures: detail.failures,
        bitmap_free: detail.bitmap_free,
        unreadable_bitmap_bytes: detail.unreadable_bitmap_bytes,
        unscanned_bitmap_bits: detail.unscanned_bitmap_bits,
        free_run_count: detail.free_run_count,
        largest_free_run: detail.largest_free_run,
        free_runs: detail
            .free_runs
            .iter()
            .map(|run| SystemPteRun {
                pte: run.pte,
                va: run.va,
                ptes: run.ptes,
            })
            .collect(),
        free_runs_truncated: detail.free_runs_truncated,
        tracking: detail.tracking,
    }
}

/// `!sysptes`'s allocators.
pub fn system_ptes(detail: &SystemPtesDetail) -> SystemPtes {
    SystemPtes {
        flags: detail.flags,
        types: detail.types.iter().map(system_pte_type).collect(),
        total: detail.total,
        free: detail.free,
        used: detail.total.saturating_sub(detail.free),
    }
}

fn address_module(m: &target_mm::AddressModule) -> AddressModule {
    AddressModule {
        name: m.name.clone(),
        base: m.base,
        size: m.size,
        offset: m.offset,
    }
}

/// One VAD or kernel region.
pub fn memory_region(r: &MemoryRegionInfo) -> MemoryRegion {
    MemoryRegion {
        start: r.start,
        end: r.end,
        size: r.size(),
        protection: r.protection.map(VadProtection::raw),
        vad_type: r.vad_type.map(VadType::raw),
        private_memory: r.private_memory,
        commit_charge: r.commit_charge,
        details: r.details.clone(),
    }
}

/// `!vprot`'s `VirtualQuery` fields.
pub fn vprot(detail: &VprotDetail) -> MemoryBasicInformation {
    MemoryBasicInformation {
        process: detail.process.clone(),
        address: detail.address,
        base_address: detail.base_address,
        allocation_base: detail.allocation_base,
        allocation_protect: detail.allocation_protect,
        allocation_protect_name: page_protection_name(detail.allocation_protect),
        region_size: detail.region_size,
        state: detail.state,
        state_name: memory_state_name(detail.state),
        protect: detail.protect,
        protect_name: page_protection_name(detail.protect),
        r#type: detail.kind,
        type_name: memory_type_name(detail.kind),
        vad: detail.vad,
        truncated: detail.truncated,
    }
}

/// What an address belongs to (`!address`).
pub fn address_description(d: &target_mm::AddressDescription) -> AddressDescription {
    AddressDescription {
        address: d.address,
        dtb: d.dtb,
        kind: d.kind,
        module: d.module.as_ref().map(address_module),
        section: d.section.clone(),
        va_type: d.va_type.clone(),
        region: d.region.as_ref().map(memory_region),
    }
}

/// A memory-search hit, with what its address belongs to.
pub fn memory_search_match(m: &target::MemorySearchMatch) -> MemorySearchMatch {
    let d = &m.description;
    MemorySearchMatch {
        address: m.address,
        offset: m.offset,
        symbol: m.symbol.clone(),
        kind: d.kind,
        module: d.module.as_ref().map(address_module),
        section: d.section.clone(),
        va_type: d.va_type.clone(),
        region: d.region.as_ref().map(memory_region),
    }
}

/// A memory-search hit outside NT's address descriptions: `kind` is
/// `physical`, `vtl1`, or `foreign`.
pub fn undescribed_search_match(
    address: u64,
    offset: u64,
    symbol: Option<String>,
    kind: &'static str,
) -> MemorySearchMatch {
    MemorySearchMatch {
        address: VirtAddr(address),
        offset,
        symbol,
        kind,
        module: None,
        section: None,
        va_type: None,
        region: None,
    }
}

fn process_memory_usage(usage: &target_mm::ProcessMemoryUsage) -> ProcessMemoryUsage {
    ProcessMemoryUsage {
        process: usage.process.clone(),
        virtual_size: usage.virtual_size.clone(),
        peak_virtual_size: usage.peak_virtual_size.clone(),
        working_set_size: usage.working_set_size.clone(),
        peak_working_set_size: usage.peak_working_set_size.clone(),
        pagefile_usage: usage.pagefile_usage.clone(),
        peak_pagefile_usage: usage.peak_pagefile_usage.clone(),
        private_usage: usage.private_usage.clone(),
    }
}

/// System memory counters and per-process usage.
pub fn memory_usage(summary: &SystemMemorySummary) -> SystemMemoryUsage {
    SystemMemoryUsage {
        physical_pages: summary.physical_pages.clone(),
        available_pages: summary.available_pages.clone(),
        committed_pages: summary.committed_pages.clone(),
        commit_limit_pages: summary.commit_limit_pages.clone(),
        paged_pool_pages: summary.paged_pool_pages.clone(),
        nonpaged_pool_bytes: summary.nonpaged_pool_bytes.clone(),
        processes: summary.processes.iter().map(process_memory_usage).collect(),
        process_count: summary.process_count,
        truncated: summary.truncated,
    }
}
