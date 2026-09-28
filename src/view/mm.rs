//! Neutral value-tree views for memory-manager inspectors.

use super::process::process;
use super::shape::{Diag, Hex, Metric, Omit, shapes};
use crate::target::mm::{
    self as target_mm, BigPoolDetail, LookasideDetail, LookasideListsDetail, MdlDetail,
    MemoryRegionInfo, PfnDetail, PoolBlockDetail, PoolFindDetail, PoolFindMatch, PoolFindRange,
    PoolPageDetail, PoolRegionDetail, PoolType, PoolUsageDetail, PoolValidationDetail, PteLevel,
    PtovDetail, PtovMapping, SystemMemorySummary, SystemPteTypeDetail, SystemPtesDetail,
    VadProtection, VadType, VmDetail, VprotDetail, VtopDetail, VtopLevel, memory_state_name,
    memory_type_name, page_protection_name,
};
use crate::target::pool::{PoolUsageRow, tag_string};
use crate::target::{self};
use crate::types::{PageTableLevel, PteAttributes, VirtAddr};

shapes! {
    /// A named memory-manager counter (`!vm`).
    VmCounter {
        name: String,
        value: Metric<u64>,
        /// What `value` counts: `pages`, `bytes`, or empty for a plain count.
        unit: &'static str,
    }

    /// Pool counters and the pool fields of `MiState` (`!vm`).
    VmPool {
        nonpaged_pool_bytes: Metric<u64>,
        nonpaged_pool_maximum: Metric<u64>,
        paged_pool_pages: Metric<u64>,
        /// The symbol-backed pool fields of `MiState`.
        fields: Vec<VmCounter>,
    }

    /// System PTE counters (`!vm`).
    VmPte {
        counters: Vec<VmCounter>,
    }

    /// Virtual-memory statistics (`!vm`).
    VmStatistics {
        system: SystemMemoryUsage,
        pool: VmPool,
        pte: VmPte,
        /// Paging-file counters.
        page_files: Vec<VmCounter>,
        /// Whether per-process usage was requested.
        include_processes: bool,
    }

    /// What `!pfn` was asked for.
    PfnSelector {
        /// `pfn` or `physical_address`.
        kind: &'static str,
        value: Hex,
    }

    /// A PFN's `PageLocation`: the list the page is on.
    PageLocation {
        value: u8,
        /// The `_MMLISTS` name (`ActiveAndValid`, `StandbyPageList`, ...).
        name: &'static str,
    }

    /// A PFN's `CacheAttribute`.
    CacheAttribute {
        value: u8,
        /// The `_MI_PFN_CACHE_ATTRIBUTE` name (`MmCached`, ...).
        name: &'static str,
    }

    /// A decoded `_MMPFN` record (`!pfn`). Union members the page's state
    /// does not use are `None`: the list links unless the page is on a list,
    /// `share_count` and `ws_index` unless it is active, `event` unless it
    /// is in transition.
    Pfn {
        selector: PfnSelector,
        /// The page frame number.
        pfn: Hex,
        /// The `_MMPFN` record's address.
        record: VirtAddr,
        /// The requested physical address, for a physical-address selector.
        physical_address: Option<Hex>,
        pte_address: Diag<VirtAddr>,
        original_pte: Diag<Hex>,
        reference_count: Diag<u64>,
        flink: Option<Diag<Hex>>,
        blink: Option<Diag<Hex>>,
        node_flink_low: Option<Diag<Hex>>,
        node_blink_low: Option<Diag<Hex>>,
        share_count: Option<Diag<u64>>,
        /// The working-set index.
        ws_index: Option<Diag<Hex>>,
        event: Option<Diag<Hex>>,
        used_entry_count: Diag<u64>,
        page_color: Diag<u64>,
        /// The PFN of the page table holding the page's PTE.
        pte_frame: Diag<Hex>,
        page_location: Diag<PageLocation>,
        modified: Diag<bool>,
        cache_attribute: Diag<CacheAttribute>,
        priority: Diag<u8>,
    }

    /// One page-table level of a walk, its entry decoded with WinDbg-style
    /// flags. For an entry pointing at a lower table, `writable`, `user`,
    /// and `nx` are the restrictions it places on what lies below.
    PageTableEntry {
        /// `PXE`, `PPE`, `PDE`, or `PTE`.
        level: &'static str,
        /// The entry's virtual address.
        address: VirtAddr,
        /// The entry as read.
        value: Hex,
        /// The frame the entry points at.
        pfn: Hex,
        present: bool,
        /// Whether the entry maps a large page rather than a lower table.
        large_page: bool,
        writable: bool,
        user: bool,
        nx: bool,
        /// WinDbg's flag string for the entry.
        flags: String,
    }

    /// A virtual address translated through a DTB's page tables (`!vtop`).
    AddressTranslation {
        address: VirtAddr,
        dtb: Hex,
        /// The levels read, top down.
        levels: Vec<PageTableEntry>,
        /// The physical address; `None` when the address is not mapped.
        physical: Option<Hex>,
        /// Whether a large page maps it.
        large: bool,
        /// Whether the leaf is a transition PTE: `physical` is a frame the guest still
        /// holds, but nothing maps it here and it cannot be written.
        transition: bool,
        /// Whether nothing maps the page here and `physical` is the frame its section
        /// PTE holds (a page of a shared image or file view not yet touched).
        section: bool,
    }

    /// A virtual address that maps a physical page.
    PhysicalMapping {
        virtual_address: VirtAddr,
        /// Whether a large page maps it.
        large: bool,
    }

    /// The virtual addresses that map a physical address (`!ptov`).
    ReverseTranslation {
        physical: Hex,
        dtb: Hex,
        mappings: Vec<PhysicalMapping>,
        /// Page-table pages read.
        table_pages: usize,
        /// Whether the walk stopped at its bound before the end.
        bounded: bool,
        /// Whether an interrupt request stopped the walk.
        interrupted: bool,
    }

    /// A virtual pool range.
    PoolRegion {
        name: String,
        start: VirtAddr,
        /// End of the range (exclusive).
        end: VirtAddr,
    }

    /// A `_POOL_HEADER` block in a pool page.
    PoolBlock {
        /// The pool header's address.
        header: VirtAddr,
        /// The allocation's address, just past the header.
        body: VirtAddr,
        /// Block size in bytes, header included.
        size: u64,
        /// The previous block's size in bytes.
        previous_size: u64,
        /// The header's `PoolType` bits.
        pool_type: u8,
        tag: Hex<u32>,
        /// The tag as its four characters.
        tag_name: String,
        allocated: bool,
        /// Whether the block holds the requested address.
        marked: bool,
        /// `allocated`, `free`, or a description of what is wrong.
        state: String,
        /// The requested address's offset into the block, when it holds it.
        target_offset: Option<Hex>,
    }

    /// A large allocation from `PoolBigPageTable`.
    BigPoolAllocation {
        /// The allocation's address.
        address: VirtAddr,
        /// The requested address.
        target: VirtAddr,
        /// Allocation size in bytes.
        size: u64,
        /// The requested address's offset into the allocation.
        offset: Hex,
        tag: Hex<u32>,
        /// The tag as its four characters.
        tag_name: String,
        /// The `PoolBigPageTable` entry's address.
        entry: VirtAddr,
        /// The entry's index in `PoolBigPageTable`.
        index: u64,
        nonpaged: bool,
        pattern: Hex<u8>,
        pool_flags: Hex<u16>,
        slush_size: u16,
    }

    /// The pool page holding an address (`!pool`).
    PoolPage {
        /// The requested address.
        target: VirtAddr,
        /// The page's address.
        page: VirtAddr,
        /// How the page is laid out: its pool kind, or why it could not be
        /// decoded.
        page_kind: String,
        /// The pool range holding the page, when known.
        region: Option<PoolRegion>,
        blocks: Vec<PoolBlock>,
        /// Index in `blocks` of the block holding the requested address.
        target_index: Option<usize>,
        /// The large allocation holding the address, when it is one.
        big: Option<BigPoolAllocation>,
        /// Set when the page belongs to the segment heap, whose blocks have no
        /// pool headers.
        segment_heap_hint: Option<String>,
        /// The symbol nearest the address, when one resolved.
        near_symbol: Option<String>,
        /// Why no blocks were decoded, when none were.
        message: Option<String>,
    }

    /// A pool header inconsistency.
    PoolProblem {
        /// The header it is found at.
        header: VirtAddr,
        /// What is wrong.
        message: String,
    }

    /// The blocks of the pool page holding an address, checked for header
    /// consistency (`!poolval`).
    PoolValidation {
        address: VirtAddr,
        /// The page's address.
        page: VirtAddr,
        /// The pool range holding the page, when known.
        region: Option<PoolRegion>,
        /// `chained` (the classic pool) or `segment heap`.
        layout: String,
        /// Whether the headers are consistent (`problem` is `None`).
        valid: bool,
        /// The first inconsistency found.
        problem: Option<PoolProblem>,
        blocks: Vec<PoolBlock>,
    }

    /// One tag's pool usage (`!poolused`), in bytes. `None` when the tracker
    /// has no entry for that pool.
    PoolTagUsage {
        tag: Hex<u32>,
        /// The tag as its four characters.
        tag_name: String,
        nonpaged_bytes: Option<u64>,
        paged_bytes: Option<u64>,
        /// Absent unless allocation counts were requested.
        nonpaged_allocs: Omit<Option<u64>>,
        /// Absent unless allocation counts were requested.
        nonpaged_frees: Omit<Option<u64>>,
        /// Absent unless allocation counts were requested.
        paged_allocs: Omit<Option<u64>>,
        /// Absent unless allocation counts were requested.
        paged_frees: Omit<Option<u64>>,
    }

    /// Pool usage by tag, from the pool tracker (`!poolused`).
    PoolUsage {
        rows: Vec<PoolTagUsage>,
        /// Whether more tags matched than are listed.
        rows_truncated: bool,
        /// How the pool tracker table read.
        tracker_status: String,
        /// How the big-pool table read.
        big_status: String,
        /// The sort order: `tag`, `nonpaged_bytes`, or `paged_bytes`.
        sort: &'static str,
        /// The tag pattern rows were filtered by, if any.
        tag_filter: Option<String>,
        /// Whether allocation and free counts were requested.
        include_counts: bool,
    }

    /// A pool allocation carrying the searched tag (`!poolfind`).
    PoolMatch {
        /// Where it was found: a pool range scan or the big-pool table.
        source: String,
        address: VirtAddr,
        /// Size in bytes.
        size: u64,
        tag: Hex<u32>,
        /// The tag as its four characters.
        tag_name: String,
        allocated: bool,
        state: String,
        /// `NonPagedPool` or `PagedPool`, when known.
        pool_type: Option<&'static str>,
        /// The `PoolBigPageTable` entry, for a big-pool match.
        table_entry: Option<VirtAddr>,
        /// The `PoolBigPageTable` index, for a big-pool match.
        index: Option<u64>,
    }

    /// How far `!poolfind` scanned one virtual pool range.
    PoolRangeScan {
        name: String,
        start: VirtAddr,
        /// End of the range (exclusive).
        end: VirtAddr,
        /// Pages the range spans, mapped or not.
        pages: u64,
        /// Mapped pages read.
        scanned_pages: u64,
        /// The mapped page the scan stopped at, unread, when the match bound
        /// or an interrupt ended it early.
        stopped_at: Option<VirtAddr>,
    }

    /// A pool-tag search (`!poolfind`).
    PoolSearch {
        /// The searched tag.
        tag: String,
        /// The pool the search was limited to, if any.
        pool_type: Option<&'static str>,
        matches: Vec<PoolMatch>,
        /// Matches found, including those past the listing bound.
        found: usize,
        ranges: Vec<PoolRangeScan>,
        /// How the big-pool table read, when it was searched.
        big_status: Option<String>,
        /// Whether more matches were found than are listed.
        truncated: bool,
        /// Whether an interrupt request stopped the search.
        interrupted: bool,
    }

    /// A pool tag.
    PoolTag {
        value: Hex<u32>,
        /// The tag as its four characters.
        name: String,
    }

    /// A decoded `_GENERAL_LOOKASIDE` list (`!lookaside`).
    LookasideList {
        address: VirtAddr,
        /// Position in the list walk.
        index: usize,
        tag: Diag<PoolTag>,
        /// Allocation size in bytes.
        size: Diag<u64>,
        depth: Diag<u64>,
        total_allocates: Diag<u64>,
        total_frees: Diag<u64>,
        allocate_misses: Diag<u64>,
    }

    /// The system lookaside lists (`!lookaside`).
    LookasideLists {
        records: Vec<LookasideList>,
        nonpaged_count: usize,
        paged_count: usize,
        /// How the nonpaged list walk ended.
        nonpaged_termination: String,
        /// How the paged list walk ended.
        paged_termination: String,
        /// Whether an interrupt request stopped the walk.
        interrupted: bool,
        /// Whether the walk stopped at its bound before the end.
        truncated: bool,
    }

    /// A decoded `_MDL` header and the page-frame array that follows it
    /// (`!mdl`).
    Mdl {
        address: VirtAddr,
        next: VirtAddr,
        /// Bytes of header plus PFN array the allocation holds.
        size: u16,
        flags: Hex<u16>,
        /// `MDL_*` names of the set `flags` bits, low bit first.
        flag_names: Vec<&'static str>,
        process: VirtAddr,
        mapped_system_va: VirtAddr,
        start_va: VirtAddr,
        byte_count: u32,
        byte_offset: Hex<u32>,
        /// Pages the described buffer spans.
        spanned_pages: u64,
        /// PFN slots `size` leaves after the header.
        capacity: u64,
        /// Where the PFN array starts (just past the header).
        pfn_array: VirtAddr,
        pfns: Vec<Hex>,
        /// Whether fewer PFNs are listed than the buffer spans: a smaller count was
        /// requested.
        truncated: bool,
    }

    /// A run of free system PTEs: clear bits in an allocation bitmap.
    SystemPteRun {
        /// Address of the run's first PTE.
        pte: VirtAddr,
        /// Virtual address that PTE maps, when `MmPteBase` is known.
        va: Option<VirtAddr>,
        /// Length in PTEs.
        ptes: u64,
    }

    /// One `_MI_SYSTEM_PTE_TYPE` bitmap allocator (`!sysptes`). Counts are
    /// in PTEs.
    SystemPteType {
        /// The `MiState` path of the allocator, e.g. `Vs.SystemPteInfo`.
        name: String,
        address: VirtAddr,
        /// The `_MI_SYSTEM_VA_TYPE` name, without the `MiVa` prefix.
        va_type: Option<String>,
        flags: Hex<u32>,
        /// PTEs each bitmap bit covers.
        ptes_per_bit: u64,
        base_pte: VirtAddr,
        /// Virtual address `base_pte` maps; `None` without `MmPteBase`.
        base_va: Option<VirtAddr>,
        bitmap: VirtAddr,
        bitmap_bits: u64,
        /// `TotalSystemPtes`: PTEs made available so far.
        total: u64,
        /// `TotalFreeSystemPtes`.
        free: u64,
        /// `total` minus `free`.
        used: u64,
        failures: u32,
        /// Free PTEs counted from the bitmap's clear bits.
        bitmap_free: u64,
        /// Bitmap bytes that could not be read (counted as allocated).
        unreadable_bitmap_bytes: u64,
        /// Bits past the bound on how much of one bitmap is read; left out of
        /// every count.
        unscanned_bitmap_bits: u64,
        free_run_count: u64,
        largest_free_run: u64,
        /// The free runs in address order, when listing was requested.
        free_runs: Vec<SystemPteRun>,
        free_runs_truncated: bool,
        /// Whether the kernel tracks which driver mapped each PTE (`TrackPtes`).
        tracking: bool,
    }

    /// Every system-PTE bitmap allocator in `MiState` (`!sysptes`). Counts
    /// are in PTEs.
    SystemPtes {
        /// The requested flags.
        flags: Hex,
        types: Vec<SystemPteType>,
        total: u64,
        free: u64,
        used: u64,
    }

    /// The loaded module an address lies in.
    AddressModule {
        /// The module's image name.
        name: String,
        /// The module's base address.
        base: VirtAddr,
        /// The module's image size.
        size: u32,
        /// The address's offset from `base`.
        offset: Hex,
    }

    /// One VAD or kernel region (`proc.regions` items, address context).
    MemoryRegion {
        /// First address of the region.
        start: VirtAddr,
        /// End of the region (exclusive).
        end: VirtAddr,
        /// Size in bytes.
        size: u64,
        /// The VAD protection value (an index into the memory manager's
        /// protection table, not a `PAGE_*` mask), when known.
        protection: Option<u64>,
        /// The VAD type (`_MI_VAD_TYPE`), when known.
        vad_type: Option<u64>,
        /// Whether the region is private (not shared or mapped).
        private_memory: Option<bool>,
        /// Committed pages charged to the region.
        commit_charge: Option<u64>,
        /// A description: the mapped file, or the kernel region kind.
        details: Option<String>,
    }

    /// What `VirtualQuery` reports for an address (`!vprot`), each
    /// `MEM_*`/`PAGE_*` value beside its name.
    MemoryBasicInformation {
        process: super::process::ProcessIdentity,
        address: VirtAddr,
        base_address: VirtAddr,
        /// The VAD's start; zero for free memory.
        allocation_base: VirtAddr,
        allocation_protect: Hex<u32>,
        allocation_protect_name: String,
        /// Bytes from `base_address` to the first page whose state or
        /// protection differs, or the end of the VAD.
        region_size: Hex,
        state: Hex<u32>,
        state_name: &'static str,
        protect: Hex<u32>,
        protect_name: String,
        r#type: Hex<u32>,
        type_name: &'static str,
        /// The VAD node; `None` for free memory.
        vad: Option<VirtAddr>,
        /// Whether the scan stopped at its bound or an unreadable page table before
        /// the region ended, so `region_size` is a lower bound.
        truncated: bool,
    }

    /// What an address belongs to: a loaded module (and section), a process
    /// VAD region, a kernel region, or nothing recognized.
    AddressDescription {
        address: VirtAddr,
        /// The address space it was looked up in.
        dtb: Hex,
        /// `kernel-module`, `user-image`, `kernel-region`, `private`,
        /// `mapped`, or `unknown`.
        kind: &'static str,
        /// The module containing the address, if any.
        module: Option<AddressModule>,
        /// The module section containing the address, if any.
        section: Option<String>,
        /// The `_MI_SYSTEM_VA_TYPE` name, for a kernel region.
        va_type: Option<String>,
        /// The region containing the address, if any.
        region: Option<MemoryRegion>,
    }

    /// A memory-search hit with symbol and location context.
    MemorySearchMatch {
        /// Where the pattern matched.
        address: VirtAddr,
        /// The match's offset from the search start.
        offset: Hex,
        /// The nearest symbol, if one resolved.
        symbol: Option<String>,
        /// What the address is: `kernel-module`, `user-image`,
        /// `kernel-region`, `private`, `mapped`, `unknown`, `physical`, or
        /// `vtl1`.
        kind: &'static str,
        /// The module containing the match, if any.
        module: Option<AddressModule>,
        /// The module section containing the match, if any.
        section: Option<String>,
        /// The `_MI_SYSTEM_VA_TYPE` name, for a kernel-region match.
        va_type: Option<String>,
        /// The region containing the match, if any.
        region: Option<MemoryRegion>,
    }

    /// A full page-table walk (`!pte`): the levels reached, top down (a
    /// large-page mapping short-circuits, so fewer levels).
    PteWalk {
        address: VirtAddr,
        /// The address space walked.
        dtb: Hex,
        levels: Vec<PageTableEntry>,
    }

    /// One process's memory counters, in bytes.
    ProcessMemoryUsage {
        process: super::process::ProcessIdentity,
        virtual_size: Diag<u64>,
        peak_virtual_size: Diag<u64>,
        working_set_size: Diag<u64>,
        peak_working_set_size: Diag<u64>,
        pagefile_usage: Diag<u64>,
        peak_pagefile_usage: Diag<u64>,
        private_usage: Diag<u64>,
    }

    /// System memory counters and per-process usage (`!memusage`).
    SystemMemoryUsage {
        physical_pages: Metric<u64>,
        available_pages: Metric<u64>,
        committed_pages: Metric<u64>,
        commit_limit_pages: Metric<u64>,
        paged_pool_pages: Metric<u64>,
        nonpaged_pool_bytes: Metric<u64>,
        processes: Vec<ProcessMemoryUsage>,
        /// Processes counted, including those past the listing bound.
        process_count: usize,
        /// Whether more processes exist than are listed.
        truncated: bool,
    }
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
        target_mm::PfnSelector::Pfn(value) => PfnSelector {
            kind: "pfn",
            value,
        },
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
        pte_address: detail.pte_address.clone(),
        original_pte: detail.original_pte.clone(),
        reference_count: detail.reference_count.clone(),
        flink: detail.flink.clone(),
        blink: detail.blink.clone(),
        node_flink_low: detail.node_flink_low.clone(),
        node_blink_low: detail.node_blink_low.clone(),
        share_count: detail.share_count.clone(),
        ws_index: detail.ws_index.clone(),
        event: detail.event.clone(),
        used_entry_count: detail.used_entry_count.clone(),
        page_color: detail.page_color.clone(),
        pte_frame: detail.pte_frame.clone(),
        page_location: detail.page_location.map(|value| PageLocation {
            value: *value,
            name: page_location_name(*value),
        }),
        modified: detail.modified.clone(),
        cache_attribute: detail.cache_attribute.map(|value| CacheAttribute {
            value: *value,
            name: cache_attribute_name(*value),
        }),
        priority: detail.priority.clone(),
    }
}

fn vtop_level(level: &VtopLevel) -> PageTableEntry {
    table_level(level.level, level.address, level.value, &level.attributes)
}

fn pte_level(pte: &PteLevel) -> PageTableEntry {
    table_level(pte.level, pte.address, pte.value.0, &pte.attributes)
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
    let count = |value: Option<i64>| include_counts.then(|| bytes(value));
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
        process: process(&detail.process),
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
/// `physical` or `vtl1`.
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

/// `!pte`'s walk.
pub fn pte_walk(walk: &target_mm::PteWalk) -> PteWalk {
    PteWalk {
        address: walk.address,
        dtb: walk.dtb,
        levels: walk.levels().map(pte_level).collect(),
    }
}

fn process_memory_usage(usage: &target_mm::ProcessMemoryUsage) -> ProcessMemoryUsage {
    ProcessMemoryUsage {
        process: process(&usage.process),
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

#[cfg(all(test, feature = "mcp"))]
mod tests {
    use super::memory_usage;
    use crate::debugger_data::MetadataSource;
    use crate::target::mm::SystemMemorySummary;
    use crate::target::{DiagnosticMetric, DiagnosticValue};
    use crate::view::to_json;

    #[test]
    fn diagnostic_memory_view_retains_values_errors_and_provenance() {
        let available = DiagnosticMetric {
            value: DiagnosticValue::Available(0x1234),
            source: Some(MetadataSource::KernelSymbol),
        };
        let unavailable = DiagnosticMetric {
            value: DiagnosticValue::Unavailable("missing MmAvailablePages".into()),
            source: None,
        };
        let summary = SystemMemorySummary {
            physical_pages: available.clone(),
            available_pages: unavailable.clone(),
            committed_pages: available.clone(),
            commit_limit_pages: available.clone(),
            paged_pool_pages: available.clone(),
            nonpaged_pool_bytes: unavailable,
            processes: Vec::new(),
            process_count: 3,
            truncated: true,
        };

        let json = to_json(&memory_usage(&summary).into_view());
        assert_eq!(json["physical_pages"]["value"], 0x1234);
        assert_eq!(json["physical_pages"]["source"], "kernel symbol");
        assert_eq!(json["available_pages"]["available"], false);
        assert_eq!(json["available_pages"]["error"], "missing MmAvailablePages");
        assert_eq!(json["process_count"], 3);
        assert_eq!(json["truncated"], true);
    }
}
