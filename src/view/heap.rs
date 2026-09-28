//! Heap [`View`] builders for the structured inspectors.

use super::shape::{Diag, Hex, shapes, unions};
use crate::target::heap::{self as target, BlockMatch, HeapKind, SegmentSubsegment};
use crate::types::VirtAddr;

shapes! {
    /// A process's PEB heap list (`!heap` / `!heap -s`).
    HeapSummary {
        /// The process environment block the list was read from.
        peb: VirtAddr,
        /// Whether the list was longer than the walk limit and was cut short.
        truncated: bool,
        heaps: Vec<HeapOverview>,
    }

    /// One heap in the PEB list, with its usage totals.
    HeapOverview {
        /// Position in the PEB heap list.
        index: usize,
        address: VirtAddr,
        /// `nt`, `segment`, or `unknown (<signature>)`.
        kind: String,
        /// Unavailable when the heap's signature, layout, memory, or symbols
        /// cannot be read.
        stats: Diag<HeapStats>,
    }

    /// Usage totals of one heap.
    HeapStats {
        /// `_HEAP.Flags` (NT heap) or `GlobalFlags` (segment heap).
        flags: Hex<u32>,
        /// Reserved bytes.
        reserved: u64,
        /// Committed bytes.
        committed: u64,
        /// Free bytes: free NT-heap blocks, or free committed segment-heap pages.
        free: u64,
        /// NT-heap segments, or segment-heap page segments.
        segments: u64,
        /// NT-heap virtually allocated blocks; 0 for a segment heap.
        virtual_blocks: u64,
        /// NT-heap front-end (LFH) address; None when there is none or for a
        /// segment heap.
        front_end: Option<VirtAddr>,
        /// NT-heap `FrontEndHeapType`; 0 for a segment heap.
        front_end_type: u8,
        /// Segment-heap VS page ranges; 0 for an NT heap.
        vs_subsegments: u64,
        /// Segment-heap LFH page ranges; 0 for an NT heap.
        lfh_subsegments: u64,
        /// Segment-heap ranges allocated straight from a segment; 0 for an NT heap.
        page_allocations: u64,
        /// Segment-heap large allocations; 0 for an NT heap.
        large_allocations: u64,
    }

    /// One decoded heap (`!heap -h|-a <heap>`, `Heap.inspect()`).
    HeapDetail {
        /// Position in the PEB heap list.
        index: usize,
        address: VirtAddr,
        /// `nt`, `segment`, or `unknown (<signature>)`.
        kind: String,
        /// Whether entries, chunks, and blocks were walked and listed.
        list_entries: bool,
        /// The NT (`_HEAP`) decoding; None for other heaps or when it failed.
        nt: Option<NtHeap>,
        /// The segment-heap decoding; None for other heaps or when it failed.
        segment: Option<SegmentHeap>,
        /// Why the heap could not be decoded.
        error: Option<String>,
    }

    /// An NT (`_HEAP`) heap.
    NtHeap {
        address: VirtAddr,
        /// `_HEAP.Flags`.
        flags: Hex<u32>,
        /// `_HEAP.ForceFlags`.
        force_flags: Hex<u32>,
        /// Size of `_HEAP_ENTRY` in bytes: 16 on x64, 8 on x86; every block
        /// starts with one.
        granule: u64,
        /// XOR mask over every entry header's metadata; None when headers are
        /// not encoded.
        encoding: Option<Hex>,
        /// Free space, in granules.
        total_free_units: u64,
        /// `_HEAP.VirtualMemoryThreshold`, in granules.
        virtual_threshold: u32,
        /// The front-end (LFH) heap; None when there is none.
        front_end: Option<VirtAddr>,
        /// `_HEAP.FrontEndHeapType`.
        front_end_type: u8,
        /// Blocks too large for a segment, allocated on their own.
        virtual_blocks: Vec<NtVirtualBlock>,
        segments: Vec<NtHeapSegment>,
    }

    /// An NT-heap block allocated on its own (`_HEAP_VIRTUAL_ALLOC_ENTRY`).
    NtVirtualBlock {
        /// The block's header.
        entry: VirtAddr,
        /// Committed bytes.
        commit_size: u64,
        /// Reserved bytes.
        reserve_size: u64,
        /// First user byte.
        user: VirtAddr,
        /// Always `virtual`.
        kind: &'static str,
    }

    /// One `_HEAP_SEGMENT` of an NT heap.
    NtHeapSegment {
        /// The segment header.
        address: VirtAddr,
        /// First byte the segment spans.
        base: VirtAddr,
        /// Byte past the segment's last page.
        end: Hex,
        pages: u32,
        uncommitted_pages: u32,
        /// Uncommitted ranges the entry chain skips over.
        uncommitted: Vec<NtUncommittedRange>,
        first_entry: VirtAddr,
        last_valid_entry: VirtAddr,
        /// The segment's entry chain; empty unless entries were listed.
        entries: Vec<NtHeapEntry>,
        /// Where and why the chain walk ended before `last_valid_entry`; None
        /// when it did not.
        stopped: Option<HeapWalkStop>,
    }

    /// An uncommitted range of an NT-heap segment.
    NtUncommittedRange {
        start: Hex,
        /// Byte past the range.
        end: Hex,
    }

    /// Where a heap walk had to stop, and why.
    HeapWalkStop {
        address: VirtAddr,
        reason: String,
    }

    /// An NT-heap entry (`_HEAP_ENTRY`), decoded from its header.
    NtHeapEntry {
        /// The entry header.
        address: VirtAddr,
        /// Bytes, header included.
        size: u64,
        /// Bytes of the entry before it.
        previous_size: u64,
        /// The header's flags byte.
        flags: Hex<u8>,
        /// `busy` or `free`.
        state: &'static str,
        /// Always `entry`.
        kind: &'static str,
        /// Slack at the end of the block, in bytes.
        unused_bytes: u8,
        /// Whether the header's XOR checksum held (always true when headers are not
        /// encoded).
        checksum_ok: bool,
        /// Header size in bytes (see `NtHeap.granule`).
        granule: u64,
        /// First user byte.
        user: Hex,
        /// Bytes the caller asked for: the block less its header and slack.
        user_size: u64,
        /// The legacy-LFH user block region inside this busy entry; `None`
        /// when there is none or it could not be read, and in a
        /// `Heaps.find_block()` result, which does not decode it.
        lfh: Option<NtLfhUserBlocks>,
        /// Why the entry's LFH region could not be read.
        lfh_error: Option<String>,
        /// Whether the region's `blocks` were cut at the walk limit.
        lfh_truncated: bool,
    }

    /// A legacy-LFH user block region living inside one busy NT-heap entry.
    NtLfhUserBlocks {
        /// The `_HEAP_USERDATA_HEADER`.
        header: VirtAddr,
        /// The owning `_HEAP_SUBSEGMENT`.
        subsegment: VirtAddr,
        /// Bytes per block.
        block_size: u64,
        block_count: u32,
        busy_count: u32,
        first_block: VirtAddr,
        /// Bytes between consecutive blocks.
        stride: u64,
        /// One bit per block, set when busy: block `i` is byte `i / 8`, bit
        /// `i % 8`.
        busy_bitmap: Vec<u8>,
        /// The region's blocks; empty unless entries were listed.
        blocks: Vec<HeapBlock>,
    }

    /// One block of a heap walk: an NT legacy-LFH block, a segment-heap VS
    /// chunk, or a segment-heap LFH block.
    HeapBlock {
        address: VirtAddr,
        /// Bytes, header included.
        size: u64,
        /// Bytes of the block before it; None where blocks do not record it.
        previous_size: Option<u64>,
        /// Header flags; None where blocks have no header of their own.
        flags: Option<Hex<u32>>,
        /// `busy` or `free`.
        state: &'static str,
        /// `nt-lfh-block`, `vs-chunk`, or `lfh-block`.
        kind: &'static str,
        /// Slack at the end of the block, in bytes; None when not recorded.
        unused_bytes: Option<u64>,
        /// Whether the header checksum held; None where there is no checksum.
        checksum_ok: Option<bool>,
        /// First user byte.
        user: Option<VirtAddr>,
        /// Bytes available to the caller.
        user_size: Option<u64>,
        /// Position in its region or subsegment; None for VS chunks.
        index: Option<u32>,
    }

    /// A segment heap (`_SEGMENT_HEAP`).
    SegmentHeap {
        address: VirtAddr,
        /// `_SEGMENT_HEAP.GlobalFlags`.
        global_flags: Hex<u32>,
        reserved_pages: u64,
        committed_pages: u64,
        free_committed_pages: u64,
        lfh_free_committed_pages: u64,
        vs_free_committed_pages: u64,
        large_reserved_pages: u64,
        large_committed_pages: u64,
        /// The `ntdll!RtlpHpHeapGlobals` keys that encode chunk headers.
        encoding_keys: SegmentHeapKeys => "keys",
        /// Size of `_HEAP_VS_CHUNK_HEADER` in bytes: 16 on x64, 8 on x86;
        /// every VS chunk starts with one.
        granule: u64,
        /// Segment contexts (`SegContexts`), one per page-segment size class.
        contexts: Vec<SegmentHeapContext>,
        large_allocations: Vec<HeapLargeAllocation>,
    }

    /// `ntdll!RtlpHpHeapGlobals`: the keys a segment heap encodes with.
    SegmentHeapKeys {
        /// The VS chunk header key (`HeapKey`).
        heap: Hex,
        /// The LFH block-offsets key (`LfhKey`).
        lfh: Hex,
    }

    /// A segment context (`_HEAP_SEG_CONTEXT`) of a segment heap.
    SegmentHeapContext {
        /// Position in `SegContexts`.
        index: usize,
        /// log2 of `unit_size`.
        unit_shift: u8,
        /// Bytes per page-range unit.
        unit_size: u64,
        segment_mask: Hex,
        /// Bytes per page segment.
        segment_size: u64,
        /// Largest allocation this context serves, in bytes.
        max_allocation_size: u32,
        segments: Vec<SegmentHeapPageSegment>,
    }

    /// A page segment (`_HEAP_PAGE_SEGMENT`) of a segment context.
    SegmentHeapPageSegment {
        address: VirtAddr,
        ranges: Vec<HeapPageRange>,
    }

    /// A page range (`_HEAP_PAGE_RANGE_DESCRIPTOR`) of a page segment.
    HeapPageRange {
        address: VirtAddr,
        /// Bytes: `units * unit_size`.
        size: u64,
        /// Byte past the range.
        end: Hex,
        units: u64,
        /// Bytes per unit.
        unit_size: u64,
        /// The descriptor's `RangeFlags`.
        flags: Hex<u8>,
        committed_pages: u8,
        /// Slack at the end of the range, in bytes.
        unused_bytes: u32,
        /// `unused`, `free`, `page` (allocated straight from the segment),
        /// `vs`, or `lfh`.
        kind: &'static str,
        /// The VS or LFH subsegment the range holds, with its blocks; `None`
        /// for other kinds or when it could not be read, and in a
        /// `Heaps.find_block()` result, which does not decode it.
        subsegment: Option<HeapSubsegment>,
        /// Why the subsegment could not be read.
        error: Option<String>,
        /// Whether the subsegment held more blocks than the walk limit.
        truncated: bool,
    }

    /// A segment-heap variable-size subsegment (`_HEAP_VS_SUBSEGMENT`).
    VsSubsegment {
        address: VirtAddr,
        /// Whether the subsegment's signature matched.
        signature_ok: bool,
        /// The subsegment's chunks; empty unless entries were listed.
        chunks: Vec<HeapBlock>,
        /// Chunks the walk found.
        chunk_count: usize,
    }

    /// A segment-heap LFH subsegment (`_HEAP_LFH_SUBSEGMENT`).
    LfhSubsegment {
        address: VirtAddr,
        /// Bytes per block.
        block_size: u64,
        block_count: u32,
        free_count: u32,
        busy_count: u32,
        /// The LFH bucket the subsegment serves.
        bucket: u16,
        first_block: VirtAddr,
        /// Blocks per `bitmap` word.
        blocks_per_word: u32,
        /// `BlockBitmap` words (a qword on x64, a dword on x86); a block's low
        /// bit is set while it is busy.
        bitmap: Vec<Hex>,
        /// The subsegment's blocks; empty unless entries were listed.
        blocks: Vec<HeapBlock>,
    }

    /// A segment-heap VS chunk, decoded from its header.
    VsChunk {
        address: VirtAddr,
        /// Bytes, header included.
        size: u64,
        /// Bytes of the chunk before it.
        previous_size: u64,
        /// Always None: VS chunk headers carry no flags.
        flags: Option<Hex>,
        /// `busy` or `free`.
        state: &'static str,
        /// Always `vs-chunk`.
        kind: &'static str,
        /// Slack recorded in the chunk's last word, in bytes; None when the
        /// header records none.
        unused_bytes: Option<u16>,
        /// Header size in bytes (see `SegmentHeap.granule`).
        granule: u64,
        /// First user byte.
        user: Hex,
        /// Bytes available to the caller.
        user_size: u64,
    }

    /// A segment-heap large allocation (`_HEAP_LARGE_ALLOC_DATA`).
    HeapLargeAllocation {
        /// The allocation's metadata record.
        metadata: VirtAddr,
        address: VirtAddr,
        /// Bytes: `pages` pages.
        size: u64,
        pages: u64,
        /// Slack at the end of the allocation, in bytes.
        unused_bytes: u16,
        extra_present: bool,
        /// Always `large`.
        kind: &'static str,
    }

    /// Which heap block holds an address (`!heap -x <addr>`,
    /// `Heaps.find_block()`).
    HeapBlockSearch {
        /// The address searched for.
        address: VirtAddr,
        /// Whether a heap holds the address.
        found: bool,
        /// Whether a heap list or walk was cut at its limit, so the search may have
        /// missed the block.
        truncated: bool,
        /// The heap holding the address; None when not found.
        heap: Option<HeapIdentity>,
        /// Where in the heap the address lands; None when not found.
        block: Option<HeapBlockMatch>,
        /// Heaps that could not be searched, and why.
        errors: Vec<String>,
    }

    /// A heap named by its PEB-list position, address, and kind.
    HeapIdentity {
        /// Position in the PEB heap list.
        index: usize,
        address: VirtAddr,
        /// `nt`, `segment`, or `unknown (<signature>)`.
        kind: String,
    }

    /// An address inside an NT-heap entry.
    HeapMatchNtEntry {
        /// Always `nt-entry`.
        kind: &'static str,
        /// The `_HEAP_SEGMENT` holding the entry.
        segment: VirtAddr,
        entry: NtHeapEntry,
    }

    /// An address inside a legacy-LFH block of an NT heap.
    HeapMatchNtLfhBlock {
        /// Always `nt-lfh-block`.
        kind: &'static str,
        /// The `_HEAP_SEGMENT` holding the region.
        segment: VirtAddr,
        /// The busy entry holding the region.
        entry: NtHeapEntry,
        /// The user block region (its `blocks` left empty).
        region: NtLfhUserBlocks,
        /// The block's position in the region.
        index: u32,
        address: VirtAddr,
        /// Bytes per block.
        size: u64,
        /// `busy` or `free`.
        state: &'static str,
        /// First user byte.
        user: Hex,
    }

    /// An address inside an NT-heap virtually allocated block.
    HeapMatchNtVirtual {
        /// Always `nt-virtual`.
        kind: &'static str,
        address: VirtAddr,
        /// Bytes: the larger of the reserve and commit sizes.
        size: u64,
        /// Always `virtual`.
        state: &'static str,
        /// The block's header.
        entry: VirtAddr,
        commit_size: u64,
        reserve_size: u64,
        /// First user byte.
        user: VirtAddr,
    }

    /// An address inside an NT-heap segment but on no entry: the heap header,
    /// an uncommitted range, or past where the walk had to stop.
    HeapMatchNtSegment {
        /// Always `nt-segment`.
        kind: &'static str,
        segment: VirtAddr,
        /// Where and why the entry walk stopped; None when it did not.
        stopped: Option<HeapWalkStop>,
    }

    /// An address inside a segment-heap range allocated straight from its
    /// segment.
    HeapMatchPage {
        /// Always `page`.
        kind: &'static str,
        range: HeapPageRange,
        /// First user byte.
        user: VirtAddr,
        /// Bytes in the range.
        size: u64,
    }

    /// An address inside a segment-heap VS chunk.
    HeapMatchVsChunk {
        /// Always `vs-chunk`.
        kind: &'static str,
        range: HeapPageRange,
        /// The `_HEAP_VS_SUBSEGMENT` holding the chunk.
        subsegment: VirtAddr,
        chunk: VsChunk,
    }

    /// An address inside a segment-heap LFH block.
    HeapMatchLfhBlock {
        /// Always `lfh-block`.
        kind: &'static str,
        range: HeapPageRange,
        /// The subsegment holding the block (its `blocks` left empty).
        subsegment: LfhSubsegment,
        /// The block's position in the subsegment.
        index: u32,
        address: Hex,
        /// `busy` or `free`.
        state: &'static str,
    }

    /// An address inside a segment-heap page range but outside its
    /// subsegment's blocks (header, bitmap, or trailing slack).
    HeapMatchRange {
        /// Always `range`.
        kind: &'static str,
        range: HeapPageRange,
    }

    /// An address inside a segment-heap large allocation.
    HeapMatchLarge {
        /// Always `large`.
        kind: &'static str,
        allocation: HeapLargeAllocation,
    }
}

unions! {
    /// A page range's subsegment: VS or LFH.
    HeapSubsegment {
        Vs(VsSubsegment),
        Lfh(LfhSubsegment),
    }
}

unions! {
    /// Where a searched address lands, told apart by `kind`.
    HeapBlockMatch {
        NtEntry(HeapMatchNtEntry),
        NtLfhBlock(HeapMatchNtLfhBlock),
        NtVirtual(HeapMatchNtVirtual),
        NtSegment(HeapMatchNtSegment),
        Page(HeapMatchPage),
        VsChunk(HeapMatchVsChunk),
        LfhBlock(HeapMatchLfhBlock),
        Range(HeapMatchRange),
        Large(HeapMatchLarge),
    }
}

fn heap_kind(kind: HeapKind) -> String {
    match kind {
        HeapKind::Nt => "nt".to_string(),
        HeapKind::Segment => "segment".to_string(),
        HeapKind::Unknown(signature) => format!("unknown ({signature:#x})"),
    }
}

fn busy_state(busy: bool) -> &'static str {
    if busy { "busy" } else { "free" }
}

fn heap_summary_stats(stats: &target::HeapSummaryStats) -> HeapStats {
    HeapStats {
        flags: stats.flags,
        reserved: stats.reserved,
        committed: stats.committed,
        free: stats.free,
        segments: stats.segments,
        virtual_blocks: stats.virtual_blocks,
        front_end: stats.front_end,
        front_end_type: stats.front_end_type,
        vs_subsegments: stats.vs_subsegments,
        lfh_subsegments: stats.lfh_subsegments,
        page_allocations: stats.page_allocations,
        large_allocations: stats.large_allocations,
    }
}

pub fn heap_summary(summary: &target::HeapSummaryDetail) -> HeapSummary {
    HeapSummary {
        peb: summary.peb,
        truncated: summary.truncated,
        heaps: summary
            .heaps
            .iter()
            .map(|item| HeapOverview {
                index: item.index,
                address: item.address,
                kind: heap_kind(item.kind),
                stats: item.stats.map(heap_summary_stats),
            })
            .collect(),
    }
}

fn nt_entry(entry: &target::NtEntry) -> NtHeapEntry {
    NtHeapEntry {
        address: entry.address,
        size: entry.size,
        previous_size: entry.previous_size,
        flags: entry.flags,
        state: busy_state(entry.busy()),
        kind: "entry",
        unused_bytes: entry.unused_bytes,
        checksum_ok: entry.checksum_ok,
        granule: entry.granule,
        user: entry.user().0,
        user_size: entry.user_size(),
        lfh: None,
        lfh_error: None,
        lfh_truncated: false,
    }
}

fn heap_block(block: &target::HeapBlockDetail) -> HeapBlock {
    HeapBlock {
        address: block.address,
        size: block.size,
        previous_size: block.previous_size,
        flags: block.flags,
        state: block.state,
        kind: block.kind,
        unused_bytes: block.unused_bytes,
        checksum_ok: block.checksum_ok,
        user: block.user,
        user_size: block.user_size,
        index: block.index,
    }
}

/// The target lists `blocks` only when entries were requested, one per
/// block of the region or subsegment, so they are the whole listing.
fn heap_blocks(blocks: &[target::HeapBlockDetail]) -> Vec<HeapBlock> {
    blocks.iter().map(heap_block).collect()
}

fn nt_lfh(region: &target::NtUserBlocks, blocks: &[target::HeapBlockDetail]) -> NtLfhUserBlocks {
    NtLfhUserBlocks {
        header: region.header,
        subsegment: region.subsegment,
        block_size: region.block_size,
        block_count: region.block_count,
        busy_count: region.busy_count(),
        first_block: region.first_block,
        stride: region.stride,
        busy_bitmap: region.busy.clone(),
        blocks: heap_blocks(blocks),
    }
}

fn nt_entry_detail(entry: &target::NtEntryDetail) -> NtHeapEntry {
    NtHeapEntry {
        lfh: entry
            .lfh
            .as_ref()
            .map(|region| nt_lfh(region, &entry.lfh_blocks)),
        lfh_error: entry.lfh_error.clone(),
        lfh_truncated: entry.lfh_truncated,
        ..nt_entry(&entry.entry)
    }
}

fn walk_stop(address: VirtAddr, reason: &str) -> HeapWalkStop {
    HeapWalkStop {
        address,
        reason: reason.to_string(),
    }
}

fn nt_segment(segment: &target::NtSegmentDetail) -> NtHeapSegment {
    let raw = &segment.segment;
    NtHeapSegment {
        address: raw.address,
        base: raw.base,
        end: raw.end().0,
        pages: raw.pages,
        uncommitted_pages: raw.uncommitted_pages,
        uncommitted: raw
            .uncommitted
            .iter()
            .map(|range| NtUncommittedRange {
                start: range.start,
                end: range.end,
            })
            .collect(),
        first_entry: raw.first_entry,
        last_valid_entry: raw.last_valid_entry,
        entries: segment.entries.iter().map(nt_entry_detail).collect(),
        stopped: segment
            .stopped
            .as_ref()
            .map(|stop| walk_stop(stop.address, &stop.reason)),
    }
}

fn nt_heap(detail: &target::NtHeapDetail) -> NtHeap {
    let heap = &detail.heap;
    NtHeap {
        address: heap.address,
        flags: heap.flags,
        force_flags: heap.force_flags,
        granule: heap.granule,
        encoding: heap.encoding,
        total_free_units: heap.total_free_units,
        virtual_threshold: heap.virtual_threshold,
        front_end: heap.front_end,
        front_end_type: heap.front_end_type,
        virtual_blocks: heap
            .virtual_blocks
            .iter()
            .map(|block| NtVirtualBlock {
                entry: block.entry,
                commit_size: block.commit_size,
                reserve_size: block.reserve_size,
                user: block.user,
                kind: "virtual",
            })
            .collect(),
        segments: detail.segments.iter().map(nt_segment).collect(),
    }
}

fn vs_chunk(chunk: &target::VsChunk) -> VsChunk {
    VsChunk {
        address: chunk.address,
        size: chunk.size,
        previous_size: chunk.previous_size,
        flags: None,
        state: busy_state(chunk.busy),
        kind: "vs-chunk",
        unused_bytes: chunk.unused_bytes,
        granule: chunk.granule,
        user: chunk.user().0,
        user_size: chunk.user_size(),
    }
}

fn lfh_subsegment(
    subsegment: &target::LfhSubsegment,
    blocks: &[target::HeapBlockDetail],
) -> LfhSubsegment {
    LfhSubsegment {
        address: subsegment.address,
        block_size: subsegment.block_size,
        block_count: subsegment.block_count,
        free_count: subsegment.free_count,
        busy_count: subsegment.busy_count(),
        bucket: subsegment.bucket,
        first_block: subsegment.first_block,
        blocks_per_word: subsegment.blocks_per_word,
        bitmap: subsegment.bitmap.to_vec(),
        blocks: heap_blocks(blocks),
    }
}

/// A page range as a block search reports it, without its decoding.
fn page_range(range: &target::PageRange) -> HeapPageRange {
    HeapPageRange {
        address: range.address,
        size: range.size(),
        end: range.end().0,
        units: range.units,
        unit_size: range.unit_size,
        flags: range.flags,
        committed_pages: range.committed_pages,
        unused_bytes: range.unused_bytes,
        kind: range.kind.name(),
        subsegment: None,
        error: None,
        truncated: false,
    }
}

fn segment_range(range: &target::SegmentRangeDetail) -> HeapPageRange {
    let subsegment = range
        .subsegment
        .as_ref()
        .map(|subsegment| match subsegment {
            SegmentSubsegment::Vs(subsegment) => HeapSubsegment::Vs(VsSubsegment {
                address: subsegment.address,
                signature_ok: subsegment.signature_ok,
                chunks: heap_blocks(&range.blocks),
                chunk_count: subsegment.chunks.len(),
            }),
            SegmentSubsegment::Lfh(subsegment) => {
                HeapSubsegment::Lfh(lfh_subsegment(subsegment, &range.blocks))
            }
        });
    HeapPageRange {
        subsegment,
        error: range.error.clone(),
        truncated: range.truncated,
        ..page_range(&range.range)
    }
}

fn segment_context(context: &target::SegmentContextDetail) -> SegmentHeapContext {
    let raw = &context.context;
    SegmentHeapContext {
        index: raw.index,
        unit_shift: raw.unit_shift,
        unit_size: raw.unit_size(),
        segment_mask: raw.segment_mask,
        segment_size: raw.segment_size(),
        max_allocation_size: raw.max_allocation_size,
        segments: context
            .segments
            .iter()
            .map(|segment| SegmentHeapPageSegment {
                address: segment.segment.address,
                ranges: segment.ranges.iter().map(segment_range).collect(),
            })
            .collect(),
    }
}

fn large_allocation(allocation: &target::LargeAllocation) -> HeapLargeAllocation {
    HeapLargeAllocation {
        metadata: allocation.metadata,
        address: allocation.address,
        size: allocation.size(),
        pages: allocation.pages,
        unused_bytes: allocation.unused_bytes,
        extra_present: allocation.extra_present,
        kind: "large",
    }
}

fn segment_heap(detail: &target::SegmentHeapDetail) -> SegmentHeap {
    let heap = &detail.heap;
    SegmentHeap {
        address: heap.address,
        global_flags: heap.global_flags,
        reserved_pages: heap.reserved_pages,
        committed_pages: heap.committed_pages,
        free_committed_pages: heap.free_committed_pages,
        lfh_free_committed_pages: heap.lfh_free_committed_pages,
        vs_free_committed_pages: heap.vs_free_committed_pages,
        large_reserved_pages: heap.large_reserved_pages,
        large_committed_pages: heap.large_committed_pages,
        encoding_keys: SegmentHeapKeys {
            heap: heap.keys.heap_key,
            lfh: heap.keys.lfh_key,
        },
        granule: heap.granule,
        contexts: detail.contexts.iter().map(segment_context).collect(),
        large_allocations: heap
            .large_allocations
            .iter()
            .map(large_allocation)
            .collect(),
    }
}

pub fn heap(detail: &target::HeapDetail) -> HeapDetail {
    HeapDetail {
        index: detail.index,
        address: detail.address,
        kind: heap_kind(detail.kind),
        list_entries: detail.list_entries,
        nt: detail.nt.as_ref().map(nt_heap),
        segment: detail.segment.as_ref().map(segment_heap),
        error: detail.error.clone(),
    }
}

fn block_match(block: &BlockMatch) -> HeapBlockMatch {
    match block {
        BlockMatch::NtEntry { segment, entry } => HeapBlockMatch::NtEntry(HeapMatchNtEntry {
            kind: "nt-entry",
            segment: *segment,
            entry: nt_entry(entry),
        }),
        BlockMatch::NtLfhBlock {
            segment,
            entry,
            region,
            index,
        } => {
            let address = region.block(*index);
            HeapBlockMatch::NtLfhBlock(HeapMatchNtLfhBlock {
                kind: "nt-lfh-block",
                segment: *segment,
                entry: nt_entry(entry),
                region: nt_lfh(region, &[]),
                index: *index,
                address,
                size: region.block_size,
                state: busy_state(region.is_busy(*index)),
                user: (address + entry.granule).0,
            })
        }
        BlockMatch::NtVirtual(block) => HeapBlockMatch::NtVirtual(HeapMatchNtVirtual {
            kind: "nt-virtual",
            address: block.entry,
            size: block.reserve_size.max(block.commit_size),
            state: "virtual",
            entry: block.entry,
            commit_size: block.commit_size,
            reserve_size: block.reserve_size,
            user: block.user,
        }),
        BlockMatch::NtSegmentOnly { segment, stopped } => {
            HeapBlockMatch::NtSegment(HeapMatchNtSegment {
                kind: "nt-segment",
                segment: *segment,
                stopped: stopped.map(|(address, reason)| walk_stop(address, reason)),
            })
        }
        BlockMatch::Direct(range) => HeapBlockMatch::Page(HeapMatchPage {
            kind: "page",
            range: page_range(range),
            user: range.address,
            size: range.size(),
        }),
        BlockMatch::VsChunk {
            range,
            subsegment,
            chunk,
        } => HeapBlockMatch::VsChunk(HeapMatchVsChunk {
            kind: "vs-chunk",
            range: page_range(range),
            subsegment: *subsegment,
            chunk: vs_chunk(chunk),
        }),
        BlockMatch::LfhBlock {
            range,
            subsegment,
            index,
        } => HeapBlockMatch::LfhBlock(HeapMatchLfhBlock {
            kind: "lfh-block",
            range: page_range(range),
            subsegment: lfh_subsegment(subsegment, &[]),
            index: *index,
            address: subsegment.block(*index).0,
            state: busy_state(subsegment.is_busy(*index)),
        }),
        BlockMatch::RangeOnly(range) => HeapBlockMatch::Range(HeapMatchRange {
            kind: "range",
            range: page_range(range),
        }),
        BlockMatch::Large(large) => HeapBlockMatch::Large(HeapMatchLarge {
            kind: "large",
            allocation: large_allocation(large),
        }),
    }
}

pub fn heap_block_search(detail: &target::HeapBlockSearchDetail) -> HeapBlockSearch {
    HeapBlockSearch {
        address: detail.address,
        found: detail.found,
        truncated: detail.truncated,
        heap: detail.heap.as_ref().map(|heap| HeapIdentity {
            index: heap.index,
            address: heap.address,
            kind: heap_kind(heap.kind),
        }),
        block: detail.block.as_ref().map(block_match),
        errors: detail.errors.clone(),
    }
}
