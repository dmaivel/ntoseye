//! Heap [`View`] builders for the structured inspectors.

use super::shape::{Diag, Hex, shapes, unions};
use crate::target::heap::{self as target, BlockMatch, HeapKind, SegmentSubsegment};
use crate::types::VirtAddr;

shapes! {
    /// A process's PEB heap list (`!heap` / `!heap -s`).
    HeapSummary {
        /// The process environment block that ntoseye read the list from.
        peb: VirtAddr,
        /// Whether the list is longer than the walk limit, which leaves it
        /// incomplete.
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
        /// Unavailable if ntoseye cannot read the heap signature, layout, memory,
        /// or symbols.
        stats: Diag<HeapStats>,
    }

    /// The usage totals of one heap.
    HeapStats {
        /// `_HEAP.Flags` (NT heap) or `GlobalFlags` (segment heap).
        flags: Hex<u32>,
        /// Reserved bytes.
        reserved: u64,
        /// Committed bytes.
        committed: u64,
        /// Free bytes: the free blocks of an NT heap, or the free committed
        /// pages of a segment heap.
        free: u64,
        /// The number of NT-heap segments or segment-heap page segments.
        segments: u64,
        /// The number of NT-heap virtually allocated blocks. 0 for a segment heap.
        virtual_blocks: u64,
        /// The address of the NT-heap front end (LFH). None if the heap has no
        /// front end or is a segment heap.
        front_end: Option<VirtAddr>,
        /// The NT-heap `FrontEndHeapType`. 0 for a segment heap.
        front_end_type: u8,
        /// The number of segment-heap VS page ranges. 0 for an NT heap.
        vs_subsegments: u64,
        /// The number of segment-heap LFH page ranges. 0 for an NT heap.
        lfh_subsegments: u64,
        /// The number of segment-heap ranges allocated directly from a segment.
        /// 0 for an NT heap.
        page_allocations: u64,
        /// The number of segment-heap large allocations. 0 for an NT heap.
        large_allocations: u64,
    }

    /// One decoded heap (`!heap -h|-a <heap>`, `Heap.inspect()`).
    HeapDetail {
        /// Position in the PEB heap list.
        index: usize,
        address: VirtAddr,
        /// `nt`, `segment`, or `unknown (<signature>)`.
        kind: String,
        /// Whether ntoseye walked and listed the entries, chunks, and blocks.
        list_entries: bool,
        /// The NT (`_HEAP`) decoding. None for other heap kinds or if the
        /// decoding failed.
        nt: Option<NtHeap>,
        /// The segment-heap decoding. None for other heap kinds or if the
        /// decoding failed.
        segment: Option<SegmentHeap>,
        /// The reason that ntoseye could not decode the heap.
        error: Option<String>,
    }

    /// An NT (`_HEAP`) heap.
    NtHeap {
        address: VirtAddr,
        /// `_HEAP.Flags`.
        flags: Hex<u32>,
        /// `_HEAP.ForceFlags`.
        force_flags: Hex<u32>,
        /// The size in bytes of the `_HEAP_ENTRY` that starts each block: 16 on
        /// x64, 8 on x86.
        granule: u64,
        /// The XOR mask on the metadata of each entry header. None if the
        /// headers are not encoded.
        encoding: Option<Hex>,
        /// The free space, in granules.
        total_free_units: u64,
        /// `_HEAP.VirtualMemoryThreshold`, in granules.
        virtual_threshold: u32,
        /// The front-end (LFH) heap. None if the heap has no front end.
        front_end: Option<VirtAddr>,
        /// `_HEAP.FrontEndHeapType`.
        front_end_type: u8,
        /// Blocks that are too large for a segment, which the heap allocates
        /// separately.
        virtual_blocks: Vec<NtVirtualBlock>,
        segments: Vec<NtHeapSegment>,
    }

    /// An NT-heap block with a separate allocation (`_HEAP_VIRTUAL_ALLOC_ENTRY`).
    NtVirtualBlock {
        /// The block header.
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
        /// The first byte of the segment.
        base: VirtAddr,
        /// The first byte after the last page of the segment.
        end: Hex,
        pages: u32,
        uncommitted_pages: u32,
        /// The uncommitted ranges that the entry chain skips.
        uncommitted: Vec<NtUncommittedRange>,
        first_entry: VirtAddr,
        last_valid_entry: VirtAddr,
        /// The entry chain of the segment. Empty unless the entries were listed.
        entries: Vec<NtHeapEntry>,
        /// Where the chain walk stopped before `last_valid_entry`, and why. None
        /// if the walk did not stop before `last_valid_entry`.
        stopped: Option<HeapWalkStop>,
    }

    /// An uncommitted range of an NT-heap segment.
    NtUncommittedRange {
        start: Hex,
        /// The first byte after the range.
        end: Hex,
    }

    /// The address where a heap walk stopped, and the reason.
    HeapWalkStop {
        address: VirtAddr,
        reason: String,
    }

    /// An NT-heap entry (`_HEAP_ENTRY`), decoded from its header.
    NtHeapEntry {
        /// The entry header.
        address: VirtAddr,
        /// The size in bytes, with the header.
        size: u64,
        /// The size in bytes of the previous entry.
        previous_size: u64,
        /// The flags byte of the header.
        flags: Hex<u8>,
        /// `busy` or `free`.
        state: &'static str,
        /// Always `entry`.
        kind: &'static str,
        /// The number of unused bytes at the end of the block.
        unused_bytes: u8,
        /// Whether the XOR checksum of the header is correct. Always true if the
        /// headers are not encoded.
        checksum_ok: bool,
        /// The header size in bytes (see `NtHeap.granule`).
        granule: u64,
        /// First user byte.
        user: Hex,
        /// The number of bytes that the caller requested: the block size minus
        /// the header and the unused bytes.
        user_size: u64,
        /// The legacy-LFH user block region in this busy entry. `None` if the
        /// entry has no region or ntoseye cannot read it. Also `None` in a
        /// `Heaps.find_block()` result, because `find_block()` does not decode
        /// the region.
        lfh: Option<NtLfhUserBlocks>,
        /// The reason that ntoseye could not read the LFH region of the entry.
        lfh_error: Option<String>,
        /// Whether the `blocks` list of the region stops at the walk limit.
        lfh_truncated: bool,
    }

    /// A legacy-LFH user block region in one busy NT-heap entry.
    NtLfhUserBlocks {
        /// The `_HEAP_USERDATA_HEADER`.
        header: VirtAddr,
        /// The `_HEAP_SUBSEGMENT` that owns the region.
        subsegment: VirtAddr,
        /// Bytes per block.
        block_size: u64,
        block_count: u32,
        busy_count: u32,
        first_block: VirtAddr,
        /// The distance in bytes between consecutive blocks.
        stride: u64,
        /// One bit for each block, set if the block is busy. Block `i` is byte
        /// `i / 8`, bit `i % 8`.
        busy_bitmap: Vec<u8>,
        /// The blocks of the region. Empty unless the entries were listed.
        blocks: Vec<HeapBlock>,
    }

    /// One block of a heap walk: an NT legacy-LFH block, a segment-heap VS
    /// chunk, or a segment-heap LFH block.
    HeapBlock {
        address: VirtAddr,
        /// The size in bytes, with the header.
        size: u64,
        /// The size in bytes of the previous block. None if the block kind
        /// does not record it.
        previous_size: Option<u64>,
        /// The header flags. None if the block kind has no header of its own.
        flags: Option<Hex<u32>>,
        /// `busy` or `free`.
        state: &'static str,
        /// `nt-lfh-block`, `vs-chunk`, or `lfh-block`.
        kind: &'static str,
        /// The number of unused bytes at the end of the block. None if the
        /// block does not record them.
        unused_bytes: Option<u64>,
        /// Whether the header checksum is correct. None if the block kind has
        /// no checksum.
        checksum_ok: Option<bool>,
        /// First user byte.
        user: Option<VirtAddr>,
        /// The number of bytes that the caller can use.
        user_size: Option<u64>,
        /// The position in the region or subsegment. None for VS chunks.
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
        /// The size in bytes of the `_HEAP_VS_CHUNK_HEADER` that starts each VS
        /// chunk: 16 on x64, 8 on x86.
        granule: u64,
        /// The segment contexts (`SegContexts`), one for each page-segment size
        /// class.
        contexts: Vec<SegmentHeapContext>,
        large_allocations: Vec<HeapLargeAllocation>,
    }

    /// `ntdll!RtlpHpHeapGlobals`: the encoding keys of a segment heap.
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
        /// The maximum allocation size for this context, in bytes.
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
        /// The size in bytes: `units * unit_size`.
        size: u64,
        /// The first byte after the range.
        end: Hex,
        units: u64,
        /// Bytes per unit.
        unit_size: u64,
        /// The descriptor's `RangeFlags`.
        flags: Hex<u8>,
        committed_pages: u8,
        /// The number of unused bytes at the end of the range.
        unused_bytes: u32,
        /// `unused`, `free`, `page` (allocated directly from the segment),
        /// `vs`, or `lfh`.
        kind: &'static str,
        /// The VS or LFH subsegment in the range, with its blocks. `None` for
        /// other kinds, or if ntoseye cannot read the subsegment. Also `None` in
        /// a `Heaps.find_block()` result, because `find_block()` does not decode
        /// the subsegment.
        subsegment: Option<HeapSubsegment>,
        /// The reason that ntoseye could not read the subsegment.
        error: Option<String>,
        /// Whether the subsegment has more blocks than the walk limit.
        truncated: bool,
    }

    /// A segment-heap variable-size subsegment (`_HEAP_VS_SUBSEGMENT`).
    VsSubsegment {
        address: VirtAddr,
        /// Whether the signature of the subsegment matches the expected value.
        signature_ok: bool,
        /// The chunks of the subsegment. Empty unless the entries were listed.
        chunks: Vec<HeapBlock>,
        /// The number of chunks that the walk found.
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
        /// The LFH bucket of the subsegment.
        bucket: u16,
        first_block: VirtAddr,
        /// Blocks per `bitmap` word.
        blocks_per_word: u32,
        /// The `BlockBitmap` words: a qword on x64, a dword on x86. The low bit
        /// for a block is set while the block is busy.
        bitmap: Vec<Hex>,
        /// The blocks of the subsegment. Empty unless the entries were listed.
        blocks: Vec<HeapBlock>,
    }

    /// A segment-heap VS chunk, decoded from its header.
    VsChunk {
        address: VirtAddr,
        /// The size in bytes, with the header.
        size: u64,
        /// The size in bytes of the previous chunk.
        previous_size: u64,
        /// Always None, because VS chunk headers have no flags.
        flags: Option<Hex>,
        /// `busy` or `free`.
        state: &'static str,
        /// Always `vs-chunk`.
        kind: &'static str,
        /// The number of unused bytes, as recorded in the last word of the
        /// chunk. None if the header records no unused bytes.
        unused_bytes: Option<u16>,
        /// The header size in bytes (see `SegmentHeap.granule`).
        granule: u64,
        /// First user byte.
        user: Hex,
        /// The number of bytes that the caller can use.
        user_size: u64,
    }

    /// A segment-heap large allocation (`_HEAP_LARGE_ALLOC_DATA`).
    HeapLargeAllocation {
        /// The metadata record of the allocation.
        metadata: VirtAddr,
        address: VirtAddr,
        /// The size in bytes: `pages` pages.
        size: u64,
        pages: u64,
        /// The number of unused bytes at the end of the allocation.
        unused_bytes: u16,
        extra_present: bool,
        /// Always `large`.
        kind: &'static str,
    }

    /// The heap block that contains an address (`!heap -x <addr>`,
    /// `Heaps.find_block()`).
    HeapBlockSearch {
        /// The search address.
        address: VirtAddr,
        /// Whether a heap contains the address.
        found: bool,
        /// Whether a heap list or heap walk stopped at its limit, in which case
        /// the search may have missed the block.
        truncated: bool,
        /// The heap that contains the address. None if no heap contains it.
        heap: Option<HeapIdentity>,
        /// The location of the address in the heap. None if no heap contains
        /// it.
        block: Option<HeapBlockMatch>,
        /// The heaps that ntoseye could not search, and the reasons.
        errors: Vec<String>,
    }

    /// A heap, identified by its PEB-list position, address, and kind.
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
        /// The `_HEAP_SEGMENT` that contains the entry.
        segment: VirtAddr,
        entry: NtHeapEntry,
    }

    /// An address inside a legacy-LFH block of an NT heap.
    HeapMatchNtLfhBlock {
        /// Always `nt-lfh-block`.
        kind: &'static str,
        /// The `_HEAP_SEGMENT` that contains the region.
        segment: VirtAddr,
        /// The busy entry that contains the region.
        entry: NtHeapEntry,
        /// The user block region. Its `blocks` list is empty.
        region: NtLfhUserBlocks,
        /// The position of the block in the region.
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
        /// The size in bytes: the larger of the reserve size and the commit
        /// size.
        size: u64,
        /// Always `virtual`.
        state: &'static str,
        /// The block header.
        entry: VirtAddr,
        commit_size: u64,
        reserve_size: u64,
        /// First user byte.
        user: VirtAddr,
    }

    /// An address in an NT-heap segment that is not in an entry: in the heap
    /// header, in an uncommitted range, or after the point where the walk
    /// stopped.
    HeapMatchNtSegment {
        /// Always `nt-segment`.
        kind: &'static str,
        segment: VirtAddr,
        /// Where the entry walk stopped, and why. None if the walk did not stop
        /// early.
        stopped: Option<HeapWalkStop>,
    }

    /// An address in a segment-heap range that the heap allocated directly
    /// from its segment.
    HeapMatchPage {
        /// Always `page`.
        kind: &'static str,
        range: HeapPageRange,
        /// First user byte.
        user: VirtAddr,
        /// The size of the range in bytes.
        size: u64,
    }

    /// An address inside a segment-heap VS chunk.
    HeapMatchVsChunk {
        /// Always `vs-chunk`.
        kind: &'static str,
        range: HeapPageRange,
        /// The `_HEAP_VS_SUBSEGMENT` that contains the chunk.
        subsegment: VirtAddr,
        chunk: VsChunk,
    }

    /// An address inside a segment-heap LFH block.
    HeapMatchLfhBlock {
        /// Always `lfh-block`.
        kind: &'static str,
        range: HeapPageRange,
        /// The subsegment that contains the block. Its `blocks` list is empty.
        subsegment: LfhSubsegment,
        /// The position of the block in the subsegment.
        index: u32,
        address: Hex,
        /// `busy` or `free`.
        state: &'static str,
    }

    /// An address in a segment-heap page range that is not in a block of its
    /// subsegment: in the header, the bitmap, or the unused bytes at the end.
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
