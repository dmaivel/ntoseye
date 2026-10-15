//! Heap [`View`] builders for the structured inspectors.

use ntoseye_macros::record;

use crate::target::heap::{self as target, BlockMatch, HeapKind, SegmentSubsegment};
use crate::types::VirtAddr;

/// One decoded heap (`!heap -h|-a <heap>`, `Heap.inspect()`).
#[record]
pub struct HeapDetail {
    /// Position in the PEB heap list.
    pub index: usize,
    pub address: VirtAddr,
    /// `nt`, `segment`, or `unknown (<signature>)`.
    pub kind: String,
    /// Whether ntoseye walked and listed the entries, chunks, and blocks.
    pub list_entries: bool,
    /// The NT (`_HEAP`) decoding. None for other heap kinds or if the
    /// decoding failed.
    pub nt: Option<NtHeap>,
    /// The segment-heap decoding. None for other heap kinds or if the
    /// decoding failed.
    pub segment: Option<SegmentHeap>,
    /// The reason that ntoseye could not decode the heap.
    pub error: Option<String>,
}

/// An NT (`_HEAP`) heap.
#[record]
pub struct NtHeap {
    pub address: VirtAddr,
    /// `_HEAP.Flags`.
    #[record(hex)]
    pub flags: u32,
    /// `_HEAP.ForceFlags`.
    #[record(hex)]
    pub force_flags: u32,
    /// The size in bytes of the `_HEAP_ENTRY` that starts each block: 16 on
    /// x64, 8 on x86.
    pub granule: u64,
    /// The XOR mask on the metadata of each entry header. None if the
    /// headers are not encoded.
    #[record(hex)]
    pub encoding: Option<u64>,
    /// The free space, in granules.
    pub total_free_units: u64,
    /// `_HEAP.VirtualMemoryThreshold`, in granules.
    pub virtual_threshold: u32,
    /// The front-end (LFH) heap. None if the heap has no front end.
    pub front_end: Option<VirtAddr>,
    /// `_HEAP.FrontEndHeapType`.
    pub front_end_type: u8,
    /// Blocks that are too large for a segment, which the heap allocates
    /// separately.
    pub virtual_blocks: Vec<NtVirtualBlock>,
    pub segments: Vec<NtHeapSegment>,
}

/// An NT-heap block with a separate allocation (`_HEAP_VIRTUAL_ALLOC_ENTRY`).
#[record]
pub struct NtVirtualBlock {
    /// The block header.
    pub entry: VirtAddr,
    /// Committed bytes.
    pub commit_size: u64,
    /// Reserved bytes.
    pub reserve_size: u64,
    /// First user byte.
    pub user: VirtAddr,
    /// Always `virtual`.
    pub kind: &'static str,
}

/// One `_HEAP_SEGMENT` of an NT heap.
#[record]
pub struct NtHeapSegment {
    /// The segment header.
    pub address: VirtAddr,
    /// The first byte of the segment.
    pub base: VirtAddr,
    /// The first byte after the last page of the segment.
    #[record(hex)]
    pub end: u64,
    pub pages: u32,
    pub uncommitted_pages: u32,
    /// The uncommitted ranges that the entry chain skips.
    pub uncommitted: Vec<NtUncommittedRange>,
    pub first_entry: VirtAddr,
    pub last_valid_entry: VirtAddr,
    /// The entry chain of the segment. Empty unless the entries were listed.
    pub entries: Vec<NtHeapEntry>,
    /// Where the chain walk stopped before `last_valid_entry`, and why. None
    /// if the walk did not stop before `last_valid_entry`.
    pub stopped: Option<HeapWalkStop>,
}

/// An uncommitted range of an NT-heap segment.
#[record]
pub struct NtUncommittedRange {
    #[record(hex)]
    pub start: u64,
    /// The first byte after the range.
    #[record(hex)]
    pub end: u64,
}

/// The address where a heap walk stopped, and the reason.
#[record]
pub struct HeapWalkStop {
    pub address: VirtAddr,
    pub reason: String,
}

/// An NT-heap entry (`_HEAP_ENTRY`), decoded from its header.
#[record]
pub struct NtHeapEntry {
    /// The entry header.
    pub address: VirtAddr,
    /// The size in bytes, with the header.
    pub size: u64,
    /// The size in bytes of the previous entry.
    pub previous_size: u64,
    /// The flags byte of the header.
    #[record(hex)]
    pub flags: u8,
    /// `busy` or `free`.
    pub state: &'static str,
    /// Always `entry`.
    pub kind: &'static str,
    /// The number of unused bytes at the end of the block.
    pub unused_bytes: u8,
    /// Whether the XOR checksum of the header is correct. Always true if the
    /// headers are not encoded.
    pub checksum_ok: bool,
    /// The header size in bytes (see `NtHeap.granule`).
    pub granule: u64,
    /// First user byte.
    #[record(hex)]
    pub user: u64,
    /// The number of bytes that the caller requested: the block size minus
    /// the header and the unused bytes.
    pub user_size: u64,
    /// The legacy-LFH user block region in this busy entry. `None` if the
    /// entry has no region or ntoseye cannot read it. Also `None` in a
    /// `Heaps.find_block()` result, because `find_block()` does not decode
    /// the region.
    pub lfh: Option<NtLfhUserBlocks>,
    /// The reason that ntoseye could not read the LFH region of the entry.
    pub lfh_error: Option<String>,
    /// Whether the `blocks` list of the region stops at the walk limit.
    pub lfh_truncated: bool,
}

/// A legacy-LFH user block region in one busy NT-heap entry.
#[record]
pub struct NtLfhUserBlocks {
    /// The `_HEAP_USERDATA_HEADER`.
    pub header: VirtAddr,
    /// The `_HEAP_SUBSEGMENT` that owns the region.
    pub subsegment: VirtAddr,
    /// Bytes per block.
    pub block_size: u64,
    pub block_count: u32,
    pub busy_count: u32,
    pub first_block: VirtAddr,
    /// The distance in bytes between consecutive blocks.
    pub stride: u64,
    /// One bit for each block, set if the block is busy. Block `i` is byte
    /// `i / 8`, bit `i % 8`.
    pub busy_bitmap: Vec<u8>,
    /// The blocks of the region. Empty unless the entries were listed.
    pub blocks: Vec<HeapBlock>,
}

/// One block of a heap walk: an NT legacy-LFH block, a segment-heap VS
/// chunk, or a segment-heap LFH block.
#[record]
pub struct HeapBlock {
    pub address: VirtAddr,
    /// The size in bytes, with the header.
    pub size: u64,
    /// The size in bytes of the previous block. None if the block kind
    /// does not record it.
    pub previous_size: Option<u64>,
    /// The header flags. None if the block kind has no header of its own.
    #[record(hex)]
    pub flags: Option<u32>,
    /// `busy` or `free`.
    pub state: &'static str,
    /// `nt-lfh-block`, `vs-chunk`, or `lfh-block`.
    pub kind: &'static str,
    /// The number of unused bytes at the end of the block. None if the
    /// block does not record them.
    pub unused_bytes: Option<u64>,
    /// Whether the header checksum is correct. None if the block kind has
    /// no checksum.
    pub checksum_ok: Option<bool>,
    /// First user byte.
    pub user: Option<VirtAddr>,
    /// The number of bytes that the caller can use.
    pub user_size: Option<u64>,
    /// The position in the region or subsegment. None for VS chunks.
    pub index: Option<u32>,
}

/// A segment heap (`_SEGMENT_HEAP`).
#[record]
pub struct SegmentHeap {
    pub address: VirtAddr,
    /// `_SEGMENT_HEAP.GlobalFlags`.
    #[record(hex)]
    pub global_flags: u32,
    pub reserved_pages: u64,
    pub committed_pages: u64,
    pub free_committed_pages: u64,
    pub lfh_free_committed_pages: u64,
    pub vs_free_committed_pages: u64,
    pub large_reserved_pages: u64,
    pub large_committed_pages: u64,
    /// The `ntdll!RtlpHpHeapGlobals` keys that encode chunk headers.
    #[record(rename = "keys")]
    pub encoding_keys: SegmentHeapKeys,
    /// The size in bytes of the `_HEAP_VS_CHUNK_HEADER` that starts each VS
    /// chunk: 16 on x64, 8 on x86.
    pub granule: u64,
    /// The segment contexts (`SegContexts`), one for each page-segment size
    /// class.
    pub contexts: Vec<SegmentHeapContext>,
    pub large_allocations: Vec<HeapLargeAllocation>,
}

/// `ntdll!RtlpHpHeapGlobals`: the encoding keys of a segment heap.
#[record]
pub struct SegmentHeapKeys {
    /// The VS chunk header key (`HeapKey`).
    #[record(hex)]
    pub heap: u64,
    /// The LFH block-offsets key (`LfhKey`).
    #[record(hex)]
    pub lfh: u64,
}

/// A segment context (`_HEAP_SEG_CONTEXT`) of a segment heap.
#[record]
pub struct SegmentHeapContext {
    /// Position in `SegContexts`.
    pub index: usize,
    /// log2 of `unit_size`.
    pub unit_shift: u8,
    /// Bytes per page-range unit.
    pub unit_size: u64,
    #[record(hex)]
    pub segment_mask: u64,
    /// Bytes per page segment.
    pub segment_size: u64,
    /// The maximum allocation size for this context, in bytes.
    pub max_allocation_size: u32,
    pub segments: Vec<SegmentHeapPageSegment>,
}

/// A page segment (`_HEAP_PAGE_SEGMENT`) of a segment context.
#[record]
pub struct SegmentHeapPageSegment {
    pub address: VirtAddr,
    pub ranges: Vec<HeapPageRange>,
}

/// A page range (`_HEAP_PAGE_RANGE_DESCRIPTOR`) of a page segment.
#[record]
pub struct HeapPageRange {
    pub address: VirtAddr,
    /// The size in bytes: `units * unit_size`.
    pub size: u64,
    /// The first byte after the range.
    #[record(hex)]
    pub end: u64,
    pub units: u64,
    /// Bytes per unit.
    pub unit_size: u64,
    /// The descriptor's `RangeFlags`.
    #[record(hex)]
    pub flags: u8,
    pub committed_pages: u8,
    /// The number of unused bytes at the end of the range.
    pub unused_bytes: u32,
    /// `unused`, `free`, `page` (allocated directly from the segment),
    /// `vs`, or `lfh`.
    pub kind: &'static str,
    /// The VS or LFH subsegment in the range, with its blocks. `None` for
    /// other kinds, or if ntoseye cannot read the subsegment. Also `None` in
    /// a `Heaps.find_block()` result, because `find_block()` does not decode
    /// the subsegment.
    pub subsegment: Option<HeapSubsegment>,
    /// The reason that ntoseye could not read the subsegment.
    pub error: Option<String>,
    /// Whether the subsegment has more blocks than the walk limit.
    pub truncated: bool,
}

/// A segment-heap variable-size subsegment (`_HEAP_VS_SUBSEGMENT`).
#[record]
pub struct VsSubsegment {
    pub address: VirtAddr,
    /// Whether the signature of the subsegment matches the expected value.
    pub signature_ok: bool,
    /// The chunks of the subsegment. Empty unless the entries were listed.
    pub chunks: Vec<HeapBlock>,
    /// The number of chunks that the walk found.
    pub chunk_count: usize,
}

/// A segment-heap LFH subsegment (`_HEAP_LFH_SUBSEGMENT`).
#[record]
pub struct LfhSubsegment {
    pub address: VirtAddr,
    /// Bytes per block.
    pub block_size: u64,
    pub block_count: u32,
    pub free_count: u32,
    pub busy_count: u32,
    /// The LFH bucket of the subsegment.
    pub bucket: u16,
    pub first_block: VirtAddr,
    /// Blocks per `bitmap` word.
    pub blocks_per_word: u32,
    /// The `BlockBitmap` words: a qword on x64, a dword on x86. The low bit
    /// for a block is set while the block is busy.
    #[record(hex)]
    pub bitmap: Vec<u64>,
    /// The blocks of the subsegment. Empty unless the entries were listed.
    pub blocks: Vec<HeapBlock>,
}

/// A segment-heap VS chunk, decoded from its header.
#[record]
pub struct VsChunk {
    pub address: VirtAddr,
    /// The size in bytes, with the header.
    pub size: u64,
    /// The size in bytes of the previous chunk.
    pub previous_size: u64,
    /// Always None, because VS chunk headers have no flags.
    #[record(hex)]
    pub flags: Option<u64>,
    /// `busy` or `free`.
    pub state: &'static str,
    /// Always `vs-chunk`.
    pub kind: &'static str,
    /// The number of unused bytes, as recorded in the last word of the
    /// chunk. None if the header records no unused bytes.
    pub unused_bytes: Option<u16>,
    /// The header size in bytes (see `SegmentHeap.granule`).
    pub granule: u64,
    /// First user byte.
    #[record(hex)]
    pub user: u64,
    /// The number of bytes that the caller can use.
    pub user_size: u64,
}

/// A segment-heap large allocation (`_HEAP_LARGE_ALLOC_DATA`).
#[record]
pub struct HeapLargeAllocation {
    /// The metadata record of the allocation.
    pub metadata: VirtAddr,
    pub address: VirtAddr,
    /// The size in bytes: `pages` pages.
    pub size: u64,
    pub pages: u64,
    /// The number of unused bytes at the end of the allocation.
    pub unused_bytes: u16,
    pub extra_present: bool,
    /// Always `large`.
    pub kind: &'static str,
}

/// The heap block that contains an address (`!heap -x <addr>`,
/// `Heaps.find_block()`).
#[record]
pub struct HeapBlockSearch {
    /// The search address.
    pub address: VirtAddr,
    /// Whether a heap contains the address.
    pub found: bool,
    /// Whether a heap list or heap walk stopped at its limit, in which case
    /// the search may have missed the block.
    pub truncated: bool,
    /// The heap that contains the address. None if no heap contains it.
    pub heap: Option<HeapIdentity>,
    /// The location of the address in the heap. None if no heap contains
    /// it.
    pub block: Option<HeapBlockMatch>,
    /// The heaps that ntoseye could not search, and the reasons.
    pub errors: Vec<String>,
}

/// A heap, identified by its PEB-list position, address, and kind.
#[record]
pub struct HeapIdentity {
    /// Position in the PEB heap list.
    pub index: usize,
    pub address: VirtAddr,
    /// `nt`, `segment`, or `unknown (<signature>)`.
    pub kind: String,
}

/// An address inside an NT-heap entry.
#[record]
pub struct HeapMatchNtEntry {
    /// Always `nt-entry`.
    pub kind: &'static str,
    /// The `_HEAP_SEGMENT` that contains the entry.
    pub segment: VirtAddr,
    pub entry: NtHeapEntry,
}

/// An address inside a legacy-LFH block of an NT heap.
#[record]
pub struct HeapMatchNtLfhBlock {
    /// Always `nt-lfh-block`.
    pub kind: &'static str,
    /// The `_HEAP_SEGMENT` that contains the region.
    pub segment: VirtAddr,
    /// The busy entry that contains the region.
    pub entry: NtHeapEntry,
    /// The user block region. Its `blocks` list is empty.
    pub region: NtLfhUserBlocks,
    /// The position of the block in the region.
    pub index: u32,
    pub address: VirtAddr,
    /// Bytes per block.
    pub size: u64,
    /// `busy` or `free`.
    pub state: &'static str,
    /// First user byte.
    #[record(hex)]
    pub user: u64,
}

/// An address inside an NT-heap virtually allocated block.
#[record]
pub struct HeapMatchNtVirtual {
    /// Always `nt-virtual`.
    pub kind: &'static str,
    pub address: VirtAddr,
    /// The size in bytes: the larger of the reserve size and the commit
    /// size.
    pub size: u64,
    /// Always `virtual`.
    pub state: &'static str,
    /// The block header.
    pub entry: VirtAddr,
    pub commit_size: u64,
    pub reserve_size: u64,
    /// First user byte.
    pub user: VirtAddr,
}

/// An address in an NT-heap segment that is not in an entry: in the heap
/// header, in an uncommitted range, or after the point where the walk
/// stopped.
#[record]
pub struct HeapMatchNtSegment {
    /// Always `nt-segment`.
    pub kind: &'static str,
    pub segment: VirtAddr,
    /// Where the entry walk stopped, and why. None if the walk did not stop
    /// early.
    pub stopped: Option<HeapWalkStop>,
}

/// An address in a segment-heap range that the heap allocated directly
/// from its segment.
#[record]
pub struct HeapMatchPage {
    /// Always `page`.
    pub kind: &'static str,
    pub range: HeapPageRange,
    /// First user byte.
    pub user: VirtAddr,
    /// The size of the range in bytes.
    pub size: u64,
}

/// An address inside a segment-heap VS chunk.
#[record]
pub struct HeapMatchVsChunk {
    /// Always `vs-chunk`.
    pub kind: &'static str,
    pub range: HeapPageRange,
    /// The `_HEAP_VS_SUBSEGMENT` that contains the chunk.
    pub subsegment: VirtAddr,
    pub chunk: VsChunk,
}

/// An address inside a segment-heap LFH block.
#[record]
pub struct HeapMatchLfhBlock {
    /// Always `lfh-block`.
    pub kind: &'static str,
    pub range: HeapPageRange,
    /// The subsegment that contains the block. Its `blocks` list is empty.
    pub subsegment: LfhSubsegment,
    /// The position of the block in the subsegment.
    pub index: u32,
    #[record(hex)]
    pub address: u64,
    /// `busy` or `free`.
    pub state: &'static str,
}

/// An address in a segment-heap page range that is not in a block of its
/// subsegment: in the header, the bitmap, or the unused bytes at the end.
#[record]
pub struct HeapMatchRange {
    /// Always `range`.
    pub kind: &'static str,
    pub range: HeapPageRange,
}

/// An address inside a segment-heap large allocation.
#[record]
pub struct HeapMatchLarge {
    /// Always `large`.
    pub kind: &'static str,
    pub allocation: HeapLargeAllocation,
}

/// A page range's subsegment: VS or LFH.
#[record]
pub enum HeapSubsegment {
    Vs(VsSubsegment),
    Lfh(LfhSubsegment),
}

/// Where a searched address lands, told apart by `kind`.
#[record]
pub enum HeapBlockMatch {
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
