//! Heap [`View`] builders for the structured inspectors.

use super::{View, diagnostic};
use crate::target::heap::{
    BlockMatch, HeapBlockDetail, HeapBlockSearchDetail, HeapDetail, HeapKind, HeapSummaryDetail,
    HeapSummaryItem, HeapSummaryStats, LargeAllocation, LfhSubsegment, NtEntry, NtEntryDetail,
    NtHeapDetail, NtSegmentDetail, NtUserBlocks, PageRange, SegmentContextDetail,
    SegmentHeapDetail, SegmentPageDetail, SegmentRangeDetail, SegmentSubsegment, VsChunk,
    VsSubsegment,
};

fn heap_kind(kind: HeapKind) -> View {
    View::Str(match kind {
        HeapKind::Nt => "nt".to_string(),
        HeapKind::Segment => "segment".to_string(),
        HeapKind::Unknown(signature) => format!("unknown ({signature:#x})"),
    })
}

fn heap_summary_stats(stats: &HeapSummaryStats) -> View {
    View::Object(vec![
        ("flags", View::Hex(stats.flags.into())),
        ("reserved", View::Num(stats.reserved)),
        ("committed", View::Num(stats.committed)),
        ("free", View::Num(stats.free)),
        ("segments", View::Num(stats.segments)),
        ("virtual_blocks", View::Num(stats.virtual_blocks)),
        (
            "front_end",
            View::OptHex(stats.front_end.map(|address| address.0)),
        ),
        ("front_end_type", View::Num(stats.front_end_type.into())),
        ("vs_subsegments", View::Num(stats.vs_subsegments)),
        ("lfh_subsegments", View::Num(stats.lfh_subsegments)),
        ("page_allocations", View::Num(stats.page_allocations)),
        ("large_allocations", View::Num(stats.large_allocations)),
    ])
}

fn heap_summary_item(item: &HeapSummaryItem) -> View {
    View::Object(vec![
        ("index", View::Num(item.index as u64)),
        ("address", View::Hex(item.address.0)),
        ("kind", heap_kind(item.kind)),
        ("stats", diagnostic(&item.stats, heap_summary_stats)),
    ])
}

/// Heap summary view; top-level keys are `peb`, `heaps`, and `truncated`.
pub fn heap_summary(summary: &HeapSummaryDetail) -> View {
    View::Object(vec![
        ("peb", View::Hex(summary.peb.0)),
        ("truncated", View::Bool(summary.truncated)),
        (
            "heaps",
            View::List(summary.heaps.iter().map(heap_summary_item).collect()),
        ),
    ])
}

fn nt_entry(entry: &NtEntry) -> View {
    View::Object(vec![
        ("address", View::Hex(entry.address.0)),
        ("size", View::Num(entry.size)),
        ("previous_size", View::Num(entry.previous_size)),
        ("flags", View::Hex(entry.flags.into())),
        (
            "state",
            View::Str(if entry.busy() { "busy" } else { "free" }.to_string()),
        ),
        ("kind", View::Str("entry".to_string())),
        ("unused_bytes", View::Num(entry.unused_bytes.into())),
        ("checksum_ok", View::Bool(entry.checksum_ok)),
        ("granule", View::Num(entry.granule)),
        ("user", View::Hex(entry.user().0)),
        ("user_size", View::Num(entry.user_size())),
    ])
}

fn nt_lfh_block(region: &NtUserBlocks, index: u32, entry: &NtEntry) -> View {
    let address = region.block(index);
    View::Object(vec![
        ("address", View::Hex(address.0)),
        ("size", View::Num(region.block_size)),
        ("previous_size", View::Null),
        ("flags", View::Null),
        (
            "state",
            View::Str(
                if region.is_busy(index) {
                    "busy"
                } else {
                    "free"
                }
                .to_string(),
            ),
        ),
        ("kind", View::Str("lfh-block".to_string())),
        ("unused_bytes", View::Null),
        ("checksum_ok", View::Null),
        ("granule", View::Num(entry.granule)),
        ("user", View::Hex((address + entry.granule).0)),
        (
            "user_size",
            View::Num(region.block_size.saturating_sub(entry.granule)),
        ),
        ("index", View::Num(index.into())),
    ])
}

fn heap_block(block: &HeapBlockDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(block.address.0)),
        ("size", View::Num(block.size)),
        ("previous_size", View::OptNum(block.previous_size)),
        ("flags", View::OptHex(block.flags.map(u64::from))),
        ("state", View::Str(block.state.to_string())),
        ("kind", View::Str(block.kind.to_string())),
        ("unused_bytes", View::OptNum(block.unused_bytes)),
        ("checksum_ok", View::OptBool(block.checksum_ok)),
        ("user", View::OptHex(block.user.map(|address| address.0))),
        ("user_size", View::OptNum(block.user_size)),
        ("index", View::OptNum(block.index.map(u64::from))),
    ])
}

fn nt_lfh(
    region: &NtUserBlocks,
    entry: &NtEntry,
    blocks: &[HeapBlockDetail],
    list_entries: bool,
) -> View {
    let blocks = if list_entries {
        if blocks.is_empty() {
            View::List(
                (0..region.block_count)
                    .map(|index| nt_lfh_block(region, index, entry))
                    .collect(),
            )
        } else {
            View::List(blocks.iter().map(heap_block).collect())
        }
    } else {
        View::List(Vec::new())
    };
    View::Object(vec![
        ("header", View::Hex(region.header.0)),
        ("subsegment", View::Hex(region.subsegment.0)),
        ("block_size", View::Num(region.block_size)),
        ("block_count", View::Num(region.block_count.into())),
        ("busy_count", View::Num(region.busy_count().into())),
        ("first_block", View::Hex(region.first_block.0)),
        ("stride", View::Num(region.stride)),
        (
            "busy_bitmap",
            View::List(
                region
                    .busy
                    .iter()
                    .map(|byte| View::Num((*byte).into()))
                    .collect(),
            ),
        ),
        ("blocks", blocks),
    ])
}

fn nt_entry_detail(entry: &NtEntryDetail, list_entries: bool) -> View {
    let mut fields = match nt_entry(&entry.entry) {
        View::Object(fields) => fields,
        _ => unreachable!(),
    };
    fields.push((
        "lfh",
        entry
            .lfh
            .as_ref()
            .map(|region| nt_lfh(region, &entry.entry, &entry.lfh_blocks, list_entries))
            .unwrap_or(View::Null),
    ));
    fields.push(("lfh_error", View::OptStr(entry.lfh_error.clone())));
    fields.push(("lfh_truncated", View::Bool(entry.lfh_truncated)));
    View::Object(fields)
}

fn nt_segment(segment: &NtSegmentDetail, list_entries: bool) -> View {
    let raw = &segment.segment;
    View::Object(vec![
        ("address", View::Hex(raw.address.0)),
        ("base", View::Hex(raw.base.0)),
        ("end", View::Hex(raw.end().0)),
        ("pages", View::Num(raw.pages.into())),
        ("uncommitted_pages", View::Num(raw.uncommitted_pages.into())),
        (
            "uncommitted",
            View::List(
                raw.uncommitted
                    .iter()
                    .map(|range| {
                        View::Object(vec![
                            ("start", View::Hex(range.start)),
                            ("end", View::Hex(range.end)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("first_entry", View::Hex(raw.first_entry.0)),
        ("last_valid_entry", View::Hex(raw.last_valid_entry.0)),
        (
            "entries",
            View::List(
                segment
                    .entries
                    .iter()
                    .map(|entry| nt_entry_detail(entry, list_entries))
                    .collect(),
            ),
        ),
        (
            "stopped",
            segment.stopped.as_ref().map_or(View::Null, |stop| {
                View::Object(vec![
                    ("address", View::Hex(stop.address.0)),
                    ("reason", View::Str(stop.reason.clone())),
                ])
            }),
        ),
    ])
}

fn nt_heap(detail: &NtHeapDetail, list_entries: bool) -> View {
    let heap = &detail.heap;
    View::Object(vec![
        ("address", View::Hex(heap.address.0)),
        ("flags", View::Hex(heap.flags.into())),
        ("force_flags", View::Hex(heap.force_flags.into())),
        ("granule", View::Num(heap.granule)),
        ("encoding", View::OptHex(heap.encoding)),
        ("total_free_units", View::Num(heap.total_free_units)),
        (
            "virtual_threshold",
            View::Num(heap.virtual_threshold.into()),
        ),
        (
            "front_end",
            View::OptHex(heap.front_end.map(|address| address.0)),
        ),
        ("front_end_type", View::Num(heap.front_end_type.into())),
        (
            "virtual_blocks",
            View::List(
                heap.virtual_blocks
                    .iter()
                    .map(|block| {
                        View::Object(vec![
                            ("entry", View::Hex(block.entry.0)),
                            ("commit_size", View::Num(block.commit_size)),
                            ("reserve_size", View::Num(block.reserve_size)),
                            ("user", View::Hex(block.user.0)),
                            ("kind", View::Str("virtual".to_string())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "segments",
            View::List(
                detail
                    .segments
                    .iter()
                    .map(|segment| nt_segment(segment, list_entries))
                    .collect(),
            ),
        ),
    ])
}

fn vs_chunk(chunk: &VsChunk) -> View {
    View::Object(vec![
        ("address", View::Hex(chunk.address.0)),
        ("size", View::Num(chunk.size)),
        ("previous_size", View::Num(chunk.previous_size)),
        ("flags", View::Null),
        (
            "state",
            View::Str(if chunk.busy { "busy" } else { "free" }.to_string()),
        ),
        ("kind", View::Str("vs-chunk".to_string())),
        (
            "unused_bytes",
            View::OptNum(chunk.unused_bytes.map(u64::from)),
        ),
        ("granule", View::Num(chunk.granule)),
        ("user", View::Hex(chunk.user().0)),
        ("user_size", View::Num(chunk.user_size())),
    ])
}

fn vs_subsegment(
    subsegment: &VsSubsegment,
    blocks: &[HeapBlockDetail],
    list_entries: bool,
) -> View {
    View::Object(vec![
        ("address", View::Hex(subsegment.address.0)),
        ("signature_ok", View::Bool(subsegment.signature_ok)),
        (
            "chunks",
            if list_entries {
                if blocks.is_empty() {
                    View::List(subsegment.chunks.iter().map(vs_chunk).collect())
                } else {
                    View::List(blocks.iter().map(heap_block).collect())
                }
            } else {
                View::List(Vec::new())
            },
        ),
        ("chunk_count", View::Num(subsegment.chunks.len() as u64)),
    ])
}

fn lfh_block(subsegment: &LfhSubsegment, index: u32) -> View {
    let address = subsegment.block(index);
    View::Object(vec![
        ("address", View::Hex(address.0)),
        ("size", View::Num(subsegment.block_size)),
        ("previous_size", View::Null),
        ("flags", View::Null),
        (
            "state",
            View::Str(
                if subsegment.is_busy(index) {
                    "busy"
                } else {
                    "free"
                }
                .to_string(),
            ),
        ),
        ("kind", View::Str("lfh-block".to_string())),
        ("index", View::Num(index.into())),
        ("user", View::Hex(address.0)),
        ("user_size", View::Num(subsegment.block_size)),
    ])
}

fn lfh_subsegment(
    subsegment: &LfhSubsegment,
    blocks: &[HeapBlockDetail],
    list_entries: bool,
) -> View {
    let blocks = if list_entries {
        if blocks.is_empty() {
            View::List(
                (0..subsegment.block_count)
                    .map(|index| lfh_block(subsegment, index))
                    .collect(),
            )
        } else {
            View::List(blocks.iter().map(heap_block).collect())
        }
    } else {
        View::List(Vec::new())
    };
    View::Object(vec![
        ("address", View::Hex(subsegment.address.0)),
        ("block_size", View::Num(subsegment.block_size)),
        ("block_count", View::Num(subsegment.block_count.into())),
        ("free_count", View::Num(subsegment.free_count.into())),
        ("busy_count", View::Num(subsegment.busy_count().into())),
        ("bucket", View::Num(subsegment.bucket.into())),
        ("first_block", View::Hex(subsegment.first_block.0)),
        (
            "blocks_per_word",
            View::Num(subsegment.blocks_per_word.into()),
        ),
        (
            "bitmap",
            View::List(
                subsegment
                    .bitmap
                    .iter()
                    .map(|word| View::Hex(*word))
                    .collect(),
            ),
        ),
        ("blocks", blocks),
    ])
}

fn segment_range_view(range: &SegmentRangeDetail, list_entries: bool) -> View {
    let raw = &range.range;
    let subsegment = match &range.subsegment {
        Some(SegmentSubsegment::Vs(subsegment)) => {
            vs_subsegment(subsegment, &range.blocks, list_entries)
        }
        Some(SegmentSubsegment::Lfh(subsegment)) => {
            lfh_subsegment(subsegment, &range.blocks, list_entries)
        }
        None => View::Null,
    };
    View::Object(vec![
        ("address", View::Hex(raw.address.0)),
        ("size", View::Num(raw.size())),
        ("end", View::Hex(raw.end().0)),
        ("units", View::Num(raw.units)),
        ("unit_size", View::Num(raw.unit_size)),
        ("flags", View::Hex(raw.flags.into())),
        ("committed_pages", View::Num(raw.committed_pages.into())),
        ("unused_bytes", View::Num(raw.unused_bytes.into())),
        ("kind", View::Str(raw.kind.name().to_string())),
        ("subsegment", subsegment),
        (
            "blocks",
            View::List(range.blocks.iter().map(heap_block).collect()),
        ),
        ("error", View::OptStr(range.error.clone())),
        ("truncated", View::Bool(range.truncated)),
    ])
}

fn page_segment(segment: &SegmentPageDetail, list_entries: bool) -> View {
    View::Object(vec![
        ("address", View::Hex(segment.segment.address.0)),
        (
            "ranges",
            View::List(
                segment
                    .ranges
                    .iter()
                    .map(|range| segment_range_view(range, list_entries))
                    .collect(),
            ),
        ),
    ])
}

fn segment_context_view(context: &SegmentContextDetail, list_entries: bool) -> View {
    let raw = &context.context;
    View::Object(vec![
        ("index", View::Num(raw.index as u64)),
        ("unit_shift", View::Num(raw.unit_shift.into())),
        ("unit_size", View::Num(raw.unit_size())),
        ("segment_mask", View::Hex(raw.segment_mask)),
        ("segment_size", View::Num(raw.segment_size())),
        (
            "max_allocation_size",
            View::Num(raw.max_allocation_size.into()),
        ),
        (
            "segments",
            View::List(
                context
                    .segments
                    .iter()
                    .map(|segment| page_segment(segment, list_entries))
                    .collect(),
            ),
        ),
    ])
}

fn large_allocation(allocation: &LargeAllocation) -> View {
    View::Object(vec![
        ("metadata", View::Hex(allocation.metadata.0)),
        ("address", View::Hex(allocation.address.0)),
        ("size", View::Num(allocation.size())),
        ("pages", View::Num(allocation.pages)),
        ("unused_bytes", View::Num(allocation.unused_bytes.into())),
        ("extra_present", View::Bool(allocation.extra_present)),
        ("kind", View::Str("large".to_string())),
    ])
}

fn segment_heap(detail: &SegmentHeapDetail, list_entries: bool) -> View {
    let heap = &detail.heap;
    View::Object(vec![
        ("address", View::Hex(heap.address.0)),
        ("global_flags", View::Hex(heap.global_flags.into())),
        ("reserved_pages", View::Num(heap.reserved_pages)),
        ("committed_pages", View::Num(heap.committed_pages)),
        ("free_committed_pages", View::Num(heap.free_committed_pages)),
        (
            "lfh_free_committed_pages",
            View::Num(heap.lfh_free_committed_pages),
        ),
        (
            "vs_free_committed_pages",
            View::Num(heap.vs_free_committed_pages),
        ),
        ("large_reserved_pages", View::Num(heap.large_reserved_pages)),
        (
            "large_committed_pages",
            View::Num(heap.large_committed_pages),
        ),
        (
            "keys",
            View::Object(vec![
                ("heap", View::Hex(heap.keys.heap_key)),
                ("lfh", View::Hex(heap.keys.lfh_key)),
            ]),
        ),
        ("granule", View::Num(heap.granule)),
        (
            "contexts",
            View::List(
                detail
                    .contexts
                    .iter()
                    .map(|context| segment_context_view(context, list_entries))
                    .collect(),
            ),
        ),
        (
            "large_allocations",
            View::List(
                heap.large_allocations
                    .iter()
                    .map(large_allocation)
                    .collect(),
            ),
        ),
    ])
}

/// Heap detail view; top-level keys are `index`, `address`, `kind`,
/// `list_entries`, `nt`, `segment`, and `error`.
pub fn heap(detail: &HeapDetail) -> View {
    View::Object(vec![
        ("index", View::Num(detail.index as u64)),
        ("address", View::Hex(detail.address.0)),
        ("kind", heap_kind(detail.kind)),
        ("list_entries", View::Bool(detail.list_entries)),
        (
            "nt",
            detail
                .nt
                .as_ref()
                .map(|nt| nt_heap(nt, detail.list_entries))
                .unwrap_or(View::Null),
        ),
        (
            "segment",
            detail
                .segment
                .as_ref()
                .map(|segment| segment_heap(segment, detail.list_entries))
                .unwrap_or(View::Null),
        ),
        ("error", View::OptStr(detail.error.clone())),
    ])
}

fn page_range(range: &PageRange) -> View {
    View::Object(vec![
        ("address", View::Hex(range.address.0)),
        ("size", View::Num(range.size())),
        ("end", View::Hex(range.end().0)),
        ("units", View::Num(range.units)),
        ("unit_size", View::Num(range.unit_size)),
        ("flags", View::Hex(range.flags.into())),
        ("committed_pages", View::Num(range.committed_pages.into())),
        ("unused_bytes", View::Num(range.unused_bytes.into())),
        ("kind", View::Str(range.kind.name().to_string())),
    ])
}

fn block_match(block: &BlockMatch) -> View {
    match block {
        BlockMatch::NtEntry { segment, entry } => View::Object(vec![
            ("kind", View::Str("nt-entry".to_string())),
            ("segment", View::Hex(segment.0)),
            ("entry", nt_entry(entry)),
        ]),
        BlockMatch::NtLfhBlock {
            segment,
            entry,
            region,
            index,
        } => {
            let address = region.block(*index);
            View::Object(vec![
                ("kind", View::Str("nt-lfh-block".to_string())),
                ("segment", View::Hex(segment.0)),
                ("entry", nt_entry(entry)),
                ("region", nt_lfh(region, entry, &[], false)),
                ("index", View::Num((*index).into())),
                ("address", View::Hex(address.0)),
                ("size", View::Num(region.block_size)),
                (
                    "state",
                    View::Str(
                        if region.is_busy(*index) {
                            "busy"
                        } else {
                            "free"
                        }
                        .to_string(),
                    ),
                ),
                ("user", View::Hex((address + entry.granule).0)),
            ])
        }
        BlockMatch::NtVirtual(block) => View::Object(vec![
            ("kind", View::Str("nt-virtual".to_string())),
            ("address", View::Hex(block.entry.0)),
            ("size", View::Num(block.reserve_size.max(block.commit_size))),
            ("state", View::Str("virtual".to_string())),
            ("entry", View::Hex(block.entry.0)),
            ("commit_size", View::Num(block.commit_size)),
            ("reserve_size", View::Num(block.reserve_size)),
            ("user", View::Hex(block.user.0)),
        ]),
        BlockMatch::NtSegmentOnly { segment, stopped } => View::Object(vec![
            ("kind", View::Str("nt-segment".to_string())),
            ("segment", View::Hex(segment.0)),
            (
                "stopped",
                stopped.as_ref().map_or(View::Null, |(address, reason)| {
                    View::Object(vec![
                        ("address", View::Hex(address.0)),
                        ("reason", View::Str((*reason).to_string())),
                    ])
                }),
            ),
        ]),
        BlockMatch::Direct(range) => View::Object(vec![
            ("kind", View::Str("page".to_string())),
            ("range", page_range(range)),
            ("user", View::Hex(range.address.0)),
            ("size", View::Num(range.size())),
        ]),
        BlockMatch::VsChunk {
            range,
            subsegment,
            chunk,
        } => View::Object(vec![
            ("kind", View::Str("vs-chunk".to_string())),
            ("range", page_range(range)),
            ("subsegment", View::Hex(subsegment.0)),
            ("chunk", vs_chunk(chunk)),
        ]),
        BlockMatch::LfhBlock {
            range,
            subsegment,
            index,
        } => View::Object(vec![
            ("kind", View::Str("lfh-block".to_string())),
            ("range", page_range(range)),
            ("subsegment", lfh_subsegment(subsegment, &[], false)),
            ("index", View::Num((*index).into())),
            ("address", View::Hex(subsegment.block(*index).0)),
            (
                "state",
                View::Str(
                    if subsegment.is_busy(*index) {
                        "busy"
                    } else {
                        "free"
                    }
                    .to_string(),
                ),
            ),
        ]),
        BlockMatch::RangeOnly(range) => View::Object(vec![
            ("kind", View::Str("range".to_string())),
            ("range", page_range(range)),
        ]),
        BlockMatch::Large(large) => View::Object(vec![
            ("kind", View::Str("large".to_string())),
            ("allocation", large_allocation(large)),
        ]),
    }
}

/// Heap block-search view; top-level keys are `address`, `found`, `truncated`,
/// `heap`, `block`, and `errors`.
pub fn heap_block_search(detail: &HeapBlockSearchDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        ("found", View::Bool(detail.found)),
        ("truncated", View::Bool(detail.truncated)),
        (
            "heap",
            detail.heap.as_ref().map_or(View::Null, |heap| {
                View::Object(vec![
                    ("index", View::Num(heap.index as u64)),
                    ("address", View::Hex(heap.address.0)),
                    ("kind", heap_kind(heap.kind)),
                ])
            }),
        ),
        (
            "block",
            detail.block.as_ref().map_or(View::Null, block_match),
        ),
        (
            "errors",
            View::List(
                detail
                    .errors
                    .iter()
                    .map(|error| View::Str(error.clone()))
                    .collect(),
            ),
        ),
    ])
}
