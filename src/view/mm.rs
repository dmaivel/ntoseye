//! Neutral value-tree views for memory-manager inspectors.

use super::{View, diagnostic, diagnostic_metric, memory_usage};
use crate::target::DiagnosticValue;
use crate::target::mm::{
    BigPoolDetail, LookasideDetail, LookasideListsDetail, PfnDetail, PfnSelector, PoolBlockDetail,
    PoolFindDetail, PoolFindMatch, PoolFindRange, PoolPageDetail, PoolRegionDetail, PoolType,
    PoolUsageDetail, PtovDetail, PtovMapping, VmCounter, VmDetail, VmPoolDetail, VmPteDetail,
    VtopDetail, VtopLevel,
};
use crate::target::pool::{PoolUsageRow, tag_string};
use crate::types::{PageTableEntry, PageTableLevel};

fn vm_counter(counter: &VmCounter) -> View {
    View::Object(vec![
        ("name", View::Str(counter.name.clone())),
        (
            "value",
            diagnostic_metric(&counter.value, |value| View::Num(*value)),
        ),
        ("unit", View::Str(counter.unit.to_string())),
    ])
}

fn vm_pool(pool: &VmPoolDetail) -> View {
    View::Object(vec![
        (
            "nonpaged_pool_bytes",
            diagnostic_metric(&pool.nonpaged_pool_bytes, |value| View::Num(*value)),
        ),
        (
            "nonpaged_pool_maximum",
            diagnostic_metric(&pool.nonpaged_pool_maximum, |value| View::Num(*value)),
        ),
        (
            "paged_pool_pages",
            diagnostic_metric(&pool.paged_pool_pages, |value| View::Num(*value)),
        ),
        (
            "fields",
            View::List(pool.fields.iter().map(vm_counter).collect()),
        ),
    ])
}

fn vm_pte(pte: &VmPteDetail) -> View {
    View::Object(vec![(
        "counters",
        View::List(pte.counters.iter().map(vm_counter).collect()),
    )])
}

/// Render `!vm`; top-level keys: `system`, `pool`, `pte`, `page_files`, `include_processes`.
pub fn vm(detail: &VmDetail) -> View {
    View::Object(vec![
        ("system", memory_usage(&detail.system)),
        ("pool", vm_pool(&detail.pool)),
        ("pte", vm_pte(&detail.pte)),
        (
            "page_files",
            View::List(detail.page_files.counters.iter().map(vm_counter).collect()),
        ),
        ("include_processes", View::Bool(detail.include_processes)),
    ])
}

fn pfn_selector(selector: PfnSelector) -> View {
    match selector {
        PfnSelector::Pfn(value) => View::Object(vec![
            ("kind", View::Str("pfn".to_string())),
            ("value", View::Hex(value)),
        ]),
        PfnSelector::PhysicalAddress(value) => View::Object(vec![
            ("kind", View::Str("physical_address".to_string())),
            ("value", View::Hex(value)),
        ]),
    }
}

fn diagnostic_opt<T>(value: Option<&DiagnosticValue<T>>, encode: impl FnOnce(&T) -> View) -> View {
    value.map_or(View::Null, |value| diagnostic(value, encode))
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

/// Render one `_MMPFN`; top-level keys: `selector`, `pfn`, `record`, `physical_address`, and decoded PFN fields.
pub fn pfn(detail: &PfnDetail) -> View {
    let page_location = diagnostic(&detail.page_location, |value| {
        View::Object(vec![
            ("value", View::Num(u64::from(*value))),
            ("name", View::Str(page_location_name(*value).to_string())),
        ])
    });
    let cache_attribute = diagnostic(&detail.cache_attribute, |value| {
        View::Object(vec![
            ("value", View::Num(u64::from(*value))),
            ("name", View::Str(cache_attribute_name(*value).to_string())),
        ])
    });
    View::Object(vec![
        ("selector", pfn_selector(detail.selector)),
        ("pfn", View::Hex(detail.pfn)),
        ("record", View::Hex(detail.record.0)),
        ("physical_address", View::OptHex(detail.physical_address)),
        (
            "pte_address",
            diagnostic(&detail.pte_address, |value| View::Hex(value.0)),
        ),
        (
            "original_pte",
            diagnostic(&detail.original_pte, |value| View::Hex(*value)),
        ),
        (
            "reference_count",
            diagnostic(&detail.reference_count, |value| View::Num(*value)),
        ),
        (
            "flink",
            diagnostic_opt(detail.flink.as_ref(), |value| View::Hex(*value)),
        ),
        (
            "blink",
            diagnostic_opt(detail.blink.as_ref(), |value| View::Hex(*value)),
        ),
        (
            "node_flink_low",
            diagnostic_opt(detail.node_flink_low.as_ref(), |value| View::Hex(*value)),
        ),
        (
            "node_blink_low",
            diagnostic_opt(detail.node_blink_low.as_ref(), |value| View::Hex(*value)),
        ),
        (
            "share_count",
            diagnostic_opt(detail.share_count.as_ref(), |value| View::Num(*value)),
        ),
        (
            "ws_index",
            diagnostic_opt(detail.ws_index.as_ref(), |value| View::Hex(*value)),
        ),
        (
            "event",
            diagnostic_opt(detail.event.as_ref(), |value| View::Hex(*value)),
        ),
        (
            "used_entry_count",
            diagnostic(&detail.used_entry_count, |value| View::Num(*value)),
        ),
        (
            "page_color",
            diagnostic(&detail.page_color, |value| View::Num(*value)),
        ),
        (
            "pte_frame",
            diagnostic(&detail.pte_frame, |value| View::Hex(*value)),
        ),
        ("page_location", page_location),
        (
            "modified",
            diagnostic(&detail.modified, |value| View::Bool(*value)),
        ),
        ("cache_attribute", cache_attribute),
        (
            "priority",
            diagnostic(&detail.priority, |value| View::Num(u64::from(*value))),
        ),
    ])
}

fn vtop_level(level: &VtopLevel) -> View {
    let value = PageTableEntry(level.value);
    let table_level = match level.name.as_str() {
        "PPE" => PageTableLevel::Ppe,
        "PDE" => PageTableLevel::Pde,
        "PTE" => PageTableLevel::Pte,
        _ => PageTableLevel::Pxe,
    };
    View::Object(vec![
        ("level", View::Str(level.name.clone())),
        ("address", View::Hex(level.address.0)),
        ("value", View::Hex(level.value)),
        ("pfn", View::Hex(value.pfn())),
        ("present", View::Bool(value.is_present())),
        ("large_page", View::Bool(value.is_large_page())),
        ("writable", View::Bool(value.is_writable())),
        ("user", View::Bool(value.is_user())),
        ("nx", View::Bool(value.is_nx())),
        ("flags", View::Str(value.flags_for_level(table_level))),
    ])
}

/// Render `!vtop`; top-level keys: `address`, `dtb`, `levels`, `physical`, `large`.
pub fn vtop(detail: &VtopDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        ("dtb", View::Hex(detail.dtb)),
        (
            "levels",
            View::List(detail.levels.iter().map(vtop_level).collect()),
        ),
        ("physical", View::OptHex(detail.physical)),
        ("large", View::Bool(detail.large)),
    ])
}

fn ptov_mapping(mapping: &PtovMapping) -> View {
    View::Object(vec![
        ("virtual_address", View::Hex(mapping.virtual_address.0)),
        ("large", View::Bool(mapping.large)),
    ])
}

/// Render `!ptov`; top-level keys: `physical`, `dtb`, `mappings`, `table_pages`, `bounded`, `interrupted`.
pub fn ptov(detail: &PtovDetail) -> View {
    View::Object(vec![
        ("physical", View::Hex(detail.physical)),
        ("dtb", View::Hex(detail.dtb)),
        (
            "mappings",
            View::List(detail.mappings.iter().map(ptov_mapping).collect()),
        ),
        ("table_pages", View::Num(detail.table_pages as u64)),
        ("bounded", View::Bool(detail.bounded)),
        ("interrupted", View::Bool(detail.interrupted)),
    ])
}

fn pool_region(region: &PoolRegionDetail) -> View {
    View::Object(vec![
        ("name", View::Str(region.name.clone())),
        ("start", View::Hex(region.start.0)),
        ("end", View::Hex(region.end.0)),
    ])
}

fn pool_block(block: &PoolBlockDetail) -> View {
    View::Object(vec![
        ("header", View::Hex(block.header.0)),
        ("body", View::Hex(block.body.0)),
        ("size", View::Num(block.size)),
        ("previous_size", View::Num(block.previous_size)),
        ("pool_type", View::Num(u64::from(block.pool_type))),
        ("tag", View::Hex(u64::from(block.tag))),
        ("tag_name", View::Str(block.tag_name.clone())),
        ("allocated", View::Bool(block.allocated)),
        ("marked", View::Bool(block.marked)),
        ("state", View::Str(block.state.clone())),
        ("target_offset", View::OptHex(block.target_offset)),
    ])
}

fn big_pool(big: &BigPoolDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(big.address.0)),
        ("target", View::Hex(big.target.0)),
        ("size", View::Num(big.size)),
        ("offset", View::Hex(big.offset)),
        ("tag", View::Hex(u64::from(big.tag))),
        ("tag_name", View::Str(big.tag_name.clone())),
        ("entry", View::Hex(big.entry.0)),
        ("index", View::Num(big.index)),
        ("nonpaged", View::Bool(big.nonpaged)),
        ("pattern", View::Hex(u64::from(big.pattern))),
        ("pool_flags", View::Hex(u64::from(big.pool_flags))),
        ("slush_size", View::Num(u64::from(big.slush_size))),
    ])
}

/// Render `!pool`; top-level keys: `target`, `page`, `page_kind`, `region`, `blocks`, `target_index`, `big`, diagnostic hints.
pub fn pool_page(detail: &PoolPageDetail) -> View {
    View::Object(vec![
        ("target", View::Hex(detail.target.0)),
        ("page", View::Hex(detail.page.0)),
        ("page_kind", View::Str(detail.page_kind.clone())),
        (
            "region",
            detail.region.as_ref().map_or(View::Null, pool_region),
        ),
        (
            "blocks",
            View::List(detail.blocks.iter().map(pool_block).collect()),
        ),
        (
            "target_index",
            View::OptNum(detail.target_index.map(|value| value as u64)),
        ),
        ("big", detail.big.as_ref().map_or(View::Null, big_pool)),
        (
            "segment_heap_hint",
            View::OptStr(detail.segment_heap_hint.clone()),
        ),
        ("near_symbol", View::OptStr(detail.near_symbol.clone())),
        ("message", View::OptStr(detail.message.clone())),
    ])
}

fn usage_row(row: &PoolUsageRow, include_counts: bool) -> View {
    let mut fields = vec![
        ("tag", View::Hex(u64::from(row.tag))),
        ("tag_name", View::Str(tag_string(row.tag))),
        (
            "nonpaged_bytes",
            View::OptNum(row.nonpaged_bytes.map(|value| value.max(0) as u64)),
        ),
        (
            "paged_bytes",
            View::OptNum(row.paged_bytes.map(|value| value.max(0) as u64)),
        ),
    ];
    if include_counts {
        fields.extend([
            (
                "nonpaged_allocs",
                View::OptNum(row.nonpaged_allocs.map(|value| value.max(0) as u64)),
            ),
            (
                "nonpaged_frees",
                View::OptNum(row.nonpaged_frees.map(|value| value.max(0) as u64)),
            ),
            (
                "paged_allocs",
                View::OptNum(row.paged_allocs.map(|value| value.max(0) as u64)),
            ),
            (
                "paged_frees",
                View::OptNum(row.paged_frees.map(|value| value.max(0) as u64)),
            ),
        ]);
    }
    View::Object(fields)
}

/// Render `!poolused`; top-level keys: `rows`, statuses, bounds, `sort`, `tag_filter`, `include_counts`.
pub fn pool_usage(detail: &PoolUsageDetail) -> View {
    View::Object(vec![
        (
            "rows",
            View::List(
                detail
                    .rows
                    .iter()
                    .map(|row| usage_row(row, detail.include_counts))
                    .collect(),
            ),
        ),
        ("rows_truncated", View::Bool(detail.rows_truncated)),
        ("tracker_status", View::Str(detail.tracker_status.clone())),
        ("big_status", View::Str(detail.big_status.clone())),
        ("sort", View::Str(detail.sort.name().to_string())),
        ("tag_filter", View::OptStr(detail.tag_filter.clone())),
        ("include_counts", View::Bool(detail.include_counts)),
    ])
}

fn pool_type(value: Option<PoolType>) -> View {
    View::OptStr(value.map(|value| value.name().to_string()))
}

fn pool_match(m: &PoolFindMatch) -> View {
    View::Object(vec![
        ("source", View::Str(m.source.clone())),
        ("address", View::Hex(m.address.0)),
        ("size", View::Num(m.size)),
        ("tag", View::Hex(u64::from(m.tag))),
        ("tag_name", View::Str(m.tag_name.clone())),
        ("allocated", View::Bool(m.allocated)),
        ("state", View::Str(m.state.clone())),
        ("pool_type", pool_type(m.pool_type)),
        (
            "table_entry",
            View::OptHex(m.table_entry.map(|value| value.0)),
        ),
        ("index", View::OptNum(m.index)),
    ])
}

fn pool_range_scan(range: &PoolFindRange) -> View {
    View::Object(vec![
        ("name", View::Str(range.name.clone())),
        ("start", View::Hex(range.start.0)),
        ("end", View::Hex(range.end.0)),
        ("pages", View::Num(range.pages)),
        ("scanned_pages", View::Num(range.scanned_pages)),
        ("bounded", View::Bool(range.bounded)),
    ])
}

/// Render `!poolfind`; top-level keys: `tag`, `pool_type`, `matches`, `found`, `ranges`, `big_status`, `truncated`, `interrupted`.
pub fn pool_find(detail: &PoolFindDetail) -> View {
    View::Object(vec![
        ("tag", View::Str(detail.tag.clone())),
        ("pool_type", pool_type(detail.pool_type)),
        (
            "matches",
            View::List(detail.matches.iter().map(pool_match).collect()),
        ),
        ("found", View::Num(detail.found as u64)),
        (
            "ranges",
            View::List(detail.ranges.iter().map(pool_range_scan).collect()),
        ),
        ("big_status", View::OptStr(detail.big_status.clone())),
        ("truncated", View::Bool(detail.truncated)),
        ("interrupted", View::Bool(detail.interrupted)),
    ])
}

/// Render one lookaside record; top-level keys: `address`, `index`, `tag`, `size`, `depth`, `total_allocates`, `total_frees`, `allocate_misses`.
pub fn lookaside(detail: &LookasideDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        ("index", View::Num(detail.index as u64)),
        (
            "tag",
            diagnostic(&detail.tag, |value| {
                View::Object(vec![
                    ("value", View::Hex(u64::from(*value))),
                    ("name", View::Str(tag_string(*value))),
                ])
            }),
        ),
        ("size", diagnostic(&detail.size, |value| View::Num(*value))),
        (
            "depth",
            diagnostic(&detail.depth, |value| View::Num(*value)),
        ),
        (
            "total_allocates",
            diagnostic(&detail.total_allocates, |value| View::Num(*value)),
        ),
        (
            "total_frees",
            diagnostic(&detail.total_frees, |value| View::Num(*value)),
        ),
        (
            "allocate_misses",
            diagnostic(&detail.allocate_misses, |value| View::Num(*value)),
        ),
    ])
}

/// Render `!lookaside` list output; top-level keys: `records`, nonpaged/paged counts and terminations, `interrupted`, `truncated`.
pub fn lookaside_lists(detail: &LookasideListsDetail) -> View {
    View::Object(vec![
        (
            "records",
            View::List(detail.records.iter().map(lookaside).collect()),
        ),
        ("nonpaged_count", View::Num(detail.nonpaged_count as u64)),
        ("paged_count", View::Num(detail.paged_count as u64)),
        (
            "nonpaged_termination",
            View::Str(detail.nonpaged_termination.clone()),
        ),
        (
            "paged_termination",
            View::Str(detail.paged_termination.clone()),
        ),
        ("interrupted", View::Bool(detail.interrupted)),
        ("truncated", View::Bool(detail.truncated)),
    ])
}
