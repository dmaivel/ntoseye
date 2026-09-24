//! The `!pool`, `!poolused`, and `!poolfind` inspectors, built on the pool
//! decoding helpers in [`crate::target::pool`].

use super::{
    BigPoolDetail, PoolBlockDetail, PoolFindDetail, PoolFindMatch, PoolFindRange, PoolPageDetail,
    PoolRegionDetail, PoolType, PoolUsageDetail, PoolUsageSort, find_mi_state_fields,
};
use crate::error::Result;
use crate::memory::PAGE_SIZE;
use crate::symbols::{format_symbol_with_offset, glob_matches};
use crate::target::Target;
use crate::target::pool::{
    BigPoolEntry, PoolHeader, big_pool_layout, classify_pool_region, collect_pool_usage,
    find_big_pool, locate_pool_block_in_page, pool_block_state, pool_layout,
    read_kernel_global_u64, scan_big_pool_entries, scan_pool_page_lax, tag_string,
};
use crate::types::VirtAddr;

const MAX_POOLFIND_PAGES: u64 = 16 * 1024;
const MAX_POOLFIND_RESULTS: usize = 1024;
const MAX_POOLUSED_ROWS: usize = 256;

impl Target {
    /// Decode the pool page containing `address`, including every plausible
    /// block and the block containing the requested address. Big-page entries
    /// are retained separately when the address lies in one.
    pub fn inspect_pool(&self, address: VirtAddr) -> Result<PoolPageDetail> {
        let layout = pool_layout(self)?;
        if address.0 & (POOL_PAGE_SIZE - 1) == 0
            && let Some(big) = find_big_pool(self, &layout, address)
        {
            return Ok(PoolPageDetail {
                target: address,
                page: VirtAddr(address.0 & !(POOL_PAGE_SIZE - 1)),
                page_kind: "big".to_string(),
                region: None,
                blocks: Vec::new(),
                target_index: None,
                big: Some(big_pool_detail(address, &big)),
                segment_heap_hint: None,
                near_symbol: None,
                message: None,
            });
        }
        let region =
            classify_pool_region(self, address).map(|(name, start, end)| PoolRegionDetail {
                name: name.to_string(),
                start,
                end,
            });
        let (blocks, index, page) = locate_pool_block_in_page(self, &layout, address);
        let details = blocks
            .iter()
            .enumerate()
            .map(|(block_index, block)| {
                pool_block_detail(block, index == Some(block_index), address)
            })
            .collect::<Vec<_>>();
        let big = if index.is_none() {
            find_big_pool(self, &layout, address).map(|entry| big_pool_detail(address, &entry))
        } else {
            None
        };
        let message = if index.is_none() && big.is_none() {
            Some("address does not lie inside a recognizable _POOL_HEADER block".to_string())
        } else {
            None
        };
        let page_kind = if big.is_some() {
            "big"
        } else if index.is_some() {
            "pool"
        } else {
            "unknown"
        };
        Ok(PoolPageDetail {
            target: address,
            page,
            page_kind: page_kind.to_string(),
            region,
            blocks: details,
            target_index: index,
            big,
            segment_heap_hint: if message.is_some() {
                segment_heap_hint(self).map(str::to_string)
            } else {
                None
            },
            near_symbol: if message.is_some() {
                annotate_near_symbol(self, address)
            } else {
                None
            },
            message,
        })
    }

    /// Aggregate bounded pool tracker and big-page usage rows, filtering and
    /// sorting them before returning the neutral result.
    pub fn pool_usage(
        &self,
        sort: PoolUsageSort,
        tag_filter: Option<&str>,
        include_counts: bool,
    ) -> Result<PoolUsageDetail> {
        let summary = collect_pool_usage(self);
        let mut rows = summary
            .rows
            .into_iter()
            .filter(|row| {
                tag_filter
                    .map(|filter| glob_matches(filter, &tag_string(row.tag), false))
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        match sort {
            PoolUsageSort::NonPagedBytes => rows.sort_by(|a, b| {
                b.nonpaged_bytes
                    .cmp(&a.nonpaged_bytes)
                    .then_with(|| a.tag.cmp(&b.tag))
            }),
            PoolUsageSort::PagedBytes => rows.sort_by(|a, b| {
                b.paged_bytes
                    .cmp(&a.paged_bytes)
                    .then_with(|| a.tag.cmp(&b.tag))
            }),
            PoolUsageSort::Tag => rows.sort_by_key(|row| row.tag),
        }
        let rows_truncated = summary.rows_truncated || rows.len() > MAX_POOLUSED_ROWS;
        rows.truncate(MAX_POOLUSED_ROWS);
        Ok(PoolUsageDetail {
            rows,
            rows_truncated,
            tracker_status: summary.tracker_status,
            big_status: summary.big.status,
            sort,
            tag_filter: tag_filter.map(str::to_string),
            include_counts,
        })
    }

    /// Scan virtual pool ranges and `PoolBigPageTable` for a tag. The bounded
    /// result records whether the scan reached a limit or was interrupted by
    /// the host.
    pub fn pool_find(&self, tag: &str, pool_type: Option<PoolType>) -> Result<PoolFindDetail> {
        let layout = pool_layout(self).ok();
        let mut matches = Vec::new();
        let mut ranges = Vec::new();
        let mut truncated = false;
        if let Some(layout) = &layout {
            for range in resolve_pool_ranges(self) {
                if pool_type.is_some_and(|kind| range.kind != kind.kind()) {
                    continue;
                }
                let Some(start) = range
                    .start
                    .checked_add(PAGE_SIZE as u64 - 1)
                    .map(|value| value & !(PAGE_SIZE as u64 - 1))
                else {
                    continue;
                };
                let end = range.end & !(PAGE_SIZE as u64 - 1);
                let pages = end.saturating_sub(start) / PAGE_SIZE as u64;
                let scan_pages = pages.min(MAX_POOLFIND_PAGES);
                let mut scanned_pages = 0;
                for page in 0..scan_pages {
                    if self.interrupted() || matches.len() >= MAX_POOLFIND_RESULTS {
                        break;
                    }
                    let Some(base) = page
                        .checked_mul(PAGE_SIZE as u64)
                        .and_then(|offset| start.checked_add(offset))
                        .map(VirtAddr)
                    else {
                        break;
                    };
                    scanned_pages += 1;
                    for block in scan_pool_page_lax(self, layout, base) {
                        if block.synthetic_free || !glob_matches(tag, &tag_string(block.tag), false)
                        {
                            continue;
                        }
                        let kind = if block.pool_type == 1 {
                            PoolType::Paged
                        } else {
                            PoolType::NonPaged
                        };
                        matches.push(PoolFindMatch {
                            source: range.name.to_string(),
                            address: block.body,
                            size: block.size,
                            tag: block.tag,
                            tag_name: tag_string(block.tag),
                            allocated: pool_block_state(&block) != "Free",
                            state: pool_block_state(&block).to_string(),
                            pool_type: Some(kind),
                            table_entry: None,
                            index: None,
                        });
                        if matches.len() >= MAX_POOLFIND_RESULTS {
                            break;
                        }
                    }
                }
                let range_bounded = scan_pages < pages;
                truncated |= range_bounded;
                ranges.push(PoolFindRange {
                    name: range.name.to_string(),
                    start: VirtAddr(start),
                    end: VirtAddr(end),
                    pages,
                    scanned_pages,
                    bounded: range_bounded,
                });
                if self.interrupted() || matches.len() >= MAX_POOLFIND_RESULTS {
                    break;
                }
            }
        }
        let big_status = if let Some(layout) = layout.as_ref() {
            Some(
                scan_big_pool_entries(
                    self,
                    layout.big_pool_type.as_deref(),
                    layout.big_pool_uses_struct,
                    layout.big_pool_has_pool_type,
                    layout.big_pool_has_slush,
                    |entry| {
                        if matches.len() < MAX_POOLFIND_RESULTS
                            && pool_type
                                .is_none_or(|kind| entry.nonpaged == (kind == PoolType::NonPaged))
                            && glob_matches(tag, &tag_string(entry.tag), false)
                        {
                            matches.push(PoolFindMatch {
                                source: "BigPool".to_string(),
                                address: entry.va,
                                size: entry.size,
                                tag: entry.tag,
                                tag_name: tag_string(entry.tag),
                                allocated: true,
                                state: "Allocated".to_string(),
                                pool_type: Some(if entry.nonpaged {
                                    PoolType::NonPaged
                                } else {
                                    PoolType::Paged
                                }),
                                table_entry: Some(entry.entry),
                                index: Some(entry.index),
                            });
                        }
                        matches.len() >= MAX_POOLFIND_RESULTS
                    },
                )
                .status,
            )
        } else {
            match big_pool_layout(self) {
                Ok((big_pool_type, uses_struct, has_pool_type, has_slush)) => Some(
                    scan_big_pool_entries(
                        self,
                        Some(&big_pool_type),
                        uses_struct,
                        has_pool_type,
                        has_slush,
                        |entry| {
                            if matches.len() < MAX_POOLFIND_RESULTS
                                && pool_type.is_none_or(|kind| {
                                    entry.nonpaged == (kind == PoolType::NonPaged)
                                })
                                && glob_matches(tag, &tag_string(entry.tag), false)
                            {
                                matches.push(PoolFindMatch {
                                    source: "BigPool".to_string(),
                                    address: entry.va,
                                    size: entry.size,
                                    tag: entry.tag,
                                    tag_name: tag_string(entry.tag),
                                    allocated: true,
                                    state: "Allocated".to_string(),
                                    pool_type: Some(if entry.nonpaged {
                                        PoolType::NonPaged
                                    } else {
                                        PoolType::Paged
                                    }),
                                    table_entry: Some(entry.entry),
                                    index: Some(entry.index),
                                });
                            }
                            matches.len() >= MAX_POOLFIND_RESULTS
                        },
                    )
                    .status,
                ),
                Err(error) => Some(format!("big-page layout unavailable: {error}")),
            }
        };
        truncated |= matches.len() >= MAX_POOLFIND_RESULTS;
        let interrupted = self.interrupted();
        Ok(PoolFindDetail {
            tag: tag.to_string(),
            pool_type,
            found: matches.len(),
            matches,
            ranges,
            big_status,
            truncated,
            interrupted,
        })
    }
}

fn pool_block_detail(block: &PoolHeader, marked: bool, target: VirtAddr) -> PoolBlockDetail {
    let state = pool_block_state(block).to_string();
    PoolBlockDetail {
        header: block.header,
        body: block.body,
        size: block.size,
        previous_size: block.previous_size,
        pool_type: block.pool_type,
        tag: block.tag,
        tag_name: tag_string(block.tag),
        allocated: state != "Free",
        marked,
        state,
        target_offset: marked.then(|| target.0.saturating_sub(block.body.0)),
    }
}

fn big_pool_detail(target: VirtAddr, entry: &BigPoolEntry) -> BigPoolDetail {
    BigPoolDetail {
        address: entry.va,
        target,
        size: entry.size,
        offset: target.0.saturating_sub(entry.va.0),
        tag: entry.tag,
        tag_name: tag_string(entry.tag),
        entry: entry.entry,
        index: entry.index,
        nonpaged: entry.nonpaged,
        pattern: entry.pattern,
        pool_flags: entry.pool_flags,
        slush_size: entry.slush_size,
    }
}

fn resolve_pool_ranges(target: &Target) -> Vec<PoolFindRangeInternal> {
    let mut ranges = Vec::new();
    if let Some(range) = pool_range(
        target,
        "NonPagedPool",
        "MmNonPagedPoolStart",
        "MmNonPagedPoolEnd",
        0,
    ) {
        ranges.push(range);
    } else if let Some(range) =
        mi_state_pool_range(target, "nonpagedpoolstart", "nonpagedpoolend", 0)
    {
        ranges.push(range);
    }
    if let Some(range) = pool_range(target, "PagedPool", "MmPagedPoolStart", "MmPagedPoolEnd", 1) {
        ranges.push(range);
    } else if let Some(range) = mi_state_pool_range(target, "pagedpoolstart", "pagedpoolend", 1) {
        ranges.push(range);
    }
    ranges
}

#[derive(Clone, Copy)]
struct PoolFindRangeInternal {
    name: &'static str,
    start: u64,
    end: u64,
    kind: u64,
}

fn pool_range(
    target: &Target,
    name: &'static str,
    start_symbol: &str,
    end_symbol: &str,
    kind: u64,
) -> Option<PoolFindRangeInternal> {
    let start = read_kernel_global_u64(target, start_symbol).ok()?;
    let end = read_kernel_global_u64(target, end_symbol).ok()?;
    (start < end).then_some(PoolFindRangeInternal {
        name,
        start,
        end,
        kind,
    })
}

fn mi_state_pool_range(
    target: &Target,
    start_name: &str,
    end_name: &str,
    kind: u64,
) -> Option<PoolFindRangeInternal> {
    let fields = find_mi_state_fields(target, &["pool", "start", "end"]);
    let start = fields.iter().find_map(|(name, value)| {
        name.to_ascii_lowercase()
            .contains(&start_name.to_ascii_lowercase())
            .then_some(*value)
    });
    let end = fields.iter().find_map(|(name, value)| {
        name.to_ascii_lowercase()
            .contains(&end_name.to_ascii_lowercase())
            .then_some(*value)
    });
    Some(PoolFindRangeInternal {
        name: if kind == 0 {
            "NonPagedPool"
        } else {
            "PagedPool"
        },
        start: start?,
        end: end?,
        kind,
    })
    .filter(|range| range.start < range.end)
}

fn segment_heap_hint(target: &Target) -> Option<&'static str> {
    target
        .symbols
        .find_symbol_across_modules(target.current_dtb(), "nt!RtlpHpHeapGlobals")
        .ok()
        .flatten()?;
    Some(
        "kernel has RtlpHpHeapGlobals (segment heap is enabled); address may be a _HEAP_VS_CHUNK_HEADER / LFH chunk instead of a _POOL_HEADER",
    )
}

fn annotate_near_symbol(target: &Target, address: VirtAddr) -> Option<String> {
    let (module, name, offset) = target
        .symbols
        .find_closest_symbol_for_address(target.current_dtb(), address)?;
    (offset <= 0x1000).then(|| format_symbol_with_offset(&module, &name, offset))
}

const POOL_PAGE_SIZE: u64 = PAGE_SIZE as u64;
