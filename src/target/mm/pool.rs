//! The `!pool`, `!poolused`, and `!poolfind` inspectors, built on the pool
//! decoding helpers in [`crate::target::pool`].

use std::ops::ControlFlow;

use super::{
    BigPoolDetail, PoolBlockDetail, PoolFindDetail, PoolFindMatch, PoolFindRange, PoolPageDetail,
    PoolRegionDetail, PoolType, PoolUsageDetail, PoolUsageSort,
};
use crate::error::Result;
use crate::memory::PAGE_SIZE;
use crate::symbols::glob_matches;
use crate::target::Target;
use crate::target::pool::{
    BigPoolEntry, NONPAGED_POOL, PAGED_POOL, POOL_PAGE_SIZE, PoolHeader, annotate_near_symbol,
    big_pool_layout, classify_pool_region, collect_pool_usage, find_big_pool,
    locate_pool_block_in_page, pool_block_state, pool_layout, pool_page_blocks, pool_range,
    scan_big_pool_entries, scan_present_pool_pages, segment_heap_hint, tag_string,
};
use crate::types::VirtAddr;

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

    /// Scan the mapped pages of the pool ranges (see
    /// [`pool_range`](crate::target::pool::pool_range)) and
    /// `PoolBigPageTable` for a tag. The result is bounded to 1,024 matches
    /// and records whether it reached that bound or the host interrupted.
    pub fn pool_find(&self, tag: &str, pool_type: Option<PoolType>) -> Result<PoolFindDetail> {
        let layout = pool_layout(self).ok();
        let mut matches = Vec::new();
        let mut ranges = Vec::new();
        if let Some(layout) = &layout {
            for kind in [PoolType::NonPaged, PoolType::Paged] {
                if pool_type.is_some_and(|wanted| wanted != kind) {
                    continue;
                }
                let pool = match kind {
                    PoolType::NonPaged => &NONPAGED_POOL,
                    PoolType::Paged => &PAGED_POOL,
                };
                let Ok((start, end)) = pool_range(self, pool) else {
                    continue;
                };
                let Some(start) = start
                    .0
                    .checked_add(PAGE_SIZE as u64 - 1)
                    .map(|value| VirtAddr(value & !(PAGE_SIZE as u64 - 1)))
                else {
                    continue;
                };
                let end = VirtAddr(end.0 & !(PAGE_SIZE as u64 - 1));
                let scan = scan_present_pool_pages(self, start, end, |page_va, page| {
                    for block in pool_page_blocks(layout, page_va, page) {
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
                            source: pool.name.to_string(),
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
                            return ControlFlow::Break(());
                        }
                    }
                    ControlFlow::Continue(())
                })?;
                ranges.push(PoolFindRange {
                    name: pool.name.to_string(),
                    start,
                    end,
                    pages: end.0.saturating_sub(start.0) / PAGE_SIZE as u64,
                    scanned_pages: scan.pages,
                    stopped_at: scan.stopped_at,
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
        let truncated = matches.len() >= MAX_POOLFIND_RESULTS;
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
