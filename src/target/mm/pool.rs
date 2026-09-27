//! The `!pool`, `!poolused`, and `!poolfind` inspectors, built on the pool
//! decoding helpers in [`crate::target::pool`].

use std::ops::ControlFlow;

use super::{
    BigPoolDetail, PoolBlockDetail, PoolFindDetail, PoolFindMatch, PoolFindRange, PoolPageDetail,
    PoolProblem, PoolRegionDetail, PoolType, PoolUsageDetail, PoolUsageSort, PoolValidationDetail,
};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::memory::PAGE_SIZE;
use crate::symbols::glob_matches;
use crate::target::Target;
use crate::target::pool::{
    BigPoolEntry, NONPAGED_POOL, PAGED_POOL, POOL_ALIGN, POOL_PAGE_SIZE, PoolHeader,
    annotate_near_symbol, big_pool_layout, classify_pool_region, collect_pool_usage, find_big_pool,
    locate_pool_block_in_page, pool_block_state, pool_header_candidates, pool_layout,
    pool_page_blocks, pool_range, scan_big_pool_entries, scan_present_pool_pages,
    segment_heap_hint, tag_looks_printable, tag_string,
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
        let region = pool_region_detail(self, address);
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

    /// `!poolval`: check the block headers of the pool page holding
    /// `address` and report the first inconsistency. A classic pool page
    /// must chain from its start to its end, each `PreviousSize` matching
    /// the `BlockSize` before it; a segment-heap page keeps no such chain,
    /// so there a block whose `BlockSize` runs over another block's header is
    /// the inconsistency. A classic block's `PoolType` must also name the
    /// pool the page lies in. Which layout applies is the kernel's: segment
    /// heap when it has `RtlpHpHeapGlobals`.
    pub fn validate_pool(&self, address: VirtAddr) -> Result<PoolValidationDetail> {
        let layout = pool_layout(self)?;
        let page = VirtAddr(address.0 & !(POOL_PAGE_SIZE - 1));
        if let Some(big) = find_big_pool(self, &layout, page) {
            return Err(Error::DebugInfo(format!(
                "{:#x} is in a big-pool allocation ('{}', {:#x} bytes at {:#x}), which has no block headers",
                address.0,
                tag_string(big.tag),
                big.size,
                big.va.0
            )));
        }
        let mut bytes = vec![0u8; POOL_PAGE_SIZE as usize];
        self.kernel_address_space().read_bytes(page, &mut bytes)?;
        let region = pool_region_detail(self, address);
        let paged = region.as_ref().and_then(|region| {
            if region.name == PAGED_POOL.name {
                Some(true)
            } else if region.name == NONPAGED_POOL.name {
                Some(false)
            } else {
                None
            }
        });
        let blocks = pool_page_blocks(&layout, page, &bytes);
        let candidates = pool_header_candidates(&layout, page, &bytes);
        let page_layout = if segment_heap_hint(self).is_some() {
            PoolPageLayout::SegmentHeap
        } else {
            PoolPageLayout::Chained
        };
        let problem = first_pool_problem(page_layout, &blocks, &candidates, page, paged);
        Ok(PoolValidationDetail {
            address,
            page,
            region,
            layout: page_layout.name().to_string(),
            blocks: blocks
                .iter()
                .map(|block| {
                    let marked = (block.header.0..block.header.0 + block.size).contains(&address.0);
                    pool_block_detail(block, marked, address)
                })
                .collect(),
            problem,
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

/// How a pool page lays its blocks out, which decides what a consistent page
/// looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolPageLayout {
    /// The classic pool: headers chain from the page start to its end, each
    /// `PreviousSize` the `BlockSize` before it, `PoolType` the POOL_TYPE + 1.
    Chained,
    /// Segment heap (Windows 10 1903 and later): `PreviousSize` is unused,
    /// variable-size blocks sit behind a 16-byte chunk header, and free
    /// chunks have no `_POOL_HEADER`.
    SegmentHeap,
}

impl PoolPageLayout {
    fn name(self) -> &'static str {
        match self {
            Self::Chained => "chained",
            Self::SegmentHeap => "segment heap",
        }
    }
}

/// The first inconsistency among the blocks of the `layout` pool page at
/// `page`: `blocks` is [`pool_page_blocks`]'s reading of it and `candidates`
/// [`pool_header_candidates`]'s; `paged` says which pool the page's range
/// belongs to, when known.
fn first_pool_problem(
    layout: PoolPageLayout,
    blocks: &[PoolHeader],
    candidates: &[PoolHeader],
    page: VirtAddr,
    paged: Option<bool>,
) -> Option<PoolProblem> {
    let page_end = page.0 + POOL_PAGE_SIZE;
    let problem = |header: VirtAddr, message: String| Some(PoolProblem { header, message });
    let Some(first) = blocks.iter().find(|block| !block.synthetic_free) else {
        return problem(page, "no _POOL_HEADER in the page".into());
    };
    if layout == PoolPageLayout::Chained && first.header != page {
        return problem(
            page,
            format!(
                "the first block header is at {:#x}, not the page start",
                first.header.0
            ),
        );
    }
    for (index, block) in blocks.iter().enumerate() {
        let end = block.header.0 + block.size;
        // The classic header's PoolType is the POOL_TYPE + 1, whose bit 0 is
        // the paged bit. The segment heap's encoding is not documented, so
        // its pool type goes unchecked.
        if layout == PoolPageLayout::Chained
            && !block.synthetic_free
            && block.pool_type != 0
            && let Some(paged) = paged
        {
            let type_paged = (block.pool_type - 1) & 1 != 0;
            if type_paged != paged {
                return problem(
                    block.header,
                    format!(
                        "PoolType {:#x} says {} pool, but the page is in {} pool",
                        block.pool_type,
                        if type_paged { "paged" } else { "nonpaged" },
                        if paged { "paged" } else { "nonpaged" }
                    ),
                );
            }
        }
        match layout {
            PoolPageLayout::Chained => match blocks.get(index + 1) {
                Some(next) if block.synthetic_free || next.synthetic_free => {
                    return problem(
                        block.header,
                        format!(
                            "no _POOL_HEADER where this block (BlockSize {:#x}) ends, at {end:#x}",
                            block.size
                        ),
                    );
                }
                Some(next) if next.previous_size != block.size => {
                    return problem(
                        next.header,
                        format!(
                            "PreviousSize {:#x} does not match BlockSize {:#x} of the block at {:#x}",
                            next.previous_size, block.size, block.header.0
                        ),
                    );
                }
                None if end != page_end => {
                    return problem(
                        block.header,
                        format!(
                            "the last block (BlockSize {:#x}) ends at {end:#x}, not the page end",
                            block.size
                        ),
                    );
                }
                _ => {}
            },
            PoolPageLayout::SegmentHeap if segment_heap_header(block) => {
                // A block header inside this block that chains to where a
                // block begins is a real one this block's BlockSize runs
                // over.
                let boundary = |address: u64| {
                    address == page_end
                        || blocks.iter().any(|other| {
                            !other.synthetic_free
                                && (other.header.0 == address
                                    || other.header.0 == address + POOL_ALIGN)
                        })
                };
                if let Some(overrun) = candidates.iter().find(|candidate| {
                    candidate.header.0 > block.header.0
                        && candidate.header.0 < end
                        && segment_heap_header(candidate)
                        && boundary(candidate.header.0 + candidate.size)
                }) {
                    return problem(
                        block.header,
                        format!(
                            "BlockSize {:#x} runs over the block header at {:#x} ('{}')",
                            block.size,
                            overrun.header.0,
                            tag_string(overrun.tag)
                        ),
                    );
                }
            }
            PoolPageLayout::SegmentHeap => {}
        }
    }
    None
}

/// Whether `header` reads as an allocated segment-heap block's: a tag, a
/// pool type made of POOL_TYPE bits a header carries (paged, must-succeed,
/// cache-aligned, quota, session), and no `PreviousSize` (only a
/// cache-aligned allocation's second header has one, pointing back at the
/// first). Anything else in the scan is a subsegment header or data it
/// tolerated.
fn segment_heap_header(header: &PoolHeader) -> bool {
    const HEADER_POOL_TYPE_BITS: u8 = 0x2f;
    !header.synthetic_free
        && header.pool_type != 0
        && header.pool_type & !HEADER_POOL_TYPE_BITS == 0
        && header.previous_size == 0
        && tag_looks_printable(header.tag)
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

fn pool_region_detail(target: &Target, address: VirtAddr) -> Option<PoolRegionDetail> {
    classify_pool_region(target, address).map(|(name, start, end)| PoolRegionDetail {
        name: name.to_string(),
        start,
        end,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: VirtAddr = VirtAddr(0xffff_8000_0000_0000);
    const TAG: u32 = u32::from_le_bytes(*b"Test");

    fn header(offset: u64, size: u64, previous_size: u64, pool_type: u8) -> PoolHeader {
        PoolHeader {
            header: VirtAddr(PAGE.0 + offset),
            body: VirtAddr(PAGE.0 + offset + 0x10),
            size,
            previous_size,
            pool_type,
            tag: TAG,
            synthetic_free: false,
        }
    }

    fn problem_at(
        layout: PoolPageLayout,
        blocks: &[PoolHeader],
        candidates: &[PoolHeader],
        paged: Option<bool>,
    ) -> Option<u64> {
        first_pool_problem(layout, blocks, candidates, PAGE, paged)
            .map(|problem| problem.header.0 - PAGE.0)
    }

    const CHAINED: PoolPageLayout = PoolPageLayout::Chained;

    #[test]
    fn chained_page_flags_a_previous_size_that_breaks_the_chain() {
        let blocks = [
            header(0, 0x100, 0, 1),
            header(0x100, 0x200, 0x100, 1),
            header(0x300, 0xd00, 0x180, 1),
        ];
        assert_eq!(
            problem_at(CHAINED, &blocks, &blocks, Some(false)),
            Some(0x300)
        );
        // No link holds, as when the only link is the corrupt one.
        let blocks = [header(0, 0x100, 0, 1), header(0x100, 0xf00, 0x80, 1)];
        assert_eq!(
            problem_at(CHAINED, &blocks, &blocks, Some(false)),
            Some(0x100)
        );
    }

    #[test]
    fn chained_page_must_end_at_the_page_end() {
        let blocks = [header(0, 0x100, 0, 1), header(0x100, 0x200, 0x100, 1)];
        assert_eq!(
            problem_at(CHAINED, &blocks, &blocks, Some(false)),
            Some(0x100)
        );
        let whole = [header(0, 0x100, 0, 1), header(0x100, 0xf00, 0x100, 1)];
        assert_eq!(problem_at(CHAINED, &whole, &whole, Some(false)), None);
    }

    #[test]
    fn chained_pool_type_must_match_the_page_region() {
        // PoolType 2 is PagedPool + 1.
        let blocks = [header(0, 0x100, 0, 2), header(0x100, 0xf00, 0x100, 2)];
        assert_eq!(problem_at(CHAINED, &blocks, &blocks, Some(false)), Some(0));
        assert_eq!(problem_at(CHAINED, &blocks, &blocks, Some(true)), None);
        assert_eq!(problem_at(CHAINED, &blocks, &blocks, None), None);
    }

    #[test]
    fn segment_heap_block_running_over_a_chained_header_is_flagged() {
        let outer = header(0x40, 0x300, 0, 2);
        // A real header at 0x150 whose block ends where the next begins.
        let overrun = header(0x150, 0x200, 0, 2);
        let next = header(0x360, 0x100, 0, 2);
        let blocks = [outer, next];
        let heap = PoolPageLayout::SegmentHeap;
        assert_eq!(
            problem_at(heap, &blocks, &[outer, overrun, next], Some(false)),
            Some(0x40)
        );
        // The second header of a cache-aligned allocation points back at the
        // first with its PreviousSize.
        let aligned = header(0x60, 0x2f0, 0x20, 6);
        assert_eq!(
            problem_at(heap, &blocks, &[outer, aligned, next], Some(false)),
            None
        );
    }
}
