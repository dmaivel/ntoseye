//! The `!pool`, `!poolused`, and `!poolfind` inspectors, built on the pool
//! decoding helpers in [`crate::nt::target::pool`].

use std::ops::ControlFlow;

use super::{
    BigPoolDetail, PoolBlockDetail, PoolBlockState, PoolFindDetail, PoolFindMatch, PoolFindRange,
    PoolPageDetail, PoolPageLayout, PoolProblem, PoolRegionDetail, PoolType, PoolUsageDetail,
    PoolUsageSort, PoolValidationDetail,
};
use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::types::VirtAddr;
use crate::nt::symbols::glob_matches;
use crate::nt::target::Target;
use crate::nt::target::pool::{
    BigPoolEntry, HeaderPoolEncoding, NONPAGED_POOL, PAGED_POOL, POOL_ALIGN, POOL_PAGE_SIZE,
    PoolHeader, PoolPageReader, PoolUsageRow, annotate_near_symbol, big_pool_layout,
    classify_pool_region, collect_pool_usage, find_big_pool, header_pool_type,
    locate_pool_block_in_page, pool_block_state, pool_header_candidates, pool_layout, pool_range,
    scan_big_pool_entries, scan_present_pool_pages, segment_heap_hint, tag_looks_printable,
    tag_string,
};

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
                pool_block_detail(
                    block,
                    index == Some(block_index),
                    address,
                    layout.header_pool,
                )
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
        let blocks = PoolPageReader::new(self, &layout).page_blocks(page, &bytes);
        let candidates = pool_header_candidates(&layout, page, &bytes);
        let page_layout = if segment_heap_hint(self).is_some() {
            PoolPageLayout::SegmentHeap
        } else {
            PoolPageLayout::Chained
        };
        let problem = first_pool_problem(
            page_layout,
            &blocks,
            &candidates,
            page,
            paged,
            layout.header_pool,
        );
        Ok(PoolValidationDetail {
            address,
            page,
            region,
            layout: page_layout,
            blocks: blocks
                .iter()
                .map(|block| {
                    let marked = (block.header.0..block.header.0 + block.size).contains(&address.0);
                    pool_block_detail(block, marked, address, layout.header_pool)
                })
                .collect(),
            problem,
        })
    }

    /// Aggregate bounded pool tracker and big-page usage rows, filtering and
    /// sorting them before returning the neutral result. The sort picks the
    /// rows kept when more tags match than the result holds.
    pub fn pool_usage(
        &self,
        sort: PoolUsageSort,
        tag_filter: Option<&str>,
    ) -> Result<PoolUsageDetail> {
        let summary = collect_pool_usage(self);
        let mut rows = summary
            .rows
            .into_iter()
            .filter(|row| {
                row.in_use()
                    && tag_filter
                        .map(|filter| glob_matches(filter, &tag_string(row.tag), false))
                        .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        sort_usage_rows(&mut rows, sort);
        let rows_truncated = summary.rows_truncated || rows.len() > MAX_POOLUSED_ROWS;
        rows.truncate(MAX_POOLUSED_ROWS);
        Ok(PoolUsageDetail {
            rows,
            rows_truncated,
            tracker_status: summary.tracker_status,
            big_status: summary.big.status,
            sort,
            tag_filter: tag_filter.map(str::to_string),
        })
    }

    /// Scan the mapped pages of the pool ranges (see
    /// [`pool_range`](crate::nt::target::pool::pool_range)) and
    /// `PoolBigPageTable` for a tag. The result is bounded to 1,024 matches
    /// and records whether it reached that bound or the host interrupted.
    pub fn pool_find(&self, tag: &str, pool_type: Option<PoolType>) -> Result<PoolFindDetail> {
        let layout = pool_layout(self).ok();
        let mut matches = Vec::new();
        let mut ranges = Vec::new();
        if let Some(layout) = &layout {
            let mut reader = PoolPageReader::new(self, layout);
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
                    for block in reader.page_blocks(page_va, page) {
                        // A tag that does not read is data the lax scan
                        // took for a header (the tracker table counts no
                        // such tag), which only a wildcard would match.
                        if block.synthetic_free
                            || !tag_looks_printable(block.tag)
                            || !glob_matches(tag, &tag_string(block.tag), false)
                        {
                            continue;
                        }
                        matches.push(PoolFindMatch {
                            source: pool.name.to_string(),
                            address: block.body,
                            size: block.size,
                            tag: block.tag,
                            tag_name: tag_string(block.tag),
                            allocated: pool_block_state(&block, layout.header_pool)
                                != PoolBlockState::Free,
                            state: pool_block_state(&block, layout.header_pool),
                            pool_type: layout
                                .header_pool
                                .and_then(|encoding| header_pool_type(block.pool_type, encoding)),
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
                                state: PoolBlockState::Allocated,
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
                                    state: PoolBlockState::Allocated,
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

/// `rows` in `!poolused`'s order: by tag, as its characters read, or by
/// nonpaged or paged bytes, largest first.
fn sort_usage_rows(rows: &mut [PoolUsageRow], sort: PoolUsageSort) {
    match sort {
        PoolUsageSort::NonPagedBytes => rows.sort_by(|a, b| {
            b.nonpaged_bytes
                .cmp(&a.nonpaged_bytes)
                .then_with(|| a.tag.to_le_bytes().cmp(&b.tag.to_le_bytes()))
        }),
        PoolUsageSort::PagedBytes => rows.sort_by(|a, b| {
            b.paged_bytes
                .cmp(&a.paged_bytes)
                .then_with(|| a.tag.to_le_bytes().cmp(&b.tag.to_le_bytes()))
        }),
        // A tag's characters are its bytes in memory order.
        PoolUsageSort::Tag => rows.sort_by_key(|row| row.tag.to_le_bytes()),
    }
}

/// The first inconsistency among the blocks of the `layout` pool page at
/// `page`: `blocks` is [`PoolPageReader::page_blocks`]'s reading of it and `candidates`
/// [`pool_header_candidates`]'s; `paged` says which pool the page's range
/// belongs to, when known, and `header_pool` how a header's `PoolType`
/// names its pool.
fn first_pool_problem(
    layout: PoolPageLayout,
    blocks: &[PoolHeader],
    candidates: &[PoolHeader],
    page: VirtAddr,
    paged: Option<bool>,
    header_pool: Option<HeaderPoolEncoding>,
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
        // A segment-heap page's blocks can include data the scan tolerated
        // as headers, so only a classic page's are held to its pool.
        if layout == PoolPageLayout::Chained
            && !block.synthetic_free
            && let Some(paged) = paged
            && let Some(pool) =
                header_pool.and_then(|encoding| header_pool_type(block.pool_type, encoding))
        {
            let type_paged = pool == PoolType::Paged;
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

fn pool_block_detail(
    block: &PoolHeader,
    marked: bool,
    target: VirtAddr,
    encoding: Option<HeaderPoolEncoding>,
) -> PoolBlockDetail {
    let state = pool_block_state(block, encoding);
    PoolBlockDetail {
        header: block.header,
        body: block.body,
        size: block.size,
        previous_size: block.previous_size,
        pool_type: block.pool_type,
        tag: block.tag,
        tag_name: tag_string(block.tag),
        allocated: state != PoolBlockState::Free,
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

    fn usage(tag: &[u8; 4], nonpaged: (i64, i64, i64)) -> PoolUsageRow {
        PoolUsageRow {
            tag: u32::from_le_bytes(*tag),
            nonpaged_allocs: Some(nonpaged.0),
            nonpaged_frees: Some(nonpaged.1),
            nonpaged_bytes: Some(nonpaged.2),
            paged_allocs: Some(0),
            paged_frees: Some(0),
            paged_bytes: Some(0),
        }
    }

    /// Tags sort as their characters read, as WinDbg lists them, not by
    /// the little-endian number they are stored as (which orders them by
    /// their last character).
    #[test]
    fn usage_rows_sort_by_tag_text() {
        let mut rows = [b"lcA\0", b"Proc", b"ConT", b"EP\0\0"].map(|tag| usage(tag, (1, 0, 16)));
        sort_usage_rows(&mut rows, PoolUsageSort::Tag);
        let order: Vec<[u8; 4]> = rows.iter().map(|row| row.tag.to_le_bytes()).collect();
        assert_eq!(order, [*b"ConT", *b"EP\0\0", *b"Proc", *b"lcA\0"]);
    }

    /// A tag is in use while it has more allocations than frees, summed
    /// over the processors' tables; one whose every allocation was freed
    /// is not, whatever any one processor's table says.
    #[test]
    fn a_tag_is_in_use_while_allocations_are_outstanding() {
        assert!(usage(b"Proc", (5, 4, 0x100)).in_use());
        assert!(!usage(b"Proc", (7, 7, 0)).in_use());
        let mut without_counts = usage(b"Proc", (0, 0, 0x40));
        without_counts.nonpaged_allocs = None;
        without_counts.nonpaged_frees = None;
        assert!(without_counts.in_use(), "bytes stand in for missing counts");
    }

    fn header(offset: u64, size: u64, previous_size: u64, pool_type: u8) -> PoolHeader {
        PoolHeader {
            header: VirtAddr(PAGE.0 + offset),
            body: VirtAddr(PAGE.0 + offset + 0x10),
            size,
            previous_size,
            pool_type,
            tag: TAG,
            synthetic_free: false,
            lfh_busy: None,
        }
    }

    fn problem_at(
        layout: PoolPageLayout,
        blocks: &[PoolHeader],
        candidates: &[PoolHeader],
        paged: Option<bool>,
    ) -> Option<u64> {
        problem_in(TYPE_ITSELF, layout, blocks, candidates, paged)
    }

    fn problem_in(
        encoding: HeaderPoolEncoding,
        layout: PoolPageLayout,
        blocks: &[PoolHeader],
        candidates: &[PoolHeader],
        paged: Option<bool>,
    ) -> Option<u64> {
        first_pool_problem(layout, blocks, candidates, PAGE, paged, Some(encoding))
            .map(|problem| problem.header.0 - PAGE.0)
    }

    const CHAINED: PoolPageLayout = PoolPageLayout::Chained;
    /// Headers holding the `POOL_TYPE` itself (Vista on), whose
    /// `PagedPool` is 1.
    const TYPE_ITSELF: HeaderPoolEncoding = HeaderPoolEncoding {
        paged_pool: 1,
        plus_one: false,
    };
    /// What a header's `PoolType` reads there for a nonpaged and a paged
    /// block.
    const NONPAGED: u8 = 2;
    const PAGED: u8 = 3;

    #[test]
    fn chained_page_flags_a_previous_size_that_breaks_the_chain() {
        let blocks = [
            header(0, 0x100, 0, NONPAGED),
            header(0x100, 0x200, 0x100, NONPAGED),
            header(0x300, 0xd00, 0x180, NONPAGED),
        ];
        assert_eq!(
            problem_at(CHAINED, &blocks, &blocks, Some(false)),
            Some(0x300)
        );
        // No link holds, as when the only link is the corrupt one.
        let blocks = [
            header(0, 0x100, 0, NONPAGED),
            header(0x100, 0xf00, 0x80, NONPAGED),
        ];
        assert_eq!(
            problem_at(CHAINED, &blocks, &blocks, Some(false)),
            Some(0x100)
        );
    }

    #[test]
    fn chained_page_must_end_at_the_page_end() {
        let blocks = [
            header(0, 0x100, 0, NONPAGED),
            header(0x100, 0x200, 0x100, NONPAGED),
        ];
        assert_eq!(
            problem_at(CHAINED, &blocks, &blocks, Some(false)),
            Some(0x100)
        );
        let whole = [
            header(0, 0x100, 0, NONPAGED),
            header(0x100, 0xf00, 0x100, NONPAGED),
        ];
        assert_eq!(problem_at(CHAINED, &whole, &whole, Some(false)), None);
    }

    /// The paged bit is `PagedPool`'s, whatever else the type holds: a
    /// nonpaged block reads 2, which is not PagedPool + 1.
    #[test]
    fn chained_pool_type_must_match_the_page_region() {
        let blocks = [
            header(0, 0x100, 0, PAGED),
            header(0x100, 0xf00, 0x100, PAGED),
        ];
        assert_eq!(problem_at(CHAINED, &blocks, &blocks, Some(false)), Some(0));
        assert_eq!(problem_at(CHAINED, &blocks, &blocks, Some(true)), None);
        assert_eq!(problem_at(CHAINED, &blocks, &blocks, None), None);
        let blocks = [
            header(0, 0x100, 0, NONPAGED),
            header(0x100, 0xf00, 0x100, NONPAGED),
        ];
        assert_eq!(problem_at(CHAINED, &blocks, &blocks, Some(true)), Some(0));
        assert_eq!(problem_at(CHAINED, &blocks, &blocks, Some(false)), None);
    }

    /// Windows Server 2003's headers hold the type plus one, with 4 set
    /// while allocated: a nonpaged block reads 5, which read as the type
    /// itself would say paged, and a paged one 6.
    #[test]
    fn server_2003_headers_hold_the_pool_type_plus_one() {
        let plus_one = HeaderPoolEncoding {
            paged_pool: 1,
            plus_one: true,
        };
        let nonpaged = [header(0, 0x100, 0, 5), header(0x100, 0xf00, 0x100, 5)];
        assert_eq!(
            problem_in(plus_one, CHAINED, &nonpaged, &nonpaged, Some(false)),
            None
        );
        assert_eq!(
            problem_in(plus_one, CHAINED, &nonpaged, &nonpaged, Some(true)),
            Some(0)
        );
        let paged = [header(0, 0x100, 0, 6), header(0x100, 0xf00, 0x100, 6)];
        assert_eq!(
            problem_in(plus_one, CHAINED, &paged, &paged, Some(true)),
            None
        );
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
