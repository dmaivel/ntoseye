//! Memory-manager commands: `!vm`, `!pfn`, `!vtop`, `!ptov`, `!pte`, the
//! pool commands (`!pool`, `!poolval`, `!poolused`, `!poolfind`),
//! `!lookaside`, `!mdl`, and `!sysptes`.

use std::borrow::Cow;

use ntoseye_macros::{command, grammar};
use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Panel};

use crate::base::error::Result;
use crate::base::memory::{DTB_IDENTITY, MemoryOps, PAGE_SIZE};
use crate::base::types::{PageTableEntry, VirtAddr};
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError, virtual_memory};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::mm::{
    LookasideDetail, LookasideListsDetail, MdlDetail, PfnDetail, PfnSelector, PoolBlockDetail,
    PoolFindDetail, PoolPageDetail, PoolType, PoolUsageDetail, PoolUsageSort, PoolValidationDetail,
    PteLevel, PteWalk, PtovDetail, SystemPtesDetail, VmCounter, VmDetail, VtopDetail,
};
use crate::nt::target::pool::tag_string;
use crate::nt::target::{DiagnosticMetric, DiagnosticValue, MemoryKind};
use crate::session::Session;

use super::diagnostics::{UnavailableNotes, print_memory_counters, print_process_memory, yes_no};

/// Show virtual-memory statistics.
///
/// The command shows system memory, pool, PTE, page-file, and process usage.
/// The flags follow WinDbg: bit 0 omits the per-process rows, and the command
/// accepts bits 1, 2, and 3 but ignores them. If the command cannot read a
/// counter, it still shows the other counters.
#[command(
    names = ["!vm", "vm"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn vm(
    session: &Session,
    #[arg(parse = vm_flags, default = true)] include_processes: bool,
) -> Result<VmDetail> {
    session.target.inspect_vm(include_processes)
}

/// `!vm`'s flags: bit 0 omits the per-process rows.
#[grammar(usage = "[flags]", complete = [Expression])]
fn vm_flags(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    match cursor.word() {
        Some(word) => Ok(cx.eval(&word)?.0 & 1 == 0),
        None => Ok(true),
    }
}

impl Render for VmDetail {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_vm(self);
    }
}

/// Decode an _MMPFN entry.
///
/// A plain value is a page-frame number. Use -a to read the value as a physical
/// address.
#[command(
    names = ["!pfn", "pfn"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn pfn(
    session: &Session,
    #[arg(parse = pfn_value)] value: u64,
    #[arg(parse = pfn_physical, default = false)] physical_address: bool,
) -> Result<PfnDetail> {
    session.target.inspect_pfn(if physical_address {
        PfnSelector::PhysicalAddress(value)
    } else {
        PfnSelector::Pfn(value)
    })
}

/// `!pfn -a`'s switch, which may come before or after the value.
fn pfn_switch(word: Option<&str>) -> bool {
    matches!(word, Some("-a" | "/a"))
}

/// `!pfn`'s value: the first word, or the one after a leading `-a`, which is
/// left for [`pfn_physical`].
#[grammar(usage = "<pfn> | -a <physical-address>", complete = [Expression, Expression])]
fn pfn_value(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u64, ArgError> {
    let word = if pfn_switch(cursor.words().next()) {
        cursor.word_at(1)
    } else {
        cursor.word()
    };
    Ok(cx.eval(&word.ok_or(ArgError::Missing)?)?.0)
}

#[grammar(usage = "")]
fn pfn_physical(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    let physical = pfn_switch(cursor.words().next());
    if physical {
        cursor.word();
    }
    Ok(physical)
}

impl Render for PfnDetail {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_pfn(self);
    }
}

/// Translate a virtual address with an explicit directory base.
///
/// The command shows each AMD64 page-table level and the final physical
/// address. A directory base of zero uses the current context, and for a large
/// page, the walk stops at its leaf level.
#[command(
    names = ["!vtop", "vtop"],
    category = "memory manager",
    kind = Query,
    target = Machine,
    python = Inspect,
)]
fn vtop(
    session: &Session,
    #[arg(parse = directory_base)] directory_base: u64,
    #[arg(name = "virtual-address")] address: VirtAddr,
) -> Result<VtopDetail> {
    session.target.vtop(directory_base, address)
}

/// `!vtop`'s directory base. Both words are required before either is read.
#[grammar(usage = "<directory-base>", complete = [Expression])]
fn directory_base(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<u64, ArgError> {
    if cursor.remaining() < 2 {
        return Err(ArgError::Missing);
    }
    let word = cursor.word().ok_or(ArgError::Missing)?;
    Ok(cx.eval(&word)?.0)
}

impl Render for VtopDetail {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_vtop(self);
    }
}

/// Find the virtual addresses in the current directory base that map a physical
/// address.
///
/// The command walks the page tables in reverse and detects cycles in them. The
/// walk stops after 32 mappings or 65,536 table pages.
#[command(
    names = ["!ptov", "ptov"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Memory,
)]
fn ptov(
    session: &Session,
    #[arg(receiver, parse = virtual_memory)] memory: MemoryKind,
    #[arg(name = "physical-address")] physical: u64,
) -> Result<PtovDetail> {
    memory.require_virtual()?;
    session.target.ptov(physical)
}

impl Render for PtovDetail {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_ptov(self);
    }
}

/// Show pool tracker usage by tag.
///
/// The command adds up the usage from the tag table of each processor, which
/// counts big allocations too; the big-page table is read only when those
/// tables cannot be. Tags with no allocation outstanding are left out. The
/// flags follow WinDbg: bit 1 (2) sorts by nonpaged bytes, bit 2 (4) sorts by
/// paged bytes, and bit 0 (1) shows the alloc/free columns. The tag match is
/// case-sensitive and supports * and ?.
#[command(
    names = ["!poolused", "poolused"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "pool_usage",
)]
fn pool_usage(
    session: &Session,
    #[arg(parse = poolused_tag, positional)] tag: Option<String>,
    #[arg(render, parse = poolused_counts)] include_counts: bool,
    #[arg(parse = poolused_sort, default = PoolUsageSort::Tag)] sort: PoolUsageSort,
) -> Result<PoolUsageDetail> {
    session.target.pool_usage(sort, tag.as_deref())
}

/// `!poolused`'s flags: its first word, if that is an expression (else the
/// word is the tag). It is left for [`poolused_sort`].
fn poolused_flags(cx: &ArgCx<'_, '_>, cursor: &ArgCursor<'_>) -> Option<u64> {
    cursor
        .words()
        .next()
        .and_then(|word| cx.eval(word).ok())
        .map(|flags| flags.0)
}

/// `!poolused`'s tag: the word after the flags, or the first word when it is
/// not an expression, in which case nothing may follow it.
#[grammar(usage = "[flags] [tag]", complete = [Expression, Expression])]
fn poolused_tag(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<String>, ArgError> {
    if poolused_flags(cx, cursor).is_some() {
        return Ok(cursor.word_at(1).map(Cow::into_owned));
    }
    let tag = cursor.word().map(Cow::into_owned);
    cursor.finish(cx.name)?;
    Ok(tag)
}

#[grammar(usage = "")]
fn poolused_counts(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    Ok(poolused_flags(cx, cursor).is_some_and(|flags| flags & 1 != 0))
}

#[grammar(usage = "")]
fn poolused_sort(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<PoolUsageSort, ArgError> {
    let flags = poolused_flags(cx, cursor);
    if flags.is_some() {
        cursor.word();
    }
    Ok(match flags.unwrap_or(0) & 0x6 {
        0x2 => PoolUsageSort::NonPagedBytes,
        0x4 => PoolUsageSort::PagedBytes,
        _ => PoolUsageSort::Tag,
    })
}

impl Render<bool> for PoolUsageDetail {
    fn render(&self, _: &mut ReplState<'_>, include_counts: bool) {
        print_pool_usage(self, include_counts);
    }
}

/// Find pool blocks with a matching tag.
///
/// The command reads the mapped pages of the pool ranges and the big-page
/// table. On Windows 10 1803 and later, the pool ranges are the fixed regions
/// in MiState.Vs.SystemVaRegions. On earlier builds, they come from
/// MmNonPagedPoolStart and related symbols. The optional type selects nonpaged
/// (0) or paged (1) pool. The scan stops after 1,024 matches, and you can
/// interrupt it.
#[command(
    names = ["!poolfind", "poolfind"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn pool_find(
    session: &Session,
    tag: String,
    #[arg(parse = poolfind_type)] pool_type: Option<PoolType>,
) -> Result<PoolFindDetail> {
    session.target.pool_find(&tag, pool_type)
}

/// `!poolfind`'s pool: 0 (nonpaged) or 1 (paged).
#[grammar(usage = "[0|1]", complete = [Expression])]
fn poolfind_type(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<PoolType>, ArgError> {
    let Some(word) = cursor.word() else {
        return Ok(None);
    };
    match cx.eval(&word).map(|value| value.0) {
        Ok(0) => Ok(Some(PoolType::NonPaged)),
        Ok(1) => Ok(Some(PoolType::Paged)),
        _ => Err(ArgError::Message(
            "pool type must be 0 (nonpaged) or 1 (paged)".to_string(),
        )),
    }
}

impl Render for PoolFindDetail {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_pool_find(self);
    }
}

/// List or decode GENERAL_LOOKASIDE caches.
///
/// With no argument, the command walks the exported nonpaged and paged
/// lookaside lists and detects cycles. With an address, it decodes only that
/// entry.
#[command(
    names = ["!lookaside", "lookaside"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    forms = [lookasides, lookaside],
)]
fn lookaside_command(session: &Session, address: Option<VirtAddr>) -> Result<Lookaside> {
    match address {
        Some(address) => lookaside(session, address).map(Lookaside::List),
        None => lookasides(session).map(Lookaside::Lists),
    }
}

/// List the exported nonpaged and paged `GENERAL_LOOKASIDE` lists
/// (`!lookaside`), detecting cycles.
#[command(form_of = lookaside_command, python = Inspect)]
fn lookasides(session: &Session) -> Result<LookasideListsDetail> {
    session.target.lookaside_lists()
}

/// Decode one `GENERAL_LOOKASIDE` (`!lookaside address`).
#[command(form_of = lookaside_command, python = Inspect)]
fn lookaside(session: &Session, address: VirtAddr) -> Result<LookasideDetail> {
    session.target.inspect_lookaside(address)
}

/// What `!lookaside` shows: one list it was given, or every system list.
enum Lookaside {
    List(LookasideDetail),
    Lists(LookasideListsDetail),
}

impl Render for Lookaside {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        match self {
            Lookaside::List(list) => print_lookaside_record(list),
            Lookaside::Lists(lists) => print_lookaside_lists(lists),
        }
    }
}

/// Show the page table entries for an address.
#[command(
    names = ["!pte", "pte"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Memory,
)]
fn pte(
    session: &Session,
    #[arg(receiver, parse = virtual_memory)] memory: MemoryKind,
    address: VirtAddr,
) -> Result<PteWalk> {
    memory.require_virtual()?;
    session.target.pte_traverse(address)
}

impl Render for PteWalk {
    fn render(&self, repl: &mut ReplState<'_>, _: ()) {
        let mask = repl.ctx.target.phys.invalid_pte_mask();
        print_pte_walk(self, mask);
        // What a non-present entry means for the page: where it is, and
        // whether a read still gets it.
        if let Some(why) = &self.non_resident {
            outln!("{}: {why}", ui::addr(self.address.0));
        }
    }
}

/// Show the pool page that contains an address.
#[command(
    names = ["!pool", "pool"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn pool(session: &Session, address: VirtAddr) -> Result<PoolPageDetail> {
    session.target.inspect_pool(address)
}

impl Render for PoolPageDetail {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_pool_page(self, self.target);
    }
}

/// Check the block headers of the pool page that contains an address.
///
/// The command reports the page as VALID or INVALID, with the first
/// inconsistency. The blocks of a classic pool page must make a chain from the
/// start of the page to its end, in which the PreviousSize of each block
/// matches the BlockSize of the block before it. Segment-heap pages (Windows 10
/// 1903 and later) have no PreviousSize chain, so on these pages the
/// inconsistency is a block whose BlockSize runs over the header of another
/// block. The PoolType of a classic block must also identify the pool (paged or
/// nonpaged) that holds the page. A level of 1 or more also lists all block
/// headers. The command does not do the single-bit-error scan of WinDbg.
#[command(
    names = ["!poolval", "poolval"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "pool_validate",
)]
fn pool_validate(
    session: &Session,
    address: VirtAddr,
    #[arg(render, default = 0)] level: u64,
) -> Result<PoolValidationDetail> {
    session.target.validate_pool(address)
}

impl Render<u64> for PoolValidationDetail {
    fn render(&self, _: &mut ReplState<'_>, level: u64) {
        print_pool_validation(self, level);
    }
}

/// Decode a memory descriptor list and the page frames it describes.
///
/// The command shows the _MDL header and the PFN array that follows it. The
/// header fields are Next, Size, MdlFlags by MDL_* name, Process,
/// MappedSystemVa, StartVa, ByteCount, and ByteOffset. By default, the PFN
/// count is the number of pages that ByteCount spans from ByteOffset, and a
/// pfn-count overrides this value. In both cases, the count cannot be more than
/// the slots that Size leaves after the header. If the Size, ByteOffset, or
/// span of the header cannot describe an MDL, the command gives an error. The
/// command does not follow Next, so for a chained MDL, run !mdl on the Next
/// address.
#[command(
    names = ["!mdl", "mdl"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn mdl(session: &Session, address: VirtAddr, pfn_count: Option<u64>) -> Result<MdlDetail> {
    session.target.inspect_mdl(address, pfn_count)
}

impl Render for MdlDetail {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_mdl(self);
    }
}

/// Show system PTE usage from the memory manager's bitmap allocators.
///
/// Windows 10 and later allocate system PTEs from _MI_SYSTEM_PTE_TYPE bitmap
/// allocators in MiState. These allocators are Vs.SystemPteInfo (the SystemPtes
/// region) and the system-view, non-cached-mapping, and kernel-stack allocators
/// of SystemPtes. For each allocator, the command shows the VA range that it
/// serves, TotalSystemPtes, TotalFreeSystemPtes, the PTEs in use, and
/// PteFailures, and from the bitmap, the number of free blocks and the largest
/// free block. The command reads all of the bitmap, up to 2^27 bits, a limit
/// that only a corrupt SizeOfBitMap exceeds. If the free count from the bitmap
/// differs from the counter, the target made an allocation between the reads
/// or a processor holds PTEs in the allocator's cache; the free count comes
/// from the bitmap. Where the counters cannot be true of the bitmap (a total
/// beyond it, a free count below zero or above the total, as on Windows 11
/// 22631 ARM64), the allocator's total and use are shown as unknown and left
/// out of the summary, and `!vm` shows no system-PTE totals.
/// All counts are in PTEs, and each bit of the system-view bitmap covers 16
/// PTEs. The flags follow WinDbg. 0x1 lists each free block with its first PTE,
/// the address that it maps, and its length, up to 256 free blocks for each
/// allocator. 0x4 (PTEs that map locked pages) needs the TrackPtes tracking of
/// the kernel, and shows which allocators track but does not list the tracked
/// mappings. The command ignores 0x2, 0x8, and 0x10, which select Windows
/// 2000/XP/Vista lists that these allocators replaced. On a build without these
/// allocators, the command gives an error.
#[command(
    names = ["!sysptes", "sysptes"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "system_ptes",
)]
fn system_ptes(
    session: &Session,
    #[arg(parse = sysptes_free_runs, default = false)] free_runs: bool,
    #[arg(render, default = 0)] flags: u64,
) -> Result<SystemPtesDetail> {
    session.target.system_ptes(free_runs)
}

/// `!sysptes`'s flag 0x1, which lists the free blocks. The flags word is
/// left for the render options.
#[grammar(usage = "")]
fn sysptes_free_runs(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    match cursor.words().next() {
        Some(word) => Ok(cx.eval(word)?.0 & 1 != 0),
        None => Ok(false),
    }
}

impl Render<u64> for SystemPtesDetail {
    fn render(&self, _: &mut ReplState<'_>, flags: u64) {
        print_system_ptes(self, flags);
    }
}

fn print_pool_validation(detail: &PoolValidationDetail, level: u64) {
    match &detail.region {
        Some(region) => outln!(
            "Pool page {} region is {}",
            ui::addr(detail.page.0),
            region.name
        ),
        None => outln!(
            "Pool page {} is in no pool range this build locates",
            ui::addr(detail.page.0)
        ),
    }
    outln!(
        "Validating {} pool headers for pool page: {}",
        detail.layout,
        ui::addr(detail.page.0)
    );
    match &detail.problem {
        None => outln!("Pool page [ {} ] is VALID.", ui::addr(detail.page.0)),
        Some(problem) => {
            outln!("Pool page [ {} ] is INVALID.", ui::addr(detail.page.0));
            outln!("  {}: {}", ui::addr(problem.header.0), problem.message);
        }
    }
    if level >= 1 {
        outln!();
        print_pool_block_header();
        for block in &detail.blocks {
            print_pool_block_row(block, detail.problem.as_ref().map(|problem| problem.header));
        }
    }
}

/// The header row of [`print_pool_block_row`]'s columns.
fn print_pool_block_header() {
    outln!(
        "    {:<16} {:<8} {:<8} {:<12} {:<6} Tag",
        "Header",
        "Size",
        "Prev",
        "State",
        "Type"
    );
}

fn print_pool_block_row(block: &PoolBlockDetail, problem: Option<VirtAddr>) {
    // WinDbg marks the block that holds the address with `*`.
    let marker = if problem == Some(block.header) {
        "!"
    } else if block.marked {
        "*"
    } else {
        " "
    };
    outln!(
        "  {} {} 0x{:<6x} 0x{:<6x} {:<12} 0x{:<4x} {}",
        marker,
        ui::addr(block.header.0),
        block.size,
        block.previous_size,
        block.state.to_string(),
        block.pool_type,
        pool_tag_text(&block.tag_name, block.tag)
    );
}

/// A pool tag as every pool command shows it: `'Proc' (0x636f7250)`.
fn pool_tag_text(name: &str, tag: u32) -> String {
    format!("'{name}' ({tag:#010x})")
}

fn print_mdl(detail: &MdlDetail) {
    outln!("MDL {}", ui::addr(detail.address.0));
    outln!("  Next           : {}", ui::addr(detail.next.0));
    outln!(
        "  Size           : {:#x} ({} PFN slot{})",
        detail.size,
        detail.capacity,
        if detail.capacity == 1 { "" } else { "s" }
    );
    outln!(
        "  MdlFlags       : {:#06x} {}",
        detail.flags,
        detail.flag_names.join(" ")
    );
    outln!("  Process        : {}", ui::addr(detail.process.0));
    outln!("  MappedSystemVa : {}", ui::addr(detail.mapped_system_va.0));
    outln!("  StartVa        : {}", ui::addr(detail.start_va.0));
    outln!("  ByteCount      : {:#x}", detail.byte_count);
    outln!("  ByteOffset     : {:#x}", detail.byte_offset);
    outln!(
        "  physical pages ({} of {} spanned) at {}",
        detail.pfns.len(),
        detail.spanned_pages,
        ui::addr(detail.pfn_array.0)
    );
    for row in detail.pfns.chunks(8) {
        let cells: Vec<String> = row.iter().map(|pfn| format!("{pfn:>8x}")).collect();
        outln!("    {}", cells.join(" "));
    }
    if detail.truncated {
        outln!(
            "    {}",
            more_pages(detail.spanned_pages - detail.pfns.len() as u64)
        );
    }
}

/// The note under `!mdl`'s PFN list for the spanned pages it leaves out.
fn more_pages(hidden: u64) -> String {
    ui::muted(&format!(
        "... {hidden} more spanned page{} not listed",
        if hidden == 1 { "" } else { "s" }
    ))
}

fn print_system_ptes(detail: &SystemPtesDetail, flags: u64) {
    outln!("System PTE Information");
    outln!("  total   {}", detail.total);
    outln!("  free    {}", detail.free);
    outln!("  in use  {}", detail.used());
    if !detail.uncounted.is_empty() {
        outln!(
            "  {}",
            ui::muted(&format!(
                "(not counting {}, whose counters do not hold)",
                detail.uncounted.join(", ")
            ))
        );
    }
    let field = |label: &str, value: String| outln!("    {label:<18}  {value}");
    for pte_type in &detail.types {
        outln!();
        outln!(
            "  {} ({}) @ {}",
            pte_type.name,
            pte_type.va_type.as_deref().unwrap_or("unknown VA type"),
            ui::addr(pte_type.address.0)
        );
        if pte_type.bitmap_bits == 0 {
            outln!("    unused (empty bitmap)");
            continue;
        }
        let span = pte_type.span();
        if let Some(base) = pte_type.base_va {
            field(
                "VA range",
                format!(
                    "{} - {}",
                    ui::addr(base.0),
                    ui::addr(base.0.wrapping_add(span.saturating_mul(PAGE_SIZE as u64)))
                ),
            );
        }
        field("first PTE", ui::addr(pte_type.base_pte.0));
        let unknown = || "-".to_string();
        let holds = pte_type.counters_hold();
        field(
            "total",
            if holds {
                pte_type.total.to_string()
            } else {
                unknown()
            },
        );
        field("free", pte_type.counted_free().to_string());
        field(
            "in use",
            pte_type
                .used()
                .map_or_else(unknown, |used| used.to_string()),
        );
        field("failures", pte_type.failures.to_string());
        field(
            "bitmap",
            format!(
                "{:#x} bits at {}, {} PTE{} per bit{}",
                pte_type.bitmap_bits,
                ui::addr(pte_type.bitmap.0),
                pte_type.ptes_per_bit,
                if pte_type.ptes_per_bit == 1 { "" } else { "s" },
                if holds {
                    format!("; {} PTEs reserved beyond the total", span - pte_type.total)
                } else {
                    String::new()
                }
            ),
        );
        field("free blocks", pte_type.free_run_count.to_string());
        field("free in bitmap", pte_type.bitmap_free.to_string());
        field("largest free block", pte_type.largest_free_run.to_string());
        if pte_type.unreadable_bitmap_bytes != 0 {
            outln!(
                "    {} bitmap bytes unreadable (counted as allocated)",
                pte_type.unreadable_bitmap_bytes
            );
        }
        if pte_type.unscanned_bitmap_bits != 0 {
            outln!(
                "    {:#x} bitmap bits past the {:#x}-bit bound not read (left out of the counts)",
                pte_type.unscanned_bitmap_bits,
                pte_type.bitmap_bits - pte_type.unscanned_bitmap_bits
            );
        }
        if !pte_type.free_runs.is_empty() {
            outln!("    free block list");
        }
        for run in &pte_type.free_runs {
            match run.va {
                Some(va) => outln!(
                    "      free ptes: {} (va {})   number free: {}.",
                    ui::addr(run.pte.0),
                    ui::addr(va.0),
                    run.ptes
                ),
                None => outln!(
                    "      free ptes: {}   number free: {}.",
                    ui::addr(run.pte.0),
                    run.ptes
                ),
            }
        }
        if pte_type.free_runs_truncated {
            outln!(
                "      ... {} more free blocks not listed",
                pte_type.free_run_count - pte_type.free_runs.len() as u64
            );
        }
        // A counter that went below zero reads as its two's complement.
        if !holds {
            outln!(
                "    (TotalSystemPtes reads {} and TotalFreeSystemPtes {}, which the bitmap of {} PTEs, {} free, contradicts: the kernel's counters do not hold here, so the total and the PTEs in use are unknown)",
                pte_type.total,
                pte_type.free as i64,
                span,
                pte_type.bitmap_free
            );
        } else if pte_type.bitmap_free != pte_type.free {
            outln!(
                "    (TotalFreeSystemPtes reads {} where the bitmap counts {} free; free counts from the bitmap)",
                pte_type.free as i64,
                pte_type.bitmap_free
            );
        }
    }
    if flags & 0x4 != 0 {
        let tracked: Vec<&str> = detail
            .types
            .iter()
            .filter(|pte_type| pte_type.tracking)
            .map(|pte_type| pte_type.name.as_str())
            .collect();
        outln!();
        if tracked.is_empty() {
            outln!(
                "  no allocator tracks its mappings (TrackPtes is off), so there is no record of the PTEs mapping locked pages"
            );
        } else {
            outln!(
                "  tracking is on for {}; listing the tracked mappings is not supported",
                tracked.join(", ")
            );
        }
    }
    if flags & 0x1a != 0 {
        outln!();
        outln!(
            "  flags 0x2, 0x8, and 0x10 apply to allocators this build does not have, so they are ignored"
        );
    }
}

fn print_vm(detail: &VmDetail) {
    print_memory_counters(&detail.system);
    // Paged pool pages and nonpaged pool bytes are in `system memory`
    // above; this block adds what only the pool counters hold.
    print_section("pool");
    let mut notes = UnavailableNotes::default();
    let maximum = metric_with_unit(
        &mut notes,
        "nonpaged pool maximum",
        &detail.pool.nonpaged_pool_maximum,
        Some("bytes"),
    );
    outln!("  nonpaged pool maximum  {maximum}");
    notes.print("  ");
    if detail.pool.fields.is_empty() {
        outln!(
            "  {}",
            ui::muted("MiState has no pool fields this build locates")
        );
    } else {
        outln!("  MiState pool fields");
        print_vm_counters(&detail.pool.fields, "    ");
    }

    print_section("PTEs");
    print_vm_counter_section(&detail.pte.counters);
    print_section("page files");
    print_vm_counter_section(&detail.page_files);
    // As in WinDbg, the per-process rows come last.
    if detail.include_processes {
        print_process_memory(&detail.system);
    }
}

/// A section of `!vm` counters, or one line saying none could be read and
/// why, rather than a column of the same failure.
fn print_vm_counter_section(counters: &[VmCounter]) {
    let first_error = counters
        .iter()
        .find_map(|counter| match &counter.value.value {
            DiagnosticValue::Unavailable(error) => Some(error),
            DiagnosticValue::Available(_) => None,
        });
    match first_error {
        _ if counters.is_empty() => outln!("  {}", ui::muted("no counters")),
        Some(error)
            if counters
                .iter()
                .all(|counter| matches!(counter.value.value, DiagnosticValue::Unavailable(_))) =>
        {
            outln!("  {}", ui::muted(&format!("unavailable: {error}")));
        }
        _ => print_vm_counters(counters, "  "),
    }
}

/// `!vm` counters as fields, each value with its unit (`75165 pages`), and a
/// note for those that could not be read.
fn print_vm_counters(counters: &[VmCounter], indent: &str) {
    let width = counters
        .iter()
        .map(|counter| counter.name.len())
        .max()
        .unwrap_or(0);
    let mut notes = UnavailableNotes::default();
    for counter in counters {
        let unit = counter.unit.map(|unit| unit.to_string());
        let value = metric_with_unit(&mut notes, &counter.name, &counter.value, unit.as_deref());
        outln!("{indent}{:<width$}  {value}", counter.name);
    }
    notes.print(indent);
}

/// A counter with its unit, `75165 pages`, or `-` noted in `notes`.
fn metric_with_unit(
    notes: &mut UnavailableNotes,
    label: &str,
    metric: &DiagnosticMetric<u64>,
    unit: Option<&str>,
) -> String {
    match (&metric.value, unit) {
        (DiagnosticValue::Available(value), Some(unit)) => format!("{value} {unit}"),
        (DiagnosticValue::Available(value), None) => value.to_string(),
        (DiagnosticValue::Unavailable(error), _) => notes.missing(label, error),
    }
}

fn print_pfn(detail: &PfnDetail) {
    outln!(
        "PFN {:08x} at address {}",
        detail.pfn,
        ui::addr(detail.record.0)
    );
    if let PfnSelector::PhysicalAddress(value) = detail.selector {
        outln!("  {:<20} : {}", "PhysicalAddress", ui::addr(value));
    }
    outln!(
        "  {:<20} : {}",
        "PteAddress",
        ui::addr(detail.pte_address.0)
    );
    outln!("  {:<20} : {:#x}", "OriginalPte", detail.original_pte);
    outln!("  {:<20} : {}", "ReferenceCount", detail.reference_count);
    if let Some(value) = detail.flink {
        outln!("  {:<20} : {value:#x}", "Flink");
    }
    if let Some(value) = detail.blink {
        outln!("  {:<20} : {value:#x}", "Blink");
    }
    if detail.flink.is_some() {
        if let Some(value) = detail.node_flink_low {
            outln!("  {:<20} : {value:#x}", "NodeFlinkLow");
        }
        if let Some(value) = detail.node_blink_low {
            outln!("  {:<20} : {value:#x}", "NodeBlinkLow");
        }
    } else if let Some(value) = detail.share_count {
        outln!("  {:<20} : {value}", "ShareCount");
        if let Some(value) = detail.ws_index {
            outln!("  {:<20} : {value:#x}", "WsIndex");
        }
        if let Some(value) = detail.event {
            outln!("  {:<20} : {value:#x}", "Event");
        }
    } else {
        outln!("  {:<20} : -", "ShareCount");
    }
    let mut notes = UnavailableNotes::default();
    outln!(
        "  {:<20} : {}",
        "UsedPageTableEntries",
        detail.used_entry_count
    );
    outln!(
        "  {:<20} : {}",
        "PageColor",
        notes.value("PageColor", &detail.page_color)
    );
    outln!(
        "  {:<20} : {:#x} (containing page)",
        "PteFrame",
        detail.pte_frame
    );
    outln!(
        "  {:<20} : {} ({:#x})",
        "PageLocation",
        detail.page_location.name(),
        detail.page_location.value & 0x7
    );
    outln!("  {:<20} : {}", "Modified", yes_no(detail.modified));
    outln!(
        "  {:<20} : {} ({:#x})",
        "CacheAttribute",
        detail.cache_attribute.name(),
        detail.cache_attribute.value & 0x3
    );
    outln!("  {:<20} : {}", "Priority", detail.priority);
    notes.print("  ");
}

/// `space` is "phys " for an entry address read from physical memory, so a
/// walk from an explicit DTB isn't mistaken for the self-map's addresses.
fn print_pte_entry(level: &PteLevel, space: &str) {
    let name = level.level;
    let (address, raw, attributes) = (level.address.0, level.value, &level.attributes);
    if attributes.present {
        outln!(
            "  {name:<4} @ {space}{} = {:016x}  pfn {:x}  flags {}",
            ui::addr(address),
            raw,
            attributes.pfn,
            attributes.flags
        );
    } else {
        outln!(
            "  {name:<4} @ {space}{} = {:016x}  software/transition/prototype PTE",
            ui::addr(address),
            raw
        );
    }
}

fn print_vtop(detail: &VtopDetail) {
    outln!(
        "VA {}  DTB {}",
        ui::addr(detail.address.0),
        ui::addr(detail.dtb)
    );
    for level in &detail.levels {
        print_pte_entry(level, if detail.physical_walk { "phys " } else { "" });
    }
    match detail.physical {
        Some(physical) => outln!("  physical  {}", ui::addr(physical)),
        None => outln!("  physical  not mapped"),
    }
    if detail.transition {
        outln!("  mapping   transition (resident, not mapped; read-only)");
    }
    if detail.section {
        outln!("  mapping   section (the view's shared page, not mapped here; read-only)");
    }
    if detail.large {
        outln!("  mapping   large page");
    }
}

fn print_ptov(detail: &PtovDetail) {
    if detail.dtb == DTB_IDENTITY {
        outln!(
            "identity dump mapping: {} -> {}",
            ui::addr(detail.physical),
            ui::addr(detail.physical)
        );
        return;
    }
    outln!(
        "PA {}  DTB {}",
        ui::addr(detail.physical),
        ui::addr(detail.dtb)
    );
    if detail.mappings.is_empty() {
        outln!(
            "  no current mappings (walked {} table pages)",
            detail.table_pages
        );
    } else {
        for mapping in &detail.mappings {
            outln!(
                "  {} -> {}{}",
                ui::addr(detail.physical),
                ui::addr(mapping.virtual_address.0),
                if mapping.large { " (large)" } else { "" }
            );
        }
    }
    if detail.bounded {
        outln!(
            "  walk bounded at {} mappings or {} table pages",
            detail.mappings.len(),
            detail.table_pages
        );
    }
    if detail.interrupted {
        outln!("  walk interrupted");
    }
}

fn usage_cell(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn print_pool_usage(detail: &PoolUsageDetail, include_counts: bool) {
    outln!(
        "pool usage by tag (tracker: {}; big pages: {})",
        detail.tracker_status,
        detail.big_status
    );
    if detail.rows_truncated {
        outln!(
            "{}",
            ui::muted(&format!(
                "the first {} tags are shown; the tracker holds more",
                detail.rows.len()
            ))
        );
    }
    let mut builder = Builder::default();
    if include_counts {
        builder.push_record([
            "Tag",
            "NP allocs",
            "NP frees",
            "NP bytes",
            "Paged allocs",
            "Paged frees",
            "Paged bytes",
        ]);
        for row in &detail.rows {
            builder.push_record([
                pool_tag_text(&tag_string(row.tag), row.tag),
                usage_cell(row.nonpaged_allocs),
                usage_cell(row.nonpaged_frees),
                usage_cell(row.nonpaged_bytes),
                usage_cell(row.paged_allocs),
                usage_cell(row.paged_frees),
                usage_cell(row.paged_bytes),
            ]);
        }
    } else {
        builder.push_record(["Tag", "NP bytes", "Paged bytes"]);
        for row in &detail.rows {
            builder.push_record([
                pool_tag_text(&tag_string(row.tag), row.tag),
                usage_cell(row.nonpaged_bytes),
                usage_cell(row.paged_bytes),
            ]);
        }
    }
    print_padded_table(builder);
}

fn print_pool_find(detail: &PoolFindDetail) {
    if detail.ranges.is_empty() {
        outln!("{}", ui::muted("no pool virtual ranges this build locates"));
    }
    // The scanned ranges' matches in range order, then the big-page table's.
    let matches = detail
        .ranges
        .iter()
        .flat_map(|range| {
            detail
                .matches
                .iter()
                .filter(move |m| m.source == range.name)
        })
        .chain(detail.matches.iter().filter(|m| m.source == "BigPool"));
    let mut builder = Builder::default();
    builder.push_record(["Address", "Tag", "Size", "State", "Pool", "Found in"]);
    let mut rows = 0;
    for m in matches {
        let source = match m.table_entry {
            Some(entry) => format!(
                "{} entry {}[{}]",
                m.source,
                ui::addr(entry.0),
                m.index.unwrap_or_default()
            ),
            None => m.source.clone(),
        };
        builder.push_record([
            ui::addr(m.address.0).to_string(),
            pool_tag_text(&m.tag_name, m.tag),
            format!("{:#x}", m.size),
            m.state.to_string(),
            m.pool_type
                .map_or_else(|| "-".to_string(), |kind| kind.to_string()),
            source,
        ]);
        rows += 1;
    }
    if rows > 0 {
        print_padded_table(builder);
    }
    for range in &detail.ranges {
        if let Some(stopped_at) = range.stopped_at {
            outln!(
                "{} scan stopped at {} after {} mapped pages",
                range.name,
                ui::addr(stopped_at.0),
                range.scanned_pages
            );
        }
    }
    if let Some(status) = &detail.big_status {
        outln!("big-page table: {status}");
    }
    if detail.found == 0 {
        outln!("no pool blocks matched '{}'", detail.tag);
    } else {
        outln!(
            "{} matching pool block{}",
            detail.found,
            if detail.found == 1 { "" } else { "s" }
        );
    }
    if detail.interrupted {
        outln!("pool scan interrupted");
    }
}

fn print_lookaside_record(detail: &LookasideDetail) {
    let mut notes = UnavailableNotes::default();
    outln!("GENERAL_LOOKASIDE {}", ui::addr(detail.address.0));
    outln!(
        "  {:<14} : {}",
        "Tag",
        lookaside_tag_cell(&mut notes, detail)
    );
    for (name, value, suffix) in [
        ("Size", &detail.size, " bytes"),
        ("Depth", &detail.depth, ""),
        ("TotalAllocates", &detail.total_allocates, ""),
        ("TotalFrees", &detail.total_frees, ""),
        ("AllocateMisses", &detail.allocate_misses, ""),
    ] {
        let value = match value {
            DiagnosticValue::Available(value) => format!("{value}{suffix}"),
            DiagnosticValue::Unavailable(error) => notes.missing(name, error),
        };
        outln!("  {name:<14} : {value}");
    }
    notes.print("  ");
}

fn lookaside_tag_cell(notes: &mut UnavailableNotes, detail: &LookasideDetail) -> String {
    match &detail.tag {
        DiagnosticValue::Available(tag) => pool_tag_text(&tag.name(), tag.value),
        DiagnosticValue::Unavailable(error) => notes.missing("Tag", error),
    }
}

fn print_lookaside_lists(detail: &LookasideListsDetail) {
    if detail.records.is_empty() {
        outln!("{}", ui::muted("no lookaside lists"));
        return;
    }
    outln!(
        "lookaside lists: {} nonpaged, {} paged or other",
        detail.nonpaged_count,
        detail.paged_count
    );
    let mut builder = Builder::default();
    builder.push_record([
        "#",
        "Address",
        "Tag",
        "Size",
        "Depth",
        "TotalAllocates",
        "TotalFrees",
        "AllocateMisses",
    ]);
    let mut notes = UnavailableNotes::default();
    for record in &detail.records {
        let index = format!("[{:03}] ", record.index);
        builder.push_record([
            format!("{:03}", record.index),
            ui::addr(record.address.0).to_string(),
            lookaside_tag_cell(&mut notes, record),
            notes.value(&format!("{index}Size"), &record.size),
            notes.value(&format!("{index}Depth"), &record.depth),
            notes.value(&format!("{index}TotalAllocates"), &record.total_allocates),
            notes.value(&format!("{index}TotalFrees"), &record.total_frees),
            notes.value(&format!("{index}AllocateMisses"), &record.allocate_misses),
        ]);
    }
    print_padded_table(builder);
    notes.print("");
    if detail.interrupted {
        outln!("lookaside walk interrupted");
    }
}

/// One `!pte` column: where the level's entry lives, its raw value, and the
/// decoded PFN and flags. A non-present entry has no flags; a transition one
/// names its frame with `invalid_pte_mask` (the L1TF swizzle) cleared.
fn pte_level_cell(level: &PteLevel, invalid_pte_mask: u64) -> String {
    let value = PageTableEntry(level.value);
    let attributes = &level.attributes;
    let decoded = if attributes.present {
        format!("pfn {:<5x} {:>11}", attributes.pfn, attributes.flags)
    } else if value.is_transition() {
        format!(
            "transition pfn {:x}",
            value.unswizzled(invalid_pte_mask).pfn()
        )
    } else {
        "not present".to_string()
    };
    format!(
        "{} at {:X}\ncontains {:016X}\n{decoded}",
        level.level,
        level.address,
        ui::Value(value.0),
    )
}

/// `!pte`: one column per level reached, under the VA and DTB.
fn print_pte_walk(result: &PteWalk, invalid_pte_mask: u64) {
    let header = format!(
        "VA {}  DTB {}",
        ui::addr(result.address.0),
        ui::addr(result.dtb)
    );
    let mut builder = Builder::default();
    let row_strings: Vec<String> = result
        .levels
        .iter()
        .map(|level| pte_level_cell(level, invalid_pte_mask))
        .collect();
    builder.push_record(row_strings);

    let mut table = builder.build();
    table
        .with(Panel::header(header))
        .with(Modify::new(Rows::first()).with(Alignment::center()))
        .with(tabled::settings::Style::empty());

    // The centered header and the padded cells leave trailing spaces.
    for line in table.to_string().lines() {
        outln!("{}", line.trim_end());
    }
}

/// `!pool`: the big-pool allocation holding `target`, or the pool page's
/// blocks with the one holding `target` marked.
fn print_pool_page(detail: &PoolPageDetail, target: VirtAddr) {
    if let Some(big) = &detail.big {
        outln!("big pool allocation {}", ui::addr(big.address.0));
        outln!("  target       {}", ui::addr(big.target.0));
        outln!(
            "  range        {} - {} ({} bytes)",
            ui::addr(big.address.0),
            ui::addr(big.address.0.saturating_add(big.size)),
            big.size
        );
        outln!("  offset       0x{:x} / 0x{:x}", big.offset, big.size);
        outln!("  tag          {}", pool_tag_text(&big.tag_name, big.tag));
        outln!("  table entry  {}[{}]", ui::addr(big.entry.0), big.index);
        outln!("  nonpaged     {}", if big.nonpaged { "yes" } else { "no" });
        outln!("  pattern      0x{:x}", big.pattern);
        outln!("  pool flags   0x{:x}", big.pool_flags);
        outln!("  slush size   0x{:x}", big.slush_size);
        return;
    }

    outln!("pool page {}", ui::addr(detail.page.0));
    outln!("  target         {}", ui::addr(target.0));
    if let Some(region) = &detail.region {
        outln!(
            "  region         {} [{} - {}]",
            region.name,
            ui::addr(region.start.0),
            ui::addr(region.end.0)
        );
    }
    if let Some(idx) = detail.target_index {
        outln!(
            "  blocks in run  {} (target is #{})",
            detail.blocks.len(),
            idx + 1
        );
    }
    if detail.blocks.is_empty() {
        outln!(
            "  {}",
            ui::muted("no plausible pool block holds this address")
        );
    } else {
        outln!();
        print_pool_block_header();
        for block in &detail.blocks {
            print_pool_block_row(block, None);
        }
        if let Some(idx) = detail.target_index {
            let block = &detail.blocks[idx];
            if let Some(offset) = block.target_offset {
                outln!();
                outln!(
                    "  target offset  0x{:x} into the body (block {}, body {})",
                    offset,
                    ui::addr(block.header.0),
                    ui::addr(block.body.0)
                );
            }
        }
    }

    if let Some(message) = &detail.message {
        outln!(
            "  {message}; it may be segment heap, special pool, a mapped view, or an image or stack"
        );
        if let Some(hint) = &detail.segment_heap_hint {
            outln!("  hint           {}", hint);
        }
        if let Some(near) = &detail.near_symbol {
            outln!("  near symbol    {}", near);
        }
    }
}
