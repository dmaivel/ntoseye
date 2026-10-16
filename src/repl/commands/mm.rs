//! Memory-manager commands: `!vm`, `!pfn`, `!vtop`, `!ptov`, `!pte`, the
//! pool commands (`!pool`, `!poolval`, `!poolused`, `!poolfind`),
//! `!lookaside`, `!mdl`, and `!sysptes`.

use std::borrow::Cow;

use ntoseye_macros::command;
use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Panel};

use crate::error::Result;
use crate::memory::{DTB_IDENTITY, MemoryOps, PAGE_SIZE};
use crate::repl::args::{ArgCursor, ArgCx, ArgError, virtual_memory};
use crate::repl::*;
use crate::session::Session;
use crate::target::mm::{
    LookasideDetail, LookasideListsDetail, MdlDetail, PfnDetail, PfnSelector, PoolBlockDetail,
    PoolFindDetail, PoolPageDetail, PoolType, PoolUsageDetail, PoolUsageSort, PoolValidationDetail,
    PteLevel, PteWalk, PtovDetail, SystemPtesDetail, VmDetail, VtopDetail,
};
use crate::target::pool::tag_string;
use crate::target::{DiagnosticValue, MemoryKind};
use crate::types::{PageTableEntry, VirtAddr};
use crate::ui;

use super::diagnostics::{diagnostic_cell, diagnostic_metric_cell, print_memory_use_summary};

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
    usage = "!vm [flags]",
    completion = Expression
)]
fn vm(
    session: &Session,
    #[arg(parse = vm_flags, default = true)] include_processes: bool,
) -> Result<VmDetail> {
    session.target.inspect_vm(include_processes)
}

/// `!vm`'s flags: bit 0 omits the per-process rows.
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
    usage = "!pfn <pfn> | !pfn -a <physical-address>",
    completion = Expression
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
    target = Kernel,
    python = Inspect,
    usage = "!vtop <directory-base> <virtual-address>",
    completion = Expression
)]
fn vtop(
    session: &Session,
    #[arg(parse = directory_base)] directory_base: u64,
    address: VirtAddr,
) -> Result<VtopDetail> {
    session.target.vtop(directory_base, address)
}

/// `!vtop`'s directory base. Both words are required before either is read.
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
    usage = "!ptov <physical-address>",
    completion = Expression
)]
fn ptov(
    session: &Session,
    #[arg(receiver, parse = virtual_memory)] memory: MemoryKind,
    physical: u64,
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
/// The command adds up the usage from the tag table of each processor. The
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
    usage = "!poolused [flags] [tag]",
    completion = Expression
)]
fn pool_usage(
    session: &Session,
    #[arg(parse = poolused_tag)] tag: Option<String>,
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

fn poolused_counts(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    Ok(poolused_flags(cx, cursor).is_some_and(|flags| flags & 1 != 0))
}

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
    usage = "!poolfind <tag> [0|1]",
    completion = Expression
)]
fn pool_find(
    session: &Session,
    tag: String,
    #[arg(parse = poolfind_type)] pool_type: Option<PoolType>,
) -> Result<PoolFindDetail> {
    session.target.pool_find(&tag, pool_type)
}

/// `!poolfind`'s pool: 0 (nonpaged) or 1 (paged).
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
    usage = "!lookaside [address]",
    completion = Expression
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
fn lookaside(
    session: &Session,
    #[arg(complete = Expression)] address: VirtAddr,
) -> Result<LookasideDetail> {
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
    usage = "!pte <address>",
    completion = Expression
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
        #[cfg(feature = "cli")]
        native::render(
            || native::inspect::pte(self, mask),
            || print_pte_walk(self, mask),
        );
        #[cfg(not(feature = "cli"))]
        print_pte_walk(self, mask);
    }
}

/// Show the pool page that contains an address.
#[command(
    names = ["!pool", "pool"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
    usage = "!pool <address-expression>",
    completion = Expression
)]
fn pool(session: &Session, address: VirtAddr) -> Result<PoolPageDetail> {
    session.target.inspect_pool(address)
}

impl Render for PoolPageDetail {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        #[cfg(feature = "cli")]
        native::render(
            || native::inspect::pool(self, self.target),
            || print_pool_page(self, self.target),
        );
        #[cfg(not(feature = "cli"))]
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
    usage = "!poolval <address> [level]",
    completion = Expression
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
    usage = "!mdl <address> [pfn-count]",
    completion = Expression
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
/// differs from the counter, the target made an allocation between the reads.
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
    usage = "!sysptes [flags]",
    completion = Expression
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
        outln!(
            "    {:<16} {:<8} {:<8} {:<12} {:<6} tag",
            "header",
            "size",
            "prev",
            "state",
            "type"
        );
        for block in &detail.blocks {
            print_pool_block_row(block, detail.problem.as_ref().map(|problem| problem.header));
        }
    }
    outln!();
}

fn print_pool_block_row(block: &PoolBlockDetail, problem: Option<VirtAddr>) {
    let marker = if problem == Some(block.header) {
        "!"
    } else if block.marked {
        ">"
    } else {
        " "
    };
    outln!(
        "  {} {} 0x{:<6x} 0x{:<6x} {:<12} 0x{:<4x} '{}'",
        marker,
        ui::addr(block.header.0),
        block.size,
        block.previous_size,
        block.state,
        block.pool_type,
        block.tag_name
    );
}

fn print_mdl(detail: &MdlDetail) {
    outln!("Mdl {}", ui::addr(detail.address.0));
    outln!("  Next           {}", ui::addr(detail.next.0));
    outln!(
        "  Size           {:#x} ({} PFN slot{})",
        detail.size,
        detail.capacity,
        if detail.capacity == 1 { "" } else { "s" }
    );
    outln!(
        "  MdlFlags       {:#06x} {}",
        detail.flags,
        detail.flag_names.join(" ")
    );
    outln!("  Process        {}", ui::addr(detail.process.0));
    outln!("  MappedSystemVa {}", ui::addr(detail.mapped_system_va.0));
    outln!("  StartVa        {}", ui::addr(detail.start_va.0));
    outln!("  ByteCount      {:#x}", detail.byte_count);
    outln!("  ByteOffset     {:#x}", detail.byte_offset);
    outln!(
        "Physical pages ({} of {} spanned) at {}:",
        detail.pfns.len(),
        detail.spanned_pages,
        ui::addr(detail.pfn_array.0)
    );
    for row in detail.pfns.chunks(8) {
        let cells: Vec<String> = row.iter().map(|pfn| format!("{pfn:>8x}")).collect();
        outln!("  {}", cells.join(" "));
    }
    if detail.truncated {
        outln!(
            "  ({} more spanned page(s) not listed)",
            detail.spanned_pages - detail.pfns.len() as u64
        );
    }
    outln!();
}

fn print_system_ptes(detail: &SystemPtesDetail, flags: u64) {
    outln!("System PTE Information");
    outln!(
        "  Total System Ptes {}   free {}   in use {}",
        detail.total,
        detail.free,
        detail.total.saturating_sub(detail.free)
    );
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
        let span = pte_type.bitmap_bits.saturating_mul(pte_type.ptes_per_bit);
        match pte_type.base_va {
            Some(base) => outln!(
                "    VA range      {} - {}   first PTE {}",
                ui::addr(base.0),
                ui::addr(base.0.wrapping_add(span.saturating_mul(PAGE_SIZE as u64))),
                ui::addr(pte_type.base_pte.0)
            ),
            None => outln!("    first PTE     {}", ui::addr(pte_type.base_pte.0)),
        }
        outln!(
            "    Total Ptes    {}   free {}   in use {}   failures {}",
            pte_type.total,
            pte_type.free,
            pte_type.total.saturating_sub(pte_type.free),
            pte_type.failures
        );
        outln!(
            "    bitmap        {:#x} bits at {}, {} PTE{} per bit; {} PTEs reserved beyond Total",
            pte_type.bitmap_bits,
            ui::addr(pte_type.bitmap.0),
            pte_type.ptes_per_bit,
            if pte_type.ptes_per_bit == 1 { "" } else { "s" },
            span.saturating_sub(pte_type.total)
        );
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
        outln!(
            "    free blocks: {}   total free: {}   largest free block: {}",
            pte_type.free_run_count,
            pte_type.bitmap_free,
            pte_type.largest_free_run
        );
        if pte_type.bitmap_free != pte_type.free {
            outln!(
                "    (the bitmap counts {} free where TotalFreeSystemPtes says {}: the target allocated between the reads)",
                pte_type.bitmap_free,
                pte_type.free
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
                "  No allocator tracks its mappings (TrackPtes is off), so there is no record of the PTEs mapping locked pages."
            );
        } else {
            outln!(
                "  Tracking is on for {}; listing the tracked mappings is not supported.",
                tracked.join(", ")
            );
        }
    }
    if flags & 0x1a != 0 {
        outln!();
        outln!("  Flags 0x2, 0x8, and 0x10 apply to allocators this build does not have; ignored.");
    }
    outln!();
}

fn print_vm(detail: &VmDetail) {
    print_memory_use_summary(&detail.system, detail.include_processes);
    outln!("pool counters:");
    outln!(
        "  {:<24}: {} bytes",
        "nonpaged pool bytes",
        diagnostic_metric_cell(&detail.pool.nonpaged_pool_bytes)
    );
    outln!(
        "  {:<24}: {} bytes",
        "nonpaged pool maximum",
        diagnostic_metric_cell(&detail.pool.nonpaged_pool_maximum)
    );
    outln!(
        "  {:<24}: {} pages",
        "paged pool pages",
        diagnostic_metric_cell(&detail.pool.paged_pool_pages)
    );
    if detail.pool.fields.is_empty() {
        outln!("  MiState pool fields   : <unavailable>");
    } else {
        outln!("  MiState pool fields (native units):");
        for field in &detail.pool.fields {
            outln!(
                "    {:<32}: {} {}",
                field.name,
                diagnostic_metric_cell(&field.value),
                field.unit
            );
        }
    }

    outln!("PTE counters:");
    if detail
        .pte
        .counters
        .iter()
        .all(|counter| matches!(counter.value.value, DiagnosticValue::Unavailable(_)))
    {
        outln!("  counters               : <unavailable>");
    } else {
        for counter in &detail.pte.counters {
            outln!(
                "  {:<24}: {}",
                counter.name,
                diagnostic_metric_cell(&counter.value)
            );
        }
    }

    outln!("page files:");
    if detail
        .page_files
        .iter()
        .all(|counter| matches!(counter.value.value, DiagnosticValue::Unavailable(_)))
    {
        outln!("  summary               : <unavailable>");
    } else {
        for counter in &detail.page_files {
            outln!(
                "  {:<24}: {}{}",
                counter.name,
                diagnostic_metric_cell(&counter.value),
                if counter.unit.is_empty() {
                    "".to_string()
                } else {
                    format!(" {}", counter.unit)
                }
            );
        }
    }
}

fn print_pfn(detail: &PfnDetail) {
    outln!(
        "PFN {:08x} at address {}",
        detail.pfn,
        ui::addr(detail.record.0)
    );
    if let PfnSelector::PhysicalAddress(value) = detail.selector {
        outln!("  {:<20}: {}", "physical address", ui::addr(value));
    }
    outln!("  {:<20}: {}", "PteAddress", ui::addr(detail.pte_address.0));
    outln!("  {:<20}: {:#x}", "OriginalPte", detail.original_pte);
    outln!("  {:<20}: {}", "ReferenceCount", detail.reference_count);
    if let Some(value) = detail.flink {
        outln!("  {:<20}: {value:#x}", "Flink");
    }
    if let Some(value) = detail.blink {
        outln!("  {:<20}: {value:#x}", "Blink");
    }
    if detail.flink.is_some() {
        if let Some(value) = detail.node_flink_low {
            outln!("  {:<20}: {value:#x}", "NodeFlinkLow");
        }
        if let Some(value) = detail.node_blink_low {
            outln!("  {:<20}: {value:#x}", "NodeBlinkLow");
        }
    } else if let Some(value) = detail.share_count {
        outln!("  {:<20}: {value}", "ShareCount");
        if let Some(value) = detail.ws_index {
            outln!("  {:<20}: {value:#x}", "WsIndex");
        }
        if let Some(value) = detail.event {
            outln!("  {:<20}: {value:#x}", "Event");
        }
    } else {
        outln!("  {:<20}: <unavailable>", "ShareCount");
    }
    outln!(
        "  {:<20}: {}",
        "UsedPageTableEntries",
        detail.used_entry_count
    );
    outln!(
        "  {:<20}: {}",
        "PageColor",
        diagnostic_cell(&detail.page_color)
    );
    outln!(
        "  {:<20}: {:#x} (containing page)",
        "PteFrame",
        detail.pte_frame
    );
    outln!(
        "  PageLocation          : {} ({})",
        detail.page_location.value & 0x7,
        detail.page_location.name()
    );
    outln!("  Modified              : {}", detail.modified);
    outln!(
        "  CacheAttribute        : {} ({})",
        detail.cache_attribute.value & 0x3,
        detail.cache_attribute.name()
    );
    outln!("  Priority              : {}", detail.priority);
}

fn print_pte_entry(level: &PteLevel) {
    let name = level.level.as_str();
    let (address, raw, attributes) = (level.address.0, level.value, &level.attributes);
    if attributes.present {
        outln!(
            "  {name:<4} @ {} = {:016x}  pfn {:x}  flags {}",
            ui::addr(address),
            raw,
            attributes.pfn,
            attributes.flags
        );
    } else {
        outln!(
            "  {name:<4} @ {} = {:016x}  software/transition/prototype PTE",
            ui::addr(address),
            raw
        );
    }
}

fn print_vtop(detail: &VtopDetail) {
    outln!(
        "VA {} DTB {}",
        ui::addr(detail.address.0),
        ui::addr(detail.dtb)
    );
    for level in &detail.levels {
        print_pte_entry(level);
    }
    match detail.physical {
        Some(physical) => outln!("  physical             : {}", ui::addr(physical)),
        None => outln!("  physical             : <not mapped>"),
    }
    if detail.transition {
        outln!("  mapping              : transition (resident, not mapped; read-only)");
    }
    if detail.section {
        outln!(
            "  mapping              : section (the view's shared page, not mapped here; read-only)"
        );
    }
    if detail.large {
        outln!("  mapping              : large page");
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
        "PA {} DTB {}",
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
        .unwrap_or_else(|| "<unavailable>".to_string())
}

fn print_pool_usage(detail: &PoolUsageDetail, include_counts: bool) {
    outln!(
        "pool usage by tag (tracker: {}; big pages: {})",
        detail.tracker_status,
        detail.big_status
    );
    if detail.rows_truncated {
        outln!("pool usage rows bounded; some tags were omitted");
    }
    let mut builder = Builder::default();
    if include_counts {
        builder.push_record([
            "Tag",
            "NP Allocs",
            "NP Frees",
            "NP Bytes",
            "Paged Allocs",
            "Paged Frees",
            "Paged Bytes",
        ]);
        for row in &detail.rows {
            let tag = tag_string(row.tag);
            builder.push_record([
                format!("{tag} ({:#x})", row.tag),
                usage_cell(row.nonpaged_allocs),
                usage_cell(row.nonpaged_frees),
                usage_cell(row.nonpaged_bytes),
                usage_cell(row.paged_allocs),
                usage_cell(row.paged_frees),
                usage_cell(row.paged_bytes),
            ]);
        }
    } else {
        builder.push_record(["Tag", "NP Bytes", "Paged Bytes"]);
        for row in &detail.rows {
            let tag = tag_string(row.tag);
            builder.push_record([
                format!("{tag} ({:#x})", row.tag),
                usage_cell(row.nonpaged_bytes),
                usage_cell(row.paged_bytes),
            ]);
        }
    }
    print_padded_table(builder);
}

fn print_pool_find(detail: &PoolFindDetail) {
    if detail.ranges.is_empty() {
        outln!("pool virtual ranges: <unavailable>");
    }
    for range in &detail.ranges {
        for m in detail.matches.iter().filter(|m| m.source == range.name) {
            outln!(
                "  {} {} tag '{}' size 0x{:x} ({}, {}, {})",
                range.name,
                ui::addr(m.address.0),
                m.tag_name,
                m.size,
                m.state,
                if m.allocated { "allocated" } else { "free" },
                m.pool_type.map_or("unknown", |kind| kind.as_str())
            );
        }
        if let Some(stopped_at) = range.stopped_at {
            outln!(
                "  {} scan stopped at {} after {} mapped pages",
                range.name,
                ui::addr(stopped_at.0),
                range.scanned_pages
            );
        }
    }
    for m in detail.matches.iter().filter(|m| m.source == "BigPool") {
        outln!(
            "  BigPool {} tag '{}' size 0x{:x} ({}, {}){}",
            ui::addr(m.address.0),
            m.tag_name,
            m.size,
            m.state,
            m.pool_type.map_or("unknown", |kind| kind.as_str()),
            m.table_entry.map_or_else(
                || "".to_string(),
                |entry| format!(
                    " entry {}[{}]",
                    ui::addr(entry.0),
                    m.index.unwrap_or_default()
                )
            )
        );
    }
    if let Some(status) = &detail.big_status {
        outln!("  big-page table: {status}");
    }
    if detail.found == 0 {
        outln!("no pool blocks matched '{}'", detail.tag);
    } else {
        outln!("{} matching pool block(s)", detail.found);
    }
    if detail.interrupted {
        outln!("pool scan interrupted");
    }
}

fn print_lookaside_record(detail: &LookasideDetail) {
    let tag_display = match &detail.tag {
        DiagnosticValue::Available(tag) => format!("'{}' (0x{:08x})", tag.name(), tag.value),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    };
    outln!(
        "  [{:03}] {} tag {}",
        detail.index,
        ui::addr(detail.address.0),
        tag_display
    );
    for (name, value, suffix) in [
        ("Size", &detail.size, " bytes"),
        ("Depth", &detail.depth, ""),
        ("TotalAllocates", &detail.total_allocates, ""),
        ("TotalFrees", &detail.total_frees, ""),
        ("AllocateMisses", &detail.allocate_misses, ""),
    ] {
        outln!("       {name:<18}: {}{suffix}", diagnostic_cell(value));
    }
}

fn print_lookaside_lists(detail: &LookasideListsDetail) {
    if detail.records.is_empty() {
        outln!("lookaside lists: <unavailable>");
        return;
    }
    outln!(
        "lookaside lists ({} nonpaged, {} paged/other):",
        detail.nonpaged_count,
        detail.paged_count
    );
    for record in &detail.records {
        print_lookaside_record(record);
    }
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
        level.level.as_str(),
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
        .levels()
        .map(|level| pte_level_cell(level, invalid_pte_mask))
        .collect();
    builder.push_record(row_strings);

    let mut table = builder.build();
    table
        .with(Panel::header(header))
        .with(Modify::new(Rows::first()).with(Alignment::center()))
        .with(tabled::settings::Style::empty());

    outln!("{}\n", table);
}

/// `!pool`: the big-pool allocation holding `target`, or the pool page's
/// blocks with the one holding `target` marked.
fn print_pool_page(detail: &PoolPageDetail, target: VirtAddr) {
    if let Some(big) = &detail.big {
        outln!("big pool @ {}", ui::addr(big.address.0));
        outln!("  target        : {}", ui::addr(big.target.0));
        outln!(
            "  range         : {} - {} ({} bytes)",
            ui::addr(big.address.0),
            ui::addr(big.address.0.saturating_add(big.size)),
            big.size
        );
        outln!("  offset        : 0x{:x} / 0x{:x}", big.offset, big.size);
        outln!("  tag           : '{}' (0x{:08x})", big.tag_name, big.tag);
        outln!("  table entry   : {}[{}]", ui::addr(big.entry.0), big.index);
        outln!(
            "  nonpaged      : {}",
            if big.nonpaged { "yes" } else { "no" }
        );
        outln!("  pattern       : 0x{:x}", big.pattern);
        outln!("  pool flags    : 0x{:x}", big.pool_flags);
        outln!("  slush size    : 0x{:x}", big.slush_size);
        return;
    }

    outln!("pool page {}", ui::addr(detail.page.0));
    outln!("  target        : {}", ui::addr(target.0));
    if let Some(region) = &detail.region {
        outln!(
            "  region        : {} [{} - {}]",
            region.name,
            ui::addr(region.start.0),
            ui::addr(region.end.0)
        );
    }
    if let Some(idx) = detail.target_index {
        outln!(
            "  blocks in run : {} (target is #{})",
            detail.blocks.len(),
            idx + 1
        );
    }
    outln!();
    if detail.blocks.is_empty() {
        outln!("  (no plausible pool block found for this address)");
    } else {
        outln!(
            "    {:<16} {:<8} {:<8} {:<12} {:<6} tag",
            "header",
            "size",
            "prev",
            "state",
            "type"
        );
        for block in &detail.blocks {
            print_pool_block_row(block, None);
        }
        if let Some(idx) = detail.target_index {
            let block = &detail.blocks[idx];
            if let Some(offset) = block.target_offset {
                outln!(
                    "  target offset : 0x{:x} into body (block @ {}, body @ {})",
                    offset,
                    ui::addr(block.header.0),
                    ui::addr(block.body.0)
                );
            }
        }
    }

    if let Some(message) = &detail.message {
        outln!("  {message}.");
        outln!("  it may be segment heap, special pool, a mapped view, or image/stack.");
        if let Some(hint) = &detail.segment_heap_hint {
            outln!("  hint          : {}", hint);
        }
        if let Some(near) = &detail.near_symbol {
            outln!("  near symbol   : {}", near);
        }
    }
}
