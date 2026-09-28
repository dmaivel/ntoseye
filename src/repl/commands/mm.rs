use tabled::builder::Builder;
use tabled::settings::object::Rows;
use tabled::settings::{Alignment, Modify, Panel};

use crate::backend::MemoryOps;
use crate::error::Result;
use crate::expr::Expr;
use crate::memory::{DTB_IDENTITY, PAGE_SIZE};
use crate::repl::*;
use crate::target::mm::{
    LookasideDetail, LookasideListsDetail, MdlDetail, PfnDetail, PfnSelector, PoolBlockDetail,
    PoolFindDetail, PoolType, PoolUsageDetail, PoolUsageSort, PoolValidationDetail, PteLevel,
    PtovDetail, SystemPtesDetail, VmDetail, VtopDetail, VtopLevel,
};
use crate::target::pool::tag_string;
use crate::target::{DiagnosticMetric, DiagnosticValue};
use crate::types::VirtAddr;
use crate::ui;

use super::diagnostics::{diagnostic_cell, diagnostic_metric_cell, print_memory_use_summary};

repl_command! {
    cmd_vm;
    names: ["!vm", "vm"],
    usage: "!vm [flags]",
    summary: "Display system memory, pool, PTE, page-file, and process usage.",
    details: "Flags follow WinDbg: bit 0 omits per-process rows; bits 1, 2, and 3 are accepted but ignored. Counters degrade independently.",
    completion: Expression,
}

repl_command! {
    cmd_pfn;
    names: ["!pfn", "pfn"],
    usage: "!pfn <pfn> | !pfn -a <physical-address>",
    summary: "Decode an _MMPFN entry.",
    details: "A plain value is a page-frame number. Use -a to force physical-address mode.",
    completion: Expression,
}

repl_command! {
    cmd_vtop;
    names: ["!vtop", "vtop"],
    usage: "!vtop <directory-base> <virtual-address>",
    summary: "Translate a virtual address with an explicit directory base.",
    details: "A zero directory base uses the current context. Each AMD64 page-table level and the final physical address are shown; large pages stop at their leaf level.",
    completion: Expression,
}

repl_command! {
    cmd_ptov;
    names: ["!ptov", "ptov"],
    usage: "!ptov <physical-address>",
    summary: "Find current-directory-base virtual mappings of a physical address.",
    details: "The reverse page-table walk is bounded to 32 mappings and 65,536 table pages, with cycle detection.",
    completion: Expression,
}

repl_command! {
    cmd_poolused;
    names: ["!poolused", "poolused"],
    usage: "!poolused [flags] [tag]",
    summary: "Aggregate pool tracker usage by tag.",
    details: "Aggregates across every processor's tag table. Flags follow WinDbg: bit 1 (2) sorts by nonpaged bytes, bit 2 (4) by paged bytes, and bit 0 (1) enables alloc/free columns. Tag matching is case-sensitive and supports * and ?.",
    completion: Expression,
}

repl_command! {
    cmd_poolfind;
    names: ["!poolfind", "poolfind"],
    usage: "!poolfind <tag> [0|1]",
    summary: "Find pool blocks with a matching tag.",
    details: "The optional type selects nonpaged (0) or paged (1). The mapped pages of the pool ranges (on Windows 10 1803 and later the fixed regions in MiState.Vs.SystemVaRegions, before that MmNonPagedPoolStart and friends) and the big-page table are read; the scan stops after 1,024 matches and is interruptible.",
    completion: Expression,
}

repl_command! {
    cmd_lookaside;
    names: ["!lookaside", "lookaside"],
    usage: "!lookaside [address]",
    summary: "List or decode GENERAL_LOOKASIDE caches.",
    details: "The no-argument form walks both exported nonpaged and paged lookaside lists with cycle detection. An address decodes one entry directly.",
    completion: Expression,
}

repl_command! {
    cmd_pte;
    names: ["!pte", "pte"],
    usage: "!pte <address>",
    summary: "Display page table entries for an address.",
    completion: Expression,
}

repl_command! {
    cmd_pool;
    names: ["!pool", "pool"],
    usage: "!pool <address-expression>",
    summary: "Inspect the pool page containing an address.",
    completion: Expression,
}

repl_command! {
    cmd_poolval;
    names: ["!poolval", "poolval"],
    usage: "!poolval <address> [level]",
    summary: "Validate the block headers of the pool page containing an address.",
    details: "Reports the page VALID or INVALID with the first inconsistency. A classic pool page must chain from its start to its end, each PreviousSize matching the BlockSize before it. Segment-heap pages (Windows 10 1903 and later) keep no PreviousSize chain, so there a block whose BlockSize runs over another block's header is the inconsistency. A classic block's PoolType must also name the pool (paged or nonpaged) the page lies in. A level of 1 or more also lists every block header. WinDbg's single-bit-error scan is not done.",
    completion: Expression,
}

repl_command! {
    cmd_mdl;
    names: ["!mdl", "mdl"],
    usage: "!mdl <address> [pfn-count]",
    summary: "Decode a memory descriptor list and the page frames it describes.",
    details: "Shows the _MDL header (Next, Size, MdlFlags by MDL_* name, Process, MappedSystemVa, StartVa, ByteCount, ByteOffset) and the PFN array after it. The PFN count defaults to the pages ByteCount spans from ByteOffset; a pfn-count overrides it. Either is bounded by the slots Size leaves after the header. A header whose Size, ByteOffset, or span cannot describe an MDL is refused. Next is not followed; run !mdl on it for a chained MDL.",
    completion: Expression,
}

repl_command! {
    cmd_sysptes;
    names: ["!sysptes", "sysptes"],
    usage: "!sysptes [flags]",
    summary: "Show system PTE usage from the memory manager's bitmap allocators.",
    details: "Windows 10 and later hand out system PTEs from _MI_SYSTEM_PTE_TYPE bitmap allocators in MiState: Vs.SystemPteInfo (the SystemPtes region) and SystemPtes' system-view, non-cached-mapping, and kernel-stack allocators. For each: the VA range it serves, TotalSystemPtes, TotalFreeSystemPtes, the PTEs in use, PteFailures, and from its bitmap the number of free blocks and the largest; the bitmap is read whole (up to 2^27 bits, a bound only a corrupt SizeOfBitMap exceeds), and a free count that differs from the counter means the target allocated between the reads. Counts are in PTEs; the system-view bitmap covers 16 PTEs per bit. Flags follow WinDbg: 0x1 lists each free block (its first PTE, the address it maps, and its length; 256 per allocator). 0x4 (PTEs mapping locked pages) needs the kernel's TrackPtes tracking: it reports which allocators track, but the tracked mappings themselves are not listed. 0x2, 0x8, and 0x10 select Windows 2000/XP/Vista lists these allocators replaced and are ignored. A build without these allocators is refused.",
    completion: Expression,
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

fn print_system_ptes(detail: &SystemPtesDetail) {
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
    if detail.flags & 0x4 != 0 {
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
    if detail.flags & 0x1a != 0 {
        outln!();
        outln!("  Flags 0x2, 0x8, and 0x10 apply to allocators this build does not have; ignored.");
    }
    outln!();
}

fn metric_cell(metric: &DiagnosticMetric<u64>) -> String {
    diagnostic_metric_cell(metric)
}

fn print_vm(detail: &VmDetail) {
    print_memory_use_summary(&detail.system, detail.include_processes);
    outln!("pool counters:");
    outln!(
        "  {:<24}: {} bytes",
        "nonpaged pool bytes",
        metric_cell(&detail.pool.nonpaged_pool_bytes)
    );
    outln!(
        "  {:<24}: {} bytes",
        "nonpaged pool maximum",
        metric_cell(&detail.pool.nonpaged_pool_maximum)
    );
    outln!(
        "  {:<24}: {} pages",
        "paged pool pages",
        metric_cell(&detail.pool.paged_pool_pages)
    );
    if detail.pool.fields.is_empty() {
        outln!("  MiState pool fields   : <unavailable>");
    } else {
        outln!("  MiState pool fields (native units):");
        for field in &detail.pool.fields {
            outln!(
                "    {:<32}: {} {}",
                field.name,
                metric_cell(&field.value),
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
            outln!("  {:<24}: {}", counter.name, metric_cell(&counter.value));
        }
    }

    outln!("page files:");
    if detail
        .page_files
        .counters
        .iter()
        .all(|counter| matches!(counter.value.value, DiagnosticValue::Unavailable(_)))
    {
        outln!("  summary               : <unavailable>");
    } else {
        for counter in &detail.page_files.counters {
            outln!(
                "  {:<24}: {}{}",
                counter.name,
                metric_cell(&counter.value),
                if counter.unit.is_empty() {
                    "".to_string()
                } else {
                    format!(" {}", counter.unit)
                }
            );
        }
    }
}

fn pfn_page_location(value: u8) -> &'static str {
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

fn pfn_cache_attribute(value: u8) -> &'static str {
    match value & 0x3 {
        0 => "MmNonCached",
        1 => "MmCached",
        2 => "MmWriteCombined",
        _ => "MmNotMapped",
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
        detail.page_location & 0x7,
        pfn_page_location(detail.page_location)
    );
    outln!("  Modified              : {}", detail.modified);
    outln!(
        "  CacheAttribute        : {} ({})",
        detail.cache_attribute & 0x3,
        pfn_cache_attribute(detail.cache_attribute)
    );
    outln!("  Priority              : {}", detail.priority);
}

fn print_pte_entry(level: &VtopLevel) {
    let name = level.level.name();
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

fn print_pool_usage(detail: &PoolUsageDetail) {
    outln!(
        "pool usage by tag (tracker: {}; big pages: {})",
        detail.tracker_status,
        detail.big_status
    );
    if detail.rows_truncated {
        outln!("pool usage rows bounded; some tags were omitted");
    }
    let mut builder = Builder::default();
    if detail.include_counts {
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
                m.pool_type.map_or("unknown", PoolType::name)
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
            m.pool_type.map_or("unknown", PoolType::name),
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
        DiagnosticValue::Available(value) => {
            format!("'{}' (0x{value:08x})", tag_string(*value))
        }
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
    let value = level.value;
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
        level.level.name(),
        level.address,
        ui::Value(value.0),
    )
}

impl ReplState<'_> {
    fn cmd_vm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let flags = match invocation.arg(0) {
            Some(arg) => match self.eval_or_report(arg) {
                Some(VirtAddr(flags)) => flags,
                None => return Ok(()),
            },
            None => 0,
        };
        let include_processes = flags & 1 == 0;
        match self.ctx.target.inspect_vm(include_processes) {
            Ok(detail) => print_vm(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_pfn(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (physical, value_arg) = if matches!(invocation.arg(0), Some("-a" | "/a")) {
            (true, invocation.arg(1))
        } else {
            (false, invocation.arg(0))
        };
        let Some(value_arg) = value_arg else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(VirtAddr(value)) = self.eval_or_report(value_arg) else {
            return Ok(());
        };
        let selector = if physical {
            PfnSelector::PhysicalAddress(value)
        } else {
            PfnSelector::Pfn(value)
        };
        match self.ctx.target.inspect_pfn(selector) {
            Ok(detail) => print_pfn(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_vtop(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(dtb_arg) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(va_arg) = invocation.arg(1) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(VirtAddr(dtb)) = self.eval_or_report(dtb_arg) else {
            return Ok(());
        };
        let Some(va) = self.eval_or_report(va_arg) else {
            return Ok(());
        };
        match self.ctx.target.vtop(dtb, va) {
            Ok(detail) => print_vtop(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_ptov(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(pa_arg) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(VirtAddr(pa)) = self.eval_or_report(pa_arg) else {
            return Ok(());
        };
        match self.ctx.target.ptov(pa) {
            Ok(detail) => print_ptov(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_poolused(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (flags, tag_filter) = match invocation.arg(0) {
            None => (0, None),
            Some(arg) => match Expr::eval_with_radix(arg, &self.ctx.target, self.radix) {
                Ok(VirtAddr(flags)) => (flags, invocation.arg(1)),
                Err(_) => (0, Some(arg)),
            },
        };
        let sort = match flags & 0x6 {
            0x2 => PoolUsageSort::NonPagedBytes,
            0x4 => PoolUsageSort::PagedBytes,
            _ => PoolUsageSort::Tag,
        };
        match self.ctx.target.pool_usage(sort, tag_filter, flags & 1 != 0) {
            Ok(detail) => print_pool_usage(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_poolfind(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(tag) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let pool_type = invocation
            .arg(1)
            .map(|value| Expr::eval_with_radix(value, &self.ctx.target, self.radix));
        let pool_type = match pool_type {
            Some(Ok(VirtAddr(0))) => Some(PoolType::NonPaged),
            Some(Ok(VirtAddr(1))) => Some(PoolType::Paged),
            Some(Ok(_)) | Some(Err(_)) => {
                outln!("pool type must be 0 (nonpaged) or 1 (paged)");
                return Ok(());
            }
            None => None,
        };
        match self.ctx.target.pool_find(tag, pool_type) {
            Ok(detail) => print_pool_find(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_lookaside(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(argument) = invocation.arg(0) {
            let Some(address) = self.eval_or_report(argument) else {
                return Ok(());
            };
            match self.ctx.target.inspect_lookaside(address) {
                Ok(detail) => print_lookaside_record(&detail),
                Err(error) => error!("{error}"),
            }
            return Ok(());
        }
        match self.ctx.target.lookaside_lists() {
            Ok(detail) => print_lookaside_lists(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_pte(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = require_arg!(invocation, 0, "pte");
        let Some(address) = self.eval_or_report(expr) else {
            return Ok(());
        };
        match self.ctx.target.pte_traverse(address) {
            Ok(result) => {
                let header = format!(
                    "VA {}  DTB {}",
                    ui::addr(result.address.0),
                    ui::addr(result.dtb)
                );
                let mut builder = Builder::default();

                let mask = self.ctx.target.phys.invalid_pte_mask();
                let row_strings: Vec<String> = result
                    .levels()
                    .map(|level| pte_level_cell(level, mask))
                    .collect();
                builder.push_record(row_strings);

                let mut table = builder.build();
                table
                    .with(Panel::header(header))
                    .with(Modify::new(Rows::first()).with(Alignment::center()))
                    .with(tabled::settings::Style::empty());

                outln!("{}\n", table);
            }
            Err(e) => {
                error!("{}\n", e);
            }
        }

        Ok(())
    }

    fn cmd_mdl(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(address) = self.eval_or_report(expr) else {
            return Ok(());
        };
        let pfn_count = match invocation.arg(1) {
            Some(count) => match self.eval_or_report(count) {
                Some(VirtAddr(count)) => Some(count),
                None => return Ok(()),
            },
            None => None,
        };
        match self.ctx.target.inspect_mdl(address, pfn_count) {
            Ok(detail) => print_mdl(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_sysptes(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let flags = match invocation.arg(0) {
            Some(arg) => match self.eval_or_report(arg) {
                Some(VirtAddr(flags)) => flags,
                None => return Ok(()),
            },
            None => 0,
        };
        match self.ctx.target.system_ptes(flags) {
            Ok(detail) => print_system_ptes(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_poolval(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = require_arg!(invocation, 0, "!poolval");
        let Some(address) = self.eval_or_report(expr) else {
            return Ok(());
        };
        let level = match invocation.arg(1) {
            Some(arg) => match self.eval_or_report(arg) {
                Some(VirtAddr(level)) => level,
                None => return Ok(()),
            },
            None => 0,
        };
        match self.ctx.target.validate_pool(address) {
            Ok(detail) => print_pool_validation(&detail, level),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_pool(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("pool"));
            return Ok(());
        };

        let Some(target) = self.eval_or_report(expr) else {
            return Ok(());
        };

        let detail = match self.ctx.target.inspect_pool(target) {
            Ok(detail) => detail,
            Err(error) => {
                error!("{}", error);
                return Ok(());
            }
        };
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
            return Ok(());
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

        Ok(())
    }
}
