use tabled::builder::Builder;

use crate::error::Result;
use crate::expr::Expr;
use crate::memory::DTB_IDENTITY;
use crate::repl::*;
use crate::target::mm::{
    LookasideDetail, LookasideListsDetail, PfnDetail, PfnSelector, PoolFindDetail, PoolType,
    PoolUsageDetail, PoolUsageSort, PtovDetail, VmDetail, VtopDetail,
};
use crate::target::pool::tag_string;
use crate::target::{DiagnosticMetric, DiagnosticValue};
use crate::types::{PageTableEntry, PageTableLevel, VirtAddr};
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
    details: "Flags follow WinDbg: bit 1 sorts by nonpaged bytes, bit 2 by paged bytes, and bit 0 enables alloc/free columns. Tag matching is case-sensitive and supports * and ?.",
    completion: Expression,
}

repl_command! {
    cmd_poolfind;
    names: ["!poolfind", "poolfind"],
    usage: "!poolfind <tag> [0|1]",
    summary: "Find pool blocks with a matching tag.",
    details: "The optional type selects nonpaged (0) or paged (1). Only virtual pool ranges and the big-page table are read; page scans are bounded and interruptible.",
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

fn eval_value(state: &ReplState<'_>, text: &str) -> std::result::Result<u64, String> {
    Expr::eval_with_radix(text, &state.ctx.target, state.radix)
        .map(|value| value.0)
        .map_err(|error| error.to_string())
}

fn eval_arg(state: &ReplState<'_>, text: &str) -> Option<u64> {
    match eval_value(state, text) {
        Ok(value) => Some(value),
        Err(error) => {
            error!("{error}");
            None
        }
    }
}

fn diagnostic_hex(value: &DiagnosticValue<u64>) -> String {
    match value {
        DiagnosticValue::Available(value) => format!("{value:#x}"),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
}

fn diagnostic_addr(value: &DiagnosticValue<VirtAddr>) -> String {
    match value {
        DiagnosticValue::Available(value) => ui::addr(value.0).to_string(),
        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
    }
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
    outln!(
        "  {:<20}: {}",
        "PteAddress",
        diagnostic_addr(&detail.pte_address)
    );
    outln!(
        "  {:<20}: {}",
        "OriginalPte",
        diagnostic_hex(&detail.original_pte)
    );
    outln!(
        "  {:<20}: {}",
        "ReferenceCount",
        diagnostic_cell(&detail.reference_count)
    );
    if let DiagnosticValue::Unavailable(error) = &detail.page_location {
        outln!("  {:<20}: <unavailable: {error}>", "PageLocation");
    }
    if let Some(value) = &detail.flink {
        outln!("  {:<20}: {}", "Flink", diagnostic_hex(value));
    }
    if let Some(value) = &detail.blink {
        outln!("  {:<20}: {}", "Blink", diagnostic_hex(value));
    }
    if detail.flink.is_some() {
        if let Some(value) = &detail.node_flink_low {
            outln!("  {:<20}: {}", "NodeFlinkLow", diagnostic_hex(value));
        }
        if let Some(value) = &detail.node_blink_low {
            outln!("  {:<20}: {}", "NodeBlinkLow", diagnostic_hex(value));
        }
    } else if let Some(value) = &detail.share_count {
        outln!("  {:<20}: {}", "ShareCount", diagnostic_cell(value));
        if let Some(value) = &detail.ws_index {
            outln!("  {:<20}: {}", "WsIndex", diagnostic_hex(value));
        }
        if let Some(value) = &detail.event {
            outln!("  {:<20}: {}", "Event", diagnostic_hex(value));
        }
    } else {
        outln!("  {:<20}: <unavailable>", "ShareCount");
    }
    outln!(
        "  {:<20}: {}",
        "UsedPageTableEntries",
        diagnostic_cell(&detail.used_entry_count)
    );
    outln!(
        "  {:<20}: {}",
        "PageColor",
        diagnostic_cell(&detail.page_color)
    );
    outln!(
        "  {:<20}: {} (containing page)",
        "PteFrame",
        diagnostic_hex(&detail.pte_frame)
    );
    match &detail.page_location {
        DiagnosticValue::Available(value) => outln!(
            "  PageLocation          : {} ({})",
            *value & 0x7,
            pfn_page_location(*value)
        ),
        DiagnosticValue::Unavailable(_) => {}
    }
    outln!(
        "  Modified              : {}",
        diagnostic_cell(&detail.modified)
    );
    match detail.cache_attribute {
        DiagnosticValue::Available(value) => outln!(
            "  CacheAttribute        : {} ({})",
            value & 0x3,
            pfn_cache_attribute(value)
        ),
        DiagnosticValue::Unavailable(ref error) => {
            outln!("  CacheAttribute        : <unavailable: {error}>")
        }
    }
    outln!(
        "  Priority              : {}",
        diagnostic_cell(&detail.priority)
    );
}

fn print_pte_entry(name: &str, address: u64, raw: u64) {
    let level = match name {
        "PPE" => PageTableLevel::Ppe,
        "PDE" => PageTableLevel::Pde,
        "PTE" => PageTableLevel::Pte,
        _ => PageTableLevel::Pxe,
    };
    let value = PageTableEntry(raw);
    if value.is_present() {
        outln!(
            "  {name:<4} @ {} = {:016x}  pfn {:x}  flags {}",
            ui::addr(address),
            raw,
            value.pfn(),
            value.flags_for_level(level)
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
        print_pte_entry(&level.name, level.address.0, level.value);
    }
    match detail.physical {
        Some(physical) => outln!("  physical             : {}", ui::addr(physical)),
        None => outln!("  physical             : <not mapped>"),
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
        if range.bounded {
            outln!(
                "  {} scan bounded at {} pages",
                range.name,
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

impl ReplState<'_> {
    fn cmd_vm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let flags = match invocation.arg(0) {
            Some(arg) => match eval_value(self, arg) {
                Ok(flags) => flags,
                Err(error) => {
                    error!("{error}");
                    return Ok(());
                }
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
        let Some(value) = eval_arg(self, value_arg) else {
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
        let Some(dtb) = eval_arg(self, dtb_arg) else {
            return Ok(());
        };
        let Some(va) = eval_arg(self, va_arg) else {
            return Ok(());
        };
        match self.ctx.target.vtop(dtb, VirtAddr(va)) {
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
        let Some(pa) = eval_arg(self, pa_arg) else {
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
            Some(arg) => match eval_value(self, arg) {
                Ok(flags) => (flags, invocation.arg(1)),
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
        let pool_type = match invocation.arg(1).map(|value| eval_value(self, value)) {
            Some(Ok(0)) => Some(PoolType::NonPaged),
            Some(Ok(1)) => Some(PoolType::Paged),
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
            let Some(address) = eval_arg(self, argument) else {
                return Ok(());
            };
            match self.ctx.target.inspect_lookaside(VirtAddr(address)) {
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
}
