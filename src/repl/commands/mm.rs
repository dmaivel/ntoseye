use std::collections::HashSet;
use std::sync::atomic::Ordering;

use tabled::builder::Builder;

use crate::backend::MemoryOps;
use crate::error::Result;
use crate::expr::Expr;
use crate::memory::{DTB_IDENTITY, PAGE_SIZE, PFN_MASK};
use crate::repl::*;
use crate::symbols::{ParsedType, TypeInfo, le_uint};
use crate::target::Target;
use crate::types::{Arch, Dtb, PageTableEntry, PageTableLevel, VirtAddr};
use crate::ui;

use super::diagnostics::{DEFAULT_MEMORY_PROCESS_LIMIT, print_memory_use_summary};

const MAX_MI_FIELDS: usize = 64;
const MAX_MI_STATE_FIELDS: usize = 16;
const MAX_LOOKASIDE_ENTRIES: usize = 256;
const MAX_POOLFIND_PAGES: u64 = 16 * 1024;
const MAX_POOLFIND_RESULTS: usize = 1024;
const MAX_POOLUSED_ROWS: usize = 256;
const MAX_PTOV_TABLE_PAGES: usize = 65_536;
const MAX_PTOV_RESULTS: usize = 32;
const LARGE_PAGE_1G: u64 = 1 << 30;
const LARGE_PAGE_2M: u64 = 1 << 21;
const MMPFN_U1_OFFSET: usize = 0;
const MMPFN_PTE_ADDRESS_OFFSET: usize = 8;
const MMPFN_ORIGINAL_PTE_OFFSET: usize = 16;
const MMPFN_U2_OFFSET: usize = 24;
const MMPFN_U3_OFFSET: usize = 32;
const MMPFN_U4_OFFSET: usize = 40;
const MMPFNENTRY1_FLAGS_OFFSET: usize = 2;
const MMPFNENTRY3_FLAGS_OFFSET: usize = 3;
const MMPTE_SOFTWARE_OFFSET: usize = 0;

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

fn scalar_from_type_tree(
    target: &Target,
    ti: &TypeInfo,
    buf: &[u8],
    base: usize,
    field: &str,
    depth: usize,
    visited: &mut HashSet<String>,
) -> Option<u64> {
    if depth > 5 {
        return None;
    }
    let slice = buf.get(base..)?;
    if let Some(value) = pool_field_from_buf(ti, slice, field) {
        return Some(value);
    }

    let mut nested = ti
        .fields
        .iter()
        .filter_map(|(name, info)| type_name(&info.type_data).map(|nested| (name, info, nested)))
        .collect::<Vec<_>>();
    nested.sort_by_key(|(_, info, _)| info.offset);
    for (_, info, nested_name) in nested {
        let nested_base = base.checked_add(info.offset as usize)?;
        let key = format!("{nested_base}:{nested_name}:{field}");
        if !visited.insert(key) {
            continue;
        }
        let Some(nested_ti) = target
            .symbols
            .find_type_across_modules(target.kernel_dtb(), nested_name)
        else {
            continue;
        };
        if let Some(value) = scalar_from_type_tree(
            target,
            &nested_ti,
            buf,
            nested_base,
            field,
            depth + 1,
            visited,
        ) {
            return Some(value);
        }
    }
    None
}

fn scalar_from_pfn_member(
    target: &Target,
    pfn_ti: &TypeInfo,
    buf: &[u8],
    member: &str,
    field: &str,
) -> Option<u64> {
    if let Some(member_info) = pfn_ti.fields.get(member) {
        if let Some(nested_name) = type_name(&member_info.type_data)
            && let Some(nested_ti) = target
                .symbols
                .find_type_across_modules(target.kernel_dtb(), nested_name)
        {
            let mut visited = HashSet::new();
            if let Some(value) = scalar_from_type_tree(
                target,
                &nested_ti,
                buf,
                member_info.offset as usize,
                field,
                0,
                &mut visited,
            ) {
                return Some(value);
            }
        }
        // Anonymous PDB members are commonly flattened into _MMPFN.  If the
        // named union itself was available but its anonymous child wasn't,
        // prefer a flattened leaf over walking unrelated overlays (such as
        // _LIST_ENTRY.Flink).
        return pool_field_from_buf(pfn_ti, buf, field);
    }

    let mut visited = HashSet::new();
    scalar_from_type_tree(target, pfn_ti, buf, 0, field, 0, &mut visited)
}

fn scalar_from_named_type(
    target: &Target,
    type_name: &str,
    buf: &[u8],
    offset: usize,
    field: &str,
) -> Option<u64> {
    let ti = target
        .symbols
        .find_type_across_modules(target.kernel_dtb(), type_name)?;
    let mut visited = HashSet::new();
    scalar_from_type_tree(target, &ti, buf, offset, field, 0, &mut visited)
}

fn member_raw(ti: &TypeInfo, buf: &[u8], member: &str, fallback_offset: usize) -> u64 {
    let (offset, size) = ti
        .fields
        .get(member)
        .map(|field| {
            (
                field.offset as usize,
                usize::try_from(field.size)
                    .ok()
                    .filter(|size| *size != 0)
                    .unwrap_or(8)
                    .clamp(1, 8),
            )
        })
        .unwrap_or((fallback_offset, 8));
    buf.get(offset..offset.saturating_add(size))
        .map(le_uint)
        .unwrap_or(0)
}

fn type_name(data: &ParsedType) -> Option<&str> {
    match data {
        ParsedType::Struct(name) | ParsedType::Union(name) => Some(name.as_str()),
        _ => None,
    }
}

fn read_type_buffer(
    memory: &impl MemoryOps<VirtAddr>,
    ti: &TypeInfo,
    base: VirtAddr,
) -> Option<Vec<u8>> {
    let size = ti.size;
    if size == 0 || size > PAGE_SIZE {
        return None;
    }
    let mut buf = vec![0u8; size];
    memory.read_bytes(base, &mut buf).ok()?;
    Some(buf)
}

fn unavailable(error: impl std::fmt::Display) -> String {
    format!("<unavailable: {error}>")
}

fn global_value(target: &Target, name: &str) -> std::result::Result<u64, String> {
    read_kernel_global_u64(target, name).map_err(|error| error.to_string())
}

fn print_global_line(target: &Target, label: &str, symbol: &str, suffix: &str) {
    match global_value(target, symbol) {
        Ok(value) => outln!("  {label:<24}: {value:#x}{suffix}"),
        Err(error) => outln!("  {label:<24}: {}", unavailable(error)),
    }
}

fn read_debugger_data_counter(
    target: &Target,
    address: Option<crate::debugger_data::MetadataValue<VirtAddr>>,
) -> Option<u64> {
    let address = address?.value;
    target.kernel_address_space().read(address).ok()
}

fn print_memory_counter_fallback(
    target: &Target,
    label: &str,
    symbol: &str,
    address: Option<crate::debugger_data::MetadataValue<VirtAddr>>,
) {
    if let Ok(value) = global_value(target, symbol) {
        outln!("  {label:<24}: {value}");
    } else if let Some(value) = read_debugger_data_counter(target, address) {
        outln!("  {label:<24}: {value} [KD]");
    } else {
        outln!("  {label:<24}: <unavailable>");
    }
}

fn nested_fields(
    target: &Target,
    base: VirtAddr,
    ti: &TypeInfo,
    prefix: &str,
    predicates: &[String],
    depth: usize,
    visited: &mut HashSet<String>,
    output: &mut Vec<(String, u64)>,
) {
    if depth > 3 || output.len() >= MAX_MI_FIELDS {
        return;
    }
    let memory = target.kernel_address_space();
    let mut fields: Vec<_> = ti.fields.iter().collect();
    fields.sort_by_key(|(_, field)| field.offset);
    for (name, field) in fields {
        if output.len() >= MAX_MI_FIELDS {
            break;
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}.{name}")
        };
        if let Some(nested) = type_name(&field.type_data)
            && depth < 3
            && visited.insert(format!("{path}:{nested}"))
            && let Some(nested_ti) = target
                .symbols
                .find_type_across_modules(target.kernel_dtb(), nested)
        {
            nested_fields(
                target,
                base + field.offset as u64,
                &nested_ti,
                &path,
                predicates,
                depth + 1,
                visited,
                output,
            );
            continue;
        }
        let matches_predicate = predicates
            .iter()
            .any(|predicate| path.to_ascii_lowercase().contains(predicate));
        if matches_predicate
            && !matches!(&field.type_data, ParsedType::Array(_, _))
            && let Some(value) = read_pool_field(ti, &memory, base, name)
        {
            output.push((path, value));
        }
    }
}

fn find_mi_state_fields(target: &Target, predicates: &[&str]) -> Vec<(String, u64)> {
    let Ok(base) = kernel_symbol_address(target, "MiState") else {
        return Vec::new();
    };
    let Some(ti) = target
        .symbols
        .find_type_across_modules(target.kernel_dtb(), "_MI_SYSTEM_INFORMATION")
    else {
        return Vec::new();
    };
    let predicates = predicates
        .iter()
        .map(|predicate| predicate.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut fields = Vec::new();
    let mut visited = HashSet::new();
    nested_fields(
        target,
        base,
        &ti,
        "",
        &predicates,
        0,
        &mut visited,
        &mut fields,
    );
    fields
}

fn print_mi_state_fields(target: &Target) {
    let fields = find_mi_state_fields(target, &["pool"])
        .into_iter()
        .filter(|(name, _)| curated_mi_state_pool_field(name))
        .take(MAX_MI_STATE_FIELDS)
        .collect::<Vec<_>>();
    if fields.is_empty() {
        outln!("  MiState pool fields   : <unavailable>");
        return;
    }
    outln!("  MiState pool fields (native units):");
    for (name, value) in fields {
        outln!(
            "    {name:<32}: {value:#x} {}",
            mi_state_pool_field_unit(&name)
        );
    }
}

fn mi_state_pool_field_unit(name: &str) -> &'static str {
    let leaf = name
        .to_ascii_lowercase()
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_string();
    if leaf == "maximumnonpagedpoolthreshold"
        || (leaf.contains("allocated")
            && (leaf.contains("nonpagedpool") || leaf.contains("pagedpool")))
    {
        "pages"
    } else {
        "bytes"
    }
}

fn curated_mi_state_pool_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let leaf = lower.rsplit('.').next().unwrap_or(&lower);
    (leaf == "allocatednonpagedpool")
        || (leaf == "allocatedpagedpool")
        || (leaf == "allocatedsecurenonpagedpool")
        || (leaf == "maximumnonpagedpoolthreshold")
        || (leaf.starts_with("total") && leaf.contains("poolquota"))
        || ((leaf.contains("nonpagedpool") || leaf.contains("pagedpool")) && leaf.contains("bytes"))
}

fn page_file_summary(target: &Target) {
    outln!("page files:");
    let mut found = false;
    for (label, symbol, suffix) in [
        ("number of paging files", "MmNumberOfPagingFiles", ""),
        (
            "pages for paging file",
            "MmTotalPagesForPagingFile",
            " pages",
        ),
        ("free paging pages", "MmFreePages", " pages"),
    ] {
        if let Ok(value) = global_value(target, symbol) {
            found = true;
            outln!("  {label:<24}: {value}{suffix}");
        }
    }
    if !found {
        outln!("  summary               : <unavailable>");
    }
}

fn print_pfn_flags(page_location: u8, modified: bool, cache_attribute: u8, priority: u8) {
    const PAGE_LOCATIONS: [&str; 8] = [
        "ZeroedPageList",
        "FreePageList",
        "StandbyPageList",
        "ModifiedPageList",
        "ModifiedNoWritePageList",
        "BadPageList",
        "ActiveAndValid",
        "TransitionPage",
    ];
    const CACHE_ATTRIBUTES: [&str; 4] =
        ["MmNonCached", "MmCached", "MmWriteCombined", "MmNotMapped"];
    let page_location = (page_location & 0x7) as usize;
    let cache_attribute = (cache_attribute & 0x3) as usize;
    outln!(
        "  PageLocation          : {} ({})",
        page_location,
        PAGE_LOCATIONS[page_location]
    );
    outln!("  Modified              : {modified}");
    outln!(
        "  CacheAttribute        : {} ({})",
        cache_attribute,
        CACHE_ATTRIBUTES[cache_attribute]
    );
    outln!("  Priority              : {}", priority & 0x7);
}

fn print_pte_entry(name: &str, address: u64, value: PageTableEntry) {
    let level = match name {
        "PPE" => PageTableLevel::Ppe,
        "PDE" => PageTableLevel::Pde,
        "PTE" => PageTableLevel::Pte,
        _ => PageTableLevel::Pxe,
    };
    if value.is_present() {
        outln!(
            "  {name:<4} @ {} = {:016x}  pfn {:x}  flags {}",
            ui::addr(address),
            value.0,
            value.pfn(),
            value.flags_for_level(level)
        );
    } else {
        outln!(
            "  {name:<4} @ {} = {:016x}  software/transition/prototype PTE",
            ui::addr(address),
            value.0
        );
    }
}

struct ExplicitWalk {
    levels: Vec<(String, u64, PageTableEntry)>,
    physical: Option<u64>,
    large: bool,
}

fn explicit_amd64_walk(
    target: &Target,
    dtb: Dtb,
    va: VirtAddr,
) -> std::result::Result<ExplicitWalk, String> {
    if dtb == DTB_IDENTITY {
        return Ok(ExplicitWalk {
            levels: Vec::new(),
            physical: Some(va.0),
            large: false,
        });
    }
    let root = dtb & PFN_MASK;
    let memory = &target.phys;
    let mut levels = Vec::with_capacity(4);
    let pml4_address = root
        .checked_add((va.pml4_index() as u64) * 8)
        .ok_or_else(|| "PML4 address overflow".to_string())?;
    let pml4e: PageTableEntry = memory
        .read(pml4_address)
        .map_err(|error| error.to_string())?;
    levels.push(("PXE".to_string(), pml4_address, pml4e));
    if !pml4e.is_present() {
        return Ok(ExplicitWalk {
            levels,
            physical: None,
            large: false,
        });
    }

    let pdpt_address = pml4e
        .page_frame()
        .checked_add((va.pdpt_index() as u64) * 8)
        .ok_or_else(|| "PDPT address overflow".to_string())?;
    let pdpte: PageTableEntry = memory
        .read(pdpt_address)
        .map_err(|error| error.to_string())?;
    levels.push(("PPE".to_string(), pdpt_address, pdpte));
    if !pdpte.is_present() {
        return Ok(ExplicitWalk {
            levels,
            physical: None,
            large: false,
        });
    }
    if pdpte.is_large_page() {
        let frame = pdpte.page_frame() & !(LARGE_PAGE_1G - 1);
        return Ok(ExplicitWalk {
            levels,
            physical: frame.checked_add(va.huge_page_offset()),
            large: true,
        });
    }

    let pde_address = pdpte
        .page_frame()
        .checked_add((va.pd_index() as u64) * 8)
        .ok_or_else(|| "PD address overflow".to_string())?;
    let pde: PageTableEntry = memory
        .read(pde_address)
        .map_err(|error| error.to_string())?;
    levels.push(("PDE".to_string(), pde_address, pde));
    if !pde.is_present() {
        return Ok(ExplicitWalk {
            levels,
            physical: None,
            large: false,
        });
    }
    if pde.is_large_page() {
        let frame = pde.page_frame() & !(LARGE_PAGE_2M - 1);
        return Ok(ExplicitWalk {
            levels,
            physical: frame.checked_add(va.large_page_offset()),
            large: true,
        });
    }

    let pte_address = pde
        .page_frame()
        .checked_add((va.pt_index() as u64) * 8)
        .ok_or_else(|| "PT address overflow".to_string())?;
    let pte: PageTableEntry = memory
        .read(pte_address)
        .map_err(|error| error.to_string())?;
    levels.push(("PTE".to_string(), pte_address, pte));
    Ok(ExplicitWalk {
        levels,
        physical: pte
            .is_present()
            .then(|| pte.page_frame().checked_add(va.page_offset()))
            .flatten(),
        large: false,
    })
}

fn scan_ptov_table(
    target: &Target,
    table: u64,
    level: u8,
    prefix: [usize; 4],
    wanted_page: u64,
    visited: &mut HashSet<u64>,
    table_pages: &mut usize,
    results: &mut Vec<(VirtAddr, bool)>,
) {
    if *table_pages >= MAX_PTOV_TABLE_PAGES
        || results.len() >= MAX_PTOV_RESULTS
        || INTERRUPT_REQUESTED.load(Ordering::Relaxed)
    {
        return;
    }
    let table = table & PFN_MASK;
    if !visited.insert(table) {
        return;
    }
    *table_pages += 1;
    let entries: [PageTableEntry; 512] = match target.phys.read(table) {
        Ok(entries) => entries,
        Err(_) => {
            visited.remove(&table);
            return;
        }
    };
    for (index, entry) in entries.into_iter().enumerate() {
        if !entry.is_present() || results.len() >= MAX_PTOV_RESULTS {
            continue;
        }
        let mut current = prefix;
        current[level as usize] = index;
        if level == 1 && entry.is_large_page() {
            let frame = entry.page_frame() & !(LARGE_PAGE_1G - 1);
            let end = frame.saturating_add(LARGE_PAGE_1G);
            if (frame..end).contains(&wanted_page) {
                let va = VirtAddr::construct(current[0], current[1], 0, 0) + (wanted_page - frame);
                results.push((va, true));
            }
            continue;
        }
        if level == 2 && entry.is_large_page() {
            let frame = entry.page_frame() & !(LARGE_PAGE_2M - 1);
            let end = frame.saturating_add(LARGE_PAGE_2M);
            if (frame..end).contains(&wanted_page) {
                let va = VirtAddr::construct(current[0], current[1], current[2], 0)
                    + (wanted_page - frame);
                results.push((va, true));
            }
            continue;
        }
        if level == 3 {
            if entry.page_frame() == wanted_page {
                let va = VirtAddr::construct(current[0], current[1], current[2], current[3]);
                results.push((va, false));
            }
            continue;
        }
        scan_ptov_table(
            target,
            entry.page_frame(),
            level + 1,
            current,
            wanted_page,
            visited,
            table_pages,
            results,
        );
    }
    visited.remove(&table);
}

fn usage_cell(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "<unavailable>".to_string())
}

fn pool_range(
    target: &Target,
    name: &'static str,
    start_symbol: &str,
    end_symbol: &str,
    kind: u64,
) -> Option<PoolRange> {
    let start = read_kernel_global_u64(target, start_symbol).ok()?;
    let end = read_kernel_global_u64(target, end_symbol).ok()?;
    (start < end).then_some(PoolRange {
        name,
        start,
        end,
        kind,
    })
}

#[derive(Clone, Copy)]
struct PoolRange {
    name: &'static str,
    start: u64,
    end: u64,
    kind: u64,
}

fn mi_state_pool_range(
    target: &Target,
    start_name: &str,
    end_name: &str,
    kind: u64,
) -> Option<PoolRange> {
    let fields = find_mi_state_fields(target, &["pool", "start", "end"]);
    let start = fields.iter().find_map(|(name, value)| {
        name.to_ascii_lowercase()
            .contains(&start_name.to_ascii_lowercase())
            .then_some(*value)
    })?;
    let end = fields.iter().find_map(|(name, value)| {
        name.to_ascii_lowercase()
            .contains(&end_name.to_ascii_lowercase())
            .then_some(*value)
    })?;
    (start < end).then_some(PoolRange {
        name: if kind == 0 {
            "NonPagedPool"
        } else {
            "PagedPool"
        },
        start,
        end,
        kind,
    })
}

fn resolve_pool_ranges(target: &Target) -> Vec<PoolRange> {
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

fn print_lookaside_record(target: &Target, ti: &TypeInfo, address: VirtAddr, index: usize) {
    let memory = target.kernel_address_space();
    let tag = read_pool_field(ti, &memory, address, "Tag");
    let tag_display = tag
        .map(|tag| format!("'{}' (0x{tag:08x})", tag_string(tag as u32)))
        .unwrap_or_else(|| "<unavailable>".to_string());
    outln!("  [{index:03}] {} tag {tag_display}", ui::addr(address.0));
    for (field, suffix) in [
        ("Size", " bytes"),
        ("Depth", ""),
        ("TotalAllocates", ""),
        ("TotalFrees", ""),
        ("AllocateMisses", ""),
    ] {
        match read_pool_field(ti, &memory, address, field) {
            Some(value) => outln!("       {field:<18}: {value}{suffix}"),
            None => outln!("       {field:<18}: <unavailable>"),
        }
    }
}

fn walk_lookaside_chain(
    target: &Target,
    ti: &TypeInfo,
    first_link: VirtAddr,
    head_link: Option<VirtAddr>,
    seen: &mut HashSet<u64>,
    records: &mut Vec<VirtAddr>,
) {
    let link_offset = ti.fields.get("ListEntry").map(|field| field.offset as u64);
    let Some(link_offset) = link_offset else {
        return;
    };
    let memory = target.kernel_address_space();
    let mut current_link = first_link;
    while records.len() < MAX_LOOKASIDE_ENTRIES
        && !current_link.is_zero()
        && !INTERRUPT_REQUESTED.load(Ordering::Relaxed)
    {
        if head_link.is_some_and(|head_link| current_link == head_link) {
            break;
        }
        let Some(record) = current_link.0.checked_sub(link_offset).map(VirtAddr) else {
            break;
        };
        if !seen.insert(record.0) {
            break;
        }
        if read_pool_field(ti, &memory, record, "Size").is_none() {
            break;
        }
        records.push(record);
        let Some(next) = memory.read::<VirtAddr>(current_link).ok() else {
            break;
        };
        current_link = next;
    }
}

fn lookaside_roots(
    target: &Target,
    symbol: &str,
    ti: &TypeInfo,
    seen: &mut HashSet<u64>,
    records: &mut Vec<VirtAddr>,
) {
    let Ok(symbol_address) = kernel_symbol_address(target, symbol) else {
        return;
    };
    let memory = target.kernel_address_space();
    let Ok(first_link) = memory.read::<VirtAddr>(symbol_address) else {
        return;
    };
    walk_lookaside_chain(target, ti, first_link, Some(symbol_address), seen, records);
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
        let include_process_stats = flags & 1 == 0;
        let target = &self.ctx.target;

        let process_limit = if include_process_stats {
            DEFAULT_MEMORY_PROCESS_LIMIT
        } else {
            1
        };
        match target.memory_use_summary(process_limit) {
            Ok(summary) => print_memory_use_summary(&summary, include_process_stats),
            Err(error) => {
                outln!("  memory-use summary    : {}", unavailable(&error));
                let debugger_data = target.debugger_data();
                print_memory_counter_fallback(
                    target,
                    "physical pages",
                    "MmNumberOfPhysicalPages",
                    debugger_data.and_then(|data| data.mm_number_of_physical_pages_address()),
                );
                print_memory_counter_fallback(
                    target,
                    "available pages",
                    "MmAvailablePages",
                    debugger_data.and_then(|data| data.mm_available_pages_address()),
                );
                print_memory_counter_fallback(
                    target,
                    "committed pages",
                    "MmTotalCommittedPages",
                    debugger_data.and_then(|data| data.mm_total_committed_pages_address()),
                );
                print_memory_counter_fallback(
                    target,
                    "commit limit pages",
                    "MmTotalCommitLimit",
                    debugger_data.and_then(|data| data.mm_total_commit_limit_address()),
                );
                if include_process_stats {
                    outln!("  process counters      : <unavailable: {error}>");
                }
            }
        }

        outln!("pool counters:");
        print_global_line(
            target,
            "nonpaged pool bytes",
            "MmSizeOfNonPagedPoolInBytes",
            " bytes",
        );
        print_global_line(
            target,
            "nonpaged pool maximum",
            "MmMaximumNonPagedPoolInBytes",
            " bytes",
        );
        print_global_line(
            target,
            "paged pool pages",
            "MmSizeOfPagedPoolInPages",
            " pages",
        );
        print_mi_state_fields(target);

        outln!("PTE counters:");
        let pte_symbols = [
            ("total system PTEs", "MmTotalSystemPtes"),
            ("free system PTEs", "MmTotalFreeSystemPtes"),
            ("nonpaged pool PTEs", "MmTotalNonPagedPoolPtes"),
            ("available system PTEs", "MmAvailableSystemPtes"),
        ];
        let mut pte_found = false;
        for (label, symbol) in pte_symbols {
            if let Ok(value) = global_value(target, symbol) {
                pte_found = true;
                outln!("  {label:<24}: {value}");
            }
        }
        if !pte_found {
            outln!("  counters               : <unavailable>");
        }
        page_file_summary(target);
        Ok(())
    }

    fn cmd_pfn(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (force_address, value_arg) = if matches!(invocation.arg(0), Some("-a" | "/a")) {
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
        let highest = global_value(&self.ctx.target, "MmHighestPhysicalPage").ok();
        // WinDbg treats the single argument as a page-frame number.  Physical
        // address mode is explicit so a large PFN (for example 0x100874) is
        // never accidentally shifted into a different database entry.
        let pfn = if force_address { value >> 12 } else { value };
        if let Some(highest) = highest
            && pfn > highest
        {
            outln!("PFN {pfn:#x} exceeds MmHighestPhysicalPage {highest:#x}");
            return Ok(());
        }
        let database = match global_value(&self.ctx.target, "MmPfnDatabase") {
            Ok(value) if value != 0 => VirtAddr(value),
            Ok(_) => {
                outln!("PFN database: <unavailable: null MmPfnDatabase>");
                return Ok(());
            }
            Err(error) => {
                outln!("PFN database: {}", unavailable(error));
                return Ok(());
            }
        };
        let ti = match self
            .ctx
            .target
            .symbols
            .find_type_across_modules(self.ctx.target.kernel_dtb(), "_MMPFN")
        {
            Some(ti) => ti,
            None => {
                outln!("_MMPFN type: <unavailable>");
                return Ok(());
            }
        };
        let record_size = ti.size as u64;
        if record_size == 0 || ti.size > PAGE_SIZE {
            outln!("_MMPFN size {record_size:#x} is invalid");
            return Ok(());
        }
        let Some(offset) = pfn.checked_mul(record_size) else {
            outln!("PFN record address overflow");
            return Ok(());
        };
        let record = match database.0.checked_add(offset) {
            Some(record) => VirtAddr(record),
            None => {
                outln!("PFN record address overflows the PFN database");
                return Ok(());
            }
        };
        let memory = self.ctx.target.kernel_address_space();
        let Some(buf) = read_type_buffer(&memory, &ti, record) else {
            outln!("PFN {pfn:#x} record {}: <unavailable>", ui::addr(record.0));
            return Ok(());
        };
        let target = &self.ctx.target;
        let pte = pool_field_from_buf(&ti, &buf, "PteAddress")
            .or_else(|| pool_field_from_buf(&ti, &buf, "PteLong"))
            .or_else(|| {
                Some(member_raw(
                    &ti,
                    &buf,
                    "PteAddress",
                    MMPFN_PTE_ADDRESS_OFFSET,
                ))
            });
        let original_pte = pool_field_from_buf(&ti, &buf, "OriginalPte").or_else(|| {
            Some(member_raw(
                &ti,
                &buf,
                "OriginalPte",
                MMPFN_ORIGINAL_PTE_OFFSET,
            ))
        });
        let u1_raw = member_raw(&ti, &buf, "u1", MMPFN_U1_OFFSET);
        let u2_raw = member_raw(&ti, &buf, "u2", MMPFN_U2_OFFSET);
        let u3_raw = member_raw(&ti, &buf, "u3", MMPFN_U3_OFFSET);
        let u4_raw = member_raw(&ti, &buf, "u4", MMPFN_U4_OFFSET);
        let e1_raw = (u3_raw >> 16) as u8;
        let e3_raw = (u3_raw >> 24) as u8;

        // The first two bytes of u3 are stable across x64 builds, while the
        // remaining bytes are a set of overlapping _MMPFNENTRY1/_3 (or newer
        // _MI_PFN_FLAGS) views; use fixed offsets when those layouts are absent.
        let reference_count = scalar_from_pfn_member(target, &ti, &buf, "u3", "ReferenceCount")
            .or_else(|| pool_field_from_buf(&ti, &buf, "ReferenceCount"))
            .unwrap_or(u3_raw & 0xffff);
        let page_location = pool_field_from_buf(&ti, &buf, "PageLocation")
            .or_else(|| {
                scalar_from_named_type(
                    target,
                    "_MMPFNENTRY1",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY1_FLAGS_OFFSET,
                    "PageLocation",
                )
            })
            .unwrap_or(u64::from(e1_raw & 0x7));
        let modified = pool_field_from_buf(&ti, &buf, "Modified")
            .or_else(|| {
                scalar_from_named_type(
                    target,
                    "_MMPFNENTRY1",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY1_FLAGS_OFFSET,
                    "Modified",
                )
            })
            .map(|value| value != 0)
            .unwrap_or(e1_raw & 0x10 != 0);
        let cache_attribute = pool_field_from_buf(&ti, &buf, "CacheAttribute")
            .or_else(|| {
                scalar_from_named_type(
                    target,
                    "_MMPFNENTRY1",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY1_FLAGS_OFFSET,
                    "CacheAttribute",
                )
            })
            .unwrap_or(u64::from((e1_raw >> 6) & 0x3));
        let priority = pool_field_from_buf(&ti, &buf, "Priority")
            .or_else(|| {
                scalar_from_named_type(
                    target,
                    "_MMPFNENTRY3",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY3_FLAGS_OFFSET,
                    "Priority",
                )
            })
            .unwrap_or(u64::from(e3_raw & 0x7));

        let active_page = page_location == 6;
        let transition_page = page_location == 7;
        let list_page = !active_page && !transition_page;
        let share_count = if active_page || transition_page {
            scalar_from_pfn_member(target, &ti, &buf, "u2", "ShareCount")
                .or_else(|| pool_field_from_buf(&ti, &buf, "ShareCount"))
                .or(Some(u2_raw & ((1u64 << 62) - 1)))
        } else {
            None
        };
        let blink = if list_page {
            scalar_from_pfn_member(target, &ti, &buf, "u2", "Blink")
                .or(Some(u2_raw & ((1u64 << 40) - 1)))
        } else {
            None
        };
        let node_blink_low = if list_page {
            scalar_from_pfn_member(target, &ti, &buf, "u2", "NodeBlinkLow")
                .or(Some((u2_raw >> 40) & ((1u64 << 19) - 1)))
        } else {
            None
        };
        let flink = if list_page {
            scalar_from_pfn_member(target, &ti, &buf, "u1", "Flink")
                .or(Some(u1_raw & ((1u64 << 40) - 1)))
        } else {
            None
        };
        let node_flink_low = if list_page {
            scalar_from_pfn_member(target, &ti, &buf, "u1", "NodeFlinkLow")
        } else {
            None
        };
        let ws_index = if active_page {
            scalar_from_pfn_member(target, &ti, &buf, "u1", "WsIndex")
        } else {
            None
        };
        let event = if transition_page {
            scalar_from_pfn_member(target, &ti, &buf, "u1", "Event")
        } else {
            None
        };
        let pte_frame = scalar_from_pfn_member(target, &ti, &buf, "u4", "PteFrame")
            .or(Some(u4_raw & ((1u64 << 40) - 1)));
        let page_color =
            scalar_from_pfn_member(target, &ti, &buf, "u4", "PageColor").or_else(|| {
                scalar_from_named_type(
                    target,
                    "_MMPFNENTRY1",
                    &u3_raw.to_le_bytes(),
                    MMPFNENTRY1_FLAGS_OFFSET,
                    "PageColor",
                )
            });
        let used_entry_count = original_pte
            .and_then(|value| {
                scalar_from_named_type(
                    target,
                    "_MMPTE_SOFTWARE",
                    &value.to_le_bytes(),
                    MMPTE_SOFTWARE_OFFSET,
                    "UsedPageTableEntries",
                )
            })
            .or_else(|| {
                scalar_from_pfn_member(target, &ti, &buf, "OriginalPte", "UsedPageTableEntries")
            })
            .or_else(|| original_pte.map(|value| (value >> 12) & 0x3ff));

        outln!("PFN {pfn:08x} at address {}", ui::addr(record.0));
        if force_address {
            outln!("  {:<20}: {}", "physical address", ui::addr(value));
        }
        match pte {
            Some(value) => outln!(
                "  {:<20}: {} (raw {value:#x})",
                "PteAddress",
                ui::addr(value)
            ),
            None => outln!("  {:<20}: <unavailable>", "PteAddress"),
        }
        match original_pte {
            Some(value) => outln!("  {:<20}: {value:#x}", "OriginalPte"),
            None => outln!("  {:<20}: <unavailable>", "OriginalPte"),
        }
        outln!("  {:<20}: {reference_count}", "ReferenceCount");
        if list_page {
            match flink {
                Some(value) => outln!("  {:<20}: {value:#x}", "Flink"),
                None => outln!("  {:<20}: <unavailable>", "Flink"),
            }
            match blink {
                Some(value) => outln!("  {:<20}: {value:#x}", "Blink"),
                None => outln!("  {:<20}: <unavailable>", "Blink"),
            }
            if let Some(value) = node_flink_low {
                outln!("  {:<20}: {value:#x}", "NodeFlinkLow");
            }
            if let Some(value) = node_blink_low {
                outln!("  {:<20}: {value:#x}", "NodeBlinkLow");
            }
        } else if let Some(value) = share_count {
            outln!("  {:<20}: {value}", "ShareCount");
            if let Some(value) = ws_index {
                outln!("  {:<20}: {value:#x}", "WsIndex");
            }
            if let Some(value) = event {
                outln!("  {:<20}: {}", "Event", ui::addr(value));
            }
        } else {
            outln!("  {:<20}: <unavailable>", "ShareCount");
        }
        match used_entry_count {
            Some(value) => outln!("  {:<20}: {value}", "UsedPageTableEntries"),
            None => outln!("  {:<20}: <unavailable>", "UsedPageTableEntries"),
        }
        match page_color {
            Some(value) => outln!("  {:<20}: {value}", "PageColor"),
            None => outln!("  {:<20}: <unavailable>", "PageColor"),
        }
        match pte_frame {
            Some(value) => outln!("  {:<20}: {value:#x} (containing page)", "PteFrame"),
            None => outln!("  {:<20}: <unavailable>", "PteFrame"),
        }
        print_pfn_flags(
            page_location as u8,
            modified,
            cache_attribute as u8,
            priority as u8,
        );
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
        let Some(dtb_value) = eval_arg(self, dtb_arg) else {
            return Ok(());
        };
        let Some(va_value) = eval_arg(self, va_arg) else {
            return Ok(());
        };
        let dtb = if dtb_value == 0 {
            self.ctx.target.current_dtb()
        } else {
            dtb_value & PFN_MASK
        };
        let va = VirtAddr(va_value);
        if self.ctx.target.arch() != Arch::Amd64 {
            match self.ctx.target.address_space(dtb).virt_to_phys(va) {
                Ok(Some(translation)) => {
                    outln!("VA {} DTB {}", ui::addr(va.0), ui::addr(dtb));
                    outln!("  physical             : {}", ui::addr(translation.address));
                    outln!("  large page           : {}", translation.large);
                }
                Ok(None) => outln!(
                    "VA {} is not mapped by DTB {}",
                    ui::addr(va.0),
                    ui::addr(dtb)
                ),
                Err(error) => error!("{error}"),
            }
            return Ok(());
        }
        match explicit_amd64_walk(&self.ctx.target, dtb, va) {
            Ok(walk) => {
                outln!("VA {} DTB {}", ui::addr(va.0), ui::addr(dtb));
                for (name, address, value) in walk.levels {
                    print_pte_entry(&name, address, value);
                }
                match walk.physical {
                    Some(physical) => outln!("  physical             : {}", ui::addr(physical)),
                    None => outln!("  physical             : <not mapped>"),
                }
                if walk.large {
                    outln!("  mapping              : large page");
                }
            }
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
        let dtb = self.ctx.target.current_dtb();
        if dtb == DTB_IDENTITY {
            outln!(
                "identity dump mapping: {} -> {}",
                ui::addr(pa),
                ui::addr(pa)
            );
            return Ok(());
        }
        if self.ctx.target.arch() != Arch::Amd64 {
            error!("!ptov reverse walking is currently available for AMD64 targets only");
            return Ok(());
        }
        let mut visited = HashSet::new();
        let mut table_pages = 0usize;
        let mut mappings = Vec::new();
        scan_ptov_table(
            &self.ctx.target,
            dtb,
            0,
            [0; 4],
            pa & !(PAGE_SIZE as u64 - 1),
            &mut visited,
            &mut table_pages,
            &mut mappings,
        );
        outln!("PA {} DTB {}", ui::addr(pa), ui::addr(dtb));
        if mappings.is_empty() {
            outln!("  no current mappings (walked {table_pages} table pages)");
        } else {
            for (va, large) in mappings {
                outln!(
                    "  {} -> {}{}",
                    ui::addr(pa),
                    ui::addr(va.0.wrapping_add(pa & (PAGE_SIZE as u64 - 1))),
                    if large { " (large)" } else { "" }
                );
            }
        }
        if table_pages >= MAX_PTOV_TABLE_PAGES {
            outln!("  walk bounded at {} table pages", MAX_PTOV_TABLE_PAGES);
        }
        if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
            outln!("  walk interrupted");
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
        let summary = collect_pool_usage(&self.ctx.target);
        outln!(
            "pool usage by tag (tracker: {}; big pages: {})",
            summary.tracker_status,
            summary.big.status
        );
        if summary.rows_truncated {
            outln!("pool usage rows bounded; some tags were omitted");
        }
        let mut rows = summary
            .rows
            .into_iter()
            .filter(|row| {
                tag_filter
                    .map(|filter| crate::symbols::glob_matches(filter, &tag_string(row.tag), false))
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();
        match flags & 0x6 {
            0x2 => rows.sort_by(|a, b| {
                b.nonpaged_bytes
                    .cmp(&a.nonpaged_bytes)
                    .then_with(|| a.tag.cmp(&b.tag))
            }),
            0x4 => rows.sort_by(|a, b| {
                b.paged_bytes
                    .cmp(&a.paged_bytes)
                    .then_with(|| a.tag.cmp(&b.tag))
            }),
            _ => rows.sort_by_key(|row| row.tag),
        }
        let mut builder = Builder::default();
        if flags & 1 != 0 {
            builder.push_record([
                "Tag",
                "NP Allocs",
                "NP Frees",
                "NP Bytes",
                "Paged Allocs",
                "Paged Frees",
                "Paged Bytes",
            ]);
            for row in rows.into_iter().take(MAX_POOLUSED_ROWS) {
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
            for row in rows.into_iter().take(MAX_POOLUSED_ROWS) {
                let tag = tag_string(row.tag);
                builder.push_record([
                    format!("{tag} ({:#x})", row.tag),
                    usage_cell(row.nonpaged_bytes),
                    usage_cell(row.paged_bytes),
                ]);
            }
        }
        print_padded_table(builder);
        Ok(())
    }

    fn cmd_poolfind(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(tag) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let pool_type = match invocation.arg(1).map(|value| eval_value(self, value)) {
            Some(Ok(value @ 0..=1)) => Some(value),
            Some(Ok(_)) | Some(Err(_)) => {
                outln!("pool type must be 0 (nonpaged) or 1 (paged)");
                return Ok(());
            }
            None => None,
        };
        let layout = match pool_layout(&self.ctx.target) {
            Ok(layout) => Some(layout),
            Err(error) => {
                outln!("pool header layout: {}", unavailable(error));
                None
            }
        };
        let mut found = 0usize;
        if let Some(layout) = &layout {
            let ranges = resolve_pool_ranges(&self.ctx.target);
            if ranges.is_empty() {
                outln!("pool virtual ranges: <unavailable>");
            }
            for range in ranges {
                if pool_type.is_some_and(|kind| range.kind != kind) {
                    continue;
                }
                let Some(start) = range
                    .start
                    .checked_add(PAGE_SIZE as u64 - 1)
                    .map(|value| value & !(PAGE_SIZE as u64 - 1))
                else {
                    outln!("  {} range start overflows", range.name);
                    continue;
                };
                let end = range.end & !(PAGE_SIZE as u64 - 1);
                let pages = end.saturating_sub(start) / PAGE_SIZE as u64;
                let scan_pages = pages.min(MAX_POOLFIND_PAGES);
                for page in 0..scan_pages {
                    if INTERRUPT_REQUESTED.load(Ordering::Relaxed) || found >= MAX_POOLFIND_RESULTS
                    {
                        break;
                    }
                    let Some(base) = page
                        .checked_mul(PAGE_SIZE as u64)
                        .and_then(|offset| start.checked_add(offset))
                        .map(VirtAddr)
                    else {
                        outln!("  {} range address overflows", range.name);
                        break;
                    };
                    for block in scan_pool_page_lax(&self.ctx.target, layout, base) {
                        if block.synthetic_free
                            || !crate::symbols::glob_matches(tag, &tag_string(block.tag), false)
                        {
                            continue;
                        }
                        found += 1;
                        outln!(
                            "  {} {} tag '{}' size 0x{:x} ({})",
                            range.name,
                            ui::addr(block.body.0),
                            tag_string(block.tag),
                            block.size,
                            pool_block_state(&block)
                        );
                        if found >= MAX_POOLFIND_RESULTS {
                            break;
                        }
                    }
                    if page != 0 && page % 1024 == 0 {
                        outln!("  {} scanned {} / {} pages", range.name, page, pages);
                    }
                }
                if scan_pages < pages {
                    outln!("  {} scan bounded at {} pages", range.name, scan_pages);
                }
            }
        }
        let mut scan_big = |big_pool_type: Option<&TypeInfo>,
                            uses_struct: bool,
                            has_pool_type: bool,
                            has_slush: bool| {
            scan_big_pool_entries(
                &self.ctx.target,
                big_pool_type,
                uses_struct,
                has_pool_type,
                has_slush,
                |entry| {
                    if found < MAX_POOLFIND_RESULTS
                        && pool_type.is_none_or(|kind| entry.nonpaged == (kind == 0))
                        && crate::symbols::glob_matches(tag, &tag_string(entry.tag), false)
                    {
                        found += 1;
                        outln!(
                            "  BigPool {} tag '{}' size 0x{:x}",
                            ui::addr(entry.va.0),
                            tag_string(entry.tag),
                            entry.size
                        );
                    }
                    found >= MAX_POOLFIND_RESULTS
                },
            )
        };
        let big = if let Some(layout) = layout.as_ref() {
            Some(scan_big(
                layout.big_pool_type.as_deref(),
                layout.big_pool_uses_struct,
                layout.big_pool_has_pool_type,
                layout.big_pool_has_slush,
            ))
        } else {
            match big_pool_layout(&self.ctx.target) {
                Ok((big_pool_type, uses_struct, has_pool_type, has_slush)) => Some(scan_big(
                    Some(&big_pool_type),
                    uses_struct,
                    has_pool_type,
                    has_slush,
                )),
                Err(error) => {
                    outln!("big-page layout: {}", unavailable(error));
                    None
                }
            }
        };
        if let Some(big) = big {
            outln!("  big-page table: {}", big.status);
        }
        if found == 0 {
            outln!("no pool blocks matched '{}'", tag);
        } else {
            outln!("{} matching pool block(s)", found);
        }
        if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
            outln!("pool scan interrupted");
        }
        Ok(())
    }

    fn cmd_lookaside(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let ti = match self
            .ctx
            .target
            .symbols
            .find_type_across_modules(self.ctx.target.kernel_dtb(), "_GENERAL_LOOKASIDE")
        {
            Some(ti) => ti,
            None => {
                outln!("_GENERAL_LOOKASIDE type: <unavailable>");
                return Ok(());
            }
        };
        if let Some(argument) = invocation.arg(0) {
            let Some(address) = eval_arg(self, argument) else {
                return Ok(());
            };
            print_lookaside_record(&self.ctx.target, &ti, VirtAddr(address), 0);
            return Ok(());
        }
        let mut records = Vec::new();
        let mut seen = HashSet::new();
        lookaside_roots(
            &self.ctx.target,
            "ExNPagedLookasideListHead",
            &ti,
            &mut seen,
            &mut records,
        );
        let nonpaged_count = records.len();
        lookaside_roots(
            &self.ctx.target,
            "ExPagedLookasideListHead",
            &ti,
            &mut seen,
            &mut records,
        );
        if records.is_empty() {
            outln!("lookaside lists: <unavailable>");
            return Ok(());
        }
        outln!(
            "lookaside lists ({} nonpaged, {} paged/other):",
            nonpaged_count,
            records.len().saturating_sub(nonpaged_count)
        );
        for (index, address) in records.into_iter().enumerate() {
            print_lookaside_record(&self.ctx.target, &ti, address, index);
        }
        if INTERRUPT_REQUESTED.load(Ordering::Relaxed) {
            outln!("lookaside walk interrupted");
        }
        Ok(())
    }
}
