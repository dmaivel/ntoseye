//! Address-space layout: the VAD tree and the flat region map of the
//! selected process (or the kernel module map when detached), and what an
//! arbitrary address belongs to.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use ntoseye_macros::command;

use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::{ModuleInfo, ProcessInfo};
use crate::memory::PAGE_SIZE;
use crate::target::mm::{
    AddressDescription, MEM_FREE, MemoryBasicInformation, MemoryRegionInfo, VadProtection, VadType,
    memory_state_name, memory_type_name, page_protection_name,
};
use crate::target::usermode::address::{
    AddressReport, AddressSummary, CapturedRange, SummaryRow, UserAddressReport, UserRegion,
    human_size, state_label, type_label,
};
use crate::target::{MemoryKind, TargetKind};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::args::{ArgCursor, ArgCx, ArgError, virtual_memory};
use crate::repl::*;
use crate::session::Session;

pub const PAGE_SHIFT: u32 = PAGE_SIZE.trailing_zeros();
const BYTES_PER_KIB: u64 = 1024;
const BYTES_PER_MIB: u64 = BYTES_PER_KIB * 1024;

/// What `!vad` or `vmmap` maps.
enum MapScope {
    /// `!vad`: the VAD tree of this process.
    Vad(ProcessInfo),
    /// `vmmap`: the attached process's regions, else the kernel modules.
    Attached,
}

/// `!vad`'s process: a PID or EPROCESS, or the current one. `vmmap` takes
/// a filter instead.
fn map_scope(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<MapScope, ArgError> {
    if cx.name != "!vad" {
        return Ok(MapScope::Attached);
    }
    let state = &*cx.state;
    let processes =
        state.ctx.target.matching_processes(None).map_err(|error| {
            ArgError::Message(format!("failed to enumerate processes: {error}"))
        })?;
    let process = match cursor.word() {
        Some(selector) => state
            .process_for_selector(&selector, &processes)
            .ok_or_else(|| {
                ArgError::Message(format!(
                    "no process matches '{selector}' (expected a PID or EPROCESS)"
                ))
            })?,
        None => state.ctx.target.current_process().ok_or_else(|| {
            ArgError::Message("!vad requires a current process or an EPROCESS selector".to_string())
        })?,
    };
    Ok(MapScope::Vad(process))
}

/// `vmmap`'s filter: an address the regions hold, or text in their bounds,
/// file, type, or protection.
fn map_filter(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<String>, ArgError> {
    if cx.name == "!vad" {
        return Ok(None);
    }
    Ok(cursor.word().map(String::from))
}

/// What `!vad` and `vmmap` show.
pub enum AddressMap {
    /// A process's VAD regions; `vad` for `!vad`'s tree columns, else
    /// `vmmap`'s flat ones.
    Regions {
        process: ProcessInfo,
        regions: Vec<MemoryRegionInfo>,
        vad: bool,
    },
    /// `vmmap` with no process attached: the kernel modules.
    KernelModules(Vec<ModuleInfo>),
}

/// Show the VAD tree of a process.
///
/// Select a process by PID or EPROCESS expression. With no argument, the
/// command uses the current process context, which you can select with
/// `.process /p <pid>`. `vmmap [address|filter]` keeps the flat region view
/// of the attached process, and shows the kernel modules when no process is
/// attached. The VAD walk has a limit, and it skips the entries that it
/// cannot read and continues the listing.
#[command(
    names = ["!vad", "vmmap"],
    category = "processes and modules",
    kind = Query,
    target = Kernel,
    python = none,
    usage = "!vad [pid|eprocess]",
    completion = [Process, None]
)]
fn vad(
    session: &Session,
    #[arg(parse = map_scope)] scope: MapScope,
    #[arg(render, parse = map_filter)] filter: Option<String>,
) -> Result<AddressMap> {
    let target = &session.target;
    let (process, vad) = match scope {
        MapScope::Vad(process) => (Some(process), true),
        MapScope::Attached => (target.attached_process().cloned(), false),
    };
    match process {
        Some(process) => {
            let regions = target
                .enumerate_vad_regions_for_process_info(&process)
                .map_err(|error| Error::DebugInfo(format!("failed to enumerate VADs: {error}")))?;
            Ok(AddressMap::Regions {
                process,
                regions,
                vad,
            })
        }
        None => target
            .kernel_modules_with_versions()
            .map(AddressMap::KernelModules)
            .map_err(|error| {
                Error::DebugInfo(format!("failed to enumerate kernel modules: {error}"))
            }),
    }
}

/// `vmmap`'s filter selects regions and modules; `!vad` shows them all.
impl Render<Option<String>> for AddressMap {
    fn render(&self, repl: &mut ReplState<'_>, filter: Option<String>) {
        let filter = filter.as_deref();
        let filter_address = filter
            .and_then(|filter| Expr::eval_with_radix(filter, &repl.ctx.target, repl.radix).ok());
        match self {
            Self::Regions {
                process,
                regions,
                vad,
            } => print_regions(process, regions, *vad, filter, filter_address),
            Self::KernelModules(modules) => print_kernel_regions(modules, filter, filter_address),
        }
    }
}

fn print_regions(
    process: &ProcessInfo,
    regions: &[MemoryRegionInfo],
    is_vad: bool,
    filter: Option<&str>,
    filter_address: Option<VirtAddr>,
) {
    let shown: Vec<&MemoryRegionInfo> = regions
        .iter()
        .filter(|region| is_vad || region_matches_filter(region, filter, filter_address))
        .collect();
    if shown.is_empty() {
        outln!("{}\n", "no matching memory regions".bright_black());
        return;
    }
    let print_text = || {
        outln!(
            "{} {} ({})",
            ui::label("process"),
            process.name,
            ui::Value(process.pid)
        );
        print_padded_table(region_table(&shown, is_vad));
    };
    #[cfg(feature = "cli")]
    native::render(
        || native::lists::regions(process, &shown, is_vad),
        print_text,
    );
    #[cfg(not(feature = "cli"))]
    print_text();
}

fn print_kernel_regions(
    modules: &[ModuleInfo],
    filter: Option<&str>,
    filter_address: Option<VirtAddr>,
) {
    let shown: Vec<ModuleInfo> = modules
        .iter()
        .filter(|module| {
            filter.is_none_or(|filter| {
                module
                    .short_name
                    .to_ascii_lowercase()
                    .contains(&filter.to_ascii_lowercase())
                    || module
                        .name
                        .to_ascii_lowercase()
                        .contains(&filter.to_ascii_lowercase())
                    || filter_address.is_some_and(|address| module.contains_address(address))
            })
        })
        .cloned()
        .collect();

    if shown.is_empty() {
        outln!("no matching kernel regions\n");
        return;
    }
    let print_text = || {
        let mut builder = Builder::default();
        builder.push_record(vec![
            "Start".to_string(),
            "End".to_string(),
            "Size".to_string(),
            "Module".to_string(),
            "Image".to_string(),
        ]);
        for module in &shown {
            builder.push_record(vec![
                ui::addr(module.base_address.0).to_string(),
                ui::addr(module.end_address().0).to_string(),
                format_region_size(module.size as u64).to_string(),
                module.short_name.to_string(),
                module.name.clone(),
            ]);
        }
        print_padded_table(builder);
    };
    #[cfg(feature = "cli")]
    native::render(|| native::lists::kernel_regions(&shown), print_text);
    #[cfg(not(feature = "cli"))]
    print_text();
}

/// `!address -summary` on a user-mode minidump: only the summary. The
/// minidump's address list takes at most one word.
fn summary_switch(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<bool, ArgError> {
    if cx.state.ctx.target.kind() != TargetKind::UserDump {
        return Ok(false);
    }
    if cursor.remaining() > 1 {
        return Err(ArgError::Missing);
    }
    Ok(cursor.switch("-summary"))
}

/// `!address`'s address: required on a kernel target; a user-mode
/// minidump without one lists its regions.
fn address_arg(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<VirtAddr>, ArgError> {
    match cursor.word() {
        Some(text) => cx.eval(&text).map(Some),
        None if cx.state.ctx.target.kind() == TargetKind::UserDump => Ok(None),
        None => Err(ArgError::Missing),
    }
}

/// Show the module and section, or the VAD region, that an address belongs
/// to.
///
/// On a user-mode minidump the command uses the regions that the dump's
/// memory-info list records. Without an argument, it lists them with their
/// state, protection, type, allocation base, usage, and how much of each the
/// dump captured, followed by a summary by usage, type, state, and
/// protection; -summary shows only the summary. With an address, it shows
/// the region that holds it. Usage comes from the dump's modules, its
/// threads' stacks and TEBs, the PEB, and the heaps in the PEB's
/// ProcessHeaps array; it is <unknown> for any other region. A dump without
/// a memory-info list shows the memory ranges it captured instead.
#[command(
    names = ["!address", "address"],
    category = "memory and disassembly",
    kind = Query,
    target = Nt,
    python = Memory,
    python_name = "describe",
    usage = "!address [-summary | address-expression]",
    completion = Expression
)]
fn address(
    session: &Session,
    #[arg(receiver, parse = virtual_memory)] memory: MemoryKind,
    #[arg(render, parse = summary_switch)] summary: bool,
    #[arg(parse = address_arg)] addr: Option<VirtAddr>,
) -> Result<AddressReport> {
    memory.require_virtual()?;
    let target = &session.target;
    if target.kind() == TargetKind::UserDump {
        return target
            .user_address_report(addr)
            .map(AddressReport::UserDump);
    }
    let addr = addr.ok_or_else(|| {
        Error::InvalidArgument("an address is required on a kernel target".to_string())
    })?;
    target.describe_address(addr).map(AddressReport::Nt)
}

/// `summary`: `-summary`, the minidump's summary without its region list.
impl Render<bool> for AddressReport {
    fn render(&self, _: &mut ReplState<'_>, summary: bool) {
        match self {
            Self::Nt(description) => print_address_description(description),
            Self::UserDump(report) => print_user_address_report(report, summary),
        }
    }
}

/// Show the VirtualQuery data for a user address.
///
/// The command shows the region, state, protection, and type of a user
/// address, as VirtualQuery reports them. It looks up the address in the
/// current process context, which you can select with `.process /p <pid>`.
/// The VAD that holds the address gives AllocationBase, AllocationProtect,
/// and Type, and the state and protection of each page come from its PTE.
/// For a page without a PTE, they come from the VAD (private memory) or
/// from its prototype PTE (a section view). RegionSize runs from the page of
/// the address to the first page that differs. An address that is not in a
/// VAD is MEM_FREE up to the next VAD. The scan stops after 262,144
/// page-table steps. On a user-mode minidump the command reads the region
/// from the dump's memory-info list, which records what VirtualQuery
/// returned when the dump was written; RegionSize runs from the page of the
/// address to the end of that region.
#[command(
    names = ["!vprot", "vprot"],
    category = "memory manager",
    kind = Query,
    python = Process,
    python_name = "protection",
    completion = Expression
)]
fn vprot(session: &Session, address: VirtAddr) -> Result<MemoryBasicInformation> {
    let target = &session.target;
    if target.user_dump_info().is_some() {
        return target.user_virtual_query(address);
    }
    let process = target.current_process().ok_or_else(|| {
        Error::DebugInfo("!vprot needs a process context (.process /p <pid>)".to_string())
    })?;
    target.virtual_query(&process, address)
}

impl Render for MemoryBasicInformation {
    fn render(&self, _: &mut ReplState<'_>, _: ()) {
        print_vprot(self);
    }
}

pub fn format_region_size(size: u64) -> String {
    if size >= BYTES_PER_MIB {
        format!("{:#x} ({} MiB)", size, size / BYTES_PER_MIB)
    } else if size >= BYTES_PER_KIB {
        format!("{:#x} ({} KiB)", size, size / BYTES_PER_KIB)
    } else {
        format!("{:#x}", size)
    }
}

pub fn vad_protection_label(protection: Option<VadProtection>) -> String {
    let label = match protection {
        Some(VadProtection::NoAccess) => "none",
        Some(VadProtection::ReadOnly) => "r",
        Some(VadProtection::Execute) => "x",
        Some(VadProtection::ExecuteRead) => "x/r",
        Some(VadProtection::ReadWrite) => "rw",
        Some(VadProtection::WriteCopy) => "cow",
        Some(VadProtection::ExecuteReadWrite) => "x/rw",
        Some(VadProtection::ExecuteWriteCopy) => "x/cow",
        Some(VadProtection::Unknown(value)) => return format!("prot:{value}"),
        None => "-",
    };
    label.to_string()
}

pub fn vad_type_label(region: &MemoryRegionInfo) -> String {
    match region.vad_type {
        Some(VadType::ImageMap) => "image".to_string(),
        Some(_) if region.private_memory == Some(true) => "private".to_string(),
        Some(VadType::None) if region.private_memory == Some(false) => "mapped".to_string(),
        Some(vad_type) => format!("vad:{}", vad_type.raw()),
        None => "vad".to_string(),
    }
}

fn region_matches_filter(
    region: &MemoryRegionInfo,
    filter: Option<&str>,
    address: Option<VirtAddr>,
) -> bool {
    // A filter that resolved to an address selects by containment only; the
    // textual match below would otherwise also pick regions whose printed
    // bounds merely contain the digits.
    if let Some(address) = address {
        return (region.start..region.end).contains(&address);
    }
    let Some(filter) = filter.map(str::to_ascii_lowercase) else {
        return true;
    };
    format!("{:#x}", region.start.0).contains(&filter)
        || format!("{:#x}", region.end.0).contains(&filter)
        || region
            .details
            .as_deref()
            .is_some_and(|details| details.to_ascii_lowercase().contains(&filter))
        || vad_type_label(region).contains(&filter)
        || vad_protection_label(region.protection).contains(&filter)
}

/// `!vad` and `vmmap`'s text table of `regions`.
fn region_table(regions: &[&MemoryRegionInfo], is_vad: bool) -> Builder {
    let mut builder = Builder::default();
    if is_vad {
        builder.push_record(vec![
            "VAD".to_string(),
            "Level".to_string(),
            "Start VPN".to_string(),
            "End VPN".to_string(),
            "Commit".to_string(),
            "Type/Protection".to_string(),
            "File".to_string(),
        ]);
    } else {
        builder.push_record(vec![
            "Start".to_string(),
            "End".to_string(),
            "Size".to_string(),
            "Protect".to_string(),
            "Type".to_string(),
            "Commit".to_string(),
            "Details".to_string(),
        ]);
    }
    for region in regions {
        let commit = region
            .commit_charge
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string());
        if is_vad {
            builder.push_record(vec![
                ui::addr(region.node_address.0),
                region.level.to_string(),
                format!("{:#x}", region.start.0 >> PAGE_SHIFT),
                format!("{:#x}", region.end.0.saturating_sub(1) >> PAGE_SHIFT),
                commit,
                format!(
                    "{}/{}",
                    vad_type_label(region),
                    vad_protection_label(region.protection)
                ),
                region.details.as_deref().unwrap_or("-").to_string(),
            ]);
        } else {
            builder.push_record(vec![
                ui::addr(region.start.0).to_string(),
                ui::addr(region.end.0).to_string(),
                format_region_size(region.size()).to_string(),
                vad_protection_label(region.protection).to_string(),
                vad_type_label(region).to_string(),
                commit,
                region.details.as_deref().unwrap_or("-").to_string(),
            ]);
        }
    }
    builder
}

fn print_address_description(d: &AddressDescription) {
    outln!("address {}", ui::addr(d.address.0));
    outln!("  kind    : {}", d.kind);
    if let Some(m) = &d.module {
        outln!(
            "  module  : {}+{:#x}  (base {}, size {:#x})",
            m.name,
            m.offset,
            ui::addr(m.base.0),
            m.size
        );
    }
    if let Some(s) = &d.section {
        outln!("  section : {}", s);
    }
    if let Some(va) = &d.va_type {
        outln!("  region  : {}", va);
    }
    if let Some(r) = &d.region {
        outln!(
            "  region  : {} - {}",
            ui::addr(r.start.0),
            ui::addr(r.end.0)
        );
        if let Some(p) = r.protection {
            outln!("    protection : {:#x}", p.raw());
        }
        if let Some(t) = r.vad_type {
            outln!("    vad type   : {:#x}", t.raw());
        }
        if let Some(pm) = r.private_memory {
            outln!("    private    : {}", pm);
        }
        if let Some(det) = &r.details {
            outln!("    details    : {}", det);
        }
    }
    if d.module.is_none() && d.region.is_none() && d.va_type.is_none() {
        outln!(
            "  {}",
            "not inside any loaded module, kernel region, or VAD".bright_black()
        );
    }
    outln!();
}

/// `!address` on a user-mode minidump: its memory-info list, or the ranges
/// it captured when it has none.
fn print_user_address_report(report: &UserAddressReport, summary_only: bool) {
    match report {
        UserAddressReport::Region {
            address,
            region,
            address_captured,
        } => match region {
            Some(region) => print_user_region(*address, region, *address_captured),
            None => outln!(
                "address {}: not in any region the minidump's memory-info list records\n",
                ui::addr(address.0)
            ),
        },
        UserAddressReport::Map { regions, summary } => {
            if !summary_only {
                print_padded_table(user_region_table(regions));
                outln!();
            }
            print_address_summary(summary);
        }
        UserAddressReport::CapturedRange { address, range } => {
            print_no_memory_info_list();
            match range {
                Some(range) => outln!(
                    "address {}: in the captured range {} - {} ({}), {}\n",
                    ui::addr(address.0),
                    ui::addr(range.start),
                    ui::addr(range.start.saturating_add(range.length)),
                    human_size(range.length),
                    captured_usage_cell(range)
                ),
                None => outln!(
                    "address {}: not in the memory the minidump captured\n",
                    ui::addr(address.0)
                ),
            }
        }
        UserAddressReport::CapturedRanges { ranges } => {
            print_no_memory_info_list();
            print_captured_ranges(ranges);
        }
    }
}

fn print_user_region(address: VirtAddr, entry: &UserRegion, captured: bool) {
    let region = &entry.region;
    outln!("address {}", ui::addr(address.0));
    outln!("  Usage:             {}", usage_cell(entry));
    outln!("  BaseAddress:       {}", ui::addr(region.base));
    outln!("  EndAddress:        {}", ui::addr(entry.end()));
    outln!(
        "  RegionSize:        {:016x} ({})",
        region.size,
        human_size(region.size)
    );
    outln!(
        "  State:             {:08x}  {}",
        region.state,
        state_label(region.state)
    );
    outln!(
        "  Protect:           {:08x}  {}",
        region.protect,
        page_protection_name(region.protect)
    );
    outln!(
        "  Type:              {:08x}  {}",
        region.kind,
        type_label(region.kind)
    );
    outln!("  AllocationBase:    {}", ui::addr(region.allocation_base));
    outln!(
        "  AllocationProtect: {:08x}  {}",
        region.allocation_protect,
        page_protection_name(region.allocation_protect)
    );
    outln!(
        "  Captured:          {} of the region; this address {}",
        captured_cell(entry),
        if captured {
            "is captured"
        } else {
            "is not captured"
        }
    );
    outln!();
}

fn print_no_memory_info_list() {
    outln!(
        "{}",
        ui::muted(
            "the minidump records no memory-info list (MemoryInfoListStream): region state, protection, and type are not known"
        )
    );
}

/// The ranges a dump without a memory-info list captured.
fn print_captured_ranges(ranges: &[CapturedRange]) {
    let total: u64 = ranges.iter().map(|range| range.length).sum();
    outln!(
        "captured memory: {} ranges, {}",
        ranges.len(),
        human_size(total)
    );
    let mut builder = Builder::default();
    builder.push_record(["Start", "End", "Size", "Usage"]);
    for range in ranges {
        builder.push_record([
            ui::addr(range.start).to_string(),
            ui::addr(range.start.saturating_add(range.length)).to_string(),
            format!("{:#x}", range.length),
            captured_usage_cell(range),
        ]);
    }
    print_padded_table(builder);
}

fn usage_cell(entry: &UserRegion) -> String {
    match &entry.detail {
        Some(detail) => format!("{} [{detail}]", entry.usage.as_str()),
        None => entry.usage.as_str().to_string(),
    }
}

fn captured_usage_cell(range: &CapturedRange) -> String {
    match &range.detail {
        Some(detail) => format!("{} [{detail}]", range.usage.as_str()),
        None => range.usage.as_str().to_string(),
    }
}

/// How much of a region the dump holds: `all`, `none`, or the bytes.
fn captured_cell(entry: &UserRegion) -> String {
    match entry.captured {
        0 => "none".to_string(),
        bytes if bytes == entry.region.size => "all".to_string(),
        bytes => format!("{bytes:#x} bytes"),
    }
}

/// `!address`'s region list on a user-mode minidump.
fn user_region_table(regions: &[UserRegion]) -> Builder {
    let mut builder = Builder::default();
    builder.push_record([
        "Base",
        "End",
        "Size",
        "Type",
        "State",
        "Protect",
        "AllocBase",
        "Usage",
        "Captured",
    ]);
    for entry in regions {
        let region = &entry.region;
        let free = region.state == MEM_FREE;
        builder.push_record([
            ui::addr(region.base).to_string(),
            ui::addr(entry.end()).to_string(),
            format!("{:#x}", region.size),
            type_label(region.kind),
            state_label(region.state),
            page_protection_name(region.protect),
            if free {
                String::new()
            } else {
                ui::addr(region.allocation_base).to_string()
            },
            usage_cell(entry),
            if free {
                String::new()
            } else {
                captured_cell(entry)
            },
        ]);
    }
    builder
}

/// One section of `!address`'s summary, each row's share of the regions in
/// use (`busy`; none for free regions) and of all of them (`total`).
fn print_summary_section(title: &str, rows: &[SummaryRow], total: u64, busy: u64) {
    let percent = |size: u64, of: u64| {
        if of == 0 {
            "-".to_string()
        } else {
            format!("{:.2}%", size as f64 * 100.0 / of as f64)
        }
    };
    let mut builder = Builder::default();
    builder.push_record([title, "Regions", "Size", "", "% busy", "% total"]);
    for row in rows {
        let free = row.label == "Free" || row.label == "MEM_FREE";
        builder.push_record([
            row.label.clone(),
            row.regions.to_string(),
            format!("{:#x}", row.size),
            human_size(row.size),
            if free {
                String::new()
            } else {
                percent(row.size, busy)
            },
            percent(row.size, total),
        ]);
    }
    print_padded_table(builder);
}

fn print_address_summary(summary: &AddressSummary) {
    let busy = summary.busy;
    print_summary_section("Usage", &summary.by_usage, summary.total, busy);
    print_summary_section("Type (in use)", &summary.by_type, summary.total, busy);
    print_summary_section("State", &summary.by_state, summary.total, busy);
    print_summary_section(
        "Protect (committed)",
        &summary.by_protect,
        summary.total,
        busy,
    );
    outln!(
        "total {:#x} ({}), in use {:#x} ({})\n",
        summary.total,
        human_size(summary.total),
        summary.busy,
        human_size(summary.busy)
    );
}

fn print_vprot(detail: &MemoryBasicInformation) {
    if let Some(process) = &detail.process {
        outln!(
            "{} {} ({})",
            ui::label("process"),
            process.name,
            ui::Value(process.pid)
        );
    }
    outln!("BaseAddress:       {}", ui::addr(detail.base_address.0));
    outln!("AllocationBase:    {}", ui::addr(detail.allocation_base.0));
    outln!(
        "AllocationProtect: {:08x}  {}",
        detail.allocation_protect,
        page_protection_name(detail.allocation_protect)
    );
    outln!(
        "RegionSize:        {:016x}{}",
        detail.region_size,
        if detail.truncated {
            "  (scan bound reached; at least this much)"
        } else {
            ""
        }
    );
    outln!(
        "State:             {:08x}  {}",
        detail.state,
        memory_state_name(detail.state)
    );
    outln!(
        "Protect:           {:08x}  {}",
        detail.protect,
        page_protection_name(detail.protect)
    );
    outln!(
        "Type:              {:08x}  {}",
        detail.kind,
        memory_type_name(detail.kind)
    );
    outln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(vad_type: u64, private_memory: bool) -> MemoryRegionInfo {
        MemoryRegionInfo {
            node_address: VirtAddr(0),
            level: 0,
            start: VirtAddr(0x10000),
            end: VirtAddr(0x20000),
            protection: None,
            vad_type: Some(VadType::from_raw(vad_type)),
            private_memory: Some(private_memory),
            commit_charge: None,
            details: None,
        }
    }

    #[test]
    fn vad_type_labels_follow_mi_vad_type() {
        assert_eq!(vad_type_label(&region(2, false)), "image");
        assert_eq!(vad_type_label(&region(0, false)), "mapped");
        assert_eq!(vad_type_label(&region(3, true)), "private");
        assert_eq!(vad_type_label(&region(3, false)), "vad:3");
    }
}
