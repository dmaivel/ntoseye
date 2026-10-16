//! Address-space layout: the VAD tree and the flat region map of the
//! selected process (or the kernel module map when detached), and what an
//! arbitrary address belongs to.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::expr::Expr;
use crate::guest::ModuleInfo;
use crate::memory::PAGE_SIZE;
use crate::target::TargetKind;
use crate::target::mm::{
    MEM_FREE, MemoryBasicInformation, MemoryRegionInfo, VadProtection, VadType, memory_state_name,
    memory_type_name, page_protection_name,
};
use crate::target::usermode::address::{
    AddressSummary, CapturedRange, SummaryRow, UserRegion, human_size, state_label, summarize,
    type_label,
};
use crate::types::VirtAddr;
use crate::ui;
use crate::userdump::MemoryRegion;

use crate::repl::*;

pub const PAGE_SHIFT: u32 = PAGE_SIZE.trailing_zeros();
const BYTES_PER_KIB: u64 = 1024;
const BYTES_PER_MIB: u64 = BYTES_PER_KIB * 1024;

repl_command! {
    cmd_vmmap;
    names: ["!vad", "vmmap"],
    category: "processes and modules",
    usage: "!vad [pid|eprocess]",
    summary: "Show the VAD tree of a process.",
    details: "Select a process by PID or EPROCESS expression. With no argument, the command uses the current process context, which you can select with `.process /p <pid>`. `vmmap [address|filter]` keeps the flat region view of the attached process, and shows the kernel modules when no process is attached. The VAD walk has a limit, and it skips the entries that it cannot read and continues the listing.",
    completion: [Process, None],
    target: Kernel,
}

repl_command! {
    cmd_address;
    names: ["!address", "address"],
    category: "memory and disassembly",
    usage: "!address [-summary | address-expression]",
    summary: "Show the module and section, or the VAD region, that an address belongs to.",
    details: "On a user-mode minidump the command uses the regions that the dump's memory-info list records. Without an argument, it lists them with their state, protection, type, allocation base, usage, and how much of each the dump captured, followed by a summary by usage, type, state, and protection; -summary shows only the summary. With an address, it shows the region that holds it. Usage comes from the dump's modules, its threads' stacks and TEBs, the PEB, and the heaps in the PEB's ProcessHeaps array; it is <unknown> for any other region. A dump without a memory-info list shows the memory ranges it captured instead.",
    completion: Expression,
}

repl_command! {
    cmd_vprot;
    names: ["!vprot", "vprot"],
    category: "memory manager",
    usage: "!vprot <address>",
    summary: "Show the VirtualQuery data for a user address.",
    details: "The command shows the region, state, protection, and type of a user address, as VirtualQuery reports them. It looks up the address in the current process context, which you can select with `.process /p <pid>`. The VAD that holds the address gives AllocationBase, AllocationProtect, and Type, and the state and protection of each page come from its PTE. For a page without a PTE, they come from the VAD (private memory) or from its prototype PTE (a section view). RegionSize runs from the page of the address to the first page that differs. An address that is not in a VAD is MEM_FREE up to the next VAD. The scan stops after 262,144 page-table steps. On a user-mode minidump the command reads the region from the dump's memory-info list, which records what VirtualQuery returned when the dump was written; RegionSize runs from the page of the address to the end of that region.",
    completion: Expression,
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

impl ReplState<'_> {
    fn cmd_vmmap(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let is_vad = invocation.name == "!vad";
        let filter = invocation.arg(0);
        let filter_address = filter
            .and_then(|filter| Expr::eval_with_radix(filter, &self.ctx.target, self.radix).ok());

        let vad_process = if is_vad {
            let processes = match self.ctx.target.matching_processes(None) {
                Ok(processes) => processes,
                Err(error) => {
                    error!("failed to enumerate processes: {}", error);
                    return Ok(());
                }
            };
            match filter {
                Some(selector) => match self.process_for_selector(selector, &processes) {
                    Some(process) => Some(process),
                    None => {
                        error!("no process matches '{selector}' (expected a PID or EPROCESS)");
                        return Ok(());
                    }
                },
                None => self.ctx.target.current_process(),
            }
        } else {
            self.ctx.target.attached_process().cloned()
        };

        if let Some(process) = vad_process {
            let regions = match self
                .ctx
                .target
                .enumerate_vad_regions_for_process_info(&process)
            {
                Ok(regions) => regions,
                Err(e) => {
                    error!("failed to enumerate VADs: {}", e);
                    return Ok(());
                }
            };

            let shown: Vec<&MemoryRegionInfo> = regions
                .iter()
                .filter(|region| is_vad || region_matches_filter(region, filter, filter_address))
                .collect();
            if shown.is_empty() {
                outln!("{}\n", "no matching memory regions".bright_black());
                return Ok(());
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
                || native::lists::regions(&process, &shown, is_vad),
                print_text,
            );
            #[cfg(not(feature = "cli"))]
            print_text();
            return Ok(());
        }

        if is_vad {
            error!("!vad requires a current process or an EPROCESS selector");
            return Ok(());
        }

        let modules = match self.ctx.target.kernel_modules_with_versions() {
            Ok(modules) => modules,
            Err(e) => {
                error!("failed to enumerate kernel modules: {}", e);
                return Ok(());
            }
        };
        let shown: Vec<ModuleInfo> = modules
            .into_iter()
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
            .collect();

        if shown.is_empty() {
            outln!("no matching kernel regions\n");
            return Ok(());
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
        Ok(())
    }

    fn cmd_vprot(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = require_arg!(invocation, 0, "!vprot");
        let Some(address) = self.eval_or_report(expr) else {
            return Ok(());
        };
        if let Some(info) = self.ctx.target.user_dump_info() {
            if info.regions.is_none() {
                error!("!vprot: the minidump has no memory-info list");
            } else if let Some(region) = info.region(address.0) {
                print_virtual_query(&VirtualQuery::in_user_dump_region(region, address.0), false);
            } else {
                error!(
                    "!vprot: the minidump's memory-info list has no region holding {}",
                    ui::addr(address.0)
                );
            }
            return Ok(());
        }
        let Some(process) = self.ctx.target.current_process() else {
            error!("!vprot needs a process context (.process /p <pid>)");
            return Ok(());
        };
        match self.ctx.target.virtual_query(&process, address) {
            Ok(detail) => print_vprot(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_address(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if self.ctx.target.kind() == TargetKind::UserDump {
            return self.cmd_address_user_dump(&invocation);
        }
        let Some(expr) = invocation.arg(0) else {
            outln!("{}\n", command_help("address"));
            return Ok(());
        };

        let Some(addr) = self.eval_or_report(expr) else {
            return Ok(());
        };

        let d = match self.ctx.target.describe_address(addr) {
            Ok(d) => d,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

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

        Ok(())
    }

    /// `!address` on a user-mode minidump: its memory-info list, or the
    /// ranges it captured when it has none.
    fn cmd_address_user_dump(&mut self, invocation: &CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("address"));
            return Ok(());
        }
        let summary_only = invocation.arg(0) == Some("-summary");
        let address = match invocation.arg(0) {
            Some(expression) if !summary_only => match self.eval_or_report(expression) {
                Some(address) => Some(address),
                None => return Ok(()),
            },
            _ => None,
        };
        let has_regions = self
            .ctx
            .target
            .user_dump_info()
            .is_some_and(|info| info.regions.is_some());
        if !has_regions {
            return self.print_captured_ranges(address);
        }
        let map = match self.ctx.target.user_address_map() {
            Ok(map) => map,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        if let Some(address) = address {
            match map.region_at(address.0) {
                Some(region) => self.print_user_region(address, region),
                None => outln!(
                    "address {}: not in any region the minidump's memory-info list records\n",
                    ui::addr(address.0)
                ),
            }
            return Ok(());
        }
        if !summary_only {
            print_padded_table(user_region_table(&map.regions));
            outln!();
        }
        print_address_summary(&summarize(&map.regions));
        Ok(())
    }

    fn print_user_region(&self, address: VirtAddr, entry: &UserRegion) {
        let region = &entry.region;
        let captured = self
            .ctx
            .target
            .user_dump()
            .is_some_and(|dump| dump.read_virtual(address, &mut [0u8; 1]).is_ok());
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

    /// What `!address` shows of a dump without a memory-info list: the
    /// ranges it captured, or the one holding `address`.
    fn print_captured_ranges(&self, address: Option<VirtAddr>) -> Result<()> {
        outln!(
            "{}",
            ui::muted(
                "the minidump records no memory-info list (MemoryInfoListStream): region state, protection, and type are not known"
            )
        );
        let ranges = match self.ctx.target.user_captured_ranges() {
            Ok(ranges) => ranges,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        if let Some(address) = address {
            match ranges
                .iter()
                .find(|range| address.0.wrapping_sub(range.start) < range.length)
            {
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
            return Ok(());
        }
        let total: u64 = ranges.iter().map(|range| range.length).sum();
        outln!(
            "captured memory: {} ranges, {}",
            ranges.len(),
            human_size(total)
        );
        let mut builder = Builder::default();
        builder.push_record(["Start", "End", "Size", "Usage"]);
        for range in &ranges {
            builder.push_record([
                ui::addr(range.start).to_string(),
                ui::addr(range.start.saturating_add(range.length)).to_string(),
                format!("{:#x}", range.length),
                captured_usage_cell(range),
            ]);
        }
        print_padded_table(builder);
        Ok(())
    }
}

fn usage_cell(entry: &UserRegion) -> String {
    match &entry.detail {
        Some(detail) => format!("{} [{detail}]", entry.usage.label()),
        None => entry.usage.label().to_string(),
    }
}

fn captured_usage_cell(range: &CapturedRange) -> String {
    match &range.detail {
        Some(detail) => format!("{} [{detail}]", range.usage.label()),
        None => range.usage.label().to_string(),
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
    print_virtual_query(
        &VirtualQuery {
            base_address: detail.base_address.0,
            allocation_base: detail.allocation_base.0,
            allocation_protect: detail.allocation_protect,
            region_size: detail.region_size,
            state: detail.state,
            protect: detail.protect,
            kind: detail.kind,
        },
        detail.truncated,
    );
}

/// The `MEMORY_BASIC_INFORMATION` fields `!vprot` shows.
struct VirtualQuery {
    base_address: u64,
    allocation_base: u64,
    allocation_protect: u32,
    region_size: u64,
    state: u32,
    protect: u32,
    kind: u32,
}

impl VirtualQuery {
    /// What VirtualQuery reports for `address` in a region of a minidump's
    /// memory-info list: the region from the address's page on.
    fn in_user_dump_region(region: &MemoryRegion, address: u64) -> Self {
        let page = address & !(PAGE_SIZE as u64 - 1);
        let base_address = page.max(region.base);
        Self {
            base_address,
            allocation_base: region.allocation_base,
            allocation_protect: region.allocation_protect,
            region_size: region.base + region.size - base_address,
            state: region.state,
            protect: region.protect,
            kind: region.kind,
        }
    }
}

fn print_virtual_query(query: &VirtualQuery, truncated: bool) {
    outln!("BaseAddress:       {}", ui::addr(query.base_address));
    outln!("AllocationBase:    {}", ui::addr(query.allocation_base));
    outln!(
        "AllocationProtect: {:08x}  {}",
        query.allocation_protect,
        page_protection_name(query.allocation_protect)
    );
    outln!(
        "RegionSize:        {:016x}{}",
        query.region_size,
        if truncated {
            "  (scan bound reached; at least this much)"
        } else {
            ""
        }
    );
    outln!(
        "State:             {:08x}  {}",
        query.state,
        memory_state_name(query.state)
    );
    outln!(
        "Protect:           {:08x}  {}",
        query.protect,
        page_protection_name(query.protect)
    );
    outln!(
        "Type:              {:08x}  {}",
        query.kind,
        memory_type_name(query.kind)
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

    #[test]
    fn user_dump_virtual_query_starts_at_the_address_page() {
        let region = MemoryRegion {
            base: 0x7ff6_0000_0000,
            allocation_base: 0x7ff5_ffff_0000,
            allocation_protect: 0x80,
            size: 0x5000,
            state: 0x1000,
            protect: 0x20,
            kind: 0x100_0000,
        };
        let middle = VirtualQuery::in_user_dump_region(&region, 0x7ff6_0000_2345);
        assert_eq!(middle.base_address, 0x7ff6_0000_2000);
        assert_eq!(middle.region_size, 0x3000);
        assert_eq!(middle.allocation_base, 0x7ff5_ffff_0000);
        let first = VirtualQuery::in_user_dump_region(&region, 0x7ff6_0000_0010);
        assert_eq!(first.base_address, region.base);
        assert_eq!(first.region_size, region.size);
        let last = VirtualQuery::in_user_dump_region(&region, 0x7ff6_0000_4fff);
        assert_eq!(last.base_address, 0x7ff6_0000_4000);
        assert_eq!(last.region_size, 0x1000);
    }
}
