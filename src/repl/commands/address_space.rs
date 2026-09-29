//! Address-space layout: the VAD tree and the flat region map of the
//! selected process (or the kernel module map when detached), and what an
//! arbitrary address belongs to.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::expr::Expr;
use crate::memory::PAGE_SIZE;
use crate::target::mm::{
    MemoryRegionInfo, VadProtection, VadType, VprotDetail, memory_state_name, memory_type_name,
    page_protection_name,
};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

const PAGE_SHIFT: u32 = PAGE_SIZE.trailing_zeros();
const BYTES_PER_KIB: u64 = 1024;
const BYTES_PER_MIB: u64 = BYTES_PER_KIB * 1024;

repl_command! {
    cmd_vmmap;
    names: ["!vad", "vmmap"],
    usage: "!vad [pid|eprocess]",
    summary: "Show the VAD tree of a process.",
    details: "Select a process by PID or EPROCESS expression. With no argument, the command uses the current process context, which you can select with `.process /p <pid>`. `vmmap [address|filter]` keeps the flat region view of the attached process, and shows the kernel modules when no process is attached. The VAD walk has a limit, and it skips the entries that it cannot read and continues the listing.",
    completion: [Process, None],
}

repl_command! {
    cmd_address;
    names: ["!address", "address"],
    usage: "!address <address-expression>",
    summary: "Show the module and section, or the VAD region, that an address belongs to.",
    completion: Expression,
}

repl_command! {
    cmd_vprot;
    names: ["!vprot", "vprot"],
    usage: "!vprot <address>",
    summary: "Show the VirtualQuery data for a user address.",
    details: "The command shows the region, state, protection, and type of a user address, as VirtualQuery reports them. It looks up the address in the current process context, which you can select with `.process /p <pid>`. The VAD that holds the address gives AllocationBase, AllocationProtect, and Type, and the state and protection of each page come from its PTE. For a page without a PTE, they come from the VAD (private memory) or from its prototype PTE (a section view). RegionSize runs from the page of the address to the first page that differs. An address that is not in a VAD is MEM_FREE up to the next VAD. The scan stops after 262,144 page-table steps.",
    completion: Expression,
}

fn format_region_size(size: u64) -> String {
    if size >= BYTES_PER_MIB {
        format!("{:#x} ({} MiB)", size, size / BYTES_PER_MIB)
    } else if size >= BYTES_PER_KIB {
        format!("{:#x} ({} KiB)", size, size / BYTES_PER_KIB)
    } else {
        format!("{:#x}", size)
    }
}

fn vad_protection_label(protection: Option<VadProtection>) -> String {
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

fn vad_type_label(region: &MemoryRegionInfo) -> String {
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
                None => self.current_process_context(&processes),
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

            let mut shown = 0usize;
            for region in regions
                .iter()
                .filter(|region| is_vad || region_matches_filter(region, filter, filter_address))
            {
                shown += 1;
                if is_vad {
                    builder.push_record(vec![
                        ui::addr(region.node_address.0),
                        region.level.to_string(),
                        format!("{:#x}", region.start.0 >> PAGE_SHIFT),
                        format!("{:#x}", region.end.0.saturating_sub(1) >> PAGE_SHIFT),
                        region
                            .commit_charge
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
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
                        region
                            .commit_charge
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        region.details.as_deref().unwrap_or("-").to_string(),
                    ]);
                }
            }

            if shown == 0 {
                outln!("{}\n", "no matching memory regions".bright_black());
            } else {
                outln!(
                    "{} {} ({})",
                    ui::label("process"),
                    process.name,
                    ui::Value(process.pid)
                );
                print_padded_table(builder);
            }
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
        let mut builder = Builder::default();
        builder.push_record(vec![
            "Start".to_string(),
            "End".to_string(),
            "Size".to_string(),
            "Module".to_string(),
            "Image".to_string(),
        ]);
        let mut shown = 0usize;
        for module in modules {
            let matches = filter.is_none_or(|filter| {
                module
                    .short_name
                    .to_ascii_lowercase()
                    .contains(&filter.to_ascii_lowercase())
                    || module
                        .name
                        .to_ascii_lowercase()
                        .contains(&filter.to_ascii_lowercase())
                    || filter_address.is_some_and(|address| module.contains_address(address))
            });
            if !matches {
                continue;
            }
            shown += 1;
            builder.push_record(vec![
                ui::addr(module.base_address.0).to_string(),
                ui::addr(module.end_address().0).to_string(),
                format_region_size(module.size as u64).to_string(),
                module.short_name.to_string(),
                module.name,
            ]);
        }

        if shown == 0 {
            outln!("no matching kernel regions\n");
        } else {
            print_padded_table(builder);
        }
        Ok(())
    }

    fn cmd_vprot(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = require_arg!(invocation, 0, "!vprot");
        let Some(address) = self.eval_or_report(expr) else {
            return Ok(());
        };
        let processes = match self.ctx.target.matching_processes(None) {
            Ok(processes) => processes,
            Err(error) => {
                error!("failed to enumerate processes: {error}");
                return Ok(());
            }
        };
        let Some(process) = self.current_process_context(&processes) else {
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
}

fn print_vprot(detail: &VprotDetail) {
    outln!(
        "{} {} ({})",
        ui::label("process"),
        detail.process.name,
        ui::Value(detail.process.pid)
    );
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
