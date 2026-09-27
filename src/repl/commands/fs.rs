//! File-system views: a section's control area (`!ca`), a volume parameter
//! block (`!vpb`), and the cache manager's mapped files (`!filecache`).

use tabled::builder::Builder;

use super::diagnostics::diagnostic_cell;
use crate::error::Result;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::fs::{ControlAreaDetail, FileCacheDetail, VpbDetail};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_ca;
    names: ["!ca", "ca"],
    usage: "!ca <control-area>",
    summary: "Decode a section's control area, its segment, and its subsections.",
    details: "Shows the section, PFN, mapped-view, and user reference counts, the _MMSECTION_FLAGS set, the backing file object and name, the segment (PTE count, size, committed pages, prototype PTEs), and each subsection (base PTE, PTE count, starting sector and sector count, protection). Subsections are read from the one after the control area along NextSubsection, bounded to 1,024 and stopping at one that names another control area. A file object's SectionObjectPointer, or a VAD's Subsection, leads to the control area.",
    completion: Expression,
}

repl_command! {
    cmd_vpb;
    names: ["!vpb", "vpb"],
    usage: "!vpb <vpb>",
    summary: "Decode a volume parameter block.",
    details: "Shows the VPB_* flags, the mounted file system's volume device and the storage device under it (with their object names), the reference count, the serial number, and the volume label. A device object's Vpb field leads to it; an address whose Type is not IO_TYPE_VPB is refused.",
    completion: Expression,
}

repl_command! {
    cmd_filecache();
    names: ["!filecache", "filecache"],
    usage: "!filecache",
    summary: "Show what the cache manager has mapped, per file.",
    details: "Walks the VACB arrays (CcVacbArrays) for views in use and groups them by shared cache map: for each file its name, the 256 KB views mapped, the pages of them present in memory, the dirty pages, the file size, and the open count, most present first. The summary gives the VACBs in use and free and the bytes mapped and present. Up to 1,024 files are listed; the walk is interruptible.",
}

fn print_control_area(detail: &ControlAreaDetail) {
    outln!("ControlArea  @ {}", ui::addr(detail.address.0));
    outln!(
        "  Segment      {}  Section Ref {:>6}  Pfn Ref {:>8}  Mapped Views {:>6}",
        ui::addr(detail.segment.0),
        detail.section_references,
        detail.pfn_references,
        detail.mapped_views
    );
    outln!(
        "  File Object  {}  User Ref    {:>6}",
        ui::addr(detail.file_object.0),
        detail.user_references
    );
    outln!(
        "  Flags ({:x}) {}",
        detail.flags,
        detail.flag_names.join(" ")
    );
    outln!("      {}", diagnostic_cell(&detail.file_name));
    outln!();
    match &detail.segment_detail {
        DiagnosticValue::Available(segment) => {
            outln!("Segment @ {}", ui::addr(detail.segment.0));
            outln!(
                "  Total Ptes {:>8x}  Segment Size {:>10x}  Committed {:>8x}{}",
                segment.total_ptes,
                segment.size,
                segment.committed_pages,
                segment
                    .prototype_ptes
                    .map(|ptes| format!("  ProtoPtes {}", ui::addr(ptes.0)))
                    .unwrap_or_default()
            );
        }
        DiagnosticValue::Unavailable(error) => {
            outln!(
                "Segment @ {}: <unavailable: {error}>",
                ui::addr(detail.segment.0)
            );
        }
    }
    outln!();
    let mut builder = Builder::default();
    builder.push_record([
        "#",
        "Subsection",
        "Base Pte",
        "Ptes",
        "Unused",
        "Starting Sector",
        "Sectors",
        "Protection",
    ]);
    for (index, subsection) in detail.subsections.iter().enumerate() {
        builder.push_record([
            (index + 1).to_string(),
            ui::addr(subsection.address.0).to_string(),
            ui::addr(subsection.base_pte.0).to_string(),
            format!("{:x}", subsection.ptes),
            format!("{:x}", subsection.unused_ptes),
            format!("{:x}", subsection.starting_sector),
            format!("{:x}", subsection.sectors),
            format!("{:x}", subsection.protection),
        ]);
    }
    print_padded_table(builder);
    if let Some(stopped) = &detail.subsections_stopped {
        outln!("  subsections stopped: {stopped}\n");
    }
}

fn print_vpb(detail: &VpbDetail) {
    let device = |address: VirtAddr, name: &Option<String>| {
        format!("{}  {}", ui::addr(address.0), name.as_deref().unwrap_or(""))
    };
    outln!("Vpb @ {}", ui::addr(detail.address.0));
    outln!(
        "  Flags         {:x}  {}",
        detail.flags,
        detail.flag_names.join(" ")
    );
    outln!(
        "  DeviceObject  {}",
        device(detail.device_object, &detail.device_name)
    );
    outln!(
        "  RealDevice    {}",
        device(detail.real_device, &detail.real_device_name)
    );
    outln!("  RefCount      {}", detail.reference_count);
    outln!("  Serial        {:08x}", detail.serial_number);
    outln!("  Volume Label  {}", detail.volume_label);
    outln!();
}

fn print_file_cache(detail: &FileCacheDetail) {
    const KB: u64 = 1024;
    outln!(
        "File cache: {} VACB arrays, {} VACBs in use, {} free",
        detail.vacb_arrays,
        detail.active_vacbs,
        diagnostic_cell(&detail.free_vacbs)
    );
    let listed = if (detail.files.len() as u64) < detail.file_count {
        format!(" (the first {} listed)", detail.files.len())
    } else {
        String::new()
    };
    outln!(
        "  {} KB mapped, {} KB present, in {} files{listed}{}",
        detail.mapped_bytes / KB,
        detail.valid_bytes / KB,
        detail.file_count,
        if detail.interrupted {
            " (interrupted)"
        } else {
            ""
        }
    );
    outln!();
    let mut builder = Builder::default();
    builder.push_record([
        "SharedCacheMap",
        "Present KB",
        "Mapped KB",
        "Dirty",
        "File Size",
        "Opens",
        "Name",
    ]);
    for file in &detail.files {
        let hex = |value: &DiagnosticValue<u64>| match value {
            DiagnosticValue::Available(value) => format!("{value:x}"),
            DiagnosticValue::Unavailable(_) => "?".to_string(),
        };
        builder.push_record([
            ui::addr(file.shared_cache_map.0).to_string(),
            (file.valid_bytes / KB).to_string(),
            (file.mapped_vacbs * 256).to_string(),
            hex(&file.dirty_pages),
            hex(&file.file_size),
            hex(&file.open_count),
            diagnostic_cell(&file.file_name),
        ]);
    }
    print_padded_table(builder);
}

impl ReplState<'_> {
    fn cmd_ca(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = require_arg!(invocation, 0, "!ca");
        let Some(address) = self.eval_or_report(expr) else {
            return Ok(());
        };
        match self.ctx.target.inspect_control_area(address) {
            Ok(detail) => print_control_area(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_vpb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr = require_arg!(invocation, 0, "!vpb");
        let Some(address) = self.eval_or_report(expr) else {
            return Ok(());
        };
        match self.ctx.target.inspect_vpb(address) {
            Ok(detail) => print_vpb(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_filecache(&mut self) -> Result<()> {
        match self.ctx.target.file_cache() {
            Ok(detail) => print_file_cache(&detail),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}
