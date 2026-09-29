//! File-system views: a section's control area (`!ca`), a volume parameter
//! block (`!vpb`), the cache manager's mapped files (`!filecache`), and the
//! filter manager's minifilters, instances, and volumes (`!fltkd.*`).

use tabled::builder::Builder;

use super::diagnostics::diagnostic_cell;
use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::fltmgr::{FltFrames, FltInstanceDetail};
use crate::target::fs::{ControlAreaDetail, FileCacheDetail, VpbDetail};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_ca;
    names: ["!ca", "ca"],
    usage: "!ca <control-area>",
    summary: "Decode the control area of a section, with its segment and subsections.",
    details: "Shows the section, PFN, mapped-view, and user reference counts, the _MMSECTION_FLAGS that are set, and the backing file object and its name. It also shows the segment (PTE count, size, committed pages, and prototype PTEs) and, for each subsection, the base PTE, the PTE count, the starting sector, the sector count, and the protection. The command reads up to 1,024 subsections along NextSubsection, starting from the subsection after the control area, and stops at a subsection that points to a different control area. To find a control area, use the SectionObjectPointer of a file object or the Subsection of a VAD.",
    completion: Expression,
}

repl_command! {
    cmd_vpb;
    names: ["!vpb", "vpb"],
    usage: "!vpb <vpb>",
    summary: "Decode a volume parameter block.",
    details: "Shows the VPB_* flags, the volume device of the mounted file system, and the storage device below it, with their object names. It also shows the reference count, the serial number, and the volume label. The Vpb field of a device object points to the VPB. If the Type at the address is not IO_TYPE_VPB, the command shows an error.",
    completion: Expression,
}

repl_command! {
    cmd_filecache();
    names: ["!filecache", "filecache"],
    usage: "!filecache",
    summary: "Show the views that the cache manager has mapped, for each file.",
    details: "Walks the VACB arrays (CcVacbArrays) to find the views in use, and groups the views by shared cache map. For each file, the command shows its name, the mapped 256 KB views, the pages of these views that are present in memory, the dirty pages, the file size, and the open count, with the file that has the most present data first. The summary shows the VACBs in use and free, and the bytes mapped and present. The command lists up to 1,024 files, and you can interrupt the walk.",
}

repl_command! {
    cmd_fltkd_filters();
    names: ["!fltkd.filters"],
    usage: "!fltkd.filters",
    summary: "List the registered minifilters and their instances.",
    details: "Walks each filter manager frame in fltmgr!FltGlobals and its registered filters. For each filter, the command shows its altitude and its attached instances, with their names and altitudes. The command uses the types from the PDB of fltmgr.",
}

repl_command! {
    cmd_fltkd_instances;
    names: ["!fltkd.instances"],
    usage: "!fltkd.instances [filter]",
    summary: "List minifilter instances with their filter and volume.",
    details: "Lists each instance of each registered filter. To list the instances of one filter, give its name (`WdFilter`) or its _FLT_FILTER address. For each instance, the command shows its name, altitude, filter, and the volume that it is attached to.",
    completion: Expression,
}

repl_command! {
    cmd_fltkd_volumes();
    names: ["!fltkd.volumes"],
    usage: "!fltkd.volumes",
    summary: "List the volumes that the filter manager is attached to, with their instances.",
    details: "Walks the attached volumes of each filter manager frame. For each volume, the command shows the device name, the file-system type, and the attached instances with their names and altitudes.",
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

fn print_flt_instance(instance: &FltInstanceDetail, indent: &str, with_volume: bool) {
    let volume = if with_volume {
        format!(
            "  {} {}",
            instance.filter_name.as_deref().unwrap_or("?"),
            instance.volume_name.as_deref().unwrap_or("?")
        )
    } else {
        String::new()
    };
    outln!(
        "{indent}FLT_INSTANCE: {} \"{}\" \"{}\"{volume}",
        ui::addr(instance.address.0),
        instance.name,
        instance.altitude
    );
}

fn print_stopped(indent: &str, stopped: &Option<String>) {
    if let Some(stopped) = stopped {
        outln!("{indent}(list stopped: {stopped})");
    }
}

/// Each frame of a `!fltkd.*` listing under `title`, its items printed by
/// `item`.
fn print_flt_frames<T>(detail: &FltFrames<T>, title: &str, mut item: impl FnMut(&T)) {
    for frame in &detail.frames {
        outln!(
            "{title}: {} \"Frame {}\"",
            ui::addr(frame.address.0),
            frame.frame_id
        );
        for entry in &frame.items {
            item(entry);
        }
        print_stopped("   ", &frame.stopped);
    }
    print_stopped("", &detail.stopped);
    outln!();
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

    fn cmd_fltkd_filters(&mut self) -> Result<()> {
        match self.ctx.target.flt_filters() {
            Ok(detail) => print_flt_frames(&detail, "Filter List", |filter| {
                outln!(
                    "   FLT_FILTER: {} \"{}\" \"{}\"",
                    ui::addr(filter.address.0),
                    filter.name,
                    filter.altitude
                );
                for instance in &filter.instances {
                    print_flt_instance(instance, "      ", false);
                }
                print_stopped("      ", &filter.instances_stopped);
            }),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_fltkd_instances(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let target = &self.ctx.target;
        let radix = self.radix;
        match target.flt_instances(invocation.arg(0), |text| {
            Expr::eval_with_radix(text, target, radix)
        }) {
            Ok(detail) => print_flt_frames(&detail, "Instance List", |instance| {
                print_flt_instance(instance, "   ", true)
            }),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_fltkd_volumes(&mut self) -> Result<()> {
        match self.ctx.target.flt_volumes() {
            Ok(detail) => print_flt_frames(&detail, "Volume List", |volume| {
                outln!(
                    "   FLT_VOLUME: {} \"{}\"  {}",
                    ui::addr(volume.address.0),
                    volume.device_name,
                    volume.file_system.as_deref().unwrap_or("")
                );
                for instance in &volume.instances {
                    print_flt_instance(instance, "      ", false);
                }
                print_stopped("      ", &volume.instances_stopped);
            }),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }
}
