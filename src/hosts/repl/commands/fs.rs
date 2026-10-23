//! File-system views: a section's control area (`!ca`), a volume parameter
//! block (`!vpb`), the cache manager's mapped files (`!filecache`), and the
//! filter manager's minifilters, instances, and volumes (`!fltkd.*`).

use tabled::builder::Builder;

use ntoseye_macros::command;

use crate::base::error::Result;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCx, ArgError, FromArg};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::DiagnosticValue;
use crate::nt::target::fltmgr::{
    FltFilterSelector, FltFilters, FltInstanceDetail, FltInstances, FltVolumes,
};
use crate::nt::target::fs::{ControlAreaDetail, FileCacheDetail, VpbDetail};
use crate::session::Session;

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
    match &detail.file_name {
        DiagnosticValue::Available(name) => outln!("      {name}"),
        DiagnosticValue::Unavailable(error) => {
            outln!(
                "      {}",
                ui::muted(&format!("file name unavailable: {error}"))
            )
        }
    }
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
            outln!("Segment @ {}", ui::addr(detail.segment.0));
            outln!("  {}", ui::muted(&format!("segment unavailable: {error}")));
        }
    }
    outln!();
    let mut builder = Builder::default();
    builder.push_record([
        "#",
        "Subsection",
        "Base PTE",
        "PTEs",
        "Unused",
        "Starting sector",
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
        outln!("  subsections stopped: {stopped}");
    }
}

fn print_vpb(detail: &VpbDetail) {
    let device = |address: VirtAddr, name: &Option<String>| {
        format!(
            "{}  {}",
            ui::addr(address.0),
            name.as_deref().unwrap_or("-")
        )
    };
    let label = if detail.volume_label.is_empty() {
        "-"
    } else {
        detail.volume_label.as_str()
    };
    outln!("VPB {}", ui::addr(detail.address.0));
    if detail.flag_names.is_empty() {
        outln!("  Flags          : {:#x}", detail.flags);
    } else {
        outln!(
            "  Flags          : {:#x} ({})",
            detail.flags,
            detail.flag_names.join(" | ")
        );
    }
    outln!(
        "  DeviceObject   : {}",
        device(detail.device_object, &detail.device_name)
    );
    outln!(
        "  RealDevice     : {}",
        device(detail.real_device, &detail.real_device_name)
    );
    outln!("  ReferenceCount : {}", detail.reference_count);
    outln!("  SerialNumber   : {:#010x}", detail.serial_number);
    outln!("  VolumeLabel    : {label}");
}

fn print_file_cache(detail: &FileCacheDetail) {
    const KIB: u64 = 1024;
    let free = match &detail.free_vacbs {
        DiagnosticValue::Available(free) => format!(", {free} free"),
        DiagnosticValue::Unavailable(_) => String::new(),
    };
    outln!(
        "file cache: {} VACB arrays, {} VACBs in use{free}",
        detail.vacb_arrays,
        detail.active_vacbs,
    );
    let listed = if (detail.files.len() as u64) < detail.file_count {
        format!(" (the first {} listed)", detail.files.len())
    } else {
        String::new()
    };
    outln!(
        "  {} KiB mapped, {} KiB present, in {} files{listed}{}",
        detail.mapped_bytes / KIB,
        detail.valid_bytes / KIB,
        detail.file_count,
        if detail.interrupted {
            " (interrupted)"
        } else {
            ""
        }
    );
    if let DiagnosticValue::Unavailable(error) = &detail.free_vacbs {
        outln!(
            "  {}",
            ui::muted(&format!("free VACBs unavailable: {error}"))
        );
    }
    outln!();
    let mut builder = Builder::default();
    builder.push_record([
        "SharedCacheMap",
        "Present KiB",
        "Mapped KiB",
        "Dirty",
        "File size",
        "Opens",
        "Name",
    ]);
    for file in &detail.files {
        let hex = |value: &DiagnosticValue<u64>| match value {
            DiagnosticValue::Available(value) => format!("{value:#x}"),
            DiagnosticValue::Unavailable(_) => "-".to_string(),
        };
        let count = |value: &DiagnosticValue<u64>| match value {
            DiagnosticValue::Available(value) => value.to_string(),
            DiagnosticValue::Unavailable(_) => "-".to_string(),
        };
        let name = match &file.file_name {
            DiagnosticValue::Available(name) if !name.is_empty() => name.clone(),
            _ => "-".to_string(),
        };
        builder.push_record([
            ui::addr(file.shared_cache_map.0).to_string(),
            (file.valid_bytes / KIB).to_string(),
            (file.mapped_vacbs * 256).to_string(),
            count(&file.dirty_pages),
            hex(&file.file_size),
            count(&file.open_count),
            name,
        ]);
    }
    print_padded_table(builder);
}

fn print_flt_instance(instance: &FltInstanceDetail, indent: &str, with_volume: bool) {
    let volume = if with_volume {
        format!(
            "  {} {}",
            instance.filter_name.as_deref().unwrap_or("-"),
            instance.volume_name.as_deref().unwrap_or("-")
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

/// The header line of a `!fltkd.*` frame.
fn print_frame_title(title: &str, address: VirtAddr, frame_id: u64) {
    outln!("{title}: {} \"Frame {frame_id}\"", ui::addr(address.0));
}

/// Decode the control area of a section, with its segment and subsections.
///
/// Shows the section, PFN, mapped-view, and user reference counts, the
/// _MMSECTION_FLAGS that are set, and the backing file object and its name. It
/// also shows the segment (PTE count, size, committed pages, and prototype
/// PTEs) and, for each subsection, the base PTE, the PTE count, the starting
/// sector, the sector count, and the protection. The command reads up to 1,024
/// subsections along NextSubsection, starting from the subsection after the
/// control area, and stops at a subsection that points to a different control
/// area. To find a control area, use the SectionObjectPointer of a file object
/// or the Subsection of a VAD.
#[command(
    names = ["!ca", "ca"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "control_area",
)]
fn ca(
    session: &Session,
    #[arg(name = "control-area")] address: VirtAddr,
) -> Result<ControlAreaDetail> {
    session.target.inspect_control_area(address)
}

impl Render for ControlAreaDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_control_area(self);
    }
}

/// Decode a volume parameter block.
///
/// Shows the VPB_* flags, the volume device of the mounted file system, and the
/// storage device below it, with their object names. It also shows the
/// reference count, the serial number, and the volume label. The Vpb field of a
/// device object points to the VPB. If the Type at the address is not
/// IO_TYPE_VPB, the command shows an error.
#[command(
    names = ["!vpb", "vpb"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn vpb(session: &Session, #[arg(name = "vpb")] address: VirtAddr) -> Result<VpbDetail> {
    session.target.inspect_vpb(address)
}

impl Render for VpbDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_vpb(self);
    }
}

/// Show the views that the cache manager has mapped, for each file.
///
/// Walks the VACB arrays (CcVacbArrays) to find the views in use, and groups
/// the views by shared cache map. For each file, the command shows its name,
/// the mapped 256 KB views, the pages of these views that are present in
/// memory, the dirty pages, the file size, and the open count, with the file
/// that has the most present data first. The summary shows the VACBs in use and
/// free, and the bytes mapped and present. The command lists up to 1,024 files,
/// and you can interrupt the walk.
#[command(
    names = ["!filecache", "filecache"],
    category = "memory manager",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn file_cache(session: &Session) -> Result<FileCacheDetail> {
    session.target.file_cache()
}

impl Render for FileCacheDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_file_cache(self);
    }
}

/// List the registered minifilters and their instances.
///
/// Walks each filter manager frame in fltmgr!FltGlobals and its registered
/// filters. For each filter, the command shows its altitude and its attached
/// instances, with their names and altitudes. The command uses the types from
/// the PDB of fltmgr.
#[command(
    names = ["!fltkd.filters"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn flt_filters(session: &Session) -> Result<FltFilters> {
    session.target.flt_filters()
}

impl Render for FltFilters {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for frame in &self.frames {
            print_frame_title("Filter List", frame.address, frame.frame_id);
            for filter in &frame.filters {
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
            }
            print_stopped("   ", &frame.stopped);
        }
        print_stopped("", &self.stopped);
    }
}

/// A minifilter's name, or its `_FLT_FILTER` address when the word
/// evaluates.
impl FromArg for FltFilterSelector {
    const COMPLETION: CompletionStrategy = CompletionStrategy::Expression;

    fn from_arg(cx: &mut ArgCx<'_, '_>, text: &str) -> std::result::Result<Self, ArgError> {
        Ok(Self {
            name: text.to_string(),
            address: cx.eval(text).ok(),
        })
    }
}

/// List minifilter instances with their filter and volume.
///
/// Lists each instance of each registered filter. To list the instances of one
/// filter, give its name (`WdFilter`) or its _FLT_FILTER address. For each
/// instance, the command shows its name, altitude, filter, and the volume that
/// it is attached to.
#[command(
    names = ["!fltkd.instances"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn flt_instances(
    session: &Session,
    #[arg(positional)] filter: Option<FltFilterSelector>,
) -> Result<FltInstances> {
    session.target.flt_instances(filter.as_ref())
}

impl Render for FltInstances {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for frame in &self.frames {
            print_frame_title("Instance List", frame.address, frame.frame_id);
            for instance in &frame.instances {
                print_flt_instance(instance, "   ", true);
            }
            print_stopped("   ", &frame.stopped);
        }
        print_stopped("", &self.stopped);
    }
}

/// List the volumes that the filter manager is attached to, with their
/// instances.
///
/// Walks the attached volumes of each filter manager frame. For each volume,
/// the command shows the device name, the file-system type, and the attached
/// instances with their names and altitudes.
#[command(
    names = ["!fltkd.volumes"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn flt_volumes(session: &Session) -> Result<FltVolumes> {
    session.target.flt_volumes()
}

impl Render for FltVolumes {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for frame in &self.frames {
            print_frame_title("Volume List", frame.address, frame.frame_id);
            for volume in &frame.volumes {
                outln!(
                    "   FLT_VOLUME: {} \"{}\"  {}",
                    ui::addr(volume.address.0),
                    volume.device_name,
                    volume.file_system.as_deref().unwrap_or("-")
                );
                for instance in &volume.instances {
                    print_flt_instance(instance, "      ", false);
                }
                print_stopped("      ", &volume.instances_stopped);
            }
            print_stopped("   ", &frame.stopped);
        }
        print_stopped("", &self.stopped);
    }
}
