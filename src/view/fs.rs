//! Neutral value-tree views for the file-system inspectors: control areas,
//! VPBs, the file cache, and the filter manager.

use super::View;
use super::shape::{Diag, Hex, ViewValue, shapes};
use crate::target::fltmgr::{
    FltFilterDetail, FltFrame, FltFrames, FltInstanceDetail, FltVolumeDetail,
};
use crate::target::fs::{
    CachedFile as CachedFileDetail, ControlAreaDetail, FileCacheDetail, SegmentDetail,
    SubsectionDetail, VpbDetail,
};

shapes! {
    /// A control area's `_SEGMENT`.
    ControlAreaSegment {
        total_ptes: u64,
        /// Bytes.
        size: Hex,
        committed_pages: u64,
        /// `None` for a data file's segment, whose prototype PTEs are in its
        /// subsections.
        prototype_ptes: Option<Hex>,
    }

    /// A `_SUBSECTION` following a control area.
    Subsection {
        address: Hex,
        /// Its first prototype PTE.
        base_pte: Hex,
        ptes: u64,
        unused_ptes: u64,
        starting_sector: Hex,
        sectors: Hex,
        /// The MM protection of `SubsectionFlags`.
        protection: Hex,
    }

    /// A section's `_CONTROL_AREA`, its segment, and its subsections (`!ca`).
    ControlArea {
        address: Hex,
        segment: Hex,
        section_references: u64,
        pfn_references: u64,
        mapped_views: u64,
        user_references: u64,
        /// `u.LongFlags`.
        flags: Hex,
        /// The `_MMSECTION_FLAGS` bits set in `flags`.
        flag_names: Vec<String>,
        file_object: Hex,
        file_name: Diag<String>,
        segment_detail: Diag<ControlAreaSegment>,
        subsections: Vec<Subsection>,
        /// Why the subsection walk stopped before a null `NextSubsection`;
        /// `None` when it reached it.
        subsections_stopped: Option<String>,
    }

    /// A volume parameter block (`!vpb`).
    Vpb {
        address: Hex,
        flags: Hex,
        /// The `VPB_*` bits set in `flags`.
        flag_names: Vec<&'static str>,
        /// The mounted file system's volume device object.
        device_object: Hex,
        device_name: Option<String>,
        /// The storage device the volume is on.
        real_device: Hex,
        real_device_name: Option<String>,
        serial_number: Hex,
        reference_count: u32,
        volume_label: String,
    }

    /// A file the cache manager maps a view of.
    CachedFile {
        shared_cache_map: Hex,
        file_object: Hex,
        file_name: Diag<String>,
        /// Bytes.
        file_size: Diag<u64>,
        /// Bytes.
        valid_data_length: Diag<u64>,
        open_count: Diag<u64>,
        dirty_pages: Diag<u64>,
        mapped_vacbs: u64,
        /// Present bytes in the mapped views.
        valid_bytes: u64,
    }

    /// The cache manager's mapped views, from its VACB arrays (`!filecache`).
    FileCache {
        vacb_arrays: u64,
        /// `CcNumberOfFreeVacbs`.
        free_vacbs: Diag<u64>,
        /// VACBs mapping a view.
        active_vacbs: u64,
        mapped_bytes: u64,
        /// Present bytes in the mapped views.
        valid_bytes: u64,
        /// One per shared cache map with a mapped view, most valid bytes
        /// first, up to 1,024.
        files: Vec<CachedFile>,
        /// The shared cache maps with a mapped view, listed or not.
        file_count: u64,
        /// Whether an interrupt request stopped the walk early.
        interrupted: bool,
    }

    /// A minifilter attached to a volume (`_FLT_INSTANCE`).
    FltInstance {
        address: Hex,
        name: String,
        altitude: String,
        /// Its `_FLT_FILTER`.
        filter: Hex,
        filter_name: Option<String>,
        /// Its `_FLT_VOLUME`.
        volume: Hex,
        volume_name: Option<String>,
    }

    /// A registered minifilter (`_FLT_FILTER`) and its instances.
    FltFilter {
        address: Hex,
        name: String,
        altitude: String,
        driver_object: Hex,
        instances: Vec<FltInstance>,
        /// Why the instance walk stopped short of its head; `None` when it
        /// completed.
        instances_stopped: Option<String>,
    }

    /// A volume the filter manager attached to (`_FLT_VOLUME`) and the
    /// instances on it.
    FltVolume {
        address: Hex,
        device_name: String,
        /// The `_FLT_FILESYSTEM_TYPE` name without its `FLT_FSTYPE_` prefix.
        file_system: Option<String>,
        instances: Vec<FltInstance>,
        /// Why the instance walk stopped short of its head; `None` when it
        /// completed.
        instances_stopped: Option<String>,
    }

    /// A filter manager frame and its registered minifilters.
    FltFilterFrame {
        /// The `_FLTP_FRAME`.
        address: Hex,
        frame_id: u64,
        filters: Vec<FltFilter>,
        /// Why the frame's list walk stopped short of its head; `None` when it
        /// completed.
        stopped: Option<String>,
    }

    /// A filter manager frame and its minifilter instances.
    FltInstanceFrame {
        /// The `_FLTP_FRAME`.
        address: Hex,
        frame_id: u64,
        instances: Vec<FltInstance>,
        /// Why the frame's list walk stopped short of its head; `None` when it
        /// completed.
        stopped: Option<String>,
    }

    /// A filter manager frame and its volumes.
    FltVolumeFrame {
        /// The `_FLTP_FRAME`.
        address: Hex,
        frame_id: u64,
        volumes: Vec<FltVolume>,
        /// Why the frame's list walk stopped short of its head; `None` when it
        /// completed.
        stopped: Option<String>,
    }

    /// The registered minifilters of each filter manager frame
    /// (`!fltkd.filters`).
    FltFilters {
        frames: Vec<FltFilterFrame>,
        /// Why the frame walk stopped short of its head; `None` when it
        /// completed.
        stopped: Option<String>,
    }

    /// Minifilter instances per filter manager frame (`!fltkd.instances`).
    FltInstances {
        frames: Vec<FltInstanceFrame>,
        /// Why the frame walk stopped short of its head; `None` when it
        /// completed.
        stopped: Option<String>,
    }

    /// The volumes of each filter manager frame (`!fltkd.volumes`).
    FltVolumes {
        frames: Vec<FltVolumeFrame>,
        /// Why the frame walk stopped short of its head; `None` when it
        /// completed.
        stopped: Option<String>,
    }
}

fn segment(segment: &SegmentDetail) -> ControlAreaSegment {
    ControlAreaSegment {
        total_ptes: segment.total_ptes,
        size: Hex(segment.size),
        committed_pages: segment.committed_pages,
        prototype_ptes: segment.prototype_ptes.map(|ptes| Hex(ptes.0)),
    }
}

fn subsection(subsection: &SubsectionDetail) -> Subsection {
    Subsection {
        address: Hex(subsection.address.0),
        base_pte: Hex(subsection.base_pte.0),
        ptes: subsection.ptes,
        unused_ptes: subsection.unused_ptes,
        starting_sector: Hex(subsection.starting_sector),
        sectors: Hex(subsection.sectors),
        protection: Hex(subsection.protection),
    }
}

/// Render `!ca`.
pub fn control_area(detail: &ControlAreaDetail) -> View {
    ControlArea {
        address: Hex(detail.address.0),
        segment: Hex(detail.segment.0),
        section_references: detail.section_references,
        pfn_references: detail.pfn_references,
        mapped_views: detail.mapped_views,
        user_references: detail.user_references,
        flags: Hex(detail.flags),
        flag_names: detail.flag_names.clone(),
        file_object: Hex(detail.file_object.0),
        file_name: Diag::of(&detail.file_name, String::clone),
        segment_detail: Diag::of(&detail.segment_detail, segment),
        subsections: detail.subsections.iter().map(subsection).collect(),
        subsections_stopped: detail.subsections_stopped.clone(),
    }
    .into_view()
}

/// Render `!vpb`.
pub fn vpb(detail: &VpbDetail) -> View {
    Vpb {
        address: Hex(detail.address.0),
        flags: Hex(detail.flags),
        flag_names: detail.flag_names.clone(),
        device_object: Hex(detail.device_object.0),
        device_name: detail.device_name.clone(),
        real_device: Hex(detail.real_device.0),
        real_device_name: detail.real_device_name.clone(),
        serial_number: Hex(detail.serial_number.into()),
        reference_count: detail.reference_count,
        volume_label: detail.volume_label.clone(),
    }
    .into_view()
}

fn cached_file(file: &CachedFileDetail) -> CachedFile {
    CachedFile {
        shared_cache_map: Hex(file.shared_cache_map.0),
        file_object: Hex(file.file_object.0),
        file_name: Diag::of(&file.file_name, String::clone),
        file_size: Diag::of(&file.file_size, |value| *value),
        valid_data_length: Diag::of(&file.valid_data_length, |value| *value),
        open_count: Diag::of(&file.open_count, |value| *value),
        dirty_pages: Diag::of(&file.dirty_pages, |value| *value),
        mapped_vacbs: file.mapped_vacbs,
        valid_bytes: file.valid_bytes,
    }
}

/// Render `!filecache`: the VACB summary and the cached files, most valid
/// bytes first.
pub fn file_cache(detail: &FileCacheDetail) -> View {
    FileCache {
        vacb_arrays: detail.vacb_arrays,
        free_vacbs: Diag::of(&detail.free_vacbs, |value| *value),
        active_vacbs: detail.active_vacbs,
        mapped_bytes: detail.mapped_bytes,
        valid_bytes: detail.valid_bytes,
        files: detail.files.iter().map(cached_file).collect(),
        file_count: detail.file_count,
        interrupted: detail.interrupted,
    }
    .into_view()
}

fn flt_instance(instance: &FltInstanceDetail) -> FltInstance {
    FltInstance {
        address: Hex(instance.address.0),
        name: instance.name.clone(),
        altitude: instance.altitude.clone(),
        filter: Hex(instance.filter.0),
        filter_name: instance.filter_name.clone(),
        volume: Hex(instance.volume.0),
        volume_name: instance.volume_name.clone(),
    }
}

fn flt_filter(filter: &FltFilterDetail) -> FltFilter {
    FltFilter {
        address: Hex(filter.address.0),
        name: filter.name.clone(),
        altitude: filter.altitude.clone(),
        driver_object: Hex(filter.driver_object.0),
        instances: filter.instances.iter().map(flt_instance).collect(),
        instances_stopped: filter.instances_stopped.clone(),
    }
}

fn flt_volume(volume: &FltVolumeDetail) -> FltVolume {
    FltVolume {
        address: Hex(volume.address.0),
        device_name: volume.device_name.clone(),
        file_system: volume.file_system.clone(),
        instances: volume.instances.iter().map(flt_instance).collect(),
        instances_stopped: volume.instances_stopped.clone(),
    }
}

/// A frame's address, id, items rendered by `item`, and why its walk
/// stopped.
fn flt_frame<T, U>(frame: &FltFrame<T>, item: fn(&T) -> U) -> (Hex, u64, Vec<U>, Option<String>) {
    (
        Hex(frame.address.0),
        frame.frame_id,
        frame.items.iter().map(item).collect(),
        frame.stopped.clone(),
    )
}

/// Render `!fltkd.filters`: frames, each with its filters and their
/// instances.
pub fn flt_filters(detail: &FltFrames<FltFilterDetail>) -> View {
    FltFilters {
        frames: detail
            .frames
            .iter()
            .map(|frame| {
                let (address, frame_id, filters, stopped) = flt_frame(frame, flt_filter);
                FltFilterFrame {
                    address,
                    frame_id,
                    filters,
                    stopped,
                }
            })
            .collect(),
        stopped: detail.stopped.clone(),
    }
    .into_view()
}

/// Render `!fltkd.instances`: frames, each with its instances.
pub fn flt_instances(detail: &FltFrames<FltInstanceDetail>) -> View {
    FltInstances {
        frames: detail
            .frames
            .iter()
            .map(|frame| {
                let (address, frame_id, instances, stopped) = flt_frame(frame, flt_instance);
                FltInstanceFrame {
                    address,
                    frame_id,
                    instances,
                    stopped,
                }
            })
            .collect(),
        stopped: detail.stopped.clone(),
    }
    .into_view()
}

/// Render `!fltkd.volumes`: frames, each with its volumes and the instances
/// on them.
pub fn flt_volumes(detail: &FltFrames<FltVolumeDetail>) -> View {
    FltVolumes {
        frames: detail
            .frames
            .iter()
            .map(|frame| {
                let (address, frame_id, volumes, stopped) = flt_frame(frame, flt_volume);
                FltVolumeFrame {
                    address,
                    frame_id,
                    volumes,
                    stopped,
                }
            })
            .collect(),
        stopped: detail.stopped.clone(),
    }
    .into_view()
}
