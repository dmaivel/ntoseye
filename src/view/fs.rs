//! Neutral value-tree views for the file-system inspectors: control areas,
//! VPBs, the file cache, and the filter manager.

use super::shape::{Diag, Hex, shapes};
use crate::types::VirtAddr;
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
        /// `None` for the segment of a data file, whose prototype PTEs are in
        /// its subsections.
        prototype_ptes: Option<VirtAddr>,
    }

    /// A `_SUBSECTION` after a control area.
    Subsection {
        address: VirtAddr,
        /// Its first prototype PTE.
        base_pte: VirtAddr,
        ptes: u64,
        unused_ptes: u64,
        starting_sector: Hex,
        sectors: Hex,
        /// The MM protection in `SubsectionFlags`.
        protection: Hex,
    }

    /// The `_CONTROL_AREA` of a section, with its segment and subsections
    /// (`!ca`).
    ControlArea {
        address: VirtAddr,
        segment: VirtAddr,
        section_references: u64,
        pfn_references: u64,
        mapped_views: u64,
        user_references: u64,
        /// `u.LongFlags`.
        flags: Hex,
        /// The `_MMSECTION_FLAGS` bits set in `flags`.
        flag_names: Vec<String>,
        file_object: VirtAddr,
        file_name: Diag<String>,
        segment_detail: Diag<ControlAreaSegment>,
        subsections: Vec<Subsection>,
        /// Why the subsection walk stopped before a null `NextSubsection`.
        /// `None` if the walk got to a null `NextSubsection`.
        subsections_stopped: Option<String>,
    }

    /// A volume parameter block (`!vpb`).
    Vpb {
        address: VirtAddr,
        flags: Hex,
        /// The `VPB_*` bits set in `flags`.
        flag_names: Vec<&'static str>,
        /// The mounted file system's volume device object.
        device_object: VirtAddr,
        device_name: Option<String>,
        /// The storage device that holds the volume.
        real_device: VirtAddr,
        real_device_name: Option<String>,
        serial_number: Hex<u32>,
        reference_count: u32,
        volume_label: String,
    }

    /// A file that the cache manager maps a view of.
    CachedFile {
        shared_cache_map: VirtAddr,
        file_object: VirtAddr,
        file_name: Diag<String>,
        /// Bytes.
        file_size: Diag<u64>,
        /// Bytes.
        valid_data_length: Diag<u64>,
        open_count: Diag<u64>,
        dirty_pages: Diag<u64>,
        mapped_vacbs: u64,
        /// The bytes in the mapped views that are present in memory.
        valid_bytes: u64,
    }

    /// The mapped views of the cache manager, from its VACB arrays
    /// (`!filecache`).
    FileCache {
        vacb_arrays: u64,
        /// `CcNumberOfFreeVacbs`.
        free_vacbs: Diag<u64>,
        /// The VACBs that map a view.
        active_vacbs: u64,
        mapped_bytes: u64,
        /// The bytes in the mapped views that are present in memory.
        valid_bytes: u64,
        /// One entry for each shared cache map that has a mapped view, most
        /// valid bytes first, up to 1,024 entries.
        files: Vec<CachedFile>,
        /// The number of shared cache maps that have a mapped view, including
        /// the maps that `files` does not list.
        file_count: u64,
        /// Whether an interrupt request stopped the walk early.
        interrupted: bool,
    }

    /// A minifilter attached to a volume (`_FLT_INSTANCE`).
    FltInstance {
        address: VirtAddr,
        name: String,
        altitude: String,
        /// Its `_FLT_FILTER`.
        filter: VirtAddr,
        filter_name: Option<String>,
        /// Its `_FLT_VOLUME`.
        volume: VirtAddr,
        volume_name: Option<String>,
    }

    /// A registered minifilter (`_FLT_FILTER`) and its instances.
    FltFilter {
        address: VirtAddr,
        name: String,
        altitude: String,
        driver_object: VirtAddr,
        instances: Vec<FltInstance>,
        /// Why the instance walk stopped before the list head. `None` if the
        /// walk completed.
        instances_stopped: Option<String>,
    }

    /// A volume that the filter manager attached to (`_FLT_VOLUME`), and the
    /// instances on it.
    FltVolume {
        address: VirtAddr,
        device_name: String,
        /// The `_FLT_FILESYSTEM_TYPE` name without its `FLT_FSTYPE_` prefix.
        file_system: Option<String>,
        instances: Vec<FltInstance>,
        /// Why the instance walk stopped before the list head. `None` if the
        /// walk completed.
        instances_stopped: Option<String>,
    }

    /// A filter manager frame and its registered minifilters.
    FltFilterFrame {
        /// The `_FLTP_FRAME`.
        address: VirtAddr,
        frame_id: u64,
        filters: Vec<FltFilter>,
        /// Why the walk of the frame list stopped before the list head. `None`
        /// if the walk completed.
        stopped: Option<String>,
    }

    /// A filter manager frame and its minifilter instances.
    FltInstanceFrame {
        /// The `_FLTP_FRAME`.
        address: VirtAddr,
        frame_id: u64,
        instances: Vec<FltInstance>,
        /// Why the walk of the frame list stopped before the list head. `None`
        /// if the walk completed.
        stopped: Option<String>,
    }

    /// A filter manager frame and its volumes.
    FltVolumeFrame {
        /// The `_FLTP_FRAME`.
        address: VirtAddr,
        frame_id: u64,
        volumes: Vec<FltVolume>,
        /// Why the walk of the frame list stopped before the list head. `None`
        /// if the walk completed.
        stopped: Option<String>,
    }

    /// The registered minifilters of each filter manager frame
    /// (`!fltkd.filters`).
    FltFilters {
        frames: Vec<FltFilterFrame>,
        /// Why the frame walk stopped before the list head. `None` if the walk
        /// completed.
        stopped: Option<String>,
    }

    /// The minifilter instances of each filter manager frame
    /// (`!fltkd.instances`).
    FltInstances {
        frames: Vec<FltInstanceFrame>,
        /// Why the frame walk stopped before the list head. `None` if the walk
        /// completed.
        stopped: Option<String>,
    }

    /// The volumes of each filter manager frame (`!fltkd.volumes`).
    FltVolumes {
        frames: Vec<FltVolumeFrame>,
        /// Why the frame walk stopped before the list head. `None` if the walk
        /// completed.
        stopped: Option<String>,
    }
}

fn segment(segment: &SegmentDetail) -> ControlAreaSegment {
    ControlAreaSegment {
        total_ptes: segment.total_ptes,
        size: segment.size,
        committed_pages: segment.committed_pages,
        prototype_ptes: segment.prototype_ptes,
    }
}

fn subsection(subsection: &SubsectionDetail) -> Subsection {
    Subsection {
        address: subsection.address,
        base_pte: subsection.base_pte,
        ptes: subsection.ptes,
        unused_ptes: subsection.unused_ptes,
        starting_sector: subsection.starting_sector,
        sectors: subsection.sectors,
        protection: subsection.protection,
    }
}

/// Render `!ca`.
pub fn control_area(detail: &ControlAreaDetail) -> ControlArea {
    ControlArea {
        address: detail.address,
        segment: detail.segment,
        section_references: detail.section_references,
        pfn_references: detail.pfn_references,
        mapped_views: detail.mapped_views,
        user_references: detail.user_references,
        flags: detail.flags,
        flag_names: detail.flag_names.clone(),
        file_object: detail.file_object,
        file_name: detail.file_name.map(String::clone),
        segment_detail: detail.segment_detail.map(segment),
        subsections: detail.subsections.iter().map(subsection).collect(),
        subsections_stopped: detail.subsections_stopped.clone(),
    }
}

/// Render `!vpb`.
pub fn vpb(detail: &VpbDetail) -> Vpb {
    Vpb {
        address: detail.address,
        flags: detail.flags,
        flag_names: detail.flag_names.clone(),
        device_object: detail.device_object,
        device_name: detail.device_name.clone(),
        real_device: detail.real_device,
        real_device_name: detail.real_device_name.clone(),
        serial_number: detail.serial_number,
        reference_count: detail.reference_count,
        volume_label: detail.volume_label.clone(),
    }
}

fn cached_file(file: &CachedFileDetail) -> CachedFile {
    CachedFile {
        shared_cache_map: file.shared_cache_map,
        file_object: file.file_object,
        file_name: file.file_name.map(String::clone),
        file_size: file.file_size.clone(),
        valid_data_length: file.valid_data_length.clone(),
        open_count: file.open_count.clone(),
        dirty_pages: file.dirty_pages.clone(),
        mapped_vacbs: file.mapped_vacbs,
        valid_bytes: file.valid_bytes,
    }
}

/// Render `!filecache`: the VACB summary and the cached files, most valid
/// bytes first.
pub fn file_cache(detail: &FileCacheDetail) -> FileCache {
    FileCache {
        vacb_arrays: detail.vacb_arrays,
        free_vacbs: detail.free_vacbs.clone(),
        active_vacbs: detail.active_vacbs,
        mapped_bytes: detail.mapped_bytes,
        valid_bytes: detail.valid_bytes,
        files: detail.files.iter().map(cached_file).collect(),
        file_count: detail.file_count,
        interrupted: detail.interrupted,
    }
}

fn flt_instance(instance: &FltInstanceDetail) -> FltInstance {
    FltInstance {
        address: instance.address,
        name: instance.name.clone(),
        altitude: instance.altitude.clone(),
        filter: instance.filter,
        filter_name: instance.filter_name.clone(),
        volume: instance.volume,
        volume_name: instance.volume_name.clone(),
    }
}

fn flt_filter(filter: &FltFilterDetail) -> FltFilter {
    FltFilter {
        address: filter.address,
        name: filter.name.clone(),
        altitude: filter.altitude.clone(),
        driver_object: filter.driver_object,
        instances: filter.instances.iter().map(flt_instance).collect(),
        instances_stopped: filter.instances_stopped.clone(),
    }
}

fn flt_volume(volume: &FltVolumeDetail) -> FltVolume {
    FltVolume {
        address: volume.address,
        device_name: volume.device_name.clone(),
        file_system: volume.file_system.clone(),
        instances: volume.instances.iter().map(flt_instance).collect(),
        instances_stopped: volume.instances_stopped.clone(),
    }
}

/// A frame's address, id, items rendered by `item`, and why its walk
/// stopped.
fn flt_frame<T, U>(
    frame: &FltFrame<T>,
    item: fn(&T) -> U,
) -> (VirtAddr, u64, Vec<U>, Option<String>) {
    (
        frame.address,
        frame.frame_id,
        frame.items.iter().map(item).collect(),
        frame.stopped.clone(),
    )
}

/// Render `!fltkd.filters`: frames, each with its filters and their
/// instances.
pub fn flt_filters(detail: &FltFrames<FltFilterDetail>) -> FltFilters {
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
}

/// Render `!fltkd.instances`: frames, each with its instances.
pub fn flt_instances(detail: &FltFrames<FltInstanceDetail>) -> FltInstances {
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
}

/// Render `!fltkd.volumes`: frames, each with its volumes and the instances
/// on them.
pub fn flt_volumes(detail: &FltFrames<FltVolumeDetail>) -> FltVolumes {
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
}
