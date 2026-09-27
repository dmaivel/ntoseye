//! Neutral value-tree views for the file-system inspectors: control areas,
//! VPBs, and the file cache.

use super::{View, diagnostic};
use crate::target::fs::{
    CachedFile, ControlAreaDetail, FileCacheDetail, SegmentDetail, SubsectionDetail, VpbDetail,
};

fn names<S: AsRef<str>>(names: &[S]) -> View {
    View::List(
        names
            .iter()
            .map(|name| View::Str(name.as_ref().to_string()))
            .collect(),
    )
}

fn segment(segment: &SegmentDetail) -> View {
    View::Object(vec![
        ("total_ptes", View::Num(segment.total_ptes)),
        ("size", View::Hex(segment.size)),
        ("committed_pages", View::Num(segment.committed_pages)),
        (
            "prototype_ptes",
            View::OptHex(segment.prototype_ptes.map(|ptes| ptes.0)),
        ),
    ])
}

fn subsection(subsection: &SubsectionDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(subsection.address.0)),
        ("base_pte", View::Hex(subsection.base_pte.0)),
        ("ptes", View::Num(subsection.ptes)),
        ("unused_ptes", View::Num(subsection.unused_ptes)),
        ("starting_sector", View::Hex(subsection.starting_sector)),
        ("sectors", View::Hex(subsection.sectors)),
        ("protection", View::Hex(subsection.protection)),
    ])
}

/// Render `!ca`: the control area's counts, flags, file, segment, and
/// subsections.
pub fn control_area(detail: &ControlAreaDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        ("segment", View::Hex(detail.segment.0)),
        ("section_references", View::Num(detail.section_references)),
        ("pfn_references", View::Num(detail.pfn_references)),
        ("mapped_views", View::Num(detail.mapped_views)),
        ("user_references", View::Num(detail.user_references)),
        ("flags", View::Hex(detail.flags)),
        ("flag_names", names(&detail.flag_names)),
        ("file_object", View::Hex(detail.file_object.0)),
        (
            "file_name",
            diagnostic(&detail.file_name, |name| View::Str(name.clone())),
        ),
        (
            "segment_detail",
            diagnostic(&detail.segment_detail, segment),
        ),
        (
            "subsections",
            View::List(detail.subsections.iter().map(subsection).collect()),
        ),
        (
            "subsections_stopped",
            View::OptStr(detail.subsections_stopped.clone()),
        ),
    ])
}

/// Render `!vpb`.
pub fn vpb(detail: &VpbDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        ("flags", View::Hex(detail.flags)),
        ("flag_names", names(&detail.flag_names)),
        ("device_object", View::Hex(detail.device_object.0)),
        ("device_name", View::OptStr(detail.device_name.clone())),
        ("real_device", View::Hex(detail.real_device.0)),
        (
            "real_device_name",
            View::OptStr(detail.real_device_name.clone()),
        ),
        ("serial_number", View::Hex(detail.serial_number.into())),
        ("reference_count", View::Num(detail.reference_count.into())),
        ("volume_label", View::Str(detail.volume_label.clone())),
    ])
}

fn cached_file(file: &CachedFile) -> View {
    let number = |value: &u64| View::Num(*value);
    View::Object(vec![
        ("shared_cache_map", View::Hex(file.shared_cache_map.0)),
        ("file_object", View::Hex(file.file_object.0)),
        (
            "file_name",
            diagnostic(&file.file_name, |name| View::Str(name.clone())),
        ),
        ("file_size", diagnostic(&file.file_size, number)),
        (
            "valid_data_length",
            diagnostic(&file.valid_data_length, number),
        ),
        ("open_count", diagnostic(&file.open_count, number)),
        ("dirty_pages", diagnostic(&file.dirty_pages, number)),
        ("mapped_vacbs", View::Num(file.mapped_vacbs)),
        ("valid_bytes", View::Num(file.valid_bytes)),
    ])
}

/// Render `!filecache`: the VACB summary and the cached files, most valid
/// bytes first.
pub fn file_cache(detail: &FileCacheDetail) -> View {
    View::Object(vec![
        ("vacb_arrays", View::Num(detail.vacb_arrays)),
        (
            "free_vacbs",
            diagnostic(&detail.free_vacbs, |value| View::Num(*value)),
        ),
        ("active_vacbs", View::Num(detail.active_vacbs)),
        ("mapped_bytes", View::Num(detail.mapped_bytes)),
        ("valid_bytes", View::Num(detail.valid_bytes)),
        (
            "files",
            View::List(detail.files.iter().map(cached_file).collect()),
        ),
        ("file_count", View::Num(detail.file_count)),
        ("interrupted", View::Bool(detail.interrupted)),
    ])
}
