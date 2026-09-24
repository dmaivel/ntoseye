//! usermode: [`View`](super::View) builders for the structured inspectors.

use super::{View, diagnostic, list_termination};
use crate::target::DiagnosticValue;
use crate::target::usermode::{
    ByteDiff, ImageCheckDetail, ImageSectionResult, LastError32Detail, LastErrorDetail,
    LoaderListHead, LoaderListHeads, LoaderModuleDetail, LoaderModulesDetail, MismatchRange,
    Peb32Detail, PebDetail, ProcessParametersDetail, SelfPatchCounts, SelfPatchRange, Teb32Detail,
    TebDetail,
};

fn process_parameters(detail: &ProcessParametersDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        (
            "command_line",
            diagnostic(&detail.command_line, |value| View::Str(value.clone())),
        ),
        (
            "image_path_name",
            diagnostic(&detail.image_path_name, |value| View::Str(value.clone())),
        ),
        (
            "current_directory",
            diagnostic(&detail.current_directory, |value| View::Str(value.clone())),
        ),
        (
            "dll_path",
            diagnostic(&detail.dll_path, |value| View::Str(value.clone())),
        ),
        (
            "window_title",
            diagnostic(&detail.window_title, |value| View::Str(value.clone())),
        ),
        (
            "desktop_info",
            diagnostic(&detail.desktop_info, |value| View::Str(value.clone())),
        ),
        (
            "shell_info",
            diagnostic(&detail.shell_info, |value| View::Str(value.clone())),
        ),
        (
            "runtime_data",
            diagnostic(&detail.runtime_data, |value| View::Str(value.clone())),
        ),
        (
            "environment",
            diagnostic(&detail.environment, |value| View::Hex(value.0)),
        ),
        (
            "environment_size",
            diagnostic(&detail.environment_size, |value| View::Num(*value)),
        ),
    ])
}

fn loader_list_head(detail: &LoaderListHead) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        (
            "flink",
            diagnostic(&detail.flink, |value| View::Hex(value.0)),
        ),
        (
            "blink",
            diagnostic(&detail.blink, |value| View::Hex(value.0)),
        ),
    ])
}

fn loader_list_heads(detail: &LoaderListHeads) -> View {
    View::Object(vec![
        (
            "in_load_order",
            diagnostic(&detail.in_load_order, loader_list_head),
        ),
        (
            "in_memory_order",
            diagnostic(&detail.in_memory_order, loader_list_head),
        ),
        (
            "in_initialization_order",
            diagnostic(&detail.in_initialization_order, loader_list_head),
        ),
    ])
}

fn peb32(detail: &Peb32Detail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        (
            "image_base_address",
            diagnostic(&detail.image_base_address, |value| View::Hex(value.0)),
        ),
        ("ldr", diagnostic(&detail.ldr, |value| View::Hex(value.0))),
        (
            "process_parameters",
            diagnostic(&detail.process_parameters, |value| View::Hex(value.0)),
        ),
        (
            "process_parameters_detail",
            diagnostic(&detail.process_parameters_detail, process_parameters),
        ),
        (
            "process_heap",
            diagnostic(&detail.process_heap, |value| View::Hex(value.0)),
        ),
        (
            "number_of_heaps",
            diagnostic(&detail.number_of_heaps, |value| View::Num(*value)),
        ),
        (
            "process_heaps",
            diagnostic(&detail.process_heaps, |value| View::Hex(value.0)),
        ),
        (
            "being_debugged",
            diagnostic(&detail.being_debugged, |value| View::Num((*value).into())),
        ),
        (
            "os_major_version",
            diagnostic(&detail.os_major_version, |value| View::Num(*value)),
        ),
        (
            "os_minor_version",
            diagnostic(&detail.os_minor_version, |value| View::Num(*value)),
        ),
        (
            "os_build_number",
            diagnostic(&detail.os_build_number, |value| View::Num(*value)),
        ),
        (
            "session_id",
            diagnostic(&detail.session_id, |value| View::Num(*value)),
        ),
        (
            "number_of_processors",
            diagnostic(&detail.number_of_processors, |value| View::Num(*value)),
        ),
        (
            "loader_lists",
            diagnostic(&detail.loader_lists, loader_list_heads),
        ),
    ])
}

/// Build a PEB view; top-level keys: `address`, `image_base_address`, `ldr`, `process_parameters`, `process_parameters_detail`, `process_heap`, `number_of_heaps`, `process_heaps`, `being_debugged`, `os_major_version`, `os_minor_version`, `os_build_number`, `session_id`, `number_of_processors`, `api_set_map`, `loader_lists`, `peb32`.
pub fn peb(detail: &PebDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        (
            "image_base_address",
            diagnostic(&detail.image_base_address, |value| View::Hex(value.0)),
        ),
        ("ldr", diagnostic(&detail.ldr, |value| View::Hex(value.0))),
        (
            "process_parameters",
            diagnostic(&detail.process_parameters, |value| View::Hex(value.0)),
        ),
        (
            "process_parameters_detail",
            diagnostic(&detail.process_parameters_detail, process_parameters),
        ),
        (
            "process_heap",
            diagnostic(&detail.process_heap, |value| View::Hex(value.0)),
        ),
        (
            "number_of_heaps",
            diagnostic(&detail.number_of_heaps, |value| View::Num(*value)),
        ),
        (
            "process_heaps",
            diagnostic(&detail.process_heaps, |value| View::Hex(value.0)),
        ),
        (
            "being_debugged",
            diagnostic(&detail.being_debugged, |value| View::Num((*value).into())),
        ),
        (
            "os_major_version",
            diagnostic(&detail.os_major_version, |value| View::Num(*value)),
        ),
        (
            "os_minor_version",
            diagnostic(&detail.os_minor_version, |value| View::Num(*value)),
        ),
        (
            "os_build_number",
            diagnostic(&detail.os_build_number, |value| View::Num(*value)),
        ),
        (
            "session_id",
            diagnostic(&detail.session_id, |value| View::Num(*value)),
        ),
        (
            "number_of_processors",
            diagnostic(&detail.number_of_processors, |value| View::Num(*value)),
        ),
        (
            "api_set_map",
            diagnostic(&detail.api_set_map, |value| View::Hex(value.0)),
        ),
        (
            "loader_lists",
            diagnostic(&detail.loader_lists, loader_list_heads),
        ),
        ("peb32", detail.peb32.as_ref().map_or(View::Null, peb32)),
    ])
}

fn teb32(detail: &Teb32Detail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        (
            "stack_base",
            diagnostic(&detail.stack_base, |value| View::Hex(value.0)),
        ),
        (
            "stack_limit",
            diagnostic(&detail.stack_limit, |value| View::Hex(value.0)),
        ),
        (
            "tls_pointer",
            diagnostic(&detail.tls_pointer, |value| View::Hex(value.0)),
        ),
        (
            "last_error_value",
            diagnostic(&detail.last_error_value, |value| View::Num((*value).into())),
        ),
        (
            "last_status_value",
            diagnostic(&detail.last_status_value, |value| {
                View::Hex((*value).into())
            }),
        ),
        (
            "count_of_owned_critical_sections",
            diagnostic(&detail.count_of_owned_critical_sections, |value| {
                View::Num((*value).into())
            }),
        ),
        ("peb", diagnostic(&detail.peb, |value| View::Hex(value.0))),
        (
            "client_id_unique_process",
            diagnostic(&detail.client_id_unique_process, |value| View::Hex(value.0)),
        ),
        (
            "client_id_unique_thread",
            diagnostic(&detail.client_id_unique_thread, |value| View::Hex(value.0)),
        ),
    ])
}

/// Build a TEB view; top-level keys: `address`, `stack_base`, `stack_limit`, `tls_pointer`, `last_error_value`, `last_status_value`, `count_of_owned_critical_sections`, `peb`, `wow_teb_offset`, `wow64_reserved`, `activation_context`, `client_id_unique_process`, `client_id_unique_thread`, `teb32`.
pub fn teb(detail: &TebDetail) -> View {
    View::Object(vec![
        ("address", View::Hex(detail.address.0)),
        (
            "stack_base",
            diagnostic(&detail.stack_base, |value| View::Hex(value.0)),
        ),
        (
            "stack_limit",
            diagnostic(&detail.stack_limit, |value| View::Hex(value.0)),
        ),
        (
            "tls_pointer",
            diagnostic(&detail.tls_pointer, |value| View::Hex(value.0)),
        ),
        (
            "last_error_value",
            diagnostic(&detail.last_error_value, |value| View::Num((*value).into())),
        ),
        (
            "last_status_value",
            diagnostic(&detail.last_status_value, |value| {
                View::Hex((*value).into())
            }),
        ),
        (
            "count_of_owned_critical_sections",
            diagnostic(&detail.count_of_owned_critical_sections, |value| {
                View::Num((*value).into())
            }),
        ),
        ("peb", diagnostic(&detail.peb, |value| View::Hex(value.0))),
        (
            "wow_teb_offset",
            diagnostic(&detail.wow_teb_offset, |value| View::Int((*value).into())),
        ),
        (
            "wow64_reserved",
            diagnostic(&detail.wow64_reserved, |value| View::Hex(value.0)),
        ),
        (
            "activation_context",
            diagnostic(&detail.activation_context, |value| {
                View::OptHex(value.map(|address| address.0))
            }),
        ),
        (
            "client_id_unique_process",
            diagnostic(&detail.client_id_unique_process, |value| View::Hex(value.0)),
        ),
        (
            "client_id_unique_thread",
            diagnostic(&detail.client_id_unique_thread, |value| View::Hex(value.0)),
        ),
        ("teb32", detail.teb32.as_ref().map_or(View::Null, teb32)),
    ])
}

/// One loader-list entry (`!dlls`).
pub fn loader_module(detail: &LoaderModuleDetail) -> View {
    let fields = vec![
        ("name", View::Str(detail.name.clone())),
        ("short_name", View::Str(detail.short_name.clone())),
        ("base_address", View::Hex(detail.base_address.0)),
        ("size", View::Num(detail.size.into())),
        ("is_32bit", View::Bool(detail.is_32bit)),
        (
            "entry_point",
            View::OptHex(detail.entry_point.map(|address| address.0)),
        ),
        (
            "time_date_stamp",
            View::OptHex(detail.time_date_stamp.map(u64::from)),
        ),
        ("checksum", View::OptHex(detail.checksum.map(u64::from))),
        ("file_version", View::OptStr(detail.file_version.clone())),
        (
            "product_version",
            View::OptStr(detail.product_version.clone()),
        ),
    ];
    View::Object(fields)
}

/// Build a loader-module view; top-level keys: `modules`, `termination`, `wow64_termination`.
pub fn loader_modules(detail: &LoaderModulesDetail) -> View {
    let View::Object(mut fields) = loader_terminations(detail) else {
        unreachable!("terminations are an object");
    };
    fields.insert(
        0,
        (
            "modules",
            View::List(detail.modules.iter().map(loader_module).collect()),
        ),
    );
    View::Object(fields)
}

/// How a process's native and WOW64 loader lists ended.
pub fn loader_terminations(detail: &LoaderModulesDetail) -> View {
    View::Object(vec![
        ("termination", list_termination(&detail.termination)),
        (
            "wow64_termination",
            detail
                .wow64_termination
                .as_ref()
                .map_or(View::Null, list_termination),
        ),
    ])
}

fn status_name(value: &DiagnosticValue<Option<String>>) -> View {
    diagnostic(value, |name| View::OptStr(name.clone()))
}

fn last_error32(detail: &LastError32Detail) -> View {
    View::Object(vec![
        ("teb", View::Hex(detail.teb.0)),
        (
            "last_error_value",
            diagnostic(&detail.last_error_value, |value| View::Num((*value).into())),
        ),
        ("last_error_name", status_name(&detail.last_error_name)),
        (
            "last_status_value",
            diagnostic(&detail.last_status_value, |value| {
                View::Hex((*value).into())
            }),
        ),
        ("last_status_name", status_name(&detail.last_status_name)),
    ])
}

/// Build a last-error view; top-level keys: `teb`, `last_error_value`, `last_error_name`, `last_status_value`, `last_status_name`, `teb32`.
pub fn last_error(detail: &LastErrorDetail) -> View {
    View::Object(vec![
        ("teb", View::Hex(detail.teb.0)),
        (
            "last_error_value",
            diagnostic(&detail.last_error_value, |value| View::Num((*value).into())),
        ),
        ("last_error_name", status_name(&detail.last_error_name)),
        (
            "last_status_value",
            diagnostic(&detail.last_status_value, |value| {
                View::Hex((*value).into())
            }),
        ),
        ("last_status_name", status_name(&detail.last_status_name)),
        (
            "teb32",
            detail.teb32.as_ref().map_or(View::Null, last_error32),
        ),
    ])
}

fn self_patch_counts(detail: &SelfPatchCounts) -> View {
    View::Object(vec![
        ("import_optimization", View::Num(detail.import_optimization)),
        ("retpoline", View::Num(detail.retpoline)),
        ("ki_patch_self", View::Num(detail.ki_patch_self)),
        ("total", View::Num(detail.total())),
    ])
}

fn section_result(detail: &ImageSectionResult) -> View {
    View::Object(vec![
        ("name", View::Str(detail.name.clone())),
        ("rva", View::Hex(detail.rva.into())),
        ("genuine_mismatches", View::Num(detail.genuine_mismatches)),
        ("total_mismatches", View::Num(detail.total_mismatches)),
        ("self_patches", self_patch_counts(&detail.self_patches)),
        ("skipped", View::Bool(detail.skipped)),
        ("skip_reason", View::OptStr(detail.skip_reason.clone())),
        ("unavailable", View::OptStr(detail.unavailable.clone())),
    ])
}

fn mismatch_range(detail: &MismatchRange) -> View {
    View::Object(vec![
        ("start", View::Hex(detail.start)),
        ("end", View::Hex(detail.end)),
        ("size", View::Num(detail.end.saturating_sub(detail.start))),
    ])
}

fn self_patch_range(detail: &SelfPatchRange) -> View {
    View::Object(vec![
        ("start", View::Hex(detail.start)),
        ("end", View::Hex(detail.end)),
        ("size", View::Num(detail.end.saturating_sub(detail.start))),
        ("kind", View::Str(detail.kind.name().to_string())),
        ("function", View::OptStr(detail.function.clone())),
    ])
}

fn byte_diff(detail: &ByteDiff) -> View {
    View::Object(vec![
        ("rva", View::Hex(detail.rva.into())),
        ("expected", View::Hex(detail.expected.into())),
        ("actual", View::Hex(detail.actual.into())),
        (
            "kind",
            View::OptStr(detail.kind.map(|kind| kind.name().to_string())),
        ),
    ])
}

/// Build an image-check view; top-level keys: `module`, `short_name`, `base_address`, `sections`, `genuine_mismatched_bytes`, `total_mismatched_bytes`, `self_patches`, `mismatch_ranges`, `mismatch_range_overflow`, `all_mismatch_ranges`, `all_mismatch_range_overflow`, `self_patch_ranges`, `self_patch_range_overflow`, `byte_diffs`, `byte_diffs_truncated`.
pub fn image_check(detail: &ImageCheckDetail) -> View {
    View::Object(vec![
        ("module", View::Str(detail.module.clone())),
        ("short_name", View::Str(detail.short_name.clone())),
        ("base_address", View::Hex(detail.base_address.0)),
        (
            "sections",
            View::List(detail.sections.iter().map(section_result).collect()),
        ),
        (
            "genuine_mismatched_bytes",
            View::Num(detail.genuine_mismatched_bytes),
        ),
        (
            "total_mismatched_bytes",
            View::Num(detail.total_mismatched_bytes),
        ),
        ("self_patches", self_patch_counts(&detail.self_patches)),
        (
            "mismatch_ranges",
            View::List(detail.mismatch_ranges.iter().map(mismatch_range).collect()),
        ),
        (
            "mismatch_range_overflow",
            View::Bool(detail.mismatch_range_overflow),
        ),
        (
            "all_mismatch_ranges",
            View::List(
                detail
                    .all_mismatch_ranges
                    .iter()
                    .map(mismatch_range)
                    .collect(),
            ),
        ),
        (
            "all_mismatch_range_overflow",
            View::Bool(detail.all_mismatch_range_overflow),
        ),
        (
            "self_patch_ranges",
            View::List(
                detail
                    .self_patch_ranges
                    .iter()
                    .map(self_patch_range)
                    .collect(),
            ),
        ),
        (
            "self_patch_range_overflow",
            View::Bool(detail.self_patch_range_overflow),
        ),
        (
            "byte_diffs",
            View::List(detail.byte_diffs.iter().map(byte_diff).collect()),
        ),
        (
            "byte_diffs_truncated",
            View::Bool(detail.byte_diffs_truncated),
        ),
    ])
}
