//! usermode: [`View`] builders for the structured inspectors.

use super::shape::{Diag, Hex, shapes};
use super::list::{ListEnd, list_termination};
use crate::target::usermode::{
    self as target, ImageCheckDetail, ImageSectionResult, LastError32Detail, LastErrorDetail,
    LoaderListHeads, LoaderModuleDetail, LoaderModulesDetail, Peb32Detail, PebDetail,
    ProcessParametersDetail, Teb32Detail, TebDetail,
};
use crate::types::VirtAddr;

shapes! {
    /// A process's `_RTL_USER_PROCESS_PARAMETERS`: its strings read on their
    /// own, each unavailable when paged out.
    ProcessParameters {
        address: VirtAddr,
        command_line: Diag<String>,
        /// The image's full path.
        image_path_name: Diag<String>,
        current_directory: Diag<String>,
        /// The DLL search path.
        dll_path: Diag<String>,
        window_title: Diag<String>,
        desktop_info: Diag<String>,
        shell_info: Diag<String>,
        runtime_data: Diag<String>,
        /// The environment block's address.
        environment: Diag<VirtAddr>,
        /// The environment block's size in bytes.
        environment_size: Diag<u64>,
    }

    /// A `_PEB_LDR_DATA` list head.
    LoaderListHead {
        /// The `LIST_ENTRY` head itself.
        address: VirtAddr,
        /// The first entry.
        flink: Diag<VirtAddr>,
        /// The last entry.
        blink: Diag<VirtAddr>,
    }

    /// The three `_PEB_LDR_DATA` module lists' heads.
    LoaderLists {
        in_load_order: Diag<LoaderListHead>,
        in_memory_order: Diag<LoaderListHead>,
        in_initialization_order: Diag<LoaderListHead>,
    }

    /// A process's `_PEB` (`!peb`), each field read on its own.
    Peb {
        address: VirtAddr,
        image_base_address: Diag<VirtAddr>,
        /// The `_PEB_LDR_DATA` address.
        ldr: Diag<VirtAddr>,
        /// The `_RTL_USER_PROCESS_PARAMETERS` address.
        process_parameters: Diag<VirtAddr>,
        /// The decoded process parameters.
        process_parameters_detail: Diag<ProcessParameters>,
        /// The default heap.
        process_heap: Diag<VirtAddr>,
        number_of_heaps: Diag<u64>,
        /// The heap pointer array.
        process_heaps: Diag<VirtAddr>,
        /// `BeingDebugged`: nonzero while a user-mode debugger is attached.
        being_debugged: Diag<u8>,
        os_major_version: Diag<u64>,
        os_minor_version: Diag<u64>,
        os_build_number: Diag<u64>,
        session_id: Diag<u64>,
        number_of_processors: Diag<u64>,
        /// The API set schema.
        api_set_map: Diag<VirtAddr>,
        /// The loader's module list heads.
        loader_lists: Diag<LoaderLists>,
        /// The WOW64 `_PEB32`; `None` for a native process.
        peb32: Option<Peb32>,
    }

    /// A WOW64 process's 32-bit `_PEB32`, each field read on its own.
    Peb32 {
        address: VirtAddr,
        image_base_address: Diag<VirtAddr>,
        /// The `_PEB_LDR_DATA32` address.
        ldr: Diag<VirtAddr>,
        /// The 32-bit process parameters' address.
        process_parameters: Diag<VirtAddr>,
        /// The decoded 32-bit process parameters.
        process_parameters_detail: Diag<ProcessParameters>,
        /// The default heap.
        process_heap: Diag<VirtAddr>,
        number_of_heaps: Diag<u64>,
        /// The heap pointer array.
        process_heaps: Diag<VirtAddr>,
        /// `BeingDebugged`: nonzero while a user-mode debugger is attached.
        being_debugged: Diag<u8>,
        os_major_version: Diag<u64>,
        os_minor_version: Diag<u64>,
        os_build_number: Diag<u64>,
        session_id: Diag<u64>,
        number_of_processors: Diag<u64>,
        /// The loader's 32-bit module list heads.
        loader_lists: Diag<LoaderLists>,
    }

    /// A thread's `_TEB` (`!teb`), each field read on its own.
    Teb {
        address: VirtAddr,
        stack_base: Diag<VirtAddr>,
        stack_limit: Diag<VirtAddr>,
        /// The thread-local storage array.
        tls_pointer: Diag<VirtAddr>,
        /// The Win32 last error.
        last_error_value: Diag<u32>,
        /// The last NTSTATUS.
        last_status_value: Diag<Hex<u32>>,
        count_of_owned_critical_sections: Diag<u32>,
        /// The process's `_PEB`.
        peb: Diag<VirtAddr>,
        /// `WowTebOffset`: the byte offset to the WOW64 `_TEB32` (0 for none).
        wow_teb_offset: Diag<i32>,
        /// `WOW32Reserved`: the WOW64 transition thunk.
        wow64_reserved: Diag<VirtAddr>,
        /// The active activation context; value `None` when there is none.
        activation_context: Diag<Option<VirtAddr>>,
        client_id_unique_process: Diag<VirtAddr>,
        client_id_unique_thread: Diag<VirtAddr>,
        /// The WOW64 `_TEB32`; `None` for a native thread.
        teb32: Option<Teb32>,
    }

    /// A WOW64 thread's 32-bit `_TEB32`, each field read on its own.
    Teb32 {
        address: VirtAddr,
        stack_base: Diag<VirtAddr>,
        stack_limit: Diag<VirtAddr>,
        /// The thread-local storage array.
        tls_pointer: Diag<VirtAddr>,
        /// The Win32 last error.
        last_error_value: Diag<u32>,
        /// The last NTSTATUS.
        last_status_value: Diag<Hex<u32>>,
        count_of_owned_critical_sections: Diag<u32>,
        /// The process's `_PEB32`.
        peb: Diag<VirtAddr>,
        client_id_unique_process: Diag<VirtAddr>,
        client_id_unique_thread: Diag<VirtAddr>,
    }

    /// One module on a process's loader list (`!dlls`).
    LoaderModule {
        /// The full path.
        name: String,
        /// The file name.
        short_name: String,
        base_address: VirtAddr,
        /// The image size in bytes.
        size: u32,
        /// On the WOW64 (32-bit) loader list.
        is_32bit: bool,
        /// `None` when the loader entry has none (or it is unreadable).
        entry_point: Option<VirtAddr>,
        /// The PE header's link timestamp; `None` when the header is
        /// unreadable.
        time_date_stamp: Option<Hex<u32>>,
        /// The PE header's checksum; `None` when the header is unreadable.
        checksum: Option<Hex<u32>>,
        /// The version resource's file version; `None` when unreadable.
        file_version: Option<String>,
        /// The version resource's product version; `None` when unreadable.
        product_version: Option<String>,
    }

    /// A process's loader-list modules (`!dlls`) and how the walks ended.
    LoaderModules {
        modules: Vec<LoaderModule>,
        /// How the native loader-list walk ended.
        termination: ListEnd,
        /// How the WOW64 loader-list walk ended; `None` for a native process.
        wow64_termination: Option<ListEnd>,
    }

    /// How a process's native and WOW64 loader-list walks ended.
    LoaderTerminations {
        termination: ListEnd,
        /// `None` for a native process.
        wow64_termination: Option<ListEnd>,
    }

    /// A thread's Win32 last error and last NTSTATUS (`!gle`).
    LastError {
        /// The `_TEB` read.
        teb: VirtAddr,
        last_error_value: Diag<u32>,
        /// The error's symbolic name; value `None` when unknown.
        last_error_name: Diag<Option<String>>,
        last_status_value: Diag<Hex<u32>>,
        /// The status's symbolic name; value `None` when unknown.
        last_status_name: Diag<Option<String>>,
        /// The WOW64 `_TEB32`'s values; `None` for a native thread.
        teb32: Option<LastError32>,
    }

    /// A WOW64 thread's 32-bit last error and last NTSTATUS.
    LastError32 {
        /// The `_TEB32` read.
        teb: VirtAddr,
        last_error_value: Diag<u32>,
        /// The error's symbolic name; value `None` when unknown.
        last_error_name: Diag<Option<String>>,
        last_status_value: Diag<Hex<u32>>,
        /// The status's symbolic name; value `None` when unknown.
        last_status_name: Diag<Option<String>>,
    }

    /// Bytes recognized as known kernel self-patches, by kind.
    ImageSelfPatchCounts {
        import_optimization: u64,
        retpoline: u64,
        /// `KiPatchSelf` / JMP thunks.
        ki_patch_self: u64,
        /// Relocated addresses of kernel VA regions moved at boot.
        region_rebase: u64,
        total: u64,
    }

    /// One executable section's comparison against the cached image.
    ImageSectionCheck {
        name: String,
        rva: Hex<u32>,
        /// Mismatched bytes, known self-patches excluded.
        genuine_mismatches: u64,
        /// Mismatched bytes, known self-patches included.
        total_mismatches: u64,
        self_patches: ImageSelfPatchCounts,
        /// The section was not compared.
        skipped: bool,
        /// Why it was skipped; `None` when compared.
        skip_reason: Option<String>,
        /// Why its memory could not be read; `None` when read.
        unavailable: Option<String>,
    }

    /// A contiguous RVA range of mismatched bytes.
    ImageMismatchRange {
        start: Hex,
        /// Exclusive.
        end: Hex,
        /// In bytes.
        size: u64,
    }

    /// A contiguous RVA range recognized as one kernel self-patch kind.
    ImageSelfPatchRange {
        start: Hex,
        /// Exclusive.
        end: Hex,
        /// In bytes.
        size: u64,
        /// `import optimization`, `retpoline`, `KiPatchSelf/JMP thunk`, or
        /// `kernel VA region rebase`.
        kind: &'static str,
        /// The function containing the patch, when a symbol covers it.
        function: Option<String>,
    }

    /// One byte that differs from the cached image.
    ImageByteDiff {
        rva: Hex<u32>,
        /// The cached image's byte.
        expected: Hex<u8>,
        /// The byte in memory.
        actual: Hex<u8>,
        /// The self-patch kind it belongs to; `None` for a genuine mismatch.
        kind: Option<&'static str>,
    }

    /// A module's in-memory code compared against its cached image
    /// (`!chkimg`). Range lists are capped; the `*_overflow` flags say when
    /// more existed.
    ImageCheck {
        /// The full path.
        module: String,
        short_name: String,
        base_address: VirtAddr,
        sections: Vec<ImageSectionCheck>,
        /// Mismatched bytes, known self-patches excluded.
        genuine_mismatched_bytes: u64,
        /// Mismatched bytes, known self-patches included.
        total_mismatched_bytes: u64,
        self_patches: ImageSelfPatchCounts,
        /// Genuine mismatch ranges.
        mismatch_ranges: Vec<ImageMismatchRange>,
        mismatch_range_overflow: bool,
        /// Mismatch ranges, self-patches included.
        all_mismatch_ranges: Vec<ImageMismatchRange>,
        all_mismatch_range_overflow: bool,
        self_patch_ranges: Vec<ImageSelfPatchRange>,
        self_patch_range_overflow: bool,
        /// Byte-level differences; empty unless requested (`-d`).
        byte_diffs: Vec<ImageByteDiff>,
        byte_diffs_truncated: bool,
    }
}

fn process_parameters(detail: &ProcessParametersDetail) -> ProcessParameters {
    ProcessParameters {
        address: detail.address,
        command_line: detail.command_line.map(String::clone),
        image_path_name: detail.image_path_name.map(String::clone),
        current_directory: detail.current_directory.map(String::clone),
        dll_path: detail.dll_path.map(String::clone),
        window_title: detail.window_title.map(String::clone),
        desktop_info: detail.desktop_info.map(String::clone),
        shell_info: detail.shell_info.map(String::clone),
        runtime_data: detail.runtime_data.map(String::clone),
        environment: detail.environment.clone(),
        environment_size: detail.environment_size.clone(),
    }
}

fn loader_list_head(detail: &target::LoaderListHead) -> LoaderListHead {
    LoaderListHead {
        address: detail.address,
        flink: detail.flink.clone(),
        blink: detail.blink.clone(),
    }
}

fn loader_lists(detail: &LoaderListHeads) -> LoaderLists {
    LoaderLists {
        in_load_order: detail.in_load_order.map(loader_list_head),
        in_memory_order: detail.in_memory_order.map(loader_list_head),
        in_initialization_order: detail.in_initialization_order.map(loader_list_head),
    }
}

fn peb32(detail: &Peb32Detail) -> Peb32 {
    Peb32 {
        address: detail.address,
        image_base_address: detail.image_base_address.clone(),
        ldr: detail.ldr.clone(),
        process_parameters: detail.process_parameters.clone(),
        process_parameters_detail: detail.process_parameters_detail.map(process_parameters),
        process_heap: detail.process_heap.clone(),
        number_of_heaps: detail.number_of_heaps.clone(),
        process_heaps: detail.process_heaps.clone(),
        being_debugged: detail.being_debugged.clone(),
        os_major_version: detail.os_major_version.clone(),
        os_minor_version: detail.os_minor_version.clone(),
        os_build_number: detail.os_build_number.clone(),
        session_id: detail.session_id.clone(),
        number_of_processors: detail.number_of_processors.clone(),
        loader_lists: detail.loader_lists.map(loader_lists),
    }
}

pub fn peb(detail: &PebDetail) -> Peb {
    Peb {
        address: detail.address,
        image_base_address: detail.image_base_address.clone(),
        ldr: detail.ldr.clone(),
        process_parameters: detail.process_parameters.clone(),
        process_parameters_detail: detail.process_parameters_detail.map(process_parameters),
        process_heap: detail.process_heap.clone(),
        number_of_heaps: detail.number_of_heaps.clone(),
        process_heaps: detail.process_heaps.clone(),
        being_debugged: detail.being_debugged.clone(),
        os_major_version: detail.os_major_version.clone(),
        os_minor_version: detail.os_minor_version.clone(),
        os_build_number: detail.os_build_number.clone(),
        session_id: detail.session_id.clone(),
        number_of_processors: detail.number_of_processors.clone(),
        api_set_map: detail.api_set_map.clone(),
        loader_lists: detail.loader_lists.map(loader_lists),
        peb32: detail.peb32.as_ref().map(peb32),
    }
}

fn teb32(detail: &Teb32Detail) -> Teb32 {
    Teb32 {
        address: detail.address,
        stack_base: detail.stack_base.clone(),
        stack_limit: detail.stack_limit.clone(),
        tls_pointer: detail.tls_pointer.clone(),
        last_error_value: detail.last_error_value.clone(),
        last_status_value: detail.last_status_value.map(|value| *value),
        count_of_owned_critical_sections: detail.count_of_owned_critical_sections.clone(),
        peb: detail.peb.clone(),
        client_id_unique_process: detail.client_id_unique_process.clone(),
        client_id_unique_thread: detail.client_id_unique_thread.clone(),
    }
}

pub fn teb(detail: &TebDetail) -> Teb {
    Teb {
        address: detail.address,
        stack_base: detail.stack_base.clone(),
        stack_limit: detail.stack_limit.clone(),
        tls_pointer: detail.tls_pointer.clone(),
        last_error_value: detail.last_error_value.clone(),
        last_status_value: detail.last_status_value.map(|value| *value),
        count_of_owned_critical_sections: detail.count_of_owned_critical_sections.clone(),
        peb: detail.peb.clone(),
        wow_teb_offset: detail.wow_teb_offset.clone(),
        wow64_reserved: detail.wow64_reserved.clone(),
        activation_context: detail.activation_context.map(|value| value.as_ref().copied()),
        client_id_unique_process: detail.client_id_unique_process.clone(),
        client_id_unique_thread: detail.client_id_unique_thread.clone(),
        teb32: detail.teb32.as_ref().map(teb32),
    }
}

/// One loader-list entry (`!dlls`).
pub fn loader_module(detail: &LoaderModuleDetail) -> LoaderModule {
    LoaderModule {
        name: detail.name.clone(),
        short_name: detail.short_name.clone(),
        base_address: detail.base_address,
        size: detail.size,
        is_32bit: detail.is_32bit,
        entry_point: detail.entry_point.as_ref().copied(),
        time_date_stamp: detail.time_date_stamp,
        checksum: detail.checksum,
        file_version: detail.file_version.clone(),
        product_version: detail.product_version.clone(),
    }
}

pub fn loader_modules(detail: &LoaderModulesDetail) -> LoaderModules {
    LoaderModules {
        modules: detail.modules.iter().map(loader_module).collect(),
        termination: list_termination(&detail.termination),
        wow64_termination: detail.wow64_termination.as_ref().map(list_termination),
    }
}

/// How a process's native and WOW64 loader lists ended.
pub fn loader_terminations(detail: &LoaderModulesDetail) -> LoaderTerminations {
    LoaderTerminations {
        termination: list_termination(&detail.termination),
        wow64_termination: detail.wow64_termination.as_ref().map(list_termination),
    }
}

fn last_error32(detail: &LastError32Detail) -> LastError32 {
    LastError32 {
        teb: detail.teb,
        last_error_value: detail.last_error_value.clone(),
        last_error_name: detail.last_error_name.map(Option::clone),
        last_status_value: detail.last_status_value.map(|value| *value),
        last_status_name: detail.last_status_name.map(Option::clone),
    }
}

pub fn last_error(detail: &LastErrorDetail) -> LastError {
    LastError {
        teb: detail.teb,
        last_error_value: detail.last_error_value.clone(),
        last_error_name: detail.last_error_name.map(Option::clone),
        last_status_value: detail.last_status_value.map(|value| *value),
        last_status_name: detail.last_status_name.map(Option::clone),
        teb32: detail.teb32.as_ref().map(last_error32),
    }
}

fn self_patch_counts(detail: &target::SelfPatchCounts) -> ImageSelfPatchCounts {
    ImageSelfPatchCounts {
        import_optimization: detail.import_optimization,
        retpoline: detail.retpoline,
        ki_patch_self: detail.ki_patch_self,
        region_rebase: detail.region_rebase,
        total: detail.total(),
    }
}

fn section_result(detail: &ImageSectionResult) -> ImageSectionCheck {
    ImageSectionCheck {
        name: detail.name.clone(),
        rva: detail.rva,
        genuine_mismatches: detail.genuine_mismatches,
        total_mismatches: detail.total_mismatches,
        self_patches: self_patch_counts(&detail.self_patches),
        skipped: detail.skipped,
        skip_reason: detail.skip_reason.clone(),
        unavailable: detail.unavailable.clone(),
    }
}

fn mismatch_range(detail: &target::MismatchRange) -> ImageMismatchRange {
    ImageMismatchRange {
        start: detail.start,
        end: detail.end,
        size: detail.end.saturating_sub(detail.start),
    }
}

fn self_patch_range(detail: &target::SelfPatchRange) -> ImageSelfPatchRange {
    ImageSelfPatchRange {
        start: detail.start,
        end: detail.end,
        size: detail.end.saturating_sub(detail.start),
        kind: detail.kind.name(),
        function: detail.function.clone(),
    }
}

fn byte_diff(detail: &target::ByteDiff) -> ImageByteDiff {
    ImageByteDiff {
        rva: detail.rva,
        expected: detail.expected,
        actual: detail.actual,
        kind: detail.kind.map(target::SelfPatchKind::name),
    }
}

pub fn image_check(detail: &ImageCheckDetail) -> ImageCheck {
    ImageCheck {
        module: detail.module.clone(),
        short_name: detail.short_name.clone(),
        base_address: detail.base_address,
        sections: detail.sections.iter().map(section_result).collect(),
        genuine_mismatched_bytes: detail.genuine_mismatched_bytes,
        total_mismatched_bytes: detail.total_mismatched_bytes,
        self_patches: self_patch_counts(&detail.self_patches),
        mismatch_ranges: detail.mismatch_ranges.iter().map(mismatch_range).collect(),
        mismatch_range_overflow: detail.mismatch_range_overflow,
        all_mismatch_ranges: detail
            .all_mismatch_ranges
            .iter()
            .map(mismatch_range)
            .collect(),
        all_mismatch_range_overflow: detail.all_mismatch_range_overflow,
        self_patch_ranges: detail
            .self_patch_ranges
            .iter()
            .map(self_patch_range)
            .collect(),
        self_patch_range_overflow: detail.self_patch_range_overflow,
        byte_diffs: detail.byte_diffs.iter().map(byte_diff).collect(),
        byte_diffs_truncated: detail.byte_diffs_truncated,
    }
}
