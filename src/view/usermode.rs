//! usermode: [`View`] builders for the structured inspectors.

use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use super::list::{ListEnd, list_termination};
use crate::target::usermode::{
    self as target, ImageCheckDetail, ImageSectionResult, LastError32Detail, LastErrorDetail,
    LoaderListHeads, LoaderModuleDetail, LoaderModulesDetail, Peb32Detail, PebDetail,
    ProcessParametersDetail, Teb32Detail, TebDetail,
};
use crate::types::VirtAddr;

/// A process's `_RTL_USER_PROCESS_PARAMETERS`. ntoseye reads each string
/// separately, and a string that is paged out is unavailable.
#[record]
pub struct ProcessParameters {
    pub address: VirtAddr,
    pub command_line: DiagnosticValue<String>,
    /// The image's full path.
    pub image_path_name: DiagnosticValue<String>,
    pub current_directory: DiagnosticValue<String>,
    /// The DLL search path.
    pub dll_path: DiagnosticValue<String>,
    pub window_title: DiagnosticValue<String>,
    pub desktop_info: DiagnosticValue<String>,
    pub shell_info: DiagnosticValue<String>,
    pub runtime_data: DiagnosticValue<String>,
    /// The environment block's address.
    pub environment: DiagnosticValue<VirtAddr>,
    /// The environment block's size in bytes.
    pub environment_size: DiagnosticValue<u64>,
}

/// A `_PEB_LDR_DATA` list head.
#[record]
pub struct LoaderListHead {
    /// The `LIST_ENTRY` head.
    pub address: VirtAddr,
    /// The first entry.
    pub flink: DiagnosticValue<VirtAddr>,
    /// The last entry.
    pub blink: DiagnosticValue<VirtAddr>,
}

/// The heads of the three `_PEB_LDR_DATA` module lists.
#[record]
pub struct LoaderLists {
    pub in_load_order: DiagnosticValue<LoaderListHead>,
    pub in_memory_order: DiagnosticValue<LoaderListHead>,
    pub in_initialization_order: DiagnosticValue<LoaderListHead>,
}

/// A process's `_PEB` (`!peb`). ntoseye reads each field separately.
#[record]
pub struct Peb {
    pub address: VirtAddr,
    pub image_base_address: DiagnosticValue<VirtAddr>,
    /// The `_PEB_LDR_DATA` address.
    pub ldr: DiagnosticValue<VirtAddr>,
    /// The `_RTL_USER_PROCESS_PARAMETERS` address.
    pub process_parameters: DiagnosticValue<VirtAddr>,
    /// The decoded process parameters.
    pub process_parameters_detail: DiagnosticValue<ProcessParameters>,
    /// The default heap.
    pub process_heap: DiagnosticValue<VirtAddr>,
    pub number_of_heaps: DiagnosticValue<u64>,
    /// The heap pointer array.
    pub process_heaps: DiagnosticValue<VirtAddr>,
    /// `BeingDebugged`: nonzero while a user-mode debugger is attached.
    pub being_debugged: DiagnosticValue<u8>,
    pub os_major_version: DiagnosticValue<u64>,
    pub os_minor_version: DiagnosticValue<u64>,
    pub os_build_number: DiagnosticValue<u64>,
    pub session_id: DiagnosticValue<u64>,
    pub number_of_processors: DiagnosticValue<u64>,
    /// The API set schema.
    pub api_set_map: DiagnosticValue<VirtAddr>,
    /// The loader's module list heads.
    pub loader_lists: DiagnosticValue<LoaderLists>,
    /// The WOW64 `_PEB32`. `None` for a native process.
    pub peb32: Option<Peb32>,
}

/// A WOW64 process's 32-bit `_PEB32`. ntoseye reads each field separately.
#[record]
pub struct Peb32 {
    pub address: VirtAddr,
    pub image_base_address: DiagnosticValue<VirtAddr>,
    /// The `_PEB_LDR_DATA32` address.
    pub ldr: DiagnosticValue<VirtAddr>,
    /// The 32-bit process parameters' address.
    pub process_parameters: DiagnosticValue<VirtAddr>,
    /// The decoded 32-bit process parameters.
    pub process_parameters_detail: DiagnosticValue<ProcessParameters>,
    /// The default heap.
    pub process_heap: DiagnosticValue<VirtAddr>,
    pub number_of_heaps: DiagnosticValue<u64>,
    /// The heap pointer array.
    pub process_heaps: DiagnosticValue<VirtAddr>,
    /// `BeingDebugged`: nonzero while a user-mode debugger is attached.
    pub being_debugged: DiagnosticValue<u8>,
    pub os_major_version: DiagnosticValue<u64>,
    pub os_minor_version: DiagnosticValue<u64>,
    pub os_build_number: DiagnosticValue<u64>,
    pub session_id: DiagnosticValue<u64>,
    pub number_of_processors: DiagnosticValue<u64>,
    /// The loader's 32-bit module list heads.
    pub loader_lists: DiagnosticValue<LoaderLists>,
}

/// A thread's `_TEB` (`!teb`). ntoseye reads each field separately.
#[record]
pub struct Teb {
    pub address: VirtAddr,
    pub stack_base: DiagnosticValue<VirtAddr>,
    pub stack_limit: DiagnosticValue<VirtAddr>,
    /// The thread-local storage array.
    pub tls_pointer: DiagnosticValue<VirtAddr>,
    /// The Win32 last error.
    pub last_error_value: DiagnosticValue<u32>,
    /// The last NTSTATUS.
    #[record(hex)]
    pub last_status_value: DiagnosticValue<u32>,
    pub count_of_owned_critical_sections: DiagnosticValue<u32>,
    /// The process's `_PEB`.
    pub peb: DiagnosticValue<VirtAddr>,
    /// `WowTebOffset`: the byte offset to the WOW64 `_TEB32`, or 0 if there
    /// is no `_TEB32`.
    pub wow_teb_offset: DiagnosticValue<i32>,
    /// `WOW32Reserved`: the WOW64 transition thunk.
    pub wow64_reserved: DiagnosticValue<VirtAddr>,
    /// The active activation context, or `None` if there is no active
    /// context.
    pub activation_context: DiagnosticValue<Option<VirtAddr>>,
    pub client_id_unique_process: DiagnosticValue<VirtAddr>,
    pub client_id_unique_thread: DiagnosticValue<VirtAddr>,
    /// The WOW64 `_TEB32`. `None` for a native thread.
    pub teb32: Option<Teb32>,
}

/// A WOW64 thread's 32-bit `_TEB32`. ntoseye reads each field separately.
#[record]
pub struct Teb32 {
    pub address: VirtAddr,
    pub stack_base: DiagnosticValue<VirtAddr>,
    pub stack_limit: DiagnosticValue<VirtAddr>,
    /// The thread-local storage array.
    pub tls_pointer: DiagnosticValue<VirtAddr>,
    /// The Win32 last error.
    pub last_error_value: DiagnosticValue<u32>,
    /// The last NTSTATUS.
    #[record(hex)]
    pub last_status_value: DiagnosticValue<u32>,
    pub count_of_owned_critical_sections: DiagnosticValue<u32>,
    /// The process's `_PEB32`.
    pub peb: DiagnosticValue<VirtAddr>,
    pub client_id_unique_process: DiagnosticValue<VirtAddr>,
    pub client_id_unique_thread: DiagnosticValue<VirtAddr>,
}

/// One module on a process's loader list (`!dlls`).
#[record]
pub struct LoaderModule {
    /// The full path.
    pub name: String,
    /// The file name.
    pub short_name: String,
    pub base_address: VirtAddr,
    /// The image size in bytes.
    pub size: u32,
    /// Whether the module is on the WOW64 (32-bit) loader list.
    pub is_32bit: bool,
    /// The entry point. `None` if the loader entry has no entry point or
    /// ntoseye cannot read it.
    pub entry_point: Option<VirtAddr>,
    /// The link timestamp from the PE header. `None` if ntoseye cannot read
    /// the header.
    #[record(hex)]
    pub time_date_stamp: Option<u32>,
    /// The checksum from the PE header. `None` if ntoseye cannot read the
    /// header.
    #[record(hex)]
    pub checksum: Option<u32>,
    /// The file version from the version resource. `None` if ntoseye cannot
    /// read it.
    pub file_version: Option<String>,
    /// The product version from the version resource. `None` if ntoseye
    /// cannot read it.
    pub product_version: Option<String>,
}

/// How a process's native and WOW64 loader-list walks ended.
#[record]
pub struct LoaderTerminations {
    pub termination: ListEnd,
    /// `None` for a native process.
    pub wow64_termination: Option<ListEnd>,
}

/// A thread's Win32 last error and last NTSTATUS (`!gle`).
#[record]
pub struct LastError {
    /// The `_TEB` that ntoseye read.
    pub teb: VirtAddr,
    pub last_error_value: DiagnosticValue<u32>,
    /// The symbolic name of the error, or `None` if the name is unknown.
    pub last_error_name: DiagnosticValue<Option<String>>,
    #[record(hex)]
    pub last_status_value: DiagnosticValue<u32>,
    /// The symbolic name of the status, or `None` if the name is unknown.
    pub last_status_name: DiagnosticValue<Option<String>>,
    /// The values from the WOW64 `_TEB32`. `None` for a native thread.
    pub teb32: Option<LastError32>,
}

/// A WOW64 thread's 32-bit last error and last NTSTATUS.
#[record]
pub struct LastError32 {
    /// The `_TEB32` that ntoseye read.
    pub teb: VirtAddr,
    pub last_error_value: DiagnosticValue<u32>,
    /// The symbolic name of the error, or `None` if the name is unknown.
    pub last_error_name: DiagnosticValue<Option<String>>,
    #[record(hex)]
    pub last_status_value: DiagnosticValue<u32>,
    /// The symbolic name of the status, or `None` if the name is unknown.
    pub last_status_name: DiagnosticValue<Option<String>>,
}

/// The number of bytes that ntoseye identifies as known kernel self-patches,
/// by kind.
#[record]
pub struct ImageSelfPatchCounts {
    pub import_optimization: u64,
    pub retpoline: u64,
    /// `KiPatchSelf` / JMP thunks.
    pub ki_patch_self: u64,
    /// Relocated addresses of the kernel VA regions that the kernel moves at
    /// boot.
    pub region_rebase: u64,
    pub total: u64,
}

/// The comparison of one executable section with the cached image.
#[record]
pub struct ImageSectionCheck {
    pub name: String,
    #[record(hex)]
    pub rva: u32,
    /// The number of mismatched bytes, without known self-patches.
    pub genuine_mismatches: u64,
    /// The number of mismatched bytes, with known self-patches.
    pub total_mismatches: u64,
    pub self_patches: ImageSelfPatchCounts,
    /// Whether ntoseye skipped the comparison of this section.
    pub skipped: bool,
    /// The reason for the skip. `None` if ntoseye compared the section.
    pub skip_reason: Option<String>,
    /// The reason that ntoseye could not read the section memory. `None` if
    /// the read succeeded.
    pub unavailable: Option<String>,
}

/// A contiguous RVA range of mismatched bytes.
#[record]
pub struct ImageMismatchRange {
    #[record(hex)]
    pub start: u64,
    /// The end, exclusive.
    #[record(hex)]
    pub end: u64,
    /// The size in bytes.
    pub size: u64,
}

/// A contiguous RVA range that ntoseye identifies as one kind of kernel
/// self-patch.
#[record]
pub struct ImageSelfPatchRange {
    #[record(hex)]
    pub start: u64,
    /// The end, exclusive.
    #[record(hex)]
    pub end: u64,
    /// The size in bytes.
    pub size: u64,
    /// `import optimization`, `retpoline`, `KiPatchSelf/JMP thunk`, or
    /// `kernel VA region rebase`.
    pub kind: &'static str,
    /// The function that contains the patch, if a symbol covers it.
    pub function: Option<String>,
}

/// One byte that differs from the cached image.
#[record]
pub struct ImageByteDiff {
    #[record(hex)]
    pub rva: u32,
    /// The byte in the cached image.
    #[record(hex)]
    pub expected: u8,
    /// The byte in memory.
    #[record(hex)]
    pub actual: u8,
    /// The self-patch kind of the byte. `None` for a genuine mismatch.
    pub kind: Option<&'static str>,
}

/// A module's in-memory code, compared with its cached image (`!chkimg`).
/// Each range list has a limit, and its `*_overflow` flag is true if more
/// ranges exist.
#[record]
pub struct ImageCheck {
    /// The full path.
    pub module: String,
    pub short_name: String,
    pub base_address: VirtAddr,
    pub sections: Vec<ImageSectionCheck>,
    /// The number of mismatched bytes, without known self-patches.
    pub genuine_mismatched_bytes: u64,
    /// The number of mismatched bytes, with known self-patches.
    pub total_mismatched_bytes: u64,
    pub self_patches: ImageSelfPatchCounts,
    /// Genuine mismatch ranges.
    pub mismatch_ranges: Vec<ImageMismatchRange>,
    pub mismatch_range_overflow: bool,
    /// Mismatch ranges, with self-patches.
    pub all_mismatch_ranges: Vec<ImageMismatchRange>,
    pub all_mismatch_range_overflow: bool,
    pub self_patch_ranges: Vec<ImageSelfPatchRange>,
    pub self_patch_range_overflow: bool,
    /// Byte-level differences. Empty if you do not request them (`-d`).
    pub byte_diffs: Vec<ImageByteDiff>,
    pub byte_diffs_truncated: bool,
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
        activation_context: detail
            .activation_context
            .map(|value| value.as_ref().copied()),
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
