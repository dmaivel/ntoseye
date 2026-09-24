use std::fs;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::guest::ModuleInfo;
use crate::layout::StructRef;
use crate::ntstatus::{ntstatus_name, win32_error_name};
use crate::pe::{image_base, read_pe_header_page, size_of_image};
use crate::target::{DiagnosticValue, ListTermination, Target};
use crate::types::{Arch, VirtAddr};
use iced_x86::{Code, Decoder, DecoderOptions};
use pelite::{PeView, Wrap};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const MAX_REPORT_RANGES: usize = 64;
const MAX_BYTE_DIFFS: usize = 4096;
const SECTION_READ_CHUNK: usize = 0x1000;

/// A decoded `_UNICODE_STRING` field in `_RTL_USER_PROCESS_PARAMETERS`.
#[derive(Debug, Clone)]
pub struct ProcessParametersDetail {
    pub address: VirtAddr,
    pub command_line: DiagnosticValue<String>,
    pub image_path_name: DiagnosticValue<String>,
    pub current_directory: DiagnosticValue<String>,
    pub dll_path: DiagnosticValue<String>,
    pub window_title: DiagnosticValue<String>,
    pub desktop_info: DiagnosticValue<String>,
    pub shell_info: DiagnosticValue<String>,
    pub runtime_data: DiagnosticValue<String>,
    pub environment: DiagnosticValue<VirtAddr>,
    pub environment_size: DiagnosticValue<u64>,
}

/// One loader list head and its two links.
#[derive(Debug, Clone)]
pub struct LoaderListHead {
    pub address: VirtAddr,
    pub flink: DiagnosticValue<VirtAddr>,
    pub blink: DiagnosticValue<VirtAddr>,
}

/// The three lists rooted in `_PEB_LDR_DATA`.
#[derive(Debug, Clone)]
pub struct LoaderListHeads {
    pub in_load_order: DiagnosticValue<LoaderListHead>,
    pub in_memory_order: DiagnosticValue<LoaderListHead>,
    pub in_initialization_order: DiagnosticValue<LoaderListHead>,
}

/// Native PEB fields, process parameters, and loader-list heads.
#[derive(Debug, Clone)]
pub struct PebDetail {
    pub address: VirtAddr,
    pub image_base_address: DiagnosticValue<VirtAddr>,
    pub ldr: DiagnosticValue<VirtAddr>,
    pub process_parameters: DiagnosticValue<VirtAddr>,
    pub process_parameters_detail: DiagnosticValue<ProcessParametersDetail>,
    pub process_heap: DiagnosticValue<VirtAddr>,
    pub number_of_heaps: DiagnosticValue<u64>,
    pub process_heaps: DiagnosticValue<VirtAddr>,
    pub being_debugged: DiagnosticValue<u8>,
    pub os_major_version: DiagnosticValue<u64>,
    pub os_minor_version: DiagnosticValue<u64>,
    pub os_build_number: DiagnosticValue<u64>,
    pub session_id: DiagnosticValue<u64>,
    pub number_of_processors: DiagnosticValue<u64>,
    pub api_set_map: DiagnosticValue<VirtAddr>,
    pub loader_lists: DiagnosticValue<LoaderListHeads>,
    pub peb32: Option<Peb32Detail>,
}

/// The 32-bit PEB and its 32-bit process-parameter view in a WOW64 process.
#[derive(Debug, Clone)]
pub struct Peb32Detail {
    pub address: VirtAddr,
    pub image_base_address: DiagnosticValue<VirtAddr>,
    pub ldr: DiagnosticValue<VirtAddr>,
    pub process_parameters: DiagnosticValue<VirtAddr>,
    pub process_parameters_detail: DiagnosticValue<ProcessParametersDetail>,
    pub process_heap: DiagnosticValue<VirtAddr>,
    pub number_of_heaps: DiagnosticValue<u64>,
    pub process_heaps: DiagnosticValue<VirtAddr>,
    pub being_debugged: DiagnosticValue<u8>,
    pub os_major_version: DiagnosticValue<u64>,
    pub os_minor_version: DiagnosticValue<u64>,
    pub os_build_number: DiagnosticValue<u64>,
    pub session_id: DiagnosticValue<u64>,
    pub number_of_processors: DiagnosticValue<u64>,
    pub loader_lists: DiagnosticValue<LoaderListHeads>,
}

/// The native fields printed by `!teb`, plus the optional WOW64 TEB.
#[derive(Debug, Clone)]
pub struct TebDetail {
    pub address: VirtAddr,
    pub stack_base: DiagnosticValue<VirtAddr>,
    pub stack_limit: DiagnosticValue<VirtAddr>,
    pub tls_pointer: DiagnosticValue<VirtAddr>,
    pub last_error_value: DiagnosticValue<u32>,
    pub last_status_value: DiagnosticValue<u32>,
    pub count_of_owned_critical_sections: DiagnosticValue<u32>,
    pub peb: DiagnosticValue<VirtAddr>,
    pub wow_teb_offset: DiagnosticValue<i32>,
    pub wow64_reserved: DiagnosticValue<VirtAddr>,
    pub activation_context: DiagnosticValue<Option<VirtAddr>>,
    pub client_id_unique_process: DiagnosticValue<VirtAddr>,
    pub client_id_unique_thread: DiagnosticValue<VirtAddr>,
    pub teb32: Option<Teb32Detail>,
}

/// The 32-bit TEB fields available to a WOW64 thread.
#[derive(Debug, Clone)]
pub struct Teb32Detail {
    pub address: VirtAddr,
    pub stack_base: DiagnosticValue<VirtAddr>,
    pub stack_limit: DiagnosticValue<VirtAddr>,
    pub tls_pointer: DiagnosticValue<VirtAddr>,
    pub last_error_value: DiagnosticValue<u32>,
    pub last_status_value: DiagnosticValue<u32>,
    pub count_of_owned_critical_sections: DiagnosticValue<u32>,
    pub peb: DiagnosticValue<VirtAddr>,
    pub client_id_unique_process: DiagnosticValue<VirtAddr>,
    pub client_id_unique_thread: DiagnosticValue<VirtAddr>,
}

/// One module recovered from a process's loader list.
#[derive(Debug, Clone)]
pub struct LoaderModuleDetail {
    pub name: String,
    pub short_name: String,
    pub base_address: VirtAddr,
    pub size: u32,
    pub is_32bit: bool,
    pub entry_point: Option<VirtAddr>,
    pub time_date_stamp: Option<u32>,
    pub checksum: Option<u32>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
}

/// Loader modules and the termination state of each list walked.
#[derive(Debug, Clone)]
pub struct LoaderModulesDetail {
    pub modules: Vec<LoaderModuleDetail>,
    pub termination: ListTermination,
    pub wow64_termination: Option<ListTermination>,
}

/// Last-error/status values for the selected thread and its WOW64 TEB.
#[derive(Debug, Clone)]
pub struct LastErrorDetail {
    pub teb: VirtAddr,
    pub last_error_value: DiagnosticValue<u32>,
    pub last_error_name: DiagnosticValue<Option<String>>,
    pub last_status_value: DiagnosticValue<u32>,
    pub last_status_name: DiagnosticValue<Option<String>>,
    pub teb32: Option<LastError32Detail>,
}

/// Last-error/status values from the 32-bit TEB of a WOW64 thread.
#[derive(Debug, Clone)]
pub struct LastError32Detail {
    pub teb: VirtAddr,
    pub last_error_value: DiagnosticValue<u32>,
    pub last_error_name: DiagnosticValue<Option<String>>,
    pub last_status_value: DiagnosticValue<u32>,
    pub last_status_name: DiagnosticValue<Option<String>>,
}

/// A kind of known kernel self-patch recognized by `!chkimg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfPatchKind {
    ImportOptimization,
    Retpoline,
    KiPatchSelf,
}

impl SelfPatchKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::ImportOptimization => "import optimization",
            Self::Retpoline => "retpoline",
            Self::KiPatchSelf => "KiPatchSelf/JMP thunk",
        }
    }
}

/// Counts of recognized self-patches by kind.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SelfPatchCounts {
    pub import_optimization: u64,
    pub retpoline: u64,
    pub ki_patch_self: u64,
}

impl SelfPatchCounts {
    pub fn add(&mut self, kind: SelfPatchKind, count: u64) {
        match kind {
            SelfPatchKind::ImportOptimization => self.import_optimization += count,
            SelfPatchKind::Retpoline => self.retpoline += count,
            SelfPatchKind::KiPatchSelf => self.ki_patch_self += count,
        }
    }

    pub fn total(self) -> u64 {
        self.import_optimization
            .saturating_add(self.retpoline)
            .saturating_add(self.ki_patch_self)
    }

    fn add_counts(&mut self, other: Self) {
        self.add(SelfPatchKind::ImportOptimization, other.import_optimization);
        self.add(SelfPatchKind::Retpoline, other.retpoline);
        self.add(SelfPatchKind::KiPatchSelf, other.ki_patch_self);
    }
}

/// A contiguous RVA range of genuine mismatches or known self-patches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MismatchRange {
    pub start: u64,
    pub end: u64,
}

/// A contiguous RVA range identified as one self-patch kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfPatchRange {
    pub start: u64,
    pub end: u64,
    pub kind: SelfPatchKind,
    pub function: Option<String>,
}

/// One bounded expected/actual byte difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteDiff {
    pub rva: u32,
    pub expected: u8,
    pub actual: u8,
    pub kind: Option<SelfPatchKind>,
}

/// Results for one checked executable section.
#[derive(Debug, Clone)]
pub struct ImageSectionResult {
    pub name: String,
    pub rva: u32,
    pub genuine_mismatches: u64,
    pub total_mismatches: u64,
    pub self_patches: SelfPatchCounts,
    pub skipped: bool,
    pub skip_reason: Option<String>,
    pub unavailable: Option<String>,
}

/// Cached-image comparison results. `total_mismatched_bytes` includes known
/// self-patches; `genuine_mismatched_bytes` excludes them so the REPL can apply
/// `-nospec` while retaining both views for structured callers.
#[derive(Debug, Clone)]
pub struct ImageCheckDetail {
    pub module: String,
    pub short_name: String,
    pub base_address: VirtAddr,
    pub sections: Vec<ImageSectionResult>,
    pub genuine_mismatched_bytes: u64,
    pub total_mismatched_bytes: u64,
    pub self_patches: SelfPatchCounts,
    pub mismatch_ranges: Vec<MismatchRange>,
    pub mismatch_range_overflow: bool,
    pub all_mismatch_ranges: Vec<MismatchRange>,
    pub all_mismatch_range_overflow: bool,
    pub self_patch_ranges: Vec<SelfPatchRange>,
    pub self_patch_range_overflow: bool,
    pub byte_diffs: Vec<ByteDiff>,
    pub byte_diffs_truncated: bool,
}

#[derive(Debug)]
struct CheckSection {
    name: String,
    rva: u32,
    expected: Vec<u8>,
    discardable: bool,
}

#[derive(Debug, Default)]
struct SectionCheckResult {
    genuine: u64,
    self_patches: SelfPatchCounts,
    skipped: bool,
    skip_reason: Option<&'static str>,
    unavailable: Option<String>,
    mismatch_ranges: Vec<MismatchRange>,
    mismatch_range_overflow: bool,
    all_mismatch_ranges: Vec<MismatchRange>,
    all_mismatch_range_overflow: bool,
    self_patch_ranges: Vec<SelfPatchRange>,
    self_patch_range_overflow: bool,
    diffs: Vec<ByteDiff>,
    diff_overflow: bool,
}

#[derive(Debug)]
struct SelfPatchMatch {
    kind: SelfPatchKind,
    function: Option<String>,
}

fn diagnostic<T>(result: Result<T>) -> DiagnosticValue<T> {
    DiagnosticValue::from_result(result)
}

fn unavailable<T>(error: &str) -> DiagnosticValue<T> {
    DiagnosticValue::Unavailable(error.to_string())
}

fn attached_dtb(target: &Target) -> Result<u64> {
    target
        .attached_process()
        .map(|process| process.dtb)
        .ok_or_else(|| Error::DebugInfo("this command requires an attached user process".into()))
}

fn selected_thread_dtb(target: &Target, attached_dtb: u64) -> Result<u64> {
    let Some(thread) = target.windows_thread_selection.as_ref() else {
        return Ok(attached_dtb);
    };
    target.thread_process_dtb(thread).ok_or_else(|| {
        Error::DebugInfo(format!(
            "selected Windows thread's owning process DTB is unavailable; refusing to read its TEB through attached DTB {attached_dtb:#x}"
        ))
    })
}

fn teb32_address(teb: VirtAddr, wow_teb_offset: Option<i32>) -> Option<VirtAddr> {
    let offset = i64::from(wow_teb_offset.filter(|offset| *offset != 0)?);
    Some(VirtAddr(teb.0.wrapping_add_signed(offset)))
}

fn read_tib_pointer(teb: &StructRef<'_>, field: &str) -> Result<VirtAddr> {
    teb.embedded("NtTib")?.read_pointer(field)
}

fn read_unicode_or_empty(record: &StructRef<'_>, field: &str) -> DiagnosticValue<String> {
    diagnostic(record.unicode_string(field))
}

fn decode_process_parameters(
    record: &StructRef<'_>,
    environment_size: Result<u64>,
) -> ProcessParametersDetail {
    let current_directory = record
        .embedded("CurrentDirectory")
        .and_then(|directory| directory.unicode_string("DosPath"))
        .or_else(|_| record.unicode_string("CurrentDirectory"));
    ProcessParametersDetail {
        address: record.addr(),
        command_line: read_unicode_or_empty(record, "CommandLine"),
        image_path_name: read_unicode_or_empty(record, "ImagePathName"),
        current_directory: diagnostic(current_directory),
        dll_path: read_unicode_or_empty(record, "DllPath"),
        window_title: read_unicode_or_empty(record, "WindowTitle"),
        desktop_info: read_unicode_or_empty(record, "DesktopInfo"),
        shell_info: read_unicode_or_empty(record, "ShellInfo"),
        runtime_data: read_unicode_or_empty(record, "RuntimeData"),
        environment: diagnostic(record.read_pointer("Environment")),
        environment_size: diagnostic(environment_size),
    }
}

fn read_loader_list_head(ldr: &StructRef<'_>, field: &str) -> DiagnosticValue<LoaderListHead> {
    match ldr.embedded(field) {
        Ok(head) => DiagnosticValue::Available(LoaderListHead {
            address: head.addr(),
            flink: diagnostic(head.read_pointer("Flink")),
            blink: diagnostic(head.read_pointer("Blink")),
        }),
        Err(error) => DiagnosticValue::Unavailable(error.to_string()),
    }
}

fn read_loader_list_heads(ldr: &StructRef<'_>) -> LoaderListHeads {
    LoaderListHeads {
        in_load_order: read_loader_list_head(ldr, "InLoadOrderModuleList"),
        in_memory_order: read_loader_list_head(ldr, "InMemoryOrderModuleList"),
        in_initialization_order: read_loader_list_head(ldr, "InInitializationOrderModuleList"),
    }
}

fn unavailable_loader_lists(error: impl ToString) -> DiagnosticValue<LoaderListHeads> {
    DiagnosticValue::Unavailable(error.to_string())
}

fn loader_module_detail(module: ModuleInfo) -> LoaderModuleDetail {
    LoaderModuleDetail {
        name: module.name,
        short_name: module.short_name,
        base_address: module.base_address,
        size: module.size,
        is_32bit: module.is_32bit,
        entry_point: module.entry_point,
        time_date_stamp: module.time_date_stamp,
        checksum: module.checksum,
        file_version: module.file_version,
        product_version: module.product_version,
    }
}

fn make_unavailable_peb32(address: VirtAddr, error: impl ToString) -> Peb32Detail {
    let error = error.to_string();
    Peb32Detail {
        address,
        image_base_address: unavailable(&error),
        ldr: unavailable(&error),
        process_parameters: unavailable(&error),
        process_parameters_detail: unavailable(&error),
        process_heap: unavailable(&error),
        number_of_heaps: unavailable(&error),
        process_heaps: unavailable(&error),
        being_debugged: unavailable(&error),
        os_major_version: unavailable(&error),
        os_minor_version: unavailable(&error),
        os_build_number: unavailable(&error),
        session_id: unavailable(&error),
        number_of_processors: unavailable(&error),
        loader_lists: unavailable(&error),
    }
}

impl Target {
    /// Decode the native `_PEB`, its process-parameter strings/pointers, and
    /// loader-list heads. Each `DiagnosticValue` records the field-specific
    /// layout or memory error when that field is unavailable; a WOW64 PEB is
    /// included when the attached process supplies one and no explicit address
    /// was requested.
    pub fn inspect_peb(&self, address: Option<VirtAddr>) -> Result<PebDetail> {
        let process = self
            .attached_process()
            .ok_or_else(|| Error::DebugInfo("no attached process".into()))?;
        let dtb = process.dtb;
        let peb_address = if let Some(address) = address {
            address
        } else {
            let eprocess = self
                .guest()?
                .ntoskrnl
                .types_in(dtb)
                .struct_at("_EPROCESS", process.eprocess_va)?;
            let peb = eprocess.follow("Peb")?;
            if peb.addr().is_zero() {
                return Err(Error::MissingPEB);
            }
            peb.addr()
        };
        let types = self.guest()?.ntoskrnl.types_in(dtb);
        let peb_ref = types.struct_at("_PEB", peb_address)?.prefetch();

        let image_base_address = diagnostic(peb_ref.read_pointer("ImageBaseAddress"));
        let ldr = diagnostic(peb_ref.read_pointer("Ldr"));
        let process_parameters = diagnostic(peb_ref.read_pointer("ProcessParameters"));
        let process_parameters_detail = match &process_parameters {
            DiagnosticValue::Available(address) if !address.is_zero() => {
                match types.struct_at("_RTL_USER_PROCESS_PARAMETERS", *address) {
                    Ok(record) => {
                        let record = record.prefetch();
                        let environment_size = record.read_field::<u64>("EnvironmentSize");
                        DiagnosticValue::Available(decode_process_parameters(
                            &record,
                            environment_size,
                        ))
                    }
                    Err(error) => DiagnosticValue::Unavailable(error.to_string()),
                }
            }
            DiagnosticValue::Available(_) => {
                DiagnosticValue::Unavailable("pointer is null".to_string())
            }
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
        };
        let loader_lists = match &ldr {
            DiagnosticValue::Available(address) if !address.is_zero() => {
                match types.struct_at("_PEB_LDR_DATA", *address) {
                    Ok(ldr_ref) => DiagnosticValue::Available(read_loader_list_heads(&ldr_ref)),
                    Err(error) => unavailable_loader_lists(error),
                }
            }
            DiagnosticValue::Available(_) => DiagnosticValue::Unavailable("pointer is null".into()),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
        };

        let peb32 = if address.is_none() {
            process.wow64_peb.map(|peb32| self.decode_peb32(dtb, peb32))
        } else {
            None
        };
        Ok(PebDetail {
            address: peb_address,
            image_base_address,
            ldr,
            process_parameters,
            process_parameters_detail,
            process_heap: diagnostic(peb_ref.read_pointer("ProcessHeap")),
            number_of_heaps: diagnostic(peb_ref.read_field::<u32>("NumberOfHeaps").map(u64::from)),
            process_heaps: diagnostic(peb_ref.read_pointer("ProcessHeaps")),
            being_debugged: diagnostic(peb_ref.read_field::<u8>("BeingDebugged")),
            os_major_version: diagnostic(
                peb_ref.read_field::<u32>("OSMajorVersion").map(u64::from),
            ),
            os_minor_version: diagnostic(
                peb_ref.read_field::<u32>("OSMinorVersion").map(u64::from),
            ),
            os_build_number: diagnostic(peb_ref.read_field::<u16>("OSBuildNumber").map(u64::from)),
            session_id: diagnostic(peb_ref.read_field::<u32>("SessionId").map(u64::from)),
            number_of_processors: diagnostic(
                peb_ref
                    .read_field::<u32>("NumberOfProcessors")
                    .map(u64::from),
            ),
            api_set_map: diagnostic(peb_ref.read_pointer("ApiSetMap")),
            loader_lists,
            peb32,
        })
    }

    fn decode_loader_heads32(&self, ldr: VirtAddr) -> DiagnosticValue<LoaderListHeads> {
        let memory = self.process_memory();
        let read_head = |offset: u64| {
            let address = ldr + offset;
            LoaderListHead {
                address,
                flink: diagnostic(memory.read::<u32>(address).map(VirtAddr::from)),
                blink: diagnostic(memory.read::<u32>(address + 4u64).map(VirtAddr::from)),
            }
        };
        DiagnosticValue::Available(LoaderListHeads {
            in_load_order: DiagnosticValue::Available(read_head(0x0c)),
            in_memory_order: DiagnosticValue::Available(read_head(0x14)),
            in_initialization_order: DiagnosticValue::Available(read_head(0x1c)),
        })
    }

    fn decode_peb32(&self, dtb: u64, address: VirtAddr) -> Peb32Detail {
        let types = match self.guest() {
            Ok(guest) => guest.ntoskrnl.types_in(dtb),
            Err(error) => return make_unavailable_peb32(address, error),
        };
        let peb_ref = match types.struct_at("_PEB32", address) {
            Ok(peb_ref) => peb_ref.prefetch(),
            Err(error) => return make_unavailable_peb32(address, error),
        };
        let ldr = diagnostic(peb_ref.read_field::<u32>("Ldr").map(VirtAddr::from));
        let process_parameters = diagnostic(
            peb_ref
                .read_field::<u32>("ProcessParameters")
                .map(VirtAddr::from),
        );
        let process_parameters_detail = match &process_parameters {
            DiagnosticValue::Available(address) if !address.is_zero() => {
                match types.struct_at("ntdll32!_RTL_USER_PROCESS_PARAMETERS", *address) {
                    Ok(record) => {
                        let record = record.prefetch();
                        let environment_size =
                            record.read_field::<u32>("EnvironmentSize").map(u64::from);
                        DiagnosticValue::Available(decode_process_parameters(
                            &record,
                            environment_size,
                        ))
                    }
                    Err(error) => DiagnosticValue::Unavailable(error.to_string()),
                }
            }
            DiagnosticValue::Available(_) => {
                DiagnosticValue::Unavailable("pointer is null".to_string())
            }
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
        };
        let loader_lists = match &ldr {
            DiagnosticValue::Available(address) if !address.is_zero() => {
                self.decode_loader_heads32(*address)
            }
            DiagnosticValue::Available(_) => DiagnosticValue::Unavailable("pointer is null".into()),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
        };
        Peb32Detail {
            address,
            image_base_address: diagnostic(
                peb_ref
                    .read_field::<u32>("ImageBaseAddress")
                    .map(VirtAddr::from),
            ),
            ldr,
            process_parameters,
            process_parameters_detail,
            process_heap: diagnostic(peb_ref.read_field::<u32>("ProcessHeap").map(VirtAddr::from)),
            number_of_heaps: diagnostic(peb_ref.read_field::<u32>("NumberOfHeaps").map(u64::from)),
            process_heaps: diagnostic(
                peb_ref
                    .read_field::<u32>("ProcessHeaps")
                    .map(VirtAddr::from),
            ),
            being_debugged: diagnostic(peb_ref.read_field::<u8>("BeingDebugged")),
            os_major_version: diagnostic(
                peb_ref.read_field::<u32>("OSMajorVersion").map(u64::from),
            ),
            os_minor_version: diagnostic(
                peb_ref.read_field::<u32>("OSMinorVersion").map(u64::from),
            ),
            os_build_number: diagnostic(peb_ref.read_field::<u16>("OSBuildNumber").map(u64::from)),
            session_id: diagnostic(peb_ref.read_field::<u32>("SessionId").map(u64::from)),
            number_of_processors: diagnostic(
                peb_ref
                    .read_field::<u32>("NumberOfProcessors")
                    .map(u64::from),
            ),
            loader_lists,
        }
    }

    /// Decode the selected/default native TEB and its WOW64 companion. The
    /// default address is the selected Windows thread's `teb` pseudo-register;
    /// every independently unreadable field carries its own diagnostic error.
    pub fn inspect_teb(&self, address: Option<VirtAddr>) -> Result<TebDetail> {
        let attached = attached_dtb(self)?;
        let dtb = selected_thread_dtb(self, attached)?;
        let teb_address = match address {
            Some(address) => address,
            None => self
                .current_thread_pseudo_register("teb")
                .filter(|address| *address != 0)
                .map(VirtAddr)
                .ok_or_else(|| {
                    Error::DebugInfo(
                        "current thread has no teb pseudo-register; select a user thread first"
                            .into(),
                    )
                })?,
        };
        let types = self.guest()?.ntoskrnl.types_in(dtb);
        let teb_ref = types.struct_at("_TEB", teb_address)?.prefetch();
        let wow_teb_offset = diagnostic(teb_ref.read_field::<i32>("WowTebOffset"));
        let teb32 = match &wow_teb_offset {
            DiagnosticValue::Available(offset) => teb32_address(teb_address, Some(*offset))
                .map(|address| self.decode_teb32(dtb, address)),
            DiagnosticValue::Unavailable(_) => None,
        };
        Ok(TebDetail {
            address: teb_address,
            stack_base: diagnostic(read_tib_pointer(&teb_ref, "StackBase")),
            stack_limit: diagnostic(read_tib_pointer(&teb_ref, "StackLimit")),
            tls_pointer: diagnostic(
                teb_ref
                    .read_pointer("ThreadLocalStoragePointer")
                    .or_else(|_| teb_ref.read_pointer("TlsPointer")),
            ),
            last_error_value: diagnostic(teb_ref.read_field::<u32>("LastErrorValue")),
            last_status_value: diagnostic(teb_ref.read_field::<u32>("LastStatusValue")),
            count_of_owned_critical_sections: diagnostic(
                teb_ref.read_field::<u32>("CountOfOwnedCriticalSections"),
            ),
            peb: diagnostic(
                teb_ref
                    .read_pointer("ProcessEnvironmentBlock")
                    .or_else(|_| teb_ref.read_pointer("Peb")),
            ),
            wow_teb_offset,
            wow64_reserved: diagnostic(
                teb_ref
                    .read_pointer("Wow32Reserved")
                    .or_else(|_| teb_ref.read_pointer("Wow64Reserved")),
            ),
            activation_context: diagnostic(
                teb_ref
                    .read_pointer("ActivationContextStackPointer")
                    .or_else(|_| teb_ref.read_pointer("ActivationContextStack"))
                    .map(|address| (!address.is_zero()).then_some(address)),
            ),
            client_id_unique_process: diagnostic(
                teb_ref
                    .embedded("ClientId")
                    .and_then(|client| client.read_pointer("UniqueProcess")),
            ),
            client_id_unique_thread: diagnostic(
                teb_ref
                    .embedded("ClientId")
                    .and_then(|client| client.read_pointer("UniqueThread")),
            ),
            teb32,
        })
    }

    fn decode_teb32(&self, dtb: u64, address: VirtAddr) -> Teb32Detail {
        let types = match self.guest() {
            Ok(guest) => guest.ntoskrnl.types_in(dtb),
            Err(error) => return make_unavailable_teb32(address, error),
        };
        let teb_ref = match types.struct_at("_TEB32", address) {
            Ok(teb_ref) => teb_ref.prefetch(),
            Err(error) => return make_unavailable_teb32(address, error),
        };
        Teb32Detail {
            address,
            stack_base: diagnostic(
                teb_ref
                    .embedded("NtTib")
                    .and_then(|tib| tib.read_field::<u32>("StackBase"))
                    .map(VirtAddr::from),
            ),
            stack_limit: diagnostic(
                teb_ref
                    .embedded("NtTib")
                    .and_then(|tib| tib.read_field::<u32>("StackLimit"))
                    .map(VirtAddr::from),
            ),
            tls_pointer: diagnostic(
                teb_ref
                    .read_field::<u32>("ThreadLocalStoragePointer")
                    .or_else(|_| teb_ref.read_field("TlsPointer"))
                    .map(VirtAddr::from),
            ),
            last_error_value: diagnostic(teb_ref.read_field::<u32>("LastErrorValue")),
            last_status_value: diagnostic(teb_ref.read_field::<u32>("LastStatusValue")),
            count_of_owned_critical_sections: diagnostic(
                teb_ref.read_field::<u32>("CountOfOwnedCriticalSections"),
            ),
            peb: diagnostic(
                teb_ref
                    .read_field::<u32>("ProcessEnvironmentBlock")
                    .or_else(|_| teb_ref.read_field("Peb"))
                    .map(VirtAddr::from),
            ),
            client_id_unique_process: diagnostic(
                teb_ref
                    .embedded("ClientId")
                    .and_then(|client| client.read_field::<u32>("UniqueProcess"))
                    .map(VirtAddr::from),
            ),
            client_id_unique_thread: diagnostic(
                teb_ref
                    .embedded("ClientId")
                    .and_then(|client| client.read_field::<u32>("UniqueThread"))
                    .map(VirtAddr::from),
            ),
        }
    }

    /// Decode the selected thread's Win32 last-error and NT status values,
    /// retaining symbolic names when known and per-value errors otherwise.
    pub fn last_error(&self) -> Result<LastErrorDetail> {
        let teb = self.inspect_teb(None)?;
        let last_error_name = error_name(&teb.last_error_value, win32_error_name);
        let last_status_name = error_name(&teb.last_status_value, ntstatus_name);
        let teb32 = teb.teb32.map(|teb32| LastError32Detail {
            teb: teb32.address,
            last_error_name: error_name(&teb32.last_error_value, win32_error_name),
            last_error_value: teb32.last_error_value,
            last_status_name: error_name(&teb32.last_status_value, ntstatus_name),
            last_status_value: teb32.last_status_value,
        });
        Ok(LastErrorDetail {
            teb: teb.address,
            last_error_value: teb.last_error_value,
            last_error_name,
            last_status_value: teb.last_status_value,
            last_status_name,
            teb32,
        })
    }

    /// Walk the attached process's native and (when present) WOW64 loader
    /// lists, bounded at 1000 entries and reporting list termination rather
    /// than hiding a partial/corrupt walk. `containing` filters after the two
    /// lists are merged, matching `!dlls -c`.
    pub fn loader_modules(&self, containing: Option<VirtAddr>) -> Result<LoaderModulesDetail> {
        let process = self
            .attached_process()
            .ok_or_else(|| {
                Error::DebugInfo("this command requires an attached user process".into())
            })?
            .clone();
        let detail = self.guest()?.process_modules_detail(&process)?;
        let modules = detail
            .modules
            .into_iter()
            .filter(|module| containing.is_none_or(|address| module.contains_address(address)))
            .map(loader_module_detail)
            .collect();
        Ok(LoaderModulesDetail {
            modules,
            termination: detail.termination,
            wow64_termination: detail.wow64_termination,
        })
    }

    /// Compare executable cached-image sections with the loaded module. Both
    /// genuine mismatches and recognized kernel self-patches are returned;
    /// `include_diffs` controls only the bounded byte-diff collection, while
    /// unavailable/paged-out sections retain their reason in the result.
    pub fn check_image(&self, module: &str, include_diffs: bool) -> Result<ImageCheckDetail> {
        let mut modules = self.modules()?;
        if find_module(&modules, module).is_none()
            && self.attached_process().is_some()
            && let Ok(kernel_modules) = self.kernel_modules()
        {
            modules.extend(kernel_modules);
        }
        let module_info = find_module(&modules, module)
            .cloned()
            .ok_or_else(|| Error::DebugInfo(format!("module '{module}' was not found")))?;
        let (timestamp, size) = module_identity(self, &module_info)?;
        let cached_path = self
            .symbols
            .ensure_module_image_on_disk(&module_info.name, timestamp, size)
            .map_err(|error| {
                Error::DebugInfo(format!(
                    "cached image for {} is unavailable: {error}; run `.reload {}` (the symbol pipeline downloads images on demand)",
                    module_info.name, module_info.short_name
                ))
            })?;
        let bytes = fs::read(&cached_path).map_err(|error| {
            Error::DebugInfo(format!(
                "failed to read cached image {}: {error}",
                cached_path.display()
            ))
        })?;
        let view = PeView::from_bytes(&bytes).map_err(|error| {
            Error::DebugInfo(format!(
                "cached image {} is not a valid PE: {error}",
                cached_path.display()
            ))
        })?;
        let mut sections = build_check_sections(&view, &bytes);
        if sections.is_empty() {
            return Ok(ImageCheckDetail {
                module: module_info.name,
                short_name: module_info.short_name,
                base_address: module_info.base_address,
                sections: Vec::new(),
                genuine_mismatched_bytes: 0,
                total_mismatched_bytes: 0,
                self_patches: SelfPatchCounts::default(),
                mismatch_ranges: Vec::new(),
                mismatch_range_overflow: false,
                all_mismatch_ranges: Vec::new(),
                all_mismatch_range_overflow: false,
                self_patch_ranges: Vec::new(),
                self_patch_range_overflow: false,
                byte_diffs: Vec::new(),
                byte_diffs_truncated: false,
            });
        }
        apply_relocations(&view, &bytes, module_info.base_address.0, &mut sections);
        let allow_kernel_self_patches = is_kernel_self_patch_module(&module_info);
        let preferred_base = image_base(&view);
        let mut section_results = Vec::with_capacity(sections.len());
        let mut genuine_total = 0u64;
        let mut total = 0u64;
        let mut self_patch_total = SelfPatchCounts::default();
        let mut ranges = Vec::new();
        let mut range_overflow = false;
        let mut all_ranges = Vec::new();
        let mut all_range_overflow = false;
        let mut self_patch_ranges = Vec::new();
        let mut self_patch_range_overflow = false;
        let mut diffs = Vec::new();
        let mut diff_overflow = false;
        for section in &sections {
            let result = self.compare_section(
                section,
                preferred_base,
                &module_info,
                allow_kernel_self_patches,
                include_diffs,
            );
            let section_total = result.genuine.saturating_add(result.self_patches.total());
            genuine_total = genuine_total.saturating_add(result.genuine);
            total = total.saturating_add(section_total);
            self_patch_total.add_counts(result.self_patches);
            for range in &result.mismatch_ranges {
                push_mismatch_range(&mut ranges, &mut range_overflow, range.start, range.end);
            }
            range_overflow |= result.mismatch_range_overflow;
            for range in &result.all_mismatch_ranges {
                push_mismatch_range(
                    &mut all_ranges,
                    &mut all_range_overflow,
                    range.start,
                    range.end,
                );
            }
            all_range_overflow |= result.all_mismatch_range_overflow;
            for range in &result.self_patch_ranges {
                push_self_patch_range(
                    &mut self_patch_ranges,
                    &mut self_patch_range_overflow,
                    range.start,
                    range.end,
                    range.kind,
                    range.function.clone(),
                );
            }
            self_patch_range_overflow |= result.self_patch_range_overflow;
            for diff in result.diffs {
                if diffs.len() < MAX_BYTE_DIFFS {
                    diffs.push(diff);
                } else {
                    diff_overflow = true;
                }
            }
            section_results.push(ImageSectionResult {
                name: section.name.clone(),
                rva: section.rva,
                genuine_mismatches: result.genuine,
                total_mismatches: section_total,
                self_patches: result.self_patches,
                skipped: result.skipped,
                skip_reason: result.skip_reason.map(str::to_string),
                unavailable: result.unavailable,
            });
            diff_overflow |= result.diff_overflow;
        }
        Ok(ImageCheckDetail {
            module: module_info.name,
            short_name: module_info.short_name,
            base_address: module_info.base_address,
            sections: section_results,
            genuine_mismatched_bytes: genuine_total,
            total_mismatched_bytes: total,
            self_patches: self_patch_total,
            mismatch_ranges: ranges,
            mismatch_range_overflow: range_overflow,
            all_mismatch_ranges: all_ranges,
            all_mismatch_range_overflow: all_range_overflow,
            self_patch_ranges,
            self_patch_range_overflow,
            byte_diffs: diffs,
            byte_diffs_truncated: diff_overflow,
        })
    }

    fn compare_section(
        &self,
        section: &CheckSection,
        preferred_base: u64,
        module: &ModuleInfo,
        allow_kernel_self_patches: bool,
        include_diffs: bool,
    ) -> SectionCheckResult {
        let base = module.base_address;
        if section.discardable {
            return SectionCheckResult {
                skipped: true,
                skip_reason: Some("discardable"),
                ..SectionCheckResult::default()
            };
        }
        let mut actual = vec![0u8; section.expected.len()];
        let memory = self.process_memory();
        for offset in (0..section.expected.len()).step_by(SECTION_READ_CHUNK) {
            let take = (section.expected.len() - offset).min(SECTION_READ_CHUNK);
            let address = base + section.rva as u64 + offset as u64;
            if let Err(error) = memory.read_bytes(address, &mut actual[offset..offset + take]) {
                if is_skippable_section_read_error(&error) {
                    return SectionCheckResult {
                        skipped: true,
                        skip_reason: Some("paged out"),
                        ..SectionCheckResult::default()
                    };
                }
                return SectionCheckResult {
                    unavailable: Some(error.to_string()),
                    ..SectionCheckResult::default()
                };
            }
        }
        let mut result = SectionCheckResult::default();
        let mut offset = 0usize;
        let bitness = self.code_bitness(base + section.rva as u64);
        while offset < section.expected.len() {
            let instruction_len = match self.arch() {
                Arch::Amd64 => expected_instruction_len(
                    &section.expected[offset..],
                    base.0 + section.rva as u64 + offset as u64,
                    bitness,
                ),
                Arch::Arm64 => 4.min(section.expected.len() - offset),
            };
            let end = (offset + instruction_len.max(1)).min(section.expected.len());
            let expected = &section.expected[offset..end];
            let actual = &actual[offset..end];
            if expected != actual {
                let patch = if allow_kernel_self_patches {
                    self.classify_self_patch(
                        section,
                        offset,
                        preferred_base,
                        module,
                        expected,
                        actual,
                    )
                } else {
                    None
                };
                let mut run_start = None;
                for index in 0..expected.len() {
                    if expected[index] == actual[index] {
                        if let Some(start) = run_start.take() {
                            record_mismatch_run(
                                &mut result,
                                patch.as_ref(),
                                section.rva as u64 + offset as u64 + start as u64,
                                section.rva as u64 + offset as u64 + index as u64,
                            );
                        }
                        continue;
                    }
                    if run_start.is_none() {
                        run_start = Some(index);
                    }
                    if include_diffs {
                        if result.diffs.len() < MAX_BYTE_DIFFS {
                            result.diffs.push(ByteDiff {
                                rva: section.rva + (offset + index) as u32,
                                expected: expected[index],
                                actual: actual[index],
                                kind: patch.as_ref().map(|patch| patch.kind),
                            });
                        } else {
                            result.diff_overflow = true;
                        }
                    }
                }
                if let Some(start) = run_start {
                    record_mismatch_run(
                        &mut result,
                        patch.as_ref(),
                        section.rva as u64 + offset as u64 + start as u64,
                        section.rva as u64 + end as u64,
                    );
                }
            }
            offset = end;
        }
        result
    }

    fn classify_self_patch(
        &self,
        section: &CheckSection,
        offset: usize,
        preferred_base: u64,
        module: &ModuleInfo,
        expected: &[u8],
        actual: &[u8],
    ) -> Option<SelfPatchMatch> {
        let base = module.base_address;
        if expected.len() == 6
            && actual.len() == 6
            && (expected.starts_with(&[0xff, 0x15]) || expected.starts_with(&[0xff, 0x25]))
            && actual[0] == if expected[1] == 0x15 { 0xe8 } else { 0xe9 }
            && actual[5] == 0x90
        {
            return Some(SelfPatchMatch {
                kind: SelfPatchKind::ImportOptimization,
                function: self.self_patch_function_note(base, section.rva, offset),
            });
        }
        if expected.len() == 5
            && actual.len() == 5
            && expected[0] == actual[0]
            && matches!(expected[0], 0xe8 | 0xe9)
            && let (Some(expected_target), Some(actual_target)) = (
                rel32_target(
                    preferred_base
                        .wrapping_add(section.rva as u64)
                        .wrapping_add(offset as u64),
                    expected,
                ),
                rel32_target(
                    base.0
                        .wrapping_add(section.rva as u64)
                        .wrapping_add(offset as u64),
                    actual,
                ),
            )
        {
            let expected_target =
                rebase_module_target(expected_target, preferred_base, base.0, module.size);
            let expected_name = self.closest_symbol_name(expected_target);
            let actual_name = self.closest_symbol_name(actual_target);
            let kind = if is_import_optimization_target(actual_name.as_deref())
                || is_import_optimization_target(expected_name.as_deref())
            {
                Some(SelfPatchKind::ImportOptimization)
            } else if is_retpoline_target(actual_name.as_deref())
                || is_retpoline_target(expected_name.as_deref())
            {
                Some(SelfPatchKind::Retpoline)
            } else if is_patch_target(actual_name.as_deref())
                || is_patch_target(expected_name.as_deref())
            {
                Some(SelfPatchKind::KiPatchSelf)
            } else {
                None
            };
            if let Some(kind) = kind {
                return Some(SelfPatchMatch {
                    kind,
                    function: self.self_patch_function_note(base, section.rva, offset),
                });
            }
        }
        None
    }

    fn closest_symbol_name(&self, address: u64) -> Option<String> {
        self.nearest_symbol_current_context(VirtAddr(address))
            .map(|(_, name, _)| name)
    }

    fn self_patch_function_note(
        &self,
        base: VirtAddr,
        section_rva: u32,
        offset: usize,
    ) -> Option<String> {
        let address = base + section_rva as u64 + offset as u64;
        self.symbols
            .find_closest_symbol_for_address(self.kernel_dtb(), address)
            .and_then(|(module, name, offset)| {
                is_patch_function_name(&name).then(|| format!("{module}!{name}+{offset:#x}"))
            })
    }
}

fn make_unavailable_teb32(address: VirtAddr, error: impl ToString) -> Teb32Detail {
    let error = error.to_string();
    Teb32Detail {
        address,
        stack_base: unavailable(&error),
        stack_limit: unavailable(&error),
        tls_pointer: unavailable(&error),
        last_error_value: unavailable(&error),
        last_status_value: unavailable(&error),
        count_of_owned_critical_sections: unavailable(&error),
        peb: unavailable(&error),
        client_id_unique_process: unavailable(&error),
        client_id_unique_thread: unavailable(&error),
    }
}

fn error_name(
    value: &DiagnosticValue<u32>,
    lookup: fn(u32) -> Option<&'static str>,
) -> DiagnosticValue<Option<String>> {
    match value {
        DiagnosticValue::Available(value) => {
            DiagnosticValue::Available(lookup(*value).map(str::to_string))
        }
        DiagnosticValue::Unavailable(error) => DiagnosticValue::Unavailable(error.clone()),
    }
}

fn record_mismatch_run(
    result: &mut SectionCheckResult,
    patch: Option<&SelfPatchMatch>,
    start: u64,
    end: u64,
) {
    let count = end.saturating_sub(start);
    if count == 0 {
        return;
    }
    push_mismatch_range(
        &mut result.all_mismatch_ranges,
        &mut result.all_mismatch_range_overflow,
        start,
        end,
    );
    if let Some(patch) = patch {
        result.self_patches.add(patch.kind, count);
        push_self_patch_range(
            &mut result.self_patch_ranges,
            &mut result.self_patch_range_overflow,
            start,
            end,
            patch.kind,
            patch.function.clone(),
        );
    } else {
        result.genuine = result.genuine.saturating_add(count);
        push_mismatch_range(
            &mut result.mismatch_ranges,
            &mut result.mismatch_range_overflow,
            start,
            end,
        );
    }
}

fn push_mismatch_range(ranges: &mut Vec<MismatchRange>, overflow: &mut bool, start: u64, end: u64) {
    if let Some(last) = ranges.last_mut()
        && last.end == start
    {
        last.end = end;
        return;
    }
    if ranges.len() < MAX_REPORT_RANGES {
        ranges.push(MismatchRange { start, end });
    } else {
        *overflow = true;
    }
}

fn push_self_patch_range(
    ranges: &mut Vec<SelfPatchRange>,
    overflow: &mut bool,
    start: u64,
    end: u64,
    kind: SelfPatchKind,
    function: Option<String>,
) {
    if let Some(last) = ranges.last_mut()
        && last.kind == kind
        && last.end == start
        && last.function == function
    {
        last.end = end;
        return;
    }
    if ranges.len() < MAX_REPORT_RANGES {
        ranges.push(SelfPatchRange {
            start,
            end,
            kind,
            function,
        });
    } else {
        *overflow = true;
    }
}

fn is_kernel_self_patch_module(module: &ModuleInfo) -> bool {
    module.short_name.eq_ignore_ascii_case("nt")
        || module.name.rsplit(['\\', '/']).next().is_some_and(|name| {
            name.eq_ignore_ascii_case("ntoskrnl.exe")
                || name.to_ascii_lowercase().starts_with("ntkrnl")
        })
}

fn is_skippable_section_read_error(error: &Error) -> bool {
    matches!(
        error,
        Error::BadVirtualAddress(_)
            | Error::PartialRead(_)
            | Error::AddressNotInDump(_)
            | Error::BadPhysicalAddress(_)
    )
}

fn expected_instruction_len(bytes: &[u8], address: u64, bitness: u32) -> usize {
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.code() == Code::INVALID || instruction.len() == 0 {
        1
    } else {
        instruction.len().min(bytes.len())
    }
}

fn rel32_target(address: u64, bytes: &[u8]) -> Option<u64> {
    (bytes.len() >= 5 && matches!(bytes[0], 0xe8 | 0xe9)).then(|| {
        let displacement = i32::from_le_bytes(bytes[1..5].try_into().unwrap());
        address
            .wrapping_add(5)
            .wrapping_add_signed(i64::from(displacement))
    })
}

fn rebase_module_target(address: u64, preferred_base: u64, actual_base: u64, size: u32) -> u64 {
    let Some(offset) = address.checked_sub(preferred_base) else {
        return address;
    };
    if offset < u64::from(size) {
        actual_base.wrapping_add(offset)
    } else {
        address
    }
}

fn symbol_leaf(name: &str) -> &str {
    name.rsplit_once('!').map(|(_, name)| name).unwrap_or(name)
}

fn is_import_optimization_target(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    let name = symbol_leaf(name).to_ascii_lowercase();
    name.contains("__memset_spec")
        || name.contains("__memcpy_spec")
        || name.contains("__memmove_spec")
        || name.contains("kecopypagentmfence")
}

fn is_retpoline_target(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    let name = symbol_leaf(name).to_ascii_lowercase();
    name.contains("__guard_dispatch_icall")
        || name.contains("__guard_retpoline_")
        || name.contains("guard_dispatch_icall")
        || name.contains("guard_retpoline")
        || name.contains("cfgdispatchusercalltarget")
}

fn is_patch_function_name(name: &str) -> bool {
    let name = symbol_leaf(name).to_ascii_lowercase();
    (name.starts_with("ki") && name.contains("patch")) || name.starts_with("expkernelpatch")
}

fn is_patch_target(name: Option<&str>) -> bool {
    let Some(name) = name else {
        return false;
    };
    let name = symbol_leaf(name);
    is_patch_function_name(name) || name.to_ascii_lowercase().contains("jmpthunk")
}

fn find_module<'a>(modules: &'a [ModuleInfo], query: &str) -> Option<&'a ModuleInfo> {
    let query = query.to_ascii_lowercase();
    modules.iter().find(|module| {
        module.short_name.eq_ignore_ascii_case(&query)
            || module.name.eq_ignore_ascii_case(&query)
            || module
                .name
                .rsplit(['\\', '/'])
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(&query))
    })
}

fn module_identity(target: &Target, module: &ModuleInfo) -> Result<(u32, u32)> {
    if let Some(timestamp) = module.time_date_stamp
        && timestamp != 0
        && module.size != 0
    {
        return Ok((timestamp, module.size));
    }
    let memory = target.process_memory();
    let header = read_pe_header_page(module.base_address, &memory)?;
    let view = PeView::from_bytes(&header)?;
    Ok((
        module
            .time_date_stamp
            .unwrap_or(view.file_header().TimeDateStamp),
        if module.size == 0 {
            size_of_image(&view)
        } else {
            module.size
        },
    ))
}

fn section_is_checked(name: &str, characteristics: u32) -> bool {
    if characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    let normalized = upper.trim_start_matches('.');
    normalized == "TEXT" || normalized.starts_with("PAGE") || normalized.starts_with("INIT")
}

fn build_check_sections(view: &PeView<'_>, image: &[u8]) -> Vec<CheckSection> {
    let image_size = size_of_image(view);
    let mut sections = Vec::new();
    for section in view.section_headers() {
        let name = section
            .name()
            .ok()
            .map(|name| name.trim_matches('\0').to_string())
            .unwrap_or_else(|| "<unnamed>".into());
        if !section_is_checked(&name, section.Characteristics) {
            continue;
        }
        let size = section.VirtualSize.max(section.SizeOfRawData);
        let max_size = image_size.saturating_sub(section.VirtualAddress);
        let size = usize::try_from(size.min(max_size)).unwrap_or(0);
        if size == 0 {
            continue;
        }
        let mut expected = vec![0u8; size];
        let raw_start = section.PointerToRawData as usize;
        let raw_size = usize::try_from(section.SizeOfRawData)
            .unwrap_or(0)
            .min(size);
        if raw_start < image.len() {
            let available = (image.len() - raw_start).min(raw_size);
            expected[..available].copy_from_slice(&image[raw_start..raw_start + available]);
        }
        sections.push(CheckSection {
            name,
            rva: section.VirtualAddress,
            expected,
            discardable: section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0,
        });
    }
    sections
}

fn apply_relocations(
    view: &PeView<'_>,
    image: &[u8],
    actual_base: u64,
    sections: &mut [CheckSection],
) {
    let preferred_base = image_base(view);
    let delta = actual_base.wrapping_sub(preferred_base) as i64;
    if delta == 0 {
        return;
    }
    let Some(directory) = view.data_directory().get(IMAGE_DIRECTORY_ENTRY_BASERELOC) else {
        return;
    };
    let size_of_headers = match view.optional_header() {
        Wrap::T32(header) => header.SizeOfHeaders,
        Wrap::T64(header) => header.SizeOfHeaders,
    };
    let rva_to_raw = |rva: u32| -> Option<usize> {
        if rva < size_of_headers {
            return Some(rva as usize);
        }
        view.section_headers().iter().find_map(|section| {
            let size = section.VirtualSize.max(section.SizeOfRawData);
            (rva >= section.VirtualAddress && rva < section.VirtualAddress.saturating_add(size))
                .then(|| {
                    (section.PointerToRawData as usize)
                        .checked_add((rva - section.VirtualAddress) as usize)
                })
                .flatten()
        })
    };
    let Some(mut cursor) = rva_to_raw(directory.VirtualAddress) else {
        return;
    };
    let end = cursor
        .checked_add(directory.Size as usize)
        .unwrap_or(image.len())
        .min(image.len());
    while cursor + 8 <= end {
        let page = u32::from_le_bytes(image[cursor..cursor + 4].try_into().unwrap());
        let block_size =
            u32::from_le_bytes(image[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        if block_size < 8 || block_size > end - cursor {
            break;
        }
        let count = (block_size - 8) / 2;
        for index in 0..count {
            let offset = cursor + 8 + index * 2;
            let entry = u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap());
            let kind = entry >> 12;
            let rva = page.saturating_add(u32::from(entry & 0x0fff));
            let (width, apply) = match kind {
                IMAGE_REL_BASED_DIR64 => (8usize, true),
                IMAGE_REL_BASED_HIGHLOW => (4usize, true),
                _ => (0usize, false),
            };
            if !apply {
                continue;
            }
            for section in sections.iter_mut() {
                let Some(offset) = rva
                    .checked_sub(section.rva)
                    .and_then(|offset| usize::try_from(offset).ok())
                else {
                    continue;
                };
                if offset + width > section.expected.len() {
                    continue;
                }
                if width == 8 {
                    let value = u64::from_le_bytes(
                        section.expected[offset..offset + 8].try_into().unwrap(),
                    );
                    section.expected[offset..offset + 8]
                        .copy_from_slice(&value.wrapping_add_signed(delta).to_le_bytes());
                } else {
                    let value = u32::from_le_bytes(
                        section.expected[offset..offset + 4].try_into().unwrap(),
                    );
                    section.expected[offset..offset + 4]
                        .copy_from_slice(&value.wrapping_add(delta as u32).to_le_bytes());
                }
                break;
            }
        }
        cursor += block_size;
    }
}
