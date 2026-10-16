use std::fs;

use crate::error::{Error, Result};
use crate::guest::{
    ModuleInfo, ProcessInfo, ProcessModulesDetail, UNKNOWN_MODULE_NAME, merge_wow64_modules,
    walk_loader_list, walk_loader_list32,
};
use crate::layout::{StructRef, Types};
use crate::memory::MemoryOps;
use crate::ntstatus::{ntstatus_name, win32_error_name};
use crate::pe::{image_base, read_pe_header_page, size_of_image};
use crate::target::{DiagnosticValue, ListTermination, Target, TargetKind};
use crate::types::{Arch, Dtb, VirtAddr};
use iced_x86::{Code, Decoder, DecoderOptions};
use ntoseye_macros::record;
use pelite::{PeView, Wrap};

pub mod address;
pub mod handles;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const MAX_REPORT_RANGES: usize = 64;
const MAX_BYTE_DIFFS: usize = 4096;
const SECTION_READ_CHUNK: usize = 0x1000;

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

/// The modules on a process's loader lists (`!dlls`), and how the native
/// and WOW64 list walks ended.
#[record]
pub struct LoaderModules {
    pub modules: Vec<LoaderModule>,
    pub termination: ListTermination,
    /// `None` for a native process.
    pub wow64_termination: Option<ListTermination>,
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

/// A kind of known kernel self-patch recognized by `!chkimg`: `import
/// optimization`, `retpoline`, `KiPatchSelf/JMP thunk`, or `kernel VA
/// region rebase`.
#[record]
#[derive(Copy, PartialEq, Eq)]
pub enum SelfPatchKind {
    #[record(rename = "import optimization")]
    ImportOptimization,
    Retpoline,
    #[record(rename = "KiPatchSelf/JMP thunk")]
    KiPatchSelf,
    /// A relocated address of a kernel VA region (the PFN database, the
    /// page tables, ...) the kernel moved to a randomized top-level slot at
    /// boot: the image holds the region's old fixed base.
    #[record(rename = "kernel VA region rebase")]
    RegionRebase,
}

impl SelfPatchKind {
    pub const ALL: [Self; 4] = [
        Self::ImportOptimization,
        Self::Retpoline,
        Self::KiPatchSelf,
        Self::RegionRebase,
    ];
}

/// The number of bytes that ntoseye identifies as known kernel self-patches,
/// by kind.
#[record(impl)]
#[derive(Default, Copy, PartialEq, Eq)]
pub struct ImageSelfPatchCounts {
    pub import_optimization: u64,
    pub retpoline: u64,
    /// `KiPatchSelf` / JMP thunks.
    pub ki_patch_self: u64,
    /// Relocated addresses of the kernel VA regions that the kernel moves at
    /// boot.
    pub region_rebase: u64,
}

#[record]
impl ImageSelfPatchCounts {
    /// The bytes of every kind.
    #[record(getter)]
    pub fn total(&self) -> u64 {
        SelfPatchKind::ALL
            .into_iter()
            .fold(0u64, |total, kind| total.saturating_add(self.get(kind)))
    }
}

impl ImageSelfPatchCounts {
    fn slot(&mut self, kind: SelfPatchKind) -> &mut u64 {
        match kind {
            SelfPatchKind::ImportOptimization => &mut self.import_optimization,
            SelfPatchKind::Retpoline => &mut self.retpoline,
            SelfPatchKind::KiPatchSelf => &mut self.ki_patch_self,
            SelfPatchKind::RegionRebase => &mut self.region_rebase,
        }
    }

    pub fn get(mut self, kind: SelfPatchKind) -> u64 {
        *self.slot(kind)
    }

    pub fn add(&mut self, kind: SelfPatchKind, count: u64) {
        let slot = self.slot(kind);
        *slot = slot.saturating_add(count);
    }

    fn add_counts(&mut self, other: Self) {
        for kind in SelfPatchKind::ALL {
            self.add(kind, other.get(kind));
        }
    }
}

/// A contiguous RVA range of mismatched bytes.
#[record(impl)]
#[derive(Copy, PartialEq, Eq)]
pub struct ImageMismatchRange {
    #[record(hex)]
    pub start: u64,
    /// The end, exclusive.
    #[record(hex)]
    pub end: u64,
}

#[record]
impl ImageMismatchRange {
    /// The size in bytes.
    #[record(getter)]
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// A contiguous RVA range that ntoseye identifies as one kind of kernel
/// self-patch.
#[record(impl)]
#[derive(PartialEq, Eq)]
pub struct ImageSelfPatchRange {
    #[record(hex)]
    pub start: u64,
    /// The end, exclusive.
    #[record(hex)]
    pub end: u64,
    pub kind: SelfPatchKind,
    /// The function that contains the patch, if a symbol covers it.
    pub function: Option<String>,
}

#[record]
impl ImageSelfPatchRange {
    /// The size in bytes.
    #[record(getter)]
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// One byte that differs from the cached image.
#[record]
#[derive(Copy, PartialEq, Eq)]
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
    pub kind: Option<SelfPatchKind>,
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
    self_patches: ImageSelfPatchCounts,
    skipped: bool,
    skip_reason: Option<&'static str>,
    unavailable: Option<String>,
    mismatch_ranges: Vec<ImageMismatchRange>,
    mismatch_range_overflow: bool,
    all_mismatch_ranges: Vec<ImageMismatchRange>,
    all_mismatch_range_overflow: bool,
    self_patch_ranges: Vec<ImageSelfPatchRange>,
    self_patch_range_overflow: bool,
    diffs: Vec<ImageByteDiff>,
    diff_overflow: bool,
}

#[derive(Debug)]
struct SelfPatchMatch {
    kind: SelfPatchKind,
    function: Option<String>,
}

/// The process a command given none decodes (see [`Target::current_process`]).
fn current_process(target: &Target) -> Result<ProcessInfo> {
    target.current_process().ok_or_else(|| {
        Error::DebugInfo(
            "no process context: no process owns the current context; select one with .process <pid>"
                .into(),
        )
    })
}

/// The root a TEB is read through: the selected Windows thread's owner's, as
/// the TEB belongs to that thread, else the current process's.
fn teb_dtb(target: &Target) -> Result<u64> {
    match target.windows_thread_selection.as_ref() {
        Some(thread) => target.thread_process_dtb(thread).ok_or_else(|| {
            Error::DebugInfo(
                "the selected Windows thread's owning process is unknown, so its TEB cannot be read"
                    .into(),
            )
        }),
        None => current_process(target).map(|process| process.dtb),
    }
}

fn teb32_address(teb: VirtAddr, wow_teb_offset: Option<i32>) -> Option<VirtAddr> {
    let offset = i64::from(wow_teb_offset.filter(|offset| *offset != 0)?);
    Some(VirtAddr(teb.0.wrapping_add_signed(offset)))
}

/// Where `!peb`, `!teb`, and `!dlls` read and which layouts decode what they
/// read. A kernel target reads through a process's page tables with the
/// kernel's layouts; a user-mode minidump has one address space and no
/// kernel, so its layouts come from the PDB of its own ntdll.
#[derive(Clone, Copy)]
struct UserModeTypes<'a> {
    types: Types<'a>,
    /// The module whose PDB holds the layouts, `None` for the kernel's.
    module: Option<&'static str>,
}

impl<'a> UserModeTypes<'a> {
    /// `name` as this view resolves it: qualified with its module unless it
    /// names one already (`ntdll32!_PEB`).
    fn qualified(self, name: &str) -> String {
        match self.module {
            Some(module) if !name.contains('!') => format!("{module}!{name}"),
            _ => name.to_string(),
        }
    }

    fn struct_at(self, name: &str, address: VirtAddr) -> Result<StructRef<'a>> {
        let name = self.qualified(name);
        self.types
            .struct_at(&name, address)
            .map_err(|error| match (error, self.module) {
                (Error::StructNotFound(_), Some(module)) => Error::DebugInfo(format!(
                    "{name} has no layout: {module}'s PDB is not loaded or does not define it"
                )),
                (error, _) => error,
            })
    }
}

fn read_tib_pointer(teb: &StructRef<'_>, field: &str) -> Result<VirtAddr> {
    teb.embedded("NtTib")?.read_pointer(field)
}

fn read_unicode_or_empty(record: &StructRef<'_>, field: &str) -> DiagnosticValue<String> {
    DiagnosticValue::from_result(record.unicode_string(field))
}

fn decode_process_parameters(
    record: &StructRef<'_>,
    environment_size: Result<u64>,
) -> ProcessParameters {
    let current_directory = record
        .embedded("CurrentDirectory")
        .and_then(|directory| directory.unicode_string("DosPath"))
        .or_else(|_| record.unicode_string("CurrentDirectory"));
    ProcessParameters {
        address: record.addr(),
        command_line: read_unicode_or_empty(record, "CommandLine"),
        image_path_name: read_unicode_or_empty(record, "ImagePathName"),
        current_directory: DiagnosticValue::from_result(current_directory),
        dll_path: read_unicode_or_empty(record, "DllPath"),
        window_title: read_unicode_or_empty(record, "WindowTitle"),
        desktop_info: read_unicode_or_empty(record, "DesktopInfo"),
        shell_info: read_unicode_or_empty(record, "ShellInfo"),
        runtime_data: read_unicode_or_empty(record, "RuntimeData"),
        environment: DiagnosticValue::from_result(record.read_pointer("Environment")),
        environment_size: DiagnosticValue::from_result(environment_size),
    }
}

fn read_loader_list_head(ldr: &StructRef<'_>, field: &str) -> DiagnosticValue<LoaderListHead> {
    DiagnosticValue::from_result(ldr.embedded(field).map(|head| LoaderListHead {
        address: head.addr(),
        flink: DiagnosticValue::from_result(head.read_pointer("Flink")),
        blink: DiagnosticValue::from_result(head.read_pointer("Blink")),
    }))
}

fn read_loader_list_heads(ldr: &StructRef<'_>) -> LoaderLists {
    LoaderLists {
        in_load_order: read_loader_list_head(ldr, "InLoadOrderModuleList"),
        in_memory_order: read_loader_list_head(ldr, "InMemoryOrderModuleList"),
        in_initialization_order: read_loader_list_head(ldr, "InInitializationOrderModuleList"),
    }
}

fn loader_module_detail(module: ModuleInfo) -> LoaderModule {
    LoaderModule {
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

fn make_unavailable_peb32(address: VirtAddr, error: impl ToString) -> Peb32 {
    let error = error.to_string();
    Peb32 {
        address,
        image_base_address: DiagnosticValue::unavailable(&error),
        ldr: DiagnosticValue::unavailable(&error),
        process_parameters: DiagnosticValue::unavailable(&error),
        process_parameters_detail: DiagnosticValue::unavailable(&error),
        process_heap: DiagnosticValue::unavailable(&error),
        number_of_heaps: DiagnosticValue::unavailable(&error),
        process_heaps: DiagnosticValue::unavailable(&error),
        being_debugged: DiagnosticValue::unavailable(&error),
        os_major_version: DiagnosticValue::unavailable(&error),
        os_minor_version: DiagnosticValue::unavailable(&error),
        os_build_number: DiagnosticValue::unavailable(&error),
        session_id: DiagnosticValue::unavailable(&error),
        number_of_processors: DiagnosticValue::unavailable(&error),
        loader_lists: DiagnosticValue::unavailable(&error),
    }
}

impl Target {
    /// The address space and layouts a TEB or PEB of `dtb` is read with.
    fn user_mode_types(&self, dtb: Dtb) -> Result<UserModeTypes<'_>> {
        Ok(match self.kind() {
            TargetKind::Kernel => UserModeTypes {
                types: self.guest()?.ntoskrnl.types_in(dtb),
                module: None,
            },
            TargetKind::UserDump => UserModeTypes {
                types: self.types_in(dtb),
                module: Some("ntdll"),
            },
        })
    }

    /// Fail unless a user-mode minidump captured `what` at `address`; a
    /// kernel target's memory is not checked up front.
    fn require_captured(&self, address: VirtAddr, what: &str) -> Result<()> {
        if self.kind() == TargetKind::Kernel {
            return Ok(());
        }
        match self.context_memory().read::<u8>(address) {
            Ok(_) => Ok(()),
            Err(Error::NotCaptured { .. }) => Err(Error::DebugInfo(format!(
                "the minidump did not capture the {what} at {:#x}",
                address.0
            ))),
            Err(error) => Err(error),
        }
    }

    /// The TEB of the captured thread selected for inspection.
    fn user_teb(&self) -> Result<VirtAddr> {
        let thread = self.user_thread().ok_or_else(|| {
            Error::DebugInfo("no captured thread is selected; select one with ~<n>s".into())
        })?;
        match thread.teb {
            0 => Err(Error::DebugInfo(format!(
                "the minidump records no TEB for thread {:x}",
                thread.tid
            ))),
            teb => Ok(VirtAddr(teb)),
        }
    }

    /// The PEB a user-mode minidump's TEB names (`TEB.ProcessEnvironmentBlock`).
    fn user_peb(&self, view: UserModeTypes<'_>, teb: VirtAddr) -> Result<VirtAddr> {
        self.require_captured(teb, "TEB")?;
        let peb = view
            .struct_at("_TEB", teb)?
            .read_pointer("ProcessEnvironmentBlock")?;
        if peb.is_zero() {
            return Err(Error::MissingPEB);
        }
        Ok(peb)
    }

    /// The 32-bit PEB of a WOW64 thread's TEB: `TEB32.ProcessEnvironmentBlock`
    /// of the TEB `TEB.WowTebOffset` places beside it. `None` for a native
    /// thread or when either TEB is unreadable.
    fn user_wow64_peb(&self, view: UserModeTypes<'_>, teb: VirtAddr) -> Option<VirtAddr> {
        let offset = view
            .struct_at("_TEB", teb)
            .ok()?
            .read_field::<i32>("WowTebOffset")
            .ok()?;
        let teb32 = teb32_address(teb, Some(offset))?;
        let peb32 = view
            .struct_at("_TEB32", teb32)
            .ok()?
            .read_field::<u32>("ProcessEnvironmentBlock")
            .ok()?;
        (peb32 != 0).then(|| VirtAddr::from(peb32))
    }

    /// The root, the default PEB (`address` when given), and the WOW64 PEB
    /// of the process `!peb` and `!dlls` decode: on a kernel target the
    /// current process's (`EPROCESS.Peb`), on a user-mode minidump its one
    /// process's, through the selected thread's TEB.
    fn peb_scope(&self, address: Option<VirtAddr>) -> Result<(Dtb, VirtAddr, Option<VirtAddr>)> {
        if self.kind() == TargetKind::UserDump {
            let dtb = self.current_dtb();
            let view = self.user_mode_types(dtb)?;
            return match address {
                Some(address) => Ok((dtb, address, None)),
                None => {
                    let teb = self.user_teb()?;
                    let peb = self.user_peb(view, teb)?;
                    Ok((dtb, peb, self.user_wow64_peb(view, teb)))
                }
            };
        }
        let process = current_process(self)?;
        let dtb = process.dtb;
        let peb_address = if let Some(address) = address {
            address
        } else {
            let eprocess = self
                .guest()?
                .ntoskrnl
                .types_in(dtb)
                .struct_at("_EPROCESS", process.eprocess)?;
            let peb = eprocess.follow("Peb")?;
            if peb.addr().is_zero() {
                return Err(Error::MissingPEB);
            }
            peb.addr()
        };
        Ok((dtb, peb_address, process.wow64_peb))
    }

    /// Decode the native `_PEB`, its process-parameter strings/pointers, and
    /// loader-list heads. Each `DiagnosticValue` records the field-specific
    /// layout or memory error when that field is unavailable; a WOW64 PEB is
    /// included when the current process has one and no explicit address was
    /// requested. On a user-mode minidump the PEB is the one the selected
    /// thread's TEB names, decoded with ntdll's layouts.
    pub fn inspect_peb(&self, address: Option<VirtAddr>) -> Result<Peb> {
        let (dtb, peb_address, wow64_peb) = self.peb_scope(address)?;
        let types = self.user_mode_types(dtb)?;
        self.require_captured(peb_address, "PEB")?;
        let peb_ref = types.struct_at("_PEB", peb_address)?.prefetch();

        let image_base_address =
            DiagnosticValue::from_result(peb_ref.read_pointer("ImageBaseAddress"));
        let ldr = DiagnosticValue::from_result(peb_ref.read_pointer("Ldr"));
        let process_parameters =
            DiagnosticValue::from_result(peb_ref.read_pointer("ProcessParameters"));
        let process_parameters_detail = match &process_parameters {
            DiagnosticValue::Available(address) if !address.is_zero() => {
                DiagnosticValue::from_result(
                    types
                        .struct_at("_RTL_USER_PROCESS_PARAMETERS", *address)
                        .map(|record| {
                            let record = record.prefetch();
                            let environment_size = record.read_field::<u64>("EnvironmentSize");
                            decode_process_parameters(&record, environment_size)
                        }),
                )
            }
            DiagnosticValue::Available(_) => DiagnosticValue::unavailable("pointer is null"),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::unavailable(error.clone()),
        };
        let loader_lists = match &ldr {
            DiagnosticValue::Available(address) if !address.is_zero() => {
                DiagnosticValue::from_result(
                    types
                        .struct_at("_PEB_LDR_DATA", *address)
                        .map(|ldr_ref| read_loader_list_heads(&ldr_ref)),
                )
            }
            DiagnosticValue::Available(_) => DiagnosticValue::unavailable("pointer is null"),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::unavailable(error.clone()),
        };

        let peb32 = if address.is_none() {
            wow64_peb.map(|peb32| self.decode_peb32(dtb, peb32))
        } else {
            None
        };
        Ok(Peb {
            address: peb_address,
            image_base_address,
            ldr,
            process_parameters,
            process_parameters_detail,
            process_heap: DiagnosticValue::from_result(peb_ref.read_pointer("ProcessHeap")),
            number_of_heaps: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("NumberOfHeaps").map(u64::from),
            ),
            process_heaps: DiagnosticValue::from_result(peb_ref.read_pointer("ProcessHeaps")),
            being_debugged: DiagnosticValue::from_result(peb_ref.read_field::<u8>("BeingDebugged")),
            os_major_version: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("OSMajorVersion").map(u64::from),
            ),
            os_minor_version: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("OSMinorVersion").map(u64::from),
            ),
            os_build_number: DiagnosticValue::from_result(
                peb_ref.read_field::<u16>("OSBuildNumber").map(u64::from),
            ),
            session_id: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("SessionId").map(u64::from),
            ),
            number_of_processors: DiagnosticValue::from_result(
                peb_ref
                    .read_field::<u32>("NumberOfProcessors")
                    .map(u64::from),
            ),
            api_set_map: DiagnosticValue::from_result(peb_ref.read_pointer("ApiSetMap")),
            loader_lists,
            peb32,
        })
    }

    fn decode_loader_heads32(&self, ldr: VirtAddr) -> DiagnosticValue<LoaderLists> {
        let memory = self.process_memory();
        let read_head = |offset: u64| {
            let address = ldr + offset;
            LoaderListHead {
                address,
                flink: DiagnosticValue::from_result(
                    memory.read::<u32>(address).map(VirtAddr::from),
                ),
                blink: DiagnosticValue::from_result(
                    memory.read::<u32>(address + 4u64).map(VirtAddr::from),
                ),
            }
        };
        DiagnosticValue::Available(LoaderLists {
            in_load_order: DiagnosticValue::Available(read_head(0x0c)),
            in_memory_order: DiagnosticValue::Available(read_head(0x14)),
            in_initialization_order: DiagnosticValue::Available(read_head(0x1c)),
        })
    }

    fn decode_peb32(&self, dtb: u64, address: VirtAddr) -> Peb32 {
        let types = match self.user_mode_types(dtb) {
            Ok(types) => types,
            Err(error) => return make_unavailable_peb32(address, error),
        };
        let peb_ref = match types.struct_at("_PEB32", address) {
            Ok(peb_ref) => peb_ref.prefetch(),
            Err(error) => return make_unavailable_peb32(address, error),
        };
        let ldr =
            DiagnosticValue::from_result(peb_ref.read_field::<u32>("Ldr").map(VirtAddr::from));
        let process_parameters = DiagnosticValue::from_result(
            peb_ref
                .read_field::<u32>("ProcessParameters")
                .map(VirtAddr::from),
        );
        let process_parameters_detail = match &process_parameters {
            DiagnosticValue::Available(address) if !address.is_zero() => {
                DiagnosticValue::from_result(
                    types
                        .struct_at("ntdll32!_RTL_USER_PROCESS_PARAMETERS", *address)
                        .map(|record| {
                            let record = record.prefetch();
                            let environment_size =
                                record.read_field::<u32>("EnvironmentSize").map(u64::from);
                            decode_process_parameters(&record, environment_size)
                        }),
                )
            }
            DiagnosticValue::Available(_) => DiagnosticValue::unavailable("pointer is null"),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::unavailable(error.clone()),
        };
        let loader_lists = match &ldr {
            DiagnosticValue::Available(address) if !address.is_zero() => {
                self.decode_loader_heads32(*address)
            }
            DiagnosticValue::Available(_) => DiagnosticValue::unavailable("pointer is null"),
            DiagnosticValue::Unavailable(error) => DiagnosticValue::unavailable(error.clone()),
        };
        Peb32 {
            address,
            image_base_address: DiagnosticValue::from_result(
                peb_ref
                    .read_field::<u32>("ImageBaseAddress")
                    .map(VirtAddr::from),
            ),
            ldr,
            process_parameters,
            process_parameters_detail,
            process_heap: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("ProcessHeap").map(VirtAddr::from),
            ),
            number_of_heaps: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("NumberOfHeaps").map(u64::from),
            ),
            process_heaps: DiagnosticValue::from_result(
                peb_ref
                    .read_field::<u32>("ProcessHeaps")
                    .map(VirtAddr::from),
            ),
            being_debugged: DiagnosticValue::from_result(peb_ref.read_field::<u8>("BeingDebugged")),
            os_major_version: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("OSMajorVersion").map(u64::from),
            ),
            os_minor_version: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("OSMinorVersion").map(u64::from),
            ),
            os_build_number: DiagnosticValue::from_result(
                peb_ref.read_field::<u16>("OSBuildNumber").map(u64::from),
            ),
            session_id: DiagnosticValue::from_result(
                peb_ref.read_field::<u32>("SessionId").map(u64::from),
            ),
            number_of_processors: DiagnosticValue::from_result(
                peb_ref
                    .read_field::<u32>("NumberOfProcessors")
                    .map(u64::from),
            ),
            loader_lists,
        }
    }

    /// Decode the selected/default native TEB and its WOW64 companion. The
    /// default address is the selected Windows thread's `teb` pseudo-register;
    /// on a user-mode minidump, the selected captured thread's TEB. Every
    /// independently unreadable field carries its own diagnostic error.
    pub fn inspect_teb(&self, address: Option<VirtAddr>) -> Result<Teb> {
        let (dtb, teb_address) = match (self.kind(), address) {
            (TargetKind::UserDump, address) => (
                self.current_dtb(),
                address.map_or_else(|| self.user_teb(), Ok)?,
            ),
            (TargetKind::Kernel, Some(address)) => (teb_dtb(self)?, address),
            (TargetKind::Kernel, None) => (
                teb_dtb(self)?,
                self.current_thread_pseudo_register("teb")
                    .filter(|address| *address != 0)
                    .map(VirtAddr)
                    .ok_or_else(|| {
                        Error::DebugInfo(
                            "current thread has no teb pseudo-register; select a user thread first"
                                .into(),
                        )
                    })?,
            ),
        };
        let types = self.user_mode_types(dtb)?;
        self.require_captured(teb_address, "TEB")?;
        let teb_ref = types.struct_at("_TEB", teb_address)?.prefetch();
        let wow_teb_offset =
            DiagnosticValue::from_result(teb_ref.read_field::<i32>("WowTebOffset"));
        let teb32 = match &wow_teb_offset {
            DiagnosticValue::Available(offset) => teb32_address(teb_address, Some(*offset))
                .map(|address| self.decode_teb32(dtb, address)),
            DiagnosticValue::Unavailable(_) => None,
        };
        Ok(Teb {
            address: teb_address,
            stack_base: DiagnosticValue::from_result(read_tib_pointer(&teb_ref, "StackBase")),
            stack_limit: DiagnosticValue::from_result(read_tib_pointer(&teb_ref, "StackLimit")),
            tls_pointer: DiagnosticValue::from_result(
                teb_ref
                    .read_pointer("ThreadLocalStoragePointer")
                    .or_else(|_| teb_ref.read_pointer("TlsPointer")),
            ),
            last_error_value: DiagnosticValue::from_result(
                teb_ref.read_field::<u32>("LastErrorValue"),
            ),
            last_status_value: DiagnosticValue::from_result(
                teb_ref.read_field::<u32>("LastStatusValue"),
            ),
            count_of_owned_critical_sections: DiagnosticValue::from_result(
                teb_ref.read_field::<u32>("CountOfOwnedCriticalSections"),
            ),
            peb: DiagnosticValue::from_result(
                teb_ref
                    .read_pointer("ProcessEnvironmentBlock")
                    .or_else(|_| teb_ref.read_pointer("Peb")),
            ),
            wow_teb_offset,
            wow64_reserved: DiagnosticValue::from_result(
                teb_ref
                    .read_pointer("Wow32Reserved")
                    .or_else(|_| teb_ref.read_pointer("Wow64Reserved")),
            ),
            activation_context: DiagnosticValue::from_result(
                teb_ref
                    .read_pointer("ActivationContextStackPointer")
                    .or_else(|_| teb_ref.read_pointer("ActivationContextStack"))
                    .map(|address| (!address.is_zero()).then_some(address)),
            ),
            client_id_unique_process: DiagnosticValue::from_result(
                teb_ref
                    .embedded("ClientId")
                    .and_then(|client| client.read_pointer("UniqueProcess")),
            ),
            client_id_unique_thread: DiagnosticValue::from_result(
                teb_ref
                    .embedded("ClientId")
                    .and_then(|client| client.read_pointer("UniqueThread")),
            ),
            teb32,
        })
    }

    fn decode_teb32(&self, dtb: u64, address: VirtAddr) -> Teb32 {
        let types = match self.user_mode_types(dtb) {
            Ok(types) => types,
            Err(error) => return make_unavailable_teb32(address, error),
        };
        let teb_ref = match types.struct_at("_TEB32", address) {
            Ok(teb_ref) => teb_ref.prefetch(),
            Err(error) => return make_unavailable_teb32(address, error),
        };
        Teb32 {
            address,
            stack_base: DiagnosticValue::from_result(
                teb_ref
                    .embedded("NtTib")
                    .and_then(|tib| tib.read_field::<u32>("StackBase"))
                    .map(VirtAddr::from),
            ),
            stack_limit: DiagnosticValue::from_result(
                teb_ref
                    .embedded("NtTib")
                    .and_then(|tib| tib.read_field::<u32>("StackLimit"))
                    .map(VirtAddr::from),
            ),
            tls_pointer: DiagnosticValue::from_result(
                teb_ref
                    .read_field::<u32>("ThreadLocalStoragePointer")
                    .or_else(|_| teb_ref.read_field("TlsPointer"))
                    .map(VirtAddr::from),
            ),
            last_error_value: DiagnosticValue::from_result(
                teb_ref.read_field::<u32>("LastErrorValue"),
            ),
            last_status_value: DiagnosticValue::from_result(
                teb_ref.read_field::<u32>("LastStatusValue"),
            ),
            count_of_owned_critical_sections: DiagnosticValue::from_result(
                teb_ref.read_field::<u32>("CountOfOwnedCriticalSections"),
            ),
            peb: DiagnosticValue::from_result(
                teb_ref
                    .read_field::<u32>("ProcessEnvironmentBlock")
                    .or_else(|_| teb_ref.read_field("Peb"))
                    .map(VirtAddr::from),
            ),
            client_id_unique_process: DiagnosticValue::from_result(
                teb_ref
                    .embedded("ClientId")
                    .and_then(|client| client.read_field::<u32>("UniqueProcess"))
                    .map(VirtAddr::from),
            ),
            client_id_unique_thread: DiagnosticValue::from_result(
                teb_ref
                    .embedded("ClientId")
                    .and_then(|client| client.read_field::<u32>("UniqueThread"))
                    .map(VirtAddr::from),
            ),
        }
    }

    /// Decode the selected thread's Win32 last-error and NT status values,
    /// retaining symbolic names when known and per-value errors otherwise.
    pub fn last_error(&self) -> Result<LastError> {
        let teb = self.inspect_teb(None)?;
        let last_error_name = error_name(&teb.last_error_value, win32_error_name);
        let last_status_name = error_name(&teb.last_status_value, ntstatus_name);
        let teb32 = teb.teb32.map(|teb32| LastError32 {
            teb: teb32.address,
            last_error_name: error_name(&teb32.last_error_value, win32_error_name),
            last_error_value: teb32.last_error_value,
            last_status_name: error_name(&teb32.last_status_value, ntstatus_name),
            last_status_value: teb32.last_status_value,
        });
        Ok(LastError {
            teb: teb.address,
            last_error_value: teb.last_error_value,
            last_error_name,
            last_status_value: teb.last_status_value,
            last_status_name,
            teb32,
        })
    }

    /// Walk the current process's native and (when present) WOW64 loader
    /// lists, bounded at 1000 entries and reporting list termination rather
    /// than hiding a partial/corrupt walk. `containing` filters after the two
    /// lists are merged, matching `!dlls -c`. On a user-mode minidump the
    /// lists are walked from the PEB the selected thread's TEB names, as far
    /// as the dump captured them.
    pub fn loader_modules(&self, containing: Option<VirtAddr>) -> Result<LoaderModules> {
        let detail = match self.kind() {
            TargetKind::Kernel => {
                let process = current_process(self)?;
                self.guest()?.process_modules_detail(&process)?
            }
            TargetKind::UserDump => self.user_loader_modules()?,
        };
        let modules = detail
            .modules
            .into_iter()
            .filter(|module| containing.is_none_or(|address| module.contains_address(address)))
            .map(loader_module_detail)
            .collect();
        Ok(LoaderModules {
            modules,
            termination: detail.termination,
            wow64_termination: detail.wow64_termination,
        })
    }

    /// A user-mode minidump's loader lists. An entry whose name is not
    /// captured is named after the module the dump's module list records at
    /// its base.
    fn user_loader_modules(&self) -> Result<ProcessModulesDetail> {
        // Without the loader's lists, the dump's own module list still names
        // every module.
        let point_to_lm = |error: Error| match error {
            Error::DebugInfo(text) => Error::DebugInfo(format!(
                "{text}; lm lists the modules the dump's module list records"
            )),
            error => error,
        };
        let (dtb, peb, wow64_peb) = self.peb_scope(None).map_err(point_to_lm)?;
        let types = self.user_mode_types(dtb)?;
        let memory = self.context_memory();
        self.require_captured(peb, "PEB").map_err(point_to_lm)?;
        let ldr = types.struct_at("_PEB", peb)?.follow("Ldr")?;
        if !ldr.addr().is_zero() {
            self.require_captured(ldr.addr(), "loader data (PEB.Ldr)")
                .map_err(point_to_lm)?;
        }
        let (mut modules, termination) = walk_loader_list(
            types.types,
            &memory,
            &ldr,
            &types.qualified("_LDR_DATA_TABLE_ENTRY"),
        )?;
        let mut wow64_termination = None;
        if let Some(peb32) = wow64_peb {
            let ldr32 = types.struct_at("_PEB32", peb32)?.read_field::<u32>("Ldr")?;
            let (modules32, termination32) = walk_loader_list32(&memory, ldr32);
            wow64_termination = Some(termination32);
            merge_wow64_modules(&mut modules, modules32);
        }
        let recorded = self.user_modules().unwrap_or_default();
        for module in modules
            .iter_mut()
            .filter(|module| module.name == UNKNOWN_MODULE_NAME)
        {
            if let Some(known) = recorded
                .iter()
                .find(|known| known.base_address == module.base_address)
            {
                module.name = known.name.clone();
                module.short_name = known.short_name.clone();
            }
        }
        Ok(ProcessModulesDetail {
            modules,
            termination,
            wow64_termination,
        })
    }

    /// Compare executable cached-image sections with the loaded module. Both
    /// genuine mismatches and recognized kernel self-patches are returned;
    /// `include_diffs` controls only the bounded byte-diff collection, while
    /// unavailable/paged-out sections retain their reason in the result.
    /// Compare `module`'s executable sections against its cached image
    /// (`!chkimg`), reading live code with `read_code`, which should mask the
    /// debugger's own breakpoints so they are not reported as tampering (see
    /// [`crate::session::Session::check_image`]).
    pub fn check_image(
        &self,
        module: &str,
        include_diffs: bool,
        read_code: &dyn Fn(VirtAddr, &mut [u8]) -> Result<()>,
    ) -> Result<ImageCheck> {
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
            return Ok(ImageCheck {
                module: module_info.name,
                short_name: module_info.short_name,
                base_address: module_info.base_address,
                sections: Vec::new(),
                genuine_mismatched_bytes: 0,
                total_mismatched_bytes: 0,
                self_patches: ImageSelfPatchCounts::default(),
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
        let mut self_patch_total = ImageSelfPatchCounts::default();
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
                read_code,
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
            section_results.push(ImageSectionCheck {
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
        Ok(ImageCheck {
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
        read_code: &dyn Fn(VirtAddr, &mut [u8]) -> Result<()>,
    ) -> SectionCheckResult {
        let base = module.base_address;
        if section.discardable {
            return SectionCheckResult {
                skipped: true,
                skip_reason: Some("discardable"),
                ..SectionCheckResult::default()
            };
        }
        let mut live = vec![0u8; section.expected.len()];
        for offset in (0..section.expected.len()).step_by(SECTION_READ_CHUNK) {
            let take = (section.expected.len() - offset).min(SECTION_READ_CHUNK);
            let address = base + section.rva as u64 + offset as u64;
            if let Err(error) = read_code(address, &mut live[offset..offset + take]) {
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
            let actual = &live[offset..end];
            if expected != actual {
                let region_rebase = match self.arch() {
                    Arch::Amd64 => is_region_rebase(expected, actual),
                    Arch::Arm64 => is_region_rebase_literal(&section.expected, &live, offset),
                };
                let patch = if allow_kernel_self_patches && region_rebase {
                    Some(SelfPatchMatch {
                        kind: SelfPatchKind::RegionRebase,
                        function: self.self_patch_function_note(base, section.rva, offset),
                    })
                } else if allow_kernel_self_patches {
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
                            result.diffs.push(ImageByteDiff {
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
        let expected_ip = preferred_base
            .wrapping_add(section.rva as u64)
            .wrapping_add(offset as u64);
        let actual_ip = base
            .0
            .wrapping_add(section.rva as u64)
            .wrapping_add(offset as u64);
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
                rel32_target(expected_ip, expected),
                rel32_target(actual_ip, actual),
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
        // The kernel also picks its CFG dispatch routine for the CPU by
        // rewriting the displacement of a RIP-relative operand, such as
        // KiSystemStartup's `lea rcx, [rip+...]` that fills
        // __guard_dispatch_icall_fptr. Both ends must start a dispatch
        // routine of the module, so code pointed anywhere else still counts.
        if self.arch() == Arch::Amd64
            && let Some((expected_target, actual_target)) =
                rip_relative_retarget(expected, expected_ip, actual, actual_ip)
            && self.starts_dispatch_routine(
                rebase_module_target(expected_target, preferred_base, base.0, module.size),
                module,
            )
            && self.starts_dispatch_routine(actual_target, module)
        {
            return Some(SelfPatchMatch {
                kind: SelfPatchKind::Retpoline,
                function: self.self_patch_function_note(base, section.rva, offset),
            });
        }
        None
    }

    /// Whether `address` is the first byte of one of `module`'s retpoline or
    /// CFG dispatch routines.
    fn starts_dispatch_routine(&self, address: u64, module: &ModuleInfo) -> bool {
        self.nearest_symbol_current_context(VirtAddr(address))
            .is_some_and(|(owner, name, offset)| {
                offset == 0
                    && owner.eq_ignore_ascii_case(&module.short_name)
                    && is_retpoline_target(Some(&name))
            })
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

fn make_unavailable_teb32(address: VirtAddr, error: impl ToString) -> Teb32 {
    let error = error.to_string();
    Teb32 {
        address,
        stack_base: DiagnosticValue::unavailable(&error),
        stack_limit: DiagnosticValue::unavailable(&error),
        tls_pointer: DiagnosticValue::unavailable(&error),
        last_error_value: DiagnosticValue::unavailable(&error),
        last_status_value: DiagnosticValue::unavailable(&error),
        count_of_owned_critical_sections: DiagnosticValue::unavailable(&error),
        peb: DiagnosticValue::unavailable(&error),
        client_id_unique_process: DiagnosticValue::unavailable(&error),
        client_id_unique_thread: DiagnosticValue::unavailable(&error),
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
        DiagnosticValue::Unavailable(error) => DiagnosticValue::unavailable(error.clone()),
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

fn push_mismatch_range(
    ranges: &mut Vec<ImageMismatchRange>,
    overflow: &mut bool,
    start: u64,
    end: u64,
) {
    if let Some(last) = ranges.last_mut()
        && last.end == start
    {
        last.end = end;
        return;
    }
    if ranges.len() < MAX_REPORT_RANGES {
        ranges.push(ImageMismatchRange { start, end });
    } else {
        *overflow = true;
    }
}

fn push_self_patch_range(
    ranges: &mut Vec<ImageSelfPatchRange>,
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
        ranges.push(ImageSelfPatchRange {
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
            | Error::NotCaptured { .. }
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

/// The addresses the RIP-relative memory operand of `expected` (at
/// `expected_ip`) and of `actual` (at `actual_ip`) refer to, when the two
/// are the same instruction but for that operand's 4-byte displacement.
fn rip_relative_retarget(
    expected: &[u8],
    expected_ip: u64,
    actual: &[u8],
    actual_ip: u64,
) -> Option<(u64, u64)> {
    let decode = |bytes: &[u8], ip: u64| {
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let offsets = decoder.get_constant_offsets(&instruction);
        (instruction, offsets)
    };
    let (disk, offsets) = decode(expected, expected_ip);
    let (live, _) = decode(actual, actual_ip);
    if disk.is_invalid()
        || disk.code() != live.code()
        || disk.len() != expected.len()
        || live.len() != actual.len()
        || !disk.is_ip_rel_memory_operand()
        || offsets.displacement_size() != 4
    {
        return None;
    }
    let field = offsets.displacement_offset()..offsets.displacement_offset() + 4;
    let only_displacement = expected
        .iter()
        .zip(actual)
        .enumerate()
        .all(|(index, (disk, live))| disk == live || field.contains(&index));
    only_displacement.then(|| (disk.ip_rel_memory_address(), live.ip_rel_memory_address()))
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

/// Whether kernel address `live` is `disk` moved to another top-level (PML4)
/// slot: bits 39-47 change from slot `a` to `b`, and every lower 9-bit field
/// that named `a` names `b`. That is how a region base moves (only the top
/// field) and how every address derived from the page-table self-map does,
/// since the self-map's slot recurs in each field (its PXE entry
/// `0xFFFFF6FB7DBEDF68` becomes `0xFFFFA6D369B4DA68` for slot 0x14D).
fn moved_with_top_level_slot(disk: u64, live: u64) -> bool {
    let field = |value: u64, shift: u32| (value >> shift) & 0x1ff;
    let (old, new) = (field(disk, 39), field(live, 39));
    disk >> 48 == 0xffff
        && live >> 48 == 0xffff
        && disk & 7 == live & 7
        && old != new
        && [30, 21, 12, 3].into_iter().all(|shift| {
            let (disk, live) = (field(disk, shift), field(live, shift));
            disk == live || (disk == old && live == new)
        })
}

/// Whether `actual` is the instruction `expected` with the kernel's boot-time
/// VA region randomization applied: a `mov r64, imm64` loading an address in
/// a region it moves (the PFN database, the page tables, ...) whose immediate
/// moved with the region's top-level slot, and nothing else changed.
fn is_region_rebase(expected: &[u8], actual: &[u8]) -> bool {
    let decode = |bytes: &[u8]| Decoder::new(64, bytes, DecoderOptions::NONE).decode();
    let (disk, live) = (decode(expected), decode(actual));
    let (Some(disk_len), Some(live_len)) = (
        (!disk.is_invalid()).then_some(disk.len()),
        (!live.is_invalid()).then_some(live.len()),
    ) else {
        return false;
    };
    disk.code() == Code::Mov_r64_imm64
        && live.code() == Code::Mov_r64_imm64
        && disk_len == expected.len()
        && live_len == actual.len()
        && disk.op0_register() == live.op0_register()
        && moved_with_top_level_slot(disk.immediate64(), live.immediate64())
}

/// Whether the 8-byte literal holding `offset` moved with a region's
/// top-level slot: ARM64 code loads a region's address from a literal pool
/// next to the function (`ldr x0, =MmPteBase`-style), not from an immediate,
/// so the kernel's boot-time region move rewrites that aligned doubleword.
/// Sections start page-aligned, so section offsets align like addresses.
fn is_region_rebase_literal(expected: &[u8], live: &[u8], offset: usize) -> bool {
    let start = offset & !7;
    let doubleword = |bytes: &[u8]| {
        bytes
            .get(start..start + 8)
            .map(|word| u64::from_le_bytes(word.try_into().expect("8-byte slice")))
    };
    matches!(
        (doubleword(expected), doubleword(live)),
        (Some(disk), Some(live)) if moved_with_top_level_slot(disk, live)
    )
}

#[cfg(test)]
mod tests {
    use super::{is_region_rebase, is_region_rebase_literal, rip_relative_retarget};

    /// `mov rax, imm64`.
    fn mov_rax(value: u64) -> Vec<u8> {
        let mut bytes = vec![0x48, 0xb8];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }

    /// Windows moves the PFN database (and the page tables, ...) to a
    /// randomized top-level slot at boot and rewrites the `mov r64, imm64`
    /// that loads its base; anything else is a real difference.
    #[test]
    fn only_a_top_level_slot_move_of_a_loaded_region_base_is_a_region_rebase() {
        let disk = mov_rax(0xffff_de00_0000_0000);
        assert!(is_region_rebase(&disk, &mov_rax(0xffff_de80_0000_0000)));
        assert!(!is_region_rebase(&disk, &mov_rax(0xffff_de00_0000_1000)));
        assert!(!is_region_rebase(&disk, &disk));

        let mut other_register = mov_rax(0xffff_de80_0000_0000);
        other_register[1] = 0xb9;
        assert!(!is_region_rebase(&disk, &other_register));

        let user = mov_rax(0x0000_5e00_0000_0000);
        assert!(!is_region_rebase(&user, &mov_rax(0x0000_5e80_0000_0000)));

        // The self-map's slot recurs in every field of an address derived
        // from it, down to its PXE entry's byte offset.
        let pxe_entry = mov_rax(0xffff_f6fb_7dbe_df68);
        assert!(is_region_rebase(
            &pxe_entry,
            &mov_rax(0xffff_a6d3_69b4_da68)
        ));
        assert!(!is_region_rebase(
            &pxe_entry,
            &mov_rax(0xffff_a6d3_69b4_da00)
        ));
    }

    /// Doublewords from an ARM64 ntoskrnl (build 22631) literal pool, on disk
    /// and after boot: the self-map's PXE entry and the PFN database base.
    #[test]
    fn a_literal_moved_with_its_top_level_slot_is_a_region_rebase() {
        let code = |value: u64| {
            // ldr x0, #8; ret; then the aligned literal.
            let mut bytes = vec![0x40, 0x00, 0x00, 0x58, 0xc0, 0x03, 0x5f, 0xd6];
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]); // ret
            bytes
        };
        let pxe_entry = code(0xffff_f6fb_7dbe_df68);
        let pfn_database = code(0xffff_de00_0000_0000);
        // Both halves of the doubleword are the literal.
        for offset in [8, 12] {
            assert!(is_region_rebase_literal(
                &pxe_entry,
                &code(0xffff_ddee_f77b_bdd8),
                offset
            ));
            assert!(is_region_rebase_literal(
                &pfn_database,
                &code(0xffff_ee80_0000_0000),
                offset
            ));
        }
        assert!(!is_region_rebase_literal(
            &pfn_database,
            &code(0xffff_ee80_0000_1000),
            8
        ));
        // The HAL's EL2 init slot, a physical address written at boot.
        assert!(!is_region_rebase_literal(&code(0), &code(0x4014_686c), 8));
    }

    /// KiSystemStartup's `lea rcx, [rip+...]` in ntoskrnl 26200, on disk
    /// (a _guard_dispatch_icall thunk) and after boot
    /// (KscpCfgDispatchUserCallTargetEsSmep), at the preferred and the
    /// loaded base: only a displacement change is a retarget.
    #[test]
    fn a_retarget_changes_only_the_rip_relative_displacement() {
        let (disk_ip, live_ip) = (0x1_40b5_9522, 0xffff_f802_cddc_9522);
        let disk = [0x48, 0x8d, 0x0d, 0x07, 0x4b, 0x07, 0x00];
        let live = [0x48, 0x8d, 0x0d, 0x37, 0x32, 0x07, 0x00];
        assert_eq!(
            rip_relative_retarget(&disk, disk_ip, &live, live_ip),
            Some((disk_ip + 7 + 0x74b07, live_ip + 7 + 0x73237))
        );

        // lea rdx: another register is another instruction.
        let other_register = [0x48, 0x8d, 0x15, 0x37, 0x32, 0x07, 0x00];
        assert_eq!(
            rip_relative_retarget(&disk, disk_ip, &other_register, live_ip),
            None
        );
        // mov rax, [rcx+0x10]: a displacement, but not from RIP.
        let not_rip = [0x48, 0x8b, 0x81, 0x10, 0x00, 0x00, 0x00];
        let moved = [0x48, 0x8b, 0x81, 0x20, 0x00, 0x00, 0x00];
        assert_eq!(
            rip_relative_retarget(&not_rip, disk_ip, &moved, live_ip),
            None
        );
        // call rel32 is a branch, which the call/jmp rule covers.
        let call = [0xe8, 0x07, 0x4b, 0x07, 0x00];
        let retargeted = [0xe8, 0x37, 0x32, 0x07, 0x00];
        assert_eq!(
            rip_relative_retarget(&call, disk_ip, &retargeted, live_ip),
            None
        );
    }
}
