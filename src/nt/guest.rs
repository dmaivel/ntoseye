use crate::arch::Arch;
use crate::{
    backend::phys::PhysMem,
    base::{
        error::{Error, Result},
        memory::{
            CompressedPages, DTB_IDENTITY, MemoryOps, PAGE_FILE_LOW, SectionLayout, SectionViews,
            StoreLayout,
        },
        types::*,
    },
    nt::{
        dmp::DmpInfo,
        layout::ParsedType,
        pe::{self, PeImage, headers::CodeView},
        symbols::{ImageFetch, SymbolStore},
        target::ListTermination,
        target::object::DriverObjectInfo,
    },
};
use ntoseye_macros::record;
use pelite::pe64::{Pe, PeView};
use std::collections::HashMap;
use std::ops::Range;
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, PoisonError,
    atomic::{AtomicBool, Ordering},
};
use vad::{MissingOffset, VadTreeOffsets, vad_root_offset};

mod discovery;
pub mod ept;
mod evmcs;
pub mod evmcs_fields;
mod exit_registers;
pub mod hv_layout;
pub mod hypercall_input;
pub mod hypercalls;
pub mod hypervisor;
mod image;
mod modules;
pub mod pdb_recovery;
mod process;
pub mod secure_kernel;
pub mod store_layout;
mod symbol_load;
mod trustlet_layout;
pub mod vad;
pub mod vm_exits;
pub mod vp_registers;

use discovery::{find_kernel, find_ntoskrnl, find_ntoskrnl_va, find_ntoskrnl_va_triage};
pub use evmcs::{EvmcsCache, EvmcsPages, EvmcsState};
pub use exit_registers::{ENTRY_CODE_BYTES, EXIT_GPRS, ExitRegisterLayout, ordered_exit_gprs};
pub use hypervisor::{
    HvMemory, HvPartition, HvProcessor, HvVirtualProcessor, HvVtl, privilege_names,
};
pub use image::{Image, SymbolRef};
pub use modules::{UNKNOWN_MODULE_NAME, merge_wow64_modules, walk_loader_list, walk_loader_list32};
pub use secure_kernel::{SecureKernel, TrustletInfo};

/// The identity of a process (`ps`, `!process 0 0`) and the root (`dtb`) of
/// its address space.
#[record(impl)]
pub struct ProcessInfo {
    /// The process identifier.
    pub pid: u64,
    /// The image name.
    pub name: String,
    /// The directory table base (page-table root).
    #[record(hex)]
    pub dtb: Dtb,
    /// The `_EPROCESS` address.
    pub eprocess: VirtAddr,
    /// The 32-bit PEB of a WOW64 process (`_EPROCESS.WoW64Process`), `None`
    /// for a native process.
    pub wow64_peb: Option<VirtAddr>,
}

#[record]
impl ProcessInfo {
    /// True if it is a 32-bit process that runs under WOW64.
    #[record(getter, rename = "wow64")]
    pub fn is_wow64(&self) -> bool {
        self.wow64_peb.is_some()
    }
}

/// A loaded module (kernel or process image), as its loader list records it.
#[record(impl)]
pub struct ModuleInfo {
    /// The image name.
    pub name: String,
    /// The name without its extension, as `nt!` and `lm` name the module
    /// (`nt` for the kernel).
    pub short_name: String,
    /// The full image path, if the loader recorded one.
    pub path: Option<String>,
    /// The base address of the loaded image.
    #[record(rename = "base")]
    pub base_address: VirtAddr,
    /// The size of the mapped image.
    pub size: u32,
    /// From a WOW64 process's 32-bit loader list: x86 code, 4-byte pointers.
    pub is_32bit: bool,
    pub entry_point: Option<VirtAddr>,
    /// The PE timestamp, if the loader record contains one.
    #[record(hex, rename = "timestamp")]
    pub time_date_stamp: Option<u32>,
    #[record(hex)]
    pub checksum: Option<u32>,
    /// The file version from the version resource of the image.
    pub file_version: Option<String>,
    /// The product version from the version resource of the image.
    pub product_version: Option<String>,
    /// The image's CodeView record when the module list itself records it
    /// (a user-mode minidump's module stream), so its PDB is known without
    /// reading the image.
    #[record(skip)]
    pub codeview: Option<CodeView>,
}

#[record]
impl ModuleInfo {
    /// The address after the last byte of the image.
    #[record(getter, rename = "end")]
    pub fn end_address(&self) -> VirtAddr {
        VirtAddr(self.base_address.0.saturating_add(self.size as u64))
    }
}

impl ModuleInfo {
    pub fn new(name: String, base_address: VirtAddr, size: u32) -> Self {
        let short_name = Self::derive_short_name(&name);
        Self {
            name,
            short_name,
            path: None,
            base_address,
            size,
            is_32bit: false,
            entry_point: None,
            time_date_stamp: None,
            checksum: None,
            file_version: None,
            product_version: None,
            codeview: None,
        }
    }

    pub fn with_time_date_stamp(mut self, tds: u32) -> Self {
        self.time_date_stamp = Some(tds);
        self
    }

    pub fn with_checksum(mut self, cs: u32) -> Self {
        self.checksum = Some(cs);
        self
    }

    pub fn with_version_info(mut self, file_ver: String, product_ver: String) -> Self {
        self.file_version = Some(file_ver);
        self.product_version = Some(product_ver);
        self
    }

    pub fn derive_short_name(name: &str) -> String {
        let filename = name.rsplit(['\\', '/']).next().unwrap_or(name);
        let without_ext = filename
            .rsplit_once('.')
            .map(|(base, _)| base)
            .unwrap_or(filename);

        let lowered = without_ext.to_lowercase();
        match lowered.as_str() {
            "ntoskrnl" | "ntkrnlmp" | "ntkrnlpa" | "ntkrpamp" => "nt".to_string(),
            "hvix64" | "hvax64" | "hvaa64" => "hv".to_string(),
            _ => lowered,
        }
    }

    pub fn contains_address(&self, address: VirtAddr) -> bool {
        address.0 >= self.base_address.0 && address.0 < self.end_address().0
    }
}

/// Native and optional WOW64 loader-list results for one process.
#[derive(Debug, Clone)]
pub struct ProcessModulesDetail {
    pub modules: Vec<ModuleInfo>,
    pub termination: ListTermination,
    pub wow64_termination: Option<ListTermination>,
}

/// One problem that ntoseye found when it loaded the symbols of a module.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSymbolDiagnostic {
    pub module: String,
    /// The load step that reported it.
    pub phase: &'static str,
    /// The compiland of the problem, if the problem is specific to one compiland.
    pub compiland: Option<String>,
    pub message: String,
}

/// Whether a symbol load covers modules in session space (win32k and
/// friends), which only a process attached to a session maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSpace {
    Load,
    Skip,
}

/// When a symbol load rebuilds a missing PDB from guest memory (see
/// [`pdb_recovery`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbRecovery {
    /// While guest memory is read from the host, where the walk is cheap:
    /// loads at attach and at stops.
    Automatic,
    /// Whatever the memory source: an explicit reload of the module.
    Requested,
}

/// The result of a symbol reload. It counts the modules that loaded, had
/// no PDB, were skipped, failed, or are still being fetched, and keeps the
/// first diagnostics up to a limit.
#[record]
#[derive(Debug, Clone, Default)]
pub struct ModuleSymbolLoadReport {
    pub total: usize,
    pub loaded: usize,
    /// The number of modules with symbols that unloaded after the previous refresh.
    pub unloaded: usize,
    pub no_pdb: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Handed to the background fetcher; not yet loaded or failed.
    pub fetching: usize,
    /// The number of all diagnostics, including those after the limit of `diagnostics`.
    pub diagnostic_count: usize,
    pub diagnostics: Vec<ModuleSymbolDiagnostic>,
    /// Why resolving the symbolic breakpoints again after the reload
    /// failed (`.reload`, `ld`); `None` if it did not fail or did not run.
    pub breakpoint_error: Option<String>,
}

pub struct Guest {
    pub ntoskrnl: Image,
    /// ntoskrnl's `KVASCODE` section (see [`Self::kernel_transition_code`]),
    /// looked up when first asked for: only a debugger whose traps reach
    /// Windows asks, and a kernel whose headers were not read at symbol
    /// load costs a read.
    kernel_transition_code: OnceLock<Option<Range<VirtAddr>>>,
    /// The code a trap runs before the kernel reports it to the debugger,
    /// found once per boot (see [`Self::trap_dispatch_code`]).
    trap_dispatch_code: OnceLock<Vec<Range<VirtAddr>>>,
    memo: Mutex<HaltMemo>,
    secure_kernel: Mutex<Option<Arc<SecureKernel>>>,
    /// Whether saved VTL state already looked for the secure kernel, which
    /// it does once per boot ([`Self::secure_kernel_if_found`]).
    secure_kernel_tried: AtomicBool,
    /// Images found outside NT's address spaces (the Windows hypervisor), by
    /// root. They stay mapped for the boot, and this `Guest` is the boot's.
    foreign_images: Mutex<Vec<(Dtb, ModuleInfo)>>,
    /// Where the Windows hypervisor's eVMCS pages are, once scanned for.
    evmcs_pages: Mutex<EvmcsCache>,
    /// Where the Windows hypervisor's exit entry code saves the guest's
    /// general-purpose registers, by entry point (`host_rip`), or why that
    /// could not be read off the code.
    exit_register_layouts: Mutex<HashMap<u64, std::result::Result<ExitRegisterLayout, String>>>,
    /// The Windows hypervisor's partition layout, by image base, or why it
    /// could not be read off the code.
    partition_layouts: Mutex<HashMap<u64, std::result::Result<hv_layout::PartitionLayout, String>>>,
    /// The names ntoseye gives the Windows hypervisor's code, by image base
    /// (its low bit set for names made with the image's file), or `None`
    /// when its hypercall table was not found.
    hypervisor_symbols: Mutex<HashMap<u64, Option<Arc<hypercalls::HypervisorSymbols>>>>,
    /// The VP and VTL each eVMCS page belongs to, by its address, from the
    /// last partition walk: a hypercall breakpoint's hit names its caller by
    /// the eVMCS loaded on its processor without walking again.
    vp_slots: Mutex<HashMap<u64, hypervisor::VpSlot>>,
    /// The processor blocks and VPs of the last partition walk, with the
    /// hypervisor's root and image base it read them through: a partition
    /// breakpoint's hit names the VP its processor runs without walking
    /// again (see [`Self::known_processor_vp`]).
    processor_vps: Mutex<Option<(Dtb, u64, hypervisor::ProcessorVps)>>,
    /// Where VPs keep their saved registers, by hypervisor image base, once
    /// calibrated. A calibration that failed is not kept: a later halt may
    /// have the mapped VPs it needs.
    vp_register_layouts: Mutex<HashMap<u64, vp_registers::VpRegisterLayout>>,
}

/// Guest-derived lists memoized for one halt epoch (see
/// [`PhysMem::halt_epoch`]). A halted guest cannot relink these lists, so the
/// first walk per halt serves every later caller: the break context, the
/// stop-time symbol refresh, completions, and listing commands would otherwise
/// each re-walk the same kernel lists over the transport. Failed walks are not
/// remembered.
#[derive(Default)]
struct HaltMemo {
    epoch: Option<u64>,
    processes: Option<Vec<ProcessInfo>>,
    kernel_modules: Option<Vec<ModuleInfo>>,
    drivers: Option<Vec<DriverObjectInfo>>,
    /// Loader lists by `_EPROCESS`; every thread of a process walked in one
    /// halt shares them.
    process_modules: HashMap<VirtAddr, Option<ProcessModulesDetail>>,
}

/// Whether `images`, those stops found outside NT with their roots, hold the
/// Windows hypervisor's image in root `dtb`.
fn hypervisor_root(images: &[(Dtb, ModuleInfo)], dtb: Dtb) -> bool {
    images
        .iter()
        .any(|(root, image)| image.short_name == "hv" && *root == dtb)
}

/// Whether `address` lies in the Windows hypervisor's image among `images`.
fn hypervisor_image_contains(images: &[(Dtb, ModuleInfo)], address: VirtAddr) -> bool {
    images
        .iter()
        .any(|(_, image)| image.short_name == "hv" && image.contains_address(address))
}

/// The entry for `key` in `cache`, made by `make` when there is none and
/// remembered, as `make` finding nothing is. An error from `make` is not
/// remembered, so the next call makes the entry again.
fn remembered<T>(
    cache: &mut HashMap<u64, Option<Arc<T>>>,
    key: u64,
    make: impl FnOnce() -> Result<Option<T>>,
) -> Option<Arc<T>> {
    if let Some(known) = cache.get(&key) {
        return known.clone();
    }
    let made = make().ok()?.map(Arc::new);
    cache.insert(key, made.clone());
    made
}

impl Guest {
    pub fn from_kernel(ntoskrnl: Image) -> Self {
        // Builds before the L1TF mitigation have no mask to undo.
        ntoskrnl
            .phys
            .set_invalid_pte_mask(invalid_pte_mask(&ntoskrnl).unwrap_or(0));
        ntoskrnl
            .phys
            .set_page_file_low(page_file_low(&ntoskrnl).unwrap_or(PAGE_FILE_LOW));
        ntoskrnl
            .phys
            .set_section_views(section_layout(&ntoskrnl).map(SectionViews::new));
        // Reading the kernel's code for the store layout waits until a page
        // may be in the store, and is done once; the store itself is looked
        // for until it exists. The resolver holds the physical memory
        // weakly, since that memory holds the resolver.
        let phys = Arc::downgrade(&ntoskrnl.phys);
        let symbols = Arc::clone(ntoskrnl.symbols());
        let (dtb, base, arch, guid) = (
            ntoskrnl.dtb(),
            ntoskrnl.base_address,
            ntoskrnl.arch(),
            ntoskrnl.guid,
        );
        let mut layout = None;
        ntoskrnl
            .phys
            .set_compressed_pages(Box::new(move |interrupt: &AtomicBool| {
                let mut kernel = Image::new(phys.upgrade()?, Arc::clone(&symbols), dtb, base, arch);
                kernel.guid = guid;
                compressed_pages(&mut kernel, &mut layout, interrupt)
            }));
        if let Ok(pte_base) = ntoskrnl.pte_base() {
            ntoskrnl.phys.set_pte_self_map(pte_base.0);
        }
        Self {
            kernel_transition_code: OnceLock::new(),
            trap_dispatch_code: OnceLock::new(),
            ntoskrnl,
            memo: Mutex::new(HaltMemo::default()),
            secure_kernel: Mutex::new(None),
            secure_kernel_tried: AtomicBool::new(false),
            foreign_images: Mutex::new(Vec::new()),
            evmcs_pages: Mutex::new(EvmcsCache::default()),
            exit_register_layouts: Mutex::new(HashMap::new()),
            partition_layouts: Mutex::new(HashMap::new()),
            hypervisor_symbols: Mutex::new(HashMap::new()),
            vp_slots: Mutex::new(HashMap::new()),
            processor_vps: Mutex::new(None),
            vp_register_layouts: Mutex::new(HashMap::new()),
        }
    }

    /// ntoskrnl's `KVASCODE` section: the code that switches between user
    /// and kernel mode, the system-call entry and the exits back to user
    /// mode (`KiSystemCall64Shadow`, `KiKernelSysretExit`, `KiKernelExit`),
    /// which kernel VA shadowing maps in the user page tables too. Its
    /// exits use the stack pointer as a scratch register and load the user
    /// CR3 before they leave, so a debug exception taken in between finds
    /// no usable kernel stack: Windows bugchecks with
    /// `UNEXPECTED_KERNEL_MODE_TRAP` (a double fault) in
    /// `KiDebugTrapOrFault`. `None` when the kernel has no such section
    /// (ARM64) or its headers cannot be read.
    pub fn kernel_transition_code(&self) -> Option<&Range<VirtAddr>> {
        self.kernel_transition_code
            .get_or_init(|| self.ntoskrnl.section_range("KVASCODE"))
            .as_ref()
    }

    /// The code a trap runs through before the kernel reports it to the
    /// debugger, as sorted, disjoint ranges: `find` finds it the first
    /// time, from the kernel's code and symbols, which only the target
    /// resolves.
    pub fn trap_dispatch_code(
        &self,
        find: impl FnOnce() -> Vec<Range<VirtAddr>>,
    ) -> &[Range<VirtAddr>] {
        self.trap_dispatch_code.get_or_init(find)
    }

    /// Where the VPs of the hypervisor image at `base` keep their saved
    /// registers, calibrated by `calibrate` the first time it succeeds and
    /// remembered for the boot.
    pub fn vp_register_layout(
        &self,
        base: u64,
        calibrate: impl FnOnce() -> Result<vp_registers::VpRegisterLayout>,
    ) -> Result<vp_registers::VpRegisterLayout> {
        let mut layouts = self
            .vp_register_layouts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(layout) = layouts.get(&base) {
            return Ok(*layout);
        }
        let layout = calibrate()?;
        layouts.insert(base, layout);
        Ok(layout)
    }

    /// The image mapped at `rip` in root `dtb`, found once with `find` and
    /// remembered for the boot. Finding one walks down page by page to its
    /// header, a read per page, on every stop and vCPU listing otherwise.
    /// `mapped` confirms a remembered image is still there.
    pub fn foreign_image(
        &self,
        dtb: Dtb,
        rip: VirtAddr,
        mapped: impl Fn(&ModuleInfo) -> bool,
        find: impl FnOnce() -> Option<ModuleInfo>,
    ) -> Option<ModuleInfo> {
        let mut images = self
            .foreign_images
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(index) = images
            .iter()
            .position(|(root, image)| *root == dtb && image.contains_address(rip))
        {
            if mapped(&images[index].1) {
                return Some(images[index].1.clone());
            }
            images.swap_remove(index);
        }
        let image = find()?;
        images.push((dtb, image.clone()));
        Some(image)
    }

    /// The image named `short_name` (`hv`) that a stop found in root `dtb`,
    /// and whether one was found in any other root.
    pub fn foreign_image_named(&self, dtb: Dtb, short_name: &str) -> (Option<ModuleInfo>, bool) {
        let images = self
            .foreign_images
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut named = images
            .iter()
            .filter(|(_, image)| image.short_name.eq_ignore_ascii_case(short_name));
        let elsewhere = named.clone().any(|(root, _)| *root != dtb);
        let here = named
            .find(|(root, _)| *root == dtb)
            .map(|(_, image)| image.clone());
        (here, elsewhere)
    }

    /// Whether `address`, read through root `dtb`, is the Windows
    /// hypervisor's: `dtb` is a root a stop found the `hv` image in, or
    /// `address` lies in that image, found in any root.
    pub fn is_hypervisor_address(&self, dtb: Dtb, address: VirtAddr) -> bool {
        self.is_hypervisor_root(dtb) || self.in_hypervisor_image(address)
    }

    /// Whether a stop found the `hv` image in root `dtb`.
    pub fn is_hypervisor_root(&self, dtb: Dtb) -> bool {
        let images = self
            .foreign_images
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        hypervisor_root(&images, dtb)
    }

    /// Whether `address` lies in the `hv` image, found in any root.
    pub fn in_hypervisor_image(&self, address: VirtAddr) -> bool {
        let images = self
            .foreign_images
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        hypervisor_image_contains(&images, address)
    }

    /// The names of a hypervisor image's code under `key` (its base, with
    /// the low bit set for names made with its file), made by `name` the
    /// first time and remembered for the boot, as finding none (`Ok(None)`)
    /// is. An error from `name` (an interrupted eVMCS scan) is not
    /// remembered: the next call makes the names again.
    pub fn hypervisor_symbols(
        &self,
        key: u64,
        name: impl FnOnce() -> Result<Option<hypercalls::HypervisorSymbols>>,
    ) -> Option<Arc<hypercalls::HypervisorSymbols>> {
        let mut symbols = self
            .hypervisor_symbols
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        remembered(&mut symbols, key, name)
    }

    /// [`hypervisor::slot_for`] in the slots of the last partition walk.
    pub fn vp_slot(
        &self,
        address: u64,
        ept_pointer: u64,
        walk: impl FnOnce() -> Option<HashMap<u64, hypervisor::VpSlot>>,
    ) -> Option<hypervisor::VpSlot> {
        let mut slots = self.vp_slots.lock().unwrap_or_else(PoisonError::into_inner);
        hypervisor::slot_for(&mut slots, address, ept_pointer, walk)
    }

    fn memo(&self) -> MutexGuard<'_, HaltMemo> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Serve `slot` from the current halt's memo, walking with `walk` on a
    /// miss. Memory without a halt signal is never memoized.
    fn memoized<T: Clone>(
        &self,
        slot: impl Fn(&mut HaltMemo) -> &mut Option<T>,
        walk: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let Some(epoch) = self.ntoskrnl.phys.halt_epoch() else {
            return walk();
        };
        {
            let mut memo = self.memo();
            if memo.epoch != Some(epoch) {
                *memo = HaltMemo {
                    epoch: Some(epoch),
                    ..HaltMemo::default()
                };
            }
            if let Some(list) = slot(&mut memo) {
                return Ok(list.clone());
            }
        }
        let list = walk()?;
        let mut memo = self.memo();
        if memo.epoch == Some(epoch) {
            *slot(&mut memo) = Some(list.clone());
        }
        Ok(list)
    }

    pub fn memoized_drivers(
        &self,
        walk: impl FnOnce() -> Result<Vec<DriverObjectInfo>>,
    ) -> Result<Vec<DriverObjectInfo>> {
        self.memoized(|memo| &mut memo.drivers, walk)
    }

    pub fn new_with_kernel_base_hint(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        kernel_base_hint: Option<VirtAddr>,
    ) -> Result<Self> {
        if let Some(base) = kernel_base_hint {
            let (dtb, arch) = find_kernel(&phys)?.ok_or(Error::NtoskrnlNotFound)?;
            return Self::at(phys, symbols, KernelLocation { dtb, base, arch });
        }
        Self::with_kernel(find_ntoskrnl(phys, symbols)?.ok_or(Error::NtoskrnlNotFound)?)
    }

    /// The guest whose kernel is at `location`, with no memory scan.
    pub fn at(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        location: KernelLocation,
    ) -> Result<Self> {
        Self::with_kernel(Image::new(
            phys,
            symbols,
            location.dtb,
            location.base,
            location.arch,
        ))
    }

    fn with_kernel(ntoskrnl: Image) -> Result<Self> {
        let ntoskrnl = Self::in_system_space(ntoskrnl.load_symbols()?)?;
        // Type/enum layout lookups prefer the kernel's definitions over
        // same-named user-mode types once attached to a process; tell the
        // symbol store which guid is the kernel's.
        ntoskrnl.register_as_kernel();
        Ok(Self::from_kernel(ntoskrnl))
    }

    pub fn new(phys: Arc<PhysMem>, symbols: Arc<SymbolStore>) -> Result<Self> {
        Self::new_with_kernel_base_hint(phys, symbols, None)
    }

    pub fn new_with_dtb(
        phys: Arc<PhysMem>,
        symbols: Arc<SymbolStore>,
        kernel_dtb: Dtb,
    ) -> Result<Self> {
        let is_triage = kernel_dtb == DTB_IDENTITY;

        // Dumps carry the machine type; live sessions reach this only from
        // discovery, which already resolved the arch.
        let arch = phys
            .dmp_info()
            .and_then(DmpInfo::arch)
            .unwrap_or(Arch::Amd64);

        let ntoskrnl_va = if is_triage {
            find_ntoskrnl_va_triage(kernel_dtb, &phys)?
        } else {
            find_ntoskrnl_va(arch, kernel_dtb, &phys)?
        };

        // For triage dumps, fall back to kern_base from KDDEBUGGER_DATA64
        // when the PE header page isn't captured in the dump.
        let ntoskrnl_va = match ntoskrnl_va {
            Some(va) => va,
            None if is_triage => phys
                .dmp_info()
                .and_then(|i| i.kern_base)
                .map(VirtAddr)
                .ok_or(Error::NtoskrnlNotFound)?,
            None => return Err(Error::NtoskrnlNotFound),
        };

        let obj = Image::new(
            Arc::clone(&phys),
            Arc::clone(&symbols),
            kernel_dtb,
            ntoskrnl_va,
            arch,
        );

        // Try normal symbol loading first; for triage dumps where the PE
        // header isn't in memory, fall back to downloading by image metadata.
        let ntoskrnl = match obj.load_symbols() {
            Ok(loaded) => loaded,
            Err(error) if is_triage => {
                // Without the driver list there is no fallback; the header
                // path's failure is the one to report.
                let Some(driver) = phys
                    .dmp_info()
                    .and_then(|info| info.triage_drivers.iter().find(|d| d.base == ntoskrnl_va.0))
                    .cloned()
                else {
                    return Err(error);
                };

                Image::new(phys, symbols, kernel_dtb, ntoskrnl_va, arch)
                    .load_symbols_from_module_info(
                        &driver.name,
                        driver.time_date_stamp,
                        driver.size,
                    )?
            }
            Err(e) => return Err(e),
        };
        let ntoskrnl = if is_triage {
            ntoskrnl
        } else {
            Self::in_system_space(ntoskrnl)?
        };

        ntoskrnl.register_as_kernel();
        Ok(Self::from_kernel(ntoskrnl))
    }

    /// `ntoskrnl`, its symbols loaded in the address space a transport
    /// named, moved to the System process's. KD names the stopped
    /// processor's, which is a user process's when the break-in interrupted
    /// one, and a dump header the one current at the crash; the kernel's
    /// modules are keyed by the kernel's space, which the symbol store shows
    /// from every process, so under a user process's space that process's
    /// own modules would show from every process too. The PDB is loaded
    /// already, so the second load only registers the module. AArch64's
    /// kernel root is TTBR1, which no process switch changes, and a
    /// process's `DirectoryTableBase` is its TTBR0, so it is left alone.
    fn in_system_space(ntoskrnl: Image) -> Result<Image> {
        if ntoskrnl.arch() != Arch::Amd64 {
            return Ok(ntoskrnl);
        }
        let Some(system) = system_dtb(&ntoskrnl) else {
            return Ok(ntoskrnl);
        };
        let mask = ntoskrnl.arch().dtb_page_mask();
        if system == ntoskrnl.dtb() & mask {
            return Ok(ntoskrnl);
        }
        ntoskrnl.symbols().clear_modules_for_dtb(ntoskrnl.dtb());
        Image::new(
            ntoskrnl.phys.clone(),
            ntoskrnl.symbols().clone(),
            system,
            ntoskrnl.base_address,
            ntoskrnl.arch(),
        )
        .load_symbols()
    }
}

/// The System process's address-space root, `PsInitialSystemProcess`'s
/// `KPROCESS.DirectoryTableBase`, masked to its page as a transport's
/// kernel root is.
fn system_dtb(kernel: &Image) -> Option<Dtb> {
    let system = kernel
        .symbol("PsInitialSystemProcess")
        .ok()?
        .read_pointer()
        .ok()?;
    let types = kernel.types();
    let pcb = types.layout("_EPROCESS").ok()?.field_offset("Pcb").ok()?;
    let offset = types
        .layout("_KPROCESS")
        .ok()?
        .field_offset("DirectoryTableBase")
        .ok()?;
    let dtb = kernel.memory().read::<u64>(system + pcb + offset).ok()?;
    Some(dtb & kernel.arch().dtb_page_mask()).filter(|dtb| *dtb != 0)
}

/// The first bit of a software PTE's page-file number
/// (`_MMPTE_SOFTWARE.PageFileLow`): bit 12 on kernels with the L1TF
/// mitigation, bit 1 before it. `None` when the PDB does not type it.
fn page_file_low(kernel: &Image) -> Option<u32> {
    let software = kernel.types().layout("_MMPTE_SOFTWARE").ok()?;
    match software.fields.get("PageFileLow")?.type_data {
        ParsedType::Bitfield { pos, .. } => Some(u32::from(pos)),
        _ => None,
    }
}

/// The kernel's `MiState.Hardware.InvalidPteMask`: the bits it sets in a
/// non-present PTE's frame so a speculative load through it reaches no real
/// memory (the L1TF mitigation). `None` on a build without one.
fn invalid_pte_mask(kernel: &Image) -> Option<u64> {
    let state = kernel.symbol("MiState").ok()?.address();
    let types = kernel.types();
    let hardware = types
        .layout("_MI_SYSTEM_INFORMATION")
        .ok()?
        .field_offset("Hardware")
        .ok()?;
    let mask = types
        .layout("_MI_HARDWARE_STATE")
        .ok()?
        .field_offset("InvalidPteMask")
        .ok()?;
    kernel.memory().read::<u64>(state + hardware + mask).ok()
}

/// The RVAs of the kernel functions the store layout is read from, by
/// name.
fn store_functions(kernel: &Image) -> Option<HashMap<String, u64>> {
    let guid = kernel.guid?;
    let symbols = kernel.symbols();
    let mut names: Vec<String> = [
        "SMKM_STORE<SM_TRAITS>::",
        "SMKM_STORE_MGR<SM_TRAITS>::",
        "ST_STORE<SM_TRAITS>::",
        "B_TREE<_SM_PAGE_KEY, ",
    ]
    .iter()
    .flat_map(|prefix| symbols.names_starting_with(guid, prefix))
    .collect();
    names.extend(
        [
            "SmStoreDecompressBuffer",
            "RtlDecompressBufferEx",
            "RtlDecompressBufferProcs",
            "KeStackAttachProcess",
            "KiStackAttachProcess",
        ]
        .map(String::from),
    );
    Some(
        names
            .into_iter()
            .filter_map(|name| {
                let rva = symbols.symbol_rva(guid, &name).ok()??;
                Some((name, u64::from(rva)))
            })
            .collect(),
    )
}

/// The file names the symbol servers keep kernels under: the usual one,
/// and x64's kernel for 5-level paging.
const KERNEL_FILE_NAMES: [&str; 2] = ["ntoskrnl.exe", "ntkrla57.exe"];

/// The kernel's file, matched by its mapped header page `mapped`: from the
/// image cache, and from the symbol servers too when reads go through the
/// target, where reading the kernel's 12 MiB of code takes over half a
/// minute.
fn kernel_file(kernel: &Image, mapped: &[u8]) -> Option<Arc<PeImage>> {
    let fetches: &[ImageFetch] = if kernel.phys.reads_through_target() {
        &[ImageFetch::CacheOnly, ImageFetch::Download]
    } else {
        &[ImageFetch::CacheOnly]
    };
    fetches
        .iter()
        .flat_map(|&fetch| KERNEL_FILE_NAMES.map(|name| (name, fetch)))
        .find_map(|(name, fetch)| kernel.symbols().module_image_matching(name, mapped, fetch))
}

/// The layout of the kernel's memory-compression store, from its code
/// (AMD64, 1703 and later): the kernel file's when [`kernel_file`] finds
/// it, at the file's own base as the corpus test reads it, else the mapped
/// image's.
fn store_layout_of(kernel: &mut Image, interrupt: &AtomicBool) -> Option<StoreLayout> {
    let headers = kernel.view()?.image().to_vec();
    let functions = store_functions(kernel)?;
    let arch = kernel.arch();
    let derive = |base: u64, bytes: &[u8], code: Vec<(u32, u32)>| {
        let functions = functions
            .iter()
            .map(|(name, rva)| (name.clone(), base + rva))
            .collect();
        let code = store_layout::KernelCode {
            image: hv_layout::ImageView {
                base,
                bytes,
                code,
                data: Vec::new(),
            },
            functions: &functions,
        };
        match arch {
            Arch::Amd64 => store_layout::derive(&code),
            Arch::Arm64 => store_layout::arm64::derive(&code),
        }
        .ok()
    };
    if let Some(file) = kernel_file(kernel, &headers) {
        let bytes = file.headers();
        let view = PeView::from_bytes(bytes).ok()?;
        return derive(
            view.optional_header().ImageBase,
            bytes,
            pe::executable_ranges(&view),
        );
    }
    let base = kernel.base_address.0;
    let code = store_layout::mapped_code(&kernel.memory(), base, &headers, interrupt).ok()?;
    derive(base, &code.bytes, code.code)
}

/// The guest's memory-compression store, when its PDB types the
/// partition's store fields, the store has an owner process (it has none
/// when compression is off, or before the store manager creates it after
/// boot), and the kernel's code gives the layout. `layout` keeps the
/// derivation's outcome, so the code is read once: a layout the code does
/// not give is not looked for again, unless Ctrl+C (`interrupt`) stopped
/// the derivation.
fn compressed_pages(
    kernel: &mut Image,
    layout: &mut Option<Option<StoreLayout>>,
    interrupt: &AtomicBool,
) -> Option<CompressedPages> {
    let memory = kernel.memory();
    let types = kernel.types();
    let partition = kernel.symbol("MiSystemPartition").ok()?.address();
    let partition_type = types.layout("_MI_PARTITION").ok()?;
    let stores_type = types.layout("_MI_PARTITION_STORES").ok()?;
    let stores = partition + partition_type.field_offset("Store").ok()?;
    let page_file = memory
        .read::<u32>(stores + stores_type.field_offset("VirtualPageFileNumber").ok()?)
        .ok()?;
    let owner = memory
        .read_pointer(stores + stores_type.field_offset("StoreProcess").ok()?)
        .ok()?;
    if owner.0 == 0 {
        return None;
    }
    // From 22H2 the manager is the system partition's SmPartition; before
    // it, SmGlobals itself.
    let manager = match types
        .layout("_EPARTITION")
        .ok()
        .and_then(|epartition| epartition.field_offset("SmPartition").ok())
    {
        Some(sm_partition) => {
            let core = partition_type.field_offset("Core").ok()?
                + types
                    .layout("_MI_PARTITION_CORE")
                    .ok()?
                    .field_offset("PartitionObject")
                    .ok()?;
            let epartition = memory.read_pointer(partition + core).ok()?;
            memory.read_pointer(epartition + sm_partition).ok()?.0
        }
        None => kernel.symbol("SmGlobals").ok()?.address().0,
    };
    let eprocess = types.layout("_EPROCESS").ok()?;
    let kprocess = types.layout("_KPROCESS").ok()?;
    let root = memory
        .read::<u64>(
            owner
                + eprocess.field_offset("Pcb").ok()?
                + kprocess.field_offset("DirectoryTableBase").ok()?,
        )
        .ok()?;
    let owner_root = root & kernel.arch().dtb_page_mask();
    let layout = match layout {
        Some(known) => known.clone()?,
        None => {
            let derived = store_layout_of(kernel, interrupt);
            if derived.is_some() || !interrupt.load(Ordering::Relaxed) {
                *layout = Some(derived.clone());
            }
            derived?
        }
    };
    Some(CompressedPages {
        layout,
        manager: VirtAddr(manager),
        owner,
        owner_root,
        page_file: u8::try_from(page_file).ok()?,
    })
}

/// Where the kernel keeps what [`SectionViews`] reads: the process list and
/// each process's VAD tree. `None` when the PDB lacks any of it.
fn section_layout(kernel: &Image) -> Option<SectionLayout> {
    let types = kernel.types();
    let eprocess = types.layout("_EPROCESS").ok()?;
    let kprocess = types.layout("_KPROCESS").ok()?;
    let short = types.layout("_MMVAD_SHORT").ok()?;
    let links = VadTreeOffsets::resolve(types, &short, MissingOffset::Fail).ok()?;
    let vad = types.layout("_MMVAD").ok()?;
    let flags = types.layout("_MMVAD_FLAGS").ok()?;
    let ParsedType::Bitfield { pos, .. } = flags.fields.get("PrivateMemory")?.type_data else {
        return None;
    };
    Some(SectionLayout {
        process_list_head: kernel.symbol("PsActiveProcessHead").ok()?.address(),
        active_process_links: eprocess.field_offset("ActiveProcessLinks").ok()?,
        directory_table_base: eprocess.field_offset("Pcb").ok()?
            + kprocess.field_offset("DirectoryTableBase").ok()?,
        root_mask: kernel.arch().dtb_page_mask(),
        vad_root: vad_root_offset(types, &eprocess).ok()?,
        left: links.left,
        right: links.right,
        vad_node: links.vad_node,
        starting_vpn: short.field_offset("StartingVpn").ok()?,
        ending_vpn: short.field_offset("EndingVpn").ok()?,
        starting_vpn_high: short.field_offset("StartingVpnHigh").ok(),
        ending_vpn_high: short.field_offset("EndingVpnHigh").ok(),
        vad_flags: short.field_offset("u").ok()?,
        private_memory_bit: u32::from(pos),
        first_prototype_pte: vad.field_offset("FirstPrototypePte").ok()?,
        last_contiguous_pte: vad.field_offset("LastContiguousPte").ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HV_ROOT: Dtb = 0x1_1514_0000;
    const NT_ROOT: Dtb = 0x1ae000;

    fn images() -> Vec<(Dtb, ModuleInfo)> {
        vec![
            (
                HV_ROOT,
                ModuleInfo::new(
                    "hvix64.exe".to_string(),
                    VirtAddr(0xffff_f840_b140_0000),
                    0x40_0000,
                ),
            ),
            (
                0x460_0000,
                ModuleInfo::new(
                    "securekernel.exe".to_string(),
                    VirtAddr(0xffff_f805_290d_3000),
                    0x20_0000,
                ),
            ),
        ]
    }

    #[test]
    fn the_root_a_stop_found_the_hypervisor_in_is_its_and_no_other() {
        assert!(hypervisor_root(&images(), HV_ROOT));
        assert!(!hypervisor_root(&images(), NT_ROOT));
        assert!(!hypervisor_root(&images(), 0x460_0000));
    }

    #[test]
    fn only_addresses_in_the_hypervisor_image_are_in_it() {
        assert!(hypervisor_image_contains(
            &images(),
            VirtAddr(0xffff_f840_b168_31e0)
        ));
        assert!(!hypervisor_image_contains(
            &images(),
            VirtAddr(0xffff_f805_9313_d130)
        ));
        assert!(!hypervisor_image_contains(
            &images(),
            VirtAddr(0xffff_f805_290d_4000)
        ));
    }

    #[test]
    fn an_interrupted_naming_is_retried_and_finding_nothing_is_not() {
        let mut cache = HashMap::new();
        let interrupted = Error::SavedVtlState("eVMCS scan interrupted".to_string());
        assert_eq!(remembered::<u32>(&mut cache, 1, || Err(interrupted)), None);
        assert_eq!(
            remembered(&mut cache, 1, || Ok(Some(7))).as_deref(),
            Some(&7)
        );
        assert_eq!(
            remembered(&mut cache, 1, || Ok(Some(8))).as_deref(),
            Some(&7)
        );

        assert_eq!(remembered::<u32>(&mut cache, 2, || Ok(None)), None);
        assert_eq!(remembered(&mut cache, 2, || Ok(Some(9))), None);
    }
}
