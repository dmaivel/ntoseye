use crate::{
    dmp::DmpInfo,
    error::{Error, Result},
    memory::DTB_IDENTITY,
    phys::PhysMem,
    symbols::SymbolStore,
    target::ListTermination,
    target::object::DriverObjectInfo,
    types::*,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

mod discovery;
mod image;
mod modules;
mod process;
mod secure_kernel;
mod symbol_load;
mod trustlet_layout;

use discovery::{
    find_kernel, find_ntoskrnl, find_ntoskrnl_va, find_ntoskrnl_va_arm64, find_ntoskrnl_va_triage,
};
pub use image::{Image, SymbolRef};
pub use secure_kernel::{SecureKernel, TrustletInfo};

/// A process's identity and the root (`dtb`) of its address space.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u64,
    pub name: String,
    pub dtb: Dtb,
    pub eprocess_va: VirtAddr,
    /// The 32-bit PEB of a WOW64 process (`_EPROCESS.WoW64Process`), `None`
    /// for a native process.
    pub wow64_peb: Option<VirtAddr>,
}

impl ProcessInfo {
    pub fn is_wow64(&self) -> bool {
        self.wow64_peb.is_some()
    }
}

/// module metadata from PEB LDR list
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub short_name: String,
    pub path: Option<String>,
    pub base_address: VirtAddr,
    pub size: u32,
    /// From a WOW64 process's 32-bit loader list: x86 code, 4-byte pointers.
    pub is_32bit: bool,
    pub entry_point: Option<VirtAddr>,
    pub time_date_stamp: Option<u32>,
    pub checksum: Option<u32>,
    pub file_version: Option<String>,
    pub product_version: Option<String>,
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
            _ => lowered,
        }
    }

    pub fn end_address(&self) -> VirtAddr {
        VirtAddr(self.base_address.0.saturating_add(self.size as u64))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleSymbolDiagnostic {
    pub module: String,
    pub phase: &'static str,
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

#[derive(Debug, Clone, Default)]
pub struct ModuleSymbolLoadReport {
    pub total: usize,
    pub loaded: usize,
    /// Symbol-bearing modules removed from this DTB since the previous refresh.
    pub unloaded: usize,
    pub no_pdb: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Handed to the background fetcher; not yet loaded or failed.
    pub fetching: usize,
    pub diagnostic_count: usize,
    pub diagnostics: Vec<ModuleSymbolDiagnostic>,
}

pub struct Guest {
    pub ntoskrnl: Image,
    memo: Mutex<HaltMemo>,
    secure_kernel: Mutex<Option<Arc<SecureKernel>>>,
    /// Images found outside NT's address spaces (the Windows hypervisor), by
    /// root. They stay mapped for the boot, and this `Guest` is the boot's.
    foreign_images: Mutex<Vec<(Dtb, ModuleInfo)>>,
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

impl Guest {
    pub fn from_kernel(ntoskrnl: Image) -> Self {
        Self {
            ntoskrnl,
            memo: Mutex::new(HaltMemo::default()),
            secure_kernel: Mutex::new(None),
            foreign_images: Mutex::new(Vec::new()),
        }
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
        let ntoskrnl = ntoskrnl.load_symbols()?;
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
            match arch {
                Arch::Amd64 => find_ntoskrnl_va(kernel_dtb, &phys)?,
                Arch::Arm64 => find_ntoskrnl_va_arm64(kernel_dtb, &phys)?,
            }
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

        ntoskrnl.register_as_kernel();
        Ok(Self::from_kernel(ntoskrnl))
    }
}
