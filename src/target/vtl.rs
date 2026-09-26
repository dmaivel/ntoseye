//! Explicit secure-kernel inspection, and naming code that runs outside NT's
//! address spaces under VBS. Selecting a VTL changes address-space reads and
//! symbol scope, not the executing processor's VTL or registers.

use std::collections::HashMap;
use std::sync::Arc;

use pelite::{PeView, image::IMAGE_FILE_DLL};

use super::Target;
use crate::{
    backend::MemoryOps,
    cpu_state::kpcr_for_processor,
    error::{Error, Result},
    guest::{
        EvmcsState, Guest, ModuleInfo, ModuleSymbolLoadReport, SecureKernel, SessionSpace,
        TrustletInfo,
    },
    memory::{AddressSpace, PAGE_SIZE},
    pe::{read_pe_header_page, size_of_image},
    symbols::SymbolStore,
    types::{Arch, Dtb, PhysAddr, VirtAddr},
};

/// How far below an instruction pointer to look for the header of the image
/// it lies in. The Windows hypervisor and secure kernel are a few MiB.
const IMAGE_SEARCH_BYTES: u64 = 16 * 1024 * 1024;

/// The context of code in the Windows hypervisor's image.
pub const HYPERVISOR_CONTEXT: &str = "hypervisor";

/// Code a vCPU was executing outside every NT address space, named by what
/// it is rather than left `unknown`.
#[derive(Debug, Clone)]
pub struct ForeignCode {
    /// `hypervisor`, `VTL1`, or the name of the image the code lies in.
    pub context: String,
    pub modules: ForeignModules,
}

/// The modules a trace of foreign code unwinds and symbolizes with.
#[derive(Debug, Clone)]
pub enum ForeignModules {
    /// VTL1 with the secure kernel discovered: its loaded modules, whose
    /// symbols are registered under its system root `root`.
    SecureKernel { root: Dtb, modules: Vec<ModuleInfo> },
    /// The image the code lies in, mapped in the stopped address space.
    Image(ModuleInfo),
    /// A known VTL1 root outside any image (trustlet heap or stack).
    None,
}

/// One VTL of the virtual processor a vCPU halted in the Windows hypervisor
/// runs, as the hypervisor last saved it in the VTL's Enlightened VMCS.
#[derive(Debug, Clone)]
pub struct SavedVtlContext {
    pub vtl: u8,
    pub state: EvmcsState,
}

impl SavedVtlContext {
    /// The saved registers under the names the register display and the
    /// unwinder use. A VMCS holds no general-purpose register but RSP: the
    /// hypervisor keeps the rest in its own undocumented VP state.
    pub fn registers(&self) -> HashMap<String, u64> {
        let state = &self.state;
        [
            ("rip", state.rip),
            ("rsp", state.rsp),
            ("eflags", state.rflags),
            ("cr0", state.cr0),
            ("cr3", state.cr3),
            ("cr4", state.cr4),
            ("dr7", state.dr7),
            ("cs", u64::from(state.cs)),
            ("ss", u64::from(state.ss)),
            ("ds", u64::from(state.ds)),
            ("es", u64::from(state.es)),
            ("fs", u64::from(state.fs)),
            ("gs", u64::from(state.gs)),
            ("fs_base", state.fs_base),
            ("gs_base", state.gs_base),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect()
    }
}

impl Target {
    /// Whether Windows runs as the root partition of its own hypervisor
    /// (`hvix64`: VBS, Hyper-V, WSL2) rather than directly on the host's.
    /// NT records it in `HvlHyperVRootPartition`; a kernel without the symbol
    /// or an unreadable byte counts as not.
    pub fn windows_hypervisor_running(&self) -> bool {
        self.guest
            .as_ref()
            .and_then(|guest| guest.ntoskrnl.symbol("HvlHyperVRootPartition").ok())
            .and_then(|flag| flag.read::<u8>().ok())
            .is_some_and(|flag| flag != 0)
    }

    /// Whether inspection is rooted in the secure kernel or a trustlet.
    pub fn in_secure_scope(&self) -> bool {
        self.secure_root.is_some()
    }

    /// An explicit VTL1 memory view or the address space of a live VTL1 stop.
    /// Unlike `in_secure_scope`, this does not imply that registers are hidden.
    pub fn in_secure_address_space(&self) -> bool {
        self.in_secure_scope() || self.symbols.is_secure_root(self.current_dtb())
    }

    /// Recognize a halted CPU's root by the secure kernel's physical image,
    /// including trustlets not yet listed by `!trustlets`. No discovery scan.
    pub fn recognize_secure_root(&self, dtb: Dtb) -> bool {
        let dtb = self.normalize_dtb(dtb);
        if self.symbols.is_secure_root(dtb) {
            return true;
        }
        if dtb == self.kernel_dtb() {
            return false;
        }
        let Some(secure) = self
            .guest
            .as_ref()
            .and_then(|guest| guest.cached_secure_kernel())
        else {
            return false;
        };
        let base = secure.image.base_address;
        let physical = |root| {
            self.address_space(root)
                .virt_to_phys(base)
                .ok()
                .flatten()
                .map(|page| page.address)
        };
        let Some(expected) = physical(secure.image.dtb()) else {
            return false;
        };
        if physical(dtb) != Some(expected) {
            return false;
        }
        self.symbols.set_secure_roots(secure.image.dtb(), [dtb]);
        true
    }

    /// A loaded secure-kernel module, even when the caller is inspecting NT.
    /// Used to reject code patching through numeric SDK addresses as well as
    /// through the explicit VTL1 symbol scope.
    pub fn is_secure_address(&self, address: VirtAddr) -> bool {
        self.symbols.is_secure_address(address)
    }

    /// Return inspection to VTL0 without touching the process or register
    /// selection, for a stop whose context now belongs to the halted vCPU.
    pub fn leave_secure_scope(&mut self) {
        self.secure_root = None;
    }

    /// Discover the secure kernel from host RAM on first use. No target state
    /// is changed; unsupported sources and architectures return an error.
    pub fn secure_kernel(&self) -> Result<Arc<SecureKernel>> {
        self.guest()?
            .secure_kernel(&self.phys, &self.symbols, &self.interrupt)
    }

    /// Validated secure processes, correlated with the NT process list.
    pub fn trustlets(&self) -> Result<Vec<TrustletInfo>> {
        let secure = self.secure_kernel()?;
        let processes = secure.trustlets(self.guest()?)?;
        self.symbols
            .set_secure_roots(secure.image.dtb(), processes.iter().map(|p| p.dtb));
        Ok(processes)
    }

    /// The VTL states the Windows hypervisor saved for the virtual processor
    /// a vCPU halted in the hypervisor runs: `cr3` is that vCPU's (the
    /// hypervisor's root for the VP) and `processor` the NT processor it is.
    /// VTL0 first, then VTL1 when the secure kernel is already discovered.
    ///
    /// The states come from Enlightened VMCS pages, which exist only when the
    /// VM exposes `hv-evmcs`. The first call of a boot scans host RAM for
    /// them (about 0.6 s for 8 GiB). Empty when this VP has no eVMCS; see
    /// [`Self::evmcs_found`] for whether any exists.
    ///
    /// A state counts as VTL0 only in an NT root, and, in kernel mode, only
    /// with `processor`'s KPCR as its GS base; as VTL1 only in a secure-kernel
    /// root. States of other partitions' VPs sharing the root are skipped.
    pub fn saved_vtl_contexts(
        &self,
        cr3: u64,
        processor: Option<u16>,
    ) -> Result<Vec<SavedVtlContext>> {
        if self.arch() != Arch::Amd64 {
            return Ok(Vec::new());
        }
        let mask = self.arch().dtb_page_mask();
        let pages = self
            .guest()?
            .evmcs_pages(&self.phys, &self.interrupt, cr3, mask)?;
        let kernel = self.kernel_dtb() & mask;
        let (mut vtl0, mut vtl1) = (Vec::new(), Vec::new());
        for state in pages.states_for_root(&*self.phys, cr3, mask) {
            let root = state.cr3 & mask;
            if root == kernel || self.process_for_cr3(root).is_some() {
                vtl0.push(state);
            } else if self.recognize_secure_root(root) {
                vtl1.push(state);
            }
        }
        let one = |states: Vec<EvmcsState>, vtl: u8| match states.as_slice() {
            [] => Ok(None),
            [state] => Ok(Some(SavedVtlContext { vtl, state: *state })),
            many => Err(Error::SavedVtlState(format!(
                "{} eVMCS pages of this virtual processor hold VTL{vtl} state",
                many.len()
            ))),
        };
        let vtl0 = one(vtl0, 0)?;
        if let (Some(saved), Some(processor)) = (&vtl0, processor)
            && saved.state.cs & 3 == 0
        {
            let kpcr = kpcr_for_processor(self, processor)?;
            if saved.state.gs_base != kpcr.0 {
                return Err(Error::SavedVtlState(format!(
                    "the saved VTL0 GS base {:#x} is not NT processor {processor}'s KPCR {:#x}",
                    saved.state.gs_base, kpcr.0
                )));
            }
        }
        Ok(vtl0.into_iter().chain(one(vtl1, 1)?).collect())
    }

    /// Whether this boot's eVMCS scan found any page; `None` before a scan.
    pub fn evmcs_found(&self) -> Option<bool> {
        let pages = self.guest.as_ref()?.cached_evmcs_pages()?;
        Some(!pages.is_empty())
    }

    /// Enter VTL1's system space, or a trustlet by its NT PID. The selection
    /// commits only after discovery and module loading succeed. Register and
    /// thread selections are cleared: VTL0 context is not VTL1 context.
    pub fn select_secure_scope(&mut self, pid: Option<u64>) -> Result<ModuleSymbolLoadReport> {
        let secure = self.secure_kernel()?;
        let root = if let Some(pid) = pid {
            self.trustlets()?
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| Error::SecureKernel(format!("no trustlet with NT PID {pid}")))?
                .dtb
        } else {
            self.symbols.set_secure_roots(secure.image.dtb(), []);
            secure.image.dtb()
        };
        let report = self.load_secure_kernel_symbols()?;
        self.enter_secure_scope(root);
        self.registers = None;
        Ok(report)
    }

    /// Index the secure kernel's modules' symbols under its system root,
    /// discovering it first. Modules already loaded are not fetched again.
    pub fn load_secure_kernel_symbols(&self) -> Result<ModuleSymbolLoadReport> {
        let secure = self.secure_kernel()?;
        self.symbols.set_secure_roots(secure.image.dtb(), []);
        let modules = secure.modules(self.guest()?)?;
        Guest::load_module_symbols(
            &self.phys,
            &self.symbols,
            modules,
            secure.image.dtb(),
            SessionSpace::Load,
            self.arch(),
        )
    }

    /// Scope reads and symbol lookups to a secure root already validated by
    /// discovery or [`Self::trustlets`], as [`Self::enter_process_scope`]
    /// does for a process. Nothing is loaded; see
    /// [`Self::load_secure_kernel_symbols`].
    pub fn enter_secure_scope(&mut self, root: Dtb) {
        self.detach();
        self.secure_root = Some(root);
    }

    /// Name the code at `rip` in the address space `cr3` when that space is
    /// none of NT's. Under VBS an idle or intercepted vCPU halts inside the
    /// Windows hypervisor, and a vCPU can halt in VTL1; both are identified
    /// by the image the code lies in (its CodeView PDB name), which needs no
    /// prior discovery. `None` when `rip` lies in no image of an unknown root.
    pub fn identify_foreign_code(&self, cr3: u64, rip: u64) -> Option<ForeignCode> {
        let dtb = cr3 & self.arch().dtb_page_mask();
        let secure_root = self.symbols.is_secure_root(dtb);
        let memory = self.address_space(dtb);
        let find = || image_containing(&memory, rip);
        let image = match &self.guest {
            Some(guest) => guest.foreign_image(
                dtb,
                VirtAddr(rip),
                |image| {
                    let mut magic = [0u8; 2];
                    memory.read_bytes(image.base_address, &mut magic).is_ok() && magic == *b"MZ"
                },
                find,
            ),
            None => find(),
        };
        let context = match &image {
            Some(image) => match image.short_name.as_str() {
                "hvix64" | "hvax64" | "hvaa64" => HYPERVISOR_CONTEXT.to_string(),
                "securekernel" => "VTL1".to_string(),
                _ if secure_root => "VTL1".to_string(),
                name => name.to_string(),
            },
            None if secure_root => "VTL1".to_string(),
            None => return None,
        };
        // Every VTL1 root maps the secure kernel's modules, and their symbols
        // live under its system root.
        let secure = (context == "VTL1")
            .then(|| self.guest.as_ref()?.cached_secure_kernel())
            .flatten()
            .and_then(|secure| {
                let modules = secure.modules(self.guest.as_ref()?).ok()?;
                self.symbols.set_secure_roots(secure.image.dtb(), [dtb]);
                Some(ForeignModules::SecureKernel {
                    root: secure.image.dtb(),
                    modules,
                })
            });
        let modules = secure
            .or_else(|| image.map(ForeignModules::Image))
            .unwrap_or(ForeignModules::None);
        Some(ForeignCode { context, modules })
    }
}

/// The image mapped at `rip`, named by its CodeView PDB and found by walking
/// down page by page to its header. Unmapped pages are skipped (images drop
/// discardable sections); a header whose image ends below `rip` means `rip`
/// lies in no image.
fn image_containing<B: MemoryOps<PhysAddr>>(
    memory: &AddressSpace<'_, B>,
    rip: u64,
) -> Option<ModuleInfo> {
    let page_mask = PAGE_SIZE as u64 - 1;
    let top = rip & !page_mask;
    let floor = top.saturating_sub(IMAGE_SEARCH_BYTES);
    let mut page = top;
    loop {
        let mut magic = [0u8; 2];
        if memory.read_bytes(VirtAddr(page), &mut magic).is_ok()
            && magic == *b"MZ"
            && let Ok(headers) = read_pe_header_page(VirtAddr(page), memory)
            && let Ok(view) = PeView::from_bytes(&headers)
        {
            let size = size_of_image(&view);
            if rip - page >= u64::from(size) {
                return None;
            }
            let path = SymbolStore::codeview_pdb_path(memory, VirtAddr(page))
                .ok()
                .flatten()?;
            let file = path.rsplit(['\\', '/']).next().unwrap_or(&path);
            // The loader's name is not in memory; the PDB's stem is the
            // image's, and the header says which kind of file it was.
            let stem = file.rsplit_once('.').map_or(file, |(stem, _)| stem);
            let extension = if view.file_header().Characteristics & IMAGE_FILE_DLL != 0 {
                "dll"
            } else {
                "exe"
            };
            let name = format!("{stem}.{extension}");
            return Some(ModuleInfo::new(name, VirtAddr(page), size));
        }
        if page <= floor {
            return None;
        }
        page -= PAGE_SIZE as u64;
    }
}
