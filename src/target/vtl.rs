//! Explicit secure-kernel inspection, and naming code that runs outside NT's
//! address spaces under VBS. Selecting a VTL changes address-space reads and
//! symbol scope, not the executing processor's VTL or registers.

use std::collections::HashMap;
use std::sync::Arc;

use pelite::{PeView, image::IMAGE_FILE_DLL};

use super::{SelectedFrame, Target};
use crate::{
    backend::MemoryOps,
    cpu_state::kpcr_for_processor,
    dbg_backend::processor_index_from_backend_thread_id,
    error::{Error, Result},
    guest::{
        EXIT_GPRS, EvmcsState, Guest, HvMemory, HvPartition, ModuleInfo, ModuleSymbolLoadReport,
        PdbRecovery, SecureKernel, SessionSpace, TrustletInfo,
        ept::{self, EptTranslation},
        hv_layout,
        hv_layout::HypercallEntry,
        hypercalls, hypervisor,
    },
    memory::{AddressSpace, PAGE_SIZE},
    pe::{read_pe_header_page, size_of_image},
    phys::PhysMem,
    symbols::SymbolStore,
    types::{Arch, Dtb, PhysAddr, VirtAddr},
    unwind::halted_in_windows_hypervisor,
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
    /// The vCPU is on the hypervisor's VM-exit entry point (`host_rip`) and
    /// did not stop there on a breakpoint, so this state may describe the
    /// exit before the one in progress. KVM writes the eVMCS when it enters
    /// the hypervisor, and a stop from outside can fall between an exit and
    /// that entry; a breakpoint fires only once the hypervisor runs.
    pub may_be_stale: bool,
    /// The general-purpose registers of the exit, where the hypervisor's
    /// exit entry code saved them (see [`crate::guest::ExitRegisterLayout`]),
    /// or why they are not known: only the current VTL's are, once the
    /// vCPU is past the entry code's stores, or, stopped on a breakpoint on
    /// the entry, the vCPU's own.
    pub general_registers: std::result::Result<HashMap<&'static str, u64>, String>,
}

/// A vCPU that stopped on an instruction breakpoint at the current stop:
/// its processor, where, and its general-purpose registers then. An
/// instruction breakpoint fires only when the instruction runs, so one on
/// the Windows hypervisor's `host_rip` means KVM has already written the
/// eVMCS for the exit, and a VM exit loads only RSP and RIP, so the other
/// registers are still the guest's at that exit.
#[derive(Debug, Clone)]
pub struct BreakpointStop {
    processor: u16,
    rip: u64,
    general_registers: HashMap<&'static str, u64>,
}

impl BreakpointStop {
    /// The stop of `vcpu`, whose live registers are `registers`, on an
    /// instruction breakpoint at `rip`. `None` when `vcpu` names no
    /// processor or a general-purpose register is missing.
    pub fn new(vcpu: &str, rip: u64, registers: &HashMap<String, u64>) -> Option<Self> {
        Some(Self {
            processor: processor_index_from_backend_thread_id(vcpu)?,
            rip,
            general_registers: EXIT_GPRS
                .iter()
                .map(|name| Some((*name, *registers.get(*name)?)))
                .collect::<Option<_>>()?,
        })
    }
}

impl SavedVtlContext {
    /// The saved registers under the names the register display and the
    /// unwinder use. A VMCS holds no general-purpose register but RSP; the
    /// rest come from where the hypervisor saved them, when known.
    pub fn registers(&self) -> HashMap<String, u64> {
        let state = &self.state;
        let mut registers: HashMap<String, u64> = [
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
        .collect();
        if let Ok(general) = &self.general_registers {
            registers.extend(
                general
                    .iter()
                    .map(|(name, value)| (name.to_string(), *value)),
            );
        }
        registers
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

    /// Whether `address` lies in the Windows hypervisor's image, as a stop
    /// found it in any root.
    pub fn in_hypervisor_image(&self, address: VirtAddr) -> bool {
        self.guest
            .as_ref()
            .is_some_and(|guest| guest.in_hypervisor_image(address))
    }

    /// Whether inspection is in the hypervisor's address space: a stop in it,
    /// whose context `.cxr` selected.
    pub fn in_hypervisor_address_space(&self) -> bool {
        self.guest
            .as_ref()
            .is_some_and(|guest| guest.is_hypervisor_root(self.normalize_dtb(self.current_dtb())))
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
    /// a vCPU halted in the hypervisor runs: `cr3` and `rip` are that vCPU's
    /// (the hypervisor's root for the VP, and where it is in the hypervisor)
    /// and `processor` the NT processor it is.
    /// VTL0 first, then VTL1. VTL1's roots are recognized by the secure
    /// kernel's image, so the first state outside NT's address spaces looks
    /// for the secure kernel, once per boot.
    ///
    /// The states come from Enlightened VMCS pages, which exist only when the
    /// VM exposes `hv-evmcs`. The first call of a boot scans host RAM for
    /// them (about 0.6 s for 8 GiB). Empty when this VP has no eVMCS; see
    /// [`Self::evmcs_found`] for whether any exists.
    ///
    /// A state counts as VTL0 only in an NT root, and, in kernel mode, only
    /// with `processor`'s KPCR as its GS base; as VTL1 only in a secure-kernel
    /// root. States of other partitions' VPs sharing the root are skipped.
    /// A vCPU on the pages' `host_rip` marks every state `may_be_stale`,
    /// unless it stopped there on a breakpoint ([`Self::breakpoint_stop`]).
    pub fn saved_vtl_contexts(
        &self,
        cr3: u64,
        rip: u64,
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
        let entered = self
            .breakpoint_stop
            .as_ref()
            .filter(|stop| Some(stop.processor) == processor && stop.rip == rip);
        let (mut vtl0, mut vtl1) = (Vec::new(), Vec::new());
        let mut outside_nt = Vec::new();
        for state in pages.states_for_root(&*self.phys, cr3, mask) {
            let root = state.cr3 & mask;
            if root == kernel || self.process_for_cr3(root).is_some() {
                vtl0.push(state);
            } else {
                outside_nt.push(state);
            }
        }
        if !outside_nt.is_empty() {
            self.guest()?
                .secure_kernel_if_found(&self.phys, &self.symbols, &self.interrupt);
            vtl1.extend(
                outside_nt
                    .into_iter()
                    .filter(|state| self.recognize_secure_root(state.cr3 & mask)),
            );
        }
        let one = |states: Vec<EvmcsState>, vtl: u8| match states.as_slice() {
            [] => Ok(None),
            [state] => Ok(Some(SavedVtlContext {
                vtl,
                state: *state,
                may_be_stale: rip == state.host_rip && entered.is_none(),
                general_registers: self.saved_general_registers(cr3 & mask, rip, state, entered),
            })),
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

    /// The general-purpose registers of `state`'s last exit, for a vCPU at
    /// `rip` on the hypervisor root `root`: read where the hypervisor's exit
    /// entry code saved them. The block they are in holds the last exit,
    /// from whichever VTL made it, so only the current VTL's state has them, and only once the vCPU is past the stores. A
    /// vCPU that `entered` the hypervisor on a breakpoint on `host_rip` still
    /// holds them itself.
    fn saved_general_registers(
        &self,
        root: u64,
        rip: u64,
        state: &EvmcsState,
        entered: Option<&BreakpointStop>,
    ) -> std::result::Result<HashMap<&'static str, u64>, String> {
        if !state.current {
            return Err("the hypervisor last saved another VTL's registers".to_string());
        }
        if rip == state.host_rip {
            return match entered {
                Some(stop) => Ok(stop.general_registers.clone()),
                None => Err(
                    "the vCPU is on the VM-exit entry: the guest's registers are still its own"
                        .to_string(),
                ),
            };
        }
        let guest = self.guest().map_err(|error| error.to_string())?;
        let memory = self.address_space(root);
        let layout = guest.exit_register_layout(state.host_rip, |code| {
            memory.read_bytes(VirtAddr(state.host_rip), code)
        })?;
        if (state.host_rip..layout.stores_end).contains(&rip) {
            return Err("the vCPU is saving them".to_string());
        }
        layout
            .read(state.host_rsp, |address| {
                memory.read::<u64>(VirtAddr(address)).ok()
            })
            .ok_or_else(|| "the block they are saved in is unreadable".to_string())
    }

    /// The VTL0 state the Windows hypervisor saved for `vcpu`, whose registers
    /// are `registers`, when it is halted in the hypervisor and the state is
    /// found and validates (see [`Self::saved_vtl_contexts`]). A state that
    /// may be one exit behind is not where NT is, so it is not returned.
    pub fn saved_vtl0_registers(
        &self,
        vcpu: &str,
        registers: &HashMap<String, u64>,
    ) -> Option<HashMap<String, u64>> {
        let cr3 = *registers.get(self.arch().dtb_register())?;
        let rip = *registers.get("rip")?;
        if !halted_in_windows_hypervisor(self, cr3, rip) {
            return None;
        }
        let processor = processor_index_from_backend_thread_id(vcpu);
        let saved = self.saved_vtl_contexts(cr3, rip, processor).ok()?;
        let vtl0 = saved
            .into_iter()
            .find(|context| context.vtl == 0 && !context.may_be_stale)?;
        Some(vtl0.registers())
    }

    /// Make where NT left off the inspection context of `vcpu`, whose live
    /// registers are [`Self::registers`], when it is halted in the Windows
    /// hypervisor and nothing else is selected: NT is what a stop there is
    /// inspected for, and the hypervisor's registers, stack, and address space
    /// map no NT memory. `.cxr` returns to them. Whether it was selected.
    pub fn select_saved_vtl0(&mut self, vcpu: &str) -> bool {
        if self.selected_frame.is_some() {
            return false;
        }
        let Some(saved) = self
            .registers
            .as_ref()
            .and_then(|registers| self.saved_vtl0_registers(vcpu, registers))
        else {
            return false;
        };
        self.select_frame(SelectedFrame::from_registers(0, saved));
        true
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
            PdbRecovery::Automatic,
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
                "hv" => {
                    self.register_hypervisor_symbols(dtb, image);
                    HYPERVISOR_CONTEXT.to_string()
                }
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

    /// Name the hypervisor image's code in root `dtb` (see
    /// [`hypercalls::hypervisor_symbols`]), once per root: its hypercall
    /// handlers from its hypercall table and its VM-exit entry points from the
    /// eVMCS pages, so `k`, `u`, `ln`, and `hv!` expressions use them.
    fn register_hypervisor_symbols(&self, dtb: Dtb, image: &ModuleInfo) {
        let Some(guest) = &self.guest else { return };
        if self
            .symbols
            .find_module_for_address(dtb, image.base_address)
            .is_some()
        {
            return;
        }
        let base = image.base_address.0;
        let Some(names) = guest.hypervisor_symbols(base, || {
            let memory = self.address_space(dtb);
            let loaded = hypervisor_image(&memory, image).ok()?;
            let table = hv_layout::hypercall_table(&loaded.view()).ok()?;
            let mut entries: Vec<u64> = guest
                .any_evmcs_pages(&self.phys, &self.interrupt)
                .map(|pages| {
                    pages
                        .all_states(&*self.phys)
                        .into_iter()
                        .map(|state| state.host_rip)
                        .collect()
                })
                .unwrap_or_default();
            entries.sort_unstable();
            entries.dedup();
            let names = hypercalls::hypervisor_symbols(base, &table, &entries);
            let extents = names
                .iter()
                .filter_map(|&(_, rva)| Some((rva, *loaded.functions.get(&rva)?)))
                .collect();
            Some(hypercalls::HypervisorSymbols { names, extents })
        }) else {
            return;
        };
        // "hv" in the high bytes keeps these keys apart from PDB GUIDs.
        let guid = (0x6876u128 << 112) | u128::from(base);
        self.symbols.register_synthetic_module(
            dtb,
            image,
            guid,
            &names.names,
            names.extents.clone(),
        );
    }

    /// The base of `name` (`hv`), an image a stop found outside NT, for
    /// expressions in the address space `dtb`: `None` when no stop found it,
    /// and an error when it was found only in other address spaces, since
    /// its address means nothing in this one.
    pub fn foreign_image_base(&self, dtb: Dtb, name: &str) -> Result<Option<VirtAddr>> {
        let Some(guest) = &self.guest else {
            return Ok(None);
        };
        let dtb = self.normalize_dtb(dtb);
        match guest.foreign_image_named(dtb, name) {
            (Some(image), _) => {
                let mut magic = [0u8; 2];
                let mapped = self
                    .address_space(dtb)
                    .read_bytes(image.base_address, &mut magic)
                    .is_ok()
                    && magic == *b"MZ";
                Ok(mapped.then_some(image.base_address))
            }
            (None, true) => Err(Error::DebugInfo(format!(
                "{name} is mapped only in the address space of the Windows hypervisor; .cxr at a stop in it selects that space"
            ))),
            (None, false) => Ok(None),
        }
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

/// Reads of the Windows hypervisor's address space for the partition walk.
struct HypervisorMemory<'a>(AddressSpace<'a, PhysMem>);

impl HvMemory for HypervisorMemory<'_> {
    fn u64_at(&self, address: u64) -> Option<u64> {
        self.0.read::<u64>(VirtAddr(address)).ok()
    }

    fn u8_at(&self, address: u64) -> Option<u8> {
        self.0.read::<u8>(VirtAddr(address)).ok()
    }
}

/// The hypervisor image as it is mapped, laid out by RVA.
struct HypervisorImage {
    base: u64,
    bytes: Vec<u8>,
    /// `(start, end)` RVAs of its executable sections, and of the others.
    code: Vec<(u32, u32)>,
    data: Vec<(u32, u32)>,
    /// The length of each function, by the RVA it begins at (`.pdata`).
    functions: HashMap<u32, u32>,
}

impl HypervisorImage {
    fn view(&self) -> hv_layout::ImageView<'_> {
        hv_layout::ImageView {
            base: self.base,
            bytes: &self.bytes,
            code: self.code.clone(),
            data: self.data.clone(),
        }
    }
}

/// Where the Windows hypervisor is: its image, mapped in `memory`, the
/// processor blocks it was reached from, and the eVMCS pages the scan found.
struct HypervisorLocation<'a> {
    memory: AddressSpace<'a, PhysMem>,
    image: ModuleInfo,
    processors: Vec<u64>,
    known: std::collections::HashSet<u64>,
}

/// The hypervisor image at `image`, laid out by RVA from its sections as
/// they are mapped in `memory`. Unmapped pages (discarded sections) read as
/// zeros, which decode as no code and no table.
fn hypervisor_image<B: MemoryOps<PhysAddr>>(
    memory: &AddressSpace<'_, B>,
    image: &ModuleInfo,
) -> Result<HypervisorImage> {
    let base = image.base_address.0;
    let headers = read_pe_header_page(image.base_address, memory)?;
    let view = PeView::from_bytes(&headers).map_err(|_| Error::ViewFailed)?;
    let size = image.size as usize;
    let mut bytes = vec![0u8; size];
    let (mut code, mut data) = (Vec::new(), Vec::new());
    for section in view.section_headers() {
        let start = section.VirtualAddress as usize;
        let end = (start + section.VirtualSize.max(section.SizeOfRawData) as usize).min(size);
        let mut page = start;
        while page < end {
            let next = ((page / PAGE_SIZE) + 1) * PAGE_SIZE;
            let chunk = &mut bytes[page..next.min(end)];
            if memory
                .read_bytes(VirtAddr(base + page as u64), chunk)
                .is_err()
            {
                chunk.fill(0);
            }
            page = next;
        }
        let range = (start as u32, end as u32);
        if section.Characteristics & 0x2000_0000 != 0 {
            code.push(range);
        } else {
            data.push(range);
        }
    }
    // The exception directory's RUNTIME_FUNCTIONs: begin, end, unwind RVAs.
    let mut functions = HashMap::new();
    if let Some(directory) = view.data_directory().get(3) {
        let start = directory.VirtualAddress as usize;
        let end = (start + directory.Size as usize).min(size);
        for entry in bytes.get(start..end).unwrap_or(&[]).as_chunks::<12>().0 {
            let begin = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let finish = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            if finish > begin {
                functions.insert(begin, finish - begin);
            }
        }
    }
    Ok(HypervisorImage {
        base,
        bytes,
        code,
        data,
        functions,
    })
}

impl Target {
    /// Translate `gpa` through the EPT of a VTL whose saved state is
    /// `state`, reading the tables from host RAM. `None` when a table is
    /// unreadable or the EPT pointer is not a 4-level walk.
    pub fn translate_guest_physical(&self, state: &EvmcsState, gpa: u64) -> Option<EptTranslation> {
        ept::translate(
            state.ept_pointer,
            gpa,
            state.mode_based_execute(),
            |address| {
                let mut entry = [0u8; 8];
                self.phys.read_bytes(address, &mut entry).ok()?;
                Some(u64::from_le_bytes(entry))
            },
        )
    }

    /// Every mapping of the EPT of a VTL whose saved state is `state`, in
    /// address order. `None` when a table is unreadable.
    pub fn guest_physical_mappings(&self, state: &EvmcsState) -> Option<Vec<ept::Leaf>> {
        ept::leaves(state.ept_pointer, state.mode_based_execute(), |table| {
            let mut bytes = [0u8; PAGE_SIZE];
            self.phys.read_bytes(table, &mut bytes).ok()?;
            let mut entries = [0u64; 512];
            for (entry, chunk) in entries.iter_mut().zip(bytes.as_chunks::<8>().0) {
                *entry = u64::from_le_bytes(*chunk);
            }
            Some(entries)
        })
    }

    /// Find the Windows hypervisor: its processor blocks from the eVMCS pages
    /// (their host GS base) and from the selected vCPU when it is halted in
    /// the hypervisor, and its image through the first root that maps it.
    fn locate_hypervisor(&self) -> Result<HypervisorLocation<'_>> {
        if self.arch() != Arch::Amd64 {
            return Err(Error::Hypervisor(
                "the Windows hypervisor needs an AMD64 target".to_string(),
            ));
        }
        let guest = self.guest()?;
        let mask = self.arch().dtb_page_mask();
        // (hypervisor root, processor block, an address in the image)
        let mut sources = Vec::new();
        if let Some(registers) = &self.registers
            && let (Some(&cr3), Some(&rip), Some(&gs)) = (
                registers.get(self.arch().dtb_register()),
                registers.get("rip"),
                registers.get("gs_base"),
            )
            && halted_in_windows_hypervisor(self, cr3, rip)
        {
            sources.push((cr3 & mask, gs, rip));
        }
        let mut known = std::collections::HashSet::new();
        match guest.any_evmcs_pages(&self.phys, &self.interrupt) {
            Ok(pages) => {
                for state in pages.all_states(&*self.phys) {
                    known.insert(state.address);
                    sources.push((state.host_cr3 & mask, state.host_gs_base, state.host_rip));
                }
            }
            Err(error) if sources.is_empty() => return Err(error),
            Err(_) => {}
        }
        if sources.is_empty() {
            return Err(Error::Hypervisor(
                "no processor block found: this needs the VM's hv-evmcs enlightenment or a vCPU stopped in the hypervisor"
                    .to_string(),
            ));
        }
        // A page left over from an earlier boot names a root that no longer
        // maps the hypervisor; the first source whose root does is used.
        let mut tried = Vec::new();
        let (memory, image) = sources
            .iter()
            .filter(|&&(root, _, _)| {
                let fresh = !tried.contains(&root);
                tried.push(root);
                fresh
            })
            .find_map(|&(root, _, rip)| {
                let memory = self.address_space(root);
                let image =
                    image_containing(&memory, rip).filter(|image| image.short_name == "hv")?;
                Some((memory, image))
            })
            .ok_or_else(|| Error::Hypervisor("the hypervisor image was not found".to_string()))?;
        let mut processors: Vec<u64> = sources.iter().map(|&(_, gs, _)| gs).collect();
        processors.sort_unstable();
        processors.dedup();
        Ok(HypervisorLocation {
            memory,
            image,
            processors,
            known,
        })
    }

    /// The Windows hypervisor's partitions and their virtual processors,
    /// root first. Its processor blocks come from the eVMCS pages (their
    /// host GS base) and from the selected vCPU when it is halted in the
    /// hypervisor; the offsets are read off the hypervisor's own code.
    pub fn hypervisor_partitions(&self) -> Result<Vec<HvPartition>> {
        let guest = self.guest()?;
        let HypervisorLocation {
            memory,
            image,
            processors,
            known,
        } = self.locate_hypervisor()?;
        self.walk_partitions(guest, memory, &image, &processors, &known)
    }

    /// The Windows hypervisor's hypercall table, indexed by call code, and
    /// the base of its image.
    pub fn hypercalls(&self) -> Result<(u64, Vec<HypercallEntry>)> {
        let HypervisorLocation { memory, image, .. } = self.locate_hypervisor()?;
        let loaded = hypervisor_image(&memory, &image)?;
        let table = hv_layout::hypercall_table(&loaded.view())?;
        Ok((loaded.base, table))
    }

    fn walk_partitions(
        &self,
        guest: &Guest,
        memory: AddressSpace<'_, PhysMem>,
        image: &ModuleInfo,
        processors: &[u64],
        known: &std::collections::HashSet<u64>,
    ) -> Result<Vec<HvPartition>> {
        let layout = guest.partition_layout(image.base_address.0, || {
            hv_layout::derive(&hypervisor_image(&memory, image)?.view())
        })?;
        let mut partitions =
            hypervisor::partitions(&layout, &HypervisorMemory(memory), processors, known)?;
        for vtl in partitions
            .iter_mut()
            .flat_map(|partition| &mut partition.virtual_processors)
            .flat_map(|vp| &mut vp.vtls)
        {
            vtl.state = vtl
                .vmcs
                .and_then(|page| EvmcsState::read(&*self.phys, page));
        }
        Ok(partitions)
    }
}
