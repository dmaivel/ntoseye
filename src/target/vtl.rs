//! Explicit secure-kernel inspection, and naming code that runs outside NT's
//! address spaces under VBS. Selecting a VTL changes address-space reads and
//! symbol scope, not the executing processor's VTL or registers.

use std::collections::HashMap;
use std::sync::Arc;

use pelite::PeView;

use super::{SelectedFrame, Target};
use crate::{
    backend::MemoryOps,
    cpu_state::kpcr_for_processor,
    dbg_backend::processor_index_from_backend_thread_id,
    disasm::{self, DisasmRow},
    error::{Error, Result},
    guest::{
        EXIT_GPRS, EvmcsState, Guest, HvMemory, HvPartition, ModuleInfo, ModuleSymbolLoadReport,
        PdbRecovery, SecureKernel, SessionSpace, TrustletInfo,
        ept::{self, EptTranslation},
        hv_layout,
        hv_layout::HypercallEntry,
        hypercall_input,
        hypercalls::{self, HypercallCaller, HypercallInput},
        hypervisor::{self, HvVirtualProcessor},
        vp_registers,
    },
    memory::{AddressSpace, PAGE_SIZE},
    pe::{PeImage, image_file_name, read_pe_header_page, size_of_image},
    phys::PhysMem,
    symbols::{ImageFetch, SymbolStore},
    types::{Arch, CodeMachine, Dtb, PhysAddr, VirtAddr},
    unwind::{halted_in_windows_hypervisor, prolog},
};

/// How far below an instruction pointer to look for the header of the image
/// it lies in. The Windows hypervisor and secure kernel are a few MiB.
const IMAGE_SEARCH_BYTES: u64 = 16 * 1024 * 1024;

/// The context of code in the Windows hypervisor's image.
pub const HYPERVISOR_CONTEXT: &str = "hypervisor";

/// How much code a listing covers, as `u` takes it: a number of
/// instructions, or every instruction that starts before an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeExtent {
    Count(usize),
    /// Up to this address, exclusive. The caller bounds the range, as the
    /// bytes it spans are read at once.
    Before(u64),
}

/// A guest partition's code, decoded as far as its memory reads.
pub struct GuestCode {
    pub rows: Vec<DisasmRow>,
    /// Where unreadable memory cut the listing short of its extent.
    pub unreadable: Option<u64>,
}

/// Code a vCPU was executing outside every NT address space, named by what
/// it is rather than left `unknown`.
#[derive(Debug, Clone)]
pub struct ForeignCode {
    /// `hypervisor`, `VTL1`, or the name of the image the code lies in.
    pub context: String,
    pub modules: ForeignModules,
    /// For the Windows hypervisor's code, the names and function starts
    /// ntoseye made for its image, which a walk of its stacks uses.
    pub hypervisor: Option<Arc<hypercalls::HypervisorSymbols>>,
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
    /// Only the exiting VTL's eVMCS, the current one, is written by that
    /// entry, so only it is marked, unless no state of the VP is current.
    pub may_be_stale: bool,
    /// The general-purpose registers of the exit, where the hypervisor's
    /// exit entry code saved them (see [`crate::guest::ExitRegisterLayout`]),
    /// or why they are not known: only the current VTL's are, once the
    /// vCPU is past the entry code's stores, or, stopped on a breakpoint on
    /// the entry, the vCPU's own.
    pub general_registers: std::result::Result<HashMap<&'static str, u64>, String>,
    /// What the exit says of a hypercall: for a VMCALL whose registers are
    /// known, the call with its input decoded (see
    /// [`Target::exit_hypercall`]).
    pub hypercall: HypercallInput,
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

/// A guest partition's virtual processor that a processor runs, or last
/// ran: at a stop in the hypervisor, the VP whose exit it handles, or which
/// it is about to enter, rather than one of the root's.
#[derive(Debug, Clone)]
pub struct ServedVp {
    pub partition: u64,
    pub vp: u32,
    /// The VTL the VP runs in, and its saved state, when the walk read it.
    pub vtl: u8,
    pub state: Option<EvmcsState>,
    /// The general-purpose registers of the VP's last exit, as
    /// [`SavedVtlContext::general_registers`], or why they are not known.
    pub general_registers: std::result::Result<HashMap<&'static str, u64>, String>,
    /// The hypercall of the VP's last exit, as
    /// [`SavedVtlContext::hypercall`].
    pub hypercall: HypercallInput,
}

impl ServedVp {
    /// `partition 0x7 VP 2`.
    pub fn label(&self) -> String {
        format!("partition {:#x} VP {}", self.partition, self.vp)
    }

    /// Where the VP left off and why, as `VTL0 00007cba12f529e3, last exit
    /// VMCALL (hypercall 0x0003 HvCallFlushVirtualAddressList)`.
    pub fn describe(&self) -> String {
        let mut text = self.left_off();
        if let Some(detail) = self.exit_detail() {
            text.push_str(&format!(" ({detail})"));
        }
        text
    }

    /// Where the VP left off and why, without the exit's detail: `VTL0
    /// 00007cba12f529e3, last exit VMCALL`.
    pub fn left_off(&self) -> String {
        match self.last_exit() {
            Some(exit) => format!("{}, {exit}", self.place()),
            None => self.place(),
        }
    }

    /// Where the VP left off: `VTL0 00007cba12f529e3`, or only its VTL
    /// when its state was not read. A line too long for the terminal puts
    /// [`Self::last_exit`] on a line of its own below it.
    pub fn place(&self) -> String {
        match &self.state {
            Some(state) => format!("VTL{} {:016x}", self.vtl, state.rip),
            None => format!("VTL{}", self.vtl),
        }
    }

    /// Why the VP left off: `last exit VMCALL`, when its state was read.
    pub fn last_exit(&self) -> Option<String> {
        let state = self.state.as_ref()?;
        let exit = state
            .exit_reason_name()
            .map_or_else(|| format!("exit {:#x}", state.exit_reason), str::to_string);
        Some(format!("last exit {exit}"))
    }

    /// The hypercall of a VMCALL exit, when its registers are known.
    pub fn exit_detail(&self) -> Option<String> {
        self.hypercall.call().map(|call| call.summary())
    }
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
    /// The hypercall of a VMCALL exit on one line, when its registers are
    /// known (see [`hypercall_input::DecodedHypercall::summary`]).
    pub fn exit_detail(&self) -> Option<String> {
        self.hypercall.call().map(|call| call.summary())
    }

    /// The saved registers under the names the register display and the
    /// unwinder use. A VMCS holds no general-purpose register but RSP; the
    /// rest come from where the hypervisor saved them, when known.
    pub fn registers(&self) -> HashMap<String, u64> {
        exit_registers(&self.state, self.general_registers.as_ref().ok())
    }
}

/// The registers a VP's state holds, in the order `r` lays out the
/// general-purpose ones: those, then what an eVMCS holds besides.
pub const VP_STATE_REGISTERS: [&str; 29] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15", "eflags", "cr0", "cr3", "cr4", "cs", "ss", "ds", "es", "fs", "gs",
    "fs_base", "gs_base",
];

/// The registers of the exit `state` saved: RIP, RSP, flags, control and
/// segment registers from the eVMCS, and the `general` registers the exit
/// entry code saved, when they are known.
pub fn exit_registers(
    state: &EvmcsState,
    general: Option<&HashMap<&'static str, u64>>,
) -> HashMap<String, u64> {
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
    if let Some(general) = general {
        registers.extend(
            general
                .iter()
                .map(|(name, value)| (name.to_string(), *value)),
        );
    }
    registers
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
        if self.phys.is_partition() {
            return Err(Error::Hypervisor(
                "a guest partition's memory is read through its VTL0 EPT, which does not map its secure kernel".to_string(),
            ));
        }
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
    /// A vCPU on the pages' `host_rip` marks the current state
    /// `may_be_stale`, or every state when none is current, unless it
    /// stopped there on a breakpoint ([`Self::breakpoint_stop`]).
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
        let any_current = vtl0.iter().chain(&vtl1).any(|state| state.current);
        let one = |states: Vec<EvmcsState>, vtl: u8| match states.as_slice() {
            [] => Ok(None),
            [state] => {
                let general_registers =
                    self.saved_general_registers(cr3 & mask, rip, state, any_current, entered);
                let xmm = self.saved_xmm_registers(cr3 & mask, rip, state, &general_registers);
                Ok(Some(SavedVtlContext {
                    vtl,
                    state: *state,
                    may_be_stale: rip == state.host_rip
                        && entered.is_none()
                        && (state.current || !any_current),
                    hypercall: self.exit_hypercall(state, general_registers.as_ref(), xmm),
                    general_registers,
                }))
            }
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
        any_current: bool,
        entered: Option<&BreakpointStop>,
    ) -> std::result::Result<HashMap<&'static str, u64>, String> {
        if !state.current && any_current {
            return Err("the hypervisor last saved another VTL's registers".to_string());
        }
        if !state.current {
            return Err(
                "the processor last ran another virtual processor, such as a guest partition's"
                    .to_string(),
            );
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

    /// The XMM0 to XMM5 of `state`'s last exit, which the hypervisor's exit
    /// entry code saves beside its `general_registers` before it clears
    /// them, for a vCPU at `rip` on the hypervisor root `root`: an XMM fast
    /// hypercall's input past RDX and R8. Known only when the
    /// general-purpose registers are, and once the vCPU is past their stores.
    fn saved_xmm_registers(
        &self,
        root: u64,
        rip: u64,
        state: &EvmcsState,
        general_registers: &std::result::Result<HashMap<&'static str, u64>, String>,
    ) -> std::result::Result<[u128; 6], String> {
        if let Err(reason) = general_registers {
            return Err(reason.clone());
        }
        if rip == state.host_rip {
            return Err("the vCPU is on the VM-exit entry, which has not saved them".to_string());
        }
        let guest = self.guest().map_err(|error| error.to_string())?;
        let memory = self.address_space(root);
        let layout = guest.exit_register_layout(state.host_rip, |code| {
            memory.read_bytes(VirtAddr(state.host_rip), code)
        })?;
        let Some((_, stores_end)) = layout.xmm else {
            return Err(
                "this hypervisor build's VM-exit entry code does not save them where ntoseye finds them"
                    .to_string(),
            );
        };
        if (state.host_rip..stores_end).contains(&rip) {
            return Err("the vCPU is saving them".to_string());
        }
        layout
            .read_xmm(state.host_rsp, |address| {
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
        let report = Guest::load_module_symbols(
            &self.phys,
            &self.symbols,
            modules,
            secure.image.dtb(),
            SessionSpace::Load,
            self.arch(),
            PdbRecovery::Automatic,
        )?;
        self.register_hypercall_pages();
        Ok(report)
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
        let mut hypervisor = None;
        let context = match &image {
            Some(image) => match image.short_name.as_str() {
                "hv" => {
                    hypervisor = self.register_hypervisor_symbols(dtb, image);
                    self.register_hypercall_pages();
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
        Some(ForeignCode {
            context,
            modules,
            hypervisor,
        })
    }

    /// The running build's `hvix64.exe`, when the symbol cache or a local
    /// symbol store on the symbol path has it (by the TimeDateStamp and
    /// SizeOfImage of the header mapped at `image`). Its `.pdata`, which the
    /// hypervisor's address space does not map, bounds its functions and
    /// unwinds its frames. No symbol server has it, so none is asked.
    pub fn hypervisor_file(&self, image: &ModuleInfo) -> Option<Arc<PeImage>> {
        self.symbols
            .module_image_on_disk(
                &image.name,
                image.time_date_stamp?,
                image.size,
                ImageFetch::Local,
            )
            .ok()
    }

    /// Name the hypervisor image's code in root `dtb` (see
    /// [`hypercalls::hypervisor_symbols`]), once per root: its hypercall
    /// handlers from its hypercall table and its VM-exit entry points from the
    /// eVMCS pages, so `k`, `u`, `ln`, and `hv!` expressions use them. The
    /// names are made again, once, when the image's file turns up (see
    /// [`Self::hypervisor_file`]), whose `.pdata` bounds them.
    fn register_hypervisor_symbols(
        &self,
        dtb: Dtb,
        image: &ModuleInfo,
    ) -> Option<Arc<hypercalls::HypervisorSymbols>> {
        let guest = self.guest.as_ref()?;
        let file = self.hypervisor_file(image);
        let base = image.base_address.0;
        // The base is page-aligned, so its low bit is free to keep the names
        // made with the file apart from those made without it.
        let key = base | u64::from(file.is_some());
        let names = guest.hypervisor_symbols(key, || {
            let memory = self.address_space(dtb);
            let Ok(mut loaded) = hypervisor_image(&memory, image) else {
                return Ok(None);
            };
            if let Some(file) = &file
                && let Ok(view) = PeView::from_bytes(file.headers())
            {
                loaded.functions = runtime_function_lengths(file.headers(), &view);
            }
            let Ok(table) = hv_layout::hypercall_table(&loaded.view()) else {
                return Ok(None);
            };
            let mut entries: Vec<u64> = match guest.any_evmcs_pages(&self.phys, &self.interrupt) {
                Ok(pages) => pages
                    .all_states(&*self.phys)
                    .into_iter()
                    .map(|state| state.host_rip)
                    .collect(),
                // An interrupted scan leaves the names unmade, so the next
                // stop in the hypervisor scans again rather than the boot
                // going without its exit entry points.
                Err(error) if self.interrupted() => return Err(error),
                Err(_) => Vec::new(),
            };
            entries.sort_unstable();
            entries.dedup();
            let names = hypercalls::hypervisor_symbols(base, &table, &entries);
            let extents = hypercalls::symbol_extents(&names, &loaded.functions, &loaded.bytes);
            let rva = |address: u64| u32::try_from(address.checked_sub(base)?).ok();
            let exit_entries: Vec<u32> = entries.iter().filter_map(|&entry| rva(entry)).collect();
            let mut starts = prolog::function_starts(&loaded.bytes, &loaded.code);
            starts.extend(loaded.functions.keys());
            starts.extend(table.iter().filter_map(|entry| rva(entry.handler)));
            starts.extend(&exit_entries);
            starts.sort_unstable();
            starts.dedup();
            Ok(Some(hypercalls::HypervisorSymbols {
                names,
                extents,
                starts,
                exit_entries,
            }))
        })?;
        // "hv" in the high bytes keeps these keys apart from PDB GUIDs; the
        // image's timestamp and size keep another build at the same base
        // from reusing these names, and the top bit marks names the file
        // bounded. A canonical address is its low 48 bits sign-extended.
        let guid = (u128::from(file.is_some()) << 127)
            | (0x6876u128 << 112)
            | (u128::from(image.time_date_stamp.unwrap_or(0)) << 80)
            | (u128::from(image.size) << 48)
            | u128::from(base & 0xffff_ffff_ffff);
        if self
            .symbols
            .find_module_for_address(dtb, image.base_address)
            .is_none_or(|registered| registered.guid != guid)
        {
            self.symbols.register_synthetic_module(
                dtb,
                image,
                guid,
                &names.names,
                names.extents.clone(),
            );
        }
        Some(names)
    }

    /// Name the hypercall pages NT and, once its symbols are loaded, the
    /// secure kernel use (each kernel's `HvcallCodeVa`): VTL0's and VTL1's
    /// saved states leave off in them at every hypercall, VTL call, and VTL
    /// return.
    fn register_hypercall_pages(&self) {
        let Some(guest) = &self.guest else { return };
        if let Ok(pointer) = guest.ntoskrnl.symbol("HvcallCodeVa") {
            self.register_hypercall_page(self.kernel_dtb(), pointer.address());
        }
        if let Some(secure) = guest.cached_secure_kernel()
            && let Ok(pointer) = secure.image.symbol("HvcallCodeVa")
        {
            self.register_hypercall_page(secure.image.dtb(), pointer.address());
        }
    }

    /// Name the hypercall page `pointer` points to in root `dtb` (see
    /// [`hypercalls::hypercall_page_symbols`]) as the module `hvcall`, once
    /// per root.
    fn register_hypercall_page(&self, dtb: Dtb, pointer: VirtAddr) {
        let memory = self.address_space(dtb);
        let Ok(page) = memory.read::<u64>(pointer) else {
            return;
        };
        if page == 0
            || self
                .symbols
                .find_module_for_address(dtb, VirtAddr(page))
                .is_some()
        {
            return;
        }
        let mut code = [0u8; 0x40];
        if memory.read_bytes(VirtAddr(page), &mut code).is_err() {
            return;
        }
        let names = hypercalls::hypercall_page_symbols(&code);
        if names.is_empty() {
            return;
        }
        // "hc" in the high bytes keeps these keys apart from PDB GUIDs and
        // from the hypervisor's ("hv"); the root and the page keep each
        // kernel's page apart.
        let guid = (0x6863u128 << 112)
            | (u128::from((dtb >> 12) & 0xffff_ffff) << 48)
            | u128::from(page & 0xffff_ffff_ffff);
        self.symbols.register_synthetic_module(
            dtb,
            &ModuleInfo::new("hvcall".to_string(), VirtAddr(page), 0x1000),
            guid,
            &names
                .iter()
                .map(|&(name, offset, _)| (name.to_string(), offset))
                .collect::<Vec<_>>(),
            names
                .iter()
                .map(|&(_, offset, length)| (offset, length))
                .collect(),
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

/// Guest virtual addresses are walked as 4-level long-mode page tables only.
fn require_four_level_paging(state: &EvmcsState) -> Result<()> {
    if state.four_level_paging() {
        Ok(())
    } else {
        Err(Error::Hypervisor(
            "the guest is not in 4-level long-mode paging; read its guest physical memory instead"
                .to_string(),
        ))
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
            // The loader's name is not in memory; the PDB's stem is the
            // image's, and the header says which kind of file it was.
            let name = image_file_name(&path, view.file_header().Characteristics);
            return Some(
                ModuleInfo::new(name, VirtAddr(page), size)
                    .with_time_date_stamp(view.file_header().TimeDateStamp),
            );
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
    let functions = runtime_function_lengths(&bytes, &view);
    Ok(HypervisorImage {
        base,
        bytes,
        code,
        data,
        functions,
    })
}

/// The length of each function by the RVA it begins at, from the
/// RUNTIME_FUNCTIONs (begin, end, unwind RVAs) of the exception directory in
/// `bytes`, an image laid out by RVA whose headers `view` reads.
fn runtime_function_lengths(bytes: &[u8], view: &PeView<'_>) -> HashMap<u32, u32> {
    let mut functions = HashMap::new();
    if let Some(directory) = view.data_directory().get(3) {
        let start = directory.VirtualAddress as usize;
        let end = start
            .saturating_add(directory.Size as usize)
            .min(bytes.len());
        for entry in bytes.get(start..end).unwrap_or(&[]).as_chunks::<12>().0 {
            let begin = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let finish = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]);
            if finish > begin {
                functions.insert(begin, finish - begin);
            }
        }
    }
    functions
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

    /// Read the memory of the guest whose VTL's saved state is `state`:
    /// guest physical through its EPT, or, when `virtual_address`, guest
    /// virtual through the VTL's page tables (its CR3), each of whose reads
    /// goes through the EPT too. Read-only.
    pub fn read_guest_partition(
        &self,
        state: &EvmcsState,
        virtual_address: bool,
        address: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let guest = ept::EptMemory::new(&*self.phys, state.ept_pointer, state.mode_based_execute());
        if virtual_address {
            require_four_level_paging(state)?;
            AddressSpace::new(&guest, state.cr3 & self.arch().dtb_page_mask())
                .read_bytes(VirtAddr(address), buf)
        } else {
            guest.read_bytes(address, buf)
        }
    }

    /// The guest physical and host physical addresses of guest virtual
    /// `address` in the VTL whose saved state is `state`, or `None` when its
    /// page tables do not map it.
    pub fn translate_guest_partition(
        &self,
        state: &EvmcsState,
        address: u64,
    ) -> Result<Option<(u64, u64)>> {
        require_four_level_paging(state)?;
        let guest = ept::EptMemory::new(&*self.phys, state.ept_pointer, state.mode_based_execute());
        let Some(translation) = AddressSpace::new(&guest, state.cr3 & self.arch().dtb_page_mask())
            .virt_to_phys(VirtAddr(address))?
        else {
            return Ok(None);
        };
        Ok(Some((
            translation.address,
            guest.host_address(translation.address)?,
        )))
    }

    /// Disassemble the code of the guest whose VTL's saved state is `state`
    /// at `address`, read as [`Self::read_guest_partition`] reads it and
    /// decoded in the mode the VTL left off in
    /// ([`EvmcsState::code_machine`]). Branch and RIP-relative comments are
    /// addresses: ntoseye has no symbols for a guest. The read stops at the
    /// first unreadable page, and the listing with it.
    pub fn disassemble_guest_partition(
        &self,
        state: &EvmcsState,
        virtual_address: bool,
        address: u64,
        extent: CodeExtent,
    ) -> Result<GuestCode> {
        let machine = state.code_machine()?;
        if virtual_address {
            // Every page would be unreadable; say why instead.
            require_four_level_paging(state)?;
        }
        let longest = machine.max_instruction_bytes();
        let (length, limit) = match extent {
            CodeExtent::Count(count) => (count.saturating_mul(longest), Some(count)),
            // The last instruction may run past the end.
            CodeExtent::Before(end) => (
                usize::try_from(end.saturating_sub(address))
                    .unwrap_or(usize::MAX)
                    .saturating_add(longest - 1),
                None,
            ),
        };
        let mut bytes = vec![0u8; length];
        let mut read = 0;
        while read < length {
            let at = address.wrapping_add(read as u64);
            let chunk = (PAGE_SIZE - (at as usize & (PAGE_SIZE - 1))).min(length - read);
            if self
                .read_guest_partition(state, virtual_address, at, &mut bytes[read..read + chunk])
                .is_err()
            {
                break;
            }
            read += chunk;
        }
        bytes.truncate(read);
        let mut rows = disasm::decode_code(&bytes, address, limit, machine, |target| {
            format!("{target:#x}")
        });
        let finished = match extent {
            CodeExtent::Count(count) => rows.len() == count,
            CodeExtent::Before(end) => {
                rows.retain(|row| row.ip < end);
                rows.last()
                    .map_or(address, |row| row.ip.saturating_add(row.length as u64))
                    >= end
            }
        };
        let unreadable = (!finished && read < length).then(|| address.wrapping_add(read as u64));
        Ok(GuestCode { rows, unreadable })
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
        // The partitions' saved states leave off in the hypercall page too,
        // and a session's first stop need not be in the hypervisor, where
        // the page is otherwise first named.
        self.register_hypercall_pages();
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
            Err(_) if sources.is_empty() && self.phys.ram_runs().is_empty() => {
                return Err(Error::Hypervisor(
                    "reading the hypervisor's memory needs direct host RAM: the memory or gdb backend, or kd/kdnet with --memory-source host"
                        .to_string(),
                ));
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

    /// [`hypervisor::guest_vp_label`] for processor `number`, walking the
    /// partitions; `None` when they cannot be walked.
    pub fn guest_vp_label(&self, number: u16) -> Option<String> {
        hypervisor::guest_vp_label(&self.hypervisor_partitions().ok()?, number)
    }

    /// The guest partition's virtual processor that processor `number`
    /// runs, or last ran, for a vCPU at `rip` halted in the hypervisor on
    /// root `cr3`: the VP whose exit it handles, or which it is about to
    /// enter. `None` when the processor's VP is the root's, or the
    /// partitions cannot be walked.
    pub fn served_guest_vp(&self, cr3: u64, rip: u64, number: u16) -> Option<ServedVp> {
        self.served_guest_vp_in(&self.hypervisor_partitions().ok()?, cr3, rip, number)
    }

    /// [`Self::served_guest_vp`] in `partitions`, walked already.
    pub fn served_guest_vp_in(
        &self,
        partitions: &[HvPartition],
        cr3: u64,
        rip: u64,
        number: u16,
    ) -> Option<ServedVp> {
        let mask = self.arch().dtb_page_mask();
        // The eVMCSes loaded with the processor's root, which assist pages
        // name: its own is that of the VP and VTL whose exits it handles now.
        let loaded = self
            .guest()
            .ok()
            .and_then(Guest::cached_evmcs_pages)
            .map(|pages| pages.loaded_for_root(&*self.phys, cr3, mask))
            .unwrap_or_default();
        let (partition, vp, vtl, state) = hypervisor::served_vp(partitions, &loaded, number)?;
        let entered = self
            .breakpoint_stop
            .as_ref()
            .filter(|stop| stop.processor == number && stop.rip == rip);
        let general_registers = match &state {
            Some(state) if state.current => {
                self.saved_general_registers(cr3 & mask, rip, state, true, entered)
            }
            Some(_) => Err("no eVMCS is known loaded on the processor".to_string()),
            None => Err("the walk found no state for the VTL it runs".to_string()),
        };
        let xmm = match &state {
            Some(state) => self.saved_xmm_registers(cr3 & mask, rip, state, &general_registers),
            None => Err("the walk found no state for the VTL it runs".to_string()),
        };
        Some(ServedVp {
            partition,
            vp: vp.index,
            vtl,
            hypercall: match &state {
                Some(state) => self.exit_hypercall(state, general_registers.as_ref(), xmm),
                None => HypercallInput::Unknown(
                    "the partition walk found no saved state of the VP".to_string(),
                ),
            },
            state,
            general_registers,
        })
    }

    /// What `state`'s exit says of a hypercall: for a VMCALL whose
    /// general-purpose registers are known (`registers`, or why they are not),
    /// the call with its input decoded. An input in memory is read at its GPA
    /// through the EPT of the calling VTL, which `state` holds, whether the
    /// VTL is the root partition's or a guest's; an XMM fast call's input
    /// past RDX and R8 is in the exit's saved `xmm` registers, or why they
    /// are not known.
    pub fn exit_hypercall(
        &self,
        state: &EvmcsState,
        registers: std::result::Result<&HashMap<&'static str, u64>, &String>,
        xmm: std::result::Result<[u128; 6], String>,
    ) -> HypercallInput {
        if !state.is_vmcall() {
            return HypercallInput::NotHypercall;
        }
        let registers = match registers {
            Ok(registers) => registers,
            Err(reason) => return HypercallInput::Unknown(reason.clone()),
        };
        let long_mode = matches!(state.code_machine(), Ok(CodeMachine::Amd64));
        let Some((value, input, output)) =
            hypercall_input::hypercall_registers(registers, long_mode)
        else {
            return HypercallInput::Unknown(
                "the exit's registers lack a hypercall parameter register".to_string(),
            );
        };
        HypercallInput::Known(Box::new(hypercall_input::decode_hypercall(
            value,
            input,
            output,
            xmm,
            |gpa, buf| {
                self.read_guest_partition(state, false, gpa, buf)
                    .map_err(|error| error.to_string())
            },
        )))
    }

    /// The VP whose exit processor `number`, a vCPU at `rip` halted in the
    /// hypervisor on root `cr3`, handles, as a hypercall's caller: the guest
    /// partition's VP it serves ([`Self::served_guest_vp`]), else the root
    /// partition's VP on that processor, whose saved state is then the
    /// loaded one. The call is known only from a current state: a served VP
    /// found through its processor block alone has a state one exit behind
    /// or more. `None` when the partitions cannot be walked, or the
    /// processor serves no guest's VP and no state of its root VP is
    /// current, which leaves the caller unknown.
    pub fn hypercall_caller(&self, cr3: u64, rip: u64, number: u16) -> Option<HypercallCaller> {
        if let Some(caller) = self.loaded_hypercall_caller(cr3, rip, number) {
            return Some(caller);
        }
        let partitions = self.hypervisor_partitions().ok()?;
        if let Some(served) = self.served_guest_vp_in(&partitions, cr3, rip, number) {
            // A state that is not the loaded one is an older exit's: its
            // registers are not this call's.
            let registers = match &served.state {
                Some(state) if state.current => {
                    exit_registers(state, served.general_registers.as_ref().ok())
                }
                _ => HashMap::new(),
            };
            let input = match &served.state {
                Some(state) if !state.current => HypercallInput::Unknown(
                    "the processor's current eVMCS is not this VP's, so its saved state is one \
                     exit behind or more"
                        .to_string(),
                ),
                _ => served.hypercall,
            };
            return Some(HypercallCaller {
                partition: served.partition,
                root: false,
                vp: served.vp,
                vtl: served.vtl,
                input,
                registers,
                state: served.state.filter(|state| state.current),
            });
        }
        let current = self
            .saved_vtl_contexts(cr3, rip, Some(number))
            .ok()?
            .into_iter()
            .find(|saved| saved.state.current)?;
        let root = partitions.first()?;
        let number = u32::from(number);
        // The root's VPs are pinned to the processors with their numbers,
        // for a build whose processor blocks keep no number.
        let vp = root
            .virtual_processors
            .iter()
            .find(|vp| {
                vp.processors
                    .iter()
                    .any(|processor| processor.number == Some(number))
            })
            .or_else(|| root.virtual_processors.iter().find(|vp| vp.index == number))?;
        Some(HypercallCaller {
            partition: root.id,
            root: true,
            vp: vp.index,
            vtl: current.vtl,
            registers: current.registers(),
            input: current.hypercall,
            state: Some(current.state),
        })
    }

    /// The Windows hypervisor's hypercall table, indexed by call code, and
    /// the base of its image.
    pub fn hypercalls(&self) -> Result<(u64, Vec<HypercallEntry>)> {
        let HypervisorLocation { memory, image, .. } = self.locate_hypervisor()?;
        let loaded = hypervisor_image(&memory, &image)?;
        let table = hv_layout::hypercall_table(&loaded.view())?;
        Ok((loaded.base, table))
    }

    /// The VM-exit entry point every VP's exits enter the Windows
    /// hypervisor through: the `host_rip` of the eVMCSes of the VTLs the
    /// partition walk finds, which the hypervisor sets alike for every VTL
    /// of every partition. Only those: the RAM scan also finds pages of
    /// VTLs that are gone, some with an older build's entry. Refused when
    /// no eVMCS is found (the VM lacks `hv-evmcs`) or when they name more
    /// than one, as one breakpoint would then miss the other's exits.
    pub fn vm_exit_entry(&self) -> Result<u64> {
        let mut entries: Vec<u64> = self
            .hypervisor_partitions()?
            .iter()
            .flat_map(|partition| &partition.virtual_processors)
            .flat_map(|vp| &vp.vtls)
            .filter_map(|vtl| vtl.state.map(|state| state.host_rip))
            .collect();
        entries.sort_unstable();
        entries.dedup();
        match entries[..] {
            [entry] => Ok(entry),
            [] => Err(Error::Hypervisor(
                "no eVMCS names the hypervisor's VM-exit entry point (the VM needs hv-evmcs)"
                    .to_string(),
            )),
            _ => Err(Error::Hypervisor(format!(
                "the eVMCSes name {} VM-exit entry points, and one breakpoint would miss the others' exits",
                entries.len()
            ))),
        }
    }

    /// The general-purpose registers `vp`, a VP of `partitions`, saved at
    /// its last exit, read from its register block through its region's
    /// descriptor (see [`vp_registers`]), mapped or not. The hypervisor
    /// resumes the VP with them, but for what it writes as the exit's
    /// result, such as a hypercall's status in RAX. A VP a processor runs
    /// now has newer ones in that vCPU.
    pub fn saved_vp_registers(
        &self,
        partitions: &[HvPartition],
        vp: &HvVirtualProcessor,
    ) -> Result<HashMap<&'static str, u64>> {
        let HypervisorLocation { memory, image, .. } = self.locate_hypervisor()?;
        let guest = self.guest()?;
        let read = |address: u64| memory.read::<u64>(VirtAddr(address)).ok();
        let phys = |address: u64| {
            let mut bytes = [0u8; 8];
            self.phys
                .read_bytes(address, &mut bytes)
                .ok()
                .map(|()| u64::from_le_bytes(bytes))
        };
        let host_rip = partitions
            .iter()
            .flat_map(|partition| &partition.virtual_processors)
            .flat_map(|vp| &vp.vtls)
            .find_map(|vtl| vtl.state.map(|state| state.host_rip))
            .ok_or_else(|| {
                Error::Hypervisor("no eVMCS names the hypervisor's VM-exit entry point".to_string())
            })?;
        let exit = guest
            .exit_register_layout(host_rip, |code| memory.read_bytes(VirtAddr(host_rip), code))
            .map_err(Error::SavedVtlState)?;
        let layout = guest.vp_register_layout(image.base_address.0, || {
            let loaded = self.loaded_vps(partitions, &exit.block_loads, &phys)?;
            vp_registers::calibrate(&loaded, |address, size| {
                let mut bytes = vec![0u8; size];
                memory.read_bytes(VirtAddr(address), &mut bytes).ok()?;
                Some(bytes)
            })
        })?;
        let offsets: Vec<_> = EXIT_GPRS.iter().copied().zip(exit.offsets).collect();
        vp_registers::saved_registers(&layout, vp.address, &offsets, read, phys)
    }

    /// A target over the guest that partition `id` of the Windows
    /// hypervisor runs (a Windows Sandbox, a Hyper-V VM): its guest physical
    /// memory read through the partition's VTL0 EPT, and its NT kernel found
    /// from the page-table root of a VP stopped in kernel mode (any VP's
    /// otherwise). Read-only. The root partition is this target itself.
    pub fn partition_target(&self, id: u64) -> Result<Target> {
        let partitions = self.hypervisor_partitions()?;
        let partition = partitions
            .iter()
            .find(|partition| partition.id == id)
            .ok_or_else(|| {
                Error::InvalidArgument(format!("the hypervisor has no partition {id:#x}"))
            })?;
        if partition.parent.is_none() {
            return Err(Error::InvalidArgument(
                "the root partition is the target itself".to_string(),
            ));
        }
        let states: Vec<EvmcsState> = partition
            .virtual_processors
            .iter()
            .filter_map(|vp| vp.vtls.iter().find(|vtl| vtl.level == 0)?.state)
            .filter(EvmcsState::four_level_paging)
            .collect();
        let state = states
            .iter()
            .find(|state| state.cs & 3 == 0)
            .or_else(|| states.first())
            .copied()
            .ok_or_else(|| {
                Error::Hypervisor(format!(
                    "no VP of partition {id:#x} runs in 4-level long-mode paging, so it runs no 64-bit NT"
                ))
            })?;
        let leaves = self.guest_physical_mappings(&state).ok_or_else(|| {
            Error::Hypervisor(format!("the EPT of partition {id:#x} is unreadable"))
        })?;
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for leaf in leaves.iter().filter(|leaf| leaf.access.read()) {
            match runs.last_mut() {
                Some((base, length)) if *base + *length == leaf.gpa => *length += leaf.size,
                _ => runs.push((leaf.gpa, leaf.size)),
            }
        }
        let phys = PhysMem::partition(
            Arc::clone(&self.phys),
            state.ept_pointer,
            state.mode_based_execute(),
            runs,
        );
        Target::with_kernel_dtb(Arc::new(phys), state.cr3 & self.arch().dtb_page_mask())
    }

    /// The VPs of `partitions` whose register region the root of their
    /// current eVMCS maps now, as their exit entry finds the block through
    /// `block_loads` from its host RSP (see [`ExitRegisterLayout`]).
    fn loaded_vps(
        &self,
        partitions: &[HvPartition],
        block_loads: &[i64],
        phys: &impl Fn(u64) -> Option<u64>,
    ) -> Result<Vec<vp_registers::LoadedVp>> {
        let Some((last, through)) = block_loads
            .split_last()
            .filter(|(_, through)| !through.is_empty())
        else {
            return Err(Error::Hypervisor(
                "this hypervisor build loads the exit registers from the processor's stack, not through the VP, so a VP no processor runs has none ntoseye can read"
                    .to_string(),
            ));
        };
        let mask = self.arch().dtb_page_mask();
        Ok(partitions
            .iter()
            .flat_map(|partition| &partition.virtual_processors)
            .filter_map(|vp| {
                let state = vp.vtls.iter().find(|vtl| vtl.level == vp.vtl)?.state?;
                let root = state.host_cr3 & mask;
                let space = self.address_space(root);
                let mut value = state.host_rsp;
                for load in through {
                    value = space
                        .read::<u64>(VirtAddr(value.wrapping_add_signed(*load)))
                        .ok()?;
                }
                let pointer = value.wrapping_add_signed(*last);
                let block = space.read::<u64>(VirtAddr(pointer)).ok()?;
                let region_pde = vp_registers::pde_of(root, block, phys)?;
                vp_registers::physical_in_region(region_pde, block, phys)?;
                Some(vp_registers::LoadedVp {
                    vp: vp.address,
                    pointer,
                    region: block & !0x1f_ffff,
                    region_pde,
                })
            })
            .collect())
    }

    /// [`Self::hypercall_caller`] without a partition walk, for each hit of
    /// a hypercall breakpoint: the caller is the VP and VTL whose eVMCS the
    /// processor's assist page names loaded (see [`hypervisor::own_loaded`]),
    /// found in the eVMCS pages the last walk named (see
    /// [`Guest::vp_slot`]); its registers are those that eVMCS's exit saved.
    /// `None` when no eVMCS is known loaded there, no walk names one, or
    /// several guest VPs' are loaded with its root, which leaves the caller
    /// to the walk.
    fn loaded_hypercall_caller(&self, cr3: u64, rip: u64, number: u16) -> Option<HypercallCaller> {
        let guest = self.guest().ok()?;
        let mask = self.arch().dtb_page_mask();
        let walk = || Some(hypervisor::vp_slots(&self.hypervisor_partitions().ok()?));
        let candidates = guest
            .cached_evmcs_pages()?
            .loaded_for_root(&*self.phys, cr3, mask)
            .into_iter()
            .map(|loaded| {
                Some((
                    loaded,
                    guest.vp_slot(loaded.address, loaded.ept_pointer, walk)?,
                ))
            })
            .collect::<Option<Vec<_>>>()?;
        let (loaded, slot) = hypervisor::own_loaded(&candidates)?;
        let entered = self
            .breakpoint_stop
            .as_ref()
            .filter(|stop| stop.processor == number && stop.rip == rip);
        let registers = self.saved_general_registers(cr3 & mask, rip, &loaded, true, entered);
        let xmm = self.saved_xmm_registers(cr3 & mask, rip, &loaded, &registers);
        Some(HypercallCaller {
            partition: slot.partition,
            root: slot.root,
            vp: slot.vp,
            vtl: slot.vtl,
            input: self.exit_hypercall(&loaded, registers.as_ref(), xmm),
            registers: exit_registers(&loaded, registers.as_ref().ok()),
            state: Some(loaded),
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::session_over_memory;

    const BASE: u64 = 0x10000;
    /// A guest virtual address whose page is the code page; the page after
    /// it is not mapped.
    const CODE_VA: u64 = 0x7ff6_1234_5000;
    const CODE_GPA: u64 = BASE + 0x8000;
    /// `mov rax, rcx; vmcall; ret` in 64-bit code; in 32-bit code the REX
    /// prefix is `dec eax`.
    const CODE: [u8; 7] = [0x48, 0x89, 0xc8, 0x0f, 0x01, 0xc1, 0xc3];
    /// Where the code starts in its page: two nops and the first byte of a
    /// `vmcall` fit after it before the page ends.
    const CODE_OFFSET: u64 = 0xff6;

    /// Host memory at `BASE` holding an EPT that maps each guest physical
    /// page of the block to the same host page, except the one after the
    /// code page, and guest 4-level page tables that map `CODE_VA` to the
    /// code page.
    fn guest_session() -> (crate::session::Session, EvmcsState) {
        let mut memory = vec![0u8; 0xa000];
        let mut put = |at: u64, entry: u64| {
            let at = (at - BASE) as usize;
            memory[at..at + 8].copy_from_slice(&entry.to_le_bytes());
        };
        const RWX: u64 = 7;
        const WB: u64 = 6 << 3;
        put(BASE, (BASE + 0x1000) | RWX);
        put(BASE + 0x1000, (BASE + 0x2000) | RWX);
        put(BASE + 0x2000, (BASE + 0x3000) | RWX);
        for page in (BASE..BASE + 0xa000).step_by(PAGE_SIZE) {
            if page != CODE_GPA + 0x1000 {
                put(BASE + 0x3000 + (page >> 12) * 8, page | RWX | WB);
            }
        }
        let va = VirtAddr(CODE_VA);
        put(
            BASE + 0x4000 + va.pml4_index() as u64 * 8,
            (BASE + 0x5000) | 7,
        );
        put(
            BASE + 0x5000 + va.pdpt_index() as u64 * 8,
            (BASE + 0x6000) | 7,
        );
        put(
            BASE + 0x6000 + va.pd_index() as u64 * 8,
            (BASE + 0x7000) | 7,
        );
        put(BASE + 0x7000 + va.pt_index() as u64 * 8, CODE_GPA | 7);
        let code = (CODE_GPA - BASE + CODE_OFFSET) as usize;
        memory[code..code + CODE.len()].copy_from_slice(&CODE);
        memory[code + CODE.len()..code + CODE.len() + 3].copy_from_slice(&[0x90, 0x90, 0x0f]);
        let state = EvmcsState {
            ept_pointer: BASE | (3 << 3) | 6,
            cr3: BASE + 0x4000,
            entry_controls: 1 << 9,
            cs_access_rights: 0xa09b,
            ..EvmcsState::at(0, true)
        };
        (session_over_memory(BASE, &memory), state)
    }

    fn listing(code: &GuestCode) -> Vec<(u64, String)> {
        // The formatter pads the mnemonic to a column; compare the words.
        code.rows
            .iter()
            .map(|row| {
                (
                    row.ip,
                    row.asm().split_whitespace().collect::<Vec<_>>().join(" "),
                )
            })
            .collect()
    }

    /// The code reads through the guest's page tables and EPT, or through
    /// the EPT alone from its guest physical address, and decodes in the
    /// mode the guest left off in.
    #[test]
    fn guest_code_decodes_where_its_page_tables_and_ept_put_it() {
        let (session, long) = guest_session();
        let start = CODE_VA + CODE_OFFSET;
        let expected = vec![
            (start, "mov rax, rcx".to_string()),
            (start + 3, "vmcall".to_string()),
            (start + 6, "ret".to_string()),
        ];
        let code = session
            .target
            .disassemble_guest_partition(&long, true, start, CodeExtent::Count(3))
            .unwrap();
        assert_eq!((listing(&code), code.unreadable), (expected, None));

        let physical = CODE_GPA + CODE_OFFSET;
        let code = session
            .target
            .disassemble_guest_partition(&long, false, physical, CodeExtent::Before(physical + 6))
            .unwrap();
        assert_eq!(
            (listing(&code), code.unreadable),
            (
                vec![
                    (physical, "mov rax, rcx".to_string()),
                    (physical + 3, "vmcall".to_string()),
                ],
                None
            )
        );

        let protected = EvmcsState {
            entry_controls: 0,
            cs_access_rights: 0xc09b,
            ..long
        };
        let code = session
            .target
            .disassemble_guest_partition(&protected, false, physical, CodeExtent::Count(2))
            .unwrap();
        assert_eq!(
            listing(&code),
            [
                (physical, "dec eax".to_string()),
                (physical + 1, "mov eax, ecx".to_string()),
            ]
        );
        // Without long-mode paging, its page tables are not 4-level ones.
        assert!(
            session
                .target
                .disassemble_guest_partition(&protected, true, start, CodeExtent::Count(2))
                .is_err()
        );
    }

    /// An unmapped page ends the listing at its start, and an instruction
    /// that runs into it is not shown; a listing that ends before it is
    /// whole.
    #[test]
    fn guest_code_stops_at_the_first_unreadable_page() {
        let (session, state) = guest_session();
        let start = CODE_VA + CODE_OFFSET;
        let code = session
            .target
            .disassemble_guest_partition(&state, true, start, CodeExtent::Count(8))
            .unwrap();
        assert_eq!(code.rows.len(), 5, "{:?}", listing(&code));
        assert_eq!(code.rows[4].ip, start + 8);
        assert_eq!(code.unreadable, Some(CODE_VA + 0x1000));

        let code = session
            .target
            .disassemble_guest_partition(&state, true, start, CodeExtent::Before(start + 9))
            .unwrap();
        assert_eq!((code.rows.len(), code.unreadable), (5, None));

        let unmapped = CODE_GPA + 0x1000;
        let code = session
            .target
            .disassemble_guest_partition(&state, false, unmapped, CodeExtent::Count(1))
            .unwrap();
        assert_eq!((code.rows.len(), code.unreadable), (0, Some(unmapped)));
    }

    /// A VMCALL's input is read at its GPA through the caller's EPT, from
    /// the code page here, up to the end of its page; an unmapped GPA keeps
    /// the call with no fields. A 32-bit caller passes register pairs, and
    /// an exit that is no VMCALL, or whose registers are unknown, has no
    /// call.
    #[test]
    fn a_vmcall_input_reads_through_the_callers_ept() {
        let (session, long) = guest_session();
        let vmcall = EvmcsState {
            exit_reason: 18,
            ..long
        };
        let registers = |rcx: u64, rdx: u64| -> HashMap<&'static str, u64> {
            EXIT_GPRS
                .iter()
                .map(|&name| (name, 0))
                .chain([("rcx", rcx), ("rdx", rdx), ("r8", 0x7000)])
                .collect()
        };
        let target = &session.target;
        let space = registers(0x0002, CODE_GPA + CODE_OFFSET - 8);
        let no_xmm = || Err("not saved".to_string());
        let HypercallInput::Known(call) = target.exit_hypercall(&vmcall, Ok(&space), no_xmm())
        else {
            panic!("no call");
        };
        assert_eq!(call.input_gpa, Some(CODE_GPA + CODE_OFFSET - 8));
        assert_eq!(call.output_gpa, Some(0x7000));
        let read: Vec<_> = call
            .fields
            .iter()
            .map(|field| (field.offset, field.value))
            .collect();
        // `CODE` and the two nops after it, little-endian.
        assert_eq!(read, [(0, 0), (8, 0x90c3_c101_0fc8_8948)]);
        assert!(call.unavailable.is_some(), "ProcessorMask is past the page");

        let unmapped = registers(0x0002, CODE_GPA + 0x1000);
        let HypercallInput::Known(call) = target.exit_hypercall(&vmcall, Ok(&unmapped), no_xmm())
        else {
            panic!("no call");
        };
        assert!(call.fields.is_empty() && call.unavailable.is_some());

        let protected = EvmcsState {
            entry_controls: 0,
            cs_access_rights: 0xc09b,
            ..vmcall
        };
        let mut pairs = registers(0, 0);
        pairs.extend([("rax", 0x0001_0008), ("rdx", 0), ("rcx", 0x2a)]);
        let HypercallInput::Known(call) = target.exit_hypercall(&protected, Ok(&pairs), no_xmm())
        else {
            panic!("no call");
        };
        assert_eq!((call.control.code, call.control.fast), (0x0008, true));
        assert_eq!(call.fields[0].value, 0x2a);

        assert_eq!(
            target.exit_hypercall(&long, Ok(&space), no_xmm()),
            HypercallInput::NotHypercall
        );
        let reason = "the vCPU is saving them".to_string();
        assert_eq!(
            target.exit_hypercall(&vmcall, Err(&reason), no_xmm()),
            HypercallInput::Unknown(reason.clone())
        );
    }
}
