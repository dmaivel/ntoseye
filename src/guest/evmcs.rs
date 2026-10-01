//! The guest state the Windows hypervisor last saved for its virtual
//! processors' VTLs, read from Enlightened VMCS pages. Their layout is the
//! Hyper-V TLFS's (Linux `struct hv_enlightened_vmcs`), so nothing here
//! depends on a hypervisor build. A hypervisor nested under KVM uses them only
//! when the VM exposes the `hv-evmcs` enlightenment; an ordinary nested VMCS
//! is in a CPU- or KVM-private format, and KVM keeps the active one out of
//! guest memory.
//!
//! The pages are hypervisor memory NT cannot name, so they are found by
//! scanning host RAM once per boot (again once for a VP whose pages did not
//! exist yet). Only where they are is remembered; what they hold is read at
//! every use. KVM writes a VP's guest state back to its current eVMCS
//! before it enters the hypervisor, so while a vCPU is halted in
//! the hypervisor that state is where the VTL left off.

use std::collections::HashSet;
use std::sync::{
    Arc, PoisonError,
    atomic::{AtomicBool, Ordering},
};

use super::Guest;
use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    memory::PAGE_SIZE,
    phys::PhysMem,
    types::{CodeMachine, PhysAddr},
};

const SCAN_BYTES: usize = 2 * 1024 * 1024;
/// `revision_id` of an Enlightened VMCS: the eVMCS version, which KVM
/// implements as 1.
const EVMCS_VERSION: u32 = 1;
/// `sizeof(struct hv_enlightened_vmcs)`.
const EVMCS_BYTES: usize = 0x400;
/// Pages a scan may accept. A VP has one eVMCS per VTL, so this bounds
/// hundreds of VPs; more means the check is matching something else.
const MAX_PAGES: usize = 4096;

const HOST_CR3: usize = 0x30;
const HOST_RIP: usize = 0x50;
const SECONDARY_CONTROLS: usize = 0x64;
const HOST_GS_BASE: usize = 0x248;
const HOST_RSP: usize = 0x268;
const EPT_POINTER: usize = 0x270;
const GUEST_ES_SELECTOR: usize = 0x80;
const GUEST_CS_SELECTOR: usize = 0x82;
const GUEST_SS_SELECTOR: usize = 0x84;
const GUEST_DS_SELECTOR: usize = 0x86;
const GUEST_FS_SELECTOR: usize = 0x88;
const GUEST_GS_SELECTOR: usize = 0x8a;
const GUEST_CS_AR_BYTES: usize = 0xbc;
const GUEST_FS_BASE: usize = 0xf8;
const GUEST_GS_BASE: usize = 0x100;
const GUEST_CR0: usize = 0x220;
const GUEST_CR3: usize = 0x228;
const GUEST_CR4: usize = 0x230;
const GUEST_DR7: usize = 0x238;
const VM_ENTRY_CONTROLS: usize = 0x31c;
const VM_EXIT_REASON: usize = 0x2b4;
const VM_EXIT_INTR_INFO: usize = 0x2b8;
const VM_EXIT_INSTRUCTION_LEN: usize = 0x2c8;
const EXIT_QUALIFICATION: usize = 0x2d0;
const GUEST_RSP: usize = 0x300;
const GUEST_RFLAGS: usize = 0x308;
const GUEST_RIP: usize = 0x330;

/// `hv_vp_assist_page.enlighten_vmentry`: the hypervisor enters its guest
/// through `current_nested_vmcs`.
const ASSIST_ENLIGHTEN_VMENTRY: usize = 0x28;
/// `hv_vp_assist_page.current_nested_vmcs`: the eVMCS it last entered its
/// guest with, or has loaded to enter next.
const ASSIST_CURRENT_NESTED_VMCS: usize = 0x30;

const CR0_PE: u64 = 1;
const CR0_PG: u64 = 1 << 31;
/// The "IA-32e mode guest" VM-entry control: the guest's IA32_EFER.LMA.
const IA32E_MODE_GUEST: u32 = 1 << 9;
/// RFLAGS.VM: virtual-8086 mode.
const RFLAGS_VM: u64 = 1 << 17;

/// Where the eVMCS pages are, as a scan found them.
#[derive(Debug, Default)]
pub struct EvmcsPages {
    /// Every eVMCS page with its hypervisor root (`host_cr3`), by address.
    pages: Vec<(PhysAddr, u64)>,
    /// The VP assist pages, by address. Which eVMCS each names current
    /// changes with every VTL switch, and every switch to another
    /// partition's VP, so it is read at each use.
    assists: Vec<PhysAddr>,
}

impl EvmcsPages {
    /// The eVMCS pages the assist pages name current now.
    fn current(&self, phys: &impl MemoryOps<PhysAddr>) -> HashSet<PhysAddr> {
        self.assists
            .iter()
            .filter_map(|&assist| {
                let mut page = [0u8; ASSIST_CURRENT_NESTED_VMCS + 8];
                phys.read_bytes(assist, &mut page).ok()?;
                let current = u64_at(&page, ASSIST_CURRENT_NESTED_VMCS);
                (page[ASSIST_ENLIGHTEN_VMENTRY] == 1).then_some(current)
            })
            .filter(|current| self.pages.iter().any(|&(address, _)| address == *current))
            .collect()
    }

    /// The eVMCS pages of the VP whose hypervisor root is `host_root`,
    /// compared under `mask`, read now. A page that no longer holds an eVMCS
    /// of that root is skipped.
    pub fn states_for_root(
        &self,
        phys: &impl MemoryOps<PhysAddr>,
        host_root: u64,
        mask: u64,
    ) -> Vec<EvmcsState> {
        let current = self.current(phys);
        self.pages
            .iter()
            .filter(|(_, root)| root & mask == host_root & mask)
            .filter_map(|&(address, _)| {
                let mut page = [0u8; EVMCS_BYTES];
                phys.read_bytes(address, &mut page).ok()?;
                let state = EvmcsState::parse(&page)?;
                (state.host_cr3 & mask == host_root & mask).then(|| EvmcsState {
                    address,
                    current: current.contains(&address),
                    ..state
                })
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    /// The eVMCS loaded now on the processor whose hypervisor root is
    /// `host_root`, compared under `mask`: the one an assist page names
    /// current with that root, whatever root it had at the scan, as a guest
    /// partition's VP moves between processors (and roots) where the root's
    /// stay on theirs.
    pub fn loaded_for_root(
        &self,
        phys: &impl MemoryOps<PhysAddr>,
        host_root: u64,
        mask: u64,
    ) -> Option<EvmcsState> {
        self.current(phys).into_iter().find_map(|address| {
            let mut page = [0u8; EVMCS_BYTES];
            phys.read_bytes(address, &mut page).ok()?;
            let state = EvmcsState::parse(&page)?;
            (state.host_cr3 & mask == host_root & mask).then_some(EvmcsState {
                address,
                current: true,
                ..state
            })
        })
    }

    /// Every page that still holds an eVMCS, read now, whatever its root.
    pub fn all_states(&self, phys: &impl MemoryOps<PhysAddr>) -> Vec<EvmcsState> {
        let current = self.current(phys);
        self.pages
            .iter()
            .filter_map(|&(address, _)| {
                let mut page = [0u8; EVMCS_BYTES];
                phys.read_bytes(address, &mut page).ok()?;
                let state = EvmcsState::parse(&page)?;
                Some(EvmcsState {
                    address,
                    current: current.contains(&address),
                    ..state
                })
            })
            .collect()
    }

    fn has_root(&self, host_root: u64, mask: u64) -> bool {
        self.pages
            .iter()
            .any(|(_, root)| root & mask == host_root & mask)
    }
}

/// One eVMCS's guest state, as the hypervisor last saved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvmcsState {
    pub address: PhysAddr,
    /// The VP's assist page names this eVMCS current: the VTL the hypervisor
    /// last entered, or is about to enter.
    pub current: bool,
    /// The hypervisor's root on the processor that runs this VP.
    pub host_cr3: u64,
    /// The hypervisor's VM-exit entry point, and the stack it runs on.
    pub host_rip: u64,
    pub host_rsp: u64,
    /// The hypervisor's per-processor block on the processor that runs
    /// this VP.
    pub host_gs_base: u64,
    /// The EPT pointer: the root of the guest's second-level address
    /// translation (SLAT) and its memory type and walk length.
    pub ept_pointer: u64,
    /// Secondary processor-based VM-execution controls (Intel SDM 25.6.2).
    pub secondary_controls: u32,
    /// Basic exit reason in bits 15:0 (Intel SDM Appendix C).
    pub exit_reason: u32,
    /// VM-exit interruption information: the vector and type of the event
    /// that caused an exception or interrupt exit (Intel SDM 25.9.2).
    pub exit_interruption_info: u32,
    /// Length of the instruction that caused the exit, for exits caused by
    /// an instruction.
    pub exit_instruction_length: u32,
    /// Exit qualification: reason-specific detail, such as the access that
    /// caused an EPT violation (Intel SDM 28.2.1).
    pub exit_qualification: u64,
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    /// VM-entry controls (Intel SDM 25.8.1). The CPU loads the guest's
    /// IA32_EFER.LMA from "IA-32e mode guest" (bit 9) at each entry and
    /// stores it back there at each exit; the guest IA32_EFER field is used
    /// only under "load IA32_EFER" (bit 15), which Hyper-V leaves clear
    /// for some guests, so that field can read 0 for a 64-bit one.
    pub entry_controls: u32,
    pub dr7: u64,
    pub cs: u16,
    pub ss: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    /// CS's access rights in the VMX format (Intel SDM 25.4.1): the segment
    /// type, P (bit 7), L (bit 13, 64-bit code), D (bit 14, 32-bit
    /// default operand size), and "unusable" (bit 16).
    pub cs_access_rights: u32,
    pub fs_base: u64,
    pub gs_base: u64,
}

fn u16_at(page: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(page[offset..offset + 2].try_into().unwrap())
}

fn u32_at(page: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(page[offset..offset + 4].try_into().unwrap())
}

fn u64_at(page: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(page[offset..offset + 8].try_into().unwrap())
}

impl EvmcsState {
    /// A state at `address`, current or not, in 64-bit paging, with every
    /// other field zero but the few an eVMCS needs to parse.
    #[cfg(test)]
    pub fn at(address: PhysAddr, current: bool) -> Self {
        let mut page = [0u8; EVMCS_BYTES];
        page[..4].copy_from_slice(&EVMCS_VERSION.to_le_bytes());
        page[HOST_RIP..HOST_RIP + 8].copy_from_slice(&0xffff_f800_0000_0000u64.to_le_bytes());
        page[GUEST_CR0..GUEST_CR0 + 8].copy_from_slice(&(CR0_PE | CR0_PG).to_le_bytes());
        page[HOST_CR3..HOST_CR3 + 8].copy_from_slice(&0x1000u64.to_le_bytes());
        page[GUEST_CR3..GUEST_CR3 + 8].copy_from_slice(&0x2000u64.to_le_bytes());
        Self {
            address,
            current,
            ..Self::parse(&page).expect("a minimal eVMCS parses")
        }
    }

    /// The guest translates virtual addresses with 4-level long-mode paging:
    /// IA32_EFER.LMA set (the "IA-32e mode guest" entry control) and
    /// CR4.LA57 clear. A guest in 32-bit paging, PAE paging, or 5-level
    /// paging walks tables of another shape.
    pub fn four_level_paging(&self) -> bool {
        const CR4_LA57: u64 = 1 << 12;
        self.entry_controls & IA32E_MODE_GUEST != 0 && self.cr4 & CR4_LA57 == 0
    }

    /// The instruction set the guest's code runs in where it left off, so
    /// its bytes decode as the CPU executes them: 64-bit in IA-32e mode
    /// with a 64-bit code segment, else 32-bit protected (or compatibility)
    /// mode. The code segment decides only when its access rights are
    /// usable and present; otherwise IA-32e mode alone means 64-bit. Real
    /// mode and 16-bit code are refused rather than decoded as 32-bit.
    pub fn code_machine(&self) -> Result<CodeMachine> {
        const PRESENT: u32 = 1 << 7;
        const LONG: u32 = 1 << 13;
        const DEFAULT_32: u32 = 1 << 14;
        const UNUSABLE: u32 = 1 << 16;
        if self.cr0 & CR0_PE == 0 {
            return Err(Error::Hypervisor(
                "the guest is in real mode, whose 16-bit code ntoseye does not disassemble"
                    .to_string(),
            ));
        }
        let cs = self.cs_access_rights;
        let cs_known = cs & UNUSABLE == 0 && cs & PRESENT != 0;
        let long_mode = self.entry_controls & IA32E_MODE_GUEST != 0;
        if long_mode && (!cs_known || cs & LONG != 0) {
            return Ok(CodeMachine::Amd64);
        }
        if self.rflags & RFLAGS_VM != 0 || (cs_known && cs & DEFAULT_32 == 0) {
            return Err(Error::Hypervisor(
                "the guest runs 16-bit code, which ntoseye does not disassemble".to_string(),
            ));
        }
        Ok(CodeMachine::X86)
    }

    /// Whether the guest runs with mode-based execute control, under which
    /// EPT entries allow supervisor and user execution separately.
    pub fn mode_based_execute(&self) -> bool {
        self.secondary_controls & (1 << 22) != 0
    }

    /// The eVMCS at `address`, read now; `None` when the page does not hold
    /// one a 64-bit paged guest runs under.
    pub fn read(phys: &impl MemoryOps<PhysAddr>, address: PhysAddr) -> Option<Self> {
        let mut page = [0u8; EVMCS_BYTES];
        phys.read_bytes(address, &mut page).ok()?;
        Some(Self {
            address,
            ..Self::parse(&page)?
        })
    }

    /// An eVMCS of a hypervisor running a 64-bit paged guest: version 1, a
    /// host entry point in the upper half, and guest paging on. Anything
    /// else in RAM that starts with a 1 fails one of these.
    fn parse(page: &[u8]) -> Option<Self> {
        let host_rip = u64_at(page, HOST_RIP);
        let cr0 = u64_at(page, GUEST_CR0);
        if u32_at(page, 0) != EVMCS_VERSION
            || host_rip >> 47 != 0x1ffff
            || cr0 & (CR0_PE | CR0_PG) != CR0_PE | CR0_PG
            || u64_at(page, HOST_CR3) == 0
            || u64_at(page, GUEST_CR3) == 0
        {
            return None;
        }
        Some(Self {
            address: 0,
            current: false,
            host_cr3: u64_at(page, HOST_CR3),
            host_rip,
            host_rsp: u64_at(page, HOST_RSP),
            host_gs_base: u64_at(page, HOST_GS_BASE),
            ept_pointer: u64_at(page, EPT_POINTER),
            secondary_controls: u32_at(page, SECONDARY_CONTROLS),
            exit_reason: u32_at(page, VM_EXIT_REASON),
            exit_interruption_info: u32_at(page, VM_EXIT_INTR_INFO),
            exit_instruction_length: u32_at(page, VM_EXIT_INSTRUCTION_LEN),
            exit_qualification: u64_at(page, EXIT_QUALIFICATION),
            rip: u64_at(page, GUEST_RIP),
            rsp: u64_at(page, GUEST_RSP),
            rflags: u64_at(page, GUEST_RFLAGS),
            cr0,
            cr3: u64_at(page, GUEST_CR3),
            cr4: u64_at(page, GUEST_CR4),
            entry_controls: u32_at(page, VM_ENTRY_CONTROLS),
            dr7: u64_at(page, GUEST_DR7),
            cs: u16_at(page, GUEST_CS_SELECTOR),
            ss: u16_at(page, GUEST_SS_SELECTOR),
            ds: u16_at(page, GUEST_DS_SELECTOR),
            es: u16_at(page, GUEST_ES_SELECTOR),
            fs: u16_at(page, GUEST_FS_SELECTOR),
            gs: u16_at(page, GUEST_GS_SELECTOR),
            cs_access_rights: u32_at(page, GUEST_CS_AR_BYTES),
            fs_base: u64_at(page, GUEST_FS_BASE),
            gs_base: u64_at(page, GUEST_GS_BASE),
        })
    }

    /// Why the VTL last left for the hypervisor, by its basic exit reason.
    pub fn exit_reason_name(&self) -> Option<&'static str> {
        exit_reason_name(self.exit_reason)
    }
}

/// Names of the basic VM-exit reasons a Windows guest commonly takes (Intel
/// SDM Vol. 3D, Appendix C). Bit 31 marks a failed VM entry.
fn exit_reason_name(reason: u32) -> Option<&'static str> {
    if reason & (1 << 31) != 0 {
        return Some("failed VM entry");
    }
    Some(match reason & 0xffff {
        0 => "exception or NMI",
        1 => "external interrupt",
        2 => "triple fault",
        7 => "interrupt window",
        8 => "NMI window",
        10 => "CPUID",
        12 => "HLT",
        14 => "INVLPG",
        16 => "RDTSC",
        18 => "VMCALL",
        28 => "control-register access",
        29 => "debug-register access",
        30 => "I/O instruction",
        31 => "RDMSR",
        32 => "WRMSR",
        36 => "MWAIT",
        40 => "PAUSE",
        44 => "APIC access",
        45 => "virtualized EOI",
        48 => "EPT violation",
        49 => "EPT misconfiguration",
        52 => "preemption timer",
        54 => "WBINVD",
        55 => "XSETBV",
        56 => "APIC write",
        _ => return None,
    })
}

fn interrupted(flag: &AtomicBool) -> Result<()> {
    if flag.load(Ordering::Relaxed) {
        Err(Error::SavedVtlState("eVMCS scan interrupted".to_string()))
    } else {
        Ok(())
    }
}

/// Scan `runs` of RAM for eVMCS pages and the VP assist pages naming them.
fn scan(
    phys: &impl MemoryOps<PhysAddr>,
    runs: &[(u64, u64)],
    interrupt: &AtomicBool,
) -> Result<EvmcsPages> {
    let mut pages = Vec::new();
    // Candidate assist pages: any page whose enlighten_vmentry byte is 1 and
    // whose current_nested_vmcs is a page address, with that address. Kept
    // only if that address turns out to be an eVMCS.
    let mut assists = Vec::new();
    let mut chunk = vec![0u8; SCAN_BYTES];
    for &(start, length) in runs {
        let end = start.checked_add(length).ok_or(Error::InvalidRange)?;
        let mut address = start;
        while address < end {
            interrupted(interrupt)?;
            let count = usize::try_from((end - address).min(SCAN_BYTES as u64)).unwrap();
            phys.read_bytes(address, &mut chunk[..count])?;
            for (index, page) in chunk[..count].as_chunks::<PAGE_SIZE>().0.iter().enumerate() {
                let page_address = address + (index * PAGE_SIZE) as u64;
                if let Some(state) = EvmcsState::parse(page) {
                    pages.push((page_address, state.host_cr3));
                    if pages.len() > MAX_PAGES {
                        return Err(Error::SavedVtlState(format!(
                            "more than {MAX_PAGES} pages look like eVMCSes"
                        )));
                    }
                }
                let current = u64_at(page, ASSIST_CURRENT_NESTED_VMCS);
                if page[ASSIST_ENLIGHTEN_VMENTRY] == 1
                    && current != 0
                    && current.is_multiple_of(PAGE_SIZE as u64)
                {
                    assists.push((page_address, current));
                }
            }
            address += count as u64;
        }
    }
    let found: HashSet<PhysAddr> = pages.iter().map(|&(address, _)| address).collect();
    let assists = assists
        .into_iter()
        .filter(|(_, current)| found.contains(current))
        .map(|(assist, _)| assist)
        .collect();
    Ok(EvmcsPages { pages, assists })
}

/// The boot's eVMCS scan, and the hypervisor roots it was repeated for.
#[derive(Default)]
pub struct EvmcsCache {
    pages: Option<Arc<EvmcsPages>>,
    rescanned: HashSet<u64>,
}

impl EvmcsCache {
    /// The remembered pages if they can serve the VP whose hypervisor root
    /// is `host_root`; `None` when a scan is due. Finding no eVMCS at all
    /// is final for the boot, and a root the pages lack earns one rescan.
    fn serve(&mut self, host_root: u64, mask: u64) -> Option<Arc<EvmcsPages>> {
        let pages = self.pages.as_ref()?;
        (pages.is_empty()
            || pages.has_root(host_root, mask)
            || !self.rescanned.insert(host_root & mask))
        .then(|| Arc::clone(pages))
    }
}

impl Guest {
    /// The eVMCS pages in host RAM, for no VP in particular: scanned on
    /// first use and remembered for the boot, as in [`Self::evmcs_pages`].
    pub fn any_evmcs_pages(
        &self,
        phys: &PhysMem,
        interrupt: &AtomicBool,
    ) -> Result<Arc<EvmcsPages>> {
        if let Some(pages) = self.cached_evmcs_pages() {
            return Ok(pages);
        }
        let runs = phys.ram_runs();
        if runs.is_empty() {
            return Err(Error::SavedVtlState(
                "direct host RAM is required to read hypervisor memory".to_string(),
            ));
        }
        let pages = Arc::new(scan(phys, &runs, interrupt)?);
        let mut cache = self
            .evmcs_pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        Ok(Arc::clone(cache.pages.get_or_insert(pages)))
    }

    /// The eVMCS pages in host RAM, for the VP whose hypervisor root is
    /// `host_root` (compared under `mask`). Scanned on first use and
    /// remembered for the boot, as is finding none (the VM does not expose
    /// `hv-evmcs`). A scan made before this VP's pages existed (a stop early
    /// in boot, before NT started every processor) is repeated once for its
    /// root. An interrupted scan is not remembered.
    pub fn evmcs_pages(
        &self,
        phys: &PhysMem,
        interrupt: &AtomicBool,
        host_root: u64,
        mask: u64,
    ) -> Result<Arc<EvmcsPages>> {
        let mut cache = self
            .evmcs_pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(pages) = cache.serve(host_root, mask) {
            return Ok(pages);
        }
        let runs = phys.ram_runs();
        if runs.is_empty() {
            return Err(Error::SavedVtlState(
                "direct host RAM is required to read hypervisor memory".to_string(),
            ));
        }
        let pages = Arc::new(scan(phys, &runs, interrupt)?);
        cache.pages = Some(Arc::clone(&pages));
        Ok(pages)
    }

    /// The eVMCS pages if a scan already ran this boot.
    pub fn cached_evmcs_pages(&self) -> Option<Arc<EvmcsPages>> {
        self.evmcs_pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pages
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ram(Vec<u8>);

    impl MemoryOps<PhysAddr> for Ram {
        fn read_bytes(&self, address: PhysAddr, output: &mut [u8]) -> Result<()> {
            let start = usize::try_from(address).map_err(|_| Error::InvalidRange)?;
            let end = start.checked_add(output.len()).ok_or(Error::InvalidRange)?;
            output.copy_from_slice(self.0.get(start..end).ok_or(Error::InvalidRange)?);
            Ok(())
        }
        fn write_bytes(&self, _: PhysAddr, _: &[u8]) -> Result<()> {
            unreachable!()
        }
    }

    impl Ram {
        fn put(&mut self, address: usize, value: &[u8]) {
            self.0[address..address + value.len()].copy_from_slice(value);
        }

        fn evmcs(&mut self, page: usize, host_cr3: u64, guest_cr3: u64, rip: u64) {
            let base = page * PAGE_SIZE;
            self.put(base, &EVMCS_VERSION.to_le_bytes());
            self.put(base + HOST_CR3, &host_cr3.to_le_bytes());
            self.put(base + HOST_RIP, &0xffff_f826_34ba_843du64.to_le_bytes());
            self.put(base + GUEST_CR0, &0x8005_0033u64.to_le_bytes());
            self.put(base + GUEST_CR3, &guest_cr3.to_le_bytes());
            self.put(base + GUEST_RIP, &rip.to_le_bytes());
        }
    }

    fn scan_ram(ram: &Ram) -> EvmcsPages {
        scan(ram, &[(0, ram.0.len() as u64)], &AtomicBool::new(false)).unwrap()
    }

    /// A WSL2 guest's eVMCS, as read live: in 64-bit 4-level paging (the
    /// "IA-32e mode guest" entry control set, CR4.LA57 clear) with the guest
    /// IA32_EFER field holding no LMA, because "load IA32_EFER" is clear.
    /// The mode is the entry control's; LA57 makes it 5-level.
    #[test]
    fn long_mode_is_the_ia32e_entry_control_not_the_unloaded_efer_field() {
        let mut page = vec![0u8; PAGE_SIZE];
        page[..4].copy_from_slice(&EVMCS_VERSION.to_le_bytes());
        page[HOST_CR3..HOST_CR3 + 8].copy_from_slice(&0x10_0000u64.to_le_bytes());
        page[HOST_RIP..HOST_RIP + 8].copy_from_slice(&0xffff_f847_989a_843du64.to_le_bytes());
        page[GUEST_CR0..GUEST_CR0 + 8].copy_from_slice(&0x8005_0033u64.to_le_bytes());
        page[GUEST_CR3..GUEST_CR3 + 8].copy_from_slice(&0x103_b802u64.to_le_bytes());
        page[0x1b8..0x1c0].copy_from_slice(&0x801u64.to_le_bytes());
        let with = |entry_controls: u32, cr4: u64| {
            let mut page = page.clone();
            page[VM_ENTRY_CONTROLS..VM_ENTRY_CONTROLS + 4]
                .copy_from_slice(&entry_controls.to_le_bytes());
            page[GUEST_CR4..GUEST_CR4 + 8].copy_from_slice(&cr4.to_le_bytes());
            EvmcsState::parse(&page).unwrap().four_level_paging()
        };
        assert!(with(0x53ff, 0x3726f0));
        assert!(!with(0x53ff, 0x3726f0 | 1 << 12), "5-level paging");
        assert!(!with(0x53ff & !(1 << 9), 0x3726f0), "not in IA-32e mode");
    }

    /// Guest code decodes in the mode the guest left off in: 64-bit only
    /// in IA-32e mode with a 64-bit CS (or a CS whose access rights say
    /// nothing), 32-bit in compatibility and protected mode, and real mode
    /// and 16-bit code are refused rather than misdecoded.
    #[test]
    fn guest_code_decodes_in_the_mode_its_entry_controls_and_cs_give() {
        const LONG_CS: u32 = 0xa09b;
        const CODE32_CS: u32 = 0xc09b;
        const CODE16_CS: u32 = 0x009b;
        const UNUSABLE: u32 = 1 << 16;
        let state = |entry_controls: u32, cs: u32, cr0: u64, rflags: u64| {
            let mut page = vec![0u8; PAGE_SIZE];
            page[..4].copy_from_slice(&EVMCS_VERSION.to_le_bytes());
            page[HOST_CR3..HOST_CR3 + 8].copy_from_slice(&0x10_0000u64.to_le_bytes());
            page[HOST_RIP..HOST_RIP + 8].copy_from_slice(&0xffff_f847_989a_843du64.to_le_bytes());
            page[GUEST_CR0..GUEST_CR0 + 8].copy_from_slice(&(CR0_PE | CR0_PG).to_le_bytes());
            page[GUEST_CR3..GUEST_CR3 + 8].copy_from_slice(&0x103_b802u64.to_le_bytes());
            page[VM_ENTRY_CONTROLS..VM_ENTRY_CONTROLS + 4]
                .copy_from_slice(&entry_controls.to_le_bytes());
            page[GUEST_CS_AR_BYTES..GUEST_CS_AR_BYTES + 4].copy_from_slice(&cs.to_le_bytes());
            page[GUEST_RFLAGS..GUEST_RFLAGS + 8].copy_from_slice(&rflags.to_le_bytes());
            EvmcsState {
                cr0,
                ..EvmcsState::parse(&page).unwrap()
            }
        };
        let machine = |entry_controls, cs, cr0, rflags| {
            state(entry_controls, cs, cr0, rflags).code_machine().ok()
        };
        let protected = CR0_PE | CR0_PG;
        let long = 0x53ff;
        let legacy = 0x53ff & !IA32E_MODE_GUEST;
        assert_eq!(
            machine(long, LONG_CS, protected, 2),
            Some(CodeMachine::Amd64)
        );
        assert_eq!(
            machine(long, 0, protected, 2),
            Some(CodeMachine::Amd64),
            "CS not present"
        );
        assert_eq!(
            machine(long, CODE32_CS | UNUSABLE, protected, 2),
            Some(CodeMachine::Amd64),
            "CS unusable"
        );
        assert_eq!(
            machine(long, CODE32_CS, protected, 2),
            Some(CodeMachine::X86),
            "compatibility mode"
        );
        assert_eq!(
            machine(legacy, CODE32_CS, protected, 2),
            Some(CodeMachine::X86)
        );
        assert_eq!(
            machine(legacy, 0, protected, 2),
            Some(CodeMachine::X86),
            "protected mode, CS not present"
        );
        assert_eq!(machine(legacy, CODE16_CS, protected, 2), None, "16-bit CS");
        assert_eq!(
            machine(legacy, CODE32_CS, protected, 2 | RFLAGS_VM),
            None,
            "virtual-8086 mode"
        );
        let real = state(legacy, CODE16_CS, 0, 2).code_machine().unwrap_err();
        assert!(real.to_string().contains("real mode"), "{real}");
    }

    /// The scan runs once per boot, but the VTL a processor last entered
    /// changes all the time: which eVMCS is current must follow its assist
    /// page, not stay what the scan saw.
    #[test]
    fn the_current_evmcs_follows_the_assist_page_after_the_scan() {
        let mut ram = Ram(vec![0; 16 * PAGE_SIZE]);
        ram.evmcs(1, 0x10_0000, 0x1ae002, 0xfffff807978a950f);
        ram.evmcs(2, 0x10_0000, 0x460_0002, 0xfffff807281c0035);
        let assist = 8 * PAGE_SIZE;
        ram.put(assist + ASSIST_ENLIGHTEN_VMENTRY, &[1]);
        ram.put(
            assist + ASSIST_CURRENT_NESTED_VMCS,
            &(PAGE_SIZE as u64).to_le_bytes(),
        );
        let pages = scan_ram(&ram);
        let current = |ram: &Ram| -> Vec<bool> {
            pages
                .states_for_root(ram, 0x10_0000, !0xfff)
                .iter()
                .map(|state| state.current)
                .collect()
        };
        assert_eq!(current(&ram), [true, false]);
        // The processor entered VTL1.
        ram.put(
            assist + ASSIST_CURRENT_NESTED_VMCS,
            &(2 * PAGE_SIZE as u64).to_le_bytes(),
        );
        assert_eq!(current(&ram), [false, true]);
        // It entered a guest partition's VP, whose eVMCS the scan never saw.
        ram.put(
            assist + ASSIST_CURRENT_NESTED_VMCS,
            &(12 * PAGE_SIZE as u64).to_le_bytes(),
        );
        assert_eq!(current(&ram), [false, false]);
    }

    #[test]
    fn scan_keeps_evmcs_pages_and_rejects_lookalikes() {
        let mut ram = Ram(vec![0; 16 * PAGE_SIZE]);
        ram.evmcs(1, 0x10_0000, 0x1ae002, 0xfffff807978a950f);
        ram.evmcs(2, 0x10_0000, 0x460_0002, 0xfffff807281c0035);
        ram.evmcs(3, 0x20_0000, 0x1ae002, 0xfffff807978a950f);
        // Version 1 but paging off, a user-half host entry point, and a
        // different version: none is a 64-bit guest's eVMCS.
        ram.evmcs(4, 0x20_0000, 0x1ae002, 0);
        ram.put(4 * PAGE_SIZE + GUEST_CR0, &0x10u64.to_le_bytes());
        ram.evmcs(5, 0x20_0000, 0x1ae002, 0);
        ram.put(5 * PAGE_SIZE + HOST_RIP, &0x7ff0_0000_0000u64.to_le_bytes());
        ram.evmcs(6, 0x20_0000, 0x1ae002, 0);
        ram.put(6 * PAGE_SIZE, &2u32.to_le_bytes());
        // VP 0x10_0000's assist page names page 1 current; another page with
        // a plausible current pointer that is no eVMCS is not an assist page.
        ram.put(8 * PAGE_SIZE + ASSIST_ENLIGHTEN_VMENTRY, &[1]);
        ram.put(
            8 * PAGE_SIZE + ASSIST_CURRENT_NESTED_VMCS,
            &(PAGE_SIZE as u64).to_le_bytes(),
        );
        ram.put(9 * PAGE_SIZE + ASSIST_ENLIGHTEN_VMENTRY, &[1]);
        ram.put(
            9 * PAGE_SIZE + ASSIST_CURRENT_NESTED_VMCS,
            &(10 * PAGE_SIZE as u64).to_le_bytes(),
        );

        let pages = scan_ram(&ram);
        let states = pages.states_for_root(&ram, 0x10_0000, !0xfff);
        assert_eq!(
            states
                .iter()
                .map(|state| (state.address, state.cr3, state.current))
                .collect::<Vec<_>>(),
            [
                (PAGE_SIZE as u64, 0x1ae002, true),
                (2 * PAGE_SIZE as u64, 0x460_0002, false),
            ]
        );
        assert_eq!(
            pages
                .states_for_root(&ram, 0x20_0000, !0xfff)
                .iter()
                .map(|state| state.address)
                .collect::<Vec<_>>(),
            [3 * PAGE_SIZE as u64]
        );
    }

    #[test]
    fn states_are_read_at_use_and_dropped_once_the_page_changes_hands() {
        let mut ram = Ram(vec![0; 4 * PAGE_SIZE]);
        ram.evmcs(1, 0x10_0000, 0x1ae002, 0x1000);
        let pages = scan_ram(&ram);

        ram.put(PAGE_SIZE + GUEST_RIP, &0x2000u64.to_le_bytes());
        let states = pages.states_for_root(&ram, 0x10_0000, !0xfff);
        assert_eq!(states[0].rip, 0x2000);

        ram.put(PAGE_SIZE + HOST_CR3, &0x30_0000u64.to_le_bytes());
        assert!(pages.states_for_root(&ram, 0x10_0000, !0xfff).is_empty());
    }

    #[test]
    fn a_root_missing_from_the_scan_rescans_once() {
        let mut ram = Ram(vec![0; 2 * PAGE_SIZE]);
        ram.evmcs(1, 0x10_0000, 0x1ae002, 0x1000);
        let mut cache = EvmcsCache::default();
        assert!(cache.serve(0x10_0000, !0xfff).is_none());
        cache.pages = Some(Arc::new(scan_ram(&ram)));

        assert!(cache.serve(0x10_0000, !0xfff).is_some());
        // A VP started after the scan: one rescan, then the result stands.
        assert!(cache.serve(0x20_0000, !0xfff).is_none());
        assert!(cache.serve(0x20_0000, !0xfff).is_some());

        // No eVMCS anywhere (no hv-evmcs) never rescans.
        cache = EvmcsCache {
            pages: Some(Arc::new(EvmcsPages::default())),
            ..EvmcsCache::default()
        };
        assert!(cache.serve(0x20_0000, !0xfff).is_some());
    }
}
