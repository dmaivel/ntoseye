//! How a code breakpoint reaches the target: the target-owned and
//! host-patched backends, the checks a site must pass before it is
//! written, and masking the patched bytes back out of display reads.

use pelite::{PeView, image::IMAGE_SCN_MEM_EXECUTE};

use super::journal::{Restore, SiteMemory, site_window};
use super::{BreakpointInfo, BreakpointManager, BreakpointScope};
use crate::arch::{Arch, Family};
use crate::backend::dbg_backend::{DebugBackend, DebugCapability};
use crate::backend::kd::trace_enabled;
use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE, Residency};
use crate::base::types::{Dtb, PhysAddr, VirtAddr};
use crate::nt::guest::ModuleInfo;
use crate::nt::pe::read_pe_header_page;
use crate::nt::target::Target;
use crate::nt::target::mm::PfnSelector;

/// Who owns the patched instruction for a breakpoint.
///
/// * `Kernel`: written through the target's debugger API
///   (`DbgKdWriteBreakPointApi` / gdb `Z0`). The target tracks the original
///   instruction and handles step-over.
/// * `GuestMemoryPatch`: a user-space site writes the architecture's
///   breakpoint instruction (`int3` on AMD64 or `brk #0xF000` on AArch64)
///   through the live VM memory handle against a specific process page table.
///   KD has no per-process breakpoint primitive: its API uses the current
///   address-space root. Writing the physical frame bypasses copy-on-write, so
///   every process mapping that frame sees the trap; the address-space filter
///   discards wrong-process hits, though those processes still pay for the
///   exception. Kernel code is never patched this way, whatever the scope: see
///   [`BreakpointManager::install_is_target_owned`].
/// * `Hardware`: an architecture debug-register watch (`ba`). The CPU traps
///   on the linear address without modifying memory or displacing an instruction.
///   The DR slot and watch parameters live on
///   [`Breakpoint::hardware`]; hits are identified by DR6, not by RIP, so
///   hardware breakpoints stay out of the int3-hit predicates.
#[derive(Debug, Clone, Copy)]
pub(super) struct BreakpointPatch {
    bytes: [u8; 4],
    len: u8,
}

impl BreakpointPatch {
    fn new(len: usize) -> Self {
        debug_assert!((1..=4).contains(&len));
        Self {
            bytes: [0; 4],
            len: len as u8,
        }
    }

    #[cfg(test)]
    pub(super) fn single(byte: u8) -> Self {
        let mut patch = Self::new(1);
        patch.bytes[0] = byte;
        patch
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len as usize;
        &mut self.bytes[..len]
    }
}

#[derive(Debug, Clone)]
pub(super) enum BreakpointBackend {
    /// Installed through the target's own breakpoint API. `original` is the
    /// displaced instruction, or `None` when the site's page was not resident
    /// and the target owes the write until it is paged in.
    Kernel {
        original: Option<BreakpointPatch>,
    },
    GuestMemoryPatch {
        original: BreakpointPatch,
    },
    Hardware,
    Deferred,
}

/// Record a host-patched site in the target's journal before its breakpoint
/// instruction is written at `address` in `dtb`'s address space: `original`
/// is the instruction it displaces, and the bytes after it come from memory.
/// Recording first means a session that dies at any point leaves nothing
/// patched that the journal does not know. The frame's PTE is recorded with
/// it, so the site can still be told from a reused frame once its address
/// no longer translates.
fn journal_site(debugger: &Target, dtb: Dtb, address: VirtAddr, original: &[u8]) {
    let Some(journal) = debugger.site_journal.as_ref() else {
        return;
    };
    let memory = debugger.address_space(dtb);
    let Ok(Some(translation)) = memory.virt_to_phys(address) else {
        return;
    };
    let mut bytes = [0u8; 8];
    let len = site_window(translation.address, &bytes).len();
    if len < original.len() || memory.read_bytes(address, &mut bytes[..len]).is_err() {
        return;
    }
    bytes[..original.len()].copy_from_slice(original);
    let pte = frame_pte(debugger, translation.address).filter(|pte| *pte != 0);
    journal.record(dtb, address, translation.address, &bytes[..len], pte);
}

/// `_MMPFN.PteAddress` of the frame holding guest-physical `address`: the
/// PTE mapping the page it holds.
fn frame_pte(debugger: &Target, address: PhysAddr) -> Option<u64> {
    debugger
        .inspect_pfn(PfnSelector::Pfn(address / PAGE_SIZE as u64))
        .ok()
        .map(|detail| detail.pte_address.0)
}

/// Drop a host-patched site planted at `address` in `dtb`'s address space
/// from the journal once its original instruction is back in guest memory.
pub fn forget_site(debugger: &Target, dtb: Dtb, address: VirtAddr) {
    if let Some(journal) = debugger.site_journal.as_ref() {
        journal.forget(dtb, address);
    }
}

/// Take out the host-patched site at `address` in `dtb`'s address space,
/// writing back `original`, the instruction it displaced.
///
/// An address that no longer translates there (its process has exited,
/// taking its page tables) cannot be written through them, but its frame
/// may still hold the breakpoint: a page of a shared image stays in every
/// other process mapping it. The journal then writes the frame it recorded,
/// only if that still holds the breakpoint and the same page (see
/// [`SiteJournal::lift`]); a frame the guest has since given to other data
/// is left alone, and the site is dropped either way, so a site whose
/// process is gone does not keep the session from detaching.
///
/// [`SiteJournal::lift`]: super::SiteJournal::lift
fn lift_user_site(debugger: &Target, dtb: Dtb, address: VirtAddr, original: &[u8]) -> Result<()> {
    let refused = match write_user_code(debugger, dtb, address, original) {
        Ok(()) => {
            forget_site(debugger, dtb, address);
            return Ok(());
        }
        Err(error) => error,
    };
    let mapped = matches!(
        debugger.address_space(dtb).virt_to_phys(address),
        Ok(Some(translation)) if translation.residency == Residency::Mapped
    );
    let opcode = debugger.arch().breakpoint_instruction();
    let lifted = debugger
        .site_journal
        .as_ref()
        .filter(|_| !mapped)
        .and_then(|journal| journal.lift(dtb, address, &SiteFrames::new(debugger), opcode));
    let Some((frame, restore)) = lifted else {
        return Err(refused);
    };
    let outcome = match restore {
        Restore::Restored => "wrote its original instruction back through its frame".to_string(),
        Restore::NotPatched => "dropped: its frame no longer holds the breakpoint".to_string(),
        Restore::Reused { now } => {
            format!("dropped: its frame now holds another page, the one PTE {now:#x} maps")
        }
        Restore::Unconfirmed => "dropped: the PFN database could not be read to tell whether \
                                 its frame still holds its page; the next attach retries it"
            .to_string(),
        Restore::Failed => {
            return Err(Error::Breakpoint(format!(
                "{:#x} no longer translates in its process, and writing its original instruction \
                 back through frame {frame:#x} failed",
                address.0
            )));
        }
    };
    if trace_enabled() {
        eprintln!(
            "breakpoint: site {:#x} no longer translates in address space {dtb:#x} ({refused}); \
             {outcome} (frame {frame:#x})",
            address.0
        );
    }
    Ok(())
}

/// Plant a breakpoint through the backend at kernel `address`, whose
/// displaced instruction is `original` (`None` when its page is not resident
/// and the target writes the site later). A backend that does not reclaim
/// what a dead session abandons has the site journaled first, and forgotten
/// again if the backend refuses it. Where Windows itself takes the trap, a
/// site it cannot take one at is refused (see
/// [`Target::breakpoint_site_refusal`]).
pub fn plant_target_site(
    client: &mut dyn DebugBackend,
    debugger: &Target,
    address: VirtAddr,
    original: Option<&[u8]>,
) -> Result<()> {
    if client.debug_traps_reach_target()
        && let Some(refusal) = debugger.breakpoint_site_refusal(address)
    {
        return Err(Error::Breakpoint(refusal));
    }
    let journaled = !client.reclaims_abandoned_breakpoints();
    if journaled && let Some(original) = original {
        journal_site(debugger, debugger.kernel_dtb(), address, original);
    }
    let planted = client.set_breakpoint(address.0);
    if planted.is_err() && journaled {
        forget_site(debugger, debugger.kernel_dtb(), address);
    }
    planted
}

/// Take out a breakpoint [`plant_target_site`] planted, and its journal entry.
pub fn lift_target_site(
    client: &mut dyn DebugBackend,
    debugger: &Target,
    address: VirtAddr,
) -> Result<()> {
    client.remove_breakpoint(address.0)?;
    if !client.reclaims_abandoned_breakpoints() {
        forget_site(debugger, debugger.kernel_dtb(), address);
    }
    Ok(())
}

impl BreakpointBackend {
    /// The instruction bytes we displaced with the breakpoint, so display
    /// paths can overlay them and never show our own patch (1 byte for an
    /// x86 `int3`, 4 for an AArch64 `brk #0xF000`). Hardware breakpoints
    /// displace nothing (they never reach the masking path).
    fn original_bytes(&self) -> &[u8] {
        match self {
            Self::Kernel {
                original: Some(original),
            }
            | Self::GuestMemoryPatch { original } => original.as_slice(),
            // A site whose page was not resident at install time displaced
            // nothing we have seen: there is no byte to overlay, and a read of
            // that page cannot succeed while it stays paged out.
            Self::Kernel { original: None } | Self::Hardware | Self::Deferred => &[],
        }
    }
}

impl BreakpointInfo {
    /// The target accepted this breakpoint but its site was not resident, so
    /// the target's own breakpoint table owes the opcode until the page is
    /// paged in (`nt!KdSetOwedBreakpoints` writes it then). Only a
    /// target-owned site can be owed; a site this debugger patches itself is
    /// refused while its page is out, since nothing tells the debugger when
    /// the page arrives. Distinct from [`Self::deferred`], which is a
    /// breakpoint whose *address* is not known yet: this one has an address
    /// the target has agreed to.
    pub fn awaiting_page_in(&self) -> bool {
        matches!(self.backend, BreakpointBackend::Kernel { original: None })
    }
}

impl BreakpointManager {
    /// Whether the target installs this site into its own breakpoint table,
    /// rather than this debugger patching guest memory.
    ///
    /// Kernel code is shared by every process, so a process scope over a
    /// kernel address is a filter on which hits are surfaced, not a license to
    /// write a shared kernel page through host memory: patching the frame
    /// ourselves would trap every process that executes it, leave the target's
    /// own breakpoint bookkeeping unaware of the `int3`, and put this debugger
    /// in charge of restoring a byte in code it does not own. The scope only
    /// picks the page tables a user-space site is resolved through.
    fn install_is_target_owned(
        arch: Arch,
        address: Option<VirtAddr>,
        scope: &BreakpointScope,
    ) -> bool {
        matches!(scope, BreakpointScope::Kernel)
            || address.is_some_and(|address| arch.paging().is_kernel_address(address))
    }

    pub(super) fn validate_scope_capability(
        client: &dyn DebugBackend,
        arch: Arch,
        address: Option<VirtAddr>,
        scope: &BreakpointScope,
    ) -> Result<()> {
        let user_space = address.is_some_and(|address| !arch.paging().is_kernel_address(address));
        // A user-space site needs the user-mode capability whatever the scope:
        // a GDB stub writes and restores it through whichever vCPU it has
        // selected, so a lift through one that does not map the page (in the
        // Windows hypervisor, the System process, or a guest partition's VP)
        // fails or restores nothing, and the stub forgets it anyway when the
        // client detaches, leaving the `int3` in shared code.
        let capability = if user_space {
            DebugCapability::UserModeBreakpoints
        } else if Self::install_is_target_owned(arch, address, scope) {
            DebugCapability::KernelBreakpoints
        } else {
            DebugCapability::UserModeBreakpoints
        };
        if client
            .capabilities()
            .iter()
            .any(|c| c.capability == capability && c.supported)
        {
            Ok(())
        } else if capability == DebugCapability::UserModeBreakpoints
            && client.supports_watchpoints()
        {
            // A deferred breakpoint scoped to a process has no address yet,
            // but its site is in user space all the same.
            let at = address
                .map(|address| format!(" ({:#x})", address.0))
                .unwrap_or_default();
            Err(Error::Breakpoint(format!(
                "this backend cannot plant a software breakpoint in user space{at}; a hardware breakpoint (ba e1) can stop there"
            )))
        } else {
            Err(Error::Breakpoint(format!(
                "the {} backend cannot plant breakpoints",
                client.name()
            )))
        }
    }

    pub(super) fn install_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        scope: &BreakpointScope,
    ) -> Result<BreakpointBackend> {
        Self::require_patchable_address(debugger, address)?;
        if Self::install_is_target_owned(debugger.arch(), Some(address), scope) {
            // Capture the displaced instruction before the kernel writes
            // the breakpoint, so display paths can mask it back out. x86
            // `int3` displaces one byte; AArch64 `brk #0xF000` displaces
            // four. Kernel code is read through the kernel's own tables: an
            // attached process's (KVA-shadow) CR3 need not map it.
            let memory = debugger.address_space(debugger.kernel_dtb());
            let mut original = BreakpointPatch::new(debugger.arch().breakpoint_instruction().len());
            // A page that is not resident has no bytes to displace yet.
            // The target's own breakpoint table records the site and writes
            // the opcode when the page arrives (`nt!KdpSetOwedBreakpoints`),
            // so refusing here would reject a breakpoint the target accepts.
            let original = match memory.read_bytes(address, original.as_mut_slice()) {
                Ok(()) => Some(original),
                Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)) => None,
                Err(error) => return Err(error),
            };
            plant_target_site(
                client,
                debugger,
                address,
                original.as_ref().map(BreakpointPatch::as_slice),
            )?;
            return Ok(BreakpointBackend::Kernel { original });
        }
        let dtb = match scope {
            BreakpointScope::Process { dtb, .. } => *dtb,
            BreakpointScope::Kernel => debugger.kernel_dtb(),
        };
        let memory = debugger.address_space(dtb);
        let opcode = debugger.arch().breakpoint_instruction();
        let mut original = BreakpointPatch::new(opcode.len());
        // This debugger owns the byte at a user-space site, and it cannot
        // write one into a page that is not there; nothing tells it when the
        // page arrives. The target's own table can owe the site instead
        // when the processor that stopped runs in the scope's process: KD
        // records a user-space site with the address space it was set in,
        // and the kernel writes it when that process faults the page in (a
        // deferred breakpoint armed as its image is mapped). Otherwise say
        // so now instead of accepting a site that would never arm.
        match memory.read_bytes(address, original.as_mut_slice()) {
            Ok(()) => {}
            Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)) => {
                if client.debug_traps_reach_target() && Self::stopped_in_scope(debugger, scope) {
                    plant_target_site(client, debugger, address, None)?;
                    return Ok(BreakpointBackend::Kernel { original: None });
                }
                return Err(Self::non_resident_site_error(debugger, dtb, address, scope));
            }
            Err(error) => return Err(error),
        }
        // A page the process has not touched is read through its section's
        // prototype, and one in transition through its frame, but neither
        // is the process's own to write: the target owes the site the same
        // way, writing it when the process faults the page in.
        let mapped = matches!(
            memory.virt_to_phys(address),
            Ok(Some(translation)) if translation.residency == Residency::Mapped
        );
        if !mapped && client.debug_traps_reach_target() && Self::stopped_in_scope(debugger, scope) {
            plant_target_site(client, debugger, address, None)?;
            return Ok(BreakpointBackend::Kernel { original: None });
        }
        journal_site(debugger, dtb, address, original.as_slice());
        write_user_code(debugger, dtb, address, opcode)?;
        // The kernel does not know about a breakpoint patched through
        // host memory, so update the backend's stop bookkeeping.
        client.note_breakpoint_installed(address.0);
        Ok(BreakpointBackend::GuestMemoryPatch { original })
    }

    pub(super) fn install_existing_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &BreakpointInfo,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            // The target owns the byte whatever the scope filters hits on.
            (_, BreakpointBackend::Kernel { original }) => plant_target_site(
                client,
                debugger,
                bp.address,
                original.as_ref().map(BreakpointPatch::as_slice),
            ),
            (
                BreakpointScope::Process { dtb, .. },
                BreakpointBackend::GuestMemoryPatch { original },
            ) => {
                journal_site(debugger, *dtb, bp.address, original.as_slice());
                write_user_code(
                    debugger,
                    *dtb,
                    bp.address,
                    debugger.arch().breakpoint_instruction(),
                )?;
                client.note_breakpoint_installed(bp.address.0);
                Ok(())
            }
            (_, BreakpointBackend::Hardware) => match bp.hardware {
                Some(hw) => {
                    client.set_hardware_breakpoint(hw.slot, bp.address.0, hw.access, hw.len)
                }
                None => Err(Error::Breakpoint(
                    "hardware breakpoint missing parameters".into(),
                )),
            },
            _ => Err(Error::Breakpoint(
                "breakpoint backend/scope mismatch".into(),
            )),
        }
    }

    pub(super) fn uninstall_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &BreakpointInfo,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (_, BreakpointBackend::Kernel { .. }) => lift_target_site(client, debugger, bp.address),
            (
                BreakpointScope::Process { dtb, .. },
                BreakpointBackend::GuestMemoryPatch { original },
            ) => {
                lift_user_site(debugger, *dtb, bp.address, original.as_slice())?;
                client.note_breakpoint_uninstalled(bp.address.0);
                Ok(())
            }
            (_, BreakpointBackend::Hardware) => match bp.hardware {
                Some(hw) => client.clear_hardware_breakpoint(hw.slot),
                None => Err(Error::Breakpoint(
                    "hardware breakpoint missing parameters".into(),
                )),
            },
            _ => Err(Error::Breakpoint(
                "breakpoint backend/scope mismatch".into(),
            )),
        }
    }

    /// Drop the backend's bookkeeping for a host-patched site that is being
    /// abandoned rather than restored (KD classifies stops by that set).
    pub(super) fn forget_backend_site(client: &mut dyn DebugBackend, bp: &BreakpointInfo) {
        if matches!(bp.backend, BreakpointBackend::GuestMemoryPatch { .. }) {
            client.note_breakpoint_uninstalled(bp.address.0);
        }
    }

    pub(super) fn validate_breakpoint_target(
        debugger: &Target,
        address: VirtAddr,
        scope: &BreakpointScope,
    ) -> Result<()> {
        Self::require_patchable_address(debugger, address)?;
        let module = Self::find_kernel_module_containing_address(debugger, address);
        let root = match scope {
            BreakpointScope::Kernel => debugger.kernel_dtb(),
            BreakpointScope::Process { dtb, .. } => *dtb,
        };
        // User code runs on the process's KVA-shadow root when it has one:
        // the kernel root's copy of the user half is non-executable.
        let dtb = if debugger.arch().paging().is_kernel_address(address) {
            root
        } else {
            let mask = debugger.arch().dtb_page_mask();
            debugger
                .process_for_cr3(root & mask)
                .zip(debugger.guest().ok())
                .and_then(|(process, guest)| guest.user_root(&process, mask))
                .unwrap_or(root)
        };
        let memory = debugger.address_space(dtb);
        let translation = match memory.virt_to_phys(address) {
            Ok(Some(translation)) => Some(translation),
            // The page is not resident. Kernel code is demand-paged and a
            // driver's `INIT` section is discarded outright, so a debugger that
            // insists on a translation cannot break on either, while the
            // target itself accepts the site and owes the write until the page
            // arrives (`nt!KdSetOwedBreakpoints`). Hand that decision to the
            // target rather than pre-empting it.
            Ok(None) if debugger.arch().paging().is_kernel_address(address) => None,
            // A user-space site is this debugger's own `int3` in that page,
            // and there is no page to put it in, unless the target can owe
            // it (see `install_breakpoint`). A view just being mapped can
            // have no translation to read at all yet.
            Ok(None) | Err(Error::BadVirtualAddress(_))
                if Self::stopped_in_scope(debugger, scope) =>
            {
                None
            }
            Ok(None) | Err(Error::BadVirtualAddress(_)) => {
                return Err(Self::non_resident_site_error(debugger, dtb, address, scope));
            }
            Err(error) => return Err(error),
        };

        // AArch64 table-level execute restrictions depend on TCR_EL1
        // hierarchical-permission controls, which passive memory inspection
        // does not capture. Do not reject a TTBR1 address solely from descriptor
        // bits; known kernel modules are still checked against PE executable
        // sections below. TTBR0 user pages can be classified by effective UXN.
        let nx = match (
            debugger.arch(),
            debugger.arch().paging().is_kernel_address(address),
            &translation,
        ) {
            (Arch::Arm64, true, _) => false,
            (Arch::Arm64, false, Some(translation)) => translation.uxn,
            (Arch::Amd64, _, Some(translation)) => translation.nx,
            // No translation to judge: the executable-section check below is
            // the only evidence available, and it does not need the page.
            (Arch::Amd64 | Arch::Arm64, _, None) => false,
        };

        if nx {
            let context = module
                .as_ref()
                .map(|module| module.short_name.as_str())
                .unwrap_or("unknown");
            return Err(Error::NotCode {
                address: address.0,
                reason: format!("target page is non-executable ({context})"),
            });
        }

        if let Some(module) = module {
            let headers = read_pe_header_page(module.base_address, &memory)?;
            let view = PeView::from_bytes(&headers)?;
            let rva = address.0.saturating_sub(module.base_address.0) as u32;
            let in_executable_section = view.section_headers().iter().any(|section| {
                let size = section.VirtualSize.max(section.SizeOfRawData);
                size != 0
                    && section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    && rva >= section.VirtualAddress
                    && rva < section.VirtualAddress.saturating_add(size)
            });

            if !in_executable_section {
                return Err(Error::NotCode {
                    address: address.0,
                    reason: format!(
                        "address falls in non-executable section of {}",
                        module.short_name
                    ),
                });
            }
        }

        Ok(())
    }

    fn require_patchable_address(debugger: &Target, address: VirtAddr) -> Result<()> {
        // NT addresses stay patchable from the hypervisor's context: the
        // breakpoint is written through a vCPU in NT.
        if debugger.in_hypervisor_image(address)
            || (debugger.in_hypervisor_address_space()
                && Self::find_kernel_module_containing_address(debugger, address).is_none())
        {
            return Err(Error::Breakpoint(
                "software breakpoints in the Windows hypervisor are refused because ntoseye does not write its memory; use a GDB hardware execution breakpoint (ba e1)".into(),
            ));
        }
        if debugger.is_secure_address(address)
            || (debugger.in_secure_address_space()
                && Self::find_kernel_module_containing_address(debugger, address).is_none())
        {
            return Err(Error::Breakpoint(
                "software breakpoints in VTL1 are refused to avoid modifying integrity-protected code; use a GDB hardware execution breakpoint (ba e1)".into(),
            ));
        }
        Ok(())
    }

    /// A user-space breakpoint site whose page is not resident.
    ///
    /// Unlike a kernel site, which the target records and writes when the
    /// page arrives, a user-space site is an `int3` this debugger patches
    /// into the page itself: there is nothing to patch while the page is out,
    /// and no event tells the debugger it arrived. Name the module when one
    /// covers the address, since that distinguishes code that simply has not
    /// been touched yet from an address that is merely wrong.
    /// Whether the processor that stopped runs in `scope`'s process: the
    /// address space the target's breakpoint API records a user-space site
    /// in.
    fn stopped_in_scope(debugger: &Target, scope: &BreakpointScope) -> bool {
        matches!(scope, BreakpointScope::Process { .. })
            && debugger
                .register_value(debugger.arch().dtb_register())
                .is_some_and(|dtb| scope.matches_dtb(dtb, debugger.arch()))
    }

    fn non_resident_site_error(
        debugger: &Target,
        dtb: Dtb,
        address: VirtAddr,
        scope: &BreakpointScope,
    ) -> Error {
        match debugger.symbols.find_module_for_address(dtb, address) {
            Some(module) => Error::Breakpoint(format!(
                "{:#x} is in {}+{:#x} but that page is not paged in; consider using \
                 `ba e1 {:#x}` instead",
                address.0,
                ModuleInfo::derive_short_name(&module.name),
                address.0.saturating_sub(module.base_address.0),
                address.0,
            )),
            None => Error::Breakpoint(format!(
                "{:#x} is not mapped in {} and no loaded image covers it",
                address.0,
                scope.label(),
            )),
        }
    }

    pub(super) fn find_kernel_module_containing_address(
        debugger: &Target,
        address: VirtAddr,
    ) -> Option<ModuleInfo> {
        debugger
            .kernel_modules()
            .ok()?
            .into_iter()
            .find(|module| module.contains_address(address))
    }

    /// Overlay our breakpoints' original bytes onto a buffer read for display,
    /// so no view ever shows the int3 we injected. `start` is the buffer's
    /// guest VA and `cr3` the address space it was read from.
    ///
    /// A site is masked wherever the read reaches the frame the byte was
    /// written into, since that is what decides whether our `int3` is what
    /// the caller would otherwise see. One rule covers a kernel site under
    /// every address space and a user site in a shared image page under every
    /// process mapping it, while leaving a process that merely has its own
    /// memory at the same address untouched.
    pub fn mask_breakpoint_bytes(
        &self,
        debugger: &Target,
        start: VirtAddr,
        buf: &mut [u8],
        cr3: u64,
    ) {
        let end = start.0.wrapping_add(buf.len() as u64);
        for bp in self.planted_sites() {
            if bp.address.0 < start.0 || bp.address.0 >= end {
                continue;
            }
            if !Self::site_is_in_view(debugger, bp, cr3) {
                continue;
            }
            let offset = (bp.address.0 - start.0) as usize;
            let bytes = bp.backend.original_bytes();
            if offset + bytes.len() <= buf.len() {
                buf[offset..offset + bytes.len()].copy_from_slice(bytes);
            }
        }
    }

    /// Whether a read under `cr3` reaches the frame `bp` patched.
    ///
    /// Both sides are translated rather than remembered: a frame recorded at
    /// install would go stale the moment the guest remapped the page, and the
    /// translations are cached per halt anyway. Scope is the fallback for an
    /// address space that cannot resolve the site at all, such as a
    /// non-resident page or a dump carrying no page tables.
    fn site_is_in_view(debugger: &Target, bp: &BreakpointInfo, cr3: u64) -> bool {
        let owner = Self::site_dtb(debugger, bp);
        let frame = |dtb| {
            debugger
                .address_space(dtb)
                .virt_to_phys(bp.address)
                .ok()
                .flatten()
                .map(|translation| translation.address & !(PAGE_SIZE as u64 - 1))
        };
        match (frame(owner), frame(cr3)) {
            (Some(patched), Some(viewed)) => patched == viewed,
            _ => bp.scope.matches_dtb(cr3, debugger.arch()),
        }
    }

    /// The address space `bp` was planted in.
    pub fn site_dtb(debugger: &Target, bp: &BreakpointInfo) -> Dtb {
        match &bp.scope {
            BreakpointScope::Process { dtb, .. } => *dtb,
            BreakpointScope::Kernel => debugger.kernel_dtb(),
        }
    }

    /// Each of our breakpoints in guest memory: the guest-physical address
    /// of its site and the bytes it displaced, which a copy of guest RAM
    /// holds there instead. A site that does not translate in the address
    /// space it was planted in is left out: its page is not in RAM to copy.
    pub fn displaced_frames(&self, debugger: &Target) -> Vec<(PhysAddr, Vec<u8>)> {
        self.planted_sites()
            .filter_map(|bp| {
                let bytes = bp.backend.original_bytes();
                if bytes.is_empty() {
                    return None;
                }
                let translation = debugger
                    .address_space(Self::site_dtb(debugger, bp))
                    .virt_to_phys(bp.address)
                    .ok()
                    .flatten()?;
                Some((translation.address, bytes.to_vec()))
            })
            .collect()
    }

    /// The breakpoints whose planted instruction a write of `len` bytes at
    /// `start` in the address space `dtb` lands on: wherever a read there
    /// would have them masked ([`Self::mask_breakpoint_bytes`]).
    pub fn sites_under_write(
        &self,
        debugger: &Target,
        dtb: Dtb,
        start: VirtAddr,
        len: usize,
    ) -> Vec<u32> {
        let end = start.0.saturating_add(len as u64);
        let site_len = debugger.arch().breakpoint_instruction().len() as u64;
        self.planted_sites()
            .filter(|bp| {
                bp.address.0 < end
                    && start.0 < bp.address.0.saturating_add(site_len)
                    && Self::site_is_in_view(debugger, bp, dtb)
            })
            .map(|bp| bp.id)
            .collect()
    }

    /// [`Self::sites_under_write`] for a write of `len` bytes at the
    /// guest-physical `start`: the breakpoints planted in the frames it
    /// covers.
    pub fn sites_under_physical_write(
        &self,
        debugger: &Target,
        start: PhysAddr,
        len: usize,
    ) -> Vec<u32> {
        let end = start.saturating_add(len as u64);
        let site_len = debugger.arch().breakpoint_instruction().len() as u64;
        self.planted_sites()
            .filter(|bp| {
                debugger
                    .address_space(Self::site_dtb(debugger, bp))
                    .virt_to_phys(bp.address)
                    .ok()
                    .flatten()
                    .is_some_and(|translation| {
                        translation.address < end
                            && start < translation.address.saturating_add(site_len)
                    })
            })
            .map(|bp| bp.id)
            .collect()
    }

    /// The breakpoints with an instruction planted in guest memory.
    fn planted_sites(&self) -> impl Iterator<Item = &BreakpointInfo> {
        self.breakpoints
            .values()
            .filter(|bp| bp.resolved && bp.enabled && bp.hardware.is_none())
    }
}

/// Write `bytes` over the user-mode code at `address` in `dtb`'s address
/// space: a host-patched site's breakpoint instruction, or the instruction it
/// displaced. The target writes it where it will. With VBS enabled, Windows
/// refuses to write some user-mode code, such as ntdll's and kernelbase's,
/// and on an x86 guest, whose processors see a write from outside it at once,
/// the site's frame is then written through the host mapping of the guest's
/// RAM, where there is one. That reaches the frame as the target's own write
/// would have: a site in a shared image page is seen by every process mapping
/// it either way (see the KD backend's `write_virtual_direct`).
pub fn write_user_code(debugger: &Target, dtb: Dtb, address: VirtAddr, bytes: &[u8]) -> Result<()> {
    let memory = debugger.address_space(dtb);
    let refused = match memory.write_bytes(address, bytes) {
        Ok(()) => return Ok(()),
        Err(error) => error,
    };
    let frame = match memory.virt_to_phys(address) {
        Ok(Some(translation)) if translation.residency == Residency::Mapped => translation.address,
        _ => return Err(refused),
    };
    write_frame_through_host(debugger, frame, bytes)
        .unwrap_or_else(|| Err(refused_patch_error(debugger, refused)))
}

/// Write a host-patched site's `bytes` at guest-physical `address` through
/// the host mapping of the guest's RAM, on an x86 guest that has one: `None`
/// otherwise. An ARM64 processor would go on running what its instruction
/// cache holds, which the guest invalidates only for writes it makes itself.
fn write_frame_through_host(
    debugger: &Target,
    address: PhysAddr,
    bytes: &[u8],
) -> Option<Result<()>> {
    if debugger.arch().family() != Family::X86 {
        return None;
    }
    debugger.phys.write_through_host(address, bytes)
}

/// `error`, from the target refusing to write a user-mode breakpoint site
/// that is mapped, saying why and what works instead. Windows says nothing
/// more than its status, or that it would not write the address.
fn refused_patch_error(debugger: &Target, error: Error) -> Error {
    let instead = if debugger.arch().family() == Family::X86 {
        "read memory from the host (--memory-source host) for ntoseye to write the site itself, \
         or use a hardware execution breakpoint, ba e1"
    } else {
        "use a hardware execution breakpoint, ba e1"
    };
    match error {
        Error::KdStatus { .. } | Error::BadVirtualAddress(_) => Error::Breakpoint(format!(
            "Windows refused to write the breakpoint ({error}): with VBS enabled, it refuses to \
             write some user-mode code, such as ntdll's and kernelbase's; {instead}"
        )),
        error => error,
    }
}

/// Guest-physical memory as a host-patched site is restored in it: through
/// the target, or, where the target refuses, the way [`write_user_code`]
/// writes a site. The site journal repairs what a dead session left with it.
pub struct SiteFrames<'a> {
    debugger: &'a Target,
}

impl<'a> SiteFrames<'a> {
    pub fn new(debugger: &'a Target) -> Self {
        Self { debugger }
    }
}

impl MemoryOps<PhysAddr> for SiteFrames<'_> {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        self.debugger.phys.read_bytes(addr, buf)
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        self.debugger
            .phys
            .write_bytes(addr, buf)
            .or_else(|refused| {
                write_frame_through_host(self.debugger, addr, buf).unwrap_or(Err(refused))
            })
    }
}

impl SiteMemory for SiteFrames<'_> {
    fn pte_address(&self, address: PhysAddr) -> Option<u64> {
        frame_pte(self.debugger, address)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::base::error::Error;
    use crate::base::types::VirtAddr;
    use crate::nt::breakpoints::test_backend::SlotRecorder;
    use crate::nt::breakpoints::{
        BreakpointConfig, BreakpointManager, BreakpointScope, SiteJournal,
    };
    use crate::session::session_over_memory;

    /// A backend whose target does not take out what a dead session planted
    /// (a GDB stub) has each kernel site journaled from before it is planted
    /// until it is lifted, so the next attach can restore it; one whose
    /// target does (KD) leaves the journal alone.
    #[test]
    fn kernel_sites_a_backend_does_not_reclaim_are_journaled_until_lifted() {
        let address = VirtAddr(0xfffff80000001000);
        let dir = std::env::temp_dir().join(format!("ntoseye-plant-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        for (mut client, journaled) in [
            (SlotRecorder::unreclaimed(), true),
            (SlotRecorder::accepting(), false),
        ] {
            let mut session = session_over_memory(address.0, &[0x48, 0x89, 0x4c, 0x24, 8, 0, 0, 0]);
            session.target.site_journal = Some(SiteJournal::open(&dir, "target", 0xfffff800));
            let mut manager = BreakpointManager::new();

            let id = manager
                .add_configured(
                    &mut client,
                    &session.target,
                    address,
                    None,
                    BreakpointConfig::default(),
                )
                .unwrap();
            assert_eq!(client.installed, vec![address.0]);
            assert_eq!(dir.join("target").exists(), journaled);

            manager.remove(&mut client, &session.target, id).unwrap();
            assert!(
                !dir.join("target").exists(),
                "a lifted site stays journaled"
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// A GDB stub plants and lifts a site through whichever vCPU it has
    /// selected, so a user-space site needs the user-mode capability even
    /// when its scope is the kernel's: a lift through a vCPU that does not
    /// map the page would leave the `int3` in shared code.
    #[test]
    fn a_user_space_site_needs_user_mode_breakpoints_whatever_its_scope() {
        let session = session_over_memory(0x1000, &[0x90; 0x40]);
        let kernel_scope = || BreakpointConfig {
            scope: Some(BreakpointScope::Kernel),
            ..BreakpointConfig::default()
        };
        let mut manager = BreakpointManager::new();
        let mut client = SlotRecorder::kernel_only();
        let user = manager.add_configured(
            &mut client,
            &session.target,
            VirtAddr(0x7ffd_4952_3ab7),
            None,
            kernel_scope(),
        );
        assert!(user.is_err() && client.installed.is_empty());
        let kernel = VirtAddr(0xfffff80000001000);
        manager
            .add_configured(&mut client, &session.target, kernel, None, kernel_scope())
            .expect("a kernel site needs only kernel breakpoints");
        assert_eq!(client.installed, vec![kernel.0]);
    }

    /// A run to a user-space address (`p` over a call, `gu` back into user
    /// code) on such a backend takes a debug register for the run instead
    /// of failing, and gives it back when the run's site is removed.
    #[test]
    fn a_run_to_user_space_takes_a_debug_register_where_no_int3_can_go() {
        let session = session_over_memory(0x1000, &[0x90; 0x40]);
        let mut manager = BreakpointManager::new();
        let mut client = SlotRecorder::kernel_only_with_debug_registers();
        let user = VirtAddr(0x7ffd_4952_3ab7);
        let id = manager
            .add_temporary_code(&mut client, &session.target, user, None, None, 0x1000)
            .expect("a debug register can stop there");
        assert!(client.installed.is_empty(), "no int3 in user space");
        assert!(client.hardware.contains(&Some(user.0)));
        manager.remove(&mut client, &session.target, id).unwrap();
        assert!(client.hardware.iter().all(Option::is_none));

        // Without debug registers it is still refused.
        let mut client = SlotRecorder::kernel_only();
        assert!(matches!(
            manager.add_temporary_code(&mut client, &session.target, user, None, None, 0x1000),
            Err(Error::Breakpoint(_))
        ));
        assert!(client.installed.is_empty());
    }

    #[test]
    fn an_unreadable_kernel_site_installs_and_reports_the_owed_write() {
        let session = session_over_memory(0x1000, &[0u8; 0x40]);
        let address = VirtAddr(0xfffff80000001000);
        let mut manager = BreakpointManager::new();
        let mut client = SlotRecorder::accepting();

        let id = manager
            .add_configured(
                &mut client,
                &session.target,
                address,
                None,
                BreakpointConfig::default(),
            )
            .expect("a non-resident kernel site is the target's decision");

        assert_eq!(client.installed, vec![address.0]);
        let breakpoint = &manager.breakpoints[&id];
        assert!(
            breakpoint.awaiting_page_in(),
            "an unread site must report that the write is owed"
        );
        // Nothing was displaced while the page remained unreadable, so there
        // is no byte to mask into a view yet.
        let mut buffer = [0xccu8; 4];
        manager.mask_breakpoint_bytes(
            &session.target,
            address,
            &mut buffer,
            session.target.current_dtb(),
        );
        assert_eq!(buffer, [0xcc; 4], "masked bytes it never read");
    }

    #[test]
    fn secure_code_is_never_patched_from_an_nt_scope() {
        let session = session_over_memory(0x1000, &[0x90; 0x40]);
        let address = VirtAddr(0xfffff80000001000);
        session.target.symbols.inject_source_lines_for_test(
            2,
            0x2000,
            address,
            0x1000,
            "secure.c",
            &[],
        );
        session.target.symbols.set_secure_roots(0x2000, []);
        assert!(!session.target.in_secure_address_space());
        let mut manager = BreakpointManager::new();
        let mut client = SlotRecorder::accepting();
        assert!(
            manager
                .add_configured(
                    &mut client,
                    &session.target,
                    address,
                    None,
                    BreakpointConfig::default(),
                )
                .is_err()
        );
        assert!(
            client.installed.is_empty(),
            "must refuse before issuing a code patch"
        );
        assert!(
            manager.list().is_empty(),
            "a refused patch must not leave a breakpoint behind"
        );
    }

    #[test]
    fn a_non_resident_user_site_is_refused_and_names_the_page() {
        let session = session_over_memory(0x1000, &[0u8; 0x40]);
        let dtb = session.target.current_dtb();
        let mapped = VirtAddr(0x00007ff000001000);
        session
            .target
            .symbols
            .inject_source_lines_for_test(1, dtb, mapped, 0x1000, "user.c", &[]);
        let scope = BreakpointScope::Process {
            dtb,
            pid: 4,
            name: "mspaint.exe".to_string(),
        };
        let config = |scope: &BreakpointScope| BreakpointConfig {
            scope: Some(scope.clone()),
            ..BreakpointConfig::default()
        };

        let mut manager = BreakpointManager::new();
        let mut client = SlotRecorder::accepting();
        let error = manager
            .add_configured(&mut client, &session.target, mapped, None, config(&scope))
            .expect_err("a page this debugger cannot write is not a site it can arm");

        let message = error.to_string();
        assert!(
            message.contains("not paged in") && message.contains("ba e1"),
            "the refusal must name the missing page and the mechanism that works: {message}"
        );
        assert!(
            manager.list().is_empty(),
            "a refused site must not be left registered"
        );
        assert!(
            client.installed.is_empty(),
            "a host-patched site must not enter the target's breakpoint table"
        );
    }
}
