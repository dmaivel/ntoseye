//! How a code breakpoint reaches the target: the target-owned and
//! host-patched backends, the checks a site must pass before it is
//! written, and masking the patched bytes back out of display reads.

use pelite::{PeView, image::IMAGE_SCN_MEM_EXECUTE};

use super::journal::site_window;
use super::{Breakpoint, BreakpointManager, BreakpointScope};
use crate::backend::MemoryOps;
use crate::bugchecks::looks_like_kernel_pointer;
use crate::dbg_backend::{DebugBackend, DebugCapability};
use crate::error::{Error, Result};
use crate::guest::ModuleInfo;
use crate::memory::{AddressSpace, PAGE_SIZE};
use crate::pe::read_pe_header_page;
use crate::phys::PhysMem;
use crate::target::Target;
use crate::types::{Arch, Dtb, VirtAddr};

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

/// The software breakpoint instruction we patch into guest code: x86 `int3`
/// (one byte) or AArch64 `brk #0xF000` (four bytes, little-endian), the same
/// opcode the kernel debugger uses so the guest reports it as a KD break.
/// The breakpoint instruction a software site holds on `arch`.
pub const fn breakpoint_opcode(arch: Arch) -> &'static [u8] {
    match arch {
        Arch::Amd64 => &[0xcc],
        // 0xD43E0000 little-endian.
        Arch::Arm64 => &[0x00, 0x00, 0x3E, 0xD4],
    }
}

/// Record a host-patched site in the target's journal before its breakpoint
/// instruction is written: `original` is the instruction it displaces, and
/// the bytes after it come from memory. Recording first means a session that
/// dies at any point leaves nothing patched that the journal does not know.
fn journal_site(
    debugger: &Target,
    memory: &AddressSpace<'_, PhysMem>,
    address: VirtAddr,
    original: &[u8],
) {
    let Some(journal) = debugger.site_journal.as_ref() else {
        return;
    };
    let Ok(Some(translation)) = memory.virt_to_phys(address) else {
        return;
    };
    let mut bytes = [0u8; 8];
    let len = site_window(translation.address, &bytes).len();
    if len < original.len() || memory.read_bytes(address, &mut bytes[..len]).is_err() {
        return;
    }
    bytes[..original.len()].copy_from_slice(original);
    journal.record(translation.address, &bytes[..len]);
}

/// Drop a host-patched site from the journal once its original instruction
/// is back in guest memory.
pub fn forget_site(debugger: &Target, memory: &AddressSpace<'_, PhysMem>, address: VirtAddr) {
    if let Some(journal) = debugger.site_journal.as_ref()
        && let Ok(Some(translation)) = memory.virt_to_phys(address)
    {
        journal.forget(translation.address);
    }
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

impl Breakpoint {
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
            || address.is_some_and(|address| Self::is_kernel_space(arch, address))
    }

    pub(super) fn validate_scope_capability(
        client: &dyn DebugBackend,
        arch: Arch,
        address: Option<VirtAddr>,
        scope: &BreakpointScope,
    ) -> Result<()> {
        let capability = if Self::install_is_target_owned(arch, address, scope) {
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
        } else {
            Err(Error::NotSupported)
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
            let mut original = BreakpointPatch::new(breakpoint_opcode(debugger.arch()).len());
            // A page that is not resident has no bytes to displace yet.
            // The target's own breakpoint table records the site and writes
            // the opcode when the page arrives (`nt!KdpSetOwedBreakpoints`),
            // so refusing here would reject a breakpoint the target accepts.
            let original = match memory.read_bytes(address, original.as_mut_slice()) {
                Ok(()) => Some(original),
                Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)) => None,
                Err(error) => return Err(error),
            };
            client.set_breakpoint(address.0)?;
            return Ok(BreakpointBackend::Kernel { original });
        }
        let dtb = match scope {
            BreakpointScope::Process { dtb, .. } => *dtb,
            BreakpointScope::Kernel => debugger.kernel_dtb(),
        };
        let memory = debugger.address_space(dtb);
        let opcode = breakpoint_opcode(debugger.arch());
        let mut original = BreakpointPatch::new(opcode.len());
        // This debugger owns the byte at a user-space site, and it cannot
        // write one into a page that is not there. Nothing reports the page
        // arriving either, so say so now instead of accepting a site that
        // would never arm.
        match memory.read_bytes(address, original.as_mut_slice()) {
            Ok(()) => {}
            Err(Error::BadVirtualAddress(_) | Error::AddressNotInDump(_)) => {
                return Err(Self::non_resident_site_error(debugger, dtb, address, scope));
            }
            Err(error) => return Err(error),
        }
        journal_site(debugger, &memory, address, original.as_slice());
        memory.write_bytes(address, opcode)?;
        // The kernel does not know about a breakpoint patched through
        // host memory, so update the backend's stop bookkeeping.
        client.note_breakpoint_installed(address.0);
        Ok(BreakpointBackend::GuestMemoryPatch { original })
    }

    pub(super) fn install_existing_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            // The target owns the byte whatever the scope filters hits on.
            (_, BreakpointBackend::Kernel { .. }) => client.set_breakpoint(bp.address.0),
            (
                BreakpointScope::Process { dtb, .. },
                BreakpointBackend::GuestMemoryPatch { original },
            ) => {
                let memory = debugger.address_space(*dtb);
                journal_site(debugger, &memory, bp.address, original.as_slice());
                memory.write_bytes(bp.address, breakpoint_opcode(debugger.arch()))?;
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
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (_, BreakpointBackend::Kernel { .. }) => client.remove_breakpoint(bp.address.0),
            (
                BreakpointScope::Process { dtb, .. },
                BreakpointBackend::GuestMemoryPatch { original },
            ) => {
                let memory = debugger.address_space(*dtb);
                memory.write_bytes(bp.address, original.as_slice())?;
                forget_site(debugger, &memory, bp.address);
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
    pub(super) fn forget_backend_site(client: &mut dyn DebugBackend, bp: &Breakpoint) {
        if matches!(bp.backend, BreakpointBackend::GuestMemoryPatch { .. }) {
            client.note_breakpoint_uninstalled(bp.address.0);
        }
    }

    /// Whether `address` is a kernel-space virtual address on this architecture.
    ///
    /// AMD64 kernel space is the canonical upper half; AArch64 selects TTBR1 by
    /// bit 55, the same test the executable-permission check above relies on.
    /// Windows places its kernel in the upper half on both, so the AMD64 bound
    /// also holds there, but the bit is what the hardware actually uses.
    fn is_kernel_space(arch: Arch, address: VirtAddr) -> bool {
        match arch {
            Arch::Amd64 => looks_like_kernel_pointer(address.0),
            Arch::Arm64 => address.0 & (1 << 55) != 0,
        }
    }

    pub(super) fn validate_breakpoint_target(
        debugger: &Target,
        address: VirtAddr,
        scope: &BreakpointScope,
    ) -> Result<()> {
        Self::require_patchable_address(debugger, address)?;
        let module = Self::find_kernel_module_containing_address(debugger, address);
        let dtb = match scope {
            BreakpointScope::Kernel => debugger.kernel_dtb(),
            BreakpointScope::Process { dtb, .. } => *dtb,
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
            Ok(None) if Self::is_kernel_space(debugger.arch(), address) => None,
            // A user-space site is this debugger's own `int3` in that page,
            // and there is no page to put it in.
            Ok(None) => return Err(Self::non_resident_site_error(debugger, dtb, address, scope)),
            Err(error) => return Err(error),
        };

        // AArch64 table-level execute restrictions depend on TCR_EL1
        // hierarchical-permission controls, which passive memory inspection
        // does not capture. Do not reject a TTBR1 address solely from descriptor
        // bits; known kernel modules are still checked against PE executable
        // sections below. TTBR0 user pages can be classified by effective UXN.
        let nx = match (debugger.arch(), address.0 & (1 << 55) != 0, &translation) {
            (Arch::Arm64, true, _) => false,
            (Arch::Arm64, false, Some(translation)) => translation.uxn,
            (_, _, Some(translation)) => translation.nx,
            // No translation to judge: the executable-section check below is
            // the only evidence available, and it does not need the page.
            (_, _, None) => false,
        };

        if nx {
            let context = module
                .as_ref()
                .map(|module| module.short_name.as_str())
                .unwrap_or("unknown");
            return Err(Error::Breakpoint(format!(
                "refusing breakpoint at {:#x}: target page is non-executable ({})",
                address.0, context
            )));
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
                return Err(Error::Breakpoint(format!(
                    "refusing breakpoint at {:#x}: address falls in non-executable section of {}",
                    address.0, module.short_name
                )));
            }
        }

        Ok(())
    }

    fn require_patchable_address(debugger: &Target, address: VirtAddr) -> Result<()> {
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
        for bp in self.breakpoints.values() {
            if !bp.resolved || !bp.enabled || bp.hardware.is_some() {
                continue;
            }
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
    fn site_is_in_view(debugger: &Target, bp: &Breakpoint, cr3: u64) -> bool {
        let owner = match &bp.scope {
            BreakpointScope::Process { dtb, .. } => *dtb,
            BreakpointScope::Kernel => debugger.kernel_dtb(),
        };
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
}

#[cfg(test)]
mod tests {
    use crate::breakpoints::test_backend::SlotRecorder;
    use crate::breakpoints::{BreakpointConfig, BreakpointManager, BreakpointScope};
    use crate::session::session_over_memory;
    use crate::types::{Arch, VirtAddr};

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

    #[test]
    fn kernel_space_is_classified_per_architecture() {
        for (arch, kernel, user) in [
            (
                Arch::Amd64,
                VirtAddr(0xfffff80000001000),
                VirtAddr(0x00007ff000001000),
            ),
            (
                Arch::Arm64,
                VirtAddr(0xffff800000001000),
                VirtAddr(0x00007ff000001000),
            ),
        ] {
            assert!(
                BreakpointManager::is_kernel_space(arch, kernel),
                "{arch:?} rejected its own kernel address {:#x}",
                kernel.0
            );
            assert!(
                !BreakpointManager::is_kernel_space(arch, user),
                "{arch:?} accepted a user address {:#x} as kernel space",
                user.0
            );
        }
        // An AArch64 kernel address is below the AMD64 canonical bound, so the
        // bit-55 rule is doing real work rather than agreeing by accident.
        assert!(!BreakpointManager::is_kernel_space(
            Arch::Amd64,
            VirtAddr(0x0080000000001000)
        ));
        assert!(BreakpointManager::is_kernel_space(
            Arch::Arm64,
            VirtAddr(0x0080000000001000)
        ));
    }
}
