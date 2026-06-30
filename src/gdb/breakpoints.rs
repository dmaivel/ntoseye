use std::collections::HashMap;

use pelite::pe64::{Pe, PeView, image::IMAGE_SCN_MEM_EXECUTE};

use crate::backend::MemoryOps;
use crate::dbg_backend::DebugBackend;
use crate::error::{Error, Result};
use crate::guest::{ModuleInfo, ProcessInfo, read_pe_image};
use crate::memory::AddressSpace;
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: u32,
    pub address: VirtAddr,
    pub enabled: bool,
    pub symbol: Option<String>,
    pub scope: BreakpointScope,
    pub condition: Option<String>,
    pub temporary: bool,
    backend: BreakpointBackend,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointScope {
    Kernel,
    Process { pid: u64, dtb: Dtb, name: String },
}

impl BreakpointScope {
    fn matches_cr3(&self, cr3: u64) -> bool {
        // Mask out the PCID (bits 0..11) and reserved/canonical bits
        // (52..63), leaving only the page-directory base physical frame.
        const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;
        match self {
            Self::Kernel => true,
            Self::Process { dtb, .. } => (cr3 & CR3_PAGE_MASK) == (*dtb & CR3_PAGE_MASK),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Kernel => "global".to_string(),
            Self::Process { pid, name, .. } => format!("{name} ({pid})"),
        }
    }
}

/// Who owns the int3 byte for a breakpoint.
///
/// * `Kernel`: written via the target's kernel debugger API
///   (`DbgKdWriteBreakPointApi` / gdb `Z0`). The kernel tracks the original
///   byte and handles step-over.
///
/// * `GuestMemoryPatch`: we write 0xCC ourselves through `/dev/kvm` against a
///   specific process's page table. No Kdp primitive supports per-process BPs
///   (KD's BP APIs all route through `MmDbgCopyMemory`, which uses the current
///   CR3), so this is the only way to scope a user-mode BP to one process.
///   Writing at the physical-frame level bypasses copy-on-write, so the int3
///   is visible to every process mapping that frame. `check_breakpoint_hit`'s
///   CR3 filter discards wrong-process hits, but the kernel still pays for
///   the trap.
#[derive(Debug, Clone)]
enum BreakpointBackend {
    Kernel { original_byte: u8 },
    GuestMemoryPatch { original_byte: u8 },
}

impl BreakpointBackend {
    /// The instruction byte we displaced with the int3, so display paths can
    /// overlay it and never show our own breakpoint.
    fn original_byte(&self) -> u8 {
        match self {
            Self::Kernel { original_byte } | Self::GuestMemoryPatch { original_byte } => {
                *original_byte
            }
        }
    }
}

pub struct BreakpointManager {
    breakpoints: HashMap<u32, Breakpoint>,
    next_id: u32,
}

impl BreakpointManager {
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
            next_id: 0,
        }
    }

    pub fn add(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        symbol: Option<String>,
        condition: Option<String>,
    ) -> Result<u32> {
        self.add_code(client, debugger, address, symbol, condition, false)
    }

    pub fn add_temporary_code(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
    ) -> Result<u32> {
        self.add_code(client, debugger, address, None, None, true)
    }

    fn add_code(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        symbol: Option<String>,
        condition: Option<String>,
        temporary: bool,
    ) -> Result<u32> {
        let scope = Self::scope_for_current_context(debugger);
        if matches!(scope, BreakpointScope::Process { .. })
            && !client.supports_user_mode_breakpoints()
        {
            return Err(Error::NotSupported);
        }

        Self::validate_breakpoint_target(debugger, address)?;
        let backend = Self::install_breakpoint(client, debugger, address, &scope)?;
        let id = self.next_id;
        self.next_id += 1;

        let bp = Breakpoint {
            id,
            address,
            enabled: true,
            symbol,
            scope,
            condition,
            temporary,
            backend,
        };

        self.breakpoints.insert(id, bp);
        Ok(id)
    }

    pub fn remove(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;

        if bp.enabled {
            let _ = Self::uninstall_breakpoint(client, debugger, &bp);
        }

        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }

        Ok(())
    }

    pub fn discard(&mut self, id: u32) -> Result<Breakpoint> {
        let bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;
        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }
        Ok(bp)
    }

    pub fn enable(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if bp.enabled {
            return Ok(());
        }

        Self::install_existing_breakpoint(client, debugger, bp)?;
        bp.enabled = true;
        Ok(())
    }

    pub fn disable(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }

        Self::uninstall_breakpoint(client, debugger, bp)?;
        bp.enabled = false;
        Ok(())
    }

    pub fn disable_guest_memory_patch_in_address_space(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
        dtb: Dtb,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }

        match bp.backend {
            BreakpointBackend::GuestMemoryPatch { original_byte } => {
                let memory = AddressSpace::new(&debugger.phys, dtb);
                memory.write_bytes(bp.address, &[original_byte])?;
                client.note_breakpoint_uninstalled(bp.address.0);
                bp.enabled = false;
                Ok(())
            }
            BreakpointBackend::Kernel { .. } => Err(Error::Rsp(
                "cannot address-space-disable a kernel breakpoint".into(),
            )),
        }
    }

    pub fn list(&self) -> Vec<&Breakpoint> {
        let mut bps: Vec<_> = self.breakpoints.values().collect();
        bps.sort_by_key(|bp| bp.id);
        bps
    }

    pub fn has_enabled_breakpoints(&self) -> bool {
        self.breakpoints.values().any(|bp| bp.enabled)
    }

    // NOTE refreshing ensures local breakpoint state matches target state in case they were cleared,
    // this should fix single stepping breaking every breakpoint proceeding the step..
    pub fn refresh_enabled(&self, client: &mut dyn DebugBackend, debugger: &Target) -> Result<()> {
        let mut enabled: Vec<_> = self.breakpoints.values().filter(|bp| bp.enabled).collect();
        enabled.sort_by_key(|bp| bp.id);

        for bp in enabled {
            let _ = Self::uninstall_breakpoint(client, debugger, bp);
            Self::install_existing_breakpoint(client, debugger, bp)?;
        }

        Ok(())
    }

    pub fn check_breakpoint_hit(&self, rip: u64, cr3: u64) -> BreakpointHitResult {
        for bp in self.breakpoints.values() {
            if bp.address.0 == rip && bp.enabled && bp.scope.matches_cr3(cr3) {
                return BreakpointHitResult::Hit(bp.clone());
            }
        }

        BreakpointHitResult::NotBreakpoint
    }

    pub fn enabled_breakpoint_id_for_current_context(
        &self,
        debugger: &Target,
        address: VirtAddr,
    ) -> Option<u32> {
        let scope = Self::scope_for_current_context(debugger);
        self.breakpoints
            .values()
            .find(|bp| bp.enabled && bp.address == address && bp.scope == scope)
            .map(|bp| bp.id)
    }

    /// Overlay our breakpoints' original bytes onto a buffer read for display,
    /// so no view ever shows the int3 we injected. `start` is the buffer's
    /// guest VA; `cr3` scopes process breakpoints to the address space the
    /// bytes were read from (kernel breakpoints are global).
    pub fn mask_breakpoint_bytes(&self, start: VirtAddr, buf: &mut [u8], cr3: u64) {
        let end = start.0.wrapping_add(buf.len() as u64);
        for bp in self.breakpoints.values() {
            if !bp.enabled || !bp.scope.matches_cr3(cr3) {
                continue;
            }
            if bp.address.0 < start.0 || bp.address.0 >= end {
                continue;
            }
            buf[(bp.address.0 - start.0) as usize] = bp.backend.original_byte();
        }
    }

    /// Find a BP at `rip` regardless of its scope; "is this int3 owned by us?"
    pub fn breakpoint_id_at_address(&self, rip: u64) -> Option<u32> {
        self.breakpoints
            .values()
            .find(|bp| bp.enabled && bp.address.0 == rip)
            .map(|bp| bp.id)
    }

    fn scope_for_current_context(debugger: &Target) -> BreakpointScope {
        match &debugger.current_process_info {
            Some(ProcessInfo { pid, name, dtb, .. }) => BreakpointScope::Process {
                pid: *pid,
                dtb: *dtb,
                name: name.clone(),
            },
            None => BreakpointScope::Kernel,
        }
    }

    fn install_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        scope: &BreakpointScope,
    ) -> Result<BreakpointBackend> {
        match scope {
            BreakpointScope::Kernel => {
                // Capture the displaced byte before the kernel writes the int3,
                // so display paths can mask it back out (the kernel owns the
                // original byte but never hands it to us)
                let memory = AddressSpace::new(&debugger.phys, debugger.current_dtb());
                let mut original = [0u8; 1];
                memory.read_bytes(address, &mut original)?;
                client.set_breakpoint(address.0)?;
                Ok(BreakpointBackend::Kernel {
                    original_byte: original[0],
                })
            }
            BreakpointScope::Process { dtb, .. } => {
                let memory = AddressSpace::new(&debugger.phys, *dtb);
                let mut original = [0u8; 1];
                memory.read_bytes(address, &mut original)?;
                memory.write_bytes(address, &[0xcc])?;
                // The kernel doesn't know about this BP (we patched it
                // directly via /dev/kvm), so the backend needs to be told
                // separately for managed-BP bookkeeping at stop time.
                client.note_breakpoint_installed(address.0);
                Ok(BreakpointBackend::GuestMemoryPatch {
                    original_byte: original[0],
                })
            }
        }
    }

    fn install_existing_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (BreakpointScope::Kernel, BreakpointBackend::Kernel { .. }) => {
                client.set_breakpoint(bp.address.0)
            }
            (BreakpointScope::Process { dtb, .. }, BreakpointBackend::GuestMemoryPatch { .. }) => {
                let memory = AddressSpace::new(&debugger.phys, *dtb);
                memory.write_bytes(bp.address, &[0xcc])?;
                client.note_breakpoint_installed(bp.address.0);
                Ok(())
            }
            _ => Err(Error::Rsp("breakpoint backend/scope mismatch".into())),
        }
    }

    fn uninstall_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (BreakpointScope::Kernel, BreakpointBackend::Kernel { .. }) => {
                client.remove_breakpoint(bp.address.0)
            }
            (
                BreakpointScope::Process { dtb, .. },
                BreakpointBackend::GuestMemoryPatch { original_byte },
            ) => {
                let memory = AddressSpace::new(&debugger.phys, *dtb);
                memory.write_bytes(bp.address, &[*original_byte])?;
                client.note_breakpoint_uninstalled(bp.address.0);
                Ok(())
            }
            _ => Err(Error::Rsp("breakpoint backend/scope mismatch".into())),
        }
    }

    fn validate_breakpoint_target(debugger: &Target, address: VirtAddr) -> Result<()> {
        let module = Self::find_kernel_module_containing_address(debugger, address);
        let memory = AddressSpace::new(&debugger.phys, debugger.current_dtb());
        let translation = memory
            .virt_to_phys(address)?
            .ok_or(Error::BadVirtualAddress(address))?;

        if translation.nx {
            let context = module
                .as_ref()
                .map(|module| module.short_name.as_str())
                .unwrap_or("unknown");
            return Err(Error::Rsp(format!(
                "refusing breakpoint at {:#x}: target page is non-executable ({})",
                address.0, context
            )));
        }

        if let Some(module) = module {
            let image = read_pe_image(module.base_address, &memory)?;
            let view = PeView::from_bytes(image.as_slice())?;
            let rva = address.0.saturating_sub(module.base_address.0) as u32;
            let in_executable_section = view.section_headers().iter().any(|section| {
                let size = section.VirtualSize.max(section.SizeOfRawData);
                size != 0
                    && section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    && rva >= section.VirtualAddress
                    && rva < section.VirtualAddress.saturating_add(size)
            });

            if !in_executable_section {
                return Err(Error::Rsp(format!(
                    "refusing breakpoint at {:#x}: address falls in non-executable section of {}",
                    address.0, module.short_name
                )));
            }
        }

        Ok(())
    }

    fn find_kernel_module_containing_address(
        debugger: &Target,
        address: VirtAddr,
    ) -> Option<ModuleInfo> {
        debugger
            .guest
            .kernel_modules()
            .ok()?
            .into_iter()
            .find(|module| module.contains_address(address))
    }
}

#[derive(Debug)]
pub enum BreakpointHitResult {
    /// Breakpoint hit
    Hit(Breakpoint),
    /// RIP doesn't match any breakpoint
    NotBreakpoint,
}

#[cfg(test)]
mod tests {
    use super::{
        Breakpoint, BreakpointBackend, BreakpointHitResult, BreakpointManager, BreakpointScope,
    };
    use crate::types::VirtAddr;

    #[test]
    fn detects_breakpoint_hit_at_exact_rip() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x1000),
                enabled: true,
                symbol: None,
                scope: BreakpointScope::Kernel,
                condition: None,
                temporary: false,
                backend: BreakpointBackend::Kernel {
                    original_byte: 0x90,
                },
            },
        );

        match manager.check_breakpoint_hit(0x1000, 0) {
            BreakpointHitResult::Hit(bp) => assert_eq!(bp.id, 0),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn process_breakpoint_hit_requires_matching_cr3() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x7ff7_1234_1000),
                enabled: true,
                symbol: None,
                scope: BreakpointScope::Process {
                    pid: 42,
                    dtb: 0x1234_5000,
                    name: "user.exe".to_string(),
                },
                condition: None,
                temporary: false,
                backend: BreakpointBackend::GuestMemoryPatch {
                    original_byte: 0x90,
                },
            },
        );

        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5000),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5fff),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x9999_9000),
            BreakpointHitResult::NotBreakpoint
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_4000),
            BreakpointHitResult::NotBreakpoint
        ));
    }
}
