//! Hardware (debug-register) breakpoints: slot allocation, installation,
//! lookup by the slot a stop reports, and their data-watch semantics.

use super::install::BreakpointBackend;
use super::{Breakpoint, BreakpointConfig, BreakpointManager, BreakpointScope, HardwareBreakpoint};
use crate::dbg_backend::{
    DebugBackend, HwBreakpointAccess, WatchpointAccess, validate_hw_breakpoint,
};
use crate::error::{Error, Result};
use crate::target::Target;
use crate::types::VirtAddr;

impl Breakpoint {
    /// Data-watch semantics for this stop point. Execute-only debug-register
    /// breakpoints remain code breakpoints and deliberately return `None`.
    pub fn watchpoint(&self) -> Option<(WatchpointAccess, u8)> {
        let hardware = self.hardware?;
        let access = match hardware.access {
            HwBreakpointAccess::Write => WatchpointAccess::Write,
            HwBreakpointAccess::ReadWrite => WatchpointAccess::ReadWrite,
            HwBreakpointAccess::Execute => return None,
        };
        Some((access, hardware.len))
    }

    /// The watched access name (`"write"`/`"read_write"`), or `None` for a
    /// code breakpoint. Presentation surfaces share this instead of
    /// destructuring [`Self::watchpoint`] themselves.
    pub fn watch_access_name(&self) -> Option<&'static str> {
        self.watchpoint().map(|(access, _)| access.name())
    }

    /// The watched byte width, or `None` for a code breakpoint.
    pub fn watch_length(&self) -> Option<u8> {
        self.watchpoint().map(|(_, length)| length)
    }
}

impl BreakpointManager {
    /// Set a hardware (debug-register) breakpoint. String conditions use the
    /// core decimal expression contract.
    pub fn add_hardware(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        symbol: Option<String>,
        condition: Option<String>,
    ) -> Result<u32> {
        self.add_hardware_configured(
            client,
            debugger,
            address,
            access,
            len,
            symbol,
            BreakpointConfig {
                condition,
                ..BreakpointConfig::default()
            },
        )
    }

    pub fn add_hardware_configured(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        symbol: Option<String>,
        config: BreakpointConfig,
    ) -> Result<u32> {
        if !client.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        if debugger.in_secure_address_space() || debugger.is_secure_address(address) {
            if client.name() != "gdb" || access != HwBreakpointAccess::Execute || len != 1 {
                return Err(Error::Breakpoint(
                    "VTL1 debugging requires a GDB hardware execution breakpoint (ba e1); data watches and code patching are not supported".into(),
                ));
            }
            if !debugger.is_secure_address(address) {
                return Err(Error::Breakpoint(
                    "VTL1 execution breakpoints must name a loaded secure-kernel module; trustlet user-code breakpoints are not supported".into(),
                ));
            }
            if config.thread.is_some()
                || matches!(config.scope, Some(BreakpointScope::Process { .. }))
            {
                return Err(Error::Breakpoint(
                    "NT process/thread filters do not describe VTL1 execution; use a processor filter or a register condition".into(),
                ));
            }
        }
        let condition_expr = Self::configured_condition(&config)?;
        validate_hw_breakpoint(access, len, address.0)?;
        self.ensure_site_available(address, true, None)?;
        let slot = self.free_hardware_slot(client, access)?;
        let automatic_scope = config.scope.is_none();
        let fallback_scope = config
            .scope
            .unwrap_or_else(|| Self::scope_for_current_context(debugger));
        let scope = if automatic_scope {
            Self::scope_for_address(debugger, address, &fallback_scope)
        } else {
            fallback_scope
        };
        client.set_hardware_breakpoint(slot, address.0, access, len)?;

        let id = self.next_id;
        self.next_id += 1;
        let pass_count = config.pass_count;
        self.breakpoints.insert(
            id,
            Breakpoint {
                id,
                address,
                enabled: true,
                symbol,
                spec: None,
                resolved: true,
                scope,
                automatic_scope,
                condition: config.condition,
                condition_expr,
                pass_count,
                hit_count: 0,
                remaining_pass_count: pass_count.saturating_sub(1),
                one_shot: config.one_shot,
                action: config.action,
                temporary: false,
                hardware: Some(HardwareBreakpoint { access, len, slot }),
                thread: config.thread,
                processor: config.processor,
                backend: BreakpointBackend::Hardware,
            },
        );
        Ok(id)
    }

    /// The lowest physical slot not already claimed by a hardware breakpoint.
    /// ARM64 uses one global ID space with separate WVR/WCR data and BVR/BCR
    /// execute ranges supplied by the backend. Disabled hardware breakpoints
    /// keep their slot reserved, matching WinDbg's fixed architectural slots.
    fn free_hardware_slot(
        &self,
        client: &dyn DebugBackend,
        access: HwBreakpointAccess,
    ) -> Result<u8> {
        let mut slots = client.hardware_slot_range(access);
        let kind = if matches!(access, HwBreakpointAccess::Execute) {
            "execute"
        } else {
            "watchpoint"
        };
        slots
            .find(|slot| {
                !self
                    .breakpoints
                    .values()
                    .any(|bp| bp.hardware.is_some_and(|hw| hw.slot == *slot))
            })
            .ok_or_else(|| {
                Error::Breakpoint(format!("all {kind} hardware breakpoint slots are in use"))
            })
    }

    /// Whether a single-step stop needs a DR6 check for hardware breakpoints.
    pub fn has_enabled_hardware_breakpoints(&self) -> bool {
        self.breakpoints
            .values()
            .any(|bp| bp.enabled && bp.hardware.is_some())
    }

    /// Execute slots no breakpoint holds (disabled ones keep theirs), for
    /// sites the debugger plants and lifts within one operation.
    pub fn free_execute_slots(&self, client: &dyn DebugBackend) -> Vec<u8> {
        client
            .hardware_slot_range(HwBreakpointAccess::Execute)
            .filter(|slot| {
                !self
                    .breakpoints
                    .values()
                    .any(|bp| bp.hardware.is_some_and(|hw| hw.slot == *slot))
            })
            .collect()
    }

    /// Map a DR6 status bit to the enabled breakpoint in DR slot `slot`.
    pub fn hardware_breakpoint_for_slot(&self, slot: u8) -> Option<Breakpoint> {
        self.breakpoints
            .values()
            .find(|bp| bp.enabled && bp.hardware.is_some_and(|hw| hw.slot == slot))
            .cloned()
    }

    /// Best-effort release of every DR slot held by a hardware breakpoint
    /// (enabled or not), so a target reload leaves no orphaned watches.
    pub fn clear_hardware_slots(&self, client: &mut dyn DebugBackend) {
        for bp in self.breakpoints.values() {
            if let Some(hw) = bp.hardware {
                let _ = client.clear_hardware_breakpoint(hw.slot);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::breakpoints::test_backend::SlotRecorder;
    use crate::breakpoints::{BreakpointManager, HardwareBreakpoint};
    use crate::dbg_backend::HwBreakpointAccess;
    use crate::types::VirtAddr;

    #[test]
    fn has_enabled_hardware_breakpoints_tracks_enabled_hw_bps() {
        let mut manager = BreakpointManager::new();

        manager.insert_for_test(0, VirtAddr(0x1000), true, None);
        assert!(!manager.has_enabled_hardware_breakpoints());

        manager.insert_for_test(
            1,
            VirtAddr(0x2000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );
        assert!(manager.has_enabled_hardware_breakpoints());

        manager.breakpoints.get_mut(&1).unwrap().enabled = false;
        assert!(!manager.has_enabled_hardware_breakpoints());
    }

    #[test]
    fn hardware_breakpoint_for_slot_resolves_enabled_slot_only() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            7,
            VirtAddr(0x3000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::ReadWrite,
                len: 8,
                slot: 1,
            }),
        );

        let found = manager
            .hardware_breakpoint_for_slot(1)
            .expect("slot 1 hw bp");
        assert_eq!(found.id, 7);
        assert_eq!(found.hardware.expect("hw params").slot, 1);

        assert!(manager.hardware_breakpoint_for_slot(0).is_none());

        manager.insert_for_test(
            8,
            VirtAddr(0x4000),
            false,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 2,
                slot: 0,
            }),
        );
        assert!(manager.hardware_breakpoint_for_slot(0).is_none());
    }

    #[test]
    fn clear_hardware_slots_releases_every_hw_slot_and_skips_software() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            0,
            VirtAddr(0x1000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 2,
            }),
        );
        manager.insert_for_test(
            1,
            VirtAddr(0x2000),
            false,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Execute,
                len: 1,
                slot: 0,
            }),
        );
        manager.insert_for_test(2, VirtAddr(0x3000), true, None);

        let mut backend = SlotRecorder::new();
        manager.clear_hardware_slots(&mut backend);

        let mut cleared = backend.cleared.clone();
        cleared.sort_unstable();
        assert_eq!(cleared, vec![0, 2]);
    }
}
