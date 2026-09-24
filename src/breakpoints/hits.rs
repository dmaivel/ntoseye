//! Matching a stop to the breakpoint that raised it and accounting the
//! hit: the software-site hit predicates, pass counts and one-shot state.

#[cfg(test)]
use super::BreakpointScope;
use super::{BreakpointHitDisposition, BreakpointHitResult, BreakpointManager};
use crate::error::{Error, Result};
use crate::target::Target;
use crate::types::{Arch, VirtAddr};

impl BreakpointManager {
    /// Record a physical hit before pass-count and condition handling.
    pub fn record_hit(&mut self, id: u32) -> Result<BreakpointHitDisposition> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;
        bp.hit_count = bp.hit_count.saturating_add(1);
        if bp.remaining_pass_count > 0 {
            bp.remaining_pass_count -= 1;
            Ok(BreakpointHitDisposition::SkipPass)
        } else {
            debug_assert!(bp.should_evaluate_after_hit());
            Ok(BreakpointHitDisposition::Evaluate)
        }
    }

    pub fn mark_one_shot_hit(&mut self, id: u32) -> Result<()> {
        let bp = self.breakpoints.get(&id).ok_or(Error::BPNotFound(id))?;
        if bp.one_shot {
            self.one_shot_hits.insert(id);
        }
        Ok(())
    }

    pub fn one_shot_hit_ids(&self) -> Vec<u32> {
        self.one_shot_hits.iter().copied().collect()
    }

    pub fn check_breakpoint_hit(&self, rip: u64, dtb: u64, arch: Arch) -> BreakpointHitResult {
        for bp in self.breakpoints.values() {
            if !self.one_shot_hits.contains(&bp.id)
                && bp.resolved
                && bp.hardware.is_none()
                && bp.address.0 == rip
                && bp.enabled
                && bp.scope.matches_dtb(dtb, arch)
            {
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
        let cr3 = debugger.current_dtb();
        self.breakpoints
            .values()
            .filter(|bp| {
                bp.resolved
                    && bp.enabled
                    && bp.hardware.is_none()
                    && bp.address == address
                    && bp.scope.matches_dtb(cr3, debugger.arch())
            })
            .map(|bp| bp.id)
            .min()
    }

    #[cfg(test)]
    fn enabled_software_breakpoint_id(
        &self,
        scope: &BreakpointScope,
        address: VirtAddr,
    ) -> Option<u32> {
        self.breakpoints
            .values()
            .filter(|bp| {
                bp.resolved
                    && bp.enabled
                    && bp.hardware.is_none()
                    && bp.address == address
                    && &bp.scope == scope
            })
            .map(|bp| bp.id)
            .min()
    }

    /// Find a BP at `rip` regardless of its scope; "is this int3 owned by us?"
    pub fn breakpoint_id_at_address(&self, rip: u64) -> Option<u32> {
        self.breakpoints
            .values()
            .find(|bp| bp.resolved && bp.enabled && bp.hardware.is_none() && bp.address.0 == rip)
            .map(|bp| bp.id)
    }
}

#[cfg(test)]
mod tests {
    use crate::breakpoints::install::{BreakpointBackend, BreakpointPatch};
    use crate::breakpoints::test_backend::SlotRecorder;
    use crate::breakpoints::{
        Breakpoint, BreakpointHitDisposition, BreakpointHitResult, BreakpointManager,
        BreakpointScope, HardwareBreakpoint,
    };
    use crate::dbg_backend::HwBreakpointAccess;
    use crate::types::{Arch, VirtAddr};

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
                spec: None,
                resolved: true,
                scope: BreakpointScope::Kernel,
                automatic_scope: false,
                thread: None,
                processor: None,
                condition: None,
                condition_expr: None,
                pass_count: 0,
                hit_count: 0,
                remaining_pass_count: 0,
                one_shot: false,
                action: None,
                temporary: false,
                hardware: None,
                backend: BreakpointBackend::Kernel {
                    original: Some(BreakpointPatch::single(0x90)),
                },
            },
        );

        match manager.check_breakpoint_hit(0x1000, 0, Arch::Amd64) {
            BreakpointHitResult::Hit(bp) => assert_eq!(bp.id, 0),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn process_breakpoint_hit_requires_matching_dtb() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x7ff7_1234_1000),
                enabled: true,
                symbol: None,
                spec: None,
                resolved: true,
                scope: BreakpointScope::Process {
                    pid: 42,
                    dtb: 0x1234_5000,
                    name: "user.exe".to_string(),
                },
                automatic_scope: false,
                thread: None,
                processor: None,
                condition: None,
                condition_expr: None,
                pass_count: 0,
                hit_count: 0,
                remaining_pass_count: 0,
                one_shot: false,
                action: None,
                temporary: false,
                hardware: None,
                backend: BreakpointBackend::GuestMemoryPatch {
                    original: BreakpointPatch::single(0x90),
                },
            },
        );
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5000, Arch::Amd64),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5fff, Arch::Amd64),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x9999_9000, Arch::Amd64),
            BreakpointHitResult::NotBreakpoint
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_4000, Arch::Amd64),
            BreakpointHitResult::NotBreakpoint
        ));

        // TTBR0_EL1 carries the ASID in bits 48..63, outside the ARM64
        // page-table base field. A process-scoped breakpoint must keep
        // matching its own address space across an ASID change.
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x000a_0000_1234_5000, Arch::Arm64),
            BreakpointHitResult::Hit(_)
        ));
    }

    #[test]
    fn hardware_breakpoint_is_ignored_by_int3_hit_predicates() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            0,
            VirtAddr(0x2000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );

        assert!(matches!(
            manager.check_breakpoint_hit(0x2000, 0, Arch::Amd64),
            BreakpointHitResult::NotBreakpoint
        ));
        assert_eq!(manager.breakpoint_id_at_address(0x2000), None);
    }

    #[test]
    fn software_and_hardware_breakpoint_coexist_at_same_address() {
        let mut manager = BreakpointManager::new();
        let addr = 0x5000;

        manager.insert_for_test(0, VirtAddr(addr), true, None);
        manager.insert_for_test(
            1,
            VirtAddr(addr),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );

        match manager.check_breakpoint_hit(addr, 0, Arch::Amd64) {
            BreakpointHitResult::Hit(bp) => {
                assert_eq!(bp.id, 0);
                assert!(bp.hardware.is_none());
            }
            other => panic!("expected software hit, got {:?}", other),
        }
        assert_eq!(manager.breakpoint_id_at_address(addr), Some(0));
        assert_eq!(
            manager.enabled_software_breakpoint_id(&BreakpointScope::Kernel, VirtAddr(addr)),
            Some(0)
        );

        manager.breakpoints.remove(&0);
        assert_eq!(
            manager.enabled_software_breakpoint_id(&BreakpointScope::Kernel, VirtAddr(addr)),
            None
        );
    }

    #[test]
    fn pass_count_records_every_hit_and_surfaces_requested_hit() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(3, VirtAddr(0x1000), true, None);
        manager.set_pass_count(3, 3).unwrap();

        assert_eq!(
            manager.record_hit(3).unwrap(),
            BreakpointHitDisposition::SkipPass
        );
        assert_eq!(
            manager.record_hit(3).unwrap(),
            BreakpointHitDisposition::SkipPass
        );
        assert_eq!(
            manager.record_hit(3).unwrap(),
            BreakpointHitDisposition::Evaluate
        );
        let bp = manager.list()[0];
        assert_eq!(bp.hit_count, 3);
        assert_eq!(bp.remaining_pass_count, 0);
    }

    #[test]
    fn one_shot_is_hidden_after_surface_but_remains_available_for_safe_step_over() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(4, VirtAddr(0x2000), true, None);
        manager.set_one_shot(4, true).unwrap();
        manager.mark_one_shot_hit(4).unwrap();

        assert!(manager.list().is_empty());
        assert_eq!(manager.breakpoint_id_at_address(0x2000), Some(4));
        assert_eq!(manager.one_shot_hit_ids(), vec![4]);
        manager.discard(&mut SlotRecorder::new(), 4).unwrap();
        assert!(manager.one_shot_hit_ids().is_empty());
    }
}
