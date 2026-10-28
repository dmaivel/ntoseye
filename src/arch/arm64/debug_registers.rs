//! AArch64 debug registers, as Windows' `CONTEXT` and `KSPECIAL_REGISTERS`
//! carry them: two watchpoints (WVR/WCR) and eight breakpoints (BVR/BCR).
//! Slots number the watchpoints first, then the breakpoints.

use std::ops::Range;

use super::{Arm64, MAX_BREAKPOINTS, MAX_WATCHPOINTS};
use crate::arch::debug_registers::{invalid_slot, validate_width};
use crate::arch::{DebugRegisters, HardwareWatch, HwBreakpointAccess, RegisterMap};
use crate::base::error::{Error, Result};

const WATCHPOINT_SLOTS: Range<usize> = 0..MAX_WATCHPOINTS;
const BREAKPOINT_SLOTS: Range<usize> = WATCHPOINT_SLOTS.end..WATCHPOINT_SLOTS.end + MAX_BREAKPOINTS;

const CONTROL_ENABLE: u32 = 1 << 0;
const CONTROL_BOTH_EXCEPTION_LEVELS: u32 = 0b11 << 1;
const CONTROL_BAS_SHIFT: u32 = 5;

/// `ID_AA64DFR0_EL1.BRPs` (bits 15:12) and `WRPs` (bits 23:20): one less
/// than the breakpoint and watchpoint register pairs the processor has.
const FEATURES_BRPS_SHIFT: u32 = 12;
const FEATURES_WRPS_SHIFT: u32 = 20;
/// Every AArch64 processor has at least two of each.
const ARCHITECTURAL_MINIMUM_PAIRS: usize = 2;

/// The value and control registers of slot `slot`: a watchpoint's WVR and
/// WCR, a breakpoint's BVR and BCR.
fn slot_pair(slot: usize) -> Result<(String, String)> {
    if WATCHPOINT_SLOTS.contains(&slot) {
        Ok((format!("wvr{slot}"), format!("wcr{slot}")))
    } else if BREAKPOINT_SLOTS.contains(&slot) {
        let index = slot - BREAKPOINT_SLOTS.start;
        Ok((format!("bvr{index}"), format!("bcr{index}")))
    } else {
        Err(invalid_slot(slot, BREAKPOINT_SLOTS.end))
    }
}

impl DebugRegisters for Arm64 {
    fn slots(&self) -> usize {
        BREAKPOINT_SLOTS.end
    }

    fn slots_for(&self, access: HwBreakpointAccess) -> Range<usize> {
        match access {
            HwBreakpointAccess::Execute => BREAKPOINT_SLOTS,
            HwBreakpointAccess::Write | HwBreakpointAccess::ReadWrite => WATCHPOINT_SLOTS,
        }
    }

    /// The `CONTEXT` holds eight breakpoint and two watchpoint pairs, but a
    /// processor may implement fewer, and a pair past them is RES0: armed,
    /// it never fires. `ID_AA64DFR0_EL1` counts them; unread, only the
    /// architecture's minimum of two of each is certain.
    fn implemented_slots_for(
        &self,
        access: HwBreakpointAccess,
        debug_features: Option<u64>,
    ) -> Range<usize> {
        let slots = self.slots_for(access);
        let shift = match access {
            HwBreakpointAccess::Execute => FEATURES_BRPS_SHIFT,
            HwBreakpointAccess::Write | HwBreakpointAccess::ReadWrite => FEATURES_WRPS_SHIFT,
        };
        let implemented = debug_features.map_or(ARCHITECTURAL_MINIMUM_PAIRS, |features| {
            ((features >> shift) & 0xf) as usize + 1
        });
        slots.start..slots.end.min(slots.start + implemented)
    }

    /// Instructions are four bytes and four-byte aligned, so an execute
    /// breakpoint elsewhere never fires.
    fn validate(&self, watch: HardwareWatch) -> Result<()> {
        validate_width(watch)?;
        if watch.access == HwBreakpointAccess::Execute && !watch.address.is_multiple_of(4) {
            return Err(Error::InvalidArgument(
                "ARM64 execute hardware breakpoints require a 4-byte-aligned address and length 1"
                    .into(),
            ));
        }
        Ok(())
    }

    fn slot_registers(&self, slot: usize) -> Result<Vec<String>> {
        let (value, control) = slot_pair(slot)?;
        Ok(vec![value, control])
    }

    fn arm(
        &self,
        map: &RegisterMap,
        registers: &mut [u8],
        slot: usize,
        watch: Option<HardwareWatch>,
    ) -> Result<()> {
        let (value_register, control_register) = slot_pair(slot)?;
        let (value, control) = match watch {
            None => (0, 0),
            Some(watch) => {
                let slots = self.slots_for(watch.access);
                if !slots.contains(&slot) {
                    return Err(Error::InvalidArgument(format!(
                        "ARM64 {} slot {slot} is outside slots {}-{}",
                        watch.access.label(),
                        slots.start,
                        slots.end - 1
                    )));
                }
                self.validate(watch)?;
                match watch.access {
                    HwBreakpointAccess::Execute => (watch.address, bcr_value()),
                    HwBreakpointAccess::Write | HwBreakpointAccess::ReadWrite => (
                        wvr_address(watch.address),
                        wcr_value(watch.address, watch.access, watch.len),
                    ),
                }
            }
        };
        map.write_u64(value_register, registers, value)?;
        map.write_u64(control_register, registers, u64::from(control))
    }

    fn exposed_in(&self, map: &RegisterMap) -> bool {
        map.contains("bcr0")
    }

    /// A watchpoint traps with FAR at the byte touched: its WVR holds FAR's
    /// granule and its BAS FAR's byte. FAR is required evidence, so that a
    /// plain single-step is not taken for a watchpoint. A breakpoint traps
    /// with the PC at its BVR.
    fn fired_slot(
        &self,
        map: &RegisterMap,
        registers: &[u8],
        pc: u64,
        armed: &dyn Fn(usize) -> Option<HardwareWatch>,
    ) -> Option<usize> {
        let read = |name: String| map.read_u64(name, registers).unwrap_or(0);
        let far = map.read_u64("far", registers).unwrap_or(0);
        let watchpoint = WATCHPOINT_SLOTS.filter(|_| far != 0).find(|&slot| {
            let Some(watch) =
                armed(slot).filter(|watch| watch.access != HwBreakpointAccess::Execute)
            else {
                return false;
            };
            let control = read(format!("wcr{slot}"));
            let bas = (control >> CONTROL_BAS_SHIFT) & 0xff;
            let in_watch = watch
                .address
                .checked_add(u64::from(watch.len))
                .is_some_and(|end| far >= watch.address && far < end);
            control & 1 != 0
                && read(format!("wvr{slot}")) == wvr_address(far)
                && bas & (1 << (far & 7)) != 0
                && in_watch
        });
        watchpoint.or_else(|| {
            BREAKPOINT_SLOTS.clone().find(|&slot| {
                let index = slot - BREAKPOINT_SLOTS.start;
                armed(slot).is_some_and(|watch| {
                    watch.access == HwBreakpointAccess::Execute && watch.address == pc
                }) && read(format!("bcr{index}")) & 1 != 0
                    && read(format!("bvr{index}")) == pc & !3
            })
        })
    }

    /// AArch64 debug exceptions leave no status to clear.
    fn clear_status(&self, _map: &RegisterMap, _registers: &mut [u8]) -> bool {
        false
    }

    /// A breakpoint exception returns past the instruction; nothing to set.
    fn resume_past_execute(&self, _map: &RegisterMap, _registers: &mut [u8]) -> bool {
        false
    }
}

/// The byte-address-select mask for a watchpoint: a WVR is eight-byte
/// granular, and BAS selects the watched bytes within the granule.
fn bas(address: u64, len: u8) -> u32 {
    let width = u32::from(len);
    let start = (address & 7) as u32;
    (((1u32 << width) - 1) << start) & 0xff
}

/// The granule a WVR holds; BAS carries the bytes within it.
const fn wvr_address(address: u64) -> u64 {
    address & !7
}

/// A DBGWCR value for a global EL0+EL1 watchpoint. `Write` selects stores;
/// `ReadWrite` loads and stores. HMC, SSC and PAC together choose the
/// exception levels and security states that match (the Arm ARM's table of
/// breakpoint and watchpoint state matching): HMC=0, SSC=0b00 and PAC=0b11
/// is the row for EL1 and EL0, in either security state, that every
/// processor implements. The rows with HMC=1 add EL2, and those with SSC
/// other than 0b00 select a security state; they are reserved on a
/// processor without EL2 or EL3, as a guest under a hypervisor sees it, and
/// a reserved combination may never match: there, a breakpoint armed with
/// HMC=1 and SSC=0b11 never fired. Windows' own controls (0x1e0) leave both
/// clear.
fn wcr_value(address: u64, access: HwBreakpointAccess, len: u8) -> u32 {
    let lsc = if access == HwBreakpointAccess::ReadWrite {
        0b11
    } else {
        0b10
    };
    CONTROL_ENABLE
        | CONTROL_BOTH_EXCEPTION_LEVELS
        | (lsc << 3)
        | (bas(address, len) << CONTROL_BAS_SHIFT)
}

/// A DBGBCR value for an execute breakpoint: BAS selects the instruction's
/// four bytes, and the levels match as [`wcr_value`]'s do.
fn bcr_value() -> u32 {
    CONTROL_ENABLE | CONTROL_BOTH_EXCEPTION_LEVELS | (0x0fu32 << CONTROL_BAS_SHIFT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::Architecture;

    #[test]
    fn bas_selects_aligned_bytes_inside_wvr_granule() {
        assert_eq!(bas(0x1000, 1), 0x01);
        assert_eq!(bas(0x1003, 1), 0x08);
        assert_eq!(bas(0x1002, 2), 0x0c);
        assert_eq!(bas(0x1000, 4), 0x0f);
        assert_eq!(bas(0x1000, 8), 0xff);
        assert_eq!(wvr_address(0x1007), 0x1000);
    }

    #[test]
    fn wcr_encodes_write_and_readwrite_conditions() {
        let write = wcr_value(0x1003, HwBreakpointAccess::Write, 1);
        assert_eq!(write & 1, 1, "E must enable the watchpoint");
        assert_eq!((write >> 1) & 0b11, 0b11, "PAC must cover EL0 and EL1");
        assert_eq!((write >> 3) & 0b11, 0b10, "write uses store-only LSC");
        assert_eq!((write >> 5) & 0xff, 0x08, "BAS selects byte 3");
        assert_eq!(
            (write >> 13) & 0b111,
            0,
            "HMC and SSC must stay clear: other values are reserved without EL2 or EL3"
        );

        let readwrite = wcr_value(0x2000, HwBreakpointAccess::ReadWrite, 8);
        assert_eq!(
            (readwrite >> 3) & 0b11,
            0b11,
            "read/write uses load+store LSC"
        );
        assert_eq!((readwrite >> 5) & 0xff, 0xff);
    }

    #[test]
    fn bcr_encodes_four_byte_execute_instruction() {
        let bcr = bcr_value();
        assert_eq!(bcr & 1, 1, "E must enable the breakpoint");
        assert_eq!((bcr >> 1) & 0b11, 0b11, "PMC must cover EL0 and EL1");
        assert_eq!((bcr >> 5) & 0xff, 0x0f, "BAS selects one ARM64 instruction");
        assert_eq!(
            bcr, 0x1e7,
            "Windows' own controls (0x1e0), enabled for EL0 and EL1"
        );
    }

    #[test]
    fn implemented_slots_follow_the_debug_feature_register() {
        use HwBreakpointAccess::{Execute, ReadWrite, Write};
        // Six breakpoint and four watchpoint pairs; the CONTEXT has room
        // for two watchpoints.
        let features = Some(0x1030_5106);
        assert_eq!(Arm64.implemented_slots_for(Execute, features), 2..8);
        assert_eq!(Arm64.implemented_slots_for(Write, features), 0..2);
        assert_eq!(Arm64.implemented_slots_for(ReadWrite, features), 0..2);
        // Sixteen breakpoints: the CONTEXT's eight.
        assert_eq!(Arm64.implemented_slots_for(Execute, Some(0xf000)), 2..10);
        // Unread: the architecture's minimum.
        assert_eq!(Arm64.implemented_slots_for(Execute, None), 2..4);
        assert_eq!(Arm64.implemented_slots_for(Write, None), 0..2);
    }

    #[test]
    fn execute_breakpoints_must_be_instruction_aligned() {
        let execute = |address| HardwareWatch {
            address,
            access: HwBreakpointAccess::Execute,
            len: 1,
        };
        assert!(Arm64.validate(execute(0x4000)).is_ok());
        assert!(Arm64.validate(execute(0x4002)).is_err());
    }

    #[test]
    fn a_trap_is_traced_to_the_slot_armed_for_it() {
        let map = Arm64.register_map();
        let mut registers = vec![0u8; Arm64.register_buffer_size()];
        let watch = HardwareWatch {
            address: 0x1004,
            access: HwBreakpointAccess::Write,
            len: 4,
        };
        let execute = HardwareWatch {
            address: 0x4000,
            access: HwBreakpointAccess::Execute,
            len: 1,
        };
        Arm64.arm(map, &mut registers, 1, Some(watch)).unwrap();
        Arm64.arm(map, &mut registers, 3, Some(execute)).unwrap();
        let armed = |slot| match slot {
            1 => Some(watch),
            3 => Some(execute),
            _ => None,
        };
        let fired = |registers: &[u8], pc| Arm64.fired_slot(map, registers, pc, &armed);

        // No fault address: a single step, not a watchpoint.
        assert_eq!(fired(&registers, 0x2000), None);
        map.write_u64("far", &mut registers, 0x1006).unwrap();
        assert_eq!(fired(&registers, 0x2000), Some(1));
        // A byte of the granule the watch leaves out.
        map.write_u64("far", &mut registers, 0x1002).unwrap();
        assert_eq!(fired(&registers, 0x2000), None);

        map.write_u64("far", &mut registers, 0).unwrap();
        assert_eq!(fired(&registers, 0x4000), Some(3));
        Arm64.arm(map, &mut registers, 3, None).unwrap();
        assert_eq!(fired(&registers, 0x4000), None);
    }
}
