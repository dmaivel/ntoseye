//! The x86 debug registers AMD64 has: DR0-DR3 hold four addresses, DR7
//! enables each slot and selects its trigger condition (R/W) and width (LEN),
//! and DR6 reports which slots trapped (B0-B3).

use std::ops::Range;

use super::Amd64;
use crate::arch::debug_registers::{invalid_slot, validate_width};
use crate::arch::{DebugRegisters, HardwareWatch, HwBreakpointAccess, RegisterMap};
use crate::base::error::Result;

const SLOTS: usize = 4;
/// DR6's B0-B3.
const STATUS_BITS: u64 = 0b1111;
/// Every cause DR6 can name: B0-B3, BD (a debug-register access), BS (a
/// single step) and BT (a task switch).
const CAUSE_BITS: u64 = STATUS_BITS | (0b111 << 13);
/// RFLAGS.RF: suppresses an execute breakpoint for one instruction.
const RESUME_FLAG: u64 = 1 << 16;
/// RFLAGS.TF: single-steps the next instruction.
const TRAP_FLAG: u64 = 1 << 8;

/// The register holding slot `slot`'s address.
fn address_register(slot: usize) -> String {
    format!("dr{slot}")
}

fn check_slot(slot: usize) -> Result<()> {
    if slot < SLOTS {
        Ok(())
    } else {
        Err(invalid_slot(slot, SLOTS))
    }
}

impl DebugRegisters for Amd64 {
    fn slots(&self) -> usize {
        SLOTS
    }

    /// Every slot traps on any access.
    fn slots_for(&self, _access: HwBreakpointAccess) -> Range<usize> {
        0..SLOTS
    }

    fn validate(&self, watch: HardwareWatch) -> Result<()> {
        validate_width(watch)
    }

    fn slot_registers(&self, slot: usize) -> Result<Vec<String>> {
        check_slot(slot)?;
        Ok(vec![address_register(slot), "dr7".into()])
    }

    fn arm(
        &self,
        map: &RegisterMap,
        registers: &mut [u8],
        slot: usize,
        watch: Option<HardwareWatch>,
    ) -> Result<()> {
        check_slot(slot)?;
        let dr7 = map.read_u64("dr7", registers)?;
        let (address, dr7) = match watch {
            Some(watch) => {
                self.validate(watch)?;
                (
                    watch.address,
                    dr7_set_slot(dr7, slot, watch.access, watch.len),
                )
            }
            None => (0, dr7_clear_slot(dr7, slot)),
        };
        map.write_u64(address_register(slot), registers, address)?;
        map.write_u64("dr7", registers, dr7)
    }

    fn exposed_in(&self, map: &RegisterMap) -> bool {
        map.contains("dr6")
    }

    /// A debug exception whose DR6 names no cause at all, and that no trap
    /// flag explains, is an execute fault that lost its status: Windows 11
    /// with VBS on, under KVM, reports some execute hits so. An
    /// execute breakpoint faults at its own address, so the slot armed to
    /// execute at `pc` is the one; otherwise the hit would be taken for a
    /// stray step, resumed without RF, and fault again.
    fn fired_slot(
        &self,
        map: &RegisterMap,
        registers: &[u8],
        pc: u64,
        armed: &dyn Fn(usize) -> Option<HardwareWatch>,
    ) -> Option<usize> {
        let dr6 = map.read_u64("dr6", registers).ok()?;
        if dr6 & CAUSE_BITS != 0 {
            return (0..SLOTS)
                .filter(|slot| dr6 & (1 << slot) != 0)
                .find(|&slot| armed(slot).is_some());
        }
        let stepping = map
            .read_u64("eflags", registers)
            .is_ok_and(|eflags| eflags & TRAP_FLAG != 0);
        if stepping {
            return None;
        }
        (0..SLOTS).find(|&slot| {
            armed(slot).is_some_and(|watch| {
                watch.access == HwBreakpointAccess::Execute && watch.address == pc
            })
        })
    }

    /// The processor never clears B0-B3 itself; the rest of DR6 stays.
    fn clear_status(&self, map: &RegisterMap, registers: &mut [u8]) -> bool {
        let Ok(dr6) = map.read_u64("dr6", registers) else {
            return false;
        };
        dr6 & STATUS_BITS != 0 && map.write_u64("dr6", registers, dr6 & !STATUS_BITS).is_ok()
    }

    /// An execute breakpoint is a fault, not a trap: it fires before the
    /// instruction runs, so a resume re-enters the instruction and faults
    /// again unless RF suppresses it for that one instruction.
    fn resume_past_execute(&self, map: &RegisterMap, registers: &mut [u8]) -> bool {
        let Ok(eflags) = map.read_u64("eflags", registers) else {
            return false;
        };
        eflags & RESUME_FLAG == 0
            && map
                .write_u64("eflags", registers, eflags | RESUME_FLAG)
                .is_ok()
    }
}

/// DR7 R/W field for an access type (2 bits): 00 execute, 01 write, 11 r/w.
fn rw_field(access: HwBreakpointAccess) -> u64 {
    match access {
        HwBreakpointAccess::Execute => 0b00,
        HwBreakpointAccess::Write => 0b01,
        HwBreakpointAccess::ReadWrite => 0b11,
    }
}

/// DR7 LEN field for a watch width in bytes (2 bits). x86 uses a quirky
/// ordering: 1→00, 2→01, 8→10, 4→11. Falls back to 0 (1 byte) for widths
/// [`validate_width`] rejects.
fn len_field(len: u8) -> u64 {
    match len {
        2 => 0b01,
        8 => 0b10,
        4 => 0b11,
        _ => 0b00,
    }
}

/// Global-enable slot `slot` in `dr7` and write its R/W+LEN condition,
/// clearing any prior state for that slot. Uses the global-enable bit (Gn) so
/// the watch survives task switches — the right choice for kernel-wide
/// breakpoints.
fn dr7_set_slot(dr7: u64, slot: usize, access: HwBreakpointAccess, len: u8) -> u64 {
    let slot = slot as u64;
    let rw = rw_field(access);
    let len_bits = len_field(len);
    let enable_mask = 0b11u64 << (slot * 2); // Ln | Gn
    let control_mask = 0b1111u64 << (16 + slot * 4); // R/Wn | LENn
    let mut out = dr7 & !enable_mask & !control_mask;
    out |= 1u64 << (slot * 2 + 1); // Gn: global enable
    out |= (rw | (len_bits << 2)) << (16 + slot * 4);
    out |= 1u64 << 10; // reserved, read-as-one on x86
    out
}

/// Disable slot `slot` in `dr7` and zero its R/W+LEN fields, leaving the
/// other slots untouched.
fn dr7_clear_slot(dr7: u64, slot: usize) -> u64 {
    let slot = slot as u64;
    let enable_mask = 0b11u64 << (slot * 2);
    let control_mask = 0b1111u64 << (16 + slot * 4);
    dr7 & !enable_mask & !control_mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ln(dr7: u64, slot: u64) -> u64 {
        (dr7 >> (2 * slot)) & 1
    }
    fn gn(dr7: u64, slot: u64) -> u64 {
        (dr7 >> (2 * slot + 1)) & 1
    }
    fn rw(dr7: u64, slot: u64) -> u64 {
        (dr7 >> (16 + 4 * slot)) & 0b11
    }
    fn len(dr7: u64, slot: u64) -> u64 {
        (dr7 >> (18 + 4 * slot)) & 0b11
    }
    fn reserved10(dr7: u64) -> u64 {
        (dr7 >> 10) & 1
    }

    #[test]
    fn set_slot0_write_4_encodes_global_enable_rw_len_and_reserved() {
        let dr7 = dr7_set_slot(0, 0, HwBreakpointAccess::Write, 4);
        assert_eq!(gn(dr7, 0), 1, "Gn (bit 1) must be set");
        assert_eq!(ln(dr7, 0), 0, "Ln (bit 0) must stay clear");
        assert_eq!(rw(dr7, 0), 0b01, "R/W field (bits 16-17) for Write");
        assert_eq!(len(dr7, 0), 0b11, "LEN field (bits 18-19) for 4 bytes");
        assert_eq!(reserved10(dr7), 1, "reserved bit 10 reads-as-one");
    }

    #[test]
    fn set_slot2_execute_1_encodes_zero_rw_zero_len() {
        let dr7 = dr7_set_slot(0, 2, HwBreakpointAccess::Execute, 1);
        assert_eq!(rw(dr7, 2), 0b00, "R/W field (bits 24-25) for Execute");
        assert_eq!(len(dr7, 2), 0b00, "LEN field (bits 26-27) for 1 byte");
        assert_eq!(gn(dr7, 2), 1, "Gn for slot 2 (bit 5) must be set");
    }

    #[test]
    fn set_slot1_readwrite_8_encodes_the_len_quirk() {
        let dr7 = dr7_set_slot(0, 1, HwBreakpointAccess::ReadWrite, 8);
        assert_eq!(rw(dr7, 1), 0b11, "R/W field (bits 20-21) for ReadWrite");
        assert_eq!(len(dr7, 1), 0b10, "LEN field (bits 22-23) for 8 bytes");
    }

    #[test]
    fn each_slot_uses_its_own_gn_bit_and_control_nibble() {
        for slot in 0..SLOTS {
            let dr7 = dr7_set_slot(0, slot, HwBreakpointAccess::Write, 2);
            let slot = slot as u64;
            let expected = (1u64 << (2 * slot + 1)) | (0b0101u64 << (16 + 4 * slot)) | (1u64 << 10);
            assert_eq!(dr7, expected, "slot {slot} must own exactly its bits");
        }
    }

    #[test]
    fn setting_a_slot_leaves_another_set_slot_intact() {
        let dr7 = dr7_set_slot(0, 0, HwBreakpointAccess::Write, 4);
        let dr7 = dr7_set_slot(dr7, 3, HwBreakpointAccess::ReadWrite, 8);
        assert_eq!(gn(dr7, 0), 1, "slot 0 Gn preserved");
        assert_eq!(ln(dr7, 0), 0, "slot 0 Ln preserved");
        assert_eq!(rw(dr7, 0), 0b01, "slot 0 R/W preserved");
        assert_eq!(len(dr7, 0), 0b11, "slot 0 LEN preserved");
        assert_eq!(gn(dr7, 3), 1, "slot 3 Gn set");
        assert_eq!(rw(dr7, 3), 0b11, "slot 3 R/W ReadWrite");
        assert_eq!(len(dr7, 3), 0b10, "slot 3 LEN 8 bytes");
    }

    #[test]
    fn clear_slot_removes_its_bits_and_spares_others() {
        let dr7 = dr7_set_slot(0, 1, HwBreakpointAccess::Write, 2);
        let dr7 = dr7_set_slot(dr7, 0, HwBreakpointAccess::ReadWrite, 8);
        let cleared = dr7_clear_slot(dr7, 0);
        assert_eq!(gn(cleared, 0), 0, "slot 0 Gn cleared");
        assert_eq!(ln(cleared, 0), 0, "slot 0 Ln cleared");
        assert_eq!(rw(cleared, 0), 0b00, "slot 0 R/W cleared");
        assert_eq!(len(cleared, 0), 0b00, "slot 0 LEN cleared");
        assert_eq!(gn(cleared, 1), 1, "slot 1 Gn preserved");
        assert_eq!(rw(cleared, 1), 0b01, "slot 1 R/W preserved");
        assert_eq!(len(cleared, 1), 0b01, "slot 1 LEN preserved");
    }
}
