//! x86-64 and ARM64 debug-register bit encoding for hardware breakpoints.
//!
//! DR0-DR3 hold up to four linear breakpoint addresses; DR7 enables each slot
//! and selects its trigger condition (R/W) and width (LEN); DR6 reports which
//! slots fired (status bits B0-B3). These helpers are pure so the wire-level
//! per-processor read-modify-write in [`crate::kd`] stays trivial and the bit
//! math is unit-testable.

use std::ops::Range;

use crate::dbg_backend::HwBreakpointAccess;

/// Number of architectural ARM64 hardware breakpoint and watchpoint slots.
/// These values are part of the Windows ARM64 ABI (`ARM64_NT_CONTEXT`).
pub const ARM64_MAX_BREAKPOINTS: u8 = 8;
pub const ARM64_MAX_WATCHPOINTS: u8 = 2;
pub const ARM64_WATCHPOINT_SLOTS: Range<u8> = 0..ARM64_MAX_WATCHPOINTS;
pub const ARM64_BREAKPOINT_SLOTS: Range<u8> =
    ARM64_MAX_WATCHPOINTS..(ARM64_MAX_WATCHPOINTS + ARM64_MAX_BREAKPOINTS);

pub fn arm64_slot_range(access: HwBreakpointAccess) -> Range<u8> {
    match access {
        HwBreakpointAccess::Execute => ARM64_BREAKPOINT_SLOTS,
        HwBreakpointAccess::Write | HwBreakpointAccess::ReadWrite => ARM64_WATCHPOINT_SLOTS,
    }
}

const ARM64_DBG_CTRL_ENABLE: u32 = 1 << 0;
const ARM64_DBG_CTRL_BOTH_EXCEPTION_LEVELS: u32 = 0b11 << 1;
const ARM64_DBG_CTRL_BAS_SHIFT: u32 = 5;
const ARM64_DBG_CTRL_HMC: u32 = 1 << 13;
const ARM64_DBG_CTRL_BOTH_SECURITY_STATES: u32 = 0b11 << 14;

/// Return the byte-address-select mask for an ARM64 watchpoint.
///
/// ARM64 watchpoint value registers are eight-byte granular; `BAS` selects
/// the bytes within that granule. Callers validate the length/alignment before
/// programming a watchpoint.
pub fn arm64_bas(addr: u64, len: u8) -> u32 {
    let width = len as u32;
    let start = (addr & 7) as u32;
    (((1u32 << width) - 1) << start) & 0xff
}

/// ARM64 WVR stores the containing eight-byte granule. `BAS` carries the
/// requested byte range within that granule.
pub const fn arm64_wvr_address(addr: u64) -> u64 {
    addr & !7
}

/// Encode one ARM64 DBGWCR value for a global EL0+EL1 watchpoint.
///
/// `Write` selects stores; `ReadWrite` selects loads and stores. HMC and SSC
/// are set so both exception levels and both security states are covered,
/// matching a WinDbg kernel-wide `ba` watchpoint.
pub fn arm64_wcr_value(addr: u64, access: HwBreakpointAccess, len: u8) -> u32 {
    let lsc = if access == HwBreakpointAccess::ReadWrite {
        0b11
    } else {
        0b10
    };
    ARM64_DBG_CTRL_ENABLE
        | ARM64_DBG_CTRL_BOTH_EXCEPTION_LEVELS
        | (lsc << 3)
        | (arm64_bas(addr, len) << ARM64_DBG_CTRL_BAS_SHIFT)
        | ARM64_DBG_CTRL_HMC
        | ARM64_DBG_CTRL_BOTH_SECURITY_STATES
}

/// Encode one ARM64 DBGBCR value for an execute breakpoint. ARM64
/// instructions are four bytes, so BAS selects the instruction's four bytes.
pub fn arm64_bcr_value(addr: u64) -> u32 {
    debug_assert!(addr.is_multiple_of(4));
    ARM64_DBG_CTRL_ENABLE
        | ARM64_DBG_CTRL_BOTH_EXCEPTION_LEVELS
        | (0x0fu32 << ARM64_DBG_CTRL_BAS_SHIFT)
        | ARM64_DBG_CTRL_HMC
        | ARM64_DBG_CTRL_BOTH_SECURITY_STATES
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
/// ordering: 1→00, 2→01, 8→10, 4→11. Falls back to 0 (1 byte) for widths the
/// caller should have rejected via [`crate::dbg_backend::validate_hw_breakpoint`].
fn len_field(len: u8) -> u64 {
    match len {
        2 => 0b01,
        8 => 0b10,
        4 => 0b11,
        _ => 0b00,
    }
}

/// Global-enable slot `slot` in `dr7` and write its R/W+LEN condition, clearing
/// any prior state for that slot. Uses the global-enable bit (Gn) so the watch
/// survives task switches — the right choice for kernel-wide breakpoints.
/// `(access, len)` must have passed [`crate::dbg_backend::validate_hw_breakpoint`].
pub fn dr7_set_slot(dr7: u64, slot: u8, access: HwBreakpointAccess, len: u8) -> u64 {
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

/// Disable slot `slot` in `dr7` and zero its R/W+LEN fields, leaving the other
/// slots untouched.
pub fn dr7_clear_slot(dr7: u64, slot: u8) -> u64 {
    let slot = slot as u64;
    let enable_mask = 0b11u64 << (slot * 2);
    let control_mask = 0b1111u64 << (16 + slot * 4);
    dr7 & !enable_mask & !control_mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbg_backend::HwBreakpointAccess;

    fn ln(dr7: u64, slot: u8) -> u64 {
        (dr7 >> (2 * slot as u64)) & 1
    }
    fn gn(dr7: u64, slot: u8) -> u64 {
        (dr7 >> (2 * slot as u64 + 1)) & 1
    }
    fn rw(dr7: u64, slot: u8) -> u64 {
        (dr7 >> (16 + 4 * slot as u64)) & 0b11
    }
    fn len(dr7: u64, slot: u8) -> u64 {
        (dr7 >> (18 + 4 * slot as u64)) & 0b11
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
        for slot in 0u8..4 {
            let dr7 = dr7_set_slot(0, slot, HwBreakpointAccess::Write, 2);
            let expected = (1u64 << (2 * slot as u64 + 1))
                | (0b0101u64 << (16 + 4 * slot as u64))
                | (1u64 << 10);
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

    #[test]
    fn arm64_bas_selects_aligned_bytes_inside_wvr_granule() {
        assert_eq!(arm64_bas(0x1000, 1), 0x01);
        assert_eq!(arm64_bas(0x1003, 1), 0x08);
        assert_eq!(arm64_bas(0x1002, 2), 0x0c);
        assert_eq!(arm64_bas(0x1000, 4), 0x0f);
        assert_eq!(arm64_bas(0x1000, 8), 0xff);
        assert_eq!(arm64_wvr_address(0x1007), 0x1000);
    }

    #[test]
    fn arm64_wcr_encodes_write_and_readwrite_conditions() {
        let write = arm64_wcr_value(0x1003, HwBreakpointAccess::Write, 1);
        assert_eq!(write & 1, 1, "E must enable the watchpoint");
        assert_eq!((write >> 1) & 0b11, 0b11, "PAC must cover EL0 and EL1");
        assert_eq!((write >> 3) & 0b11, 0b10, "write uses store-only LSC");
        assert_eq!((write >> 5) & 0xff, 0x08, "BAS selects byte 3");
        assert_eq!((write >> 13) & 1, 1, "HMC must cover both security states");
        assert_eq!((write >> 14) & 0b11, 0b11, "SSC must cover both states");

        let readwrite = arm64_wcr_value(0x2000, HwBreakpointAccess::ReadWrite, 8);
        assert_eq!(
            (readwrite >> 3) & 0b11,
            0b11,
            "read/write uses load+store LSC"
        );
        assert_eq!((readwrite >> 5) & 0xff, 0xff);
    }

    #[test]
    fn arm64_bcr_encodes_four_byte_execute_instruction() {
        let bcr = arm64_bcr_value(0x4000);
        assert_eq!(bcr & 1, 1, "E must enable the breakpoint");
        assert_eq!((bcr >> 1) & 0b11, 0b11, "PMC must cover EL0 and EL1");
        assert_eq!((bcr >> 5) & 0xff, 0x0f, "BAS selects one ARM64 instruction");
    }
}
