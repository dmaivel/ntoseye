//! Hardware breakpoints: how a processor family's debug registers arm a slot
//! and report the slot that trapped, behind [`DebugRegisters`]. Registers are
//! read and written by name in whatever layout holds them: KD's
//! `KSPECIAL_REGISTERS` to arm a slot, the register file at a stop to find
//! the one that trapped.

use std::ops::Range;

use ntoseye_macros::record;

use crate::arch::RegisterMap;
use crate::base::error::{Error, Result};

/// What memory access a hardware (debug-register) breakpoint traps on. The x86
/// debug registers have no read-only condition, so a "read" watch is really
/// read/write ([`Self::ReadWrite`]). Named in snake case.
#[record]
#[derive(Copy, PartialEq, Eq)]
pub enum HwBreakpointAccess {
    /// Instruction execution at the address (length 1).
    Execute,
    /// Data write to the address.
    Write,
    /// Data read or write at the address.
    ReadWrite,
}

impl HwBreakpointAccess {
    pub fn label(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::Write => "write",
            Self::ReadWrite => "read/write",
        }
    }

    /// The WinDbg-style access letter (`e`/`w`/`r`).
    pub fn letter(self) -> char {
        match self {
            Self::Execute => 'e',
            Self::Write => 'w',
            Self::ReadWrite => 'r',
        }
    }
}

/// What a slot traps on: `access` to the `len` bytes at `address`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareWatch {
    pub address: u64,
    pub access: HwBreakpointAccess,
    pub len: u8,
}

/// A processor family's hardware breakpoint registers.
pub trait DebugRegisters: Sync {
    /// The slots, numbered from 0.
    fn slots(&self) -> usize;

    /// The slots that can trap on `access`.
    fn slots_for(&self, access: HwBreakpointAccess) -> Range<usize>;

    /// Why `watch` cannot be armed, if it cannot.
    fn validate(&self, watch: HardwareWatch) -> Result<()>;

    /// The registers slot `slot` is armed through. Their values are the
    /// slot's state, which a failed update restores.
    fn slot_registers(&self, slot: usize) -> Result<Vec<String>>;

    /// Arm slot `slot` for `watch`, or disarm it with `None`, in `registers`
    /// laid out as `map`.
    fn arm(
        &self,
        map: &RegisterMap,
        registers: &mut [u8],
        slot: usize,
        watch: Option<HardwareWatch>,
    ) -> Result<()>;

    /// Whether `map` shows these registers, so that a stop can be traced to
    /// its slot. A GDB stub programs them itself and shows none.
    fn exposed_in(&self, map: &RegisterMap) -> bool;

    /// The slot a debug exception at `pc` trapped on, from `registers` (laid
    /// out as `map`) and what `armed` says each slot was armed for.
    fn fired_slot(
        &self,
        map: &RegisterMap,
        registers: &[u8],
        pc: u64,
        armed: &dyn Fn(usize) -> Option<HardwareWatch>,
    ) -> Option<usize>;

    /// Clear the status a debug exception left, so that the next one reads
    /// unambiguously. Whether it wrote `registers`.
    fn clear_status(&self, map: &RegisterMap, registers: &mut [u8]) -> bool;

    /// Let a resume run the instruction an execute breakpoint stopped
    /// before, where it would otherwise trap again. Whether it wrote
    /// `registers`.
    fn resume_past_execute(&self, map: &RegisterMap, registers: &mut [u8]) -> bool;
}

/// The rules every family's slots share: an execute breakpoint covers one
/// byte, a watch 1, 2, 4 or 8 bytes, and the address is aligned to its
/// length (a misaligned one never fires).
pub fn validate_width(watch: HardwareWatch) -> Result<()> {
    let HardwareWatch {
        address,
        access,
        len,
    } = watch;
    if access == HwBreakpointAccess::Execute && len != 1 {
        return Err(Error::InvalidArgument(
            "execute hardware breakpoints must be 1 byte".into(),
        ));
    }
    if !matches!(len, 1 | 2 | 4 | 8) {
        return Err(Error::InvalidArgument(format!(
            "invalid hardware breakpoint length {len} (use 1, 2, 4, or 8)"
        )));
    }
    if !address.is_multiple_of(u64::from(len)) {
        return Err(Error::InvalidArgument(format!(
            "hardware breakpoint address {address:#x} must be {len}-byte aligned"
        )));
    }
    Ok(())
}

/// An error for slot `slot` of a register set with `slots` slots.
pub fn invalid_slot(slot: usize, slots: usize) -> Error {
    Error::InvalidArgument(format!(
        "invalid hardware breakpoint slot {slot} (expected 0-{})",
        slots - 1
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(access: HwBreakpointAccess, len: u8, address: u64) -> HardwareWatch {
        HardwareWatch {
            address,
            access,
            len,
        }
    }

    #[test]
    fn execute_breakpoints_are_one_byte() {
        assert!(validate_width(watch(HwBreakpointAccess::Execute, 1, 0x1003)).is_ok());
        for len in [2, 4, 8] {
            assert!(validate_width(watch(HwBreakpointAccess::Execute, len, 0x1000)).is_err());
        }
    }

    #[test]
    fn watches_take_aligned_power_of_two_widths() {
        for access in [HwBreakpointAccess::Write, HwBreakpointAccess::ReadWrite] {
            for (len, address) in [(1, 0x1003), (2, 0x1000), (4, 0x1000), (8, 0x2000)] {
                assert!(validate_width(watch(access, len, address)).is_ok());
            }
            for len in [0, 3, 5, 16] {
                assert!(validate_width(watch(access, len, 0x1000)).is_err());
            }
            for (len, address) in [(2, 0x1001), (4, 0x1002), (8, 0x1004)] {
                assert!(validate_width(watch(access, len, address)).is_err());
            }
        }
    }
}
