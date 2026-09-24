//! Hardware breakpoint slots programmed into every processor's
//! `KSPECIAL_REGISTERS` as one transaction; the bit encoding is [`super::hwbp`].

use crate::bytes;
use crate::dbg_backend::{DebugBackend, HwBreakpointAccess};
use crate::error::{Error, Result};
use crate::types::Arch;

use super::registers::{
    ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET, ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET,
    ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET, ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET,
    KSPECIAL_REGISTERS_DR0_OFFSET, KSPECIAL_REGISTERS_DR7_OFFSET,
};
use super::{KdBackend, hwbp};

fn arm64_slot_offsets(slot: u8) -> Result<(usize, usize)> {
    if hwbp::ARM64_WATCHPOINT_SLOTS.contains(&slot) {
        Ok((
            ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET + slot as usize * 8,
            ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET + slot as usize * 4,
        ))
    } else if hwbp::ARM64_BREAKPOINT_SLOTS.contains(&slot) {
        let index = (slot - hwbp::ARM64_BREAKPOINT_SLOTS.start) as usize;
        Ok((
            ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET + index * 8,
            ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET + index * 4,
        ))
    } else {
        Err(Error::Kd(format!(
            "invalid ARM64 hardware breakpoint slot {slot} (expected 0-{})",
            hwbp::ARM64_BREAKPOINT_SLOTS.end - 1
        )))
    }
}

fn arm64_slot_offsets_for_access(slot: u8, access: HwBreakpointAccess) -> Result<(usize, usize)> {
    let slots = hwbp::arm64_slot_range(access);
    if slots.contains(&slot) {
        return arm64_slot_offsets(slot);
    }
    let kind = if matches!(access, HwBreakpointAccess::Execute) {
        "execute"
    } else {
        "watchpoint"
    };
    Err(Error::Kd(format!(
        "ARM64 {kind} slot {slot} is outside slots {}-{}",
        slots.start,
        slots.end - 1
    )))
}

#[derive(Clone, Copy)]
struct DebugRegisterSlotState {
    address: u64,
    dr7: u64,
}

#[derive(Clone, Copy)]
struct Arm64DebugRegisterSlotState {
    address: u64,
    control: u32,
}

impl KdBackend {
    fn read_dr_slot_state(&mut self, slot: u8) -> Result<DebugRegisterSlotState> {
        let special = self.read_special_registers_uncached(self.current_processor)?;
        Ok(DebugRegisterSlotState {
            address: bytes::read_u64(&special, Self::kspecial_dr_offset(slot)),
            dr7: bytes::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET),
        })
    }

    fn apply_dr_restore(&mut self, slot: u8, state: DebugRegisterSlotState) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        bytes::write_u64(&mut special, Self::kspecial_dr_offset(slot), state.address);
        bytes::write_u64(&mut special, KSPECIAL_REGISTERS_DR7_OFFSET, state.dr7);
        self.write_special_registers(special)
    }

    fn read_arm64_slot_state(&mut self, slot: u8) -> Result<Arm64DebugRegisterSlotState> {
        let special = self.read_special_registers_uncached(self.current_processor)?;
        let (address_offset, control_offset) = arm64_slot_offsets(slot)?;
        Ok(Arm64DebugRegisterSlotState {
            address: bytes::read_u64(&special, address_offset),
            control: bytes::read_u32(&special, control_offset),
        })
    }

    fn apply_arm64_restore(&mut self, slot: u8, state: Arm64DebugRegisterSlotState) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let (address_offset, control_offset) = arm64_slot_offsets(slot)?;
        bytes::write_u64(&mut special, address_offset, state.address);
        bytes::write_u32(&mut special, control_offset, state.control);
        self.write_special_registers(special)
    }

    fn rollback_slot_states<S: Copy>(
        &mut self,
        slot: u8,
        states: &[(u16, S)],
        mut restore: impl FnMut(&mut Self, u8, S) -> Result<()>,
    ) -> Result<()> {
        let mut first_error = None;
        for &(processor, state) in states.iter().rev() {
            self.current_processor = processor;
            if let Err(error) = restore(self, slot, state)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Apply one hardware-slot update to every processor as a transaction.
    /// Each processor's prior slot state is captured before its write; a
    /// failure restores every processor that may have been modified.
    fn update_slot_on_all_processors<S: Copy>(
        &mut self,
        slot: u8,
        operation: &str,
        label: &str,
        mut read: impl FnMut(&mut Self, u8) -> Result<S>,
        mut restore: impl FnMut(&mut Self, u8, S) -> Result<()>,
        mut update: impl FnMut(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let slot_count = self.hardware_breakpoint_slots();
        if slot >= slot_count {
            return Err(Error::Kd(format!(
                "invalid hardware breakpoint slot {slot} (expected 0-{})",
                slot_count.saturating_sub(1)
            )));
        }
        let saved = self.current_processor;
        let result = (|| {
            let mut applied = Vec::with_capacity(self.processor_count.max(1) as usize);
            let mut failure = None;

            for processor in 0..self.processor_count.max(1) {
                self.current_processor = processor;
                let previous = match read(self, slot) {
                    Ok(previous) => previous,
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                };
                applied.push((processor, previous));
                if let Err(error) = update(self) {
                    failure = Some(error);
                    break;
                }
            }

            let Some(error) = failure else {
                return Ok(());
            };
            match self.rollback_slot_states(slot, &applied, &mut restore) {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(Error::Kd(format!(
                    "{label} {operation} failed: {error}; rollback also failed: {rollback_error}"
                ))),
            }
        })();
        self.current_processor = saved;
        result
    }

    fn apply_arm64_set(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        let (address_offset, control_offset) = arm64_slot_offsets_for_access(slot, access)?;
        if matches!(access, HwBreakpointAccess::Execute) && (len != 1 || !addr.is_multiple_of(4)) {
            return Err(Error::InvalidArgument(
                "ARM64 execute hardware breakpoints require a 4-byte-aligned address and length 1"
                    .into(),
            ));
        }

        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        if matches!(access, HwBreakpointAccess::Execute) {
            bytes::write_u64(&mut special, address_offset, addr);
            bytes::write_u32(&mut special, control_offset, hwbp::arm64_bcr_value(addr));
        } else {
            bytes::write_u64(&mut special, address_offset, hwbp::arm64_wvr_address(addr));
            bytes::write_u32(
                &mut special,
                control_offset,
                hwbp::arm64_wcr_value(addr, access, len),
            );
        }
        self.write_special_registers(special)
    }

    fn apply_arm64_clear(&mut self, slot: u8) -> Result<()> {
        let (address_offset, control_offset) = arm64_slot_offsets(slot)?;
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        bytes::write_u64(&mut special, address_offset, 0);
        bytes::write_u32(&mut special, control_offset, 0);
        self.write_special_registers(special)
    }

    fn kspecial_dr_offset(slot: u8) -> usize {
        KSPECIAL_REGISTERS_DR0_OFFSET + slot as usize * 8
    }

    /// Program the currently selected processor's kernel debug-register state
    /// to trap on `access` at `addr` (`len` bytes) via slot `slot`.
    fn apply_dr_set(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        bytes::write_u64(&mut special, Self::kspecial_dr_offset(slot), addr);
        let dr7 = bytes::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET);
        let dr7 = hwbp::dr7_set_slot(dr7, slot, access, len);
        bytes::write_u64(&mut special, KSPECIAL_REGISTERS_DR7_OFFSET, dr7);
        self.write_special_registers(special)
    }

    /// Disable slot `slot` on the currently selected processor and zero its
    /// address register.
    fn apply_dr_clear(&mut self, slot: u8) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let dr7 = bytes::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET);
        let dr7 = hwbp::dr7_clear_slot(dr7, slot);
        bytes::write_u64(&mut special, KSPECIAL_REGISTERS_DR7_OFFSET, dr7);
        bytes::write_u64(&mut special, Self::kspecial_dr_offset(slot), 0);
        self.write_special_registers(special)
    }

    pub(super) fn set_hardware_slot(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        if !self.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        match self.arch {
            Arch::Amd64 => {
                // DR state is per-processor, so program every CPU: watched code
                // can run anywhere. The shared transaction prevents an
                // untracked partial set.
                self.update_slot_on_all_processors(
                    slot,
                    "install",
                    "hardware breakpoint",
                    |backend, slot| backend.read_dr_slot_state(slot),
                    |backend, slot, state| backend.apply_dr_restore(slot, state),
                    |backend| backend.apply_dr_set(slot, addr, access, len),
                )
            }
            Arch::Arm64 => {
                arm64_slot_offsets_for_access(slot, access)?;
                self.update_slot_on_all_processors(
                    slot,
                    "install",
                    "ARM64 hardware breakpoint",
                    |backend, slot| backend.read_arm64_slot_state(slot),
                    |backend, slot, state| backend.apply_arm64_restore(slot, state),
                    |backend| backend.apply_arm64_set(slot, addr, access, len),
                )
            }
        }
    }

    pub(super) fn clear_hardware_slot(&mut self, slot: u8) -> Result<()> {
        if !self.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        // A failed disable/remove must leave the manager's still-enabled entry
        // truthful, so clearing receives the same rollback guarantee as set.
        match self.arch {
            Arch::Amd64 => self.update_slot_on_all_processors(
                slot,
                "clear",
                "hardware breakpoint",
                |backend, slot| backend.read_dr_slot_state(slot),
                |backend, slot, state| backend.apply_dr_restore(slot, state),
                |backend| backend.apply_dr_clear(slot),
            ),
            Arch::Arm64 => {
                arm64_slot_offsets(slot)?;
                self.update_slot_on_all_processors(
                    slot,
                    "clear",
                    "ARM64 hardware breakpoint",
                    |backend, slot| backend.read_arm64_slot_state(slot),
                    |backend, slot, state| backend.apply_arm64_restore(slot, state),
                    |backend| backend.apply_arm64_clear(slot),
                )
            }
        }
    }
}
