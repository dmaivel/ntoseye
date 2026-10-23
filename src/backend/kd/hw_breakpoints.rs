//! Hardware breakpoint slots programmed into every processor's
//! `KSPECIAL_REGISTERS` as one transaction; the bit encoding is
//! [`debug_registers`].

use crate::arch::Family;
use crate::backend::dbg_backend::{DebugBackend, HwBreakpointAccess, debug_registers};
use crate::base::error::{Error, Result};

use super::KdBackend;

/// The address and control registers of ARM64 slot `slot`: a watchpoint's
/// WVR and WCR, a breakpoint's BVR and BCR.
fn arm64_slot_registers(slot: u8) -> Result<(String, String)> {
    if debug_registers::ARM64_WATCHPOINT_SLOTS.contains(&slot) {
        Ok((format!("wvr{slot}"), format!("wcr{slot}")))
    } else if debug_registers::ARM64_BREAKPOINT_SLOTS.contains(&slot) {
        let index = slot - debug_registers::ARM64_BREAKPOINT_SLOTS.start;
        Ok((format!("bvr{index}"), format!("bcr{index}")))
    } else {
        Err(Error::Kd(format!(
            "invalid ARM64 hardware breakpoint slot {slot} (expected 0-{})",
            debug_registers::ARM64_BREAKPOINT_SLOTS.end - 1
        )))
    }
}

fn arm64_slot_registers_for_access(
    slot: u8,
    access: HwBreakpointAccess,
) -> Result<(String, String)> {
    let slots = debug_registers::arm64_slot_range(access);
    if slots.contains(&slot) {
        return arm64_slot_registers(slot);
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

/// The AMD64 debug register holding slot `slot`'s address.
fn dr_register(slot: u8) -> String {
    format!("dr{slot}")
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
        let map = self.arch.special_register_map();
        Ok(DebugRegisterSlotState {
            address: map.read_u64(dr_register(slot), &special)?,
            dr7: map.read_u64("dr7", &special)?,
        })
    }

    fn apply_dr_restore(&mut self, slot: u8, state: DebugRegisterSlotState) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let map = self.arch.special_register_map();
        map.write_u64(dr_register(slot), &mut special, state.address)?;
        map.write_u64("dr7", &mut special, state.dr7)?;
        self.write_special_registers(special)
    }

    fn read_arm64_slot_state(&mut self, slot: u8) -> Result<Arm64DebugRegisterSlotState> {
        let special = self.read_special_registers_uncached(self.current_processor)?;
        let (address, control) = arm64_slot_registers(slot)?;
        let map = self.arch.special_register_map();
        Ok(Arm64DebugRegisterSlotState {
            address: map.read_u64(address, &special)?,
            control: map.read_u64(control, &special)? as u32,
        })
    }

    fn apply_arm64_restore(&mut self, slot: u8, state: Arm64DebugRegisterSlotState) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let (address, control) = arm64_slot_registers(slot)?;
        let map = self.arch.special_register_map();
        map.write_u64(address, &mut special, state.address)?;
        map.write_u64(control, &mut special, u64::from(state.control))?;
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
        if usize::from(slot) >= slot_count {
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
        let (address, control) = arm64_slot_registers_for_access(slot, access)?;
        if matches!(access, HwBreakpointAccess::Execute) && (len != 1 || !addr.is_multiple_of(4)) {
            return Err(Error::InvalidArgument(
                "ARM64 execute hardware breakpoints require a 4-byte-aligned address and length 1"
                    .into(),
            ));
        }

        let (address_value, control_value) = if matches!(access, HwBreakpointAccess::Execute) {
            (addr, debug_registers::arm64_bcr_value(addr))
        } else {
            (
                debug_registers::arm64_wvr_address(addr),
                debug_registers::arm64_wcr_value(addr, access, len),
            )
        };
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let map = self.arch.special_register_map();
        map.write_u64(address, &mut special, address_value)?;
        map.write_u64(control, &mut special, u64::from(control_value))?;
        self.write_special_registers(special)
    }

    fn apply_arm64_clear(&mut self, slot: u8) -> Result<()> {
        let (address, control) = arm64_slot_registers(slot)?;
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let map = self.arch.special_register_map();
        map.write_u64(address, &mut special, 0)?;
        map.write_u64(control, &mut special, 0)?;
        self.write_special_registers(special)
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
        let map = self.arch.special_register_map();
        map.write_u64(dr_register(slot), &mut special, addr)?;
        let dr7 = map.read_u64("dr7", &special)?;
        let dr7 = debug_registers::dr7_set_slot(dr7, slot, access, len);
        map.write_u64("dr7", &mut special, dr7)?;
        self.write_special_registers(special)
    }

    /// Disable slot `slot` on the currently selected processor and zero its
    /// address register.
    fn apply_dr_clear(&mut self, slot: u8) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let map = self.arch.special_register_map();
        let dr7 = map.read_u64("dr7", &special)?;
        let dr7 = debug_registers::dr7_clear_slot(dr7, slot);
        map.write_u64("dr7", &mut special, dr7)?;
        map.write_u64(dr_register(slot), &mut special, 0)?;
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
        match self.arch.family() {
            Family::X86 => {
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
            Family::Arm => {
                arm64_slot_registers_for_access(slot, access)?;
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
        match self.arch.family() {
            Family::X86 => self.update_slot_on_all_processors(
                slot,
                "clear",
                "hardware breakpoint",
                |backend, slot| backend.read_dr_slot_state(slot),
                |backend, slot, state| backend.apply_dr_restore(slot, state),
                |backend| backend.apply_dr_clear(slot),
            ),
            Family::Arm => {
                arm64_slot_registers(slot)?;
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
