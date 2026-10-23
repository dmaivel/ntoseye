//! Hardware breakpoint slots programmed into every processor's
//! `KSPECIAL_REGISTERS` as one transaction. The family's
//! [`DebugRegisters`] names the registers a slot uses and what to write.

use crate::arch::{DebugRegisters, HardwareWatch, HwBreakpointAccess};
use crate::backend::dbg_backend::DebugBackend;
use crate::base::error::{Error, Result};

use super::KdBackend;

/// A slot's registers on one processor, by name, before an update.
type SlotState = Vec<(String, u64)>;

impl KdBackend {
    fn debug_registers(&self) -> &'static dyn DebugRegisters {
        self.arch.debug_registers()
    }

    /// Slot `slot`'s registers on the selected processor.
    fn read_slot_state(&mut self, slot: usize) -> Result<SlotState> {
        let special = self.read_special_registers_uncached(self.current_processor)?;
        let map = self.arch.special_register_map();
        self.debug_registers()
            .slot_registers(slot)?
            .into_iter()
            .map(|name| {
                let value = map.read_u64(&name, &special)?;
                Ok((name, value))
            })
            .collect()
    }

    fn restore_slot_state(&mut self, state: &SlotState) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        let map = self.arch.special_register_map();
        for (name, value) in state {
            map.write_u64(name, &mut special, *value)?;
        }
        self.write_special_registers(special)
    }

    /// Arm slot `slot` for `watch` on the selected processor, or disarm it.
    fn arm_slot(&mut self, slot: usize, watch: Option<HardwareWatch>) -> Result<()> {
        let mut special = self.read_special_registers_uncached(self.current_processor)?;
        self.debug_registers()
            .arm(self.arch.special_register_map(), &mut special, slot, watch)?;
        self.write_special_registers(special)
    }

    fn rollback_slot_states(&mut self, states: &[(u16, SlotState)]) -> Result<()> {
        let mut first_error = None;
        for (processor, state) in states.iter().rev() {
            self.current_processor = *processor;
            if let Err(error) = self.restore_slot_state(state)
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

    /// Arm or disarm slot `slot` on every processor as a transaction: debug
    /// state is per processor, and watched code can run on any of them.
    /// Each processor's prior slot state is captured before its write; a
    /// failure restores every processor that may have been modified, so a
    /// failed set leaves no untracked partial watch and a failed clear
    /// leaves the manager's still-enabled entry truthful.
    fn update_slot_on_all_processors(
        &mut self,
        slot: usize,
        watch: Option<HardwareWatch>,
    ) -> Result<()> {
        if !self.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        let slot_count = self.hardware_breakpoint_slots();
        if slot >= slot_count {
            return Err(Error::Kd(format!(
                "invalid hardware breakpoint slot {slot} (expected 0-{})",
                slot_count.saturating_sub(1)
            )));
        }
        if let Some(watch) = watch {
            let slots = self.debug_registers().slots_for(watch.access);
            if !slots.contains(&slot) {
                return Err(Error::Kd(format!(
                    "{} slot {slot} is outside slots {}-{}",
                    watch.access.label(),
                    slots.start,
                    slots.end - 1
                )));
            }
        }
        let saved = self.current_processor;
        let result = (|| {
            let mut applied = Vec::with_capacity(self.processor_count.max(1) as usize);
            let mut failure = None;

            for processor in 0..self.processor_count.max(1) {
                self.current_processor = processor;
                let previous = match self.read_slot_state(slot) {
                    Ok(previous) => previous,
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                };
                applied.push((processor, previous));
                if let Err(error) = self.arm_slot(slot, watch) {
                    failure = Some(error);
                    break;
                }
            }

            let Some(error) = failure else {
                return Ok(());
            };
            let operation = if watch.is_some() { "install" } else { "clear" };
            match self.rollback_slot_states(&applied) {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(Error::Kd(format!(
                    "hardware breakpoint {operation} failed: {error}; rollback also failed: \
                     {rollback_error}"
                ))),
            }
        })();
        self.current_processor = saved;
        result
    }

    pub(super) fn set_hardware_slot(
        &mut self,
        slot: usize,
        address: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        let watch = HardwareWatch {
            address,
            access,
            len,
        };
        self.update_slot_on_all_processors(slot, Some(watch))
    }

    pub(super) fn clear_hardware_slot(&mut self, slot: usize) -> Result<()> {
        self.update_slot_on_all_processors(slot, None)
    }
}
