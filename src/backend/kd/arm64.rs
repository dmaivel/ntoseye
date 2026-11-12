//! The KD protocol on ARM64: a continue has no DR7 to carry (the kernel
//! single-steps through MDSCR), and the system registers past the
//! `CONTEXT` are read as MSRs.

use super::event_loop::with_framing_read_timeout;
use super::framing::KdFraming;
use super::machine::KdMachine;
use super::registers::{
    ARM64_WINDBG_ESR_EL1, ARM64_WINDBG_FAR_EL1, ARM64_WINDBG_ID_AA64DFR0_EL1,
    ARM64_WINDBG_TTBR0_EL1, ARM64_WINDBG_TTBR1_EL1, arm64_x18, check_special_size,
    special_into_context,
};
use super::transport::KdTransport;
use super::{ControlReport, KD_REQUEST_TIMEOUT, KdBackend, TrapState, api};
use crate::arch::Arch;
use crate::base::error::Result;

pub struct Arm64Kd;

impl KdMachine for Arm64Kd {
    fn kernel_root(&self, kd: &mut KdBackend, processor: u16) -> Result<u64> {
        with_framing_read_timeout(kd.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::read_machine_specific_register(framing, processor, ARM64_WINDBG_TTBR1_EL1)
        })
    }

    fn debug_features(&self, kd: &mut KdBackend, processor: u16) -> Option<u64> {
        with_framing_read_timeout(kd.framing().ok()?, KD_REQUEST_TIMEOUT, |framing| {
            api::read_machine_specific_register(framing, processor, ARM64_WINDBG_ID_AA64DFR0_EL1)
        })
        .inspect_err(|error| kd_trace!("kd: ARM64 ID_AA64DFR0_EL1 unavailable: {error}"))
        .ok()
    }

    // ARM64_DBGKD_CONTROL_SET has no Dr7 field; the kernel single-steps via
    // MDSCR when TraceFlag is set.
    fn resume(&self, kd: &mut KdBackend, processor: u16, status: u32, trace: bool) -> Result<()> {
        with_framing_read_timeout(kd.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::continue_api2_arm64(framing, processor, status, trace)
        })
    }

    fn resume_from_pump(
        &self,
        framing: &mut KdFraming<KdTransport>,
        processor: u16,
        status: u32,
    ) -> Result<()> {
        api::continue_api2_arm64(framing, processor, status, false)
    }

    fn stop_trap_state(&self, _: &mut KdBackend) -> Option<TrapState> {
        None
    }

    // The ARM64 control report is not read, so a stop is taken to have
    // deleted the entries in the whole stream window.
    fn reported_instruction_count(&self, _: &ControlReport) -> Option<u64> {
        None
    }

    // TTBR0, the syndrome and the fault address are MSRs, which the target
    // reads only on the processor that stopped it, whatever processor a
    // request names: another processor's TTBR0 comes from its current
    // thread's process, and its syndrome, of no exception, stays 0. x18
    // holds the KPCR or the TEB; the kernel root fills its own slot.
    fn append_registers(&self, kd: &mut KdBackend, context: &mut Vec<u8>) -> Result<()> {
        let arch = Arch::Arm64;
        let map = arch.register_map();
        let processor = kd.current_processor;
        let stopped_here = processor == kd.last_stop_processor;
        let ttbr0 = if stopped_here {
            kd.system_register_or_zero(ARM64_WINDBG_TTBR0_EL1, "ARM64 TTBR0_EL1")
        } else {
            kd.processor_process_root(processor).unwrap_or(0)
        } & arch.dtb_page_mask();
        let fault = stopped_here.then(|| {
            (
                kd.system_register_or_zero(ARM64_WINDBG_ESR_EL1, "ARM64 ESR_EL1"),
                kd.system_register_or_zero(ARM64_WINDBG_FAR_EL1, "ARM64 FAR_EL1"),
            )
        });
        if let Some(x18) = arm64_x18(context, kd.thread_layout, kd) {
            map.write_u64("x18", context, x18)?;
        }
        context.resize(arch.register_buffer_size(), 0);
        map.write_u64(arch.kernel_dtb_register(), context, kd.kernel_dtb_override)?;
        map.write_u64("ttbr0", context, ttbr0)?;
        if let Some((esr, far)) = fault {
            map.write_u64("esr", context, esr)?;
            map.write_u64("far", context, far)?;
        }
        if let Some(special) = special_registers(kd) {
            special_into_context(arch, context, special)?;
        }
        Ok(())
    }

    // The SetContext the write sent already carried the debug registers, so
    // a target that refuses control space must not fail an applied write.
    fn special_registers_to_mirror(
        &self,
        kd: &mut KdBackend,
        processor: u16,
    ) -> Result<Option<Vec<u8>>> {
        if kd.special_registers_unsupported {
            return Ok(None);
        }
        match kd.read_special_registers_uncached(processor) {
            Ok(special) => Ok(Some(special)),
            Err(error) => {
                kd_trace!("kd: ARM64 KSPECIAL_REGISTERS mirror skipped: {error}");
                kd.special_registers_unsupported = true;
                Ok(None)
            }
        }
    }
}

/// The current processor's KSPECIAL_REGISTERS, the kernel's copies of the
/// debug registers; `None` once the target refused them, and the registers
/// come from GetContext alone.
fn special_registers(kd: &mut KdBackend) -> Option<&[u8]> {
    if kd.special_registers_unsupported {
        return None;
    }
    if let Err(error) = kd.read_special_registers().map(|_| ()) {
        kd_trace!("kd: ARM64 KSPECIAL_REGISTERS unavailable: {error}");
        kd.special_registers_unsupported = true;
        return None;
    }
    kd.registers
        .special(kd.current_processor)
        .filter(|special| check_special_size(Arch::Arm64, special).is_ok())
}
