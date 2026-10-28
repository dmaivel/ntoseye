//! The KD protocol on AMD64: DR7 rides along every continue, and the stop's
//! control report carries the trap flag and DR6.

use super::event_loop::with_framing_read_timeout;
use super::framing::KdFraming;
use super::machine::KdMachine;
use super::registers::{CONTROL_SPACE_KSPECIAL, MSR_EFER, special_into_context};
use super::transport::KdTransport;
use super::{ControlReport, KD_REQUEST_TIMEOUT, KdBackend, TrapState, api};
use crate::arch::Arch;
use crate::base::bytes;
use crate::base::error::{Error, Result};

pub struct Amd64Kd;

impl KdMachine for Amd64Kd {
    fn kernel_root(&self, kd: &mut KdBackend, processor: u16) -> Result<u64> {
        let special = kd.read_special_registers_uncached(processor)?;
        Arch::Amd64.special_register_map().read_u64("cr3", &special)
    }

    // DR0-DR3 are architectural: every x64 processor has all four.
    fn debug_features(&self, _: &mut KdBackend, _: u16) -> Option<u64> {
        None
    }

    fn resume(&self, kd: &mut KdBackend, processor: u16, status: u32, trace: bool) -> Result<()> {
        // The stop reported DR7, so a resume that read no special registers
        // needs none: only a host write can have changed it, and that drops
        // the report along with the rest of the processor's halt state.
        let reported_dr7 = kd.registers.report(processor).and_then(reported_dr7);
        if reported_dr7.is_none() && kd.registers.special(processor).is_none() {
            let special = kd.read_special_registers_uncached(processor)?;
            kd.registers.set_special(processor, special);
        }
        let dr7 = match kd.registers.special(processor) {
            // A `ba` installed during this halt wrote the cache; it is newer
            // than the report.
            Some(special) => Arch::Amd64
                .special_register_map()
                .read_u64("dr7", special)?,
            None => reported_dr7.expect("read the registers when no report offered DR7"),
        };
        with_framing_read_timeout(kd.framing()?, KD_REQUEST_TIMEOUT, |framing| {
            api::continue_api2(framing, processor, status, trace, dr7)
        })
    }

    // KernelDr7 is read from the processor's KSPECIAL_REGISTERS, so data
    // watchpoints keep firing across a transparent state change; the pump
    // holds no cache to read it from.
    fn resume_from_pump(
        &self,
        framing: &mut KdFraming<KdTransport>,
        processor: u16,
        status: u32,
    ) -> Result<()> {
        let special_map = Arch::Amd64.special_register_map();
        let special = api::read_control_space(
            framing,
            processor,
            CONTROL_SPACE_KSPECIAL,
            special_map.extent() as u32,
        )?;
        let dr7 = special_map.read_u64("dr7", &special).map_err(|_| {
            Error::Kd(format!(
                "KSPECIAL_REGISTERS buffer too short for KernelDr7: {} bytes",
                special.len()
            ))
        })?;
        api::continue_api2(framing, processor, status, false, dr7)
    }

    // KD reports TF and DR6 in every AMD64 state change, so an absorbed
    // breakpoint hit can decide it has no single-step residue to clear
    // without fetching a `CONTEXT` it would read two fields from.
    fn stop_trap_state(&self, kd: &mut KdBackend) -> Option<TrapState> {
        trap_state(kd.registers.report(kd.current_processor)?)
    }

    fn reported_instruction_count(&self, report: &ControlReport) -> Option<u64> {
        instruction_count(report)
    }

    // The control registers from KSPECIAL_REGISTERS, and EFER, read once
    // per processor.
    fn append_registers(&self, kd: &mut KdBackend, context: &mut Vec<u8>) -> Result<()> {
        let processor = kd.current_processor;
        let special = kd.read_special_registers()?;
        special_into_context(Arch::Amd64, context, special)?;
        let efer = kd.efer_cache.get(&processor).copied().or_else(|| {
            match kd.read_msr_value(processor, MSR_EFER) {
                Ok(value) => {
                    kd.efer_cache.insert(processor, value);
                    Some(value)
                }
                Err(error) => {
                    kd_trace!("kd: EFER read unavailable: {error}");
                    None
                }
            }
        });
        if let Some(efer) = efer {
            Arch::Amd64
                .register_map()
                .write_u64("efer", context, efer)?;
        }
        Ok(())
    }

    fn special_registers_to_mirror(
        &self,
        kd: &mut KdBackend,
        processor: u16,
    ) -> Result<Option<Vec<u8>>> {
        kd.read_special_registers_uncached(processor).map(Some)
    }
}

/// `AMD64_DBGKD_CONTROL_REPORT`: Dr6, Dr7, EFlags, InstructionCount,
/// ReportFlags, InstructionStream[16], SegCs, SegDs, SegEs, SegFs.
pub const CONTROL_REPORT_SIZE: usize = 48;
pub const CONTROL_DR6_OFFSET: usize = 0;
pub const CONTROL_DR7_OFFSET: usize = 8;
pub const CONTROL_EFLAGS_OFFSET: usize = 16;
pub const CONTROL_INSTRUCTION_COUNT_OFFSET: usize = 20;

/// The AMD64 fields of a stop's control report.
fn fields(report: &ControlReport) -> Option<&[u8]> {
    report.0.get(..CONTROL_REPORT_SIZE)
}

/// DR6 and RFLAGS as the target reported them at the stop.
pub fn trap_state(report: &ControlReport) -> Option<TrapState> {
    let fields = fields(report)?;
    Some(TrapState {
        eflags: u64::from(bytes::read_u32(fields, CONTROL_EFLAGS_OFFSET)),
        dr6: bytes::read_u64(fields, CONTROL_DR6_OFFSET),
    })
}

/// DR7 as the target reported it at the stop, which a continue must
/// preserve.
pub fn reported_dr7(report: &ControlReport) -> Option<u64> {
    Some(bytes::read_u64(fields(report)?, CONTROL_DR7_OFFSET))
}

/// `InstructionCount`: the bytes of `InstructionStream` the target copied
/// from the stop PC, never more than the stream holds.
pub fn instruction_count(report: &ControlReport) -> Option<u64> {
    let count = bytes::read_u16(fields(report)?, CONTROL_INSTRUCTION_COUNT_OFFSET);
    Some(u64::from(count).min(api::DBGKD_MAXSTREAM))
}
