//! What the KD protocol does differently on each architecture: where the
//! kernel's page-table root is read, how a continue keeps the hardware
//! breakpoints set during the halt, which halt state a stop reports, and the
//! registers beyond the `CONTEXT` that KD fills one by one. The backend asks
//! the target's [`KdMachine`] and never names an architecture itself.

use super::framing::KdFraming;
use super::transport::KdTransport;
use super::{ControlReport, KdBackend, TrapState, amd64, arm64};
use crate::arch::Arch;
use crate::base::error::Result;

pub trait KdMachine: Sync {
    /// The kernel's page-table root as `processor` holds it, before
    /// [`super::connect::normalize_kernel_dtb`].
    fn kernel_root(&self, kd: &mut KdBackend, processor: u16) -> Result<u64>;

    /// The debug feature register of `processor`, which counts the hardware
    /// breakpoints it implements (see
    /// [`crate::arch::DebugRegisters::implemented_slots_for`]); `None` where
    /// the architecture has none or the target does not answer.
    fn debug_features(&self, kd: &mut KdBackend, processor: u16) -> Option<u64>;

    /// Continue `processor` with `status`, single-stepping when `trace`,
    /// with the hardware breakpoints the halt set kept.
    fn resume(&self, kd: &mut KdBackend, processor: u16, status: u32, trace: bool) -> Result<()>;

    /// The same continue from the event pump, which holds only the framing
    /// and none of the backend's halt state.
    fn resume_from_pump(
        &self,
        framing: &mut KdFraming<KdTransport>,
        processor: u16,
        status: u32,
    ) -> Result<()>;

    /// The trap flag and debug status the current processor's stop
    /// reported, where the architecture's report carries them.
    fn stop_trap_state(&self, kd: &mut KdBackend) -> Option<TrapState>;

    /// How many bytes of `InstructionStream` a stop's control `report`
    /// carries from its PC, where the architecture's report is read: the
    /// target copies up to [`super::api::DBGKD_MAXSTREAM`], fewer when the
    /// next page is unreadable, and deletes the breakpoint-table entries in
    /// just what it copied.
    fn reported_instruction_count(&self, report: &ControlReport) -> Option<u64>;

    /// Fill the register buffer's slots past the `CONTEXT` in `context`.
    fn append_registers(&self, kd: &mut KdBackend, context: &mut Vec<u8>) -> Result<()>;

    /// The `KSPECIAL_REGISTERS` of `processor` a register write is mirrored
    /// into, since KD restores the hardware breakpoints from there; `None`
    /// when the target keeps none to mirror into.
    fn special_registers_to_mirror(
        &self,
        kd: &mut KdBackend,
        processor: u16,
    ) -> Result<Option<Vec<u8>>>;
}

/// The KD protocol's ways on `arch`.
pub fn machine(arch: Arch) -> &'static dyn KdMachine {
    match arch {
        Arch::Amd64 => &amd64::Amd64Kd,
        Arch::Arm64 => &arm64::Arm64Kd,
    }
}
