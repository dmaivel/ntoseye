//! The Windows `CONTEXT` record of each architecture: its layout, its
//! `ContextFlags` bits, and the register buffer ntoseye builds on it.
//!
//! Every Windows source of a thread's registers hands back this record: KD's
//! `DBGKD_GET_CONTEXT`, a kernel dump's PRCB context frames, a triage or
//! user-mode minidump's thread contexts. The register buffer is the record
//! followed by synthetic slots for state it does not carry (control and
//! system registers), so one register map serves every one of them.
//!
//! Each architecture's module is also the one place its register lists
//! live: the grid's display order and the instruction set's numbering.

use crate::base::types::Arch;

pub mod amd64;
pub mod arm64;

/// The general registers of `arch`, in the order the register grid shows
/// them, flags last.
pub fn general_registers(arch: Arch) -> &'static [&'static str] {
    match arch {
        Arch::Amd64 => &amd64::GENERAL_REGISTERS,
        Arch::Arm64 => &arm64::GENERAL_REGISTERS,
    }
}

/// The integer registers of `arch`, numbered as its instruction set encodes
/// them.
pub fn encoded_registers(arch: Arch) -> &'static [&'static str] {
    match arch {
        Arch::Amd64 => &amd64::ENCODED_REGISTERS,
        Arch::Arm64 => &arm64::ENCODED_REGISTERS,
    }
}
