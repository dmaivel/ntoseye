//! The Windows `CONTEXT` record of each architecture: its layout, its
//! `ContextFlags` bits, and the register buffer ntoseye builds on it.
//!
//! Every Windows source of a thread's registers hands back this record: KD's
//! `DBGKD_GET_CONTEXT`, a kernel dump's PRCB context frames, a triage or
//! user-mode minidump's thread contexts. The register buffer is the record
//! followed by synthetic slots for state it does not carry (control and
//! system registers), so one register map serves every one of them.

pub mod amd64;
pub mod arm64;
