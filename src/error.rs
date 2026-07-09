use std::num::ParseIntError;
use std::path::PathBuf;

use hex::FromHexError;
use indicatif::style::TemplateError;
use thiserror::Error;

use crate::types::{PhysAddr, VirtAddr};

#[derive(Debug, Error)]
pub enum Error {
    // Handle crate errors
    #[error(transparent)]
    Nix(#[from] nix::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Pdb2(#[from] pdb2::Error),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    PeLite(#[from] pelite::Error),

    #[error(transparent)]
    ParseInt(#[from] ParseIntError),

    #[error(transparent)]
    Hex(#[from] FromHexError),

    #[error(transparent)]
    Indicatif(#[from] TemplateError),

    #[cfg(feature = "cli")]
    #[error(transparent)]
    CtrlC(#[from] ctrlc::Error),

    #[error("GDB protocol failure: {0}")]
    Rsp(String),

    #[error("KD protocol failure: {0}")]
    Kd(String),

    #[error("KD protocol failure: kernel returned NTSTATUS {ntstatus:#x} for api {api:#x}")]
    KdStatus { ntstatus: u32, api: u32 },

    #[error("Register '{0}' not found")]
    RegisterNotFound(String),

    #[error("Breakpoint '{0}' not found")]
    BPNotFound(u32),

    #[error("Not supported")]
    NotSupported,

    #[error("{0}")]
    DebugInfo(String),

    // Handle other errors
    #[error("PDB file not found for {0:?}")]
    PdbNotFound(PathBuf),

    #[error("Ntoskrnl not found")]
    NtoskrnlNotFound,

    #[error("PE view failed")]
    ViewFailed,

    #[error("Storage directory wasn't found")]
    StorageNotFound,

    #[error("Symbol '{0}' not found")]
    SymbolNotFound(String),

    #[error("No symbol found near {0:x}")]
    UnknownAddress(VirtAddr),

    #[error("Process '{0}' not found")]
    ProcessNotFound(u64),

    #[error("Structure '{0}' not found")]
    StructNotFound(String),

    #[error("Field '{0}' not found")]
    FieldNotFound(String),

    #[error("Field '{0}' is not a {1}")]
    FieldTypeMismatch(String, String),

    #[error("Invalid expression: {0}")]
    InvalidExpression(String),

    #[error("Expected loaded symbols")]
    ExpectedSymbols,

    #[error("Process missing PEB (kernel process?)")]
    MissingPEB,

    #[error("Process missing ImageBase")]
    MissingImageBase,

    #[error("Process image not found")]
    MissingImage,

    #[error("No memory regions found in kvm")]
    NoKvmRegions,

    #[error("KVM process not found")]
    KvmNotFound,

    #[error(
        "permission denied reading from KVM process (PID {pid}).\n\
         /proc/sys/kernel/yama/ptrace_scope is currently {scope}. to allow attaching, run:\n    \
             echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n\
         (or run ntoseye as root)"
    )]
    PtraceDenied { pid: i32, scope: String },

    #[error("Another instance of ntoseye is already attached to {0}")]
    AlreadyRunning(String),

    #[error("Data doesn't fit in buffer")]
    BufferNotEnough,

    #[error("Invalid range")]
    InvalidRange,

    #[error("Partial read: {0}b")]
    PartialRead(usize),

    #[error("Partial write: {0}b")]
    PartialWrite(usize),

    #[error("Bad virtual address: {0:x}")]
    BadVirtualAddress(VirtAddr),

    #[error("Bad physical address: {0:x}")]
    BadPhysicalAddress(PhysAddr),

    #[error("crash dump is read-only")]
    ReadOnlyDump,

    #[error("invalid crash dump: {0}")]
    InvalidDump(String),
}

pub type Result<T> = std::result::Result<T, Error>;
