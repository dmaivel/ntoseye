use std::num::ParseIntError;
use std::path::PathBuf;

use hex::FromHexError;
use indicatif::style::TemplateError;
use thiserror::Error;

use crate::types::{PhysAddr, VirtAddr};

#[derive(Debug, Error)]
pub enum Error {
    #[cfg(target_os = "linux")]
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
    #[error("KD protocol failure: send exceeded retry budget: {0}")]
    KdSendExhausted(String),
    #[error("KD protocol failure: kernel returned NTSTATUS {ntstatus:#x} for api {api:#x}")]
    KdStatus { ntstatus: u32, api: u32 },

    #[error("breakpoint: {0}")]
    Breakpoint(String),

    #[error("Register '{0}' not found")]
    RegisterNotFound(String),

    #[error("Breakpoint '{0}' not found")]
    BPNotFound(u32),

    #[error("Not supported")]
    NotSupported,

    #[error("target must be halted to write registers")]
    TargetRunning,

    #[error("the current backend does not support register writes")]
    RegisterWriteUnsupported,

    #[error("the current backend cannot continue an exception as not handled")]
    ExceptionDispositionUnsupported,

    #[error("{0}")]
    DebugInfo(String),

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

    #[error("Symbol '{name}' is ambiguous: {candidates}", candidates = .candidates.join(", "))]
    AmbiguousSymbol {
        name: String,
        candidates: Vec<String>,
    },

    #[error("Unsupported target architecture: {0}")]
    UnsupportedArchitecture(String),

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

    #[error("no usable guest RAM mapping found in the VM process")]
    NoVmMemoryRegion,

    #[error(
        "VM process not found\n  KVM (QEMU/Linux): no process has /dev/kvm open\n  VMware: no vmware-vmx process found with /dev/vmmon open — is the VM powered on?\n  macOS (UTM): no qemu-aarch64-softmmu process found — is the VM powered on?"
    )]
    VmNotFound,

    #[error(
        "permission denied accessing VM process (PID {pid}): {detail}\n\
         macOS restricts task_for_pid to root or the com.apple.security.cs.debugger entitlement.\n\
         UTM's QEMU is a normal (sandboxed) third-party process, not SIP-protected, so run ntoseye as root:\n\
         sudo ntoseye ...\n\
         (or sign ntoseye with the debugger entitlement and approve it in System Settings > Privacy & Security > Developer Tools)"
    )]
    TaskForPidDenied { pid: i32, detail: String },

    #[error(
        "permission denied reading from VM process (PID {pid}).\n\
         /proc/sys/kernel/yama/ptrace_scope is currently {scope}. To allow attaching, run:\n    \
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

    #[error("Address {0:x} is not captured in the triage dump's memory snapshot")]
    AddressNotInDump(VirtAddr),

    #[error("Bad physical address: {0:x}")]
    BadPhysicalAddress(PhysAddr),

    #[error("crash dump is read-only")]
    ReadOnlyDump,

    #[error("invalid crash dump: {0}")]
    InvalidDump(String),
}

pub type Result<T> = std::result::Result<T, Error>;
