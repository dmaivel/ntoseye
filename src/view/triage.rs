//! Crash-triage [`View`] builders: the triage report and the
//! dump metadata, failure signature, and findings it aggregates.

use ntoseye_macros::record;

use super::bugcheck::{Bugcheck, bugcheck};
use super::execution::{run_status, stack_frames};
use crate::dmp::triage::TriagePrcbInfo;
use crate::dmp::{self, DmpException, DmpSystemInfo};
use crate::target::DiagnosticValue;
use crate::target::pnp::DeviceStackDetail;
use crate::triage_report::{
    BlackboxFinding, BlackboxKind, BlackboxState, CodeOwner as CodeOwnerDetail, CulpritAttribution,
    CulpritConfidence, CulpritEvidenceKind, CulpritSubject, FailureCodeKind,
    FailureSignatureSource, PowerFailureFinding as PowerDetail, PowerThreadRole,
    UserDumpTriage as UserDumpDetail, UserExceptionFinding, UserExceptionKind, UserFrame,
    UserStackSource, WheaRecordState, WheaSectionKind, exception_code_name,
    time::{filetime_to_iso, unix_time_to_iso},
};
use crate::triage_report::{
    FailureSignature as SignatureDetail, TriageCrashInfo, TriageReport as ReportDetail,
    VerifierFinding as VerifierFindingDetail, WheaFinding as WheaFindingDetail,
};

/// The exception a crash dump recorded.
#[record]
pub struct DumpException {
    /// The exception code (NTSTATUS).
    pub code: u32,
    /// The same code in hex.
    #[record(hex)]
    pub code_hex: u32,
    /// The code's symbolic name.
    pub code_name: String,
    pub flags: u32,
    /// Where the exception occurred.
    #[record(hex)]
    pub address: u64,
    /// The exception's `ExceptionInformation` parameters.
    #[record(hex)]
    pub parameters: Vec<u64>,
}

/// The system that a crash dump comes from, as the system-info stream of
/// the dump records it.
#[record]
pub struct DumpSystemInfo {
    pub major_version: u32,
    /// The build number (the stream's minor version).
    pub build: u32,
    pub service_pack_build: u32,
    /// The machine type (`IMAGE_FILE_MACHINE_*`).
    #[record(hex)]
    pub machine_image_type: u32,
    /// `I386`, `AMD64`, `ARM64`, or `Unknown`.
    pub machine: &'static str,
    /// The time when the dump was taken (ISO 8601 UTC). `None` if the dump
    /// does not record it.
    pub system_time: Option<String>,
    /// The system uptime in seconds. `None` if the dump does not record
    /// it.
    pub system_up_time_secs: Option<u64>,
    /// `Workstation`, `DomainController`, `Server`, or `Unknown`.
    pub product_type: &'static str,
    /// The product suite (`VER_SUITE_*`) bits.
    #[record(hex)]
    pub suite_mask: u32,
}

/// The process and thread that crashed, as a triage dump recorded them.
/// A field is `None` if the dump does not record it.
#[record]
pub struct CrashContext {
    pub process_name: Option<String>,
    pub process_id: Option<u64>,
    pub thread_id: Option<u64>,
    pub parent_process_id: Option<u64>,
    /// The process's exit status (NTSTATUS).
    #[record(hex)]
    pub exit_status: Option<u64>,
    /// The time when the process was created (ISO 8601 UTC). Also `None` if
    /// ntoseye cannot convert the recorded time.
    pub create_time: Option<String>,
    /// The thread's exit status (NTSTATUS).
    #[record(hex)]
    pub thread_exit_status: Option<u64>,
}

/// The main `_KPRCB` data of the crashed processor, as a triage dump
/// recorded it.
#[record]
pub struct TriagePrcb {
    /// The `_KTHREAD` running on the processor.
    #[record(hex)]
    pub current_thread: u64,
    pub processor_number: u16,
    /// The processor's clock speed in MHz.
    pub mhz: u32,
    pub cpu_type: u16,
    /// The CPU vendor (`GenuineIntel`, `AuthenticAMD`, ...).
    pub vendor_string: String,
}

/// A deterministic identity for a failure that does not depend on
/// addresses, so you can use it to compare failures.
#[record]
pub struct FailureSignature {
    /// `bugcheck` or `exception`.
    pub code_kind: &'static str,
    /// The bugcheck or exception code.
    #[record(hex)]
    pub code: u32,
    /// The source of the failing location: `bugcheck_fault`,
    /// `exception_address`, `current_instruction`, `top_frame`,
    /// `power_failure_driver` (the driver a 0x9F names),
    /// `first_non_system_frame` (on a user-mode minidump, the first frame
    /// outside the system modules), or `code_only`.
    pub source: &'static str,
    /// The module at the failing location.
    pub module: Option<String>,
    /// The symbol at the failing location.
    pub symbol: Option<String>,
    /// The ordered parts that make `bucket`.
    pub components: Vec<String>,
    /// The failure bucket.
    pub bucket: String,
}

/// What the available evidence identifies as the cause of the crash: a
/// module, or on a user-mode minidump, generated code no module holds.
#[record]
pub struct Culprit {
    /// `module`, or `dynamic_code` (JIT-compiled or generated code that
    /// a dynamic function table covers; see `dynamic_code`).
    pub kind: &'static str,
    /// The module. `None` for `dynamic_code`.
    pub module: Option<String>,
    /// The generated code, for `dynamic_code`.
    pub dynamic_code: Option<CulpritDynamicCode>,
    /// `low`, `medium`, or `high`.
    pub confidence: &'static str,
    /// The evidence that points to the culprit.
    pub evidence: Vec<CulpritEvidence>,
}

/// Generated code a culprit attribution names: no module holds it, and
/// a dynamic function table the process registered covers it.
#[record]
pub struct CulpritDynamicCode {
    /// The blamed frame's address.
    #[record(hex)]
    pub address: u64,
    /// The start of the dynamic function table's range.
    #[record(hex)]
    pub table_start: u64,
    /// The end (exclusive) of the table's range.
    #[record(hex)]
    pub table_end: u64,
    /// The first frame further out that a module holds: the module
    /// code that called into the generated code.
    pub caller: Option<UserTriageFrame>,
}

/// One item of evidence for a culprit attribution.
#[record]
pub struct CulpritEvidence {
    /// `recorded_broken_driver`, `recorded_bugcheck_driver`,
    /// `bugcheck_fault_address`, `exception_address`,
    /// `current_instruction`, `top_frame`, `power_failure_driver`,
    /// `pnp_lock_owner_stack`, or `first_non_system_frame`.
    pub kind: &'static str,
    pub detail: String,
    /// The address that the evidence uses, if the evidence is an address.
    #[record(hex)]
    pub address: Option<u64>,
}

/// A Driver Verifier bugcheck, decoded from its subcode.
#[record]
pub struct VerifierFinding {
    #[record(hex)]
    pub bugcheck_code: u32,
    pub bugcheck_name: String,
    /// The verifier subcode (the first bugcheck parameter).
    #[record(hex)]
    pub subcode: u64,
    /// `True` if the decoder recognizes the subcode.
    pub known_subcode: bool,
    /// What the subcode means, or `unknown verifier subcode`.
    pub subcode_description: String,
    /// The driver that ntoseye attributes the violation to.
    pub associated_driver: Option<String>,
    /// The bugcheck parameters, with descriptions for the subcode.
    pub arguments: Vec<VerifierFindingArgument>,
    /// The addresses in the parameters, with their roles.
    pub addresses: Vec<VerifierFindingAddress>,
}

/// A verifier bugcheck parameter and what it means for the subcode.
#[record]
pub struct VerifierFindingArgument {
    #[record(hex)]
    pub value: u64,
    pub description: String,
}

/// An address in a verifier bugcheck, and its role.
#[record]
pub struct VerifierFindingAddress {
    pub role: String,
    #[record(hex)]
    pub address: u64,
}

/// The WHEA error record of a hardware-error bugcheck.
#[record]
pub struct WheaFinding {
    /// The address of the record. `None` if the bugcheck does not give
    /// one.
    #[record(hex)]
    pub record_address: Option<u64>,
    /// The decoded record, or the reason that decoding failed.
    pub record: DiagnosticValue<WheaRecord>,
}

/// A decoded WHEA error record.
#[record]
pub struct WheaRecord {
    #[record(hex)]
    pub revision: u16,
    /// The record's error severity (`WHEA_ERROR_SEVERITY`).
    pub severity: u32,
    /// The record's length in bytes.
    pub length: u32,
    /// The number of sections in the record. `sections` holds at most 64.
    pub sections_total: usize,
    pub sections: Vec<WheaSection>,
}

/// One section of a WHEA error record.
#[record]
pub struct WheaSection {
    /// The section's offset in the record, in bytes.
    pub offset: u32,
    /// The section's length in bytes.
    pub length: u32,
    /// The section's error severity.
    pub severity: u32,
    /// The section type GUID.
    pub section_type: String,
    /// `processor_generic`, `memory`, `pci_express`, `x64_processor`, or
    /// `unknown`.
    pub kind: &'static str,
}

/// A blackbox record (pnp, ntfs, bsd, winlogon) of a crash dump: a block
/// of its tagged data that ntoseye decodes as WinDbg's `!blackbox*`
/// commands do.
#[record]
pub struct BlackboxStream {
    /// `pnp`, `ntfs`, `bsd`, or `winlogon`.
    pub kind: &'static str,
    /// `PnP`, `NTFS`, `BSD`, or `Winlogon`.
    pub name: String,
    /// The command that shows the whole record, such as `!blackboxpnp`.
    pub command: &'static str,
    /// The block's size in bytes. None if the dump has no block.
    pub size: Option<u64>,
    /// `True` if the dump has the block.
    pub present: bool,
    /// What the record holds, in one line. None if it does not decode.
    pub summary: Option<String>,
    /// Why the record does not decode, or that the dump has none. None
    /// if it decodes.
    pub reason: Option<String>,
}

/// A driver that the system unloaded recently, as the crash dump records
/// it.
#[record]
pub struct UnloadedDriver {
    pub name: String,
    #[record(hex)]
    pub start_address: u64,
    #[record(hex)]
    pub end_address: u64,
}

/// The IRP that a 0x9F/0x3 names, and where it is pending.
#[record]
pub struct BlockedPowerIrp {
    #[record(hex)]
    pub irp: u64,
    /// The driver of the IRP's current stack location.
    pub holder: DiagnosticValue<crate::target::power::IrpHolder>,
    /// The IRP's entry on the power IRP list. `None` when it is not on
    /// the list.
    pub data: Option<crate::target::power::PowerIrp>,
}

/// The driver that a DRIVER_POWER_STATE_FAILURE names, and why.
#[record]
pub struct PowerFailureCulprit {
    pub driver: crate::target::power::DeviceDriver,
    /// The device object that ties the driver to the failure.
    #[record(hex)]
    pub device: u64,
    pub reason: String,
}

/// A thread that a DRIVER_POWER_STATE_FAILURE names, with its stack.
#[record]
pub struct PowerFailureThread {
    /// `irp_worker` or `pnp_lock_owner`.
    pub role: &'static str,
    #[record(hex)]
    pub thread: u64,
    /// For an IRP worker, the IRP it is passing to a driver; 0 while it
    /// waits.
    #[record(hex)]
    pub irp: Option<u64>,
    #[record(hex)]
    pub device: Option<u64>,
    pub stack: DiagnosticValue<Vec<super::execution::StackFrame>>,
}

/// What a DRIVER_POWER_STATE_FAILURE (0x9F) names as stuck.
#[record]
pub struct PowerFailure {
    /// Parameter 1.
    #[record(hex)]
    pub subtype: u64,
    pub description: &'static str,
    /// The device object that the parameters name.
    #[record(hex)]
    pub device: Option<u64>,
    /// The stack of `device`.
    pub device_stack: Option<DiagnosticValue<DeviceStackDetail>>,
    /// 0x3: the blocked IRP.
    pub blocked_irp: Option<BlockedPowerIrp>,
    /// 0x3: the power IRPs on the list that `TRIAGE_9F_POWER` names.
    pub irps: Option<crate::target::power::PowerIrpList>,
    /// 0x3: the IRP worker threads on the list that `TRIAGE_9F_POWER`
    /// names.
    pub workers: Option<crate::target::power::PowerWorkerList>,
    /// 0x4: the thread that holds the PnP lock.
    #[record(hex)]
    pub pnp_lock_owner: Option<u64>,
    /// 0x4: the timeout in seconds.
    pub timeout_seconds: Option<u64>,
    pub culprit: Option<PowerFailureCulprit>,
    /// The IRP worker threads and the PnP lock owner, with their stacks.
    pub threads: Vec<PowerFailureThread>,
    /// What could not be read, and why.
    pub notes: Vec<String>,
}

/// The one-shot crash triage report (`!analyze`), with the run status, the
/// bugcheck or exception, the backtrace, the modules, the dump records,
/// and the findings.
#[record]
pub struct TriageReport {
    /// The target's run status.
    pub status: super::execution::RunStatus,
    /// The bugcheck, if the target is in a bugcheck.
    pub bugcheck: Option<Bugcheck>,
    /// The exception that a dump recorded.
    pub exception: Option<DumpException>,
    /// The system information of the dump.
    pub system_info: Option<DumpSystemInfo>,
    /// The stack of the current thread. `None` while the target runs or
    /// if the unwind failed (see `warnings`).
    pub backtrace: Option<Vec<super::execution::StackFrame>>,
    /// The loaded modules, up to a maximum that the caller sets (see
    /// `modules_total`).
    pub modules: Vec<crate::guest::ModuleInfo>,
    /// The number of loaded modules.
    pub modules_total: usize,
    pub unloaded_drivers: Vec<UnloadedDriver>,
    /// The process and thread that crashed, as a triage dump recorded them.
    pub crash_context: Option<CrashContext>,
    /// The processor that crashed, as a triage dump recorded it.
    pub prcb: Option<TriagePrcb>,
    /// The driver that the dump records as broken.
    pub broken_driver: Option<String>,
    /// `True` if the triage data of the dump overflowed. `None` if the
    /// target is not a dump.
    pub triage_overflowed: Option<bool>,
    pub failure_signature: Option<FailureSignature>,
    /// What the evidence identifies as the cause: a module, or on a
    /// user-mode minidump, JIT-compiled code. `None` if the evidence
    /// identifies neither a non-kernel (or, on a user dump, non-system)
    /// module nor generated code.
    pub culprit: Option<Culprit>,
    /// The Driver Verifier violation of a verifier bugcheck.
    pub verifier: Option<VerifierFinding>,
    /// The hardware error record of a WHEA bugcheck.
    pub whea: Option<WheaFinding>,
    pub blackboxes: Vec<BlackboxStream>,
    /// What a DRIVER_POWER_STATE_FAILURE names as stuck.
    pub power: Option<PowerFailure>,
    /// What a user-mode minidump adds: the process, the exception
    /// decoded, and the frame the failure is blamed on. `None` for a
    /// kernel target, whose bugcheck and kernel findings do not apply to
    /// a user dump.
    pub user: Option<UserTriage>,
    /// Failures in best-effort data collection that did not stop the
    /// report.
    pub warnings: Vec<String>,
}

/// The triage of a user-mode minidump.
#[record]
pub struct UserTriage {
    pub process: UserTriageProcess,
    /// The exception the dump was written for. `None` if it records
    /// none.
    pub exception: Option<UserTriageException>,
    /// The thread whose stack `backtrace` is. `None` if no thread is
    /// selected.
    pub stack_thread: Option<UserTriageStackThread>,
    /// The general-purpose registers of the exception's context, in
    /// display order. Empty without an exception or when its context is
    /// unusable.
    pub exception_registers: Vec<UserTriageRegister>,
}

/// The captured process, as the dump's streams record it.
#[record]
pub struct UserTriageProcess {
    /// The executable's file name.
    pub name: Option<String>,
    pub pid: Option<u32>,
    /// `AMD64` or `ARM64`.
    pub arch: &'static str,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    /// The full build string (`MINIDUMP_MISC_INFO_4.BuildString`).
    pub build_string: Option<String>,
    /// When the dump was written (ISO 8601 UTC).
    pub dump_time: Option<String>,
    /// When the process was created (ISO 8601 UTC).
    pub create_time: Option<String>,
    /// User-mode time the process had run, in seconds.
    pub user_time_secs: Option<u32>,
    /// Kernel-mode time the process had run, in seconds.
    pub kernel_time_secs: Option<u32>,
    pub threads: usize,
    pub modules: usize,
    pub unloaded_modules: usize,
    /// `None` if the dump has no handle stream.
    pub handles: Option<usize>,
}

/// The thread a user dump report's stack belongs to.
#[record]
pub struct UserTriageStackThread {
    pub tid: u32,
    /// The id as `~` lists it (`<pid>.<tid>` in hex).
    pub id: String,
    pub name: Option<String>,
    /// `exception_context` (walked from the exception's CONTEXT) or
    /// `thread_context` (the selected thread's).
    pub source: &'static str,
}

/// A register of the exception's context.
#[record]
pub struct UserTriageRegister {
    pub name: String,
    #[record(hex)]
    pub value: u64,
}

/// The exception a user-mode minidump was written for, decoded.
#[record]
pub struct UserTriageException {
    #[record(hex)]
    pub code: u32,
    /// `ntstatus`, `cpp_exception`, `clr_exception`, `well_known`,
    /// `application_defined` (customer bit set, no name), or `unknown`.
    pub kind: &'static str,
    /// The code's name, or what kind of code it is when it has none.
    pub name: &'static str,
    #[record(hex)]
    pub flags: u32,
    /// The `EXCEPTION_*` flags set, with unknown bits in hex.
    pub flag_names: Vec<String>,
    /// The address of a chained exception record; 0 for none.
    #[record(hex)]
    pub record: u64,
    #[record(hex)]
    pub address: u64,
    pub symbol: String,
    /// What holds the exception address: the faulting module.
    pub module: UserTriageCodeOwner,
    pub parameters: Vec<UserTriageExceptionParameter>,
    /// What the parameters say in one line, such as `write to 0x10`.
    pub summary: Option<String>,
    pub thread_id: u32,
    /// The faulting thread's id as `~` lists it.
    pub thread: String,
    pub thread_name: Option<String>,
    /// The index in `backtrace` of the frame at the exception address.
    pub faulting_frame: Option<usize>,
    /// The first frame from the faulting one outward outside the system
    /// modules (ntdll, kernelbase, the C++ and .NET runtimes): the code
    /// the failure is blamed on. `None` if every frame is in a system
    /// module.
    pub blamed_frame: Option<UserTriageFrame>,
    /// When `blamed_frame` is in no module, the first frame further out
    /// that a module holds: the module code that called into it.
    pub module_caller: Option<UserTriageFrame>,
}

/// One `ExceptionInformation` entry of a user dump's exception.
#[record]
pub struct UserTriageExceptionParameter {
    #[record(hex)]
    pub value: u64,
    /// What the entry is for the code (`access`, `address`,
    /// `ThrowInfo`, ...). `None` if the code defines no meaning.
    pub label: Option<&'static str>,
    /// The value decoded (`write`, a status name, a module).
    pub meaning: Option<String>,
}

/// What holds a code address of a user dump.
#[record]
pub struct UserTriageCodeOwner {
    /// `module`, `dynamic_code` (no module; a dynamic function table
    /// covers it, as for JIT-compiled code), or `unowned`.
    pub kind: &'static str,
    pub module: Option<String>,
    /// Whether the module is part of Windows or a language runtime.
    pub system: bool,
    /// For `unowned`, the memory region as the dump's memory-info list
    /// records it.
    pub region: Option<String>,
    /// For `dynamic_code`, the range of the dynamic function table that
    /// covers the address.
    #[record(hex)]
    pub table_start: Option<u64>,
    #[record(hex)]
    pub table_end: Option<u64>,
}

/// A frame of a user dump report's stack.
#[record]
pub struct UserTriageFrame {
    /// The frame's index in `backtrace`.
    pub index: usize,
    #[record(hex)]
    pub ip: u64,
    pub symbol: String,
    /// How the frame was recovered (`unwind`, `scan`, ...).
    pub source: &'static str,
    pub owner: UserTriageCodeOwner,
}

pub fn dump_exception(exception: &DmpException) -> DumpException {
    DumpException {
        code: exception.code,
        code_hex: exception.code,
        code_name: exception_code_name(exception.code).to_string(),
        flags: exception.flags,
        address: exception.address,
        parameters: exception.parameters.to_vec(),
    }
}

pub fn system_info(info: &DmpSystemInfo) -> DumpSystemInfo {
    let product = match info.product_type {
        1 => "Workstation",
        2 => "DomainController",
        3 => "Server",
        _ => "Unknown",
    };
    let machine = match info.machine_image_type {
        0x014c => "I386",
        0x8664 => "AMD64",
        0xAA64 => "ARM64",
        _ => "Unknown",
    };
    DumpSystemInfo {
        major_version: info.major_version,
        build: info.minor_version,
        service_pack_build: info.service_pack_build,
        machine_image_type: info.machine_image_type,
        machine,
        system_time: (info.system_time != 0)
            .then(|| filetime_to_iso(info.system_time as u64))
            .flatten(),
        system_up_time_secs: (info.system_up_time > 0)
            .then(|| u64::try_from(info.system_up_time / 10_000_000).ok())
            .flatten(),
        product_type: product,
        suite_mask: info.suite_mask,
    }
}

pub fn crash_context(context: &TriageCrashInfo) -> CrashContext {
    CrashContext {
        process_name: context.process_name.clone(),
        process_id: context.process_id,
        thread_id: context.thread_id,
        parent_process_id: context.parent_process_id,
        exit_status: context.exit_status.map(|status| status as u64),
        create_time: context.create_time.and_then(filetime_to_iso),
        thread_exit_status: context.thread_exit_status.map(|status| status as u64),
    }
}

pub fn prcb(prcb: &TriagePrcbInfo) -> TriagePrcb {
    TriagePrcb {
        current_thread: prcb.current_thread,
        processor_number: prcb.processor_number,
        mhz: prcb.mhz,
        cpu_type: prcb.cpu_type,
        vendor_string: prcb.vendor_string.clone(),
    }
}

fn failure_signature(signature: &SignatureDetail) -> FailureSignature {
    let code_kind = match signature.code_kind {
        FailureCodeKind::Bugcheck => "bugcheck",
        FailureCodeKind::Exception => "exception",
    };
    let source = match signature.source {
        FailureSignatureSource::BugcheckFault => "bugcheck_fault",
        FailureSignatureSource::ExceptionAddress => "exception_address",
        FailureSignatureSource::CurrentInstruction => "current_instruction",
        FailureSignatureSource::TopFrame => "top_frame",
        FailureSignatureSource::PowerFailureDriver => "power_failure_driver",
        FailureSignatureSource::FirstNonSystemFrame => "first_non_system_frame",
        FailureSignatureSource::CodeOnly => "code_only",
    };
    FailureSignature {
        code_kind,
        code: signature.code,
        source,
        module: signature.module.clone(),
        symbol: signature.symbol.clone(),
        components: signature.components.clone(),
        bucket: signature.bucket.clone(),
    }
}

fn culprit(culprit: &CulpritAttribution) -> Culprit {
    let confidence = match culprit.confidence {
        CulpritConfidence::Low => "low",
        CulpritConfidence::Medium => "medium",
        CulpritConfidence::High => "high",
    };
    let (kind, module, dynamic_code) = match &culprit.subject {
        CulpritSubject::Module(module) => ("module", Some(module.clone()), None),
        CulpritSubject::DynamicCode(code) => (
            "dynamic_code",
            None,
            Some(CulpritDynamicCode {
                address: code.address,
                table_start: code.table_start,
                table_end: code.table_end,
                caller: code.caller.as_ref().map(user_frame),
            }),
        ),
    };
    Culprit {
        kind,
        module,
        dynamic_code,
        confidence,
        evidence: culprit
            .evidence
            .iter()
            .map(|evidence| CulpritEvidence {
                kind: match evidence.kind {
                    CulpritEvidenceKind::RecordedBrokenDriver => "recorded_broken_driver",
                    CulpritEvidenceKind::RecordedBugcheckDriver => "recorded_bugcheck_driver",
                    CulpritEvidenceKind::BugcheckFaultAddress => "bugcheck_fault_address",
                    CulpritEvidenceKind::ExceptionAddress => "exception_address",
                    CulpritEvidenceKind::CurrentInstruction => "current_instruction",
                    CulpritEvidenceKind::TopFrame => "top_frame",
                    CulpritEvidenceKind::PowerFailureDriver => "power_failure_driver",
                    CulpritEvidenceKind::PnpLockOwnerStack => "pnp_lock_owner_stack",
                    CulpritEvidenceKind::FirstNonSystemFrame => "first_non_system_frame",
                },
                detail: evidence.detail.clone(),
                address: evidence.address,
            })
            .collect(),
    }
}

fn verifier(verifier: &VerifierFindingDetail) -> VerifierFinding {
    VerifierFinding {
        bugcheck_code: verifier.bugcheck_code,
        bugcheck_name: verifier.bugcheck_name.clone(),
        subcode: verifier.subcode,
        known_subcode: verifier.known_subcode,
        subcode_description: verifier.subcode_description.clone(),
        associated_driver: verifier.associated_driver.clone(),
        arguments: verifier
            .arguments
            .iter()
            .map(|argument| VerifierFindingArgument {
                value: argument.value,
                description: argument.description.clone(),
            })
            .collect(),
        addresses: verifier
            .addresses
            .iter()
            .map(|address| VerifierFindingAddress {
                role: address.role.clone(),
                address: address.address,
            })
            .collect(),
    }
}

fn whea(whea: &WheaFindingDetail) -> WheaFinding {
    const SECTION_LIMIT: usize = 64;
    WheaFinding {
        record_address: whea.record_address,
        record: match &whea.state {
            WheaRecordState::Unavailable { reason } => DiagnosticValue::unavailable(reason.clone()),
            WheaRecordState::Decoded(record) => DiagnosticValue::Available(WheaRecord {
                revision: record.revision,
                severity: record.severity,
                length: record.length,
                sections_total: record.sections.len(),
                sections: record
                    .sections
                    .iter()
                    .take(SECTION_LIMIT)
                    .map(|section| WheaSection {
                        offset: section.offset,
                        length: section.length,
                        severity: section.severity,
                        section_type: section.section_type.clone(),
                        kind: match section.kind {
                            WheaSectionKind::ProcessorGeneric => "processor_generic",
                            WheaSectionKind::Memory => "memory",
                            WheaSectionKind::PciExpress => "pci_express",
                            WheaSectionKind::X64Processor => "x64_processor",
                            WheaSectionKind::Unknown => "unknown",
                        },
                    })
                    .collect(),
            }),
        },
    }
}

fn blackbox(blackbox: &BlackboxFinding) -> BlackboxStream {
    let kind = match blackbox.kind {
        BlackboxKind::Pnp => "pnp",
        BlackboxKind::Ntfs => "ntfs",
        BlackboxKind::Bsd => "bsd",
        BlackboxKind::Winlogon => "winlogon",
    };
    let (present, summary, reason) = match &blackbox.state {
        BlackboxState::Decoded { summary } => (true, Some(summary.clone()), None),
        BlackboxState::Malformed { reason } => (true, None, Some(reason.clone())),
        BlackboxState::Absent => (false, None, Some("not in this dump".to_string())),
    };
    BlackboxStream {
        kind,
        name: blackbox.name.clone(),
        command: blackbox.command,
        size: blackbox.size,
        present,
        summary,
        reason,
    }
}

fn unloaded_driver(driver: &dmp::UnloadedDriver) -> UnloadedDriver {
    UnloadedDriver {
        name: driver.name.clone(),
        start_address: driver.start_address,
        end_address: driver.end_address,
    }
}

fn power_failure(finding: &PowerDetail) -> PowerFailure {
    let failure = &finding.failure;
    let diagnostic = |value: &std::result::Result<DeviceStackDetail, String>| match value {
        Ok(stack) => DiagnosticValue::Available(stack.clone()),
        Err(error) => DiagnosticValue::unavailable(error.clone()),
    };
    PowerFailure {
        subtype: failure.subtype,
        description: failure.description,
        device: failure.device.map(|device| device.0),
        device_stack: failure.stack.as_ref().map(diagnostic),
        blocked_irp: failure.blocked_irp.as_ref().map(|blocked| BlockedPowerIrp {
            irp: blocked.irp.0,
            holder: blocked.holder.clone(),
            data: blocked.data.clone(),
        }),
        irps: failure.irps.clone(),
        workers: failure.workers.clone(),
        pnp_lock_owner: failure.pnp_lock_owner.map(|thread| thread.0),
        timeout_seconds: failure.timeout_seconds,
        culprit: failure.culprit.as_ref().map(|culprit| PowerFailureCulprit {
            driver: culprit.driver.clone(),
            device: culprit.device.0,
            reason: culprit.reason.clone(),
        }),
        threads: finding
            .threads
            .iter()
            .map(|thread| {
                let (role, irp, device) = match thread.role {
                    PowerThreadRole::IrpWorker { irp, device } => {
                        ("irp_worker", Some(irp.0), Some(device.0))
                    }
                    PowerThreadRole::PnpLockOwner => ("pnp_lock_owner", None, None),
                };
                PowerFailureThread {
                    role,
                    thread: thread.thread.0,
                    irp,
                    device,
                    stack: match &thread.stack {
                        Ok(trace) => DiagnosticValue::Available(stack_frames(&trace.frames)),
                        Err(error) => DiagnosticValue::unavailable(error.clone()),
                    },
                }
            })
            .collect(),
        notes: failure.notes.clone(),
    }
}

/// Canonical structured crash-triage shape used by MCP and Python. The caller
/// chooses its module cap; all other collections are already bounded by the
/// presentation-free report builder.
pub fn triage_report(report: &ReportDetail, module_limit: usize) -> TriageReport {
    TriageReport {
        status: run_status(&report.status),
        bugcheck: report.bugcheck.as_ref().map(bugcheck),
        exception: report.exception.as_ref().map(dump_exception),
        system_info: report.system_info.as_ref().map(system_info),
        backtrace: report
            .backtrace
            .as_ref()
            .map(|trace| stack_frames(&trace.frames)),
        modules: report.modules.iter().take(module_limit).cloned().collect(),
        modules_total: report.modules.len(),
        unloaded_drivers: report
            .unloaded_drivers
            .iter()
            .map(unloaded_driver)
            .collect(),
        crash_context: report.crash_context.as_ref().map(crash_context),
        prcb: report.prcb.as_ref().map(prcb),
        broken_driver: report.broken_driver.clone(),
        triage_overflowed: report.triage_overflowed,
        failure_signature: report.failure_signature.as_ref().map(failure_signature),
        culprit: report.culprit.as_ref().map(culprit),
        verifier: report.verifier.as_ref().map(verifier),
        whea: report.whea.as_ref().map(whea),
        blackboxes: report.blackboxes.iter().map(blackbox).collect(),
        power: report.power.as_ref().map(power_failure),
        user: report.user.as_ref().map(user_dump_triage),
        warnings: report.warnings.clone(),
    }
}

fn code_owner(owner: &CodeOwnerDetail) -> UserTriageCodeOwner {
    match owner {
        CodeOwnerDetail::Module { name, system } => UserTriageCodeOwner {
            kind: "module",
            module: Some(name.clone()),
            system: *system,
            region: None,
            table_start: None,
            table_end: None,
        },
        CodeOwnerDetail::DynamicCode {
            table_start,
            table_end,
        } => UserTriageCodeOwner {
            kind: "dynamic_code",
            module: None,
            system: false,
            region: None,
            table_start: Some(*table_start),
            table_end: Some(*table_end),
        },
        CodeOwnerDetail::Unowned { region } => UserTriageCodeOwner {
            kind: "unowned",
            module: None,
            system: false,
            region: region.clone(),
            table_start: None,
            table_end: None,
        },
    }
}

fn user_frame(frame: &UserFrame) -> UserTriageFrame {
    UserTriageFrame {
        index: frame.index,
        ip: frame.ip,
        symbol: frame.symbol.clone(),
        source: frame.source.as_str(),
        owner: code_owner(&frame.owner),
    }
}

fn user_exception(exception: &UserExceptionFinding) -> UserTriageException {
    UserTriageException {
        code: exception.code,
        kind: match exception.kind {
            UserExceptionKind::Ntstatus => "ntstatus",
            UserExceptionKind::CppException => "cpp_exception",
            UserExceptionKind::ClrException => "clr_exception",
            UserExceptionKind::WellKnown => "well_known",
            UserExceptionKind::ApplicationDefined => "application_defined",
            UserExceptionKind::Unknown => "unknown",
        },
        name: exception.name,
        flags: exception.flags,
        flag_names: exception.flag_names.clone(),
        record: exception.record,
        address: exception.address,
        symbol: exception.symbol.clone(),
        module: code_owner(&exception.address_owner),
        parameters: exception
            .parameters
            .iter()
            .map(|parameter| UserTriageExceptionParameter {
                value: parameter.value,
                label: parameter.label,
                meaning: parameter.meaning.clone(),
            })
            .collect(),
        summary: exception.summary.clone(),
        thread_id: exception.thread_id,
        thread: exception.thread.clone(),
        thread_name: exception.thread_name.clone(),
        faulting_frame: exception.faulting_frame,
        blamed_frame: exception.blamed_frame.as_ref().map(user_frame),
        module_caller: exception.module_caller.as_ref().map(user_frame),
    }
}

fn user_dump_triage(user: &UserDumpDetail) -> UserTriage {
    let process = &user.process;
    UserTriage {
        process: UserTriageProcess {
            name: process.name.clone(),
            pid: process.pid,
            arch: process.arch.label(),
            major_version: process.major_version,
            minor_version: process.minor_version,
            build_number: process.build_number,
            build_string: process.build_string.clone(),
            dump_time: unix_time_to_iso(u64::from(process.dump_time)),
            create_time: process
                .create_time
                .and_then(|time| unix_time_to_iso(u64::from(time))),
            user_time_secs: process.cpu_times.map(|(user, _)| user),
            kernel_time_secs: process.cpu_times.map(|(_, kernel)| kernel),
            threads: process.threads,
            modules: process.modules,
            unloaded_modules: process.unloaded_modules,
            handles: process.handles,
        },
        exception: user.exception.as_ref().map(user_exception),
        stack_thread: user
            .stack_thread
            .as_ref()
            .map(|thread| UserTriageStackThread {
                tid: thread.tid,
                id: thread.id.clone(),
                name: thread.name.clone(),
                source: match thread.source {
                    UserStackSource::ExceptionContext => "exception_context",
                    UserStackSource::ThreadContext => "thread_context",
                },
            }),
        exception_registers: user
            .exception_registers
            .iter()
            .map(|(name, value)| UserTriageRegister {
                name: name.clone(),
                value: *value,
            })
            .collect(),
    }
}
