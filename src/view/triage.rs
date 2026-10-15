//! Crash-triage [`View`] builders: the triage report and the
//! dump metadata, failure signature, and findings it aggregates.

use super::bugcheck::{Bugcheck, bugcheck};
use super::execution::{run_status, stack_frames};
use super::module::module;
use super::pnp::device_stack;
use super::power::{power_driver, power_irp, power_irp_holder, power_irp_list, power_worker_list};
use super::shape::{Diag, Hex, shapes};
use crate::dmp::triage::TriagePrcbInfo;
use crate::dmp::{self, DmpException, DmpSystemInfo};
use crate::triage_report::{
    BlackboxFinding, BlackboxKind, BlackboxState, CodeOwner as CodeOwnerDetail,
    CulpritAttribution, CulpritConfidence, CulpritEvidenceKind, CulpritSubject, FailureCodeKind,
    FailureSignatureSource, PowerFailureFinding as PowerDetail, PowerThreadRole,
    UserDumpTriage as UserDumpDetail, UserExceptionFinding, UserExceptionKind, UserFrame,
    UserStackSource, WheaRecordState, WheaSectionKind, exception_code_name,
    time::{filetime_to_iso, unix_time_to_iso},
};
use crate::triage_report::{
    FailureSignature as SignatureDetail, TriageCrashInfo, TriageReport as ReportDetail,
    VerifierFinding as VerifierFindingDetail, WheaFinding as WheaFindingDetail,
};
use crate::target::DiagnosticValue;

shapes! {
    /// The exception a crash dump recorded.
    DumpException {
        /// The exception code (NTSTATUS).
        code: u32,
        /// The same code in hex.
        code_hex: Hex<u32>,
        /// The code's symbolic name.
        code_name: String,
        flags: u32,
        /// Where the exception occurred.
        address: Hex,
        /// The exception's `ExceptionInformation` parameters.
        parameters: Vec<Hex>,
    }

    /// The system that a crash dump comes from, as the system-info stream of
    /// the dump records it.
    DumpSystemInfo {
        major_version: u32,
        /// The build number (the stream's minor version).
        build: u32,
        service_pack_build: u32,
        /// The machine type (`IMAGE_FILE_MACHINE_*`).
        machine_image_type: Hex<u32>,
        /// `I386`, `AMD64`, `ARM64`, or `Unknown`.
        machine: &'static str,
        /// The time when the dump was taken (ISO 8601 UTC). `None` if the dump
        /// does not record it.
        system_time: Option<String>,
        /// The system uptime in seconds. `None` if the dump does not record
        /// it.
        system_up_time_secs: Option<u64>,
        /// `Workstation`, `DomainController`, `Server`, or `Unknown`.
        product_type: &'static str,
        /// The product suite (`VER_SUITE_*`) bits.
        suite_mask: Hex<u32>,
    }

    /// The process and thread that crashed, as a triage dump recorded them.
    /// A field is `None` if the dump does not record it.
    CrashContext {
        process_name: Option<String>,
        process_id: Option<u64>,
        thread_id: Option<u64>,
        parent_process_id: Option<u64>,
        /// The process's exit status (NTSTATUS).
        exit_status: Option<Hex>,
        /// The time when the process was created (ISO 8601 UTC). Also `None` if
        /// ntoseye cannot convert the recorded time.
        create_time: Option<String>,
        /// The thread's exit status (NTSTATUS).
        thread_exit_status: Option<Hex>,
    }

    /// The main `_KPRCB` data of the crashed processor, as a triage dump
    /// recorded it.
    TriagePrcb {
        /// The `_KTHREAD` running on the processor.
        current_thread: Hex,
        processor_number: u16,
        /// The processor's clock speed in MHz.
        mhz: u32,
        cpu_type: u16,
        /// The CPU vendor (`GenuineIntel`, `AuthenticAMD`, ...).
        vendor_string: String,
    }

    /// A deterministic identity for a failure that does not depend on
    /// addresses, so you can use it to compare failures.
    FailureSignature {
        /// `bugcheck` or `exception`.
        code_kind: &'static str,
        /// The bugcheck or exception code.
        code: Hex<u32>,
        /// The source of the failing location: `bugcheck_fault`,
        /// `exception_address`, `current_instruction`, `top_frame`,
        /// `power_failure_driver` (the driver a 0x9F names),
        /// `first_non_system_frame` (on a user-mode minidump, the first frame
        /// outside the system modules), or `code_only`.
        source: &'static str,
        /// The module at the failing location.
        module: Option<String>,
        /// The symbol at the failing location.
        symbol: Option<String>,
        /// The ordered parts that make `bucket`.
        components: Vec<String>,
        /// The failure bucket.
        bucket: String,
    }

    /// What the available evidence identifies as the cause of the crash: a
    /// module, or on a user-mode minidump, generated code no module holds.
    Culprit {
        /// `module`, or `dynamic_code` (JIT-compiled or generated code that
        /// a dynamic function table covers; see `dynamic_code`).
        kind: &'static str,
        /// The module. `None` for `dynamic_code`.
        module: Option<String>,
        /// The generated code, for `dynamic_code`.
        dynamic_code: Option<CulpritDynamicCode>,
        /// `low`, `medium`, or `high`.
        confidence: &'static str,
        /// The evidence that points to the culprit.
        evidence: Vec<CulpritEvidence>,
    }

    /// Generated code a culprit attribution names: no module holds it, and
    /// a dynamic function table the process registered covers it.
    CulpritDynamicCode {
        /// The blamed frame's address.
        address: Hex,
        /// The start of the dynamic function table's range.
        table_start: Hex,
        /// The end (exclusive) of the table's range.
        table_end: Hex,
        /// The first frame further out that a module holds: the module
        /// code that called into the generated code.
        caller: Option<UserTriageFrame>,
    }

    /// One item of evidence for a culprit attribution.
    CulpritEvidence {
        /// `recorded_broken_driver`, `recorded_bugcheck_driver`,
        /// `bugcheck_fault_address`, `exception_address`,
        /// `current_instruction`, `top_frame`, `power_failure_driver`,
        /// `pnp_lock_owner_stack`, or `first_non_system_frame`.
        kind: &'static str,
        detail: String,
        /// The address that the evidence uses, if the evidence is an address.
        address: Option<Hex>,
    }

    /// A Driver Verifier bugcheck, decoded from its subcode.
    VerifierFinding {
        bugcheck_code: Hex<u32>,
        bugcheck_name: String,
        /// The verifier subcode (the first bugcheck parameter).
        subcode: Hex,
        /// `True` if the decoder recognizes the subcode.
        known_subcode: bool,
        /// What the subcode means, or `unknown verifier subcode`.
        subcode_description: String,
        /// The driver that ntoseye attributes the violation to.
        associated_driver: Option<String>,
        /// The bugcheck parameters, with descriptions for the subcode.
        arguments: Vec<VerifierFindingArgument>,
        /// The addresses in the parameters, with their roles.
        addresses: Vec<VerifierFindingAddress>,
    }

    /// A verifier bugcheck parameter and what it means for the subcode.
    VerifierFindingArgument {
        value: Hex,
        description: String,
    }

    /// An address in a verifier bugcheck, and its role.
    VerifierFindingAddress {
        role: String,
        address: Hex,
    }

    /// The WHEA error record of a hardware-error bugcheck.
    WheaFinding {
        /// The address of the record. `None` if the bugcheck does not give
        /// one.
        record_address: Option<Hex>,
        /// The decoded record, or the reason that decoding failed.
        record: Diag<WheaRecord>,
    }

    /// A decoded WHEA error record.
    WheaRecord {
        revision: Hex<u16>,
        /// The record's error severity (`WHEA_ERROR_SEVERITY`).
        severity: u32,
        /// The record's length in bytes.
        length: u32,
        /// The number of sections in the record. `sections` holds at most 64.
        sections_total: usize,
        sections: Vec<WheaSection>,
    }

    /// One section of a WHEA error record.
    WheaSection {
        /// The section's offset in the record, in bytes.
        offset: u32,
        /// The section's length in bytes.
        length: u32,
        /// The section's error severity.
        severity: u32,
        /// The section type GUID.
        section_type: String,
        /// `processor_generic`, `memory`, `pci_express`, `x64_processor`, or
        /// `unknown`.
        kind: &'static str,
    }

    /// A blackbox record (pnp, ntfs, bsd, winlogon) of a crash dump: a block
    /// of its tagged data that ntoseye decodes as WinDbg's `!blackbox*`
    /// commands do.
    BlackboxStream {
        /// `pnp`, `ntfs`, `bsd`, or `winlogon`.
        kind: &'static str,
        /// `PnP`, `NTFS`, `BSD`, or `Winlogon`.
        name: String,
        /// The command that shows the whole record, such as `!blackboxpnp`.
        command: &'static str,
        /// The block's size in bytes. None if the dump has no block.
        size: Option<u64>,
        /// `True` if the dump has the block.
        present: bool,
        /// What the record holds, in one line. None if it does not decode.
        summary: Option<String>,
        /// Why the record does not decode, or that the dump has none. None
        /// if it decodes.
        reason: Option<String>,
    }

    /// A driver that the system unloaded recently, as the crash dump records
    /// it.
    UnloadedDriver {
        name: String,
        start_address: Hex,
        end_address: Hex,
    }

    /// The IRP that a 0x9F/0x3 names, and where it is pending.
    BlockedPowerIrp {
        irp: Hex,
        /// The driver of the IRP's current stack location.
        holder: Diag<super::power::PowerIrpHolder>,
        /// The IRP's entry on the power IRP list. `None` when it is not on
        /// the list.
        data: Option<super::power::PowerIrp>,
    }

    /// The driver that a DRIVER_POWER_STATE_FAILURE names, and why.
    PowerFailureCulprit {
        driver: super::power::PowerDriver,
        /// The device object that ties the driver to the failure.
        device: Hex,
        reason: String,
    }

    /// A thread that a DRIVER_POWER_STATE_FAILURE names, with its stack.
    PowerFailureThread {
        /// `irp_worker` or `pnp_lock_owner`.
        role: &'static str,
        thread: Hex,
        /// For an IRP worker, the IRP it is passing to a driver; 0 while it
        /// waits.
        irp: Option<Hex>,
        device: Option<Hex>,
        stack: Diag<Vec<super::execution::StackFrame>>,
    }

    /// What a DRIVER_POWER_STATE_FAILURE (0x9F) names as stuck.
    PowerFailure {
        /// Parameter 1.
        subtype: Hex,
        description: &'static str,
        /// The device object that the parameters name.
        device: Option<Hex>,
        /// The stack of `device`.
        device_stack: Option<Diag<super::pnp::DeviceStack>>,
        /// 0x3: the blocked IRP.
        blocked_irp: Option<BlockedPowerIrp>,
        /// 0x3: the power IRPs on the list that `TRIAGE_9F_POWER` names.
        irps: Option<super::power::PowerIrpList>,
        /// 0x3: the IRP worker threads on the list that `TRIAGE_9F_POWER`
        /// names.
        workers: Option<super::power::PowerWorkerList>,
        /// 0x4: the thread that holds the PnP lock.
        pnp_lock_owner: Option<Hex>,
        /// 0x4: the timeout in seconds.
        timeout_seconds: Option<u64>,
        culprit: Option<PowerFailureCulprit>,
        /// The IRP worker threads and the PnP lock owner, with their stacks.
        threads: Vec<PowerFailureThread>,
        /// What could not be read, and why.
        notes: Vec<String>,
    }

    /// The one-shot crash triage report (`!analyze`), with the run status, the
    /// bugcheck or exception, the backtrace, the modules, the dump records,
    /// and the findings.
    TriageReport {
        /// The target's run status.
        status: super::execution::RunStatus,
        /// The bugcheck, if the target is in a bugcheck.
        bugcheck: Option<Bugcheck>,
        /// The exception that a dump recorded.
        exception: Option<DumpException>,
        /// The system information of the dump.
        system_info: Option<DumpSystemInfo>,
        /// The stack of the current thread. `None` while the target runs or
        /// if the unwind failed (see `warnings`).
        backtrace: Option<Vec<super::execution::StackFrame>>,
        /// The loaded modules, up to a maximum that the caller sets (see
        /// `modules_total`).
        modules: Vec<super::module::LoadedModule>,
        /// The number of loaded modules.
        modules_total: usize,
        unloaded_drivers: Vec<UnloadedDriver>,
        /// The process and thread that crashed, as a triage dump recorded them.
        crash_context: Option<CrashContext>,
        /// The processor that crashed, as a triage dump recorded it.
        prcb: Option<TriagePrcb>,
        /// The driver that the dump records as broken.
        broken_driver: Option<String>,
        /// `True` if the triage data of the dump overflowed. `None` if the
        /// target is not a dump.
        triage_overflowed: Option<bool>,
        failure_signature: Option<FailureSignature>,
        /// What the evidence identifies as the cause: a module, or on a
        /// user-mode minidump, JIT-compiled code. `None` if the evidence
        /// identifies neither a non-kernel (or, on a user dump, non-system)
        /// module nor generated code.
        culprit: Option<Culprit>,
        /// The Driver Verifier violation of a verifier bugcheck.
        verifier: Option<VerifierFinding>,
        /// The hardware error record of a WHEA bugcheck.
        whea: Option<WheaFinding>,
        blackboxes: Vec<BlackboxStream>,
        /// What a DRIVER_POWER_STATE_FAILURE names as stuck.
        power: Option<PowerFailure>,
        /// What a user-mode minidump adds: the process, the exception
        /// decoded, and the frame the failure is blamed on. `None` for a
        /// kernel target, whose bugcheck and kernel findings do not apply to
        /// a user dump.
        user: Option<UserTriage>,
        /// Failures in best-effort data collection that did not stop the
        /// report.
        warnings: Vec<String>,
    }

    /// The triage of a user-mode minidump.
    UserTriage {
        process: UserTriageProcess,
        /// The exception the dump was written for. `None` if it records
        /// none.
        exception: Option<UserTriageException>,
        /// The thread whose stack `backtrace` is. `None` if no thread is
        /// selected.
        stack_thread: Option<UserTriageStackThread>,
        /// The general-purpose registers of the exception's context, in
        /// display order. Empty without an exception or when its context is
        /// unusable.
        exception_registers: Vec<UserTriageRegister>,
    }

    /// The captured process, as the dump's streams record it.
    UserTriageProcess {
        /// The executable's file name.
        name: Option<String>,
        pid: Option<u32>,
        /// `AMD64` or `ARM64`.
        arch: &'static str,
        major_version: u32,
        minor_version: u32,
        build_number: u32,
        /// The full build string (`MINIDUMP_MISC_INFO_4.BuildString`).
        build_string: Option<String>,
        /// When the dump was written (ISO 8601 UTC).
        dump_time: Option<String>,
        /// When the process was created (ISO 8601 UTC).
        create_time: Option<String>,
        /// User-mode time the process had run, in seconds.
        user_time_secs: Option<u32>,
        /// Kernel-mode time the process had run, in seconds.
        kernel_time_secs: Option<u32>,
        threads: usize,
        modules: usize,
        unloaded_modules: usize,
        /// `None` if the dump has no handle stream.
        handles: Option<usize>,
    }

    /// The thread a user dump report's stack belongs to.
    UserTriageStackThread {
        tid: u32,
        /// The id as `~` lists it (`<pid>.<tid>` in hex).
        id: String,
        name: Option<String>,
        /// `exception_context` (walked from the exception's CONTEXT) or
        /// `thread_context` (the selected thread's).
        source: &'static str,
    }

    /// A register of the exception's context.
    UserTriageRegister {
        name: String,
        value: Hex,
    }

    /// The exception a user-mode minidump was written for, decoded.
    UserTriageException {
        code: Hex<u32>,
        /// `ntstatus`, `cpp_exception`, `clr_exception`, `well_known`,
        /// `application_defined` (customer bit set, no name), or `unknown`.
        kind: &'static str,
        /// The code's name, or what kind of code it is when it has none.
        name: &'static str,
        flags: Hex<u32>,
        /// The `EXCEPTION_*` flags set, with unknown bits in hex.
        flag_names: Vec<String>,
        /// The address of a chained exception record; 0 for none.
        record: Hex,
        address: Hex,
        symbol: String,
        /// What holds the exception address: the faulting module.
        module: UserTriageCodeOwner,
        parameters: Vec<UserTriageExceptionParameter>,
        /// What the parameters say in one line, such as `write to 0x10`.
        summary: Option<String>,
        thread_id: u32,
        /// The faulting thread's id as `~` lists it.
        thread: String,
        thread_name: Option<String>,
        /// The index in `backtrace` of the frame at the exception address.
        faulting_frame: Option<usize>,
        /// The first frame from the faulting one outward outside the system
        /// modules (ntdll, kernelbase, the C++ and .NET runtimes): the code
        /// the failure is blamed on. `None` if every frame is in a system
        /// module.
        blamed_frame: Option<UserTriageFrame>,
        /// When `blamed_frame` is in no module, the first frame further out
        /// that a module holds: the module code that called into it.
        module_caller: Option<UserTriageFrame>,
    }

    /// One `ExceptionInformation` entry of a user dump's exception.
    UserTriageExceptionParameter {
        value: Hex,
        /// What the entry is for the code (`access`, `address`,
        /// `ThrowInfo`, ...). `None` if the code defines no meaning.
        label: Option<&'static str>,
        /// The value decoded (`write`, a status name, a module).
        meaning: Option<String>,
    }

    /// What holds a code address of a user dump.
    UserTriageCodeOwner {
        /// `module`, `dynamic_code` (no module; a dynamic function table
        /// covers it, as for JIT-compiled code), or `unowned`.
        kind: &'static str,
        module: Option<String>,
        /// Whether the module is part of Windows or a language runtime.
        system: bool,
        /// For `unowned`, the memory region as the dump's memory-info list
        /// records it.
        region: Option<String>,
        /// For `dynamic_code`, the range of the dynamic function table that
        /// covers the address.
        table_start: Option<Hex>,
        table_end: Option<Hex>,
    }

    /// A frame of a user dump report's stack.
    UserTriageFrame {
        /// The frame's index in `backtrace`.
        index: usize,
        ip: Hex,
        symbol: String,
        /// How the frame was recovered (`unwind`, `scan`, ...).
        source: &'static str,
        owner: UserTriageCodeOwner,
    }
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
    let diagnostic = |value: &std::result::Result<_, String>| match value {
        Ok(stack) => DiagnosticValue::Available(device_stack(stack)),
        Err(error) => DiagnosticValue::unavailable(error.clone()),
    };
    PowerFailure {
        subtype: failure.subtype,
        description: failure.description,
        device: failure.device.map(|device| device.0),
        device_stack: failure.stack.as_ref().map(diagnostic),
        blocked_irp: failure.blocked_irp.as_ref().map(|blocked| BlockedPowerIrp {
            irp: blocked.irp.0,
            holder: match &blocked.holder {
                Ok(holder) => DiagnosticValue::Available(power_irp_holder(holder)),
                Err(error) => DiagnosticValue::unavailable(error.clone()),
            },
            data: blocked.data.as_ref().map(power_irp),
        }),
        irps: failure.irps.as_ref().map(power_irp_list),
        workers: failure.workers.as_ref().map(power_worker_list),
        pnp_lock_owner: failure.pnp_lock_owner.map(|thread| thread.0),
        timeout_seconds: failure.timeout_seconds,
        culprit: failure
            .culprit
            .as_ref()
            .map(|culprit| PowerFailureCulprit {
                driver: power_driver(&culprit.driver),
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
        modules: report
            .modules
            .iter()
            .take(module_limit)
            .map(module)
            .collect(),
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
