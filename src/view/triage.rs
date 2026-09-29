//! Crash-triage [`View`] builders: the triage report and the
//! dump metadata, failure signature, and findings it aggregates.

use super::bugcheck::{Bugcheck, bugcheck};
use super::execution::{run_status, stack_frames};
use super::module::module;
use super::shape::{Diag, Hex, shapes};
use crate::dmp::{self, DmpException, DmpSystemInfo, TriageCrashInfo};
use crate::triage::TriagePrcbInfo;
use crate::triage_report::{
    BlackboxFinding, BlackboxKind, BlackboxState, CulpritAttribution, CulpritConfidence,
    CulpritEvidenceKind, FailureCodeKind, FailureSignatureSource, WheaRecordState,
    WheaSectionKind, exception_code_name, time::filetime_to_iso,
};
use crate::triage_report::{
    FailureSignature as SignatureDetail, TriageReport as ReportDetail,
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
        /// The time when the system made the dump (ISO 8601 UTC). `None` if
        /// the dump does not record it.
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
        /// The time when the process started (ISO 8601 UTC). Also `None` if
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
        /// `exception_address`, `current_instruction`, `top_frame`, or
        /// `code_only`.
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

    /// The module that the available evidence identifies as the cause of the
    /// crash.
    Culprit {
        module: String,
        /// `low`, `medium`, or `high`.
        confidence: &'static str,
        /// The evidence that points to the module.
        evidence: Vec<CulpritEvidence>,
    }

    /// One item of evidence for a culprit attribution.
    CulpritEvidence {
        /// `recorded_broken_driver`, `recorded_bugcheck_driver`,
        /// `bugcheck_fault_address`, `exception_address`,
        /// `current_instruction`, or `top_frame`.
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

    /// A blackbox stream (pnp, ntfs, bsd, winlogon) of a crash dump, whose
    /// payload ntoseye does not parse.
    BlackboxStream {
        /// `pnp`, `ntfs`, `bsd`, or `winlogon`.
        kind: &'static str,
        /// The stream's recorded name.
        name: String,
        /// The stream's size in bytes, when recorded.
        size: Option<u64>,
        /// `True` if the dump records the stream. `None` if the dump has no
        /// stream directory that shows this.
        present: Option<bool>,
        /// `True` if the payload is available. Always `False`.
        available: bool,
        /// `True` if ntoseye parsed the payload. Always `False`.
        parsed: bool,
        /// The reason that the payload is not available.
        reason: String,
    }

    /// A driver that the system unloaded recently, as the crash dump records
    /// it.
    UnloadedDriver {
        name: String,
        start_address: Hex,
        end_address: Hex,
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
        /// The module that the evidence identifies as the cause. `None` if
        /// the evidence does not identify a non-kernel module.
        culprit: Option<Culprit>,
        /// The Driver Verifier violation of a verifier bugcheck.
        verifier: Option<VerifierFinding>,
        /// The hardware error record of a WHEA bugcheck.
        whea: Option<WheaFinding>,
        blackboxes: Vec<BlackboxStream>,
        /// Failures in best-effort data collection that did not stop the
        /// report.
        warnings: Vec<String>,
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
    Culprit {
        module: culprit.module.clone(),
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
    let (present, reason) = match &blackbox.state {
        BlackboxState::Unavailable { reason } => (None, reason.clone()),
        BlackboxState::PresentUnparsed => (
            Some(true),
            "stream payload is not exposed by the dump parser".to_string(),
        ),
    };
    BlackboxStream {
        kind,
        name: blackbox.name.clone(),
        size: blackbox.size,
        present,
        available: false,
        parsed: false,
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
        warnings: report.warnings.clone(),
    }
}
