//! Crash-triage [`View`](super::View) builders: the triage report and the
//! dump metadata, failure signature, and findings it aggregates.

use super::View;
use super::bugcheck::bugcheck;
use super::execution::{run_status, stack_frame};
use super::module::module;
use crate::dmp::{DmpException, DmpSystemInfo, TriageCrashInfo, UnloadedDriver};
use crate::triage::TriagePrcbInfo;
use crate::triage_report::{
    BlackboxFinding, BlackboxKind, BlackboxState, CulpritAttribution, CulpritConfidence,
    CulpritEvidenceKind, FailureCodeKind, FailureSignature, FailureSignatureSource, TriageReport,
    VerifierFinding, WheaFinding, WheaRecordState, WheaSectionKind, exception_code_name,
    filetime_to_iso,
};

pub fn dump_exception(exception: &DmpException) -> View {
    View::Object(vec![
        ("code", View::Num(exception.code.into())),
        ("code_hex", View::Hex(exception.code.into())),
        (
            "code_name",
            View::Str(exception_code_name(exception.code).to_string()),
        ),
        ("flags", View::Num(exception.flags.into())),
        ("address", View::Hex(exception.address)),
        (
            "parameters",
            View::List(
                exception
                    .parameters
                    .iter()
                    .copied()
                    .map(View::Hex)
                    .collect(),
            ),
        ),
    ])
}

pub fn system_info(info: &DmpSystemInfo) -> View {
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
    View::Object(vec![
        ("major_version", View::Num(info.major_version.into())),
        ("build", View::Num(info.minor_version.into())),
        (
            "service_pack_build",
            View::Num(info.service_pack_build.into()),
        ),
        (
            "machine_image_type",
            View::Hex(info.machine_image_type.into()),
        ),
        ("machine", View::Str(machine.to_string())),
        (
            "system_time",
            View::OptStr(
                (info.system_time != 0)
                    .then(|| filetime_to_iso(info.system_time as u64))
                    .flatten(),
            ),
        ),
        (
            "system_up_time_secs",
            View::OptNum(
                (info.system_up_time > 0)
                    .then(|| u64::try_from(info.system_up_time / 10_000_000).ok())
                    .flatten(),
            ),
        ),
        ("product_type", View::Str(product.to_string())),
        ("suite_mask", View::Hex(info.suite_mask.into())),
    ])
}

pub fn crash_context(context: &TriageCrashInfo) -> View {
    let mut fields = vec![
        ("process_name", View::OptStr(context.process_name.clone())),
        ("process_id", View::OptNum(context.process_id)),
        ("thread_id", View::OptNum(context.thread_id)),
    ];
    if let Some(parent_process_id) = context.parent_process_id {
        fields.push(("parent_process_id", View::Num(parent_process_id)));
    }
    if let Some(exit_status) = context.exit_status {
        fields.push(("exit_status", View::Hex(exit_status as u64)));
    }
    if let Some(create_time) = context.create_time {
        fields.push(("create_time", View::OptStr(filetime_to_iso(create_time))));
    }
    if let Some(exit_status) = context.thread_exit_status {
        fields.push(("thread_exit_status", View::Hex(exit_status as u64)));
    }
    View::Object(fields)
}

pub fn prcb(prcb: &TriagePrcbInfo) -> View {
    View::Object(vec![
        ("current_thread", View::Hex(prcb.current_thread)),
        ("processor_number", View::Num(prcb.processor_number.into())),
        ("mhz", View::Num(prcb.mhz.into())),
        ("cpu_type", View::Num(prcb.cpu_type.into())),
        ("vendor_string", View::Str(prcb.vendor_string.clone())),
    ])
}

fn failure_signature(signature: &FailureSignature) -> View {
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
    View::Object(vec![
        ("code_kind", View::Str(code_kind.to_string())),
        ("code", View::Hex(signature.code.into())),
        ("source", View::Str(source.to_string())),
        ("module", View::OptStr(signature.module.clone())),
        ("symbol", View::OptStr(signature.symbol.clone())),
        (
            "components",
            View::List(
                signature
                    .components
                    .iter()
                    .cloned()
                    .map(View::Str)
                    .collect(),
            ),
        ),
        ("bucket", View::Str(signature.bucket.clone())),
    ])
}

fn culprit(culprit: &CulpritAttribution) -> View {
    let confidence = match culprit.confidence {
        CulpritConfidence::Low => "low",
        CulpritConfidence::Medium => "medium",
        CulpritConfidence::High => "high",
    };
    View::Object(vec![
        ("module", View::Str(culprit.module.clone())),
        ("confidence", View::Str(confidence.to_string())),
        (
            "evidence",
            View::List(
                culprit
                    .evidence
                    .iter()
                    .map(|evidence| {
                        let kind = match evidence.kind {
                            CulpritEvidenceKind::RecordedBrokenDriver => "recorded_broken_driver",
                            CulpritEvidenceKind::RecordedBugcheckDriver => {
                                "recorded_bugcheck_driver"
                            }
                            CulpritEvidenceKind::BugcheckFaultAddress => "bugcheck_fault_address",
                            CulpritEvidenceKind::ExceptionAddress => "exception_address",
                            CulpritEvidenceKind::CurrentInstruction => "current_instruction",
                            CulpritEvidenceKind::TopFrame => "top_frame",
                        };
                        View::Object(vec![
                            ("kind", View::Str(kind.to_string())),
                            ("detail", View::Str(evidence.detail.clone())),
                            ("address", View::OptHex(evidence.address)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn verifier(verifier: &VerifierFinding) -> View {
    View::Object(vec![
        ("bugcheck_code", View::Hex(verifier.bugcheck_code.into())),
        ("bugcheck_name", View::Str(verifier.bugcheck_name.clone())),
        ("subcode", View::Hex(verifier.subcode)),
        ("known_subcode", View::Bool(verifier.known_subcode)),
        (
            "subcode_description",
            View::Str(verifier.subcode_description.clone()),
        ),
        (
            "associated_driver",
            View::OptStr(verifier.associated_driver.clone()),
        ),
        (
            "arguments",
            View::List(
                verifier
                    .arguments
                    .iter()
                    .map(|argument| {
                        View::Object(vec![
                            ("value", View::Hex(argument.value)),
                            ("description", View::Str(argument.description.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "addresses",
            View::List(
                verifier
                    .addresses
                    .iter()
                    .map(|address| {
                        View::Object(vec![
                            ("role", View::Str(address.role.clone())),
                            ("address", View::Hex(address.address)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn whea(whea: &WheaFinding) -> View {
    const SECTION_LIMIT: usize = 64;
    match &whea.state {
        WheaRecordState::Unavailable { reason } => View::Object(vec![
            ("record_address", View::OptHex(whea.record_address)),
            ("available", View::Bool(false)),
            ("reason", View::Str(reason.clone())),
        ]),
        WheaRecordState::Decoded(record) => View::Object(vec![
            ("record_address", View::OptHex(whea.record_address)),
            ("available", View::Bool(true)),
            ("revision", View::Hex(record.revision.into())),
            ("severity", View::Num(record.severity.into())),
            ("length", View::Num(record.length.into())),
            ("sections_total", View::Num(record.sections.len() as u64)),
            (
                "sections",
                View::List(
                    record
                        .sections
                        .iter()
                        .take(SECTION_LIMIT)
                        .map(|section| {
                            let kind = match section.kind {
                                WheaSectionKind::ProcessorGeneric => "processor_generic",
                                WheaSectionKind::Memory => "memory",
                                WheaSectionKind::PciExpress => "pci_express",
                                WheaSectionKind::X64Processor => "x64_processor",
                                WheaSectionKind::Unknown => "unknown",
                            };
                            View::Object(vec![
                                ("offset", View::Num(section.offset.into())),
                                ("length", View::Num(section.length.into())),
                                ("severity", View::Num(section.severity.into())),
                                ("section_type", View::Str(section.section_type.clone())),
                                ("kind", View::Str(kind.to_string())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
    }
}

fn blackbox(blackbox: &BlackboxFinding) -> View {
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
    View::Object(vec![
        ("kind", View::Str(kind.to_string())),
        ("name", View::Str(blackbox.name.clone())),
        ("size", View::OptNum(blackbox.size)),
        ("present", View::OptBool(present)),
        ("available", View::Bool(false)),
        ("parsed", View::Bool(false)),
        ("reason", View::Str(reason)),
    ])
}

fn unloaded_driver(driver: &UnloadedDriver) -> View {
    View::Object(vec![
        ("name", View::Str(driver.name.clone())),
        ("start_address", View::Hex(driver.start_address)),
        ("end_address", View::Hex(driver.end_address)),
    ])
}

/// Canonical structured crash-triage shape used by MCP and Python. The caller
/// chooses its module cap; all other collections are already bounded by the
/// presentation-free report builder.
pub fn triage_report(report: &TriageReport, module_limit: usize) -> View {
    View::Object(vec![
        ("status", run_status(&report.status)),
        (
            "bugcheck",
            report.bugcheck.as_ref().map(bugcheck).unwrap_or(View::Null),
        ),
        (
            "exception",
            report
                .exception
                .as_ref()
                .map(dump_exception)
                .unwrap_or(View::Null),
        ),
        (
            "system_info",
            report
                .system_info
                .as_ref()
                .map(system_info)
                .unwrap_or(View::Null),
        ),
        (
            "backtrace",
            report
                .backtrace
                .as_ref()
                .map(|trace| View::List(trace.frames.iter().map(stack_frame).collect()))
                .unwrap_or(View::Null),
        ),
        (
            "modules",
            View::List(
                report
                    .modules
                    .iter()
                    .take(module_limit)
                    .map(module)
                    .collect(),
            ),
        ),
        ("modules_total", View::Num(report.modules.len() as u64)),
        (
            "unloaded_drivers",
            View::List(
                report
                    .unloaded_drivers
                    .iter()
                    .map(unloaded_driver)
                    .collect(),
            ),
        ),
        (
            "crash_context",
            report
                .crash_context
                .as_ref()
                .map(crash_context)
                .unwrap_or(View::Null),
        ),
        ("prcb", report.prcb.as_ref().map(prcb).unwrap_or(View::Null)),
        ("broken_driver", View::OptStr(report.broken_driver.clone())),
        ("triage_overflowed", View::OptBool(report.triage_overflowed)),
        (
            "failure_signature",
            report
                .failure_signature
                .as_ref()
                .map(failure_signature)
                .unwrap_or(View::Null),
        ),
        (
            "culprit",
            report.culprit.as_ref().map(culprit).unwrap_or(View::Null),
        ),
        (
            "verifier",
            report.verifier.as_ref().map(verifier).unwrap_or(View::Null),
        ),
        ("whea", report.whea.as_ref().map(whea).unwrap_or(View::Null)),
        (
            "blackboxes",
            View::List(report.blackboxes.iter().map(blackbox).collect()),
        ),
        (
            "warnings",
            View::List(
                report
                    .warnings
                    .iter()
                    .map(|warning| View::Str(warning.clone()))
                    .collect(),
            ),
        ),
    ])
}
