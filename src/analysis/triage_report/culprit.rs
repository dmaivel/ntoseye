//! Culprit attribution: ranks the modules implicated by recorded evidence
//! and names a non-kernel culprit when the evidence supports one.

use super::{
    CodeOwner, CulpritAttribution, CulpritConfidence, CulpritEvidence, CulpritEvidenceKind,
    CulpritSubject, DynamicCodeCulprit, PowerThreadRole, TriageReport, canonical_module_component,
    evidence_module_for_address, names_match,
};
use crate::nt::bugchecks::module_filename;
use crate::nt::guest::ModuleInfo;
use crate::nt::unwind::FrameSource;

#[derive(Debug)]
struct CulpritCandidate {
    module: String,
    confidence: CulpritConfidence,
    evidence: Vec<CulpritEvidence>,
}

pub(super) fn culprit_attribution(report: &TriageReport) -> Option<CulpritAttribution> {
    let mut candidates = Vec::<CulpritCandidate>::new();
    if let Some(driver) = report.broken_driver.as_deref() {
        add_culprit_evidence(
            &mut candidates,
            driver,
            CulpritConfidence::High,
            CulpritEvidence {
                kind: CulpritEvidenceKind::RecordedBrokenDriver,
                detail: "triage dump records this broken driver".into(),
                address: None,
            },
        );
    }
    if let Some(bugcheck) = &report.bugcheck {
        if let Some(driver) = bugcheck.driver.as_deref() {
            let derived_from_fault = bugcheck
                .fault
                .as_ref()
                .and_then(|fault| fault.driver.as_deref())
                .is_some_and(|fault_driver| names_match(driver, fault_driver));
            if !derived_from_fault {
                add_culprit_evidence(
                    &mut candidates,
                    driver,
                    CulpritConfidence::High,
                    CulpritEvidence {
                        kind: CulpritEvidenceKind::RecordedBugcheckDriver,
                        detail: "bugcheck event records this driver".into(),
                        address: None,
                    },
                );
            }
        }
        if let Some(fault) = &bugcheck.fault
            && let Some(module) = evidence_module_for_address(report, fault.ip)
        {
            add_culprit_evidence(
                &mut candidates,
                module,
                CulpritConfidence::Medium,
                CulpritEvidence {
                    kind: CulpritEvidenceKind::BugcheckFaultAddress,
                    detail: format!("bugcheck fault address resolves to {module}"),
                    address: Some(fault.ip),
                },
            );
        }
    }
    if let Some(power) = &report.power {
        if let Some(culprit) = &power.failure.culprit
            && let Some(module) = culprit.driver.module.as_deref()
        {
            add_culprit_evidence(
                &mut candidates,
                module,
                CulpritConfidence::High,
                CulpritEvidence {
                    kind: CulpritEvidenceKind::PowerFailureDriver,
                    detail: format!("{} {}", culprit.driver.label(), culprit.reason),
                    address: Some(culprit.device.0),
                },
            );
        }
        // The first frame outside the kernel on the stack of the thread
        // that holds the PnP lock: the driver it waits in or for.
        let owner_frame = power
            .threads
            .iter()
            .filter(|thread| thread.role == PowerThreadRole::PnpLockOwner)
            .filter_map(|thread| thread.stack.as_ref().ok())
            .flat_map(|stack| stack.frames.iter())
            .find_map(|frame| {
                evidence_module_for_address(report, frame.ip)
                    .filter(|module| !is_kernel_module(module))
                    .map(|module| (frame, module))
            });
        if let Some((frame, module)) = owner_frame {
            add_culprit_evidence(
                &mut candidates,
                module,
                CulpritConfidence::Medium,
                CulpritEvidence {
                    kind: CulpritEvidenceKind::PnpLockOwnerStack,
                    detail: format!(
                        "the thread holding the PnP lock runs {} in {module}",
                        frame.symbol
                    ),
                    address: Some(frame.ip),
                },
            );
        }
    }
    if let Some(exception) = &report.exception
        && let Some(module) = evidence_module_for_address(report, exception.address)
    {
        add_culprit_evidence(
            &mut candidates,
            module,
            CulpritConfidence::Medium,
            CulpritEvidence {
                kind: CulpritEvidenceKind::ExceptionAddress,
                detail: format!("exception address resolves to {module}"),
                address: Some(exception.address),
            },
        );
    }
    if let Some(address) = report.current_instruction()
        && let Some(module) = evidence_module_for_address(report, address)
    {
        add_culprit_evidence(
            &mut candidates,
            module,
            CulpritConfidence::Low,
            CulpritEvidence {
                kind: CulpritEvidenceKind::CurrentInstruction,
                detail: format!("current instruction is inside {module}"),
                address: Some(address),
            },
        );
    }
    if let Some(frame) = report
        .backtrace
        .as_ref()
        .and_then(|trace| trace.frames.first())
        && let Some(module) = evidence_module_for_address(report, frame.ip)
    {
        add_culprit_evidence(
            &mut candidates,
            module,
            CulpritConfidence::Low,
            CulpritEvidence {
                kind: CulpritEvidenceKind::TopFrame,
                detail: format!("top frame {} is inside {module}", frame.symbol),
                address: Some(frame.ip),
            },
        );
    }

    candidates.sort_by(|left, right| {
        right
            .confidence
            .cmp(&left.confidence)
            .then_with(|| right.evidence.len().cmp(&left.evidence.len()))
            .then_with(|| left.module.cmp(&right.module))
    });
    let candidate = candidates.into_iter().find(|candidate| {
        !is_kernel_module(&candidate.module)
            || (candidate.confidence == CulpritConfidence::High && candidate.evidence.len() > 1)
    })?;
    Some(CulpritAttribution {
        subject: CulpritSubject::Module(candidate.module),
        confidence: candidate.confidence,
        evidence: candidate.evidence,
    })
}

fn add_culprit_evidence(
    candidates: &mut Vec<CulpritCandidate>,
    module: &str,
    confidence: CulpritConfidence,
    evidence: CulpritEvidence,
) {
    let module = module_filename(module);
    let candidate = candidates
        .iter_mut()
        .find(|candidate| names_match(&candidate.module, module));
    if let Some(candidate) = candidate {
        candidate.confidence = candidate.confidence.max(confidence);
        if !candidate
            .evidence
            .iter()
            .any(|existing| existing.kind == evidence.kind && existing.address == evidence.address)
        {
            candidate.evidence.push(evidence);
        }
    } else {
        candidates.push(CulpritCandidate {
            module: module.to_owned(),
            confidence,
            evidence: vec![evidence],
        });
    }
}

fn is_kernel_module(name: &str) -> bool {
    matches!(
        canonical_module_component(name).as_str(),
        "nt" | "ntoskrnl" | "ntkrnlmp" | "ntkrnlpa" | "ntkrpamp"
    )
}

/// Whether a user-mode module is part of Windows or of a language runtime:
/// code that raises, dispatches, and rethrows exceptions on behalf of its
/// caller (`RaiseException`, `_CxxThrowException`, the CLR's throw
/// helpers), so a fault reported in it is blamed on the code that called
/// it.
pub fn is_user_system_module(name: &str) -> bool {
    matches!(
        ModuleInfo::derive_short_name(name).as_str(),
        "ntdll"
            | "kernelbase"
            | "kernel32"
            | "wow64"
            | "wow64win"
            | "wow64cpu"
            | "user32"
            | "win32u"
            | "gdi32"
            | "gdi32full"
            | "combase"
            | "ole32"
            | "oleaut32"
            | "rpcrt4"
            | "sechost"
            | "advapi32"
            | "msvcrt"
            | "ucrtbase"
            | "msvcp_win"
            | "vcruntime140"
            | "vcruntime140_1"
            | "msvcp140"
            | "clr"
            | "coreclr"
            | "mscorwks"
    )
}

/// The culprit of a user-mode minidump's exception: the first frame outside
/// the system modules on the faulting thread's stack. In a module, that
/// module; in generated code a dynamic function table covers (JIT-compiled
/// code), that code, with low confidence: no module or symbol says what it
/// is. None when that frame is in memory nothing describes as code, or
/// every frame is in a system module.
pub fn user_culprit_attribution(report: &TriageReport) -> Option<CulpritAttribution> {
    let exception = report.user.as_ref()?.exception.as_ref()?;
    let frame = exception.blamed_frame.as_ref()?;
    let (subject, place) = match &frame.owner {
        CodeOwner::Module {
            name,
            system: false,
        } => (CulpritSubject::Module(name.clone()), name.clone()),
        CodeOwner::DynamicCode {
            table_start,
            table_end,
        } => (
            CulpritSubject::DynamicCode(DynamicCodeCulprit {
                address: frame.ip,
                table_start: *table_start,
                table_end: *table_end,
                caller: exception.module_caller.clone(),
            }),
            "JIT-compiled code".to_string(),
        ),
        _ => return None,
    };
    let evidence = if Some(frame.index) == exception.faulting_frame {
        CulpritEvidence {
            kind: CulpritEvidenceKind::ExceptionAddress,
            detail: format!("exception address resolves to {place}"),
            address: Some(exception.address),
        }
    } else {
        CulpritEvidence {
            kind: CulpritEvidenceKind::FirstNonSystemFrame,
            detail: format!(
                "frame {:02} {} is the first outside the system modules, in {place}",
                frame.index, frame.symbol
            ),
            address: Some(frame.ip),
        }
    };
    // A frame found by scanning the stack for return addresses may not be
    // a caller at all; generated code has no module or symbol to say what
    // it is.
    let confidence =
        if frame.source == FrameSource::Scan || matches!(subject, CulpritSubject::DynamicCode(_)) {
            CulpritConfidence::Low
        } else {
            CulpritConfidence::Medium
        };
    Some(CulpritAttribution {
        subject,
        confidence,
        evidence: vec![evidence],
    })
}
