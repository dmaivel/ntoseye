//! Culprit attribution: ranks the modules implicated by recorded evidence
//! and names a non-kernel culprit when the evidence supports one.

use super::{
    CulpritAttribution, CulpritConfidence, CulpritEvidence, CulpritEvidenceKind, TriageReport,
    canonical_module_component, evidence_module_for_address, names_match,
};
use crate::bugchecks::module_filename;

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
    if let Some(address) = report.status.rip
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
        module: candidate.module,
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
