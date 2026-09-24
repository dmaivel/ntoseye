//! Driver Verifier bugcheck analysis.

use super::{VerifierAddress, VerifierArgument, VerifierFinding};
use crate::bugchecks::BugcheckAnalysis;

pub(super) fn verifier_finding(bugcheck: &BugcheckAnalysis) -> Option<VerifierFinding> {
    if !matches!(
        bugcheck.code,
        0x0000_00c4
            | 0x0000_00c9
            | 0x0000_00e6
            | 0x0000_00f1
            | 0x0000_00f6
            | 0x0000_0bfe
            | 0x0000_0bff
    ) {
        return None;
    }
    let subcode = bugcheck.args.first().map(|arg| arg.value).unwrap_or(0);
    let known_description = match (bugcheck.code, subcode) {
        (0x0000_00c4, 0xf6) => Some("a kernel handle was referenced as a user-mode handle"),
        (0x0000_00e6, 0x26) => Some("an IOMMU detected a DMA violation"),
        _ => None,
    };
    let addresses = match (bugcheck.code, subcode) {
        (0x0000_00c4, 0xf6) => bugcheck
            .args
            .get(3)
            .into_iter()
            .map(|arg| VerifierAddress {
                role: "driver instruction".into(),
                address: arg.value,
            })
            .collect(),
        (0x0000_00e6, 0x26) => bugcheck
            .args
            .get(2)
            .into_iter()
            .map(|arg| VerifierAddress {
                role: "DMA fault information".into(),
                address: arg.value,
            })
            .collect(),
        _ => Vec::new(),
    };
    Some(VerifierFinding {
        bugcheck_code: bugcheck.code,
        bugcheck_name: bugcheck.name.clone(),
        subcode,
        known_subcode: known_description.is_some(),
        subcode_description: known_description
            .map(str::to_string)
            .unwrap_or_else(|| format!("unknown verifier subcode {subcode:#x}")),
        arguments: bugcheck
            .args
            .iter()
            .map(|arg| VerifierArgument {
                value: arg.value,
                description: arg.description.clone(),
            })
            .collect(),
        associated_driver: bugcheck.driver.clone(),
        addresses,
    })
}
