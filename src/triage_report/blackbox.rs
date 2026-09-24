//! Blackbox findings: which dump blackbox streams are recorded.

use super::{BlackboxFinding, BlackboxKind, BlackboxState};
use crate::dmp::DmpBlackboxStream;

pub(super) fn blackbox_findings(streams: &[DmpBlackboxStream]) -> Vec<BlackboxFinding> {
    [
        (BlackboxKind::Pnp, "PnP"),
        (BlackboxKind::Ntfs, "NTFS"),
        (BlackboxKind::Bsd, "BSD"),
        (BlackboxKind::Winlogon, "Winlogon"),
    ]
    .into_iter()
    .map(|(kind, display_name)| {
        let stream = streams.iter().find(|stream| {
            let name = stream.name.to_ascii_lowercase();
            match kind {
                BlackboxKind::Pnp => name.contains("pnp"),
                BlackboxKind::Ntfs => name.contains("ntfs"),
                BlackboxKind::Bsd => name.contains("bsd"),
                BlackboxKind::Winlogon => name.contains("winlogon"),
            }
        });
        match stream {
            Some(stream) => BlackboxFinding {
                kind,
                name: stream.name.clone(),
                size: Some(stream.size),
                state: BlackboxState::PresentUnparsed,
            },
            None => BlackboxFinding {
                kind,
                name: display_name.into(),
                size: None,
                state: BlackboxState::Unavailable {
                    reason: "dump parser exposes no matching blackbox stream metadata".into(),
                },
            },
        }
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blackbox_presence_falls_back_to_recorded_name_and_size() {
        let findings = blackbox_findings(&[DmpBlackboxStream {
            name: "BLACKBOXPNP".into(),
            size: 0x240,
        }]);
        let pnp = findings
            .iter()
            .find(|finding| finding.kind == BlackboxKind::Pnp)
            .unwrap();
        assert_eq!(pnp.name, "BLACKBOXPNP");
        assert_eq!(pnp.size, Some(0x240));
        assert_eq!(pnp.state, BlackboxState::PresentUnparsed);
        assert!(matches!(
            findings
                .iter()
                .find(|finding| finding.kind == BlackboxKind::Ntfs)
                .unwrap()
                .state,
            BlackboxState::Unavailable { .. }
        ));
    }
}
