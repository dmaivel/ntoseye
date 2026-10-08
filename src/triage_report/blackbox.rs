//! Blackbox findings: what each of the dump's blackbox records holds.

use super::{BlackboxFinding, BlackboxKind, BlackboxState};
use crate::blackbox::{
    BSD_TAG, NTFS_OPLOCK_BREAK_TIMEOUT, NTFS_SLOW_IO_TIMEOUT, NTFS_TAG, PNP_TAG, WINLOGON_TAG,
    decode_boot_status, decode_ntfs, decode_pnp, decode_winlogon, tagged_data,
};
use crate::dmp::tagged::TaggedBlock;

/// The blackboxes WinDbg's `!analyze` lists, each decoded to one line.
pub(super) fn blackbox_findings(blocks: &[TaggedBlock]) -> Vec<BlackboxFinding> {
    [
        (BlackboxKind::Pnp, "PnP", PNP_TAG, "!blackboxpnp"),
        (BlackboxKind::Ntfs, "NTFS", NTFS_TAG, "!blackboxntfs"),
        (BlackboxKind::Bsd, "BSD", BSD_TAG, "!blackboxbsd"),
        (
            BlackboxKind::Winlogon,
            "Winlogon",
            WINLOGON_TAG,
            "!blackboxwinlogon",
        ),
    ]
    .into_iter()
    .map(|(kind, name, tag, command)| {
        let data = tagged_data(blocks, tag);
        BlackboxFinding {
            kind,
            name: name.into(),
            command,
            size: data.map(|data| data.len() as u64),
            state: match data {
                None => BlackboxState::Absent,
                Some(data) => match summarize(kind, data) {
                    Ok(summary) => BlackboxState::Decoded { summary },
                    Err(reason) => BlackboxState::Malformed { reason },
                },
            },
        }
    })
    .collect()
}

fn summarize(kind: BlackboxKind, data: &[u8]) -> Result<String, String> {
    Ok(match kind {
        BlackboxKind::Pnp => {
            let pnp = decode_pnp(data)?;
            let device = if pnp.device_id.is_empty() {
                "no device".to_string()
            } else {
                pnp.device_id
            };
            let mut summary = format!(
                "{device}, problem code {}, event information {}, {}",
                pnp.problem_code,
                pnp.event_information,
                if pnp.event_in_progress != 0 {
                    "event in progress"
                } else {
                    "no event in progress"
                }
            );
            if pnp.veto_type != 0 || pnp.veto_string.is_some() {
                summary.push_str(&format!(
                    ", veto type {} {}",
                    pnp.veto_type,
                    pnp.veto_string.unwrap_or_default()
                ));
            }
            summary
        }
        BlackboxKind::Ntfs => {
            let records = decode_ntfs(data)?;
            let count = |kind| records.iter().filter(|record| record.kind == kind).count();
            format!(
                "{} slow I/O and {} oplock break timeout records",
                count(NTFS_SLOW_IO_TIMEOUT),
                count(NTFS_OPLOCK_BREAK_TIMEOUT)
            )
        }
        BlackboxKind::Bsd => {
            let bsd = decode_boot_status(data)?;
            format!(
                "last boot {}, {}; boot id {}, last successful shutdown in boot {}, last reported \
                 abnormal shutdown in boot {}",
                if bsd.last_boot_succeeded {
                    "succeeded"
                } else {
                    "did not succeed"
                },
                if bsd.last_boot_shutdown {
                    "shut down"
                } else {
                    "not shut down"
                },
                bsd.last_boot_id,
                bsd.last_successful_shutdown_boot_id,
                bsd.last_reported_abnormal_shutdown_boot_id
            )
        }
        BlackboxKind::Winlogon => {
            let winlogon = decode_winlogon(data)?;
            format!(
                "{}, {}",
                winlogon.thread_name,
                if winlogon.is_operation_pending != 0 {
                    "operation pending"
                } else {
                    "no operation pending"
                }
            )
        }
    })
}
