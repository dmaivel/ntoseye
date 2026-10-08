//! Windows' blackbox records in a crash dump's tagged data
//! ([`crate::dmp::tagged`]), decoded as WinDbg's `!blackbox*` commands decode
//! them: the boot status data (`bootstat.dat`), NTFS's timeout records, the
//! PnP event in progress, winlogon's state, and the PCI configuration
//! snapshot. The layouts and checks follow WinDbg's `ext.dll`.

use crate::bytes::{read_u16, read_u32, read_u64};
use crate::dmp::tagged::TaggedBlock;
use crate::layout::utf16le_nul_terminated;
use crate::target::etw::parse_guid;

pub const BSD_TAG: &str = "{f57308df-cc45-4e01-ad76-29a4ebb010ec}";
pub const NTFS_TAG: &str = "{00afe9c4-940d-4213-8016-cd3719b5bc20}";
pub const PNP_TAG: &str = "{b7631941-532a-4cd6-b1b1-edb5917d4557}";
pub const WINLOGON_TAG: &str = "{80cc79cf-a719-4af1-bf97-fe29ff76ebc1}";
pub const PCI_TAG: &str = "{9276c055-eb87-425c-b8b5-04e4d247f6cd}";

/// The block tagged `tag`.
pub fn tagged_block<'a>(blocks: &'a [TaggedBlock], tag: &str) -> Option<&'a TaggedBlock> {
    let tag = parse_guid(tag)?;
    blocks.iter().find(|block| block.tag == tag)
}

/// The data of the block tagged `tag`.
pub fn tagged_data<'a>(blocks: &'a [TaggedBlock], tag: &str) -> Option<&'a [u8]> {
    tagged_block(blocks, tag).map(|block| &*block.data)
}

fn u8_at(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or(0)
}

/// The boot status data (`RTL_BSD_DATA`) the boot manager and the kernel
/// keep in `bootstat.dat`. Sections past `version` (its size) are absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootStatus {
    pub version: u32,
    /// The block's size when it is smaller than `version` says.
    pub truncated_to: Option<u32>,
    pub product_type: u32,
    pub auto_advanced_boot: bool,
    pub advanced_boot_menu_timeout: u8,
    pub last_boot_succeeded: bool,
    pub last_boot_shutdown: bool,
    pub sleep_in_progress: bool,
    pub power_transition: PowerTransition,
    pub boot_attempt_count: u8,
    pub last_boot_checkpoint: bool,
    pub checksum: u8,
    pub last_boot_id: u32,
    pub last_successful_shutdown_boot_id: u32,
    pub last_reported_abnormal_shutdown_boot_id: u32,
    pub error_info: Option<BsdErrorInfo>,
    pub power_button: Option<PowerButton>,
    pub transition_extension: Option<TransitionExtension>,
    /// `0` uninitialized, `1` boot pending, `2` LKG pending, `3` rollback
    /// pending, `4` committed.
    pub feature_configuration_state: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerTransition {
    pub power_button_timestamp: u64,
    pub system_running: bool,
    pub connected_standby_in_progress: bool,
    pub user_shutdown_in_progress: bool,
    pub system_shutdown_in_progress: bool,
    pub sleep_in_progress: u8,
    pub connected_standby_scenario_instance_id: u8,
    pub connected_standby_entry_reason: u8,
    pub connected_standby_exit_reason: u8,
    pub system_sleep_transitions_to_on: u16,
    pub last_reference_time: u64,
    pub last_reference_time_checksum: u32,
    pub last_update_boot_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsdErrorInfo {
    pub boot_id: u32,
    pub repeat_count: u32,
    pub other_error_count: u32,
    pub code: u32,
    pub status: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerButton {
    pub last_press_time: u64,
    pub cumulative_press_count: u32,
    pub last_press_boot_id: u16,
    pub last_power_watchdog_stage: u8,
    pub watchdog_armed: bool,
    pub shutdown_in_progress: bool,
    pub last_release_time: u64,
    pub cumulative_release_count: u32,
    pub last_release_boot_id: u16,
    pub error_count: u16,
    pub current_connected_standby_phase: u8,
    pub transition_latest_checkpoint_id: u32,
    pub transition_latest_checkpoint_type: u32,
    pub transition_latest_checkpoint_sequence_number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionExtension {
    pub shutdown_device_type: u8,
    pub setup_in_progress: bool,
    pub oobe_in_progress: bool,
    pub sleep_checkpoint_source: u8,
    pub sleep_checkpoint: u8,
    pub connected_standby_entry_reason_category: u8,
    pub connected_standby_exit_reason_category: u8,
    pub connected_standby_entry_scenario_instance_id: u64,
}

/// The name WinDbg gives a feature configuration state.
pub fn feature_configuration_state_name(state: u32) -> Option<&'static str> {
    Some(match state {
        0 => "Uninitialized",
        1 => "Boot Pending",
        2 => "LKG Pending",
        3 => "Rollback Pending",
        4 => "Committed",
        _ => return None,
    })
}

/// Decode the boot status data, read into a zeroed 200-byte record as
/// WinDbg does; a version of 0x40 or less is not one it knows.
pub fn decode_boot_status(block: &[u8]) -> Result<BootStatus, String> {
    let mut data = [0u8; 200];
    let copied = block.len().min(data.len());
    data[..copied].copy_from_slice(&block[..copied]);
    let version = read_u32(&data, 0);
    let size = u32::try_from(block.len()).unwrap_or(u32::MAX);
    let (extent, truncated_to) = if size < version {
        (size, Some(size))
    } else {
        (version, None)
    };
    if extent <= 0x40 {
        return Err(format!("unsupported bootstat.dat version {version:#x}"));
    }
    let flags = data[0x18];
    let extension_flags = data[0x99];
    let categories = data[0xaf];
    Ok(BootStatus {
        version,
        truncated_to,
        product_type: read_u32(&data, 4),
        auto_advanced_boot: data[8] != 0,
        advanced_boot_menu_timeout: data[9],
        last_boot_succeeded: data[0xa] != 0,
        last_boot_shutdown: data[0xb] != 0,
        sleep_in_progress: data[0xc] != 0,
        power_transition: PowerTransition {
            power_button_timestamp: read_u64(&data, 0x10),
            system_running: flags & 1 != 0,
            connected_standby_in_progress: flags & 2 != 0,
            user_shutdown_in_progress: flags & 4 != 0,
            system_shutdown_in_progress: flags & 8 != 0,
            sleep_in_progress: flags >> 4,
            connected_standby_scenario_instance_id: data[0x19],
            connected_standby_entry_reason: data[0x1a] & 0x3f,
            connected_standby_exit_reason: data[0x1b] & 0x3f,
            system_sleep_transitions_to_on: read_u16(&data, 0x1c),
            last_reference_time: read_u64(&data, 0x20),
            last_reference_time_checksum: read_u32(&data, 0x28),
            last_update_boot_id: read_u32(&data, 0x2c),
        },
        boot_attempt_count: data[0x30],
        last_boot_checkpoint: data[0x31] != 0,
        checksum: data[0x32],
        last_boot_id: read_u32(&data, 0x34),
        last_successful_shutdown_boot_id: read_u32(&data, 0x38),
        last_reported_abnormal_shutdown_boot_id: read_u32(&data, 0x3c),
        error_info: (extent >= 0x58).then(|| BsdErrorInfo {
            boot_id: read_u32(&data, 0x40),
            repeat_count: read_u32(&data, 0x44),
            other_error_count: read_u32(&data, 0x48),
            code: read_u32(&data, 0x4c),
            status: read_u32(&data, 0x50),
        }),
        power_button: (extent >= 0x88).then(|| PowerButton {
            last_press_time: read_u64(&data, 0x58),
            cumulative_press_count: read_u32(&data, 0x60),
            last_press_boot_id: read_u16(&data, 0x64),
            last_power_watchdog_stage: data[0x66],
            watchdog_armed: data[0x67] & 1 != 0,
            shutdown_in_progress: data[0x67] & 2 != 0,
            last_release_time: read_u64(&data, 0x78),
            cumulative_release_count: read_u32(&data, 0x80),
            last_release_boot_id: read_u16(&data, 0x84),
            error_count: read_u16(&data, 0x86),
            current_connected_standby_phase: data[0x88],
            transition_latest_checkpoint_id: read_u32(&data, 0x8c),
            transition_latest_checkpoint_type: read_u32(&data, 0x90),
            transition_latest_checkpoint_sequence_number: read_u32(&data, 0x94),
        }),
        transition_extension: (extent >= 0xa8).then(|| TransitionExtension {
            shutdown_device_type: data[0x98],
            setup_in_progress: extension_flags & 1 != 0,
            oobe_in_progress: extension_flags & 2 != 0,
            sleep_checkpoint_source: (extension_flags >> 2) & 3,
            sleep_checkpoint: data[0x9a],
            connected_standby_entry_reason_category: categories & 0xf,
            connected_standby_exit_reason_category: categories >> 4,
            connected_standby_entry_scenario_instance_id: read_u64(&data, 0xb0),
        }),
        feature_configuration_state: (extent >= 0xb0).then(|| read_u32(&data, 0xb8)),
    })
}

/// One NTFS blackbox record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsRecord {
    /// `1` slow I/O timeout, `2` oplock break timeout.
    pub kind: u32,
    pub length: u32,
    pub irp: u64,
    pub scb: u64,
    /// A slow I/O timeout's waiting thread.
    pub thread: Option<u64>,
    /// An oplock break's reason: `1` `NtfsFsdSetInformation` to `5`
    /// `NtfsFsdWrite`.
    pub break_reason: Option<u32>,
    pub owner_process_name: Option<String>,
    pub breaking_process_name: Option<String>,
}

pub const NTFS_SLOW_IO_TIMEOUT: u32 = 1;
pub const NTFS_OPLOCK_BREAK_TIMEOUT: u32 = 2;

/// The name WinDbg gives an NTFS record type.
pub fn ntfs_record_kind_name(kind: u32) -> &'static str {
    match kind {
        0 => "<Empty>",
        NTFS_SLOW_IO_TIMEOUT => "Slow I/O Timeout",
        NTFS_OPLOCK_BREAK_TIMEOUT => "Oplock Break Timeout",
        _ => "<Unknown>",
    }
}

/// The NTFS routine an oplock break reason names.
pub fn ntfs_break_reason_name(reason: u32) -> &'static str {
    match reason {
        1 => "NtfsFsdSetInformation",
        2 => "NtfsFspDispatch",
        3 => "NtfsFsdCleanup",
        4 => "NtfsFsdCreate",
        5 => "NtfsFsdWrite",
        _ => "<Unknown>",
    }
}

/// The NTFS blackbox's records: the slow I/O timeout slots in use, then
/// the chained variable records. The header is a version (0), its total
/// size, the offset of the first chained record, and a FILETIME; at 0x10,
/// the number of 32-byte slow I/O slots and where they start.
pub fn decode_ntfs(data: &[u8]) -> Result<Vec<NtfsRecord>, String> {
    if data.len() < 0x10 {
        return Err("NTFS blackbox data found, but truncated".into());
    }
    let total_size = usize::from(read_u16(data, 2));
    if total_size < 0x10 {
        return Err("NTFS blackbox data found, but with an invalid header".into());
    }
    if read_u16(data, 0) != 0 {
        return Err("NTFS blackbox data found, but of an unsupported version".into());
    }
    let first_chained = usize::from(read_u16(data, 4));
    let slot_count = usize::from(read_u16(data, 0x10));
    let slots_at = usize::from(read_u16(data, 0x12));
    let scan_failed =
        || "NTFS blackbox data scan failed: the header does not fit the data".to_string();
    if (first_chained != 0 && first_chained + 8 > data.len())
        || data.len() < 0x18
        || total_size < 0x18
        || total_size > data.len()
        || slots_at < 0x18
        || total_size.min(data.len()) < slots_at + 32 * slot_count
    {
        return Err(scan_failed());
    }
    let record = |kind: u32, length: u32, bytes: &[u8]| {
        let qword = |at: usize| bytes.get(at..at + 8).map_or(0, |_| read_u64(bytes, at));
        let name = |at: usize| {
            let raw = bytes
                .get(at..(at + 15).min(bytes.len()))
                .unwrap_or_default();
            let end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..end]).into_owned()
        };
        match kind {
            NTFS_SLOW_IO_TIMEOUT => NtfsRecord {
                kind,
                length,
                irp: qword(0),
                scb: qword(8),
                thread: Some(qword(16)),
                break_reason: None,
                owner_process_name: None,
                breaking_process_name: None,
            },
            NTFS_OPLOCK_BREAK_TIMEOUT => NtfsRecord {
                kind,
                length,
                irp: qword(8),
                scb: qword(16),
                thread: None,
                break_reason: Some(bytes.get(24..28).map_or(0, |_| read_u32(bytes, 24))),
                owner_process_name: Some(name(28)),
                breaking_process_name: Some(name(43)),
            },
            _ => NtfsRecord {
                kind,
                length,
                irp: 0,
                scb: 0,
                thread: None,
                break_reason: None,
                owner_process_name: None,
                breaking_process_name: None,
            },
        }
    };
    let mut records = Vec::new();
    for slot in 0..slot_count {
        let bytes = &data[slots_at + 32 * slot..slots_at + 32 * (slot + 1)];
        if read_u64(bytes, 0) != 0 || read_u64(bytes, 8) != 0 {
            records.push(record(NTFS_SLOW_IO_TIMEOUT, 32, bytes));
        }
    }
    let mut at = first_chained;
    // A chain that loops would never end; no blackbox holds more records
    // than its size has room for headers.
    for _ in 0..data.len() / 8 {
        if at == 0 || at + 8 > data.len() {
            break;
        }
        let kind = u32::from(read_u16(data, at));
        let length = usize::from(read_u16(data, at + 2));
        if at + length > data.len() {
            break;
        }
        if kind != 0 {
            records.push(record(kind, length as u32, &data[at..at + length]));
        }
        at = usize::from(read_u16(data, at + 4));
    }
    Ok(records)
}

/// The PnP event in progress, or the last one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PnpBlackbox {
    pub activity_id: [u8; 16],
    pub activity_time: u64,
    pub event_information: i32,
    pub event_in_progress: u8,
    pub problem_code: u32,
    pub veto_type: i32,
    pub device_id: String,
    pub veto_string: Option<String>,
}

/// Decode the PnP blackbox: fixed fields, the device ID from 0x2c, and the
/// veto string at the offset stored at 0x28.
pub fn decode_pnp(data: &[u8]) -> Result<PnpBlackbox, String> {
    if data.len() < 0x30 {
        return Err("PnP blackbox data found, but truncated".into());
    }
    let veto_at = read_u32(data, 0x28) as usize;
    Ok(PnpBlackbox {
        activity_id: data[..16].try_into().unwrap_or_default(),
        activity_time: read_u64(data, 0x10),
        event_information: read_u32(data, 0x18) as i32,
        event_in_progress: u8_at(data, 0x1c),
        problem_code: read_u32(data, 0x20),
        veto_type: read_u32(data, 0x24) as i32,
        device_id: utf16le_nul_terminated(&data[0x2c..]),
        veto_string: (veto_at != 0 && veto_at < data.len())
            .then(|| utf16le_nul_terminated(&data[veto_at..])),
    })
}

/// What winlogon was doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinlogonBlackbox {
    pub thread_name: String,
    pub is_operation_pending: i32,
}

/// Decode the winlogon blackbox: version 1 and the block's own size, then
/// the pending flag and the thread name.
pub fn decode_winlogon(data: &[u8]) -> Result<WinlogonBlackbox, String> {
    if data.len() < 0x10 || read_u32(data, 0) != 1 || read_u32(data, 4) as usize != data.len() {
        return Err(
            "winlogon blackbox data found, but not of version 1 or not its own size".into(),
        );
    }
    Ok(WinlogonBlackbox {
        thread_name: utf16le_nul_terminated(&data[0xc..]),
        is_operation_pending: read_u32(data, 8) as i32,
    })
}

/// One function's configuration header as pci.sys recorded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciRecord {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision: u8,
}

const PCI_RECORD_SIGNATURE: u32 = u32::from_le_bytes(*b"PCfg");
const PCI_RECORD_MIN: usize = 0x7c;

/// Decode pci.sys's records: each starts with `PCfg` and its size, holds
/// the function's location at 12 and its configuration header from 60.
pub fn decode_pci(data: &[u8]) -> Result<Vec<PciRecord>, String> {
    if data.len() < 0x80 {
        return Err("PCI blackbox data found, but truncated".into());
    }
    let mut records = Vec::new();
    let mut at = 0;
    while at + PCI_RECORD_MIN <= data.len() {
        let record = &data[at..];
        let size = read_u32(record, 4) as usize;
        if read_u32(record, 0) != PCI_RECORD_SIGNATURE || size < PCI_RECORD_MIN {
            break;
        }
        let location = read_u32(record, 12);
        records.push(PciRecord {
            bus: (location >> 8) as u8,
            device: (location as u8) >> 3,
            function: (location as u8) & 7,
            vendor_id: read_u16(record, 60),
            device_id: read_u16(record, 62),
            command: read_u16(record, 64),
            status: read_u16(record, 66),
            revision: record[68],
        });
        at += size;
    }
    Ok(records)
}

/// The command register's flags as WinDbg lists them: I/O, memory, bus
/// master, VGA palette snoop, parity error response, SERR.
pub fn pci_command_flags(command: u16) -> String {
    [
        (1, 'i'),
        (2, 'm'),
        (4, 'b'),
        (0x20, 'v'),
        (0x40, 'p'),
        (0x100, 's'),
    ]
    .iter()
    .map(|&(bit, letter)| if command & bit != 0 { letter } else { '.' })
    .collect()
}

/// The status register's flags as WinDbg lists them: capability list,
/// 66 MHz, master data parity error, signaled target abort, signaled
/// system error.
pub fn pci_status_flags(status: u16) -> String {
    [
        (0x10, 'c'),
        (0x20, '6'),
        (0x100, 'P'),
        (0x800, 'A'),
        (0x4000, 'S'),
    ]
    .iter()
    .map(|&(bit, letter)| if status & bit != 0 { letter } else { '.' })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boot status block of a Windows 11 26100 kernel dump: WinDbg's
    /// `!blackboxbsd` on it reads these values, the connected standby exit
    /// reason 0 out of the byte 0xc0 that holds it in its low six bits.
    fn real_bsd() -> Vec<u8> {
        let mut data = vec![0u8; 0xc8];
        data[..0x40].copy_from_slice(&[
            0xc8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0c, 0xc0,
            0x00, 0x00, 0x40, 0x00, 0x9f, 0xfb, 0xb7, 0xc0, 0x5e, 0x55, 0xdd, 0x01, 0x0f, 0xc3,
            0x15, 0x19, 0xbc, 0x02, 0x00, 0x00, 0x01, 0x01, 0xcc, 0x00, 0xbc, 0x02, 0x00, 0x00,
            0xba, 0x02, 0x00, 0x00, 0xbb, 0x02, 0x00, 0x00,
        ]);
        data[0xb0..].copy_from_slice(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x00, 0x00,
        ]);
        data
    }

    #[test]
    fn boot_status_reads_as_windbg_reads_a_real_block() {
        let bsd = decode_boot_status(&real_bsd()).unwrap();
        assert_eq!(
            (
                bsd.version,
                bsd.product_type,
                bsd.advanced_boot_menu_timeout
            ),
            (0xc8, 1, 30)
        );
        assert!(bsd.last_boot_succeeded && !bsd.last_boot_shutdown && !bsd.auto_advanced_boot);
        let transition = &bsd.power_transition;
        assert!(transition.system_running && transition.connected_standby_in_progress);
        assert_eq!(
            (
                transition.connected_standby_entry_reason,
                transition.connected_standby_exit_reason
            ),
            (12, 0)
        );
        assert_eq!(transition.last_reference_time, 0x01dd_555e_c0b7_fb9f);
        assert_eq!(transition.last_reference_time_checksum, 0x1915_c30f);
        assert_eq!((bsd.boot_attempt_count, bsd.checksum), (1, 0xcc));
        assert_eq!(
            (
                bsd.last_boot_id,
                bsd.last_successful_shutdown_boot_id,
                bsd.last_reported_abnormal_shutdown_boot_id
            ),
            (700, 698, 699)
        );
        let extension = bsd.transition_extension.unwrap();
        assert_eq!(extension.connected_standby_entry_scenario_instance_id, 1);
        assert_eq!(bsd.feature_configuration_state, Some(1));
        assert_eq!(feature_configuration_state_name(1), Some("Boot Pending"));
    }

    /// The version is the record's size: smaller versions leave out the
    /// later sections, and a block shorter than its version reads only as
    /// far as it reaches.
    #[test]
    fn boot_status_sections_follow_the_version_and_the_block() {
        let mut short = real_bsd();
        short[0] = 0x60;
        let bsd = decode_boot_status(&short).unwrap();
        assert!(bsd.error_info.is_some() && bsd.power_button.is_none());
        assert_eq!(bsd.feature_configuration_state, None);
        let truncated = decode_boot_status(&real_bsd()[..0x90]).unwrap();
        assert_eq!(truncated.truncated_to, Some(0x90));
        assert!(truncated.power_button.is_some() && truncated.transition_extension.is_none());
        let mut old = real_bsd();
        old[0] = 0x40;
        assert!(decode_boot_status(&old).is_err());
    }

    fn ntfs_header() -> Vec<u8> {
        let mut data = vec![0u8; 0x1000];
        data[..0x14].copy_from_slice(&[
            0x00, 0x00, 0x00, 0x10, 0x18, 0x01, 0x00, 0x00, 0xba, 0x1e, 0x9f, 0xdb, 0x5d, 0x55,
            0xdd, 0x01, 0x08, 0x00, 0x18, 0x00,
        ]);
        data
    }

    /// A real NTFS blackbox has eight empty slow I/O slots and no chained
    /// record; with a slot in use, an oplock break record and an unknown
    /// record chained after it, WinDbg lists them in that order with these
    /// values.
    #[test]
    fn ntfs_records_come_from_used_slots_then_the_chain() {
        assert_eq!(decode_ntfs(&ntfs_header()).unwrap(), []);
        let mut data = ntfs_header();
        for (index, value) in [
            0xffff_1111_1111_1110u64,
            0xffff_2222_2222_2220,
            0xffff_3333_3333_3330,
        ]
        .iter()
        .enumerate()
        {
            data[0x18 + 8 * index..0x20 + 8 * index].copy_from_slice(&value.to_le_bytes());
        }
        data[0x118..0x120].copy_from_slice(&[2, 0, 0x40, 0, 0x58, 0x01, 0, 0]);
        data[0x120..0x128].copy_from_slice(&0xffff_5555_5555_5550u64.to_le_bytes());
        data[0x128..0x130].copy_from_slice(&0xffff_6666_6666_6660u64.to_le_bytes());
        data[0x130..0x134].copy_from_slice(&4u32.to_le_bytes());
        data[0x134..0x143].copy_from_slice(b"OWNERPROCESS.EX");
        data[0x143..0x152].copy_from_slice(b"BREAKERPROC.EXE");
        data[0x158..0x160].copy_from_slice(&[7, 0, 0x10, 0, 0, 0, 0, 0]);
        let records = decode_ntfs(&data).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(
            (
                records[0].kind,
                records[0].irp,
                records[0].scb,
                records[0].thread
            ),
            (
                1,
                0xffff_1111_1111_1110,
                0xffff_2222_2222_2220,
                Some(0xffff_3333_3333_3330)
            )
        );
        assert_eq!(
            (records[1].kind, records[1].length, records[1].break_reason),
            (2, 0x40, Some(4))
        );
        assert_eq!(
            (records[1].irp, records[1].scb),
            (0xffff_5555_5555_5550, 0xffff_6666_6666_6660)
        );
        assert_eq!(
            records[1].owner_process_name.as_deref(),
            Some("OWNERPROCESS.EX")
        );
        assert_eq!(
            records[1].breaking_process_name.as_deref(),
            Some("BREAKERPROC.EXE")
        );
        assert_eq!((records[2].kind, records[2].length), (7, 0x10));
        let mut versioned = ntfs_header();
        versioned[0] = 1;
        assert!(decode_ntfs(&versioned).is_err());
    }

    #[test]
    fn pnp_and_winlogon_read_as_windbg_reads_real_blocks() {
        let mut pnp = vec![0u8; 0x92];
        pnp[0x10..0x18].copy_from_slice(&0x01dd_555e_2536_0b31u64.to_le_bytes());
        pnp[0x18] = 3;
        pnp[0x20] = 24;
        let device = "SWD\\MSDAS\\{ce958e9a-424f-4c88-86f4-11314821e75a}";
        for (index, unit) in device.encode_utf16().enumerate() {
            pnp[0x2c + 2 * index..0x2e + 2 * index].copy_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode_pnp(&pnp).unwrap();
        assert_eq!(decoded.activity_time, 134_357_426_730_568_497);
        assert_eq!((decoded.event_information, decoded.problem_code), (3, 24));
        assert_eq!(decoded.device_id, device);
        assert_eq!(decoded.veto_string, None);
        pnp[0x28] = 0x2c;
        assert_eq!(
            decode_pnp(&pnp).unwrap().veto_string.as_deref(),
            Some(device)
        );

        let mut winlogon = vec![1, 0, 0, 0, 0x2a, 0, 0, 0, 0, 0, 0, 0];
        winlogon.extend("WluiReleaseUI".encode_utf16().flat_map(u16::to_le_bytes));
        winlogon.resize(0x2a, 0);
        let decoded = decode_winlogon(&winlogon).unwrap();
        assert_eq!(
            (decoded.thread_name.as_str(), decoded.is_operation_pending),
            ("WluiReleaseUI", 0)
        );
        winlogon[4] = 0x30;
        assert!(decode_winlogon(&winlogon).is_err());
    }

    /// pci.sys's first two records in a QEMU q35 guest: the host bridge and
    /// the PCIe root port WinDbg's `!blackboxpci` lists first.
    #[test]
    fn pci_records_follow_their_sizes() {
        let mut data = vec![0u8; 0x80 + 0x7c];
        let record = |at: usize, data: &mut Vec<u8>, location: u32, ids: [u16; 4], revision: u8| {
            data[at..at + 4].copy_from_slice(b"PCfg");
            data[at + 4..at + 8].copy_from_slice(&0x7cu32.to_le_bytes());
            data[at + 12..at + 16].copy_from_slice(&location.to_le_bytes());
            for (index, value) in ids.iter().enumerate() {
                data[at + 60 + 2 * index..at + 62 + 2 * index]
                    .copy_from_slice(&value.to_le_bytes());
            }
            data[at + 68] = revision;
        };
        record(0, &mut data, 0, [0x8086, 0x29c0, 0x0007, 0x0000], 0);
        record(0x7c, &mut data, 8, [0x1b36, 0x0100, 0x0406, 0x0010], 5);
        let records = decode_pci(&data).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            (
                records[1].bus,
                records[1].device,
                records[1].function,
                records[1].device_id,
                records[1].revision
            ),
            (0, 1, 0, 0x0100, 5)
        );
        assert_eq!(pci_command_flags(records[0].command), "imb...");
        assert_eq!(pci_command_flags(records[1].command), ".mb...");
        assert_eq!(pci_status_flags(records[1].status), "c....");
    }
}
