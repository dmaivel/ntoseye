//! WHEA findings: the error-record address a machine-check bugcheck
//! carries and the bounded decoding of that `WHEA_ERROR_RECORD`.

use super::{WheaFinding, WheaRecord, WheaRecordState, WheaSection, WheaSectionKind};
use crate::backend::MemoryOps;
use crate::bugchecks::BugcheckAnalysis;
use crate::bytes::{read_u16, read_u32};
use crate::types::VirtAddr;

pub(super) fn whea_without_memory(bugcheck: &BugcheckAnalysis) -> Option<WheaFinding> {
    match bugcheck.code {
        0x0000_0124 => {
            let address = bugcheck
                .args
                .get(1)
                .map(|arg| arg.value)
                .filter(|&address| address != 0);
            Some(WheaFinding {
                record_address: address,
                state: WheaRecordState::Unavailable {
                    reason: if address.is_some() {
                        "WHEA_ERROR_RECORD bytes were not read".into()
                    } else {
                        "bugcheck parameter 2 does not contain a WHEA_ERROR_RECORD address".into()
                    },
                },
            })
        }
        0x0000_0122 => Some(WheaFinding {
            record_address: None,
            state: WheaRecordState::Unavailable {
                reason: "WHEA_INTERNAL_ERROR does not record a WHEA_ERROR_RECORD address".into(),
            },
        }),
        _ => None,
    }
}

const WHEA_HEADER_SIZE: usize = 128;
const WHEA_SECTION_DESCRIPTOR_SIZE: usize = 72;
const WHEA_MAX_RECORD_SIZE: usize = 1024 * 1024;
const WHEA_RECORD_SIGNATURE: u32 = 0x5245_5043;
const WHEA_RECORD_SIGNATURE_END: u32 = 0xffff_ffff;
const WHEA_SUPPORTED_REVISION: u16 = 0x0210;

pub(super) fn decode_whea_record<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: u64,
) -> WheaRecordState {
    let mut header = [0u8; WHEA_HEADER_SIZE];
    if let Err(error) = memory.read_bytes(VirtAddr(address), &mut header) {
        return WheaRecordState::Unavailable {
            reason: format!("WHEA_ERROR_RECORD header is not captured: {error}"),
        };
    }
    decode_whea_header_and_read(memory, address, &header)
}

fn decode_whea_header_and_read<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: u64,
    header: &[u8; WHEA_HEADER_SIZE],
) -> WheaRecordState {
    let signature = read_u32(header, 0);
    if signature != WHEA_RECORD_SIGNATURE {
        return whea_malformed(format!("invalid WHEA signature {signature:#010x}"));
    }
    let revision = read_u16(header, 4);
    if revision != WHEA_SUPPORTED_REVISION {
        return whea_malformed(format!("unsupported WHEA record revision {revision:#06x}"));
    }
    let signature_end = read_u32(header, 6);
    if signature_end != WHEA_RECORD_SIGNATURE_END {
        return whea_malformed(format!(
            "invalid WHEA ending signature {signature_end:#010x}"
        ));
    }
    let section_count = read_u16(header, 10) as usize;
    let severity = read_u32(header, 12);
    let length = read_u32(header, 20) as usize;
    let descriptors_end = match section_count
        .checked_mul(WHEA_SECTION_DESCRIPTOR_SIZE)
        .and_then(|bytes| WHEA_HEADER_SIZE.checked_add(bytes))
    {
        Some(end) => end,
        None => return whea_malformed("WHEA section descriptor count overflows".into()),
    };
    if length < descriptors_end {
        return whea_malformed(format!(
            "WHEA length {length:#x} is smaller than the {descriptors_end:#x}-byte header and descriptor table"
        ));
    }
    if length > WHEA_MAX_RECORD_SIZE {
        return whea_malformed(format!(
            "WHEA length {length:#x} exceeds the {WHEA_MAX_RECORD_SIZE:#x}-byte safety cap"
        ));
    }

    let mut record = vec![0u8; length];
    if let Err(error) = memory.read_bytes(VirtAddr(address), &mut record) {
        return WheaRecordState::Unavailable {
            reason: format!("WHEA_ERROR_RECORD is only partially captured: {error}"),
        };
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let descriptor = WHEA_HEADER_SIZE + index * WHEA_SECTION_DESCRIPTOR_SIZE;
        let offset = read_u32(&record, descriptor) as usize;
        let section_length = read_u32(&record, descriptor + 4) as usize;
        let section_end = match offset.checked_add(section_length) {
            Some(end) => end,
            None => {
                return whea_malformed(format!("WHEA section {index} range overflows"));
            }
        };
        if offset < descriptors_end || section_end > length {
            return whea_malformed(format!(
                "WHEA section {index} range {offset:#x}..{section_end:#x} is outside record bounds {descriptors_end:#x}..{length:#x}"
            ));
        }
        let section_type = format_guid(&record[descriptor + 16..descriptor + 32]);
        sections.push(WheaSection {
            offset: offset as u32,
            length: section_length as u32,
            severity: read_u32(&record, descriptor + 48),
            kind: whea_section_kind(&section_type),
            section_type,
        });
    }
    WheaRecordState::Decoded(WheaRecord {
        revision,
        severity,
        length: length as u32,
        sections,
    })
}

fn whea_malformed(reason: String) -> WheaRecordState {
    WheaRecordState::Unavailable {
        reason: format!("malformed WHEA_ERROR_RECORD: {reason}"),
    }
}

fn whea_section_kind(section_type: &str) -> WheaSectionKind {
    match section_type {
        "9876ccad-47b4-4bdb-b65e-16f193c4f3db" => WheaSectionKind::ProcessorGeneric,
        "a5bc1114-6f64-4ede-b863-3e83ed7c83b1" => WheaSectionKind::Memory,
        "d995e954-bbc1-430f-ad91-b44dcb3c6f35" => WheaSectionKind::PciExpress,
        "dc3ea0b0-a144-4797-b95b-53fa242b6e1d" => WheaSectionKind::X64Processor,
        _ => WheaSectionKind::Unknown,
    }
}

fn format_guid(bytes: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        read_u32(bytes, 0),
        read_u16(bytes, 4),
        read_u16(bytes, 6),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;

    struct NoMemory;

    impl MemoryOps<VirtAddr> for NoMemory {
        fn read_bytes(&self, _addr: VirtAddr, _buf: &mut [u8]) -> Result<()> {
            panic!("malformed header must be rejected before a record read")
        }

        fn write_bytes(&self, _addr: VirtAddr, _buf: &[u8]) -> Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn malformed_whea_descriptor_bounds_are_rejected() {
        let mut header = [0u8; WHEA_HEADER_SIZE];
        header[0..4].copy_from_slice(&WHEA_RECORD_SIGNATURE.to_le_bytes());
        header[4..6].copy_from_slice(&WHEA_SUPPORTED_REVISION.to_le_bytes());
        header[6..10].copy_from_slice(&WHEA_RECORD_SIGNATURE_END.to_le_bytes());
        header[10..12].copy_from_slice(&1u16.to_le_bytes());
        header[20..24].copy_from_slice(&(WHEA_HEADER_SIZE as u32).to_le_bytes());

        let state = decode_whea_header_and_read(&NoMemory, 0x1000, &header);
        let WheaRecordState::Unavailable { reason } = state else {
            panic!("malformed record unexpectedly decoded")
        };
        assert!(reason.contains("smaller than"));
    }
}
