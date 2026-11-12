//! The tagged blocks that bugcheck callbacks add to a crash dump
//! (`KbCallbackSecondaryDumpData`), which WinDbg's `.enumtag` lists and its
//! `!blackbox*` commands decode.
//!
//! The region starts with a `DumpBlob` file header (signature, header size,
//! `NtBuildNumber`) and holds one block after another: a header (its size, the
//! GUID tag, the data size and the padding before and after the data), then
//! the data. It follows the last page of a full or kernel dump, and the
//! triage data (`SizeOfDump`) of a minidump. A header that is not a block
//! header ends it, as WinDbg stops there too.

use std::sync::Arc;

use crate::base::bytes::read_u32;
use crate::nt::target::etw::{GuidStyle, format_guid};

const FILE_SIGNATURE: &[u8; 8] = b"DumpBlob";
const FILE_HEADER_SIZE: usize = 0x10;
const BLOCK_HEADER_SIZE: usize = 0x20;

/// One block: the GUID its writer tags it with, as it lies in memory, and
/// its data, read once from the dump and shared by every reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedBlock {
    pub tag: [u8; 16],
    pub data: Arc<[u8]>,
}

impl TaggedBlock {
    /// The tag as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub fn tag_text(&self) -> String {
        format_guid(&self.tag, GuidStyle::Braced)
    }
}

/// The blocks of the region at `offset` in the dump file `file`; none when
/// no `DumpBlob` header is there.
pub fn tagged_blocks_at(file: &[u8], offset: usize) -> Vec<TaggedBlock> {
    file.get(offset..)
        .filter(|region| region.starts_with(FILE_SIGNATURE))
        .map(parse_tagged_blocks)
        .unwrap_or_default()
}

/// The blocks of a region that starts with its `DumpBlob` header.
pub fn parse_tagged_blocks(region: &[u8]) -> Vec<TaggedBlock> {
    let header_size = region
        .get(8..12)
        .map(|_| read_u32(region, 8) as usize)
        .unwrap_or(0);
    let mut offset = header_size.max(FILE_HEADER_SIZE);
    let mut blocks = Vec::new();
    while let Some(header) = region.get(offset..offset + BLOCK_HEADER_SIZE) {
        let header_size = read_u32(header, 0) as usize;
        if header_size < BLOCK_HEADER_SIZE {
            break;
        }
        let tag: [u8; 16] = header[4..20].try_into().unwrap_or_default();
        let data_size = read_u32(header, 20) as usize;
        let pre_pad = read_u32(header, 24) as usize;
        let post_pad = read_u32(header, 28) as usize;
        let Some(start) = offset
            .checked_add(header_size)
            .and_then(|at| at.checked_add(pre_pad))
        else {
            break;
        };
        let Some(data) = start
            .checked_add(data_size)
            .and_then(|end| region.get(start..end))
        else {
            break;
        };
        blocks.push(TaggedBlock {
            tag,
            data: Arc::from(data),
        });
        offset = start + data_size + post_pad;
    }
    blocks
}

/// The global that holds a tag in its writer's image, and what the block
/// holds, for the tags Windows itself writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownTag {
    pub owner: &'static str,
    pub holds: &'static str,
}

/// `text`, a braced GUID (`{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`), as it
/// lies in memory, for tags spelled the way Windows documents them.
const fn guid(text: &str) -> [u8; 16] {
    // Where each byte's two hex digits start in the text: the first three
    // groups are little-endian integers, the last two plain bytes.
    const DIGITS: [usize; 16] = [7, 5, 3, 1, 12, 10, 17, 15, 20, 22, 25, 27, 29, 31, 33, 35];
    const fn nibble(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => panic!("not a hex digit"),
        }
    }
    let text = text.as_bytes();
    assert!(text.len() == 38 && text[0] == b'{' && text[37] == b'}');
    let mut bytes = [0u8; 16];
    let mut index = 0;
    while index < 16 {
        let at = DIGITS[index];
        bytes[index] = nibble(text[at]) << 4 | nibble(text[at + 1]);
        index += 1;
    }
    bytes
}

/// `nt!PopBlackBoxBsdGuid`: the boot status data.
pub const BSD_TAG: [u8; 16] = guid("{f57308df-cc45-4e01-ad76-29a4ebb010ec}");
/// `nt!PopBlackBoxNtfsGuid`: NTFS's timeout records.
pub const NTFS_TAG: [u8; 16] = guid("{00afe9c4-940d-4213-8016-cd3719b5bc20}");
/// `nt!PopBlackBoxPnpGuid`: the PnP event in progress.
pub const PNP_TAG: [u8; 16] = guid("{b7631941-532a-4cd6-b1b1-edb5917d4557}");
/// `nt!PopBlackBoxWinLogonGuid`: winlogon's state.
pub const WINLOGON_TAG: [u8; 16] = guid("{80cc79cf-a719-4af1-bf97-fe29ff76ebc1}");
/// `pci!PCI_CFG_RECORD_GUID`: the PCI configuration snapshot.
pub const PCI_TAG: [u8; 16] = guid("{9276c055-eb87-425c-b8b5-04e4d247f6cd}");
/// `nt!EtwSecondaryDumpDataGuid`: the ETW sessions' buffers.
pub const ETW_DUMP_DATA_TAG: [u8; 16] = guid("{2b88b710-1c93-4f7c-b06c-655ecc50decc}");
/// `wdf01000!WdfDumpGuid`: the IFR log Wdf01000 copies into a crash dump.
pub const WDF_DUMP_LOG_TAG: [u8; 16] = guid("{54c84888-01d1-4c1e-bed6-282c98241303}");
/// `wdf01000!WdfDumpGuid2`: Wdf01000's list of client drivers.
pub const WDF_DUMP_DRIVERS_TAG: [u8; 16] = guid("{f87e4a4c-c5a1-4d2f-bff0-d5de63a5e4c3}");

/// Each tag, the symbol that holds it in its
/// writer's image or, where the GUID has no symbol, the bugcheck callback
/// that writes it (read off the images in a Windows 11 26100 dump), and
/// what the block holds.
const KNOWN_TAGS: &[([u8; 16], &str, &str)] = &[
    (
        BSD_TAG,
        "nt!PopBlackBoxBsdGuid",
        "boot status data (!blackboxbsd)",
    ),
    (
        NTFS_TAG,
        "nt!PopBlackBoxNtfsGuid",
        "NTFS blackbox (!blackboxntfs)",
    ),
    (
        PNP_TAG,
        "nt!PopBlackBoxPnpGuid",
        "PnP blackbox (!blackboxpnp)",
    ),
    (
        WINLOGON_TAG,
        "nt!PopBlackBoxWinLogonGuid",
        "winlogon blackbox (!blackboxwinlogon)",
    ),
    (
        guid("{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}"),
        "nt!PopBlackBoxCodeIntegrityGuid",
        "code integrity blackbox",
    ),
    (
        PCI_TAG,
        "pci!PCI_CFG_RECORD_GUID",
        "PCI configuration (!blackboxpci)",
    ),
    (
        guid("{2b4ae195-a64d-4f04-8ede-7e4f981bd42a}"),
        "nt!GUID_TRIAGEDUMP_DATA",
        "triage data blocks",
    ),
    (
        ETW_DUMP_DATA_TAG,
        "nt!EtwSecondaryDumpDataGuid",
        "ETW sessions' buffers (!wmitrace.strdump)",
    ),
    (
        guid("{b0692a5e-6b7b-4073-8a7c-604e35032970}"),
        "nt!HvlSkCrashdumpGuid",
        "secure kernel crash data",
    ),
    (
        guid("{5bc8704a-6cb7-4378-ac72-ad06e2416e4a}"),
        "nt!CarSecondaryDataGuid",
        "CAR secondary data",
    ),
    (
        WDF_DUMP_LOG_TAG,
        "wdf01000!WdfDumpGuid",
        "KMDF driver's IFR log (!wdfkd.wdfcrashdump)",
    ),
    (
        WDF_DUMP_DRIVERS_TAG,
        "wdf01000!WdfDumpGuid2",
        "KMDF client drivers (!wdfkd.wdfcrashdump loader)",
    ),
    (
        guid("{c939c73b-17dc-4a44-904c-e2d987f52649}"),
        "storport!GUID_STORPORT_PAGING_DEVICE_DUMP",
        "StorPort paging device",
    ),
    (
        guid("{da82441d-7142-4bc1-b844-0807c5a4b67f}"),
        "storport!GUID_DEVICEDUMP_DRIVER_STORAGE_PORT",
        "StorPort device dump",
    ),
    (
        guid("{270a33fd-3da6-460d-ba89-3c1bae21e39b}"),
        "watchdog!WdDxgkSecondaryDataGUID",
        "display (dxgkrnl) state",
    ),
    (
        guid("{65755a40-f146-43ea-8c91-36b85728fd35}"),
        "crashdmp!CRASHDUMP_GUID_ID",
        "crash dump driver",
    ),
    (
        guid("{00dae7ca-6833-45c5-b147-bdaed7b61fd6}"),
        "hvservice!HbEvtSystemDiagLogCrashdumpAreaGuid",
        "Hyper-V boot event log",
    ),
    (
        guid("{bc5c008f-1e3a-44d7-988d-86f6884c6758}"),
        "mssmbios!SMBiosGuidSMBios",
        "SMBIOS tables",
    ),
    (
        guid("{6c7ac389-4313-47dc-9f34-a8800a0fb56c}"),
        "mssmbios!SMBiosGuidBios",
        "BIOS registry values",
    ),
    (
        guid("{d03dc06f-d88e-44c5-ba2a-fae035172d19}"),
        "mssmbios!SMBiosGuidRegisters",
        "processor registers",
    ),
    (
        guid("{e83b40d2-b0a0-4842-abea-71c9e3463dd1}"),
        "mssmbios!SMBiosGuidAcpi",
        "ACPI tables",
    ),
    (
        guid("{9282756a-ab95-4d24-a137-ecddc5de53f5}"),
        "nt!PspVsmLogBugCheckCallback",
        "VSM (secure kernel) failure log",
    ),
    (
        guid("{0f1f53f3-561f-42e7-bdb4-ba8e66b726d5}"),
        "nt!CmFcpSecondaryMultiPartDumpDataCallback",
        "feature configuration data",
    ),
];

/// What Windows writes under `tag`, when it is one of its own.
pub fn known_tag(tag: &[u8; 16]) -> Option<KnownTag> {
    KNOWN_TAGS
        .iter()
        .find(|(known, _, _)| known == tag)
        .map(|(_, owner, holds)| KnownTag { owner, holds })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{TaggedBlock, guid, known_tag, parse_tagged_blocks, tagged_blocks_at};
    use crate::nt::target::etw::parse_guid;

    /// The compile-time spelling lays a GUID out as the runtime parser does:
    /// its first three groups little-endian, the rest byte by byte.
    #[test]
    fn a_tag_constant_lies_in_memory_as_the_guid_parser_has_it() {
        let text = "{2B88B710-1c93-4f7c-b06c-655ecc50decc}";
        assert_eq!(Some(guid(text)), parse_guid(text));
    }

    fn block(tag: &str, data: &[u8], post_pad: usize) -> Vec<u8> {
        let mut bytes = 0x20u32.to_le_bytes().to_vec();
        bytes.extend(parse_guid(tag).unwrap());
        bytes.extend((data.len() as u32).to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend((post_pad as u32).to_le_bytes());
        bytes.extend(data);
        bytes.extend(vec![0xcc; post_pad]);
        bytes
    }

    fn region(blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = b"DumpBlob".to_vec();
        bytes.extend(0x10u32.to_le_bytes());
        bytes.extend(0xf000_65f4u32.to_le_bytes());
        for block in blocks {
            bytes.extend(block);
        }
        bytes
    }

    /// Blocks follow one another past their padding, as a minidump aligns
    /// them; an empty block is kept, and a zero header ends the walk with
    /// bytes still after it, as WinDbg stops there.
    #[test]
    fn blocks_are_walked_past_their_padding_to_the_first_non_header() {
        let bsd = "{f57308df-cc45-4e01-ad76-29a4ebb010ec}";
        let crashdmp = "{65755a40-f146-43ea-8c91-36b85728fd35}";
        let mut bytes = region(&[block(bsd, &[0xc8, 0, 0, 0, 1], 3), block(crashdmp, &[], 0)]);
        bytes.extend([0u8; 0x20]);
        bytes.extend(block(bsd, &[9], 0));
        let blocks = parse_tagged_blocks(&bytes);
        assert_eq!(
            blocks,
            [
                TaggedBlock {
                    tag: parse_guid(bsd).unwrap(),
                    data: Arc::from([0xc8, 0, 0, 0, 1].as_slice()),
                },
                TaggedBlock {
                    tag: parse_guid(crashdmp).unwrap(),
                    data: Arc::from([].as_slice()),
                },
            ]
        );
        assert_eq!(
            known_tag(&blocks[0].tag).unwrap().owner,
            "nt!PopBlackBoxBsdGuid"
        );
    }

    /// A block whose data runs past the region ends the walk there; a file
    /// without the signature at the offset has no blocks.
    #[test]
    fn a_truncated_block_or_a_missing_signature_yields_what_is_whole() {
        let bsd = "{f57308df-cc45-4e01-ad76-29a4ebb010ec}";
        let mut bytes = region(&[block(bsd, &[1, 2, 3, 4], 0)]);
        bytes.truncate(bytes.len() - 2);
        assert!(parse_tagged_blocks(&bytes).is_empty());
        let mut file = vec![0u8; 0x40];
        file.extend(region(&[block(bsd, &[7], 0)]));
        assert_eq!(tagged_blocks_at(&file, 0x40).len(), 1);
        assert!(tagged_blocks_at(&file, 0x20).is_empty());
    }
}
