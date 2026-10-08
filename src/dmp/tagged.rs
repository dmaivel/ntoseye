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

use crate::bytes::read_u32;
use crate::target::etw::format_guid;

const FILE_SIGNATURE: &[u8; 8] = b"DumpBlob";
const FILE_HEADER_SIZE: usize = 0x10;
const BLOCK_HEADER_SIZE: usize = 0x20;

/// One block: the GUID its writer tags it with, as it lies in memory, and
/// its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaggedBlock {
    pub tag: [u8; 16],
    pub data: Vec<u8>,
}

impl TaggedBlock {
    /// The tag as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub fn tag_text(&self) -> String {
        format_guid(&self.tag)
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
            data: data.to_vec(),
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

/// Each tag as `format_guid` writes it, the symbol that holds it in its
/// writer's image or, where the GUID has no symbol, the bugcheck callback
/// that writes it (read off the images in a Windows 11 26100 dump), and
/// what the block holds.
const KNOWN_TAGS: &[(&str, &str, &str)] = &[
    (
        "{f57308df-cc45-4e01-ad76-29a4ebb010ec}",
        "nt!PopBlackBoxBsdGuid",
        "boot status data (!blackboxbsd)",
    ),
    (
        "{00afe9c4-940d-4213-8016-cd3719b5bc20}",
        "nt!PopBlackBoxNtfsGuid",
        "NTFS blackbox (!blackboxntfs)",
    ),
    (
        "{b7631941-532a-4cd6-b1b1-edb5917d4557}",
        "nt!PopBlackBoxPnpGuid",
        "PnP blackbox (!blackboxpnp)",
    ),
    (
        "{80cc79cf-a719-4af1-bf97-fe29ff76ebc1}",
        "nt!PopBlackBoxWinLogonGuid",
        "winlogon blackbox (!blackboxwinlogon)",
    ),
    (
        "{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}",
        "nt!PopBlackBoxCodeIntegrityGuid",
        "code integrity blackbox",
    ),
    (
        "{9276c055-eb87-425c-b8b5-04e4d247f6cd}",
        "pci!PCI_CFG_RECORD_GUID",
        "PCI configuration (!blackboxpci)",
    ),
    (
        "{2b4ae195-a64d-4f04-8ede-7e4f981bd42a}",
        "nt!GUID_TRIAGEDUMP_DATA",
        "triage data blocks",
    ),
    (
        "{2b88b710-1c93-4f7c-b06c-655ecc50decc}",
        "nt!EtwSecondaryDumpDataGuid",
        "ETW buffers",
    ),
    (
        "{b0692a5e-6b7b-4073-8a7c-604e35032970}",
        "nt!HvlSkCrashdumpGuid",
        "secure kernel crash data",
    ),
    (
        "{5bc8704a-6cb7-4378-ac72-ad06e2416e4a}",
        "nt!CarSecondaryDataGuid",
        "CAR secondary data",
    ),
    (
        "{54c84888-01d1-4c1e-bed6-282c98241303}",
        "wdf01000!WdfDumpGuid",
        "KMDF crash data",
    ),
    (
        "{f87e4a4c-c5a1-4d2f-bff0-d5de63a5e4c3}",
        "wdf01000!WdfDumpGuid2",
        "KMDF crash data",
    ),
    (
        "{c939c73b-17dc-4a44-904c-e2d987f52649}",
        "storport!GUID_STORPORT_PAGING_DEVICE_DUMP",
        "StorPort paging device",
    ),
    (
        "{da82441d-7142-4bc1-b844-0807c5a4b67f}",
        "storport!GUID_DEVICEDUMP_DRIVER_STORAGE_PORT",
        "StorPort device dump",
    ),
    (
        "{270a33fd-3da6-460d-ba89-3c1bae21e39b}",
        "watchdog!WdDxgkSecondaryDataGUID",
        "display (dxgkrnl) state",
    ),
    (
        "{65755a40-f146-43ea-8c91-36b85728fd35}",
        "crashdmp!CRASHDUMP_GUID_ID",
        "crash dump driver",
    ),
    (
        "{00dae7ca-6833-45c5-b147-bdaed7b61fd6}",
        "hvservice!HbEvtSystemDiagLogCrashdumpAreaGuid",
        "Hyper-V boot event log",
    ),
    (
        "{bc5c008f-1e3a-44d7-988d-86f6884c6758}",
        "mssmbios!SMBiosGuidSMBios",
        "SMBIOS tables",
    ),
    (
        "{6c7ac389-4313-47dc-9f34-a8800a0fb56c}",
        "mssmbios!SMBiosGuidBios",
        "BIOS registry values",
    ),
    (
        "{d03dc06f-d88e-44c5-ba2a-fae035172d19}",
        "mssmbios!SMBiosGuidRegisters",
        "processor registers",
    ),
    (
        "{e83b40d2-b0a0-4842-abea-71c9e3463dd1}",
        "mssmbios!SMBiosGuidAcpi",
        "ACPI tables",
    ),
    (
        "{9282756a-ab95-4d24-a137-ecddc5de53f5}",
        "nt!PspVsmLogBugCheckCallback",
        "VSM (secure kernel) failure log",
    ),
    (
        "{0f1f53f3-561f-42e7-bdb4-ba8e66b726d5}",
        "nt!CmFcpSecondaryMultiPartDumpDataCallback",
        "feature configuration data",
    ),
];

/// What Windows writes under `tag`, when it is one of its own.
pub fn known_tag(tag: &[u8; 16]) -> Option<KnownTag> {
    let text = format_guid(tag);
    KNOWN_TAGS
        .iter()
        .find(|(guid, _, _)| *guid == text)
        .map(|(_, owner, holds)| KnownTag { owner, holds })
}

#[cfg(test)]
mod tests {
    use super::{TaggedBlock, known_tag, parse_tagged_blocks, tagged_blocks_at};
    use crate::target::etw::parse_guid;

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
                    data: vec![0xc8, 0, 0, 0, 1],
                },
                TaggedBlock {
                    tag: parse_guid(crashdmp).unwrap(),
                    data: Vec::new(),
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
