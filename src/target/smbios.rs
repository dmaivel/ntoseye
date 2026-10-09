//! SMBIOS (`!sysinfo`): the firmware's table of system, board, processor,
//! and memory information, which the kernel located at boot
//! (`nt!WmipSMBiosTablePhysicalAddress`, `nt!WmipSMBiosTableLength`) and
//! reads from physical memory, decoded per the DMTF SMBIOS specification.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::target::Target;

/// The longest table read; SMBIOS 2.x tables are at most 64 KiB.
const MAX_TABLE: u64 = 0x10000;
/// Structure type 127, End-of-Table.
const END_OF_TABLE: u8 = 127;

/// One SMBIOS structure: its header, its formatted area, and its strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbiosStructure {
    pub kind: u8,
    pub handle: u16,
    /// The formatted area, header included, so offsets are the
    /// specification's.
    pub formatted: Vec<u8>,
    /// The strings, string 1 first.
    pub strings: Vec<String>,
}

impl SmbiosStructure {
    pub fn byte(&self, offset: usize) -> Option<u8> {
        self.formatted.get(offset).copied()
    }

    pub fn word(&self, offset: usize) -> Option<u16> {
        Some(u16::from_le_bytes([
            self.byte(offset)?,
            self.byte(offset + 1)?,
        ]))
    }

    pub fn dword(&self, offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.formatted.get(offset..offset + 4)?.try_into().ok()?,
        ))
    }

    pub fn qword(&self, offset: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            self.formatted.get(offset..offset + 8)?.try_into().ok()?,
        ))
    }

    /// The string the byte at `offset` numbers; `None` for string 0 (none)
    /// or a field past the formatted area.
    pub fn string(&self, offset: usize) -> Option<&str> {
        let index = usize::from(self.byte(offset)?);
        (index != 0)
            .then(|| self.strings.get(index - 1).map(String::as_str))
            .flatten()
    }
}

/// The SMBIOS table the kernel found.
#[derive(Debug, Clone)]
pub struct SmbiosTable {
    pub physical_address: u64,
    pub length: u32,
    /// The version the entry point gave, as `(major, minor)`.
    pub version: (u8, u8),
    pub structures: Vec<SmbiosStructure>,
    /// Why the parse stopped before End-of-Table.
    pub stopped: Option<String>,
}

impl SmbiosTable {
    /// The first structure of type `kind`.
    pub fn first(&self, kind: u8) -> Option<&SmbiosStructure> {
        self.structures
            .iter()
            .find(|structure| structure.kind == kind)
    }
}

/// Parse the structures of an SMBIOS table: each a header (type, length,
/// handle), a formatted area of that length, and a string set ended by two
/// NULs, up to End-of-Table.
pub fn parse_structures(table: &[u8]) -> (Vec<SmbiosStructure>, Option<String>) {
    let mut structures = Vec::new();
    let mut at = 0;
    while at < table.len() {
        let Some(header) = table.get(at..at + 4) else {
            return (
                structures,
                Some(format!("a header at {at:#x} runs past the table")),
            );
        };
        let length = usize::from(header[1]);
        if length < 4 {
            return (
                structures,
                Some(format!("the structure at {at:#x} has length {length}")),
            );
        }
        let Some(formatted) = table.get(at..at + length) else {
            return (
                structures,
                Some(format!("the structure at {at:#x} runs past the table")),
            );
        };
        // The string set ends at the first double NUL after the formatted
        // area; a structure without strings has just the two NULs.
        let rest = &table[at + length..];
        let Some(end) = rest.windows(2).position(|pair| pair == [0, 0]) else {
            return (
                structures,
                Some(format!(
                    "the strings of the structure at {at:#x} do not end"
                )),
            );
        };
        let strings = rest[..end]
            .split(|&byte| byte == 0)
            .filter(|text| !text.is_empty())
            .map(|text| String::from_utf8_lossy(text).trim().to_string())
            .collect();
        let kind = header[0];
        structures.push(SmbiosStructure {
            kind,
            handle: u16::from_le_bytes([header[2], header[3]]),
            formatted: formatted.to_vec(),
            strings,
        });
        at += length + end + 2;
        if kind == END_OF_TABLE {
            return (structures, None);
        }
    }
    (structures, None)
}

/// The DMTF name of structure type `kind`.
pub fn structure_name(kind: u8) -> &'static str {
    match kind {
        0 => "BIOS Information",
        1 => "System Information",
        2 => "Baseboard Information",
        3 => "System Enclosure",
        4 => "Processor Information",
        5 => "Memory Controller Information",
        6 => "Memory Module Information",
        7 => "Cache Information",
        8 => "Port Connector Information",
        9 => "System Slots",
        10 => "On Board Devices Information",
        11 => "OEM Strings",
        12 => "System Configuration Options",
        13 => "BIOS Language Information",
        14 => "Group Associations",
        15 => "System Event Log",
        16 => "Physical Memory Array",
        17 => "Memory Device",
        18 => "32-Bit Memory Error Information",
        19 => "Memory Array Mapped Address",
        20 => "Memory Device Mapped Address",
        21 => "Built-in Pointing Device",
        22 => "Portable Battery",
        23 => "System Reset",
        24 => "Hardware Security",
        25 => "System Power Controls",
        26 => "Voltage Probe",
        27 => "Cooling Device",
        28 => "Temperature Probe",
        29 => "Electrical Current Probe",
        30 => "Out-of-Band Remote Access",
        31 => "Boot Integrity Services Entry Point",
        32 => "System Boot Information",
        33 => "64-Bit Memory Error Information",
        34 => "Management Device",
        35 => "Management Device Component",
        36 => "Management Device Threshold Data",
        37 => "Memory Channel",
        38 => "IPMI Device Information",
        39 => "System Power Supply",
        40 => "Additional Information",
        41 => "Onboard Devices Extended Information",
        42 => "Management Controller Host Interface",
        43 => "TPM Device",
        44 => "Processor Additional Information",
        45 => "Firmware Inventory Information",
        46 => "String Property",
        126 => "Inactive",
        127 => "End-of-Table",
        128..=255 => "OEM-specific",
        _ => "Unknown",
    }
}

/// A system UUID as SMBIOS 2.6 and later store it: the first three fields
/// little-endian.
pub fn uuid_text(bytes: &[u8; 16]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}",
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10..]
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<String>()
    )
}

/// The fields of a structure the specification defines, by name, for the
/// types `!sysinfo` decodes; other types have none.
pub fn structure_fields(structure: &SmbiosStructure) -> Vec<(&'static str, String)> {
    let mut fields = Vec::new();
    let s = structure;
    let mut text = |name: &'static str, value: Option<String>| {
        if let Some(value) = value {
            fields.push((name, value));
        }
    };
    let string = |offset| s.string(offset).map(str::to_string);
    let mhz = |offset| {
        s.word(offset)
            .filter(|&v| v != 0)
            .map(|v| format!("{v} MHz"))
    };
    match s.kind {
        0 => {
            text("Vendor", string(4));
            text("Version", string(5));
            text("Release Date", string(8));
            text(
                "ROM Size",
                s.byte(9)
                    .map(|size| format!("{} KiB", (u32::from(size) + 1) * 64)),
            );
            if let (Some(major), Some(minor)) = (s.byte(0x14), s.byte(0x15))
                && (major, minor) != (0xff, 0xff)
            {
                text("BIOS Release", Some(format!("{major}.{minor}")));
            }
            if let (Some(major), Some(minor)) = (s.byte(0x16), s.byte(0x17))
                && (major, minor) != (0xff, 0xff)
            {
                text("EC Firmware Release", Some(format!("{major}.{minor}")));
            }
        }
        1 => {
            text("Manufacturer", string(4));
            text("Product Name", string(5));
            text("Version", string(6));
            text("Serial Number", string(7));
            if let Some(bytes) = s.formatted.get(8..0x18) {
                text("UUID", Some(uuid_text(bytes.try_into().unwrap())));
            }
            text("SKU Number", string(0x19));
            text("Family", string(0x1a));
        }
        2 | 3 => {
            text("Manufacturer", string(4));
            if s.kind == 2 {
                text("Product", string(5));
            } else {
                text("Type", s.byte(5).map(|kind| format!("{:#x}", kind & 0x7f)));
            }
            text("Version", string(6));
            text("Serial Number", string(7));
            text("Asset Tag", string(8));
        }
        4 => {
            text("Socket Designation", string(4));
            text("Manufacturer", string(7));
            text("Version", string(0x10));
            // The CPUID leaf 1 EAX (signature) and EDX (features).
            text(
                "Processor ID",
                s.qword(8).map(|id| {
                    format!("signature {:#010x}, features {:#010x}", id as u32, id >> 32)
                }),
            );
            text("External Clock", mhz(0x12));
            text("Max Speed", mhz(0x14));
            text("Current Speed", mhz(0x16));
            text(
                "Status",
                s.byte(0x18).map(|status| {
                    format!(
                        "{:#04x} ({}, {})",
                        status,
                        if status & 0x40 != 0 {
                            "populated"
                        } else {
                            "unpopulated"
                        },
                        match status & 7 {
                            1 => "enabled",
                            2 => "disabled by user",
                            3 => "disabled by BIOS",
                            4 => "idle",
                            _ => "unknown",
                        }
                    )
                }),
            );
            text(
                "Core Count",
                s.byte(0x23)
                    .filter(|&count| count != 0)
                    .map(|count| count.to_string()),
            );
            text(
                "Core Enabled",
                s.byte(0x24)
                    .filter(|&count| count != 0)
                    .map(|count| count.to_string()),
            );
            text(
                "Thread Count",
                s.byte(0x25)
                    .filter(|&count| count != 0)
                    .map(|count| count.to_string()),
            );
        }
        16 => {
            text(
                "Maximum Capacity",
                s.dword(7).map(|kib| {
                    if kib == 0x8000_0000 {
                        s.qword(0x0f)
                            .map_or_else(|| "extended".into(), |bytes| format!("{bytes:#x} bytes"))
                    } else {
                        format!("{} MiB", kib / 1024)
                    }
                }),
            );
            text("Devices", s.word(0x0d).map(|count| count.to_string()));
        }
        17 => {
            text("Device Locator", string(0x10));
            text("Bank Locator", string(0x11));
            text(
                "Size",
                s.word(0x0c).and_then(|size| match size {
                    0 => Some("not installed".into()),
                    0xffff => Some("unknown".into()),
                    0x7fff => s.dword(0x1c).map(|mib| format!("{mib} MiB")),
                    _ if size & 0x8000 != 0 => Some(format!("{} KiB", size & 0x7fff)),
                    _ => Some(format!("{size} MiB")),
                }),
            );
            text(
                "Speed",
                s.word(0x15)
                    .filter(|&v| v != 0)
                    .map(|v| format!("{v} MT/s")),
            );
            text("Manufacturer", string(0x17));
            text("Serial Number", string(0x18));
            text("Part Number", string(0x1a));
        }
        19 => {
            if let (Some(start), Some(end)) = (s.dword(4), s.dword(8)) {
                let (start, end) = if start == u32::MAX {
                    (s.qword(0x0f).unwrap_or(0), s.qword(0x17).unwrap_or(0))
                } else {
                    (u64::from(start) * 1024, u64::from(end) * 1024 + 1023)
                };
                text("Address Range", Some(format!("{start:#x} - {end:#x}")));
            }
        }
        _ => {}
    }
    fields
}

impl Target {
    /// The SMBIOS table the kernel found at boot, read from physical memory.
    pub fn smbios_table(&self) -> Result<SmbiosTable> {
        let symbol = |name: &str| -> Result<u64> {
            let address = self
                .symbols
                .find_symbol_across_modules(self.kernel_dtb(), name)?
                .ok_or_else(|| {
                    Error::DebugInfo(format!("{name} is not in the kernel's symbols"))
                })?;
            let mut bytes = [0u8; 8];
            self.kernel_address_space()
                .read_bytes(address, &mut bytes)
                .map_err(|error| Error::DebugInfo(format!("{name}: {error}")))?;
            Ok(u64::from_le_bytes(bytes))
        };
        let physical_address = symbol("nt!WmipSMBiosTablePhysicalAddress")?;
        let length = symbol("nt!WmipSMBiosTableLength")? as u32;
        // SMBIOSVERSIONINFO: Used20CallingMethod, SMBiosMajorVersion,
        // SMBiosMinorVersion, DMIBiosRevision.
        let version_info = symbol("nt!WmipSMBiosVersionInfo")?.to_le_bytes();
        if physical_address == 0 || length == 0 {
            return Err(Error::DebugInfo(
                "the kernel found no SMBIOS table (WmipSMBiosTablePhysicalAddress is 0)".into(),
            ));
        }
        if u64::from(length) > MAX_TABLE {
            return Err(Error::DebugInfo(format!(
                "WmipSMBiosTableLength {length:#x} is more than an SMBIOS table's 64 KiB"
            )));
        }
        let mut table = vec![0u8; length as usize];
        self.read_physical(physical_address, &mut table)
            .map_err(|error| {
                Error::DebugInfo(format!(
                    "the SMBIOS table at physical {physical_address:#x}: {error}"
                ))
            })?;
        let (structures, stopped) = parse_structures(&table);
        Ok(SmbiosTable {
            physical_address,
            length,
            version: (version_info[1], version_info[2]),
            structures,
            stopped,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The start of QEMU's q35 table, as read live: a type 1 structure with
    /// three strings, then a type 3 one.
    const QEMU: &[u8] = b"\x01\x1b\x00\x01\x01\x02\x03\x00\xaa\xc3\x0f\x3d\xc0\xff\xe1\x4f\
\x9f\x82\x5e\x83\xc9\x1f\xee\xdb\x06\x00\x00QEMU\0Standard PC (Q35 + ICH9, 2009)\0\
pc-q35-10.1\0\0\x03\x16\x00\x03\x01\x01\x02\x00\x00\x03\x03\x03\x02\x00\x00\x00\x00\x00\
\x00\x00\x00\x00QEMU\0pc-q35-10.1\0\0\x7f\x04\xff\xfe\0\0";

    #[test]
    fn structures_split_at_their_double_nul() {
        let (structures, stopped) = parse_structures(QEMU);
        assert_eq!(stopped, None);
        let kinds: Vec<u8> = structures.iter().map(|s| s.kind).collect();
        assert_eq!(kinds, [1, 3, 127]);
        let system = &structures[0];
        assert_eq!(system.handle, 0x100);
        assert_eq!(system.string(4), Some("QEMU"));
        assert_eq!(system.string(5), Some("Standard PC (Q35 + ICH9, 2009)"));
        assert_eq!(system.string(7), None, "string 0 means none");
        // End-of-Table has no strings, only the two NULs.
        assert!(structures[2].strings.is_empty());
    }

    #[test]
    fn a_truncated_table_says_where_it_stopped() {
        let (structures, stopped) = parse_structures(&QEMU[..0x20]);
        assert!(structures.is_empty());
        assert!(stopped.is_some_and(|why| why.contains("do not end")));
        let (_, stopped) = parse_structures(&[0x01, 0x02, 0, 0, 0, 0]);
        assert!(stopped.is_some_and(|why| why.contains("length 2")));
    }

    #[test]
    fn uuids_swap_their_first_three_fields() {
        let bytes: [u8; 16] = QEMU[8..0x18].try_into().unwrap();
        assert_eq!(uuid_text(&bytes), "3D0FC3AA-FFC0-4FE1-9F82-5E83C91FEEDB");
    }
}
