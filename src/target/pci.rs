//! PCI: the device hierarchy pci.sys keeps (`!pcitree`), and configuration
//! space read through the backend and decoded (`!pci`).

use std::collections::HashSet;
use std::sync::atomic::Ordering;

use crate::backend::MemoryOps;
use crate::dbg_backend::PciConfigAddress;
use crate::error::{Error, Result};
use crate::session::Session;
use crate::target::Target;
use crate::types::VirtAddr;

/// Conventional configuration space; the rest of the 4 KiB is PCI Express
/// extended space.
pub const PCI_CONFIG_SIZE: usize = 0x100;
pub const PCI_EXTENDED_CONFIG_SIZE: usize = 0x1000;
pub const PCI_MAX_DEVICES: u8 = 32;
pub const PCI_MAX_FUNCTIONS: u8 = 8;

/// Tree bounds against corrupt links: nodes overall, nesting depth, segments.
const MAX_TREE_NODES: usize = 4096;
const MAX_BUS_DEPTH: usize = 32;
const MAX_SEGMENTS: usize = 64;
/// More MCFG entries than one table can describe for real (one per segment
/// bus range).
const MAX_MCFG_ENTRIES: usize = 256;
/// `ACPI_TABLE_HEADER` plus MCFG's reserved 8 bytes, and one allocation entry.
const MCFG_ENTRIES_OFFSET: usize = 44;
const MCFG_ENTRY_SIZE: usize = 16;
/// Capability-list steps before a looping list is cut off: conventional space
/// holds at most 48 capabilities, extended space 960.
const MAX_CAPABILITIES: usize = 48;
const MAX_EXTENDED_CAPABILITIES: usize = 960;
/// The PCI Express capability ID, whose presence means extended space exists.
pub const CAPABILITY_PCI_EXPRESS: u16 = 0x10;

/// pci.sys's view of the hierarchy: segments, their root buses, and each
/// bus's functions and child buses.
#[derive(Debug, Clone)]
pub struct PciTree {
    pub segments: Vec<PciTreeSegment>,
    /// The walk stopped at [`MAX_TREE_NODES`] or a nesting/link limit.
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct PciTreeSegment {
    /// The `pci!_PCI_SEGMENT`.
    pub address: VirtAddr,
    pub number: u16,
    pub root_buses: Vec<PciTreeBus>,
}

#[derive(Debug, Clone)]
pub struct PciTreeBus {
    /// The bus FDO's extension (`pci!_PCI_BUS`).
    pub extension: VirtAddr,
    pub number: u32,
    pub subordinate: u32,
    /// The PDO of the bridge that produces this bus (the root bus's comes
    /// from ACPI).
    pub bridge_pdo: VirtAddr,
    pub devices: Vec<PciTreeDevice>,
    pub child_buses: Vec<PciTreeBus>,
}

#[derive(Debug, Clone)]
pub struct PciTreeDevice {
    /// The function PDO's extension (`pci!_PCI_DEVICE`).
    pub extension: VirtAddr,
    /// The PDO, bottom of the function's device stack.
    pub device_object: VirtAddr,
    pub bus: u32,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub revision: u8,
    pub base_class: u8,
    pub sub_class: u8,
    pub prog_if: u8,
    pub subsystem_vendor_id: u16,
    pub subsystem_id: u16,
    pub header_type: u8,
    /// The PnP instance path of the PDO's device node (`PCI\VEN_...`).
    pub instance_path: Option<String>,
}

/// One ACPI MCFG allocation: segment `segment`'s buses `start_bus..=end_bus`
/// have their configuration space at `base + (bus << 20 | device << 15 |
/// function << 12)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcamWindow {
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl EcamWindow {
    /// The physical address of a function's 4 KiB configuration page, when
    /// this window covers it.
    pub fn function_page(&self, segment: u16, bus: u8, device: u8, function: u8) -> Option<u64> {
        if segment != self.segment || bus < self.start_bus || bus > self.end_bus {
            return None;
        }
        // The window starts at bus 0's page even when start_bus is higher.
        let offset =
            (u64::from(bus) << 20) | (u64::from(device) << 15) | (u64::from(function) << 12);
        self.base.checked_add(offset)
    }
}

/// The allocations in an ACPI MCFG table (`bytes`, header included). Entries
/// past the table's own length, or past what was read, are ignored.
pub fn parse_mcfg(bytes: &[u8]) -> Vec<EcamWindow> {
    if bytes.len() < MCFG_ENTRIES_OFFSET || &bytes[..4] != b"MCFG" {
        return Vec::new();
    }
    let length = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let end = length.min(bytes.len());
    bytes
        .get(MCFG_ENTRIES_OFFSET..end)
        .unwrap_or_default()
        .as_chunks::<MCFG_ENTRY_SIZE>()
        .0
        .iter()
        .take(MAX_MCFG_ENTRIES)
        .map(|entry| EcamWindow {
            base: u64::from_le_bytes([
                entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[7],
            ]),
            segment: u16::from_le_bytes([entry[8], entry[9]]),
            start_bus: entry[10],
            end_bus: entry[11],
        })
        .collect()
}

/// A function's configuration space as read (256 bytes, or 4 KiB with
/// extended space), with where it is.
#[derive(Debug, Clone)]
pub struct PciFunctionConfig {
    pub segment: u16,
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub config: Vec<u8>,
}

/// What `!pci` scans: one segment's buses `first_bus..=last_bus`, optionally
/// one device and function, reading `size` bytes of each function found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciQuery {
    pub segment: u16,
    pub first_bus: u8,
    pub last_bus: u8,
    pub device: Option<u8>,
    pub function: Option<u8>,
    pub size: usize,
}

/// `!pci`'s flag bits this implementation honors.
pub const PCI_FLAG_VERBOSE: u64 = 0x1;
pub const PCI_FLAG_BUS_RANGE: u64 = 0x2;
pub const PCI_FLAG_RAW_BYTES: u64 = 0x4;
pub const PCI_FLAG_RAW_DWORDS: u64 = 0x8;
pub const PCI_FLAG_CAPABILITIES: u64 = 0x40;
pub const PCI_FLAG_CONFIG_SPACE: u64 = 0x100;
const PCI_FLAGS: u64 = PCI_FLAG_VERBOSE
    | PCI_FLAG_BUS_RANGE
    | PCI_FLAG_RAW_BYTES
    | PCI_FLAG_RAW_DWORDS
    | PCI_FLAG_CAPABILITIES
    | PCI_FLAG_CONFIG_SPACE;

/// A parsed `!pci [flags] [bus [device [function [min max]]]]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciRequest {
    pub query: PciQuery,
    pub verbose: bool,
    pub capabilities: bool,
    pub raw: Option<PciRawRange>,
}

/// Configuration bytes `start..end` to dump, as bytes or dwords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciRawRange {
    pub start: usize,
    pub end: usize,
    pub dwords: bool,
}

/// Build a request from `!pci`'s evaluated arguments, WinDbg's way: no
/// arguments is bus 0; flag 0x2 scans buses 0 through `bus`; a raw dump
/// covers `min..=max` when given (which needs a device and function), else
/// the whole 256 bytes with 0x100, else the 64-byte header.
pub fn parse_pci_request(values: &[u64]) -> Result<PciRequest> {
    if values.len() > 6 || values.len() == 5 {
        return Err(Error::InvalidArgument(
            "expected [flags] [bus [device [function [min max]]]]".into(),
        ));
    }
    let flags = values.first().copied().unwrap_or(0);
    if flags & !PCI_FLAGS != 0 {
        return Err(Error::InvalidArgument(format!(
            "unsupported flag bits {:#x} (supported: 0x1 verbose, 0x2 buses 0 through bus, 0x4 raw \
             bytes, 0x8 raw dwords, 0x40 capabilities, 0x100 configuration space)",
            flags & !PCI_FLAGS
        )));
    }
    let byte = |index: usize, what: &str, limit: u64| -> Result<Option<u8>> {
        values
            .get(index)
            .map(|value| {
                if *value >= limit {
                    Err(Error::InvalidArgument(format!(
                        "{what} {value:#x} is out of range (0-{:#x})",
                        limit - 1
                    )))
                } else {
                    Ok(*value as u8)
                }
            })
            .transpose()
    };
    let bus = byte(1, "bus", 0x100)?.unwrap_or(0);
    let device = byte(2, "device", PCI_MAX_DEVICES.into())?;
    let function = byte(3, "function", PCI_MAX_FUNCTIONS.into())?;
    let dwords = flags & PCI_FLAG_RAW_DWORDS != 0;
    let raw = match values.get(4..6) {
        Some([min, max]) => {
            if *max >= PCI_EXTENDED_CONFIG_SIZE as u64 || min > max {
                return Err(Error::InvalidArgument(format!(
                    "configuration range {min:#x}-{max:#x} is not inside 0-0xfff"
                )));
            }
            // A dword dump covers the dwords holding `min` and `max`.
            Some(PciRawRange {
                start: if dwords { *min & !3 } else { *min } as usize,
                end: if dwords { *max | 3 } else { *max } as usize + 1,
                dwords,
            })
        }
        _ if flags & PCI_FLAG_CONFIG_SPACE != 0 => Some(PciRawRange {
            start: 0,
            end: PCI_CONFIG_SIZE,
            dwords,
        }),
        _ if flags & (PCI_FLAG_RAW_BYTES | PCI_FLAG_RAW_DWORDS) != 0 => Some(PciRawRange {
            start: 0,
            end: 0x40,
            dwords,
        }),
        _ => None,
    };
    let verbose = flags & PCI_FLAG_VERBOSE != 0;
    let capabilities = flags & PCI_FLAG_CAPABILITIES != 0;
    let extended = verbose || capabilities || raw.is_some_and(|raw| raw.end > PCI_CONFIG_SIZE);
    Ok(PciRequest {
        query: PciQuery {
            segment: 0,
            first_bus: if flags & PCI_FLAG_BUS_RANGE != 0 {
                0
            } else {
                bus
            },
            last_bus: bus,
            device,
            function,
            size: if extended {
                PCI_EXTENDED_CONFIG_SIZE
            } else {
                PCI_CONFIG_SIZE
            },
        },
        verbose,
        capabilities,
        raw,
    })
}

#[derive(Debug, Clone)]
pub struct PciScan {
    pub functions: Vec<PciFunctionConfig>,
    /// The scan stopped at a host interrupt.
    pub interrupted: bool,
}

/// The decoded type 0/1/2 configuration header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciHeader {
    pub vendor_id: u16,
    pub device_id: u16,
    pub command: u16,
    pub status: u16,
    pub revision: u8,
    pub prog_if: u8,
    pub sub_class: u8,
    pub base_class: u8,
    pub cache_line_size: u8,
    pub latency_timer: u8,
    /// Layout in the low 7 bits; bit 7 marks a multi-function device.
    pub header_type: u8,
    pub bist: u8,
    pub bars: Vec<PciBar>,
    /// Type 0 subsystem IDs (type 2 keeps them at 0x40).
    pub subsystem: Option<(u16, u16)>,
    /// Expansion ROM base register (type 0 at 0x30, type 1 at 0x38).
    pub expansion_rom: Option<u32>,
    /// Type 1/2 primary, secondary, subordinate bus numbers.
    pub buses: Option<(u8, u8, u8)>,
    pub capabilities_pointer: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciHeader {
    pub fn layout(&self) -> u8 {
        self.header_type & 0x7f
    }

    pub fn multifunction(&self) -> bool {
        self.header_type & 0x80 != 0
    }

    pub fn has_capabilities(&self) -> bool {
        self.status & 0x10 != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciBarKind {
    Io,
    Memory32,
    /// Below 1 MiB (legacy type 01b).
    Memory1M,
    Memory64,
}

impl PciBarKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Io => "io",
            Self::Memory32 => "mem32",
            Self::Memory1M => "mem1m",
            Self::Memory64 => "mem64",
        }
    }
}

/// A base address register: its index, the raw register (both halves of a
/// 64-bit BAR), and the address it decodes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciBar {
    pub index: u8,
    pub raw: u64,
    pub kind: PciBarKind,
    pub address: u64,
    pub prefetchable: bool,
}

/// A capability-list entry: its offset, ID, and (extended capabilities) the
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciCapability {
    pub offset: u16,
    pub id: u16,
    pub version: Option<u8>,
}

fn u16_at(config: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([config[offset], config[offset + 1]])
}

fn u32_at(config: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        config[offset],
        config[offset + 1],
        config[offset + 2],
        config[offset + 3],
    ])
}

/// Decode the header in `config` (at least the first 64 bytes).
pub fn parse_header(config: &[u8]) -> Option<PciHeader> {
    if config.len() < 0x40 {
        return None;
    }
    let header_type = config[0x0e];
    let bar_count = match header_type & 0x7f {
        0 => 6,
        1 => 2,
        _ => 0,
    };
    let mut bars = Vec::new();
    let mut index = 0;
    while index < bar_count {
        let offset = 0x10 + usize::from(index) * 4;
        let low = u32_at(config, offset);
        let this = index;
        index += 1;
        if low == 0 {
            continue;
        }
        let bar = if low & 1 != 0 {
            PciBar {
                index: this,
                raw: low.into(),
                kind: PciBarKind::Io,
                address: u64::from(low & !0x3),
                prefetchable: false,
            }
        } else {
            let prefetchable = low & 0x8 != 0;
            match (low >> 1) & 0x3 {
                2 if index < bar_count => {
                    let high = u32_at(config, offset + 4);
                    index += 1;
                    let raw = u64::from(low) | (u64::from(high) << 32);
                    PciBar {
                        index: this,
                        raw,
                        kind: PciBarKind::Memory64,
                        address: raw & !0xf,
                        prefetchable,
                    }
                }
                1 => PciBar {
                    index: this,
                    raw: low.into(),
                    kind: PciBarKind::Memory1M,
                    address: u64::from(low & !0xf),
                    prefetchable,
                },
                _ => PciBar {
                    index: this,
                    raw: low.into(),
                    kind: PciBarKind::Memory32,
                    address: u64::from(low & !0xf),
                    prefetchable,
                },
            }
        };
        bars.push(bar);
    }
    let (subsystem, expansion_rom, buses) = match header_type & 0x7f {
        0 => (
            Some((u16_at(config, 0x2c), u16_at(config, 0x2e))),
            Some(u32_at(config, 0x30)),
            None,
        ),
        1 => (
            None,
            Some(u32_at(config, 0x38)),
            Some((config[0x18], config[0x19], config[0x1a])),
        ),
        2 => (
            (config.len() >= 0x44).then(|| (u16_at(config, 0x40), u16_at(config, 0x42))),
            None,
            Some((config[0x18], config[0x19], config[0x1a])),
        ),
        _ => (None, None, None),
    };
    Some(PciHeader {
        vendor_id: u16_at(config, 0),
        device_id: u16_at(config, 2),
        command: u16_at(config, 4),
        status: u16_at(config, 6),
        revision: config[8],
        prog_if: config[9],
        sub_class: config[0x0a],
        base_class: config[0x0b],
        cache_line_size: config[0x0c],
        latency_timer: config[0x0d],
        header_type,
        bist: config[0x0f],
        bars,
        subsystem,
        expansion_rom,
        buses,
        // Type 2 keeps its capability pointer at 0x14.
        capabilities_pointer: if header_type & 0x7f == 2 {
            config[0x14]
        } else {
            config[0x34]
        },
        interrupt_line: config[0x3c],
        interrupt_pin: config[0x3d],
    })
}

/// The conventional capability list, following the header's pointer through
/// `config` (256 bytes). Stops at a pointer into the header or out of range,
/// and at a loop.
pub fn capabilities(header: &PciHeader, config: &[u8]) -> Vec<PciCapability> {
    let mut found = Vec::new();
    if !header.has_capabilities() {
        return found;
    }
    let mut seen = HashSet::new();
    let mut offset = usize::from(header.capabilities_pointer & 0xfc);
    while offset >= 0x40
        && offset + 1 < config.len().min(PCI_CONFIG_SIZE)
        && found.len() < MAX_CAPABILITIES
        && seen.insert(offset)
    {
        found.push(PciCapability {
            offset: offset as u16,
            id: config[offset].into(),
            version: None,
        });
        offset = usize::from(config[offset + 1] & 0xfc);
    }
    found
}

/// The PCI Express extended capability list from 0x100, when `config` holds
/// extended space. An all-zero or all-ones first header means none.
pub fn extended_capabilities(config: &[u8]) -> Vec<PciCapability> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let mut offset = PCI_CONFIG_SIZE;
    while offset >= PCI_CONFIG_SIZE
        && offset + 4 <= config.len()
        && found.len() < MAX_EXTENDED_CAPABILITIES
        && seen.insert(offset)
    {
        let header = u32_at(config, offset);
        if header == 0 || header == u32::MAX {
            break;
        }
        found.push(PciCapability {
            offset: offset as u16,
            id: (header & 0xffff) as u16,
            version: Some(((header >> 16) & 0xf) as u8),
        });
        offset = ((header >> 20) & 0xffc) as usize;
    }
    found
}

/// The PCI-SIG name of a conventional capability ID.
pub fn capability_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x01 => "Power Management",
        0x02 => "AGP",
        0x03 => "VPD",
        0x04 => "Slot ID",
        0x05 => "MSI",
        0x06 => "CompactPCI Hot Swap",
        0x07 => "PCI-X",
        0x08 => "HyperTransport",
        0x09 => "Vendor Specific",
        0x0a => "Debug Port",
        0x0b => "CompactPCI Resource Control",
        0x0c => "PCI Hot-Plug",
        0x0d => "Bridge Subsystem ID",
        0x0e => "AGP 8x",
        0x0f => "Secure Device",
        0x10 => "PCI Express",
        0x11 => "MSI-X",
        0x12 => "SATA Configuration",
        0x13 => "Advanced Features",
        0x14 => "Enhanced Allocation",
        0x15 => "Flattening Portal Bridge",
        _ => return None,
    })
}

/// The PCI-SIG name of a PCI Express extended capability ID.
pub fn extended_capability_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x01 => "Advanced Error Reporting",
        0x02 | 0x09 => "Virtual Channel",
        0x03 => "Device Serial Number",
        0x04 => "Power Budgeting",
        0x05 => "Root Complex Link Declaration",
        0x06 => "Root Complex Internal Link Control",
        0x07 => "Root Complex Event Collector Endpoint Association",
        0x08 => "Multi-Function Virtual Channel",
        0x0a => "RCRB Header",
        0x0b => "Vendor Specific",
        0x0c => "Configuration Access Correlation",
        0x0d => "Access Control Services",
        0x0e => "Alternative Routing-ID Interpretation",
        0x0f => "Address Translation Services",
        0x10 => "Single Root I/O Virtualization",
        0x11 => "Multi-Root I/O Virtualization",
        0x12 => "Multicast",
        0x13 => "Page Request",
        0x15 => "Resizable BAR",
        0x16 => "Dynamic Power Allocation",
        0x17 => "TPH Requester",
        0x18 => "Latency Tolerance Reporting",
        0x19 => "Secondary PCI Express",
        0x1a => "Protocol Multiplexing",
        0x1b => "Process Address Space ID",
        0x1c => "LN Requester",
        0x1d => "Downstream Port Containment",
        0x1e => "L1 PM Substates",
        0x1f => "Precision Time Measurement",
        0x20 => "M-PCIe",
        0x21 => "FRS Queueing",
        0x22 => "Readiness Time Reporting",
        0x23 => "Designated Vendor-Specific",
        0x24 => "VF Resizable BAR",
        0x25 => "Data Link Feature",
        0x26 => "Physical Layer 16.0 GT/s",
        0x27 => "Lane Margining at the Receiver",
        0x28 => "Hierarchy ID",
        0x29 => "Native PCIe Enclosure Management",
        0x2a => "Physical Layer 32.0 GT/s",
        0x2b => "Alternate Protocol",
        0x2c => "System Firmware Intermediary",
        0x2d => "Shadow Functions",
        0x2e => "Data Object Exchange",
        0x2f => "Device 3",
        0x30 => "Integrity and Data Encryption",
        0x31 => "Physical Layer 64.0 GT/s",
        _ => return None,
    })
}

/// The PCI class code's base class and sub-class names, `Base/Sub` as WinDbg
/// prints them (`Bridge/PCI to PCI`); the base alone for an unlisted
/// sub-class.
pub fn class_name(base_class: u8, sub_class: u8) -> Option<String> {
    let (base, subs): (&str, &[(u8, &str)]) = match base_class {
        0x00 => ("Pre-2.0", &[(0x00, "Non-VGA"), (0x01, "VGA")]),
        0x01 => (
            "Mass Storage Controller",
            &[
                (0x00, "SCSI"),
                (0x01, "IDE"),
                (0x02, "Floppy"),
                (0x03, "IPI"),
                (0x04, "RAID"),
                (0x05, "ATA"),
                (0x06, "SATA"),
                (0x07, "SAS"),
                (0x08, "NVM"),
                (0x09, "UFS"),
                (0x80, "Other"),
            ],
        ),
        0x02 => (
            "Network Controller",
            &[
                (0x00, "Ethernet"),
                (0x01, "Token Ring"),
                (0x02, "FDDI"),
                (0x03, "ATM"),
                (0x04, "ISDN"),
                (0x05, "WorldFip"),
                (0x06, "PICMG"),
                (0x07, "InfiniBand"),
                (0x08, "Fabric"),
                (0x80, "Other"),
            ],
        ),
        0x03 => (
            "Display Controller",
            &[(0x00, "VGA"), (0x01, "XGA"), (0x02, "3D"), (0x80, "Other")],
        ),
        0x04 => (
            "Multimedia Device",
            &[
                (0x00, "Video"),
                (0x01, "Audio"),
                (0x02, "Telephony"),
                (0x03, "HD Audio"),
                (0x80, "Other"),
            ],
        ),
        0x05 => (
            "Memory Controller",
            &[
                (0x00, "RAM"),
                (0x01, "Flash"),
                (0x02, "CXL"),
                (0x80, "Other"),
            ],
        ),
        0x06 => (
            "Bridge",
            &[
                (0x00, "HOST to PCI"),
                (0x01, "PCI to ISA"),
                (0x02, "PCI to EISA"),
                (0x03, "PCI to MCA"),
                (0x04, "PCI to PCI"),
                (0x05, "PCI to PCMCIA"),
                (0x06, "PCI to NUBUS"),
                (0x07, "PCI to CardBus"),
                (0x08, "RACEway"),
                (0x09, "Semi-transparent PCI to PCI"),
                (0x0a, "InfiniBand to PCI"),
                (0x0b, "Advanced Switching to PCI"),
                (0x80, "Other"),
            ],
        ),
        0x07 => (
            "Simple Serial Communications Controller",
            &[
                (0x00, "Serial Port"),
                (0x01, "Parallel Port"),
                (0x02, "Multiport Serial"),
                (0x03, "Modem"),
                (0x04, "GPIB"),
                (0x05, "Smart Card"),
                (0x80, "Other"),
            ],
        ),
        0x08 => (
            "Base System Device",
            &[
                (0x00, "Interrupt Controller"),
                (0x01, "DMA Controller"),
                (0x02, "System Timer"),
                (0x03, "Real-Time Clock"),
                (0x04, "PCI Hot-Plug Controller"),
                (0x05, "SD Host Controller"),
                (0x06, "IOMMU"),
                (0x07, "Root Complex Event Collector"),
                (0x80, "Other"),
            ],
        ),
        0x09 => (
            "Input Device",
            &[
                (0x00, "Keyboard"),
                (0x01, "Digitizer"),
                (0x02, "Mouse"),
                (0x03, "Scanner"),
                (0x04, "Gameport"),
                (0x80, "Other"),
            ],
        ),
        0x0a => ("Docking Station", &[(0x00, "Generic"), (0x80, "Other")]),
        0x0b => (
            "Processor",
            &[
                (0x00, "386"),
                (0x01, "486"),
                (0x02, "Pentium"),
                (0x10, "Alpha"),
                (0x20, "PowerPC"),
                (0x30, "MIPS"),
                (0x40, "Co-processor"),
                (0x80, "Other"),
            ],
        ),
        0x0c => (
            "Serial Bus Controller",
            &[
                (0x00, "IEEE 1394"),
                (0x01, "ACCESS.bus"),
                (0x02, "SSA"),
                (0x03, "USB"),
                (0x04, "Fibre Channel"),
                (0x05, "SMBus"),
                (0x06, "InfiniBand"),
                (0x07, "IPMI"),
                (0x08, "SERCOS"),
                (0x09, "CANbus"),
                (0x0a, "MIPI I3C"),
                (0x80, "Other"),
            ],
        ),
        0x0d => (
            "Wireless Controller",
            &[
                (0x00, "iRDA"),
                (0x01, "Consumer IR"),
                (0x10, "RF"),
                (0x11, "Bluetooth"),
                (0x12, "Broadband"),
                (0x20, "802.11a"),
                (0x21, "802.11b"),
                (0x80, "Other"),
            ],
        ),
        0x0e => ("Intelligent I/O Controller", &[(0x00, "I2O")]),
        0x0f => (
            "Satellite Communication Controller",
            &[
                (0x01, "TV"),
                (0x02, "Audio"),
                (0x03, "Voice"),
                (0x04, "Data"),
            ],
        ),
        0x10 => (
            "Encryption/Decryption Controller",
            &[(0x00, "Network"), (0x10, "Entertainment"), (0x80, "Other")],
        ),
        0x11 => (
            "Data Acquisition/Signal Processing",
            &[
                (0x00, "DPIO"),
                (0x01, "Performance Counters"),
                (0x10, "Communications Synchronizer"),
                (0x20, "Management Card"),
                (0x80, "Other"),
            ],
        ),
        0x12 => ("Processing Accelerator", &[]),
        0x13 => ("Non-Essential Instrumentation", &[]),
        0xff => ("Unassigned", &[]),
        _ => return None,
    };
    Some(match subs.iter().find(|(code, _)| *code == sub_class) {
        Some((_, sub)) => format!("{base}/{sub}"),
        None => base.to_string(),
    })
}

/// Command-register bits set, by name.
pub fn command_flags(command: u16) -> Vec<&'static str> {
    const BITS: [(u16, &str); 10] = [
        (0x0001, "IoSpace"),
        (0x0002, "MemorySpace"),
        (0x0004, "BusMaster"),
        (0x0008, "SpecialCycles"),
        (0x0010, "MemWriteInvalidate"),
        (0x0020, "VgaPaletteSnoop"),
        (0x0040, "ParityErrorResponse"),
        (0x0100, "SERR"),
        (0x0200, "FastBackToBack"),
        (0x0400, "InterruptDisable"),
    ];
    flags(command, &BITS)
}

/// Status-register bits set, by name.
pub fn status_flags(status: u16) -> Vec<&'static str> {
    const BITS: [(u16, &str); 11] = [
        (0x0008, "InterruptPending"),
        (0x0010, "CapList"),
        (0x0020, "66MHz"),
        (0x0080, "FastBackToBack"),
        (0x0100, "MasterDataParityError"),
        (0x0800, "SignaledTargetAbort"),
        (0x1000, "ReceivedTargetAbort"),
        (0x2000, "ReceivedMasterAbort"),
        (0x4000, "SignaledSystemError"),
        (0x8000, "DetectedParityError"),
        (0x0001, "ImmediateReadiness"),
    ];
    flags(status, &BITS)
}

fn flags(value: u16, bits: &[(u16, &'static str)]) -> Vec<&'static str> {
    bits.iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

impl Target {
    /// The ECAM windows in the firmware's ACPI MCFG table, which the HAL keeps
    /// mapped (`HalpPciMcfgTable`; in hal.dll before the HAL moved into the
    /// kernel).
    pub fn pci_ecam_windows(&self) -> Result<Vec<EcamWindow>> {
        let dtb = self.kernel_dtb();
        let table = ["nt!HalpPciMcfgTable", "hal!HalpPciMcfgTable"]
            .into_iter()
            .find_map(|name| {
                self.symbols
                    .find_symbol_across_modules(dtb, name)
                    .ok()
                    .flatten()
            })
            .ok_or_else(|| {
                Error::SymbolNotFound("HalpPciMcfgTable (the HAL's ACPI MCFG table)".into())
            })?;
        let memory = self.kernel_address_space();
        let table: VirtAddr = memory.read(table)?;
        if table.is_zero() {
            return Ok(Vec::new());
        }
        let mut header = [0u8; 8];
        memory.read_bytes(table, &mut header)?;
        let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let length = length.min(MCFG_ENTRIES_OFFSET + MAX_MCFG_ENTRIES * MCFG_ENTRY_SIZE);
        if &header[..4] != b"MCFG" || length < MCFG_ENTRIES_OFFSET {
            return Err(Error::DebugInfo(format!(
                "HalpPciMcfgTable ({table}) does not hold an ACPI MCFG table"
            )));
        }
        let mut bytes = vec![0; length];
        memory.read_bytes(table, &mut bytes)?;
        Ok(parse_mcfg(&bytes))
    }

    /// pci.sys's bus and function hierarchy, from `pci!PciSegmentList`
    /// (`!pcitree`). Reads guest memory only.
    pub fn pci_tree(&self) -> Result<PciTree> {
        let dtb = self.kernel_dtb();
        let list = self
            .symbols
            .find_symbol_across_modules(dtb, "pci!PciSegmentList")?
            .ok_or_else(|| {
                Error::SymbolNotFound(
                    "pci!PciSegmentList (pci.sys's symbols are needed; Windows 8 and later)".into(),
                )
            })?;
        let mut walk = TreeWalk {
            target: self,
            seen: HashSet::new(),
            truncated: false,
        };
        let mut segments = Vec::new();
        let mut next: VirtAddr = self.kernel_address_space().read(list)?;
        while !next.is_zero() {
            if segments.len() >= MAX_SEGMENTS || !walk.seen.insert(next.0) {
                walk.truncated = true;
                break;
            }
            let segment = self.types_in(dtb).struct_at("pci!_PCI_SEGMENT", next)?;
            let mut root_buses = Vec::new();
            let mut bus = segment.read_pointer("PciRootBusList")?;
            while !bus.is_zero() && !walk.exhausted() {
                let (node, sibling) = walk.bus(bus, 0)?;
                root_buses.extend(node);
                bus = sibling;
            }
            segments.push(PciTreeSegment {
                address: next,
                number: segment.read_field("SegmentNumber")?,
                root_buses,
            });
            next = segment.read_pointer("Next")?;
        }
        Ok(PciTree {
            segments,
            truncated: walk.truncated,
        })
    }
}

struct TreeWalk<'a> {
    target: &'a Target,
    seen: HashSet<u64>,
    truncated: bool,
}

impl TreeWalk<'_> {
    fn exhausted(&mut self) -> bool {
        if self.seen.len() >= MAX_TREE_NODES {
            self.truncated = true;
        }
        self.truncated
    }

    /// Visit `address` once; a repeat (a looping link) truncates.
    fn visit(&mut self, address: VirtAddr) -> bool {
        if self.exhausted() {
            return false;
        }
        if !self.seen.insert(address.0) {
            self.truncated = true;
            return false;
        }
        true
    }

    /// The bus at `address` with its functions and child buses, and its
    /// `SiblingBus` link.
    fn bus(&mut self, address: VirtAddr, depth: usize) -> Result<(Option<PciTreeBus>, VirtAddr)> {
        let types = self.target.types_in(self.target.kernel_dtb());
        let bus = types.struct_at("pci!_PCI_BUS", address)?;
        let sibling = bus.read_pointer("SiblingBus")?;
        if depth >= MAX_BUS_DEPTH || !self.visit(address) {
            self.truncated = true;
            return Ok((None, VirtAddr(0)));
        }
        let mut devices = Vec::new();
        let mut device = bus.read_pointer("ChildDevices")?;
        while !device.is_zero() && self.visit(device) {
            let (node, next) = self.device(device)?;
            devices.push(node);
            device = next;
        }
        let mut child_buses = Vec::new();
        let mut child = bus.read_pointer("ChildBuses")?;
        while !child.is_zero() && !self.exhausted() {
            let (node, next) = self.bus(child, depth + 1)?;
            child_buses.extend(node);
            child = next;
        }
        Ok((
            Some(PciTreeBus {
                extension: address,
                number: bus.read_field("SecondaryBusNumber")?,
                subordinate: bus.read_field("SubordinateBusNumber")?,
                bridge_pdo: bus.read_pointer("PhysicalDeviceObject")?,
                devices,
                child_buses,
            }),
            sibling,
        ))
    }

    /// The function whose `_PCI_DEVICE` is at `address`, and its `Sibling`.
    fn device(&self, address: VirtAddr) -> Result<(PciTreeDevice, VirtAddr)> {
        let types = self.target.types_in(self.target.kernel_dtb());
        let device = types.struct_at("pci!_PCI_DEVICE", address)?;
        let slot: u32 = device.read_field("Slot")?;
        let device_object = device.read_pointer("DeviceObject")?;
        let node = PciTreeDevice {
            extension: address,
            device_object,
            bus: device.read_field("BusNumber")?,
            device: (slot & 0x1f) as u8,
            function: ((slot >> 5) & 0x7) as u8,
            vendor_id: device.read_field("VendorID")?,
            device_id: device.read_field("DeviceID")?,
            revision: device.read_field("RevisionID")?,
            base_class: device.read_field("BaseClass")?,
            sub_class: device.read_field("SubClass")?,
            prog_if: device.read_field("ProgIf")?,
            subsystem_vendor_id: device.read_field("SubVendorID")?,
            subsystem_id: device.read_field("SubSystemID")?,
            header_type: device.read_field("HeaderType")?,
            instance_path: self.instance_path(device_object),
        };
        Ok((node, device.read_pointer("Sibling")?))
    }

    /// The PDO's device node instance path, as `!devnode` shows it.
    fn instance_path(&self, pdo: VirtAddr) -> Option<String> {
        if pdo.is_zero() {
            return None;
        }
        let types = self.target.guest().ok()?.ntoskrnl.types();
        let extension = types
            .struct_at("_DEVICE_OBJECT", pdo)
            .ok()?
            .read_pointer("DeviceObjectExtension")
            .ok()?;
        let node = types
            .struct_at("_DEVOBJ_EXTENSION", extension)
            .ok()?
            .read_pointer("DeviceNode")
            .ok()?;
        if node.is_zero() {
            return None;
        }
        types
            .struct_at("_DEVICE_NODE", node)
            .ok()?
            .unicode_string("InstancePath")
            .ok()
    }
}

/// [`Error::TargetRunning`] payload for configuration-space reads.
const PCI_CONFIG_NEEDS_HALT: &str = "PCI configuration space is read on a halted target.";

impl Session {
    /// Refuse a configuration-space read the backend cannot make, saying why,
    /// or one the target cannot take while running.
    fn check_pci_config(&self) -> Result<()> {
        if !self.backend.supports_pci_config() {
            return Err(Error::DebugInfo(format!(
                "the {} backend cannot read PCI configuration space: it is device registers \
                 (the ECAM window or ports 0xcf8/0xcfc), not the RAM this backend reads; use \
                 the gdb backend (QEMU) or kd/kdnet",
                self.backend.name()
            )));
        }
        if self.backend.is_running() {
            return Err(Error::TargetRunning(PCI_CONFIG_NEEDS_HALT));
        }
        Ok(())
    }

    /// Read `len` bytes of a function's configuration space from `offset`.
    fn read_function_config(
        &mut self,
        windows: &[EcamWindow],
        segment: u16,
        bus: u8,
        device: u8,
        function: u8,
        offset: u16,
        len: usize,
    ) -> Result<Vec<u8>> {
        let ecam = windows
            .iter()
            .find_map(|window| window.function_page(segment, bus, device, function));
        let mut config = vec![0; len];
        self.backend.read_pci_config(
            PciConfigAddress {
                segment,
                bus,
                device,
                function,
                ecam,
            },
            offset,
            &mut config,
        )?;
        Ok(config)
    }

    /// Scan configuration space as `!pci` does: each device's function 0,
    /// and functions 1-7 of a multi-function device, reading `query.size`
    /// bytes of every function whose vendor ID is not all-ones. A named
    /// function is read whatever function 0 says.
    pub fn scan_pci(&mut self, query: &PciQuery) -> Result<PciScan> {
        if let Some(device) = query.device.filter(|device| *device >= PCI_MAX_DEVICES) {
            return Err(Error::InvalidArgument(format!(
                "PCI device {device:#x} is out of range (0-0x1f)"
            )));
        }
        if let Some(function) = query
            .function
            .filter(|function| *function >= PCI_MAX_FUNCTIONS)
        {
            return Err(Error::InvalidArgument(format!(
                "PCI function {function:#x} is out of range (0-7)"
            )));
        }
        if query.first_bus > query.last_bus {
            return Err(Error::InvalidArgument(format!(
                "bus range {:#x}-{:#x} is empty",
                query.first_bus, query.last_bus
            )));
        }
        self.check_pci_config()?;
        let size = query.size.clamp(0x40, PCI_EXTENDED_CONFIG_SIZE);
        // Only the gdb backend needs them; a missing table is its error then.
        let windows = self.target.pci_ecam_windows().unwrap_or_default();
        let interrupt = std::sync::Arc::clone(&self.target.interrupt);
        let mut scan = PciScan {
            functions: Vec::new(),
            interrupted: false,
        };
        for bus in query.first_bus..=query.last_bus {
            let devices = match query.device {
                Some(device) => device..=device,
                None => 0..=PCI_MAX_DEVICES - 1,
            };
            for device in devices {
                if interrupt.load(Ordering::Relaxed) {
                    scan.interrupted = true;
                    return Ok(scan);
                }
                let functions = match query.function {
                    Some(function) => function..=function,
                    None => {
                        let head = self.read_function_config(
                            &windows,
                            query.segment,
                            bus,
                            device,
                            0,
                            0,
                            0x10,
                        )?;
                        if u16_at(&head, 0) == u16::MAX {
                            continue;
                        }
                        let last = if head[0x0e] & 0x80 != 0 {
                            PCI_MAX_FUNCTIONS - 1
                        } else {
                            0
                        };
                        0..=last
                    }
                };
                for function in functions {
                    let config = self.read_function_config(
                        &windows,
                        query.segment,
                        bus,
                        device,
                        function,
                        0,
                        size,
                    )?;
                    if u16_at(&config, 0) == u16::MAX {
                        continue;
                    }
                    scan.functions.push(PciFunctionConfig {
                        segment: query.segment,
                        bus,
                        device,
                        function,
                        config,
                    });
                }
            }
        }
        Ok(scan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Vec<u8> {
        let mut config = vec![0u8; PCI_CONFIG_SIZE];
        config[..4].copy_from_slice(&[0xf4, 0x1a, 0x41, 0x10]);
        config[6] = 0x10; // capability list
        config[0x0b] = 0x02;
        config
    }

    #[test]
    fn a_64_bit_bar_takes_the_next_register_and_the_last_slot_cannot_start_one() {
        let mut config = config();
        // BAR0: I/O at 0xc040; BAR1-2: 64-bit prefetchable memory; BAR5
        // claims 64-bit but has no register after it.
        config[0x10..0x14].copy_from_slice(&0xc041u32.to_le_bytes());
        config[0x14..0x18].copy_from_slice(&0xfe00_000cu32.to_le_bytes());
        config[0x18..0x1c].copy_from_slice(&0x1u32.to_le_bytes());
        config[0x24..0x28].copy_from_slice(&0xfea4_0004u32.to_le_bytes());
        let header = parse_header(&config).unwrap();
        assert_eq!(header.bars.len(), 3);
        assert_eq!(header.bars[0].kind, PciBarKind::Io);
        assert_eq!(header.bars[0].address, 0xc040);
        assert_eq!(header.bars[1].index, 1);
        assert_eq!(header.bars[1].kind, PciBarKind::Memory64);
        assert!(header.bars[1].prefetchable);
        assert_eq!(header.bars[1].address, 0x1_fe00_0000);
        assert_eq!(header.bars[2].index, 5);
        assert_eq!(header.bars[2].kind, PciBarKind::Memory32);
        assert_eq!(header.bars[2].address, 0xfea4_0000);
    }

    #[test]
    fn a_bridge_header_has_two_bars_and_bus_numbers() {
        let mut config = config();
        config[0x0e] = 0x81;
        config[0x18..0x1b].copy_from_slice(&[0, 1, 3]);
        config[0x20..0x24].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        let header = parse_header(&config).unwrap();
        assert!(header.multifunction());
        assert_eq!(header.layout(), 1);
        assert!(header.bars.is_empty());
        assert_eq!(header.buses, Some((0, 1, 3)));
    }

    #[test]
    fn capability_walks_stop_at_loops_and_pointers_into_the_header() {
        let mut config = config();
        config[0x34] = 0x40;
        config[0x40..0x42].copy_from_slice(&[0x11, 0x50]);
        config[0x50..0x52].copy_from_slice(&[0x05, 0x40]); // back to 0x40
        let header = parse_header(&config).unwrap();
        let ids: Vec<u16> = capabilities(&header, &config)
            .iter()
            .map(|capability| capability.id)
            .collect();
        assert_eq!(ids, [0x11, 0x05]);

        config[0x51] = 0x3c; // into the header
        let header = parse_header(&config).unwrap();
        assert_eq!(capabilities(&header, &config).len(), 2);

        config[6] = 0; // no capability list
        let header = parse_header(&config).unwrap();
        assert!(capabilities(&header, &config).is_empty());
    }

    #[test]
    fn extended_capabilities_follow_next_offsets_until_zero_or_all_ones() {
        let mut config = vec![0u8; PCI_EXTENDED_CONFIG_SIZE];
        config[0x100..0x104]
            .copy_from_slice(&(0x0001u32 | (2 << 16) | (0x148 << 20)).to_le_bytes());
        config[0x148..0x14c]
            .copy_from_slice(&(0x000eu32 | (1 << 16) | (0x100 << 20)).to_le_bytes());
        let found = extended_capabilities(&config);
        assert_eq!(found.len(), 2, "the loop back to 0x100 ends the walk");
        assert_eq!((found[0].id, found[0].version), (0x01, Some(2)));
        assert_eq!((found[1].offset, found[1].id), (0x148, 0x0e));

        config[0x100..0x104].fill(0xff);
        assert!(extended_capabilities(&config).is_empty());
        assert!(extended_capabilities(&config[..PCI_CONFIG_SIZE]).is_empty());
    }

    #[test]
    fn pci_arguments_select_buses_and_the_raw_range_windbg_style() {
        let request = parse_pci_request(&[]).unwrap();
        assert_eq!((request.query.first_bus, request.query.last_bus), (0, 0));
        assert_eq!(request.query.size, PCI_CONFIG_SIZE);
        assert_eq!(request.raw, None);

        let request = parse_pci_request(&[0x2, 0x3]).unwrap();
        assert_eq!((request.query.first_bus, request.query.last_bus), (0, 3));

        let request = parse_pci_request(&[0x100, 0, 2, 0]).unwrap();
        assert_eq!(
            request.raw,
            Some(PciRawRange {
                start: 0,
                end: PCI_CONFIG_SIZE,
                dwords: false
            })
        );
        assert_eq!(request.query.size, PCI_CONFIG_SIZE);

        // A range into extended space reads it; a dword dump covers the
        // dwords holding both ends.
        let request = parse_pci_request(&[0x8, 0, 2, 0, 0x102, 0x10d]).unwrap();
        assert_eq!(
            request.raw,
            Some(PciRawRange {
                start: 0x100,
                end: 0x110,
                dwords: true
            })
        );
        assert_eq!(request.query.size, PCI_EXTENDED_CONFIG_SIZE);

        assert!(parse_pci_request(&[0, 0, 0x20]).is_err());
        assert!(parse_pci_request(&[0, 0x100]).is_err());
        assert!(parse_pci_request(&[0, 0, 0, 0, 0x10]).is_err());
        assert!(parse_pci_request(&[0, 0, 0, 0, 0x20, 0x10]).is_err());
        assert!(parse_pci_request(&[0, 0, 0, 0, 0, 0x1000]).is_err());
        assert!(parse_pci_request(&[0x10]).is_err());
    }

    #[test]
    fn mcfg_entries_stop_at_the_table_length() {
        let mut table = vec![0u8; MCFG_ENTRIES_OFFSET + 2 * MCFG_ENTRY_SIZE];
        table[..4].copy_from_slice(b"MCFG");
        // Declares one entry and 8 stray bytes; the second entry is outside.
        let length = (MCFG_ENTRIES_OFFSET + MCFG_ENTRY_SIZE + 8) as u32;
        table[4..8].copy_from_slice(&length.to_le_bytes());
        table[44..52].copy_from_slice(&0xe000_0000u64.to_le_bytes());
        table[54] = 0;
        table[55] = 0xff;
        let windows = parse_mcfg(&table);
        assert_eq!(
            windows,
            [EcamWindow {
                base: 0xe000_0000,
                segment: 0,
                start_bus: 0,
                end_bus: 0xff,
            }]
        );
        assert_eq!(
            windows[0].function_page(0, 1, 2, 3),
            Some(0xe000_0000 + (1 << 20) + (2 << 15) + (3 << 12))
        );
        assert_eq!(windows[0].function_page(1, 1, 2, 3), None);
        assert!(parse_mcfg(&table[..40]).is_empty());
        table[0] = b'X';
        assert!(parse_mcfg(&table).is_empty());
    }
}
