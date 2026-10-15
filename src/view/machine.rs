//! Interrupt controllers and firmware tables as SDK records: a processor's
//! local APIC (`!apic`), the interrupt controllers the HAL registered
//! (`!ioapic`), and the SMBIOS table (`!sysinfo`).

use ntoseye_macros::record;

use crate::target::apic::{self, bitmap_vectors, decode_icr, timer_divisor};
use crate::target::smbios::{self, structure_fields, structure_name};
use crate::types::VirtAddr;

/// A local vector table entry.
#[record]
pub struct ApicLvt {
    /// `Timer`, `LINT0`, `LINT1`, `Error`, `PerfMon`, `Thermal`, or
    /// `CMCI`.
    pub name: &'static str,
    #[record(hex)]
    pub raw: u32,
    #[record(hex)]
    pub vector: u8,
    /// `Fixed`, `SMI`, `NMI`, `INIT`, `ExtINT`, or the mode in hex.
    pub delivery: String,
    pub pending: bool,
    pub active_low: bool,
    pub remote_irr: bool,
    pub level: bool,
    pub masked: bool,
    /// The timer's mode: `one-shot`, `periodic`, or `TSC-deadline`.
    pub timer_mode: Option<&'static str>,
}

/// The interrupt command register.
#[record]
pub struct ApicIcr {
    #[record(hex)]
    pub raw: u64,
    #[record(hex)]
    pub vector: u8,
    pub delivery: String,
    pub logical: bool,
    pub pending: bool,
    pub level_assert: bool,
    pub level_triggered: bool,
    /// `none`, `self`, `all`, or `all-but-self`.
    pub shorthand: &'static str,
    #[record(hex)]
    pub destination: u32,
}

/// A processor's local APIC (`!apic`).
#[record]
pub struct LocalApic {
    pub processor: u16,
    /// `IA32_APIC_BASE`.
    #[record(hex)]
    pub apic_base: u64,
    /// In x2APIC mode, read through MSRs; else through its registers.
    pub x2apic: bool,
    pub bootstrap_processor: bool,
    pub enabled: bool,
    #[record(hex)]
    pub id: u32,
    #[record(hex)]
    pub version: u32,
    #[record(hex)]
    pub tpr: u32,
    #[record(hex)]
    pub ppr: u32,
    #[record(hex)]
    pub ldr: u32,
    /// The spurious-interrupt vector register.
    #[record(hex)]
    pub svr: u32,
    pub software_enabled: bool,
    /// `None` when the error status does not read.
    #[record(hex)]
    pub esr: Option<u32>,
    pub icr: ApicIcr,
    /// The LVT entries the APIC implements.
    pub lvt: Vec<ApicLvt>,
    /// The ones it does not (the thermal or CMCI entry).
    pub lvt_missing: Vec<&'static str>,
    #[record(hex)]
    pub timer_initial: u32,
    #[record(hex)]
    pub timer_current: u32,
    pub timer_divisor: u32,
    /// The vectors in service, requested, and level-triggered.
    pub isr: Vec<u8>,
    pub irr: Vec<u8>,
    pub tmr: Vec<u8>,
}

/// A line of an interrupt controller as the HAL set it up
/// (`_INTERRUPT_LINE_STATE`).
#[record]
pub struct HalLine {
    pub line: i64,
    /// The global system interrupt, for a pin.
    pub gsi: Option<u64>,
    #[record(hex)]
    pub vector: u32,
    /// The IRQL its interrupt runs at.
    pub irql: u32,
    pub level: bool,
    pub polarity: String,
    /// `_INTERRUPT_TARGET_TYPE` without its prefix, with its ID.
    pub target: String,
    #[record(hex)]
    pub flags: u32,
}

/// A range of a controller's lines (`_INTERRUPT_LINES`).
#[record]
pub struct HalLineRange {
    pub address: VirtAddr,
    /// `_INTERRUPT_LINE_TYPE` without its prefix (`StandardPin`).
    pub kind: String,
    pub min_line: i64,
    pub max_line: i64,
    pub gsi_base: Option<u64>,
    /// The lines the HAL set up.
    pub lines: Vec<HalLine>,
}

/// An interrupt controller the HAL registered
/// (`_REGISTERED_INTERRUPT_CONTROLLER`).
#[record]
pub struct HalController {
    pub address: VirtAddr,
    /// `_KNOWN_CONTROLLER_TYPE` without its prefix (`Apic`, `Pic`).
    pub kind: String,
    #[record(hex)]
    pub unit_id: u32,
    pub resource_id: String,
    pub min_line: i64,
    pub max_line: i64,
    pub problem: Option<String>,
    pub ranges: Vec<HalLineRange>,
    pub ranges_stopped: Option<String>,
}

/// A controller that does not read.
#[record]
pub struct HalUnreadable {
    pub address: VirtAddr,
    pub error: String,
}

/// The interrupt controllers on `nt!HalpRegisteredInterruptControllers`
/// (`!ioapic`).
#[record]
pub struct HalControllers {
    pub controllers: Vec<HalController>,
    pub unreadable: Vec<HalUnreadable>,
    pub stopped: Option<String>,
}

/// A field of an SMBIOS structure, by the specification's name.
#[record]
pub struct SmbiosField {
    pub name: &'static str,
    pub value: String,
}

/// An SMBIOS structure.
#[record]
pub struct SmbiosStructure {
    /// The structure type (0 BIOS, 1 system, 4 processor, 17 memory
    /// device, ...).
    pub kind: u8,
    pub kind_name: &'static str,
    #[record(hex)]
    pub handle: u16,
    /// The formatted area, its header included.
    pub formatted: Vec<u8>,
    /// The strings, string 1 first.
    pub strings: Vec<String>,
    /// The fields `!sysinfo smbios` decodes for its type.
    pub fields: Vec<SmbiosField>,
}

/// The SMBIOS table the kernel found at boot (`!sysinfo smbios`).
#[record]
pub struct SmbiosTable {
    #[record(hex)]
    pub physical_address: u64,
    pub length: u32,
    /// The version the entry point gave (`2.8`).
    pub version: String,
    pub structures: Vec<SmbiosStructure>,
    /// Why the parse stopped before End-of-Table.
    pub stopped: Option<String>,
}

pub fn local_apic(apic: &apic::LocalApic) -> LocalApic {
    let icr = decode_icr(apic.icr, apic.x2apic);
    let mut lvt = Vec::new();
    let mut lvt_missing = Vec::new();
    for (name, entry) in &apic.lvt {
        match entry {
            Some(entry) => lvt.push(ApicLvt {
                name,
                raw: entry.raw,
                vector: entry.vector,
                delivery: entry.delivery.clone(),
                pending: entry.pending,
                active_low: entry.active_low,
                remote_irr: entry.remote_irr,
                level: entry.level,
                masked: entry.masked,
                timer_mode: entry.timer_mode,
            }),
            None => lvt_missing.push(*name),
        }
    }
    LocalApic {
        processor: apic.processor,
        apic_base: apic.apic_base,
        x2apic: apic.x2apic,
        bootstrap_processor: apic.bsp(),
        enabled: apic.enabled(),
        id: apic.id,
        version: apic.version,
        tpr: apic.tpr,
        ppr: apic.ppr,
        ldr: apic.ldr,
        svr: apic.svr,
        software_enabled: apic.svr & (1 << 8) != 0,
        esr: apic.esr,
        icr: ApicIcr {
            raw: icr.raw,
            vector: icr.vector,
            delivery: icr.delivery,
            logical: icr.logical,
            pending: icr.pending,
            level_assert: icr.level_assert,
            level_triggered: icr.level_triggered,
            shorthand: icr.shorthand,
            destination: icr.destination,
        },
        lvt,
        lvt_missing,
        timer_initial: apic.timer_initial,
        timer_current: apic.timer_current,
        timer_divisor: timer_divisor(apic.timer_divide),
        isr: bitmap_vectors(&apic.isr),
        irr: bitmap_vectors(&apic.irr),
        tmr: bitmap_vectors(&apic.tmr),
    }
}

pub fn controllers(list: &apic::HalControllers) -> HalControllers {
    let mut controllers = Vec::new();
    let mut unreadable = Vec::new();
    for entry in &list.controllers {
        match entry {
            Ok(controller) => controllers.push(HalController {
                address: controller.address,
                kind: controller.kind.clone(),
                unit_id: controller.unit_id,
                resource_id: controller.resource_id.clone(),
                min_line: controller.min_line,
                max_line: controller.max_line,
                problem: controller.problem.clone(),
                ranges: controller
                    .ranges
                    .iter()
                    .map(|range| HalLineRange {
                        address: range.address,
                        kind: range.kind.clone(),
                        min_line: range.min_line,
                        max_line: range.max_line,
                        gsi_base: range.gsi_base,
                        lines: range
                            .lines
                            .iter()
                            .map(|line| HalLine {
                                line: line.line,
                                gsi: line.gsi,
                                vector: line.vector,
                                irql: line.irql,
                                level: line.level,
                                polarity: line.polarity.clone(),
                                target: line.target.clone(),
                                flags: line.flags,
                            })
                            .collect(),
                    })
                    .collect(),
                ranges_stopped: controller.ranges_stopped.clone(),
            }),
            Err((address, error)) => unreadable.push(HalUnreadable {
                address: *address,
                error: error.clone(),
            }),
        }
    }
    HalControllers {
        controllers,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

pub fn smbios_table(table: &smbios::SmbiosTable) -> SmbiosTable {
    SmbiosTable {
        physical_address: table.physical_address,
        length: table.length,
        version: format!("{}.{}", table.version.0, table.version.1),
        structures: table
            .structures
            .iter()
            .map(|structure| SmbiosStructure {
                kind: structure.kind,
                kind_name: structure_name(structure.kind),
                handle: structure.handle,
                formatted: structure.formatted.clone(),
                strings: structure.strings.clone(),
                fields: structure_fields(structure)
                    .into_iter()
                    .map(|(name, value)| SmbiosField { name, value })
                    .collect(),
            })
            .collect(),
        stopped: table.stopped.clone(),
    }
}
