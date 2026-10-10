//! Interrupt controllers and firmware tables as SDK records: a processor's
//! local APIC (`!apic`), the interrupt controllers the HAL registered
//! (`!ioapic`), and the SMBIOS table (`!sysinfo`).

use super::shape::{Hex, shapes};
use crate::target::apic::{self, bitmap_vectors, decode_icr, timer_divisor};
use crate::target::smbios::{self, structure_fields, structure_name};
use crate::types::VirtAddr;

shapes! {
    /// A local vector table entry.
    ApicLvt {
        /// `Timer`, `LINT0`, `LINT1`, `Error`, `PerfMon`, `Thermal`, or
        /// `CMCI`.
        name: &'static str,
        raw: Hex<u32>,
        vector: Hex<u8>,
        /// `Fixed`, `SMI`, `NMI`, `INIT`, `ExtINT`, or the mode in hex.
        delivery: String,
        pending: bool,
        active_low: bool,
        remote_irr: bool,
        level: bool,
        masked: bool,
        /// The timer's mode: `one-shot`, `periodic`, or `TSC-deadline`.
        timer_mode: Option<&'static str>,
    }

    /// The interrupt command register.
    ApicIcr {
        raw: Hex,
        vector: Hex<u8>,
        delivery: String,
        logical: bool,
        pending: bool,
        level_assert: bool,
        level_triggered: bool,
        /// `none`, `self`, `all`, or `all-but-self`.
        shorthand: &'static str,
        destination: Hex<u32>,
    }

    /// A processor's local APIC (`!apic`).
    LocalApic {
        processor: u16,
        /// `IA32_APIC_BASE`.
        apic_base: Hex,
        /// In x2APIC mode, read through MSRs; else through its registers.
        x2apic: bool,
        bootstrap_processor: bool,
        enabled: bool,
        id: Hex<u32>,
        version: Hex<u32>,
        tpr: Hex<u32>,
        ppr: Hex<u32>,
        ldr: Hex<u32>,
        /// The spurious-interrupt vector register.
        svr: Hex<u32>,
        software_enabled: bool,
        /// `None` when the error status does not read.
        esr: Option<Hex<u32>>,
        icr: ApicIcr,
        /// The LVT entries the APIC implements.
        lvt: Vec<ApicLvt>,
        /// The ones it does not (the thermal or CMCI entry).
        lvt_missing: Vec<&'static str>,
        timer_initial: Hex<u32>,
        timer_current: Hex<u32>,
        timer_divisor: u32,
        /// The vectors in service, requested, and level-triggered.
        isr: Vec<u8>,
        irr: Vec<u8>,
        tmr: Vec<u8>,
    }

    /// A line of an interrupt controller as the HAL set it up
    /// (`_INTERRUPT_LINE_STATE`).
    HalLine {
        line: i64,
        /// The global system interrupt, for a pin.
        gsi: Option<u64>,
        vector: Hex<u32>,
        /// The IRQL its interrupt runs at.
        irql: u32,
        level: bool,
        polarity: String,
        /// `_INTERRUPT_TARGET_TYPE` without its prefix, with its ID.
        target: String,
        flags: Hex<u32>,
    }

    /// A range of a controller's lines (`_INTERRUPT_LINES`).
    HalLineRange {
        address: VirtAddr,
        /// `_INTERRUPT_LINE_TYPE` without its prefix (`StandardPin`).
        kind: String,
        min_line: i64,
        max_line: i64,
        gsi_base: Option<u64>,
        /// The lines the HAL set up.
        lines: Vec<HalLine>,
    }

    /// An interrupt controller the HAL registered
    /// (`_REGISTERED_INTERRUPT_CONTROLLER`).
    HalController {
        address: VirtAddr,
        /// `_KNOWN_CONTROLLER_TYPE` without its prefix (`Apic`, `Pic`).
        kind: String,
        unit_id: Hex<u32>,
        resource_id: String,
        min_line: i64,
        max_line: i64,
        problem: Option<String>,
        ranges: Vec<HalLineRange>,
        ranges_stopped: Option<String>,
    }

    /// A controller that does not read.
    HalUnreadable {
        address: VirtAddr,
        error: String,
    }

    /// The interrupt controllers on `nt!HalpRegisteredInterruptControllers`
    /// (`!ioapic`).
    HalControllers {
        controllers: Vec<HalController>,
        unreadable: Vec<HalUnreadable>,
        stopped: Option<String>,
    }

    /// A field of an SMBIOS structure, by the specification's name.
    SmbiosField {
        name: &'static str,
        value: String,
    }

    /// An SMBIOS structure.
    SmbiosStructure {
        /// The structure type (0 BIOS, 1 system, 4 processor, 17 memory
        /// device, ...).
        kind: u8,
        kind_name: &'static str,
        handle: Hex<u16>,
        /// The formatted area, its header included.
        formatted: Vec<u8>,
        /// The strings, string 1 first.
        strings: Vec<String>,
        /// The fields `!sysinfo smbios` decodes for its type.
        fields: Vec<SmbiosField>,
    }

    /// The SMBIOS table the kernel found at boot (`!sysinfo smbios`).
    SmbiosTable {
        physical_address: Hex,
        length: u32,
        /// The version the entry point gave (`2.8`).
        version: String,
        structures: Vec<SmbiosStructure>,
        /// Why the parse stopped before End-of-Table.
        stopped: Option<String>,
    }
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
