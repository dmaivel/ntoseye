//! Interrupt controllers (`!apic`, `!ioapic`): a processor's local APIC,
//! read through its x2APIC MSRs, and the I/O APIC lines as the HAL
//! programmed them, from the HAL's own record of each controller
//! (`nt!HalpRegisteredInterruptControllers`).

use std::collections::HashMap;
use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::dbg_backend::ProcessorRead;
use crate::error::{Error, Result};
use crate::layout::{TypeInfo, Types};
use crate::session::Session;
use crate::target::{Target, bounded_list_walk};
use crate::types::{Arch, VirtAddr};

/// `IA32_APIC_BASE`.
const IA32_APIC_BASE: u32 = 0x1b;
/// `IA32_APIC_BASE` bits: the bootstrap processor, x2APIC mode, and the
/// APIC enabled.
const APIC_BASE_BSP: u64 = 1 << 8;
const APIC_BASE_X2APIC: u64 = 1 << 10;
const APIC_BASE_ENABLE: u64 = 1 << 11;
/// The first x2APIC MSR; a register at xAPIC offset `o` is MSR
/// `0x800 + o / 16`.
const X2APIC_MSR_BASE: u32 = 0x800;
/// The physical base of the xAPIC page in `IA32_APIC_BASE`.
const APIC_BASE_ADDRESS: u64 = 0x000f_ffff_ffff_f000;

/// Why the first register read of an xAPIC failed: a backend without
/// device reads, or the read itself.
fn apic_read_error(base: Option<u64>, error: Error) -> Error {
    match (base, error) {
        (Some(base), Error::NotSupported) => Error::DebugInfo(format!(
            "the local APIC is in xAPIC mode, with its registers at physical {base:#x}, which \
             this backend cannot read; attach over KD (kd or kdnet)"
        )),
        (_, error) => error,
    }
}

const MAX_CONTROLLERS: usize = 256;
const MAX_LINE_RANGES: usize = 256;
/// More lines than one range of a controller holds.
const MAX_LINES: i64 = 4096;

/// A register of the local APIC by its xAPIC offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApicRegister {
    Id = 0x20,
    Version = 0x30,
    Tpr = 0x80,
    Ppr = 0xa0,
    Ldr = 0xd0,
    Svr = 0xf0,
    Isr = 0x100,
    Tmr = 0x180,
    Irr = 0x200,
    Esr = 0x280,
    Cmci = 0x2f0,
    Icr = 0x300,
    LvtTimer = 0x320,
    LvtThermal = 0x330,
    LvtPerf = 0x340,
    LvtLint0 = 0x350,
    LvtLint1 = 0x360,
    LvtError = 0x370,
    TimerInitial = 0x380,
    TimerCurrent = 0x390,
    TimerDivide = 0x3e0,
}

impl ApicRegister {
    /// The x2APIC MSR of the register, or of word `index` of a 256-bit
    /// bitmap register (ISR, TMR, IRR).
    pub fn msr(self, index: u32) -> u32 {
        X2APIC_MSR_BASE + (self as u32 >> 4) + index
    }
}

/// The words `!apic` reads, each a register and its index: the eight
/// words of each bitmap, and an xAPIC's ICR as its low and high halves,
/// where x2APIC's is one 64-bit MSR.
fn apic_words(x2apic: bool) -> Vec<(ApicRegister, u32)> {
    use ApicRegister::*;
    let mut words: Vec<(ApicRegister, u32)> = [
        Id,
        Version,
        Tpr,
        Ppr,
        Ldr,
        Svr,
        Esr,
        Icr,
        LvtTimer,
        LvtLint0,
        LvtLint1,
        LvtError,
        LvtPerf,
        LvtThermal,
        Cmci,
        TimerInitial,
        TimerCurrent,
        TimerDivide,
    ]
    .into_iter()
    .map(|register| (register, 0))
    .collect();
    if !x2apic {
        words.push((Icr, 1));
    }
    for register in [Isr, Tmr, Irr] {
        words.extend((0..8).map(|index| (register, index)));
    }
    words
}

/// A local vector table entry, decoded (Intel SDM vol. 3, 11.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvtEntry {
    pub raw: u32,
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

/// Decode an LVT entry; `timer` reads bits 17-18 as the timer mode.
pub fn decode_lvt(raw: u32, timer: bool) -> LvtEntry {
    LvtEntry {
        raw,
        vector: raw as u8,
        delivery: match (raw >> 8) & 7 {
            0 => "Fixed".into(),
            2 => "SMI".into(),
            4 => "NMI".into(),
            5 => "INIT".into(),
            7 => "ExtINT".into(),
            other => format!("{other:#x}"),
        },
        pending: raw & (1 << 12) != 0,
        active_low: raw & (1 << 13) != 0,
        remote_irr: raw & (1 << 14) != 0,
        level: raw & (1 << 15) != 0,
        masked: raw & (1 << 16) != 0,
        timer_mode: timer.then_some(match (raw >> 17) & 3 {
            0 => "one-shot",
            1 => "periodic",
            2 => "TSC-deadline",
            _ => "reserved",
        }),
    }
}

/// The interrupt command register, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcrValue {
    pub raw: u64,
    pub vector: u8,
    pub delivery: String,
    pub logical: bool,
    pub pending: bool,
    pub level_assert: bool,
    pub level_triggered: bool,
    /// `none`, `self`, `all`, or `all-but-self`.
    pub shorthand: &'static str,
    pub destination: u32,
}

/// Decode the ICR; an x2APIC ICR keeps its 32-bit destination in the high
/// half, an xAPIC one its 8-bit destination in the top byte.
pub fn decode_icr(raw: u64, x2apic: bool) -> IcrValue {
    let low = raw as u32;
    IcrValue {
        raw,
        vector: low as u8,
        delivery: match (low >> 8) & 7 {
            0 => "Fixed".into(),
            1 => "LowestPriority".into(),
            2 => "SMI".into(),
            4 => "NMI".into(),
            5 => "INIT".into(),
            6 => "StartUp".into(),
            other => format!("{other:#x}"),
        },
        logical: low & (1 << 11) != 0,
        pending: low & (1 << 12) != 0,
        level_assert: low & (1 << 14) != 0,
        level_triggered: low & (1 << 15) != 0,
        shorthand: match (low >> 18) & 3 {
            0 => "none",
            1 => "self",
            2 => "all",
            _ => "all-but-self",
        },
        destination: if x2apic {
            (raw >> 32) as u32
        } else {
            (raw >> 56) as u32
        },
    }
}

/// The vectors set in a 256-bit bitmap register, read as eight words.
pub fn bitmap_vectors(words: &[u32; 8]) -> Vec<u8> {
    let mut vectors = Vec::new();
    for (index, word) in words.iter().enumerate() {
        for bit in 0..32 {
            if word & (1 << bit) != 0 {
                vectors.push((index * 32 + bit) as u8);
            }
        }
    }
    vectors
}

/// The divisor the timer's divide configuration register selects: bits 0,
/// 1, and 3 (Intel SDM vol. 3, figure 11-10).
pub fn timer_divisor(raw: u32) -> u32 {
    let code = (raw & 3) | ((raw >> 1) & 4);
    if code == 7 { 1 } else { 2 << code }
}

/// A processor's local APIC, read through its x2APIC MSRs. A register the
/// processor does not implement (the thermal or CMCI LVT) is `None`.
#[derive(Debug, Clone)]
pub struct LocalApic {
    pub processor: u16,
    pub apic_base: u64,
    /// In x2APIC mode, read through MSRs; else through its registers.
    pub x2apic: bool,
    pub id: u32,
    pub version: u32,
    pub tpr: u32,
    pub ppr: u32,
    pub ldr: u32,
    pub svr: u32,
    pub esr: Option<u32>,
    pub icr: u64,
    pub isr: [u32; 8],
    pub tmr: [u32; 8],
    pub irr: [u32; 8],
    pub lvt: Vec<(&'static str, Option<LvtEntry>)>,
    pub timer_initial: u32,
    pub timer_current: u32,
    pub timer_divide: u32,
}

impl LocalApic {
    pub fn bsp(&self) -> bool {
        self.apic_base & APIC_BASE_BSP != 0
    }

    pub fn enabled(&self) -> bool {
        self.apic_base & APIC_BASE_ENABLE != 0
    }
}

impl Session {
    /// The local APIC of `processor`, which needs a backend that reads MSRs
    /// and device registers on a given processor (KD): in x2APIC mode
    /// through its MSRs, in xAPIC mode through its registers at the
    /// physical base `IA32_APIC_BASE` names, read uncached.
    pub fn local_apic(&mut self, processor: u16) -> Result<LocalApic> {
        if self.target.arch() != Arch::Amd64 {
            return Err(Error::DebugInfo(
                "!apic reads an x86 local APIC; an ARM64 target has a GIC".into(),
            ));
        }
        if self.backend.is_running() {
            return Err(Error::TargetRunning(
                "the local APIC is read on a halted processor.",
            ));
        }
        let apic_base = self
            .read_msr(processor, IA32_APIC_BASE)
            .map_err(|error| match error {
                Error::NotSupported => Error::DebugInfo(
                    "!apic reads the local APIC through MSRs, which this backend cannot read; \
                 attach over KD (kd or kdnet)"
                        .into(),
                ),
                other => other,
            })?;
        let x2apic = apic_base & APIC_BASE_X2APIC != 0;
        let base = (!x2apic).then_some(apic_base & APIC_BASE_ADDRESS);
        let words = apic_words(x2apic);
        let reads: Vec<ProcessorRead> = words
            .iter()
            .map(|&(register, index)| match base {
                None => ProcessorRead::Msr(register.msr(index)),
                Some(base) => {
                    ProcessorRead::Device(base + register as u64 + u64::from(index) * 0x10)
                }
            })
            .collect();
        let results = self
            .backend
            .read_on_processor(processor, &reads)
            .map_err(|error| apic_read_error(base, error))?;
        let mut values: HashMap<(ApicRegister, u32), Result<u64>> =
            words.into_iter().zip(results).collect();
        let mut word = |register: ApicRegister, index: u32| -> Result<u64> {
            values
                .remove(&(register, index))
                .unwrap_or(Err(Error::NotSupported))
                .map_err(|error| apic_read_error(base, error))
        };
        let mut bitmap = |register: ApicRegister| -> Result<[u32; 8]> {
            let mut bits = [0u32; 8];
            for (index, value) in bits.iter_mut().enumerate() {
                *value = word(register, index as u32)? as u32;
            }
            Ok(bits)
        };
        let (isr, tmr, irr) = (
            bitmap(ApicRegister::Isr)?,
            bitmap(ApicRegister::Tmr)?,
            bitmap(ApicRegister::Irr)?,
        );
        // An xAPIC keeps its ID in the top byte and its ICR in two
        // registers; x2APIC's ID MSR is the whole ID and its ICR MSR 64 bits.
        let id = word(ApicRegister::Id, 0)?;
        let id = if x2apic { id } else { id >> 24 };
        let icr = word(ApicRegister::Icr, 0)?;
        let icr = if x2apic {
            icr
        } else {
            icr | word(ApicRegister::Icr, 1)? << 32
        };
        let mut read = |register: ApicRegister| word(register, 0);
        let version = read(ApicRegister::Version)? as u32;
        let max_lvt = (version >> 16) & 0xff;
        let mut lvt = Vec::new();
        for (name, register, timer) in [
            ("Timer", ApicRegister::LvtTimer, true),
            ("LINT0", ApicRegister::LvtLint0, false),
            ("LINT1", ApicRegister::LvtLint1, false),
            ("Error", ApicRegister::LvtError, false),
            ("PerfMon", ApicRegister::LvtPerf, false),
            ("Thermal", ApicRegister::LvtThermal, false),
            ("CMCI", ApicRegister::Cmci, false),
        ] {
            // The version register says how many LVT entries the APIC has
            // past the first; the thermal and CMCI entries are optional.
            let optional = matches!(register, ApicRegister::LvtThermal | ApicRegister::Cmci);
            let present = match register {
                ApicRegister::LvtThermal => max_lvt >= 5,
                ApicRegister::Cmci => max_lvt >= 6,
                _ => true,
            };
            let entry = if present {
                match read(register) {
                    Ok(raw) => Some(decode_lvt(raw as u32, timer)),
                    Err(_) if optional => None,
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            lvt.push((name, entry));
        }
        Ok(LocalApic {
            processor,
            apic_base,
            x2apic,
            id: id as u32,
            version,
            tpr: read(ApicRegister::Tpr)? as u32,
            ppr: read(ApicRegister::Ppr)? as u32,
            ldr: read(ApicRegister::Ldr)? as u32,
            svr: read(ApicRegister::Svr)? as u32,
            esr: read(ApicRegister::Esr).ok().map(|value| value as u32),
            icr,
            isr,
            tmr,
            irr,
            lvt,
            timer_initial: read(ApicRegister::TimerInitial)? as u32,
            timer_current: read(ApicRegister::TimerCurrent)? as u32,
            timer_divide: read(ApicRegister::TimerDivide)? as u32,
        })
    }
}

/// A line of an interrupt controller as the HAL set it
/// (`_INTERRUPT_LINE_STATE`).
#[derive(Debug, Clone)]
pub struct HalLine {
    pub line: i64,
    /// The global system interrupt, for a pin.
    pub gsi: Option<u64>,
    pub vector: u32,
    /// The IRQL the line's interrupt runs at (`Priority`).
    pub irql: u32,
    pub level: bool,
    pub polarity: String,
    /// `_INTERRUPT_TARGET_TYPE` without its prefix, and the target ID the
    /// type uses.
    pub target: String,
    pub flags: u32,
}

/// A range of a controller's lines (`_INTERRUPT_LINES`).
#[derive(Debug, Clone)]
pub struct HalLineRange {
    pub address: VirtAddr,
    /// `_INTERRUPT_LINE_TYPE` without its prefix (`StandardPin`).
    pub kind: String,
    pub min_line: i64,
    pub max_line: i64,
    pub gsi_base: Option<u64>,
    /// The lines the HAL set up; the others are unused.
    pub lines: Vec<HalLine>,
}

/// An interrupt controller the HAL registered
/// (`_REGISTERED_INTERRUPT_CONTROLLER`).
#[derive(Debug, Clone)]
pub struct HalController {
    pub address: VirtAddr,
    /// `_KNOWN_CONTROLLER_TYPE` without its prefix (`Apic`, `Pic`).
    pub kind: String,
    pub unit_id: u32,
    /// The ACPI ID the HAL gave the controller's device.
    pub resource_id: String,
    pub min_line: i64,
    pub max_line: i64,
    /// `_INTERRUPT_PROBLEM` without its prefix; `None` for no problem.
    pub problem: Option<String>,
    pub ranges: Vec<HalLineRange>,
    pub ranges_stopped: Option<String>,
}

/// The controllers on `nt!HalpRegisteredInterruptControllers`.
#[derive(Debug, Clone)]
pub struct HalControllers {
    pub controllers: Vec<std::result::Result<HalController, (VirtAddr, String)>>,
    pub stopped: Option<String>,
}

fn nt_layout(types: Types<'_>, name: &str) -> Result<Arc<TypeInfo>> {
    types.layout(format!("nt!{name}")).map_err(|_| {
        Error::DebugInfo(format!(
            "the kernel's symbols do not describe {name}, the HAL's record of its interrupt \
             controllers"
        ))
    })
}

/// The name `variants` gives `value` without `prefix`, or the value.
fn variant_text(variants: &[(String, i64)], value: i64, prefix: &str) -> String {
    variants
        .iter()
        .find(|(_, variant)| *variant == value)
        .map(|(name, _)| name.strip_prefix(prefix).unwrap_or(name).to_string())
        .unwrap_or_else(|| format!("{value:#x}"))
}

impl Target {
    fn nt_enum(&self, name: &str) -> Vec<(String, i64)> {
        self.symbols
            .find_enum_across_modules(self.kernel_dtb(), &format!("nt!{name}"))
            .unwrap_or_default()
    }

    /// The interrupt controllers the HAL registered, each with its line
    /// ranges and the lines the HAL set up.
    pub fn hal_interrupt_controllers(&self) -> Result<HalControllers> {
        let types = self.types_in(self.kernel_dtb());
        let controller = nt_layout(types, "_REGISTERED_INTERRUPT_CONTROLLER")?;
        let head = self
            .symbols
            .find_symbol_across_modules(self.kernel_dtb(), "nt!HalpRegisteredInterruptControllers")?
            .ok_or_else(|| {
                Error::DebugInfo(
                    "nt!HalpRegisteredInterruptControllers is not in the kernel's symbols".into(),
                )
            })?;
        let memory = self.kernel_address_space();
        // `ListEntry` is the record's first field, so a link is its record.
        let (links, termination) =
            bounded_list_walk(head, MAX_CONTROLLERS, |at| memory.read::<VirtAddr>(at));
        let controllers = links
            .into_iter()
            .map(|address| {
                self.hal_controller(types, &controller, address)
                    .map_err(|error| (address, error.to_string()))
            })
            .collect();
        Ok(HalControllers {
            controllers,
            stopped: termination.diagnostic(),
        })
    }

    fn hal_controller(
        &self,
        types: Types<'_>,
        layout: &Arc<TypeInfo>,
        address: VirtAddr,
    ) -> Result<HalController> {
        let controller = types
            .struct_with_layout(Arc::clone(layout), address)
            .prefetch();
        let lines_layout = nt_layout(types, "_INTERRUPT_LINES")?;
        let state_layout = nt_layout(types, "_INTERRUPT_LINE_STATE")?;
        let head = address + layout.field_offset("LinesHead")?;
        let memory = self.kernel_address_space();
        let (links, termination) =
            bounded_list_walk(head, MAX_LINE_RANGES, |at| memory.read::<VirtAddr>(at));
        let line_types = self.nt_enum("_INTERRUPT_LINE_TYPE");
        let polarities = self.nt_enum("_KINTERRUPT_POLARITY");
        let targets = self.nt_enum("_INTERRUPT_TARGET_TYPE");
        let mut ranges = Vec::new();
        for link in links {
            let range = types
                .struct_with_layout(Arc::clone(&lines_layout), link)
                .prefetch();
            let min_line = range.read_uint("MinLine")? as u32 as i32 as i64;
            let max_line = range.read_uint("MaxLine")? as u32 as i32 as i64;
            let gsi_base = range.read_uint("GsiBase")?;
            let gsi_base = (gsi_base != u64::from(u32::MAX)).then_some(gsi_base);
            let states = range.read_pointer("State")?;
            let mut lines = Vec::new();
            if !states.is_zero() && max_line >= min_line && max_line - min_line < MAX_LINES {
                for line in min_line..=max_line {
                    let index = (line - min_line) as u64;
                    let state = types
                        .struct_with_layout(
                            Arc::clone(&state_layout),
                            states + index * state_layout.size as u64,
                        )
                        .prefetch();
                    let flags = state.read_uint("Flags")? as u32;
                    let vector = state.read_uint("Vector")? as u32;
                    // A line the HAL never set up is all zeros.
                    if flags == 0 && vector == 0 {
                        continue;
                    }
                    let target = state.embedded("ProcessorTarget")?;
                    let target_type = target.read_uint("Target")? as i64;
                    let target_name = variant_text(&targets, target_type, "InterruptTarget");
                    let target_id = target.read_uint("PhysicalTarget")?;
                    let target_text = match target_name.as_str() {
                        "Physical" | "LogicalFlat" => format!("{target_name} {target_id:#x}"),
                        "LogicalClustered" => format!(
                            "{target_name} cluster {target_id:#x} mask {:#x}",
                            target.read_uint("ClusterMask")?
                        ),
                        "RemapIndex" => format!("{target_name} {target_id:#x}"),
                        _ => target_name,
                    };
                    lines.push(HalLine {
                        line,
                        gsi: gsi_base.map(|base| base + (line - min_line) as u64),
                        vector,
                        irql: state.read_uint("Priority")? as u32,
                        level: state.read_uint("TriggerMode")? == 0,
                        polarity: variant_text(
                            &polarities,
                            state.read_uint("Polarity")? as i64,
                            "Interrupt",
                        ),
                        target: target_text,
                        flags,
                    });
                }
            }
            ranges.push(HalLineRange {
                address: link,
                kind: variant_text(
                    &line_types,
                    range.read_uint("Type")? as i64,
                    "InterruptLine",
                ),
                min_line,
                max_line,
                gsi_base,
                lines,
            });
        }
        let problem = controller.read_uint("Problem")? as i64;
        Ok(HalController {
            address,
            kind: variant_text(
                &self.nt_enum("_KNOWN_CONTROLLER_TYPE"),
                controller.read_uint("KnownType")? as i64,
                "InterruptController",
            ),
            unit_id: controller.read_uint("UnitId")? as u32,
            resource_id: controller.unicode_string("ResourceId").unwrap_or_default(),
            min_line: controller.read_uint("MinLine")? as u32 as i32 as i64,
            max_line: controller.read_uint("MaxLine")? as u32 as i32 as i64,
            problem: (problem != 0).then(|| {
                variant_text(
                    &self.nt_enum("_INTERRUPT_PROBLEM"),
                    problem,
                    "InterruptProblem",
                )
            }),
            ranges,
            ranges_stopped: termination.diagnostic(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lvt_entries_decode_mode_mask_and_trigger() {
        // LINT0 as Windows leaves it: ExtINT, masked.
        let lint0 = decode_lvt(0x0001_0700, false);
        assert_eq!(lint0.delivery, "ExtINT");
        assert!(lint0.masked && !lint0.level && lint0.timer_mode.is_none());
        // LINT1: NMI, level-sensitive bit set by firmware.
        let lint1 = decode_lvt(0x0000_8400, false);
        assert_eq!(lint1.delivery, "NMI");
        assert!(lint1.level && !lint1.masked);
        // A periodic timer on vector 0xd1, and a TSC-deadline one.
        let timer = decode_lvt(0x0002_00d1, true);
        assert_eq!((timer.vector, timer.timer_mode), (0xd1, Some("periodic")));
        assert_eq!(
            decode_lvt(0x0004_00d1, true).timer_mode,
            Some("TSC-deadline")
        );
    }

    #[test]
    fn icr_destination_depends_on_the_mode() {
        // A fixed IPI to x2APIC ID 3 on vector 0x2f.
        let x2 = decode_icr(0x0000_0003_0000_402f, true);
        assert_eq!((x2.vector, x2.destination, x2.shorthand), (0x2f, 3, "none"));
        assert!(x2.level_assert && !x2.logical);
        // The same in xAPIC form keeps the destination in bits 56-63.
        assert_eq!(decode_icr(0x0300_0000_0000_402f, false).destination, 3);
        // An NMI to all but self.
        let nmi = decode_icr(0x000c_0400, true);
        assert_eq!(
            (nmi.delivery.as_str(), nmi.shorthand),
            ("NMI", "all-but-self")
        );
    }

    #[test]
    fn bitmaps_list_vectors_across_words() {
        let mut words = [0u32; 8];
        words[0] = 1 << 2;
        words[7] = 1 << 31;
        words[5] = 1 << 1;
        assert_eq!(bitmap_vectors(&words), [2, 0xa1, 0xff]);
    }

    #[test]
    fn timer_divisor_reads_bits_0_1_and_3() {
        assert_eq!(timer_divisor(0b0000), 2);
        assert_eq!(timer_divisor(0b0011), 16);
        assert_eq!(timer_divisor(0b1000), 32);
        assert_eq!(timer_divisor(0b1011), 1);
        // Bit 2 is reserved and does not change the divisor.
        assert_eq!(timer_divisor(0b0100), 2);
    }

    #[test]
    fn x2apic_msrs_follow_the_xapic_offsets() {
        assert_eq!(ApicRegister::Id.msr(0), 0x802);
        assert_eq!(ApicRegister::Icr.msr(0), 0x830);
        assert_eq!(ApicRegister::Irr.msr(7), 0x827);
        assert_eq!(ApicRegister::TimerDivide.msr(0), 0x83e);
    }
}
