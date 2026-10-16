//! Interrupt controllers and firmware tables: a processor's local APIC
//! (`!apic`), the I/O APIC lines the HAL set up (`!ioapic`), and SMBIOS
//! (`!sysinfo`).

use std::fmt::Display;

use tabled::builder::Builder;

use ntoseye_macros::command;

use super::cpu::print_cpuinfo;
use crate::error::{Error, Result};
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::*;
use crate::session::Session;
use crate::target::apic::{
    ApicLvt, HalController, HalControllerEntry, HalControllers, LVT_NAMES, LocalApic,
};
use crate::target::cpu::CpuInfo;
use crate::target::cpu::Processor;
use crate::target::smbios::{SmbiosTable, structure_fields, structure_name};
use crate::ui;

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(&format!("{label:<20}")));
}

fn vectors_text(vectors: &[u8]) -> String {
    if vectors.is_empty() {
        ui::muted("none")
    } else {
        vectors
            .iter()
            .map(|vector| format!("{vector:#04x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn lvt_text(entry: &ApicLvt) -> String {
    let mut text = format!(
        "{:#010x}  vector {:#04x}, {}",
        entry.raw, entry.vector, entry.delivery
    );
    if let Some(mode) = entry.timer_mode {
        text.push_str(&format!(", {mode}"));
    }
    text.push_str(if entry.level { ", level" } else { ", edge" });
    if entry.active_low {
        text.push_str(", active low");
    }
    if entry.remote_irr {
        text.push_str(", remote IRR");
    }
    if entry.pending {
        text.push_str(", send pending");
    }
    if entry.masked {
        text.push_str(", masked");
    }
    text
}

fn print_apic(apic: &LocalApic) {
    field(
        "Local APIC",
        format!(
            "processor {}, APIC ID {:#x}, {} mode{}{}",
            apic.processor,
            apic.id,
            if apic.x2apic { "x2APIC" } else { "xAPIC" },
            if apic.bootstrap_processor() {
                ", bootstrap processor"
            } else {
                ""
            },
            if apic.enabled() { "" } else { ", disabled" }
        ),
    );
    field(
        "Version",
        format!(
            "{:#x} (version {:#04x}, {} LVT entries{})",
            apic.version,
            apic.version & 0xff,
            ((apic.version >> 16) & 0xff) + 1,
            if apic.version & (1 << 24) != 0 {
                ", EOI broadcast suppression"
            } else {
                ""
            }
        ),
    );
    field("IA32_APIC_BASE", format!("{:#x}", apic.apic_base));
    field(
        "Priorities",
        format!("TPR {:#04x}, PPR {:#04x}", apic.tpr, apic.ppr),
    );
    field(
        "Spurious (SVR)",
        format!(
            "{:#x}  vector {:#04x}, {}{}",
            apic.svr,
            apic.svr & 0xff,
            if apic.svr & (1 << 8) != 0 {
                "software-enabled"
            } else {
                "software-disabled"
            },
            if apic.svr & (1 << 12) != 0 {
                ", EOI broadcast suppressed"
            } else {
                ""
            }
        ),
    );
    field("Logical destination", format!("{:#x}", apic.ldr));
    let icr = &apic.icr;
    field(
        "Command (ICR)",
        format!(
            "{:#x}  vector {:#04x}, {}, {} destination {:#x}, shorthand {}{}",
            icr.raw,
            icr.vector,
            icr.delivery,
            if icr.logical { "logical" } else { "physical" },
            icr.destination,
            icr.shorthand,
            if icr.pending { ", send pending" } else { "" }
        ),
    );
    outln!();
    for name in LVT_NAMES {
        field(
            &format!("LVT {name}"),
            match apic.lvt.iter().find(|entry| entry.name == name) {
                Some(entry) => lvt_text(entry),
                None => ui::muted("not implemented"),
            },
        );
    }
    field(
        "Timer",
        format!(
            "initial count {:#x}, current count {:#x}, divide by {}",
            apic.timer_initial,
            apic.timer_current,
            apic.timer_divisor()
        ),
    );
    field(
        "Error status",
        apic.esr
            .map_or_else(|| ui::muted("unreadable"), |esr| format!("{esr:#x}")),
    );
    outln!();
    field("In service (ISR)", vectors_text(&apic.isr));
    field("Requested (IRR)", vectors_text(&apic.irr));
    field("Level (TMR)", vectors_text(&apic.tmr));
    outln!();
}

fn print_controller(controller: &HalController) {
    let mut title = format!(
        "{} {}  unit {:#x}  lines {} to {}",
        ui::label(&controller.kind),
        ui::addr(controller.address.0),
        controller.unit_id,
        controller.min_line,
        controller.max_line
    );
    if !controller.resource_id.is_empty() {
        title.push_str(&format!("  {}", ui::muted(&controller.resource_id)));
    }
    outln!("{title}");
    if let Some(problem) = &controller.problem {
        outln!("  problem: {problem}");
    }
    for range in &controller.ranges {
        outln!(
            "  {} lines {} to {}{}: {} set up",
            range.kind,
            range.min_line,
            range.max_line,
            range
                .gsi_base
                .map(|base| format!(" (GSI from {base})"))
                .unwrap_or_default(),
            range.lines.len()
        );
        if range.lines.is_empty() {
            continue;
        }
        let mut builder = Builder::default();
        builder.push_record([
            "Line", "GSI", "Vector", "IRQL", "Trigger", "Polarity", "Target", "Flags",
        ]);
        for line in &range.lines {
            builder.push_record([
                line.line.to_string(),
                line.gsi.map(|gsi| gsi.to_string()).unwrap_or_default(),
                format!("{:#04x}", line.vector),
                line.irql.to_string(),
                if line.level { "level" } else { "edge" }.to_string(),
                line.polarity.clone(),
                line.target.clone(),
                format!("{:#x}", line.flags),
            ]);
        }
        print_padded_table(builder);
    }
    if let Some(stopped) = &controller.ranges_stopped {
        outln!(
            "{}",
            ui::muted(&format!("  (line list stopped: {stopped})"))
        );
    }
    outln!();
}

fn print_controllers(controllers: &HalControllers) {
    if controllers.controllers.is_empty() {
        outln!(
            "{}\n",
            ui::muted("the HAL registered no interrupt controllers")
        );
    }
    for entry in &controllers.controllers {
        match entry {
            HalControllerEntry::Controller(controller) => print_controller(controller),
            HalControllerEntry::Unreadable(unreadable) => {
                error!(
                    "controller {:#x}: {}",
                    unreadable.address.0, unreadable.error
                );
            }
        }
    }
    if let Some(stopped) = &controllers.stopped {
        outln!(
            "{}",
            ui::muted(&format!("(controller list stopped: {stopped})"))
        );
    }
}

/// The `name = value` lines of `!sysinfo machineid`, from the BIOS,
/// system, and baseboard structures.
fn print_machine_id(table: &SmbiosTable) {
    outln!(
        "Machine ID Information [From Smbios {}.{}, Size={}]",
        table.version.0,
        table.version.1,
        table.length
    );
    let line = |name: &str, value: Option<String>| {
        if let Some(value) = value {
            outln!("{name} = {value}");
        }
    };
    if let Some(bios) = table.first(0) {
        if let (Some(major), Some(minor)) = (bios.byte(0x14), bios.byte(0x15)) {
            line("BiosMajorRelease", Some(major.to_string()));
            line("BiosMinorRelease", Some(minor.to_string()));
        }
        line("BiosVendor", bios.string(4).map(str::to_string));
        line("BiosVersion", bios.string(5).map(str::to_string));
        line("BiosReleaseDate", bios.string(8).map(str::to_string));
    }
    if let Some(system) = table.first(1) {
        line("SystemManufacturer", system.string(4).map(str::to_string));
        line("SystemProductName", system.string(5).map(str::to_string));
        line("SystemFamily", system.string(0x1a).map(str::to_string));
        line("SystemVersion", system.string(6).map(str::to_string));
        line("SystemSKU", system.string(0x19).map(str::to_string));
    }
    if let Some(board) = table.first(2) {
        line("BaseBoardManufacturer", board.string(4).map(str::to_string));
        line("BaseBoardProduct", board.string(5).map(str::to_string));
        line("BaseBoardVersion", board.string(6).map(str::to_string));
    }
    outln!();
}

fn print_smbios(table: &SmbiosTable) {
    outln!(
        "{} v{}.{} at physical {:#x}, {:#x} bytes, {} structures",
        ui::label("SMBIOS"),
        table.version.0,
        table.version.1,
        table.physical_address,
        table.length,
        table.structures.len()
    );
    outln!();
    for structure in &table.structures {
        outln!(
            "{} (type {}) - handle {:#06x}, length {:#x}",
            ui::label(structure_name(structure.kind)),
            structure.kind,
            structure.handle,
            structure.formatted.len()
        );
        for (name, value) in structure_fields(structure) {
            outln!("  {name:<20} {value}");
        }
    }
    if let Some(stopped) = &table.stopped {
        outln!(
            "{}",
            ui::muted(&format!("(table parse stopped: {stopped})"))
        );
    }
    outln!();
}

/// The processor of `!apic`, whose errors name the command.
fn apic_processor(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<Processor>, ArgError> {
    let Some(text) = cursor.word() else {
        return Ok(None);
    };
    match <Processor as crate::repl::args::FromArg>::from_arg(cx, &text) {
        Ok(processor) => Ok(Some(processor)),
        Err(ArgError::Message(message)) => Err(ArgError::Message(format!("!apic: {message}"))),
        Err(error) => Err(error),
    }
}

/// Show a processor's local APIC: its ID, priorities, LVT, timer, and pending
/// vectors.
///
/// Reads the local APIC of the selected processor, or of the processor you
/// give: in x2APIC mode through its MSRs (0x800-0x83f), in xAPIC mode through
/// its registers at the physical address IA32_APIC_BASE names, read uncached.
/// Both need a backend that reads MSRs and device registers: kd or kdnet. The
/// target reads them on the processor that stopped it, so for another processor
/// ntoseye switches the target to it and back, as rdmsr /p does. Shows the APIC
/// ID and version, whether it is the bootstrap processor, the task and
/// processor priorities, the spurious-interrupt vector register, the logical
/// destination, the interrupt command register as an IPI (vector, delivery
/// mode, destination), each local vector table entry (timer, LINT0, LINT1,
/// error, performance counter, thermal, CMCI) with its vector, delivery mode,
/// trigger, and mask, the timer's counts and divisor, the error status, and the
/// vectors in service (ISR), requested (IRR), and level-triggered (TMR).
#[command(
    names = ["!apic", "apic"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    state = Halted,
    python = Cpu,
    usage = "!apic [processor]",
    completion = [Expression]
)]
fn apic(
    session: &mut Session,
    #[arg(receiver, parse = apic_processor)] processor: Option<Processor>,
) -> Result<LocalApic> {
    let prefixed = |error: Error| Error::DebugInfo(format!("!apic: {error}"));
    let processor = session.processor(processor).map_err(prefixed)?;
    session.local_apic(processor).map_err(prefixed)
}

impl Render for LocalApic {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_apic(self);
    }
}

/// Show the I/O APIC and PIC lines as the HAL set them up.
///
/// Walks the HAL's registered interrupt controllers
/// (nt!HalpRegisteredInterruptControllers) and shows each one, an I/O APIC or a
/// legacy PIC, with its unit ID, ACPI resource ID, line range, and any problem
/// the HAL recorded, then each line the HAL set up, from its own record of the
/// line (_INTERRUPT_LINE_STATE): the line and its global system interrupt, the
/// vector, the IRQL, edge or level trigger, polarity, and the processor target.
/// This is what the HAL programmed into the redirection entries, read from
/// kernel memory, so it works on every backend and in a kernel dump; it does
/// not read the I/O APIC's registers.
#[command(
    names = ["!ioapic", "ioapic"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "interrupt_controllers",
    usage = "!ioapic"
)]
fn ioapic(session: &mut Session) -> Result<HalControllers> {
    session
        .target
        .hal_interrupt_controllers()
        .map_err(|error| Error::DebugInfo(format!("!ioapic: {error}")))
}

impl Render for HalControllers {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_controllers(self);
    }
}

/// The `!sysinfo` section: `machineid`, `smbios`, or `cpuinfo`, in any case;
/// anything else shows the help.
fn sysinfo_section(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<String, ArgError> {
    let section = cursor.word().map(|word| word.to_ascii_lowercase());
    match section.as_deref() {
        Some(section @ ("machineid" | "smbios" | "cpuinfo")) => Ok(section.to_string()),
        _ => Err(ArgError::Missing),
    }
}

/// Show the machine's SMBIOS identity, its SMBIOS tables, or its processor.
///
/// Reads the SMBIOS table the kernel found at boot
/// (nt!WmipSMBiosTablePhysicalAddress) from physical memory. machineid shows
/// the BIOS vendor, version, and date, and the system's and baseboard's
/// manufacturer, product, and version, as WinDbg's !sysinfo machineid does.
/// smbios lists every structure in the table with its type, handle, and length,
/// and decodes the BIOS, system, baseboard, enclosure, processor, memory array,
/// memory device, and mapped address structures. cpuinfo shows the current
/// processor as !cpuinfo does.
#[command(
    names = ["!sysinfo", "sysinfo"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    forms = [smbios],
    usage = "!sysinfo machineid | smbios | cpuinfo",
    completion = []
)]
fn sysinfo(
    session: &mut Session,
    #[arg(parse = sysinfo_section)] section: String,
) -> Result<SysInfo> {
    match section.to_ascii_lowercase().as_str() {
        "cpuinfo" => session
            .processor(None)
            .and_then(|processor| session.target.inspect_cpuinfo(processor))
            .map(SysInfo::CpuInfo)
            .map_err(|error| Error::DebugInfo(format!("!sysinfo cpuinfo: {error}"))),
        section @ ("machineid" | "smbios") => {
            let table =
                smbios(session).map_err(|error| Error::DebugInfo(format!("!sysinfo: {error}")))?;
            Ok(if section == "machineid" {
                SysInfo::MachineId(table)
            } else {
                SysInfo::Smbios(table)
            })
        }
        other => Err(Error::InvalidArgument(format!(
            "unknown !sysinfo section '{other}': expected machineid, smbios, or cpuinfo"
        ))),
    }
}

/// Read the SMBIOS table the kernel found at boot
/// (`nt!WmipSMBiosTablePhysicalAddress`) from physical memory, with every
/// structure it holds (`!sysinfo smbios`; `!sysinfo machineid` shows the
/// identity strings of the same table).
#[command(form_of = sysinfo, python = Inspect, word = "smbios")]
fn smbios(session: &Session) -> Result<SmbiosTable> {
    session.target.smbios_table()
}

/// What `!sysinfo` shows.
enum SysInfo {
    /// `machineid`: the identity lines from the SMBIOS table.
    MachineId(SmbiosTable),
    /// `smbios`: every structure of the table.
    Smbios(SmbiosTable),
    /// `cpuinfo`: the current processor, as `!cpuinfo` shows it.
    CpuInfo(CpuInfo),
}

impl Render for SysInfo {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::MachineId(table) => print_machine_id(table),
            Self::Smbios(table) => print_smbios(table),
            Self::CpuInfo(detail) => print_cpuinfo(detail),
        }
    }
}
