//! Interrupt controllers and firmware tables: a processor's local APIC
//! (`!apic`), the I/O APIC lines the HAL set up (`!ioapic`), and SMBIOS
//! (`!sysinfo`).

use std::fmt::Display;

use tabled::builder::Builder;

use super::cpu::{parse_processor, print_cpuinfo};
use crate::error::Result;
use crate::repl::*;
use crate::target::apic::{
    HalController, HalControllers, LocalApic, LvtEntry, bitmap_vectors, decode_icr, timer_divisor,
};
use crate::target::smbios::{SmbiosTable, structure_fields, structure_name};
use crate::ui;

repl_command! {
    cmd_apic;
    names: ["!apic", "apic"],
    usage: "!apic [processor]",
    summary: "Show a processor's local APIC: its ID, priorities, LVT, timer, and pending vectors.",
    details: "Reads the local APIC of the selected processor, or of the processor you give: in x2APIC mode through its MSRs (0x800-0x83f), in xAPIC mode through its registers at the physical address IA32_APIC_BASE names, read uncached. Both need a backend that reads MSRs and device registers: kd or kdnet. The target reads them on the processor that stopped it, so for another processor ntoseye switches the target to it and back, as rdmsr /p does. Shows the APIC ID and version, whether it is the bootstrap processor, the task and processor priorities, the spurious-interrupt vector register, the logical destination, the interrupt command register as an IPI (vector, delivery mode, destination), each local vector table entry (timer, LINT0, LINT1, error, performance counter, thermal, CMCI) with its vector, delivery mode, trigger, and mask, the timer's counts and divisor, the error status, and the vectors in service (ISR), requested (IRR), and level-triggered (TMR).",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_ioapic();
    names: ["!ioapic", "ioapic"],
    usage: "!ioapic",
    summary: "Show the I/O APIC and PIC lines as the HAL set them up.",
    details: "Walks the HAL's registered interrupt controllers (nt!HalpRegisteredInterruptControllers) and shows each one, an I/O APIC or a legacy PIC, with its unit ID, ACPI resource ID, line range, and any problem the HAL recorded, then each line the HAL set up, from its own record of the line (_INTERRUPT_LINE_STATE): the line and its global system interrupt, the vector, the IRQL, edge or level trigger, polarity, and the processor target. This is what the HAL programmed into the redirection entries, read from kernel memory, so it works on every backend and in a kernel dump; it does not read the I/O APIC's registers.",
}

repl_command! {
    cmd_sysinfo;
    names: ["!sysinfo", "sysinfo"],
    usage: "!sysinfo machineid | smbios | cpuinfo",
    summary: "Show the machine's SMBIOS identity, its SMBIOS tables, or its processor.",
    details: "Reads the SMBIOS table the kernel found at boot (nt!WmipSMBiosTablePhysicalAddress) from physical memory. machineid shows the BIOS vendor, version, and date, and the system's and baseboard's manufacturer, product, and version, as WinDbg's !sysinfo machineid does. smbios lists every structure in the table with its type, handle, and length, and decodes the BIOS, system, baseboard, enclosure, processor, memory array, memory device, and mapped address structures. cpuinfo shows the current processor as !cpuinfo does.",
}

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(&format!("{label:<20}")));
}

fn vectors_text(words: &[u32; 8]) -> String {
    let vectors = bitmap_vectors(words);
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

fn lvt_text(entry: &LvtEntry) -> String {
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
            if apic.bsp() {
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
    let icr = decode_icr(apic.icr, apic.x2apic);
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
    for (name, entry) in &apic.lvt {
        field(
            &format!("LVT {name}"),
            match entry {
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
            timer_divisor(apic.timer_divide)
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
            Ok(controller) => print_controller(controller),
            Err((address, error)) => {
                error!("controller {:#x}: {error}", address.0);
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

impl ReplState<'_> {
    fn cmd_apic(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let processor = match parse_processor(self, invocation.arg(0)) {
            Ok(processor) => processor,
            Err(error) => {
                error!("!apic: {error}");
                return Ok(());
            }
        };
        match self.ctx.local_apic(processor) {
            Ok(apic) => print_apic(&apic),
            Err(error) => error!("!apic: {error}"),
        }
        Ok(())
    }

    fn cmd_ioapic(&mut self) -> Result<()> {
        match self.ctx.target.hal_interrupt_controllers() {
            Ok(controllers) => print_controllers(&controllers),
            Err(error) => error!("!ioapic: {error}"),
        }
        Ok(())
    }

    fn cmd_sysinfo(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let subcommand = invocation.arg(0).map(str::to_ascii_lowercase);
        match subcommand.as_deref() {
            Some("cpuinfo") => {
                match parse_processor(self, None)
                    .and_then(|processor| self.ctx.target.inspect_cpuinfo(processor))
                {
                    Ok(detail) => print_cpuinfo(&detail),
                    Err(error) => error!("!sysinfo cpuinfo: {error}"),
                }
                return Ok(());
            }
            Some("machineid" | "smbios") => {}
            _ => {
                outln!("{}\n", command_help(invocation.name));
                return Ok(());
            }
        }
        let table = match self.ctx.target.smbios_table() {
            Ok(table) => table,
            Err(error) => {
                error!("!sysinfo: {error}");
                return Ok(());
            }
        };
        if subcommand.as_deref() == Some("machineid") {
            print_machine_id(&table);
        } else {
            print_smbios(&table);
        }
        Ok(())
    }
}
