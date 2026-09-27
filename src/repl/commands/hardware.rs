//! Hang diagnosis from the processor blocks (`!qlocks`, `!ipi`), I/O-port
//! access (`ib`/`iw`/`id`, `ob`/`ow`/`od`), and PCI (`!pcitree`, `!pci`).

use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::hang::{
    IpiProcessor, QueuedLockState, QueuedLocksDetail, ipi_frozen_name, ipi_request_type_name,
};
use crate::target::pci::{
    CAPABILITY_PCI_EXPRESS, PCI_CONFIG_SIZE, PciFunctionConfig, PciRawRange, PciRequest, PciTree,
    PciTreeBus, PciTreeDevice, capabilities, capability_name, class_name, command_flags,
    extended_capabilities, extended_capability_name, parse_header, parse_pci_request, status_flags,
};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_qlocks;
    names: ["!qlocks", "qlocks"],
    usage: "!qlocks",
    summary: "Show which processors own or wait for each numbered queued spinlock.",
    details: "Reads every processor's _KPRCB.LockQueue entries (one _KSPIN_LOCK_QUEUE per _KSPIN_LOCK_QUEUE_NUMBER lock) and lays them out as WinDbg does: a row per lock, a column per processor, O for the owner, 1-n for the wait order (found by following the queue links from the owner), and C for an entry whose owner/wait bits the links contradict. Only the numbered locks (KeAcquireQueuedSpinLock) appear; in-stack queued spinlocks live on their acquirers' stacks.",
}

repl_command! {
    cmd_ipi;
    names: ["!ipi", "ipi"],
    usage: "!ipi [processor]",
    summary: "Show interprocessor-interrupt state for one processor or all of them.",
    details: "For each processor, the IPI fields its _KPRCB has on this build: IpiFrozen (the freeze state the debugger and KeFreezeExecution drive: Running, Frozen, Freeze owner...), TargetCount and PacketBarrier (as a sender, the targets still to finish its packet), SelfIpiRequestSummary, and IpiFrame (the trap frame of the IPI being serviced). On builds with per-sender mailboxes (Windows 10 and later), also the requests queued to the processor and not yet taken: the sender, the request type (packet, TB or cache flush, from RequestSummary), and a packet's worker routine and parameters; and, as a sender, the processors whose queues still hold its request.",
    completion: Expression,
}

repl_command! {
    cmd_pcitree;
    names: ["!pcitree", "pcitree"],
    usage: "!pcitree",
    summary: "Show the PCI bus hierarchy and the functions on each bus, as pci.sys tracks them.",
    details: "Walks pci.sys's segment list (pci!PciSegmentList), each segment's root buses, and each bus's functions and child buses, from the driver's own extensions (pci!_PCI_BUS, pci!_PCI_DEVICE; Windows 8 and later), so it reads guest memory only and works on every backend. A bus line gives its number and FDO extension; a function line gives its device and function number, vendor and device ID, PDO extension (devext), PDO (devstack, for !devstack), and class code and name. A bridge's secondary bus follows the bridge, indented. JSON adds each function's PnP instance path.",
}

repl_command! {
    cmd_pci;
    names: ["!pci", "pci"],
    usage: "!pci [flags] [bus [device [function [min max]]]]",
    summary: "Read and decode PCI configuration space.",
    details: "Scans a bus as WinDbg does (bus 0 by default): function 0 of each device, and functions 1-7 when function 0 is multi-function, and prints a line per function: device:function, vendor:device.revision, the command and status registers (Cmd letters: i I/O space, m memory space, b bus master, w memory write and invalidate, p parity error response, s SERR; Sts letters: c capability list, 6 66 MHz, p master data parity error, a signaled target abort, s signaled system error), the class, and the subsystem IDs or a bridge's primary->secondary-subordinate buses. Arguments are hex. Flags: 0x1 verbose, decoding the whole header (class code, header type, command and status bits by name, BARs, expansion ROM, bridge bus numbers, interrupt pin and line, and the capability lists); 0x2 scan buses 0 through bus; 0x4 raw bytes of the 64-byte header; 0x8 the same as dwords; 0x40 capability lists (the PCI capabilities, and a PCI Express function's extended capabilities); 0x100 raw bytes of the 256-byte configuration space. min and max (with a device and function) dump that range, extended space included (0-0xfff). Configuration space is device registers, not RAM, so it is read through the backend: over kd/kdnet the HAL reads it (DbgKdGetBusDataApi; segment 0), and over gdb QEMU's stub reads the function's ECAM page in its physical-memory mode, located by the ACPI MCFG table the HAL keeps. The memory and dump backends cannot read it; !pcitree still works there. Needs a halted target.",
    completion: Expression,
}

const PORT_READ_DETAILS: &str = "Reads the port (a byte for ib, a word for iw, a dword for id) on the current processor through the Windows KD protocol (DbgKdReadIoSpaceApi), so it needs the kd or kdnet backend and a halted target; the GDB, memory, and dump backends have no I/O space. The port must be aligned to the access size. Reading a port can change device state (a FIFO or status latch), as it does on real hardware.";

const PORT_WRITE_DETAILS: &str = "Writes the value to the port (a byte for ob, a word for ow, a dword for od) on the current processor through the Windows KD protocol (DbgKdWriteIoSpaceApi), so it needs the kd or kdnet backend and a halted target. The port must be aligned to the access size and the value must fit in it.";

repl_command! {
    cmd_ib;
    names: ["ib"],
    usage: "ib <port>",
    summary: "Read a byte from an I/O port.",
    details: PORT_READ_DETAILS,
    completion: Expression,
}

repl_command! {
    cmd_ob;
    names: ["ob"],
    usage: "ob <port> <value>",
    summary: "Write a byte to an I/O port.",
    details: PORT_WRITE_DETAILS,
    completion: Expression,
}

repl_command! {
    cmd_iw;
    names: ["iw"],
    usage: "iw <port>",
    summary: "Read a word from an I/O port.",
    details: PORT_READ_DETAILS,
    completion: Expression,
}

repl_command! {
    cmd_ow;
    names: ["ow"],
    usage: "ow <port> <value>",
    summary: "Write a word to an I/O port.",
    details: PORT_WRITE_DETAILS,
    completion: Expression,
}

repl_command! {
    cmd_id;
    names: ["id"],
    usage: "id <port>",
    summary: "Read a dword from an I/O port.",
    details: PORT_READ_DETAILS,
    completion: Expression,
}

repl_command! {
    cmd_od;
    names: ["od"],
    usage: "od <port> <value>",
    summary: "Write a dword to an I/O port.",
    details: PORT_WRITE_DETAILS,
    completion: Expression,
}

impl ReplState<'_> {
    fn cmd_ib(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.read_port(invocation, 1)
    }

    fn cmd_ob(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_port(invocation, 1)
    }

    fn cmd_iw(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.read_port(invocation, 2)
    }

    fn cmd_ow(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_port(invocation, 2)
    }

    fn cmd_id(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.read_port(invocation, 4)
    }

    fn cmd_od(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.write_port(invocation, 4)
    }

    /// `ib`/`iw`/`id`: WinDbg's `port: value` line.
    fn read_port(&mut self, invocation: CommandInvocation<'_>, size: u8) -> Result<()> {
        let [port] = invocation.argv.as_slice() else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(VirtAddr(port)) = self.eval_or_report(port) else {
            return Ok(());
        };
        match self.ctx.read_io_port(port, size) {
            Ok(value) => outln!(
                "{port:08x}: {value:0width$x}",
                width = usize::from(size) * 2
            ),
            Err(error) => error!("{}: {error}", invocation.name),
        }
        Ok(())
    }

    fn write_port(&mut self, invocation: CommandInvocation<'_>, size: u8) -> Result<()> {
        let [port, value] = invocation.argv.as_slice() else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(VirtAddr(port)) = self.eval_or_report(port) else {
            return Ok(());
        };
        let Some(VirtAddr(value)) = self.eval_or_report(value) else {
            return Ok(());
        };
        if let Err(error) = self.ctx.write_io_port(port, size, value) {
            error!("{}: {error}", invocation.name);
        }
        Ok(())
    }
    fn cmd_pcitree(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        match self.ctx.target.pci_tree() {
            Ok(tree) => print_pci_tree(&tree),
            Err(error) => error!("failed to read pci.sys's device tree: {error}"),
        }
        Ok(())
    }

    fn cmd_pci(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut values = Vec::with_capacity(invocation.argv.len());
        for text in &invocation.argv {
            let Some(VirtAddr(value)) = self.eval_or_report(text) else {
                return Ok(());
            };
            values.push(value);
        }
        let request = match parse_pci_request(&values) {
            Ok(request) => request,
            Err(error) => {
                error!("!pci: {error}");
                return Ok(());
            }
        };
        let scan = match self.ctx.scan_pci(&request.query) {
            Ok(scan) => scan,
            Err(error) => {
                error!("!pci: {error}");
                return Ok(());
            }
        };
        print_pci_scan(&request, &scan.functions);
        if scan.interrupted {
            outln!("(interrupted)");
        }
        Ok(())
    }

    fn cmd_qlocks(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        match self.ctx.target.queued_locks() {
            Ok(detail) => print_queued_locks(&detail),
            Err(error) => error!("failed to read the queued spinlocks: {error}"),
        }
        Ok(())
    }

    fn cmd_ipi(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let processor = match invocation.arg(0) {
            None => None,
            Some(text) => match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
                Ok(value) => match u16::try_from(value.0) {
                    Ok(processor) => Some(processor),
                    Err(_) => {
                        error!("processor index out of range: {:#x}", value.0);
                        return Ok(());
                    }
                },
                Err(error) => {
                    error!("invalid processor '{text}': {error}");
                    return Ok(());
                }
            },
        };
        let detail = match self.ctx.target.ipi_state(processor) {
            Ok(detail) => detail,
            Err(error) => {
                error!("failed to read IPI state: {error}");
                return Ok(());
            }
        };
        for processor in &detail.processors {
            print_ipi_processor(processor);
        }
        for error in &detail.errors {
            outln!(
                "processor {}: <unavailable: {}>",
                error.processor,
                error.message
            );
        }
        Ok(())
    }
}

fn print_queued_locks(detail: &QueuedLocksDetail) {
    outln!("Key: O = Owner, 1-n = Wait order, blank = not owned/waiting, C = Corrupt\n");
    let width = detail
        .locks
        .iter()
        .map(|lock| lock.name.len())
        .max()
        .unwrap_or(0)
        .max(9);
    let columns: String = detail
        .processors
        .iter()
        .map(|processor| format!("{processor:>3}"))
        .collect();
    outln!("    {:width$}  Processor Number", "");
    outln!("    {:width$}{columns}", "Lock Name");
    outln!("");
    for lock in &detail.locks {
        let cells: String = detail
            .processors
            .iter()
            .map(|processor| {
                let cell = lock
                    .holders
                    .iter()
                    .find(|holder| holder.processor == *processor)
                    .map_or_else(String::new, |holder| match &holder.state {
                        QueuedLockState::Owner => "O".to_string(),
                        QueuedLockState::Waiting(order) => order.to_string(),
                        QueuedLockState::Corrupt(_) => "C".to_string(),
                    });
                format!("{cell:>3}")
            })
            .collect();
        outln!("    {:width$}{}", lock.name, cells.trim_end());
    }
    outln!("");
    for lock in &detail.locks {
        for holder in &lock.holders {
            if let QueuedLockState::Corrupt(reason) = &holder.state {
                outln!(
                    "{}: processor {} {reason} (lock {})",
                    lock.name,
                    holder.processor,
                    lock.lock
                        .map_or_else(|| "?".into(), |lock| ui::addr(lock.0))
                );
            }
        }
    }
    for error in &detail.errors {
        outln!(
            "processor {}: <unavailable: {}>",
            error.processor,
            error.message
        );
    }
}

fn print_ipi_processor(processor: &IpiProcessor) {
    outln!(
        "IPI State for Processor {} (KPRCB {})",
        processor.processor,
        ui::addr(processor.kprcb.0)
    );
    let field = |name: &str| processor.fields.iter().find(|field| field.name == name);
    for entry in &processor.fields {
        let value = match (&entry.value, entry.name) {
            (DiagnosticValue::Available(value), "IpiFrozen") => {
                format!("{value:#x} [{}]", ipi_frozen_name(*value))
            }
            (DiagnosticValue::Available(value), "IpiFrame") => ui::addr(*value),
            (DiagnosticValue::Available(value), _) => format!("{value:#x}"),
            (DiagnosticValue::Unavailable(error), _) => format!("<unavailable: {error}>"),
        };
        outln!("    {:<22}{value}", entry.name);
    }
    let outstanding = matches!(
        field("TargetCount").map(|field| &field.value),
        Some(DiagnosticValue::Available(count)) if *count != 0
    );
    if !processor.awaiting.is_empty() {
        let list: Vec<String> = processor.awaiting.iter().map(u16::to_string).collect();
        outln!(
            "    As a sender, awaiting request completion from processor(s) {}",
            list.join(" ")
        );
    } else if outstanding {
        outln!("    As a sender, a packet is outstanding (targets already took the request)");
    }
    match &processor.pending {
        DiagnosticValue::Available(requests) if requests.is_empty() => {
            outln!("    As a receiver, no requests are pending");
        }
        DiagnosticValue::Available(requests) => {
            outln!("    As a receiver, the following requests are pending:");
            for request in requests {
                let sender = request.sender.map_or_else(
                    || "an unknown processor".into(),
                    |sender| format!("processor {sender}"),
                );
                let kind = match &request.request_summary {
                    DiagnosticValue::Available(summary) => format!(
                        "[{}] summary {summary:#x}",
                        ipi_request_type_name(*summary).unwrap_or("unknown type")
                    ),
                    DiagnosticValue::Unavailable(error) => {
                        format!("summary <unavailable: {error}>")
                    }
                };
                outln!(
                    "      from {sender} (mailbox {}): {kind}",
                    ui::addr(request.mailbox.0)
                );
                let is_packet = matches!(&request.request_summary,
                    DiagnosticValue::Available(summary) if ipi_request_type_name(*summary) == Some("packet"));
                if is_packet {
                    let worker = match &request.worker_routine {
                        DiagnosticValue::Available(routine) => match &request.worker_symbol {
                            Some(symbol) => {
                                format!("{} ({})", ui::symbol(symbol), ui::addr(routine.0))
                            }
                            None => ui::addr(routine.0),
                        },
                        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
                    };
                    outln!("        Worker Routine: {worker}");
                    if let DiagnosticValue::Available(parameters) = &request.parameters {
                        for (index, parameter) in parameters.iter().enumerate() {
                            outln!("        Parameter[{index}]: {}", ui::addr(*parameter));
                        }
                    }
                }
            }
            if processor.pending_truncated {
                outln!("      (list walk stopped at a repeated or unreadable mailbox)");
            }
        }
        DiagnosticValue::Unavailable(error) => {
            outln!(
                "    {}",
                ui::muted(&format!("pending requests unavailable: {error}"))
            );
        }
    }
    outln!("");
}

fn print_pci_tree(tree: &PciTree) {
    let mut root_buses = 0;
    for segment in &tree.segments {
        if tree.segments.len() > 1 {
            outln!(
                "Segment 0x{:x} ({})",
                segment.number,
                ui::addr(segment.address.0)
            );
        }
        for bus in &segment.root_buses {
            print_pci_tree_bus(bus, 0);
            root_buses += 1;
        }
    }
    outln!("");
    outln!("Total PCI Root busses processed = {root_buses}");
    outln!("Total PCI Segments processed = {}", tree.segments.len());
    if tree.truncated {
        outln!("(walk stopped at a repeated link or its size limit)");
    }
}

fn print_pci_tree_bus(bus: &PciTreeBus, depth: usize) {
    let indent = "  ".repeat(depth);
    outln!(
        "{indent}Bus 0x{:x} (FDO Ext {})",
        bus.number,
        ui::addr(bus.extension.0)
    );
    let mut printed = vec![false; bus.child_buses.len()];
    for device in &bus.devices {
        print_pci_tree_device(device, &indent);
        for (index, child) in bus.child_buses.iter().enumerate() {
            if !printed[index]
                && !device.device_object.is_zero()
                && child.bridge_pdo == device.device_object
            {
                print_pci_tree_bus(child, depth + 1);
                printed[index] = true;
            }
        }
    }
    for (index, child) in bus.child_buses.iter().enumerate() {
        if !printed[index] {
            print_pci_tree_bus(child, depth + 1);
        }
    }
}

fn print_pci_tree_device(device: &PciTreeDevice, indent: &str) {
    let slot = format!("{:x},", device.device);
    outln!(
        "{indent}  (d={slot:<3} f={:x}) {:04x}{:04x} devext 0x{} devstack 0x{} {:02x}{:02x} {}",
        device.function,
        device.vendor_id,
        device.device_id,
        ui::addr(device.extension.0),
        ui::addr(device.device_object.0),
        device.base_class,
        device.sub_class,
        class_name(device.base_class, device.sub_class).unwrap_or_default()
    );
}

/// WinDbg's register letters: a letter per listed bit, `.` when clear.
fn register_letters(value: u16, bits: &[(u16, char)]) -> String {
    bits.iter()
        .map(|(bit, letter)| if value & bit != 0 { *letter } else { '.' })
        .collect()
}

const COMMAND_LETTERS: [(u16, char); 6] = [
    (0x0001, 'i'),
    (0x0002, 'm'),
    (0x0004, 'b'),
    (0x0010, 'w'),
    (0x0040, 'p'),
    (0x0100, 's'),
];

const STATUS_LETTERS: [(u16, char); 5] = [
    (0x0010, 'c'),
    (0x0020, '6'),
    (0x0100, 'p'),
    (0x0800, 'a'),
    (0x4000, 's'),
];

fn print_pci_scan(request: &PciRequest, functions: &[PciFunctionConfig]) {
    if functions.is_empty() {
        let query = &request.query;
        let place = match (query.device, query.function) {
            (Some(device), Some(function)) => format!(
                "at bus 0x{:x} device 0x{device:x} function 0x{function:x}",
                query.last_bus
            ),
            (Some(device), None) => {
                format!("at bus 0x{:x} device 0x{device:x}", query.last_bus)
            }
            _ if query.first_bus == query.last_bus => format!("on bus 0x{:x}", query.last_bus),
            _ => format!("on buses 0x{:x}-0x{:x}", query.first_bus, query.last_bus),
        };
        outln!("no PCI function responds {place}");
        return;
    }
    let mut current_bus = None;
    for function in functions {
        if current_bus != Some((function.segment, function.bus)) {
            if current_bus.is_some() {
                outln!("");
            }
            outln!("PCI Segment {} Bus 0x{:x}", function.segment, function.bus);
            current_bus = Some((function.segment, function.bus));
        }
        print_pci_function(request, function);
    }
}

fn print_pci_function(request: &PciRequest, function: &PciFunctionConfig) {
    let config = &function.config;
    let Some(header) = parse_header(config) else {
        return;
    };
    let class = class_name(header.base_class, header.sub_class)
        .unwrap_or_else(|| format!("Class {:02x}{:02x}", header.base_class, header.sub_class));
    let tail = match (header.subsystem, header.buses) {
        (_, Some((primary, secondary, subordinate))) => {
            format!("  Bus:{primary:x}->{secondary:x}-{subordinate:x}")
        }
        (Some((vendor, id)), None) if vendor != 0 || id != 0 => {
            format!("  SubID:{vendor:04x}:{id:04x}")
        }
        _ => String::new(),
    };
    outln!(
        "{:02x}:{:x}  {:04x}:{:04x}.{:02x}  Cmd[{:04x}:{}]  Sts[{:04x}:{}]  {class}{tail}",
        function.device,
        function.function,
        header.vendor_id,
        header.device_id,
        header.revision,
        header.command,
        register_letters(header.command, &COMMAND_LETTERS),
        header.status,
        register_letters(header.status, &STATUS_LETTERS),
    );
    const INDENT: &str = "      ";
    if request.verbose {
        let layout = match header.layout() {
            0 => "device",
            1 => "PCI-to-PCI bridge",
            2 => "CardBus bridge",
            _ => "unknown layout",
        };
        outln!(
            "{INDENT}Class {:02x}:{:02x}:{:02x}  Header {:02x} ({layout}{})  CacheLine {:x}  Latency {:x}  BIST {:02x}",
            header.base_class,
            header.sub_class,
            header.prog_if,
            header.header_type,
            if header.multifunction() {
                ", multi-function"
            } else {
                ""
            },
            header.cache_line_size,
            header.latency_timer,
            header.bist
        );
        outln!(
            "{INDENT}Command {:04x} {}",
            header.command,
            command_flags(header.command).join(" ")
        );
        outln!(
            "{INDENT}Status  {:04x} {}",
            header.status,
            status_flags(header.status).join(" ")
        );
        for bar in &header.bars {
            let width = if bar.raw > u64::from(u32::MAX) { 16 } else { 8 };
            outln!(
                "{INDENT}BAR{} {} {:0width$x}{}",
                bar.index,
                bar.kind.name(),
                bar.address,
                if bar.prefetchable {
                    " prefetchable"
                } else {
                    ""
                }
            );
        }
        if let Some(rom) = header.expansion_rom.filter(|rom| *rom != 0) {
            outln!(
                "{INDENT}ROM  {:08x} {}",
                rom & !0x7ff,
                if rom & 1 != 0 { "enabled" } else { "disabled" }
            );
        }
        if let Some((primary, secondary, subordinate)) = header.buses {
            outln!(
                "{INDENT}Buses primary {primary:x} secondary {secondary:x} subordinate {subordinate:x}"
            );
        }
        let pin = match header.interrupt_pin {
            0 => "none".to_string(),
            pin @ 1..=4 => format!("{pin} (INT{})", char::from(b'A' + pin - 1)),
            pin => format!("{pin:#x} (invalid)"),
        };
        outln!(
            "{INDENT}Interrupt pin {pin} line 0x{:x}",
            header.interrupt_line
        );
    }
    if request.verbose || request.capabilities {
        let list = capabilities(&header, config);
        if !list.is_empty() {
            let names: Vec<String> = list
                .iter()
                .map(|capability| {
                    format!(
                        "{:02x} {}",
                        capability.offset,
                        capability_name(capability.id)
                            .map_or_else(|| format!("ID {:#x}", capability.id), str::to_string)
                    )
                })
                .collect();
            outln!("{INDENT}Capabilities: {}", names.join(", "));
        }
        let express = list
            .iter()
            .any(|capability| capability.id == CAPABILITY_PCI_EXPRESS);
        let extended = if express && config.len() > PCI_CONFIG_SIZE {
            extended_capabilities(config)
        } else {
            Vec::new()
        };
        if !extended.is_empty() {
            let names: Vec<String> = extended
                .iter()
                .map(|capability| {
                    format!(
                        "{:03x} {} v{}",
                        capability.offset,
                        extended_capability_name(capability.id)
                            .map_or_else(|| format!("ID {:#x}", capability.id), str::to_string),
                        capability.version.unwrap_or(0)
                    )
                })
                .collect();
            outln!("{INDENT}Extended capabilities: {}", names.join(", "));
        }
    }
    if let Some(raw) = request.raw {
        print_pci_raw(config, raw);
    }
}

fn print_pci_raw(config: &[u8], raw: PciRawRange) {
    let end = raw.end.min(config.len());
    let mut offset = raw.start & !0xf;
    while offset < end {
        let line_end = (offset + 16).min(end);
        let mut text = String::new();
        if raw.dwords {
            let mut at = offset;
            while at + 4 <= line_end {
                if at >= raw.start {
                    let value = u32::from_le_bytes([
                        config[at],
                        config[at + 1],
                        config[at + 2],
                        config[at + 3],
                    ]);
                    text.push_str(&format!(" {value:08x}"));
                } else {
                    text.push_str("         ");
                }
                at += 4;
            }
        } else {
            for (at, byte) in config.iter().enumerate().take(line_end).skip(offset) {
                if at >= raw.start {
                    text.push_str(&format!(" {byte:02x}"));
                } else {
                    text.push_str("   ");
                }
            }
        }
        outln!("      {offset:03x}:{text}");
        offset += 16;
    }
}
