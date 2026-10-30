//! Hang diagnosis from the processor blocks (`!qlocks`, `!ipi`), I/O-port
//! access (`ib`/`iw`/`id`, `ob`/`ow`/`od`), and PCI (`!pcitree`, `!pci`).

use std::borrow::Cow;

use ntoseye_macros::{command, grammar};

use crate::base::error::{Error, Result};
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::expr::Expr;
use crate::nt::target::DiagnosticValue;
use crate::nt::target::hang::{
    IpiProcessor, IpiState, QueuedLockState, QueuedLocks, ipi_frozen_name, ipi_request_type_name,
};
use crate::nt::target::pci::{
    CAPABILITY_PCI_EXPRESS, PCI_CONFIG_SIZE, PCI_EXTENDED_CONFIG_SIZE, PciFunction, PciQuery,
    PciRawRange, PciRequest, PciScan, PciTree, PciTreeBus, PciTreeDevice, capabilities,
    capability_name, class_name, command_flags, extended_capabilities, extended_capability_name,
    parse_pci_request, status_flags,
};
use crate::session::Session;

/// Show which processors own or wait for each numbered queued spinlock.
///
/// Reads the _KPRCB.LockQueue entries of each processor, which hold one
/// _KSPIN_LOCK_QUEUE for each _KSPIN_LOCK_QUEUE_NUMBER lock. The table has the
/// same layout as in WinDbg, with one row for each lock and one column for each
/// processor. O marks the owner, and 1-n marks the wait order, which the
/// command finds by following the queue links from the owner. C marks an entry
/// whose owner or wait bits do not agree with the links. The table shows only
/// the numbered locks (KeAcquireQueuedSpinLock). In-stack queued spinlocks are
/// on the stacks of the callers that acquire them.
#[command(
    names = ["!qlocks", "qlocks"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "queued_locks",
)]
fn qlocks(session: &mut Session) -> Result<QueuedLocks> {
    session
        .target
        .queued_locks()
        .map_err(|error| Error::DebugInfo(format!("failed to read the queued spinlocks: {error}")))
}

impl Render for QueuedLocks {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_queued_locks(self);
    }
}

/// The processor of `!ipi` (one word) or `!ready` (the rest of the line),
/// as an expression; omitted, every processor.
fn processor_filter(
    cx: &mut ArgCx<'_, '_>,
    text: Option<String>,
) -> std::result::Result<Option<u16>, ArgError> {
    let Some(text) = text else {
        return Ok(None);
    };
    let value = Expr::eval_with_radix(&text, &cx.state.ctx.target, cx.state.ctx.radix)
        .map_err(|error| ArgError::Message(format!("invalid processor '{text}': {error}")))?
        .0;
    u16::try_from(value)
        .map(Some)
        .map_err(|_| ArgError::Message(format!("processor index out of range: {value:#x}")))
}

/// `!ipi`'s processor: one word.
#[grammar(usage = "[processor]", complete = [Expression])]
fn ipi_processor(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<u16>, ArgError> {
    let text = cursor.word().map(Cow::into_owned);
    processor_filter(cx, text)
}

/// `!ready`'s processor: the rest of the line.
#[grammar(usage = "[{}]", complete = [Expression])]
pub fn ready_processor(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<u16>, ArgError> {
    let text = (cursor.remaining() != 0).then(|| cursor.rest());
    processor_filter(cx, text)
}

/// Show the interprocessor interrupt (IPI) state of one processor or of all
/// processors.
///
/// For each processor, shows the IPI fields that its _KPRCB has on this Windows
/// build. IpiFrozen is the freeze state that the debugger and KeFreezeExecution
/// control (Running, Frozen, Freeze owner, ...). TargetCount and PacketBarrier
/// apply to the processor as a sender and show the targets that did not finish
/// its packet yet. The command also shows SelfIpiRequestSummary and IpiFrame,
/// the trap frame of the IPI that the processor services now. Windows 10 and
/// later builds have one mailbox for each sender, and on these builds the
/// command also shows the requests that are in the queue of the processor and
/// are not taken yet. For each request, it shows the sender, the request type,
/// and for a packet, the worker routine and parameters. The request type
/// (packet, TB flush, or cache flush) comes from RequestSummary. For the
/// processor as a sender, the command also shows the processors whose queues
/// still hold its request.
#[command(
    names = ["!ipi", "ipi"],
    category = "cpu",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn ipi(
    session: &mut Session,
    #[arg(parse = ipi_processor, positional)] processor: Option<u16>,
) -> Result<IpiState> {
    session
        .target
        .ipi_state(processor)
        .map_err(|error| Error::DebugInfo(format!("failed to read IPI state: {error}")))
}

impl Render for IpiState {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        for processor in &self.processors {
            print_ipi_processor(processor);
        }
        for error in &self.errors {
            outln!(
                "{}",
                ui::muted(&format!(
                    "processor {}: IPI state unavailable: {}",
                    error.processor, error.message
                ))
            );
        }
    }
}

/// Show the PCI bus hierarchy that pci.sys tracks, with the functions on each
/// bus.
///
/// Reads the pci.sys segment list (pci!PciSegmentList), the root buses of each
/// segment, and the functions and child buses of each bus. The data comes from
/// the extensions of the driver (pci!_PCI_BUS and pci!_PCI_DEVICE), which exist
/// on Windows 8 and later. Because the command reads only guest memory, it
/// works on all backends. A bus line shows the bus number and the FDO
/// extension. A function line shows the device and function number, the vendor
/// and device ID, the PDO extension (devext), the PDO (devstack, for
/// !devstack), and the class code and name. The secondary bus of a bridge
/// follows the bridge and is indented. The JSON output also has the PnP
/// instance path of each function.
#[command(
    names = ["!pcitree", "pcitree"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
    python_name = "pci_tree",
)]
fn pcitree(session: &mut Session) -> Result<PciTree> {
    session
        .target
        .pci_tree()
        .map_err(|error| Error::DebugInfo(format!("failed to read pci.sys's device tree: {error}")))
}

impl Render for PciTree {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_pci_tree(self);
    }
}

/// `!pci`'s words, each an expression, as WinDbg reads them.
#[grammar(usage = "[flags] [bus [device [function [min max]]]]", complete = Expression)]
fn pci_request(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<PciRequest, ArgError> {
    let mut values = Vec::with_capacity(cursor.remaining());
    while let Some(text) = cursor.word() {
        values.push(cx.eval(&text)?.0);
    }
    parse_pci_request(&values).map_err(|error| ArgError::Message(format!("!pci: {error}")))
}

/// A `!pci` scan and the request that chose what it shows.
pub struct PciReport {
    request: PciRequest,
    scan: PciScan,
}

/// Read and decode PCI configuration space.
///
/// Scans a bus (0 by default) in the same way as WinDbg. The command reads
/// function 0 of each device, and functions 1-7 when function 0 is
/// multi-function, and prints one line for each function. The line shows
/// device:function, vendor:device.revision, the command and status registers,
/// the class, and the subsystem IDs or, for a bridge, the
/// primary->secondary-subordinate buses. Cmd letters: i I/O space, m memory
/// space, b bus master, w memory write and invalidate, p parity error response,
/// s SERR. Sts letters: c capability list, 6 66 MHz, p master data parity
/// error, A signaled target abort, s signaled system error. All arguments are
/// hex. Flags: 0x1 is verbose and decodes the full header, including the class
/// code, the header type, the command and status bits by name, the BARs, the
/// expansion ROM, the bridge bus numbers, the interrupt pin and line, and the
/// capability lists. 0x2 scans buses 0 through bus. 0x4 shows the raw bytes of
/// the 64-byte header, and 0x8 shows the same bytes as dwords. 0x40 shows the
/// capability lists (the PCI capabilities, and the extended capabilities of a
/// PCI Express function). 0x100 shows the raw bytes of the 256-byte
/// configuration space. If you give a device and a function, min and max dump
/// that range, which can include extended space (0-0xfff). Configuration space
/// contains device registers and is not RAM, so the command reads it through
/// the backend. Over kd/kdnet, the HAL reads it (DbgKdGetBusDataApi, segment
/// 0). Over gdb, the QEMU stub reads the ECAM page of the function in its
/// physical-memory mode, and the command finds this page from the ACPI MCFG
/// table that the HAL keeps. The memory and dump backends cannot read
/// configuration space, but !pcitree works on them. The target must be halted.
#[command(
    names = ["!pci", "pci"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [pci],
)]
fn pci_command(
    session: &mut Session,
    #[arg(parse = pci_request)] request: PciRequest,
) -> Result<PciReport> {
    let scan = session
        .scan_pci(&request.query)
        .map_err(|error| Error::DebugInfo(format!("!pci: {error}")))?;
    Ok(PciReport { request, scan })
}

/// Read and decode PCI configuration space (`!pci`) for the functions on
/// `bus` (through `last_bus`), or for one `device` and `function`. It reads
/// all 4 KiB of each function, with the extended capabilities, as `config`.
/// This needs a halted target and a backend that can get to configuration
/// space (kd/kdnet, or gdb on QEMU).
#[command(form_of = pci_command, python = Inspect)]
fn pci(
    session: &mut Session,
    #[arg(default = 0, positional)] bus: u8,
    #[arg(positional)] device: Option<u8>,
    #[arg(positional)] function: Option<u8>,
    last_bus: Option<u8>,
) -> Result<PciScan> {
    session.scan_pci(&PciQuery {
        segment: 0,
        first_bus: bus,
        last_bus: last_bus.unwrap_or(bus),
        device,
        function,
        size: PCI_EXTENDED_CONFIG_SIZE,
    })
}

impl Render for PciReport {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_pci_scan(&self.request, &self.scan.functions);
        if self.scan.interrupted {
            outln!("(interrupted)");
        }
    }
}

/// A value read from an I/O port, as `ib`/`iw`/`id` read it.
pub struct PortValue {
    port: u64,
    size: u8,
    value: u32,
}

impl Render for PortValue {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        outln!(
            "{:08x}: {:0width$x}",
            self.port,
            self.value,
            width = usize::from(self.size) * 2
        );
    }
}

/// `ib`/`iw`/`id`: `size` bytes from `port`, the error named as typed.
fn read_port(session: &mut Session, name: &str, port: u64, size: u8) -> Result<PortValue> {
    let value = session
        .read_io_port(port, size)
        .map_err(|error| Error::DebugInfo(format!("{name}: {error}")))?;
    Ok(PortValue { port, size, value })
}

/// `ob`/`ow`/`od`: `value` as `size` bytes to `port`, the error named as
/// typed.
fn write_port(session: &mut Session, name: &str, port: u64, size: u8, value: u64) -> Result<()> {
    session
        .write_io_port(port, size, value)
        .map_err(|error| Error::DebugInfo(format!("{name}: {error}")))
}

/// Read a byte from an I/O port.
///
/// Reads the port (a byte for ib, a word for iw, a dword for id) on the current
/// processor. The command uses the Windows KD protocol (DbgKdReadIoSpaceApi),
/// so it needs the kd or kdnet backend and a halted target, and the GDB,
/// memory, and dump backends have no I/O space. The port must be aligned to the
/// access size. As on real hardware, a port read can change the device state
/// (for example, a FIFO or a status latch).
#[command(
    names = ["ib"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Hardware],
    capability = IoPorts,
    python = none,
)]
fn ib(session: &mut Session, #[arg(invoked)] name: &str, port: u64) -> Result<PortValue> {
    read_port(session, name, port, 1)
}

/// Write a byte to an I/O port.
///
/// Writes the value to the port (a byte for ob, a word for ow, a dword for od)
/// on the current processor. The command uses the Windows KD protocol
/// (DbgKdWriteIoSpaceApi), so it needs the kd or kdnet backend and a halted
/// target. The port must be aligned to the access size, and the value must fit
/// in it.
#[command(
    names = ["ob"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Hardware],
    capability = IoPorts,
    python = none,
)]
fn ob(session: &mut Session, #[arg(invoked)] name: &str, port: u64, value: u64) -> Result<()> {
    write_port(session, name, port, 1, value)
}

/// Read a word from an I/O port.
///
/// Reads the port (a byte for ib, a word for iw, a dword for id) on the current
/// processor. The command uses the Windows KD protocol (DbgKdReadIoSpaceApi),
/// so it needs the kd or kdnet backend and a halted target, and the GDB,
/// memory, and dump backends have no I/O space. The port must be aligned to the
/// access size. As on real hardware, a port read can change the device state
/// (for example, a FIFO or a status latch).
#[command(
    names = ["iw"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Hardware],
    capability = IoPorts,
    python = none,
)]
fn iw(session: &mut Session, #[arg(invoked)] name: &str, port: u64) -> Result<PortValue> {
    read_port(session, name, port, 2)
}

/// Write a word to an I/O port.
///
/// Writes the value to the port (a byte for ob, a word for ow, a dword for od)
/// on the current processor. The command uses the Windows KD protocol
/// (DbgKdWriteIoSpaceApi), so it needs the kd or kdnet backend and a halted
/// target. The port must be aligned to the access size, and the value must fit
/// in it.
#[command(
    names = ["ow"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Hardware],
    capability = IoPorts,
    python = none,
)]
fn ow(session: &mut Session, #[arg(invoked)] name: &str, port: u64, value: u64) -> Result<()> {
    write_port(session, name, port, 2, value)
}

/// Read a dword from an I/O port.
///
/// Reads the port (a byte for ib, a word for iw, a dword for id) on the current
/// processor. The command uses the Windows KD protocol (DbgKdReadIoSpaceApi),
/// so it needs the kd or kdnet backend and a halted target, and the GDB,
/// memory, and dump backends have no I/O space. The port must be aligned to the
/// access size. As on real hardware, a port read can change the device state
/// (for example, a FIFO or a status latch).
#[command(
    names = ["id"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Hardware],
    capability = IoPorts,
    python = none,
)]
fn id(session: &mut Session, #[arg(invoked)] name: &str, port: u64) -> Result<PortValue> {
    read_port(session, name, port, 4)
}

/// Write a dword to an I/O port.
///
/// Writes the value to the port (a byte for ob, a word for ow, a dword for od)
/// on the current processor. The command uses the Windows KD protocol
/// (DbgKdWriteIoSpaceApi), so it needs the kd or kdnet backend and a halted
/// target. The port must be aligned to the access size, and the value must fit
/// in it.
#[command(
    names = ["od"],
    category = "memory and disassembly",
    kind = Action,
    target = Kernel,
    state = Halted,
    writes = [Hardware],
    capability = IoPorts,
    python = none,
)]
fn od(session: &mut Session, #[arg(invoked)] name: &str, port: u64, value: u64) -> Result<()> {
    write_port(session, name, port, 4, value)
}

fn print_queued_locks(detail: &QueuedLocks) {
    outln!("Key: O = Owner, 1-n = Wait order, blank = not owned/waiting, C = Corrupt\n");
    let width = detail
        .locks
        .iter()
        .map(|lock| lock.name.len())
        .max()
        .unwrap_or(0)
        .max(9);
    // A space before each processor number, however many digits it has.
    let highest = detail.processors.iter().max().copied().unwrap_or(0);
    let cell = highest.to_string().len().max(2) + 1;
    let columns: String = detail
        .processors
        .iter()
        .map(|processor| format!("{processor:>cell$}"))
        .collect();
    outln!("    {:width$}  Processor Number", "");
    outln!("    {:width$}{columns}", "Lock Name");
    outln!("");
    for lock in &detail.locks {
        let cells: String = detail
            .processors
            .iter()
            .map(|processor| {
                let text = lock
                    .holders
                    .iter()
                    .find(|holder| holder.processor == *processor)
                    .map_or_else(String::new, |holder| match &holder.state {
                        QueuedLockState::Owner => "O".to_string(),
                        QueuedLockState::Waiting(order) => order.to_string(),
                        QueuedLockState::Corrupt(_) => "C".to_string(),
                    });
                format!("{text:>cell$}")
            })
            .collect();
        outln!("{}", format!("    {:width$}{cells}", lock.name).trim_end());
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
                        .map_or_else(|| "-".into(), |lock| ui::addr(lock.0))
                );
            }
        }
    }
    for error in &detail.errors {
        outln!(
            "{}",
            ui::muted(&format!(
                "processor {}: queued locks unavailable: {}",
                error.processor, error.message
            ))
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
    let mut unavailable = Vec::new();
    for entry in &processor.fields {
        let value = match (&entry.value, entry.name) {
            (DiagnosticValue::Available(value), "IpiFrozen") => match ipi_frozen_name(*value) {
                "Unknown" => format!("{value:#x}"),
                name => format!("{name} ({value:#x})"),
            },
            (DiagnosticValue::Available(value), "IpiFrame") => ui::addr(*value),
            (DiagnosticValue::Available(value), _) => format!("{value:#x}"),
            (DiagnosticValue::Unavailable(error), _) => {
                unavailable.push(format!("{} unavailable: {error}", entry.name));
                "-".to_string()
            }
        };
        outln!("    {:<22}{value}", entry.name);
    }
    for note in unavailable {
        outln!("    {}", ui::muted(&note));
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
                        format!("summary unavailable: {error}")
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
                        DiagnosticValue::Unavailable(error) => {
                            format!("- {}", ui::muted(&format!("(unavailable: {error})")))
                        }
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
    for error in &tree.errors {
        outln!("(skipped the rest of a list at an unreadable node, {error})");
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
    (0x0800, 'A'),
    (0x4000, 's'),
];

fn print_pci_scan(request: &PciRequest, functions: &[PciFunction]) {
    if functions.is_empty() {
        let query = &request.query;
        let buses = if query.first_bus == query.last_bus {
            format!("bus 0x{:x}", query.last_bus)
        } else {
            format!("buses 0x{:x}-0x{:x}", query.first_bus, query.last_bus)
        };
        let place = match (query.device, query.function) {
            (Some(device), Some(function)) => {
                format!("at {buses} device 0x{device:x} function 0x{function:x}")
            }
            (Some(device), None) => format!("at {buses} device 0x{device:x}"),
            _ => format!("on {buses}"),
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

fn print_pci_function(request: &PciRequest, function: &PciFunction) {
    let config = &function.config;
    let header = &function.header;
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
                bar.kind.as_str(),
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
            0 => "-".to_string(),
            pin @ 1..=4 => format!("{pin} (INT{})", char::from(b'A' + pin - 1)),
            pin => format!("{pin:#x} (invalid)"),
        };
        outln!(
            "{INDENT}Interrupt pin {pin} line 0x{:x}",
            header.interrupt_line
        );
    }
    if request.verbose || request.capabilities {
        let list = capabilities(header, config);
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
