//! StorPort adapters and units (`!storagekd.storadapter`,
//! `!storagekd.storunit`), StorPort's adapter log
//! (`!storagekd.storloglist`, `!storagekd.storlogirp`,
//! `!storagekd.storlogsrb`), SRBs (`!storagekd.storsrb`), and classpnp's
//! class devices (`!storagekd.storclass`).

use std::fmt::Display;

use ntoseye_macros::{command, grammar};
use tabled::builder::Builder;

use crate::base::error::{Error, Result};
use crate::base::time::filetime_to_iso_precise;
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::Target;
use crate::nt::target::classpnp::{ClassDevice, ClassDeviceDetail, ClassDevices};
use crate::nt::target::srb::{Srb, srb_function_name, srb_status_text};
use crate::nt::target::storport::{
    StorAdapter, StorAdapterEntry, StorDrivers, StorEnumValue, StorLog, StorLogEntry, StorUnit,
    StorUnitEntry, log_request,
};
use crate::nt::target::virtio_request::{scsi_command, scsi_status};
use crate::session::Session;

/// List the StorPort adapters, or show one adapter and its units.
///
/// Without an argument, walks storport's driver list (storport!RaidpPortData)
/// and each driver's adapters, and shows one line per adapter: the miniport
/// driver, the adapter extension (_RAID_ADAPTER_EXTENSION), the FDO, the PnP
/// state, the port device name, the PCI location, the number of units, and the
/// I/O state. With the address of an adapter extension or of its FDO, shows the
/// adapter: its driver, device objects, PnP and power state, the miniport's own
/// device extension (the HwDeviceExtension that StorPort passes to every Hw
/// routine, which you read with dt and the miniport's private PDB) and its
/// size, the flags (_FLAGS, _FLAGS2), the paging and crash-dump path counts,
/// each I/O gateway's outstanding and waiting requests, and each unit with its
/// bus/target/LUN, PDO, state, inquiry product, and I/O state. The command
/// needs storport's PDB. It stops each list at the head, a null or repeated
/// link, or 256 drivers or adapters, and says why it stopped early. Adapters of
/// storport's native NVMe path are listed but not decoded.
#[command(
    names = ["!storagekd.storadapter"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [storport_adapters, storport_adapter],
)]
fn storport_adapter_command(
    session: &Session,
    #[arg(name = "adapter")] address: Option<VirtAddr>,
) -> Result<StorAdapterOrList> {
    match address {
        None => storport_adapters(session).map(StorAdapterOrList::Drivers),
        Some(address) => storport_adapter(session, address).map(StorAdapterOrList::Adapter),
    }
    .map_err(|error| Error::DebugInfo(format!("!storagekd.storadapter: {error}")))
}

/// List StorPort's drivers, their adapters, and their units
/// (`!storagekd.storadapter`).
#[command(form_of = storport_adapter_command, python = Inspect)]
fn storport_adapters(session: &Session) -> Result<StorDrivers> {
    session.target.storport_drivers()
}

/// Read the StorPort adapter whose extension or FDO is at `address`
/// (`!storagekd.storadapter <address>`).
#[command(form_of = storport_adapter_command, python = Inspect)]
fn storport_adapter(session: &Session, address: VirtAddr) -> Result<StorAdapter> {
    session.target.storport_adapter(address)
}

/// What `!storagekd.storadapter` shows: every driver and its adapters, or
/// one adapter.
enum StorAdapterOrList {
    Drivers(StorDrivers),
    Adapter(StorAdapter),
}

impl Render for StorAdapterOrList {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Drivers(drivers) => print_adapters(drivers),
            Self::Adapter(adapter) => print_adapter(adapter),
        }
    }
}

/// Show a StorPort logical unit, its queue, and the requests the miniport
/// holds.
///
/// Give the address of a unit extension (_RAID_UNIT_EXTENSION), as
/// !storagekd.storadapter lists them, or of the unit's PDO. Shows the unit's
/// bus/target/LUN, the inquiry vendor, product and revision, the adapter, the
/// PnP and power state, the flags, the miniport's per-unit extension
/// (StorPortGetLogicalUnit), and its device queue: the depth, whether it is
/// frozen or locked, the pause and busy counts, and the requests waiting in
/// storport. Then it lists each request that storport handed to the miniport
/// and has not seen completed, from the unit's per-processor pending queues,
/// with its _EXTENDED_REQUEST_BLOCK, IRP and SRB; use !irp on the IRP. It lists
/// at most 256 requests and says why a list stopped early.
#[command(
    names = ["!storagekd.storunit"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn storport_unit(session: &Session, #[arg(name = "unit")] address: VirtAddr) -> Result<StorUnit> {
    session
        .target
        .storport_unit(address)
        .map_err(|error| Error::DebugInfo(format!("!storagekd.storunit: {error}")))
}

impl Render for StorUnit {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        print_unit(&repl.ctx.target, self);
    }
}

/// Show a StorPort adapter's internal log of requests, pauses, and resumes.
///
/// Give the address of an adapter extension or of its FDO, as
/// !storagekd.storadapter lists them. StorPort keeps a ring of its last 256
/// events for each adapter (RaidLogList): requests it builds, starts, and sees
/// completed, pauses and resumes of the adapter and its units, busy and ready
/// notifications, timeouts, resets, and PnP and power IRPs. Each entry shows
/// its number, its time (UTC), the event, and for a request its IRP, SRB,
/// command, and SRB status, or else the four parameters StorPort logged, a code
/// address by symbol. Without a range, the command shows the last 50 entries;
/// <start> shows entries from that number, <start> <end> that range, and L
/// <count> how many.
#[command(
    names = ["!storagekd.storloglist"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn storport_log(
    session: &Session,
    #[arg(name = "adapter")] address: VirtAddr,
    #[arg(render, parse = log_range)] range: LogRange,
) -> Result<StorLog> {
    session
        .target
        .storport_log(address)
        .map_err(|error| Error::DebugInfo(format!("!storagekd.storloglist: {error}")))
}

/// The entries `!storagekd.storloglist` shows: up to two entry numbers (a
/// start, and an end), and a count after `L`.
#[derive(Debug, Default)]
struct LogRange {
    bounds: Vec<u64>,
    count: Option<u64>,
}

/// `[<start> [<end>]] [L <count>]`, `L<count>` glued too.
#[grammar(usage = "[start [end]] [L<count>]", complete = Expression)]
fn log_range(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<LogRange, ArgError> {
    let mut range = LogRange::default();
    while let Some(arg) = cursor.word() {
        let count_text = match arg.as_ref() {
            "L" | "l" => match cursor.word() {
                Some(text) => Some(text),
                None => {
                    return Err(ArgError::usage(
                        cx.name,
                        format!("{}: L needs a count", cx.name),
                    ));
                }
            },
            _ => arg
                .strip_prefix(['L', 'l'])
                .filter(|rest| !rest.is_empty())
                .map(|rest| rest.to_string().into()),
        };
        let value = cx.eval(count_text.as_deref().unwrap_or(arg.as_ref()))?;
        if count_text.is_some() {
            range.count = Some(value.0);
        } else if range.bounds.len() < 2 {
            range.bounds.push(value.0);
        } else {
            return Err(ArgError::usage(
                cx.name,
                format!("{}: unexpected argument {arg}", cx.name),
            ));
        }
    }
    Ok(range)
}

impl Render<LogRange> for StorLog {
    fn render(&self, repl: &mut ReplState<'_>, range: LogRange) {
        let count = range.count.unwrap_or(DEFAULT_LOG_ENTRIES);
        let shown: Vec<&StorLogEntry> = match range.bounds.as_slice() {
            [] => {
                let skip = self.entries.len().saturating_sub(count as usize);
                self.entries[skip..].iter().collect()
            }
            [start] => self
                .entries
                .iter()
                .filter(|entry| entry.number >= *start)
                .take(count as usize)
                .collect(),
            [start, end, ..] => self
                .entries
                .iter()
                .filter(|entry| (*start..=*end).contains(&entry.number))
                .collect(),
        };
        print_log(&repl.ctx.target, self, &shown, None);
    }
}

/// Show the entries of a StorPort adapter's log that name an IRP.
///
/// Shows the entries of the adapter's internal log, as !storagekd.storloglist
/// shows them, whose request is the IRP you give, or that log it as a
/// parameter: when StorPort built, started, and saw the request completed.
// No SDK method: filter `storport_log(address).entries` by their `irp`
// (or `parameters`).
#[command(
    names = ["!storagekd.storlogirp"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn storlogirp(session: &Session, adapter: VirtAddr, irp: VirtAddr) -> Result<LogNaming> {
    log_naming(
        session,
        "!storagekd.storlogirp",
        adapter,
        LogObject::Irp(irp),
    )
}

/// Show the entries of a StorPort adapter's log that name an SRB.
///
/// Shows the entries of the adapter's internal log, as !storagekd.storloglist
/// shows them, whose request carries the SRB you give, or that log it as a
/// parameter.
// No SDK method: filter `storport_log(address).entries` by their `srb`
// (or `parameters`).
#[command(
    names = ["!storagekd.storlogsrb"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = none,
)]
fn storlogsrb(session: &Session, adapter: VirtAddr, srb: VirtAddr) -> Result<LogNaming> {
    log_naming(
        session,
        "!storagekd.storlogsrb",
        adapter,
        LogObject::Srb(srb),
    )
}

/// The IRP or SRB whose log entries `!storagekd.storlogirp` and
/// `!storagekd.storlogsrb` show.
#[derive(Debug, Clone, Copy)]
enum LogObject {
    Irp(VirtAddr),
    Srb(VirtAddr),
}

/// An adapter's log, and the IRP or SRB whose entries to show.
#[derive(Debug)]
struct LogNaming {
    log: StorLog,
    object: LogObject,
}

fn log_naming(
    session: &Session,
    name: &str,
    adapter: VirtAddr,
    object: LogObject,
) -> Result<LogNaming> {
    let log = session
        .target
        .storport_log(adapter)
        .map_err(|error| Error::DebugInfo(format!("{name}: {error}")))?;
    Ok(LogNaming { log, object })
}

impl Render for LogNaming {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        let (what, object) = match self.object {
            LogObject::Irp(irp) => ("IRP", irp),
            LogObject::Srb(srb) => ("SRB", srb),
        };
        let shown: Vec<&StorLogEntry> = self
            .log
            .entries
            .iter()
            .filter(|entry| match (log_request(entry), self.object) {
                (Some(request), LogObject::Irp(irp)) => request.irp == irp,
                (Some(request), LogObject::Srb(srb)) => request.srb == srb,
                (None, _) => entry.parameters.contains(&object.0),
            })
            .collect();
        print_log(&repl.ctx.target, &self.log, &shown, Some((what, object)));
    }
}

/// Decode an SRB: its function, status, command, address, data, and sense.
///
/// Decodes a STORAGE_REQUEST_BLOCK (an extended SRB, which StorPort, classpnp,
/// and miniports use on Windows 8 and later) or a legacy SCSI_REQUEST_BLOCK
/// with storport's public PDB: the SRB function, the SRB status with
/// QUEUE_FROZEN and AUTOSENSE_VALID, the SCSI status, the command its CDB holds
/// with its LBA and block count, the port, path, target, and LUN, the data
/// buffer and length, the IRP (OriginalRequest), the flags by SRB_FLAGS_ name,
/// the timeout, tag, and priority, the sense data when AUTOSENSE_VALID says it
/// is valid, the class, port, and miniport contexts, and an extended SRB's
/// extended data blocks. An address whose Function and Signature, or Length,
/// are not an SRB's is refused.
#[command(
    names = ["!storagekd.storsrb"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn srb(session: &Session, #[arg(name = "srb")] address: VirtAddr) -> Result<Srb> {
    session
        .target
        .decode_srb(address)
        .map_err(|error| Error::DebugInfo(format!("!storagekd.storsrb: {error}")))
}

impl Render for Srb {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_srb(self);
    }
}

/// List the storage class devices (disks, CD-ROMs), or show one with its
/// requests and errors.
///
/// Without an argument, walks classpnp!AllFdosList and shows each class device
/// that classpnp drives for disk.sys, cdrom.sys, and the other class drivers:
/// its FDO, class driver, device number, bus, vendor and product, and how many
/// of its transfer packets are in flight. With the address of an FDO, its
/// device extension, or its private data, shows the device: its identity and
/// serial number, bus, lower device and PDO, capacity and sector size, timeout
/// and retry limit, ErrorCount, each request in flight (a transfer packet that
/// is not on classpnp's free lists) with its IRP, the client's IRP, the SRB,
/// the command, and the retries, and the last 16 errors classpnp logged, each
/// with its age, address, command, SRB and SCSI status, and sense key and code.
/// The command needs the PDB for classpnp.sys.
#[command(
    names = ["!storagekd.storclass"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [class_devices, class_device],
)]
fn class_device_command(
    session: &Session,
    #[arg(name = "device")] address: Option<VirtAddr>,
) -> Result<ClassDeviceOrList> {
    match address {
        None => class_devices(session).map(ClassDeviceOrList::Devices),
        Some(address) => class_device(session, address).map(ClassDeviceOrList::Device),
    }
    .map_err(|error| Error::DebugInfo(format!("!storagekd.storclass: {error}")))
}

/// List the storage class devices on `classpnp!AllFdosList`
/// (`!storagekd.storclass`).
#[command(form_of = class_device_command, python = Inspect)]
fn class_devices(session: &Session) -> Result<ClassDevices> {
    session.target.classpnp_devices()
}

/// Read the class device whose FDO, device extension, or private data
/// is at `address`, with its requests in flight and its error log
/// (`!storagekd.storclass <address>`).
#[command(form_of = class_device_command, python = Inspect)]
fn class_device(session: &Session, address: VirtAddr) -> Result<ClassDeviceDetail> {
    session.target.classpnp_device(address)
}

/// What `!storagekd.storclass` shows: every class device, or one in
/// detail.
enum ClassDeviceOrList {
    Devices(ClassDevices),
    Device(ClassDeviceDetail),
}

impl Render for ClassDeviceOrList {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Devices(list) => print_class_devices(list),
            Self::Device(detail) => print_class_device(detail),
        }
    }
}

/// The log entries `!storagekd.storloglist` shows without a range.
const DEFAULT_LOG_ENTRIES: u64 = 50;

/// A request's command, from the operation code alone.
fn opcode_text(opcode: u8) -> String {
    scsi_command(&[opcode]).unwrap_or_else(|| "-".to_string())
}

/// What a log entry records: the request for an entry of storport's
/// request path, else its four parameters, a code address by symbol.
fn log_details(target: &Target, entry: &StorLogEntry) -> String {
    if let Some(request) = log_request(entry) {
        return format!(
            "IRP {} SRB {} {}, SRB status {}",
            ui::addr(request.irp.0),
            ui::addr(request.srb.0),
            opcode_text(request.opcode),
            srb_status_text(request.srb_status)
        );
    }
    entry
        .parameters
        .iter()
        .enumerate()
        .map(|(index, &value)| {
            let symbol = (value >> 48 == 0xffff)
                .then(|| target.format_code_address(target.kernel_dtb(), VirtAddr(value)))
                .flatten();
            match symbol {
                Some(symbol) => format!("P{} {value:#x} ({symbol})", index + 1),
                None => format!("P{} {value:#x}", index + 1),
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

fn print_log(
    target: &Target,
    log: &StorLog,
    shown: &[&StorLogEntry],
    naming: Option<(&str, VirtAddr)>,
) {
    outln!(
        "{} {}  {}  (ring {}, {} entries, newest {:#x})",
        ui::label("StorPort log of adapter"),
        ui::addr(log.adapter.0),
        log.driver_name,
        ui::addr_opt(log.ring),
        log.size,
        log.newest
    );
    if let Some((what, object)) = naming {
        outln!(
            "{} entries of {} that name {what} {}",
            shown.len(),
            log.entries.len(),
            ui::addr(object.0)
        );
    }
    if shown.is_empty() {
        outln!("{}", ui::muted("no entries"));
        return;
    }
    let mut builder = Builder::default();
    builder.push_record(["Entry", "Time", "Event", "Details"]);
    for entry in shown {
        let event = entry
            .event()
            .unwrap_or_else(|| format!("{:#x}", entry.event_value()));
        builder.push_record([
            format!("{:#x}", entry.number),
            filetime_to_iso_precise(entry.time).unwrap_or_else(|| format!("{:#x}", entry.time)),
            event,
            log_details(target, entry),
        ]);
    }
    print_padded_table(builder);
}

/// An address, or a muted `-` for a null pointer.
fn addr_or_none(value: VirtAddr) -> String {
    if value.is_zero() {
        ui::muted("-")
    } else {
        ui::addr(value.0)
    }
}

/// A command by name, with its LBA and length when it has them, and the
/// CDB's bytes.
fn cdb_text(cdb: &[u8]) -> String {
    let bytes = cdb
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    match scsi_command(cdb) {
        Some(command) => format!("{command}  {}", ui::muted(&format!("(CDB {bytes})"))),
        None => ui::muted("-"),
    }
}

fn print_srb(srb: &Srb) {
    heading(
        "SRB",
        format!(
            "{}  ({})",
            ui::addr(srb.address.0),
            if srb.extended {
                "STORAGE_REQUEST_BLOCK"
            } else {
                "SCSI_REQUEST_BLOCK"
            }
        ),
    );
    field(
        "function",
        match srb_function_name(srb.function) {
            Some(name) => format!("{name} ({:#x})", srb.function),
            None => format!("{:#x}", srb.function),
        },
    );
    let mut status = format!(
        "SRB {} ({:#04x})",
        srb_status_text(srb.srb_status),
        srb.srb_status
    );
    if let Some(scsi) = srb.scsi_status {
        status.push_str(&format!(", SCSI {}", scsi_status(scsi)));
    }
    field("status", status);
    if !srb.cdb.is_empty() {
        field("command", cdb_text(&srb.cdb));
    }
    if let (Some(path), Some(target), Some(lun)) = (srb.path, srb.target, srb.lun) {
        field(
            "address",
            match srb.port {
                Some(port) => format!("port {port}, path {path}, target {target}, LUN {lun}"),
                None => format!("path {path}, target {target}, LUN {lun}"),
            },
        );
    }
    field(
        "data",
        if srb.data_buffer.is_zero() {
            format!(
                "{:#x} bytes, DataBuffer {}",
                srb.data_transfer_length,
                ui::muted("-")
            )
        } else {
            format!(
                "{:#x} bytes at {}",
                srb.data_transfer_length,
                ui::addr(srb.data_buffer.0)
            )
        },
    );
    field("IRP", addr_or_none(srb.original_request));
    let flags = srb.flag_names();
    field(
        "flags",
        if flags.is_empty() {
            format!("{:#x}", srb.flags)
        } else {
            format!("{:#x} ({})", srb.flags, flags.join(" | "))
        },
    );
    field("timeout", format!("{} s", srb.timeout));
    if let (Some(tag), Some(priority)) = (srb.request_tag, srb.priority) {
        field("tag", format!("{tag:#x}, priority {priority}"));
    }
    field(
        "sense",
        if srb.sense_buffer.is_zero() {
            ui::muted("no buffer")
        } else {
            format!(
                "{} bytes at {}: {}",
                srb.sense_length,
                ui::addr(srb.sense_buffer.0),
                match &srb.sense {
                    Some(sense) => sense.clone(),
                    None => ui::muted("not valid (no AUTOSENSE_VALID)"),
                }
            )
        },
    );
    if let (Some(class), Some(port), Some(miniport)) =
        (srb.class_context, srb.port_context, srb.miniport_context)
    {
        field(
            "contexts",
            format!(
                "class {}, port {}, miniport {}",
                addr_or_none(class),
                addr_or_none(port),
                addr_or_none(miniport)
            ),
        );
    }
    field("next SRB", addr_or_none(srb.next_srb));
    if !srb.ex_data.is_empty() {
        print_section(&format!("extended data ({})", srb.ex_data.len()));
        let mut builder = Builder::default();
        builder.push_record(["Address", "Type", "Length"]);
        for data in &srb.ex_data {
            builder.push_record([
                ui::addr(data.address.0),
                data.kind.clone(),
                format!("{:#x}", data.length),
            ]);
        }
        print_padded_table(builder);
    }
}

fn class_product(device: &ClassDevice) -> String {
    [&device.vendor, &device.product, &device.revision]
        .iter()
        .filter_map(|part| part.as_deref())
        .collect::<Vec<_>>()
        .join(" ")
}

fn packets_text(device: &ClassDevice) -> String {
    format!(
        "{} in flight, {} free of {}",
        device.in_flight.len(),
        device.packets_free,
        device.packets_total
    )
}

fn print_class_devices(list: &ClassDevices) {
    let mut builder = Builder::default();
    builder.push_record([
        "FDO", "Driver", "Number", "Bus", "Product", "Packets", "Notes",
    ]);
    for device in &list.devices {
        let mut notes = Vec::new();
        if device.boot_device {
            notes.push("boot");
        }
        if device.removable {
            notes.push("removable");
        }
        builder.push_record([
            device.fdo.map_or_else(
                || ui::muted(&format!("private {:x}", device.private_data.0)),
                |fdo| ui::addr(fdo.0),
            ),
            device.driver.clone().unwrap_or_else(|| "-".into()),
            device
                .device_number
                .map(|number| number.to_string())
                .unwrap_or_else(|| "-".to_string()),
            device.bus_type.clone().unwrap_or_else(|| "-".to_string()),
            or_dash(class_product(device)),
            packets_text(device),
            or_dash(notes.join(" ")),
        ]);
    }
    if list.devices.is_empty() && list.unreadable.is_empty() {
        outln!("{}", ui::muted("no class devices on classpnp!AllFdosList"));
    } else {
        print_padded_table(builder);
    }
    for entry in &list.unreadable {
        outln!(
            "{}",
            ui::muted(&format!(
                "private data {}: {}",
                ui::addr(entry.private_data.0),
                entry.error
            ))
        );
    }
    stopped_line("device list", &list.stopped);
}

/// A byte count in the largest binary unit it reaches.
fn size_text(bytes: u64) -> String {
    for (unit, name) in [
        (1u64 << 40, "TiB"),
        (1 << 30, "GiB"),
        (1 << 20, "MiB"),
        (1 << 10, "KiB"),
    ] {
        if bytes >= unit {
            return format!("{:.1} {name}", bytes as f64 / unit as f64);
        }
    }
    format!("{bytes} bytes")
}

fn print_class_device(detail: &ClassDeviceDetail) {
    let device = &detail.device;
    heading(
        "class device",
        format!(
            "FDO {}  extension {}  private data {}",
            device
                .fdo
                .map_or_else(|| ui::muted("unknown"), |fdo| ui::addr(fdo.0)),
            device
                .extension
                .map_or_else(|| ui::muted("unknown"), |extension| ui::addr(extension.0)),
            ui::addr(device.private_data.0)
        ),
    );
    if let Some(driver) = &device.driver {
        field(
            "driver",
            match device.device_number {
                Some(number) => format!("{driver}, device number {number}"),
                None => driver.clone(),
            },
        );
    }
    let product = class_product(device);
    if !product.is_empty() {
        field(
            "device",
            match &device.serial {
                Some(serial) => format!("{product}  serial {serial}"),
                None => product,
            },
        );
    }
    field(
        "bus",
        format!(
            "{}{}{}",
            device.bus_type.as_deref().unwrap_or("-"),
            if device.removable { ", removable" } else { "" },
            if device.boot_device {
                ", boot device"
            } else {
                ""
            }
        ),
    );
    if device.extension.is_some() {
        field(
            "lower devices",
            format!(
                "next {}  PDO {}",
                addr_or_none(detail.lower_device),
                addr_or_none(detail.lower_pdo)
            ),
        );
        field(
            "capacity",
            format!(
                "{} ({:#x} bytes), {}-byte sectors",
                size_text(detail.length),
                detail.length,
                detail.bytes_per_sector
            ),
        );
        field(
            "timeout",
            format!("{} s, up to {} retries", detail.timeout, detail.max_retries),
        );
        field("error count", detail.error_count);
    } else {
        field(
            "note",
            ui::muted("no transfer packet names the FDO, so its extension is not read"),
        );
    }
    field("transfer packets", packets_text(device));
    if device.in_flight.is_empty() {
        outln!();
        outln!("{}", ui::muted("no requests in flight"));
    } else {
        print_section("requests in flight");
        let mut builder = Builder::default();
        builder.push_record([
            "Packet",
            "IRP",
            "Client IRP",
            "SRB",
            "Command",
            "Status",
            "Retries left",
        ]);
        for packet in &device.in_flight {
            let (command, status) = match &packet.request {
                Ok(srb) => (
                    scsi_command(&srb.cdb).unwrap_or_else(|| "-".to_string()),
                    srb_status_text(srb.srb_status),
                ),
                Err(error) => (ui::muted(error), "-".to_string()),
            };
            builder.push_record([
                ui::addr(packet.address.0),
                addr_or_none(packet.irp),
                addr_or_none(packet.original_irp),
                addr_or_none(packet.srb),
                command,
                status,
                format!(
                    "{}{}",
                    packet.retries_left,
                    if packet.timed_out { ", timed out" } else { "" }
                ),
            ]);
        }
        print_padded_table(builder);
    }
    for stopped in &device.packets_stopped {
        outln!("{}", ui::muted(&format!("({stopped})")));
    }
    // A table already ends with a blank line.
    let after_table = !device.in_flight.is_empty() && device.packets_stopped.is_empty();
    if detail.errors.is_empty() {
        if !after_table {
            outln!();
        }
        outln!("{}", ui::muted("no errors logged"));
        return;
    }
    let title = format!("error log ({}, oldest first)", detail.errors.len());
    if after_table {
        outln!("{}", ui::label(&title));
    } else {
        print_section(&title);
    }
    let mut builder = Builder::default();
    builder.push_record([
        "Age",
        "Port",
        "B/T/L",
        "Command",
        "SRB status",
        "SCSI status",
        "Sense",
        "Notes",
    ]);
    for error in &detail.errors {
        let mut notes = Vec::new();
        if error.paging {
            notes.push("paging");
        }
        if error.retried {
            notes.push("retried");
        }
        if error.unhandled {
            notes.push("unhandled");
        }
        let port = error
            .port
            .map_or_else(|| "-".to_string(), |port| port.to_string());
        builder.push_record([
            error.age_seconds.map_or_else(
                || format!("tick {:#x}", error.tick),
                |age| format!("{age:.1} s ago"),
            ),
            port,
            format!("{}/{}/{}", error.path, error.target, error.lun),
            scsi_command(&error.cdb).unwrap_or_else(|| "-".to_string()),
            srb_status_text(error.srb_status),
            scsi_status(error.scsi_status),
            error.sense.clone().unwrap_or_else(|| "-".to_string()),
            or_dash(notes.join(" ")),
        ]);
    }
    print_padded_table(builder);
}

/// A table cell, or `-` when it is empty.
fn or_dash(text: String) -> String {
    if text.is_empty() {
        "-".to_string()
    } else {
        text
    }
}

/// The first line of a detail view, naming the object.
fn heading(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(label));
}

/// A labeled line of a detail view, under its heading.
fn field(label: &str, value: impl Display) {
    outln!("  {}  {value}", ui::label(&format!("{label:<19}")));
}

/// An enum value by name without the prefix its type gives every name
/// (`DeviceStateWorking` reads `Working`), or its number.
fn enum_text(value: &StorEnumValue, prefix: &str) -> String {
    match &value.name {
        Some(name) => name.strip_prefix(prefix).unwrap_or(name).to_string(),
        None => format!("{:#x}", value.value),
    }
}

fn location_text(adapter: &StorAdapter) -> String {
    match adapter.pci {
        Some((bus, device, function)) => format!("PCI {bus:02x}:{device:02x}.{function:x}"),
        None if adapter.virtual_miniport => "virtual".to_string(),
        None => enum_text(&adapter.interface, ""),
    }
}

fn stopped_line(what: &str, stopped: &Option<String>) {
    if let Some(stopped) = stopped {
        outln!("{}", ui::muted(&format!("({what} stopped: {stopped})")));
    }
}

fn print_adapters(drivers: &StorDrivers) {
    outln!(
        "{} (RaidpPortData {})",
        ui::label("StorPort adapters"),
        ui::addr(drivers.port_data.0)
    );
    let mut builder = Builder::default();
    builder.push_record([
        "Driver", "Adapter", "FDO", "State", "Port", "Location", "Units", "I/O",
    ]);
    let mut problems = Vec::new();
    for driver in &drivers.drivers {
        if driver.adapters.is_empty() {
            problems.push(format!(
                "{}: no adapters (_RAID_DRIVER_EXTENSION {})",
                driver.name,
                ui::addr(driver.extension.0)
            ));
        }
        for StorAdapterEntry { extension, adapter } in &driver.adapters {
            match adapter {
                Ok(adapter) => builder.push_record([
                    driver.name.clone(),
                    ui::addr(adapter.extension.0),
                    ui::addr_opt(adapter.fdo),
                    enum_text(&adapter.state, "DeviceState"),
                    adapter.device_name.clone(),
                    location_text(adapter),
                    adapter.units.len().to_string(),
                    adapter.io(),
                ]),
                Err(why) => problems.push(format!(
                    "{}: adapter {}: {why}",
                    driver.name,
                    ui::addr(extension.0)
                )),
            }
        }
        if let Some(stopped) = &driver.stopped {
            problems.push(format!("{}: adapter list stopped: {stopped}", driver.name));
        }
    }
    if drivers.drivers.is_empty() {
        outln!("{}", ui::muted("no StorPort drivers"));
    } else {
        print_padded_table(builder);
    }
    for problem in problems {
        outln!("{}", ui::muted(&problem));
    }
    stopped_line("driver list", &drivers.stopped);
}

fn print_adapter(adapter: &StorAdapter) {
    heading(
        "adapter",
        format!(
            "{}  {}  {} (port {})",
            ui::addr(adapter.extension.0),
            adapter
                .miniport_name
                .as_deref()
                .unwrap_or(&adapter.driver_name),
            adapter.device_name,
            adapter.port_number
        ),
    );
    field(
        "driver",
        format!(
            "{}  DRIVER_OBJECT {}  _RAID_DRIVER_EXTENSION {}",
            adapter.driver_name,
            ui::addr_opt(adapter.driver_object),
            ui::addr_opt(adapter.driver)
        ),
    );
    field("state", enum_text(&adapter.state, "DeviceState"));
    field(
        "power",
        format!(
            "{}, system {}",
            enum_text(&adapter.device_power, "PowerDevice"),
            enum_text(&adapter.system_power, "PowerSystem")
        ),
    );
    field(
        "device objects",
        format!(
            "FDO {}  PDO {}  lower {}",
            ui::addr_opt(adapter.fdo),
            ui::addr_opt(adapter.pdo),
            ui::addr_opt(adapter.lower)
        ),
    );
    field("location", location_text(adapter));
    if let Some(id) = &adapter.adapter_id {
        field("adapter ID", id);
    }
    field(
        "miniport extension",
        if adapter.hw_device_extension.is_zero() {
            ui::muted("-")
        } else {
            format!(
                "{}{}",
                ui::addr(adapter.hw_device_extension.0),
                adapter
                    .hw_device_extension_size
                    .map(|size| format!("  ({size:#x} bytes)"))
                    .unwrap_or_default()
            )
        },
    );
    if let Some(size) = adapter.lu_extension_size {
        field("unit extension size", format!("{size:#x} bytes"));
    }
    field(
        "paths",
        format!(
            "paging {}, crash dump {}, hibernation {}",
            adapter.paging_paths, adapter.dump_paths, adapter.hiber_paths
        ),
    );
    field(
        "flags",
        if adapter.flags.is_empty() {
            ui::muted("-")
        } else {
            adapter.flags.join(" | ")
        },
    );
    field(
        "I/O",
        format!(
            "{}  (pause count {}, busy count {})",
            adapter.io(),
            adapter.pause_count,
            adapter.busy_count
        ),
    );
    for gateway in &adapter.gateways {
        field(
            "gateway",
            format!(
                "{}  outstanding {} of {}, waiting {}, busy {}, paused {}",
                ui::addr(gateway.address.0),
                gateway.outstanding,
                gateway.outstanding_max,
                gateway.pending,
                gateway.busy,
                gateway.paused
            ),
        );
    }
    if let Some(error) = &adapter.gateways_error {
        field("gateway", ui::muted(error));
    }
    print_units(&adapter.units);
    stopped_line("unit list", &adapter.units_stopped);
}

fn product_text(unit: &StorUnit) -> String {
    [unit.vendor.as_str(), unit.product.as_str()]
        .iter()
        .filter(|text| !text.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ")
}

fn print_units(units: &[StorUnitEntry]) {
    if units.is_empty() {
        outln!();
        outln!("{}", ui::muted("no units"));
        return;
    }
    print_section("units");
    let mut builder = Builder::default();
    builder.push_record(["B/T/L", "Unit", "PDO", "State", "Product", "I/O"]);
    let mut problems = Vec::new();
    for StorUnitEntry { extension, unit } in units {
        match unit {
            Ok(unit) => builder.push_record([
                format!("{}/{}/{}", unit.path, unit.target, unit.lun),
                ui::addr(unit.extension.0),
                ui::addr_opt(unit.device_object),
                enum_text(&unit.state, "DeviceState"),
                product_text(unit),
                unit.io(),
            ]),
            Err(why) => problems.push(format!("unit {}: {why}", ui::addr(extension.0))),
        }
    }
    print_padded_table(builder);
    for problem in problems {
        outln!("{}", ui::muted(&problem));
    }
}

fn print_unit(target: &Target, unit: &StorUnit) {
    heading(
        "unit",
        format!(
            "{}  {}  {}",
            ui::addr(unit.extension.0),
            product_text(unit),
            unit.revision
        ),
    );
    field(
        "address",
        format!(
            "bus {}, target {}, LUN {}",
            unit.path, unit.target, unit.lun
        ),
    );
    field("adapter", ui::addr_opt(unit.adapter));
    field("device object", ui::addr_opt(unit.device_object));
    field("state", enum_text(&unit.state, "DeviceState"));
    field("power", enum_text(&unit.device_power, "PowerDevice"));
    field(
        "miniport extension",
        if unit.lu_extension.is_zero() {
            ui::muted("-")
        } else {
            ui::addr(unit.lu_extension.0)
        },
    );
    field(
        "flags",
        if unit.flags.is_empty() {
            ui::muted("-")
        } else {
            unit.flags.join(" | ")
        },
    );
    let queue = &unit.queue;
    let mut held = Vec::new();
    for (set, name) in [
        (queue.frozen, "Frozen"),
        (queue.locked, "Locked"),
        (queue.untagged, "Untagged"),
        (queue.power_locked, "PowerLocked"),
    ] {
        if set {
            held.push(name);
        }
    }
    field(
        "queue",
        format!(
            "depth {} (unit maximum {}){}",
            queue.depth,
            unit.max_queue_depth,
            if held.is_empty() {
                String::new()
            } else {
                format!(", {}", held.join(" "))
            }
        ),
    );
    field(
        "counts",
        format!(
            "pause {}, busy {}, bypass {}, waiting {}, waiting to bypass {}",
            queue.pause_count,
            queue.busy_count,
            queue.bypass_count,
            queue.waiting,
            queue.bypass_waiting
        ),
    );
    field("I/O", unit.io());
    for stopped in &queue.waiting_stopped {
        outln!(
            "{}",
            ui::muted(&format!("(waiting count stopped: {stopped})"))
        );
    }
    if unit.requests.is_empty() {
        outln!();
        outln!("{}", ui::muted("no requests with the miniport"));
    } else {
        print_section("requests with the miniport");
        let mut builder = Builder::default();
        builder.push_record(["XRB", "IRP", "SRB", "CPU", "Command"]);
        for request in &unit.requests {
            let command = if request.srb.is_zero() {
                "-".to_string()
            } else {
                match target.decode_srb(request.srb) {
                    Ok(srb) => scsi_command(&srb.cdb).unwrap_or_else(|| {
                        srb_function_name(srb.function)
                            .map_or_else(|| format!("{:#x}", srb.function), str::to_string)
                    }),
                    Err(error) => ui::muted(&error.to_string()),
                }
            };
            builder.push_record([
                ui::addr(request.xrb.0),
                ui::addr_opt(request.irp),
                ui::addr_opt(request.srb),
                request.processor.to_string(),
                command,
            ]);
        }
        print_padded_table(builder);
    }
    for stopped in &unit.requests_stopped {
        outln!("{}", ui::muted(&format!("(pending queue: {stopped})")));
    }
}
