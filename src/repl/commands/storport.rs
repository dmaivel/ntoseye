//! StorPort adapters and units (`!storagekd.storadapter`,
//! `!storagekd.storunit`), StorPort's adapter log
//! (`!storagekd.storloglist`, `!storagekd.storlogirp`,
//! `!storagekd.storlogsrb`), SRBs (`!storagekd.storsrb`), and classpnp's
//! class devices (`!storagekd.storclass`).

use std::fmt::Display;

use tabled::builder::Builder;

use crate::error::Result;
use crate::repl::*;
use crate::target::Target;
use crate::target::classpnp::{ClassDevice, ClassDeviceDetail, ClassDeviceList};
use crate::target::etw::format_filetime_precise;
use crate::target::srb::{Srb, srb_flag_names, srb_function_name, srb_status_text};
use crate::target::storport::{
    AdapterEntry, StorAdapter, StorEnum, StorLog, StorLogEntry, StorPortDrivers, StorUnit,
    UnitEntry, adapter_verdict, log_request, unit_verdict,
};
use crate::target::virtio_request::{scsi_command, scsi_status};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_storagekd_storadapter;
    names: ["!storagekd.storadapter"],
    usage: "!storagekd.storadapter [<adapter>]",
    summary: "List the StorPort adapters, or show one adapter and its units.",
    details: "Without an argument, walks storport's driver list (storport!RaidpPortData) and each driver's adapters, and shows one line per adapter: the miniport driver, the adapter extension (_RAID_ADAPTER_EXTENSION), the FDO, the PnP state, the port device name, the PCI location, the number of units, and the I/O state. With the address of an adapter extension or of its FDO, shows the adapter: its driver, device objects, PnP and power state, the miniport's own device extension (the HwDeviceExtension that StorPort passes to every Hw routine, which you read with dt and the miniport's private PDB) and its size, the flags (_FLAGS, _FLAGS2), the paging and crash-dump path counts, each I/O gateway's outstanding and waiting requests, and each unit with its bus/target/LUN, PDO, state, inquiry product, and I/O state. The command needs storport's PDB. It stops each list at the head, a null or repeated link, or 256 drivers or adapters, and says why it stopped early. Adapters of storport's native NVMe path are listed but not decoded.",
    completion: Expression,
}

repl_command! {
    cmd_storagekd_storunit;
    names: ["!storagekd.storunit"],
    usage: "!storagekd.storunit <unit>",
    summary: "Show a StorPort logical unit, its queue, and the requests the miniport holds.",
    details: "Give the address of a unit extension (_RAID_UNIT_EXTENSION), as !storagekd.storadapter lists them, or of the unit's PDO. Shows the unit's bus/target/LUN, the inquiry vendor, product and revision, the adapter, the PnP and power state, the flags, the miniport's per-unit extension (StorPortGetLogicalUnit), and its device queue: the depth, whether it is frozen or locked, the pause and busy counts, and the requests waiting in storport. Then it lists each request that storport handed to the miniport and has not seen completed, from the unit's per-processor pending queues, with its _EXTENDED_REQUEST_BLOCK, IRP and SRB; use !irp on the IRP. It lists at most 256 requests and says why a list stopped early.",
    completion: Expression,
}

repl_command! {
    cmd_storagekd_storloglist;
    names: ["!storagekd.storloglist"],
    usage: "!storagekd.storloglist <adapter> [<start> [<end>]] [L <count>]",
    summary: "Show a StorPort adapter's internal log of requests, pauses, and resumes.",
    details: "Give the address of an adapter extension or of its FDO, as !storagekd.storadapter lists them. StorPort keeps a ring of its last 256 events for each adapter (RaidLogList): requests it builds, starts, and sees completed, pauses and resumes of the adapter and its units, busy and ready notifications, timeouts, resets, and PnP and power IRPs. Each entry shows its number, its time (UTC), the event, and for a request its IRP, SRB, command, and SRB status, or else the four parameters StorPort logged, a code address by symbol. Without a range, the command shows the last 50 entries; <start> shows entries from that number, <start> <end> that range, and L <count> how many.",
    completion: Expression,
}

repl_command! {
    cmd_storagekd_storlogirp;
    names: ["!storagekd.storlogirp"],
    usage: "!storagekd.storlogirp <adapter> <irp>",
    summary: "Show the entries of a StorPort adapter's log that name an IRP.",
    details: "Shows the entries of the adapter's internal log, as !storagekd.storloglist shows them, whose request is the IRP you give, or that log it as a parameter: when StorPort built, started, and saw the request completed.",
    completion: Expression,
}

repl_command! {
    cmd_storagekd_storlogsrb;
    names: ["!storagekd.storlogsrb"],
    usage: "!storagekd.storlogsrb <adapter> <srb>",
    summary: "Show the entries of a StorPort adapter's log that name an SRB.",
    details: "Shows the entries of the adapter's internal log, as !storagekd.storloglist shows them, whose request carries the SRB you give, or that log it as a parameter.",
    completion: Expression,
}

repl_command! {
    cmd_storagekd_storsrb;
    names: ["!storagekd.storsrb"],
    usage: "!storagekd.storsrb <srb>",
    summary: "Decode an SRB: its function, status, command, address, data, and sense.",
    details: "Decodes a STORAGE_REQUEST_BLOCK (an extended SRB, which StorPort, classpnp, and miniports use on Windows 8 and later) or a legacy SCSI_REQUEST_BLOCK with storport's public PDB: the SRB function, the SRB status with QUEUE_FROZEN and AUTOSENSE_VALID, the SCSI status, the command its CDB holds with its LBA and block count, the port, path, target, and LUN, the data buffer and length, the IRP (OriginalRequest), the flags by SRB_FLAGS_ name, the timeout, tag, and priority, the sense data when AUTOSENSE_VALID says it is valid, the class, port, and miniport contexts, and an extended SRB's extended data blocks. An address whose Function and Signature, or Length, are not an SRB's is refused.",
    completion: Expression,
}

repl_command! {
    cmd_storagekd_storclass;
    names: ["!storagekd.storclass"],
    usage: "!storagekd.storclass [<device>]",
    summary: "List the storage class devices (disks, CD-ROMs), or show one with its requests and errors.",
    details: "Without an argument, walks classpnp!AllFdosList and shows each class device that classpnp drives for disk.sys, cdrom.sys, and the other class drivers: its FDO, class driver, device number, bus, vendor and product, and how many of its transfer packets are in flight. With the address of an FDO, its device extension, or its private data, shows the device: its identity and serial number, bus, lower device and PDO, capacity and sector size, timeout and retry limit, ErrorCount, each request in flight (a transfer packet that is not on classpnp's free lists) with its IRP, the client's IRP, the SRB, the command, and the retries, and the last 16 errors classpnp logged, each with its age, address, command, SRB and SCSI status, and sense key and code. The command needs the PDB for classpnp.sys.",
    completion: Expression,
}

impl ReplState<'_> {
    fn cmd_storagekd_storadapter(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            match self.ctx.target.storport_drivers() {
                Ok(drivers) => print_adapters(&drivers),
                Err(error) => error!("!storagekd.storadapter: {error}"),
            }
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.storport_adapter(address) {
            Ok(adapter) => print_adapter(&adapter),
            Err(error) => error!("!storagekd.storadapter: {error}"),
        }
        Ok(())
    }

    fn cmd_storagekd_storunit(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.storport_unit(address) {
            Ok(unit) => print_unit(&self.ctx.target, &unit),
            Err(error) => error!("!storagekd.storunit: {error}"),
        }
        Ok(())
    }

    fn cmd_storagekd_storloglist(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        const USAGE: &str = "!storagekd.storloglist <adapter> [<start> [<end>]] [L <count>]";
        let Some(address) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        // The range: up to two entry numbers, and a count after `L`.
        let mut bounds = Vec::new();
        let mut count = None;
        let mut args = invocation.argv[1..].iter().map(|arg| arg.as_ref());
        while let Some(arg) = args.next() {
            let count_text = match arg {
                "L" | "l" => match args.next() {
                    Some(text) => Some(text),
                    None => {
                        error!("!storagekd.storloglist: L needs a count; usage: {USAGE}");
                        return Ok(());
                    }
                },
                _ => arg.strip_prefix(['L', 'l']).filter(|rest| !rest.is_empty()),
            };
            let text = count_text.unwrap_or(arg);
            let Some(value) = self.eval_or_report(text) else {
                return Ok(());
            };
            if count_text.is_some() {
                count = Some(value.0);
            } else if bounds.len() < 2 {
                bounds.push(value.0);
            } else {
                error!("!storagekd.storloglist: unexpected argument {arg}; usage: {USAGE}");
                return Ok(());
            }
        }
        let log = match self.ctx.target.storport_log(address) {
            Ok(log) => log,
            Err(error) => {
                error!("!storagekd.storloglist: {error}");
                return Ok(());
            }
        };
        let count = count.unwrap_or(DEFAULT_LOG_ENTRIES);
        let shown: Vec<&StorLogEntry> = match bounds.as_slice() {
            [] => {
                let skip = log.entries.len().saturating_sub(count as usize);
                log.entries[skip..].iter().collect()
            }
            [start] => log
                .entries
                .iter()
                .filter(|entry| entry.number >= *start)
                .take(count as usize)
                .collect(),
            [start, end, ..] => log
                .entries
                .iter()
                .filter(|entry| (*start..=*end).contains(&entry.number))
                .collect(),
        };
        print_log(&self.ctx.target, &log, &shown, None);
        Ok(())
    }

    fn cmd_storagekd_storlogirp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.storlog_naming(invocation, "IRP")
    }

    fn cmd_storagekd_storlogsrb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.storlog_naming(invocation, "SRB")
    }

    /// The adapter log's entries that name the IRP or SRB `what` the second
    /// argument gives.
    fn storlog_naming(&mut self, invocation: CommandInvocation<'_>, what: &str) -> Result<()> {
        let (Some(adapter), Some(object)) = (invocation.arg(0), invocation.arg(1)) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(adapter) = self.eval_or_report(adapter) else {
            return Ok(());
        };
        let Some(object) = self.eval_or_report(object) else {
            return Ok(());
        };
        let log = match self.ctx.target.storport_log(adapter) {
            Ok(log) => log,
            Err(error) => {
                error!("{}: {error}", invocation.name);
                return Ok(());
            }
        };
        let shown: Vec<&StorLogEntry> = log
            .entries
            .iter()
            .filter(|entry| match log_request(entry) {
                Some(request) if what == "IRP" => request.irp == object,
                Some(request) => request.srb == object,
                None => entry.parameters.contains(&object.0),
            })
            .collect();
        print_log(&self.ctx.target, &log, &shown, Some((what, object)));
        Ok(())
    }

    fn cmd_storagekd_storsrb(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.decode_srb(address) {
            Ok(srb) => print_srb(&srb),
            Err(error) => error!("!storagekd.storsrb: {error}"),
        }
        Ok(())
    }

    fn cmd_storagekd_storclass(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(address) = invocation.arg(0) else {
            match self.ctx.target.classpnp_devices() {
                Ok(list) => print_class_devices(&list),
                Err(error) => error!("!storagekd.storclass: {error}"),
            }
            return Ok(());
        };
        let Some(address) = self.eval_or_report(address) else {
            return Ok(());
        };
        match self.ctx.target.classpnp_device(address) {
            Ok(detail) => print_class_device(&detail),
            Err(error) => error!("!storagekd.storclass: {error}"),
        }
        Ok(())
    }
}

/// The log entries `!storagekd.storloglist` shows without a range.
const DEFAULT_LOG_ENTRIES: u64 = 50;

/// A request's command, from the operation code alone.
fn opcode_text(opcode: u8) -> String {
    scsi_command(&[opcode]).unwrap_or_default()
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
        outln!("{}\n", ui::muted("no entries"));
        return;
    }
    let mut builder = Builder::default();
    builder.push_record(["Entry", "Time (UTC)", "Event", "Details"]);
    for entry in shown {
        let event = match &entry.reason.name {
            Some(name) => name.strip_prefix("Log").unwrap_or(name).to_string(),
            None => format!("{:#x}", entry.reason.value),
        };
        builder.push_record([
            format!("{:#x}", entry.number),
            format_filetime_precise(entry.time).unwrap_or_else(|| format!("{:#x}", entry.time)),
            event,
            log_details(target, entry),
        ]);
    }
    print_padded_table(builder);
}

/// An address, or a muted `none` for a null pointer.
fn addr_or_none(value: VirtAddr) -> String {
    if value.is_zero() {
        ui::muted("none")
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
        None => ui::muted("none"),
    }
}

fn print_srb(srb: &Srb) {
    field(
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
        "Function",
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
    field("Status", status);
    if !srb.cdb.is_empty() {
        field("Command", cdb_text(&srb.cdb));
    }
    if let Some((path, target, lun)) = srb.path_target_lun {
        field(
            "Address",
            match srb.port {
                Some(port) => format!("port {port}, path {path}, target {target}, LUN {lun}"),
                None => format!("path {path}, target {target}, LUN {lun}"),
            },
        );
    }
    field(
        "Data",
        if srb.data_buffer.is_zero() {
            format!(
                "{:#x} bytes, {}",
                srb.data_transfer_length,
                ui::muted("DataBuffer null")
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
    let flags = srb_flag_names(srb.flags);
    field(
        "Flags",
        if flags.is_empty() {
            format!("{:#x}", srb.flags)
        } else {
            format!("{:#x} ({})", srb.flags, flags.join(" "))
        },
    );
    field("Timeout", format!("{} s", srb.timeout));
    if let (Some(tag), Some(priority)) = (srb.request_tag, srb.priority) {
        field("Tag", format!("{tag:#x}, priority {priority}"));
    }
    field(
        "Sense",
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
    if let Some([class, port, miniport]) = srb.contexts {
        field(
            "Contexts",
            format!(
                "class {}, port {}, miniport {}",
                addr_or_none(class),
                addr_or_none(port),
                addr_or_none(miniport)
            ),
        );
    }
    field("Next SRB", addr_or_none(srb.next_srb));
    if !srb.ex_data.is_empty() {
        outln!();
        outln!("{} ({})", ui::label("Extended data"), srb.ex_data.len());
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
    } else {
        outln!();
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
        device.packets.in_flight.len(),
        device.packets.free,
        device.packets.total
    )
}

fn print_class_devices(list: &ClassDeviceList) {
    let mut builder = Builder::default();
    builder.push_record([
        "FDO", "Driver", "Number", "Bus", "Product", "Packets", "Notes",
    ]);
    let mut problems = Vec::new();
    for entry in &list.devices {
        match entry {
            Ok(device) => {
                let mut notes = Vec::new();
                if device.boot_device {
                    notes.push("boot");
                }
                if device.removable {
                    notes.push("removable");
                }
                builder.push_record([
                    device.fdo.map_or_else(
                        || ui::muted(&format!("private {:x}", device.private.0)),
                        |fdo| ui::addr(fdo.0),
                    ),
                    device.driver.clone().unwrap_or_else(|| "?".into()),
                    device
                        .device_number
                        .map(|number| number.to_string())
                        .unwrap_or_default(),
                    device.bus_type.clone().unwrap_or_default(),
                    class_product(device),
                    packets_text(device),
                    notes.join(" "),
                ]);
            }
            Err((private, error)) => {
                problems.push(format!("private data {}: {error}", ui::addr(private.0)))
            }
        }
    }
    if list.devices.is_empty() {
        outln!(
            "{}\n",
            ui::muted("no class devices on classpnp!AllFdosList")
        );
    } else {
        print_padded_table(builder);
    }
    for problem in problems {
        outln!("{}", ui::muted(&problem));
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
    field(
        "Class device",
        format!(
            "FDO {}  extension {}  private data {}",
            device
                .fdo
                .map_or_else(|| ui::muted("unknown"), |fdo| ui::addr(fdo.0)),
            device
                .extension
                .map_or_else(|| ui::muted("unknown"), |extension| ui::addr(extension.0)),
            ui::addr(device.private.0)
        ),
    );
    if let Some(driver) = &device.driver {
        field(
            "Driver",
            match device.device_number {
                Some(number) => format!("{driver}, device number {number}"),
                None => driver.clone(),
            },
        );
    }
    let product = class_product(device);
    if !product.is_empty() {
        field(
            "Device",
            match &device.serial {
                Some(serial) => format!("{product}  serial {serial}"),
                None => product,
            },
        );
    }
    field(
        "Bus",
        format!(
            "{}{}{}",
            device.bus_type.as_deref().unwrap_or("?"),
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
            "Lower devices",
            format!(
                "next {}  PDO {}",
                addr_or_none(detail.lower_device),
                addr_or_none(detail.lower_pdo)
            ),
        );
        field(
            "Capacity",
            format!(
                "{} ({:#x} bytes), {}-byte sectors",
                size_text(detail.length),
                detail.length,
                detail.bytes_per_sector
            ),
        );
        field(
            "Timeout",
            format!("{} s, up to {} retries", detail.timeout, detail.max_retries),
        );
        field("Error count", detail.error_count);
    } else {
        field(
            "Note",
            ui::muted("no transfer packet names the FDO, so its extension is not read"),
        );
    }
    field("Transfer packets", packets_text(device));
    outln!();
    if device.packets.in_flight.is_empty() {
        outln!("{}", ui::muted("no requests in flight"));
    } else {
        outln!("{}", ui::label("Requests in flight"));
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
        for packet in &device.packets.in_flight {
            let (command, status) = match &packet.request {
                Ok(srb) => (
                    scsi_command(&srb.cdb).unwrap_or_default(),
                    srb_status_text(srb.srb_status),
                ),
                Err(error) => (ui::muted(error), String::new()),
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
                    packet.retries,
                    if packet.timed_out { ", timed out" } else { "" }
                ),
            ]);
        }
        print_padded_table(builder);
    }
    for stopped in &device.packets.stopped {
        outln!("{}", ui::muted(&format!("({stopped})")));
    }
    outln!();
    if detail.errors.is_empty() {
        outln!("{}\n", ui::muted("no errors logged"));
        return;
    }
    outln!(
        "{} ({}, oldest first)",
        ui::label("Error log"),
        detail.errors.len()
    );
    let mut builder = Builder::default();
    builder.push_record([
        "Age",
        "P/T/L",
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
        let (path, target, lun) = error.path_target_lun;
        // classpnp logs port -1 when it does not know the port.
        let port = if error.port == u32::MAX {
            "-".to_string()
        } else {
            error.port.to_string()
        };
        builder.push_record([
            error.age_seconds.map_or_else(
                || format!("tick {:#x}", error.tick),
                |age| format!("{age:.1} s ago"),
            ),
            format!("{port}/{path}/{target}/{lun}"),
            scsi_command(&error.cdb).unwrap_or_default(),
            srb_status_text(error.srb_status),
            scsi_status(error.scsi_status),
            error.sense.clone().unwrap_or_default(),
            notes.join(" "),
        ]);
    }
    print_padded_table(builder);
}

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(&format!("{label:<20}")));
}

/// An enum value by name without the prefix its type gives every name
/// (`DeviceStateWorking` reads `Working`), or its number.
fn enum_text(value: &StorEnum, prefix: &str) -> String {
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

fn print_adapters(drivers: &StorPortDrivers) {
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
        for AdapterEntry { extension, adapter } in &driver.adapters {
            match adapter {
                Ok(adapter) => builder.push_record([
                    driver.name.clone(),
                    ui::addr(adapter.extension.0),
                    ui::addr_opt(adapter.fdo),
                    enum_text(&adapter.state, "DeviceState"),
                    adapter.device_name.clone(),
                    location_text(adapter),
                    adapter.units.len().to_string(),
                    adapter_verdict(adapter),
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
        outln!("{}\n", ui::muted("no StorPort drivers"));
    } else {
        print_padded_table(builder);
    }
    for problem in problems {
        outln!("{}", ui::muted(&problem));
    }
    stopped_line("driver list", &drivers.stopped);
}

fn print_adapter(adapter: &StorAdapter) {
    field(
        "Adapter",
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
        "Driver",
        format!(
            "{}  DRIVER_OBJECT {}  _RAID_DRIVER_EXTENSION {}",
            adapter.driver_name,
            ui::addr_opt(adapter.driver_object),
            ui::addr_opt(adapter.driver)
        ),
    );
    field("State", enum_text(&adapter.state, "DeviceState"));
    field(
        "Power",
        format!(
            "{}, system {}",
            enum_text(&adapter.device_power, "PowerDevice"),
            enum_text(&adapter.system_power, "PowerSystem")
        ),
    );
    field(
        "Device objects",
        format!(
            "FDO {}  PDO {}  lower {}",
            ui::addr_opt(adapter.fdo),
            ui::addr_opt(adapter.pdo),
            ui::addr_opt(adapter.lower)
        ),
    );
    field("Location", location_text(adapter));
    if let Some(id) = &adapter.adapter_id {
        field("Adapter ID", id);
    }
    field(
        "Miniport extension",
        if adapter.hw_device_extension.is_zero() {
            ui::muted("none")
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
        field("Unit extension size", format!("{size:#x} bytes"));
    }
    field(
        "Paths",
        format!(
            "paging {}, crash dump {}, hibernation {}",
            adapter.paging_paths, adapter.dump_paths, adapter.hiber_paths
        ),
    );
    field(
        "Flags",
        if adapter.flags.is_empty() {
            ui::muted("none")
        } else {
            adapter.flags.join(" ")
        },
    );
    field(
        "I/O",
        format!(
            "{}  (pause count {}, busy count {})",
            adapter_verdict(adapter),
            adapter.pause_count,
            adapter.busy_count
        ),
    );
    for gateway in &adapter.gateways {
        field(
            "Gateway",
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
        field("Gateway", ui::muted(error));
    }
    outln!();
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

fn print_units(units: &[UnitEntry]) {
    if units.is_empty() {
        outln!("{}\n", ui::muted("no units"));
        return;
    }
    outln!("{}", ui::label("Units"));
    let mut builder = Builder::default();
    builder.push_record(["B/T/L", "Unit", "PDO", "State", "Product", "I/O"]);
    let mut problems = Vec::new();
    for UnitEntry { extension, unit } in units {
        match unit {
            Ok(unit) => builder.push_record([
                format!(
                    "{}/{}/{}",
                    unit.address.path, unit.address.target, unit.address.lun
                ),
                ui::addr(unit.extension.0),
                ui::addr_opt(unit.device_object),
                enum_text(&unit.state, "DeviceState"),
                product_text(unit),
                unit_verdict(&unit.queue, unit.requests.len()),
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
    field(
        "Unit",
        format!(
            "{}  {}  {}",
            ui::addr(unit.extension.0),
            product_text(unit),
            unit.revision
        ),
    );
    field(
        "Address",
        format!(
            "bus {}, target {}, LUN {}",
            unit.address.path, unit.address.target, unit.address.lun
        ),
    );
    field("Adapter", ui::addr_opt(unit.adapter));
    field("Device object", ui::addr_opt(unit.device_object));
    field("State", enum_text(&unit.state, "DeviceState"));
    field("Power", enum_text(&unit.device_power, "PowerDevice"));
    field(
        "Miniport extension",
        if unit.lu_extension.is_zero() {
            ui::muted("none")
        } else {
            ui::addr(unit.lu_extension.0)
        },
    );
    field(
        "Flags",
        if unit.flags.is_empty() {
            ui::muted("none")
        } else {
            unit.flags.join(" ")
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
        "Queue",
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
        "Counts",
        format!(
            "pause {}, busy {}, bypass {}, waiting {}, waiting to bypass {}",
            queue.pause_count,
            queue.busy_count,
            queue.bypass_count,
            queue.waiting,
            queue.bypass_waiting
        ),
    );
    field("I/O", unit_verdict(queue, unit.requests.len()));
    for stopped in &queue.waiting_stopped {
        outln!(
            "{}",
            ui::muted(&format!("(waiting count stopped: {stopped})"))
        );
    }
    outln!();
    if unit.requests.is_empty() {
        outln!("{}", ui::muted("no requests with the miniport"));
    } else {
        outln!("{}", ui::label("Requests with the miniport"));
        let mut builder = Builder::default();
        builder.push_record(["XRB", "IRP", "SRB", "CPU", "Command"]);
        for request in &unit.requests {
            let command = if request.srb.is_zero() {
                String::new()
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
    outln!();
}
