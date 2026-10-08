//! StorPort adapters and units (`!storagekd.storadapter`,
//! `!storagekd.storunit`).

use std::fmt::Display;

use tabled::builder::Builder;

use crate::error::Result;
use crate::repl::*;
use crate::target::storport::{
    AdapterEntry, StorAdapter, StorEnum, StorPortDrivers, StorUnit, UnitEntry, adapter_verdict,
    unit_verdict,
};
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
            Ok(unit) => print_unit(&unit),
            Err(error) => error!("!storagekd.storunit: {error}"),
        }
        Ok(())
    }
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

fn print_unit(unit: &StorUnit) {
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
        builder.push_record(["XRB", "IRP", "SRB", "CPU"]);
        for request in &unit.requests {
            builder.push_record([
                ui::addr(request.xrb.0),
                ui::addr_opt(request.irp),
                ui::addr_opt(request.srb),
                request.processor.to_string(),
            ]);
        }
        print_padded_table(builder);
    }
    for stopped in &unit.requests_stopped {
        outln!("{}", ui::muted(&format!("(pending queue: {stopped})")));
    }
    outln!();
}
