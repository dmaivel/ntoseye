//! KMDF (`!wdfkd.*`): client drivers, handles, devices, queues, and
//! In-Flight Recorder logs.

use std::fmt::Display;

use tabled::builder::Builder;

use crate::error::Result;
use crate::repl::*;
use crate::target::etw::{format_filetime_precise, format_guid};
use crate::target::wdf::{
    IfrEnd, WdfClient, WdfDeviceDetail, WdfDriverInfo, WdfDumpDriver, WdfEnumValue, WdfLoader,
    WdfLogDump, WdfObject, WdfObjectRef, WdfQueueDetail, WdfRequestList,
};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_wdfkd_wdfldr();
    names: ["!wdfkd.wdfldr"],
    usage: "!wdfkd.wdfldr",
    summary: "List the KMDF client drivers.",
    details: "Walks the list at Wdf01000!FxLibraryGlobals.FxDriverGlobalsList. For each client driver, it shows the name, the KMDF version that the driver bound to (WdfBindInfo), the _FX_DRIVER_GLOBALS, the WDFDRIVER handle, the DRIVER_OBJECT, and whether the driver has an In-Flight Recorder log. The command needs the PDB for Wdf01000. The walk continues only while the Blink of each entry points back to the entry before it. A client has an empty DriverName if it bound to KMDF but did not create an FxDriver, and the command then lists the client by the name of its DRIVER_OBJECT, which you also use with !wdfkd.wdfdriverinfo and !wdfkd.wdflogdump. When a client name is not printable, or the FxDriver of a client fails the checks of its type, owner, or handle, the command lists the client with the problem.",
}

repl_command! {
    cmd_wdfkd_wdfdriverinfo;
    names: ["!wdfkd.wdfdriverinfo"],
    usage: "!wdfkd.wdfdriverinfo <driver-name>",
    summary: "Show a KMDF client driver and its WDF devices.",
    details: "Give the driver name as !wdfkd.wdfldr lists it. The name is not case-sensitive, and `.sys` is optional. The command shows the DRIVER_OBJECT, the FxDriver, the WDFDRIVER handle, the _FX_DRIVER_GLOBALS, the KMDF version, the registry path, and the image. Then it shows each device object on the DeviceObject/NextDevice chain of the driver object, with the related WDFDEVICE and its kind and PnP state. A device object links to its WDFDEVICE through its DeviceExtension, which KMDF sets to point to the first context of the device. The command checks the context header, the type and owner of the object, and the device object of the FxDevice, and if a check fails, it lists the device object with the reason.",
    completion: Driver,
}

repl_command! {
    cmd_wdfkd_wdfhandle;
    names: ["!wdfkd.wdfhandle"],
    usage: "!wdfkd.wdfhandle <handle>",
    summary: "Decode a WDF handle and show its object.",
    details: "A handle is the address of its object, XORed with ~7. An offset handle has bit 0 set and points to a WDFOBJECT_OFFSET value inside the object, which the command subtracts from the address that the handle points to. The command shows the FxObject, its type (FX_OBJECT_TYPES), size, reference count, state (FxObjectState), flags, owning driver, and parent, and each context with its type name, size, and address. It shows an error if the value does not decode to a kernel address, or if the type, state, size, context header, or owning driver of the object is not valid.",
    completion: Expression,
}

repl_command! {
    cmd_wdfkd_wdfdevice;
    names: ["!wdfkd.wdfdevice"],
    usage: "!wdfkd.wdfdevice <WDFDEVICE>",
    summary: "Show a WDFDEVICE and its device objects, state machines, and queues.",
    details: "Shows the kind of the device (FDO, filter, PDO, or control), its WDM device object, the device object that it is attached to, and the PDO of the stack. It also shows the current states of the PnP, power, and power policy state machines (_WDF_DEVICE_PNP_STATE, _WDF_DEVICE_POWER_STATE, _WDF_DEVICE_POWER_POLICY_STATE), and the device and system power states. For a PDO, it shows the parent device, and for an FDO, the child lists. For each queue of the I/O package, it shows the dispatch type, the power management, and the counts of pending and driver-owned requests, and it marks the default queue.",
    completion: Expression,
}

repl_command! {
    cmd_wdfkd_wdfqueue;
    names: ["!wdfkd.wdfqueue"],
    usage: "!wdfkd.wdfqueue <WDFQUEUE>",
    summary: "Show a WDFQUEUE and its configuration, state, callbacks, and requests.",
    details: "Shows the dispatch type of the queue, the state bits (_FX_IO_QUEUE_STATE), the power state, and the power management. It also shows the execution level, the synchronization scope, the request counts, and the Evt callbacks that the driver set. Then it shows the requests on three lists: the requests that wait in the queue, the requests that the driver marked cancelable, and the requests presented to the driver. For each request, it shows the WDFREQUEST handle, the FxRequest, and the IRP. If a request is not valid, the command stops that list at the request and shows the reason.",
    completion: Expression,
}

repl_command! {
    cmd_wdfkd_wdflogdump;
    names: ["!wdfkd.wdflogdump"],
    usage: "!wdfkd.wdflogdump <driver-name>",
    summary: "Show the In-Flight Recorder log of a KMDF driver, oldest record first.",
    details: "Reads the IFR log of the driver (_FX_DRIVER_GLOBALS.WdfLogHeader). The command walks the records back from the newest record along PrevOffset, and stops at the first record written or at records that newer records overwrote. For each record, it shows the sequence number, the UTC time (only when the log keeps timestamps), the function, and the message. The command formats the message from the trace message format (TMF) annotations in the PDB for Wdf01000. For a record with a message that no loaded PDB declares, or with arguments that do not fit the message, it shows the message GUID, the message number, and the argument bytes. The command checks the header (its GUID, base, and size) and each record (signature, length, position, and sequence), and the walk stops at the first item that fails a check, with the reason.",
    completion: Driver,
}

repl_command! {
    cmd_wdfkd_wdfcrashdump;
    names: ["!wdfkd.wdfcrashdump"],
    usage: "!wdfkd.wdfcrashdump [log | loader]",
    summary: "Show the KMDF data in a crash dump: one driver's In-Flight Recorder log, or the client drivers.",
    details: "When Windows writes a crash dump, Wdf01000 copies one client driver's In-Flight Recorder log into the dump's tagged data (WdfDumpGuid): the log of the driver whose code the bugcheck parameters point to, or of a driver set to keep its log in minidumps, or else of the last KMDF driver that ran on the processor that crashed. A minidump has no other copy of the log. Without an argument or with log, the command shows that log, oldest record first, as !wdfkd.wdflogdump shows a log in memory. Unlike WinDbg, it shows a log's only record once, and it keeps the oldest record that survives in a log that has wrapped. With loader, it lists the client drivers that Wdf01000 recorded (WdfDumpGuid2), with the KMDF version each bound to and its _FX_DRIVER_GLOBALS; the first entry is the framework itself. The command needs the PDB for Wdf01000.",
    completion: None,
}

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(&format!("{label:<22}")));
}

fn enum_text(value: &WdfEnumValue) -> String {
    match &value.name {
        Some(name) => format!("{name} ({:#x})", value.value),
        None => format!("{:#x}", value.value),
    }
}

fn object_ref_text(object: &Option<WdfObjectRef>) -> String {
    let Some(object) = object else {
        return ui::muted("none");
    };
    let mut text = ui::addr(object.address.0);
    if let Some(handle) = object.handle {
        text.push_str(&format!("  handle {}", ui::addr(handle)));
    }
    if let Some(type_name) = &object.type_name {
        text.push_str(&format!("  {type_name}"));
    }
    text
}

fn handle_text(handle: Option<u64>) -> String {
    handle.map_or_else(|| ui::muted("none"), ui::addr)
}

fn version_text(client: &WdfClient) -> String {
    client.version.map_or_else(
        || ui::muted("unknown"),
        |version| {
            format!(
                "v{}.{} (build {})",
                version.major, version.minor, version.build
            )
        },
    )
}

fn print_stopped(indent: &str, what: &str, stopped: &Option<String>) {
    if let Some(stopped) = stopped {
        outln!("{indent}({what} stopped: {stopped})");
    }
}

/// A client's name, or a muted `(unnamed)`.
fn name_text(name: &Option<String>) -> String {
    name.clone().unwrap_or_else(|| ui::muted("(unnamed)"))
}

/// A client's name, or, without one, its driver object's (`\Driver\kdnic`).
fn client_name_text(client: &WdfClient) -> String {
    match (&client.name, &client.driver_object_name) {
        (Some(name), _) => name.clone(),
        (None, Some(object)) => ui::muted(object),
        (None, None) => ui::muted("(unnamed)"),
    }
}

fn print_loader(loader: &WdfLoader) {
    outln!(
        "{} (FxLibraryGlobals {})",
        ui::label("KMDF client drivers"),
        ui::addr(loader.library_globals.0)
    );
    let mut builder = Builder::default();
    builder.push_record([
        "Driver",
        "KMDF",
        "_FX_DRIVER_GLOBALS",
        "WDFDRIVER",
        "DRIVER_OBJECT",
        "IFR log",
    ]);
    for client in &loader.clients {
        builder.push_record([
            client_name_text(client),
            client.version.map_or_else(
                || "?".to_string(),
                |version| format!("v{}.{}", version.major, version.minor),
            ),
            ui::addr(client.globals.0),
            handle_text(client.wdf_driver),
            ui::addr_opt(client.driver_object),
            if client.log_header.is_some() {
                "yes"
            } else {
                "no"
            }
            .to_string(),
        ]);
    }
    print_padded_table(builder);
    for client in loader
        .clients
        .iter()
        .filter(|client| !client.problems.is_empty())
    {
        outln!(
            "{} {}: {}",
            ui::muted("_FX_DRIVER_GLOBALS"),
            ui::addr(client.globals.0),
            client.problems.join("; ")
        );
    }
    print_stopped("", "client list", &loader.stopped);
}

fn print_client(client: &WdfClient) {
    field("Driver", name_text(&client.name));
    field("KMDF version", version_text(client));
    field("_FX_DRIVER_GLOBALS", ui::addr(client.globals.0));
    field(
        "DRIVER_OBJECT",
        format!(
            "{}  {}",
            ui::addr(client.driver_object.0),
            client.driver_object_name.as_deref().unwrap_or_default()
        ),
    );
    field(
        "FxDriver",
        client
            .driver
            .map_or_else(|| ui::muted("none"), |driver| ui::addr(driver.0)),
    );
    field("WDFDRIVER", handle_text(client.wdf_driver));
    if let Some(path) = &client.registry_path {
        field("Registry path", path);
    }
    field(
        "Image",
        format!(
            "{}  size {:#x}",
            ui::addr(client.image_base.0),
            client.image_size
        ),
    );
    field(
        "IFR log",
        client
            .log_header
            .map_or_else(|| ui::muted("none"), |header| ui::addr(header.0)),
    );
    field("Verifier", if client.verifier_on { "on" } else { "off" });
    for problem in &client.problems {
        field("Problem", problem);
    }
}

fn print_driver_info(info: &WdfDriverInfo) {
    print_client(&info.client);
    outln!();
    outln!("{}", ui::label("Devices"));
    let mut builder = Builder::default();
    builder.push_record(["DEVICE_OBJECT", "WDFDEVICE", "Kind", "PnP state"]);
    for device in &info.devices {
        match &device.unlinked {
            None => builder.push_record([
                ui::addr(device.device_object.0),
                handle_text(device.handle),
                device.kind.unwrap_or("?").to_string(),
                device.pnp_state.as_ref().map(enum_text).unwrap_or_default(),
            ]),
            Some(why) => builder.push_record([
                ui::addr(device.device_object.0),
                ui::muted("none"),
                String::new(),
                ui::muted(&format!("not a WDFDEVICE of this driver: {why}")),
            ]),
        }
    }
    print_padded_table(builder);
    print_stopped("", "device list", &info.devices_stopped);
}

fn print_handle(object: &WdfObject) {
    field("Handle", ui::addr(object.handle));
    let mut address = ui::addr(object.address.0);
    if let Some(offset) = object.offset {
        address.push_str(&format!("  (offset handle, WDFOBJECT_OFFSET {offset:#x})"));
    }
    field("FxObject", address);
    field(
        "Type",
        format!("{} ({:#x})", object.type_name, object.type_value),
    );
    field(
        "Driver",
        format!(
            "{}  (globals {})",
            name_text(&object.driver),
            ui::addr(object.globals.0)
        ),
    );
    field("Object size", format!("{:#x}", object.object_size));
    field("Reference count", object.refcount);
    field("State", enum_text(&object.state));
    field(
        "Flags",
        format!("{:#x}  {}", object.flags, object.flag_names.join(" ")),
    );
    field("Parent", object_ref_text(&object.parent));
    if object.contexts.is_empty() {
        field("Contexts", ui::muted("none"));
    }
    for context in &object.contexts {
        let name = context.name.as_deref().unwrap_or("(no type)");
        let size = context
            .size
            .map(|size| format!("  size {size:#x}"))
            .unwrap_or_default();
        field(
            "Context",
            format!(
                "{} {}{size}  (header {})",
                ui::addr(context.context.0),
                name,
                ui::addr(context.header.0)
            ),
        );
    }
    print_stopped("", "context chain", &object.contexts_stopped);
}

fn print_device(device: &WdfDeviceDetail) {
    field("WDFDEVICE", ui::addr(device.handle));
    field("FxDevice", ui::addr(device.address.0));
    field(
        "Driver",
        format!(
            "{}  (globals {})",
            name_text(&device.driver),
            ui::addr(device.globals.0)
        ),
    );
    field("Kind", device.kind);
    if let Some(name) = &device.device_name {
        field("Name", name);
    }
    field("Device object", ui::addr_opt(device.device_object));
    field("Attached to", ui::addr_opt(device.attached_device));
    field("PDO", ui::addr_opt(device.physical_device));
    if device.parent.is_some() {
        field("Parent", object_ref_text(&device.parent));
    }
    field("PnP state", enum_text(&device.pnp_state));
    field("Power state", enum_text(&device.power_state));
    field("Power policy state", enum_text(&device.power_policy_state));
    if let Some(state) = &device.device_power_state {
        field("Device power state", enum_text(state));
    }
    if let Some(state) = &device.system_power_state {
        field("System power state", enum_text(state));
    }
    field("FxPkgPnp", ui::addr_opt(device.pkg_pnp));
    field("FxPkgIo", ui::addr_opt(device.pkg_io));
    if device.default_child_list.is_some() || device.static_child_list.is_some() {
        field("Default child list", handle_text(device.default_child_list));
        field("Static child list", handle_text(device.static_child_list));
    }
    outln!();
    outln!("{}", ui::label("Queues"));
    let mut builder = Builder::default();
    builder.push_record([
        "WDFQUEUE",
        "FxIoQueue",
        "Dispatch",
        "Power managed",
        "Pending",
        "Driver owned",
        "",
    ]);
    for queue in &device.queues {
        builder.push_record([
            ui::addr(queue.handle),
            ui::addr(queue.address.0),
            queue.dispatch_type.name.as_deref().map_or_else(
                || format!("{:#x}", queue.dispatch_type.value),
                |name| name.trim_start_matches("WdfIoQueueDispatch").to_string(),
            ),
            if queue.power_managed { "yes" } else { "no" }.to_string(),
            queue.pending.to_string(),
            queue.driver_owned.to_string(),
            if queue.is_default { "default" } else { "" }.to_string(),
        ]);
    }
    print_padded_table(builder);
    print_stopped("", "queue list", &device.queues_stopped);
}

fn print_requests(title: &str, list: &WdfRequestList) {
    outln!("{} ({})", ui::label(title), list.requests.len());
    for request in &list.requests {
        outln!(
            "   WDFREQUEST {}  FxRequest {}  IRP {}",
            ui::addr(request.handle),
            ui::addr(request.address.0),
            ui::addr_opt(request.irp)
        );
    }
    print_stopped("   ", "list", &list.stopped);
}

fn print_queue(queue: &WdfQueueDetail) {
    field("WDFQUEUE", ui::addr(queue.handle));
    field("FxIoQueue", ui::addr(queue.address.0));
    field("Driver", name_text(&queue.driver));
    field("Device", object_ref_text(&queue.device));
    field("Dispatch type", enum_text(&queue.dispatch_type));
    field(
        "State",
        format!("{:#x}  {}", queue.state, queue.state_names.join(" ")),
    );
    field("Power state", enum_text(&queue.power_state));
    field("Power managed", queue.power_managed);
    field("Zero-length requests", queue.allow_zero_length_requests);
    if queue.deleted {
        field("Deleted", true);
    }
    field("Execution level", enum_text(&queue.execution_level));
    field("Synchronization", enum_text(&queue.synchronization_scope));
    field("Max parallel", queue.max_parallel_requests);
    field("Pending", queue.pending_count);
    field("Driver cancelable", queue.driver_cancelable_count);
    field("Driver owned", queue.driver_owned_count);
    field("Two-phase completions", queue.two_phase_completions);
    for callback in &queue.callbacks {
        let symbol = callback
            .symbol
            .as_deref()
            .map(ui::symbol)
            .unwrap_or_default();
        field(
            callback.name,
            format!("{}  {symbol}", ui::addr(callback.address.0)),
        );
    }
    outln!();
    print_requests("Pending requests", &queue.pending);
    print_requests("Driver cancelable requests", &queue.driver_cancelable);
    print_requests("Driver owned requests", &queue.driver_owned);
}

fn print_log(log: &WdfLogDump) {
    outln!(
        "{} {} (IFR header {}, {:#x} bytes, sequence {}{})",
        ui::label("IFR log of"),
        log.driver,
        ui::addr(log.header.0),
        log.size,
        log.sequence,
        if log.use_timestamps {
            ", timestamps"
        } else {
            ""
        }
    );
    for entry in &log.entries {
        let record = &entry.record;
        let time = record
            .timestamp
            .and_then(format_filetime_precise)
            .map(|time| format!("{time} "))
            .unwrap_or_default();
        match &entry.text {
            Ok(text) => {
                let function = entry
                    .message
                    .as_ref()
                    .and_then(|message| message.function.as_deref())
                    .map(|function| format!("{function} - "))
                    .unwrap_or_default();
                outln!("{}: {time}{function}{text}", record.sequence);
            }
            Err(why) => {
                let args: String = record.args.iter().map(|b| format!("{b:02x}")).collect();
                outln!(
                    "{}: {time}{} #{} {}  {}",
                    record.sequence,
                    format_guid(&record.message_guid),
                    record.message_number,
                    ui::muted(&format!("({why})")),
                    args
                );
            }
        }
    }
    match &log.end {
        IfrEnd::Corrupt(why) => error!("{why}"),
        end => outln!(
            "{}",
            ui::muted(&format!(
                "({} records; {})",
                log.entries.len(),
                end.describe()
            ))
        ),
    }
    outln!();
}

impl ReplState<'_> {
    /// Evaluate a handle argument; a failure is reported.
    fn wdf_handle_arg(&self, invocation: &CommandInvocation<'_>, command: &str) -> Option<u64> {
        let Some(text) = invocation.arg(0) else {
            outln!("{}\n", command_help(command));
            return None;
        };
        self.eval_or_report(text).map(|value: VirtAddr| value.0)
    }

    fn cmd_wdfkd_wdfldr(&mut self) -> Result<()> {
        match self.ctx.target.wdf_loader() {
            Ok(loader) => print_loader(&loader),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_wdfkd_wdfdriverinfo(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let name = require_arg!(invocation, 0, "!wdfkd.wdfdriverinfo");
        match self.ctx.target.wdf_driver_info(name) {
            Ok(info) => print_driver_info(&info),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_wdfkd_wdfhandle(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(handle) = self.wdf_handle_arg(&invocation, "!wdfkd.wdfhandle") else {
            return Ok(());
        };
        match self.ctx.target.wdf_handle(handle) {
            Ok(object) => print_handle(&object),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_wdfkd_wdfdevice(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(handle) = self.wdf_handle_arg(&invocation, "!wdfkd.wdfdevice") else {
            return Ok(());
        };
        match self.ctx.target.wdf_device(handle) {
            Ok(device) => print_device(&device),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_wdfkd_wdfqueue(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(handle) = self.wdf_handle_arg(&invocation, "!wdfkd.wdfqueue") else {
            return Ok(());
        };
        match self.ctx.target.wdf_queue(handle) {
            Ok(queue) => print_queue(&queue),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_wdfkd_wdflogdump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let name = require_arg!(invocation, 0, "!wdfkd.wdflogdump");
        match self.ctx.target.wdf_log_dump(name) {
            Ok(log) => print_log(&log),
            Err(error) => error!("{error}"),
        }
        Ok(())
    }

    fn cmd_wdfkd_wdfcrashdump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        match invocation.arg(0).map(str::to_ascii_lowercase).as_deref() {
            None | Some("log") => match self.ctx.target.wdf_crash_log() {
                Ok(log) => print_log(&log),
                Err(error) => error!("{error}"),
            },
            Some("loader") => match self.ctx.target.wdf_crash_drivers() {
                Ok(drivers) => print_dump_drivers(&drivers),
                Err(error) => error!("{error}"),
            },
            Some(other) => error!("!wdfkd.wdfcrashdump: '{other}' is neither log nor loader"),
        }
        Ok(())
    }
}

fn print_dump_drivers(drivers: &[WdfDumpDriver]) {
    let mut builder = Builder::default();
    builder.push_record(["ImageName", "Version", "FxGlobals"]);
    for driver in drivers {
        builder.push_record([
            driver
                .name
                .clone()
                .unwrap_or_else(|| "<missing name>".into()),
            format!("v{}.{}({:04})", driver.major, driver.minor, driver.build),
            if driver.globals.0 == 0 {
                String::new()
            } else {
                ui::addr(driver.globals.0).to_string()
            },
        ]);
    }
    print_padded_table(builder);
    outln!("{}", ui::muted(&format!("({} drivers)", drivers.len())));
    outln!();
}
