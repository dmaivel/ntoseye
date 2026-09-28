//! KMDF (`!wdfkd.*`): client drivers, handles, devices, queues, and
//! In-Flight Recorder logs.

use std::fmt::Display;

use tabled::builder::Builder;

use crate::error::Result;
use crate::repl::*;
use crate::target::etw::{format_filetime_precise, format_guid};
use crate::target::wdf::{
    IfrEnd, WdfClient, WdfDeviceDetail, WdfDriverInfo, WdfEnumValue, WdfLoader, WdfLogDump,
    WdfObject, WdfObjectRef, WdfQueueDetail, WdfRequestList,
};
use crate::types::VirtAddr;
use crate::ui;

repl_command! {
    cmd_wdfkd_wdfldr();
    names: ["!wdfkd.wdfldr"],
    usage: "!wdfkd.wdfldr",
    summary: "List the KMDF client drivers.",
    details: "Walks Wdf01000!FxLibraryGlobals.FxDriverGlobalsList: for each client driver its name, the KMDF version it bound to (WdfBindInfo), its _FX_DRIVER_GLOBALS, WDFDRIVER handle, and DRIVER_OBJECT, and whether it has an In-Flight Recorder log. Needs Wdf01000's PDB. The list is followed while each entry's Blink points back at the one before it. A client with an empty DriverName (one bound to KMDF with no FxDriver created) is listed by its DRIVER_OBJECT's name, which also names it to !wdfkd.wdfdriverinfo and !wdfkd.wdflogdump; a client whose name is not printable, or whose FxDriver does not check out (its type, owner, or handle), is listed with the problem.",
}

repl_command! {
    cmd_wdfkd_wdfdriverinfo;
    names: ["!wdfkd.wdfdriverinfo"],
    usage: "!wdfkd.wdfdriverinfo <driver-name>",
    summary: "Show a KMDF client driver and its WDF devices.",
    details: "The driver is named as !wdfkd.wdfldr lists it (without case; `.sys` is optional). Shows its DRIVER_OBJECT, FxDriver and WDFDRIVER handle, _FX_DRIVER_GLOBALS, KMDF version, registry path, and image, then every device object on the driver object's DeviceObject/NextDevice chain with the WDFDEVICE behind it (kind and PnP state). A device object leads to its WDFDEVICE through its DeviceExtension, which KMDF points at the device's first context; a device object whose link does not check out (the context header, the object's type and owner, and the FxDevice's own device object) is listed with the reason.",
    completion: Driver,
}

repl_command! {
    cmd_wdfkd_wdfhandle;
    names: ["!wdfkd.wdfhandle"],
    usage: "!wdfkd.wdfhandle <handle>",
    summary: "Decode a WDF handle and show the object it names.",
    details: "A handle is its object's address XORed with ~7; an offset handle (bit 0 set) points at a WDFOBJECT_OFFSET inside the object to subtract. Shows the FxObject, its type (FX_OBJECT_TYPES), size, reference count, state (FxObjectState), flags, owning driver, parent, and each context (type name, size, address). A value that does not decode to a kernel address, or an object whose type, state, size, context header, or owning driver does not check out, is refused rather than shown.",
    completion: Expression,
}

repl_command! {
    cmd_wdfkd_wdfdevice;
    names: ["!wdfkd.wdfdevice"],
    usage: "!wdfkd.wdfdevice <WDFDEVICE>",
    summary: "Show a WDFDEVICE: its device objects, state machines, and queues.",
    details: "Shows the device's kind (FDO, filter, PDO, or control), its WDM device object, the device object it is attached to, and the stack's PDO; its PnP, power, and power policy state machines' current states (_WDF_DEVICE_PNP_STATE, _WDF_DEVICE_POWER_STATE, _WDF_DEVICE_POWER_POLICY_STATE) and device and system power states; a PDO's parent device, an FDO's child lists; and each queue of its I/O package (dispatch type, power management, pending and driver-owned request counts), marking the default queue.",
    completion: Expression,
}

repl_command! {
    cmd_wdfkd_wdfqueue;
    names: ["!wdfkd.wdfqueue"],
    usage: "!wdfkd.wdfqueue <WDFQUEUE>",
    summary: "Show a WDFQUEUE: its configuration, state, callbacks, and requests.",
    details: "Shows the queue's dispatch type, state bits (_FX_IO_QUEUE_STATE), power state and management, execution level and synchronization scope, request counts, the Evt callbacks the driver set, and the requests on its lists: waiting in the queue, marked cancelable by the driver, and presented to the driver (WDFREQUEST handle, FxRequest, and IRP). A request that does not check out ends its list, with the reason.",
    completion: Expression,
}

repl_command! {
    cmd_wdfkd_wdflogdump;
    names: ["!wdfkd.wdflogdump"],
    usage: "!wdfkd.wdflogdump <driver-name>",
    summary: "Print a KMDF driver's In-Flight Recorder log, oldest record first.",
    details: "Reads the driver's IFR log (_FX_DRIVER_GLOBALS.WdfLogHeader) and walks its records from the newest back along PrevOffset, stopping at the first record written or at records newer ones overwrote. Each record prints as its sequence number, UTC time (when the log keeps timestamps), function, and message, formatted from the trace message format (TMF) annotations in Wdf01000's PDB. A record whose message no loaded PDB declares, or whose arguments do not fit it, prints its message GUID and number and its argument bytes. The header (its GUID, base, and size) and each record (signature, length, position, and sequence) are checked; the walk stops at the first that fails, and says why.",
    completion: Driver,
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
}
