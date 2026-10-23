//! KMDF (`!wdfkd.*`): client drivers, handles, objects, devices, queues,
//! requests, I/O targets, and In-Flight Recorder logs.

use std::fmt::{Display, LowerHex};

use ntoseye_macros::{command, grammar};
use tabled::builder::Builder;

use crate::base::error::Result;
use crate::base::time::filetime_to_iso_precise;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::DiagnosticValue;
use crate::nt::target::irp_minor_function_name;
use crate::nt::target::wdf::{
    IfrEnd, WdfCallback, WdfClient, WdfDeviceDetail, WdfDriverInfo, WdfDumpDriver, WdfEnumValue,
    WdfIoParameters, WdfIoTargetDetail, WdfIrpLocation, WdfIrpQueueRole, WdfLoader, WdfLogDump,
    WdfLogEntry, WdfObject, WdfObjectDetail, WdfObjectRef, WdfQueueDetail, WdfRequestDetail,
    WdfRequestRef, WdfTargetRequest,
};
use crate::session::Session;

/// List the KMDF client drivers.
///
/// Walks the list at Wdf01000!FxLibraryGlobals.FxDriverGlobalsList. For each
/// client driver, it shows the name, the KMDF version that the driver bound to
/// (WdfBindInfo), the _FX_DRIVER_GLOBALS, the WDFDRIVER handle, the
/// DRIVER_OBJECT, and whether the driver has an In-Flight Recorder log. The
/// command needs the PDB for Wdf01000. The walk continues only while the Blink
/// of each entry points back to the entry before it. A client has an empty
/// DriverName if it bound to KMDF but did not create an FxDriver, and the
/// command then lists the client by the name of its DRIVER_OBJECT, which you
/// also use with !wdfkd.wdfdriverinfo and !wdfkd.wdflogdump. When a client name
/// is not printable, or the FxDriver of a client fails the checks of its type,
/// owner, or handle, the command lists the client with the problem.
#[command(
    names = ["!wdfkd.wdfldr"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn wdf_loader(session: &Session) -> Result<WdfLoader> {
    session.target.wdf_loader()
}

impl Render for WdfLoader {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_loader(self);
    }
}

/// Show a KMDF client driver and its WDF devices.
///
/// Give the driver name as !wdfkd.wdfldr lists it. The name is not
/// case-sensitive, and `.sys` is optional. The command shows the DRIVER_OBJECT,
/// the FxDriver, the WDFDRIVER handle, the _FX_DRIVER_GLOBALS, the KMDF
/// version, the registry path, and the image. Then it shows each device object
/// on the DeviceObject/NextDevice chain of the driver object, with the related
/// WDFDEVICE and its kind and PnP state. A device object links to its WDFDEVICE
/// through its DeviceExtension, which KMDF sets to point to the first context
/// of the device. The command checks the context header, the type and owner of
/// the object, and the device object of the FxDevice, and if a check fails, it
/// lists the device object with the reason.
#[command(
    names = ["!wdfkd.wdfdriverinfo"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn wdf_driver_info(
    session: &Session,
    #[arg(complete = Driver, name = "driver-name")] driver: String,
) -> Result<WdfDriverInfo> {
    session.target.wdf_driver_info(&driver)
}

impl Render for WdfDriverInfo {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_driver_info(self);
    }
}

/// Decode a WDF handle and show its object.
///
/// A handle is the address of its object, XORed with ~7. An offset handle has
/// bit 0 set and points to a WDFOBJECT_OFFSET value inside the object, which
/// the command subtracts from the address that the handle points to. The
/// command shows the FxObject, its type (FX_OBJECT_TYPES), size, reference
/// count, state (FxObjectState), flags, owning driver, and parent, and each
/// context with its type name, size, and address. Then it names the command
/// that shows the object in full: !wdfkd.wdfdevice, !wdfkd.wdfqueue,
/// !wdfkd.wdfrequest, or !wdfkd.wdfiotarget for those types,
/// !wdfkd.wdfdriverinfo for a WDFDRIVER, and !wdfkd.wdfobject, which adds the
/// children of the object, for any other type. It shows an error if the value
/// does not decode to a kernel address, or if the type, state, size, context
/// header, or owning driver of the object is not valid.
#[command(
    names = ["!wdfkd.wdfhandle"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn wdf_handle(session: &Session, handle: u64) -> Result<WdfObject> {
    session.target.wdf_handle(handle)
}

impl Render for WdfObject {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_object(self);
        field("view", object_command(self));
    }
}

/// Show a KMDF object's header, contexts, and children.
///
/// Give a handle, as for !wdfkd.wdfhandle, or the address of an FxObject. The
/// command shows what !wdfkd.wdfhandle shows: the handle, the type
/// (FX_OBJECT_TYPES), size, reference count, state (FxObjectState), flags
/// (FXOBJECT_FLAGS), owning driver, and parent, and each context with its type
/// name, size, and address. Then it lists the children of the object
/// (m_ChildListHead), each with its handle and type. The framework's own
/// children, such as the packages of a device, have no handle. Use the command
/// for an object whose type has no command of its own, such as a WDFMEMORY,
/// WDFTIMER, or WDFWORKITEM. The object must pass the same checks as for
/// !wdfkd.wdfhandle, and the list of children stops at a child whose
/// m_ParentObject is not this object.
#[command(
    names = ["!wdfkd.wdfobject"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn wdf_object(
    session: &Session,
    #[arg(name = "handle|FxObject")] object: u64,
) -> Result<WdfObjectDetail> {
    session.target.wdf_object(object)
}

impl Render for WdfObjectDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_object_detail(self);
    }
}

/// Show a WDFDEVICE and its device objects, state machines, queues, and I/O
/// targets.
///
/// Shows the kind of the device (FDO, filter, PDO, or control), its WDM device
/// object, the device object that it is attached to, and the PDO of the stack.
/// It also shows the current states of the PnP, power, and power policy state
/// machines (_WDF_DEVICE_PNP_STATE, _WDF_DEVICE_POWER_STATE,
/// _WDF_DEVICE_POWER_POLICY_STATE), and the device and system power states. For
/// a PDO, it shows the parent device, and for an FDO, the child lists and the
/// default and self I/O targets. For each queue of the I/O package, it shows
/// the dispatch type, the power management, and the counts of pending and
/// driver-owned requests, and it marks the default queue. For each I/O target
/// of the device (m_IoTargetsList), it shows the WDFIOTARGET handle, the kind
/// of target, its state, and the device object that it sends to, and it marks
/// the default target. Pass a WDFQUEUE to !wdfkd.wdfqueue and a WDFIOTARGET to
/// !wdfkd.wdfiotarget.
#[command(
    names = ["!wdfkd.wdfdevice"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn wdf_device(
    session: &Session,
    #[arg(name = "WDFDEVICE")] handle: u64,
) -> Result<WdfDeviceDetail> {
    session.target.wdf_device(handle)
}

impl Render for WdfDeviceDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_device(self);
    }
}

/// Show a WDFQUEUE and its configuration, state, callbacks, and requests.
///
/// Shows the dispatch type of the queue, the state bits (_FX_IO_QUEUE_STATE),
/// the power state, and the power management. It also shows the execution
/// level, the synchronization scope, the request counts, and the Evt callbacks
/// that the driver set. Then it shows the requests on three lists: the requests
/// that wait in the queue, the requests that the driver marked cancelable, and
/// the requests presented to the driver. For each request, it shows the
/// WDFREQUEST handle, which you pass to !wdfkd.wdfrequest, the FxRequest, and
/// the IRP. If a request is not valid, the command stops that list at the
/// request and shows the reason.
#[command(
    names = ["!wdfkd.wdfqueue"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn wdf_queue(session: &Session, #[arg(name = "WDFQUEUE")] handle: u64) -> Result<WdfQueueDetail> {
    session.target.wdf_queue(handle)
}

impl Render for WdfQueueDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_queue(self);
    }
}

/// Show a WDFREQUEST, its IRP, its queue, and the I/O target it was sent to.
///
/// Shows the FxRequest, its owning driver, parent, reference count, and object
/// state. For the IRP of the request, it shows the current stack location: the
/// major and minor function, the device object and its driver, and the buffer
/// lengths of a read, a write, or a device control with its control code. It
/// also shows the system buffer, the user buffer, and the MDL of the IRP; pass
/// the IRP to !irp for all of its stack locations. If the IRP was freed or
/// reused, the command shows why it is not a live IRP. The command shows
/// whether the IRP came from the I/O manager or the framework or the driver
/// allocated it (FxRequestAllocationSource), whether the request is completed
/// or canceled, and whether its queue presented it to the driver. It shows the
/// queue that the request came from or waits in (m_IoQueue) and the cancel-safe
/// queue that holds the IRP: the requests that wait in the queue, the requests
/// that the driver marked cancelable with its EvtRequestCancel routine, which
/// the command shows, or the requests that an I/O target holds until it starts.
/// A request that none of these holds cannot be canceled. For a request that
/// the driver sent, it shows the I/O target (m_Target), the completion routine
/// and its context, and the target flags (FxRequestTargetFlags). KMDF sets the
/// verifier flags (FxRequestVerifierFlags) only when its verifier is on for the
/// driver.
#[command(
    names = ["!wdfkd.wdfrequest"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn wdf_request(
    session: &Session,
    #[arg(name = "WDFREQUEST")] handle: u64,
) -> Result<WdfRequestDetail> {
    session.target.wdf_request(handle)
}

impl Render for WdfRequestDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_request(self);
    }
}

/// Show a WDFIOTARGET, the device object it sends to, and the requests sent to
/// it.
///
/// Shows the kind of the target: local (in the device's own stack, as the
/// default target is), remote (a target that the driver opened with
/// WdfIoTargetOpen), self, or a USB device or USB pipe, and whether it is the
/// default I/O target of its device. It shows the state (_WDF_IO_TARGET_STATE),
/// the open state of a remote target, the WDFDEVICE that the target belongs to,
/// the device object that the target sends requests to and the driver of that
/// device object, the PDO of that stack, the file object, the I/O count, and
/// the stack size. Then it lists the requests on three lists: the requests sent
/// to the target and not completed (m_SentIoListHead), the requests sent with
/// WDF_REQUEST_SEND_OPTION_IGNORE_TARGET_STATE while the target was not started
/// (m_IgnoredIoListHead), and the requests that the target holds until it
/// starts (m_PendedQueue). For each request, it shows the WDFREQUEST handle,
/// the FxRequest, and the IRP. A request without a handle is the framework's
/// own, such as the request that a synchronous send builds. A list stops at a
/// request whose m_Target is not this target, with the reason.
#[command(
    names = ["!wdfkd.wdfiotarget"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn wdf_io_target(
    session: &Session,
    #[arg(name = "WDFIOTARGET")] handle: u64,
) -> Result<WdfIoTargetDetail> {
    session.target.wdf_io_target(handle)
}

impl Render for WdfIoTargetDetail {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_io_target(self);
    }
}

/// Show the In-Flight Recorder log of a KMDF driver, oldest record first.
///
/// Reads the IFR log of the driver (_FX_DRIVER_GLOBALS.WdfLogHeader). The
/// command walks the records back from the newest record along PrevOffset, and
/// stops at the first record written or at records that newer records
/// overwrote. For each record, it shows the sequence number, the UTC time (only
/// when the log keeps timestamps), the function, and the message. The command
/// formats the message from the trace message format (TMF) annotations in the
/// PDB for Wdf01000. For a record with a message that no loaded PDB declares,
/// or with arguments that do not fit the message, it shows the message GUID,
/// the message number, and the argument bytes. The command checks the header
/// (its GUID, base, and size) and each record (signature, length, position, and
/// sequence), and the walk stops at the first item that fails a check, with the
/// reason.
#[command(
    names = ["!wdfkd.wdflogdump"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect,
)]
fn wdf_log(
    session: &Session,
    #[arg(complete = Driver, name = "driver-name")] driver: String,
) -> Result<WdfLogDump> {
    session.target.wdf_log_dump(&driver)
}

impl Render for WdfLogDump {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_log(self);
    }
}

/// Show the KMDF data in a crash dump: one driver's In-Flight Recorder log, or
/// the client drivers.
///
/// When Windows writes a crash dump, Wdf01000 copies one client driver's
/// In-Flight Recorder log into the dump's tagged data (WdfDumpGuid): the log of
/// the driver whose code the bugcheck parameters point to, or of a driver set
/// to keep its log in minidumps, or else of the last KMDF driver that ran on
/// the processor that crashed. A minidump has no other copy of the log. Without
/// an argument or with log, the command shows that log, oldest record first, as
/// !wdfkd.wdflogdump shows a log in memory. Unlike WinDbg, it shows a log's
/// only record once, and it keeps the oldest record that survives in a log that
/// has wrapped. With loader, it lists the client drivers that Wdf01000 recorded
/// (WdfDumpGuid2), with the KMDF version each bound to and its
/// _FX_DRIVER_GLOBALS; the first entry is the framework itself. The command
/// needs the PDB for Wdf01000.
#[command(
    names = ["!wdfkd.wdfcrashdump"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [wdf_crash_log, wdf_crash_drivers],
)]
fn wdf_crash_dump(
    session: &Session,
    #[arg(parse = crash_dump_part)] loader: Option<bool>,
) -> Result<WdfCrashDump> {
    if loader.unwrap_or(false) {
        wdf_crash_drivers(session).map(WdfCrashDump::Loader)
    } else {
        wdf_crash_log(session).map(WdfCrashDump::Log)
    }
}

/// Get the In-Flight Recorder log of the one KMDF client driver that
/// KMDF copied into a crash dump (`!wdfkd.wdfcrashdump`): the driver
/// that the bugcheck parameters point to, or one set to keep its log in
/// minidumps, or else the last one that ran on the processor that
/// crashed. A minidump has no other copy of it.
#[command(form_of = wdf_crash_dump, python = Inspect)]
fn wdf_crash_log(session: &Session) -> Result<WdfLogDump> {
    session.target.wdf_crash_log()
}

/// List the KMDF client drivers that KMDF recorded in a crash dump, with
/// their version and globals (`!wdfkd.wdfcrashdump loader`).
#[command(form_of = wdf_crash_dump, python = Inspect)]
fn wdf_crash_drivers(session: &Session) -> Result<Vec<WdfDumpDriver>> {
    session.target.wdf_crash_drivers()
}

/// `!wdfkd.wdfcrashdump`'s word: `log` (or none) is `Some(false)` (or
/// `None`), `loader` is `Some(true)`, in any case.
#[grammar(usage = "[log|loader]")]
fn crash_dump_part(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<bool>, ArgError> {
    let Some(word) = cursor.word() else {
        return Ok(None);
    };
    match word.to_ascii_lowercase().as_str() {
        "log" => Ok(Some(false)),
        "loader" => Ok(Some(true)),
        other => Err(ArgError::Message(format!(
            "!wdfkd.wdfcrashdump: '{other}' is neither log nor loader"
        ))),
    }
}

/// What `!wdfkd.wdfcrashdump` shows: the IFR log Wdf01000 copied into the
/// dump, or with `loader`, the client drivers it recorded.
enum WdfCrashDump {
    Log(WdfLogDump),
    Loader(Vec<WdfDumpDriver>),
}

impl Render for WdfCrashDump {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Log(log) => print_log(log),
            Self::Loader(drivers) => print_dump_drivers(drivers),
        }
    }
}

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("  {}  {value}", ui::label(&format!("{label:<21}")));
}

fn enum_text(value: &WdfEnumValue) -> String {
    match &value.name {
        Some(name) => format!("{name} ({:#x})", value.value),
        None => format!("{:#x}", value.value),
    }
}

fn object_ref_text(object: &Option<WdfObjectRef>) -> String {
    let Some(object) = object else {
        return ui::muted("-");
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
    handle.map_or_else(|| ui::muted("-"), ui::addr)
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

/// A client's name, or a muted `-`.
fn name_text(name: &Option<String>) -> String {
    name.clone().unwrap_or_else(|| ui::muted("-"))
}

/// A client's name, or, without one, the last part of its driver object's
/// name (`kdnic` for `\Driver\kdnic`), which is the same service name the
/// other clients go by.
fn client_name_text(client: &WdfClient) -> String {
    match (&client.name, &client.driver_object_name) {
        (Some(name), _) => name.clone(),
        (None, Some(object)) => ui::muted(object.rsplit('\\').next().unwrap_or(object.as_str())),
        (None, None) => ui::muted("-"),
    }
}

/// A flags value with the names of its set flags: `0x3 (A | B)`, or only
/// the value when no name is known.
fn flags_text(value: impl LowerHex, names: &[String]) -> String {
    if names.is_empty() {
        format!("{value:#x}")
    } else {
        format!("{value:#x} ({})", names.join(" | "))
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
                || "-".to_string(),
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
    outln!("{} {}", ui::label("driver"), name_text(&client.name));
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
            .map_or_else(|| ui::muted("-"), |driver| ui::addr(driver.0)),
    );
    field("WDFDRIVER", handle_text(client.wdf_driver));
    if let Some(path) = &client.registry_path {
        field("registry path", path);
    }
    field(
        "image",
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
            .map_or_else(|| ui::muted("-"), |header| ui::addr(header.0)),
    );
    field("verifier", if client.verifier_on { "on" } else { "off" });
    for problem in &client.problems {
        field("problem", problem);
    }
}

fn print_driver_info(info: &WdfDriverInfo) {
    print_client(&info.client);
    print_section("devices");
    let mut builder = Builder::default();
    builder.push_record(["DEVICE_OBJECT", "WDFDEVICE", "Kind", "PnP state"]);
    for device in &info.devices {
        match &device.unlinked {
            None => builder.push_record([
                ui::addr(device.device_object.0),
                handle_text(device.handle),
                device
                    .kind
                    .map_or_else(|| "-".to_string(), |kind| kind.to_string()),
                device
                    .pnp_state
                    .as_ref()
                    .map_or_else(|| "-".to_string(), enum_text),
            ]),
            Some(why) => builder.push_record([
                ui::addr(device.device_object.0),
                ui::muted("-"),
                ui::muted("-"),
                ui::muted(&format!("not a WDFDEVICE of this driver: {why}")),
            ]),
        }
    }
    print_padded_table(builder);
    print_stopped("", "device list", &info.devices_stopped);
}

/// The command that shows `object` in full, with the argument it takes.
fn object_command(object: &WdfObject) -> String {
    // A dedicated command takes the object's own handle, not an offset
    // handle into it; !wdfkd.wdfobject also takes the object's address.
    if object.offset.is_some() {
        return format!("!wdfkd.wdfobject {}", ui::addr(object.address.0));
    }
    let handle = ui::addr(object.handle);
    match object.type_name.as_str() {
        "FX_TYPE_DEVICE" => format!("!wdfkd.wdfdevice {handle}"),
        "FX_TYPE_QUEUE" => format!("!wdfkd.wdfqueue {handle}"),
        "FX_TYPE_REQUEST" => format!("!wdfkd.wdfrequest {handle}"),
        name if name.starts_with("FX_TYPE_IO_TARGET") => format!("!wdfkd.wdfiotarget {handle}"),
        "FX_TYPE_DRIVER" if object.driver.is_some() => format!(
            "!wdfkd.wdfdriverinfo {}",
            object.driver.as_deref().unwrap_or_default()
        ),
        _ => format!("!wdfkd.wdfobject {handle}"),
    }
}

fn print_object(object: &WdfObject) {
    outln!("{} {}", ui::label("handle"), ui::addr(object.handle));
    let mut address = ui::addr(object.address.0);
    if let Some(offset) = object.offset {
        address.push_str(&format!("  (offset handle, WDFOBJECT_OFFSET {offset:#x})"));
    }
    field("FxObject", address);
    field(
        "type",
        format!("{} ({:#x})", object.type_name, object.type_value),
    );
    field(
        "driver",
        format!(
            "{}  (globals {})",
            name_text(&object.driver),
            ui::addr(object.globals.0)
        ),
    );
    field("object size", format!("{:#x}", object.object_size));
    field("reference count", object.refcount);
    field("state", enum_text(&object.state));
    field("flags", flags_text(object.flags, &object.flag_names));
    field("parent", object_ref_text(&object.parent));
    if object.contexts.is_empty() {
        field("contexts", ui::muted("-"));
    }
    for context in &object.contexts {
        let name = context.name.as_deref().unwrap_or("(no type)");
        let size = context
            .size
            .map(|size| format!("  size {size:#x}"))
            .unwrap_or_default();
        field(
            "context",
            format!(
                "{}  {}{size}  (header {})",
                ui::addr(context.context.0),
                name,
                ui::addr(context.header.0)
            ),
        );
    }
    print_stopped("", "context chain", &object.contexts_stopped);
}

fn print_object_detail(detail: &WdfObjectDetail) {
    print_object(&detail.object);
    let command = object_command(&detail.object);
    if !command.starts_with("!wdfkd.wdfobject") {
        field("view", command);
    }
    print_section(&format!("children ({})", detail.children.len()));
    if detail.children.is_empty() {
        print_stopped("", "child list", &detail.children_stopped);
        return;
    }
    let mut builder = Builder::default();
    builder.push_record(["Handle", "FxObject", "Type"]);
    for child in &detail.children {
        builder.push_record([
            handle_text(child.handle),
            ui::addr(child.address.0),
            child.type_name.as_deref().unwrap_or("-").to_string(),
        ]);
    }
    print_padded_table(builder);
    print_stopped("", "child list", &detail.children_stopped);
}

fn print_device(device: &WdfDeviceDetail) {
    outln!("{} {}", ui::label("WDFDEVICE"), ui::addr(device.handle));
    field("FxDevice", ui::addr(device.address.0));
    field(
        "driver",
        format!(
            "{}  (globals {})",
            name_text(&device.driver),
            ui::addr(device.globals.0)
        ),
    );
    field("kind", device.kind);
    if let Some(name) = &device.device_name {
        field("name", name);
    }
    field("device object", ui::addr_opt(device.device_object));
    field("attached to", ui::addr_opt(device.attached_device));
    field("PDO", ui::addr_opt(device.physical_device));
    if device.parent.is_some() {
        field("parent", object_ref_text(&device.parent));
    }
    field("PnP state", enum_text(&device.pnp_state));
    field("power state", enum_text(&device.power_state));
    field("power policy state", enum_text(&device.power_policy_state));
    if let Some(state) = &device.device_power_state {
        field("device power state", enum_text(state));
    }
    if let Some(state) = &device.system_power_state {
        field("system power state", enum_text(state));
    }
    field("FxPkgPnp", ui::addr_opt(device.pkg_pnp));
    field("FxPkgIo", ui::addr_opt(device.pkg_io));
    if device.default_child_list.is_some() || device.static_child_list.is_some() {
        field("default child list", handle_text(device.default_child_list));
        field("static child list", handle_text(device.static_child_list));
    }
    if device.default_io_target.is_some() || device.self_io_target.is_some() {
        field("default I/O target", handle_text(device.default_io_target));
        field("self I/O target", handle_text(device.self_io_target));
    }
    print_section("queues");
    let mut builder = Builder::default();
    builder.push_record([
        "WDFQUEUE",
        "FxIoQueue",
        "Dispatch",
        "Power managed",
        "Pending",
        "Driver owned",
        "Default",
    ]);
    for queue in &device.queues {
        builder.push_record([
            ui::addr(queue.handle),
            ui::addr(queue.address.0),
            queue.dispatch_type.name.as_deref().map_or_else(
                || format!("{:#x}", queue.dispatch_type.value),
                |name| name.trim_start_matches("WdfIoQueueDispatch").to_string(),
            ),
            yes_no(queue.power_managed).to_string(),
            queue.pending.to_string(),
            queue.driver_owned.to_string(),
            yes_no(queue.is_default).to_string(),
        ]);
    }
    print_padded_table(builder);
    print_stopped("", "queue list", &device.queues_stopped);
    outln!("{}", ui::label("I/O targets"));
    let mut builder = Builder::default();
    builder.push_record([
        "WDFIOTARGET",
        "FxIoTarget",
        "Kind",
        "State",
        "Target device",
        "Default",
    ]);
    for target in &device.io_targets {
        builder.push_record([
            ui::addr(target.handle),
            ui::addr(target.address.0),
            target.kind.to_string(),
            io_target_state_text(&target.state),
            ui::addr_opt(target.target_device),
            yes_no(target.is_default).to_string(),
        ]);
    }
    print_padded_table(builder);
    print_stopped("", "I/O target list", &device.io_targets_stopped);
}

/// `_WDF_IO_TARGET_STATE` without its `WdfIoTarget` prefix.
fn io_target_state_text(state: &WdfEnumValue) -> String {
    state.name.as_deref().map_or_else(
        || format!("{:#x}", state.value),
        |name| {
            name.trim_start_matches("WdfIoTargetState")
                .trim_start_matches("WdfIoTarget")
                .to_string()
        },
    )
}

fn print_requests(title: &str, requests: &[WdfRequestRef], stopped: &Option<String>) {
    print_section(&format!("{title} ({})", requests.len()));
    for request in requests {
        outln!(
            "  WDFREQUEST {}  FxRequest {}  IRP {}",
            ui::addr(request.handle),
            ui::addr(request.address.0),
            ui::addr_opt(request.irp)
        );
    }
    print_stopped("  ", "list", stopped);
}

fn print_queue(queue: &WdfQueueDetail) {
    outln!("{} {}", ui::label("WDFQUEUE"), ui::addr(queue.handle));
    field("FxIoQueue", ui::addr(queue.address.0));
    field("driver", name_text(&queue.driver));
    field("device", object_ref_text(&queue.device));
    field("dispatch type", enum_text(&queue.dispatch_type));
    field("state", flags_text(queue.state, &queue.state_names));
    field("power state", enum_text(&queue.power_state));
    field("power managed", yes_no(queue.power_managed));
    field(
        "zero-length requests",
        yes_no(queue.allow_zero_length_requests),
    );
    if queue.deleted {
        field("deleted", true);
    }
    field("execution level", enum_text(&queue.execution_level));
    field("synchronization", enum_text(&queue.synchronization_scope));
    field("max parallel", queue.max_parallel_requests);
    field("pending", queue.pending_count);
    field("driver cancelable", queue.driver_cancelable_count);
    field("driver owned", queue.driver_owned_count);
    field("two-phase completions", queue.two_phase_completions);
    for callback in &queue.callbacks {
        field(callback.name, callback_text(callback));
    }
    print_requests("pending requests", &queue.pending, &queue.pending_stopped);
    print_requests(
        "driver cancelable requests",
        &queue.driver_cancelable,
        &queue.driver_cancelable_stopped,
    );
    print_requests(
        "driver owned requests",
        &queue.driver_owned,
        &queue.driver_owned_stopped,
    );
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn callback_text(callback: &WdfCallback) -> String {
    let symbol = callback
        .symbol
        .as_deref()
        .map(ui::symbol)
        .unwrap_or_default();
    format!("{}  {symbol}", ui::addr(callback.address.0))
}

/// `IRP_MJ_READ`, with the minor function when it has a name or is not 0.
fn location_function_text(location: &WdfIrpLocation) -> String {
    let major = location.major_function_name();
    match irp_minor_function_name(location.major_function, location.minor_function) {
        Some(minor) => format!("{major} IRP_MN_{minor}"),
        None if location.minor_function != 0 => {
            format!("{major} minor {:#x}", location.minor_function)
        }
        None => major,
    }
}

fn parameters_text(parameters: &WdfIoParameters) -> Option<String> {
    let parts: Vec<String> = [
        ("length", parameters.length),
        ("input", parameters.input_length),
        ("output", parameters.output_length),
        ("IOCTL", parameters.io_control_code),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.map(|value| format!("{name} {value:#x}")))
    .collect();
    (!parts.is_empty()).then(|| parts.join("  "))
}

fn cancelable_text(request: &WdfRequestDetail) -> String {
    if request.irp_queue.is_zero() {
        return "no".into();
    }
    match request.irp_queue_role {
        Some(WdfIrpQueueRole::Pending) => "yes, while it waits in its queue".into(),
        Some(WdfIrpQueueRole::DriverCancelable) => "yes, the driver marked it cancelable".into(),
        Some(WdfIrpQueueRole::TargetPended) => {
            "yes, while its I/O target holds it until the target starts".into()
        }
        None => format!("yes, on FxIrpQueue {}", ui::addr(request.irp_queue.0)),
    }
}

fn print_request(request: &WdfRequestDetail) {
    outln!("{} {}", ui::label("WDFREQUEST"), ui::addr(request.handle));
    field("FxRequest", ui::addr(request.address.0));
    field(
        "driver",
        format!(
            "{}  (globals {})",
            name_text(&request.driver),
            ui::addr(request.globals.0)
        ),
    );
    field("reference count", request.refcount);
    field("object state", enum_text(&request.object_state));
    field("parent", object_ref_text(&request.parent));
    if request.irp.is_zero() {
        field("IRP", ui::muted("-"));
    } else {
        field(
            "IRP",
            format!("{}  {}", ui::addr(request.irp.0), ui::muted("(!irp)")),
        );
    }
    if let Some(problem) = &request.irp_problem {
        field("IRP problem", problem);
    }
    if let Some(irp) = &request.irp_detail {
        match &irp.current {
            Some(location) => {
                field(
                    "current location",
                    format!(
                        "{} of {}: {}",
                        location.number,
                        irp.stack_count,
                        location_function_text(location)
                    ),
                );
                field(
                    "  device",
                    format!(
                        "{}  {}  {}",
                        ui::addr_opt(location.device_object),
                        location.driver.as_deref().unwrap_or_default(),
                        ui::muted("(!devobj)")
                    ),
                );
                if let Some(text) = parameters_text(&location.parameters) {
                    field("  parameters", text);
                }
                if !location.file_object.is_zero() {
                    field("  file object", ui::addr(location.file_object.0));
                }
            }
            None => field(
                "current location",
                ui::muted(&format!(
                    "- (CurrentLocation {} of {}: the IRP has left the stack)",
                    irp.current_location, irp.stack_count
                )),
            ),
        }
        for (label, address) in [
            ("  system buffer", irp.system_buffer),
            ("  user buffer", irp.user_buffer),
            ("  MDL", irp.mdl_address),
        ] {
            if !address.is_zero() {
                field(label, ui::addr(address.0));
            }
        }
    }
    field("IRP allocated by", enum_text(&request.irp_allocation));
    field("IRP references", request.irp_reference_count);
    field("completed", yes_no(request.completed));
    field("canceled", yes_no(request.canceled));
    field("presented", yes_no(request.presented));
    field("completion state", enum_text(&request.completion_state));
    let queue = object_ref_text(&request.queue);
    field(
        "queue",
        match request.queue {
            Some(_) => format!("{queue}  {}", ui::muted("(!wdfkd.wdfqueue)")),
            None => queue,
        },
    );
    field("cancelable", cancelable_text(request));
    if let Some(callback) = &request.cancel_routine {
        field(callback.name, callback_text(callback));
    }
    let target = object_ref_text(&request.target);
    field(
        "I/O target",
        match request.target {
            Some(_) => format!("{target}  {}", ui::muted("(!wdfkd.wdfiotarget)")),
            None => target,
        },
    );
    if let Some(callback) = &request.completion_routine {
        field("completion routine", callback_text(callback));
        field("completion context", ui::addr(request.completion_context.0));
    }
    field(
        "target flags",
        flags_text(request.target_flags, &request.target_flag_names),
    );
    if request.verifier_flags != 0 {
        field(
            "verifier flags",
            flags_text(request.verifier_flags, &request.verifier_flag_names),
        );
    }
}

fn print_target_requests(title: &str, requests: &[WdfTargetRequest], stopped: &Option<String>) {
    print_section(&format!("{title} ({})", requests.len()));
    for request in requests {
        let handle = request
            .handle
            .map_or_else(|| ui::muted("- (the framework's own)"), ui::addr);
        outln!(
            "  WDFREQUEST {handle}  FxRequest {}  IRP {}",
            ui::addr(request.address.0),
            ui::addr_opt(request.irp)
        );
    }
    print_stopped("  ", "list", stopped);
}

fn print_io_target(target: &WdfIoTargetDetail) {
    outln!("{} {}", ui::label("WDFIOTARGET"), ui::addr(target.handle));
    field("FxIoTarget", ui::addr(target.address.0));
    field(
        "driver",
        format!(
            "{}  (globals {})",
            name_text(&target.driver),
            ui::addr(target.globals.0)
        ),
    );
    field(
        "kind",
        format!(
            "{}{}  ({})",
            target.kind,
            if target.is_default {
                ", the default I/O target"
            } else {
                ""
            },
            target.type_name
        ),
    );
    field("state", enum_text(&target.state));
    if let Some(state) = &target.open_state {
        field("open state", enum_text(state));
    }
    let device = object_ref_text(&target.device);
    field(
        "device",
        match target.device {
            Some(_) => format!("{device}  {}", ui::muted("(!wdfkd.wdfdevice)")),
            None => device,
        },
    );
    field("in stack", yes_no(target.in_stack));
    field("in-stack device", ui::addr_opt(target.in_stack_device));
    field(
        "target device",
        if target.target_device.is_zero() {
            ui::addr_opt(target.target_device)
        } else {
            format!(
                "{}  {}  {}",
                ui::addr(target.target_device.0),
                target.target_driver.as_deref().unwrap_or_default(),
                ui::muted("(!devobj)")
            )
        },
    );
    field("target PDO", ui::addr_opt(target.target_pdo));
    if !target.file_object.is_zero() {
        field(
            "file object",
            format!(
                "{}  {}",
                ui::addr(target.file_object.0),
                ui::muted("(!fileobj)")
            ),
        );
    }
    field("I/O count", target.io_count);
    field("stack size", target.stack_size);
    print_target_requests("sent requests", &target.sent, &target.sent_stopped);
    print_target_requests(
        "requests sent ignoring the target state",
        &target.ignored,
        &target.ignored_stopped,
    );
    print_target_requests("pended requests", &target.pended, &target.pended_stopped);
}

/// An IFR record as one line: its sequence number, its time when it has
/// one, and its message formatted, or the message's GUID and number and
/// its argument bytes when no loaded PDB declares it.
pub fn ifr_entry_line(entry: &WdfLogEntry) -> String {
    let record = &entry.record;
    let time = record
        .timestamp
        .and_then(filetime_to_iso_precise)
        .map(|time| format!("{time} "))
        .unwrap_or_default();
    match &entry.text {
        DiagnosticValue::Available(text) => {
            let function = entry
                .function()
                .map(|function| format!("{function} - "))
                .unwrap_or_default();
            format!("{}: {time}{function}{text}", record.sequence)
        }
        DiagnosticValue::Unavailable(why) => {
            let args: String = record.args.iter().map(|b| format!("{b:02x}")).collect();
            format!(
                "{}: {time}{} #{} {}  {}",
                record.sequence,
                record.message_guid_text(),
                record.message_number,
                ui::muted(&format!("({why})")),
                args
            )
        }
    }
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
        outln!("{}", ifr_entry_line(entry));
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
                "-".to_string()
            } else {
                ui::addr(driver.globals.0).to_string()
            },
        ]);
    }
    print_padded_table(builder);
    outln!("{}", ui::muted(&format!("({} drivers)", drivers.len())));
}
