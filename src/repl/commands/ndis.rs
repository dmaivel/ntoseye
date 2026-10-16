//! NDIS (`!ndiskd.*`): network miniports, their filter stacks, protocol
//! bindings, and pending OID requests, and the miniport drivers.

use std::fmt::Display;

use ntoseye_macros::command;
use tabled::builder::Builder;

use crate::error::{Error, Result};
use crate::ntstatus::ntstatus_name;
use crate::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::repl::memory_view::{AsciiCell, MemoryDisplayMode, row_ascii, row_items};
use crate::repl::*;
use crate::session::Session;
use crate::target::ndis::{
    MAX_NET_BUFFER_DATA, NdisDriver, NdisDriverList, NdisFilterDetail, NdisFilterDriverDetail,
    NdisFilterDriverList, NdisFilterList, NdisFilterListEntry, NdisMinidriver, NdisMiniport,
    NdisMiniportDetail, NdisMiniportList, NdisMiniportListEntry, NdisNbl, NdisNblChain,
    NdisOidRequest, NdisPendingOids, NdisProtocolDetail, NdisProtocolList, link_speed_text,
    oid_name,
};
use crate::types::VirtAddr;
use crate::ui;

/// List the NDIS miniports (network adapters).
///
/// Walks ndis!ndisMiniportList and shows one line per miniport: the address of
/// its _NDIS_MINIPORT_BLOCK, which !ndiskd.miniport takes, the service of its
/// miniport driver, the miniport state (Running, Pausing, Paused, Restarting,
/// Initializing, Halted), the media connect state with the transmit link speed
/// (and the receive speed when it differs), the device power state, the
/// interface index, and the friendly name. Virtual miniports, such as Hyper-V's
/// adapters, are on the list too. The command needs the PDB for ndis.sys.
#[command(
    names = ["!ndiskd.miniports"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn ndis_miniports(session: &Session) -> Result<NdisMiniportList> {
    session.target.ndis_miniports()
}

impl Render for NdisMiniportList {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_miniport_table(&self.entries);
        print_stopped("miniport list", &self.stopped);
    }
}

/// What `!ndiskd.miniport` shows: the miniports, or one in detail.
enum Miniports {
    List(NdisMiniportList),
    Miniport(NdisMiniportDetail),
}

/// Show an NDIS miniport: its driver, state, filter stack, bindings, and
/// pending OID.
///
/// Give the address that !ndiskd.miniports lists. The command shows the device
/// name and instance ID, the miniport driver with its image and versions, the
/// adapter context (MiniportAdapterContext, the driver's own context, which you
/// can dt with the driver's PDB), the FDO and PDO (none for a virtual
/// miniport), the miniport, PnP, and power states, the medium and link, the
/// interface index and NetLuid, the reference count, the reset counts and the
/// status of the last reset, the pending OID request with its OID, type, and
/// buffer, and PendingReturnNBLCount. Then it shows the filter stack from the
/// top down along each filter's LowerFilter link, with each filter's state,
/// driver image, module context, and pending OID request, and the protocols
/// bound to the miniport. A filter whose HigherFilter does not lead back ends
/// the stack walk with the reason. Without an address, the command lists the
/// miniports as !ndiskd.miniports does.
#[command(
    names = ["!ndiskd.miniport"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [ndis_miniport],
    usage = "!ndiskd.miniport [<miniport>]"
)]
fn ndis_miniport_command(session: &Session, address: Option<VirtAddr>) -> Result<Miniports> {
    let Some(address) = address else {
        return ndis_miniports(session).map(Miniports::List);
    };
    ndis_miniport(session, address)
        .map(Miniports::Miniport)
        .map_err(|error| detail_error("!ndiskd.miniport", address, &error))
}

/// Read the NDIS miniport at `address` with its driver, filter stack,
/// bindings, and pending OID request (`!ndiskd.miniport`).
#[command(form_of = ndis_miniport_command, python = Inspect)]
fn ndis_miniport(
    session: &Session,
    #[arg(name = "miniport")] address: VirtAddr,
) -> Result<NdisMiniportDetail> {
    session.target.ndis_miniport(address)
}

impl Render for Miniports {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        match self {
            Self::List(list) => list.render(repl, ()),
            Self::Miniport(detail) => print_miniport(detail),
        }
    }
}

/// What `!ndiskd.minidriver` shows: the miniport drivers, or one and its
/// miniports.
enum Minidrivers {
    List(NdisDriverList),
    Driver(NdisMinidriver),
}

/// List the NDIS miniport drivers, or show one and its miniports.
///
/// Without an address, walks ndis!ndisMiniDriverList and shows each miniport
/// driver's _NDIS_M_DRIVER_BLOCK, service name, image, NDIS version, driver
/// version, and number of miniports. With the address of a driver block, as
/// this list or !ndiskd.miniport shows it, the command shows the driver's
/// DRIVER_OBJECT, the module its code is in, its versions, and its miniports.
#[command(
    names = ["!ndiskd.minidriver"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [ndis_minidrivers, ndis_minidriver],
    usage = "!ndiskd.minidriver [<minidriver>]"
)]
fn ndis_minidriver_command(session: &Session, address: Option<VirtAddr>) -> Result<Minidrivers> {
    let Some(address) = address else {
        return ndis_minidrivers(session).map(Minidrivers::List);
    };
    ndis_minidriver(session, address)
        .map(Minidrivers::Driver)
        .map_err(|error| detail_error("!ndiskd.minidriver", address, &error))
}

/// List the NDIS miniport drivers (`!ndiskd.minidriver`).
#[command(form_of = ndis_minidriver_command, python = Inspect)]
fn ndis_minidrivers(session: &Session) -> Result<NdisDriverList> {
    session.target.ndis_minidrivers()
}

/// Read the NDIS miniport driver block at `address` and its miniports
/// (`!ndiskd.minidriver <address>`).
#[command(form_of = ndis_minidriver_command, python = Inspect)]
fn ndis_minidriver(
    session: &Session,
    #[arg(name = "minidriver")] address: VirtAddr,
) -> Result<NdisMinidriver> {
    session.target.ndis_minidriver(address)
}

impl Render for Minidrivers {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::List(list) => print_minidrivers(list),
            Self::Driver(detail) => print_minidriver(detail),
        }
    }
}

/// What `!ndiskd.protocol` shows: the protocol drivers, or one and its
/// bindings.
enum Protocols {
    List(NdisProtocolList),
    Protocol(NdisProtocolDetail),
}

/// List the NDIS protocol drivers, or show one and its bindings.
///
/// Without an address, walks ndis!ndisProtocolList and shows each protocol's
/// _NDIS_PROTOCOL_BLOCK, name, image, NDIS version, driver version, and number
/// of bindings. With the address of a protocol block, as this list or
/// !ndiskd.miniport shows it, the command shows the protocol's driver context,
/// flags, and BindAdapterHandlerEx, and each binding (_NDIS_OPEN_BLOCK) with
/// the miniport it opened and the protocol's binding context. The command needs
/// the PDB for ndis.sys.
#[command(
    names = ["!ndiskd.protocol"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [ndis_protocols, ndis_protocol],
    usage = "!ndiskd.protocol [<protocol>]"
)]
fn ndis_protocol_command(session: &Session, address: Option<VirtAddr>) -> Result<Protocols> {
    let Some(address) = address else {
        return ndis_protocols(session).map(Protocols::List);
    };
    ndis_protocol(session, address)
        .map(Protocols::Protocol)
        .map_err(|error| detail_error("!ndiskd.protocol", address, &error))
}

/// List the NDIS protocol drivers (`!ndiskd.protocol`).
#[command(form_of = ndis_protocol_command, python = Inspect)]
fn ndis_protocols(session: &Session) -> Result<NdisProtocolList> {
    session.target.ndis_protocols()
}

/// Read the NDIS protocol block at `address` and its bindings
/// (`!ndiskd.protocol <address>`).
#[command(form_of = ndis_protocol_command, python = Inspect)]
fn ndis_protocol(
    session: &Session,
    #[arg(name = "protocol")] address: VirtAddr,
) -> Result<NdisProtocolDetail> {
    session.target.ndis_protocol_detail(address)
}

impl Render for Protocols {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::List(list) => print_protocols(list),
            Self::Protocol(detail) => print_protocol(detail),
        }
    }
}

/// What `!ndiskd.filterdriver` shows: the filter drivers, or one and its
/// filter modules.
enum FilterDrivers {
    List(NdisFilterDriverList),
    Driver(NdisFilterDriverDetail),
}

/// List the NDIS filter drivers, or show one and its filter modules.
///
/// Without an address, walks ndis!ndisFilterDriverList and shows each filter
/// driver's _NDIS_FILTER_DRIVER_BLOCK, friendly name, service, image, NDIS
/// version, driver version, and number of filter modules. With the address of a
/// filter driver block, the command shows the driver's unique name (its GUID),
/// DRIVER_OBJECT, the module its code is in, its driver context and flags, and
/// its filter modules, one for each miniport it is attached to. The command
/// needs the PDB for ndis.sys.
#[command(
    names = ["!ndiskd.filterdriver"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [ndis_filter_drivers, ndis_filter_driver],
    usage = "!ndiskd.filterdriver [<filterdriver>]"
)]
fn ndis_filter_driver_command(
    session: &Session,
    address: Option<VirtAddr>,
) -> Result<FilterDrivers> {
    let Some(address) = address else {
        return ndis_filter_drivers(session).map(FilterDrivers::List);
    };
    ndis_filter_driver(session, address)
        .map(FilterDrivers::Driver)
        .map_err(|error| detail_error("!ndiskd.filterdriver", address, &error))
}

/// List the NDIS filter drivers (`!ndiskd.filterdriver`).
#[command(form_of = ndis_filter_driver_command, python = Inspect)]
fn ndis_filter_drivers(session: &Session) -> Result<NdisFilterDriverList> {
    session.target.ndis_filter_drivers()
}

/// Read the NDIS filter driver block at `address` and its filter
/// modules (`!ndiskd.filterdriver <address>`).
#[command(form_of = ndis_filter_driver_command, python = Inspect)]
fn ndis_filter_driver(
    session: &Session,
    #[arg(name = "filterdriver")] address: VirtAddr,
) -> Result<NdisFilterDriverDetail> {
    session.target.ndis_filter_driver_detail(address)
}

impl Render for FilterDrivers {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::List(list) => print_filter_drivers(list),
            Self::Driver(detail) => print_filter_driver(detail),
        }
    }
}

/// What `!ndiskd.filter` shows: the filter modules, or one in detail.
enum Filters {
    List(NdisFilterList),
    Filter(NdisFilterDetail),
}

/// List the NDIS filter modules, or show one.
///
/// Without an address, walks ndis!ndisGlobalFilterList and shows each filter
/// module of every miniport: its _NDIS_FILTER_BLOCK, state, driver image,
/// miniport, and name. With the address of a filter block, as this list or
/// !ndiskd.miniport shows it, the command shows the filter driver, the
/// miniport, the filter modules above and below it on the miniport's stack, the
/// module context (FilterModuleContext, which you can dt with the driver's
/// PDB), the link the filter last saw indicated, the reference count, the NBLs
/// and status indications NDIS dropped because the filter was not running, and
/// the pending OID request. The command needs the PDB for ndis.sys.
#[command(
    names = ["!ndiskd.filter"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [ndis_filters, ndis_filter],
    usage = "!ndiskd.filter [<filter>]"
)]
fn ndis_filter_command(session: &Session, address: Option<VirtAddr>) -> Result<Filters> {
    let Some(address) = address else {
        return ndis_filters(session).map(Filters::List);
    };
    ndis_filter(session, address)
        .map(Filters::Filter)
        .map_err(|error| detail_error("!ndiskd.filter", address, &error))
}

/// List the NDIS filter modules of every miniport (`!ndiskd.filter`).
#[command(form_of = ndis_filter_command, python = Inspect)]
fn ndis_filters(session: &Session) -> Result<NdisFilterList> {
    session.target.ndis_filters_all()
}

/// Read the NDIS filter module at `address` (`!ndiskd.filter <address>`).
#[command(form_of = ndis_filter_command, python = Inspect)]
fn ndis_filter(
    session: &Session,
    #[arg(name = "filter")] address: VirtAddr,
) -> Result<NdisFilterDetail> {
    session.target.ndis_filter_detail(address)
}

impl Render for Filters {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::List(list) => {
                print_filter_table(&list.entries);
                print_stopped("filter list", &list.stopped);
            }
            Self::Filter(detail) => print_filter(detail),
        }
    }
}

/// Show the OID requests that miniports and filters have not completed.
///
/// Reads the PendingOidRequest of every miniport on ndis!ndisMiniportList and
/// every filter module on ndis!ndisGlobalFilterList, and shows each request
/// with its owner, type, OID by its ntddndis.h name, and buffer. NDIS passes a
/// miniport or filter one OID request at a time, apart from direct OID
/// requests, so a request that stays here holds up the ones behind it. The
/// command needs the PDB for ndis.sys.
#[command(
    names = ["!ndiskd.oid"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    python = Inspect
)]
fn ndis_oids(session: &Session) -> Result<NdisPendingOids> {
    session.target.ndis_pending_oids()
}

impl Render for NdisPendingOids {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        print_pending_oids(self);
    }
}

/// What `!ndiskd.nbl` shows: one NBL, or the NBLs on its `Next` chain
/// (`-chain`).
enum Nbls {
    Nbl(NdisNbl),
    Chain(NdisNblChain),
}

const NBL_USAGE: &str = "usage: !ndiskd.nbl <nbl> [-chain] [-data]";

/// `!ndiskd.nbl`'s address, once its switches are taken: the one word that
/// is not an option.
fn nbl_address(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<VirtAddr, ArgError> {
    let mut address = None;
    while let Some(word) = cursor.word() {
        if word.len() > 1
            && word.starts_with('-')
            && word[1..].chars().all(|ch| ch.is_ascii_alphabetic())
        {
            return Err(ArgError::Message(format!(
                "!ndiskd.nbl: unknown option {word}; {NBL_USAGE}"
            )));
        }
        if address.is_some() {
            return Err(ArgError::Message(format!(
                "!ndiskd.nbl: unexpected argument {word}; {NBL_USAGE}"
            )));
        }
        address = Some(word);
    }
    let Some(address) = address else {
        return Err(ArgError::Message(NBL_USAGE.to_string()));
    };
    cx.eval(&address)
}

/// Show a NET_BUFFER_LIST and its NET_BUFFERs.
///
/// Shows the _NET_BUFFER_LIST at the address: its next and parent NBLs, its
/// source handle with the miniport, filter module, or binding it names, its
/// pool, context, Flags and NblFlags (by NDIS_NBL_FLAGS_ name), status, and
/// child reference count, and each NET_BUFFER with its data length, data
/// offset, current MDL and offset into it, and MDL chain. -chain lists every
/// NBL on the Next chain from the address, with its NET_BUFFERs, bytes, source,
/// and status. -data dumps each NET_BUFFER's data, up to 64 KiB of it, read
/// through the MDLs' PFNs, so a buffer that is not mapped into system space
/// reads too. The command needs the PDB for ndis.sys.
#[command(
    names = ["!ndiskd.nbl"],
    category = "objects and I/O",
    kind = Query,
    target = Kernel,
    forms = [ndis_nbl, ndis_nbl_chain],
    usage = "!ndiskd.nbl <nbl> [-chain] [-data]"
)]
fn ndis_nbl_command(
    session: &Session,
    #[arg(parse = nbl_address, complete = Expression)] address: VirtAddr,
    #[arg(switch = "-chain")] chain: bool,
    #[arg(switch = "-data")] data: bool,
) -> Result<Nbls> {
    let error = |error: Error| detail_error("!ndiskd.nbl", address, &error);
    if chain {
        return ndis_nbl_chain(session, address, data)
            .map(Nbls::Chain)
            .map_err(error);
    }
    ndis_nbl(session, address, data)
        .map(Nbls::Nbl)
        .map_err(error)
}

/// Decode the NET_BUFFER_LIST at `address` and its NET_BUFFERs
/// (`!ndiskd.nbl`). With `data`, each NET_BUFFER's `data` holds up to
/// 64 KiB of its frame, read through its MDLs' PFNs, or `data_error` why it
/// does not read (`!ndiskd.nbl -data`).
#[command(form_of = ndis_nbl_command, python = Inspect)]
fn ndis_nbl(
    session: &Session,
    #[arg(name = "nbl")] address: VirtAddr,
    #[arg(default = false, name = "-data")] data: bool,
) -> Result<NdisNbl> {
    let target = &session.target;
    let mut nbl = target.ndis_nbl(address)?;
    if data {
        target.ndis_read_nbl_data(&mut nbl);
    }
    Ok(nbl)
}

/// Decode the NET_BUFFER_LISTs on the `Next` chain from `address`
/// (`!ndiskd.nbl -chain`). With `data`, each NET_BUFFER's `data` holds up
/// to 64 KiB of its frame, or `data_error` why it does not read
/// (`!ndiskd.nbl -chain -data`).
#[command(form_of = ndis_nbl_command, python = Inspect, word = "-chain")]
fn ndis_nbl_chain(
    session: &Session,
    #[arg(name = "nbl")] address: VirtAddr,
    #[arg(default = false, name = "-data")] data: bool,
) -> Result<NdisNblChain> {
    let target = &session.target;
    let mut chain = target.ndis_nbl_chain(address)?;
    if data {
        for nbl in &mut chain.nbls {
            target.ndis_read_nbl_data(nbl);
        }
    }
    Ok(chain)
}

impl Render for Nbls {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Nbl(nbl) => {
                print_nbl(nbl);
                print_nbl_data(nbl);
            }
            Self::Chain(chain) => {
                print_nbl_chain(chain);
                for nbl in &chain.nbls {
                    print_nbl_data(nbl);
                }
            }
        }
    }
}

/// A detail form's error, with the command and the address it was given.
fn detail_error(command: &str, address: VirtAddr, error: &Error) -> Error {
    Error::DebugInfo(format!("{command} {:#x}: {error}", address.0))
}

/// A labeled line of a detail view.
fn field(label: &str, value: impl Display) {
    outln!("{} {value}", ui::label(&format!("{label:<20}")));
}

/// An address, or a muted `none` for a null pointer that means there is
/// none, such as the end of a chain.
fn addr_or_none(value: VirtAddr) -> String {
    if value.is_zero() {
        ui::muted("none")
    } else {
        ui::addr(value.0)
    }
}

fn print_stopped(what: &str, stopped: &Option<String>) {
    if let Some(stopped) = stopped {
        outln!("({what} stopped: {stopped})");
    }
}

/// The media connect state, with the link speed of a connected miniport:
/// the transmit speed, and the receive speed when it differs.
fn media_text(miniport: &NdisMiniport) -> String {
    if !miniport.connected {
        return miniport.media_connect.clone();
    }
    if miniport.xmit_link_speed == miniport.rcv_link_speed {
        format!(
            "{} {}",
            miniport.media_connect,
            link_speed_text(miniport.xmit_link_speed)
        )
    } else {
        format!(
            "{} {} / {}",
            miniport.media_connect,
            link_speed_text(miniport.xmit_link_speed),
            link_speed_text(miniport.rcv_link_speed)
        )
    }
}

fn oid_text(request: &NdisOidRequest) -> String {
    let name = oid_name(request.oid).unwrap_or("unknown OID");
    let mut text = format!(
        "{}  {} {name} ({:#x})  buffer {} {:#x} bytes",
        ui::addr(request.address.0),
        request.request_type,
        request.oid,
        ui::addr_opt(request.buffer),
        request.buffer_length
    );
    if let (Some(output_length), Some(method_id)) = (request.output_length, request.method_id) {
        text.push_str(&format!(
            ", output {output_length:#x} bytes, method {method_id:#x}"
        ));
    }
    if request.port != 0 {
        text.push_str(&format!(", port {}", request.port));
    }
    if request.timeout != 0 {
        text.push_str(&format!(", timeout {}s", request.timeout));
    }
    text
}

/// A pending OID request, why it does not decode, or a muted `none`.
fn pending_oid_text(request: &Option<NdisOidRequest>, error: &Option<String>) -> String {
    match (request, error) {
        (Some(request), _) => oid_text(request),
        (None, Some(error)) => ui::muted(error),
        (None, None) => ui::muted("none"),
    }
}

fn print_miniport_table(miniports: &[NdisMiniportListEntry]) {
    let mut builder = Builder::default();
    builder.push_record([
        "Miniport", "Driver", "State", "Media", "Power", "IfIndex", "Name",
    ]);
    for entry in miniports {
        match entry {
            Ok(miniport) => builder.push_record([
                ui::addr(miniport.address.0),
                miniport.driver_name.clone().unwrap_or_else(|| "?".into()),
                miniport.state.clone(),
                media_text(miniport),
                miniport.power.clone(),
                miniport.if_index.to_string(),
                miniport
                    .friendly_name
                    .clone()
                    .unwrap_or_else(|| miniport.name.clone()),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
            ]),
        }
    }
    print_padded_table(builder);
}

fn print_driver_fields(driver: &NdisDriver) {
    field("Service", &driver.service_name);
    field(
        "Image",
        match &driver.module {
            Some(module) => format!("{}  (module {module})", driver.image_name),
            None => driver.image_name.clone(),
        },
    );
    field("DRIVER_OBJECT", ui::addr_opt(driver.driver_object));
    field("NDIS version", &driver.ndis_version);
    if let Some(version) = &driver.driver_version {
        field("Driver version", version);
    }
}

fn print_minidrivers(list: &NdisDriverList) {
    let mut builder = Builder::default();
    builder.push_record([
        "Driver block",
        "Service",
        "Image",
        "NDIS",
        "Version",
        "Miniports",
    ]);
    for entry in &list.entries {
        match entry {
            Ok(driver) => builder.push_record([
                ui::addr(driver.address.0),
                driver.service_name.clone(),
                driver.image_name.clone(),
                driver.ndis_version.clone(),
                driver.driver_version.clone().unwrap_or_default(),
                driver.miniports.len().to_string(),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]),
        }
    }
    print_padded_table(builder);
    print_stopped("driver list", &list.stopped);
}

fn print_minidriver(detail: &NdisMinidriver) {
    let driver = &detail.driver;
    let miniports = &detail.entries;
    field("Driver block", ui::addr(driver.address.0));
    print_driver_fields(driver);
    outln!();
    outln!("{} ({})", ui::label("Miniports"), miniports.len());
    if !miniports.is_empty() {
        print_miniport_table(miniports);
    }
    print_stopped("miniport list", &driver.miniports_stopped);
}

fn print_miniport(detail: &NdisMiniportDetail) {
    let miniport = &detail.miniport;
    field(
        "Miniport",
        format!(
            "{}  {}",
            ui::addr(miniport.address.0),
            miniport.friendly_name.as_deref().unwrap_or_default()
        ),
    );
    if !detail.listed {
        field(
            "Note",
            ui::muted("not on ndis!ndisMiniportList (being added or removed, or not a miniport)"),
        );
    }
    field("Device name", &miniport.name);
    if let Some(instance_id) = &detail.instance_id {
        field("Instance ID", instance_id);
    }
    field("NDIS version", &detail.ndis_version);
    match (&detail.driver, &detail.driver_error) {
        (Some(driver), _) => {
            let mut text = format!("{}  {}", ui::addr(driver.address.0), driver.service_name);
            if !driver.image_name.is_empty() {
                text.push_str(&format!(" ({})", driver.image_name));
            }
            if let Some(version) = &driver.driver_version {
                text.push_str(&format!(" v{version}"));
            }
            field("Driver", text);
            field("DRIVER_OBJECT", ui::addr_opt(driver.driver_object));
        }
        (None, error) => field("Driver", ui::muted(error.as_deref().unwrap_or_default())),
    }
    // A driver without a DRIVER_OBJECT has no module to look up; its image
    // name without the extension is the module name its PDB goes by.
    let module = detail.driver.as_ref().and_then(|driver| {
        driver.module.as_deref().or_else(|| {
            driver
                .image_name
                .rsplit_once('.')
                .map(|(stem, _)| stem)
                .filter(|stem| !stem.is_empty())
        })
    });
    field(
        "Adapter context",
        if detail.adapter_context.is_zero() {
            ui::muted("none")
        } else {
            format!(
                "{}  {}",
                ui::addr(detail.adapter_context.0),
                ui::muted(&format!(
                    "(dt {}!<adapter type> {:x})",
                    module.unwrap_or("<driver>"),
                    detail.adapter_context.0
                ))
            )
        },
    );
    if detail.device_object.is_zero() && detail.pdo.is_zero() {
        field("Device objects", ui::muted("none (a virtual miniport)"));
    } else {
        field(
            "Device objects",
            format!(
                "FDO {}  PDO {}",
                ui::addr_opt(detail.device_object),
                ui::addr_opt(detail.pdo)
            ),
        );
    }
    outln!();
    field("State", &miniport.state);
    field("PnP state", &miniport.pnp_state);
    field("Power", &miniport.power);
    field(
        "Media",
        format!(
            "{}, {} duplex, medium {}, physical {}",
            miniport.media_connect, detail.duplex, detail.medium, detail.physical_medium
        ),
    );
    field(
        "Link speed",
        format!(
            "{} transmit, {} receive",
            link_speed_text(miniport.xmit_link_speed),
            link_speed_text(miniport.rcv_link_speed)
        ),
    );
    field(
        "Interface",
        format!(
            "IfIndex {}, NetLuid {:#x}, {}",
            miniport.if_index, detail.net_luid, detail.oper_status
        ),
    );
    field(
        "References",
        detail
            .references
            .map_or_else(|| ui::muted("unreadable"), |count| count.to_string()),
    );
    field(
        "Resets",
        format!(
            "internal {}, miniport {}, last status {:#x}",
            detail.internal_resets, detail.miniport_resets, detail.reset_status
        ),
    );
    field(
        "Pending OID",
        pending_oid_text(&detail.pending_oid, &detail.pending_oid_error),
    );
    field("Pending return NBLs", detail.pending_return_nbls);
    field(
        "Flags",
        format!("{:#x}, PnP flags {:#x}", detail.flags, detail.pnp_flags),
    );

    outln!();
    outln!(
        "{} ({}, top first)",
        ui::label("Filters"),
        detail.filters.len()
    );
    if !detail.filters.is_empty() {
        let mut builder = Builder::default();
        builder.push_record(["Filter", "State", "Driver", "Context", "Name"]);
        for filter in &detail.filters {
            builder.push_record([
                ui::addr(filter.address.0),
                filter.state.clone(),
                filter.driver_image.clone().unwrap_or_else(|| "?".into()),
                ui::addr_opt(filter.context),
                filter.name.clone().unwrap_or_default(),
            ]);
        }
        print_padded_table(builder);
        for filter in &detail.filters {
            if filter.pending_oid.is_some() || filter.pending_oid_error.is_some() {
                outln!(
                    "filter {} pending OID: {}",
                    ui::addr(filter.address.0),
                    pending_oid_text(&filter.pending_oid, &filter.pending_oid_error)
                );
            }
        }
    }
    print_stopped("filter stack", &detail.filters_stopped);

    outln!();
    outln!(
        "{} ({}, NumOpens {})",
        ui::label("Protocol bindings"),
        detail.opens.len(),
        detail.num_opens
    );
    if !detail.opens.is_empty() {
        let mut builder = Builder::default();
        builder.push_record(["Open", "Protocol", "Protocol block", "Context"]);
        for open in &detail.opens {
            builder.push_record([
                ui::addr(open.address.0),
                open.protocol_name.clone().unwrap_or_else(|| "?".into()),
                ui::addr_opt(open.protocol),
                ui::addr_opt(open.context),
            ]);
        }
        print_padded_table(builder);
    }
    print_stopped("binding list", &detail.opens_stopped);
}

fn print_filter_table(filters: &[NdisFilterListEntry]) {
    let mut builder = Builder::default();
    builder.push_record(["Filter", "State", "Driver", "Miniport", "Name"]);
    for entry in filters {
        match entry {
            Ok(filter) => builder.push_record([
                ui::addr(filter.address.0),
                filter.state.clone(),
                filter.driver_image.clone().unwrap_or_else(|| "?".into()),
                ui::addr_opt(filter.miniport),
                filter.name.clone().unwrap_or_default(),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                String::new(),
                String::new(),
                String::new(),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
            ]),
        }
    }
    print_padded_table(builder);
}

fn print_filter(detail: &NdisFilterDetail) {
    let filter = &detail.filter;
    field(
        "Filter",
        format!(
            "{}  {}",
            ui::addr(filter.address.0),
            filter.name.as_deref().unwrap_or_default()
        ),
    );
    if !detail.listed {
        field(
            "Note",
            ui::muted("not on ndis!ndisGlobalFilterList (being attached or detached)"),
        );
    }
    let mut driver = ui::addr_opt(filter.driver);
    if let Some(name) = &detail.driver_name {
        driver.push_str(&format!("  {name}"));
    }
    if let Some(image) = &filter.driver_image {
        driver.push_str(&format!(" ({image})"));
    }
    field("Filter driver", driver);
    field(
        "Miniport",
        format!(
            "{}  {}",
            ui::addr_opt(filter.miniport),
            filter.miniport_name.as_deref().unwrap_or_default()
        ),
    );
    let module = filter
        .driver_image
        .as_deref()
        .and_then(|image| image.rsplit_once('.').map(|(stem, _)| stem))
        .unwrap_or("<driver>");
    field(
        "Module context",
        if filter.context.is_zero() {
            ui::muted("none")
        } else {
            format!(
                "{}  {}",
                ui::addr(filter.context.0),
                ui::muted(&format!(
                    "(dt {module}!<context type> {:x})",
                    filter.context.0
                ))
            )
        },
    );
    field(
        "Stack",
        format!(
            "higher {}, lower {}",
            if detail.higher.is_zero() {
                ui::muted("none (top)")
            } else {
                ui::addr(detail.higher.0)
            },
            if detail.lower.is_zero() {
                ui::muted("none (bottom, above the miniport)")
            } else {
                ui::addr(detail.lower.0)
            }
        ),
    );
    outln!();
    field("State", &filter.state);
    field(
        "Link",
        format!(
            "{}, {} transmit, {} receive",
            detail.media_connect,
            link_speed_text(detail.xmit_link_speed),
            link_speed_text(detail.rcv_link_speed)
        ),
    );
    field("IfIndex", detail.if_index);
    field(
        "References",
        detail
            .references
            .map_or_else(|| ui::muted("unreadable"), |count| count.to_string()),
    );
    field(
        "Dropped",
        format!(
            "{} receive NBLs, {} send NBLs, {} status indications",
            detail.dropped_receive_nbls,
            detail.dropped_send_nbls,
            detail.dropped_status_indications
        ),
    );
    field(
        "Pending OID",
        pending_oid_text(&filter.pending_oid, &filter.pending_oid_error),
    );
    field("Flags", format!("{:#x}", detail.flags));
}

fn print_filter_drivers(list: &NdisFilterDriverList) {
    let mut builder = Builder::default();
    builder.push_record([
        "Driver block",
        "Name",
        "Service",
        "Image",
        "NDIS",
        "Version",
        "Filters",
    ]);
    for entry in &list.entries {
        match entry {
            Ok(driver) => builder.push_record([
                ui::addr(driver.address.0),
                driver.friendly_name.clone(),
                driver.service_name.clone(),
                driver.image_name.clone(),
                driver.ndis_version.clone(),
                driver.driver_version.clone(),
                driver.filters.len().to_string(),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]),
        }
    }
    print_padded_table(builder);
    print_stopped("filter driver list", &list.stopped);
}

fn print_filter_driver(detail: &NdisFilterDriverDetail) {
    let driver = &detail.driver;
    let filters = &detail.entries;
    field("Driver block", ui::addr(driver.address.0));
    field("Name", &driver.friendly_name);
    field("Unique name", &driver.unique_name);
    field("Service", &driver.service_name);
    field(
        "Image",
        match &driver.module {
            Some(module) => format!("{}  (module {module})", driver.image_name),
            None => driver.image_name.clone(),
        },
    );
    field("DRIVER_OBJECT", ui::addr_opt(driver.driver_object));
    field("Driver context", addr_or_none(driver.context));
    field("NDIS version", &driver.ndis_version);
    field("Driver version", &driver.driver_version);
    field("Flags", format!("{:#x}", driver.flags));
    outln!();
    outln!("{} ({})", ui::label("Filter modules"), filters.len());
    if !filters.is_empty() {
        print_filter_table(filters);
    }
    print_stopped("filter module list", &driver.filters_stopped);
}

fn print_protocols(list: &NdisProtocolList) {
    let mut builder = Builder::default();
    builder.push_record([
        "Protocol block",
        "Name",
        "Image",
        "NDIS",
        "Version",
        "Bindings",
    ]);
    for entry in &list.entries {
        match entry {
            Ok(protocol) => builder.push_record([
                ui::addr(protocol.address.0),
                protocol.name.clone(),
                protocol.image_name.clone().unwrap_or_default(),
                protocol.ndis_version.clone(),
                protocol.driver_version.clone(),
                protocol.opens.len().to_string(),
            ]),
            Err(unreadable) => builder.push_record([
                ui::addr(unreadable.address.0),
                ui::muted(&format!("unreadable: {}", unreadable.error)),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ]),
        }
    }
    print_padded_table(builder);
    print_stopped("protocol list", &list.stopped);
}

fn print_protocol(detail: &NdisProtocolDetail) {
    let protocol = &detail.protocol;
    field(
        "Protocol block",
        format!("{}  {}", ui::addr(protocol.address.0), protocol.name),
    );
    if !detail.listed {
        field(
            "Note",
            ui::muted("not on ndis!ndisProtocolList (being registered or deregistered)"),
        );
    }
    if let Some(image) = &protocol.image_name {
        field("Image", image);
    }
    field("NDIS version", &protocol.ndis_version);
    field("Driver version", &protocol.driver_version);
    field("Driver context", addr_or_none(protocol.context));
    field(
        "BindAdapterHandlerEx",
        match &detail.bind_handler_name {
            Some(name) => format!("{}  {name}", ui::addr(protocol.bind_handler.0)),
            None => addr_or_none(protocol.bind_handler),
        },
    );
    field("Flags", format!("{:#x}", protocol.flags));
    outln!();
    outln!("{} ({})", ui::label("Bindings"), detail.bindings.len());
    if !detail.bindings.is_empty() {
        let mut builder = Builder::default();
        builder.push_record(["Open", "Miniport", "Context", "Name"]);
        for binding in &detail.bindings {
            builder.push_record([
                ui::addr(binding.open.0),
                ui::addr_opt(binding.miniport),
                ui::addr_opt(binding.context),
                binding.miniport_name.clone().unwrap_or_default(),
            ]);
        }
        print_padded_table(builder);
    }
    print_stopped("binding list", &detail.bindings_stopped);
}

fn print_pending_oids(oids: &NdisPendingOids) {
    if oids.pending.is_empty() {
        outln!(
            "No pending OID requests on {} miniports and {} filter modules.",
            oids.miniports,
            oids.filters
        );
    } else {
        let mut builder = Builder::default();
        builder.push_record(["Owner", "Address", "Request", "Name"]);
        for pending in &oids.pending {
            builder.push_record([
                pending.owner.to_string(),
                ui::addr(pending.address.0),
                pending_oid_text(&pending.request, &pending.error),
                pending.name.clone().unwrap_or_default(),
            ]);
        }
        print_padded_table(builder);
    }
    for problem in &oids.problems {
        outln!("({problem})");
    }
}

fn status_text(status: u32) -> String {
    match ntstatus_name(status) {
        Some(name) => format!("{status:#x} ({name})"),
        None => format!("{status:#x}"),
    }
}

fn print_nbl(nbl: &NdisNbl) {
    field("NBL", ui::addr(nbl.address.0));
    field("Next", addr_or_none(nbl.next));
    field("Parent", addr_or_none(nbl.parent));
    field(
        "Source",
        match &nbl.source {
            Some(source) => format!("{}  {source}", ui::addr(nbl.source_handle.0)),
            None => addr_or_none(nbl.source_handle),
        },
    );
    field("Pool", addr_or_none(nbl.pool));
    field("Context", addr_or_none(nbl.context));
    let names = nbl.nbl_flag_names();
    field(
        "Flags",
        format!(
            "{:#x}, NblFlags {:#x}{}",
            nbl.flags,
            nbl.nbl_flags,
            if names.is_empty() {
                String::new()
            } else {
                format!(" ({})", names.join(" "))
            }
        ),
    );
    field("Status", status_text(nbl.status));
    field("Child references", nbl.child_ref_count);
    outln!();
    outln!("{} ({})", ui::label("NET_BUFFERs"), nbl.net_buffers.len());
    if !nbl.net_buffers.is_empty() {
        let mut builder = Builder::default();
        builder.push_record([
            "NET_BUFFER",
            "Length",
            "Offset",
            "Current MDL",
            "MDL offset",
            "MDL chain",
        ]);
        for nb in &nbl.net_buffers {
            builder.push_record([
                ui::addr(nb.address.0),
                format!("{:#x}", nb.data_length),
                format!("{:#x}", nb.data_offset),
                addr_or_none(nb.current_mdl),
                format!("{:#x}", nb.current_mdl_offset),
                addr_or_none(nb.mdl_chain),
            ]);
        }
        print_padded_table(builder);
    }
    print_stopped("NET_BUFFER chain", &nbl.net_buffers_stopped);
}

fn print_nbl_chain(chain: &NdisNblChain) {
    let mut builder = Builder::default();
    builder.push_record(["NBL", "NET_BUFFERs", "Bytes", "Status", "Source"]);
    for nbl in &chain.nbls {
        let bytes: u64 = nbl
            .net_buffers
            .iter()
            .map(|nb| u64::from(nb.data_length))
            .sum();
        builder.push_record([
            ui::addr(nbl.address.0),
            nbl.net_buffers.len().to_string(),
            format!("{bytes:#x}"),
            status_text(nbl.status),
            nbl.source
                .clone()
                .unwrap_or_else(|| addr_or_none(nbl.source_handle)),
        ]);
    }
    print_padded_table(builder);
    print_stopped("NBL chain", &chain.stopped);
}

/// Each NET_BUFFER's data as rows of 16 bytes, by offset into the frame,
/// when it was read (`-data`).
fn print_nbl_data(nbl: &NdisNbl) {
    let mode = MemoryDisplayMode::bytes();
    let read = nbl
        .net_buffers
        .iter()
        .filter(|nb| nb.data.is_some() || nb.data_error.is_some());
    for nb in read {
        let shown = (nb.data_length as usize).min(MAX_NET_BUFFER_DATA);
        let mut title = format!(
            "{} {} ({:#x} bytes",
            ui::label("Data of NET_BUFFER"),
            ui::addr(nb.address.0),
            nb.data_length
        );
        if shown < nb.data_length as usize {
            title.push_str(&format!(", the first {shown:#x} shown"));
        }
        outln!("{title})");
        let data = match (&nb.data, &nb.data_error) {
            (Some(data), _) => data,
            (None, error) => {
                error!(
                    "NET_BUFFER {:#x}: {}",
                    nb.address.0,
                    error.as_deref().unwrap_or_default()
                );
                continue;
            }
        };
        for (row, chunk) in data.chunks(mode.bytes_per_row()).enumerate() {
            out!("{:04x}  ", row * mode.bytes_per_row());
            row_items(row, chunk, None, &mode, |_, text| out!("{text}"));
            out!(" ");
            row_ascii(row, chunk, None, &mode, |cell| match cell {
                AsciiCell::Unreadable => out!("?"),
                AsciiCell::Char(character) => out!("{character}"),
                AsciiCell::Dot => out!("{}", ui::muted(".")),
            });
            outln!();
        }
        outln!();
    }
}
