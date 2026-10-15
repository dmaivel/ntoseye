//! NDIS (`!ndiskd.*`) as SDK records: miniports, miniport drivers, filter
//! modules, filter drivers, protocols, pending OID requests, and
//! NET_BUFFER_LISTs.

use ntoseye_macros::record;

use crate::ntstatus::ntstatus_name;
use crate::target::ndis as target;
use crate::target::ndis::{NdisOidOwner, nbl_flag_names, oid_name};
use crate::types::VirtAddr;

/// A block a list names but that does not read.
#[record]
pub struct NdisUnreadable {
    pub address: VirtAddr,
    pub error: String,
}

/// A miniport as `!ndiskd.miniports` lists it (`_NDIS_MINIPORT_BLOCK`).
#[record]
pub struct NdisMiniport {
    pub address: VirtAddr,
    /// `MiniportName`, the adapter's device name.
    pub name: String,
    /// The adapter's friendly name.
    pub friendly_name: Option<String>,
    /// The `_NDIS_M_DRIVER_BLOCK`.
    pub driver: VirtAddr,
    /// The miniport driver's service name.
    pub driver_name: Option<String>,
    /// `Running`, `Pausing`, `Paused`, `Restarting`, `Initializing`, or
    /// `Halted`.
    pub state: String,
    pub pnp_state: String,
    pub media_connect: String,
    pub connected: bool,
    /// Bits per second; `0xffffffffffffffff` when the miniport has not
    /// reported one.
    pub xmit_link_speed: u64,
    pub rcv_link_speed: u64,
    /// The device power state (`D0`).
    pub power: String,
    pub if_index: u32,
}

/// The miniports on `ndis!ndisMiniportList`.
#[record]
pub struct NdisMiniports {
    pub miniports: Vec<NdisMiniport>,
    pub unreadable: Vec<NdisUnreadable>,
    /// Why the walk stopped before the end of the list.
    pub stopped: Option<String>,
}

/// An `_NDIS_OID_REQUEST`.
#[record]
pub struct NdisOidRequest {
    pub address: VirtAddr,
    /// `QueryInformation`, `SetInformation`, `Method`, ...
    pub request_type: String,
    #[record(hex)]
    pub oid: u32,
    /// The `ntddndis.h` name of the OID.
    pub oid_name: Option<&'static str>,
    pub port: u32,
    /// Seconds; 0 lets NDIS pick one.
    pub timeout: u32,
    pub buffer: VirtAddr,
    /// `InformationBufferLength`, or a method request's input length.
    pub buffer_length: u32,
    /// A method request's `OutputBufferLength`.
    pub output_length: Option<u32>,
    /// A method request's `MethodId`.
    #[record(hex)]
    pub method_id: Option<u32>,
}

/// A filter module on a miniport's stack (`_NDIS_FILTER_BLOCK`).
#[record]
pub struct NdisFilter {
    pub address: VirtAddr,
    /// `FilterFriendlyName`.
    pub name: Option<String>,
    /// The `_NDIS_FILTER_DRIVER_BLOCK`.
    pub driver: VirtAddr,
    pub driver_image: Option<String>,
    pub miniport: VirtAddr,
    pub miniport_name: Option<String>,
    pub state: String,
    /// `FilterModuleContext`, the filter driver's own context.
    pub context: VirtAddr,
    /// The OID request the filter has not completed.
    pub pending_oid: Option<NdisOidRequest>,
    /// Why `pending_oid` does not decode.
    pub pending_oid_error: Option<String>,
}

/// A protocol's binding to a miniport (`_NDIS_OPEN_BLOCK`).
#[record]
pub struct NdisOpen {
    pub address: VirtAddr,
    /// The `_NDIS_PROTOCOL_BLOCK`.
    pub protocol: VirtAddr,
    pub protocol_name: Option<String>,
    /// `ProtocolBindingContext`.
    pub context: VirtAddr,
}

/// A miniport driver (`_NDIS_M_DRIVER_BLOCK`).
#[record]
pub struct NdisDriver {
    pub address: VirtAddr,
    pub service_name: String,
    pub image_name: String,
    /// The loaded module the driver's code is in, the name its PDB's
    /// types go by.
    pub module: Option<String>,
    pub driver_object: VirtAddr,
    /// The NDIS version it registered with (`6.50`).
    pub ndis_version: String,
    /// Its own version, from its NDIS 6 characteristics.
    pub driver_version: Option<String>,
    /// Its miniports, on its `MiniportQueue`.
    pub miniports: Vec<VirtAddr>,
    pub miniports_stopped: Option<String>,
}

/// One miniport in detail (`!ndiskd.miniport`).
#[record]
pub struct NdisMiniportDetail {
    pub miniport: NdisMiniport,
    /// Whether it is on `ndis!ndisMiniportList`.
    pub listed: bool,
    pub ndis_version: String,
    /// `MiniportAdapterContext`, the miniport driver's own context.
    pub adapter_context: VirtAddr,
    pub driver: Option<NdisDriver>,
    /// Why `driver` is `None`.
    pub driver_error: Option<String>,
    /// The FDO NDIS created; null for a virtual miniport.
    pub device_object: VirtAddr,
    pub pdo: VirtAddr,
    pub instance_id: Option<String>,
    pub medium: String,
    pub physical_medium: String,
    pub duplex: String,
    pub oper_status: String,
    #[record(hex)]
    pub net_luid: u64,
    #[record(hex)]
    pub flags: u32,
    #[record(hex)]
    pub pnp_flags: u32,
    pub references: Option<u64>,
    /// `ResetStatus`, the NTSTATUS of the last reset.
    #[record(hex)]
    pub reset_status: u32,
    pub internal_resets: u64,
    pub miniport_resets: u64,
    pub pending_oid: Option<NdisOidRequest>,
    pub pending_oid_error: Option<String>,
    /// `PendingReturnNBLCount`.
    pub pending_return_nbls: u32,
    /// The filter stack, top first.
    pub filters: Vec<NdisFilter>,
    pub filters_stopped: Option<String>,
    pub num_opens: u32,
    pub opens: Vec<NdisOpen>,
    pub opens_stopped: Option<String>,
}

/// The miniport drivers on `ndis!ndisMiniDriverList`.
#[record]
pub struct NdisDrivers {
    pub drivers: Vec<NdisDriver>,
    pub unreadable: Vec<NdisUnreadable>,
    pub stopped: Option<String>,
}

/// A miniport driver and its miniports (`!ndiskd.minidriver`).
#[record]
pub struct NdisMinidriver {
    pub driver: NdisDriver,
    pub miniports: Vec<NdisMiniport>,
    pub unreadable: Vec<NdisUnreadable>,
}

/// The filter modules on `ndis!ndisGlobalFilterList`.
#[record]
pub struct NdisFilters {
    pub filters: Vec<NdisFilter>,
    pub unreadable: Vec<NdisUnreadable>,
    pub stopped: Option<String>,
}

/// One filter module in detail (`!ndiskd.filter`).
#[record]
pub struct NdisFilterDetail {
    pub filter: NdisFilter,
    /// Whether it is on `ndis!ndisGlobalFilterList`.
    pub listed: bool,
    /// The filter driver's friendly name.
    pub driver_name: Option<String>,
    /// The filter modules above and below it; null at the top and at the
    /// bottom.
    pub higher: VirtAddr,
    pub lower: VirtAddr,
    /// The link the filter last saw indicated from below.
    pub media_connect: String,
    pub xmit_link_speed: u64,
    pub rcv_link_speed: u64,
    pub if_index: u32,
    #[record(hex)]
    pub flags: u32,
    pub references: Option<u64>,
    /// What NDIS dropped because the filter was not running.
    pub dropped_receive_nbls: i32,
    pub dropped_send_nbls: i32,
    pub dropped_status_indications: u32,
}

/// A filter driver (`_NDIS_FILTER_DRIVER_BLOCK`).
#[record]
pub struct NdisFilterDriver {
    pub address: VirtAddr,
    pub friendly_name: String,
    /// The filter's GUID.
    pub unique_name: String,
    pub service_name: String,
    pub image_name: String,
    pub module: Option<String>,
    pub driver_object: VirtAddr,
    /// `FilterDriverContext`.
    pub context: VirtAddr,
    #[record(hex)]
    pub flags: u32,
    pub ndis_version: String,
    pub driver_version: String,
    /// Its filter modules, one for each miniport it is attached to.
    pub filters: Vec<VirtAddr>,
    pub filters_stopped: Option<String>,
}

/// The filter drivers on `ndis!ndisFilterDriverList`.
#[record]
pub struct NdisFilterDrivers {
    pub drivers: Vec<NdisFilterDriver>,
    pub unreadable: Vec<NdisUnreadable>,
    pub stopped: Option<String>,
}

/// A filter driver and its filter modules (`!ndiskd.filterdriver`).
#[record]
pub struct NdisFilterDriverDetail {
    pub driver: NdisFilterDriver,
    pub filters: Vec<NdisFilter>,
    pub unreadable: Vec<NdisUnreadable>,
}

/// A protocol driver (`_NDIS_PROTOCOL_BLOCK`).
#[record]
pub struct NdisProtocol {
    pub address: VirtAddr,
    pub name: String,
    pub image_name: Option<String>,
    pub ndis_version: String,
    pub driver_version: String,
    /// `ProtocolDriverContext`.
    pub context: VirtAddr,
    #[record(hex)]
    pub flags: u32,
    /// `BindAdapterHandlerEx`.
    pub bind_handler: VirtAddr,
    /// Its bindings (`_NDIS_OPEN_BLOCK`), on its `OpenQueue`.
    pub opens: Vec<VirtAddr>,
    pub opens_stopped: Option<String>,
}

/// The protocol drivers on `ndis!ndisProtocolList`.
#[record]
pub struct NdisProtocols {
    pub protocols: Vec<NdisProtocol>,
    pub unreadable: Vec<NdisUnreadable>,
    pub stopped: Option<String>,
}

/// A protocol's binding, with the miniport it opened.
#[record]
pub struct NdisBinding {
    /// The `_NDIS_OPEN_BLOCK`.
    pub open: VirtAddr,
    pub miniport: VirtAddr,
    pub miniport_name: Option<String>,
    /// `ProtocolBindingContext`.
    pub context: VirtAddr,
}

/// One protocol driver in detail (`!ndiskd.protocol`).
#[record]
pub struct NdisProtocolDetail {
    pub protocol: NdisProtocol,
    /// Whether it is on `ndis!ndisProtocolList`.
    pub listed: bool,
    /// `BindAdapterHandlerEx` as a symbol.
    pub bind_handler_name: Option<String>,
    pub bindings: Vec<NdisBinding>,
    pub bindings_stopped: Option<String>,
}

/// An OID request a miniport or filter module has not completed.
#[record]
pub struct NdisPendingOid {
    /// `miniport` or `filter`.
    pub owner: &'static str,
    /// The miniport or filter block.
    pub address: VirtAddr,
    pub name: Option<String>,
    pub request: Option<NdisOidRequest>,
    /// Why `request` does not decode.
    pub error: Option<String>,
}

/// The pending OID requests of every miniport and filter module
/// (`!ndiskd.oid`).
#[record]
pub struct NdisPendingOids {
    pub pending: Vec<NdisPendingOid>,
    /// How many miniports and filter modules were checked.
    pub miniports: usize,
    pub filters: usize,
    /// Why a walk stopped short, or a block that did not read.
    pub problems: Vec<String>,
}

/// A `_NET_BUFFER`.
#[record]
pub struct NdisNetBuffer {
    pub address: VirtAddr,
    pub next: VirtAddr,
    /// The MDL the data starts in, and where in it.
    pub current_mdl: VirtAddr,
    pub current_mdl_offset: u32,
    pub data_length: u32,
    /// Where the data starts from the start of `mdl_chain`.
    pub data_offset: u32,
    pub mdl_chain: VirtAddr,
}

/// A `_NET_BUFFER_LIST` (`!ndiskd.nbl`).
#[record]
pub struct NdisNbl {
    pub address: VirtAddr,
    pub next: VirtAddr,
    pub parent: VirtAddr,
    pub context: VirtAddr,
    pub pool: VirtAddr,
    /// The NDIS handle of the miniport, filter module, or binding that
    /// owns it on its way.
    pub source_handle: VirtAddr,
    /// What `source_handle` is, when NDIS knows it.
    pub source: Option<String>,
    #[record(hex)]
    pub flags: u32,
    #[record(hex)]
    pub nbl_flags: u32,
    /// The `NDIS_NBL_FLAGS_*` names of `nbl_flags`, without the prefix.
    pub nbl_flag_names: Vec<String>,
    pub child_ref_count: i32,
    #[record(hex)]
    pub status: u32,
    pub status_name: Option<&'static str>,
    pub net_buffers: Vec<NdisNetBuffer>,
    pub net_buffers_stopped: Option<String>,
}

/// The NBLs on a `Next` chain.
#[record]
pub struct NdisNblChain {
    pub nbls: Vec<NdisNbl>,
    pub stopped: Option<String>,
}

fn version_text((major, minor): (u8, u8)) -> String {
    format!("{major}.{minor}")
}

fn unreadable(entry: &target::NdisUnreadable) -> NdisUnreadable {
    NdisUnreadable {
        address: entry.address,
        error: entry.error.clone(),
    }
}

/// Split a list's entries into the records that read and the ones that
/// did not.
fn split<T, U>(
    entries: &[Result<T, target::NdisUnreadable>],
    record: impl Fn(&T) -> U,
) -> (Vec<U>, Vec<NdisUnreadable>) {
    let mut read = Vec::new();
    let mut failed = Vec::new();
    for entry in entries {
        match entry {
            Ok(value) => read.push(record(value)),
            Err(entry) => failed.push(unreadable(entry)),
        }
    }
    (read, failed)
}

pub fn miniport(miniport: &target::NdisMiniport) -> NdisMiniport {
    NdisMiniport {
        address: miniport.address,
        name: miniport.name.clone(),
        friendly_name: miniport.friendly_name.clone(),
        driver: miniport.driver,
        driver_name: miniport.driver_name.clone(),
        state: miniport.state.clone(),
        pnp_state: miniport.pnp_state.clone(),
        media_connect: miniport.media_connect.clone(),
        connected: miniport.connected,
        xmit_link_speed: miniport.xmit_link_speed,
        rcv_link_speed: miniport.rcv_link_speed,
        power: miniport.power.clone(),
        if_index: miniport.if_index,
    }
}

pub fn miniports(list: &target::NdisMiniportList) -> NdisMiniports {
    let (miniports, unreadable) = split(&list.miniports, miniport);
    NdisMiniports {
        miniports,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

fn oid_request(request: &target::NdisOidRequest) -> NdisOidRequest {
    NdisOidRequest {
        address: request.address,
        request_type: request.request_type.clone(),
        oid: request.oid,
        oid_name: oid_name(request.oid),
        port: request.port,
        timeout: request.timeout,
        buffer: request.buffer,
        buffer_length: request.buffer_length,
        output_length: request.method.map(|(output, _)| output),
        method_id: request.method.map(|(_, method)| method),
    }
}

/// A pending OID request and why it does not decode.
fn pending(
    pending: &Option<Result<target::NdisOidRequest, String>>,
) -> (Option<NdisOidRequest>, Option<String>) {
    match pending {
        None => (None, None),
        Some(Ok(request)) => (Some(oid_request(request)), None),
        Some(Err(error)) => (None, Some(error.clone())),
    }
}

fn filter(filter: &target::NdisFilter) -> NdisFilter {
    let (pending_oid, pending_oid_error) = pending(&filter.pending_oid);
    NdisFilter {
        address: filter.address,
        name: filter.name.clone(),
        driver: filter.driver,
        driver_image: filter.driver_image.clone(),
        miniport: filter.miniport,
        miniport_name: filter.miniport_name.clone(),
        state: filter.state.clone(),
        context: filter.context,
        pending_oid,
        pending_oid_error,
    }
}

fn driver(driver: &target::NdisDriver) -> NdisDriver {
    NdisDriver {
        address: driver.address,
        service_name: driver.service_name.clone(),
        image_name: driver.image_name.clone(),
        module: driver.module.clone(),
        driver_object: driver.driver_object,
        ndis_version: version_text(driver.ndis_version),
        driver_version: driver.driver_version.map(version_text),
        miniports: driver.miniports.clone(),
        miniports_stopped: driver.miniports_stopped.clone(),
    }
}

pub fn miniport_detail(detail: &target::NdisMiniportDetail) -> NdisMiniportDetail {
    let (pending_oid, pending_oid_error) = pending(&detail.pending_oid);
    let (driver, driver_error) = match &detail.driver {
        Ok(value) => (Some(self::driver(value)), None),
        Err(error) => (None, Some(error.clone())),
    };
    NdisMiniportDetail {
        miniport: miniport(&detail.summary),
        listed: detail.listed,
        ndis_version: version_text(detail.ndis_version),
        adapter_context: detail.adapter_context,
        driver,
        driver_error,
        device_object: detail.device_object,
        pdo: detail.pdo,
        instance_id: detail.instance_id.clone(),
        medium: detail.medium.clone(),
        physical_medium: detail.physical_medium.clone(),
        duplex: detail.duplex.clone(),
        oper_status: detail.oper_status.clone(),
        net_luid: detail.net_luid,
        flags: detail.flags,
        pnp_flags: detail.pnp_flags,
        references: detail.references,
        reset_status: detail.reset_status,
        internal_resets: detail.resets.0,
        miniport_resets: detail.resets.1,
        pending_oid,
        pending_oid_error,
        pending_return_nbls: detail.pending_return_nbls,
        filters: detail.filters.iter().map(filter).collect(),
        filters_stopped: detail.filters_stopped.clone(),
        num_opens: detail.num_opens,
        opens: detail
            .opens
            .iter()
            .map(|open| NdisOpen {
                address: open.address,
                protocol: open.protocol,
                protocol_name: open.protocol_name.clone(),
                context: open.context,
            })
            .collect(),
        opens_stopped: detail.opens_stopped.clone(),
    }
}

pub fn drivers(list: &target::NdisDriverList) -> NdisDrivers {
    let (drivers, unreadable) = split(&list.drivers, driver);
    NdisDrivers {
        drivers,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

pub fn minidriver(
    detail: &target::NdisDriver,
    miniports: &[target::NdisMiniportListEntry],
) -> NdisMinidriver {
    let (miniports, unreadable) = split(miniports, miniport);
    NdisMinidriver {
        driver: driver(detail),
        miniports,
        unreadable,
    }
}

pub fn filters(list: &target::NdisFilterList) -> NdisFilters {
    let (filters, unreadable) = split(&list.filters, filter);
    NdisFilters {
        filters,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

pub fn filter_detail(detail: &target::NdisFilterDetail) -> NdisFilterDetail {
    NdisFilterDetail {
        filter: filter(&detail.filter),
        listed: detail.listed,
        driver_name: detail.driver_name.clone(),
        higher: detail.higher,
        lower: detail.lower,
        media_connect: detail.media_connect.clone(),
        xmit_link_speed: detail.xmit_link_speed,
        rcv_link_speed: detail.rcv_link_speed,
        if_index: detail.if_index,
        flags: detail.flags,
        references: detail.references,
        dropped_receive_nbls: detail.dropped_receive_nbls,
        dropped_send_nbls: detail.dropped_send_nbls,
        dropped_status_indications: detail.dropped_status_indications,
    }
}

fn filter_driver(driver: &target::NdisFilterDriver) -> NdisFilterDriver {
    NdisFilterDriver {
        address: driver.address,
        friendly_name: driver.friendly_name.clone(),
        unique_name: driver.unique_name.clone(),
        service_name: driver.service_name.clone(),
        image_name: driver.image_name.clone(),
        module: driver.module.clone(),
        driver_object: driver.driver_object,
        context: driver.context,
        flags: driver.flags,
        ndis_version: version_text(driver.ndis_version),
        driver_version: version_text(driver.driver_version),
        filters: driver.filters.clone(),
        filters_stopped: driver.filters_stopped.clone(),
    }
}

pub fn filter_drivers(list: &target::NdisFilterDriverList) -> NdisFilterDrivers {
    let (drivers, unreadable) = split(&list.drivers, filter_driver);
    NdisFilterDrivers {
        drivers,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

pub fn filter_driver_detail(
    detail: &target::NdisFilterDriver,
    filters: &[target::NdisFilterListEntry],
) -> NdisFilterDriverDetail {
    let (filters, unreadable) = split(filters, filter);
    NdisFilterDriverDetail {
        driver: filter_driver(detail),
        filters,
        unreadable,
    }
}

fn protocol(protocol: &target::NdisProtocol) -> NdisProtocol {
    NdisProtocol {
        address: protocol.address,
        name: protocol.name.clone(),
        image_name: protocol.image_name.clone(),
        ndis_version: version_text(protocol.ndis_version),
        driver_version: version_text(protocol.driver_version),
        context: protocol.context,
        flags: protocol.flags,
        bind_handler: protocol.bind_handler,
        opens: protocol.opens.clone(),
        opens_stopped: protocol.opens_stopped.clone(),
    }
}

pub fn protocols(list: &target::NdisProtocolList) -> NdisProtocols {
    let (protocols, unreadable) = split(&list.protocols, protocol);
    NdisProtocols {
        protocols,
        unreadable,
        stopped: list.stopped.clone(),
    }
}

pub fn protocol_detail(detail: &target::NdisProtocolDetail) -> NdisProtocolDetail {
    NdisProtocolDetail {
        protocol: protocol(&detail.protocol),
        listed: detail.listed,
        bind_handler_name: detail.bind_handler_name.clone(),
        bindings: detail
            .bindings
            .iter()
            .map(|binding| NdisBinding {
                open: binding.open,
                miniport: binding.miniport,
                miniport_name: binding.miniport_name.clone(),
                context: binding.context,
            })
            .collect(),
        bindings_stopped: detail.bindings_stopped.clone(),
    }
}

pub fn pending_oids(oids: &target::NdisPendingOids) -> NdisPendingOids {
    NdisPendingOids {
        pending: oids
            .pending
            .iter()
            .map(|entry| {
                let (request, error) = match &entry.request {
                    Ok(request) => (Some(oid_request(request)), None),
                    Err(error) => (None, Some(error.clone())),
                };
                NdisPendingOid {
                    owner: match entry.owner {
                        NdisOidOwner::Miniport => "miniport",
                        NdisOidOwner::Filter => "filter",
                    },
                    address: entry.address,
                    name: entry.name.clone(),
                    request,
                    error,
                }
            })
            .collect(),
        miniports: oids.miniports,
        filters: oids.filters,
        problems: oids.problems.clone(),
    }
}

pub fn nbl(nbl: &target::NdisNbl) -> NdisNbl {
    NdisNbl {
        address: nbl.address,
        next: nbl.next,
        parent: nbl.parent,
        context: nbl.context,
        pool: nbl.pool,
        source_handle: nbl.source_handle,
        source: nbl.source.clone(),
        flags: nbl.flags,
        nbl_flags: nbl.nbl_flags,
        nbl_flag_names: nbl_flag_names(nbl.nbl_flags),
        child_ref_count: nbl.child_ref_count,
        status: nbl.status,
        status_name: ntstatus_name(nbl.status),
        net_buffers: nbl
            .net_buffers
            .iter()
            .map(|nb| NdisNetBuffer {
                address: nb.address,
                next: nb.next,
                current_mdl: nb.current_mdl,
                current_mdl_offset: nb.current_mdl_offset,
                data_length: nb.data_length,
                data_offset: nb.data_offset,
                mdl_chain: nb.mdl_chain,
            })
            .collect(),
        net_buffers_stopped: nbl.net_buffers_stopped.clone(),
    }
}

pub fn nbl_chain(nbls: &[target::NdisNbl], stopped: &Option<String>) -> NdisNblChain {
    NdisNblChain {
        nbls: nbls.iter().map(nbl).collect(),
        stopped: stopped.clone(),
    }
}
