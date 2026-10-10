//! NDIS (`!ndiskd.*`) as SDK records: miniports, miniport drivers, filter
//! modules, filter drivers, protocols, pending OID requests, and
//! NET_BUFFER_LISTs.

use super::shape::{Hex, shapes};
use crate::ntstatus::ntstatus_name;
use crate::target::ndis as target;
use crate::target::ndis::{NdisOidOwner, nbl_flag_names, oid_name};
use crate::types::VirtAddr;

shapes! {
    /// A block a list names but that does not read.
    NdisUnreadable {
        address: VirtAddr,
        error: String,
    }

    /// A miniport as `!ndiskd.miniports` lists it (`_NDIS_MINIPORT_BLOCK`).
    NdisMiniport {
        address: VirtAddr,
        /// `MiniportName`, the adapter's device name.
        name: String,
        /// The adapter's friendly name.
        friendly_name: Option<String>,
        /// The `_NDIS_M_DRIVER_BLOCK`.
        driver: VirtAddr,
        /// The miniport driver's service name.
        driver_name: Option<String>,
        /// `Running`, `Pausing`, `Paused`, `Restarting`, `Initializing`, or
        /// `Halted`.
        state: String,
        pnp_state: String,
        media_connect: String,
        connected: bool,
        /// Bits per second; `0xffffffffffffffff` when the miniport has not
        /// reported one.
        xmit_link_speed: u64,
        rcv_link_speed: u64,
        /// The device power state (`D0`).
        power: String,
        if_index: u32,
    }

    /// The miniports on `ndis!ndisMiniportList`.
    NdisMiniports {
        miniports: Vec<NdisMiniport>,
        unreadable: Vec<NdisUnreadable>,
        /// Why the walk stopped before the end of the list.
        stopped: Option<String>,
    }

    /// An `_NDIS_OID_REQUEST`.
    NdisOidRequest {
        address: VirtAddr,
        /// `QueryInformation`, `SetInformation`, `Method`, ...
        request_type: String,
        oid: Hex<u32>,
        /// The `ntddndis.h` name of the OID.
        oid_name: Option<&'static str>,
        port: u32,
        /// Seconds; 0 lets NDIS pick one.
        timeout: u32,
        buffer: VirtAddr,
        /// `InformationBufferLength`, or a method request's input length.
        buffer_length: u32,
        /// A method request's `OutputBufferLength`.
        output_length: Option<u32>,
        /// A method request's `MethodId`.
        method_id: Option<Hex<u32>>,
    }

    /// A filter module on a miniport's stack (`_NDIS_FILTER_BLOCK`).
    NdisFilter {
        address: VirtAddr,
        /// `FilterFriendlyName`.
        name: Option<String>,
        /// The `_NDIS_FILTER_DRIVER_BLOCK`.
        driver: VirtAddr,
        driver_image: Option<String>,
        miniport: VirtAddr,
        miniport_name: Option<String>,
        state: String,
        /// `FilterModuleContext`, the filter driver's own context.
        context: VirtAddr,
        /// The OID request the filter has not completed.
        pending_oid: Option<NdisOidRequest>,
        /// Why `pending_oid` does not decode.
        pending_oid_error: Option<String>,
    }

    /// A protocol's binding to a miniport (`_NDIS_OPEN_BLOCK`).
    NdisOpen {
        address: VirtAddr,
        /// The `_NDIS_PROTOCOL_BLOCK`.
        protocol: VirtAddr,
        protocol_name: Option<String>,
        /// `ProtocolBindingContext`.
        context: VirtAddr,
    }

    /// A miniport driver (`_NDIS_M_DRIVER_BLOCK`).
    NdisDriver {
        address: VirtAddr,
        service_name: String,
        image_name: String,
        /// The loaded module the driver's code is in, the name its PDB's
        /// types go by.
        module: Option<String>,
        driver_object: VirtAddr,
        /// The NDIS version it registered with (`6.50`).
        ndis_version: String,
        /// Its own version, from its NDIS 6 characteristics.
        driver_version: Option<String>,
        /// Its miniports, on its `MiniportQueue`.
        miniports: Vec<VirtAddr>,
        miniports_stopped: Option<String>,
    }

    /// One miniport in detail (`!ndiskd.miniport`).
    NdisMiniportDetail {
        miniport: NdisMiniport,
        /// Whether it is on `ndis!ndisMiniportList`.
        listed: bool,
        ndis_version: String,
        /// `MiniportAdapterContext`, the miniport driver's own context.
        adapter_context: VirtAddr,
        driver: Option<NdisDriver>,
        /// Why `driver` is `None`.
        driver_error: Option<String>,
        /// The FDO NDIS created; null for a virtual miniport.
        device_object: VirtAddr,
        pdo: VirtAddr,
        instance_id: Option<String>,
        medium: String,
        physical_medium: String,
        duplex: String,
        oper_status: String,
        net_luid: Hex,
        flags: Hex<u32>,
        pnp_flags: Hex<u32>,
        references: Option<u64>,
        /// `ResetStatus`, the NTSTATUS of the last reset.
        reset_status: Hex<u32>,
        internal_resets: u64,
        miniport_resets: u64,
        pending_oid: Option<NdisOidRequest>,
        pending_oid_error: Option<String>,
        /// `PendingReturnNBLCount`.
        pending_return_nbls: u32,
        /// The filter stack, top first.
        filters: Vec<NdisFilter>,
        filters_stopped: Option<String>,
        num_opens: u32,
        opens: Vec<NdisOpen>,
        opens_stopped: Option<String>,
    }

    /// The miniport drivers on `ndis!ndisMiniDriverList`.
    NdisDrivers {
        drivers: Vec<NdisDriver>,
        unreadable: Vec<NdisUnreadable>,
        stopped: Option<String>,
    }

    /// A miniport driver and its miniports (`!ndiskd.minidriver`).
    NdisMinidriver {
        driver: NdisDriver,
        miniports: Vec<NdisMiniport>,
        unreadable: Vec<NdisUnreadable>,
    }

    /// The filter modules on `ndis!ndisGlobalFilterList`.
    NdisFilters {
        filters: Vec<NdisFilter>,
        unreadable: Vec<NdisUnreadable>,
        stopped: Option<String>,
    }

    /// One filter module in detail (`!ndiskd.filter`).
    NdisFilterDetail {
        filter: NdisFilter,
        /// Whether it is on `ndis!ndisGlobalFilterList`.
        listed: bool,
        /// The filter driver's friendly name.
        driver_name: Option<String>,
        /// The filter modules above and below it; null at the top and at the
        /// bottom.
        higher: VirtAddr,
        lower: VirtAddr,
        /// The link the filter last saw indicated from below.
        media_connect: String,
        xmit_link_speed: u64,
        rcv_link_speed: u64,
        if_index: u32,
        flags: Hex<u32>,
        references: Option<u64>,
        /// What NDIS dropped because the filter was not running.
        dropped_receive_nbls: i32,
        dropped_send_nbls: i32,
        dropped_status_indications: u32,
    }

    /// A filter driver (`_NDIS_FILTER_DRIVER_BLOCK`).
    NdisFilterDriver {
        address: VirtAddr,
        friendly_name: String,
        /// The filter's GUID.
        unique_name: String,
        service_name: String,
        image_name: String,
        module: Option<String>,
        driver_object: VirtAddr,
        /// `FilterDriverContext`.
        context: VirtAddr,
        flags: Hex<u32>,
        ndis_version: String,
        driver_version: String,
        /// Its filter modules, one for each miniport it is attached to.
        filters: Vec<VirtAddr>,
        filters_stopped: Option<String>,
    }

    /// The filter drivers on `ndis!ndisFilterDriverList`.
    NdisFilterDrivers {
        drivers: Vec<NdisFilterDriver>,
        unreadable: Vec<NdisUnreadable>,
        stopped: Option<String>,
    }

    /// A filter driver and its filter modules (`!ndiskd.filterdriver`).
    NdisFilterDriverDetail {
        driver: NdisFilterDriver,
        filters: Vec<NdisFilter>,
        unreadable: Vec<NdisUnreadable>,
    }

    /// A protocol driver (`_NDIS_PROTOCOL_BLOCK`).
    NdisProtocol {
        address: VirtAddr,
        name: String,
        image_name: Option<String>,
        ndis_version: String,
        driver_version: String,
        /// `ProtocolDriverContext`.
        context: VirtAddr,
        flags: Hex<u32>,
        /// `BindAdapterHandlerEx`.
        bind_handler: VirtAddr,
        /// Its bindings (`_NDIS_OPEN_BLOCK`), on its `OpenQueue`.
        opens: Vec<VirtAddr>,
        opens_stopped: Option<String>,
    }

    /// The protocol drivers on `ndis!ndisProtocolList`.
    NdisProtocols {
        protocols: Vec<NdisProtocol>,
        unreadable: Vec<NdisUnreadable>,
        stopped: Option<String>,
    }

    /// A protocol's binding, with the miniport it opened.
    NdisBinding {
        /// The `_NDIS_OPEN_BLOCK`.
        open: VirtAddr,
        miniport: VirtAddr,
        miniport_name: Option<String>,
        /// `ProtocolBindingContext`.
        context: VirtAddr,
    }

    /// One protocol driver in detail (`!ndiskd.protocol`).
    NdisProtocolDetail {
        protocol: NdisProtocol,
        /// Whether it is on `ndis!ndisProtocolList`.
        listed: bool,
        /// `BindAdapterHandlerEx` as a symbol.
        bind_handler_name: Option<String>,
        bindings: Vec<NdisBinding>,
        bindings_stopped: Option<String>,
    }

    /// An OID request a miniport or filter module has not completed.
    NdisPendingOid {
        /// `miniport` or `filter`.
        owner: &'static str,
        /// The miniport or filter block.
        address: VirtAddr,
        name: Option<String>,
        request: Option<NdisOidRequest>,
        /// Why `request` does not decode.
        error: Option<String>,
    }

    /// The pending OID requests of every miniport and filter module
    /// (`!ndiskd.oid`).
    NdisPendingOids {
        pending: Vec<NdisPendingOid>,
        /// How many miniports and filter modules were checked.
        miniports: usize,
        filters: usize,
        /// Why a walk stopped short, or a block that did not read.
        problems: Vec<String>,
    }

    /// A `_NET_BUFFER`.
    NdisNetBuffer {
        address: VirtAddr,
        next: VirtAddr,
        /// The MDL the data starts in, and where in it.
        current_mdl: VirtAddr,
        current_mdl_offset: u32,
        data_length: u32,
        /// Where the data starts from the start of `mdl_chain`.
        data_offset: u32,
        mdl_chain: VirtAddr,
    }

    /// A `_NET_BUFFER_LIST` (`!ndiskd.nbl`).
    NdisNbl {
        address: VirtAddr,
        next: VirtAddr,
        parent: VirtAddr,
        context: VirtAddr,
        pool: VirtAddr,
        /// The NDIS handle of the miniport, filter module, or binding that
        /// owns it on its way.
        source_handle: VirtAddr,
        /// What `source_handle` is, when NDIS knows it.
        source: Option<String>,
        flags: Hex<u32>,
        nbl_flags: Hex<u32>,
        /// The `NDIS_NBL_FLAGS_*` names of `nbl_flags`, without the prefix.
        nbl_flag_names: Vec<String>,
        child_ref_count: i32,
        status: Hex<u32>,
        status_name: Option<&'static str>,
        net_buffers: Vec<NdisNetBuffer>,
        net_buffers_stopped: Option<String>,
    }

    /// The NBLs on a `Next` chain.
    NdisNblChain {
        nbls: Vec<NdisNbl>,
        stopped: Option<String>,
    }
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
