//! Neutral value-tree views for KMDF (`!wdfkd.*`): client drivers, handles,
//! devices, queues, and In-Flight Recorder logs.

use super::shape::{Hex, shapes};
use crate::target::etw::{format_filetime_precise, format_guid};
use crate::target::wdf as target;
use crate::types::VirtAddr;

shapes! {
    /// A PDB enum value and its name.
    WdfState {
        value: Hex,
        /// `None` when the enum has no name for `value`.
        name: Option<String>,
    }

    /// A KMDF version.
    WdfVersion {
        major: u32,
        minor: u32,
        build: u32,
    }

    /// A KMDF client driver (`_FX_DRIVER_GLOBALS`).
    WdfClient {
        /// The `_FX_DRIVER_GLOBALS`.
        globals: VirtAddr,
        /// `Public.DriverName`. `None` if it is empty or not printable.
        name: Option<String>,
        /// The `FxDriver`. `None` before the driver calls `WdfDriverCreate`.
        driver: Option<VirtAddr>,
        /// The WDFDRIVER handle (`Public.Driver`).
        wdf_driver: Option<Hex>,
        driver_object: VirtAddr,
        /// The `DRIVER_OBJECT`'s name (`\\Driver\\kdnic`).
        driver_object_name: Option<String>,
        /// The `FxDriver`'s registry path.
        registry_path: Option<String>,
        /// The KMDF version that the driver bound to (`WdfBindInfo->Version`).
        version: Option<WdfVersion>,
        image_base: VirtAddr,
        /// Bytes.
        image_size: Hex,
        /// The `_WDF_IFR_HEADER` of the IFR log (`WdfLogHeader`). `None` if the
        /// driver has no IFR log.
        log_header: Option<VirtAddr>,
        /// `FxVerifierOn`.
        verifier_on: bool,
        /// The parts of the globals that failed validation, whose related
        /// fields are `None`.
        problems: Vec<String>,
    }

    /// The KMDF client drivers on `FxLibraryGlobals.FxDriverGlobalsList`
    /// (`!wdfkd.wdfldr`).
    WdfLoader {
        /// `Wdf01000!FxLibraryGlobals`.
        library_globals: VirtAddr,
        clients: Vec<WdfClient>,
        /// Why the walk of the client list stopped before the list head. `None`
        /// if the walk completed.
        stopped: Option<String>,
    }

    /// The address, handle, and type of a KMDF object, when ntoseye can read
    /// them.
    WdfObjectRef {
        address: VirtAddr,
        /// `None` for an object that has no handle or that ntoseye cannot read.
        handle: Option<Hex>,
        /// The `FX_OBJECT_TYPES` name of its `m_Type`.
        type_name: Option<String>,
    }

    /// A device object of a driver, and its related WDFDEVICE.
    WdfDriverDevice {
        device_object: VirtAddr,
        /// The `FxDevice`. `None` if the device object is not a WDFDEVICE of
        /// this driver.
        device: Option<VirtAddr>,
        /// The WDFDEVICE handle.
        handle: Option<Hex>,
        /// `FDO`, `filter`, `PDO`, or `control`.
        kind: Option<&'static str>,
        /// `m_CurrentPnpState` (`_WDF_DEVICE_PNP_STATE`).
        pnp_state: Option<WdfState>,
        /// Why the device object does not link to a WDFDEVICE of this driver.
        unlinked: Option<String>,
    }

    /// A KMDF client driver and its device objects (`!wdfkd.wdfdriverinfo`).
    WdfDriverInfo {
        client: WdfClient,
        /// The driver object's `DeviceObject`/`NextDevice` chain.
        devices: Vec<WdfDriverDevice>,
        /// Why the walk of the device chain stopped before a null link. `None`
        /// if the walk got to a null link.
        devices_stopped: Option<String>,
    }

    /// An object's context (`FxContextHeader`).
    WdfContext {
        /// The `FxContextHeader`.
        header: VirtAddr,
        /// The context itself.
        context: VirtAddr,
        /// The `_WDF_OBJECT_CONTEXT_TYPE_INFO`. `None` for a header that has no
        /// context type.
        type_info: Option<VirtAddr>,
        /// The context type's name.
        name: Option<String>,
        /// Bytes.
        size: Option<Hex>,
    }

    /// A WDF handle and the object it names (`!wdfkd.wdfhandle`).
    WdfHandle {
        handle: Hex,
        /// The `FxObject`.
        address: VirtAddr,
        /// For an offset handle, the `WDFOBJECT_OFFSET` value to subtract from
        /// the address that the handle points to.
        offset: Option<Hex<u16>>,
        /// `m_Type`.
        type_value: Hex<u16>,
        /// Its `FX_OBJECT_TYPES` name.
        type_name: String,
        /// `m_ObjectSize`: the size of the object and its extra bytes.
        object_size: Hex<u16>,
        refcount: i32,
        /// `m_ObjectState` (`FxObjectState`).
        state: WdfState,
        /// `m_ObjectFlags`.
        flags: Hex<u16>,
        /// The `FXOBJECT_FLAGS` set in `flags`.
        flag_names: Vec<String>,
        /// The owning driver's `_FX_DRIVER_GLOBALS`.
        globals: VirtAddr,
        /// The owning driver's name, when it has one.
        driver: Option<String>,
        parent: Option<WdfObjectRef>,
        contexts: Vec<WdfContext>,
        /// Why the walk of the context header chain stopped before a null
        /// `NextHeader`. `None` if the walk got to a null `NextHeader`.
        contexts_stopped: Option<String>,
    }

    /// A device's queue.
    WdfQueueSummary {
        /// The WDFQUEUE handle.
        handle: Hex,
        /// The `FxIoQueue`.
        address: VirtAddr,
        /// `_WDF_IO_QUEUE_DISPATCH_TYPE`.
        dispatch_type: WdfState,
        power_managed: bool,
        /// Requests waiting in the queue.
        pending: i32,
        /// Requests the driver owns.
        driver_owned: i32,
        /// Whether it is the default queue of the device.
        is_default: bool,
    }

    /// A WDFDEVICE with its device objects, state machines, and queues
    /// (`!wdfkd.wdfdevice`).
    WdfDevice {
        handle: Hex,
        /// The `FxDevice`.
        address: VirtAddr,
        /// The owning driver's name, when it has one.
        driver: Option<String>,
        /// The owning driver's `_FX_DRIVER_GLOBALS`.
        globals: VirtAddr,
        /// `FDO`, `filter`, `PDO`, or `control`.
        kind: &'static str,
        device_object: VirtAddr,
        /// The device object this one is attached to.
        attached_device: VirtAddr,
        /// The device stack's PDO.
        physical_device: VirtAddr,
        device_name: Option<String>,
        /// A PDO's parent WDFDEVICE.
        parent: Option<WdfObjectRef>,
        /// `_WDF_DEVICE_PNP_STATE`.
        pnp_state: WdfState,
        /// `_WDF_DEVICE_POWER_STATE`.
        power_state: WdfState,
        /// `_WDF_DEVICE_POWER_POLICY_STATE`.
        power_policy_state: WdfState,
        /// The `FxPkgPnp`. Null for a control device.
        pkg_pnp: VirtAddr,
        /// `_DEVICE_POWER_STATE`.
        device_power_state: Option<WdfState>,
        /// `_SYSTEM_POWER_STATE`.
        system_power_state: Option<WdfState>,
        /// The `FxPkgIo`.
        pkg_io: VirtAddr,
        /// The default queue's WDFQUEUE handle.
        default_queue: Option<Hex>,
        queues: Vec<WdfQueueSummary>,
        /// Why the walk of the queue list stopped before the list head. `None`
        /// if the walk completed.
        queues_stopped: Option<String>,
        /// An FDO's default child list (WDFCHILDLIST).
        default_child_list: Option<Hex>,
        /// An FDO's static child list (WDFCHILDLIST).
        static_child_list: Option<Hex>,
    }

    /// A request on a queue's list.
    WdfRequest {
        /// The WDFREQUEST handle.
        handle: Hex,
        /// The `FxRequest`.
        address: VirtAddr,
        irp: VirtAddr,
    }

    /// A queue event callback.
    WdfCallback {
        /// `EvtIoRead`, ...
        name: &'static str,
        address: VirtAddr,
        symbol: Option<String>,
    }

    /// A WDFQUEUE with its configuration, state, and requests
    /// (`!wdfkd.wdfqueue`).
    WdfQueue {
        handle: Hex,
        /// The `FxIoQueue`.
        address: VirtAddr,
        /// The owning driver's name, when it has one.
        driver: Option<String>,
        device: Option<WdfObjectRef>,
        /// `_WDF_IO_QUEUE_DISPATCH_TYPE`.
        dispatch_type: WdfState,
        /// `m_QueueState`.
        state: Hex,
        /// The `_FX_IO_QUEUE_STATE` bits set in `state`.
        state_names: Vec<String>,
        /// `FxIoQueuePowerState`.
        power_state: WdfState,
        power_managed: bool,
        allow_zero_length_requests: bool,
        deleted: bool,
        /// `_WDF_EXECUTION_LEVEL`.
        execution_level: WdfState,
        /// `_WDF_SYNCHRONIZATION_SCOPE`.
        synchronization_scope: WdfState,
        /// `m_MaxParallelQueuePresentedRequests`.
        max_parallel_requests: u64,
        /// Requests waiting in the queue.
        pending_count: i32,
        /// Requests the driver marked cancelable.
        driver_cancelable_count: i32,
        /// Requests the driver owns.
        driver_owned_count: i32,
        two_phase_completions: i32,
        /// The callbacks the driver set.
        callbacks: Vec<WdfCallback>,
        /// Requests waiting in the queue.
        pending: Vec<WdfRequest>,
        /// Why the walk stopped early. `None` if the walk completed.
        pending_stopped: Option<String>,
        /// Requests the driver marked cancelable.
        driver_cancelable: Vec<WdfRequest>,
        /// Why the walk stopped early. `None` if the walk completed.
        driver_cancelable_stopped: Option<String>,
        /// Requests presented to the driver.
        driver_owned: Vec<WdfRequest>,
        /// Why the walk stopped early. `None` if the walk completed.
        driver_owned_stopped: Option<String>,
    }

    /// An In-Flight Recorder record.
    WdfLogRecord {
        /// Its offset in the log.
        offset: Hex,
        sequence: i32,
        /// The FILETIME. `None` for an 'LR' record, because it has no
        /// timestamp.
        timestamp: Option<u64>,
        /// `timestamp` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`).
        timestamp_utc: Option<String>,
        message_guid: String,
        message_number: u16,
        /// The TMF message's provider, when a loaded PDB declares it.
        provider: Option<String>,
        /// Its `FUNC=`.
        function: Option<String>,
        /// Its `LEVEL=`.
        level: Option<String>,
        /// Its `FLAGS=`.
        flags: Option<String>,
        /// The formatted message.
        text: Option<String>,
        /// Why the message is not formatted.
        error: Option<String>,
        /// The argument bytes, as hex.
        args: String,
    }

    /// The In-Flight Recorder log of a client driver, oldest record first
    /// (`!wdfkd.wdflogdump`).
    WdfLog {
        driver: String,
        /// The `_FX_DRIVER_GLOBALS`.
        globals: VirtAddr,
        /// The `_WDF_IFR_HEADER`.
        header: VirtAddr,
        /// The record area.
        base: VirtAddr,
        /// The size of the record area, in bytes.
        size: Hex,
        /// The offset where KMDF writes the next record.
        current: Hex<u16>,
        /// The newest record's offset.
        previous: Hex<u16>,
        /// The header's sequence number.
        sequence: i32,
        /// Whether the records have timestamps ('L2').
        use_timestamps: bool,
        records: Vec<WdfLogRecord>,
        /// Why the walk ended: `empty`, `first_record`, `overwritten`, or
        /// `corrupt`.
        end: &'static str,
        /// The item that failed validation, when `end` is `corrupt`.
        corruption: Option<String>,
    }
}

fn state(value: &target::WdfEnumValue) -> WdfState {
    WdfState {
        value: value.value,
        name: value.name.clone(),
    }
}

fn client(client: &target::WdfClient) -> WdfClient {
    WdfClient {
        globals: client.globals,
        name: client.name.clone(),
        driver: client.driver,
        wdf_driver: client.wdf_driver,
        driver_object: client.driver_object,
        driver_object_name: client.driver_object_name.clone(),
        registry_path: client.registry_path.clone(),
        version: client.version.map(|version| WdfVersion {
            major: version.major,
            minor: version.minor,
            build: version.build,
        }),
        image_base: client.image_base,
        image_size: client.image_size,
        log_header: client.log_header,
        verifier_on: client.verifier_on,
        problems: client.problems.clone(),
    }
}

fn object_ref(object: &target::WdfObjectRef) -> WdfObjectRef {
    WdfObjectRef {
        address: object.address,
        handle: object.handle,
        type_name: object.type_name.clone(),
    }
}

/// Render `!wdfkd.wdfldr`.
pub fn loader(detail: &target::WdfLoader) -> WdfLoader {
    WdfLoader {
        library_globals: detail.library_globals,
        clients: detail.clients.iter().map(client).collect(),
        stopped: detail.stopped.clone(),
    }
}

/// Render `!wdfkd.wdfdriverinfo`.
pub fn driver_info(detail: &target::WdfDriverInfo) -> WdfDriverInfo {
    WdfDriverInfo {
        client: client(&detail.client),
        devices: detail
            .devices
            .iter()
            .map(|device| WdfDriverDevice {
                device_object: device.device_object,
                device: device.device,
                handle: device.handle,
                kind: device.kind,
                pnp_state: device.pnp_state.as_ref().map(state),
                unlinked: device.unlinked.clone(),
            })
            .collect(),
        devices_stopped: detail.devices_stopped.clone(),
    }
}

/// Render `!wdfkd.wdfhandle`.
pub fn handle(detail: &target::WdfObject) -> WdfHandle {
    WdfHandle {
        handle: detail.handle,
        address: detail.address,
        offset: detail.offset,
        type_value: detail.type_value,
        type_name: detail.type_name.clone(),
        object_size: detail.object_size,
        refcount: detail.refcount,
        state: state(&detail.state),
        flags: detail.flags,
        flag_names: detail.flag_names.clone(),
        globals: detail.globals,
        driver: detail.driver.clone(),
        parent: detail.parent.as_ref().map(object_ref),
        contexts: detail
            .contexts
            .iter()
            .map(|context| WdfContext {
                header: context.header,
                context: context.context,
                type_info: context.type_info,
                name: context.name.clone(),
                size: context.size,
            })
            .collect(),
        contexts_stopped: detail.contexts_stopped.clone(),
    }
}

/// Render `!wdfkd.wdfdevice`.
pub fn device(detail: &target::WdfDeviceDetail) -> WdfDevice {
    WdfDevice {
        handle: detail.handle,
        address: detail.address,
        driver: detail.driver.clone(),
        globals: detail.globals,
        kind: detail.kind,
        device_object: detail.device_object,
        attached_device: detail.attached_device,
        physical_device: detail.physical_device,
        device_name: detail.device_name.clone(),
        parent: detail.parent.as_ref().map(object_ref),
        pnp_state: state(&detail.pnp_state),
        power_state: state(&detail.power_state),
        power_policy_state: state(&detail.power_policy_state),
        pkg_pnp: detail.pkg_pnp,
        device_power_state: detail.device_power_state.as_ref().map(state),
        system_power_state: detail.system_power_state.as_ref().map(state),
        pkg_io: detail.pkg_io,
        default_queue: detail.default_queue,
        queues: detail
            .queues
            .iter()
            .map(|queue| WdfQueueSummary {
                handle: queue.handle,
                address: queue.address,
                dispatch_type: state(&queue.dispatch_type),
                power_managed: queue.power_managed,
                pending: queue.pending,
                driver_owned: queue.driver_owned,
                is_default: queue.is_default,
            })
            .collect(),
        queues_stopped: detail.queues_stopped.clone(),
        default_child_list: detail.default_child_list,
        static_child_list: detail.static_child_list,
    }
}

fn requests(list: &target::WdfRequestList) -> Vec<WdfRequest> {
    list.requests
        .iter()
        .map(|request| WdfRequest {
            handle: request.handle,
            address: request.address,
            irp: request.irp,
        })
        .collect()
}

/// Render `!wdfkd.wdfqueue`.
pub fn queue(detail: &target::WdfQueueDetail) -> WdfQueue {
    WdfQueue {
        handle: detail.handle,
        address: detail.address,
        driver: detail.driver.clone(),
        device: detail.device.as_ref().map(object_ref),
        dispatch_type: state(&detail.dispatch_type),
        state: detail.state,
        state_names: detail.state_names.clone(),
        power_state: state(&detail.power_state),
        power_managed: detail.power_managed,
        allow_zero_length_requests: detail.allow_zero_length_requests,
        deleted: detail.deleted,
        execution_level: state(&detail.execution_level),
        synchronization_scope: state(&detail.synchronization_scope),
        max_parallel_requests: detail.max_parallel_requests,
        pending_count: detail.pending_count,
        driver_cancelable_count: detail.driver_cancelable_count,
        driver_owned_count: detail.driver_owned_count,
        two_phase_completions: detail.two_phase_completions,
        callbacks: detail
            .callbacks
            .iter()
            .map(|callback| WdfCallback {
                name: callback.name,
                address: callback.address,
                symbol: callback.symbol.clone(),
            })
            .collect(),
        pending: requests(&detail.pending),
        pending_stopped: detail.pending.stopped.clone(),
        driver_cancelable: requests(&detail.driver_cancelable),
        driver_cancelable_stopped: detail.driver_cancelable.stopped.clone(),
        driver_owned: requests(&detail.driver_owned),
        driver_owned_stopped: detail.driver_owned.stopped.clone(),
    }
}

fn log_record(entry: &target::WdfLogEntry) -> WdfLogRecord {
    let record = &entry.record;
    let message = entry.message.as_deref();
    WdfLogRecord {
        offset: record.offset as u64,
        sequence: record.sequence,
        timestamp: record.timestamp,
        timestamp_utc: record.timestamp.and_then(format_filetime_precise),
        message_guid: format_guid(&record.message_guid),
        message_number: record.message_number,
        provider: message.map(|message| message.provider.clone()),
        function: message.and_then(|message| message.function.clone()),
        level: message.and_then(|message| message.level.clone()),
        flags: message.and_then(|message| message.flags.clone()),
        text: entry.text.as_ref().ok().cloned(),
        error: entry.text.as_ref().err().cloned(),
        args: record.args.iter().map(|byte| format!("{byte:02x}")).collect(),
    }
}

/// Render `!wdfkd.wdflogdump`.
pub fn log(detail: &target::WdfLogDump) -> WdfLog {
    let (end, corruption) = match &detail.end {
        target::IfrEnd::Empty => ("empty", None),
        target::IfrEnd::FirstRecord => ("first_record", None),
        target::IfrEnd::Overwritten => ("overwritten", None),
        target::IfrEnd::Corrupt(why) => ("corrupt", Some(why.clone())),
    };
    WdfLog {
        driver: detail.driver.clone(),
        globals: detail.globals,
        header: detail.header,
        base: detail.base,
        size: detail.size,
        current: detail.current,
        previous: detail.previous,
        sequence: detail.sequence,
        use_timestamps: detail.use_timestamps,
        records: detail.entries.iter().map(log_record).collect(),
        end,
        corruption,
    }
}
