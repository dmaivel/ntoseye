//! Object- and I/O-manager [`View`] builders: IRPs, driver and
//! device objects, object headers, handles, file objects, executive
//! resources, notification callbacks, service tables, and ALPC ports.

use super::process::process;
use super::shape::{Diag, Hex, Keyed, shapes};
use super::list::{ListEnd, list_termination};
use crate::target::alpc::{
    AlpcConnection as AlpcConnectionDetail, AlpcField, AlpcMessageDetail, AlpcPortDetail,
    AlpcPortKind, AlpcProcessPorts as AlpcProcessPortsDetail, lpc_message_type_name,
};
use crate::target::htrace::{HandleTraceDetail, handle_trace_kind_name};
use crate::target::irpfind::{IrpFindDetail, IrpFindEntry, IrpPool};
use crate::target::object::{
    DeviceObjectDetail, DriverObjectDetail, DriverObjectInfo, FileObjectDetail, HandleEntryDetail,
    HandleTableSummary, IoStackLocationInfo, IrpHit, IrpInfo, NotifyCallback as NotifyCallbackInfo,
    ObjectDetail, ResourceDetail, ResourceListSummary, ResourceOwner as ResourceOwnerInfo,
    SsdtTable as SsdtTableInfo,
};
use crate::target::{Target, irp_major_function_name, kthread_state_name, wait_reason_name};
use crate::types::VirtAddr;

shapes! {
    /// An `_IO_STACK_LOCATION`, which is the part of an IRP for one driver.
    IoStackLocation {
        address: VirtAddr,
        /// The `IRP_MJ_*` code.
        major_function: u8,
        /// The name of the major function (`IRP_MJ_READ`, ...).
        major_function_name: String,
        minor_function: u8,
        device_object: VirtAddr,
        file_object: VirtAddr,
        completion_routine: VirtAddr,
        /// The context argument of the completion routine.
        context: VirtAddr,
    }

    /// An `_IRP` and its current I/O stack location (`!irp`).
    Irp {
        address: VirtAddr,
        /// `Type`. For a valid IRP, this is `IO_TYPE_IRP` (6).
        r#type: u16,
        /// `Size` in bytes. The size includes the stack locations.
        size: u16,
        stack_count: u8,
        /// `CurrentLocation`. After the IRP completes, it is more than `stack_count`.
        current_location: u8,
        pending_returned: bool,
        /// 0 for `KernelMode`, 1 for `UserMode`.
        requestor_mode: u8,
        /// `IoStatus.Status` as an NTSTATUS. None if ntoseye cannot read it.
        io_status: Option<Hex<u32>>,
        user_event: VirtAddr,
        user_buffer: VirtAddr,
        mdl_address: VirtAddr,
        /// `Tail.Overlay.Thread`, the thread that issued the IRP.
        thread: VirtAddr,
        /// None if the current location is out of range or ntoseye cannot read it.
        current_stack: Option<IoStackLocation>,
    }

    /// A device on the `DeviceObject`/`NextDevice` chain of a driver.
    DriverDeviceLink {
        device: VirtAddr,
        device_type: u32,
        flags: u32,
        characteristics: u32,
        /// `AttachedDevice`, the device layered above this device. 0 if there is none.
        attached: VirtAddr,
        /// `NextDevice`, the next device of the driver. 0 at the end of the chain.
        next: VirtAddr,
    }

    /// One slot in the `MajorFunction` dispatch table.
    IrpDispatchRoutine {
        /// The `IRP_MJ_*` code.
        index: usize,
        /// The name of the major function (`IRP_MJ_CREATE`, ...).
        name: String,
        routine: VirtAddr,
        /// The nearest symbol to the routine. None if no symbol resolves.
        symbol: Option<String>,
    }

    /// A `_DRIVER_OBJECT` with its device chain and dispatch table (`!drvobj`).
    DriverObject {
        object: VirtAddr,
        /// Whether the argument pointed to a pointer to the driver object.
        via_pointer: bool,
        /// `DriverName`. None if ntoseye cannot read it.
        name: Option<String>,
        driver_start: VirtAddr,
        /// The size of the driver image in bytes.
        driver_size: u64,
        driver_section: VirtAddr,
        driver_unload: VirtAddr,
        devices: Vec<DriverDeviceLink>,
        /// The 28 `IRP_MJ_*` dispatch routines, in `IRP_MJ_*` code order.
        dispatch: Vec<IrpDispatchRoutine>,
    }

    /// A device on the `AttachedDevice` stack of a device.
    AttachedDevice {
        device: VirtAddr,
        driver_object: VirtAddr,
        device_type: u32,
        flags: u32,
    }

    /// A `_DEVICE_OBJECT` and the devices attached above it (`!devobj`).
    DeviceObject {
        object: VirtAddr,
        /// Whether the argument pointed to a pointer to the device object.
        via_pointer: bool,
        device_type: u32,
        flags: u32,
        characteristics: u32,
        driver_object: VirtAddr,
        /// The device layered directly above this device. 0 if there is none.
        attached_device: VirtAddr,
        /// The next device of the driver. 0 at the end of the chain.
        next_device: VirtAddr,
        current_irp: VirtAddr,
        device_extension: VirtAddr,
        /// The `AttachedDevice` chain, from the bottom up.
        attached_stack: Vec<AttachedDevice>,
    }

    /// A named object in an object directory.
    ObjectDirectoryEntry {
        name: String,
        object: VirtAddr,
        /// The type of the object (`Directory`, `Driver`, `SymbolicLink`, ...).
        /// None if ntoseye cannot decode its header.
        r#type: Option<String>,
    }

    /// An executive object with its `_OBJECT_HEADER`, type, and name, and the
    /// entries of a directory (`!object`).
    ExecutiveObject {
        /// The address that you gave.
        input: VirtAddr,
        /// `body` if the input pointed to the object body. `header` if the input
        /// pointed to the object header.
        mode: &'static str,
        header: VirtAddr,
        body: VirtAddr,
        pointer_count: i64,
        handle_count: i64,
        /// The decoded `TypeIndex` of the header. None if ntoseye cannot read it.
        type_index: Option<u64>,
        /// The `_OBJECT_TYPE`. None if ntoseye cannot resolve it.
        type_object: Option<VirtAddr>,
        type_name: Option<String>,
        /// The `InfoMask` of the header. It shows which optional headers come before the header.
        info_mask: Option<u8>,
        /// The `_OBJECT_HEADER_NAME_INFO`. None if the object has none.
        name_info: Option<VirtAddr>,
        /// None for an unnamed object.
        name: Option<String>,
        /// The entries of a directory. None for all other objects.
        entries: Option<Vec<ObjectDirectoryEntry>>,
    }

    /// A process, thread, or image notification callback (`callbacks`).
    NotifyCallback {
        /// `process`, `thread`, or `image`.
        kind: &'static str,
        /// The slot of the callback in the kernel callback array.
        index: usize,
        function: VirtAddr,
        /// The nearest symbol to the function. None if no symbol resolves.
        symbol: Option<String>,
        /// The `_EX_CALLBACK_ROUTINE_BLOCK`.
        block: VirtAddr,
        /// The raw `_EX_FAST_REF` value of the slot.
        raw: VirtAddr,
        context: VirtAddr,
    }

    /// A slot in a system-service table.
    SsdtEntry {
        /// The system-service number.
        index: u32,
        /// The routine that the slot resolves to.
        target: VirtAddr,
        /// The symbol of the routine. None if no symbol resolves.
        symbol: Option<String>,
        /// The module that contains the routine. None if no module contains it.
        module: Option<String>,
    }

    /// A system-service table, either the kernel SSDT or the win32k shadow (`ssdt`).
    SsdtTable {
        /// The label of the table.
        label: String,
        base: VirtAddr,
        /// The number of services.
        limit: u32,
        entries: Vec<SsdtEntry>,
    }

    /// An in-flight IRP that ntoseye found on the `IrpList` of a thread or in the
    /// `CurrentIrp` of a device (`irps`).
    InFlightIrp {
        irp: VirtAddr,
        /// `thread` or `device`. It tells where ntoseye found the IRP.
        source: &'static str,
        stack_count: u8,
        current_location: u8,
        /// The process that issued the IRP. None if ntoseye found the IRP on a device.
        pid: Option<u64>,
        /// The thread that issued the IRP. None if ntoseye found the IRP on a device.
        tid: Option<u64>,
        ethread: Option<VirtAddr>,
        /// The state name of the thread. None if ntoseye found the IRP on a device.
        state: Option<&'static str>,
        /// The wait-reason name of the thread. None if ntoseye found the IRP on a
        /// device.
        wait_reason: Option<&'static str>,
        /// The driver that owns the device of the current stack location. None if
        /// ntoseye cannot resolve it.
        driver: Option<String>,
        /// The device of the current stack location. None if ntoseye cannot resolve it.
        device: Option<VirtAddr>,
    }

    /// A `_DRIVER_OBJECT` from the Driver and FileSystem directories of the
    /// object manager (`drivers`).
    DriverObjectSummary {
        name: String,
        object: VirtAddr,
        driver_start: VirtAddr,
        /// The size of the driver image in bytes.
        driver_size: u64,
        /// The first device on the chain of the driver. 0 if there is none.
        device_object: VirtAddr,
        driver_unload: VirtAddr,
    }

    /// A handle-table entry (`!handle <handle>`).
    HandleEntry {
        handle: Hex,
        /// The `_HANDLE_TABLE_ENTRY`.
        entry: VirtAddr,
        /// The body of the object.
        object: Diag<VirtAddr>,
        type_name: Diag<Option<String>>,
        /// The name of the object. The value is None for an unnamed object.
        name: Diag<Option<String>>,
        granted_access: Diag<Hex<u32>>,
        /// The attribute bits of the entry (inherit, protect-from-close, audit).
        attributes: Diag<Hex<u32>>,
    }

    /// The handle table of a process (`!handle`).
    HandleTable {
        /// The process that owns the table.
        process: super::process::ProcessIdentity,
        /// The `_HANDLE_TABLE`.
        table: VirtAddr,
        /// The level of the table (0-2). It is the number of pointer levels before the
        /// entries.
        table_level: u8,
        /// The handle count that the table reports.
        advertised_handles: usize,
        scanned_handles: usize,
        /// The number of entries that ntoseye could not read.
        skipped_entries: usize,
        /// Whether the enumeration stopped at its limit.
        truncated: bool,
        entries: Vec<HandleEntry>,
    }

    /// A `_FILE_OBJECT` (`!fileobj`).
    FileObject {
        address: VirtAddr,
        /// `Type`. For a valid file object, this is `IO_TYPE_FILE` (5).
        file_type: Diag<i16>,
        size: Diag<i16>,
        device_object: Diag<VirtAddr>,
        device_type: Diag<Hex<u32>>,
        /// The object name of the device. The value is None for an unnamed device.
        device_name: Diag<Option<String>>,
        file_name: Diag<String>,
        related_file_object: Diag<VirtAddr>,
        flags: Diag<Hex<u32>>,
        current_byte_offset: Diag<i64>,
        /// The `FsContext` of the file system (its FCB).
        fs_context: Diag<VirtAddr>,
        /// The `FsContext2` of the file system (its CCB).
        fs_context2: Diag<VirtAddr>,
        section_object_pointer: Diag<VirtAddr>,
        private_cache_map: Diag<VirtAddr>,
        /// The NTSTATUS that the file object completed with.
        final_status: Diag<Hex>,
        lock_operation: Diag<bool>,
        delete_pending: Diag<bool>,
        read_access: Diag<bool>,
        write_access: Diag<bool>,
        delete_access: Diag<bool>,
        shared_read: Diag<bool>,
        shared_write: Diag<bool>,
        shared_delete: Diag<bool>,
    }

    /// A thread that owns an executive resource.
    ResourceOwner {
        thread: VirtAddr,
        /// The number of times that the thread acquired the resource.
        count: i32,
    }

    /// An `_ERESOURCE` (`!locks <address>`).
    ExecutiveResource {
        address: VirtAddr,
        active_count: Diag<i16>,
        flags: Diag<Hex<u16>>,
        contention_count: Diag<u32>,
        /// The number of threads that wait for shared access.
        shared_waiters: Diag<u32>,
        /// The number of threads that wait for exclusive access.
        exclusive_waiters: Diag<u32>,
        /// The threads that own the resource.
        owners: Diag<Vec<ResourceOwner>>,
    }

    /// The executive-resource list of the kernel (`!locks`).
    ResourceList {
        /// `nt!ExpSystemResourcesList`.
        head: VirtAddr,
        resources: Vec<ExecutiveResource>,
        termination: ListEnd,
    }

    /// An IRP that `!irpfind` found in pool.
    PoolIrp {
        irp: Irp,
        /// The `_POOL_HEADER` before the IRP. None for a big-pool allocation.
        pool_header: Option<VirtAddr>,
        /// The pool tag of the allocation.
        tag: String,
        /// `Tail.Overlay.OriginalFileObject`.
        original_file_object: VirtAddr,
        /// `MdlAddress->Process`. None if the IRP has no MDL.
        mdl_process: Option<VirtAddr>,
        /// The driver that owns the device of the current stack location. None if
        /// ntoseye cannot resolve it.
        driver: Option<String>,
        /// Whether all stack locations are used. If true, completion of the IRP is
        /// in progress or done.
        completed: bool,
    }

    /// The criteria that an `!irpfind` search used to match IRPs.
    IrpFindCriteria {
        /// `arg`, `device`, `fileobject`, `mdlprocess`, `thread`, or
        /// `userevent`.
        name: &'static str,
        value: Hex,
    }

    /// One `!irpfind` pool scan.
    IrpFindResult {
        /// `nonpaged` or `paged`.
        pool: &'static str,
        region_start: VirtAddr,
        region_end: VirtAddr,
        /// The address where the page scan started. This is the region start or
        /// the restart address.
        scan_start: VirtAddr,
        /// None if the scan has no filter.
        criteria: Option<IrpFindCriteria>,
        scanned_pages: u64,
        /// The result of the big-pool table scan.
        big_pool_status: String,
        irps: Vec<PoolIrp>,
        /// Whether the result limit caused ntoseye to leave out IRPs. This occurs
        /// if the page scan stopped at `restart`, or if ntoseye did not check some
        /// big-pool allocations.
        truncated: bool,
        interrupted: bool,
        /// The address where the page scan can continue. None if the scan finished.
        restart: Option<VirtAddr>,
    }

    /// A return address on the stack of a handle trace.
    HandleTraceFrame {
        address: VirtAddr,
        /// The symbol of the address in the traced process. None if no symbol
        /// resolves.
        symbol: Option<String>,
    }

    /// One `_HANDLE_TRACE_DB_ENTRY`.
    HandleTrace {
        handle: Hex,
        /// 1 open, 2 close, 3 bad reference.
        kind: u32,
        /// `OPEN`, `CLOSE`, `BAD REFERENCE`, or `UNKNOWN`.
        kind_name: &'static str,
        process_id: u64,
        thread_id: u64,
        /// Newest frame first.
        stack: Vec<HandleTraceFrame>,
    }

    /// The handle traces of a process (`!htrace`).
    HandleTraces {
        /// The traced process.
        process: super::process::ProcessIdentity,
        object_table: VirtAddr,
        /// The `_HANDLE_TRACE_DEBUG_INFO`. None if handle tracing is off.
        debug_info: Option<VirtAddr>,
        /// The capacity of the ring.
        table_size: u64,
        /// The total number of recorded traces. The ring keeps the last `table_size`
        /// traces.
        recorded: u64,
        /// The number of ring slots that ntoseye read.
        parsed: u64,
        /// The number of ring slots that ntoseye could not read.
        unreadable: u64,
        /// The matching traces, newest first.
        traces: Vec<HandleTrace>,
    }

    /// A connection to an ALPC connection port, with its communication info
    /// and the two ports that it connects.
    AlpcConnection {
        communication_info: VirtAddr,
        server_port: VirtAddr,
        /// The number of messages queued on the server port (main, large, and
        /// pending). None if ntoseye cannot read it.
        server_queued: Option<u64>,
        client_port: VirtAddr,
        /// The number of messages queued on the client port. None if ntoseye cannot
        /// read it.
        client_queued: Option<u64>,
        /// The `_EPROCESS` of the client.
        client_owner: VirtAddr,
        client_owner_name: Option<String>,
    }

    /// One message queue of an ALPC port, or its wait queue.
    AlpcQueue {
        /// The `_ALPC_PORT` list head, for example `PendingQueue`.
        field: &'static str,
        /// The snake_case name of the queue.
        key: &'static str,
        /// The count that the port keeps for the queue. None if the port keeps no
        /// count.
        length: Option<u64>,
        /// The queued `_KALPC_MESSAGE`s. For the wait queue, the waiting
        /// `_ETHREAD`s.
        entries: Vec<VirtAddr>,
        termination: ListEnd,
    }

    /// An `_ALPC_PORT` (`!alpc /p`). A field is None if this Windows build does
    /// not have it, or if ntoseye cannot read it.
    AlpcPort {
        address: VirtAddr,
        name: Option<String>,
        pointer_count: i64,
        handle_count: i64,
        /// The WinDbg port type name (`ALPC_CONNECTION_PORT`, ...).
        kind: Option<&'static str>,
        /// `u1.State`.
        state: Option<Hex>,
        /// The `Type` bits of `u1.State`.
        port_type: Option<u64>,
        /// The PDB names of the one-bit `u1.s1` state flags that are set.
        state_flags: Vec<String>,
        /// The `_EPROCESS` that owns the port.
        owner: VirtAddr,
        owner_name: Option<String>,
        communication_info: VirtAddr,
        connection_port: Option<VirtAddr>,
        server_port: Option<VirtAddr>,
        client_port: Option<VirtAddr>,
        sequence_no: Option<u64>,
        completion_port: Option<VirtAddr>,
        completion_list: Option<VirtAddr>,
        port_context: Option<VirtAddr>,
        /// `PortAttributes.Flags`.
        attribute_flags: Option<Hex>,
        /// `PortAttributes.MaxMessageLength`.
        max_message_length: Option<u64>,
        queues: Vec<AlpcQueue>,
        direct_queue_length: Option<u64>,
        /// The connections of a connection port.
        connections: Vec<AlpcConnection>,
        /// How the walk of the connection list ended. None if there was no walk.
        connection_termination: Option<ListEnd>,
    }

    /// A `_KALPC_MESSAGE` (`!alpc /m`). A field is None if this Windows build
    /// does not have it, or if ntoseye cannot read it.
    AlpcMessage {
        address: VirtAddr,
        message_id: Option<u64>,
        callback_id: Option<u64>,
        sequence_no: Option<u64>,
        /// `PortMessage.u2.s2.Type`.
        message_type: Option<Hex>,
        /// The `LPC_*` name of the low byte of the message type.
        message_type_name: Option<&'static str>,
        data_length: Option<u64>,
        total_length: Option<u64>,
        /// `PortMessage.ClientId`, the sender.
        client_process_id: Option<u64>,
        client_thread_id: Option<u64>,
        /// `u1.State`.
        state: Option<Hex>,
        /// The `QueueType` bits of `u1.State`.
        queue_type: Option<u64>,
        /// The `QueuePortType` bits of `u1.State`.
        queue_port_type: Option<u64>,
        /// The PDB names of the one-bit `u1.s1` state flags that are set.
        state_flags: Vec<String>,
        owner_port: VirtAddr,
        /// The WinDbg port type name of the owner port.
        owner_port_kind: Option<&'static str>,
        /// The port whose queue holds the message.
        port_queue: VirtAddr,
        port_queue_kind: Option<&'static str>,
        /// The `_EPROCESS` that owns the queue port.
        port_queue_owner: Option<VirtAddr>,
        port_queue_owner_name: Option<String>,
        cancel_sequence_no: Option<u64>,
        extension_buffer_size: Option<u64>,
        /// The pointer fields of the message in this build, by snake_case name.
        pointers: Keyed<VirtAddr>,
        /// The `_KALPC_MESSAGE_ATTRIBUTES` fields in this build, by snake_case
        /// name.
        attributes: Keyed<VirtAddr>,
    }

    /// A connection port that a process owns, and its connections.
    AlpcOwnedPort {
        handle: Hex,
        port: VirtAddr,
        name: Option<String>,
        connections: Vec<AlpcConnection>,
        termination: ListEnd,
    }

    /// A client communication port that a process holds, and the ports that it
    /// is connected to.
    AlpcClientPort {
        handle: Hex,
        port: VirtAddr,
        /// The number of messages queued on the port. None if ntoseye cannot read it.
        queued: Option<u64>,
        connection_port: VirtAddr,
        connection_name: Option<String>,
        server_port: VirtAddr,
        /// The number of messages queued on the server port. None if ntoseye cannot
        /// read it.
        server_queued: Option<u64>,
        /// The `_EPROCESS` of the server. None if ntoseye cannot read it.
        server_owner: Option<VirtAddr>,
        server_owner_name: Option<String>,
    }

    /// The ALPC ports that a process holds handles to (`!alpc /lpp`).
    AlpcProcessPorts {
        process: super::process::ProcessIdentity,
        /// The connection ports that the process owns.
        created: Vec<AlpcOwnedPort>,
        /// The client ports that the process holds.
        connected: Vec<AlpcClientPort>,
        /// The number of server communication ports that the process holds. These
        /// are its ends of connections to its own ports.
        server_ports: usize,
        scanned_handles: usize,
        /// The handle count that the table reports.
        advertised_handles: usize,
        /// The number of handle-table entries that ntoseye could not read.
        skipped_entries: usize,
    }
}

fn io_stack(s: &IoStackLocationInfo) -> IoStackLocation {
    IoStackLocation {
        address: s.address,
        major_function: s.major_function,
        major_function_name: format!("IRP_MJ_{}", irp_major_function_name(s.major_function)),
        minor_function: s.minor_function,
        device_object: s.device_object,
        file_object: s.file_object,
        completion_routine: s.completion_routine,
        context: s.context,
    }
}

/// `_IRP` plus its current `_IO_STACK_LOCATION`.
pub fn irp(irp: &IrpInfo) -> Irp {
    Irp {
        address: irp.address,
        r#type: irp.irp_type,
        size: irp.size,
        stack_count: irp.stack_count,
        current_location: irp.current_location,
        pending_returned: irp.pending_returned,
        requestor_mode: irp.requestor_mode,
        io_status: irp.io_status,
        user_event: irp.user_event,
        user_buffer: irp.user_buffer,
        mdl_address: irp.mdl_address,
        thread: irp.thread,
        current_stack: irp.current_stack.as_ref().map(io_stack),
    }
}

/// `_DRIVER_OBJECT`: header fields, device chain, and the 28-entry `IRP_MJ_*`
/// dispatch table (each routine resolved to its nearest symbol).
pub fn driver_object(target: &Target, d: &DriverObjectDetail) -> DriverObject {
    let dtb = target.kernel_dtb();
    DriverObject {
        object: d.object,
        via_pointer: d.via_pointer,
        name: d.name.clone(),
        driver_start: d.driver_start,
        driver_size: d.driver_size,
        driver_section: d.driver_section,
        driver_unload: d.driver_unload,
        devices: d
            .device_chain
            .iter()
            .map(|x| DriverDeviceLink {
                device: x.device,
                device_type: x.device_type,
                flags: x.flags,
                characteristics: x.characteristics,
                attached: x.attached,
                next: x.next,
            })
            .collect(),
        dispatch: d
            .dispatch
            .iter()
            .enumerate()
            .map(|(index, routine)| IrpDispatchRoutine {
                index,
                name: format!("IRP_MJ_{}", irp_major_function_name(index as u8)),
                routine: *routine,
                symbol: target
                    .symbols
                    .format_closest_symbol_for_address(dtb, *routine),
            })
            .collect(),
    }
}

/// `_DEVICE_OBJECT` plus its `AttachedDevice` stack.
pub fn device_object(d: &DeviceObjectDetail) -> DeviceObject {
    DeviceObject {
        object: d.object,
        via_pointer: d.via_pointer,
        device_type: d.device_type,
        flags: d.flags,
        characteristics: d.characteristics,
        driver_object: d.driver_object,
        attached_device: d.attached_device,
        next_device: d.next_device,
        current_irp: d.current_irp,
        device_extension: d.device_extension,
        attached_stack: d
            .attached_stack
            .iter()
            .map(|x| AttachedDevice {
                device: x.device,
                driver_object: x.driver_object,
                device_type: x.device_type,
                flags: x.flags,
            })
            .collect(),
    }
}

/// An object's executive header, type, and name, plus a directory's contents.
pub fn object(detail: &ObjectDetail) -> ExecutiveObject {
    let o = &detail.header;
    ExecutiveObject {
        input: o.input,
        mode: o.mode,
        header: o.header,
        body: o.body,
        pointer_count: o.pointer_count,
        handle_count: o.handle_count,
        type_index: o.type_index,
        type_object: o.type_object,
        type_name: o.type_name.clone(),
        info_mask: o.info_mask,
        name_info: o.name_info,
        name: o.name.clone(),
        entries: detail.entries.as_ref().map(|entries| {
            entries
                .iter()
                .map(|entry| ObjectDirectoryEntry {
                    name: entry.name.clone(),
                    object: entry.object,
                    r#type: entry.type_name.clone(),
                })
                .collect()
        }),
    }
}

/// One notification-callback row; `symbol` is resolved by the surface (it also
/// drives MCP's symbol filter) and passed in.
pub fn notify_callback(c: &NotifyCallbackInfo, symbol: Option<String>) -> NotifyCallback {
    NotifyCallback {
        kind: c.kind,
        index: c.index,
        function: c.function,
        symbol,
        block: c.block,
        raw: c.raw,
        context: c.context,
    }
}

/// One system-service table (the kernel SSDT or the win32k shadow).
pub fn ssdt_table(t: &SsdtTableInfo) -> SsdtTable {
    SsdtTable {
        label: t.label.clone(),
        base: t.base,
        limit: t.limit,
        entries: t
            .entries
            .iter()
            .map(|e| SsdtEntry {
                index: e.index,
                target: e.target,
                symbol: e.symbol.clone(),
                module: e.module.clone(),
            })
            .collect(),
    }
}

/// One discovered in-flight IRP plus the context it was found in.
pub fn irp_hit(h: &IrpHit) -> InFlightIrp {
    InFlightIrp {
        irp: h.irp,
        source: h.source,
        stack_count: h.stack_count,
        current_location: h.current_location,
        pid: h.pid,
        tid: h.tid,
        ethread: h.ethread,
        state: h.state.map(kthread_state_name),
        wait_reason: h.wait_reason.map(wait_reason_name),
        driver: h.driver.clone(),
        device: h.device,
    }
}

/// A `_DRIVER_OBJECT` as enumerated from the object directory.
pub fn driver_object_info(driver: &DriverObjectInfo) -> DriverObjectSummary {
    DriverObjectSummary {
        name: driver.name.clone(),
        object: driver.object,
        driver_start: driver.driver_start,
        driver_size: driver.driver_size,
        device_object: driver.device_object,
        driver_unload: driver.driver_unload,
    }
}

pub fn handle_entry(entry: &HandleEntryDetail) -> HandleEntry {
    HandleEntry {
        handle: entry.handle,
        entry: entry.entry,
        object: entry.object.clone(),
        type_name: entry.type_name.clone(),
        name: entry.name.clone(),
        granted_access: entry.granted_access.map(|access| *access),
        attributes: entry.attributes.map(|attributes| *attributes),
    }
}

pub fn handle_table(summary: &HandleTableSummary) -> HandleTable {
    HandleTable {
        process: process(&summary.process),
        table: summary.table,
        table_level: summary.table_level,
        advertised_handles: summary.advertised_handles,
        scanned_handles: summary.scanned_handles,
        skipped_entries: summary.skipped_entries,
        truncated: summary.truncated,
        entries: summary.entries.iter().map(handle_entry).collect(),
    }
}

pub fn file_object(file: &FileObjectDetail) -> FileObject {
    let flag = |value: &bool| *value;
    FileObject {
        address: file.address,
        file_type: file.file_type.clone(),
        size: file.size.clone(),
        device_object: file.device_object.clone(),
        device_type: file.device_type.clone(),
        device_name: file.device_name.clone(),
        file_name: file.file_name.clone(),
        related_file_object: file.related_file_object.clone(),
        flags: file.flags.clone(),
        current_byte_offset: file.current_byte_offset.clone(),
        fs_context: file.fs_context.clone(),
        fs_context2: file.fs_context2.clone(),
        section_object_pointer: file.section_object_pointer.clone(),
        private_cache_map: file.private_cache_map.clone(),
        final_status: file.final_status.map(|value| *value as u32 as u64),
        lock_operation: file.lock_operation.map(flag),
        delete_pending: file.delete_pending.map(flag),
        read_access: file.read_access.map(flag),
        write_access: file.write_access.map(flag),
        delete_access: file.delete_access.map(flag),
        shared_read: file.shared_read.map(flag),
        shared_write: file.shared_write.map(flag),
        shared_delete: file.shared_delete.map(flag),
    }
}

pub fn resource(resource: &ResourceDetail) -> ExecutiveResource {
    ExecutiveResource {
        address: resource.address,
        active_count: resource.active_count.clone(),
        flags: resource.flags.map(|value| *value),
        contention_count: resource.contention_count.clone(),
        shared_waiters: resource.shared_waiters.clone(),
        exclusive_waiters: resource.exclusive_waiters.clone(),
        owners: resource.owners.map(|owners| {
            owners
                .iter()
                .map(|owner: &ResourceOwnerInfo| ResourceOwner {
                    thread: owner.thread,
                    count: owner.count,
                })
                .collect()
        }),
    }
}

pub fn resource_list(summary: &ResourceListSummary) -> ResourceList {
    ResourceList {
        head: summary.head,
        resources: summary.resources.iter().map(resource).collect(),
        termination: list_termination(&summary.termination),
    }
}

fn irp_find_entry(entry: &IrpFindEntry) -> PoolIrp {
    PoolIrp {
        irp: irp(&entry.irp),
        pool_header: entry.pool_header,
        tag: entry.tag.clone(),
        original_file_object: entry.original_file_object,
        mdl_process: entry.mdl_process,
        driver: entry.driver.clone(),
        completed: entry.completed(),
    }
}

/// `!irpfind`'s pool scan and the IRPs it found.
pub fn irp_find(detail: &IrpFindDetail) -> IrpFindResult {
    IrpFindResult {
        pool: match detail.pool {
            IrpPool::NonPaged => "nonpaged",
            IrpPool::Paged => "paged",
        },
        region_start: detail.region_start,
        region_end: detail.region_end,
        scan_start: detail.scan_start,
        criteria: detail.criteria.map(|criteria| IrpFindCriteria {
            name: criteria.name(),
            value: criteria.value(),
        }),
        scanned_pages: detail.scanned_pages,
        big_pool_status: detail.big_pool_status.clone(),
        irps: detail.irps.iter().map(irp_find_entry).collect(),
        truncated: detail.truncated,
        interrupted: detail.interrupted,
        restart: detail.restart,
    }
}

/// `!htrace`: a process's handle traces, newest first.
pub fn handle_traces(detail: &HandleTraceDetail) -> HandleTraces {
    HandleTraces {
        process: process(&detail.process),
        object_table: detail.object_table,
        debug_info: detail.debug_info,
        table_size: detail.table_size,
        recorded: detail.recorded,
        parsed: detail.parsed,
        unreadable: detail.unreadable,
        traces: detail
            .traces
            .iter()
            .map(|trace| HandleTrace {
                handle: trace.handle,
                kind: trace.kind,
                kind_name: handle_trace_kind_name(trace.kind),
                process_id: trace.process_id,
                thread_id: trace.thread_id,
                stack: trace
                    .stack
                    .iter()
                    .map(|(address, symbol)| HandleTraceFrame {
                        address: *address,
                        symbol: symbol.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn alpc_kind(kind: Option<AlpcPortKind>) -> Option<&'static str> {
    kind.map(AlpcPortKind::name)
}

/// ALPC fields by snake_case name: which ones exist depends on the build.
fn alpc_fields(fields: &[AlpcField]) -> Vec<(&'static str, VirtAddr)> {
    fields.iter().map(|field| (field.key, field.value)).collect()
}

fn alpc_connection(connection: &AlpcConnectionDetail) -> AlpcConnection {
    AlpcConnection {
        communication_info: connection.communication_info,
        server_port: connection.server_port,
        server_queued: connection.server_queued,
        client_port: connection.client_port,
        client_queued: connection.client_queued,
        client_owner: connection.client_owner,
        client_owner_name: connection.client_owner_name.clone(),
    }
}

/// `!alpc /p`: a port, its queues, and a connection port's connections.
pub fn alpc_port(port: &AlpcPortDetail) -> AlpcPort {
    AlpcPort {
        address: port.address,
        name: port.name.clone(),
        pointer_count: port.pointer_count,
        handle_count: port.handle_count,
        kind: alpc_kind(port.kind),
        state: port.state,
        port_type: port.port_type,
        state_flags: port.state_flags.clone(),
        owner: port.owner,
        owner_name: port.owner_name.clone(),
        communication_info: port.communication_info,
        connection_port: port.connection_port,
        server_port: port.server_port,
        client_port: port.client_port,
        sequence_no: port.sequence_no,
        completion_port: port.completion_port,
        completion_list: port.completion_list,
        port_context: port.port_context,
        attribute_flags: port.attribute_flags,
        max_message_length: port.max_message_length,
        queues: port
            .queues
            .iter()
            .map(|queue| AlpcQueue {
                field: queue.field,
                key: queue.key,
                length: queue.length,
                entries: queue.entries.clone(),
                termination: list_termination(&queue.termination),
            })
            .collect(),
        direct_queue_length: port.direct_queue_length,
        connections: port.connections.iter().map(alpc_connection).collect(),
        connection_termination: port.connection_termination.as_ref().map(list_termination),
    }
}

/// `!alpc /m`: a message, its state, and the port queue holding it.
pub fn alpc_message(message: &AlpcMessageDetail) -> AlpcMessage {
    AlpcMessage {
        address: message.address,
        message_id: message.message_id,
        callback_id: message.callback_id,
        sequence_no: message.sequence_no,
        message_type: message.message_type,
        message_type_name: message.message_type.and_then(lpc_message_type_name),
        data_length: message.data_length,
        total_length: message.total_length,
        client_process_id: message.client_process_id,
        client_thread_id: message.client_thread_id,
        state: message.state,
        queue_type: message.queue_type,
        queue_port_type: message.queue_port_type,
        state_flags: message.state_flags.clone(),
        owner_port: message.owner_port,
        owner_port_kind: alpc_kind(message.owner_port_kind),
        port_queue: message.port_queue,
        port_queue_kind: alpc_kind(message.port_queue_kind),
        port_queue_owner: message.port_queue_owner,
        port_queue_owner_name: message.port_queue_owner_name.clone(),
        cancel_sequence_no: message.cancel_sequence_no,
        extension_buffer_size: message.extension_buffer_size,
        pointers: alpc_fields(&message.pointers),
        attributes: alpc_fields(&message.attributes),
    }
}

/// `!alpc /lpp`: the connection ports a process owns and the client ports it
/// holds.
pub fn alpc_process_ports(ports: &AlpcProcessPortsDetail) -> AlpcProcessPorts {
    AlpcProcessPorts {
        process: process(&ports.process),
        created: ports
            .created
            .iter()
            .map(|port| AlpcOwnedPort {
                handle: port.handle,
                port: port.port,
                name: port.name.clone(),
                connections: port.connections.iter().map(alpc_connection).collect(),
                termination: list_termination(&port.termination),
            })
            .collect(),
        connected: ports
            .connected
            .iter()
            .map(|port| AlpcClientPort {
                handle: port.handle,
                port: port.port,
                queued: port.queued,
                connection_port: port.connection_port,
                connection_name: port.connection_name.clone(),
                server_port: port.server_port,
                server_queued: port.server_queued,
                server_owner: port.server_owner,
                server_owner_name: port.server_owner_name.clone(),
            })
            .collect(),
        server_ports: ports.server_ports,
        scanned_handles: ports.scanned_handles,
        advertised_handles: ports.advertised_handles,
        skipped_entries: ports.skipped_entries,
    }
}
