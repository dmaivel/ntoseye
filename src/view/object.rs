//! Object- and I/O-manager [`View`] builders: IRPs, driver and
//! device objects, object headers, handles, file objects, executive
//! resources, notification callbacks, service tables, and ALPC ports.

use super::process::process;
use super::shape::{Diag, Hex, ViewValue, shapes};
use super::{ListEnd, View, list_termination};
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
    /// An `_IO_STACK_LOCATION`: one driver's part of an IRP.
    IoStackLocation {
        address: Hex,
        /// The `IRP_MJ_*` code.
        major_function: u8,
        /// The major function's name (`IRP_MJ_READ`, ...).
        major_function_name: String,
        minor_function: u8,
        device_object: Hex,
        file_object: Hex,
        completion_routine: Hex,
        /// The completion routine's context argument.
        context: Hex,
    }

    /// An `_IRP` and its current I/O stack location (`!irp`).
    Irp {
        address: Hex,
        /// `Type` (`IO_TYPE_IRP`, 6, for a valid IRP).
        r#type: u16,
        /// `Size` in bytes, stack locations included.
        size: u16,
        stack_count: u8,
        /// `CurrentLocation`; above `stack_count` once the IRP completes.
        current_location: u8,
        pending_returned: bool,
        /// 0 for `KernelMode`, 1 for `UserMode`.
        requestor_mode: u8,
        /// `IoStatus.Status`, as an NTSTATUS; None when unreadable.
        io_status: Option<Hex>,
        user_event: Hex,
        user_buffer: Hex,
        mdl_address: Hex,
        /// `Tail.Overlay.Thread`: the thread that issued it.
        thread: Hex,
        /// None when the current location is out of range or unreadable.
        current_stack: Option<IoStackLocation>,
    }

    /// A device on a driver's `DeviceObject`/`NextDevice` chain.
    DriverDeviceLink {
        device: Hex,
        device_type: u32,
        flags: u32,
        characteristics: u32,
        /// `AttachedDevice`: the device layered above it; 0 when none.
        attached: Hex,
        /// `NextDevice`: the driver's next device; 0 at the end.
        next: Hex,
    }

    /// One `MajorFunction` dispatch-table slot.
    IrpDispatchRoutine {
        /// The `IRP_MJ_*` code.
        index: usize,
        /// The major function's name (`IRP_MJ_CREATE`, ...).
        name: String,
        routine: Hex,
        /// The routine's nearest symbol; None when none resolves.
        symbol: Option<String>,
    }

    /// A `_DRIVER_OBJECT` with its device chain and dispatch table (`!drvobj`).
    DriverObject {
        object: Hex,
        /// Whether the argument pointed at a pointer to the driver object.
        via_pointer: bool,
        /// `DriverName`; None when unreadable.
        name: Option<String>,
        driver_start: Hex,
        /// The driver image's size in bytes.
        driver_size: u64,
        driver_section: Hex,
        driver_unload: Hex,
        devices: Vec<DriverDeviceLink>,
        /// The 28 `IRP_MJ_*` dispatch routines, by code.
        dispatch: Vec<IrpDispatchRoutine>,
    }

    /// A device on a device's `AttachedDevice` stack.
    AttachedDevice {
        device: Hex,
        driver_object: Hex,
        device_type: u32,
        flags: u32,
    }

    /// A `_DEVICE_OBJECT` and the devices attached above it (`!devobj`).
    DeviceObject {
        object: Hex,
        /// Whether the argument pointed at a pointer to the device object.
        via_pointer: bool,
        device_type: u32,
        flags: u32,
        characteristics: u32,
        driver_object: Hex,
        /// The device layered directly above; 0 when none.
        attached_device: Hex,
        /// The driver's next device; 0 at the end.
        next_device: Hex,
        current_irp: Hex,
        device_extension: Hex,
        /// The `AttachedDevice` chain, bottom up.
        attached_stack: Vec<AttachedDevice>,
    }

    /// A named object in an object directory.
    ObjectDirectoryEntry {
        name: String,
        object: Hex,
        /// The object's type (`Directory`, `Driver`, `SymbolicLink`, ...);
        /// None when its header cannot be decoded.
        r#type: Option<String>,
    }

    /// An executive object: its `_OBJECT_HEADER`, type, and name, and a
    /// directory's entries (`!object`).
    ExecutiveObject {
        /// The address given.
        input: Hex,
        /// `body` when the input pointed at the object body, `header` when
        /// at its header.
        mode: &'static str,
        header: Hex,
        body: Hex,
        pointer_count: i64,
        handle_count: i64,
        /// The header's (decoded) `TypeIndex`; None when unreadable.
        type_index: Option<u64>,
        /// The `_OBJECT_TYPE`; None when unresolved.
        type_object: Option<Hex>,
        type_name: Option<String>,
        /// The header's `InfoMask` (which optional headers precede it).
        info_mask: Option<u8>,
        /// The `_OBJECT_HEADER_NAME_INFO`; None when the object has none.
        name_info: Option<Hex>,
        /// None for an unnamed object.
        name: Option<String>,
        /// A directory's entries; None for any other object.
        entries: Option<Vec<ObjectDirectoryEntry>>,
    }

    /// A process, thread, or image notification callback (`callbacks`).
    NotifyCallback {
        /// `process`, `thread`, or `image`.
        kind: &'static str,
        /// Its slot in the kernel's callback array.
        index: usize,
        function: Hex,
        /// The function's nearest symbol; None when none resolves.
        symbol: Option<String>,
        /// The `_EX_CALLBACK_ROUTINE_BLOCK`.
        block: Hex,
        /// The slot's raw `_EX_FAST_REF` value.
        raw: Hex,
        context: Hex,
    }

    /// A system-service table slot.
    SsdtEntry {
        /// The system-service number.
        index: u32,
        /// The routine the slot resolves to.
        target: Hex,
        /// The routine's symbol; None when none resolves.
        symbol: Option<String>,
        /// The module containing the routine; None when none does.
        module: Option<String>,
    }

    /// A system-service table: the kernel SSDT or the win32k shadow (`!ssdt`).
    SsdtTable {
        /// Which table.
        label: String,
        base: Hex,
        /// The number of services.
        limit: u32,
        entries: Vec<SsdtEntry>,
    }

    /// An in-flight IRP found on a thread's `IrpList` or as a device's
    /// `CurrentIrp` (`irps`).
    InFlightIrp {
        irp: Hex,
        /// `thread` or `device`: where it was found.
        source: &'static str,
        stack_count: u8,
        current_location: u8,
        /// The issuing process; None when found on a device.
        pid: Option<u64>,
        /// The issuing thread; None when found on a device.
        tid: Option<u64>,
        ethread: Option<Hex>,
        /// The thread's state name; None when found on a device.
        state: Option<&'static str>,
        /// The thread's wait-reason name; None when found on a device.
        wait_reason: Option<&'static str>,
        /// The driver owning the current stack location's device; None when
        /// unresolved.
        driver: Option<String>,
        /// The current stack location's device; None when unresolved.
        device: Option<Hex>,
    }

    /// A `_DRIVER_OBJECT` as listed in the `\Driver` and `\FileSystem`
    /// directories (`drivers`).
    DriverObjectSummary {
        name: String,
        object: Hex,
        driver_start: Hex,
        /// The driver image's size in bytes.
        driver_size: u64,
        /// The first device on its chain; 0 when none.
        device_object: Hex,
        driver_unload: Hex,
    }

    /// A handle-table entry (`!handle <handle>`).
    HandleEntry {
        handle: Hex,
        /// The `_HANDLE_TABLE_ENTRY`.
        entry: Hex,
        /// The object's body.
        object: Diag<Hex>,
        type_name: Diag<Option<String>>,
        /// The object's name; the value is None for an unnamed object.
        name: Diag<Option<String>>,
        granted_access: Diag<Hex>,
        /// The entry's attribute bits (inherit, protect-from-close, audit).
        attributes: Diag<Hex>,
    }

    /// A process's handle table (`!handle`).
    HandleTable {
        /// The process whose table it is.
        process: View,
        /// The `_HANDLE_TABLE`.
        table: Hex,
        /// The table's level (0-2: how many pointer levels lead to entries).
        table_level: u8,
        /// The handle count the table reports.
        advertised_handles: usize,
        scanned_handles: usize,
        /// Entries that could not be read.
        skipped_entries: usize,
        /// Whether the enumeration stopped at its limit.
        truncated: bool,
        entries: Vec<HandleEntry>,
    }

    /// A `_FILE_OBJECT` (`!fileobj`).
    FileObject {
        address: Hex,
        /// `Type` (`IO_TYPE_FILE`, 5, for a valid file object).
        file_type: Diag<i64>,
        size: Diag<i64>,
        device_object: Diag<Hex>,
        device_type: Diag<Hex>,
        /// The device's object name; the value is None for an unnamed device.
        device_name: Diag<Option<String>>,
        file_name: Diag<String>,
        related_file_object: Diag<Hex>,
        flags: Diag<Hex>,
        current_byte_offset: Diag<i64>,
        /// The file system's `FsContext` (its FCB).
        fs_context: Diag<Hex>,
        /// The file system's `FsContext2` (its CCB).
        fs_context2: Diag<Hex>,
        section_object_pointer: Diag<Hex>,
        private_cache_map: Diag<Hex>,
        /// The NTSTATUS the file object completed with.
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

    /// A thread owning an executive resource.
    ResourceOwner {
        thread: Hex,
        /// How many times the thread acquired it.
        count: i64,
    }

    /// An `_ERESOURCE` (`!locks <address>`).
    ExecutiveResource {
        address: Hex,
        active_count: Diag<i64>,
        flags: Diag<Hex>,
        contention_count: Diag<u32>,
        /// Threads waiting for shared access.
        shared_waiters: Diag<u32>,
        /// Threads waiting for exclusive access.
        exclusive_waiters: Diag<u32>,
        /// The owning threads.
        owners: Diag<Vec<ResourceOwner>>,
    }

    /// The kernel's executive-resource list (`!locks`).
    ResourceList {
        /// `nt!ExpSystemResourcesList`.
        head: Hex,
        resources: Vec<ExecutiveResource>,
        termination: ListEnd,
    }

    /// An IRP `!irpfind` found in pool.
    PoolIrp {
        irp: Irp,
        /// The `_POOL_HEADER` before it; None for a big-pool allocation.
        pool_header: Option<Hex>,
        /// The allocation's pool tag.
        tag: String,
        /// `Tail.Overlay.OriginalFileObject`.
        original_file_object: Hex,
        /// `MdlAddress->Process`; None without an MDL.
        mdl_process: Option<Hex>,
        /// The driver owning the current stack location's device; None when
        /// unresolved.
        driver: Option<String>,
        /// Whether every stack location is used up: the IRP is being (or
        /// was) completed.
        completed: bool,
    }

    /// The criteria an `!irpfind` search matched IRPs against.
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
        region_start: Hex,
        region_end: Hex,
        /// Where the page scan began: the region start or the restart
        /// address.
        scan_start: Hex,
        /// None when unfiltered.
        criteria: Option<IrpFindCriteria>,
        scanned_pages: u64,
        /// How the big-pool table scan went.
        big_pool_status: String,
        irps: Vec<PoolIrp>,
        /// Whether the result bound left IRPs out: the page scan stopped at
        /// `restart`, or big-pool allocations went unchecked.
        truncated: bool,
        interrupted: bool,
        /// Where to resume the page scan; None when it finished.
        restart: Option<Hex>,
    }

    /// A return address on a handle trace's stack.
    HandleTraceFrame {
        address: Hex,
        /// The symbol it resolves to in the traced process; None when none
        /// does.
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

    /// A process's handle traces (`!htrace`).
    HandleTraces {
        /// The traced process.
        process: View,
        object_table: Hex,
        /// The `_HANDLE_TRACE_DEBUG_INFO`; None when handle tracing is off.
        debug_info: Option<Hex>,
        /// The ring's capacity.
        table_size: u64,
        /// Traces ever recorded; the ring keeps the last `table_size`.
        recorded: u64,
        /// Ring slots read.
        parsed: u64,
        /// Ring slots that could not be read.
        unreadable: u64,
        /// The matching traces, newest first.
        traces: Vec<HandleTrace>,
    }

    /// A connection to an ALPC connection port: its communication info and
    /// the two ports it joins.
    AlpcConnection {
        communication_info: Hex,
        server_port: Hex,
        /// Messages queued on the server port (main, large, and pending);
        /// None when unreadable.
        server_queued: Option<u64>,
        client_port: Hex,
        /// Messages queued on the client port; None when unreadable.
        client_queued: Option<u64>,
        /// The client's `_EPROCESS`.
        client_owner: Hex,
        client_owner_name: Option<String>,
    }

    /// One of an ALPC port's message queues, or its wait queue.
    AlpcQueue {
        /// The `_ALPC_PORT` list head, e.g. `PendingQueue`.
        field: &'static str,
        /// The queue's snake_case name.
        key: &'static str,
        /// The port's count for the queue; None when it keeps none.
        length: Option<u64>,
        /// The queued `_KALPC_MESSAGE`s, or for the wait queue the waiting
        /// `_ETHREAD`s.
        entries: Vec<Hex>,
        termination: ListEnd,
    }

    /// An `_ALPC_PORT` (`!alpc /p`). A field is None when this build lacks
    /// it or it cannot be read.
    AlpcPort {
        address: Hex,
        name: Option<String>,
        pointer_count: i64,
        handle_count: i64,
        /// WinDbg's port type name (`ALPC_CONNECTION_PORT`, ...).
        kind: Option<&'static str>,
        /// `u1.State`.
        state: Option<Hex>,
        /// `u1.State`'s `Type` bits.
        port_type: Option<u64>,
        /// The one-bit `u1.s1` state flags set, by their PDB names.
        state_flags: Vec<String>,
        /// The owning `_EPROCESS`.
        owner: Hex,
        owner_name: Option<String>,
        communication_info: Hex,
        connection_port: Option<Hex>,
        server_port: Option<Hex>,
        client_port: Option<Hex>,
        sequence_no: Option<u64>,
        completion_port: Option<Hex>,
        completion_list: Option<Hex>,
        port_context: Option<Hex>,
        /// `PortAttributes.Flags`.
        attribute_flags: Option<Hex>,
        /// `PortAttributes.MaxMessageLength`.
        max_message_length: Option<u64>,
        queues: Vec<AlpcQueue>,
        direct_queue_length: Option<u64>,
        /// A connection port's connections.
        connections: Vec<AlpcConnection>,
        /// How the connection-list walk ended; None when there was none.
        connection_termination: Option<ListEnd>,
    }

    /// A `_KALPC_MESSAGE` (`!alpc /m`). A field is None when this build
    /// lacks it or it cannot be read.
    AlpcMessage {
        address: Hex,
        message_id: Option<u64>,
        callback_id: Option<u64>,
        sequence_no: Option<u64>,
        /// `PortMessage.u2.s2.Type`.
        message_type: Option<Hex>,
        /// The `LPC_*` name of the message type's low byte.
        message_type_name: Option<&'static str>,
        data_length: Option<u64>,
        total_length: Option<u64>,
        /// `PortMessage.ClientId`: the sender.
        client_process_id: Option<u64>,
        client_thread_id: Option<u64>,
        /// `u1.State`.
        state: Option<Hex>,
        /// `u1.State`'s `QueueType` bits.
        queue_type: Option<u64>,
        /// `u1.State`'s `QueuePortType` bits.
        queue_port_type: Option<u64>,
        /// The one-bit `u1.s1` state flags set, by their PDB names.
        state_flags: Vec<String>,
        owner_port: Hex,
        /// WinDbg's port type name of the owner port.
        owner_port_kind: Option<&'static str>,
        /// The port whose queue holds the message.
        port_queue: Hex,
        port_queue_kind: Option<&'static str>,
        /// The queue port's owning `_EPROCESS`.
        port_queue_owner: Option<Hex>,
        port_queue_owner_name: Option<String>,
        cancel_sequence_no: Option<u64>,
        extension_buffer_size: Option<u64>,
        /// The message's pointer fields this build has, by snake_case name.
        pointers: View,
        /// The `_KALPC_MESSAGE_ATTRIBUTES` fields this build has, by
        /// snake_case name.
        attributes: View,
    }

    /// A connection port a process owns, and its connections.
    AlpcOwnedPort {
        handle: Hex,
        port: Hex,
        name: Option<String>,
        connections: Vec<AlpcConnection>,
        termination: ListEnd,
    }

    /// A client communication port a process holds: what it is connected to.
    AlpcClientPort {
        handle: Hex,
        port: Hex,
        /// Messages queued on the port; None when unreadable.
        queued: Option<u64>,
        connection_port: Hex,
        connection_name: Option<String>,
        server_port: Hex,
        /// Messages queued on the server port; None when unreadable.
        server_queued: Option<u64>,
        /// The server's `_EPROCESS`; None when unreadable.
        server_owner: Option<Hex>,
        server_owner_name: Option<String>,
    }

    /// The ALPC ports a process holds handles to (`!alpc /lpp`).
    AlpcProcessPorts {
        process: View,
        /// Connection ports the process owns.
        created: Vec<AlpcOwnedPort>,
        /// Client ports the process holds.
        connected: Vec<AlpcClientPort>,
        /// Server communication ports it holds (its ends of connections to
        /// its own ports).
        server_ports: usize,
        scanned_handles: usize,
        /// The handle count the table reports.
        advertised_handles: usize,
        /// Handle-table entries that could not be read.
        skipped_entries: usize,
    }
}

fn io_stack(s: &IoStackLocationInfo) -> IoStackLocation {
    IoStackLocation {
        address: Hex(s.address.0),
        major_function: s.major_function,
        major_function_name: format!("IRP_MJ_{}", irp_major_function_name(s.major_function)),
        minor_function: s.minor_function,
        device_object: Hex(s.device_object.0),
        file_object: Hex(s.file_object.0),
        completion_routine: Hex(s.completion_routine.0),
        context: Hex(s.context.0),
    }
}

fn irp_shape(irp: &IrpInfo) -> Irp {
    Irp {
        address: Hex(irp.address.0),
        r#type: irp.irp_type,
        size: irp.size,
        stack_count: irp.stack_count,
        current_location: irp.current_location,
        pending_returned: irp.pending_returned,
        requestor_mode: irp.requestor_mode,
        io_status: irp.io_status.map(|status| Hex(status.into())),
        user_event: Hex(irp.user_event.0),
        user_buffer: Hex(irp.user_buffer.0),
        mdl_address: Hex(irp.mdl_address.0),
        thread: Hex(irp.thread.0),
        current_stack: irp.current_stack.as_ref().map(io_stack),
    }
}

/// `_IRP` plus its current `_IO_STACK_LOCATION`.
pub fn irp(irp: &IrpInfo) -> View {
    irp_shape(irp).into_view()
}

/// `_DRIVER_OBJECT`: header fields, device chain, and the 28-entry `IRP_MJ_*`
/// dispatch table (each routine resolved to its nearest symbol).
pub fn driver_object(target: &Target, d: &DriverObjectDetail) -> View {
    let dtb = target.kernel_dtb();
    DriverObject {
        object: Hex(d.object.0),
        via_pointer: d.via_pointer,
        name: d.name.clone(),
        driver_start: Hex(d.driver_start.0),
        driver_size: d.driver_size,
        driver_section: Hex(d.driver_section.0),
        driver_unload: Hex(d.driver_unload.0),
        devices: d
            .device_chain
            .iter()
            .map(|x| DriverDeviceLink {
                device: Hex(x.device.0),
                device_type: x.device_type,
                flags: x.flags,
                characteristics: x.characteristics,
                attached: Hex(x.attached.0),
                next: Hex(x.next.0),
            })
            .collect(),
        dispatch: d
            .dispatch
            .iter()
            .enumerate()
            .map(|(index, routine)| IrpDispatchRoutine {
                index,
                name: format!("IRP_MJ_{}", irp_major_function_name(index as u8)),
                routine: Hex(routine.0),
                symbol: target
                    .symbols
                    .format_closest_symbol_for_address(dtb, *routine),
            })
            .collect(),
    }
    .into_view()
}

/// `_DEVICE_OBJECT` plus its `AttachedDevice` stack.
pub fn device_object(d: &DeviceObjectDetail) -> View {
    DeviceObject {
        object: Hex(d.object.0),
        via_pointer: d.via_pointer,
        device_type: d.device_type,
        flags: d.flags,
        characteristics: d.characteristics,
        driver_object: Hex(d.driver_object.0),
        attached_device: Hex(d.attached_device.0),
        next_device: Hex(d.next_device.0),
        current_irp: Hex(d.current_irp.0),
        device_extension: Hex(d.device_extension.0),
        attached_stack: d
            .attached_stack
            .iter()
            .map(|x| AttachedDevice {
                device: Hex(x.device.0),
                driver_object: Hex(x.driver_object.0),
                device_type: x.device_type,
                flags: x.flags,
            })
            .collect(),
    }
    .into_view()
}

/// An object's executive header, type, and name, plus a directory's contents.
pub fn object(detail: &ObjectDetail) -> View {
    let o = &detail.header;
    ExecutiveObject {
        input: Hex(o.input.0),
        mode: o.mode,
        header: Hex(o.header.0),
        body: Hex(o.body.0),
        pointer_count: o.pointer_count,
        handle_count: o.handle_count,
        type_index: o.type_index,
        type_object: o.type_object.map(|t| Hex(t.0)),
        type_name: o.type_name.clone(),
        info_mask: o.info_mask,
        name_info: o.name_info.map(|n| Hex(n.0)),
        name: o.name.clone(),
        entries: detail.entries.as_ref().map(|entries| {
            entries
                .iter()
                .map(|entry| ObjectDirectoryEntry {
                    name: entry.name.clone(),
                    object: Hex(entry.object.0),
                    r#type: entry.type_name.clone(),
                })
                .collect()
        }),
    }
    .into_view()
}

/// One notification-callback row; `symbol` is resolved by the surface (it also
/// drives MCP's symbol filter) and passed in.
pub fn notify_callback(c: &NotifyCallbackInfo, symbol: Option<String>) -> View {
    NotifyCallback {
        kind: c.kind,
        index: c.index,
        function: Hex(c.function.0),
        symbol,
        block: Hex(c.block.0),
        raw: Hex(c.raw.0),
        context: Hex(c.context.0),
    }
    .into_view()
}

/// One system-service table (the kernel SSDT or the win32k shadow).
pub fn ssdt_table(t: &SsdtTableInfo) -> View {
    SsdtTable {
        label: t.label.clone(),
        base: Hex(t.base.0),
        limit: t.limit,
        entries: t
            .entries
            .iter()
            .map(|e| SsdtEntry {
                index: e.index,
                target: Hex(e.target.0),
                symbol: e.symbol.clone(),
                module: e.module.clone(),
            })
            .collect(),
    }
    .into_view()
}

/// One discovered in-flight IRP plus the context it was found in.
pub fn irp_hit(h: &IrpHit) -> View {
    InFlightIrp {
        irp: Hex(h.irp.0),
        source: h.source,
        stack_count: h.stack_count,
        current_location: h.current_location,
        pid: h.pid,
        tid: h.tid,
        ethread: h.ethread.map(|e| Hex(e.0)),
        state: h.state.map(kthread_state_name),
        wait_reason: h.wait_reason.map(wait_reason_name),
        driver: h.driver.clone(),
        device: h.device.map(|d| Hex(d.0)),
    }
    .into_view()
}

/// A `_DRIVER_OBJECT` as enumerated from the object directory.
pub fn driver_object_info(driver: &DriverObjectInfo) -> View {
    DriverObjectSummary {
        name: driver.name.clone(),
        object: Hex(driver.object.0),
        driver_start: Hex(driver.driver_start.0),
        driver_size: driver.driver_size,
        device_object: Hex(driver.device_object.0),
        driver_unload: Hex(driver.driver_unload.0),
    }
    .into_view()
}

fn handle_entry_shape(entry: &HandleEntryDetail) -> HandleEntry {
    HandleEntry {
        handle: Hex(entry.handle),
        entry: Hex(entry.entry.0),
        object: Diag::of(&entry.object, |address| Hex(address.0)),
        type_name: Diag::of(&entry.type_name, Clone::clone),
        name: Diag::of(&entry.name, Clone::clone),
        granted_access: Diag::of(&entry.granted_access, |access| Hex((*access).into())),
        attributes: Diag::of(&entry.attributes, |attributes| Hex((*attributes).into())),
    }
}

pub fn handle_entry(entry: &HandleEntryDetail) -> View {
    handle_entry_shape(entry).into_view()
}

pub fn handle_table(summary: &HandleTableSummary) -> View {
    HandleTable {
        process: process(&summary.process),
        table: Hex(summary.table.0),
        table_level: summary.table_level,
        advertised_handles: summary.advertised_handles,
        scanned_handles: summary.scanned_handles,
        skipped_entries: summary.skipped_entries,
        truncated: summary.truncated,
        entries: summary.entries.iter().map(handle_entry_shape).collect(),
    }
    .into_view()
}

pub fn file_object(file: &FileObjectDetail) -> View {
    let hex = |value: &VirtAddr| Hex(value.0);
    let flag = |value: &bool| *value;
    FileObject {
        address: Hex(file.address.0),
        file_type: Diag::of(&file.file_type, |value| (*value).into()),
        size: Diag::of(&file.size, |value| (*value).into()),
        device_object: Diag::of(&file.device_object, hex),
        device_type: Diag::of(&file.device_type, |value| Hex((*value).into())),
        device_name: Diag::of(&file.device_name, Clone::clone),
        file_name: Diag::of(&file.file_name, Clone::clone),
        related_file_object: Diag::of(&file.related_file_object, hex),
        flags: Diag::of(&file.flags, |value| Hex((*value).into())),
        current_byte_offset: Diag::of(&file.current_byte_offset, |value| *value),
        fs_context: Diag::of(&file.fs_context, hex),
        fs_context2: Diag::of(&file.fs_context2, hex),
        section_object_pointer: Diag::of(&file.section_object_pointer, hex),
        private_cache_map: Diag::of(&file.private_cache_map, hex),
        final_status: Diag::of(&file.final_status, |value| Hex(*value as u32 as u64)),
        lock_operation: Diag::of(&file.lock_operation, flag),
        delete_pending: Diag::of(&file.delete_pending, flag),
        read_access: Diag::of(&file.read_access, flag),
        write_access: Diag::of(&file.write_access, flag),
        delete_access: Diag::of(&file.delete_access, flag),
        shared_read: Diag::of(&file.shared_read, flag),
        shared_write: Diag::of(&file.shared_write, flag),
        shared_delete: Diag::of(&file.shared_delete, flag),
    }
    .into_view()
}

fn resource_shape(resource: &ResourceDetail) -> ExecutiveResource {
    ExecutiveResource {
        address: Hex(resource.address.0),
        active_count: Diag::of(&resource.active_count, |value| (*value).into()),
        flags: Diag::of(&resource.flags, |value| Hex((*value).into())),
        contention_count: Diag::of(&resource.contention_count, |value| *value),
        shared_waiters: Diag::of(&resource.shared_waiters, |value| *value),
        exclusive_waiters: Diag::of(&resource.exclusive_waiters, |value| *value),
        owners: Diag::of(&resource.owners, |owners| {
            owners
                .iter()
                .map(|owner: &ResourceOwnerInfo| ResourceOwner {
                    thread: Hex(owner.thread.0),
                    count: owner.count.into(),
                })
                .collect()
        }),
    }
}

pub fn resource(resource: &ResourceDetail) -> View {
    resource_shape(resource).into_view()
}

pub fn resource_list(summary: &ResourceListSummary) -> View {
    ResourceList {
        head: Hex(summary.head.0),
        resources: summary.resources.iter().map(resource_shape).collect(),
        termination: list_termination(&summary.termination),
    }
    .into_view()
}

fn irp_find_entry(entry: &IrpFindEntry) -> PoolIrp {
    PoolIrp {
        irp: irp_shape(&entry.irp),
        pool_header: entry.pool_header.map(|header| Hex(header.0)),
        tag: entry.tag.clone(),
        original_file_object: Hex(entry.original_file_object.0),
        mdl_process: entry.mdl_process.map(|process| Hex(process.0)),
        driver: entry.driver.clone(),
        completed: entry.completed(),
    }
}

/// `!irpfind`'s pool scan and the IRPs it found.
pub fn irp_find(detail: &IrpFindDetail) -> View {
    IrpFindResult {
        pool: match detail.pool {
            IrpPool::NonPaged => "nonpaged",
            IrpPool::Paged => "paged",
        },
        region_start: Hex(detail.region_start.0),
        region_end: Hex(detail.region_end.0),
        scan_start: Hex(detail.scan_start.0),
        criteria: detail.criteria.map(|criteria| IrpFindCriteria {
            name: criteria.name(),
            value: Hex(criteria.value()),
        }),
        scanned_pages: detail.scanned_pages,
        big_pool_status: detail.big_pool_status.clone(),
        irps: detail.irps.iter().map(irp_find_entry).collect(),
        truncated: detail.truncated,
        interrupted: detail.interrupted,
        restart: detail.restart.map(|restart| Hex(restart.0)),
    }
    .into_view()
}

/// `!htrace`: a process's handle traces, newest first.
pub fn handle_traces(detail: &HandleTraceDetail) -> View {
    HandleTraces {
        process: process(&detail.process),
        object_table: Hex(detail.object_table.0),
        debug_info: detail.debug_info.map(|info| Hex(info.0)),
        table_size: detail.table_size,
        recorded: detail.recorded,
        parsed: detail.parsed,
        unreadable: detail.unreadable,
        traces: detail
            .traces
            .iter()
            .map(|trace| HandleTrace {
                handle: Hex(trace.handle),
                kind: trace.kind,
                kind_name: handle_trace_kind_name(trace.kind),
                process_id: trace.process_id,
                thread_id: trace.thread_id,
                stack: trace
                    .stack
                    .iter()
                    .map(|(address, symbol)| HandleTraceFrame {
                        address: Hex(address.0),
                        symbol: symbol.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
    .into_view()
}

fn alpc_kind(kind: Option<AlpcPortKind>) -> Option<&'static str> {
    kind.map(AlpcPortKind::name)
}

/// ALPC fields by snake_case name: which ones exist depends on the build.
fn alpc_fields(fields: &[AlpcField]) -> View {
    View::Object(
        fields
            .iter()
            .map(|field| (field.key, View::Hex(field.value.0)))
            .collect(),
    )
}

fn alpc_connection(connection: &AlpcConnectionDetail) -> AlpcConnection {
    AlpcConnection {
        communication_info: Hex(connection.communication_info.0),
        server_port: Hex(connection.server_port.0),
        server_queued: connection.server_queued,
        client_port: Hex(connection.client_port.0),
        client_queued: connection.client_queued,
        client_owner: Hex(connection.client_owner.0),
        client_owner_name: connection.client_owner_name.clone(),
    }
}

/// `!alpc /p`: a port, its queues, and a connection port's connections.
pub fn alpc_port(port: &AlpcPortDetail) -> View {
    let hex = |value: Option<VirtAddr>| value.map(|at| Hex(at.0));
    AlpcPort {
        address: Hex(port.address.0),
        name: port.name.clone(),
        pointer_count: port.pointer_count,
        handle_count: port.handle_count,
        kind: alpc_kind(port.kind),
        state: port.state.map(Hex),
        port_type: port.port_type,
        state_flags: port.state_flags.clone(),
        owner: Hex(port.owner.0),
        owner_name: port.owner_name.clone(),
        communication_info: Hex(port.communication_info.0),
        connection_port: hex(port.connection_port),
        server_port: hex(port.server_port),
        client_port: hex(port.client_port),
        sequence_no: port.sequence_no,
        completion_port: hex(port.completion_port),
        completion_list: hex(port.completion_list),
        port_context: hex(port.port_context),
        attribute_flags: port.attribute_flags.map(Hex),
        max_message_length: port.max_message_length,
        queues: port
            .queues
            .iter()
            .map(|queue| AlpcQueue {
                field: queue.field,
                key: queue.key,
                length: queue.length,
                entries: queue.entries.iter().map(|at| Hex(at.0)).collect(),
                termination: list_termination(&queue.termination),
            })
            .collect(),
        direct_queue_length: port.direct_queue_length,
        connections: port.connections.iter().map(alpc_connection).collect(),
        connection_termination: port.connection_termination.as_ref().map(list_termination),
    }
    .into_view()
}

/// `!alpc /m`: a message, its state, and the port queue holding it.
pub fn alpc_message(message: &AlpcMessageDetail) -> View {
    AlpcMessage {
        address: Hex(message.address.0),
        message_id: message.message_id,
        callback_id: message.callback_id,
        sequence_no: message.sequence_no,
        message_type: message.message_type.map(Hex),
        message_type_name: message.message_type.and_then(lpc_message_type_name),
        data_length: message.data_length,
        total_length: message.total_length,
        client_process_id: message.client_process_id,
        client_thread_id: message.client_thread_id,
        state: message.state.map(Hex),
        queue_type: message.queue_type,
        queue_port_type: message.queue_port_type,
        state_flags: message.state_flags.clone(),
        owner_port: Hex(message.owner_port.0),
        owner_port_kind: alpc_kind(message.owner_port_kind),
        port_queue: Hex(message.port_queue.0),
        port_queue_kind: alpc_kind(message.port_queue_kind),
        port_queue_owner: message.port_queue_owner.map(|owner| Hex(owner.0)),
        port_queue_owner_name: message.port_queue_owner_name.clone(),
        cancel_sequence_no: message.cancel_sequence_no,
        extension_buffer_size: message.extension_buffer_size,
        pointers: alpc_fields(&message.pointers),
        attributes: alpc_fields(&message.attributes),
    }
    .into_view()
}

/// `!alpc /lpp`: the connection ports a process owns and the client ports it
/// holds.
pub fn alpc_process_ports(ports: &AlpcProcessPortsDetail) -> View {
    AlpcProcessPorts {
        process: process(&ports.process),
        created: ports
            .created
            .iter()
            .map(|port| AlpcOwnedPort {
                handle: Hex(port.handle),
                port: Hex(port.port.0),
                name: port.name.clone(),
                connections: port.connections.iter().map(alpc_connection).collect(),
                termination: list_termination(&port.termination),
            })
            .collect(),
        connected: ports
            .connected
            .iter()
            .map(|port| AlpcClientPort {
                handle: Hex(port.handle),
                port: Hex(port.port.0),
                queued: port.queued,
                connection_port: Hex(port.connection_port.0),
                connection_name: port.connection_name.clone(),
                server_port: Hex(port.server_port.0),
                server_queued: port.server_queued,
                server_owner: port.server_owner.map(|owner| Hex(owner.0)),
                server_owner_name: port.server_owner_name.clone(),
            })
            .collect(),
        server_ports: ports.server_ports,
        scanned_handles: ports.scanned_handles,
        advertised_handles: ports.advertised_handles,
        skipped_entries: ports.skipped_entries,
    }
    .into_view()
}
