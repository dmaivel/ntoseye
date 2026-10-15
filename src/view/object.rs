//! Object- and I/O-manager [`View`] builders: IRPs, driver and
//! device objects, object headers, handles, file objects, executive
//! resources, notification callbacks, service tables, and ALPC ports.

use super::record::Keyed;
use crate::target::DiagnosticValue;
use ntoseye_macros::record;

use super::list::{ListEnd, list_termination};
use super::process::process;
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
use crate::target::{
    Target, irp_major_function_name, irp_minor_function_name, kthread_state_name, wait_reason_name,
};
use crate::types::VirtAddr;

/// An `_IO_STACK_LOCATION`, which is the part of an IRP for one driver.
#[record]
pub struct IoStackLocation {
    pub address: VirtAddr,
    /// The `IRP_MJ_*` code.
    pub major_function: u8,
    /// The name of the major function (`IRP_MJ_READ`, ...).
    pub major_function_name: String,
    pub minor_function: u8,
    /// The name of the minor function (`IRP_MN_START_DEVICE`, ...), for
    /// Plug and Play, power, WMI, and SCSI requests.
    pub minor_function_name: Option<String>,
    /// `Flags`, the request's `SL_*` flags.
    #[record(hex)]
    pub flags: u8,
    /// `Control`: `SL_PENDING_RETURNED` (0x01) and when the completion
    /// routine runs, `SL_INVOKE_ON_CANCEL` (0x20), `SL_INVOKE_ON_SUCCESS`
    /// (0x40) and `SL_INVOKE_ON_ERROR` (0x80).
    #[record(hex)]
    pub control: u8,
    /// `Parameters.Others.Argument1` to `Argument4`: the first four
    /// words of the request's parameters, such as a read's length and
    /// offset or an IOCTL's buffer lengths and code.
    #[record(hex)]
    pub arguments: Vec<u64>,
    pub device_object: VirtAddr,
    pub file_object: VirtAddr,
    /// The completion routine that the driver of the next location up
    /// set for when this location's driver completes the IRP.
    pub completion_routine: VirtAddr,
    /// The context argument of the completion routine.
    pub context: VirtAddr,
}

/// An `_IRP` and its I/O stack locations (`!irp`).
#[record]
pub struct Irp {
    pub address: VirtAddr,
    /// `Type`, which is `IO_TYPE_IRP` (6) for a valid IRP.
    pub r#type: u16,
    /// `Size` in bytes, including the stack locations.
    pub size: u16,
    pub stack_count: u8,
    /// `CurrentLocation`, which is more than `stack_count` after the IRP
    /// completes.
    pub current_location: u8,
    pub pending_returned: bool,
    /// 0 for `KernelMode`, 1 for `UserMode`.
    pub requestor_mode: u8,
    /// `IoStatus.Status` as an NTSTATUS. None if ntoseye cannot read it.
    #[record(hex)]
    pub io_status: Option<u32>,
    pub user_event: VirtAddr,
    pub user_buffer: VirtAddr,
    pub mdl_address: VirtAddr,
    /// `AssociatedIrp.SystemBuffer`, the copy of the data for buffered I/O.
    pub system_buffer: VirtAddr,
    /// `Tail.Overlay.Thread`, the thread that issued the IRP.
    pub thread: VirtAddr,
    /// Every stack location, from location 1 (the lowest driver's) to
    /// `stack_count`, ending early at one ntoseye cannot read.
    pub stack: Vec<IoStackLocation>,
    /// None if the current location is out of range or ntoseye cannot read it.
    pub current_stack: Option<IoStackLocation>,
}

/// A device on the `DeviceObject`/`NextDevice` chain of a driver.
#[record]
pub struct DriverDeviceLink {
    pub device: VirtAddr,
    pub device_type: u32,
    pub flags: u32,
    pub characteristics: u32,
    /// `AttachedDevice`, the device layered above this device. 0 if there is none.
    pub attached: VirtAddr,
    /// `NextDevice`, the next device of the driver. 0 at the end of the chain.
    pub next: VirtAddr,
}

/// One slot in the `MajorFunction` dispatch table.
#[record]
pub struct IrpDispatchRoutine {
    /// The `IRP_MJ_*` code.
    pub index: usize,
    /// The name of the major function (`IRP_MJ_CREATE`, ...).
    pub name: String,
    pub routine: VirtAddr,
    /// The nearest symbol to the routine. None if no symbol resolves.
    pub symbol: Option<String>,
}

/// A `_DRIVER_OBJECT` with its device chain and dispatch table (`!drvobj`).
#[record]
pub struct DriverObject {
    pub object: VirtAddr,
    /// Whether the argument pointed to a pointer to the driver object.
    pub via_pointer: bool,
    /// `DriverName`. None if ntoseye cannot read it.
    pub name: Option<String>,
    pub driver_start: VirtAddr,
    /// The size of the driver image in bytes.
    pub driver_size: u64,
    pub driver_section: VirtAddr,
    pub driver_unload: VirtAddr,
    pub devices: Vec<DriverDeviceLink>,
    /// The 28 `IRP_MJ_*` dispatch routines, in `IRP_MJ_*` code order.
    pub dispatch: Vec<IrpDispatchRoutine>,
}

/// A device on the `AttachedDevice` stack of a device.
#[record]
pub struct AttachedDevice {
    pub device: VirtAddr,
    pub driver_object: VirtAddr,
    pub device_type: u32,
    pub flags: u32,
}

/// A `_DEVICE_OBJECT` and the devices attached above it (`!devobj`).
#[record]
pub struct DeviceObject {
    pub object: VirtAddr,
    /// Whether the argument pointed to a pointer to the device object.
    pub via_pointer: bool,
    pub device_type: u32,
    pub flags: u32,
    pub characteristics: u32,
    pub driver_object: VirtAddr,
    /// The device layered directly above this device. 0 if there is none.
    pub attached_device: VirtAddr,
    /// The next device of the driver. 0 at the end of the chain.
    pub next_device: VirtAddr,
    pub current_irp: VirtAddr,
    pub device_extension: VirtAddr,
    /// The `AttachedDevice` chain, from the bottom up.
    pub attached_stack: Vec<AttachedDevice>,
}

/// A named object in an object directory.
#[record]
pub struct ObjectDirectoryEntry {
    pub name: String,
    pub object: VirtAddr,
    /// The type of the object (`Directory`, `Driver`, `SymbolicLink`, ...).
    /// None if ntoseye cannot decode its header.
    pub r#type: Option<String>,
}

/// An executive object with its `_OBJECT_HEADER`, type, and name, and the
/// entries of a directory (`!object`).
#[record]
pub struct ExecutiveObject {
    /// The address that you gave.
    pub input: VirtAddr,
    /// `body` if the input pointed to the object body, or `header` if it
    /// pointed to the object header.
    pub mode: &'static str,
    pub header: VirtAddr,
    pub body: VirtAddr,
    pub pointer_count: i64,
    pub handle_count: i64,
    /// The decoded `TypeIndex` of the header. None if ntoseye cannot read it.
    pub type_index: Option<u64>,
    /// The `_OBJECT_TYPE`. None if ntoseye cannot resolve it.
    pub type_object: Option<VirtAddr>,
    pub type_name: Option<String>,
    /// The `InfoMask` of the header, which shows which optional headers
    /// come before it.
    pub info_mask: Option<u8>,
    /// The `_OBJECT_HEADER_NAME_INFO`. None if the object has none.
    pub name_info: Option<VirtAddr>,
    /// None for an unnamed object.
    pub name: Option<String>,
    /// The entries of a directory. None for all other objects.
    pub entries: Option<Vec<ObjectDirectoryEntry>>,
}

/// A process, thread, or image notification callback (`callbacks`).
#[record]
pub struct NotifyCallback {
    /// `process`, `thread`, or `image`.
    pub kind: &'static str,
    /// The slot of the callback in the kernel callback array.
    pub index: usize,
    pub function: VirtAddr,
    /// The nearest symbol to the function. None if no symbol resolves.
    pub symbol: Option<String>,
    /// The `_EX_CALLBACK_ROUTINE_BLOCK`.
    pub block: VirtAddr,
    /// The raw `_EX_FAST_REF` value of the slot.
    pub raw: VirtAddr,
    pub context: VirtAddr,
}

/// A slot in a system-service table.
#[record]
pub struct SsdtEntry {
    /// The system-service number.
    pub index: u32,
    /// The routine that the slot resolves to.
    pub target: VirtAddr,
    /// The symbol of the routine. None if no symbol resolves.
    pub symbol: Option<String>,
    /// The module that contains the routine. None if no module contains it.
    pub module: Option<String>,
}

/// A system-service table, either the kernel SSDT or the win32k shadow (`ssdt`).
#[record]
pub struct SsdtTable {
    /// The label of the table.
    pub label: String,
    pub base: VirtAddr,
    /// The number of services.
    pub limit: u32,
    pub entries: Vec<SsdtEntry>,
}

/// An in-flight IRP that ntoseye found on the `IrpList` of a thread or in the
/// `CurrentIrp` of a device (`irps`).
#[record]
pub struct InFlightIrp {
    pub irp: VirtAddr,
    /// Where ntoseye found the IRP: `thread` or `device`.
    pub source: &'static str,
    pub stack_count: u8,
    pub current_location: u8,
    /// The process that issued the IRP. None if ntoseye found the IRP on a device.
    pub pid: Option<u64>,
    /// The thread that issued the IRP. None if ntoseye found the IRP on a device.
    pub tid: Option<u64>,
    pub ethread: Option<VirtAddr>,
    /// The state name of the thread. None if ntoseye found the IRP on a device.
    pub state: Option<&'static str>,
    /// The wait-reason name of the thread. None if ntoseye found the IRP on a
    /// device.
    pub wait_reason: Option<&'static str>,
    /// The driver that owns the device of the current stack location. None if
    /// ntoseye cannot resolve it.
    pub driver: Option<String>,
    /// The device of the current stack location. None if ntoseye cannot resolve it.
    pub device: Option<VirtAddr>,
}

/// A `_DRIVER_OBJECT` from the Driver and FileSystem directories of the
/// object manager (`drivers`).
#[record]
pub struct DriverObjectSummary {
    pub name: String,
    pub object: VirtAddr,
    pub driver_start: VirtAddr,
    /// The size of the driver image in bytes.
    pub driver_size: u64,
    /// The first device on the chain of the driver. 0 if there is none.
    pub device_object: VirtAddr,
    pub driver_unload: VirtAddr,
}

/// A handle-table entry (`!handle <handle>`).
#[record]
pub struct HandleEntry {
    #[record(hex)]
    pub handle: u64,
    /// The `_HANDLE_TABLE_ENTRY`.
    pub entry: VirtAddr,
    /// The body of the object.
    pub object: DiagnosticValue<VirtAddr>,
    pub type_name: DiagnosticValue<Option<String>>,
    /// The name of the object, or None for an unnamed object.
    pub name: DiagnosticValue<Option<String>>,
    #[record(hex)]
    pub granted_access: DiagnosticValue<u32>,
    /// The attribute bits of the entry (inherit, protect-from-close, audit).
    #[record(hex)]
    pub attributes: DiagnosticValue<u32>,
}

/// The handle table of a process (`!handle`).
#[record]
pub struct HandleTable {
    /// The process that owns the table.
    pub process: super::process::ProcessIdentity,
    /// The `_HANDLE_TABLE`.
    pub table: VirtAddr,
    /// The level of the table (0-2), which is the number of pointer levels
    /// before the entries.
    pub table_level: u8,
    /// The handle count that the table reports.
    pub advertised_handles: usize,
    pub scanned_handles: usize,
    /// The number of entries that ntoseye could not read.
    pub skipped_entries: usize,
    /// Whether the enumeration stopped at its limit.
    pub truncated: bool,
    pub entries: Vec<HandleEntry>,
}

/// A `_FILE_OBJECT` (`!fileobj`).
#[record]
pub struct FileObject {
    pub address: VirtAddr,
    /// `Type`, which is `IO_TYPE_FILE` (5) for a valid file object.
    pub file_type: DiagnosticValue<i16>,
    pub size: DiagnosticValue<i16>,
    pub device_object: DiagnosticValue<VirtAddr>,
    #[record(hex)]
    pub device_type: DiagnosticValue<u32>,
    /// The object name of the device, or None for an unnamed device.
    pub device_name: DiagnosticValue<Option<String>>,
    pub file_name: DiagnosticValue<String>,
    pub related_file_object: DiagnosticValue<VirtAddr>,
    #[record(hex)]
    pub flags: DiagnosticValue<u32>,
    pub current_byte_offset: DiagnosticValue<i64>,
    /// The `FsContext` of the file system (its FCB).
    pub fs_context: DiagnosticValue<VirtAddr>,
    /// The `FsContext2` of the file system (its CCB).
    pub fs_context2: DiagnosticValue<VirtAddr>,
    pub section_object_pointer: DiagnosticValue<VirtAddr>,
    pub private_cache_map: DiagnosticValue<VirtAddr>,
    /// The NTSTATUS that the file object completed with.
    #[record(hex)]
    pub final_status: DiagnosticValue<u64>,
    pub lock_operation: DiagnosticValue<bool>,
    pub delete_pending: DiagnosticValue<bool>,
    pub read_access: DiagnosticValue<bool>,
    pub write_access: DiagnosticValue<bool>,
    pub delete_access: DiagnosticValue<bool>,
    pub shared_read: DiagnosticValue<bool>,
    pub shared_write: DiagnosticValue<bool>,
    pub shared_delete: DiagnosticValue<bool>,
}

/// A thread that owns an executive resource.
#[record]
pub struct ResourceOwner {
    pub thread: VirtAddr,
    /// The number of times that the thread acquired the resource.
    pub count: i32,
}

/// An `_ERESOURCE` (`!locks <address>`).
#[record]
pub struct ExecutiveResource {
    pub address: VirtAddr,
    pub active_count: DiagnosticValue<i16>,
    #[record(hex)]
    pub flags: DiagnosticValue<u16>,
    pub contention_count: DiagnosticValue<u32>,
    /// The number of threads that wait for shared access.
    pub shared_waiters: DiagnosticValue<u32>,
    /// The number of threads that wait for exclusive access.
    pub exclusive_waiters: DiagnosticValue<u32>,
    /// The threads that own the resource.
    pub owners: DiagnosticValue<Vec<ResourceOwner>>,
}

/// The executive-resource list of the kernel (`!locks`).
#[record]
pub struct ResourceList {
    /// `nt!ExpSystemResourcesList`.
    pub head: VirtAddr,
    pub resources: Vec<ExecutiveResource>,
    pub termination: ListEnd,
}

/// An IRP that `!irpfind` found in pool.
#[record]
pub struct PoolIrp {
    pub irp: Irp,
    /// The `_POOL_HEADER` before the IRP. None for a big-pool allocation.
    pub pool_header: Option<VirtAddr>,
    /// The pool tag of the allocation.
    pub tag: String,
    /// `Tail.Overlay.OriginalFileObject`.
    pub original_file_object: VirtAddr,
    /// `MdlAddress->Process`. None if the IRP has no MDL.
    pub mdl_process: Option<VirtAddr>,
    /// The driver that owns the device of the current stack location. None if
    /// ntoseye cannot resolve it.
    pub driver: Option<String>,
    /// Whether all stack locations are used, which means that completion of
    /// the IRP is in progress or done.
    pub completed: bool,
}

/// The criteria that an `!irpfind` search used to match IRPs.
#[record]
pub struct IrpFindCriteria {
    /// `arg`, `device`, `fileobject`, `mdlprocess`, `thread`, or
    /// `userevent`.
    pub name: &'static str,
    #[record(hex)]
    pub value: u64,
}

/// One `!irpfind` pool scan.
#[record]
pub struct IrpFindResult {
    /// `nonpaged` or `paged`.
    pub pool: &'static str,
    pub region_start: VirtAddr,
    pub region_end: VirtAddr,
    /// The address where the page scan started: the region start or the
    /// restart address.
    pub scan_start: VirtAddr,
    /// None if the scan has no filter.
    pub criteria: Option<IrpFindCriteria>,
    pub scanned_pages: u64,
    /// The result of the big-pool table scan.
    pub big_pool_status: String,
    pub irps: Vec<PoolIrp>,
    /// Whether the result limit caused ntoseye to leave out IRPs, which
    /// happens when the page scan stopped at `restart` or ntoseye did not
    /// check some big-pool allocations.
    pub truncated: bool,
    pub interrupted: bool,
    /// The address where the page scan can continue. None if the scan finished.
    pub restart: Option<VirtAddr>,
}

/// A return address on the stack of a handle trace.
#[record]
pub struct HandleTraceFrame {
    pub address: VirtAddr,
    /// The symbol of the address in the traced process. None if no symbol
    /// resolves.
    pub symbol: Option<String>,
}

/// One `_HANDLE_TRACE_DB_ENTRY`.
#[record]
pub struct HandleTrace {
    #[record(hex)]
    pub handle: u64,
    /// 1 open, 2 close, 3 bad reference.
    pub kind: u32,
    /// `OPEN`, `CLOSE`, `BAD REFERENCE`, or `UNKNOWN`.
    pub kind_name: &'static str,
    pub process_id: u64,
    pub thread_id: u64,
    /// Newest frame first.
    pub stack: Vec<HandleTraceFrame>,
}

/// The handle traces of a process (`!htrace`).
#[record]
pub struct HandleTraces {
    /// The traced process.
    pub process: super::process::ProcessIdentity,
    pub object_table: VirtAddr,
    /// The `_HANDLE_TRACE_DEBUG_INFO`. None if handle tracing is off.
    pub debug_info: Option<VirtAddr>,
    /// The capacity of the ring.
    pub table_size: u64,
    /// The total number of recorded traces, of which the ring keeps the
    /// last `table_size`.
    pub recorded: u64,
    /// The number of ring slots that ntoseye read.
    pub parsed: u64,
    /// The number of ring slots that ntoseye could not read.
    pub unreadable: u64,
    /// The matching traces, newest first.
    pub traces: Vec<HandleTrace>,
}

/// A connection to an ALPC connection port, with its communication info
/// and the two ports that it connects.
#[record]
pub struct AlpcConnection {
    pub communication_info: VirtAddr,
    pub server_port: VirtAddr,
    /// The number of messages queued on the server port (main, large, and
    /// pending). None if ntoseye cannot read it.
    pub server_queued: Option<u64>,
    pub client_port: VirtAddr,
    /// The number of messages queued on the client port. None if ntoseye cannot
    /// read it.
    pub client_queued: Option<u64>,
    /// The `_EPROCESS` of the client.
    pub client_owner: VirtAddr,
    pub client_owner_name: Option<String>,
}

/// One message queue of an ALPC port, or its wait queue.
#[record]
pub struct AlpcQueue {
    /// The `_ALPC_PORT` list head, for example `PendingQueue`.
    pub field: &'static str,
    /// The snake_case name of the queue.
    pub key: &'static str,
    /// The count that the port keeps for the queue. None if the port keeps no
    /// count.
    pub length: Option<u64>,
    /// The queued `_KALPC_MESSAGE`s. For the wait queue, the waiting
    /// `_ETHREAD`s.
    pub entries: Vec<VirtAddr>,
    pub termination: ListEnd,
}

/// An `_ALPC_PORT` (`!alpc /p`). A field is None if this Windows build does
/// not have it, or if ntoseye cannot read it.
#[record]
pub struct AlpcPort {
    pub address: VirtAddr,
    pub name: Option<String>,
    pub pointer_count: i64,
    pub handle_count: i64,
    /// The WinDbg port type name (`ALPC_CONNECTION_PORT`, ...).
    pub kind: Option<&'static str>,
    /// `u1.State`.
    #[record(hex)]
    pub state: Option<u64>,
    /// The `Type` bits of `u1.State`.
    pub port_type: Option<u64>,
    /// The PDB names of the one-bit `u1.s1` state flags that are set.
    pub state_flags: Vec<String>,
    /// The `_EPROCESS` that owns the port.
    pub owner: VirtAddr,
    pub owner_name: Option<String>,
    pub communication_info: VirtAddr,
    pub connection_port: Option<VirtAddr>,
    pub server_port: Option<VirtAddr>,
    pub client_port: Option<VirtAddr>,
    pub sequence_no: Option<u64>,
    pub completion_port: Option<VirtAddr>,
    pub completion_list: Option<VirtAddr>,
    pub port_context: Option<VirtAddr>,
    /// `PortAttributes.Flags`.
    #[record(hex)]
    pub attribute_flags: Option<u64>,
    /// `PortAttributes.MaxMessageLength`.
    pub max_message_length: Option<u64>,
    pub queues: Vec<AlpcQueue>,
    pub direct_queue_length: Option<u64>,
    /// The connections of a connection port.
    pub connections: Vec<AlpcConnection>,
    /// How the walk of the connection list ended. None if there was no walk.
    pub connection_termination: Option<ListEnd>,
}

/// A `_KALPC_MESSAGE` (`!alpc /m`). A field is None if this Windows build
/// does not have it, or if ntoseye cannot read it.
#[record]
pub struct AlpcMessage {
    pub address: VirtAddr,
    pub message_id: Option<u64>,
    pub callback_id: Option<u64>,
    pub sequence_no: Option<u64>,
    /// `PortMessage.u2.s2.Type`.
    #[record(hex)]
    pub message_type: Option<u64>,
    /// The `LPC_*` name of the low byte of the message type.
    pub message_type_name: Option<&'static str>,
    pub data_length: Option<u64>,
    pub total_length: Option<u64>,
    /// `PortMessage.ClientId`, the sender.
    pub client_process_id: Option<u64>,
    pub client_thread_id: Option<u64>,
    /// `u1.State`.
    #[record(hex)]
    pub state: Option<u64>,
    /// The `QueueType` bits of `u1.State`.
    pub queue_type: Option<u64>,
    /// The `QueuePortType` bits of `u1.State`.
    pub queue_port_type: Option<u64>,
    /// The PDB names of the one-bit `u1.s1` state flags that are set.
    pub state_flags: Vec<String>,
    pub owner_port: VirtAddr,
    /// The WinDbg port type name of the owner port.
    pub owner_port_kind: Option<&'static str>,
    /// The port whose queue holds the message.
    pub port_queue: VirtAddr,
    pub port_queue_kind: Option<&'static str>,
    /// The `_EPROCESS` that owns the queue port.
    pub port_queue_owner: Option<VirtAddr>,
    pub port_queue_owner_name: Option<String>,
    pub cancel_sequence_no: Option<u64>,
    pub extension_buffer_size: Option<u64>,
    /// The pointer fields of the message in this build, by snake_case name.
    pub pointers: Keyed<VirtAddr>,
    /// The `_KALPC_MESSAGE_ATTRIBUTES` fields in this build, by snake_case
    /// name.
    pub attributes: Keyed<VirtAddr>,
}

/// A connection port that a process owns, and its connections.
#[record]
pub struct AlpcOwnedPort {
    #[record(hex)]
    pub handle: u64,
    pub port: VirtAddr,
    pub name: Option<String>,
    pub connections: Vec<AlpcConnection>,
    pub termination: ListEnd,
}

/// A client communication port that a process holds, and the ports that it
/// is connected to.
#[record]
pub struct AlpcClientPort {
    #[record(hex)]
    pub handle: u64,
    pub port: VirtAddr,
    /// The number of messages queued on the port. None if ntoseye cannot read it.
    pub queued: Option<u64>,
    pub connection_port: VirtAddr,
    pub connection_name: Option<String>,
    pub server_port: VirtAddr,
    /// The number of messages queued on the server port. None if ntoseye cannot
    /// read it.
    pub server_queued: Option<u64>,
    /// The `_EPROCESS` of the server. None if ntoseye cannot read it.
    pub server_owner: Option<VirtAddr>,
    pub server_owner_name: Option<String>,
}

/// The ALPC ports that a process holds handles to (`!alpc /lpp`).
#[record]
pub struct AlpcProcessPorts {
    pub process: super::process::ProcessIdentity,
    /// The connection ports that the process owns.
    pub created: Vec<AlpcOwnedPort>,
    /// The client ports that the process holds.
    pub connected: Vec<AlpcClientPort>,
    /// The number of server communication ports that the process holds,
    /// which are its ends of connections to its own ports.
    pub server_ports: usize,
    pub scanned_handles: usize,
    /// The handle count that the table reports.
    pub advertised_handles: usize,
    /// The number of handle-table entries that ntoseye could not read.
    pub skipped_entries: usize,
}

fn io_stack(s: &IoStackLocationInfo) -> IoStackLocation {
    IoStackLocation {
        address: s.address,
        major_function: s.major_function,
        major_function_name: format!("IRP_MJ_{}", irp_major_function_name(s.major_function)),
        minor_function: s.minor_function,
        minor_function_name: irp_minor_function_name(s.major_function, s.minor_function)
            .map(|name| format!("IRP_MN_{name}")),
        flags: s.flags,
        control: s.control,
        arguments: s.arguments.to_vec(),
        device_object: s.device_object,
        file_object: s.file_object,
        completion_routine: s.completion_routine,
        context: s.context,
    }
}

/// `_IRP` and its `_IO_STACK_LOCATION`s.
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
        system_buffer: irp.system_buffer,
        thread: irp.thread,
        stack: irp.stack.iter().map(io_stack).collect(),
        current_stack: irp.current_stack().map(io_stack),
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
                symbol: target.format_code_address(dtb, *routine),
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
fn alpc_fields(fields: &[AlpcField]) -> Keyed<VirtAddr> {
    fields
        .iter()
        .map(|field| (field.key, field.value))
        .collect()
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
