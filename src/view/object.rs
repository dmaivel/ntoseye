//! Object- and I/O-manager [`View`] builders: IRPs, driver and
//! device objects, object headers, notification callbacks, and service
//! tables.

use ntoseye_macros::record;

use crate::target::irpfind::{IrpFindDetail, IrpFindEntry, IrpPool};
use crate::target::object::{
    DeviceObjectDetail, DriverObjectDetail, DriverObjectInfo, IoStackLocationInfo, IrpHit, IrpInfo,
    NotifyCallback as NotifyCallbackInfo, ObjectDetail, SsdtTable as SsdtTableInfo,
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
