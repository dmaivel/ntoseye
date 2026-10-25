//! Object-manager inspectors: names, directories, driver/device objects, IRPs, handles, file objects, resources, object headers, notify callbacks, SSDT.

use std::sync::Arc;

use ntoseye_macros::record;

use crate::base::bytes;
use crate::base::error::{Error, Result};
use crate::base::memory::{MemoryOps, PAGE_SIZE};
use crate::base::types::VirtAddr;
use crate::nt::bugchecks::looks_like_kernel_pointer;
use crate::nt::guest::{Guest, ProcessInfo};
use crate::nt::layout::{StructRef, TypeInfo, Types};
use crate::nt::symbols::format_symbol_with_offset;

use super::{
    DiagnosticValue, ListCursor, ListTermination, Target, bounded_record_list_walk,
    fast_ref_address, irp_major_function_name, irp_minor_function_name, kthread_state_name,
    wait_reason_name,
};

/// A `_DRIVER_OBJECT` from the Driver and FileSystem directories of the
/// object manager (`drivers`).
#[record]
pub struct DriverObjectInfo {
    /// The name of the driver object.
    pub name: String,
    /// The `_DRIVER_OBJECT` address.
    pub object: VirtAddr,
    /// The base address of the driver image.
    #[record(rename = "start")]
    pub driver_start: VirtAddr,
    /// The size of the driver image in bytes.
    #[record(rename = "size")]
    pub driver_size: u64,
    /// The first device on the chain of the driver. 0 if there is none.
    pub device_object: VirtAddr,
    pub driver_unload: VirtAddr,
}

/// An `_IRP` and its I/O stack locations (`!irp`).
#[record(impl)]
pub struct IrpInfo {
    pub address: VirtAddr,
    /// `Type`, which is `IO_TYPE_IRP` (6) for a valid IRP.
    #[record(rename = "type")]
    pub irp_type: u16,
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
    /// `stack_count`, ending early at one ntoseye cannot read; empty when
    /// `StackCount` is implausible.
    pub stack: Vec<IoStackLocationInfo>,
}

impl IrpInfo {
    /// The location that `CurrentLocation` names, if the IRP has not
    /// completed and ntoseye read it.
    pub fn current_stack(&self) -> Option<&IoStackLocationInfo> {
        usize::from(self.current_location)
            .checked_sub(1)
            .and_then(|index| self.stack.get(index))
    }
}

#[record]
impl IrpInfo {
    /// The location that `CurrentLocation` names. None if the current
    /// location is out of range or ntoseye cannot read it.
    #[record(getter, rename = "current_stack")]
    pub fn current_stack_location(&self) -> Option<IoStackLocationInfo> {
        self.current_stack().cloned()
    }
}

/// The most stack locations read for one IRP. The I/O manager allocates a
/// few dozen at most, so a larger `StackCount` is garbage.
const MAX_IRP_STACK_COUNT: u8 = 0x40;

/// `SL_PENDING_RETURNED`: the driver of this location returned
/// `STATUS_PENDING`.
pub const SL_PENDING_RETURNED: u8 = 0x01;
/// `SL_INVOKE_ON_CANCEL`, `SL_INVOKE_ON_SUCCESS` and `SL_INVOKE_ON_ERROR`:
/// when the location's completion routine runs.
pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;
pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;

/// An `_IO_STACK_LOCATION`, which is the part of an IRP for one driver.
#[record(impl)]
pub struct IoStackLocationInfo {
    pub address: VirtAddr,
    /// The `IRP_MJ_*` code.
    pub major_function: u8,
    pub minor_function: u8,
    /// `Flags`, the request's `SL_*` flags, such as
    /// `SL_OVERRIDE_VERIFY_VOLUME`.
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
    pub arguments: [u64; 4],
    pub device_object: VirtAddr,
    pub file_object: VirtAddr,
    /// The completion routine that the driver of the next location up
    /// set for when this location's driver completes the IRP.
    pub completion_routine: VirtAddr,
    /// The context argument of the completion routine.
    pub context: VirtAddr,
}

#[record]
impl IoStackLocationInfo {
    /// The name of the major function (`IRP_MJ_READ`, ...).
    #[record(getter)]
    pub fn major_function_name(&self) -> String {
        format!("IRP_MJ_{}", irp_major_function_name(self.major_function))
    }

    /// The name of the minor function (`IRP_MN_START_DEVICE`, ...), for
    /// Plug and Play, power, WMI, and SCSI requests.
    #[record(getter)]
    pub fn minor_function_name(&self) -> Option<String> {
        irp_minor_function_name(self.major_function, self.minor_function)
            .map(|name| format!("IRP_MN_{name}"))
    }
}

impl IoStackLocationInfo {
    /// Whether nothing was ever written to the location: a driver below
    /// the current one that the IRP has not reached. A request a driver
    /// got always names its device.
    pub fn is_unused(&self) -> bool {
        self.device_object.is_zero()
            && self.file_object.is_zero()
            && self.completion_routine.is_zero()
            && self.context.is_zero()
            && self.major_function == 0
            && self.minor_function == 0
            && self.flags == 0
            && self.control == 0
            && self.arguments == [0; 4]
    }
}

/// A `_DRIVER_OBJECT` with its device chain and dispatch table (`!drvobj`).
#[record]
pub struct DriverObjectDetail {
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
    /// The `DeviceObject`/`NextDevice` chain.
    pub devices: Vec<DriverDeviceLink>,
    /// The 28 `IRP_MJ_*` dispatch routines (`MajorFunction`), in `IRP_MJ_*`
    /// code order.
    pub dispatch: Vec<IrpDispatchRoutine>,
}

/// One slot in the `MajorFunction` dispatch table.
#[record(impl)]
pub struct IrpDispatchRoutine {
    /// The `IRP_MJ_*` code.
    pub index: usize,
    pub routine: VirtAddr,
    /// The nearest symbol to the routine. None if no symbol resolves.
    pub symbol: Option<String>,
}

#[record]
impl IrpDispatchRoutine {
    /// The name of the major function (`IRP_MJ_CREATE`, ...).
    #[record(getter)]
    pub fn name(&self) -> String {
        format!("IRP_MJ_{}", irp_major_function_name(self.index as u8))
    }
}

/// A device on the `DeviceObject`/`NextDevice` chain of a driver.
#[record]
pub struct DriverDeviceLink {
    /// The `_DEVICE_OBJECT` address.
    #[record(rename = "address")]
    pub device: VirtAddr,
    pub device_type: u32,
    pub flags: u32,
    pub characteristics: u32,
    /// `AttachedDevice`, the device layered above this device. 0 if there is none.
    pub attached: VirtAddr,
    /// `NextDevice`, the next device of the driver. 0 at the end of the chain.
    pub next: VirtAddr,
}

/// A `_DEVICE_OBJECT` and the devices attached above it (`!devobj`).
#[record]
pub struct DeviceObjectDetail {
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

/// A device on the `AttachedDevice` stack of a device.
#[record]
pub struct AttachedDevice {
    pub device: VirtAddr,
    pub driver_object: VirtAddr,
    pub device_type: u32,
    pub flags: u32,
}

/// An executive object's `_OBJECT_HEADER`, type, and name.
#[record]
pub struct ObjectHeaderDetail {
    /// The address that you gave.
    pub input: VirtAddr,
    /// `body` if the input pointed to the object body, or `header` if it
    /// pointed to the object header.
    pub mode: ObjectHeaderInput,
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
}

/// An executive object with its header, type, and name, and the entries of
/// a directory (`!object`).
#[record]
pub struct ObjectDetail {
    #[record(rename = "info")]
    pub header: ObjectHeaderDetail,
    /// The entries of a directory, by name. None for all other objects.
    pub entries: Option<Vec<ObjectDirectoryEntry>>,
}

/// A named object in an object directory.
#[record]
pub struct ObjectDirectoryEntry {
    pub name: String,
    pub object: VirtAddr,
    /// The type of the object (`Directory`, `Driver`, `SymbolicLink`, ...).
    /// None if ntoseye cannot decode its header.
    #[record(rename = "type")]
    pub type_name: Option<String>,
}

/// What `!object` names: an object by body or header address, or by its
/// path in the object namespace (`\Driver\ACPI`).
#[derive(Debug, Clone)]
pub enum ObjectName {
    Address(VirtAddr),
    Path(String),
}

/// The object type name of an object directory.
const DIRECTORY_TYPE: &str = "Directory";

/// What the address given to `inspect_object_header` pointed to: `body` or
/// `header`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectHeaderInput {
    Body,
    Header,
}

/// The kind of a notification callback: `process`, `thread`, or `image`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyCallbackKind {
    Process,
    Thread,
    Image,
}

/// Where ntoseye found an IRP: `thread` (an `IrpList`) or `device` (a
/// `CurrentIrp`).
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrpSource {
    Thread,
    Device,
}

/// A process, thread, or image notification callback (`callbacks`).
#[record]
pub struct NotifyCallback {
    /// `process`, `thread`, or `image`.
    pub kind: NotifyCallbackKind,
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
#[record(impl)]
pub struct IrpHit {
    pub irp: VirtAddr,
    /// Where ntoseye found the IRP: `thread` or `device`.
    pub source: IrpSource,
    pub stack_count: u8,
    pub current_location: u8,
    /// The process that issued the IRP. None if ntoseye found the IRP on a device.
    pub pid: Option<u64>,
    /// The thread that issued the IRP. None if ntoseye found the IRP on a device.
    pub tid: Option<u64>,
    pub ethread: Option<VirtAddr>,
    /// The `_KTHREAD.State` of the thread. None if ntoseye found the IRP on a
    /// device.
    pub state: Option<u8>,
    /// The `_KTHREAD.WaitReason` of the thread. None if ntoseye found the IRP
    /// on a device.
    pub wait_reason: Option<u8>,
    /// The driver that owns the device of the current stack location. None if
    /// ntoseye cannot resolve it.
    pub driver: Option<String>,
    /// The device of the current stack location. None if ntoseye cannot resolve it.
    pub device: Option<VirtAddr>,
}

#[record]
impl IrpHit {
    /// The state name of the thread. None if ntoseye found the IRP on a device.
    #[record(getter)]
    pub fn state_name(&self) -> Option<&'static str> {
        self.state.map(kthread_state_name)
    }

    /// The wait-reason name of the thread. None if ntoseye found the IRP on a
    /// device.
    #[record(getter)]
    pub fn wait_reason_name(&self) -> Option<&'static str> {
        self.wait_reason.map(wait_reason_name)
    }
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
    pub process: ProcessInfo,
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
    pub final_status: DiagnosticValue<u32>,
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub termination: ListTermination,
}

/// The most resources `!locks` walks: a guard against a corrupt list, far
/// above what a system has.
pub const MAX_RESOURCES: usize = 1 << 20;

/// `_ERESOURCE.Flag` of a resource owned exclusively.
pub const RESOURCE_OWNED_EXCLUSIVE: u16 = 0x80;

/// `_CM_KEY_NODE` (and KCB) flag of a hive's root key.
const KEY_HIVE_ENTRY: u64 = 0x4;

struct ObjectNameLayout {
    body_offset: u64,
    name_info_at: NameInfoAt,
    creator_info_size: Option<u64>,
    name_info_size: u64,
    name_offset: u64,
    /// `_OBJECT_HEADER_NAME_INFO.Directory`, the directory the object is
    /// named in.
    directory_offset: Option<u64>,
}

/// Where an object header records where its name info is.
#[derive(Clone, Copy)]
enum NameInfoAt {
    /// The offset of `InfoMask` (Windows 7 on), whose bits say which
    /// optional headers precede the header.
    InfoMask(u64),
    /// The offset of `NameInfoOffset` (Vista and earlier): how far before
    /// the header the name info starts, 0 for none.
    Offset(u64),
}

impl ObjectNameLayout {
    /// The `_OBJECT_HEADER_NAME_INFO` of the object whose header is at
    /// `header`; `None` for an unnamed object.
    fn name_info(
        &self,
        memory: &impl MemoryOps<VirtAddr>,
        header: VirtAddr,
    ) -> Result<Option<VirtAddr>> {
        match self.name_info_at {
            NameInfoAt::InfoMask(offset) => {
                self.name_info_address(header, memory.read(header + offset)?)
            }
            NameInfoAt::Offset(offset) => {
                let back: u8 = memory.read(header + offset)?;
                Ok((back != 0).then(|| header - u64::from(back)))
            }
        }
    }

    fn name_info_address(&self, header: VirtAddr, info_mask: u8) -> Result<Option<VirtAddr>> {
        const CREATOR_INFO_BIT: u8 = 0x01;
        const NAME_INFO_BIT: u8 = 0x02;

        if info_mask & NAME_INFO_BIT == 0 {
            return Ok(None);
        }

        // Optional headers run backwards from OBJECT_HEADER in increasing bit
        // order. NameInfo is therefore displaced only by lower-bit CreatorInfo,
        // never by HandleInfo or any higher-bit header.
        let creator_size = if info_mask & CREATOR_INFO_BIT != 0 {
            self.creator_info_size
                .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER_CREATOR_INFO".to_string()))?
        } else {
            0
        };
        let offset = self
            .name_info_size
            .checked_add(creator_size)
            .ok_or_else(|| Error::DebugInfo("object name-info offset overflow".to_string()))?;
        let address =
            header.0.checked_sub(offset).map(VirtAddr).ok_or_else(|| {
                Error::DebugInfo("object name-info address underflow".to_string())
            })?;
        Ok(Some(address))
    }
}

struct ObjectDirectoryLayout {
    buckets_offset: u64,
    bucket_count: u64,
    chain_offset: u64,
    object_offset: u64,
    name_offset: Option<u64>,
}

/// `_IRP.Thread` is a direct field on some builds and inside the `Tail.Overlay`
/// union on others; read whichever is present, else null (never fatal).
pub(crate) fn irp_thread(irp: &StructRef) -> VirtAddr {
    if let Ok(t) = irp.read_pointer("Thread") {
        return t;
    }
    irp.embedded("Tail")
        .and_then(|tail| tail.embedded("Overlay"))
        .and_then(|ov| ov.read_pointer("Thread"))
        .unwrap_or(VirtAddr(0))
}

fn select_object_header_candidate(
    input: VirtAddr,
    body_offset: u64,
    body_candidate: Option<VirtAddr>,
    direct_candidate: Option<VirtAddr>,
    body_has_type: bool,
    direct_has_type: bool,
) -> Option<(VirtAddr, VirtAddr, ObjectHeaderInput)> {
    match (body_candidate, direct_candidate) {
        (Some(header), Some(_)) if body_has_type => Some((header, input, ObjectHeaderInput::Body)),
        (Some(_), Some(header)) if direct_has_type => {
            Some((header, header + body_offset, ObjectHeaderInput::Header))
        }
        // Both locations are readable but neither decodes through the type
        // table. Guessing here would make an arbitrary pool address look valid.
        (Some(_), Some(_)) => None,
        (Some(header), None) => Some((header, input, ObjectHeaderInput::Body)),
        (None, Some(header)) => Some((header, header + body_offset, ObjectHeaderInput::Header)),
        (None, None) => None,
    }
}

/// The `stack_count` stack locations after the `_IRP` at `irp`, read in
/// `types`, up to the first that cannot be read.
fn read_io_stack(
    types: Types<'_>,
    irp: VirtAddr,
    stack_count: u8,
) -> Result<Vec<IoStackLocationInfo>> {
    // The I/O manager allocates at most a few dozen; a larger count is
    // garbage and must not drive reads far past the IRP.
    if stack_count > MAX_IRP_STACK_COUNT {
        return Ok(Vec::new());
    }
    let irp_size = types.layout("_IRP")?.size as u64;
    let layout = types.layout("_IO_STACK_LOCATION")?;
    let stack_size = layout.size as u64;
    let mut stack = Vec::with_capacity(usize::from(stack_count));
    for index in 0..u64::from(stack_count) {
        let address = irp + irp_size + index * stack_size;
        let ios = types
            .struct_with_layout(Arc::clone(&layout), address)
            .prefetch();
        let read = || -> Result<IoStackLocationInfo> {
            let others = ios.embedded("Parameters")?.embedded("Others")?;
            let argument = |name| others.read_uint(name);
            Ok(IoStackLocationInfo {
                address,
                major_function: ios.read_field("MajorFunction")?,
                minor_function: ios.read_field("MinorFunction")?,
                flags: ios.read_field("Flags")?,
                control: ios.read_field("Control")?,
                arguments: [
                    argument("Argument1")?,
                    argument("Argument2")?,
                    argument("Argument3")?,
                    argument("Argument4")?,
                ],
                device_object: ios.read_pointer("DeviceObject")?,
                file_object: ios.read_pointer("FileObject")?,
                completion_routine: ios.read_pointer("CompletionRoutine")?,
                context: ios.read_pointer("Context")?,
            })
        };
        match read() {
            Ok(location) => stack.push(location),
            Err(_) => break,
        }
    }
    Ok(stack)
}

impl Target {
    /// Open a fluent cursor over a kernel struct (ntoskrnl's layout, read
    /// through ntoskrnl's address space).
    fn kernel_struct(&self, name: &str, base: VirtAddr) -> Result<StructRef<'_>> {
        self.guest()?.ntoskrnl.types().struct_at(name, base)
    }

    fn read_kernel_unicode_string(&self, addr: VirtAddr) -> Result<String> {
        self.kernel_struct("_UNICODE_STRING", addr)?
            .read_unicode_string()
    }

    fn object_name_layout(&self) -> Result<ObjectNameLayout> {
        let dtb = self.guest()?.ntoskrnl.dtb();
        let header_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER".to_string()))?;
        let creator_info_size = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER_CREATOR_INFO")
            .map(|ty| ty.size as u64);
        let name_info_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER_NAME_INFO")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER_NAME_INFO".to_string()))?;
        let name_info_at = match header_type.field_offset("InfoMask") {
            Ok(offset) => NameInfoAt::InfoMask(offset),
            Err(_) => NameInfoAt::Offset(header_type.field_offset("NameInfoOffset")?),
        };
        Ok(ObjectNameLayout {
            body_offset: header_type.field_offset("Body")?,
            name_info_at,
            creator_info_size,
            name_info_size: name_info_type.size as u64,
            name_offset: name_info_type.field_offset("Name")?,
            directory_offset: name_info_type.field_offset("Directory").ok(),
        })
    }

    /// The full path of a named object, through the directories it is named
    /// in (`\Device\HarddiskVolume3`); `None` for an unnamed one.
    fn kernel_object_path(&self, object: VirtAddr) -> Result<Option<String>> {
        const MAX_DEPTH: usize = 32;
        let layout = self.object_name_layout()?;
        let memory = self.guest()?.ntoskrnl.memory();
        let mut components = Vec::new();
        let mut current = object;
        for _ in 0..MAX_DEPTH {
            let header = current - layout.body_offset;
            let Some(name_info) = layout.name_info(&memory, header)? else {
                break;
            };
            let name = self.read_kernel_unicode_string(name_info + layout.name_offset)?;
            // The root directory is named `\`.
            if name != "\\" {
                components.push(name);
            }
            let Some(directory) = layout
                .directory_offset
                .map(|offset| memory.read_pointer(name_info + offset))
                .transpose()?
                .filter(|directory| !directory.is_zero())
            else {
                break;
            };
            current = directory;
        }
        if components.is_empty() {
            return Ok(None);
        }
        components.reverse();
        Ok(Some(format!("\\{}", components.join("\\"))))
    }

    /// A name for the object at `body` of type `type_name` that has none in
    /// its header, as WinDbg's `!handle` gives one: a file's path on its
    /// device, a process's image and PID, a thread's TID and process.
    /// `None` for other types; keys are named by [`Self::name_key_handles`].
    fn unnamed_object_name(&self, type_name: &str, body: VirtAddr) -> Result<Option<String>> {
        let types = self.guest()?.ntoskrnl.types_in(self.kernel_dtb());
        match type_name {
            "File" => {
                let file = types.struct_at("_FILE_OBJECT", body)?;
                let name = file.unicode_string("FileName").unwrap_or_default();
                let device = file
                    .read_pointer("DeviceObject")
                    .ok()
                    .filter(|device| !device.is_zero())
                    .and_then(|device| self.kernel_object_path(device).ok().flatten());
                Ok(match (device, name.is_empty()) {
                    (Some(device), _) => Some(format!("{device}{name}")),
                    (None, false) => Some(name),
                    (None, true) => None,
                })
            }
            // Named in one pass per listing (see `name_key_handles`), which
            // reads the registry once.
            "Key" => Ok(None),
            "Process" => {
                let process = types.struct_at("_EPROCESS", body)?;
                let pid = process.read_pointer("UniqueProcessId")?.0;
                let image = process.read_field_bytes("ImageFileName", 15)?;
                let end = image
                    .iter()
                    .position(|&byte| byte == 0)
                    .unwrap_or(image.len());
                Ok(Some(format!(
                    "{} (PID {pid})",
                    String::from_utf8_lossy(&image[..end])
                )))
            }
            "Thread" => {
                let thread = self.thread_info_from_ethread(body)?;
                Ok(thread
                    .tid
                    .map(|tid| match (&thread.process_name, thread.pid) {
                        (Some(process), Some(pid)) => format!("TID {tid} ({process}, PID {pid})"),
                        _ => format!("TID {tid}"),
                    }))
            }
            _ => Ok(None),
        }
    }

    /// Name the key handles of `entries` with their registry paths, reading
    /// the registry once: as the hives name the keys, else, upper-cased, from
    /// the names their control blocks keep.
    fn name_key_handles(&self, entries: &mut [HandleEntry]) {
        let Ok(types) = self
            .guest()
            .map(|guest| guest.ntoskrnl.types_in(self.kernel_dtb()))
        else {
            return;
        };
        let keys: Vec<(usize, VirtAddr)> = entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                matches!(&entry.type_name, DiagnosticValue::Available(Some(name)) if name == "Key")
                    && matches!(entry.name, DiagnosticValue::Available(None))
            })
            .filter_map(|(index, entry)| {
                let DiagnosticValue::Available(body) = entry.object else {
                    return None;
                };
                let kcb = types
                    .struct_at("_CM_KEY_BODY", body)
                    .and_then(|key| key.read_pointer("KeyControlBlock"))
                    .ok()?;
                Some((index, kcb))
            })
            .collect();
        if keys.is_empty() {
            return;
        }
        let kcbs: Vec<VirtAddr> = keys.iter().map(|&(_, kcb)| kcb).collect();
        let paths = self.registry_key_paths(&kcbs);
        for ((index, kcb), path) in keys.into_iter().zip(paths) {
            if let Some(path) = path.or_else(|| self.key_path(kcb).ok()) {
                entries[index].name = DiagnosticValue::Available(Some(path));
            }
        }
    }

    /// The registry path of the key whose control block is `kcb`, from the
    /// names it and its parents keep, upper-cased
    /// (`\REGISTRY\MACHINE\SOFTWARE`).
    fn key_path(&self, kcb: VirtAddr) -> Result<String> {
        const MAX_DEPTH: usize = 512;
        let types = self.guest()?.ntoskrnl.types_in(self.kernel_dtb());
        let kcb_layout = types.layout("_CM_KEY_CONTROL_BLOCK")?;
        let name_layout = types.layout("_CM_NAME_CONTROL_BLOCK")?;
        let name_offset = name_layout.field_offset("Name")?;
        let memory = self.kernel_address_space();
        let mut components = Vec::new();
        let mut current = kcb;
        for _ in 0..MAX_DEPTH {
            if current.is_zero() {
                break;
            }
            let block: VirtAddr =
                VirtAddr(self.read_kernel_layout_field(&kcb_layout, current, "NameBlock")?);
            let compressed =
                self.extract_kernel_layout_bits(&name_layout, block, "Compressed")? != 0;
            let length: u16 = self.read_kernel_layout_field(&name_layout, block, "NameLength")?;
            let mut bytes = vec![0u8; usize::from(length)];
            memory.read_bytes(block + name_offset, &mut bytes)?;
            // A compressed name keeps one byte per character.
            components.push(if compressed {
                bytes.iter().map(|&byte| char::from(byte)).collect()
            } else {
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|&pair| u16::from_le_bytes(pair))
                    .collect();
                String::from_utf16_lossy(&units)
            });
            let parent =
                VirtAddr(self.read_kernel_layout_field(&kcb_layout, current, "ParentKcb")?);
            // A hive's root (KEY_HIVE_ENTRY) hangs under the hive's link in
            // the master hive, which has the same name: the path names it
            // once.
            let hive_root = self.extract_kernel_layout_bits(&kcb_layout, current, "Flags")?
                & KEY_HIVE_ENTRY
                != 0;
            current = if hive_root && !parent.is_zero() {
                VirtAddr(self.read_kernel_layout_field(&kcb_layout, parent, "ParentKcb")?)
            } else {
                parent
            };
        }
        components.reverse();
        Ok(format!("\\{}", components.join("\\")))
    }

    fn read_kernel_object_name(
        &self,
        object: VirtAddr,
        object_name: &ObjectNameLayout,
    ) -> Result<Option<String>> {
        let memory = self.guest()?.ntoskrnl.memory();
        let header = object - object_name.body_offset;
        let Some(name_info) = object_name.name_info(&memory, header)? else {
            return Ok(None);
        };
        Ok(Some(self.read_kernel_unicode_string(
            name_info + object_name.name_offset,
        )?))
    }

    fn object_directory_layout(&self) -> Result<ObjectDirectoryLayout> {
        let dtb = self.guest()?.ntoskrnl.dtb();
        let dir_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_DIRECTORY")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_DIRECTORY".to_string()))?;
        let entry_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_DIRECTORY_ENTRY")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_DIRECTORY_ENTRY".to_string()))?;
        let buckets = dir_type.field("HashBuckets")?;
        Ok(ObjectDirectoryLayout {
            buckets_offset: buckets.offset as u64,
            bucket_count: (buckets.size / self.arch().pointer_size()).max(1),
            chain_offset: entry_type.field_offset("ChainLink")?,
            object_offset: entry_type.field_offset("Object")?,
            name_offset: entry_type.fields.get("Name").map(|f| f.offset as u64),
        })
    }

    fn enumerate_object_directory(
        &self,
        directory: VirtAddr,
        dir: &ObjectDirectoryLayout,
        object_name: &ObjectNameLayout,
    ) -> Result<Vec<(String, VirtAddr)>> {
        let memory = self.guest()?.ntoskrnl.memory();
        let pointer_size = memory.arch().pointer_size();
        let mut out = Vec::new();
        for bucket in 0..dir.bucket_count {
            let entry =
                memory.read_pointer(directory + dir.buckets_offset + bucket * pointer_size)?;
            Self::walk_object_directory_bucket(entry, |entry| {
                let object = memory.read_pointer(entry + dir.object_offset)?;
                if !object.is_zero() {
                    let name = match dir.name_offset {
                        Some(offset) => Some(self.read_kernel_unicode_string(entry + offset)?),
                        None => self.read_kernel_object_name(object, object_name)?,
                    };
                    if let Some(name) = name
                        && !name.is_empty()
                    {
                        out.push((name, object));
                    }
                }
                memory.read_pointer(entry + dir.chain_offset)
            })?;
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    fn walk_object_directory_bucket(
        entry: VirtAddr,
        mut visit: impl FnMut(VirtAddr) -> Result<VirtAddr>,
    ) -> Result<()> {
        let mut cursor = ListCursor::from_first(entry, 4096);
        while let Some(current) = cursor.take_current() {
            cursor.advance(Ok(visit(current)?));
        }
        Ok(())
    }

    pub fn enumerate_driver_objects(&self) -> Result<Vec<DriverObjectInfo>> {
        let guest = self.guest()?;
        guest.memoized_drivers(|| self.walk_driver_objects())
    }

    /// The object at `path` in the object namespace (`\`, `\Driver`,
    /// `\Driver\ACPI`): each component looked up in the directory before it,
    /// from `ObpRootDirectoryObject`, by name without case as the object
    /// manager does. Symbolic links along the path are not followed.
    pub fn object_at_path(&self, path: &str) -> Result<VirtAddr> {
        let components = path
            .strip_prefix('\\')
            .ok_or_else(|| {
                Error::InvalidArgument(format!("object path {path} does not start with \\"))
            })?
            .split('\\')
            .filter(|component| !component.is_empty());
        let guest = self.guest()?;
        let root_ptr = guest.ntoskrnl.symbol("ObpRootDirectoryObject")?.address();
        let mut object = guest.ntoskrnl.memory().read_pointer(root_ptr)?;
        let object_name = self.object_name_layout()?;
        let dir = self.object_directory_layout()?;
        let mut walked = String::new();
        for component in components {
            let type_name = self.inspect_object_header(object)?.type_name;
            if type_name.as_deref() != Some(DIRECTORY_TYPE) {
                return Err(Error::DebugInfo(format!(
                    "{} is a {}, not a directory",
                    if walked.is_empty() { "\\" } else { &walked },
                    type_name.as_deref().unwrap_or("object of unknown type")
                )));
            }
            walked.push('\\');
            walked.push_str(component);
            object = self
                .enumerate_object_directory(object, &dir, &object_name)?
                .into_iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(component))
                .map(|(_, object)| object)
                .ok_or_else(|| Error::DebugInfo(format!("{walked} not found")))?;
        }
        Ok(object)
    }

    /// The object at `address` (body or header) and, when it is a
    /// directory, its entries.
    pub fn inspect_object(&self, address: VirtAddr) -> Result<ObjectDetail> {
        let header = self.inspect_object_header(address)?;
        let entries = if header.type_name.as_deref() == Some(DIRECTORY_TYPE) {
            let object_name = self.object_name_layout()?;
            let dir = self.object_directory_layout()?;
            Some(
                self.enumerate_object_directory(header.body, &dir, &object_name)?
                    .into_iter()
                    .map(|(name, object)| ObjectDirectoryEntry {
                        type_name: self
                            .inspect_object_header(object)
                            .ok()
                            .and_then(|header| header.type_name),
                        name,
                        object,
                    })
                    .collect(),
            )
        } else {
            None
        };
        Ok(ObjectDetail { header, entries })
    }

    /// The address of the object that `name` names.
    pub fn object_address(&self, name: &ObjectName) -> Result<VirtAddr> {
        match name {
            ObjectName::Address(address) => Ok(*address),
            ObjectName::Path(path) => self.object_at_path(path),
        }
    }

    fn walk_driver_objects(&self) -> Result<Vec<DriverObjectInfo>> {
        let object_name = self.object_name_layout()?;
        let dir = self.object_directory_layout()?;
        let driver_dir = self.object_at_path("\\Driver")?;

        let mut drivers = Vec::new();
        for (name, object) in self.enumerate_object_directory(driver_dir, &dir, &object_name)? {
            let driver = self.kernel_struct("_DRIVER_OBJECT", object)?;
            drivers.push(DriverObjectInfo {
                name: format!("\\Driver\\{name}"),
                object,
                driver_start: driver.read_pointer("DriverStart")?,
                driver_size: driver.read_field::<u32>("DriverSize")? as u64,
                device_object: driver.read_pointer("DeviceObject")?,
                driver_unload: driver.read_pointer("DriverUnload")?,
            });
        }
        Ok(drivers)
    }

    /// Decode the `_IRP` at `address` and its I/O stack locations, which
    /// follow it: location N is at `irp + sizeof(_IRP) + (N - 1) *
    /// sizeof(_IO_STACK_LOCATION)`.
    pub fn inspect_irp(&self, address: VirtAddr) -> Result<IrpInfo> {
        self.irp_info(&self.kernel_struct("_IRP", address)?)
    }

    /// [`Self::inspect_irp`] of the `_IRP` under the cursor `irp`, which may
    /// hold a prefetched copy.
    pub(crate) fn irp_info(&self, irp: &StructRef<'_>) -> Result<IrpInfo> {
        let address = irp.addr();
        let io_status = irp
            .embedded("IoStatus")
            .and_then(|s| s.read_field::<u32>("Status"))
            .ok();
        let stack_count: u8 = irp.read_field("StackCount")?;
        let system_buffer = irp
            .embedded("AssociatedIrp")
            .and_then(|associated| associated.read_pointer("SystemBuffer"))
            .unwrap_or(VirtAddr(0));
        Ok(IrpInfo {
            address,
            irp_type: irp.read_field("Type")?,
            size: irp.read_field("Size")?,
            stack_count,
            current_location: irp.read_field("CurrentLocation")?,
            pending_returned: irp.read_field::<u8>("PendingReturned")? != 0,
            requestor_mode: irp.read_field("RequestorMode")?,
            io_status,
            user_event: irp.read_pointer("UserEvent")?,
            user_buffer: irp.read_pointer("UserBuffer")?,
            mdl_address: irp.read_pointer("MdlAddress")?,
            system_buffer,
            thread: irp_thread(irp),
            stack: read_io_stack(irp.types(), address, stack_count).unwrap_or_default(),
        })
    }

    /// The name of the driver whose device object is at `device`, such as
    /// `\Driver\disk`; `None` when it cannot be read or is empty.
    pub fn device_driver_name(&self, device: VirtAddr) -> Option<String> {
        let types = self.guest().ok()?.ntoskrnl.types();
        let driver = types
            .struct_at("_DEVICE_OBJECT", device)
            .and_then(|device| device.read_pointer("DriverObject"))
            .ok()?;
        types
            .struct_at("_DRIVER_OBJECT", driver)
            .and_then(|driver| driver.unicode_string("DriverName"))
            .ok()
            .filter(|name| !name.is_empty())
    }

    /// The `_DEVICE_OBJECT` at `device`, as its driver's chain lists it.
    pub fn read_device_link(&self, device: VirtAddr) -> Result<DriverDeviceLink> {
        let d = self.kernel_struct("_DEVICE_OBJECT", device)?;
        Ok(DriverDeviceLink {
            device,
            device_type: d.read_field("DeviceType")?,
            flags: d.read_field("Flags")?,
            characteristics: d.read_field("Characteristics")?,
            attached: d.read_pointer("AttachedDevice")?,
            next: d.read_pointer("NextDevice")?,
        })
    }

    /// Decode a `_DRIVER_OBJECT` at `addr` (or at the pointer `addr` points to),
    /// including its device chain and `MajorFunction` dispatch table.
    pub fn inspect_driver_object(&self, addr: VirtAddr) -> Result<DriverObjectDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_DRIVER_OBJECT")?;
        let size_off = layout.field_offset("Size")?;
        let mf_off = layout.field_offset("MajorFunction")?;
        let name_off = layout.field_offset("DriverName")?;
        let pointer_size = mem.arch().pointer_size();
        let min_size = mf_off + 28 * pointer_size;

        // A `_DRIVER_OBJECT` has Type == 4 (IO_TYPE_DRIVER) and is large enough
        // to hold the dispatch table; use that to tell a direct object from a
        // pointer to one.
        let valid = |a: VirtAddr| -> bool {
            let ty: u16 = match mem.read(a) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let size: u16 = match mem.read(a + size_off) {
                Ok(v) => v,
                Err(_) => return false,
            };
            ty == 4 && size as u64 >= min_size
        };

        let object = if valid(addr) {
            addr
        } else {
            let ptr = mem.read_pointer(addr)?;
            if !ptr.is_zero() && valid(ptr) {
                ptr
            } else {
                return Err(Error::DebugInfo(format!(
                    "{:#x} is not a _DRIVER_OBJECT or a pointer to one",
                    addr.0
                )));
            }
        };

        let drv = self.kernel_struct("_DRIVER_OBJECT", object)?;
        let name = self
            .read_kernel_unicode_string(object + name_off)
            .ok()
            .filter(|s| !s.is_empty());

        let mut device_chain = Vec::new();
        let mut devices = ListCursor::from_first(drv.read_pointer("DeviceObject")?, 128);
        while let Some(cur) = devices.take_current() {
            let Ok(link) = self.read_device_link(cur) else {
                break;
            };
            devices.advance(Ok(link.next));
            device_chain.push(link);
        }

        let dtb = self.kernel_dtb();
        let mut dispatch = Vec::with_capacity(28);
        for index in 0..28usize {
            let routine = mem
                .read_pointer(object + mf_off + index as u64 * pointer_size)
                .unwrap_or(VirtAddr(0));
            dispatch.push(IrpDispatchRoutine {
                index,
                routine,
                symbol: self.format_code_address(dtb, routine),
            });
        }

        Ok(DriverObjectDetail {
            object,
            via_pointer: object != addr,
            name,
            driver_start: drv.read_pointer("DriverStart")?,
            driver_size: drv.read_field::<u32>("DriverSize")? as u64,
            driver_section: drv.read_pointer("DriverSection")?,
            driver_unload: drv.read_pointer("DriverUnload")?,
            devices: device_chain,
            dispatch,
        })
    }

    /// Decode a `_DEVICE_OBJECT` at `addr` (or the pointer `addr` points to) and
    /// walk its `AttachedDevice` stack.
    pub fn inspect_device_object(&self, addr: VirtAddr) -> Result<DeviceObjectDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_DEVICE_OBJECT")?;
        let size_off = layout.field_offset("Size")?;
        let min_size = layout.size as u64;

        let valid = |a: VirtAddr| -> bool {
            let ty: u16 = match mem.read(a) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let size: u16 = match mem.read(a + size_off) {
                Ok(v) => v,
                Err(_) => return false,
            };
            ty == 3 && size as u64 >= min_size
        };

        let object = if valid(addr) {
            addr
        } else {
            let ptr = mem.read_pointer(addr)?;
            if !ptr.is_zero() && valid(ptr) {
                ptr
            } else {
                return Err(Error::DebugInfo(format!(
                    "{:#x} is not a _DEVICE_OBJECT or a pointer to one",
                    addr.0
                )));
            }
        };

        let dev = self.kernel_struct("_DEVICE_OBJECT", object)?;
        let attached_device = dev.read_pointer("AttachedDevice")?;

        let mut attached_stack = Vec::new();
        let mut devices = ListCursor::from_first(attached_device, 64);
        while let Some(cur) = devices.take_current() {
            let Ok(d) = self.kernel_struct("_DEVICE_OBJECT", cur) else {
                break;
            };
            let next = d.read_pointer("AttachedDevice")?;
            attached_stack.push(AttachedDevice {
                device: cur,
                driver_object: d.read_pointer("DriverObject")?,
                device_type: d.read_field("DeviceType")?,
                flags: d.read_field("Flags")?,
            });
            devices.advance(Ok(next));
        }

        Ok(DeviceObjectDetail {
            object,
            via_pointer: object != addr,
            device_type: dev.read_field("DeviceType")?,
            flags: dev.read_field("Flags")?,
            characteristics: dev.read_field("Characteristics")?,
            driver_object: dev.read_pointer("DriverObject")?,
            attached_device,
            next_device: dev.read_pointer("NextDevice")?,
            current_irp: dev.read_pointer("CurrentIrp")?,
            device_extension: dev.read_pointer("DeviceExtension")?,
            attached_stack,
        })
    }

    fn handle_entry_address(
        &self,
        table_base: VirtAddr,
        level: u8,
        index: usize,
        entry_size: usize,
    ) -> Result<VirtAddr> {
        let memory = self.kernel_address_space();
        let pointer_size = memory.arch().pointer_size() as usize;
        let pointers_per_page = PAGE_SIZE / pointer_size;
        let leaf_entries = PAGE_SIZE / entry_size;
        match level {
            0 => Ok(table_base + (index * entry_size) as u64),
            1 => {
                let leaf = memory
                    .read_pointer(table_base + ((index / leaf_entries) * pointer_size) as u64)?;
                if leaf.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle leaf {} is null",
                        index / leaf_entries
                    )));
                }
                Ok(leaf + ((index % leaf_entries) * entry_size) as u64)
            }
            2 => {
                let middle_index = index / (leaf_entries * pointers_per_page);
                let leaf_index = (index / leaf_entries) % pointers_per_page;
                let middle =
                    memory.read_pointer(table_base + (middle_index * pointer_size) as u64)?;
                if middle.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle middle table {middle_index} is null"
                    )));
                }
                let leaf = memory.read_pointer(middle + (leaf_index * pointer_size) as u64)?;
                if leaf.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle leaf {middle_index}:{leaf_index} is null"
                    )));
                }
                Ok(leaf + ((index % leaf_entries) * entry_size) as u64)
            }
            _ => Err(Error::DebugInfo(format!(
                "unsupported HANDLE_TABLE level {level}"
            ))),
        }
    }

    fn decode_handle_entry(
        &self,
        entry_layout: &TypeInfo,
        entry: VirtAddr,
        handle: u64,
    ) -> HandleEntry {
        let object = (|| -> Result<VirtAddr> {
            if entry_layout.fields.contains_key("ObjectPointerBits") {
                let bits =
                    self.extract_kernel_layout_bits(entry_layout, entry, "ObjectPointerBits")?;
                let mut pointer = bits << 4;
                if pointer & (1 << 47) != 0 {
                    pointer |= 0xffff_0000_0000_0000;
                }
                return Ok(VirtAddr(pointer));
            }
            let raw = self.extract_kernel_layout_bits(entry_layout, entry, "Object")?;
            Ok(VirtAddr(raw & !0xf))
        })();

        let granted_access = ["GrantedAccessBits", "GrantedAccess"]
            .into_iter()
            .find_map(|name| {
                entry_layout
                    .fields
                    .contains_key(name)
                    .then(|| self.extract_kernel_layout_bits(entry_layout, entry, name))
            })
            .unwrap_or_else(|| Err(Error::FieldNotFound("GrantedAccessBits".to_string())))
            .map(|value| value as u32);
        // Before Windows 8, `ObAttributes` overlays the object pointer, whose
        // low three bits are the attributes.
        let overlaid = entry_layout
            .field_offset("ObAttributes")
            .ok()
            .zip(entry_layout.field_offset("Object").ok())
            .is_some_and(|(attributes, object)| attributes == object);
        let attributes = ["ObAttributes", "Attributes"]
            .into_iter()
            .find_map(|name| {
                entry_layout
                    .fields
                    .contains_key(name)
                    .then(|| self.extract_kernel_layout_bits(entry_layout, entry, name))
            })
            .unwrap_or_else(|| Err(Error::FieldNotFound("ObAttributes".to_string())))
            .map(|value| if overlaid { value & 0x7 } else { value } as u32);

        // The entry holds the object's header; the body follows it, and is
        // what the record names and what `!object` and `!fileobj` take.
        let object = object.and_then(|header| {
            if header.is_zero() {
                return Ok(header);
            }
            let types = self.guest()?.ntoskrnl.types();
            let body = types.layout("_OBJECT_HEADER")?.field_offset("Body")?;
            Ok(header + body)
        });
        let header = object
            .as_ref()
            .map_err(|error| Error::DebugInfo(error.to_string()))
            .and_then(|object| {
                if object.is_zero() {
                    Err(Error::DebugInfo("handle entry is free".to_string()))
                } else {
                    // Looked up by its body, so the bytes before a header
                    // can't pass for one.
                    self.inspect_object_header(*object)
                }
            });
        let type_name = match &header {
            Ok(header) => DiagnosticValue::Available(header.type_name.clone()),
            Err(error) => DiagnosticValue::unavailable(error.to_string()),
        };
        let name = match &header {
            Ok(header) => DiagnosticValue::Available(header.name.clone().or_else(|| {
                let type_name = header.type_name.as_deref()?;
                self.unnamed_object_name(type_name, header.body)
                    .ok()
                    .flatten()
            })),
            Err(error) => DiagnosticValue::unavailable(error.to_string()),
        };

        HandleEntry {
            handle,
            entry,
            object: DiagnosticValue::from_result(object),
            type_name,
            name,
            granted_access: DiagnosticValue::from_result(granted_access),
            attributes: DiagnosticValue::from_result(attributes),
        }
    }

    fn handle_table_context(
        &self,
        process: ProcessInfo,
    ) -> Result<(ProcessInfo, VirtAddr, VirtAddr, u8, usize, Arc<TypeInfo>)> {
        // The `_EPROCESS` and its handle table are kernel memory, which the
        // kernel's DTB maps even where a dump lacks the process's own page
        // directory.
        let types = self.guest()?.ntoskrnl.types_in(self.kernel_dtb());
        let eprocess = types.struct_at("_EPROCESS", process.eprocess)?;
        let table = eprocess.read_pointer("ObjectTable")?;
        if table.is_zero() {
            return Err(Error::DebugInfo(
                "_EPROCESS.ObjectTable is null".to_string(),
            ));
        }
        let table_layout = types.layout("_HANDLE_TABLE")?;
        let table_code = types
            .struct_with_layout(Arc::clone(&table_layout), table)
            .read_pointer("TableCode")?
            .0;
        let level = (table_code & 3) as u8;
        if level > 2 {
            return Err(Error::DebugInfo(format!(
                "unsupported HANDLE_TABLE level {level}"
            )));
        }
        // A ULONG; the field after it is not part of the count.
        let next_handle = u64::from(self.read_kernel_layout_field::<u32>(
            &table_layout,
            table,
            "NextHandleNeedingPool",
        )?);
        let entry_layout = types.layout("_HANDLE_TABLE_ENTRY")?;
        Ok((
            process,
            table,
            VirtAddr(table_code & !3),
            level,
            (next_handle / 4) as usize,
            entry_layout,
        ))
    }

    /// List non-free handles in the selected/current process.  Both page-table
    /// traversal and slot count are bounded by `limit`.
    pub fn enumerate_handles(&self, limit: usize) -> Result<HandleTable> {
        self.enumerate_process_handles(self.selected_process_info()?, limit.clamp(1, 4096))
    }

    /// List the non-free handles of `process`, scanning at most `limit`
    /// slots.
    pub fn enumerate_process_handles(
        &self,
        process: ProcessInfo,
        limit: usize,
    ) -> Result<HandleTable> {
        let (process, table, table_base, level, advertised, entry_layout) =
            self.handle_table_context(process)?;
        let scanned = advertised.min(limit);
        let mut entries = Vec::new();
        let mut skipped_entries = 0usize;
        for index in 0..scanned {
            let entry = match self.handle_entry_address(table_base, level, index, entry_layout.size)
            {
                Ok(entry) => entry,
                Err(_) => {
                    skipped_entries += 1;
                    continue;
                }
            };
            let decoded = self.decode_handle_entry(&entry_layout, entry, (index as u64) * 4);
            if !matches!(
                decoded.object,
                DiagnosticValue::Available(address) if address.is_zero()
            ) {
                entries.push(decoded);
            }
        }
        self.name_key_handles(&mut entries);
        Ok(HandleTable {
            process,
            table,
            table_level: level,
            advertised_handles: advertised,
            scanned_handles: scanned,
            skipped_entries,
            truncated: advertised > scanned,
            entries,
        })
    }

    /// Decode one handle from the same selected/current process handle table.
    pub fn inspect_handle(&self, handle: u64) -> Result<HandleEntry> {
        if handle & 3 != 0 {
            return Err(Error::DebugInfo(format!(
                "handle {handle:#x} is not 4-byte aligned"
            )));
        }
        let (_, _, table_base, level, advertised, entry_layout) =
            self.handle_table_context(self.selected_process_info()?)?;
        let index = (handle / 4) as usize;
        if index >= advertised {
            return Err(Error::DebugInfo(format!(
                "handle {handle:#x} is beyond NextHandleNeedingPool ({:#x})",
                advertised * 4
            )));
        }
        let entry = self.handle_entry_address(table_base, level, index, entry_layout.size)?;
        let mut entries = [self.decode_handle_entry(&entry_layout, entry, handle)];
        self.name_key_handles(&mut entries);
        let [entry] = entries;
        Ok(entry)
    }

    /// Decode a `_FILE_OBJECT` strictly from the loaded kernel PDB layout.
    pub fn inspect_file_object(&self, address: VirtAddr) -> Result<FileObject> {
        let types = self.guest()?.ntoskrnl.types_in(self.kernel_dtb());
        let layout = types.layout("_FILE_OBJECT")?;
        let file = types.struct_with_layout(Arc::clone(&layout), address);
        let read_ptr = |name| DiagnosticValue::from_result(file.read_pointer(name));
        let read_bool = |name| {
            DiagnosticValue::from_result(
                self.read_kernel_layout_field::<u8>(&layout, address, name)
                    .map(|value| value != 0),
            )
        };
        let device_object = file.read_pointer("DeviceObject");
        let device_type = match &device_object {
            Ok(device) if !device.is_zero() => DiagnosticValue::from_result(
                self.inspect_device_object(*device)
                    .map(|detail| detail.device_type),
            ),
            Ok(_) => DiagnosticValue::unavailable("_FILE_OBJECT.DeviceObject is null"),
            Err(error) => DiagnosticValue::unavailable(error.to_string()),
        };
        let device_name = match &device_object {
            Ok(device) if !device.is_zero() => DiagnosticValue::from_result(
                self.inspect_object_header(*device)
                    .map(|detail| detail.name),
            ),
            Ok(_) => DiagnosticValue::unavailable("_FILE_OBJECT.DeviceObject is null"),
            Err(error) => DiagnosticValue::unavailable(error.to_string()),
        };

        Ok(FileObject {
            address,
            file_type: DiagnosticValue::from_result(
                self.read_kernel_layout_field(&layout, address, "Type"),
            ),
            size: DiagnosticValue::from_result(
                self.read_kernel_layout_field(&layout, address, "Size"),
            ),
            device_object: DiagnosticValue::from_result(device_object),
            device_type,
            device_name,
            file_name: DiagnosticValue::from_result(
                types
                    .struct_at("_FILE_OBJECT", address)?
                    .unicode_string("FileName"),
            ),
            related_file_object: read_ptr("RelatedFileObject"),
            flags: DiagnosticValue::from_result(
                self.read_kernel_layout_field(&layout, address, "Flags"),
            ),
            current_byte_offset: DiagnosticValue::from_result(self.read_kernel_layout_field(
                &layout,
                address,
                "CurrentByteOffset",
            )),
            fs_context: read_ptr("FsContext"),
            fs_context2: read_ptr("FsContext2"),
            section_object_pointer: read_ptr("SectionObjectPointer"),
            private_cache_map: read_ptr("PrivateCacheMap"),
            final_status: DiagnosticValue::from_result(self.read_kernel_layout_field(
                &layout,
                address,
                "FinalStatus",
            )),
            lock_operation: read_bool("LockOperation"),
            delete_pending: read_bool("DeletePending"),
            read_access: read_bool("ReadAccess"),
            write_access: read_bool("WriteAccess"),
            delete_access: read_bool("DeleteAccess"),
            shared_read: read_bool("SharedRead"),
            shared_write: read_bool("SharedWrite"),
            shared_delete: read_bool("SharedDelete"),
        })
    }

    /// Decode one executive resource at an explicit address.
    pub fn inspect_resource(&self, address: VirtAddr) -> Result<ExecutiveResource> {
        const MAX_RESOURCE_OWNERS: usize = 64;
        let types = self.guest()?.ntoskrnl.types_in(self.kernel_dtb());
        let layout = types.layout("_ERESOURCE")?;
        let owner_layout = types.layout("_OWNER_ENTRY")?;
        let owner_thread = |entry: VirtAddr| -> Result<u64> {
            Ok(types
                .struct_with_layout(Arc::clone(&owner_layout), entry)
                .read_pointer("OwnerThread")?
                .0)
        };
        // A 29-bit field above three flags from Windows 10, a whole LONG
        // before.
        let owner_count = |entry: VirtAddr| -> Result<i32> {
            Ok(self.extract_kernel_layout_bits(&owner_layout, entry, "OwnerCount")? as i32)
        };
        let owners = DiagnosticValue::from_result((|| -> Result<Vec<ResourceOwner>> {
            let mut owners = Vec::new();
            let owner_entry = address + layout.field_offset("OwnerEntry")?;
            let thread = owner_thread(owner_entry)?;
            let count = owner_count(owner_entry)?;
            if thread & !3 != 0 && count != 0 {
                owners.push(ResourceOwner {
                    thread: VirtAddr(thread & !3),
                    count,
                });
            }

            // An exclusive owner is OwnerEntry alone; the table keeps the
            // entries of the shared owners before it, which no longer own.
            let flag: u16 = self.read_kernel_layout_field(&layout, address, "Flag")?;
            if flag & RESOURCE_OWNED_EXCLUSIVE != 0 {
                return Ok(owners);
            }
            let table = types
                .struct_with_layout(Arc::clone(&layout), address)
                .read_pointer("OwnerTable")?;
            if table.is_zero() {
                return Ok(owners);
            }
            let table_size: u32 =
                self.read_kernel_layout_field(&owner_layout, table, "TableSize")?;
            if table_size as usize > MAX_RESOURCE_OWNERS {
                return Err(Error::DebugInfo(format!(
                    "_OWNER_ENTRY.TableSize {table_size} exceeds bound {MAX_RESOURCE_OWNERS}"
                )));
            }
            for index in 1..table_size as usize {
                let entry = table + (index * owner_layout.size) as u64;
                let thread = owner_thread(entry)?;
                let count = owner_count(entry)?;
                if thread & !3 != 0 && count != 0 {
                    owners.push(ResourceOwner {
                        thread: VirtAddr(thread & !3),
                        count,
                    });
                }
            }
            Ok(owners)
        })());

        Ok(ExecutiveResource {
            address,
            active_count: DiagnosticValue::from_result(self.read_kernel_layout_field(
                &layout,
                address,
                "ActiveCount",
            )),
            flags: DiagnosticValue::from_result(
                self.read_kernel_layout_field(&layout, address, "Flag"),
            ),
            contention_count: DiagnosticValue::from_result(self.read_kernel_layout_field(
                &layout,
                address,
                "ContentionCount",
            )),
            shared_waiters: DiagnosticValue::from_result(self.read_kernel_layout_field(
                &layout,
                address,
                "NumberOfSharedWaiters",
            )),
            exclusive_waiters: DiagnosticValue::from_result(self.read_kernel_layout_field(
                &layout,
                address,
                "NumberOfExclusiveWaiters",
            )),
            owners,
        })
    }

    /// Enumerate the kernel-maintained executive-resource list when the private
    /// list-head symbol and `_ERESOURCE.SystemResourcesList` metadata exist.
    /// There is deliberately no memory-scan fallback.
    pub fn enumerate_resources(&self, limit: usize) -> Result<ResourceList> {
        let limit = limit.clamp(1, MAX_RESOURCES);
        let guest = self.guest()?;
        let head = guest.ntoskrnl.symbol("ExpSystemResourcesList")?.address();
        let layout = guest.ntoskrnl.types().layout("_ERESOURCE")?;
        let link_offset = layout.field_offset("SystemResourcesList")?;
        let memory = self.kernel_address_space();
        // Each resource is read whole, once: its link to the next is in it.
        let mut read = Vec::new();
        let (records, termination) = bounded_record_list_walk(head, link_offset, limit, |link| {
            if link == head {
                return memory.read_pointer(link);
            }
            let mut bytes = vec![0u8; layout.size];
            memory.read_bytes(link - link_offset, &mut bytes)?;
            let next = bytes::get_u64(&bytes, link_offset as usize)
                .ok_or_else(|| Error::DebugInfo("_ERESOURCE link out of bounds".to_string()))?;
            read.push(bytes);
            Ok(VirtAddr(next))
        });
        let resources = records
            .into_iter()
            .zip(read)
            .map(|(address, bytes)| self.resource_from_bytes(&layout, address, &bytes))
            .collect();
        Ok(ResourceList {
            head,
            resources,
            termination,
        })
    }

    /// The resource at `address` from its bytes, `bytes`; its owners are read
    /// only when it is held (a nonzero `ActiveCount`).
    fn resource_from_bytes(
        &self,
        layout: &TypeInfo,
        address: VirtAddr,
        bytes: &[u8],
    ) -> ExecutiveResource {
        let field = |name: &str, size: usize| -> Result<u64> {
            let offset = layout.field_offset(name)? as usize;
            let raw = bytes
                .get(offset..offset + size)
                .ok_or_else(|| Error::DebugInfo(format!("_ERESOURCE.{name} out of bounds")))?;
            let mut value = [0u8; 8];
            value[..size].copy_from_slice(raw);
            Ok(u64::from_le_bytes(value))
        };
        let active_count = field("ActiveCount", 2).map(|value| value as u16 as i16);
        let owners = match active_count {
            Ok(0) => DiagnosticValue::Available(Vec::new()),
            _ => self.inspect_resource(address).map_or_else(
                |error| DiagnosticValue::unavailable(error.to_string()),
                |held| held.owners,
            ),
        };
        ExecutiveResource {
            address,
            active_count: DiagnosticValue::from_result(active_count),
            flags: DiagnosticValue::from_result(field("Flag", 2).map(|value| value as u16)),
            contention_count: DiagnosticValue::from_result(
                field("ContentionCount", 4).map(|value| value as u32),
            ),
            shared_waiters: DiagnosticValue::from_result(
                field("NumberOfSharedWaiters", 4).map(|value| value as u32),
            ),
            exclusive_waiters: DiagnosticValue::from_result(
                field("NumberOfExclusiveWaiters", 4).map(|value| value as u32),
            ),
            owners,
        }
    }

    /// Decode the executive `_OBJECT_HEADER` for `addr`, accepting either the
    /// object body or the header itself, and resolve its type and name.
    pub fn inspect_object_header(&self, addr: VirtAddr) -> Result<ObjectHeaderDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_OBJECT_HEADER")?;
        let header_size = layout.size as u64;
        let body_off = layout.field_offset("Body")?;
        // Windows 7 on index their type; before, a header holds the type
        // object's address in `Type`.
        let type_index_off = layout.field_offset("TypeIndex").ok();
        let type_pointer_off = match type_index_off {
            Some(_) => None,
            None => Some(layout.field_offset("Type")?),
        };
        let object_name = self.object_name_layout().ok();
        // Windows 10 stores TypeIndex obfuscated: the real index is the
        // stored one ^ the second byte of the header's address ^
        // nt!ObHeaderCookie. Before, there is no cookie and it is stored as
        // is.
        let cookie = match guest.ntoskrnl.symbol("ObHeaderCookie") {
            Ok(symbol) => Some(symbol.read::<u8>()?),
            Err(Error::SymbolNotFound(_)) => None,
            Err(error) => return Err(error),
        };
        let decode = |raw: u8, header: VirtAddr| -> u64 {
            u64::from(cookie.map_or(raw, |cookie| raw ^ (header.0 >> 8) as u8 ^ cookie))
        };
        let type_table = guest
            .ntoskrnl
            .symbol("ObTypeIndexTable")
            .ok()
            .map(|symbol| symbol.address());

        let header_ok = |header: VirtAddr| -> bool {
            header_size
                .checked_sub(1)
                .and_then(|last| header.0.checked_add(last))
                .map(VirtAddr)
                .is_some_and(|end| mem.read::<u8>(header).is_ok() && mem.read::<u8>(end).is_ok())
        };
        let candidate_type_object = |header: VirtAddr| -> Option<VirtAddr> {
            let object = match (type_index_off, type_pointer_off) {
                (Some(offset), _) => {
                    let index = decode(mem.read(header + offset).ok()?, header);
                    mem.read_pointer(type_table? + index * mem.arch().pointer_size())
                }
                (None, Some(offset)) => mem.read_pointer(header + offset),
                (None, None) => return None,
            };
            object
                .ok()
                .filter(|object| looks_like_kernel_pointer(self.arch(), object.0))
        };

        // The input is usually the object body. If both possible headers are
        // readable, use the decoded type table to distinguish a real header
        // from unrelated readable pool bytes before it.
        let body_candidate = addr
            .0
            .checked_sub(body_off)
            .map(VirtAddr)
            .filter(|header| header_ok(*header));
        let direct_candidate = header_ok(addr).then_some(addr);
        let body_type = body_candidate.and_then(candidate_type_object);
        let direct_type = direct_candidate.and_then(candidate_type_object);
        let (header, body, mode) = select_object_header_candidate(
            addr,
            body_off,
            body_candidate,
            direct_candidate,
            body_type.is_some(),
            direct_type.is_some(),
        )
        .ok_or_else(|| {
            Error::DebugInfo(format!("no plausible _OBJECT_HEADER for {:#x}", addr.0))
        })?;

        let h = self.kernel_struct("_OBJECT_HEADER", header)?;
        let info_mask: Option<u8> = h.read_field("InfoMask").ok();

        let type_index: Option<u64> = h
            .read_field::<u8>("TypeIndex")
            .ok()
            .map(|raw| decode(raw, header));

        // The type object: ObTypeIndexTable[index] (the symbol is the array
        // itself), or the header's own pointer before indexes.
        let type_object = match (type_table, type_index) {
            (Some(table), Some(index)) => mem
                .read_pointer(table + index * mem.arch().pointer_size())
                .ok()
                .filter(|object| looks_like_kernel_pointer(self.arch(), object.0)),
            _ => candidate_type_object(header),
        };
        let type_name = type_object.and_then(|object| {
            let off = guest
                .ntoskrnl
                .types()
                .layout("_OBJECT_TYPE")
                .ok()?
                .field_offset("Name")
                .ok()?;
            self.read_kernel_unicode_string(object + off)
                .ok()
                .filter(|s| !s.is_empty())
        });

        let name_info = object_name
            .as_ref()
            .and_then(|layout| layout.name_info(&mem, header).ok().flatten());
        let name = name_info.and_then(|info| {
            object_name.as_ref().and_then(|layout| {
                self.read_kernel_unicode_string(info + layout.name_offset)
                    .ok()
                    .filter(|name| !name.is_empty())
            })
        });

        Ok(ObjectHeaderDetail {
            input: addr,
            mode,
            header,
            body,
            pointer_count: h.read_field("PointerCount")?,
            handle_count: h.read_field("HandleCount")?,
            type_index,
            type_object,
            type_name,
            info_mask,
            name_info,
            name,
        })
    }

    /// Enumerate the process/thread/image notification callbacks registered in
    /// the `Psp*NotifyRoutine` fast-ref arrays.
    pub fn enumerate_notify_callbacks(&self) -> Result<Vec<NotifyCallback>> {
        const MAX_NOTIFY: u64 = 64;
        let sets: [(NotifyCallbackKind, &str); 3] = [
            (NotifyCallbackKind::Process, "PspCreateProcessNotifyRoutine"),
            (NotifyCallbackKind::Thread, "PspCreateThreadNotifyRoutine"),
            (NotifyCallbackKind::Image, "PspLoadImageNotifyRoutine"),
        ];

        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let pointer_size = mem.arch().pointer_size();
        let ex_callback_size = guest
            .ntoskrnl
            .types()
            .layout("_EX_CALLBACK")
            .ok()
            .map(|l| l.size as u64)
            .filter(|s| (pointer_size..=0x40).contains(s))
            .unwrap_or(pointer_size);
        let block_layout = guest
            .ntoskrnl
            .types()
            .layout("_EX_CALLBACK_ROUTINE_BLOCK")
            .ok();
        let function_off = block_layout
            .as_ref()
            .and_then(|l| l.field_offset("Function").ok())
            .unwrap_or(pointer_size);
        let context_off = block_layout
            .as_ref()
            .and_then(|l| l.field_offset("Context").ok())
            .unwrap_or(2 * pointer_size);

        let is_kernel = |a: VirtAddr| looks_like_kernel_pointer(self.arch(), a.0);
        let dtb = self.kernel_dtb();
        let mut out = Vec::new();

        for &(kind, symbol) in &sets {
            let Ok(sym) = guest.ntoskrnl.symbol(symbol) else {
                continue;
            };
            let base = sym.address();
            // The array's size is in no global; it ends before the next of
            // these arrays and their counts. XP's hold 8 slots each, packed
            // together.
            let slots = sets
                .iter()
                .flat_map(|(_, array)| {
                    ["", "Count", "ExCount"].map(|suffix| format!("{array}{suffix}"))
                })
                .filter_map(|name| guest.ntoskrnl.symbol(name).ok())
                .map(|global| global.address())
                .filter(|global| *global > base)
                .map(|global| (global.0 - base.0) / ex_callback_size)
                .fold(MAX_NOTIFY, u64::min);
            for i in 0..slots {
                let entry = base + i * ex_callback_size;
                let Ok(raw) = mem.read_pointer(entry) else {
                    continue;
                };
                if raw.is_zero() {
                    continue;
                }
                let block = fast_ref_address(raw.0);
                if block.is_zero() {
                    continue;
                }
                // Prefer the PDB-described layout; fall back to the stable
                // EX_RUNDOWN_REF / function / context shape when it doesn't
                // point at a kernel routine.
                let mut function = mem
                    .read_pointer(block + function_off)
                    .unwrap_or(VirtAddr(0));
                let mut context = mem.read_pointer(block + context_off).unwrap_or(VirtAddr(0));
                if !is_kernel(function) {
                    function = mem
                        .read_pointer(block + pointer_size)
                        .unwrap_or(VirtAddr(0));
                    context = mem
                        .read_pointer(block + 2 * pointer_size)
                        .unwrap_or(VirtAddr(0));
                }
                if !is_kernel(function) {
                    continue;
                }
                out.push(NotifyCallback {
                    kind,
                    index: i as usize,
                    function,
                    symbol: self.format_code_address(dtb, function),
                    block,
                    raw,
                    context,
                });
            }
        }

        Ok(out)
    }

    fn dump_ssdt_table(&self, label: &str, base: VirtAddr, limit: u32, guest: &Guest) -> SsdtTable {
        let mem = guest.ntoskrnl.memory();
        let dtb = guest.ntoskrnl.dtb();
        let mut entries = Vec::new();
        // Clamp implausible limits so a garbage descriptor can't spin.
        let limit = limit.min(0x4000);
        for i in 0..limit {
            let Ok(raw) = mem.read::<u32>(base + (i as u64) * 4) else {
                break;
            };
            // Entries encode a signed offset in the high 28 bits: target =
            // base + (entry >> 4) with arithmetic shift.
            let offset = (raw as i32 >> 4) as i64;
            let target = VirtAddr((base.0 as i64 + offset) as u64);
            let resolved = self.symbols.find_closest_symbol_for_address(dtb, target);
            let (symbol, module) = match resolved {
                Some((module, name, off)) => (
                    Some(format_symbol_with_offset(&module, &name, off)),
                    Some(module),
                ),
                None => (None, None),
            };
            entries.push(SsdtEntry {
                index: i,
                target,
                symbol,
                module,
            });
        }
        SsdtTable {
            label: label.to_string(),
            base,
            limit,
            entries,
        }
    }

    /// Dump the kernel SSDT (`KiServiceTable`) and, when initialized, the
    /// win32k shadow table from `KeServiceDescriptorTableShadow`.
    pub fn dump_ssdt(&self) -> Result<Vec<SsdtTable>> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let base = guest.ntoskrnl.symbol("KiServiceTable")?.address();
        let limit = guest.ntoskrnl.symbol("KiServiceLimit")?.read::<u32>()?;
        let mut tables = vec![self.dump_ssdt_table("SSDT", base, limit, guest)];

        // Shadow table: [0] is the kernel SSDT, [1] is win32k. Only present once
        // a GUI thread has initialized it.
        if let Ok(sdt) = guest.ntoskrnl.symbol("KeServiceDescriptorTableShadow") {
            let desc = guest.ntoskrnl.types().layout("_KSERVICE_TABLE_DESCRIPTOR");
            let desc_size = desc.as_ref().ok().map(|l| l.size as u64).unwrap_or(0x20);
            let base_off = desc
                .as_ref()
                .ok()
                .and_then(|l| l.field_offset("Base").ok())
                .unwrap_or(0);
            let limit_off = desc
                .as_ref()
                .ok()
                .and_then(|l| l.field_offset("Limit").ok())
                .unwrap_or(0x10);
            let win32k = sdt.address() + desc_size;
            if let Ok(w_base) = mem.read_pointer(win32k + base_off)
                && !w_base.is_zero()
            {
                let w_limit = mem.read::<u32>(win32k + limit_off).unwrap_or(0);
                tables.push(self.dump_ssdt_table("shadow SSDT (win32k)", w_base, w_limit, guest));
            }
        }

        Ok(tables)
    }

    /// Read an `_IRP` only if it looks like one (Type == 6, plausible Size),
    /// returning `(stack_count, current_location)`.
    fn plausible_irp(&self, irp: VirtAddr) -> Option<(u8, u8)> {
        let guest = self.guest.as_ref()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_IRP").ok()?;
        let ty: u16 = mem.read(irp).ok()?;
        if ty != 6 {
            return None;
        }
        let size: u16 = mem.read(irp + layout.field_offset("Size").ok()?).ok()?;
        if (size as u64) < layout.size as u64 || size > 0x1000 {
            return None;
        }
        let sc = mem
            .read::<u8>(irp + layout.field_offset("StackCount").ok()?)
            .unwrap_or(0);
        let cl = mem
            .read::<u8>(irp + layout.field_offset("CurrentLocation").ok()?)
            .unwrap_or(0);
        Some((sc, cl))
    }

    /// Discover in-flight IRPs by walking each thread's `_ETHREAD.IrpList` and
    /// each device's `_DEVICE_OBJECT.CurrentIrp`. `filter` scopes processes
    /// (pid or name substring) and, for the device sweep, driver names.
    pub fn discover_irps(&self, filter: Option<&str>) -> Result<Vec<IrpHit>> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let off = |ty: &str, field: &str| -> Option<u64> {
            guest
                .ntoskrnl
                .types()
                .layout(ty)
                .ok()
                .and_then(|l| l.field_offset(field).ok())
        };
        let read_ptr = |a: VirtAddr| mem.read_pointer(a).ok();

        let filter_l = filter.map(|f| f.to_ascii_lowercase());
        let numeric_filter = filter.and_then(|f| f.parse::<u64>().ok());
        let mut out = Vec::new();

        let procs = guest.enumerate_processes()?;
        let thread_head_off = off("_EPROCESS", "ThreadListHead");
        let thread_link_off = off("_ETHREAD", "ThreadListEntry");
        let irp_list_off = off("_ETHREAD", "IrpList");
        let irp_link_off = off("_IRP", "ThreadListEntry");
        let cid_off = off("_ETHREAD", "Cid");
        let tcb_off = off("_ETHREAD", "Tcb").unwrap_or(0);
        let unique_thread_off = off("_CLIENT_ID", "UniqueThread");
        let state_off = off("_KTHREAD", "State");
        let wait_off = off("_KTHREAD", "WaitReason");

        for p in &procs {
            let matched = match (&filter_l, numeric_filter) {
                (None, _) => true,
                (Some(_), Some(pid)) => p.pid == pid,
                (Some(f), None) => p.name.to_ascii_lowercase().contains(f.as_str()),
            };
            if !matched {
                continue;
            }
            let (Some(head_off), Some(link_off), Some(list_off), Some(rec_off)) =
                (thread_head_off, thread_link_off, irp_list_off, irp_link_off)
            else {
                break;
            };

            // Walk the process thread list (ETHREAD.ThreadListEntry).
            let head = p.eprocess + head_off;
            let (ethreads, _) =
                bounded_record_list_walk(head, link_off, 4096, |link| mem.read_pointer(link));
            for ethread in ethreads {
                let tid = cid_off
                    .zip(unique_thread_off)
                    .and_then(|(c, u)| mem.read_pointer(ethread + c + u).ok())
                    .map(|id| id.0);
                let state = state_off.and_then(|o| mem.read::<u8>(ethread + tcb_off + o).ok());
                let wait = wait_off.and_then(|o| mem.read::<u8>(ethread + tcb_off + o).ok());

                // Walk this thread's IrpList (IRP.ThreadListEntry).
                let (irps, _) =
                    bounded_record_list_walk(ethread + list_off, rec_off, 256, |link| {
                        mem.read_pointer(link)
                    });
                for irp in irps {
                    if let Some((sc, cl)) = self.plausible_irp(irp) {
                        out.push(IrpHit {
                            irp,
                            source: IrpSource::Thread,
                            stack_count: sc,
                            current_location: cl,
                            pid: Some(p.pid),
                            tid,
                            ethread: Some(ethread),
                            state,
                            wait_reason: wait,
                            driver: None,
                            device: None,
                        });
                    }
                }
            }
        }

        if numeric_filter.is_none() {
            let current_irp_off = off("_DEVICE_OBJECT", "CurrentIrp");
            let next_off = off("_DEVICE_OBJECT", "NextDevice");
            if let (Some(cur_off), Some(next_off)) = (current_irp_off, next_off) {
                for driver in self.enumerate_driver_objects()? {
                    if let Some(f) = &filter_l
                        && !driver.name.to_ascii_lowercase().contains(f.as_str())
                    {
                        continue;
                    }
                    let mut devices = ListCursor::from_first(driver.device_object, 256);
                    while let Some(dev) = devices.take_current() {
                        let current_irp = read_ptr(dev + cur_off).unwrap_or(VirtAddr(0));
                        if !current_irp.is_zero()
                            && let Some((sc, cl)) = self.plausible_irp(current_irp)
                        {
                            out.push(IrpHit {
                                irp: current_irp,
                                source: IrpSource::Device,
                                stack_count: sc,
                                current_location: cl,
                                pid: None,
                                tid: None,
                                ethread: None,
                                state: None,
                                wait_reason: None,
                                driver: Some(driver.name.clone()),
                                device: Some(dev),
                            });
                        }
                        devices.advance(
                            mem.read_pointer(dev + next_off)
                                .map_err(|error: Error| error.to_string()),
                        );
                    }
                }
            }
        }

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::error::Error;
    use crate::base::types::VirtAddr;

    fn irp_with(stack_count: u8, current_location: u8, readable: u8) -> IrpInfo {
        let location = |number: u8| IoStackLocationInfo {
            address: VirtAddr(0x1000 + u64::from(number) * 0x48),
            major_function: 3,
            minor_function: 0,
            flags: 0,
            control: 0,
            arguments: [0; 4],
            device_object: VirtAddr(0x2000 + u64::from(number)),
            file_object: VirtAddr(0),
            completion_routine: VirtAddr(0),
            context: VirtAddr(0),
        };
        IrpInfo {
            address: VirtAddr(0x1000),
            irp_type: 6,
            size: 0,
            stack_count,
            current_location,
            pending_returned: false,
            requestor_mode: 0,
            io_status: None,
            user_event: VirtAddr(0),
            user_buffer: VirtAddr(0),
            mdl_address: VirtAddr(0),
            system_buffer: VirtAddr(0),
            thread: VirtAddr(0),
            stack: (1..=readable).map(location).collect(),
        }
    }

    /// `CurrentLocation` counts from 1, the lowest driver's location; 0
    /// and one past `StackCount` (completed) name none, and neither does a
    /// location past the ones that could be read.
    #[test]
    fn the_current_stack_location_counts_from_one() {
        let device = |irp: &IrpInfo| irp.current_stack().map(|ios| ios.device_object.0);
        assert_eq!(device(&irp_with(3, 1, 3)), Some(0x2001));
        assert_eq!(device(&irp_with(3, 3, 3)), Some(0x2003));
        assert_eq!(device(&irp_with(3, 0, 3)), None);
        assert_eq!(device(&irp_with(3, 4, 3)), None);
        assert_eq!(device(&irp_with(3, 3, 2)), None);
    }

    #[test]
    fn object_directory_two_entry_cycle_emits_each_entry_once() {
        let mut entries = Vec::new();
        Target::walk_object_directory_bucket(VirtAddr(1), |entry| {
            entries.push(entry);
            Ok(if entry == VirtAddr(1) {
                VirtAddr(2)
            } else {
                VirtAddr(1)
            })
        })
        .unwrap();

        assert_eq!(entries, [VirtAddr(1), VirtAddr(2)]);
    }

    #[test]
    fn direct_object_header_wins_when_only_it_has_a_valid_type() {
        let input = VirtAddr(0x1000);
        assert_eq!(
            select_object_header_candidate(
                input,
                0x30,
                Some(VirtAddr(0x0fd0)),
                Some(input),
                false,
                true,
            ),
            Some((input, VirtAddr(0x1030), ObjectHeaderInput::Header))
        );
    }

    #[test]
    fn ambiguous_readable_object_headers_are_rejected() {
        assert_eq!(
            select_object_header_candidate(
                VirtAddr(0x1000),
                0x30,
                Some(VirtAddr(0x0fd0)),
                Some(VirtAddr(0x1000)),
                false,
                false,
            ),
            None
        );
    }

    #[test]
    fn object_name_info_address_accounts_for_creator_info_only() {
        let layout = ObjectNameLayout {
            body_offset: 0x30,
            name_info_at: NameInfoAt::InfoMask(0x1a),
            creator_info_size: Some(0x20),
            name_info_size: 0x20,
            name_offset: 0x08,
            directory_offset: Some(0x00),
        };
        let header = VirtAddr(0x1000);

        assert_eq!(layout.name_info_address(header, 0x00).unwrap(), None);
        assert_eq!(
            layout.name_info_address(header, 0x02).unwrap(),
            Some(VirtAddr(0x0fe0))
        );
        assert_eq!(
            layout.name_info_address(header, 0x03).unwrap(),
            Some(VirtAddr(0x0fc0))
        );
        assert_eq!(
            layout.name_info_address(header, 0x7e).unwrap(),
            Some(VirtAddr(0x0fe0))
        );
    }

    #[test]
    fn object_name_info_address_requires_present_creator_layout() {
        let layout = ObjectNameLayout {
            body_offset: 0x30,
            name_info_at: NameInfoAt::InfoMask(0x1a),
            creator_info_size: None,
            name_info_size: 0x20,
            name_offset: 0x08,
            directory_offset: Some(0x00),
        };

        let error = layout
            .name_info_address(VirtAddr(0x1000), 0x03)
            .unwrap_err();
        assert!(matches!(
            &error,
            Error::StructNotFound(name)
                if name == "_OBJECT_HEADER_CREATOR_INFO"
        ));
    }
}
