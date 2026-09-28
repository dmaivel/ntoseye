//! KMDF (`!wdfkd.*`): the client drivers Wdf01000 keeps on
//! `FxLibraryGlobals.FxDriverGlobalsList`, the objects their handles name,
//! their devices and queues, and their In-Flight Recorder logs, decoded with
//! Wdf01000's own PDB types.

use std::sync::Arc;

use super::{ListCursor, ListTermination, Target, bounded_list_walk};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::layout::{StructRef, TypeInfo, Types};
use crate::symbols::format_symbol_with_offset;
use crate::types::VirtAddr;
use crate::wpp::{TmfMessage, format_message};

const MAX_DRIVERS: usize = 512;
const MAX_DEVICES: usize = 256;
const MAX_QUEUES: usize = 256;
const MAX_REQUESTS: usize = 1024;
const MAX_CONTEXTS: usize = 16;
const MAX_CONTEXT_NAME: usize = 256;

/// `FxHandleFlagMask`: the low handle bits KMDF keeps for flags.
const HANDLE_FLAG_MASK: u64 = 0x7;
/// `FxHandleFlagIsOffset`: the decoded pointer is a `WDFOBJECT_OFFSET` inside
/// the object, which it subtracts to reach the object.
const HANDLE_FLAG_IS_OFFSET: u64 = 0x1;

/// `FX_IFR_MAX_BUFFER_SIZE`: an IFR log area is at most 64 KB.
const IFR_MAX_LOG_SIZE: u64 = 0x10000;
/// `FxIFRMaxMessageSize`: the argument bytes one IFR record carries at most.
const IFR_MAX_MESSAGE_SIZE: usize = 256;
/// `WdfTraceGuid` ({544d4c9d-942c-46d5-bf50-df5cd9524a50}) as stored in memory:
/// the `Guid` of every IFR header.
const WDF_TRACE_GUID: [u8; 16] = [
    0x9d, 0x4c, 0x4d, 0x54, 0x2c, 0x94, 0xd5, 0x46, 0xbf, 0x50, 0xdf, 0x5c, 0xd9, 0x52, 0x4a, 0x50,
];

/// The class each `FX_OBJECT_TYPES` value is an instance of, where one class
/// has the type: an object whose `m_ObjectSize` is below its class's size is
/// refused.
const TYPE_CLASSES: &[(&str, &str)] = &[
    ("FX_TYPE_DRIVER", "FxDriver"),
    ("FX_TYPE_DEVICE", "FxDevice"),
    ("FX_TYPE_QUEUE", "FxIoQueue"),
    ("FX_TYPE_REQUEST", "FxRequest"),
    ("FX_TYPE_CHILD_LIST", "FxChildList"),
];

/// A PDB enum value and its name, when the enum has one for it.
#[derive(Debug, Clone)]
pub struct WdfEnumValue {
    pub value: u64,
    pub name: Option<String>,
}

/// The KMDF version a client bound to (`_WDF_BIND_INFO.Version`).
#[derive(Debug, Clone, Copy)]
pub struct WdfVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
}

/// A KMDF client driver (`_FX_DRIVER_GLOBALS`).
#[derive(Debug, Clone)]
pub struct WdfClient {
    pub globals: VirtAddr,
    /// `Public.DriverName`; `None` when it is empty or not printable.
    pub name: Option<String>,
    /// `Driver`, the `FxDriver`; `None` before `WdfDriverCreate`.
    pub driver: Option<VirtAddr>,
    /// `Public.Driver`, the WDFDRIVER handle.
    pub wdf_driver: Option<u64>,
    pub driver_object: VirtAddr,
    /// The `DRIVER_OBJECT`'s `DriverName` (`\Driver\kdnic`): what names a
    /// client whose `Public.DriverName` is empty.
    pub driver_object_name: Option<String>,
    /// The `FxDriver`'s `m_RegistryPath`.
    pub registry_path: Option<String>,
    /// `WdfBindInfo->Version`; `None` when `WdfBindInfo` is null.
    pub version: Option<WdfVersion>,
    pub image_base: VirtAddr,
    pub image_size: u64,
    /// `WdfLogHeader`, the IFR log's `_WDF_IFR_HEADER`; `None` without one.
    pub log_header: Option<VirtAddr>,
    /// `FxVerifierOn`.
    pub verifier_on: bool,
    /// What in the globals failed validation (a name that is not printable,
    /// a `Driver` that is not this driver's `FxDriver`, ...); the fields it
    /// concerns are `None`.
    pub problems: Vec<String>,
}

/// The KMDF client drivers (`!wdfkd.wdfldr`).
#[derive(Debug, Clone)]
pub struct WdfLoader {
    /// `Wdf01000!FxLibraryGlobals`.
    pub library_globals: VirtAddr,
    pub clients: Vec<WdfClient>,
    /// Why the client list walk stopped short of its head.
    pub stopped: Option<String>,
}

/// An object's address with its handle and type, as far as they read.
#[derive(Debug, Clone)]
pub struct WdfObjectRef {
    pub address: VirtAddr,
    /// `None` for an object without a handle (`m_ObjectSize` 0) or unreadable.
    pub handle: Option<u64>,
    pub type_name: Option<String>,
}

/// One of a driver's `DEVICE_OBJECT`s and the WDFDEVICE behind it.
#[derive(Debug, Clone)]
pub struct WdfDriverDevice {
    pub device_object: VirtAddr,
    /// The `FxDevice`; `None` when the device object does not lead to one.
    pub device: Option<VirtAddr>,
    pub handle: Option<u64>,
    pub kind: Option<&'static str>,
    pub pnp_state: Option<WdfEnumValue>,
    /// Why the device object is not linked to a WDFDEVICE of this driver.
    pub unlinked: Option<String>,
}

/// A client driver and its devices (`!wdfkd.wdfdriverinfo`).
#[derive(Debug, Clone)]
pub struct WdfDriverInfo {
    pub client: WdfClient,
    pub devices: Vec<WdfDriverDevice>,
    /// Why the `DeviceObject`/`NextDevice` walk stopped before a null link.
    pub devices_stopped: Option<String>,
}

/// One `FxContextHeader` of an object.
#[derive(Debug, Clone)]
pub struct WdfContext {
    pub header: VirtAddr,
    /// The context itself (`FxContextHeader.Context`).
    pub context: VirtAddr,
    /// `ContextTypeInfo`; `None` for a header without a context type.
    pub type_info: Option<VirtAddr>,
    pub name: Option<String>,
    /// `ContextSize`, bytes.
    pub size: Option<u64>,
}

/// A decoded WDF handle and the object it names (`!wdfkd.wdfhandle`).
#[derive(Debug, Clone)]
pub struct WdfObject {
    pub handle: u64,
    pub address: VirtAddr,
    /// The `WDFOBJECT_OFFSET` an offset handle subtracts.
    pub offset: Option<u16>,
    pub type_value: u16,
    /// The `FX_OBJECT_TYPES` name of `m_Type`.
    pub type_name: String,
    /// `m_ObjectSize`, the object and its extra bytes.
    pub object_size: u16,
    pub refcount: i32,
    pub state: WdfEnumValue,
    pub flags: u16,
    /// The `FXOBJECT_FLAGS` set in `flags`.
    pub flag_names: Vec<String>,
    pub globals: VirtAddr,
    /// The owning client's `DriverName`, when it has one.
    pub driver: Option<String>,
    pub parent: Option<WdfObjectRef>,
    pub contexts: Vec<WdfContext>,
    /// Why the context header chain stopped before a null `NextHeader`.
    pub contexts_stopped: Option<String>,
}

/// A queue of a device.
#[derive(Debug, Clone)]
pub struct WdfQueueSummary {
    pub handle: u64,
    pub address: VirtAddr,
    pub dispatch_type: WdfEnumValue,
    pub power_managed: bool,
    /// Requests waiting in the queue (`m_Queue.m_RequestCount`).
    pub pending: i32,
    /// Requests the driver owns (`m_DriverIoCount`).
    pub driver_owned: i32,
    pub is_default: bool,
}

/// A WDFDEVICE (`!wdfkd.wdfdevice`).
#[derive(Debug, Clone)]
pub struct WdfDeviceDetail {
    pub handle: u64,
    pub address: VirtAddr,
    pub driver: Option<String>,
    pub globals: VirtAddr,
    /// `FDO`, `filter`, `PDO`, or `control`.
    pub kind: &'static str,
    pub device_object: VirtAddr,
    /// The device object this one is attached to (`m_AttachedDevice`).
    pub attached_device: VirtAddr,
    /// The stack's PDO (`m_PhysicalDevice`).
    pub physical_device: VirtAddr,
    pub device_name: Option<String>,
    /// A PDO's parent WDFDEVICE (`m_ParentDevice`).
    pub parent: Option<WdfObjectRef>,
    pub pnp_state: WdfEnumValue,
    pub power_state: WdfEnumValue,
    pub power_policy_state: WdfEnumValue,
    /// `m_PkgPnp`; null for a control device.
    pub pkg_pnp: VirtAddr,
    pub device_power_state: Option<WdfEnumValue>,
    pub system_power_state: Option<WdfEnumValue>,
    pub pkg_io: VirtAddr,
    pub default_queue: Option<u64>,
    pub queues: Vec<WdfQueueSummary>,
    pub queues_stopped: Option<String>,
    /// An FDO's `m_DefaultDeviceList` and `m_StaticDeviceList` (WDFCHILDLIST).
    pub default_child_list: Option<u64>,
    pub static_child_list: Option<u64>,
}

/// A request on one of a queue's lists.
#[derive(Debug, Clone)]
pub struct WdfRequestRef {
    pub handle: u64,
    pub address: VirtAddr,
    pub irp: VirtAddr,
}

/// A request list of a queue and why its walk stopped short.
#[derive(Debug, Clone, Default)]
pub struct WdfRequestList {
    pub requests: Vec<WdfRequestRef>,
    pub stopped: Option<String>,
}

/// A queue's event callback.
#[derive(Debug, Clone)]
pub struct WdfCallback {
    /// `EvtIoRead`, ...
    pub name: &'static str,
    pub address: VirtAddr,
    pub symbol: Option<String>,
}

/// A WDFQUEUE (`!wdfkd.wdfqueue`).
#[derive(Debug, Clone)]
pub struct WdfQueueDetail {
    pub handle: u64,
    pub address: VirtAddr,
    pub driver: Option<String>,
    pub device: Option<WdfObjectRef>,
    pub dispatch_type: WdfEnumValue,
    /// `m_QueueState`.
    pub state: u64,
    /// The `_FX_IO_QUEUE_STATE` bits set in `state`.
    pub state_names: Vec<String>,
    pub power_state: WdfEnumValue,
    pub power_managed: bool,
    pub allow_zero_length_requests: bool,
    pub deleted: bool,
    pub execution_level: WdfEnumValue,
    pub synchronization_scope: WdfEnumValue,
    pub max_parallel_requests: u64,
    pub pending_count: i32,
    pub driver_cancelable_count: i32,
    pub driver_owned_count: i32,
    pub two_phase_completions: i32,
    pub callbacks: Vec<WdfCallback>,
    /// Requests waiting in the queue (`m_Queue`).
    pub pending: WdfRequestList,
    /// Requests the driver marked cancelable (`m_DriverCancelable`).
    pub driver_cancelable: WdfRequestList,
    /// Requests presented to the driver (`m_DriverOwned`).
    pub driver_owned: WdfRequestList,
}

/// One IFR record and its formatted message.
#[derive(Debug, Clone)]
pub struct WdfLogEntry {
    pub record: IfrRecord,
    /// The record's TMF message, when a loaded PDB declares it.
    pub message: Option<Arc<TmfMessage>>,
    /// The message with its arguments, or why it could not be formatted.
    pub text: std::result::Result<String, String>,
}

/// A client driver's In-Flight Recorder log (`!wdfkd.wdflogdump`).
#[derive(Debug, Clone)]
pub struct WdfLogDump {
    pub driver: String,
    pub globals: VirtAddr,
    /// The `_WDF_IFR_HEADER`.
    pub header: VirtAddr,
    /// The record area (`Base`).
    pub base: VirtAddr,
    pub size: u64,
    /// `Offset.Current`: where the next record goes.
    pub current: u16,
    /// `Offset.Previous`: the newest record.
    pub previous: u16,
    /// The header's `Sequence`, the newest record's sequence number.
    pub sequence: i32,
    /// `UseTimeStamp`: records are 'L2', with a timestamp.
    pub use_timestamps: bool,
    /// Oldest first.
    pub entries: Vec<WdfLogEntry>,
    pub end: IfrEnd,
}

/// Where `_WDF_IFR_RECORD`'s fields sit. The 'LR' (v1) record is the 'L2'
/// record without its trailing `TimeStamp`, so its header is `timestamp`
/// bytes.
#[derive(Debug, Clone, Copy)]
pub struct IfrRecordLayout {
    /// `sizeof(_WDF_IFR_RECORD)`, the 'L2' header.
    pub size: usize,
    pub signature: usize,
    pub length: usize,
    pub sequence: usize,
    pub prev_offset: usize,
    pub message_number: usize,
    pub message_guid: usize,
    pub timestamp: usize,
}

/// One IFR record.
#[derive(Debug, Clone)]
pub struct IfrRecord {
    /// Its offset in the log area.
    pub offset: usize,
    /// `Length`: header and arguments.
    pub length: usize,
    pub sequence: i32,
    pub prev_offset: usize,
    pub message_number: u16,
    pub message_guid: [u8; 16],
    /// FILETIME (UTC); an 'LR' record has none.
    pub timestamp: Option<u64>,
    /// The WPP argument bytes after the header, padded to 4 bytes.
    pub args: Vec<u8>,
}

/// Why an IFR walk ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfrEnd {
    /// No record was ever written.
    Empty,
    /// The oldest record reached is the first the log held.
    FirstRecord,
    /// The records before the oldest one reached were overwritten.
    Overwritten,
    /// A record failed validation; the walk stopped there.
    Corrupt(String),
}

impl IfrEnd {
    pub fn describe(&self) -> String {
        match self {
            Self::Empty => "the log is empty".into(),
            Self::FirstRecord => "reached the first record written".into(),
            Self::Overwritten => "older records were overwritten".into(),
            Self::Corrupt(why) => format!("corrupt log: {why}"),
        }
    }
}

/// The records of an IFR log area, oldest first, and why the walk ended.
#[derive(Debug, Clone)]
pub struct IfrWalk {
    pub records: Vec<IfrRecord>,
    pub end: IfrEnd,
}

/// A handle's decoded bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedHandle {
    /// The object, or for an offset handle the `WDFOBJECT_OFFSET` in it.
    pub pointer: VirtAddr,
    pub is_offset: bool,
}

fn pointer_mask(pointer_size: u8) -> u64 {
    if pointer_size == 4 {
        0xffff_ffff
    } else {
        u64::MAX
    }
}

fn is_kernel_address(address: u64, pointer_size: u8) -> bool {
    if pointer_size == 4 {
        (0x8000_0000..=0xffff_ffff).contains(&address)
    } else {
        address >= 0xffff_8000_0000_0000
    }
}

/// The handle of the object at `object` (`FxObject::_ToHandle`).
pub fn object_handle(object: VirtAddr, pointer_size: u8) -> u64 {
    (object.0 ^ !HANDLE_FLAG_MASK) & pointer_mask(pointer_size)
}

/// Decode a WDF handle's bits (`FxObject::_GetObjectFromHandle`):
/// `(handle & ~7) ^ ~7`, and whether it is an offset handle. Err says why the
/// value is not a handle.
pub fn decode_handle(handle: u64, pointer_size: u8) -> std::result::Result<DecodedHandle, String> {
    let mask = pointer_mask(pointer_size);
    if handle == 0 {
        return Err("it is null".into());
    }
    if handle & !mask != 0 {
        return Err("it is wider than a pointer".into());
    }
    if is_kernel_address(handle, pointer_size) {
        return Err(format!(
            "it is a kernel address, not a handle; the handle of an object there would be {:#x}",
            object_handle(VirtAddr(handle), pointer_size)
        ));
    }
    let flags = handle & HANDLE_FLAG_MASK;
    if flags & !HANDLE_FLAG_IS_OFFSET != 0 {
        return Err(format!(
            "it sets handle flag bits {flags:#x}; KMDF sets only the offset bit (0x1)"
        ));
    }
    let pointer = ((handle & !HANDLE_FLAG_MASK) ^ !HANDLE_FLAG_MASK) & mask;
    if !is_kernel_address(pointer, pointer_size) {
        return Err(format!("it decodes to {pointer:#x}, not a kernel address"));
    }
    Ok(DecodedHandle {
        pointer: VirtAddr(pointer),
        is_offset: flags & HANDLE_FLAG_IS_OFFSET != 0,
    })
}

/// The object a decoded handle names, and the offset an offset handle
/// subtracted; `read_offset` reads the `WDFOBJECT_OFFSET` at a pointer.
pub fn handle_object(
    decoded: DecodedHandle,
    read_offset: impl FnOnce(VirtAddr) -> std::result::Result<u16, String>,
) -> std::result::Result<(VirtAddr, Option<u16>), String> {
    if !decoded.is_offset {
        return Ok((decoded.pointer, None));
    }
    let offset = read_offset(decoded.pointer).map_err(|error| {
        format!(
            "its WDFOBJECT_OFFSET at {:#x} is unreadable: {error}",
            decoded.pointer.0
        )
    })?;
    if offset == 0 {
        return Err(format!(
            "it is an offset handle whose WDFOBJECT_OFFSET at {:#x} is 0",
            decoded.pointer.0
        ));
    }
    Ok((decoded.pointer - u64::from(offset), Some(offset)))
}

/// An `FxObject`'s header fields.
#[derive(Debug, Clone, Copy)]
struct ObjectHeader {
    type_value: u16,
    object_size: u16,
    refcount: i32,
    globals: VirtAddr,
    flags: u16,
    state: u16,
    parent: VirtAddr,
    /// `m_DeviceBase`.
    device: VirtAddr,
}

/// What an object header must satisfy beyond its own fields.
struct ObjectRules<'n> {
    /// The `FX_OBJECT_TYPES` name of `m_Type`, if it has one.
    type_name: Option<&'n str>,
    /// `sizeof(FxObject)`.
    min_size: usize,
    /// The type's class and its size, when [`TYPE_CLASSES`] names one.
    class: Option<(&'n str, usize)>,
    /// `MEMORY_ALLOCATION_ALIGNMENT`, which `m_ObjectSize` is rounded to.
    alignment: u16,
    /// Whether `m_ObjectState` is an `FxObjectState` value.
    state_known: bool,
}

/// Why `header` is not a live KMDF object with a handle; `None` when it is
/// consistent with `rules`.
fn object_problem(header: &ObjectHeader, rules: &ObjectRules<'_>) -> Option<String> {
    let Some(type_name) = rules.type_name else {
        return Some(format!(
            "m_Type {:#x} is no FX_OBJECT_TYPES value",
            header.type_value
        ));
    };
    if header.object_size == 0 {
        return Some(format!(
            "m_ObjectSize is 0: a {type_name} without a handle (internal or embedded)"
        ));
    }
    if usize::from(header.object_size) < rules.min_size
        || !header.object_size.is_multiple_of(rules.alignment)
    {
        return Some(format!(
            "m_ObjectSize {:#x} is not an aligned FxObject size",
            header.object_size
        ));
    }
    if let Some((class, size)) = rules.class
        && usize::from(header.object_size) < size
    {
        return Some(format!(
            "m_ObjectSize {:#x} is smaller than a {type_name}'s {class} ({size:#x} bytes)",
            header.object_size
        ));
    }
    if !rules.state_known {
        return Some(format!(
            "m_ObjectState {} is no FxObjectState value",
            header.state
        ));
    }
    if header.refcount < 0 {
        return Some(format!("m_Refcnt {} is negative", header.refcount));
    }
    None
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Parse the IFR record at `at` in `log`, checking its signature, length,
/// and bounds.
fn parse_ifr_record(
    log: &[u8],
    at: usize,
    layout: &IfrRecordLayout,
) -> std::result::Result<IfrRecord, String> {
    let v1_size = layout.timestamp;
    if at.checked_add(v1_size).is_none_or(|end| end > log.len()) {
        return Err("its header runs past the log's end".into());
    }
    let header_size = match &log[at + layout.signature..at + layout.signature + 2] {
        b"L2" => layout.size,
        b"LR" => v1_size,
        other => {
            return Err(format!(
                "signature {:02x} {:02x} is neither 'L2' nor 'LR'",
                other[0], other[1]
            ));
        }
    };
    let length = usize::from(read_u16(log, at + layout.length));
    if length < header_size || length - header_size > IFR_MAX_MESSAGE_SIZE || length % 4 != 0 {
        return Err(format!("length {length:#x} is not a record's"));
    }
    if at + length > log.len() {
        return Err(format!(
            "its {length:#x} bytes run past the log's end ({:#x})",
            log.len()
        ));
    }
    let mut message_guid = [0u8; 16];
    message_guid.copy_from_slice(&log[at + layout.message_guid..at + layout.message_guid + 16]);
    let timestamp = (header_size == layout.size).then(|| {
        u64::from(read_u32(log, at + layout.timestamp))
            | u64::from(read_u32(log, at + layout.timestamp + 4)) << 32
    });
    Ok(IfrRecord {
        offset: at,
        length,
        sequence: read_u32(log, at + layout.sequence) as i32,
        prev_offset: usize::from(read_u16(log, at + layout.prev_offset)),
        message_number: read_u16(log, at + layout.message_number),
        message_guid,
        timestamp,
        args: log[at + header_size..at + length].to_vec(),
    })
}

/// Walk an IFR log area (`log`, the `Size` bytes at the header's `Base`)
/// from its newest record (`previous`, ending at `current`) back along
/// `PrevOffset`, and return the records oldest first.
///
/// `FxIFR` writes each record at `Offset.Current` and, when it would not fit
/// before the end, at offset 0, so a record ends where the next newer one
/// starts unless that one is at 0. Once the walk crosses that wrap, a record
/// below `current` has been overwritten by the newest records: the walk ends
/// there. It also ends at the first record ever written, the one at 0 whose
/// `PrevOffset` is 0. Anything else inconsistent ends it as corrupt: a bad
/// signature or length, a record that does not end where the newer one
/// starts, a `PrevOffset` that does not lead back, or a sequence number that
/// does not fall.
pub fn walk_ifr(log: &[u8], current: usize, previous: usize, layout: &IfrRecordLayout) -> IfrWalk {
    let mut records: Vec<IfrRecord> = Vec::new();
    let finish = |mut records: Vec<IfrRecord>, end: IfrEnd| {
        records.reverse();
        IfrWalk { records, end }
    };
    if current == 0 && previous == 0 {
        return finish(records, IfrEnd::Empty);
    }
    if current > log.len() || previous >= current {
        return finish(
            records,
            IfrEnd::Corrupt(format!(
                "offsets current {current:#x} and previous {previous:#x} do not fit a {:#x}-byte log",
                log.len()
            )),
        );
    }
    let mut at = previous;
    // Where the record at `at` must end: the start of the newer one, or no
    // constraint for the record before the wrap.
    let mut end = Some(current);
    let mut wrapped = false;
    let end_reason = loop {
        if wrapped && at < current {
            break IfrEnd::Overwritten;
        }
        let record = match parse_ifr_record(log, at, layout) {
            Ok(record) => record,
            Err(why) => break IfrEnd::Corrupt(format!("record at {at:#x}: {why}")),
        };
        if let Some(end) = end
            && at + record.length != end
        {
            break IfrEnd::Corrupt(format!(
                "record at {at:#x} is {:#x} bytes long but the next record starts at {end:#x}",
                record.length
            ));
        }
        if let Some(newer) = records.last()
            && newer.sequence.wrapping_sub(record.sequence) <= 0
        {
            break IfrEnd::Corrupt(format!(
                "record at {at:#x} has sequence {}, not below the newer record's {}",
                record.sequence, newer.sequence
            ));
        }
        let prev = record.prev_offset;
        records.push(record);
        if at == 0 {
            if prev == 0 {
                break IfrEnd::FirstRecord;
            }
            wrapped = true;
            end = None;
        } else {
            if prev >= at {
                break IfrEnd::Corrupt(format!(
                    "record at {at:#x} links back to {prev:#x}, not to an earlier offset"
                ));
            }
            end = Some(at);
        }
        at = prev;
    };
    finish(records, end_reason)
}

/// The name `variants` gives `value`.
fn enum_name(variants: &[(String, i64)], value: u64) -> Option<String> {
    variants
        .iter()
        .find(|(_, v)| *v as u64 == value)
        .map(|(name, _)| name.clone())
}

fn enum_value(variants: &[(String, i64)], value: u64) -> WdfEnumValue {
    WdfEnumValue {
        value,
        name: enum_name(variants, value),
    }
}

/// The names of the single-bit `variants` set in `value`.
fn flag_names(variants: &[(String, i64)], value: u64) -> Vec<String> {
    variants
        .iter()
        .filter(|(_, v)| *v > 0 && (*v as u64).is_power_of_two() && value & *v as u64 != 0)
        .map(|(name, _)| name.clone())
        .collect()
}

/// `Public.DriverName`, a NUL-terminated `CHAR` array: `None` when empty
/// (globals the framework keeps without a name), Err when it holds anything
/// but printable ASCII.
pub fn driver_name(bytes: &[u8]) -> std::result::Result<Option<String>, String> {
    let text = &bytes[..bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len())];
    if text.is_empty() {
        return Ok(None);
    }
    if !text.iter().all(|b| (0x20..0x7f).contains(b)) {
        return Err("Public.DriverName is not printable ASCII".into());
    }
    Ok(Some(String::from_utf8_lossy(text).into_owned()))
}

/// How many of `links`, the Flinks followed from the list head `head`, are
/// linked both ways: each one's Blink (`blink`) must be the link before it.
/// Returns that count and, when it is short, why.
pub fn doubly_linked_prefix(
    head: VirtAddr,
    links: &[VirtAddr],
    mut blink: impl FnMut(VirtAddr) -> std::result::Result<VirtAddr, String>,
) -> (usize, Option<String>) {
    let mut previous = head;
    for (index, &link) in links.iter().enumerate() {
        match blink(link) {
            Ok(back) if back == previous => previous = link,
            Ok(back) => {
                return (
                    index,
                    Some(format!(
                        "link {:#x}'s Blink is {:#x}, not the previous link {:#x}",
                        link.0, back.0, previous.0
                    )),
                );
            }
            Err(error) => {
                return (
                    index,
                    Some(format!("link {:#x}'s Blink is unreadable: {error}", link.0)),
                );
            }
        }
    }
    (links.len(), None)
}

/// Wdf01000's layouts and enums the commands share, resolved once per
/// command.
struct WdfTypes<'a> {
    types: Types<'a>,
    pointer_size: u8,
    globals: Arc<TypeInfo>,
    object: Arc<TypeInfo>,
    context: Arc<TypeInfo>,
    object_types: Vec<(String, i64)>,
    object_states: Vec<(String, i64)>,
}

impl<'a> WdfTypes<'a> {
    fn layout(&self, name: &str) -> Result<Arc<TypeInfo>> {
        wdf_layout(self.types, name)
    }

    fn at(&self, layout: &Arc<TypeInfo>, address: VirtAddr) -> StructRef<'a> {
        self.types
            .struct_with_layout(Arc::clone(layout), address)
            .prefetch()
    }

    fn type_name(&self, value: u16) -> Option<&str> {
        self.object_types
            .iter()
            .find(|(_, v)| *v == i64::from(value))
            .map(|(name, _)| name.as_str())
    }

    fn handle(&self, object: VirtAddr) -> u64 {
        object_handle(object, self.pointer_size)
    }
}

fn wdf_layout(types: Types<'_>, name: &str) -> Result<Arc<TypeInfo>> {
    types.layout(format!("Wdf01000!{name}")).map_err(|_| {
        Error::DebugInfo(format!(
            "Wdf01000's symbols do not describe {name}; is Wdf01000 loaded with its PDB?"
        ))
    })
}

/// An object that passed [`Target::wdf_check_object`].
struct CheckedObject {
    address: VirtAddr,
    header: ObjectHeader,
    type_name: String,
}

/// Each client's globals and name, what object ownership is checked against.
type ClientNames = Vec<(VirtAddr, Option<String>)>;

impl Target {
    fn wdf_types(&self) -> Result<WdfTypes<'_>> {
        let types = self.types_in(self.kernel_dtb());
        let globals = wdf_layout(types, "_FX_DRIVER_GLOBALS")?;
        let object_types = self.wdf_enum("FX_OBJECT_TYPES");
        let object_states = self.wdf_enum("FxObjectState");
        if object_types.is_empty() || object_states.is_empty() {
            return Err(Error::DebugInfo(
                "Wdf01000's symbols do not describe FX_OBJECT_TYPES and FxObjectState".into(),
            ));
        }
        Ok(WdfTypes {
            pointer_size: globals.pointer_size,
            object: wdf_layout(types, "FxObject")?,
            context: wdf_layout(types, "FxContextHeader")?,
            globals,
            object_types,
            object_states,
            types,
        })
    }

    /// The variants of Wdf01000's enum `name`; empty when its PDB lacks it.
    fn wdf_enum(&self, name: &str) -> Vec<(String, i64)> {
        self.symbols
            .find_enum_across_modules(self.kernel_dtb(), &format!("Wdf01000!{name}"))
            .unwrap_or_default()
    }

    fn wdf_symbol(&self, address: VirtAddr) -> Option<String> {
        self.symbols
            .find_closest_symbol_for_address(self.kernel_dtb(), address)
            .map(|(module, name, offset)| format_symbol_with_offset(&module, &name, offset))
    }

    fn wdf_library_globals(&self) -> Result<VirtAddr> {
        self.symbols
            .find_symbol_across_modules(self.kernel_dtb(), "Wdf01000!FxLibraryGlobals")?
            .ok_or_else(|| Error::SymbolNotFound("Wdf01000!FxLibraryGlobals".into()))
    }

    /// The `_FX_DRIVER_GLOBALS` on `FxLibraryGlobals.FxDriverGlobalsList`,
    /// and why the walk stopped short of the head. A link whose Blink is not
    /// the link before it ends the list there.
    fn wdf_client_list(&self, wdf: &WdfTypes<'_>) -> Result<(Vec<VirtAddr>, Option<String>)> {
        let library = self.wdf_library_globals()?;
        let head = library
            + wdf
                .layout("FxLibraryGlobalsType")?
                .field_offset("FxDriverGlobalsList")?;
        let link = wdf.globals.field_offset("Linkage")?;
        let memory = self.kernel_address_space();
        let (mut links, termination) =
            bounded_list_walk(head, MAX_DRIVERS, |link| memory.read::<VirtAddr>(link));
        let pointer = u64::from(wdf.pointer_size);
        let (linked, broken) = doubly_linked_prefix(head, &links, |link| {
            memory
                .read::<VirtAddr>(link + pointer)
                .map_err(|error| error.to_string())
        });
        links.truncate(linked);
        Ok((
            links.into_iter().map(|address| address - link).collect(),
            broken.or_else(|| termination.diagnostic()),
        ))
    }

    /// A client's `Public.DriverName` (see [`driver_name`]).
    fn wdf_driver_name(
        &self,
        wdf: &WdfTypes<'_>,
        globals: VirtAddr,
    ) -> Result<std::result::Result<Option<String>, String>> {
        let bytes = wdf
            .at(&wdf.globals, globals)
            .embedded("Public")?
            .read_field_bytes("DriverName", 256)?;
        Ok(driver_name(&bytes))
    }

    /// Each registered client's globals, and its name when it has a readable
    /// one.
    fn wdf_client_names(&self, wdf: &WdfTypes<'_>) -> Result<ClientNames> {
        let (addresses, _) = self.wdf_client_list(wdf)?;
        Ok(addresses
            .into_iter()
            .map(|globals| {
                let name = self
                    .wdf_driver_name(wdf, globals)
                    .ok()
                    .and_then(|name| name.ok().flatten());
                (globals, name)
            })
            .collect())
    }

    fn wdf_object_header(&self, wdf: &WdfTypes<'_>, address: VirtAddr) -> Result<ObjectHeader> {
        let object = wdf.at(&wdf.object, address);
        Ok(ObjectHeader {
            type_value: object.read_uint("m_Type")? as u16,
            object_size: object.read_uint("m_ObjectSize")? as u16,
            refcount: object.read_uint("m_Refcnt")? as u32 as i32,
            globals: object.read_pointer("m_Globals")?,
            flags: object.read_uint("m_ObjectFlags")? as u16,
            state: object.read_uint("m_ObjectState")? as u16,
            parent: object.read_pointer("m_ParentObject")?,
            device: object.read_pointer("m_DeviceBase")?,
        })
    }

    /// Check that `address` holds a live, handle-bearing `FxObject`: a known
    /// type and state, an aligned size no smaller than its class, and a first
    /// context header that points back at it. Err says why not.
    fn wdf_check_object(
        &self,
        wdf: &WdfTypes<'_>,
        address: VirtAddr,
    ) -> std::result::Result<CheckedObject, String> {
        let header = self
            .wdf_object_header(wdf, address)
            .map_err(|error| format!("its FxObject header is unreadable: {error}"))?;
        let type_name = wdf.type_name(header.type_value);
        let class = type_name
            .and_then(|name| TYPE_CLASSES.iter().find(|(t, _)| *t == name))
            .and_then(|(_, class)| wdf.layout(class).ok().map(|layout| (*class, layout.size)));
        let rules = ObjectRules {
            type_name,
            min_size: wdf.object.size,
            class,
            alignment: 2 * u16::from(wdf.pointer_size),
            state_known: wdf
                .object_states
                .iter()
                .any(|(_, value)| *value == i64::from(header.state)),
        };
        if let Some(problem) = object_problem(&header, &rules) {
            return Err(problem);
        }
        let context_header = address + u64::from(header.object_size);
        let back = wdf
            .at(&wdf.context, context_header)
            .read_pointer("Object")
            .map_err(|error| {
                format!(
                    "its context header at {:#x} is unreadable: {error}",
                    context_header.0
                )
            })?;
        if back != address {
            return Err(format!(
                "its context header at {:#x} names object {:#x}",
                context_header.0, back.0
            ));
        }
        Ok(CheckedObject {
            address,
            header,
            type_name: type_name.unwrap_or_default().to_string(),
        })
    }

    /// Resolve `handle` to its checked object, owned by one of `clients`,
    /// with the offset an offset handle subtracted.
    fn wdf_resolve_handle(
        &self,
        wdf: &WdfTypes<'_>,
        handle: u64,
        clients: &ClientNames,
    ) -> Result<(CheckedObject, Option<u16>, Option<String>)> {
        let refuse =
            |why: String| Error::DebugInfo(format!("{handle:#x} is not a WDF handle: {why}"));
        let decoded = decode_handle(handle, wdf.pointer_size).map_err(refuse)?;
        let memory = self.kernel_address_space();
        let (address, offset) = handle_object(decoded, |pointer| {
            memory
                .read::<u16>(pointer)
                .map_err(|error| error.to_string())
        })
        .map_err(refuse)?;
        let object = self
            .wdf_check_object(wdf, address)
            .map_err(|why| refuse(format!("object {:#x}: {why}", address.0)))?;
        let driver = clients
            .iter()
            .find(|(globals, _)| *globals == object.header.globals)
            .map(|(_, name)| name.clone())
            .ok_or_else(|| {
                refuse(format!(
                    "object {:#x}: m_Globals {:#x} is no registered KMDF client's",
                    address.0, object.header.globals.0
                ))
            })?;
        Ok((object, offset, driver))
    }

    /// Resolve `handle` to a checked object of type `expected`.
    fn wdf_typed_handle(
        &self,
        wdf: &WdfTypes<'_>,
        handle: u64,
        expected: &str,
        what: &str,
    ) -> Result<(CheckedObject, Option<String>)> {
        let clients = self.wdf_client_names(wdf)?;
        let (object, offset, driver) = self.wdf_resolve_handle(wdf, handle, &clients)?;
        if offset.is_some() || object.type_name != expected {
            return Err(Error::DebugInfo(format!(
                "{handle:#x} is not a {what}: it names a {} at {:#x}",
                object.type_name, object.address.0
            )));
        }
        Ok((object, driver))
    }

    /// An object's address, handle, and type, as far as they read.
    fn wdf_object_ref(&self, wdf: &WdfTypes<'_>, address: VirtAddr) -> Option<WdfObjectRef> {
        if address.is_zero() {
            return None;
        }
        let header = self.wdf_object_header(wdf, address).ok();
        Some(WdfObjectRef {
            address,
            handle: header
                .filter(|header| header.object_size != 0)
                .map(|_| wdf.handle(address)),
            type_name: header.and_then(|header| wdf.type_name(header.type_value).map(String::from)),
        })
    }

    /// Decode a client's globals. A name, `FxDriver`, or bind info that does
    /// not check out is one of its `problems`; only unreadable globals fail.
    fn wdf_client(&self, wdf: &WdfTypes<'_>, address: VirtAddr) -> Result<WdfClient> {
        let globals = wdf.at(&wdf.globals, address);
        let public = globals.embedded("Public")?;
        let mut problems = Vec::new();
        let name = self.wdf_driver_name(wdf, address)?.unwrap_or_else(|why| {
            problems.push(why);
            None
        });
        let fx_driver = globals.read_pointer("Driver")?;
        let public_driver = public.read_pointer("Driver")?;
        let checked_driver = if fx_driver.is_zero() {
            Ok(None)
        } else {
            self.wdf_check_object(wdf, fx_driver)
                .map_err(|why| format!("Driver {:#x}: {why}", fx_driver.0))
                .and_then(|object| {
                    if object.type_name != "FX_TYPE_DRIVER" || object.header.globals != address {
                        return Err(format!(
                            "Driver {:#x} is a {} of globals {:#x}, not this driver's FxDriver",
                            fx_driver.0, object.type_name, object.header.globals.0
                        ));
                    }
                    if !public_driver.is_zero() && public_driver.0 != wdf.handle(fx_driver) {
                        return Err(format!(
                            "Public.Driver {:#x} is not the handle of Driver {:#x}",
                            public_driver.0, fx_driver.0
                        ));
                    }
                    Ok(Some(fx_driver))
                })
        };
        let (driver, wdf_driver, registry_path) = match checked_driver {
            Ok(Some(fx_driver)) => (
                Some(fx_driver),
                (!public_driver.is_zero()).then_some(public_driver.0),
                wdf.at(&wdf.layout("FxDriver")?, fx_driver)
                    .unicode_string("m_RegistryPath")
                    .ok()
                    .filter(|path| !path.is_empty()),
            ),
            Ok(None) => (None, None, None),
            Err(why) => {
                problems.push(why);
                (None, None, None)
            }
        };
        let bind_info = globals.read_pointer("WdfBindInfo")?;
        let version = if bind_info.is_zero() {
            None
        } else {
            let read = || -> Result<WdfVersion> {
                let version = wdf
                    .at(&wdf.layout("_WDF_BIND_INFO")?, bind_info)
                    .embedded("Version")?;
                Ok(WdfVersion {
                    major: version.read_uint("Major")? as u32,
                    minor: version.read_uint("Minor")? as u32,
                    build: version.read_uint("Build")? as u32,
                })
            };
            read()
                .map_err(|error| {
                    problems.push(format!("WdfBindInfo {:#x}: {error}", bind_info.0));
                })
                .ok()
        };
        let log_header = globals.read_pointer("WdfLogHeader")?;
        let driver_object = globals
            .embedded("DriverObject")?
            .read_pointer("m_DriverObject")?;
        let driver_object_name = if driver_object.is_zero() {
            None
        } else {
            self.guest()?
                .ntoskrnl
                .types()
                .struct_at("_DRIVER_OBJECT", driver_object)?
                .unicode_string("DriverName")
                .ok()
                .filter(|name| !name.is_empty())
        };
        Ok(WdfClient {
            globals: address,
            name,
            driver,
            wdf_driver,
            driver_object,
            driver_object_name,
            registry_path,
            version,
            image_base: globals.read_pointer("ImageAddress")?,
            image_size: globals.read_uint("ImageSize")?,
            log_header: (!log_header.is_zero()).then_some(log_header),
            verifier_on: globals.read_uint("FxVerifierOn")? != 0,
            problems,
        })
    }

    /// Decode each client; one whose globals do not read ends the list there.
    fn wdf_clients(&self, wdf: &WdfTypes<'_>) -> Result<(Vec<WdfClient>, Option<String>)> {
        let (addresses, mut stopped) = self.wdf_client_list(wdf)?;
        let mut clients = Vec::with_capacity(addresses.len());
        for address in addresses {
            match self.wdf_client(wdf, address) {
                Ok(client) => clients.push(client),
                Err(error) => {
                    stopped = Some(format!("_FX_DRIVER_GLOBALS {:#x}: {error}", address.0));
                    break;
                }
            }
        }
        Ok((clients, stopped))
    }

    /// The client whose `DriverName` is `name` (case-insensitive, with or
    /// without `.sys`), and that name as the client spells it. A client
    /// without one matches by its `DRIVER_OBJECT`'s name (`\Driver\kdnic`
    /// as `kdnic`).
    fn wdf_client_named(&self, wdf: &WdfTypes<'_>, name: &str) -> Result<(String, WdfClient)> {
        let wanted = name.trim();
        let wanted = wanted
            .len()
            .checked_sub(4)
            .filter(|&cut| {
                wanted.is_char_boundary(cut) && wanted[cut..].eq_ignore_ascii_case(".sys")
            })
            .map_or(wanted, |cut| &wanted[..cut]);
        let names = self.wdf_client_names(wdf)?;
        if let Some((globals, name)) = names.iter().find_map(|(globals, name)| {
            name.as_ref()
                .filter(|name| name.eq_ignore_ascii_case(wanted))
                .map(|name| (*globals, name.clone()))
        }) {
            return Ok((name, self.wdf_client(wdf, globals)?));
        }
        for (globals, _) in names.iter().filter(|(_, name)| name.is_none()) {
            let client = self.wdf_client(wdf, *globals)?;
            let object_name = client
                .driver_object_name
                .as_deref()
                .and_then(|path| path.rsplit('\\').next())
                .filter(|short| short.eq_ignore_ascii_case(wanted))
                .map(str::to_string);
            if let Some(object_name) = object_name {
                return Ok((object_name, client));
            }
        }
        Err(Error::InvalidArgument(format!(
            "no KMDF client driver is named '{wanted}'"
        )))
    }

    /// `!wdfkd.wdfldr`: the KMDF client drivers.
    pub fn wdf_loader(&self) -> Result<WdfLoader> {
        let wdf = self.wdf_types()?;
        let (clients, stopped) = self.wdf_clients(&wdf)?;
        Ok(WdfLoader {
            library_globals: self.wdf_library_globals()?,
            clients,
            stopped,
        })
    }

    /// `m_PkgPnp`'s kind of device: `control` without one (a legacy device),
    /// else by the package's type.
    fn wdf_device_kind(&self, wdf: &WdfTypes<'_>, device: &StructRef<'_>) -> Result<&'static str> {
        if device.read_uint("m_Legacy")? != 0 {
            return Ok("control");
        }
        let pkg = device.read_pointer("m_PkgPnp")?;
        let header = self.wdf_object_header(wdf, pkg)?;
        Ok(match wdf.type_name(header.type_value) {
            Some("FX_TYPE_PACKAGE_PDO") => "PDO",
            Some("FX_TYPE_PACKAGE_FDO") if device.read_uint("m_Filter")? != 0 => "filter",
            Some("FX_TYPE_PACKAGE_FDO") => "FDO",
            _ => {
                return Err(Error::DebugInfo(format!(
                    "m_PkgPnp {:#x} is neither an FDO nor a PDO package (m_Type {:#x})",
                    pkg.0, header.type_value
                )));
            }
        })
    }

    /// The WDFDEVICE of `globals`' driver behind `device_object`:
    /// `DeviceExtension` is its first context (`FxContextHeader.Context`),
    /// whose header names the `FxDevice`, whose `m_DeviceObject` must be
    /// `device_object` again.
    fn wdf_device_link<'t>(
        &'t self,
        wdf: &WdfTypes<'t>,
        device_object: VirtAddr,
        globals: VirtAddr,
    ) -> std::result::Result<(CheckedObject, StructRef<'t>), String> {
        let nt = self.guest().map_err(|e| e.to_string())?.ntoskrnl.types();
        let extension = nt
            .struct_at("_DEVICE_OBJECT", device_object)
            .and_then(|device| device.read_pointer("DeviceExtension"))
            .map_err(|error| format!("unreadable: {error}"))?;
        if extension.is_zero() {
            return Err("DeviceExtension is null".into());
        }
        let context_offset = wdf
            .context
            .field_offset("Context")
            .map_err(|e| e.to_string())?;
        let header = extension - context_offset;
        let object = wdf
            .at(&wdf.context, header)
            .read_pointer("Object")
            .map_err(|error| {
                format!(
                    "DeviceExtension {:#x} is not a KMDF context: {error}",
                    extension.0
                )
            })?;
        if object.is_zero() {
            return Err(format!(
                "DeviceExtension {:#x} is not a KMDF context: it names no object",
                extension.0
            ));
        }
        let checked = self.wdf_check_object(wdf, object).map_err(|why| {
            format!(
                "DeviceExtension {:#x} leads to {:#x}, not a KMDF object: {why}",
                extension.0, object.0
            )
        })?;
        if checked.type_name != "FX_TYPE_DEVICE" {
            return Err(format!(
                "DeviceExtension {:#x} leads to a {}, not a WDFDEVICE",
                extension.0, checked.type_name
            ));
        }
        if checked.address + u64::from(checked.header.object_size) != header {
            return Err(format!(
                "DeviceExtension {:#x} is not FxDevice {:#x}'s first context",
                extension.0, object.0
            ));
        }
        if checked.header.globals != globals {
            return Err(format!(
                "FxDevice {:#x} belongs to globals {:#x}, not this driver's",
                object.0, checked.header.globals.0
            ));
        }
        let device = wdf.at(&wdf.layout("FxDevice").map_err(|e| e.to_string())?, object);
        let back = device
            .embedded("m_DeviceObject")
            .and_then(|mx| mx.read_pointer("m_DeviceObject"))
            .map_err(|error| error.to_string())?;
        if back != device_object {
            return Err(format!(
                "FxDevice {:#x} has device object {:#x}",
                object.0, back.0
            ));
        }
        Ok((checked, device))
    }

    /// `!wdfkd.wdfdriverinfo <driver>`: a client driver and its devices.
    pub fn wdf_driver_info(&self, name: &str) -> Result<WdfDriverInfo> {
        let wdf = self.wdf_types()?;
        let (_, client) = self.wdf_client_named(&wdf, name)?;
        let nt = self.guest()?.ntoskrnl.types();
        let driver_object = nt.struct_at("_DRIVER_OBJECT", client.driver_object)?;
        let pnp_states = self.wdf_enum("_WDF_DEVICE_PNP_STATE");
        let mut devices = Vec::new();
        let mut cursor =
            ListCursor::from_first(driver_object.read_pointer("DeviceObject")?, MAX_DEVICES);
        while let Some(device_object) = cursor.take_current() {
            let next = nt
                .struct_at("_DEVICE_OBJECT", device_object)
                .and_then(|device| device.read_pointer("NextDevice"))
                .map_err(|error| error.to_string());
            cursor.advance(next);
            devices.push(
                match self.wdf_device_link(&wdf, device_object, client.globals) {
                    Ok((object, device)) => WdfDriverDevice {
                        device_object,
                        device: Some(object.address),
                        handle: Some(wdf.handle(object.address)),
                        kind: self.wdf_device_kind(&wdf, &device).ok(),
                        pnp_state: device
                            .read_uint("m_CurrentPnpState")
                            .ok()
                            .map(|value| enum_value(&pnp_states, value)),
                        unlinked: None,
                    },
                    Err(why) => WdfDriverDevice {
                        device_object,
                        device: None,
                        handle: None,
                        kind: None,
                        pnp_state: None,
                        unlinked: Some(why),
                    },
                },
            );
        }
        let devices_stopped = match cursor.finish() {
            ListTermination::Null => None,
            other => other.diagnostic(),
        };
        Ok(WdfDriverInfo {
            client,
            devices,
            devices_stopped,
        })
    }

    /// `!wdfkd.wdfhandle <handle>`: the object a handle names.
    pub fn wdf_handle(&self, handle: u64) -> Result<WdfObject> {
        let wdf = self.wdf_types()?;
        let clients = self.wdf_client_names(&wdf)?;
        let (object, offset, driver) = self.wdf_resolve_handle(&wdf, handle, &clients)?;
        let header = object.header;
        let (contexts, contexts_stopped) = self.wdf_contexts(&wdf, &object)?;
        Ok(WdfObject {
            handle,
            address: object.address,
            offset,
            type_value: header.type_value,
            type_name: object.type_name,
            object_size: header.object_size,
            refcount: header.refcount,
            state: enum_value(&wdf.object_states, u64::from(header.state)),
            flags: header.flags,
            flag_names: flag_names(&self.wdf_enum("FXOBJECT_FLAGS"), u64::from(header.flags)),
            globals: header.globals,
            driver,
            parent: self.wdf_object_ref(&wdf, header.parent),
            contexts,
            contexts_stopped,
        })
    }

    /// The object's context headers, along `NextHeader`; the first one's
    /// back pointer was checked with the object.
    fn wdf_contexts(
        &self,
        wdf: &WdfTypes<'_>,
        object: &CheckedObject,
    ) -> Result<(Vec<WdfContext>, Option<String>)> {
        let type_info_layout = wdf.layout("_WDF_OBJECT_CONTEXT_TYPE_INFO")?;
        let context_offset = wdf.context.field_offset("Context")?;
        let mut contexts = Vec::new();
        let mut header = object.address + u64::from(object.header.object_size);
        let stopped = loop {
            if contexts.len() == MAX_CONTEXTS {
                break Some(format!("more than {MAX_CONTEXTS} contexts"));
            }
            let context = wdf.at(&wdf.context, header);
            let (back, next, type_info) = match (
                context.read_pointer("Object"),
                context.read_pointer("NextHeader"),
                context.read_pointer("ContextTypeInfo"),
            ) {
                (Ok(back), Ok(next), Ok(type_info)) => (back, next, type_info),
                _ => break Some(format!("context header {:#x} is unreadable", header.0)),
            };
            if back != object.address {
                break Some(format!(
                    "context header {:#x} names object {:#x}",
                    header.0, back.0
                ));
            }
            let (name, size) = if type_info.is_zero() {
                (None, None)
            } else {
                // A driver's type info may point at the canonical one.
                let info = wdf.at(&type_info_layout, type_info);
                let info = match info.read_pointer("UniqueType") {
                    Ok(unique) if !unique.is_zero() && unique != type_info => {
                        wdf.at(&type_info_layout, unique)
                    }
                    _ => info,
                };
                (
                    info.read_pointer("ContextName")
                        .ok()
                        .filter(|name| !name.is_zero())
                        .and_then(|name| self.read_c_string(name, MAX_CONTEXT_NAME).ok()),
                    info.read_uint("ContextSize").ok(),
                )
            };
            contexts.push(WdfContext {
                header,
                context: header + context_offset,
                type_info: (!type_info.is_zero()).then_some(type_info),
                name,
                size,
            });
            if next.is_zero() {
                break None;
            }
            header = next;
        };
        Ok((contexts, stopped))
    }

    fn wdf_queue_summary(
        &self,
        wdf: &WdfTypes<'_>,
        queue_layout: &Arc<TypeInfo>,
        irp_queue: &TypeInfo,
        dispatch_types: &[(String, i64)],
        address: VirtAddr,
        default_queue: VirtAddr,
    ) -> Result<WdfQueueSummary> {
        let queue = wdf.at(queue_layout, address);
        Ok(WdfQueueSummary {
            handle: wdf.handle(address),
            address,
            dispatch_type: enum_value(dispatch_types, queue.read_uint("m_Type")?),
            power_managed: queue.read_uint("m_PowerManaged")? != 0,
            pending: self.wdf_request_count(&queue, irp_queue, "m_Queue")?,
            driver_owned: queue.read_uint("m_DriverIoCount")? as u32 as i32,
            is_default: address == default_queue,
        })
    }

    /// `m_RequestCount` of the `FxIrpQueue` field `field` of `queue`.
    fn wdf_request_count(
        &self,
        queue: &StructRef<'_>,
        irp_queue: &TypeInfo,
        field: &str,
    ) -> Result<i32> {
        let address = queue.addr()
            + queue.layout().field_offset(field)?
            + irp_queue.field_offset("m_RequestCount")?;
        self.kernel_address_space().read::<i32>(address)
    }

    /// The queues on `FxPkgIo.m_IoQueueListHead`; bookmark nodes are skipped
    /// and a queue that does not check out ends the list.
    fn wdf_device_queues(
        &self,
        wdf: &WdfTypes<'_>,
        pkg_io: VirtAddr,
        default_queue: VirtAddr,
    ) -> Result<(Vec<WdfQueueSummary>, Option<String>)> {
        let pkg_layout = wdf.layout("FxPkgIo")?;
        let queue_layout = wdf.layout("FxIoQueue")?;
        let node_layout = wdf.layout("FxIoQueueNode")?;
        let irp_queue = wdf.layout("FxIrpQueue")?;
        let dispatch_types = self.wdf_enum("_WDF_IO_QUEUE_DISPATCH_TYPE");
        let queue_node = enum_name_value(
            &self.wdf_enum("FxIoQueueNodeType"),
            "FxIoQueueNodeTypeQueue",
        )
        .ok_or_else(|| {
            Error::DebugInfo("Wdf01000's symbols do not describe FxIoQueueNodeType".into())
        })?;
        let node_offset = queue_layout.field_offset("m_IoPkgListNode")?;
        let link_offset = node_offset + node_layout.field_offset("m_ListEntry")?;
        let head = pkg_io + pkg_layout.field_offset("m_IoQueueListHead")?;
        let memory = self.kernel_address_space();
        let (links, termination) =
            bounded_list_walk(head, MAX_QUEUES, |link| memory.read::<VirtAddr>(link));
        let mut stopped = termination.diagnostic();
        let mut queues = Vec::new();
        for link in links {
            let node = link - node_layout.field_offset("m_ListEntry")?;
            let node_type = wdf.at(&node_layout, node).read_uint("m_Type")?;
            if node_type as i64 != queue_node {
                continue;
            }
            let address = link - link_offset;
            let summary = self
                .wdf_check_object(wdf, address)
                .and_then(|object| {
                    if object.type_name == "FX_TYPE_QUEUE" {
                        Ok(())
                    } else {
                        Err(format!("a {}, not a queue", object.type_name))
                    }
                })
                .map_err(|why| format!("{:#x}: {why}", address.0))
                .and_then(|()| {
                    self.wdf_queue_summary(
                        wdf,
                        &queue_layout,
                        &irp_queue,
                        &dispatch_types,
                        address,
                        default_queue,
                    )
                    .map_err(|error| format!("{:#x}: {error}", address.0))
                });
            match summary {
                Ok(summary) => queues.push(summary),
                Err(why) => {
                    stopped = Some(why);
                    break;
                }
            }
        }
        Ok((queues, stopped))
    }

    /// `!wdfkd.wdfdevice <handle>`: a WDFDEVICE's device objects, state
    /// machines, and queues.
    pub fn wdf_device(&self, handle: u64) -> Result<WdfDeviceDetail> {
        let wdf = self.wdf_types()?;
        let (object, driver) =
            self.wdf_typed_handle(&wdf, handle, "FX_TYPE_DEVICE", "WDFDEVICE")?;
        let address = object.address;
        let device = wdf.at(&wdf.layout("FxDevice")?, address);
        let mx = |field: &str| -> Result<VirtAddr> {
            device.embedded(field)?.read_pointer("m_DeviceObject")
        };
        let kind = self.wdf_device_kind(&wdf, &device)?;
        let pkg_pnp = device.read_pointer("m_PkgPnp")?;
        let (device_power_state, system_power_state) = if pkg_pnp.is_zero() {
            (None, None)
        } else {
            let pnp = wdf.at(&wdf.layout("FxPkgPnp")?, pkg_pnp);
            (
                Some(enum_value(
                    &self.wdf_enum("_DEVICE_POWER_STATE"),
                    pnp.read_uint("m_DevicePowerState")?,
                )),
                Some(enum_value(
                    &self.wdf_enum("_SYSTEM_POWER_STATE"),
                    pnp.read_uint("m_SystemPowerState")?,
                )),
            )
        };
        let (default_child_list, static_child_list) = if matches!(kind, "FDO" | "filter") {
            let fdo = wdf.at(&wdf.layout("FxPkgFdo")?, pkg_pnp);
            let list = |field: &str| -> Result<Option<u64>> {
                let list = fdo.read_pointer(field)?;
                Ok((!list.is_zero()).then(|| wdf.handle(list)))
            };
            (list("m_DefaultDeviceList")?, list("m_StaticDeviceList")?)
        } else {
            (None, None)
        };
        let pkg_io = device.read_pointer("m_PkgIo")?;
        let (default_queue, queues, queues_stopped) = if pkg_io.is_zero() {
            (VirtAddr(0), Vec::new(), None)
        } else {
            let default_queue = wdf
                .at(&wdf.layout("FxPkgIo")?, pkg_io)
                .read_pointer("m_DefaultQueue")?;
            let (queues, stopped) = self.wdf_device_queues(&wdf, pkg_io, default_queue)?;
            (default_queue, queues, stopped)
        };
        let parent = device.read_pointer("m_ParentDevice")?;
        Ok(WdfDeviceDetail {
            handle,
            address,
            driver,
            globals: object.header.globals,
            kind,
            device_object: mx("m_DeviceObject")?,
            attached_device: mx("m_AttachedDevice")?,
            physical_device: mx("m_PhysicalDevice")?,
            device_name: device
                .unicode_string("m_DeviceName")
                .ok()
                .filter(|name| !name.is_empty()),
            parent: self.wdf_object_ref(&wdf, parent),
            pnp_state: enum_value(
                &self.wdf_enum("_WDF_DEVICE_PNP_STATE"),
                device.read_uint("m_CurrentPnpState")?,
            ),
            power_state: enum_value(
                &self.wdf_enum("_WDF_DEVICE_POWER_STATE"),
                device.read_uint("m_CurrentPowerState")?,
            ),
            power_policy_state: enum_value(
                &self.wdf_enum("_WDF_DEVICE_POWER_POLICY_STATE"),
                device.read_uint("m_CurrentPowerPolicyState")?,
            ),
            pkg_pnp,
            device_power_state,
            system_power_state,
            pkg_io,
            default_queue: (!default_queue.is_zero()).then(|| wdf.handle(default_queue)),
            queues,
            queues_stopped,
            default_child_list,
            static_child_list,
        })
    }

    /// The request at `address`, checked to be an `FxRequest`.
    fn wdf_request(
        &self,
        wdf: &WdfTypes<'_>,
        request_layout: &Arc<TypeInfo>,
        address: VirtAddr,
    ) -> std::result::Result<WdfRequestRef, String> {
        let object = self.wdf_check_object(wdf, address)?;
        if object.type_name != "FX_TYPE_REQUEST" {
            return Err(format!("a {}, not a request", object.type_name));
        }
        let irp = wdf
            .at(request_layout, address)
            .embedded("m_Irp")
            .and_then(|irp| irp.read_pointer("m_Irp"))
            .map_err(|error| error.to_string())?;
        Ok(WdfRequestRef {
            handle: wdf.handle(address),
            address,
            irp,
        })
    }

    /// The requests whose IRPs are on the `FxIrpQueue` at `irp_queue`: each
    /// IRP's `Tail.Overlay.DriverContext[3]` is its request's
    /// `m_CsqContext`, whose `Irp` must be the IRP again.
    fn wdf_irp_queue_requests(
        &self,
        wdf: &WdfTypes<'_>,
        request_layout: &Arc<TypeInfo>,
        irp_queue: VirtAddr,
    ) -> Result<WdfRequestList> {
        let nt = self.guest()?.ntoskrnl.types();
        let irp_layout = nt.layout("_IRP")?;
        let overlay = nt
            .struct_with_layout(Arc::clone(&irp_layout), VirtAddr(0))
            .embedded("Tail")?
            .embedded("Overlay")?;
        let overlay_offset = overlay.addr().0;
        let list_offset = overlay_offset + overlay.layout().field_offset("ListEntry")?;
        let context_offset = overlay_offset
            + overlay.layout().field_offset("DriverContext")?
            + 3 * u64::from(wdf.pointer_size);
        let csq_layout = wdf.layout("_IO_CSQ_IRP_CONTEXT")?;
        let csq_offset = request_layout.field_offset("m_CsqContext")?;
        let head = irp_queue + wdf.layout("FxIrpQueue")?.field_offset("m_Queue")?;
        let memory = self.kernel_address_space();
        let (links, termination) =
            bounded_list_walk(head, MAX_REQUESTS, |link| memory.read::<VirtAddr>(link));
        let mut list = WdfRequestList {
            requests: Vec::new(),
            stopped: termination.diagnostic(),
        };
        for link in links {
            let irp = link - list_offset;
            let request = memory
                .read::<VirtAddr>(irp + context_offset)
                .map_err(|error| error.to_string())
                .and_then(|csq| {
                    let back = wdf
                        .at(&csq_layout, csq)
                        .read_pointer("Irp")
                        .map_err(|error| error.to_string())?;
                    if back != irp {
                        return Err(format!(
                            "its CSQ context {:#x} names IRP {:#x}",
                            csq.0, back.0
                        ));
                    }
                    self.wdf_request(wdf, request_layout, csq - csq_offset)
                });
            match request {
                Ok(request) => list.requests.push(request),
                Err(why) => {
                    list.stopped = Some(format!("IRP {:#x}: {why}", irp.0));
                    break;
                }
            }
        }
        Ok(list)
    }

    /// The requests on the `_LIST_ENTRY` at `head`, linked through
    /// `FxRequest`'s `link` field.
    fn wdf_request_list(
        &self,
        wdf: &WdfTypes<'_>,
        request_layout: &Arc<TypeInfo>,
        head: VirtAddr,
        link: &str,
    ) -> Result<WdfRequestList> {
        let link_offset = request_layout.field_offset(link)?;
        let memory = self.kernel_address_space();
        let (links, termination) =
            bounded_list_walk(head, MAX_REQUESTS, |link| memory.read::<VirtAddr>(link));
        let mut list = WdfRequestList {
            requests: Vec::new(),
            stopped: termination.diagnostic(),
        };
        for entry in links {
            let address = entry - link_offset;
            match self.wdf_request(wdf, request_layout, address) {
                Ok(request) => list.requests.push(request),
                Err(why) => {
                    list.stopped = Some(format!("{:#x}: {why}", address.0));
                    break;
                }
            }
        }
        Ok(list)
    }

    /// `!wdfkd.wdfqueue <handle>`: a WDFQUEUE's configuration, state, and
    /// requests.
    pub fn wdf_queue(&self, handle: u64) -> Result<WdfQueueDetail> {
        const CALLBACKS: [(&str, &str); 8] = [
            ("EvtIoDefault", "m_IoDefault"),
            ("EvtIoRead", "m_IoRead"),
            ("EvtIoWrite", "m_IoWrite"),
            ("EvtIoDeviceControl", "m_IoDeviceControl"),
            ("EvtIoInternalDeviceControl", "m_IoInternalDeviceControl"),
            ("EvtIoStop", "m_IoStop"),
            ("EvtIoResume", "m_IoResume"),
            ("EvtIoCanceledOnQueue", "m_IoCanceledOnQueue"),
        ];
        let wdf = self.wdf_types()?;
        let (object, driver) = self.wdf_typed_handle(&wdf, handle, "FX_TYPE_QUEUE", "WDFQUEUE")?;
        let address = object.address;
        let queue_layout = wdf.layout("FxIoQueue")?;
        let irp_queue = wdf.layout("FxIrpQueue")?;
        let request_layout = wdf.layout("FxRequest")?;
        let queue = wdf.at(&queue_layout, address);
        let mut callbacks = Vec::new();
        for (name, field) in CALLBACKS {
            let callback = queue.embedded(field)?.read_pointer("Method")?;
            if !callback.is_zero() {
                callbacks.push(WdfCallback {
                    name,
                    address: callback,
                    symbol: self.wdf_symbol(callback),
                });
            }
        }
        let state = queue.read_uint("m_QueueState")?;
        let field =
            |name: &str| -> Result<VirtAddr> { Ok(address + queue_layout.field_offset(name)?) };
        Ok(WdfQueueDetail {
            handle,
            address,
            driver,
            device: self.wdf_object_ref(&wdf, object.header.device),
            dispatch_type: enum_value(
                &self.wdf_enum("_WDF_IO_QUEUE_DISPATCH_TYPE"),
                queue.read_uint("m_Type")?,
            ),
            state,
            state_names: flag_names(&self.wdf_enum("_FX_IO_QUEUE_STATE"), state),
            power_state: enum_value(
                &self.wdf_enum("FxIoQueuePowerState"),
                queue.read_uint("m_PowerState")?,
            ),
            power_managed: queue.read_uint("m_PowerManaged")? != 0,
            allow_zero_length_requests: queue.read_uint("m_AllowZeroLengthRequests")? != 0,
            deleted: queue.read_uint("m_Deleted")? != 0,
            execution_level: enum_value(
                &self.wdf_enum("_WDF_EXECUTION_LEVEL"),
                queue.read_uint("m_ExecutionLevel")?,
            ),
            synchronization_scope: enum_value(
                &self.wdf_enum("_WDF_SYNCHRONIZATION_SCOPE"),
                queue.read_uint("m_SynchronizationScope")?,
            ),
            max_parallel_requests: queue.read_uint("m_MaxParallelQueuePresentedRequests")?,
            pending_count: self.wdf_request_count(&queue, &irp_queue, "m_Queue")?,
            driver_cancelable_count: self.wdf_request_count(
                &queue,
                &irp_queue,
                "m_DriverCancelable",
            )?,
            driver_owned_count: queue.read_uint("m_DriverIoCount")? as u32 as i32,
            two_phase_completions: queue.read_uint("m_TwoPhaseCompletions")? as u32 as i32,
            callbacks,
            pending: self.wdf_irp_queue_requests(&wdf, &request_layout, field("m_Queue")?)?,
            driver_cancelable: self.wdf_irp_queue_requests(
                &wdf,
                &request_layout,
                field("m_DriverCancelable")?,
            )?,
            driver_owned: self.wdf_request_list(
                &wdf,
                &request_layout,
                field("m_DriverOwned")?,
                "m_OwnerListEntry2",
            )?,
        })
    }

    /// `!wdfkd.wdflogdump <driver>`: a client driver's IFR log, oldest
    /// record first, each formatted from the TMF message a loaded PDB
    /// declares for it.
    pub fn wdf_log_dump(&self, name: &str) -> Result<WdfLogDump> {
        let wdf = self.wdf_types()?;
        let (name, client) = self.wdf_client_named(&wdf, name)?;
        let header = client.log_header.ok_or_else(|| {
            Error::DebugInfo(format!("{name} has no IFR log (WdfLogHeader is null)"))
        })?;
        let header_layout = wdf.layout("_WDF_IFR_HEADER")?;
        let record_layout = wdf.layout("_WDF_IFR_RECORD")?;
        let layout = IfrRecordLayout {
            size: record_layout.size,
            signature: record_layout.field_offset("Signature")? as usize,
            length: record_layout.field_offset("Length")? as usize,
            sequence: record_layout.field_offset("Sequence")? as usize,
            prev_offset: record_layout.field_offset("PrevOffset")? as usize,
            message_number: record_layout.field_offset("MessageNumber")? as usize,
            message_guid: record_layout.field_offset("MessageGuid")? as usize,
            timestamp: record_layout.field_offset("TimeStamp")? as usize,
        };
        let ifr = wdf.at(&header_layout, header);
        let bad =
            |why: String| Error::DebugInfo(format!("{name}'s IFR header {:#x}: {why}", header.0));
        if ifr.read_field_bytes("Guid", 16)? != WDF_TRACE_GUID {
            return Err(bad("its Guid is not WdfTraceGuid".into()));
        }
        let base = ifr.read_pointer("Base")?;
        if base != header + header_layout.size as u64 {
            return Err(bad(format!(
                "Base {:#x} does not follow the header",
                base.0
            )));
        }
        let size = ifr.read_uint("Size")?;
        if size == 0 || size > IFR_MAX_LOG_SIZE {
            return Err(bad(format!("Size {size:#x} is not a log size")));
        }
        // `Offset` is `{USHORT Current; USHORT Previous}` read as one LONG.
        let offset = ifr.read_uint("Offset")?;
        let (current, previous) = (offset as u16, (offset >> 16) as u16);
        let mut log = vec![0u8; size as usize];
        self.kernel_address_space().read_bytes(base, &mut log)?;
        let walk = walk_ifr(&log, usize::from(current), usize::from(previous), &layout);
        let entries = walk
            .records
            .into_iter()
            .map(|record| {
                let message = self
                    .symbols
                    .wpp_message(&record.message_guid, record.message_number);
                let text = match &message {
                    Some(message) => format_message(message, &record.args, wdf.pointer_size),
                    None => Err("no loaded PDB declares this message".into()),
                };
                WdfLogEntry {
                    record,
                    message,
                    text,
                }
            })
            .collect();
        Ok(WdfLogDump {
            driver: name,
            globals: client.globals,
            header,
            base,
            size,
            current,
            previous,
            sequence: ifr.read_uint("Sequence")? as u32 as i32,
            use_timestamps: ifr.read_uint("UseTimeStamp")? != 0,
            entries,
            end: walk.end,
        })
    }
}

/// The value `variants` gives `name`.
fn enum_name_value(variants: &[(String, i64)], name: &str) -> Option<i64> {
    variants
        .iter()
        .find(|(variant, _)| variant == name)
        .map(|(_, value)| *value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `_WDF_IFR_RECORD`'s offsets in the 26200 Wdf01000 PDB.
    const LAYOUT: IfrRecordLayout = IfrRecordLayout {
        size: 0x24,
        signature: 0,
        length: 2,
        sequence: 4,
        prev_offset: 8,
        message_number: 0xa,
        message_guid: 0xc,
        timestamp: 0x1c,
    };

    const GUID: [u8; 16] = [0x11; 16];

    /// Write an 'L2' record with `args` at `at`, as `FxIFR` does.
    fn put(
        log: &mut [u8],
        at: usize,
        sequence: i32,
        prev: usize,
        number: u16,
        args: &[u8],
    ) -> usize {
        let padded = args.len().div_ceil(4) * 4;
        let length = LAYOUT.size + padded;
        let record = &mut log[at..at + length];
        record.fill(0);
        record[0..2].copy_from_slice(b"L2");
        record[2..4].copy_from_slice(&(length as u16).to_le_bytes());
        record[4..8].copy_from_slice(&sequence.to_le_bytes());
        record[8..10].copy_from_slice(&(prev as u16).to_le_bytes());
        record[0xa..0xc].copy_from_slice(&number.to_le_bytes());
        record[0xc..0x1c].copy_from_slice(&GUID);
        record[0x1c..0x24]
            .copy_from_slice(&(0x01dc_0000_0000_0000u64 + sequence as u64).to_le_bytes());
        record[LAYOUT.size..LAYOUT.size + args.len()].copy_from_slice(args);
        at + length
    }

    fn sequences(walk: &IfrWalk) -> Vec<i32> {
        walk.records.iter().map(|record| record.sequence).collect()
    }

    #[test]
    fn ifr_walk_returns_an_unwrapped_log_oldest_first() {
        let mut log = vec![0u8; 0x100];
        let second = put(&mut log, 0, 1, 0, 10, &[1, 2, 3, 4]);
        let third = put(&mut log, second, 2, 0, 11, &[5]);
        let current = put(&mut log, third, 3, second, 12, &[]);
        let walk = walk_ifr(&log, current, third, &LAYOUT);
        assert_eq!(walk.end, IfrEnd::FirstRecord);
        assert_eq!(sequences(&walk), [1, 2, 3]);
        assert_eq!(walk.records[0].args, [1, 2, 3, 4]);
        // One argument byte is padded to four.
        assert_eq!(walk.records[1].args, [5, 0, 0, 0]);
        assert_eq!(walk.records[1].message_number, 11);
        assert_eq!(walk.records[2].timestamp, Some(0x01dc_0000_0000_0003));
    }

    #[test]
    fn ifr_walk_crosses_the_wrap_and_stops_at_overwritten_records() {
        // 0x28-byte records (one argument dword) in a 0x100-byte log: the
        // first lap fills 0x00..0xf0, then the log wraps.
        let mut log = vec![0u8; 0x100];
        let mut at = 0;
        let mut prev = 0;
        for sequence in 1..=6 {
            let end = put(&mut log, at, sequence, prev, 0, &[sequence as u8]);
            prev = at;
            at = end;
        }
        assert_eq!(at, 0xf0);
        // Records 7 and 8 overwrite records 1 and 2 at 0x00 and 0x28.
        let end = put(&mut log, 0, 7, prev, 0, &[7]);
        let current = put(&mut log, end, 8, 0, 0, &[8]);
        let walk = walk_ifr(&log, current, end, &LAYOUT);
        assert_eq!(walk.end, IfrEnd::Overwritten);
        assert_eq!(sequences(&walk), [3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn ifr_walk_keeps_newer_records_and_reports_a_bad_signature() {
        let mut log = vec![0u8; 0x100];
        let second = put(&mut log, 0, 1, 0, 0, &[]);
        let current = put(&mut log, second, 2, 0, 0, &[]);
        log[0] = b'X';
        let walk = walk_ifr(&log, current, second, &LAYOUT);
        assert_eq!(sequences(&walk), [2]);
        assert!(
            matches!(&walk.end, IfrEnd::Corrupt(why) if why.contains("record at 0x0") && why.contains("signature"))
        );
    }

    #[test]
    fn ifr_walk_rejects_a_record_that_does_not_end_where_the_next_starts() {
        let mut log = vec![0u8; 0x100];
        let second = put(&mut log, 0, 1, 0, 0, &[1, 2, 3, 4]);
        let current = put(&mut log, second, 2, 0, 0, &[]);
        // Record 1 claims to be one dword shorter than it is.
        log[2..4].copy_from_slice(&((second - 4) as u16).to_le_bytes());
        let walk = walk_ifr(&log, current, second, &LAYOUT);
        assert_eq!(sequences(&walk), [2]);
        assert!(
            matches!(&walk.end, IfrEnd::Corrupt(why) if why.contains("next record starts at 0x28"))
        );
    }

    #[test]
    fn ifr_walk_rejects_sequences_that_do_not_fall() {
        let mut log = vec![0u8; 0x100];
        let second = put(&mut log, 0, 5, 0, 0, &[]);
        let current = put(&mut log, second, 5, 0, 0, &[]);
        let walk = walk_ifr(&log, current, second, &LAYOUT);
        assert!(matches!(&walk.end, IfrEnd::Corrupt(why) if why.contains("sequence 5")));
    }

    #[test]
    fn ifr_walk_reads_v1_records_without_a_timestamp() {
        let mut log = vec![0u8; 0x40];
        log[0..2].copy_from_slice(b"LR");
        log[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        log[4..8].copy_from_slice(&1i32.to_le_bytes());
        log[0x1c..0x20].copy_from_slice(&[9, 9, 9, 9]);
        let walk = walk_ifr(&log, 0x20, 0, &LAYOUT);
        assert_eq!(walk.end, IfrEnd::FirstRecord);
        assert_eq!(walk.records[0].timestamp, None);
        assert_eq!(walk.records[0].args, [9, 9, 9, 9]);
    }

    #[test]
    fn ifr_walk_handles_empty_and_out_of_range_offsets() {
        let log = vec![0u8; 0x100];
        assert_eq!(walk_ifr(&log, 0, 0, &LAYOUT).end, IfrEnd::Empty);
        assert!(matches!(
            walk_ifr(&log, 0x200, 0, &LAYOUT).end,
            IfrEnd::Corrupt(_)
        ));
        assert!(matches!(
            walk_ifr(&log, 0x40, 0x40, &LAYOUT).end,
            IfrEnd::Corrupt(_)
        ));
    }

    #[test]
    fn ifr_walk_rejects_a_record_running_past_the_log() {
        let mut log = vec![0u8; 0x100];
        let current = put(&mut log, 0xd8, 1, 0, 0, &[]);
        assert_eq!(current, 0xfc);
        log[0xda..0xdc].copy_from_slice(&0x40u16.to_le_bytes());
        let walk = walk_ifr(&log, current, 0xd8, &LAYOUT);
        assert!(walk.records.is_empty());
        assert!(matches!(&walk.end, IfrEnd::Corrupt(why) if why.contains("past the log's end")));
    }

    #[test]
    fn handles_decode_to_objects() {
        let object = 0xffff_c10a_1234_5670u64;
        let handle = object_handle(VirtAddr(object), 8);
        assert_eq!(handle, 0x0000_3ef5_edcb_a988);
        let decoded = decode_handle(handle, 8).unwrap();
        assert_eq!(
            decoded,
            DecodedHandle {
                pointer: VirtAddr(object),
                is_offset: false
            }
        );
        assert_eq!(
            handle_object(decoded, |_| unreachable!()).unwrap(),
            (VirtAddr(object), None)
        );
    }

    #[test]
    fn offset_handles_subtract_their_offset() {
        // A WDFMEMORY inside an FxRequest: the handle names the embedded
        // memory object's WDFOBJECT_OFFSET, 0x100 bytes into the request.
        let request = 0xffff_c10a_1234_5600u64;
        let handle = object_handle(VirtAddr(request + 0x100), 8) | HANDLE_FLAG_IS_OFFSET;
        let decoded = decode_handle(handle, 8).unwrap();
        assert!(decoded.is_offset);
        let (object, offset) = handle_object(decoded, |pointer| {
            assert_eq!(pointer, VirtAddr(request + 0x100));
            Ok(0x100)
        })
        .unwrap();
        assert_eq!((object, offset), (VirtAddr(request), Some(0x100)));
        assert!(
            handle_object(decoded, |_| Ok(0))
                .unwrap_err()
                .contains("is 0")
        );
    }

    #[test]
    fn non_handles_are_refused() {
        assert!(decode_handle(0, 8).unwrap_err().contains("null"));
        // An object address instead of its handle names the handle.
        let why = decode_handle(0xffff_c10a_1234_5670, 8).unwrap_err();
        assert!(why.contains("0x3ef5edcba988"), "{why}");
        assert!(
            decode_handle(0x0000_3ef5_edcb_a98a, 8)
                .unwrap_err()
                .contains("flag bits 0x2")
        );
        // Decodes to 0xffff7ffffffffff8, below the kernel's half.
        assert!(
            decode_handle(0x0000_8000_0000_0000, 8)
                .unwrap_err()
                .contains("not a kernel address")
        );
        // 32-bit handles stay 32-bit.
        assert_eq!(object_handle(VirtAddr(0x8a12_3450), 4), 0x75ed_cba8);
        assert_eq!(
            decode_handle(0x75ed_cba8, 4).unwrap().pointer,
            VirtAddr(0x8a12_3450)
        );
    }

    fn header(type_value: u16, object_size: u16) -> ObjectHeader {
        ObjectHeader {
            type_value,
            object_size,
            refcount: 1,
            globals: VirtAddr(0xffff_c10a_0000_0000),
            flags: 0,
            state: 1,
            parent: VirtAddr(0),
            device: VirtAddr(0),
        }
    }

    fn rules<'n>(type_name: Option<&'n str>, class: Option<(&'n str, usize)>) -> ObjectRules<'n> {
        ObjectRules {
            type_name,
            min_size: 0x68,
            class,
            alignment: 16,
            state_known: true,
        }
    }

    #[test]
    fn object_headers_must_be_consistent() {
        let device = Some(("FxDevice", 0x2c0));
        assert_eq!(
            object_problem(
                &header(0x1002, 0x2c0),
                &rules(Some("FX_TYPE_DEVICE"), device)
            ),
            None
        );
        // Extra bytes after the class are fine.
        assert_eq!(
            object_problem(
                &header(0x1002, 0x2d0),
                &rules(Some("FX_TYPE_DEVICE"), device)
            ),
            None
        );
        let problem =
            |header: ObjectHeader, rules: ObjectRules<'_>| object_problem(&header, &rules).unwrap();
        assert!(problem(header(0x4242, 0x2c0), rules(None, None)).contains("m_Type 0x4242"));
        assert!(
            problem(header(0x1002, 0x100), rules(Some("FX_TYPE_DEVICE"), device))
                .contains("smaller than a FX_TYPE_DEVICE's FxDevice")
        );
        assert!(
            problem(header(0x1002, 0), rules(Some("FX_TYPE_DEVICE"), device))
                .contains("without a handle")
        );
        assert!(
            problem(header(0x1000, 0x78), rules(Some("FX_TYPE_OBJECT"), None))
                .contains("not an aligned")
        );
        assert!(
            problem(header(0x1000, 0x40), rules(Some("FX_TYPE_OBJECT"), None))
                .contains("not an aligned")
        );
        let mut unknown_state = rules(Some("FX_TYPE_OBJECT"), None);
        unknown_state.state_known = false;
        assert!(problem(header(0x1000, 0x70), unknown_state).contains("m_ObjectState"));
        let mut dead = header(0x1000, 0x70);
        dead.refcount = -1;
        assert!(problem(dead, rules(Some("FX_TYPE_OBJECT"), None)).contains("negative"));
    }

    #[test]
    fn driver_names_tell_unnamed_clients_from_corrupt_ones() {
        let mut name = [0u8; 32];
        assert_eq!(driver_name(&name), Ok(None));
        name[..7].copy_from_slice(b"BALLOON");
        // Bytes after the terminator are not part of the name.
        name[20] = 0xff;
        assert_eq!(driver_name(&name), Ok(Some("BALLOON".into())));
        name[3] = 0x07;
        assert!(driver_name(&name).is_err());
    }

    #[test]
    fn client_list_ends_at_the_first_link_that_does_not_point_back() {
        let head = VirtAddr(0xffff_f805_1000_0168);
        let links = [VirtAddr(0xa000), VirtAddr(0xb000), VirtAddr(0xc000)];
        let blinks = |bad: Option<VirtAddr>| {
            move |link: VirtAddr| -> std::result::Result<VirtAddr, String> {
                Ok(match link.0 {
                    0xa000 => head,
                    0xb000 => VirtAddr(0xa000),
                    _ => bad.unwrap_or(VirtAddr(0xb000)),
                })
            }
        };
        assert_eq!(doubly_linked_prefix(head, &links, blinks(None)), (3, None));
        let (linked, why) = doubly_linked_prefix(head, &links, blinks(Some(VirtAddr(0xa000))));
        assert_eq!(linked, 2);
        assert!(why.unwrap().contains("0xc000"));
        let (linked, _) = doubly_linked_prefix(head, &links, |link| {
            if link.0 == 0xb000 {
                Err("paged out".into())
            } else {
                Ok(head)
            }
        });
        assert_eq!(linked, 1);
    }
}
