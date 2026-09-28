//! ETW trace sessions (`!wmitrace`): the kernel's `_WMI_LOGGER_CONTEXT`s,
//! the trace buffers each one owns, and the events in those buffers.
//!
//! Active loggers are the host silo's `_ETW_SILODRIVERSTATE.EtwpLoggerContext`
//! array (`nt!EtwpHostSiloState`, Windows 10 1607 and later), indexed by
//! logger id; a free slot holds 1. Every buffer a logger allocated, whether
//! a processor's current buffer, queued for flushing or free, is linked from
//! its `GlobalList`, so one walk of that list reaches all the events still in
//! memory.
//!
//! Buffer and logger layouts come from the kernel PDB, and so does
//! `_EVENT_HEADER`. The other trace headers (`SYSTEM_TRACE_HEADER`,
//! `PERFINFO_TRACE_HEADER`, `EVENT_TRACE_HEADER`,
//! `EVENT_INSTANCE_GUID_HEADER`, `MESSAGE_TRACE_HEADER`) are in no public
//! PDB; their layouts are the ETL on-disk format (NTWMI.H, evntrace.h), the
//! same in 32- and 64-bit Windows and unchanged since Windows 8, and are
//! written out below.

use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::bugchecks::looks_like_kernel_pointer;
use crate::bytes::{get_u16, get_u32, get_u64, write_u16, write_u32, write_u64};
use crate::error::{Error, Result};
use crate::expr::{Expr, NumberRadix};
use crate::kuser_shared::KuserSharedData;
use crate::layout::TypeInfo;
use crate::target::{ListCursor, Target};
use crate::triage_report::time::filetime_to_iso;
use crate::types::VirtAddr;
use crate::wpp::{TmfMessage, format_message};

/// Most `GlobalList` nodes walked for one logger; a logger's `MaximumBuffers`
/// is far below this.
const MAX_LOGGER_BUFFERS: usize = 65_536;

/// Largest trace buffer read (ETW caps `BufferSize` at 16 MiB).
const MAX_BUFFER_SIZE: u32 = 16 << 20;

/// `_WMI_LOGGER_CONTEXT.LoggerMode` bits (`EVENT_TRACE_*_MODE`, evntrace.h).
const LOGGER_MODE_NAMES: &[(u32, &str)] = &[
    (0x0000_0001, "FILE_MODE_SEQUENTIAL"),
    (0x0000_0002, "FILE_MODE_CIRCULAR"),
    (0x0000_0004, "FILE_MODE_APPEND"),
    (0x0000_0008, "FILE_MODE_NEWFILE"),
    (0x0000_0020, "FILE_MODE_PREALLOCATE"),
    (0x0000_0040, "NONSTOPPABLE_MODE"),
    (0x0000_0080, "SECURE_MODE"),
    (0x0000_0100, "REAL_TIME_MODE"),
    (0x0000_0200, "DELAY_OPEN_FILE_MODE"),
    (0x0000_0400, "BUFFERING_MODE"),
    (0x0000_0800, "PRIVATE_LOGGER_MODE"),
    (0x0000_1000, "ADD_HEADER_MODE"),
    (0x0000_2000, "USE_KBYTES_FOR_SIZE"),
    (0x0000_4000, "USE_GLOBAL_SEQUENCE"),
    (0x0000_8000, "USE_LOCAL_SEQUENCE"),
    (0x0001_0000, "RELOG_MODE"),
    (0x0002_0000, "PRIVATE_IN_PROC"),
    (0x0004_0000, "BUFFER_INTERFACE_MODE"),
    (0x0008_0000, "KD_FILTER_MODE"),
    (0x0010_0000, "REALTIME_RELOG_MODE"),
    (0x0020_0000, "LOST_EVENTS_DEBUG_MODE"),
    (0x0040_0000, "STOP_ON_HYBRID_SHUTDOWN"),
    (0x0080_0000, "PERSIST_ON_HYBRID_SHUTDOWN"),
    (0x0100_0000, "USE_PAGED_MEMORY"),
    (0x0200_0000, "SYSTEM_LOGGER_MODE"),
    (0x0400_0000, "COMPRESSED_MODE"),
    (0x0800_0000, "INDEPENDENT_SESSION_MODE"),
    (0x1000_0000, "NO_PER_PROCESSOR_BUFFERING"),
    (0x2000_0000, "BLOCKING_MODE"),
    (0x8000_0000, "ADDTO_TRIAGE_DUMP"),
];

/// `EVENT_TRACE_GROUP_*` (evntrace.h): the high byte of a kernel event's
/// hook id.
const EVENT_TRACE_GROUPS: &[&str] = &[
    "Header",
    "Io",
    "Memory",
    "Process",
    "File",
    "Thread",
    "TcpIp",
    "Job",
    "UdpIp",
    "Registry",
    "DbgPrint",
    "Config",
    "Spare1",
    "Wnf",
    "Pool",
    "PerfInfo",
    "Heap",
    "Object",
    "Power",
    "ModBound",
    "Image",
    "Dpc",
    "Cc",
    "CritSec",
    "StackWalk",
    "Ums",
    "Alpc",
    "SplitIo",
    "ThreadPool",
    "Hypervisor",
    "HypervisorX",
];

/// `EVENT_HEADER_EXT_TYPE_*` (evntcons.h), from 1.
const EXTENDED_TYPES: &[&str] = &[
    "RELATED_ACTIVITYID",
    "SID",
    "TS_ID",
    "INSTANCE_INFO",
    "STACK_TRACE32",
    "STACK_TRACE64",
    "PEBS_INDEX",
    "PMC_COUNTERS",
    "PSM_KEY",
    "EVENT_KEY",
    "EVENT_SCHEMA_TL",
    "PROV_TRAITS",
    "PROCESS_START_KEY",
    "CONTROL_GUID",
    "QPC_DELTA",
    "CONTAINER_ID",
    "STACK_KEY32",
    "STACK_KEY64",
];

/// The `EVENT_HEADER_EXT_TYPE_*` name of an extended data item's type.
pub fn extended_type_name(ext_type: u16) -> Option<&'static str> {
    EXTENDED_TYPES
        .get(usize::from(ext_type).checked_sub(1)?)
        .copied()
}

/// The names of the `EVENT_TRACE_*_MODE` bits set in `mode`.
pub fn logger_mode_names(mode: u32) -> Vec<&'static str> {
    LOGGER_MODE_NAMES
        .iter()
        .filter(|(bit, _)| mode & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// The `EVENT_TRACE_GROUP_*` name of a kernel event's hook id.
pub fn event_trace_group_name(hook_id: u16) -> Option<&'static str> {
    EVENT_TRACE_GROUPS.get(usize::from(hook_id >> 8)).copied()
}

/// `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` for a GUID's in-memory bytes.
pub fn format_guid(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    format!(
        "{{{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )
}

/// A FILETIME as `YYYY-MM-DD HH:MM:SS.fffffff` UTC, to the 100 ns tick.
pub fn format_filetime_precise(filetime: u64) -> Option<String> {
    let iso = filetime_to_iso(filetime)?;
    let (date, time) = iso.trim_end_matches('Z').split_once('T')?;
    Some(format!("{date} {time}.{:07}", filetime % 10_000_000))
}

/// What an ETW timestamp counts, from `_WMI_LOGGER_CONTEXT.ClockType`
/// (`EVENT_TRACE_CLOCK_*` in `WNODE_HEADER.ClientContext`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwClock {
    /// `QueryPerformanceCounter` ticks.
    PerformanceCounter,
    /// FILETIME, 100 ns since 1601.
    SystemTime,
    /// Processor cycle counter ticks.
    CpuCycle,
    Unknown(u32),
}

impl EtwClock {
    fn from_raw(raw: u32) -> Self {
        match raw {
            1 => Self::PerformanceCounter,
            2 => Self::SystemTime,
            3 => Self::CpuCycle,
            other => Self::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::PerformanceCounter => "PerfCounter",
            Self::SystemTime => "SystemTime",
            Self::CpuCycle => "CpuCycle",
            Self::Unknown(_) => "Unknown",
        }
    }

    pub fn raw(self) -> u32 {
        match self {
            Self::PerformanceCounter => 1,
            Self::SystemTime => 2,
            Self::CpuCycle => 3,
            Self::Unknown(raw) => raw,
        }
    }
}

/// One active trace session, decoded from its `_WMI_LOGGER_CONTEXT`.
#[derive(Debug, Clone)]
pub struct EtwLogger {
    pub address: VirtAddr,
    pub logger_id: u32,
    /// `LoggerName` and `LogFileName`, `None` when their buffer is
    /// unreadable (pool freed or paged out while a session stops).
    pub name: Option<String>,
    pub log_file_name: Option<String>,
    pub logger_mode: u32,
    /// Names of the `Flags` bitfields that are set, from the PDB.
    pub flag_names: Vec<String>,
    pub flags: u32,
    pub buffer_size: u32,
    pub maximum_event_size: u32,
    pub minimum_buffers: u32,
    pub maximum_buffers: u32,
    pub number_of_buffers: i32,
    pub buffers_available: i32,
    pub peak_buffers: i32,
    pub buffers_written: u32,
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub real_time_buffers_delivered: u32,
    pub real_time_buffers_lost: u32,
    pub maximum_file_size: u32,
    pub flush_timer: u32,
    pub flush_threshold: u32,
    pub clock: EtwClock,
    /// `StartTime`, a FILETIME.
    pub start_time: u64,
    /// `ReferenceTime`: the system time (FILETIME) at the clock value
    /// `reference_clock`, from which event timestamps are converted.
    pub reference_system_time: u64,
    pub reference_clock: u64,
    pub logger_thread: VirtAddr,
    pub logger_status: i32,
    pub consumers: u32,
    pub instance_guid: [u8; 16],
    pub collection_on: bool,
}

impl EtwLogger {
    /// Buffers taken from the free pool (`NumberOfBuffers -
    /// BuffersAvailable`): current on a processor, full, or being flushed.
    pub fn buffers_in_use(&self) -> i64 {
        i64::from(self.number_of_buffers) - i64::from(self.buffers_available)
    }
}

/// Every active logger of the host silo.
#[derive(Debug, Clone)]
pub struct EtwLoggerTable {
    pub silo_state: VirtAddr,
    /// `EtwpLoggerContext`: the array of `MaxLoggers` context pointers.
    pub context_array: VirtAddr,
    pub max_loggers: u32,
    pub loggers: Vec<EtwLogger>,
}

/// One trace buffer (`_WMI_BUFFER_HEADER`) of a logger.
#[derive(Debug, Clone)]
pub struct EtwBuffer {
    pub address: VirtAddr,
    pub state: u32,
    pub state_name: String,
    pub processor: u16,
    pub sequence_number: i64,
    pub timestamp: u64,
    pub saved_offset: u32,
    pub current_offset: u32,
    pub reference_count: i32,
    /// Bytes of the buffer holding the header and complete events.
    pub data_end: u32,
}

/// A logger and the buffers on its `GlobalList`.
#[derive(Debug, Clone)]
pub struct EtwLoggerBuffers {
    pub logger: EtwLogger,
    pub buffers: Vec<EtwBuffer>,
    /// Why the `GlobalList` walk ended before returning to its head.
    pub list_stop: Option<String>,
}

/// Which trace header an event record starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwHeaderKind {
    /// `SYSTEM_TRACE_HEADER` (kernel events, types 0x01/0x02).
    System,
    /// Compact `SYSTEM_TRACE_HEADER` (types 0x03/0x04).
    Compact,
    /// `PERFINFO_TRACE_HEADER` (types 0x10/0x11).
    PerfInfo,
    /// `EVENT_TRACE_HEADER` (classic providers, types 0x0a/0x14).
    FullHeader,
    /// `EVENT_INSTANCE_GUID_HEADER` (types 0x0b/0x15).
    Instance,
    /// `EVENT_HEADER` (manifest and TraceLogging providers, types 0x12/0x13).
    EventHeader,
    /// `MESSAGE_TRACE_HEADER` (WPP and other `TraceMessage` callers).
    Message,
}

impl EtwHeaderKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Compact => "compact",
            Self::PerfInfo => "perfinfo",
            Self::FullHeader => "classic",
            Self::Instance => "instance",
            Self::EventHeader => "event",
            Self::Message => "message",
        }
    }
}

/// `EVENT_DESCRIPTOR` of an `EVENT_HEADER` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwEventDescriptor {
    pub id: u16,
    pub version: u8,
    pub channel: u8,
    pub level: u8,
    pub opcode: u8,
    pub task: u16,
    pub keyword: u64,
}

/// The fields a `MESSAGE_TRACE_HEADER` carries after itself, as its
/// `TRACE_MESSAGE_*` option flags select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwMessage {
    pub number: u16,
    pub option_flags: u16,
    pub sequence: Option<u32>,
    pub guid: Option<[u8; 16]>,
    pub component_id: Option<u32>,
}

/// An `EVENT_HEADER` extended data item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwExtendedItem {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

/// One event record decoded out of a buffer's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwRecord {
    /// Offset of the record in its buffer.
    pub offset: u32,
    pub kind: EtwHeaderKind,
    pub header_type: u8,
    /// Record size, header included (unaligned).
    pub size: u16,
    /// Raw timestamp in the logger's clock; a WPP message without
    /// `TRACE_MESSAGE_TIMESTAMP` has none.
    pub timestamp: Option<u64>,
    pub thread_id: Option<u32>,
    pub process_id: Option<u32>,
    /// Provider (`EVENT_HEADER`), event class (`EVENT_TRACE_HEADER`) or
    /// message (`MESSAGE_TRACE_HEADER`) GUID.
    pub guid: Option<[u8; 16]>,
    pub descriptor: Option<EtwEventDescriptor>,
    /// `EVENT_HEADER.Flags`.
    pub event_flags: Option<u16>,
    pub activity_id: Option<[u8; 16]>,
    /// Kernel hook id (group << 8 | type) of system and perfinfo events.
    pub hook_id: Option<u16>,
    /// `Class.Type`/`Level`/`Version` of a classic event.
    pub class: Option<(u8, u8, u16)>,
    pub message: Option<EtwMessage>,
    pub extended: Vec<EtwExtendedItem>,
    pub payload: Vec<u8>,
}

/// Where a buffer's event walk stopped short of its data end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwDecodeStop {
    pub offset: u32,
    pub reason: String,
}

/// A WPP message with the TMF an indexed PDB declares for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwMessageFormat {
    /// The TMF's provider (component) name.
    pub provider: String,
    pub function: Option<String>,
    pub level: Option<String>,
    pub flags: Option<String>,
    /// The rendered message, or why the payload does not fit the TMF's
    /// argument types.
    pub text: std::result::Result<String, String>,
}

/// Render a WPP message record from the TMF `lookup` finds for its message
/// GUID and number. `None` for other records, messages without a GUID
/// (component ids), and messages no TMF describes.
pub fn format_message_record(
    record: &EtwRecord,
    lookup: impl FnOnce(&[u8; 16], u16) -> Option<Arc<TmfMessage>>,
    pointer_size: u8,
) -> Option<EtwMessageFormat> {
    let message = record.message.as_ref()?;
    let tmf = lookup(message.guid.as_ref()?, message.number)?;
    Some(EtwMessageFormat {
        provider: tmf.provider.clone(),
        function: tmf.function.clone(),
        level: tmf.level.clone(),
        flags: tmf.flags.clone(),
        text: format_message(&tmf, &record.payload, pointer_size),
    })
}

/// An event with the buffer it came from and its time.
#[derive(Debug, Clone)]
pub struct EtwEvent {
    pub buffer: VirtAddr,
    pub processor: u16,
    /// FILETIME, when the logger's clock converts to one.
    pub system_time: Option<u64>,
    pub record: EtwRecord,
    /// A WPP message's TMF rendering; `None` when no indexed PDB declares
    /// its TMF, or the record is not a WPP message.
    pub message_format: Option<EtwMessageFormat>,
}

/// A buffer whose events could not all be decoded.
#[derive(Debug, Clone)]
pub struct EtwBufferIssue {
    pub buffer: VirtAddr,
    pub offset: u32,
    pub reason: String,
}

/// `!wmitrace.logdump`: a logger's in-memory events in time order.
#[derive(Debug, Clone)]
pub struct EtwEventDump {
    pub logger: EtwLogger,
    pub buffers_walked: usize,
    /// Why the `GlobalList` walk ended before returning to its head.
    pub list_stop: Option<String>,
    /// Buffers skipped whole (compressed) and walks that stopped early.
    pub issues: Vec<EtwBufferIssue>,
    /// Events found before `-t` kept the most recent.
    pub total_events: usize,
    pub events: Vec<EtwEvent>,
    /// QPC frequency used for PerfCounter timestamps.
    pub qpc_frequency: Option<u64>,
    /// Processor speed used for CpuCycle timestamps.
    pub cpu_mhz: Option<u64>,
    /// Why some WPP messages have no `message_format`; `None` when every
    /// one has.
    pub message_format_note: Option<String>,
}

/// Why WPP messages among `events` have no TMF rendering, when some do not.
fn message_format_note(events: &[EtwEvent]) -> Option<String> {
    let raw = events
        .iter()
        .filter(|event| {
            event.record.kind == EtwHeaderKind::Message && event.message_format.is_none()
        })
        .count();
    (raw > 0).then(|| {
        format!(
            "{raw} WPP message{} shown raw: no loaded PDB carries their trace message \
             format (TMF), which only a provider's private PDB holds; add its directory \
             with .sympath+ <dir>, then .reload <driver>",
            if raw == 1 { " is" } else { "s are" }
        )
    })
}

/// Byte offsets of `_EVENT_HEADER` and its `_EVENT_DESCRIPTOR`, from the PDB.
#[derive(Debug, Clone, Copy)]
pub struct EventHeaderLayout {
    pub size: usize,
    pub flags: usize,
    pub thread_id: usize,
    pub process_id: usize,
    pub time_stamp: usize,
    pub provider_id: usize,
    pub descriptor: usize,
    pub activity_id: usize,
    pub descriptor_id: usize,
    pub descriptor_version: usize,
    pub descriptor_channel: usize,
    pub descriptor_level: usize,
    pub descriptor_opcode: usize,
    pub descriptor_task: usize,
    pub descriptor_keyword: usize,
}

impl EventHeaderLayout {
    fn from_pdb(header: &TypeInfo, descriptor: &TypeInfo) -> Result<Self> {
        let off =
            |ti: &TypeInfo, name: &str| -> Result<usize> { Ok(ti.field(name)?.offset as usize) };
        Ok(Self {
            size: header.size,
            flags: off(header, "Flags")?,
            thread_id: off(header, "ThreadId")?,
            process_id: off(header, "ProcessId")?,
            time_stamp: off(header, "TimeStamp")?,
            provider_id: off(header, "ProviderId")?,
            descriptor: off(header, "EventDescriptor")?,
            activity_id: off(header, "ActivityId")?,
            descriptor_id: off(descriptor, "Id")?,
            descriptor_version: off(descriptor, "Version")?,
            descriptor_channel: off(descriptor, "Channel")?,
            descriptor_level: off(descriptor, "Level")?,
            descriptor_opcode: off(descriptor, "Opcode")?,
            descriptor_task: off(descriptor, "Task")?,
            descriptor_keyword: off(descriptor, "Keyword")?,
        })
    }
}

/// The high bit of a trace header's fourth byte (`TRACE_HEADER_FLAG`):
/// set in every trace header, never in a `WNODE_HEADER`'s size.
const TRACE_HEADER_FLAG: u8 = 0x80;
/// `TRACE_HEADER_EVENT_TRACE`: the header continues with a header type.
const TRACE_HEADER_EVENT_TRACE: u8 = 0x40;
/// `TRACE_MESSAGE`: a `MESSAGE_TRACE_HEADER`.
const TRACE_MESSAGE: u8 = 0x10;

const TRACE_MESSAGE_SEQUENCE: u16 = 0x0001;
const TRACE_MESSAGE_GUID: u16 = 0x0002;
const TRACE_MESSAGE_COMPONENTID: u16 = 0x0004;
const TRACE_MESSAGE_TIMESTAMP: u16 = 0x0008;
const TRACE_MESSAGE_SYSTEMINFO: u16 = 0x0020;

const EVENT_HEADER_FLAG_EXTENDED_INFO: u16 = 0x0001;

fn guid_at(bytes: &[u8], at: usize) -> Option<[u8; 16]> {
    bytes.get(at..at.checked_add(16)?)?.try_into().ok()
}

fn align8(value: usize) -> usize {
    (value + 7) & !7
}

/// Decode the event records of one buffer's bytes, from `start` (the end of
/// its `_WMI_BUFFER_HEADER`) to `end` (its valid data end). Records are
/// 8-byte aligned. The walk stops at the first record it cannot recognize,
/// and says where and why, rather than guess where the next one starts.
pub fn decode_buffer_records(
    data: &[u8],
    start: usize,
    end: usize,
    layout: &EventHeaderLayout,
) -> (Vec<EtwRecord>, Option<EtwDecodeStop>) {
    let end = end.min(data.len());
    let mut records = Vec::new();
    let mut offset = start;
    while offset + 4 <= end {
        let stop = |reason: String| {
            Some(EtwDecodeStop {
                offset: offset as u32,
                reason,
            })
        };
        let record = match decode_record(&data[offset..end], layout) {
            Ok(record) => record,
            Err(reason) => return (records, stop(reason)),
        };
        let size = usize::from(record.size);
        records.push(EtwRecord {
            offset: offset as u32,
            ..record
        });
        offset += align8(size);
    }
    (records, None)
}

/// Decode the record at the start of `bytes`, which runs to the buffer's
/// data end.
fn decode_record(
    bytes: &[u8],
    layout: &EventHeaderLayout,
) -> std::result::Result<EtwRecord, String> {
    let marker = get_u32(bytes, 0).ok_or("truncated marker")?;
    let [b0, b1, header_type, flags] = marker.to_le_bytes();
    if marker == 0 {
        return Err("zero marker (unused space)".into());
    }
    if flags & TRACE_HEADER_FLAG == 0 {
        return Err(format!("marker {marker:#010x} is not a trace header"));
    }
    let leading = u16::from_le_bytes([b0, b1]);

    let kind = if flags & TRACE_HEADER_EVENT_TRACE != 0 {
        match header_type {
            0x01 | 0x02 => EtwHeaderKind::System,
            0x03 | 0x04 => EtwHeaderKind::Compact,
            0x10 | 0x11 => EtwHeaderKind::PerfInfo,
            0x0a | 0x14 => EtwHeaderKind::FullHeader,
            0x0b | 0x15 => EtwHeaderKind::Instance,
            0x12 | 0x13 => EtwHeaderKind::EventHeader,
            other => return Err(format!("unknown trace header type {other:#04x}")),
        }
    } else if flags & TRACE_MESSAGE != 0 {
        EtwHeaderKind::Message
    } else {
        return Err(format!("marker {marker:#010x} names no known trace header"));
    };

    // SYSTEM/PERFINFO headers keep a version in the first word and the size
    // in the WMI_TRACE_PACKET that follows; the rest start with their size.
    let (size, header_len) = match kind {
        EtwHeaderKind::System => (get_u16(bytes, 4), 0x20),
        EtwHeaderKind::Compact => (get_u16(bytes, 4), 0x18),
        EtwHeaderKind::PerfInfo => (get_u16(bytes, 4), 0x10),
        EtwHeaderKind::FullHeader => (Some(leading), 0x30),
        EtwHeaderKind::Instance => (Some(leading), 0x48),
        EtwHeaderKind::EventHeader => (Some(leading), layout.size),
        EtwHeaderKind::Message => (Some(leading), 8),
    };
    let size = size.ok_or("truncated header")?;
    let len = usize::from(size);
    if len < header_len {
        return Err(format!(
            "{} record size {size:#x} is below its {header_len:#x}-byte header",
            kind.name()
        ));
    }
    if len > bytes.len() {
        return Err(format!(
            "{} record size {size:#x} runs past the buffer's data end",
            kind.name()
        ));
    }
    let bytes = &bytes[..len];
    let mut record = EtwRecord {
        offset: 0,
        kind,
        header_type,
        size,
        timestamp: None,
        thread_id: None,
        process_id: None,
        guid: None,
        descriptor: None,
        event_flags: None,
        activity_id: None,
        hook_id: None,
        class: None,
        message: None,
        extended: Vec::new(),
        payload: Vec::new(),
    };
    let truncated = || format!("{} header is truncated", kind.name());

    let payload_start = match kind {
        EtwHeaderKind::System | EtwHeaderKind::Compact => {
            record.hook_id = get_u16(bytes, 6);
            record.thread_id = get_u32(bytes, 8);
            record.process_id = get_u32(bytes, 12);
            record.timestamp = Some(get_u64(bytes, 16).ok_or_else(truncated)?);
            header_len
        }
        EtwHeaderKind::PerfInfo => {
            record.hook_id = get_u16(bytes, 6);
            record.timestamp = Some(get_u64(bytes, 8).ok_or_else(truncated)?);
            header_len
        }
        EtwHeaderKind::FullHeader | EtwHeaderKind::Instance => {
            record.class = Some((bytes[4], bytes[5], get_u16(bytes, 6).ok_or_else(truncated)?));
            record.thread_id = get_u32(bytes, 8);
            record.process_id = get_u32(bytes, 12);
            record.timestamp = Some(get_u64(bytes, 16).ok_or_else(truncated)?);
            record.guid = guid_at(bytes, 24);
            header_len
        }
        EtwHeaderKind::EventHeader => {
            let flags = get_u16(bytes, layout.flags).ok_or_else(truncated)?;
            record.event_flags = Some(flags);
            record.thread_id = get_u32(bytes, layout.thread_id);
            record.process_id = get_u32(bytes, layout.process_id);
            record.timestamp = Some(get_u64(bytes, layout.time_stamp).ok_or_else(truncated)?);
            record.guid = guid_at(bytes, layout.provider_id);
            record.activity_id = guid_at(bytes, layout.activity_id);
            let d = layout.descriptor;
            record.descriptor = Some(EtwEventDescriptor {
                id: get_u16(bytes, d + layout.descriptor_id).ok_or_else(truncated)?,
                version: bytes[d + layout.descriptor_version],
                channel: bytes[d + layout.descriptor_channel],
                level: bytes[d + layout.descriptor_level],
                opcode: bytes[d + layout.descriptor_opcode],
                task: get_u16(bytes, d + layout.descriptor_task).ok_or_else(truncated)?,
                keyword: get_u64(bytes, d + layout.descriptor_keyword).ok_or_else(truncated)?,
            });
            let mut at = header_len;
            if flags & EVENT_HEADER_FLAG_EXTENDED_INFO != 0 {
                // Each item: USHORT size (8 + DataSize, rounded up to 8),
                // USHORT ExtType, USHORT Linkage (bit 0: another item
                // follows), USHORT DataSize, then the data.
                loop {
                    let item = |field| get_u16(bytes, at + field);
                    let (Some(total), Some(ext_type), Some(linkage), Some(data_size)) =
                        (item(0), item(2), item(4), item(6))
                    else {
                        return Err(format!(
                            "extended data item at +{at:#x} runs past the event"
                        ));
                    };
                    let total = usize::from(total);
                    let data_end = at + 8 + usize::from(data_size);
                    if total != align8(8 + usize::from(data_size)) || at + total > len {
                        return Err(format!(
                            "extended data item at +{at:#x} has size {total:#x} for {data_size:#x} data bytes"
                        ));
                    }
                    record.extended.push(EtwExtendedItem {
                        ext_type,
                        data: bytes[at + 8..data_end].to_vec(),
                    });
                    at += total;
                    if linkage & 1 == 0 {
                        break;
                    }
                }
            }
            at.min(len)
        }
        EtwHeaderKind::Message => {
            let number = get_u16(bytes, 4).ok_or_else(truncated)?;
            let option_flags = get_u16(bytes, 6).ok_or_else(truncated)?;
            let mut at = 8;
            let mut take = |n: usize| -> std::result::Result<usize, String> {
                let here = at;
                if here + n > len {
                    return Err(format!(
                        "message options {option_flags:#06x} need more than its {size:#x} bytes"
                    ));
                }
                at += n;
                Ok(here)
            };
            let sequence = if option_flags & TRACE_MESSAGE_SEQUENCE != 0 {
                get_u32(bytes, take(4)?)
            } else {
                None
            };
            let (component_id, guid) = if option_flags & TRACE_MESSAGE_COMPONENTID != 0 {
                (get_u32(bytes, take(4)?), None)
            } else if option_flags & TRACE_MESSAGE_GUID != 0 {
                (None, guid_at(bytes, take(16)?))
            } else {
                (None, None)
            };
            if option_flags & TRACE_MESSAGE_TIMESTAMP != 0 {
                record.timestamp = Some(get_u64(bytes, take(8)?).ok_or_else(truncated)?);
            }
            if option_flags & TRACE_MESSAGE_SYSTEMINFO != 0 {
                let info = take(8)?;
                record.thread_id = get_u32(bytes, info);
                record.process_id = get_u32(bytes, info + 4);
            }
            record.guid = guid;
            record.message = Some(EtwMessage {
                number,
                option_flags,
                sequence,
                guid,
                component_id,
            });
            at
        }
    };
    record.payload = bytes[payload_start..].to_vec();
    Ok(record)
}

/// `!wmitrace.logdump`'s arguments: `[-t count] <logger>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogDumpArguments {
    pub logger: String,
    /// `-t`: keep only this many of the most recent events.
    pub most_recent: Option<usize>,
}

impl LogDumpArguments {
    /// Parse `[-t count] <logger>`; `None` when no logger is named. The count
    /// is decimal, or hex with `0x`, whatever the radix, as WinDbg takes it.
    pub fn parse<'a>(args: impl IntoIterator<Item = &'a str>) -> Result<Option<Self>> {
        let mut most_recent = None;
        let mut logger = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            if arg.eq_ignore_ascii_case("-t") {
                let count = args
                    .next()
                    .ok_or_else(|| Error::InvalidArgument("-t needs a count of events".into()))?;
                let parsed = match count
                    .strip_prefix("0x")
                    .or_else(|| count.strip_prefix("0X"))
                {
                    Some(hex) => usize::from_str_radix(hex, 16),
                    None => count.parse(),
                };
                most_recent = Some(parsed.map_err(|_| {
                    Error::InvalidArgument(format!("-t count '{count}' is not a number"))
                })?);
            } else if logger.is_none() {
                logger = Some(arg.to_string());
            } else {
                return Err(Error::InvalidArgument(format!(
                    "unexpected argument '{arg}': quote a session name that has spaces; filtering by a GUID file is not supported"
                )));
            }
        }
        Ok(logger.map(|logger| Self {
            logger,
            most_recent,
        }))
    }
}

/// How a logger's raw timestamps become FILETIMEs.
#[derive(Debug, Clone, Copy)]
struct TimeBase {
    clock: EtwClock,
    reference_system_time: u64,
    reference_clock: u64,
    qpc_frequency: Option<u64>,
    cpu_mhz: Option<u64>,
}

impl TimeBase {
    /// The reference system time plus `timestamp - reference_clock` clock
    /// ticks, at `per` 100 ns units every `ticks` ticks.
    fn after_reference(&self, timestamp: u64, per: i128, ticks: u64) -> Option<u64> {
        let delta = i128::from(timestamp) - i128::from(self.reference_clock);
        let elapsed = delta * per / i128::from(ticks);
        u64::try_from(i128::from(self.reference_system_time) + elapsed).ok()
    }

    fn system_time(&self, timestamp: u64) -> Option<u64> {
        match self.clock {
            EtwClock::SystemTime => Some(timestamp),
            EtwClock::PerformanceCounter => {
                let frequency = self.qpc_frequency.filter(|f| *f != 0)?;
                self.after_reference(timestamp, 10_000_000, frequency)
            }
            // Cycles at the processor's rated speed, as a consumer converts
            // them with the logfile header's CpuSpeedInMHz.
            EtwClock::CpuCycle => {
                let mhz = self.cpu_mhz.filter(|f| *f != 0)?;
                self.after_reference(timestamp, 10, mhz)
            }
            EtwClock::Unknown(_) => None,
        }
    }
}

/// A logger picked by `!wmitrace` argument: a session name, a logger id,
/// or a `_WMI_LOGGER_CONTEXT` address.
fn select_logger<'t>(
    table: &'t EtwLoggerTable,
    text: &str,
    evaluate: impl FnOnce(&str) -> Result<VirtAddr>,
) -> Result<&'t EtwLogger> {
    if let Some(logger) = table.loggers.iter().find(|logger| {
        logger
            .name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case(text))
    }) {
        return Ok(logger);
    }
    let value = evaluate(text).map_err(|e| {
        Error::InvalidArgument(format!(
            "'{text}' is not an active logger's name, and not a logger id or address: {e}"
        ))
    })?;
    let found = if value.0 < u64::from(table.max_loggers) {
        table
            .loggers
            .iter()
            .find(|l| u64::from(l.logger_id) == value.0)
    } else {
        table.loggers.iter().find(|l| l.address == value)
    };
    found.ok_or_else(|| {
        Error::InvalidArgument(if value.0 < u64::from(table.max_loggers) {
            format!("no active logger has id {:#x}", value.0)
        } else {
            format!(
                "{:#x} is not the _WMI_LOGGER_CONTEXT of an active logger",
                value.0
            )
        })
    })
}

struct EtwTypes {
    logger: Arc<TypeInfo>,
    buffer: Arc<TypeInfo>,
    event_header: EventHeaderLayout,
    /// `_ETW_BUFFER_STATE`'s variants; empty when the PDB lacks the enum.
    buffer_states: Vec<(String, i64)>,
}

impl EtwTypes {
    /// The value of the `_ETW_BUFFER_STATE` variant `name`.
    fn buffer_state(&self, name: &str) -> Option<i64> {
        self.buffer_states
            .iter()
            .find(|(variant, _)| variant == name)
            .map(|(_, value)| *value)
    }
}

impl Target {
    fn etw_types(&self) -> Result<EtwTypes> {
        let guest = self.guest()?;
        let types = guest.ntoskrnl.types();
        Ok(EtwTypes {
            logger: types.layout("_WMI_LOGGER_CONTEXT")?,
            buffer: types.layout("_WMI_BUFFER_HEADER")?,
            event_header: EventHeaderLayout::from_pdb(
                &*types.layout("_EVENT_HEADER")?,
                &*types.layout("_EVENT_DESCRIPTOR")?,
            )?,
            buffer_states: guest
                .ntoskrnl
                .guid
                .and_then(|guid| self.symbols.enum_variants(guid, "_ETW_BUFFER_STATE"))
                .unwrap_or_default(),
        })
    }

    /// Every active logger of the host silo, in logger-id order.
    pub fn etw_loggers(&self) -> Result<EtwLoggerTable> {
        let guest = self.guest()?;
        let silo_symbol = guest.ntoskrnl.symbol("EtwpHostSiloState").map_err(|_| {
            Error::DebugInfo(
                "nt!EtwpHostSiloState is not in the kernel's symbols; loggers are read from \
                 the host silo's ETW state, which kernels before Windows 10 1607 do not have"
                    .into(),
            )
        })?;
        let silo_state: VirtAddr = silo_symbol.read()?;
        if silo_state.is_zero() {
            return Err(Error::DebugInfo(
                "nt!EtwpHostSiloState is null: ETW is not initialized".into(),
            ));
        }
        let silo = guest
            .ntoskrnl
            .types()
            .struct_at("_ETW_SILODRIVERSTATE", silo_state)?;
        let max_loggers = silo.read_uint("MaxLoggers")? as u32;
        let context_array = silo.read_pointer("EtwpLoggerContext")?;
        if max_loggers == 0 || max_loggers > 0x1_0000 || context_array.is_zero() {
            return Err(Error::DebugInfo(format!(
                "_ETW_SILODRIVERSTATE at {:#x} has MaxLoggers {max_loggers} and \
                 EtwpLoggerContext {:#x}; not a logger table",
                silo_state.0, context_array.0
            )));
        }
        let mut raw = vec![0u8; max_loggers as usize * 8];
        self.kernel_address_space()
            .read_bytes(context_array, &mut raw)?;
        let types = self.etw_types()?;
        let mut loggers = Vec::new();
        for (slot, bytes) in raw.as_chunks::<8>().0.iter().enumerate() {
            let context = u64::from_le_bytes(*bytes);
            // A free slot holds 1 (ETW_UNUSED_LOGGER), a never-used one 0.
            if context <= 1 {
                continue;
            }
            if !looks_like_kernel_pointer(context) {
                return Err(Error::DebugInfo(format!(
                    "EtwpLoggerContext[{slot:#x}] at {:#x} holds {context:#x}, not a logger context",
                    context_array.0 + slot as u64 * 8
                )));
            }
            let logger = self.read_etw_logger(&types.logger, VirtAddr(context))?;
            if logger.logger_id as usize != slot {
                return Err(Error::DebugInfo(format!(
                    "EtwpLoggerContext[{slot:#x}] points at {context:#x}, whose LoggerId is {:#x}",
                    logger.logger_id
                )));
            }
            loggers.push(logger);
        }
        Ok(EtwLoggerTable {
            silo_state,
            context_array,
            max_loggers,
            loggers,
        })
    }

    fn read_etw_logger(&self, layout: &Arc<TypeInfo>, address: VirtAddr) -> Result<EtwLogger> {
        let ctx = self
            .guest()?
            .ntoskrnl
            .types()
            .struct_with_layout(layout.clone(), address)
            .prefetch();
        let flags = ctx.read_field::<u32>("Flags")?;
        let flag_names = layout.set_bit_names("Flags", u64::from(flags));
        let reference = ctx.embedded("ReferenceTime")?;
        let instance_guid: [u8; 16] = ctx
            .read_field_bytes("InstanceGuid", 16)?
            .try_into()
            .map_err(|_| Error::DebugInfo("InstanceGuid is not 16 bytes".into()))?;
        Ok(EtwLogger {
            address,
            logger_id: ctx.read_field("LoggerId")?,
            name: ctx.unicode_string("LoggerName").ok(),
            log_file_name: ctx.unicode_string("LogFileName").ok(),
            logger_mode: ctx.read_field("LoggerMode")?,
            flag_names,
            flags,
            buffer_size: ctx.read_field("BufferSize")?,
            maximum_event_size: ctx.read_field("MaximumEventSize")?,
            minimum_buffers: ctx.read_field("MinimumBuffers")?,
            maximum_buffers: ctx.read_field("MaximumBuffers")?,
            number_of_buffers: ctx.read_field("NumberOfBuffers")?,
            buffers_available: ctx.read_field("BuffersAvailable")?,
            peak_buffers: ctx.read_field("PeakBuffersCount")?,
            buffers_written: ctx.read_field("BuffersWritten")?,
            events_lost: ctx.read_field("EventsLost")?,
            log_buffers_lost: ctx.read_field("LogBuffersLost")?,
            real_time_buffers_delivered: ctx.read_field("RealTimeBuffersDelivered")?,
            real_time_buffers_lost: ctx.read_field("RealTimeBuffersLost")?,
            maximum_file_size: ctx.read_field("MaximumFileSize")?,
            flush_timer: ctx.read_field("FlushTimer")?,
            flush_threshold: ctx.read_field("FlushThreshold")?,
            clock: EtwClock::from_raw(ctx.read_field("ClockType")?),
            start_time: ctx.read_field("StartTime")?,
            reference_system_time: reference.read_field("StartTime")?,
            reference_clock: reference.read_field("StartPerfClock")?,
            logger_thread: ctx.read_pointer("LoggerThread")?,
            logger_status: ctx.read_field("LoggerStatus")?,
            consumers: ctx.read_field("NumConsumers")?,
            instance_guid,
            collection_on: ctx.read_field::<i32>("CollectionOn")? != 0,
        })
    }

    /// The active logger `text` names: a session name (without case), a
    /// logger id, or a `_WMI_LOGGER_CONTEXT` address, evaluated with `radix`.
    pub fn etw_logger(&self, text: &str, radix: NumberRadix) -> Result<EtwLogger> {
        let table = self.etw_loggers()?;
        select_logger(&table, text, |text| {
            Expr::eval_with_radix(text, self, radix)
        })
        .cloned()
    }

    /// The logger `text` names (see [`Self::etw_logger`]) and every buffer on
    /// its `GlobalList`.
    pub fn etw_logger_buffers(&self, text: &str, radix: NumberRadix) -> Result<EtwLoggerBuffers> {
        let logger = self.etw_logger(text, radix)?;
        let types = self.etw_types()?;
        let (buffers, list_stop) = self.read_etw_buffers(&types, &logger)?;
        Ok(EtwLoggerBuffers {
            logger,
            buffers,
            list_stop,
        })
    }

    /// The buffers on `logger`'s `GlobalList`, and why the walk ended before
    /// returning to the list head, if it did: a bad link or a node that is
    /// not one of the logger's buffers keeps the buffers already found.
    fn read_etw_buffers(
        &self,
        types: &EtwTypes,
        logger: &EtwLogger,
    ) -> Result<(Vec<EtwBuffer>, Option<String>)> {
        if logger.buffer_size as usize <= types.buffer.size || logger.buffer_size > MAX_BUFFER_SIZE
        {
            return Err(Error::DebugInfo(format!(
                "logger {:#x}'s BufferSize {:#x} is not a trace buffer size (above the {:#x}-byte \
                 buffer header, at most ETW's 16 MB)",
                logger.logger_id, logger.buffer_size, types.buffer.size
            )));
        }
        let memory = self.kernel_address_space();
        let head = logger.address + types.logger.field_offset("GlobalList")?;
        let global_entry = types.buffer.field_offset("GlobalEntry")?;
        let next = |link: VirtAddr| memory.read::<VirtAddr>(link).map_err(|e| e.to_string());
        let mut buffers = Vec::new();
        let mut cursor = ListCursor::new(head, MAX_LOGGER_BUFFERS);
        cursor.advance(next(head));
        while let Some(link) = cursor.take_current() {
            // Windows 10 links a small node per buffer ({LIST_ENTRY, buffer
            // pointer}, pool tag Etwn); earlier kernels linked the buffers'
            // own GlobalEntry. Take whichever is one of this logger's buffers.
            let node_buffer = memory.read::<VirtAddr>(link + 0x10u64).ok();
            let buffer = [
                node_buffer,
                Some(VirtAddr(link.0.wrapping_sub(global_entry))),
            ]
            .into_iter()
            .flatten()
            .find_map(|candidate| self.read_etw_buffer(types, logger, candidate).ok());
            let Some(buffer) = buffer else {
                let reason = format!(
                    "entry {:#x} leads to no _WMI_BUFFER_HEADER of this logger (BufferSize \
                     {:#x}, LoggerId {:#x})",
                    link.0, logger.buffer_size, logger.logger_id
                );
                // No buffer at all means the list is not laid out as
                // expected, rather than torn at one node.
                if buffers.is_empty() {
                    return Err(Error::DebugInfo(format!(
                        "logger {:#x}'s GlobalList {reason}",
                        logger.logger_id
                    )));
                }
                return Ok((
                    buffers,
                    Some(format!("GlobalList at {:#x} {reason}", head.0)),
                ));
            };
            buffers.push(buffer);
            cursor.advance(next(link));
        }
        let list_stop = cursor
            .finish()
            .diagnostic()
            .map(|reason| format!("GlobalList at {:#x} ends early: {reason}", head.0));
        Ok((buffers, list_stop))
    }

    fn read_etw_buffer(
        &self,
        types: &EtwTypes,
        logger: &EtwLogger,
        address: VirtAddr,
    ) -> Result<EtwBuffer> {
        if !looks_like_kernel_pointer(address.0) {
            return Err(Error::DebugInfo("not a kernel address".into()));
        }
        let header = self
            .guest()?
            .ntoskrnl
            .types()
            .struct_with_layout(types.buffer.clone(), address)
            .prefetch();
        let buffer_size: u32 = header.read_field("BufferSize")?;
        let context = header.embedded("ClientContext")?;
        let logger_id: u16 = context.read_field("LoggerId")?;
        if buffer_size != logger.buffer_size || u32::from(logger_id) != logger.logger_id {
            return Err(Error::DebugInfo(format!(
                "BufferSize {buffer_size:#x}, LoggerId {logger_id:#x}"
            )));
        }
        let state: u32 = header.read_field("State")?;
        let saved_offset: u32 = header.read_field("SavedOffset")?;
        let current_offset: u32 = header.read_field("CurrentOffset")?;
        // SavedOffset is set when a buffer is switched out and counts the
        // valid bytes; a processor's current buffer has only its live
        // CurrentOffset, which a failed reservation can push past the end.
        let data_end = if saved_offset != 0 {
            saved_offset
        } else {
            current_offset
        }
        .min(buffer_size);
        Ok(EtwBuffer {
            address,
            state,
            state_name: types
                .buffer_states
                .iter()
                .find(|(_, value)| *value == i64::from(state))
                .map(|(name, _)| name.trim_start_matches("EtwBufferState").to_string())
                .unwrap_or_else(|| format!("{state:#x}")),
            processor: context.read_field("ProcessorIndex")?,
            sequence_number: header.read_field("SequenceNumber")?,
            timestamp: header.read_field("TimeStamp")?,
            saved_offset,
            current_offset,
            reference_count: header.read_field("ReferenceCount")?,
            data_end,
        })
    }

    /// `!wmitrace.logdump`: the events in the buffers of the logger `text`
    /// names, oldest first; `most_recent` keeps only that many of the newest.
    pub fn etw_log_dump(
        &self,
        text: &str,
        radix: NumberRadix,
        most_recent: Option<usize>,
    ) -> Result<EtwEventDump> {
        let logger = self.etw_logger(text, radix)?;
        let types = self.etw_types()?;
        let (buffers, list_stop) = self.read_etw_buffers(&types, &logger)?;
        let qpc_frequency = KuserSharedData::new(self).qpc_frequency();
        let cpu_mhz = match logger.clock {
            EtwClock::CpuCycle => Some(self.processor_mhz()?),
            _ => None,
        };
        let time = TimeBase {
            clock: logger.clock,
            reference_system_time: logger.reference_system_time,
            reference_clock: logger.reference_clock,
            qpc_frequency,
            cpu_mhz,
        };
        let header_size = types.buffer.size;
        let compressed = types.buffer_state("EtwBufferStateCompressed");
        let memory = self.kernel_address_space();
        // Each event with the time it sorts by.
        let mut events = Vec::new();
        let mut issues = Vec::new();
        let mut walked = 0;
        // read_etw_buffers bounded BufferSize, and every data_end by it.
        let mut data = vec![0u8; logger.buffer_size as usize];
        for buffer in &buffers {
            if self.interrupted() {
                return Err(Error::DebugInfo("interrupted".into()));
            }
            if compressed == Some(i64::from(buffer.state)) {
                issues.push(EtwBufferIssue {
                    buffer: buffer.address,
                    offset: 0,
                    reason: "buffer is compressed".into(),
                });
                continue;
            }
            let end = buffer.data_end as usize;
            if end <= header_size {
                continue;
            }
            if let Err(e) = memory.read_bytes(buffer.address, &mut data[..end]) {
                issues.push(EtwBufferIssue {
                    buffer: buffer.address,
                    offset: 0,
                    reason: format!("unreadable: {e}"),
                });
                continue;
            }
            walked += 1;
            let (records, stop) =
                decode_buffer_records(&data, header_size, end, &types.event_header);
            if let Some(stop) = stop {
                issues.push(EtwBufferIssue {
                    buffer: buffer.address,
                    offset: stop.offset,
                    reason: stop.reason,
                });
            }
            // A WPP message without a timestamp sorts after the record
            // before it in its buffer.
            let mut previous = 0;
            events.extend(records.into_iter().map(|record| {
                let order = record.timestamp.unwrap_or(previous);
                previous = order;
                let message_format = format_message_record(
                    &record,
                    |guid, number| self.symbols.wpp_message(guid, number),
                    types.buffer.pointer_size,
                );
                let event = EtwEvent {
                    buffer: buffer.address,
                    processor: buffer.processor,
                    system_time: record.timestamp.and_then(|t| time.system_time(t)),
                    record,
                    message_format,
                };
                (order, event)
            }));
        }
        events.sort_by_key(|(order, event)| (*order, event.buffer.0, event.record.offset));
        let total_events = events.len();
        let events: Vec<EtwEvent> = events
            .into_iter()
            .skip(most_recent.map_or(0, |count| total_events.saturating_sub(count)))
            .map(|(_, event)| event)
            .collect();
        let message_format_note = message_format_note(&events);
        Ok(EtwEventDump {
            logger,
            buffers_walked: walked,
            list_stop,
            issues,
            total_events,
            events,
            qpc_frequency,
            cpu_mhz,
            message_format_note,
        })
    }

    /// Processor 0's rated speed (`_KPRCB.MHz`), which converts CpuCycle
    /// timestamps.
    fn processor_mhz(&self) -> Result<u64> {
        let kprcb = crate::cpu_state::kprcb_for_processor(self, 0)?;
        let mhz = self
            .guest()?
            .ntoskrnl
            .types()
            .struct_at("_KPRCB", kprcb)?
            .read_uint("MHz")?;
        Ok(mhz)
    }
}

/// `!wmitrace.logsave`: a logger's in-memory buffers as an .etl file.
#[derive(Debug, Clone)]
pub struct EtwLogFile {
    pub logger: EtwLogger,
    /// Buffers with events written after the header buffer.
    pub buffers: usize,
    /// Why the `GlobalList` walk ended before returning to its head.
    pub list_stop: Option<String>,
    /// Buffers left out (unreadable) and buffers cut short before a record
    /// that does not decode.
    pub issues: Vec<EtwBufferIssue>,
    pub bytes: Vec<u8>,
}

/// What the logfile header event records besides the logger's own fields.
#[derive(Debug, Clone, Copy)]
struct LogFileSystem {
    major_version: u8,
    minor_version: u8,
    build_number: u32,
    processors: u32,
    timer_resolution: u32,
    cpu_mhz: u32,
    boot_time: u64,
    qpc_frequency: u64,
    end_time: u64,
    /// UTC minus local time, in minutes.
    time_zone_bias: i32,
}

/// `WMI_LOG_TYPE_HEADER`: the hook id of the logfile header event.
const WMI_LOG_TYPE_HEADER: u16 = 0x0000;
/// `ETW_BUFFER_FLAG_FLUSH_MARKER | ETW_BUFFER_FLAG_PROC_INDEX`, as the kernel
/// marks the header buffer it writes.
const HEADER_BUFFER_FLAG: u16 = 0x0021;
/// `ETW_BUFFER_FLAG_PROC_INDEX`: `ClientContext` holds a processor index.
const DATA_BUFFER_FLAG: u16 = 0x0020;
/// `ETW_BUFFER_TYPE_HEADER`.
const HEADER_BUFFER_TYPE: u16 = 4;
/// `ETW_BUFFER_TYPE_GENERIC`.
const DATA_BUFFER_TYPE: u16 = 0;
/// `sizeof(TRACE_LOGFILE_HEADER64)`.
const TRACE_LOGFILE_HEADER64_SIZE: usize = 0x118;
/// `EVENT_TRACE_REAL_TIME_MODE | STOP_ON_HYBRID_SHUTDOWN |
/// PERSIST_ON_HYBRID_SHUTDOWN`: modes the kernel clears from the header's
/// LogFileMode.
const LOGFILE_MODE_CLEARED: u32 = 0x0000_0100 | 0x0040_0000 | 0x0080_0000;

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Offsets in `_WMI_BUFFER_HEADER` that an .etl buffer's header needs.
struct BufferHeaderOffsets {
    size: usize,
    buffer_size: usize,
    saved_offset: usize,
    current_offset: usize,
    logger_id: usize,
    state: usize,
    offset: usize,
    buffer_flag: usize,
    buffer_type: usize,
}

impl BufferHeaderOffsets {
    fn from_pdb(buffer: &TypeInfo, context: &TypeInfo) -> Result<Self> {
        let off =
            |ti: &TypeInfo, name: &str| -> Result<usize> { Ok(ti.field(name)?.offset as usize) };
        Ok(Self {
            size: buffer.size,
            buffer_size: off(buffer, "BufferSize")?,
            saved_offset: off(buffer, "SavedOffset")?,
            current_offset: off(buffer, "CurrentOffset")?,
            logger_id: off(buffer, "ClientContext")? + off(context, "LoggerId")?,
            state: off(buffer, "State")?,
            offset: off(buffer, "Offset")?,
            buffer_flag: off(buffer, "BufferFlag")?,
            buffer_type: off(buffer, "BufferType")?,
        })
    }

    /// Mark `buffer` as flushed with `used` valid bytes, as the logger
    /// writes it to its file: the rest of the buffer is filled with 0xff.
    fn seal(&self, buffer: &mut [u8], used: usize, state: u32, flag: u16, kind: u16) {
        write_u32(buffer, self.saved_offset, used as u32);
        write_u32(buffer, self.current_offset, used as u32);
        write_u32(buffer, self.offset, used as u32);
        write_u32(buffer, self.state, state);
        write_u16(buffer, self.buffer_flag, flag);
        write_u16(buffer, self.buffer_type, kind);
        buffer[used..].fill(0xff);
    }
}

/// The header buffer that begins an .etl file: a `WMI_BUFFER_HEADER` and
/// the `WMI_LOG_TYPE_HEADER` event, a `SYSTEM_TRACE_HEADER` followed by a
/// `TRACE_LOGFILE_HEADER64` and the logger and log file names. Laid out as
/// the kernel writes it (checked against a 26200 kernel's own .etl).
/// `buffer` is one zeroed trace buffer of the logger's `BufferSize`.
fn write_logfile_header_buffer(
    buffer: &mut [u8],
    logger: &EtwLogger,
    system: &LogFileSystem,
    offsets: &BufferHeaderOffsets,
    flush_state: u32,
    buffers_written: u32,
) -> Result<()> {
    let size = buffer.len();
    let logger_name = utf16z(logger.name.as_deref().unwrap_or_default());
    let file_name = utf16z(logger.log_file_name.as_deref().unwrap_or_default());
    let event_size = 0x20 + TRACE_LOGFILE_HEADER64_SIZE + logger_name.len() + file_name.len();
    let event = offsets.size;
    let used = align8(event + event_size);
    // The buffer header fields lie below `event`, so this bounds every write.
    if event_size > usize::from(u16::MAX) || used > size {
        return Err(Error::DebugInfo(format!(
            "the logfile header event ({event_size:#x} bytes) does not fit a {size:#x}-byte buffer"
        )));
    }
    write_u32(buffer, offsets.buffer_size, logger.buffer_size);
    write_u16(buffer, offsets.logger_id, logger.logger_id as u16);
    // SYSTEM_TRACE_HEADER: version 2, TRACE_HEADER_TYPE_SYSTEM64, flags
    // 0xc0; the thread, process and CPU times stay 0.
    write_u32(buffer, event, 0xc002_0002);
    write_u16(buffer, event + 4, event_size as u16);
    write_u16(buffer, event + 6, WMI_LOG_TYPE_HEADER);
    write_u64(buffer, event + 0x10, logger.reference_clock);

    let h = event + 0x20;
    // Layout 1.5 (QPC and platform clock in the header), 2.0 for buffers
    // over 1 MB, compressed loggers or more than 256 processors.
    let sub_version: u16 = if logger.buffer_size > 1 << 20
        || logger.logger_mode & 0x0400_0000 != 0
        || system.processors > 256
    {
        0x0002
    } else {
        0x0501
    };
    write_u32(buffer, h, logger.buffer_size);
    buffer[h + 4] = system.major_version;
    buffer[h + 5] = system.minor_version;
    write_u16(buffer, h + 6, sub_version);
    write_u32(buffer, h + 0x08, system.build_number);
    write_u32(buffer, h + 0x0c, system.processors);
    write_u64(buffer, h + 0x10, system.end_time);
    write_u32(buffer, h + 0x18, system.timer_resolution);
    write_u32(buffer, h + 0x1c, logger.maximum_file_size);
    write_u32(buffer, h + 0x20, logger.logger_mode & !LOGFILE_MODE_CLEARED);
    write_u32(buffer, h + 0x24, buffers_written);
    write_u32(buffer, h + 0x28, 1); // StartBuffers
    write_u32(buffer, h + 0x2c, 8); // PointerSize
    write_u32(buffer, h + 0x30, logger.events_lost);
    write_u32(buffer, h + 0x34, system.cpu_mhz);
    // LoggerName/LogFileName (0x38/0x40) hold platform timer sources, not
    // known here; TimeZone (0x48) gets only the bias.
    write_u32(buffer, h + 0x48, system.time_zone_bias as u32);
    write_u64(buffer, h + 0xf8, system.boot_time);
    write_u64(buffer, h + 0x100, system.qpc_frequency);
    write_u64(buffer, h + 0x108, logger.reference_system_time);
    write_u32(buffer, h + 0x110, logger.clock.raw());
    write_u32(buffer, h + 0x114, logger.log_buffers_lost);
    let names = h + TRACE_LOGFILE_HEADER64_SIZE;
    buffer[names..names + logger_name.len()].copy_from_slice(&logger_name);
    let names = names + logger_name.len();
    buffer[names..names + file_name.len()].copy_from_slice(&file_name);

    offsets.seal(
        buffer,
        used,
        flush_state,
        HEADER_BUFFER_FLAG,
        HEADER_BUFFER_TYPE,
    );
    Ok(())
}

impl Target {
    /// `!wmitrace.logsave`: the logger `text` names as an .etl file: a header
    /// buffer, then each of its buffers that holds events, sealed as the
    /// logger flushes them after its last record that decodes.
    pub fn etw_log_file(&self, text: &str, radix: NumberRadix) -> Result<EtwLogFile> {
        let logger = self.etw_logger(text, radix)?;
        let types = self.etw_types()?;
        let (buffers, list_stop) = self.read_etw_buffers(&types, &logger)?;
        let guest = self.guest()?;
        let kernel = guest.ntoskrnl.types();
        let offsets =
            BufferHeaderOffsets::from_pdb(&types.buffer, &*kernel.layout("_ETW_BUFFER_CONTEXT")?)?;
        let flush_state = types.buffer_state("EtwBufferStateFlush").ok_or_else(|| {
            Error::DebugInfo("_ETW_BUFFER_STATE has no EtwBufferStateFlush in the PDB".into())
        })? as u32;
        let compressed = types.buffer_state("EtwBufferStateCompressed");
        if let Some(buffer) = buffers
            .iter()
            .find(|buffer| Some(i64::from(buffer.state)) == compressed)
        {
            return Err(Error::DebugInfo(format!(
                "buffer {:#x} of logger {:#x} is compressed; an .etl of it would need \
                 the logger's compression state",
                buffer.address.0, logger.logger_id
            )));
        }

        let kuser = KuserSharedData::new(self);
        let missing =
            |what: &str| Error::DebugInfo(format!("KUSER_SHARED_DATA.{what} is unreadable"));
        let system = LogFileSystem {
            major_version: kuser
                .nt_major_version()
                .ok_or_else(|| missing("NtMajorVersion"))? as u8,
            minor_version: kuser
                .nt_minor_version()
                .ok_or_else(|| missing("NtMinorVersion"))? as u8,
            build_number: (kuser
                .nt_build_number()
                .ok_or_else(|| missing("NtBuildNumber"))?
                & 0xffff) as u32,
            processors: u32::from(crate::cpu_state::processor_count(self)?),
            timer_resolution: guest.ntoskrnl.symbol("KeMaximumIncrement")?.read()?,
            cpu_mhz: self.processor_mhz()? as u32,
            boot_time: guest.ntoskrnl.symbol("KeBootTime")?.read()?,
            qpc_frequency: kuser
                .qpc_frequency()
                .ok_or_else(|| missing("QpcFrequency"))?,
            end_time: kuser.system_time().ok_or_else(|| missing("SystemTime"))?,
            time_zone_bias: (kuser
                .time_zone_bias()
                .ok_or_else(|| missing("TimeZoneBias"))?
                / 600_000_000) as i32,
        };

        // The whole file in one allocation: the header buffer first, filled
        // in once the data buffers are counted, then each data buffer read
        // in place. read_etw_buffers bounded BufferSize, and every data_end
        // by it.
        let size = logger.buffer_size as usize;
        let memory = self.kernel_address_space();
        let with_data: Vec<&EtwBuffer> = buffers
            .iter()
            .filter(|b| b.data_end as usize > offsets.size)
            .collect();
        let total = size * (with_data.len() + 1);
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(total).map_err(|e| {
            Error::DebugInfo(format!(
                "cannot hold the {total:#x} bytes of logger {:#x}'s buffers: {e}",
                logger.logger_id
            ))
        })?;
        bytes.resize(size, 0);
        let mut issues = Vec::new();
        let mut data_buffers = 0u32;
        for buffer in with_data {
            if self.interrupted() {
                return Err(Error::DebugInfo("interrupted".into()));
            }
            let start = bytes.len();
            bytes.resize(start + size, 0);
            let slot = &mut bytes[start..];
            // The rest of the buffer is sealed with 0xff: read only the data.
            let end = buffer.data_end as usize;
            if let Err(e) = memory.read_bytes(buffer.address, &mut slot[..end]) {
                issues.push(EtwBufferIssue {
                    buffer: buffer.address,
                    offset: 0,
                    reason: format!("left out, unreadable: {e}"),
                });
                bytes.truncate(start);
                continue;
            }
            // A processor's current buffer can end in a record still being
            // written, or in stale bytes past a failed reservation: keep
            // exactly the records logdump decodes.
            let used = match decode_buffer_records(slot, offsets.size, end, &types.event_header).1 {
                Some(stop) => {
                    let used = stop.offset as usize;
                    issues.push(EtwBufferIssue {
                        buffer: buffer.address,
                        offset: stop.offset,
                        reason: format!("sealed here: {}", stop.reason),
                    });
                    used
                }
                None => end,
            };
            if used <= offsets.size {
                bytes.truncate(start);
                continue;
            }
            offsets.seal(slot, used, flush_state, DATA_BUFFER_FLAG, DATA_BUFFER_TYPE);
            data_buffers += 1;
        }
        write_logfile_header_buffer(
            &mut bytes[..size],
            &logger,
            &system,
            &offsets,
            flush_state,
            data_buffers + 1,
        )?;
        Ok(EtwLogFile {
            logger,
            buffers: data_buffers as usize,
            list_stop,
            issues,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `_EVENT_HEADER`/`_EVENT_DESCRIPTOR` offsets of the 26200 kernel PDB.
    fn layout() -> EventHeaderLayout {
        EventHeaderLayout {
            size: 0x50,
            flags: 4,
            thread_id: 8,
            process_id: 12,
            time_stamp: 16,
            provider_id: 24,
            descriptor: 40,
            activity_id: 64,
            descriptor_id: 0,
            descriptor_version: 2,
            descriptor_channel: 3,
            descriptor_level: 4,
            descriptor_opcode: 5,
            descriptor_task: 6,
            descriptor_keyword: 8,
        }
    }

    fn hex(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    #[test]
    fn decodes_wpp_messages_with_guid_timestamp_and_system_info() {
        // Two NtfsLog records read live (build 26200), after the buffer header.
        let data = hex(
            "28 00 00 90 0a 00 aa 00 38 5a 46 26 75 b7 bf 37 c9 af 18 10 e9 18 87 cd \
             f3 48 35 28 5b 4e dd 01 c0 00 00 00 8c 0b 00 00 \
             50 00 00 90 0d 00 aa 00 bb 68 90 6e 21 fb 30 34 ae c3 b8 c3 6d 4e b7 a8 \
             39 fb 36 28 5b 4e dd 01 cc 08 00 00 8c 0b 00 00 \
             90 97 a2 8b 8b be ff ff e0 2c 3f 8c 8b be ff ff \
             73 94 ce 4f 36 ba f1 11 98 b0 e6 00 ef 9c be aa 48 00 00 00 00 00 00 00",
        );
        let (records, stop) = decode_buffer_records(&data, 0, data.len(), &layout());
        assert_eq!(stop, None);
        assert_eq!(records.len(), 2);
        let first = &records[0];
        assert_eq!(first.kind, EtwHeaderKind::Message);
        let message = first.message.unwrap();
        assert_eq!((message.number, message.option_flags), (0x0a, 0xaa));
        assert_eq!(
            format_guid(&message.guid.unwrap()),
            "{26465a38-b775-37bf-c9af-1810e91887cd}"
        );
        assert_eq!(first.timestamp, Some(0x01dd_4e5b_2835_48f3));
        assert_eq!(
            (first.thread_id, first.process_id),
            (Some(0xc0), Some(0xb8c))
        );
        assert!(first.payload.is_empty());
        let second = &records[1];
        assert_eq!(second.offset, 0x28);
        assert_eq!(second.message.unwrap().number, 0x0d);
        assert_eq!(second.payload.len(), 0x50 - 0x28);
    }

    #[test]
    fn formats_wpp_messages_whose_tmf_is_known() {
        // The NtfsLog records above: the second's payload is two pointers,
        // a GUID and a 64-bit count. Its TMF is written here, as ntfs.pdb
        // has none.
        let data = hex(
            "28 00 00 90 0a 00 aa 00 38 5a 46 26 75 b7 bf 37 c9 af 18 10 e9 18 87 cd \
             f3 48 35 28 5b 4e dd 01 c0 00 00 00 8c 0b 00 00 \
             50 00 00 90 0d 00 aa 00 bb 68 90 6e 21 fb 30 34 ae c3 b8 c3 6d 4e b7 a8 \
             39 fb 36 28 5b 4e dd 01 cc 08 00 00 8c 0b 00 00 \
             90 97 a2 8b 8b be ff ff e0 2c 3f 8c 8b be ff ff \
             73 94 ce 4f 36 ba f1 11 98 b0 e6 00 ef 9c be aa 48 00 00 00 00 00 00 00",
        );
        let tmf = Arc::new(
            TmfMessage::parse(
                &[
                    "TMF:",
                    "6e9068bb-fb21-3430-aec3-b8c36d4eb7a8 NtfsLog // SRC=ntfs.c MJ= MN=",
                    "#typev ntfs_c10 13 \"%0Scb %10!p! Fcb %11!p! id %12!s! size %13!I64u!\" //   LEVEL=TRACE_LEVEL_INFORMATION FLAGS=NTFS_ALL FUNC=NtfsCommonWrite",
                    "{",
                    "Scb, ItemPtr -- 10",
                    "Scb->Fcb, ItemPtr -- 11",
                    "&Id, ItemGuid -- 12",
                    "Size, ItemULongLong -- 13",
                    "}",
                ],
                None,
            )
            .unwrap(),
        );
        let lookup =
            |guid: &[u8; 16], number: u16| ((*guid, number) == tmf.key()).then(|| tmf.clone());
        let (records, _) = decode_buffer_records(&data, 0, data.len(), &layout());
        let events: Vec<EtwEvent> = records
            .into_iter()
            .map(|record| EtwEvent {
                buffer: VirtAddr(0),
                processor: 0,
                system_time: None,
                message_format: format_message_record(&record, lookup, 8),
                record,
            })
            .collect();

        assert_eq!(events[0].message_format, None);
        let format = events[1].message_format.as_ref().unwrap();
        assert_eq!(
            (format.provider.as_str(), format.function.as_deref()),
            ("NtfsLog", Some("NtfsCommonWrite"))
        );
        assert_eq!(
            format.text.as_deref(),
            Ok("Scb FFFFBE8B8BA29790 Fcb FFFFBE8B8C3F2CE0 \
                id {4fce9473-ba36-11f1-98b0-e600ef9cbeaa} size 72")
        );
        // The raw payload stays.
        assert_eq!(events[1].record.payload.len(), 0x28);
        // Only the message without a TMF counts as raw.
        let note = message_format_note(&events).unwrap();
        assert!(note.starts_with("1 WPP message "));
        assert_eq!(message_format_note(&events[1..]), None);
    }

    #[test]
    fn decodes_event_header_records_and_steps_over_unaligned_sizes() {
        // Microsoft-Windows-Kernel-Process ProcessStop, 0xaf bytes, read live;
        // the next record starts at the 8-byte aligned 0xb0.
        let mut data = hex("af 00 13 c0 00 00 00 00 c8 0a 00 00 8c 13 00 00 \
             6c a8 06 79 1e 00 00 00 d6 2c fb 22 7b 0e 2b 42 \
             a0 c7 2f ad 1f d0 e7 16 02 00 02 10 04 02 02 00 \
             10 00 00 00 00 00 00 80 04 00 00 00 01 00 00 00 \
             00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        data.resize(0xb0, 0xee);
        data.extend(hex(
            "10 00 11 c0 18 00 45 0f 2e d0 41 2b e6 17 00 00 01 02 03 04 05 06 07 08",
        ));
        let (records, stop) = decode_buffer_records(&data, 0, data.len(), &layout());
        assert_eq!(stop, None);
        let event = &records[0];
        assert_eq!(event.kind, EtwHeaderKind::EventHeader);
        assert_eq!(event.size, 0xaf);
        assert_eq!(
            format_guid(&event.guid.unwrap()),
            "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}"
        );
        assert_eq!(
            (event.thread_id, event.process_id),
            (Some(0xac8), Some(0x138c))
        );
        assert_eq!(event.timestamp, Some(0x1e_7906_a86c));
        let descriptor = event.descriptor.unwrap();
        assert_eq!(
            (
                descriptor.id,
                descriptor.opcode,
                descriptor.task,
                descriptor.keyword
            ),
            (2, 2, 2, 0x8000_0000_0000_0010)
        );
        assert_eq!(event.payload.len(), 0xaf - 0x50);
        let perfinfo = &records[1];
        assert_eq!(perfinfo.offset, 0xb0);
        assert_eq!(perfinfo.kind, EtwHeaderKind::PerfInfo);
        assert_eq!(perfinfo.hook_id, Some(0x0f45));
        assert_eq!(perfinfo.timestamp, Some(0x17e6_2b41_d02e));
        assert_eq!(perfinfo.payload, (1..=8).collect::<Vec<u8>>());
    }

    #[test]
    fn walks_event_header_extended_items_by_linkage() {
        // A DiagLog event read live: SID (S-1-5-18), TS_ID and PROV_TRAITS
        // items, each sized up to 8 bytes (the TS_ID's padding is ff), and
        // no payload.
        let data = hex(
            "98 00 13 c0 01 00 00 00 9c 0d 00 00 8c 03 00 00 34 f9 df 37 1c 00 00 00 \
             39 11 47 3f b7 ac 01 4a b7 a7 ff 5d a4 ba 2d 43 53 04 00 10 05 01 0b 00 \
             01 00 08 00 00 00 00 80 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 \
             00 00 00 00 00 00 00 00 18 00 02 00 01 00 0c 00 01 01 00 00 00 00 00 05 \
             12 00 00 00 00 00 00 00 10 00 03 00 01 00 04 00 00 00 00 00 ff ff ff ff \
             20 00 0c 00 00 00 16 00 16 00 00 13 00 01 1a 73 50 4f cf 89 82 47 b3 e0 \
             dc e8 c9 04 76 ba 00 00",
        );
        let (records, stop) = decode_buffer_records(&data, 0, data.len(), &layout());
        assert_eq!(stop, None);
        let event = &records[0];
        let items: Vec<(u16, usize)> = event
            .extended
            .iter()
            .map(|item| (item.ext_type, item.data.len()))
            .collect();
        assert_eq!(items, vec![(2, 0xc), (3, 4), (12, 0x16)]);
        assert_eq!(
            event.extended[0].data,
            hex("01 01 00 00 00 00 00 05 12 00 00 00")
        );
        assert!(event.payload.is_empty());
        assert_eq!(
            (event.process_id, event.thread_id),
            (Some(0x38c), Some(0xd9c))
        );
    }

    #[test]
    fn stops_at_an_unrecognized_record_instead_of_resynchronizing() {
        let mut data = hex("10 00 11 c0 10 00 45 0f 2e d0 41 2b e6 17 00 00");
        data.extend(hex("ff ff ff 7f 00 00 00 00"));
        let (records, stop) = decode_buffer_records(&data, 0, data.len(), &layout());
        assert_eq!(records.len(), 1);
        assert_eq!(stop.unwrap().offset, 0x10);

        let oversized = hex("00 01 13 c0 00 00 00 00");
        let (records, stop) = decode_buffer_records(&oversized, 0, oversized.len(), &layout());
        assert!(records.is_empty());
        assert_eq!(stop.unwrap().offset, 0);
    }

    #[test]
    fn decodes_classic_instance_and_compact_headers() {
        let mut classic = hex("38 00 0a c0 02 04 01 00 11 00 00 00 22 00 00 00 \
             08 07 06 05 04 03 02 01");
        classic.extend(1..=16u8);
        classic.extend([0; 8]);
        classic.extend(hex("aa bb cc dd ee ff 00 11"));
        let mut instance = classic[..0x30].to_vec();
        instance[..4].copy_from_slice(&hex("48 00 0b c0"));
        instance.resize(0x48, 0);
        let compact = hex("02 00 03 c0 18 00 10 05 33 00 00 00 44 00 00 00 \
             ff ee dd cc bb aa 99 88");
        let data = [classic, instance, compact].concat();
        let (records, stop) = decode_buffer_records(&data, 0, data.len(), &layout());
        assert_eq!(stop, None);
        let kinds: Vec<(EtwHeaderKind, u32)> = records.iter().map(|r| (r.kind, r.offset)).collect();
        assert_eq!(
            kinds,
            vec![
                (EtwHeaderKind::FullHeader, 0),
                (EtwHeaderKind::Instance, 0x38),
                (EtwHeaderKind::Compact, 0x80)
            ]
        );
        let classic = &records[0];
        assert_eq!(classic.class, Some((2, 4, 1)));
        assert_eq!(
            (classic.thread_id, classic.process_id),
            (Some(0x11), Some(0x22))
        );
        assert_eq!(classic.timestamp, Some(0x0102_0304_0506_0708));
        assert_eq!(classic.guid, Some(std::array::from_fn(|i| i as u8 + 1)));
        assert_eq!(classic.payload, hex("aa bb cc dd ee ff 00 11"));
        assert!(records[1].payload.is_empty());
        let compact = &records[2];
        assert_eq!(compact.hook_id, Some(0x0510));
        assert_eq!(
            (compact.thread_id, compact.process_id),
            (Some(0x33), Some(0x44))
        );
        assert_eq!(compact.timestamp, Some(0x8899_aabb_ccdd_eeff));
    }

    #[test]
    fn a_wpp_message_without_timestamp_option_has_no_timestamp() {
        // TRACE_MESSAGE_SEQUENCE | TRACE_MESSAGE_COMPONENTID.
        let data = hex("14 00 00 90 07 00 05 00 01 00 00 00 33 00 00 00 de ad be ef");
        let (records, stop) = decode_buffer_records(&data, 0, data.len(), &layout());
        assert_eq!(stop, None);
        let record = &records[0];
        assert_eq!(record.timestamp, None);
        assert_eq!(record.guid, None);
        let message = record.message.unwrap();
        assert_eq!(
            (message.number, message.sequence, message.component_id),
            (7, Some(1), Some(0x33))
        );
        assert_eq!(record.payload, hex("de ad be ef"));
    }

    #[test]
    fn stops_at_an_extended_item_that_runs_past_its_event() {
        let mut data = hex("58 00 13 c0 01 00");
        data.resize(0x50, 0);
        // A 0x10-byte item (8 data bytes) in an event with only 8 bytes left.
        data.extend(hex("10 00 01 00 00 00 08 00"));
        let (records, stop) = decode_buffer_records(&data, 0, data.len(), &layout());
        assert!(records.is_empty());
        let stop = stop.unwrap();
        assert_eq!(stop.offset, 0);
        assert!(stop.reason.contains("extended data item at +0x50"));
    }

    #[test]
    fn parses_logdump_arguments() {
        let parse = |args: &[&str]| LogDumpArguments::parse(args.iter().copied());
        let arguments = |logger: &str, most_recent| {
            Some(LogDumpArguments {
                logger: logger.to_string(),
                most_recent,
            })
        };
        assert_eq!(parse(&[]).unwrap(), None);
        assert_eq!(parse(&["-t", "5"]).unwrap(), None);
        assert_eq!(parse(&["0x24"]).unwrap(), arguments("0x24", None));
        assert_eq!(
            parse(&["-t", "0x10", "NT Kernel Logger"]).unwrap(),
            arguments("NT Kernel Logger", Some(0x10))
        );
        assert_eq!(
            parse(&["NtfsLog", "-T", "10"]).unwrap(),
            arguments("NtfsLog", Some(10))
        );
        assert!(parse(&["NtfsLog", "-t"]).is_err());
        assert!(parse(&["-t", "ten", "NtfsLog"]).is_err());
        assert!(parse(&["NT", "Kernel"]).is_err());
    }

    /// `_WMI_BUFFER_HEADER` offsets of the 26200 kernel PDB.
    fn buffer_offsets() -> BufferHeaderOffsets {
        BufferHeaderOffsets {
            size: 0x48,
            buffer_size: 0,
            saved_offset: 4,
            current_offset: 8,
            logger_id: 0x2a,
            state: 0x2c,
            offset: 0x30,
            buffer_flag: 0x34,
            buffer_type: 0x36,
        }
    }

    fn logger(buffer_size: u32) -> EtwLogger {
        EtwLogger {
            address: VirtAddr(0xffff_8000_0000_1000),
            logger_id: 0x24,
            name: Some("ntoseyetest".into()),
            log_file_name: Some(r"C:\Windows\Temp\ntoseyetest.etl".into()),
            logger_mode: 0x0000_0001,
            flag_names: Vec::new(),
            flags: 0,
            buffer_size,
            maximum_event_size: 0,
            minimum_buffers: 0,
            maximum_buffers: 0,
            number_of_buffers: 0,
            buffers_available: 0,
            peak_buffers: 0,
            buffers_written: 0,
            events_lost: 0,
            log_buffers_lost: 0,
            real_time_buffers_delivered: 0,
            real_time_buffers_lost: 0,
            maximum_file_size: 0,
            flush_timer: 0,
            flush_threshold: 0,
            clock: EtwClock::PerformanceCounter,
            start_time: 0,
            reference_system_time: 0x01dd_4e61_8a67_b359,
            reference_clock: 0x1e_7905_eb4d,
            logger_thread: VirtAddr(0),
            logger_status: 0,
            consumers: 0,
            instance_guid: [0; 16],
            collection_on: true,
        }
    }

    const SYSTEM: LogFileSystem = LogFileSystem {
        major_version: 10,
        minor_version: 0,
        build_number: 26200,
        processors: 4,
        timer_resolution: 156_250,
        cpu_mhz: 1997,
        boot_time: 0x01dd_4e43_1189_c5c0,
        qpc_frequency: 10_000_000,
        end_time: 0x01dd_4e70_0000_0000,
        time_zone_bias: 0,
    };

    #[test]
    fn logfile_header_buffer_holds_one_header_event_and_is_sealed() {
        let logger = logger(0x1_0000);
        let offsets = buffer_offsets();
        let mut buffer = vec![0u8; 0x1_0000];
        write_logfile_header_buffer(&mut buffer, &logger, &SYSTEM, &offsets, 2, 7).unwrap();

        let names = utf16z("ntoseyetest").len() + utf16z(r"C:\Windows\Temp\ntoseyetest.etl").len();
        let event_size = 0x20 + TRACE_LOGFILE_HEADER64_SIZE + names;
        let used = align8(0x48 + event_size);
        let field = |at| crate::bytes::read_u32(&buffer, at) as usize;
        assert_eq!(field(offsets.buffer_size), 0x1_0000);
        assert_eq!(crate::bytes::read_u16(&buffer, offsets.logger_id), 0x24);
        assert_eq!(
            (
                field(offsets.saved_offset),
                field(offsets.current_offset),
                field(offsets.offset)
            ),
            (used, used, used)
        );
        assert!(buffer[used..].iter().all(|&b| b == 0xff));

        let (records, stop) = decode_buffer_records(&buffer, 0x48, used, &layout());
        assert_eq!(stop, None);
        assert_eq!(records.len(), 1);
        let header = &records[0];
        assert_eq!(header.kind, EtwHeaderKind::System);
        assert_eq!(header.hook_id, Some(WMI_LOG_TYPE_HEADER));
        assert_eq!(usize::from(header.size), event_size);
        assert_eq!(header.timestamp, Some(logger.reference_clock));
        // TRACE_LOGFILE_HEADER64.BuffersWritten.
        assert_eq!(crate::bytes::read_u32(&header.payload, 0x24), 7);
    }

    #[test]
    fn logfile_header_buffer_refuses_a_buffer_too_small_for_it() {
        let offsets = buffer_offsets();
        for size in [0, 0x20, 0x48, 0x100] {
            let mut buffer = vec![0u8; size];
            let result = write_logfile_header_buffer(
                &mut buffer,
                &logger(size as u32),
                &SYSTEM,
                &offsets,
                2,
                1,
            );
            assert!(result.is_err(), "size {size:#x}");
        }
    }

    #[test]
    fn converts_perf_counter_timestamps_from_the_logger_reference() {
        let time = TimeBase {
            clock: EtwClock::PerformanceCounter,
            reference_system_time: 0x01dd_4e00_0000_0000,
            reference_clock: 1_000_000,
            qpc_frequency: Some(10_000_000),
            cpu_mhz: None,
        };
        assert_eq!(time.system_time(1_000_000), Some(0x01dd_4e00_0000_0000));
        assert_eq!(
            time.system_time(11_000_000),
            Some(0x01dd_4e00_0000_0000 + 10_000_000)
        );
        assert_eq!(time.system_time(0), Some(0x01dd_4e00_0000_0000 - 1_000_000));
        let unknown = TimeBase {
            qpc_frequency: None,
            ..time
        };
        assert_eq!(unknown.system_time(5), None);
        let cycles = TimeBase {
            clock: EtwClock::CpuCycle,
            cpu_mhz: Some(2_000),
            ..time
        };
        // 2e9 cycles at 2000 MHz: one second.
        assert_eq!(
            cycles.system_time(1_000_000 + 2_000_000_000),
            Some(0x01dd_4e00_0000_0000 + 10_000_000)
        );
    }
}
