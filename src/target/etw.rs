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

use std::collections::HashSet;
use std::sync::Arc;

use crate::backend::MemoryOps;
use crate::bugchecks::looks_like_kernel_pointer;
use crate::error::{Error, Result};
use crate::expr::{Expr, NumberRadix};
use crate::kuser_shared::KuserSharedData;
use crate::layout::{ParsedType, TypeInfo};
use crate::target::Target;
use crate::triage_report::time::filetime_to_iso;
use crate::types::VirtAddr;

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
    pub name: String,
    pub log_file_name: String,
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
    /// Raw timestamp in the logger's clock.
    pub timestamp: u64,
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

/// An event with the buffer it came from and its time.
#[derive(Debug, Clone)]
pub struct EtwEvent {
    pub buffer: VirtAddr,
    pub processor: u16,
    /// FILETIME, when the logger's clock converts to one.
    pub system_time: Option<u64>,
    pub record: EtwRecord,
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
    /// Buffers skipped whole (compressed) and walks that stopped early.
    pub issues: Vec<EtwBufferIssue>,
    /// Events found before `-t` kept the most recent.
    pub total_events: usize,
    pub events: Vec<EtwEvent>,
    /// QPC frequency used for PerfCounter timestamps.
    pub qpc_frequency: Option<u64>,
    /// Processor speed used for CpuCycle timestamps.
    pub cpu_mhz: Option<u64>,
    /// Why WPP messages are shown raw.
    pub message_format_note: Option<String>,
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

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn guid_at(bytes: &[u8], at: usize) -> Option<[u8; 16]> {
    bytes.get(at..at + 16)?.try_into().ok()
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
    let marker = u32_at(bytes, 0).ok_or("truncated marker")?;
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
        EtwHeaderKind::System => (u16_at(bytes, 4), 0x20),
        EtwHeaderKind::Compact => (u16_at(bytes, 4), 0x18),
        EtwHeaderKind::PerfInfo => (u16_at(bytes, 4), 0x10),
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
        timestamp: 0,
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
            record.hook_id = u16_at(bytes, 6);
            record.thread_id = u32_at(bytes, 8);
            record.process_id = u32_at(bytes, 12);
            record.timestamp = u64_at(bytes, 16).ok_or_else(truncated)?;
            header_len
        }
        EtwHeaderKind::PerfInfo => {
            record.hook_id = u16_at(bytes, 6);
            record.timestamp = u64_at(bytes, 8).ok_or_else(truncated)?;
            header_len
        }
        EtwHeaderKind::FullHeader | EtwHeaderKind::Instance => {
            record.class = Some((bytes[4], bytes[5], u16_at(bytes, 6).ok_or_else(truncated)?));
            record.thread_id = u32_at(bytes, 8);
            record.process_id = u32_at(bytes, 12);
            record.timestamp = u64_at(bytes, 16).ok_or_else(truncated)?;
            record.guid = guid_at(bytes, 24);
            header_len
        }
        EtwHeaderKind::EventHeader => {
            let flags = u16_at(bytes, layout.flags).ok_or_else(truncated)?;
            record.event_flags = Some(flags);
            record.thread_id = u32_at(bytes, layout.thread_id);
            record.process_id = u32_at(bytes, layout.process_id);
            record.timestamp = u64_at(bytes, layout.time_stamp).ok_or_else(truncated)?;
            record.guid = guid_at(bytes, layout.provider_id);
            record.activity_id = guid_at(bytes, layout.activity_id);
            let d = layout.descriptor;
            record.descriptor = Some(EtwEventDescriptor {
                id: u16_at(bytes, d + layout.descriptor_id).ok_or_else(truncated)?,
                version: bytes[d + layout.descriptor_version],
                channel: bytes[d + layout.descriptor_channel],
                level: bytes[d + layout.descriptor_level],
                opcode: bytes[d + layout.descriptor_opcode],
                task: u16_at(bytes, d + layout.descriptor_task).ok_or_else(truncated)?,
                keyword: u64_at(bytes, d + layout.descriptor_keyword).ok_or_else(truncated)?,
            });
            let mut at = header_len;
            if flags & EVENT_HEADER_FLAG_EXTENDED_INFO != 0 {
                // Each item: USHORT size (8 + DataSize, rounded up to 8),
                // USHORT ExtType, USHORT Linkage (bit 0: another item
                // follows), USHORT DataSize, then the data.
                loop {
                    let item = |field| u16_at(bytes, at + field);
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
            let number = u16_at(bytes, 4).ok_or_else(truncated)?;
            let option_flags = u16_at(bytes, 6).ok_or_else(truncated)?;
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
                u32_at(bytes, take(4)?)
            } else {
                None
            };
            let (component_id, guid) = if option_flags & TRACE_MESSAGE_COMPONENTID != 0 {
                (u32_at(bytes, take(4)?), None)
            } else if option_flags & TRACE_MESSAGE_GUID != 0 {
                (None, guid_at(bytes, take(16)?))
            } else {
                (None, None)
            };
            if option_flags & TRACE_MESSAGE_TIMESTAMP != 0 {
                record.timestamp = u64_at(bytes, take(8)?).unwrap_or(0);
            }
            if option_flags & TRACE_MESSAGE_SYSTEMINFO != 0 {
                let info = take(8)?;
                record.thread_id = u32_at(bytes, info);
                record.process_id = u32_at(bytes, info + 4);
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
    if let Some(logger) = table
        .loggers
        .iter()
        .find(|logger| logger.name.eq_ignore_ascii_case(text))
    {
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
}

impl Target {
    fn etw_types(&self) -> Result<EtwTypes> {
        let types = self.guest()?.ntoskrnl.types();
        Ok(EtwTypes {
            logger: types.layout("_WMI_LOGGER_CONTEXT")?,
            buffer: types.layout("_WMI_BUFFER_HEADER")?,
            event_header: EventHeaderLayout::from_pdb(
                &*types.layout("_EVENT_HEADER")?,
                &*types.layout("_EVENT_DESCRIPTOR")?,
            )?,
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
        let flags_field = layout.field("Flags")?;
        let flags = ctx.read_field::<u32>("Flags")?;
        let mut flag_names: Vec<(u8, String)> = layout
            .fields
            .iter()
            .filter_map(|(name, field)| match field.type_data {
                ParsedType::Bitfield { pos, len: 1, .. }
                    if field.offset == flags_field.offset && flags >> pos & 1 != 0 =>
                {
                    Some((pos, name.clone()))
                }
                _ => None,
            })
            .collect();
        flag_names.sort();
        let reference = ctx.embedded("ReferenceTime")?;
        let instance_guid: [u8; 16] = ctx
            .read_field_bytes("InstanceGuid", 16)?
            .try_into()
            .map_err(|_| Error::DebugInfo("InstanceGuid is not 16 bytes".into()))?;
        Ok(EtwLogger {
            address,
            logger_id: ctx.read_field("LoggerId")?,
            name: ctx.unicode_string("LoggerName")?,
            log_file_name: ctx.unicode_string("LogFileName")?,
            logger_mode: ctx.read_field("LoggerMode")?,
            flag_names: flag_names.into_iter().map(|(_, name)| name).collect(),
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
        let buffers = self.read_etw_buffers(&types, &logger)?;
        Ok(EtwLoggerBuffers { logger, buffers })
    }

    fn read_etw_buffers(&self, types: &EtwTypes, logger: &EtwLogger) -> Result<Vec<EtwBuffer>> {
        let memory = self.kernel_address_space();
        let head = logger.address + types.logger.field_offset("GlobalList")?;
        let global_entry = types.buffer.field_offset("GlobalEntry")?;
        let states = self
            .guest()?
            .ntoskrnl
            .guid
            .and_then(|guid| self.symbols.enum_variants(guid, "_ETW_BUFFER_STATE"))
            .unwrap_or_default();
        let mut buffers = Vec::new();
        let mut seen = HashSet::new();
        let mut link: VirtAddr = memory.read(head)?;
        while link != head {
            if link.is_zero() || !seen.insert(link.0) {
                return Err(Error::DebugInfo(format!(
                    "logger {:#x}'s GlobalList at {:#x} breaks at {:#x}",
                    logger.logger_id, head.0, link.0
                )));
            }
            if buffers.len() >= MAX_LOGGER_BUFFERS {
                return Err(Error::DebugInfo(format!(
                    "logger {:#x}'s GlobalList has more than {MAX_LOGGER_BUFFERS} entries",
                    logger.logger_id
                )));
            }
            // Windows 10 links a small node per buffer ({LIST_ENTRY, buffer
            // pointer}, pool tag Etwn); earlier kernels linked the buffers'
            // own GlobalEntry. Take whichever is one of this logger's buffers.
            let node_buffer: VirtAddr = memory.read(link + 0x10u64)?;
            let buffer = [node_buffer, VirtAddr(link.0.wrapping_sub(global_entry))]
                .into_iter()
                .find_map(|candidate| self.read_etw_buffer(types, logger, &states, candidate).ok())
                .ok_or_else(|| {
                    Error::DebugInfo(format!(
                        "logger {:#x}'s GlobalList entry {:#x} leads to no _WMI_BUFFER_HEADER \
                         of this logger (BufferSize {:#x}, LoggerId {:#x})",
                        logger.logger_id, link.0, logger.buffer_size, logger.logger_id
                    ))
                })?;
            buffers.push(buffer);
            link = memory.read(link)?;
        }
        Ok(buffers)
    }

    fn read_etw_buffer(
        &self,
        types: &EtwTypes,
        logger: &EtwLogger,
        states: &[(String, i64)],
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
            state_name: states
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
        let buffers = self.read_etw_buffers(&types, &logger)?;
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
        let states = self
            .guest()?
            .ntoskrnl
            .guid
            .and_then(|guid| self.symbols.enum_variants(guid, "_ETW_BUFFER_STATE"))
            .unwrap_or_default();
        let compressed = states
            .iter()
            .find(|(name, _)| name == "EtwBufferStateCompressed")
            .map(|(_, value)| *value);
        let memory = self.kernel_address_space();
        let mut events = Vec::new();
        let mut issues = Vec::new();
        let mut walked = 0;
        let mut data = vec![0u8; logger.buffer_size.min(MAX_BUFFER_SIZE) as usize];
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
            events.extend(records.into_iter().map(|record| EtwEvent {
                buffer: buffer.address,
                processor: buffer.processor,
                system_time: time.system_time(record.timestamp),
                record,
            }));
        }
        events.sort_by_key(|event| (event.record.timestamp, event.buffer.0, event.record.offset));
        let total_events = events.len();
        if let Some(count) = most_recent {
            events.drain(..total_events.saturating_sub(count));
        }
        let message_format_note = events
            .iter()
            .any(|event| event.record.kind == EtwHeaderKind::Message)
            .then(|| {
                "WPP messages are shown raw: their trace message format (TMF) is kept only \
                 in the provider's private PDB, and no loaded symbol file carries it"
                    .to_string()
            });
        Ok(EtwEventDump {
            logger,
            buffers_walked: walked,
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
        let kprcb = self.inspect_prcb(0)?.kprcb;
        let mhz = self
            .guest()?
            .ntoskrnl
            .types()
            .struct_at("_KPRCB", kprcb)?
            .read_uint("MHz")?;
        Ok(mhz)
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
        assert_eq!(first.timestamp, 0x01dd_4e5b_2835_48f3);
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
        assert_eq!(event.timestamp, 0x1e_7906_a86c);
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
        assert_eq!(perfinfo.timestamp, 0x17e6_2b41_d02e);
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
