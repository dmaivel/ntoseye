//! ETW [`View`] builders: trace sessions, their buffers, and their events.

use ntoseye_macros::record;

use crate::target::etw::dump::{EtwDumpData, EtwDumpLogger};
use crate::target::etw::{
    self, EtwEventDump as EtwEventDumpDetail, EtwLoggerBuffers as EtwLoggerBuffersDetail,
    EtwLoggerTable as EtwLoggerTableDetail, GuidStyle, event_trace_group_name, extended_type_name,
    format_filetime_precise, format_guid, logger_mode_names,
};
use crate::types::VirtAddr;

/// An active ETW trace session, decoded from its `_WMI_LOGGER_CONTEXT`.
#[record]
pub struct EtwLogger {
    /// The `_WMI_LOGGER_CONTEXT`.
    pub address: VirtAddr,
    pub logger_id: u32,
    /// `LoggerName`. `None` if ntoseye cannot read its buffer, which can
    /// happen when the pool is freed or paged out while a session stops.
    pub name: Option<String>,
    /// `LogFileName`. `None` if ntoseye cannot read its buffer.
    pub log_file_name: Option<String>,
    #[record(hex)]
    pub logger_mode: u32,
    /// The `EVENT_TRACE_*_MODE` bits that are set in `logger_mode`.
    pub logger_mode_names: Vec<&'static str>,
    #[record(hex)]
    pub flags: u32,
    /// The `Flags` bitfields that are set, from the PDB.
    pub flag_names: Vec<String>,
    pub collection_on: bool,
    /// Bytes per buffer.
    pub buffer_size: u32,
    pub maximum_event_size: u32,
    pub minimum_buffers: u32,
    pub maximum_buffers: u32,
    pub number_of_buffers: i32,
    pub buffers_available: i32,
    /// The buffers taken from the free pool (`number_of_buffers -
    /// buffers_available`). Each of these buffers is current on a processor,
    /// full, or in a flush.
    pub buffers_in_use: i64,
    pub peak_buffers: i32,
    pub buffers_written: u32,
    pub events_lost: u32,
    pub log_buffers_lost: u32,
    pub real_time_buffers_delivered: u32,
    pub real_time_buffers_lost: u32,
    pub consumers: u32,
    /// `ClockType` (`EVENT_TRACE_CLOCK_*`).
    pub clock_type: u32,
    /// The name of what the event timestamps count.
    pub clock: &'static str,
    /// `StartTime`, a FILETIME.
    pub start_time: u64,
    /// `start_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`). `None` if it is
    /// out of range.
    pub start_time_utc: Option<String>,
    pub flush_timer: u32,
    pub flush_threshold: u32,
    pub maximum_file_size: u32,
    pub logger_thread: VirtAddr,
    pub logger_status: i32,
    pub instance_guid: String,
}

/// All active ETW loggers of the host silo (`!wmitrace.strdump`).
#[record]
pub struct EtwLoggerTable {
    pub silo_state: VirtAddr,
    /// `EtwpLoggerContext`: the array of `max_loggers` context pointers.
    pub context_array: VirtAddr,
    pub max_loggers: u32,
    pub loggers: Vec<EtwLogger>,
}

/// A trace buffer of a logger (`_WMI_BUFFER_HEADER`).
#[record]
pub struct EtwBuffer {
    pub address: VirtAddr,
    pub state: u32,
    pub state_name: String,
    pub processor: u16,
    pub sequence_number: i64,
    /// The raw timestamp in the clock of the logger.
    pub timestamp: u64,
    pub saved_offset: u32,
    pub current_offset: u32,
    /// The number of bytes in the buffer that hold the header and complete
    /// events.
    pub data_end: u32,
    pub reference_count: i32,
}

/// A logger and the buffers on its `GlobalList`
/// (`!wmitrace.strdump <logger>`).
#[record]
pub struct EtwLoggerBuffers {
    pub logger: EtwLogger,
    pub buffers: Vec<EtwBuffer>,
    /// Why the walk of the `GlobalList` stopped before it came back to the
    /// list head. `None` if the walk completed.
    pub list_stop: Option<String>,
}

/// The `EVENT_DESCRIPTOR` of an `EVENT_HEADER` event.
#[record]
pub struct EtwEventDescriptor {
    pub id: u16,
    pub version: u8,
    pub channel: u8,
    pub level: u8,
    pub opcode: u8,
    pub task: u16,
    #[record(hex)]
    pub keyword: u64,
}

/// The fields that follow a `MESSAGE_TRACE_HEADER`, as the
/// `TRACE_MESSAGE_*` option flags of the header select them. A field is
/// `None` if the flags do not select it, and the TMF fields are `None` if
/// no loaded PDB declares the trace message format (TMF) of the message.
#[record]
pub struct EtwEventMessage {
    /// The message number.
    pub number: u16,
    #[record(hex)]
    pub option_flags: u16,
    pub sequence: Option<u32>,
    pub guid: Option<String>,
    pub component_id: Option<u32>,
    /// The provider (component) name from the TMF.
    pub provider: Option<String>,
    /// The function that traced the message.
    pub function: Option<String>,
    /// The trace level from the TMF (`TRACE_LEVEL_ERROR`, or a number).
    pub level: Option<String>,
    /// The trace flag name from the TMF.
    pub flags: Option<String>,
    /// The message text, rendered from its TMF and the payload.
    pub text: Option<String>,
    /// Why the payload does not fit the argument types of the TMF.
    pub format_error: Option<String>,
}

/// `Class.Type`/`Level`/`Version` of a classic event.
#[record]
pub struct EtwEventClass {
    pub r#type: u8,
    pub level: u8,
    pub version: u16,
}

/// An `EVENT_HEADER` extended data item.
#[record]
pub struct EtwExtendedData {
    /// `EVENT_HEADER_EXT_TYPE_*`.
    pub r#type: u16,
    /// The name of the type, if it is known.
    pub type_name: Option<&'static str>,
    /// The bytes of the item, as hex.
    pub data: String,
}

/// An event record that ntoseye decoded from a trace buffer. A field is
/// `None` if the header kind of the event does not have it.
#[record]
pub struct EtwEvent {
    /// The buffer that the event came from.
    pub buffer: VirtAddr,
    /// The offset of the record in its buffer.
    pub offset: u32,
    pub processor: u16,
    /// The trace header at the start of the record (`EVENT_HEADER`, ...).
    pub header: &'static str,
    pub header_type: u8,
    /// The record size, with the header included (unaligned).
    pub size: u16,
    /// The raw timestamp in the clock of the logger. A WPP message without
    /// `TRACE_MESSAGE_TIMESTAMP` has no timestamp.
    pub timestamp: Option<u64>,
    /// The FILETIME, if the clock of the logger converts to one.
    pub system_time: Option<u64>,
    /// `system_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`).
    pub system_time_utc: Option<String>,
    pub process_id: Option<u32>,
    pub thread_id: Option<u32>,
    /// The provider GUID (`EVENT_HEADER`), event class GUID
    /// (`EVENT_TRACE_HEADER`), or message GUID (`MESSAGE_TRACE_HEADER`).
    pub guid: Option<String>,
    pub descriptor: Option<EtwEventDescriptor>,
    /// `EVENT_HEADER.Flags`.
    #[record(hex)]
    pub event_flags: Option<u16>,
    pub activity_id: Option<String>,
    /// The kernel hook id (group << 8 | type) of system and perfinfo events.
    #[record(hex)]
    pub hook_id: Option<u16>,
    /// The `EVENT_TRACE_GROUP_*` name of the hook id, if it is known.
    pub group: Option<&'static str>,
    /// The class of a classic event. The JSON key is `class`.
    #[record(rename = "class")]
    pub event_class: Option<EtwEventClass>,
    pub message: Option<EtwEventMessage>,
    pub extended: Vec<EtwExtendedData>,
    /// The user data of the event, as hex.
    pub payload: String,
}

/// A buffer in which ntoseye could not decode all events.
#[record]
pub struct EtwEventIssue {
    pub buffer: VirtAddr,
    /// The position in the buffer where the walk stopped.
    pub offset: u32,
    pub reason: String,
}

/// The in-memory events of a logger, oldest first (`!wmitrace.logdump`).
#[record]
pub struct EtwEventDump {
    pub logger: EtwLogger,
    pub buffers_walked: usize,
    /// Why the walk of the `GlobalList` stopped before it came back to the
    /// list head. `None` if the walk completed.
    pub list_stop: Option<String>,
    /// The number of events found before a count kept the most recent.
    pub total_events: usize,
    /// QPC frequency used for PerfCounter timestamps.
    pub qpc_frequency: Option<u64>,
    /// Processor speed used for CpuCycle timestamps.
    pub cpu_mhz: Option<u64>,
    /// The buffers that ntoseye skipped fully (compressed), and the walks that
    /// stopped early.
    pub issues: Vec<EtwEventIssue>,
    /// Why some WPP messages have no `text`. `None` if all messages have
    /// `text`.
    pub message_format_note: Option<String>,
    pub events: Vec<EtwEvent>,
}

/// An ETW trace session that Windows saved in a crash dump, as the
/// session's header in the dump records it.
#[record]
pub struct EtwCrashSession {
    pub logger_id: u32,
    pub name: String,
    #[record(hex)]
    pub logger_mode: u32,
    /// The `EVENT_TRACE_*_MODE` bits that are set in `logger_mode`.
    pub logger_mode_names: Vec<&'static str>,
    /// Bytes per buffer.
    pub buffer_size: u32,
    /// `ClockType` (`EVENT_TRACE_CLOCK_*`).
    pub clock_type: u32,
    /// The name of what the event timestamps count.
    pub clock: &'static str,
    /// `StartTime`, a FILETIME.
    pub start_time: u64,
    /// `start_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`). `None` if it is
    /// out of range.
    pub start_time_utc: Option<String>,
    /// The buffers saved of the session. A buffer's `address` is the
    /// offset of its header in the dump's ETW data.
    pub buffers: Vec<EtwBuffer>,
}

/// The ETW trace sessions that Windows saved as it wrote a crash dump
/// (tagged data `nt!EtwSecondaryDumpDataGuid`): the sessions started
/// with `EVENT_TRACE_ADDTO_TRIAGE_DUMP`, such as EventLog-System.
#[record]
pub struct EtwCrashData {
    /// Bytes of the ETW data.
    pub size: usize,
    /// `KeMaximumIncrement`, the clock interrupt interval in 100 ns.
    pub timer_resolution: u32,
    /// `NtBuildNumber`.
    #[record(hex)]
    pub build_number: u32,
    /// `EtwCPUSpeedInMHz`.
    pub cpu_mhz: u32,
    /// `EtwpBootTime`, a FILETIME.
    pub boot_time: u64,
    /// `boot_time` as UTC. `None` if it is out of range.
    pub boot_time_utc: Option<String>,
    /// `EtwPerfFreq`, the QPC frequency of PerfCounter timestamps.
    pub perf_frequency: u64,
    pub sessions: Vec<EtwCrashSession>,
    /// Why the walk of the data stopped before its end. `None` if it read
    /// all of it.
    pub stop: Option<String>,
}

/// The events of a session that Windows saved in a crash dump, oldest
/// first.
#[record]
pub struct EtwCrashEvents {
    pub session: EtwCrashSession,
    pub buffers_walked: usize,
    /// The number of events found before a count kept the most recent.
    pub total_events: usize,
    /// The buffers that ntoseye skipped fully (compressed), and the walks
    /// that stopped early.
    pub issues: Vec<EtwEventIssue>,
    /// Why some WPP messages have no `text`. `None` if all messages have
    /// `text`.
    pub message_format_note: Option<String>,
    pub events: Vec<EtwEvent>,
}

fn guid(value: Option<&[u8; 16]>) -> Option<String> {
    value.map(|guid| format_guid(guid, GuidStyle::Braced))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn filetime(value: Option<u64>) -> Option<String> {
    value.and_then(format_filetime_precise)
}

/// A `_WMI_LOGGER_CONTEXT`: configuration, counters, and clock.
pub fn logger(l: &etw::EtwLogger) -> EtwLogger {
    EtwLogger {
        address: l.address,
        logger_id: l.logger_id,
        name: l.name.clone(),
        log_file_name: l.log_file_name.clone(),
        logger_mode: l.logger_mode,
        logger_mode_names: logger_mode_names(l.logger_mode),
        flags: l.flags,
        flag_names: l.flag_names.clone(),
        collection_on: l.collection_on,
        buffer_size: l.buffer_size,
        maximum_event_size: l.maximum_event_size,
        minimum_buffers: l.minimum_buffers,
        maximum_buffers: l.maximum_buffers,
        number_of_buffers: l.number_of_buffers,
        buffers_available: l.buffers_available,
        buffers_in_use: l.buffers_in_use(),
        peak_buffers: l.peak_buffers,
        buffers_written: l.buffers_written,
        events_lost: l.events_lost,
        log_buffers_lost: l.log_buffers_lost,
        real_time_buffers_delivered: l.real_time_buffers_delivered,
        real_time_buffers_lost: l.real_time_buffers_lost,
        consumers: l.consumers,
        clock_type: l.clock.raw(),
        clock: l.clock.name(),
        start_time: l.start_time,
        start_time_utc: filetime(Some(l.start_time)),
        flush_timer: l.flush_timer,
        flush_threshold: l.flush_threshold,
        maximum_file_size: l.maximum_file_size,
        logger_thread: l.logger_thread,
        logger_status: l.logger_status,
        instance_guid: format_guid(&l.instance_guid, GuidStyle::Braced),
    }
}

/// `!wmitrace.strdump`: every active logger.
pub fn logger_table(table: &EtwLoggerTableDetail) -> EtwLoggerTable {
    EtwLoggerTable {
        silo_state: table.silo_state,
        context_array: table.context_array,
        max_loggers: table.max_loggers,
        loggers: table.loggers.iter().map(logger).collect(),
    }
}

fn buffer(b: &etw::EtwBuffer) -> EtwBuffer {
    EtwBuffer {
        address: b.address,
        state: b.state,
        state_name: b.state_name.clone(),
        processor: b.processor,
        sequence_number: b.sequence_number,
        timestamp: b.timestamp,
        saved_offset: b.saved_offset,
        current_offset: b.current_offset,
        data_end: b.data_end,
        reference_count: b.reference_count,
    }
}

/// `!wmitrace.strdump <logger>`: a logger and the buffers on its GlobalList.
pub fn logger_buffers(detail: &EtwLoggerBuffersDetail) -> EtwLoggerBuffers {
    EtwLoggerBuffers {
        logger: logger(&detail.logger),
        buffers: detail.buffers.iter().map(buffer).collect(),
        list_stop: detail.list_stop.clone(),
    }
}

fn event(e: &etw::EtwEvent) -> EtwEvent {
    let r = &e.record;
    EtwEvent {
        buffer: e.buffer,
        offset: r.offset,
        processor: e.processor,
        header: r.kind.name(),
        header_type: r.header_type,
        size: r.size,
        timestamp: r.timestamp,
        system_time: e.system_time,
        system_time_utc: filetime(e.system_time),
        process_id: r.process_id,
        thread_id: r.thread_id,
        guid: guid(r.guid.as_ref()),
        descriptor: r.descriptor.map(|d| EtwEventDescriptor {
            id: d.id,
            version: d.version,
            channel: d.channel,
            level: d.level,
            opcode: d.opcode,
            task: d.task,
            keyword: d.keyword,
        }),
        event_flags: r.event_flags,
        activity_id: guid(r.activity_id.as_ref()),
        hook_id: r.hook_id,
        group: r.hook_id.and_then(event_trace_group_name),
        event_class: r.class.map(|(kind, level, version)| EtwEventClass {
            r#type: kind,
            level,
            version,
        }),
        message: r.message.map(|m| {
            let format = e.message_format.as_ref();
            EtwEventMessage {
                number: m.number,
                option_flags: m.option_flags,
                sequence: m.sequence,
                guid: guid(m.guid.as_ref()),
                component_id: m.component_id,
                provider: format.map(|f| f.provider.clone()),
                function: format.and_then(|f| f.function.clone()),
                level: format.and_then(|f| f.level.clone()),
                flags: format.and_then(|f| f.flags.clone()),
                text: format.and_then(|f| f.text.clone().ok()),
                format_error: format.and_then(|f| f.text.clone().err()),
            }
        }),
        extended: r
            .extended
            .iter()
            .map(|item| EtwExtendedData {
                r#type: item.ext_type,
                type_name: extended_type_name(item.ext_type),
                data: hex_bytes(&item.data),
            })
            .collect(),
        payload: hex_bytes(&r.payload),
    }
}

/// `!wmitrace.logdump`: a logger's in-memory events, oldest first.
pub fn event_dump(dump: &EtwEventDumpDetail) -> EtwEventDump {
    let decoded = &dump.events;
    EtwEventDump {
        logger: logger(&dump.logger),
        buffers_walked: decoded.buffers_walked,
        list_stop: dump.list_stop.clone(),
        total_events: decoded.total_events,
        qpc_frequency: dump.qpc_frequency,
        cpu_mhz: dump.cpu_mhz,
        issues: issues(decoded),
        message_format_note: decoded.message_format_note.clone(),
        events: decoded.events.iter().map(event).collect(),
    }
}

fn issues(decoded: &etw::EtwEvents) -> Vec<EtwEventIssue> {
    decoded
        .issues
        .iter()
        .map(|issue| EtwEventIssue {
            buffer: issue.buffer,
            offset: issue.offset,
            reason: issue.reason.clone(),
        })
        .collect()
}

fn crash_session(session: &EtwDumpLogger) -> EtwCrashSession {
    EtwCrashSession {
        logger_id: session.logger_id,
        name: session.name.clone(),
        logger_mode: session.logger_mode,
        logger_mode_names: logger_mode_names(session.logger_mode),
        buffer_size: session.buffer_size,
        clock_type: session.clock.raw(),
        clock: session.clock.name(),
        start_time: session.start_time,
        start_time_utc: filetime(Some(session.start_time)),
        buffers: session.buffers.iter().map(buffer).collect(),
    }
}

/// The ETW sessions a crash dump saved.
pub fn crash_data(data: &EtwDumpData) -> EtwCrashData {
    EtwCrashData {
        size: data.size(),
        timer_resolution: data.timer_resolution,
        build_number: data.build_number,
        cpu_mhz: data.cpu_mhz,
        boot_time: data.boot_time,
        boot_time_utc: filetime(Some(data.boot_time)),
        perf_frequency: data.perf_frequency,
        sessions: data.loggers.iter().map(crash_session).collect(),
        stop: data.stop.clone(),
    }
}

/// The events of `session`, one of the sessions a crash dump saved.
pub fn crash_events(session: &EtwDumpLogger, decoded: &etw::EtwEvents) -> EtwCrashEvents {
    EtwCrashEvents {
        session: crash_session(session),
        buffers_walked: decoded.buffers_walked,
        total_events: decoded.total_events,
        issues: issues(decoded),
        message_format_note: decoded.message_format_note.clone(),
        events: decoded.events.iter().map(event).collect(),
    }
}
