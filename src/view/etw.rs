//! ETW [`View`] builders: trace sessions, their buffers, and their events.

use super::shape::{Hex, shapes};
use crate::types::VirtAddr;
use crate::target::etw::{
    self, EtwEventDump as EtwEventDumpDetail, EtwLoggerBuffers as EtwLoggerBuffersDetail,
    EtwLoggerTable as EtwLoggerTableDetail, event_trace_group_name, extended_type_name,
    format_filetime_precise, format_guid, logger_mode_names,
};

shapes! {
    /// An active ETW trace session, decoded from its `_WMI_LOGGER_CONTEXT`.
    EtwLogger {
        /// The `_WMI_LOGGER_CONTEXT`.
        address: VirtAddr,
        logger_id: u32,
        /// `LoggerName`. `None` if ntoseye cannot read its buffer, which can
        /// happen when the pool is freed or paged out while a session stops.
        name: Option<String>,
        /// `LogFileName`. `None` if ntoseye cannot read its buffer.
        log_file_name: Option<String>,
        logger_mode: Hex<u32>,
        /// The `EVENT_TRACE_*_MODE` bits that are set in `logger_mode`.
        logger_mode_names: Vec<&'static str>,
        flags: Hex<u32>,
        /// The `Flags` bitfields that are set, from the PDB.
        flag_names: Vec<String>,
        collection_on: bool,
        /// Bytes per buffer.
        buffer_size: u32,
        maximum_event_size: u32,
        minimum_buffers: u32,
        maximum_buffers: u32,
        number_of_buffers: i32,
        buffers_available: i32,
        /// The buffers taken from the free pool (`number_of_buffers -
        /// buffers_available`). Each of these buffers is current on a processor,
        /// full, or in a flush.
        buffers_in_use: i64,
        peak_buffers: i32,
        buffers_written: u32,
        events_lost: u32,
        log_buffers_lost: u32,
        real_time_buffers_delivered: u32,
        real_time_buffers_lost: u32,
        consumers: u32,
        /// `ClockType` (`EVENT_TRACE_CLOCK_*`).
        clock_type: u32,
        /// The name of what the event timestamps count.
        clock: &'static str,
        /// `StartTime`, a FILETIME.
        start_time: u64,
        /// `start_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`). `None` if it is
        /// out of range.
        start_time_utc: Option<String>,
        flush_timer: u32,
        flush_threshold: u32,
        maximum_file_size: u32,
        logger_thread: VirtAddr,
        logger_status: i32,
        instance_guid: String,
    }

    /// All active ETW loggers of the host silo (`!wmitrace.strdump`).
    EtwLoggerTable {
        silo_state: VirtAddr,
        /// `EtwpLoggerContext`: the array of `max_loggers` context pointers.
        context_array: VirtAddr,
        max_loggers: u32,
        loggers: Vec<EtwLogger>,
    }

    /// A trace buffer of a logger (`_WMI_BUFFER_HEADER`).
    EtwBuffer {
        address: VirtAddr,
        state: u32,
        state_name: String,
        processor: u16,
        sequence_number: i64,
        /// The raw timestamp in the clock of the logger.
        timestamp: u64,
        saved_offset: u32,
        current_offset: u32,
        /// The number of bytes in the buffer that hold the header and complete
        /// events.
        data_end: u32,
        reference_count: i32,
    }

    /// A logger and the buffers on its `GlobalList`
    /// (`!wmitrace.strdump <logger>`).
    EtwLoggerBuffers {
        logger: EtwLogger,
        buffers: Vec<EtwBuffer>,
        /// Why the walk of the `GlobalList` stopped before it came back to the
        /// list head. `None` if the walk completed.
        list_stop: Option<String>,
    }

    /// The `EVENT_DESCRIPTOR` of an `EVENT_HEADER` event.
    EtwEventDescriptor {
        id: u16,
        version: u8,
        channel: u8,
        level: u8,
        opcode: u8,
        task: u16,
        keyword: Hex,
    }

    /// The fields that follow a `MESSAGE_TRACE_HEADER`, as the
    /// `TRACE_MESSAGE_*` option flags of the header select them. A field is
    /// `None` if the flags do not select it, and the TMF fields are `None` if
    /// no loaded PDB declares the trace message format (TMF) of the message.
    EtwEventMessage {
        /// The message number.
        number: u16,
        option_flags: Hex<u16>,
        sequence: Option<u32>,
        guid: Option<String>,
        component_id: Option<u32>,
        /// The provider (component) name from the TMF.
        provider: Option<String>,
        /// The function that traced the message.
        function: Option<String>,
        /// The trace level from the TMF (`TRACE_LEVEL_ERROR`, or a number).
        level: Option<String>,
        /// The trace flag name from the TMF.
        flags: Option<String>,
        /// The message text, rendered from its TMF and the payload.
        text: Option<String>,
        /// Why the payload does not fit the argument types of the TMF.
        format_error: Option<String>,
    }

    /// `Class.Type`/`Level`/`Version` of a classic event.
    EtwEventClass {
        r#type: u8,
        level: u8,
        version: u16,
    }

    /// An `EVENT_HEADER` extended data item.
    EtwExtendedData {
        /// `EVENT_HEADER_EXT_TYPE_*`.
        r#type: u16,
        /// The name of the type, if it is known.
        type_name: Option<&'static str>,
        /// The bytes of the item, as hex.
        data: String,
    }

    /// An event record that ntoseye decoded from a trace buffer. A field is
    /// `None` if the header kind of the event does not have it.
    EtwEvent {
        /// The buffer that the event came from.
        buffer: VirtAddr,
        /// The offset of the record in its buffer.
        offset: u32,
        processor: u16,
        /// The trace header at the start of the record (`EVENT_HEADER`, ...).
        header: &'static str,
        header_type: u8,
        /// The record size, with the header included (unaligned).
        size: u16,
        /// The raw timestamp in the clock of the logger. A WPP message without
        /// `TRACE_MESSAGE_TIMESTAMP` has no timestamp.
        timestamp: Option<u64>,
        /// The FILETIME, if the clock of the logger converts to one.
        system_time: Option<u64>,
        /// `system_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`).
        system_time_utc: Option<String>,
        process_id: Option<u32>,
        thread_id: Option<u32>,
        /// The provider GUID (`EVENT_HEADER`), event class GUID
        /// (`EVENT_TRACE_HEADER`), or message GUID (`MESSAGE_TRACE_HEADER`).
        guid: Option<String>,
        descriptor: Option<EtwEventDescriptor>,
        /// `EVENT_HEADER.Flags`.
        event_flags: Option<Hex<u16>>,
        activity_id: Option<String>,
        /// The kernel hook id (group << 8 | type) of system and perfinfo events.
        hook_id: Option<Hex<u16>>,
        /// The `EVENT_TRACE_GROUP_*` name of the hook id, if it is known.
        group: Option<&'static str>,
        /// The class of a classic event. The JSON key is `class`.
        event_class: Option<EtwEventClass> => "class",
        message: Option<EtwEventMessage>,
        extended: Vec<EtwExtendedData>,
        /// The user data of the event, as hex.
        payload: String,
    }

    /// A buffer in which ntoseye could not decode all events.
    EtwEventIssue {
        buffer: VirtAddr,
        /// The position in the buffer where the walk stopped.
        offset: u32,
        reason: String,
    }

    /// The in-memory events of a logger, oldest first (`!wmitrace.logdump`).
    EtwEventDump {
        logger: EtwLogger,
        buffers_walked: usize,
        /// Why the walk of the `GlobalList` stopped before it came back to the
        /// list head. `None` if the walk completed.
        list_stop: Option<String>,
        /// The number of events found before a count kept the most recent.
        total_events: usize,
        /// QPC frequency used for PerfCounter timestamps.
        qpc_frequency: Option<u64>,
        /// Processor speed used for CpuCycle timestamps.
        cpu_mhz: Option<u64>,
        /// The buffers that ntoseye skipped fully (compressed), and the walks that
        /// stopped early.
        issues: Vec<EtwEventIssue>,
        /// Why some WPP messages have no `text`. `None` if all messages have
        /// `text`.
        message_format_note: Option<String>,
        events: Vec<EtwEvent>,
    }
}

fn guid(value: Option<&[u8; 16]>) -> Option<String> {
    value.map(format_guid)
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
        instance_guid: format_guid(&l.instance_guid),
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
    EtwEventDump {
        logger: logger(&dump.logger),
        buffers_walked: dump.buffers_walked,
        list_stop: dump.list_stop.clone(),
        total_events: dump.total_events,
        qpc_frequency: dump.qpc_frequency,
        cpu_mhz: dump.cpu_mhz,
        issues: dump
            .issues
            .iter()
            .map(|issue| EtwEventIssue {
                buffer: issue.buffer,
                offset: issue.offset,
                reason: issue.reason.clone(),
            })
            .collect(),
        message_format_note: dump.message_format_note.clone(),
        events: dump.events.iter().map(event).collect(),
    }
}
