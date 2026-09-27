//! ETW [`View`] builders: trace sessions, their buffers, and their events.

use super::View;
use super::shape::{Hex, ViewValue, shapes};
use crate::target::etw::{
    self, EtwEventDump as EtwEventDumpDetail, EtwLoggerBuffers as EtwLoggerBuffersDetail,
    EtwLoggerTable as EtwLoggerTableDetail, event_trace_group_name, extended_type_name,
    format_filetime_precise, format_guid, logger_mode_names,
};

shapes! {
    /// An active ETW trace session, decoded from its `_WMI_LOGGER_CONTEXT`.
    EtwLogger {
        /// The `_WMI_LOGGER_CONTEXT`.
        address: Hex,
        logger_id: u32,
        /// `LoggerName`; `None` when its buffer is unreadable (pool freed or
        /// paged out while a session stops).
        name: Option<String>,
        /// `LogFileName`; `None` when its buffer is unreadable.
        log_file_name: Option<String>,
        logger_mode: Hex,
        /// The `EVENT_TRACE_*_MODE` bits set in `logger_mode`.
        logger_mode_names: Vec<&'static str>,
        flags: Hex,
        /// The `Flags` bitfields that are set, from the PDB.
        flag_names: Vec<String>,
        collection_on: bool,
        /// Bytes per buffer.
        buffer_size: u32,
        maximum_event_size: u32,
        minimum_buffers: u32,
        maximum_buffers: u32,
        number_of_buffers: i64,
        buffers_available: i64,
        /// Buffers taken from the free pool (`number_of_buffers -
        /// buffers_available`): current on a processor, full, or being
        /// flushed.
        buffers_in_use: i64,
        peak_buffers: i64,
        buffers_written: u32,
        events_lost: u32,
        log_buffers_lost: u32,
        real_time_buffers_delivered: u32,
        real_time_buffers_lost: u32,
        consumers: u32,
        /// `ClockType` (`EVENT_TRACE_CLOCK_*`).
        clock_type: u32,
        /// What event timestamps count, named.
        clock: &'static str,
        /// `StartTime`, a FILETIME.
        start_time: u64,
        /// `start_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`); `None` when
        /// out of range.
        start_time_utc: Option<String>,
        flush_timer: u32,
        flush_threshold: u32,
        maximum_file_size: u32,
        logger_thread: Hex,
        logger_status: i64,
        instance_guid: String,
    }

    /// Every active ETW logger of the host silo (`!wmitrace.strdump`).
    EtwLoggerTable {
        silo_state: Hex,
        /// `EtwpLoggerContext`: the array of `max_loggers` context pointers.
        context_array: Hex,
        max_loggers: u32,
        loggers: Vec<EtwLogger>,
    }

    /// A logger's trace buffer (`_WMI_BUFFER_HEADER`).
    EtwBuffer {
        address: Hex,
        state: u32,
        state_name: String,
        processor: u16,
        sequence_number: i64,
        /// Raw timestamp in the logger's clock.
        timestamp: u64,
        saved_offset: u32,
        current_offset: u32,
        /// Bytes of the buffer holding the header and complete events.
        data_end: u32,
        reference_count: i64,
    }

    /// A logger and the buffers on its `GlobalList`
    /// (`!wmitrace.strdump <logger>`).
    EtwLoggerBuffers {
        logger: EtwLogger,
        buffers: Vec<EtwBuffer>,
        /// Why the `GlobalList` walk ended before returning to its head;
        /// `None` when it completed.
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

    /// The fields a `MESSAGE_TRACE_HEADER` carries after itself, as its
    /// `TRACE_MESSAGE_*` option flags select; each `None` when not selected.
    EtwEventMessage {
        /// The message number.
        number: u16,
        option_flags: Hex,
        sequence: Option<u32>,
        guid: Option<String>,
        component_id: Option<u32>,
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
        /// The type's name, when it is a known one.
        type_name: Option<&'static str>,
        /// The item's bytes, as hex.
        data: String,
    }

    /// An event record decoded out of a trace buffer. Fields its header
    /// kind lacks are `None`.
    EtwEvent {
        /// The buffer it came from.
        buffer: Hex,
        /// Offset of the record in its buffer.
        offset: u32,
        processor: u16,
        /// The trace header it starts with (`EVENT_HEADER`, ...).
        header: &'static str,
        header_type: u8,
        /// Record size, header included (unaligned).
        size: u16,
        /// Raw timestamp in the logger's clock; a WPP message without
        /// `TRACE_MESSAGE_TIMESTAMP` has none.
        timestamp: Option<u64>,
        /// FILETIME, when the logger's clock converts to one.
        system_time: Option<u64>,
        /// `system_time` as UTC (`YYYY-MM-DD HH:MM:SS.fffffff`).
        system_time_utc: Option<String>,
        process_id: Option<u32>,
        thread_id: Option<u32>,
        /// Provider (`EVENT_HEADER`), event class (`EVENT_TRACE_HEADER`) or
        /// message (`MESSAGE_TRACE_HEADER`) GUID.
        guid: Option<String>,
        descriptor: Option<EtwEventDescriptor>,
        /// `EVENT_HEADER.Flags`.
        event_flags: Option<Hex>,
        activity_id: Option<String>,
        /// Kernel hook id (group << 8 | type) of system and perfinfo events.
        hook_id: Option<Hex>,
        /// The hook id's `EVENT_TRACE_GROUP_*` name, when it is a known one.
        group: Option<&'static str>,
        /// A classic event's class; the JSON key is `class`.
        event_class: Option<EtwEventClass> => "class",
        message: Option<EtwEventMessage>,
        extended: Vec<EtwExtendedData>,
        /// The event's user data, as hex.
        payload: String,
    }

    /// A buffer whose events could not all be decoded.
    EtwEventIssue {
        buffer: Hex,
        /// Where in the buffer the walk stopped.
        offset: u32,
        reason: String,
    }

    /// A logger's in-memory events, oldest first (`!wmitrace.logdump`).
    EtwEventDump {
        logger: EtwLogger,
        buffers_walked: usize,
        /// Why the `GlobalList` walk ended before returning to its head;
        /// `None` when it completed.
        list_stop: Option<String>,
        /// Events found before a count kept the most recent.
        total_events: usize,
        /// QPC frequency used for PerfCounter timestamps.
        qpc_frequency: Option<u64>,
        /// Processor speed used for CpuCycle timestamps.
        cpu_mhz: Option<u64>,
        /// Buffers skipped whole (compressed) and walks that stopped early.
        issues: Vec<EtwEventIssue>,
        /// Why WPP messages are shown raw.
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

fn etw_logger(l: &etw::EtwLogger) -> EtwLogger {
    EtwLogger {
        address: Hex(l.address.0),
        logger_id: l.logger_id,
        name: l.name.clone(),
        log_file_name: l.log_file_name.clone(),
        logger_mode: Hex(l.logger_mode.into()),
        logger_mode_names: logger_mode_names(l.logger_mode),
        flags: Hex(l.flags.into()),
        flag_names: l.flag_names.clone(),
        collection_on: l.collection_on,
        buffer_size: l.buffer_size,
        maximum_event_size: l.maximum_event_size,
        minimum_buffers: l.minimum_buffers,
        maximum_buffers: l.maximum_buffers,
        number_of_buffers: l.number_of_buffers.into(),
        buffers_available: l.buffers_available.into(),
        buffers_in_use: l.buffers_in_use(),
        peak_buffers: l.peak_buffers.into(),
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
        logger_thread: Hex(l.logger_thread.0),
        logger_status: l.logger_status.into(),
        instance_guid: format_guid(&l.instance_guid),
    }
}

/// A `_WMI_LOGGER_CONTEXT`: configuration, counters, and clock.
pub fn logger(l: &etw::EtwLogger) -> View {
    etw_logger(l).into_view()
}

/// `!wmitrace.strdump`: every active logger.
pub fn logger_table(table: &EtwLoggerTableDetail) -> View {
    EtwLoggerTable {
        silo_state: Hex(table.silo_state.0),
        context_array: Hex(table.context_array.0),
        max_loggers: table.max_loggers,
        loggers: table.loggers.iter().map(etw_logger).collect(),
    }
    .into_view()
}

fn buffer(b: &etw::EtwBuffer) -> EtwBuffer {
    EtwBuffer {
        address: Hex(b.address.0),
        state: b.state,
        state_name: b.state_name.clone(),
        processor: b.processor,
        sequence_number: b.sequence_number,
        timestamp: b.timestamp,
        saved_offset: b.saved_offset,
        current_offset: b.current_offset,
        data_end: b.data_end,
        reference_count: b.reference_count.into(),
    }
}

/// `!wmitrace.strdump <logger>`: a logger and the buffers on its GlobalList.
pub fn logger_buffers(detail: &EtwLoggerBuffersDetail) -> View {
    EtwLoggerBuffers {
        logger: etw_logger(&detail.logger),
        buffers: detail.buffers.iter().map(buffer).collect(),
        list_stop: detail.list_stop.clone(),
    }
    .into_view()
}

fn event(e: &etw::EtwEvent) -> EtwEvent {
    let r = &e.record;
    EtwEvent {
        buffer: Hex(e.buffer.0),
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
            keyword: Hex(d.keyword),
        }),
        event_flags: r.event_flags.map(|flags| Hex(flags.into())),
        activity_id: guid(r.activity_id.as_ref()),
        hook_id: r.hook_id.map(|hook| Hex(hook.into())),
        group: r.hook_id.and_then(event_trace_group_name),
        event_class: r.class.map(|(kind, level, version)| EtwEventClass {
            r#type: kind,
            level,
            version,
        }),
        message: r.message.map(|m| EtwEventMessage {
            number: m.number,
            option_flags: Hex(m.option_flags.into()),
            sequence: m.sequence,
            guid: guid(m.guid.as_ref()),
            component_id: m.component_id,
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
pub fn event_dump(dump: &EtwEventDumpDetail) -> View {
    EtwEventDump {
        logger: etw_logger(&dump.logger),
        buffers_walked: dump.buffers_walked,
        list_stop: dump.list_stop.clone(),
        total_events: dump.total_events,
        qpc_frequency: dump.qpc_frequency,
        cpu_mhz: dump.cpu_mhz,
        issues: dump
            .issues
            .iter()
            .map(|issue| EtwEventIssue {
                buffer: Hex(issue.buffer.0),
                offset: issue.offset,
                reason: issue.reason.clone(),
            })
            .collect(),
        message_format_note: dump.message_format_note.clone(),
        events: dump.events.iter().map(event).collect(),
    }
    .into_view()
}
