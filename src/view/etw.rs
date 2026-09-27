//! ETW [`View`] builders: trace sessions, their buffers, and their events.

use super::View;
use crate::target::etw::{
    EtwBuffer, EtwEvent, EtwEventDump, EtwLogger, EtwLoggerBuffers, EtwLoggerTable,
    event_trace_group_name, extended_type_name, format_filetime_precise, format_guid,
    logger_mode_names,
};

fn guid(value: Option<&[u8; 16]>) -> View {
    View::OptStr(value.map(format_guid))
}

fn hex_bytes(bytes: &[u8]) -> View {
    View::Str(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn filetime(value: Option<u64>) -> View {
    View::OptStr(value.and_then(format_filetime_precise))
}

/// A `_WMI_LOGGER_CONTEXT`: configuration, counters, and clock.
pub fn logger(l: &EtwLogger) -> View {
    View::Object(vec![
        ("address", View::Hex(l.address.0)),
        ("logger_id", View::Num(l.logger_id.into())),
        ("name", View::Str(l.name.clone())),
        ("log_file_name", View::Str(l.log_file_name.clone())),
        ("logger_mode", View::Hex(l.logger_mode.into())),
        (
            "logger_mode_names",
            View::List(
                logger_mode_names(l.logger_mode)
                    .into_iter()
                    .map(|name| View::Str(name.to_string()))
                    .collect(),
            ),
        ),
        ("flags", View::Hex(l.flags.into())),
        (
            "flag_names",
            View::List(l.flag_names.iter().cloned().map(View::Str).collect()),
        ),
        ("collection_on", View::Bool(l.collection_on)),
        ("buffer_size", View::Num(l.buffer_size.into())),
        ("maximum_event_size", View::Num(l.maximum_event_size.into())),
        ("minimum_buffers", View::Num(l.minimum_buffers.into())),
        ("maximum_buffers", View::Num(l.maximum_buffers.into())),
        ("number_of_buffers", View::Int(l.number_of_buffers.into())),
        ("buffers_available", View::Int(l.buffers_available.into())),
        ("buffers_in_use", View::Int(l.buffers_in_use())),
        ("peak_buffers", View::Int(l.peak_buffers.into())),
        ("buffers_written", View::Num(l.buffers_written.into())),
        ("events_lost", View::Num(l.events_lost.into())),
        ("log_buffers_lost", View::Num(l.log_buffers_lost.into())),
        (
            "real_time_buffers_delivered",
            View::Num(l.real_time_buffers_delivered.into()),
        ),
        (
            "real_time_buffers_lost",
            View::Num(l.real_time_buffers_lost.into()),
        ),
        ("consumers", View::Num(l.consumers.into())),
        ("clock_type", View::Num(l.clock.raw().into())),
        ("clock", View::Str(l.clock.name().to_string())),
        ("start_time", View::Num(l.start_time)),
        ("start_time_utc", filetime(Some(l.start_time))),
        ("flush_timer", View::Num(l.flush_timer.into())),
        ("flush_threshold", View::Num(l.flush_threshold.into())),
        ("maximum_file_size", View::Num(l.maximum_file_size.into())),
        ("logger_thread", View::Hex(l.logger_thread.0)),
        ("logger_status", View::Int(l.logger_status.into())),
        ("instance_guid", View::Str(format_guid(&l.instance_guid))),
    ])
}

/// `!wmitrace.strdump`: every active logger.
pub fn logger_table(table: &EtwLoggerTable) -> View {
    View::Object(vec![
        ("silo_state", View::Hex(table.silo_state.0)),
        ("context_array", View::Hex(table.context_array.0)),
        ("max_loggers", View::Num(table.max_loggers.into())),
        (
            "loggers",
            View::List(table.loggers.iter().map(logger).collect()),
        ),
    ])
}

fn buffer(b: &EtwBuffer) -> View {
    View::Object(vec![
        ("address", View::Hex(b.address.0)),
        ("state", View::Num(b.state.into())),
        ("state_name", View::Str(b.state_name.clone())),
        ("processor", View::Num(b.processor.into())),
        ("sequence_number", View::Int(b.sequence_number)),
        ("timestamp", View::Num(b.timestamp)),
        ("saved_offset", View::Num(b.saved_offset.into())),
        ("current_offset", View::Num(b.current_offset.into())),
        ("data_end", View::Num(b.data_end.into())),
        ("reference_count", View::Int(b.reference_count.into())),
    ])
}

/// `!wmitrace.strdump <logger>`: a logger and the buffers on its GlobalList.
pub fn logger_buffers(detail: &EtwLoggerBuffers) -> View {
    View::Object(vec![
        ("logger", logger(&detail.logger)),
        (
            "buffers",
            View::List(detail.buffers.iter().map(buffer).collect()),
        ),
        ("list_stop", View::OptStr(detail.list_stop.clone())),
    ])
}

fn event(e: &EtwEvent) -> View {
    let r = &e.record;
    let descriptor = r.descriptor.map_or(View::Null, |d| {
        View::Object(vec![
            ("id", View::Num(d.id.into())),
            ("version", View::Num(d.version.into())),
            ("channel", View::Num(d.channel.into())),
            ("level", View::Num(d.level.into())),
            ("opcode", View::Num(d.opcode.into())),
            ("task", View::Num(d.task.into())),
            ("keyword", View::Hex(d.keyword)),
        ])
    });
    let message = r.message.map_or(View::Null, |m| {
        View::Object(vec![
            ("number", View::Num(m.number.into())),
            ("option_flags", View::Hex(m.option_flags.into())),
            ("sequence", View::OptNum(m.sequence.map(u64::from))),
            ("guid", guid(m.guid.as_ref())),
            ("component_id", View::OptNum(m.component_id.map(u64::from))),
        ])
    });
    let class = r.class.map_or(View::Null, |(kind, level, version)| {
        View::Object(vec![
            ("type", View::Num(kind.into())),
            ("level", View::Num(level.into())),
            ("version", View::Num(version.into())),
        ])
    });
    View::Object(vec![
        ("buffer", View::Hex(e.buffer.0)),
        ("offset", View::Num(r.offset.into())),
        ("processor", View::Num(e.processor.into())),
        ("header", View::Str(r.kind.name().to_string())),
        ("header_type", View::Num(r.header_type.into())),
        ("size", View::Num(r.size.into())),
        ("timestamp", View::Num(r.timestamp)),
        ("system_time", View::OptNum(e.system_time)),
        ("system_time_utc", filetime(e.system_time)),
        ("process_id", View::OptNum(r.process_id.map(u64::from))),
        ("thread_id", View::OptNum(r.thread_id.map(u64::from))),
        ("guid", guid(r.guid.as_ref())),
        ("descriptor", descriptor),
        ("event_flags", View::OptHex(r.event_flags.map(u64::from))),
        ("activity_id", guid(r.activity_id.as_ref())),
        ("hook_id", View::OptHex(r.hook_id.map(u64::from))),
        (
            "group",
            View::OptStr(
                r.hook_id
                    .and_then(event_trace_group_name)
                    .map(str::to_string),
            ),
        ),
        ("class", class),
        ("message", message),
        (
            "extended",
            View::List(
                r.extended
                    .iter()
                    .map(|item| {
                        View::Object(vec![
                            ("type", View::Num(item.ext_type.into())),
                            (
                                "type_name",
                                View::OptStr(extended_type_name(item.ext_type).map(str::to_string)),
                            ),
                            ("data", hex_bytes(&item.data)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("payload", hex_bytes(&r.payload)),
    ])
}

/// `!wmitrace.logdump`: a logger's in-memory events, oldest first.
pub fn event_dump(dump: &EtwEventDump) -> View {
    View::Object(vec![
        ("logger", logger(&dump.logger)),
        ("buffers_walked", View::Num(dump.buffers_walked as u64)),
        ("list_stop", View::OptStr(dump.list_stop.clone())),
        ("total_events", View::Num(dump.total_events as u64)),
        ("qpc_frequency", View::OptNum(dump.qpc_frequency)),
        ("cpu_mhz", View::OptNum(dump.cpu_mhz)),
        (
            "issues",
            View::List(
                dump.issues
                    .iter()
                    .map(|issue| {
                        View::Object(vec![
                            ("buffer", View::Hex(issue.buffer.0)),
                            ("offset", View::Num(issue.offset.into())),
                            ("reason", View::Str(issue.reason.clone())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "message_format_note",
            View::OptStr(dump.message_format_note.clone()),
        ),
        (
            "events",
            View::List(dump.events.iter().map(event).collect()),
        ),
    ])
}
