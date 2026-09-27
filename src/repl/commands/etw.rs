//! `!wmitrace`: ETW trace sessions, their buffers, and the events in them.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::target::etw::{
    EtwClock, EtwEvent, EtwHeaderKind, EtwLogger, LogDumpArguments, event_trace_group_name,
    extended_type_name, format_filetime_precise, format_guid, logger_mode_names,
};
use crate::ui;

use crate::repl::*;

/// Payload bytes `!wmitrace.logdump` prints per event.
const PAYLOAD_DISPLAY_BYTES: usize = 256;

/// Bytes of each extended data item `!wmitrace.logdump` prints.
const EXTENDED_DISPLAY_BYTES: usize = 32;

repl_command! {
    cmd_wmitrace_strdump;
    names: ["!wmitrace.strdump", "wmitrace.strdump"],
    usage: "!wmitrace.strdump [logger-id|logger-name|context-address]",
    summary: "List the active ETW trace sessions, or one session's trace buffers.",
    details: "Without an argument, lists every active logger of the host silo (nt!EtwpHostSiloState's EtwpLoggerContext array): its id, _WMI_LOGGER_CONTEXT, name, logger mode, buffer size, buffers allocated/in use/free, buffers written, events lost, and log file. With a logger (its id, its session name without case, or its _WMI_LOGGER_CONTEXT address), lists every _WMI_BUFFER_HEADER on the logger's GlobalList: its state (free, logging, flush, ...), the processor it belongs to, its sequence number, and how many bytes hold events. Sessions that `logman query -ets` hides (secure and private ones) are listed too.",
}

repl_command! {
    cmd_wmitrace_logger;
    names: ["!wmitrace.logger", "wmitrace.logger"],
    usage: "!wmitrace.logger <logger-id|logger-name|context-address>",
    summary: "Show one ETW trace session's configuration and counters.",
    details: "Decodes the session's _WMI_LOGGER_CONTEXT: logger mode and its EVENT_TRACE_*_MODE names, the context flags set (from the PDB's bitfields), buffer size and counts (minimum, maximum, allocated, free, peak), buffers written, events and buffers lost, real-time delivery, clock type, start time, flush timer, logger thread, consumers, and log file. It does not show events; use !wmitrace.logdump for those.",
}

repl_command! {
    cmd_wmitrace_logdump;
    names: ["!wmitrace.logdump", "wmitrace.logdump"],
    usage: "!wmitrace.logdump [-t count] <logger-id|logger-name|context-address>",
    summary: "Print the events still in an ETW trace session's buffers, oldest first.",
    details: "Walks every buffer on the session's GlobalList (each processor's current buffer, buffers waiting to be flushed, and free buffers whose events were already delivered but not yet overwritten) and decodes each event record by its trace header: EVENT_HEADER (manifest and TraceLogging providers: provider GUID, event id, version, opcode, task, level, keyword), EVENT_TRACE_HEADER (classic providers), SYSTEM_TRACE_HEADER and PERFINFO_TRACE_HEADER (kernel events: group and hook id), and MESSAGE_TRACE_HEADER (WPP: message GUID and number). Each event is printed as [cpu]pid.tid::time (hex ids, UTC time converted from the session's clock) with its payload in hex (the first 256 bytes). -t count keeps the most recent count events. WPP messages are printed raw: their trace message format lives only in the provider's private PDB. A buffer whose records stop making sense is reported with the offset, not resynchronized.",
}

repl_command! {
    cmd_wmitrace_logsave;
    names: ["!wmitrace.logsave", "wmitrace.logsave"],
    usage: "!wmitrace.logsave <logger-id|logger-name|context-address> <file>",
    summary: "Save an ETW trace session's in-memory buffers as an .etl file on the host.",
    details: "Writes an .etl file that ETW consumers such as tracerpt open: a header buffer holding the logfile header event (TRACE_LOGFILE_HEADER: buffer size, OS version and build, processor count, timer resolution, CPU speed, boot time, QPC frequency, the session's start reference and clock type, and its names), then every buffer on the session's GlobalList that holds events, sealed as the logger flushes one (valid length set, the rest filled with 0xff). Buffers already flushed to the session's own log file are included when their events are still in memory. The time zone records only the current bias, and a compressed buffer is refused.",
}

impl ReplState<'_> {
    fn cmd_wmitrace_strdump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        match invocation.arg(0) {
            None => self.print_etw_loggers(),
            Some(text) => self.print_etw_buffers(text),
        }
        Ok(())
    }

    fn print_etw_loggers(&self) {
        let table = match self.ctx.target.etw_loggers() {
            Ok(table) => table,
            Err(e) => {
                error!("{e}");
                return;
            }
        };
        outln!(
            "{} loggers active of {} (EtwpLoggerContext {}, host silo state {})",
            table.loggers.len(),
            table.max_loggers,
            ui::addr(table.context_array.0),
            ui::addr(table.silo_state.0)
        );
        let mut builder = Builder::default();
        builder.push_record([
            "Id", "Context", "Name", "Mode", "BufSize", "Buffers", "InUse", "Free", "Written",
            "Lost", "LogFile",
        ]);
        for logger in &table.loggers {
            builder.push_record([
                format!("{:#04x}", logger.logger_id),
                ui::addr(logger.address.0),
                logger.name.clone(),
                format!("{:#010x}", logger.logger_mode),
                format!("{} KB", logger.buffer_size / 1024),
                logger.number_of_buffers.to_string(),
                logger.buffers_in_use().to_string(),
                logger.buffers_available.to_string(),
                logger.buffers_written.to_string(),
                logger.events_lost.to_string(),
                logger.log_file_name.clone(),
            ]);
        }
        outln!();
        print_padded_table(builder);
    }

    fn print_etw_buffers(&self, text: &str) {
        let detail = match self.ctx.target.etw_logger_buffers(text, self.radix) {
            Ok(detail) => detail,
            Err(e) => {
                error!("{e}");
                return;
            }
        };
        let logger = &detail.logger;
        print_logger_title(logger);
        outln!(
            "  {} buffers of {:#x} bytes on GlobalList ({} allocated, {} free)",
            detail.buffers.len(),
            logger.buffer_size,
            logger.number_of_buffers,
            logger.buffers_available
        );
        if detail.buffers.is_empty() {
            outln!();
            return;
        }
        let mut builder = Builder::default();
        builder.push_record([
            "Buffer", "State", "Cpu", "Sequence", "Saved", "Current", "Data", "Refs",
        ]);
        for buffer in &detail.buffers {
            builder.push_record([
                ui::addr(buffer.address.0),
                buffer.state_name.clone(),
                buffer.processor.to_string(),
                buffer.sequence_number.to_string(),
                format!("{:#x}", buffer.saved_offset),
                format!("{:#x}", buffer.current_offset),
                format!("{:#x}", buffer.data_end),
                buffer.reference_count.to_string(),
            ]);
        }
        outln!();
        print_padded_table(builder);
    }

    fn cmd_wmitrace_logger(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(text) = invocation.arg(0) else {
            outln!("{}\n", command_help("!wmitrace.logger"));
            return Ok(());
        };
        let logger = match self.ctx.target.etw_logger(text, self.radix) {
            Ok(logger) => logger,
            Err(e) => {
                error!("{e}");
                return Ok(());
            }
        };
        print_logger_title(&logger);
        let row = |label: &str, value: String| {
            outln!("  {} {}", ui::muted(&format!("{label:<25}")), value)
        };
        row("CollectionOn", u8::from(logger.collection_on).to_string());
        row(
            "LoggerMode",
            format!(
                "{:#010x} ({})",
                logger.logger_mode,
                logger_mode_names(logger.logger_mode).join(" | ")
            ),
        );
        row(
            "Flags",
            format!("{:#010x} ({})", logger.flags, logger.flag_names.join(" ")),
        );
        row(
            "BufferSize",
            format!(
                "{} KB ({:#x})",
                logger.buffer_size / 1024,
                logger.buffer_size
            ),
        );
        row(
            "MaximumEventSize",
            format!("{:#x}", logger.maximum_event_size),
        );
        row("MinimumBuffers", logger.minimum_buffers.to_string());
        row("MaximumBuffers", logger.maximum_buffers.to_string());
        row("NumberOfBuffers", logger.number_of_buffers.to_string());
        row("BuffersAvailable", logger.buffers_available.to_string());
        row("BuffersInUse", logger.buffers_in_use().to_string());
        row("PeakBuffersCount", logger.peak_buffers.to_string());
        row("BuffersWritten", logger.buffers_written.to_string());
        row("EventsLost", logger.events_lost.to_string());
        row("LogBuffersLost", logger.log_buffers_lost.to_string());
        row(
            "RealTimeBuffersDelivered",
            logger.real_time_buffers_delivered.to_string(),
        );
        row(
            "RealTimeBuffersLost",
            logger.real_time_buffers_lost.to_string(),
        );
        row("NumConsumers", logger.consumers.to_string());
        row(
            "ClockType",
            format!("{} ({})", logger.clock.name(), logger.clock.raw()),
        );
        row(
            "StartTime",
            format_filetime_precise(logger.start_time)
                .unwrap_or_else(|| format!("{:#x}", logger.start_time)),
        );
        row("FlushTimer", format!("{} s", logger.flush_timer));
        row("FlushThreshold", logger.flush_threshold.to_string());
        row(
            "MaximumFileSize",
            format!("{} MB", logger.maximum_file_size),
        );
        row("LoggerThread", ui::addr(logger.logger_thread.0));
        row("LoggerStatus", format!("{:#x}", logger.logger_status));
        row("InstanceGuid", format_guid(&logger.instance_guid));
        row(
            "LogFileName",
            if logger.log_file_name.is_empty() {
                ui::muted("(none)")
            } else {
                logger.log_file_name.clone()
            },
        );
        outln!();
        Ok(())
    }

    fn cmd_wmitrace_logdump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let arguments = LogDumpArguments::parse(invocation.argv.iter().map(|arg| arg.as_ref()));
        let LogDumpArguments {
            logger,
            most_recent,
        } = match arguments {
            Ok(Some(arguments)) => arguments,
            Ok(None) => {
                outln!("{}\n", command_help("!wmitrace.logdump"));
                return Ok(());
            }
            Err(e) => {
                error!("{e}");
                return Ok(());
            }
        };
        let dump = match self
            .ctx
            .target
            .etw_log_dump(&logger, self.radix, most_recent)
        {
            Ok(dump) => dump,
            Err(e) => {
                error!("{e}");
                return Ok(());
            }
        };
        print_logger_title(&dump.logger);
        let frequency = match dump.logger.clock {
            EtwClock::PerformanceCounter => dump.qpc_frequency.map(|f| format!(", QPC {f} Hz")),
            EtwClock::CpuCycle => dump
                .cpu_mhz
                .map(|mhz| format!(" at the rated {mhz} MHz, times approximate")),
            _ => None,
        }
        .unwrap_or_default();
        outln!(
            "  {} events in {} buffers ({} clock{frequency}){}",
            dump.total_events,
            dump.buffers_walked,
            dump.logger.clock.name(),
            if dump.events.len() < dump.total_events {
                format!(", showing the last {}", dump.events.len())
            } else {
                String::new()
            }
        );
        outln!();
        for event in &dump.events {
            print_event(event);
        }
        for issue in &dump.issues {
            outln!(
                "  {} buffer {} +{:#x}: {}",
                "stopped:".yellow(),
                ui::addr(issue.buffer.0),
                issue.offset,
                issue.reason
            );
        }
        if let Some(note) = &dump.message_format_note {
            outln!("  {}", ui::muted(note));
        }
        outln!();
        Ok(())
    }

    fn cmd_wmitrace_logsave(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (Some(logger), Some(path)) = (invocation.arg(0), invocation.arg(1)) else {
            outln!("{}\n", command_help("!wmitrace.logsave"));
            return Ok(());
        };
        let file = match self.ctx.target.etw_log_file(logger, self.radix) {
            Ok(file) => file,
            Err(e) => {
                error!("{e}");
                return Ok(());
            }
        };
        if let Err(e) = std::fs::write(path, &file.bytes) {
            error!("failed to write '{path}': {e}");
            return Ok(());
        }
        outln!(
            "wrote logger {:#04x} '{}' to '{}': header buffer and {} buffers of {:#x} bytes ({:#x} bytes)\n",
            file.logger.logger_id,
            file.logger.name,
            path,
            file.buffers,
            file.logger.buffer_size,
            file.bytes.len()
        );
        Ok(())
    }
}

fn print_logger_title(logger: &EtwLogger) {
    outln!(
        "Logger {:#04x} @ {} '{}'",
        logger.logger_id,
        ui::addr(logger.address.0),
        logger.name
    );
}

fn print_event(event: &EtwEvent) {
    let record = &event.record;
    let ids = match (record.process_id, record.thread_id) {
        (Some(pid), Some(tid)) => format!("{pid:04x}.{tid:04x}"),
        _ => "----.----".to_string(),
    };
    let time = event
        .system_time
        .and_then(format_filetime_precise)
        .unwrap_or_else(|| format!("{:#x}", record.timestamp));
    let guid = record.guid.as_ref().map(format_guid);
    let what = match record.kind {
        EtwHeaderKind::EventHeader => {
            let d = record
                .descriptor
                .expect("EVENT_HEADER records carry a descriptor");
            format!(
                "{} id {} v{} opcode {} task {} level {} keyword {:#x}",
                guid.unwrap_or_default(),
                d.id,
                d.version,
                d.opcode,
                d.task,
                d.level,
                d.keyword
            )
        }
        EtwHeaderKind::Message => {
            let message = record.message.expect("message records carry their header");
            let source = match (guid, message.component_id) {
                (Some(guid), _) => guid,
                (None, Some(component)) => format!("component {component:#x}"),
                (None, None) => "(no guid)".to_string(),
            };
            format!("wpp {source} #{}", message.number)
        }
        EtwHeaderKind::FullHeader | EtwHeaderKind::Instance => {
            let (kind, level, version) = record.class.unwrap_or_default();
            format!(
                "{} type {kind} level {level} version {version}",
                guid.unwrap_or_default()
            )
        }
        EtwHeaderKind::System | EtwHeaderKind::Compact | EtwHeaderKind::PerfInfo => {
            let hook = record.hook_id.unwrap_or_default();
            format!(
                "{}/{:#04x} hook {hook:#06x}",
                event_trace_group_name(hook).unwrap_or("?"),
                hook & 0xff
            )
        }
    };
    outln!(
        "[{}]{}::{} {} {}",
        event.processor,
        ids,
        time,
        ui::muted(record.kind.name()),
        what
    );
    for item in &record.extended {
        let name = extended_type_name(item.ext_type)
            .map_or_else(|| format!("type {}", item.ext_type), str::to_string);
        let shown = &item.data[..item.data.len().min(EXTENDED_DISPLAY_BYTES)];
        let hex: String = shown.iter().map(|b| format!("{b:02x}")).collect();
        let more = if item.data.len() > shown.len() {
            "..."
        } else {
            ""
        };
        outln!(
            "    {} {name} ({:#x} bytes) {hex}{more}",
            ui::muted("extended"),
            item.data.len()
        );
    }
    let shown = &record.payload[..record.payload.len().min(PAYLOAD_DISPLAY_BYTES)];
    for (row, chunk) in shown.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        outln!("    {:04x}  {:<47}  {}", row * 16, hex.join(" "), ascii);
    }
    if record.payload.len() > shown.len() {
        outln!(
            "    {}",
            ui::muted(&format!(
                "... {:#x} more payload bytes",
                record.payload.len() - shown.len()
            ))
        );
    }
}
