//! `!wmitrace`: ETW trace sessions, their buffers, and the events in them.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::target::etw::{
    EtwBufferIssue, EtwClock, EtwEvent, EtwHeaderKind, EtwLogger, EtwMessageFormat,
    LogDumpArguments, event_trace_group_name, extended_type_name, format_filetime_precise,
    format_guid, logger_mode_names,
};
use crate::ui;

use crate::repl::*;

/// Payload bytes `!wmitrace.logdump` prints per event.
const PAYLOAD_DISPLAY_BYTES: usize = 256;

/// Bytes of each extended data item `!wmitrace.logdump` prints.
const EXTENDED_DISPLAY_BYTES: usize = 32;

/// Shown for a logger or log file name whose buffer could not be read.
const UNREADABLE_NAME: &str = "<unreadable>";

repl_command! {
    cmd_wmitrace_strdump;
    names: ["!wmitrace.strdump", "wmitrace.strdump"],
    usage: "!wmitrace.strdump [logger-id|logger-name|context-address]",
    summary: "List the active ETW trace sessions, or the trace buffers of one session.",
    details: "Without an argument, lists all active loggers of the host silo. The list comes from the EtwpLoggerContext array of nt!EtwpHostSiloState. For each logger, it shows the id, the _WMI_LOGGER_CONTEXT, the name, the logger mode, and the buffer size. It also shows the buffers allocated/in use/free, the buffers written, the events lost, and the log file. With a logger argument, lists each _WMI_BUFFER_HEADER on the GlobalList of the logger. The argument is the logger id, the session name, or the _WMI_LOGGER_CONTEXT address. The session name match ignores case. For each buffer, the command shows the state (free, logging, flush, ...) and the processor of the buffer. It also shows the sequence number and the number of bytes that hold events. The command also lists the sessions that `logman query -ets` does not show (secure and private sessions).",
}

repl_command! {
    cmd_wmitrace_logger;
    names: ["!wmitrace.logger", "wmitrace.logger"],
    usage: "!wmitrace.logger <logger-id|logger-name|context-address>",
    summary: "Show the configuration and counters of one ETW trace session.",
    details: "Decodes the _WMI_LOGGER_CONTEXT of the session. The command shows the logger mode and its EVENT_TRACE_*_MODE names, and the context flags that are set (from the PDB bitfields). It shows the buffer size, the buffer counts (minimum, maximum, allocated, free, peak), and the buffers written. It also shows the events and buffers lost, the real-time delivery, the clock type, the start time, and the flush timer. Then it shows the logger thread, the consumers, and the log file. The command does not show events. To see the events, use !wmitrace.logdump.",
}

repl_command! {
    cmd_wmitrace_logdump;
    names: ["!wmitrace.logdump", "wmitrace.logdump"],
    usage: "!wmitrace.logdump [-t count] <logger-id|logger-name|context-address>",
    summary: "Show the events that are still in the buffers of an ETW trace session, oldest first.",
    details: "Reads each buffer on the GlobalList of the session. These include the current buffer of each processor, the buffers that wait for a flush, and the free buffers. ETW delivered the events of a free buffer, but did not overwrite them yet. The command decodes each event record by its trace header. EVENT_HEADER is for manifest and TraceLogging providers. It gives the provider GUID, event id, version, opcode, task, level, and keyword. EVENT_TRACE_HEADER is for classic providers. SYSTEM_TRACE_HEADER and PERFINFO_TRACE_HEADER are for kernel events and give the group and hook id. MESSAGE_TRACE_HEADER is for WPP and gives the message GUID and number. The command prints each event as [cpu]pid.tid::time, with its payload in hex (the first 256 bytes). The ids are hex. The time is UTC, converted from the clock of the session. A loaded PDB can declare the trace message format (TMF) of a WPP message. Then the command prints the message formatted: the provider, the function, and the rendered text. If the payload does not fit its TMF, the command prints the message raw, with the reason. The public Microsoft Wdf01000.pdb contains the TMF of KMDF. For other providers, the TMF is only in the private PDB of the provider. So add the PDB directory of the driver with .sympath+. Then use .reload for the driver. -t count keeps the most recent count events. If the records in a buffer stop being valid, the command reports the buffer with the offset. It does not resynchronize.",
}

repl_command! {
    cmd_wmitrace_logsave;
    names: ["!wmitrace.logsave", "wmitrace.logsave"],
    usage: "!wmitrace.logsave <logger-id|logger-name|context-address> <file>",
    summary: "Save the in-memory buffers of an ETW trace session as an .etl file on the host.",
    details: "Writes an .etl file that ETW consumers such as tracerpt can open. The file starts with a header buffer that holds the logfile header event (TRACE_LOGFILE_HEADER). This event records the buffer size, the OS version and build, the processor count, the timer resolution, and the CPU speed. It also records the boot time, the QPC frequency, the start reference and clock type of the session, and the session names. After the header buffer, the file has each buffer on the GlobalList of the session that holds events. The command seals each buffer in the same way as the logger when it flushes a buffer. It sets the valid length and fills the rest of the buffer with 0xff. Each buffer ends after its last record that decodes. So the file holds the events that !wmitrace.logdump shows. The current buffer of a processor can end in a record that is not fully written yet. The file also includes buffers that the logger already flushed to the log file of the session, if their events are still in memory. The command does not include an unreadable buffer. After it writes the file, it lists each unreadable buffer and each buffer that it cut short. The time zone data records only the current bias. If a buffer is compressed, the command gives an error.",
}

impl ReplState<'_> {
    fn cmd_wmitrace_strdump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("!wmitrace.strdump"));
            return Ok(());
        }
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
                logger_name(&logger.name),
                format!("{:#010x}", logger.logger_mode),
                format!("{} KB", logger.buffer_size / 1024),
                logger.number_of_buffers.to_string(),
                logger.buffers_in_use().to_string(),
                logger.buffers_available.to_string(),
                logger.buffers_written.to_string(),
                logger.events_lost.to_string(),
                logger_name(&logger.log_file_name),
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
        print_issues(detail.list_stop.as_deref(), &[]);
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
        let (Some(text), 1) = (invocation.arg(0), invocation.argv.len()) else {
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
            match logger.log_file_name.as_deref() {
                Some("") => ui::muted("(none)"),
                Some(name) => name.to_string(),
                None => ui::muted(UNREADABLE_NAME),
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
        print_issues(dump.list_stop.as_deref(), &dump.issues);
        if let Some(note) = &dump.message_format_note {
            outln!("  {}", ui::muted(note));
        }
        outln!();
        Ok(())
    }

    fn cmd_wmitrace_logsave(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (Some(logger), Some(path), 2) =
            (invocation.arg(0), invocation.arg(1), invocation.argv.len())
        else {
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
            logger_name(&file.logger.name),
            path,
            file.buffers,
            file.logger.buffer_size,
            file.bytes.len()
        );
        print_issues(file.list_stop.as_deref(), &file.issues);
        Ok(())
    }
}

/// A logger's name or log file name, which may have been unreadable.
fn logger_name(name: &Option<String>) -> String {
    name.clone().unwrap_or_else(|| UNREADABLE_NAME.to_string())
}

fn print_logger_title(logger: &EtwLogger) {
    outln!(
        "Logger {:#04x} @ {} '{}'",
        logger.logger_id,
        ui::addr(logger.address.0),
        logger_name(&logger.name)
    );
}

/// Where a `GlobalList` walk ended early, and the buffers not read whole.
fn print_issues(list_stop: Option<&str>, issues: &[EtwBufferIssue]) {
    if let Some(stop) = list_stop {
        outln!("  {} {stop}", "stopped:".yellow());
    }
    for issue in issues {
        outln!(
            "  {} buffer {} +{:#x}: {}",
            "stopped:".yellow(),
            ui::addr(issue.buffer.0),
            issue.offset,
            issue.reason
        );
    }
}

fn print_event(event: &EtwEvent) {
    let record = &event.record;
    let ids = match (record.process_id, record.thread_id) {
        (Some(pid), Some(tid)) => format!("{pid:04x}.{tid:04x}"),
        _ => "----.----".to_string(),
    };
    let time = match (
        event.system_time.and_then(format_filetime_precise),
        record.timestamp,
    ) {
        (Some(time), _) => time,
        (None, Some(raw)) => format!("{raw:#x}"),
        (None, None) => "(no timestamp)".to_string(),
    };
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
        EtwHeaderKind::Message => match &event.message_format {
            Some(EtwMessageFormat {
                provider,
                function,
                text: Ok(text),
                ..
            }) => {
                // Format strings written for DbgPrint end their line.
                let text = text.trim_end_matches(['\r', '\n']);
                match function {
                    Some(function) => format!("{provider} {function}: {text}"),
                    None => format!("{provider}: {text}"),
                }
            }
            _ => {
                let message = record.message.expect("message records carry their header");
                let source = match (guid, message.component_id) {
                    (Some(guid), _) => guid,
                    (None, Some(component)) => format!("component {component:#x}"),
                    (None, None) => "(no guid)".to_string(),
                };
                format!("wpp {source} #{}", message.number)
            }
        },
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
    if let Some(format) = &event.message_format {
        match &format.text {
            // The rendered text stands in for the payload.
            Ok(_) => return,
            Err(error) => outln!(
                "    {} {} ({error})",
                ui::muted("unformatted:"),
                format.provider
            ),
        }
    }
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
