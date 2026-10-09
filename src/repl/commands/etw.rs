//! `!wmitrace`: ETW trace sessions, their buffers, and the events in them.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::target::etw::dump::{EtwDumpData, EtwDumpLogger};
use crate::target::etw::{
    EtwBuffer, EtwBufferIssue, EtwClock, EtwEvent, EtwEvents, EtwHeaderKind, EtwLogger,
    EtwMessageFormat, LogDumpArguments, event_trace_group_name, extended_type_name,
    format_filetime_precise, format_guid, logger_mode_names,
};
use crate::types::VirtAddr;
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
    details: "Without an argument, lists all active loggers of the host silo from the EtwpLoggerContext array of nt!EtwpHostSiloState. For each logger, it shows the id, the _WMI_LOGGER_CONTEXT, the name, the logger mode, and the buffer size, and also the buffers allocated/in use/free, the buffers written, the events lost, and the log file. With a logger argument, it lists each _WMI_BUFFER_HEADER on the GlobalList of the logger. The argument is the logger id, the session name, or the _WMI_LOGGER_CONTEXT address, and the session name match ignores case. For each buffer, the command shows the state (free, logging, flush, ...), the processor of the buffer, the sequence number, and the number of bytes that hold events. The command also lists the sessions that `logman query -ets` does not show (secure and private sessions). A minidump holds no kernel pool, so in a minidump the command lists instead the sessions that Windows saved in the tagged data of the dump (nt!EtwSecondaryDumpDataGuid, see .enumtag): those started with EVENT_TRACE_ADDTO_TRIAGE_DUMP. For each session, it shows the id, the name, the logger mode, the buffer size, the clock, the start time, and the buffers saved, which are all the buffers on the GlobalList of the session. With a logger argument, it lists these buffers, each at its offset in the tagged data.",
}

repl_command! {
    cmd_wmitrace_logger;
    names: ["!wmitrace.logger", "wmitrace.logger"],
    usage: "!wmitrace.logger <logger-id|logger-name|context-address>",
    summary: "Show the configuration and counters of one ETW trace session.",
    details: "Decodes the _WMI_LOGGER_CONTEXT of the session. The command shows the logger mode with its EVENT_TRACE_*_MODE names, and the context flags that are set (from the PDB bitfields). It shows the buffer size, the buffer counts (minimum, maximum, allocated, free, peak), and the buffers written, then the events and buffers lost, the real-time delivery, the clock type, the start time, and the flush timer. Last come the logger thread, the consumers, and the log file. The command does not show events. To see them, use !wmitrace.logdump. In a minidump, the command shows the few fields that the tagged data of the dump records for the session: the logger mode, the buffer size, the number of buffers, the clock type, and the start time.",
}

repl_command! {
    cmd_wmitrace_logdump;
    names: ["!wmitrace.logdump", "wmitrace.logdump"],
    usage: "!wmitrace.logdump [-t count] <logger-id|logger-name|context-address>",
    summary: "Show the events that are still in the buffers of an ETW trace session, oldest first.",
    details: "Reads each buffer on the GlobalList of the session: the current buffer of each processor, the buffers that wait for a flush, and the free buffers, whose events ETW delivered but did not overwrite yet. The command decodes each event record by its trace header. EVENT_HEADER is for manifest and TraceLogging providers and gives the provider GUID, event id, version, opcode, task, level, and keyword. EVENT_TRACE_HEADER is for classic providers. SYSTEM_TRACE_HEADER and PERFINFO_TRACE_HEADER are for kernel events and give the group and hook id. MESSAGE_TRACE_HEADER is for WPP and gives the message GUID and number. The command prints each event as [cpu]pid.tid::time, with its payload in hex (the first 256 bytes). The ids are hex, and the time is UTC, converted from the clock of the session. When a loaded PDB declares the trace message format (TMF) of a WPP message, the command prints the message formatted: the provider, the function, and the rendered text. If the payload does not fit its TMF, it prints the message raw, with the reason. The public Microsoft Wdf01000.pdb contains the TMF of KMDF, but for other providers the TMF is only in the private PDB of the provider, so add the PDB directory of the driver with .sympath+ and then use .reload for the driver. -t count keeps the most recent count events. If the records in a buffer stop being valid, the command reports the buffer with the offset and does not resynchronize. In a minidump, the command decodes the buffers that Windows saved in the tagged data of the dump (see !wmitrace.strdump), which hold the same events as the buffers in memory.",
}

repl_command! {
    cmd_wmitrace_logsave;
    names: ["!wmitrace.logsave", "wmitrace.logsave"],
    usage: "!wmitrace.logsave <logger-id|logger-name|context-address> <file>",
    summary: "Save the in-memory buffers of an ETW trace session as an .etl file on the host.",
    details: "Writes an .etl file that ETW consumers such as tracerpt can open. The file starts with a header buffer that holds the logfile header event (TRACE_LOGFILE_HEADER). This event records the buffer size, the OS version and build, the processor count, the timer resolution, and the CPU speed, and also the boot time, the QPC frequency, the start reference and clock type of the session, and the session names. After the header buffer comes each buffer on the GlobalList of the session that holds events. The command seals each buffer as the logger does when it flushes a buffer, by setting the valid length and filling the rest of the buffer with 0xff. Each buffer ends after its last record that decodes, so the file holds the events that !wmitrace.logdump shows. The current buffer of a processor can end in a record that is not fully written yet. The file also includes buffers that the logger already flushed to the log file of the session, if their events are still in memory. The command leaves out an unreadable buffer, and after it writes the file, it lists each unreadable buffer and each buffer that it cut short. The time zone data records only the current bias. If a buffer is compressed, the command gives an error. In a minidump, the command saves the buffers of the tagged data of the dump (see !wmitrace.strdump), with the boot time, the QPC frequency, the timer resolution, and the CPU speed that the tagged data records.",
}

impl ReplState<'_> {
    fn cmd_wmitrace_strdump(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if invocation.argv.len() > 1 {
            outln!("{}\n", command_help("!wmitrace.strdump"));
            return Ok(());
        }
        let Some(dump) = self.etw_dump_data() else {
            return Ok(());
        };
        match (dump, invocation.arg(0)) {
            (Some(data), None) => print_dump_loggers(&data),
            (Some(data), Some(text)) => {
                if let Some(logger) = self.etw_dump_logger(&data, text) {
                    print_dump_buffers(logger);
                }
            }
            (None, None) => self.print_etw_loggers(),
            (None, Some(text)) => self.print_etw_buffers(text),
        }
        Ok(())
    }

    /// Where a minidump's sessions are: `Some(Some(data))`, its ETW data;
    /// `Some(None)` on a target whose memory holds them; `None` after
    /// printing why a minidump has none.
    fn etw_dump_data(&self) -> Option<Option<EtwDumpData>> {
        self.ctx
            .target
            .etw_dump_data()
            .map_err(|e| error!("{e}"))
            .ok()
    }

    /// The session of `data` that `text` names, or `None` after printing
    /// why none is.
    fn etw_dump_logger<'d>(&self, data: &'d EtwDumpData, text: &str) -> Option<&'d EtwDumpLogger> {
        self.ctx
            .target
            .etw_dump_logger(data, text, self.radix)
            .map_err(|e| error!("{e}"))
            .ok()
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
        print_issues(detail.list_stop.as_deref(), &[], kernel_buffer);
        if detail.buffers.is_empty() {
            outln!();
            return;
        }
        print_buffer_table("Buffer", &detail.buffers, kernel_buffer);
    }

    fn cmd_wmitrace_logger(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (Some(text), 1) = (invocation.arg(0), invocation.argv.len()) else {
            outln!("{}\n", command_help("!wmitrace.logger"));
            return Ok(());
        };
        let Some(dump) = self.etw_dump_data() else {
            return Ok(());
        };
        if let Some(data) = dump {
            if let Some(logger) = self.etw_dump_logger(&data, text) {
                print_dump_logger(logger);
            }
            return Ok(());
        }
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
        let Some(dump) = self.etw_dump_data() else {
            return Ok(());
        };
        if let Some(data) = dump {
            let Some(logger) = self.etw_dump_logger(&data, &logger) else {
                return Ok(());
            };
            match self.ctx.target.etw_dump_events(&data, logger, most_recent) {
                Ok(events) => {
                    print_dump_logger_title(logger);
                    print_events(
                        logger.clock,
                        Some(data.perf_frequency),
                        Some(u64::from(data.cpu_mhz)),
                        data.stop.as_deref(),
                        &events,
                        dump_buffer,
                    );
                }
                Err(e) => error!("{e}"),
            }
            return Ok(());
        }
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
        print_events(
            dump.logger.clock,
            dump.qpc_frequency,
            dump.cpu_mhz,
            dump.list_stop.as_deref(),
            &dump.events,
            kernel_buffer,
        );
        Ok(())
    }

    fn cmd_wmitrace_logsave(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (Some(logger), Some(path), 2) =
            (invocation.arg(0), invocation.arg(1), invocation.argv.len())
        else {
            outln!("{}\n", command_help("!wmitrace.logsave"));
            return Ok(());
        };
        let Some(dump) = self.etw_dump_data() else {
            return Ok(());
        };
        let (file, buffer_at): (_, fn(VirtAddr) -> String) = match &dump {
            Some(data) => {
                let Some(logger) = self.etw_dump_logger(data, logger) else {
                    return Ok(());
                };
                (self.ctx.target.etw_dump_log_file(data, logger), dump_buffer)
            }
            None => (
                self.ctx.target.etw_log_file(logger, self.radix),
                kernel_buffer,
            ),
        };
        let file = match file {
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
            file.logger_id,
            logger_name(&file.name),
            path,
            file.buffers,
            file.buffer_size,
            file.bytes.len()
        );
        print_issues(file.list_stop.as_deref(), &file.issues, buffer_at);
        Ok(())
    }
}

/// A logger's name or log file name, which may have been unreadable.
fn logger_name(name: &Option<String>) -> String {
    name.clone().unwrap_or_else(|| UNREADABLE_NAME.to_string())
}

/// A buffer in kernel memory, by its address.
fn kernel_buffer(address: VirtAddr) -> String {
    ui::addr(address.0)
}

/// A buffer of a minidump's ETW data, by its offset in the block.
fn dump_buffer(offset: VirtAddr) -> String {
    format!("+{:#x}", offset.0)
}

/// Each buffer of `buffers`, the first column `where_` headed and filled
/// by `buffer_at`.
fn print_buffer_table(where_: &str, buffers: &[EtwBuffer], buffer_at: fn(VirtAddr) -> String) {
    let mut builder = Builder::default();
    builder.push_record([
        where_, "State", "Cpu", "Sequence", "Saved", "Current", "Data", "Refs",
    ]);
    for buffer in buffers {
        builder.push_record([
            buffer_at(buffer.address),
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

/// `!wmitrace.strdump` in a minidump: the sessions of its ETW data.
fn print_dump_loggers(data: &EtwDumpData) {
    outln!(
        "{} loggers in the dump's ETW data ({:#x} bytes, nt!EtwSecondaryDumpDataGuid)",
        data.loggers.len(),
        data.size()
    );
    let mut builder = Builder::default();
    builder.push_record([
        "Id",
        "Name",
        "Mode",
        "BufSize",
        "Clock",
        "Buffers",
        "Data",
        "StartTime",
    ]);
    for logger in &data.loggers {
        builder.push_record([
            format!("{:#04x}", logger.logger_id),
            logger.name.clone(),
            format!("{:#010x}", logger.logger_mode),
            format!("{} KB", logger.buffer_size / 1024),
            logger.clock.name().to_string(),
            logger.buffers.len().to_string(),
            format!(
                "{:#x}",
                logger
                    .buffers
                    .iter()
                    .map(|buffer| u64::from(buffer.data_end))
                    .sum::<u64>()
            ),
            format_filetime_precise(logger.start_time)
                .unwrap_or_else(|| format!("{:#x}", logger.start_time)),
        ]);
    }
    outln!();
    print_padded_table(builder);
    print_issues(data.stop.as_deref(), &[], dump_buffer);
}

fn print_dump_logger_title(logger: &EtwDumpLogger) {
    outln!(
        "Logger {:#04x} '{}' in the dump's ETW data",
        logger.logger_id,
        logger.name
    );
}

/// `!wmitrace.strdump <logger>` in a minidump: the session's buffers, by
/// their offset in the block.
fn print_dump_buffers(logger: &EtwDumpLogger) {
    print_dump_logger_title(logger);
    outln!(
        "  {} buffers of {:#x} bytes",
        logger.buffers.len(),
        logger.buffer_size
    );
    if logger.buffers.is_empty() {
        outln!();
        return;
    }
    print_buffer_table("Offset", &logger.buffers, dump_buffer);
}

/// `!wmitrace.logger` in a minidump: the fields of the session's
/// `_WMI_LOGGER_CONTEXT` that its ETW data records.
fn print_dump_logger(logger: &EtwDumpLogger) {
    print_dump_logger_title(logger);
    let row =
        |label: &str, value: String| outln!("  {} {}", ui::muted(&format!("{label:<25}")), value);
    row(
        "LoggerMode",
        format!(
            "{:#010x} ({})",
            logger.logger_mode,
            logger_mode_names(logger.logger_mode).join(" | ")
        ),
    );
    row(
        "BufferSize",
        format!(
            "{} KB ({:#x})",
            logger.buffer_size / 1024,
            logger.buffer_size
        ),
    );
    row("Buffers", logger.buffers.len().to_string());
    row(
        "ClockType",
        format!("{} ({})", logger.clock.name(), logger.clock.raw()),
    );
    row(
        "StartTime",
        format_filetime_precise(logger.start_time)
            .unwrap_or_else(|| format!("{:#x}", logger.start_time)),
    );
    outln!(
        "  {}",
        ui::muted(
            "a minidump keeps no more of the session's _WMI_LOGGER_CONTEXT; its counters \
             are in a full or kernel dump"
        )
    );
    outln!();
}

/// `!wmitrace.logdump`'s events after the logger's title: how many, in how
/// many buffers and by which clock, each event, and what could not be read.
fn print_events(
    clock: EtwClock,
    qpc_frequency: Option<u64>,
    cpu_mhz: Option<u64>,
    list_stop: Option<&str>,
    events: &EtwEvents,
    buffer_at: fn(VirtAddr) -> String,
) {
    let frequency = match clock {
        EtwClock::PerformanceCounter => qpc_frequency.map(|f| format!(", QPC {f} Hz")),
        EtwClock::CpuCycle => {
            cpu_mhz.map(|mhz| format!(" at the rated {mhz} MHz, times approximate"))
        }
        _ => None,
    }
    .unwrap_or_default();
    outln!(
        "  {} events in {} buffers ({} clock{frequency}){}",
        events.total_events,
        events.buffers_walked,
        clock.name(),
        if events.events.len() < events.total_events {
            format!(", showing the last {}", events.events.len())
        } else {
            String::new()
        }
    );
    outln!();
    for event in &events.events {
        print_event(event);
    }
    print_issues(list_stop, &events.issues, buffer_at);
    if let Some(note) = &events.message_format_note {
        outln!("  {}", ui::muted(note));
    }
    outln!();
}

fn print_logger_title(logger: &EtwLogger) {
    outln!(
        "Logger {:#04x} @ {} '{}'",
        logger.logger_id,
        ui::addr(logger.address.0),
        logger_name(&logger.name)
    );
}

/// Where a `GlobalList` walk ended early, and the buffers not read whole,
/// each named by `buffer_at`.
fn print_issues(
    list_stop: Option<&str>,
    issues: &[EtwBufferIssue],
    buffer_at: fn(VirtAddr) -> String,
) {
    if let Some(stop) = list_stop {
        outln!("  {} {stop}", "stopped:".yellow());
    }
    for issue in issues {
        outln!(
            "  {} buffer {} +{:#x}: {}",
            "stopped:".yellow(),
            buffer_at(issue.buffer),
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
