//! `!wmitrace`: ETW trace sessions, their buffers, and the events in them.

use tabled::builder::Builder;

use owo_colors::OwoColorize;

use ntoseye_macros::{command, grammar};

use crate::base::error::{Error, Result};
use crate::base::types::VirtAddr;
use crate::hosts::repl::args::{ArgCursor, ArgCx, ArgError};
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::target::etw::dump::{EtwDumpData, EtwDumpLogger};
use crate::nt::target::etw::{
    EtwBuffer, EtwBufferIssue, EtwClock, EtwEvent, EtwEventDump, EtwHeaderKind, EtwLogFile,
    EtwLogSave, EtwLogger, EtwLoggerBuffers, EtwLoggerRef, EtwLoggerTable, EtwMessageFormat,
    EtwSession, GuidStyle, event_trace_group_name, extended_type_name, format_filetime_precise,
    format_guid, logger_mode_names,
};
use crate::session::Session;

/// Payload bytes `!wmitrace.logdump` prints per event.
const PAYLOAD_DISPLAY_BYTES: usize = 256;

/// Bytes of each extended data item `!wmitrace.logdump` prints.
const EXTENDED_DISPLAY_BYTES: usize = 32;

/// Shown for a logger or log file name whose buffer could not be read.
const UNREADABLE_NAME: &str = "<unreadable>";

/// List the active ETW trace sessions, or the trace buffers of one session.
///
/// Without an argument, lists all active loggers of the host silo from the
/// EtwpLoggerContext array of nt!EtwpHostSiloState. For each logger, it shows
/// the id, the _WMI_LOGGER_CONTEXT, the name, the logger mode, and the buffer
/// size, and also the buffers allocated/in use/free, the buffers written, the
/// events lost, and the log file. With a logger argument, it lists each
/// _WMI_BUFFER_HEADER on the GlobalList of the logger. The argument is the
/// logger id, the session name, or the _WMI_LOGGER_CONTEXT address, and the
/// session name match ignores case. For each buffer, the command shows the
/// state (free, logging, flush, ...), the processor of the buffer, the sequence
/// number, and the number of bytes that hold events. The command also lists the
/// sessions that `logman query -ets` does not show (secure and private
/// sessions). A minidump holds no kernel pool, so in a minidump the command
/// lists instead the sessions that Windows saved in the tagged data of the dump
/// (nt!EtwSecondaryDumpDataGuid, see .enumtag): those started with
/// EVENT_TRACE_ADDTO_TRIAGE_DUMP. For each session, it shows the id, the name,
/// the logger mode, the buffer size, the clock, the start time, and the buffers
/// saved, which are all the buffers on the GlobalList of the session. With a
/// logger argument, it lists these buffers, each at its offset in the tagged
/// data.
#[command(
    names = ["!wmitrace.strdump", "wmitrace.strdump"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    forms = [etw_loggers, etw_buffers, etw_crash_sessions],
)]
fn wmitrace_strdump(
    session: &Session,
    #[arg(parse = optional_logger)] logger: Option<EtwLoggerRef>,
) -> Result<EtwLoggerList> {
    match (session.target.etw_reads_dump_data(), logger) {
        (true, None) => etw_crash_sessions(session).map(EtwLoggerList::Saved),
        (true, Some(logger)) => etw_crash_session(session, logger).map(EtwLoggerList::SavedBuffers),
        (false, None) => etw_loggers(session).map(EtwLoggerList::Active),
        (false, Some(logger)) => etw_buffers(session, logger).map(EtwLoggerList::Buffers),
    }
}

/// List the active ETW trace sessions (`!wmitrace.strdump`).
#[command(form_of = wmitrace_strdump, python = Inspect)]
fn etw_loggers(session: &Session) -> Result<EtwLoggerTable> {
    session.target.etw_loggers()
}

/// List the trace buffers on the GlobalList of an ETW trace session
/// (`!wmitrace.strdump logger`).
#[command(form_of = wmitrace_strdump, python = Inspect)]
fn etw_buffers(session: &Session, logger: EtwLoggerRef) -> Result<EtwLoggerBuffers> {
    session.target.etw_logger_buffers(&logger)
}

/// List the ETW trace sessions that Windows saved as it wrote a crash
/// dump, and their buffers (`!wmitrace.strdump` in a minidump): the
/// sessions started with `EVENT_TRACE_ADDTO_TRIAGE_DUMP`, such as
/// EventLog-System. A minidump has no other copy of them; in a kernel or
/// full dump, `etw_loggers()` reads every session from memory.
#[command(form_of = wmitrace_strdump, python = Inspect)]
fn etw_crash_sessions(session: &Session) -> Result<EtwDumpData> {
    session.target.etw_crash_data()
}

/// What `!wmitrace.strdump` lists: the active sessions, or the buffers of
/// one; in a minidump, the sessions of its ETW data, or one of them with
/// its buffers.
enum EtwLoggerList {
    Active(EtwLoggerTable),
    Buffers(EtwLoggerBuffers),
    Saved(EtwDumpData),
    SavedBuffers(EtwDumpLogger),
}

impl Render for EtwLoggerList {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Active(table) => print_loggers(table),
            Self::Buffers(buffers) => print_logger_buffers(buffers),
            Self::Saved(data) => print_dump_loggers(data),
            Self::SavedBuffers(logger) => print_dump_buffers(logger),
        }
    }
}

/// Show the configuration and counters of one ETW trace session.
///
/// Decodes the _WMI_LOGGER_CONTEXT of the session. The command shows the logger
/// mode with its EVENT_TRACE_*_MODE names, and the context flags that are set
/// (from the PDB bitfields). It shows the buffer size, the buffer counts
/// (minimum, maximum, allocated, free, peak), and the buffers written, then the
/// events and buffers lost, the real-time delivery, the clock type, the start
/// time, and the flush timer. Last come the logger thread, the consumers, and
/// the log file. The command does not show events. To see them, use
/// !wmitrace.logdump. In a minidump, the command shows the few fields that the
/// tagged data of the dump records for the session: the logger mode, the buffer
/// size, the number of buffers, the clock type, and the start time.
#[command(
    names = ["!wmitrace.logger", "wmitrace.logger"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    forms = [etw_logger, etw_crash_session],
)]
fn wmitrace_logger(
    session: &Session,
    #[arg(parse = sole_logger)] logger: EtwLoggerRef,
) -> Result<EtwSession> {
    if session.target.etw_reads_dump_data() {
        etw_crash_session(session, logger).map(EtwSession::Saved)
    } else {
        etw_logger(session, logger).map(EtwSession::Active)
    }
}

/// Decode the `_WMI_LOGGER_CONTEXT` of one ETW trace session
/// (`!wmitrace.logger`). `logger` is the logger ID, the context address, or
/// the session name.
#[command(form_of = wmitrace_logger, python = Inspect)]
fn etw_logger(session: &Session, logger: EtwLoggerRef) -> Result<EtwLogger> {
    session.target.etw_logger(&logger)
}

/// Show one ETW trace session that Windows saved in a crash dump, with its
/// buffers (`!wmitrace.logger` and `!wmitrace.strdump logger` in a
/// minidump). `logger` is the logger ID or the session name.
#[command(form_of = wmitrace_logger, python = Inspect)]
fn etw_crash_session(session: &Session, logger: EtwLoggerRef) -> Result<EtwDumpLogger> {
    let target = &session.target;
    let data = target.etw_crash_data()?;
    target.etw_dump_logger(&data, &logger).cloned()
}

impl Render for EtwSession {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match self {
            Self::Active(logger) => print_logger(logger),
            Self::Saved(logger) => print_dump_logger(logger),
        }
    }
}

/// Show the events that are still in the buffers of an ETW trace session,
/// oldest first.
///
/// Reads each buffer on the GlobalList of the session: the current buffer of
/// each processor, the buffers that wait for a flush, and the free buffers,
/// whose events ETW delivered but did not overwrite yet. The command decodes
/// each event record by its trace header. EVENT_HEADER is for manifest and
/// TraceLogging providers and gives the provider GUID, event id, version,
/// opcode, task, level, and keyword. EVENT_TRACE_HEADER is for classic
/// providers. SYSTEM_TRACE_HEADER and PERFINFO_TRACE_HEADER are for kernel
/// events and give the group and hook id. MESSAGE_TRACE_HEADER is for WPP and
/// gives the message GUID and number. The command prints each event as
/// [cpu]pid.tid::time, with its payload in hex (the first 256 bytes). The ids
/// are hex, and the time is UTC, converted from the clock of the session. When
/// a loaded PDB declares the trace message format (TMF) of a WPP message, the
/// command prints the message formatted: the provider, the function, and the
/// rendered text. If the payload does not fit its TMF, it prints the message
/// raw, with the reason. The public Microsoft Wdf01000.pdb contains the TMF of
/// KMDF, but for other providers the TMF is only in the private PDB of the
/// provider, so add the PDB directory of the driver with .sympath+ and then use
/// .reload for the driver. -t count keeps the most recent count events. If the
/// records in a buffer stop being valid, the command reports the buffer with
/// the offset and does not resynchronize. In a minidump, the command decodes
/// the buffers that Windows saved in the tagged data of the dump (see
/// !wmitrace.strdump), which hold the same events as the buffers in memory.
#[command(
    names = ["!wmitrace.logdump", "wmitrace.logdump"],
    category = "analysis",
    kind = Query,
    target = Kernel,
    forms = [etw_events, etw_crash_events],
)]
fn wmitrace_logdump(
    session: &Session,
    #[arg(parse = logdump_logger)] logger: EtwLoggerRef,
    #[arg(parse = logdump_count)] count: Option<u64>,
) -> Result<EtwEventDump> {
    let count = count.map(|count| usize::try_from(count).unwrap_or(usize::MAX));
    if session.target.etw_reads_dump_data() {
        etw_crash_events(session, logger, count)
    } else {
        etw_events(session, logger, count)
    }
}

/// Decode the events that are still in the buffers of an ETW trace session,
/// oldest first (`!wmitrace.logdump`). `count` keeps only the most recent
/// events. For a WPP message, `message_format.text` is the message rendered
/// from the TMF that a loaded PDB declares, and the raw `record.payload` is
/// always kept.
#[command(form_of = wmitrace_logdump, python = Inspect)]
fn etw_events(
    session: &Session,
    logger: EtwLoggerRef,
    count: Option<usize>,
) -> Result<EtwEventDump> {
    session.target.etw_log_dump(&logger, count)
}

/// Decode the events of an ETW trace session that Windows saved in a
/// crash dump, oldest first (`!wmitrace.logdump` in a minidump).
/// `logger` is the logger ID or the session name, and `count` keeps
/// only the most recent events.
#[command(form_of = wmitrace_logdump, python = Inspect)]
fn etw_crash_events(
    session: &Session,
    logger: EtwLoggerRef,
    count: Option<usize>,
) -> Result<EtwEventDump> {
    let target = &session.target;
    let data = target.etw_crash_data()?;
    let logger = target.etw_dump_logger(&data, &logger)?;
    target.etw_dump_events(&data, logger, count)
}

impl Render for EtwEventDump {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        match &self.logger {
            EtwSession::Active(logger) => print_logger_title(logger),
            EtwSession::Saved(logger) => print_dump_logger_title(logger),
        }
        print_events(self);
    }
}

/// Save the in-memory buffers of an ETW trace session as an .etl file on the
/// host.
///
/// Writes an .etl file that ETW consumers such as tracerpt can open. The file
/// starts with a header buffer that holds the logfile header event
/// (TRACE_LOGFILE_HEADER). This event records the buffer size, the OS version
/// and build, the processor count, the timer resolution, and the CPU speed, and
/// also the boot time, the QPC frequency, the start reference and clock type of
/// the session, and the session names. After the header buffer comes each
/// buffer on the GlobalList of the session that holds events. The command seals
/// each buffer as the logger does when it flushes a buffer, by setting the
/// valid length and filling the rest of the buffer with 0xff. Each buffer ends
/// after its last record that decodes, so the file holds the events that
/// !wmitrace.logdump shows. The current buffer of a processor can end in a
/// record that is not fully written yet. The file also includes buffers that
/// the logger already flushed to the log file of the session, if their events
/// are still in memory. The command leaves out an unreadable buffer, and after
/// it writes the file, it lists each unreadable buffer and each buffer that it
/// cut short. The time zone data records only the current bias. If a buffer is
/// compressed, the command gives an error. In a minidump, the command saves the
/// buffers of the tagged data of the dump (see !wmitrace.strdump), with the
/// boot time, the QPC frequency, the timer resolution, and the CPU speed that
/// the tagged data records.
#[command(
    names = ["!wmitrace.logsave", "wmitrace.logsave"],
    category = "analysis",
    kind = Action,
    target = Kernel,
    writes = [Files],
    forms = [etw_save, etw_crash_save],
)]
fn wmitrace_logsave(
    session: &Session,
    #[arg(parse = logsave_logger)] logger: EtwLoggerRef,
    #[arg(name = "file")] path: String,
) -> Result<EtwLogSave> {
    if session.target.etw_reads_dump_data() {
        etw_crash_save(session, logger, path)
    } else {
        etw_save(session, logger, path)
    }
}

/// Save the in-memory buffers of an ETW trace session as an .etl file at
/// `path` on the host (`!wmitrace.logsave`), which ETW consumers such as
/// tracerpt open. `logger` is the logger ID, the context address, or the
/// session name.
#[command(form_of = wmitrace_logsave, python = Inspect)]
fn etw_save(session: &Session, logger: EtwLoggerRef, path: String) -> Result<EtwLogSave> {
    let file = session.target.etw_log_file(&logger)?;
    write_log_file(path, file)
}

/// Save the buffers of an ETW trace session that Windows saved in a crash
/// dump as an .etl file at `path` on the host (`!wmitrace.logsave` in a
/// minidump). `logger` is the logger ID or the session name.
#[command(form_of = wmitrace_logsave, python = Inspect)]
fn etw_crash_save(session: &Session, logger: EtwLoggerRef, path: String) -> Result<EtwLogSave> {
    let target = &session.target;
    let data = target.etw_crash_data()?;
    let logger = target.etw_dump_logger(&data, &logger)?;
    let file = target.etw_dump_log_file(&data, logger)?;
    write_log_file(path, file)
}

/// Writes `file` at `path` on the host.
fn write_log_file(path: String, file: EtwLogFile) -> Result<EtwLogSave> {
    std::fs::write(&path, &file.bytes)
        .map_err(|e| Error::DebugInfo(format!("failed to write '{path}': {e}")))?;
    Ok(EtwLogSave { path, file })
}

impl Render for EtwLogSave {
    fn render(&self, _: &mut ReplState<'_>, (): ()) {
        let file = &self.file;
        outln!(
            "wrote logger {:#04x} '{}' to '{}': header buffer and {} buffers of {:#x} bytes ({:#x} bytes)\n",
            file.logger.logger_id(),
            logger_name(file.logger.name()),
            self.path,
            file.buffers,
            file.logger.buffer_size(),
            file.bytes.len()
        );
        print_issues(
            file.list_stop.as_deref(),
            &file.issues,
            buffer_at(&file.logger),
        );
    }
}

/// The logger of a command that takes only it; any other number of words
/// shows the help.
#[grammar(usage = "<logger-id|logger-name|context-address>", complete = [None])]
fn sole_logger(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<EtwLoggerRef, ArgError> {
    if cursor.remaining() != 1 {
        return Err(ArgError::Missing);
    }
    next_logger(cx, cursor)
}

/// `!wmitrace.strdump`'s logger, if one is named; more words show the help.
#[grammar(usage = "[logger-id|logger-name|context-address]")]
fn optional_logger(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<EtwLoggerRef>, ArgError> {
    match cursor.remaining() {
        0 => Ok(None),
        1 => next_logger(cx, cursor).map(Some),
        _ => Err(ArgError::Missing),
    }
}

/// `!wmitrace.logsave`'s logger, before its file; any other number of words
/// shows the help.
#[grammar(usage = "<logger-id|logger-name|context-address>", complete = [None])]
fn logsave_logger(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<EtwLoggerRef, ArgError> {
    if cursor.remaining() != 2 {
        return Err(ArgError::Missing);
    }
    next_logger(cx, cursor)
}

/// The next word as a logger, which the operation resolves in the current
/// radix.
fn next_logger(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<EtwLoggerRef, ArgError> {
    let text = cursor.word().ok_or(ArgError::Missing)?;
    Ok(EtwLoggerRef {
        text: text.into_owned(),
        radix: cx.state.radix,
    })
}

/// `!wmitrace.logdump`'s line, `[-t count] <logger>` in any order: the
/// index of the logger among `words`, if one is named, and the last count.
/// The count is decimal, or hex with `0x`, whatever the radix, as WinDbg
/// takes it. The error is the first bad word's, wherever it is.
fn logdump_line<'a>(
    words: impl IntoIterator<Item = &'a str>,
) -> std::result::Result<(Option<usize>, Option<u64>), String> {
    let mut logger = None;
    let mut count = None;
    let mut words = words.into_iter().enumerate();
    while let Some((index, word)) = words.next() {
        if word.eq_ignore_ascii_case("-t") {
            let (_, text) = words
                .next()
                .ok_or_else(|| "-t needs a count of events".to_string())?;
            let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => text.parse(),
            };
            count = Some(parsed.map_err(|_| format!("-t count '{text}' is not a number"))?);
        } else if logger.is_none() {
            logger = Some(index);
        } else {
            return Err(format!(
                "unexpected argument '{word}': quote a session name that has spaces; filtering by a GUID file is not supported"
            ));
        }
    }
    Ok((logger, count))
}

fn logdump_error(message: String) -> ArgError {
    ArgError::Message(Error::InvalidArgument(message).to_string())
}

/// `!wmitrace.logdump`'s logger, once the whole line checks out.
#[grammar(usage = "<logger-id|logger-name|context-address>", complete = [None])]
fn logdump_logger(
    cx: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<EtwLoggerRef, ArgError> {
    let (logger, _) = logdump_line(cursor.words()).map_err(logdump_error)?;
    let index = logger.ok_or(ArgError::Missing)?;
    let text = cursor.word_at(index).ok_or(ArgError::Missing)?;
    Ok(EtwLoggerRef {
        text: text.into_owned(),
        radix: cx.state.radix,
    })
}

/// `!wmitrace.logdump`'s `-t count`: the words left once
/// [`logdump_logger`] took the logger.
#[grammar(usage = "[-t <count>]", complete = [None])]
fn logdump_count(
    _: &mut ArgCx<'_, '_>,
    cursor: &mut ArgCursor<'_>,
) -> std::result::Result<Option<u64>, ArgError> {
    let (_, count) = logdump_line(cursor.words()).map_err(logdump_error)?;
    while cursor.word().is_some() {}
    Ok(count)
}

/// A logger's name or log file name, which may have been unreadable.
fn logger_name(name: Option<&str>) -> &str {
    name.unwrap_or(UNREADABLE_NAME)
}

/// A buffer in kernel memory, by its address.
fn kernel_buffer(address: VirtAddr) -> String {
    ui::addr(address.0)
}

/// A buffer of a minidump's ETW data, by its offset in the block.
fn dump_buffer(offset: VirtAddr) -> String {
    format!("+{:#x}", offset.0)
}

/// How the buffers of `logger` are named: by kernel address, or by offset
/// in a minidump's ETW data.
fn buffer_at(logger: &EtwSession) -> fn(VirtAddr) -> String {
    match logger {
        EtwSession::Active(_) => kernel_buffer,
        EtwSession::Saved(_) => dump_buffer,
    }
}

/// `!wmitrace.strdump`: every active logger.
fn print_loggers(table: &EtwLoggerTable) {
    outln!(
        "{} loggers active of {} (EtwpLoggerContext {}, host silo state {})",
        table.loggers.len(),
        table.max_loggers,
        ui::addr(table.context_array.0),
        ui::addr(table.silo_state.0)
    );
    let mut builder = Builder::default();
    builder.push_record([
        "Id", "Context", "Name", "Mode", "BufSize", "Buffers", "InUse", "Free", "Written", "Lost",
        "LogFile",
    ]);
    for logger in &table.loggers {
        builder.push_record([
            format!("{:#04x}", logger.logger_id),
            ui::addr(logger.address.0),
            logger_name(logger.name.as_deref()).to_string(),
            format!("{:#010x}", logger.logger_mode),
            format!("{} KB", logger.buffer_size / 1024),
            logger.number_of_buffers.to_string(),
            logger.buffers_in_use().to_string(),
            logger.buffers_available.to_string(),
            logger.buffers_written.to_string(),
            logger.events_lost.to_string(),
            logger_name(logger.log_file_name.as_deref()).to_string(),
        ]);
    }
    outln!();
    print_padded_table(builder);
}

/// `!wmitrace.strdump <logger>`: the buffers on the logger's GlobalList.
fn print_logger_buffers(detail: &EtwLoggerBuffers) {
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

/// `!wmitrace.logger`: the configuration and counters of the logger.
fn print_logger(logger: &EtwLogger) {
    print_logger_title(logger);
    let row =
        |label: &str, value: String| outln!("  {} {}", ui::muted(&format!("{label:<25}")), value);
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
    row(
        "InstanceGuid",
        format_guid(&logger.instance_guid, GuidStyle::Braced),
    );
    row(
        "LogFileName",
        match logger.log_file_name.as_deref() {
            Some("") => ui::muted("(none)"),
            Some(name) => name.to_string(),
            None => ui::muted(UNREADABLE_NAME),
        },
    );
    outln!();
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
fn print_events(dump: &EtwEventDump) {
    let clock = dump.logger.clock();
    let frequency = match clock {
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
        clock.name(),
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
    print_issues(
        dump.list_stop.as_deref(),
        &dump.issues,
        buffer_at(&dump.logger),
    );
    if let Some(note) = &dump.message_format_note {
        outln!("  {}", ui::muted(note));
    }
    outln!();
}

fn print_logger_title(logger: &EtwLogger) {
    outln!(
        "Logger {:#04x} @ {} '{}'",
        logger.logger_id,
        ui::addr(logger.address.0),
        logger_name(logger.name.as_deref())
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
    let guid = record
        .guid
        .as_ref()
        .map(|guid| format_guid(guid, GuidStyle::Braced));
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
            let class = record.event_class.unwrap_or_default();
            format!(
                "{} type {} level {} version {}",
                guid.unwrap_or_default(),
                class.r#type,
                class.level,
                class.version
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
        ui::muted(record.kind.as_str()),
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
        let (hex, ascii) = hex_ascii_row(chunk, HexCase::Lower);
        outln!("    {:04x}  {hex:<47}  {ascii}", row * 16);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_logdump_lines() {
        let parse = |words: &[&str]| logdump_line(words.iter().copied());
        assert_eq!(parse(&[]).unwrap(), (None, None));
        assert_eq!(parse(&["-t", "5"]).unwrap(), (None, Some(5)));
        assert_eq!(parse(&["0x24"]).unwrap(), (Some(0), None));
        assert_eq!(
            parse(&["-t", "0x10", "NT Kernel Logger"]).unwrap(),
            (Some(2), Some(0x10))
        );
        assert_eq!(
            parse(&["NtfsLog", "-T", "10"]).unwrap(),
            (Some(0), Some(10))
        );
        assert!(parse(&["NtfsLog", "-t"]).is_err());
        assert!(parse(&["-t", "ten", "NtfsLog"]).is_err());
        assert!(
            parse(&["NT", "Kernel", "-t"])
                .unwrap_err()
                .starts_with("unexpected argument 'Kernel'")
        );
    }
}
