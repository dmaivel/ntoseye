//! The ETW sessions a minidump keeps. A minidump holds none of the kernel's
//! pool, so the `_WMI_LOGGER_CONTEXT`s and buffers the `!wmitrace` commands
//! read are not in it. Instead, nt's `EtwpBugCheckMultiPartCallback` adds
//! them as tagged data, under `nt!EtwSecondaryDumpDataGuid`, for each
//! session started with `EVENT_TRACE_ADDTO_TRIAGE_DUMP` whose buffers are in
//! nonpaged pool (Windows' own are EventLog-System, WiFiSession,
//! CldFltLog and the RDP display driver's).
//!
//! The block starts with a 0x20-byte header: `KeMaximumIncrement`,
//! `NtBuildNumber`, `EtwCPUSpeedInMHz`, 4 bytes of padding, `EtwpBootTime` and
//! `EtwPerfFreq`. Each session follows with a 0x30-byte header: the
//! signature 0x01EBAFE1, then `LoggerId`, `LoggerMode`, `ClockType`,
//! `BufferSize`, the byte length of `LoggerName`, `StartTime` and
//! `ReferenceTime`, then `LoggerName`'s characters. After it comes each
//! buffer on the session's `GlobalList`, a `_WMI_BUFFER_HEADER` and its
//! events, cut at the end of its data: its `SavedOffset` once `CurrentOffset`
//! is past the buffer, else `CurrentOffset`. The callback also stores that
//! length in the buffer's `Offset`. The buffers are the ones a full or kernel
//! dump holds in memory.

use std::sync::Arc;

use super::{
    BufferHeaderOffsets, EtwBuffer, EtwClock, EtwEvents, EtwLogFile, EventCollector, LogFileLogger,
    LogFileSystem, MAX_BUFFER_SIZE, TimeBase, etw_buffer,
};
use crate::bytes::{read_u32, read_u64};
use crate::error::{Error, Result};
use crate::expr::{Expr, NumberRadix};
use crate::kuser_shared::KuserSharedData;
use crate::target::Target;
use crate::types::VirtAddr;

/// `nt!EtwSecondaryDumpDataGuid`, {2B88B710-1C93-4F7C-B06C-655ECC50DECC},
/// as it lies in memory.
const ETW_DUMP_DATA_TAG: [u8; 16] = [
    0x10, 0xb7, 0x88, 0x2b, 0x93, 0x1c, 0x7c, 0x4f, 0xb0, 0x6c, 0x65, 0x5e, 0xcc, 0x50, 0xde, 0xcc,
];

const HEADER_SIZE: usize = 0x20;
const LOGGER_HEADER_SIZE: usize = 0x30;
/// The first field of a session's header. It is above ETW's 16 MB largest
/// buffer, so no buffer's `BufferSize` can be taken for it.
const LOGGER_SIGNATURE: u32 = 0x01eb_afe1;

/// The sessions of a minidump's ETW data, and the system fields that the
/// logfile header of an .etl records.
#[derive(Debug, Clone)]
pub struct EtwDumpData {
    /// `KeMaximumIncrement`, the clock interrupt interval in 100 ns.
    pub timer_resolution: u32,
    /// `NtBuildNumber`, its top nibble the free or checked build.
    pub build_number: u32,
    /// `EtwCPUSpeedInMHz`.
    pub cpu_mhz: u32,
    /// `EtwpBootTime`, a FILETIME.
    pub boot_time: u64,
    /// `EtwPerfFreq`, the QPC frequency.
    pub perf_frequency: u64,
    pub loggers: Vec<EtwDumpLogger>,
    /// Why the walk of the block ended before its end.
    pub stop: Option<String>,
    data: Arc<[u8]>,
}

/// A session of a minidump's ETW data: what its header records of its
/// `_WMI_LOGGER_CONTEXT`, and its buffers.
#[derive(Debug, Clone)]
pub struct EtwDumpLogger {
    pub logger_id: u32,
    pub name: String,
    pub logger_mode: u32,
    pub clock: EtwClock,
    pub buffer_size: u32,
    /// `StartTime`, a FILETIME.
    pub start_time: u64,
    /// `ReferenceTime`: the system time (FILETIME) at the clock value
    /// `reference_clock`.
    pub reference_system_time: u64,
    pub reference_clock: u64,
    /// The buffers, each [`EtwBuffer::address`] the offset of its header in
    /// the block, and `data_end` its bytes in the block.
    pub buffers: Vec<EtwBuffer>,
}

impl EtwDumpLogger {
    fn time_base(&self, data: &EtwDumpData) -> TimeBase {
        TimeBase {
            clock: self.clock,
            reference_system_time: self.reference_system_time,
            reference_clock: self.reference_clock,
            qpc_frequency: Some(data.perf_frequency),
            cpu_mhz: Some(u64::from(data.cpu_mhz)),
        }
    }
}

impl EtwDumpData {
    /// Size of the block in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// The header and events of `buffer`, one of this block's.
    fn buffer_bytes(&self, buffer: &EtwBuffer) -> &[u8] {
        let start = buffer.address.0 as usize;
        &self.data[start..start + buffer.data_end as usize]
    }

    /// The session `text` names: its name (without case), or its logger id
    /// as `evaluate` reads it.
    pub fn logger(
        &self,
        text: &str,
        evaluate: impl FnOnce(&str) -> Result<VirtAddr>,
    ) -> Result<&EtwDumpLogger> {
        if let Some(logger) = self
            .loggers
            .iter()
            .find(|logger| logger.name.eq_ignore_ascii_case(text))
        {
            return Ok(logger);
        }
        let value = evaluate(text).map_err(|e| {
            Error::InvalidArgument(format!(
                "'{text}' is not the name of a session in the dump's ETW data, and not a \
                 logger id: {e}"
            ))
        })?;
        self.loggers
            .iter()
            .find(|logger| u64::from(logger.logger_id) == value.0)
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "the dump's ETW data has no session with logger id {:#x}; it holds {}",
                    value.0,
                    self.loggers
                        .iter()
                        .map(|logger| format!("{:#04x}", logger.logger_id))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })
    }
}

/// Parse the block `data`, reading each buffer header at `offsets` and
/// naming its state from `buffer_states`. A part that is neither a session
/// header nor a buffer of the session before it ends the walk, keeping
/// what came before.
fn parse_dump_data(
    data: Arc<[u8]>,
    offsets: &BufferHeaderOffsets,
    buffer_states: &[(String, i64)],
) -> Result<EtwDumpData> {
    let bytes = &*data;
    if bytes.len() < HEADER_SIZE {
        return Err(Error::DebugInfo(format!(
            "the dump's ETW data is {:#x} bytes, short of its {HEADER_SIZE:#x}-byte header",
            bytes.len()
        )));
    }
    let mut loggers: Vec<EtwDumpLogger> = Vec::new();
    let mut stop = None;
    let mut at = HEADER_SIZE;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.len() >= 4 && read_u32(rest, 0) == LOGGER_SIGNATURE {
            let name_size = rest
                .get(0x14..0x18)
                .map_or(usize::MAX, |_| read_u32(rest, 0x14) as usize);
            let Some(name) = LOGGER_HEADER_SIZE
                .checked_add(name_size)
                .and_then(|end| rest.get(LOGGER_HEADER_SIZE..end))
            else {
                stop = Some(format!(
                    "the session header at +{at:#x} runs past the end of the block"
                ));
                break;
            };
            let name: Vec<u16> = name
                .as_chunks::<2>()
                .0
                .iter()
                .map(|unit| u16::from_le_bytes(*unit))
                .collect();
            let buffer_size = read_u32(rest, 0x10);
            if buffer_size as usize <= offsets.size || buffer_size > MAX_BUFFER_SIZE {
                stop = Some(format!(
                    "the session header at +{at:#x} has BufferSize {buffer_size:#x}, not a \
                     trace buffer size"
                ));
                break;
            }
            loggers.push(EtwDumpLogger {
                logger_id: read_u32(rest, 0x04),
                logger_mode: read_u32(rest, 0x08),
                clock: EtwClock::from_raw(read_u32(rest, 0x0c)),
                buffer_size,
                start_time: read_u64(rest, 0x18),
                reference_system_time: read_u64(rest, 0x20),
                reference_clock: read_u64(rest, 0x28),
                name: String::from_utf16_lossy(&name),
                buffers: Vec::new(),
            });
            at += LOGGER_HEADER_SIZE + name_size;
            continue;
        }
        let Some(logger) = loggers.last_mut() else {
            stop = Some(format!("no session header at +{at:#x}"));
            break;
        };
        if rest.len() < offsets.size {
            stop = Some(format!(
                "{:#x} bytes at +{at:#x} are too few for a buffer header",
                rest.len()
            ));
            break;
        }
        let header = offsets.header(rest);
        if let Err(e) = header.check_owner(logger.buffer_size, logger.logger_id) {
            stop = Some(format!(
                "+{at:#x} is neither a session header nor a buffer of logger {:#x} ({e})",
                logger.logger_id
            ));
            break;
        }
        let length = if header.current_offset > header.buffer_size {
            header.saved_offset
        } else {
            header.current_offset
        };
        // Logdump and logsave count on a buffer's data within BufferSize.
        if (length as usize) < offsets.size
            || length > header.buffer_size
            || length as usize > rest.len()
        {
            stop = Some(format!(
                "the buffer at +{at:#x} holds {length:#x} bytes, which do not fit between \
                 its header and the end of the buffer or the block"
            ));
            break;
        }
        logger.buffers.push(etw_buffer(
            buffer_states,
            VirtAddr(at as u64),
            &header,
            length,
        ));
        at += length as usize;
    }
    Ok(EtwDumpData {
        timer_resolution: read_u32(bytes, 0x00),
        build_number: read_u32(bytes, 0x04),
        cpu_mhz: read_u32(bytes, 0x08),
        boot_time: read_u64(bytes, 0x10),
        perf_frequency: read_u64(bytes, 0x18),
        loggers,
        stop,
        data,
    })
}

impl<'a> From<&'a EtwDumpLogger> for LogFileLogger<'a> {
    fn from(logger: &'a EtwDumpLogger) -> Self {
        // A consumer reads a circular log (FILE_MODE_CIRCULAR) only up to
        // its MaximumFileSize, which the block does not record: give the
        // size of a file of the header buffer and every buffer, in MB.
        let file_size = (logger.buffers.len() as u64 + 1) * u64::from(logger.buffer_size);
        Self {
            logger_id: logger.logger_id,
            name: &logger.name,
            log_file_name: "",
            buffer_size: logger.buffer_size,
            logger_mode: logger.logger_mode,
            maximum_file_size: file_size.div_ceil(1 << 20) as u32,
            events_lost: 0,
            log_buffers_lost: 0,
            clock: logger.clock,
            reference_system_time: logger.reference_system_time,
            reference_clock: logger.reference_clock,
        }
    }
}

impl Target {
    /// The ETW data of a minidump, where the `!wmitrace` commands read the
    /// sessions from; `None` for a live target and a full or kernel dump,
    /// whose memory holds the sessions themselves.
    pub fn etw_dump_data(&self) -> Result<Option<EtwDumpData>> {
        let Some(dump) = self.phys.dmp_info().filter(|dump| dump.is_triage) else {
            return Ok(None);
        };
        let block = dump
            .tagged_blocks
            .iter()
            .find(|block| block.tag == ETW_DUMP_DATA_TAG)
            .ok_or_else(|| {
                Error::DebugInfo(
                    "a minidump does not hold the kernel's ETW sessions, only the tagged data \
                     nt!EtwSecondaryDumpDataGuid of those that log to triage dumps, and this \
                     one has none"
                        .into(),
                )
            })?;
        let types = self.etw_types()?;
        parse_dump_data(
            Arc::clone(&block.data),
            &types.offsets,
            &types.buffer_states,
        )
        .map(Some)
    }

    /// `!wmitrace.logdump` in a minidump: the events in `logger`'s buffers,
    /// oldest first; `most_recent` keeps only that many of the newest.
    pub fn etw_dump_events(
        &self,
        data: &EtwDumpData,
        logger: &EtwDumpLogger,
        most_recent: Option<usize>,
    ) -> Result<EtwEvents> {
        let types = self.etw_types()?;
        let time = logger.time_base(data);
        let mut collector = EventCollector::default();
        for buffer in &logger.buffers {
            if collector.wants(&types, buffer) {
                collector.add(self, &types, &time, buffer, data.buffer_bytes(buffer));
            }
        }
        Ok(collector.finish(most_recent))
    }

    /// The session of `data` that `text` names: its name (without case), or
    /// its logger id evaluated with `radix`.
    pub fn etw_dump_logger<'d>(
        &self,
        data: &'d EtwDumpData,
        text: &str,
        radix: NumberRadix,
    ) -> Result<&'d EtwDumpLogger> {
        data.logger(text, |text| Expr::eval_with_radix(text, self, radix))
    }

    /// `!wmitrace.logsave` in a minidump: `logger`'s buffers as an .etl file.
    pub fn etw_dump_log_file(
        &self,
        data: &EtwDumpData,
        logger: &EtwDumpLogger,
    ) -> Result<EtwLogFile> {
        let types = self.etw_types()?;
        let processors = self
            .phys
            .dmp_info()
            .map_or(1, |dump| dump.number_processors);
        let system = LogFileSystem {
            build_number: data.build_number & 0xffff,
            processors,
            timer_resolution: data.timer_resolution,
            cpu_mhz: data.cpu_mhz,
            boot_time: data.boot_time,
            qpc_frequency: data.perf_frequency,
            ..LogFileSystem::from_kuser(&KuserSharedData::new(self))?
        };
        let (buffers, issues, bytes) = self.write_etl(
            &types,
            &LogFileLogger::from(logger),
            &system,
            &logger.buffers,
            |buffer, slot| {
                slot.copy_from_slice(data.buffer_bytes(buffer));
                Ok(())
            },
        )?;
        Ok(EtwLogFile {
            logger_id: logger.logger_id,
            name: Some(logger.name.clone()),
            buffer_size: logger.buffer_size,
            buffers,
            list_stop: data.stop.clone(),
            issues,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::etw::tests::buffer_offsets;

    fn logger_header(id: u32, mode: u32, clock: u32, buffer_size: u32, name: &str) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut bytes = Vec::new();
        for value in [
            LOGGER_SIGNATURE,
            id,
            mode,
            clock,
            buffer_size,
            name.len() as u32,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [0x01dd_555d_db0d_1ef0u64, 0x01dd_555d_db08_201e, 0x57_d982] {
            bytes.extend(value.to_le_bytes());
        }
        bytes.extend(name);
        bytes
    }

    /// A buffer of `length` bytes as the callback cuts it: header, then
    /// zeroed event bytes.
    fn buffer(id: u16, buffer_size: u32, saved: u32, current: u32, length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        bytes[0..4].copy_from_slice(&buffer_size.to_le_bytes());
        bytes[4..8].copy_from_slice(&saved.to_le_bytes());
        bytes[8..12].copy_from_slice(&current.to_le_bytes());
        bytes[0x18..0x20].copy_from_slice(&0xa0bu64.to_le_bytes());
        bytes[0x28..0x2a].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x2a..0x2c].copy_from_slice(&id.to_le_bytes());
        bytes[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes());
        bytes
    }

    fn header() -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [156_250u32, 0xf000_6658, 1997, 0] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [0x01dd_555d_daf8_2d40u64, 10_000_000] {
            bytes.extend(value.to_le_bytes());
        }
        bytes
    }

    fn states() -> Vec<(String, i64)> {
        vec![("EtwBufferStateGeneralLogging".into(), 1)]
    }

    #[test]
    fn parses_sessions_and_buffers_cut_at_their_data_end() {
        let mut block = header();
        block.extend(logger_header(
            0xa,
            0x9880_0180,
            2,
            0x1_0000,
            "EventLog-System",
        ));
        // A processor's current buffer, then one switched out (its
        // CurrentOffset past the buffer, its data length in SavedOffset).
        block.extend(buffer(0xa, 0x1_0000, 0, 0x6a8, 0x6a8));
        block.extend(buffer(0xa, 0x1_0000, 0xd08, 0x1_0d08, 0xd08));
        block.extend(logger_header(0x1d, 0x9080_0002, 1, 0x1000, "CldFltLog"));
        block.extend(buffer(0x1d, 0x1000, 0, 0x48, 0x48));
        let data = parse_dump_data(Arc::from(block), &buffer_offsets(), &states()).unwrap();

        assert_eq!(data.stop, None);
        assert_eq!(
            (
                data.timer_resolution,
                data.build_number & 0xffff,
                data.cpu_mhz,
                data.perf_frequency
            ),
            (156_250, 26200, 1997, 10_000_000)
        );
        assert_eq!(data.loggers.len(), 2);
        let system = &data.loggers[0];
        assert_eq!(
            (
                system.logger_id,
                system.name.as_str(),
                system.logger_mode,
                system.clock,
                system.buffer_size
            ),
            (
                0xa,
                "EventLog-System",
                0x9880_0180,
                EtwClock::SystemTime,
                0x1_0000
            )
        );
        assert_eq!(
            (
                system.start_time,
                system.reference_system_time,
                system.reference_clock
            ),
            (0x01dd_555d_db0d_1ef0, 0x01dd_555d_db08_201e, 0x57_d982)
        );
        let at: Vec<(u64, u32)> = system
            .buffers
            .iter()
            .map(|b| (b.address.0, b.data_end))
            .collect();
        assert_eq!(at, [(0x6e, 0x6a8), (0x6e + 0x6a8, 0xd08)]);
        let first = &system.buffers[0];
        assert_eq!(
            (
                first.state_name.as_str(),
                first.processor,
                first.sequence_number
            ),
            ("GeneralLogging", 2, 0xa0b)
        );
        assert_eq!(data.buffer_bytes(first).len(), 0x6a8);
        let cldflt = &data.loggers[1];
        assert_eq!(
            (cldflt.clock, cldflt.buffers.len()),
            (EtwClock::PerformanceCounter, 1)
        );
    }

    #[test]
    fn stops_at_a_part_that_is_no_buffer_of_the_session_before_it() {
        let mut block = header();
        block.extend(logger_header(0xa, 0, 2, 0x1_0000, "EventLog-System"));
        block.extend(buffer(0xa, 0x1_0000, 0, 0x48, 0x48));
        // Another logger's buffer where one of 0xa's should be.
        block.extend(buffer(0x15, 0x1_0000, 0, 0x48, 0x48));
        let data = parse_dump_data(Arc::from(block), &buffer_offsets(), &[]).unwrap();
        assert_eq!(data.loggers[0].buffers.len(), 1);
        assert!(data.stop.unwrap().contains("+0xb6"));

        // A buffer whose data runs past the end of the block.
        let mut block = header();
        block.extend(logger_header(0xa, 0, 2, 0x1_0000, "EventLog-System"));
        let mut cut = buffer(0xa, 0x1_0000, 0, 0x100, 0x100);
        cut.truncate(0x80);
        block.extend(cut);
        let data = parse_dump_data(Arc::from(block), &buffer_offsets(), &[]).unwrap();
        assert!(data.loggers[0].buffers.is_empty());
        assert!(data.stop.is_some());

        // Buffers before any session header, and a block short of its header.
        let mut block = header();
        block.extend(buffer(0xa, 0x1_0000, 0, 0x48, 0x48));
        let data = parse_dump_data(Arc::from(block), &buffer_offsets(), &[]).unwrap();
        assert!(data.loggers.is_empty());
        assert!(data.stop.is_some());
        assert!(parse_dump_data(Arc::from(vec![0u8; 0x10]), &buffer_offsets(), &[]).is_err());
    }
}
