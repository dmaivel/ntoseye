use std::io::{Read, Write};

use crate::dbg_backend::{BugcheckInfo, DebugLog};
use crate::error::{Error, Result};
use crate::kd::framing::{KdFraming, PACKET_TYPE_KD_DEBUG_IO, PACKET_TYPE_KD_FILE_IO};
use crate::kd::wire::{read_u16, read_u32, write_u16, write_u32};

use super::{
    DBGKD_CLOSE_FILE_API, DBGKD_CREATE_FILE_API, DBGKD_DEBUG_IO_HEADER_SIZE,
    DBGKD_DEBUG_IO_MIN_HEADER_SIZE, DBGKD_FILE_IO_HEADER_SIZE, DBGKD_GET_STRING_API,
    DBGKD_PRINT_STRING_API, DBGKD_READ_FILE_API, DBGKD_WRITE_FILE_API, KD_REFRESH_MESSAGE,
    STATUS_UNSUCCESSFUL,
};

pub enum DebugIo<'a> {
    PrintString {
        text: &'a [u8],
    },
    GetString {
        processor_level: u16,
        processor: u16,
        prompt: &'a [u8],
    },
}

#[derive(Default)]
pub struct BugcheckCapture {
    text: String,
    info: Option<BugcheckInfo>,
    pending_driver: Option<String>,
}

impl BugcheckCapture {
    pub fn observe_debug_text(&mut self, text: &[u8]) {
        let text = String::from_utf8_lossy(text);
        self.text.push_str(&text);
        if self.text.len() > 8192 {
            // Advance to the next char boundary so draining never splits a
            // multi-byte sequence (from_utf8_lossy can emit 3-byte U+FFFD)
            let mut keep_from = self.text.len() - 8192;
            while !self.text.is_char_boundary(keep_from) {
                keep_from += 1;
            }
            self.text.drain(..keep_from);
        }

        if self.info.is_none()
            && let Some((code, parameters)) = parse_bugcheck_fatal_system_error(&self.text)
        {
            self.info = Some(BugcheckInfo {
                code,
                parameters,
                driver: self.pending_driver.clone(),
            });
        }

        if let Some(driver) = parse_bugcheck_driver(&self.text) {
            self.pending_driver = Some(driver.clone());
            if let Some(info) = self.info.as_mut() {
                info.driver = Some(driver);
            }
        }
    }

    pub fn finish(&self) -> Option<BugcheckInfo> {
        self.info.clone()
    }

    pub fn code(&self) -> Option<u32> {
        self.info.as_ref().map(|info| info.code)
    }

    fn should_suppress_output(&self) -> bool {
        self.text.contains("*** Fatal System Error:") || self.text.contains("Driver at fault:")
    }
}

fn parse_first_hex_u64(text: &str) -> Option<u64> {
    let marker = text
        .find("0x")
        .or_else(|| text.find("0X"))
        .map(|idx| idx + 2)?;
    let hex: String = text[marker..]
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect();
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

fn parse_hex_u64(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let hex: String = hex
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect();
    if hex.is_empty() {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

fn parse_bugcheck_fatal_system_error(text: &str) -> Option<(u32, [u64; 4])> {
    let marker = "*** Fatal System Error:";
    let rest = &text[text.find(marker)? + marker.len()..];
    let code = parse_first_hex_u64(rest)? as u32;
    let params_start = rest.find('(')? + 1;
    let params_end = rest[params_start..].find(')')? + params_start;
    let mut params = [0u64; 4];
    let mut count = 0usize;
    for (slot, value) in params
        .iter_mut()
        .zip(rest[params_start..params_end].split(','))
    {
        *slot = parse_hex_u64(value)?;
        count += 1;
    }
    (count == 4).then_some((code, params))
}

fn parse_bugcheck_driver(text: &str) -> Option<String> {
    let marker = "Driver at fault:";
    let rest = &text[text.find(marker)? + marker.len()..];
    let line = rest.lines().next().unwrap_or(rest);
    let driver = line.trim().trim_end_matches('.').trim();
    (!driver.is_empty()).then(|| driver.to_string())
}

pub fn handle_debug_io<T: Read + Write>(
    framing: &mut KdFraming<T>,
    payload: &[u8],
    detect_kd_refresh: bool,
) -> Result<bool> {
    let mut stderr = std::io::stderr();
    handle_debug_io_with_output(
        framing,
        payload,
        detect_kd_refresh,
        None,
        false,
        None,
        &mut stderr,
    )
}

pub fn handle_debug_io_with_output<T: Read + Write, W: Write>(
    framing: &mut KdFraming<T>,
    payload: &[u8],
    detect_kd_refresh: bool,
    bugcheck_capture: Option<&mut BugcheckCapture>,
    suppress_bugcheck_text: bool,
    debug_log: Option<&DebugLog>,
    output: &mut W,
) -> Result<bool> {
    let mut kd_refresh_seen = false;
    match parse_debug_io(payload) {
        Some(DebugIo::PrintString { text }) => {
            // Capture into the log regardless of terminal suppression: the ring
            // is the complete record, while `suppress_bugcheck_text` only keeps
            // the raw crash spam off stderr next to the structured analysis.
            if let Some(log) = debug_log {
                log.record(text);
            }
            let mut suppress_output = false;
            if let Some(capture) = bugcheck_capture {
                capture.observe_debug_text(text);
                suppress_output = suppress_bugcheck_text && capture.should_suppress_output();
            }
            if !suppress_output {
                output.write_all(text)?;
            }
            kd_refresh_seen = detect_kd_refresh
                && text
                    .windows(KD_REFRESH_MESSAGE.len())
                    .any(|w| w == KD_REFRESH_MESSAGE);
            if kd_refresh_seen {
                // recv_data already ACKed this packet before we got here, so
                // reaching this point means we serviced the refresh promptly.
                // If the kernel still won't break in on its own afterwards,
                // KdDebuggerNotPresent was already TRUE before the refresh
                kd_trace!("kd: debug_io: refresh print read and ACKed");
            }
        }
        Some(DebugIo::GetString {
            processor_level,
            processor,
            prompt,
        }) => {
            output.write_all(prompt)?;
            let response = get_string_auto_response(prompt);
            send_debug_io_response(framing, processor_level, processor, response)?;
        }
        None => {}
    }
    Ok(kd_refresh_seen)
}

fn debug_io_data(payload: &[u8], len: usize) -> &[u8] {
    let offset = if payload.len() >= DBGKD_DEBUG_IO_HEADER_SIZE + len {
        DBGKD_DEBUG_IO_HEADER_SIZE
    } else {
        DBGKD_DEBUG_IO_MIN_HEADER_SIZE.min(payload.len())
    };
    let end = offset.saturating_add(len).min(payload.len());
    &payload[offset..end]
}

pub fn parse_debug_io(payload: &[u8]) -> Option<DebugIo<'_>> {
    // DBGKD_DEBUG_IO:
    //   ULONG ApiNumber          @ 0
    //   USHORT ProcessorLevel    @ 4
    //   USHORT Processor         @ 6
    //   union                    @ 8
    // The full header is 16 bytes because DbgKdGetStringApi's union member
    // is 8 bytes. Some old stubs only send the 12-byte print-string prefix,
    // so the text offset accepts both layouts.
    if payload.len() < DBGKD_DEBUG_IO_MIN_HEADER_SIZE {
        return None;
    }
    let api = read_u32(payload, 0);
    let processor_level = read_u16(payload, 4);
    let processor = read_u16(payload, 6);
    match api {
        DBGKD_PRINT_STRING_API => {
            let len = read_u32(payload, 8) as usize;
            Some(DebugIo::PrintString {
                text: debug_io_data(payload, len),
            })
        }
        DBGKD_GET_STRING_API if payload.len() >= DBGKD_DEBUG_IO_HEADER_SIZE => {
            let len = read_u32(payload, 8) as usize;
            Some(DebugIo::GetString {
                processor_level,
                processor,
                prompt: debug_io_data(payload, len),
            })
        }
        _ => None,
    }
}

fn get_string_auto_response(prompt: &[u8]) -> &'static [u8] {
    let text = std::str::from_utf8(prompt).unwrap_or("");
    if text.contains("(bic)") || text.contains("(BiC)") {
        b"b"
    } else {
        b""
    }
}

fn send_debug_io_response<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor_level: u16,
    processor: u16,
    response: &[u8],
) -> Result<()> {
    let mut reply = vec![0u8; DBGKD_DEBUG_IO_HEADER_SIZE + response.len()];
    write_u32(&mut reply, 0, DBGKD_GET_STRING_API);
    write_u16(&mut reply, 4, processor_level);
    write_u16(&mut reply, 6, processor);
    write_u32(&mut reply, 12, response.len() as u32);
    reply[DBGKD_DEBUG_IO_HEADER_SIZE..].copy_from_slice(response);
    framing.send_data(PACKET_TYPE_KD_DEBUG_IO, &reply)
}

pub fn handle_file_io<T: Read + Write>(framing: &mut KdFraming<T>, payload: &[u8]) -> Result<()> {
    if payload.len() < 8 {
        return Err(Error::Kd(format!(
            "KD file I/O payload too short: {} bytes",
            payload.len()
        )));
    }

    let api = read_u32(payload, 0);
    let mut reply = [0u8; DBGKD_FILE_IO_HEADER_SIZE];
    write_u32(&mut reply, 0, api);
    write_u32(&mut reply, 4, STATUS_UNSUCCESSFUL);

    kd_trace!(
        "kd: file_io: failing {} request",
        match api {
            DBGKD_CREATE_FILE_API => "CreateFile",
            DBGKD_READ_FILE_API => "ReadFile",
            DBGKD_WRITE_FILE_API => "WriteFile",
            DBGKD_CLOSE_FILE_API => "CloseFile",
            _ => "unknown",
        }
    );

    framing.send_data(PACKET_TYPE_KD_FILE_IO, &reply)
}
