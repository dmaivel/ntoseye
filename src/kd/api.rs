#![allow(dead_code)]

// `DBGKD_MANIPULATE_STATE64` is 56 bytes: 12-byte prefix, 4 bytes padding,
// then a 40-byte per-API union.

use std::io::{Read, Write};

use crate::dbg_backend::ContinueDisposition;
use crate::error::{Error, Result};
use crate::kd::{
    framing::{
        DataPacket, KdFraming, PACKET_TYPE_KD_DEBUG_IO, PACKET_TYPE_KD_FILE_IO,
        PACKET_TYPE_KD_STATE_MANIPULATE,
    },
    handle_debug_io, handle_file_io,
    wire::{read_u16, read_u32, read_u64, write_u16, write_u32, write_u64},
};

pub const DBGKD_READ_VIRTUAL_MEMORY: u32 = 0x0000_3130;
pub const DBGKD_WRITE_VIRTUAL_MEMORY: u32 = 0x0000_3131;
pub const DBGKD_GET_CONTEXT: u32 = 0x0000_3132;
pub const DBGKD_WRITE_BREAKPOINT: u32 = 0x0000_3134;
pub const DBGKD_RESTORE_BREAKPOINT: u32 = 0x0000_3135;
pub const DBGKD_READ_CONTROL_SPACE: u32 = 0x0000_3137;
pub const DBGKD_WRITE_CONTROL_SPACE: u32 = 0x0000_3138;
pub const DBGKD_CONTINUE_API2: u32 = 0x0000_313C;
pub const DBGKD_READ_PHYSICAL_MEMORY: u32 = 0x0000_313D;
pub const DBGKD_WRITE_PHYSICAL_MEMORY: u32 = 0x0000_313E;
pub const DBGKD_GET_VERSION: u32 = 0x0000_3146;
pub const DBGKD_SWITCH_PROCESSOR: u32 = 0x0000_3150;
pub const DBGKD_READ_MACHINE_SPECIFIC_REGISTER: u32 = 0x0000_3152;
pub const DBGKD_SET_CONTEXT_EX: u32 = 0x0000_3160;

pub const DBGKD_VERS_FLAG_DATA: u16 = 0x0002;

/// `DBGKD_MANIPULATE_STATE64` wire size
pub const MANIPULATE_HEADER_SIZE: usize = 56;

const CONTEXT_EX_CHUNK_SIZE: usize = 512;
const CONTEXT_EX_MAX_SIZE: u32 = 0x3000;
/// Per-API union offset in `DBGKD_MANIPULATE_STATE64`
const UNION_OFFSET: usize = 16;

pub const DBG_CONTINUE: u32 = 0x0001_0002;
pub const DBG_EXCEPTION_NOT_HANDLED: u32 = 0x8001_0001;

pub fn status_for_disposition(disposition: ContinueDisposition) -> u32 {
    match disposition {
        ContinueDisposition::Handled => DBG_CONTINUE,
        ContinueDisposition::NotHandled => DBG_EXCEPTION_NOT_HANDLED,
    }
}
pub const STATUS_SUCCESS: u32 = 0x0000_0000;

/// Build a zeroed manipulate-state request header
fn make_header(api_number: u32, processor: u16) -> [u8; MANIPULATE_HEADER_SIZE] {
    let mut hdr = [0u8; MANIPULATE_HEADER_SIZE];
    write_u32(&mut hdr, 0, api_number);
    // ProcessorLevel left zero; debuggers conventionally pass 0
    write_u16(&mut hdr, 6, processor);
    // ReturnStatus left zero on requests
    hdr
}

#[derive(Debug, Clone, Copy)]
pub struct ManipulateHeader {
    pub api_number: u32,
    pub processor: u16,
    pub return_status: u32,
}

impl ManipulateHeader {
    fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < MANIPULATE_HEADER_SIZE {
            return Err(Error::Kd(format!(
                "manipulate header too short: {} bytes",
                buf.len()
            )));
        }
        Ok(Self {
            api_number: read_u32(buf, 0),
            processor: read_u16(buf, 6),
            return_status: read_u32(buf, 8),
        })
    }
}

fn recv_manipulate_reply(
    framing: &mut KdFraming<impl Read + Write>,
    requested_processor: u16,
) -> Result<(ManipulateHeader, Vec<u8>, Vec<u8>)> {
    loop {
        let pkt = framing.recv_data()?;
        match pkt.packet_type {
            PACKET_TYPE_KD_STATE_MANIPULATE => {
                if pkt.payload.len() < MANIPULATE_HEADER_SIZE {
                    return Err(Error::Kd(format!(
                        "short manipulate reply: {} bytes",
                        pkt.payload.len()
                    )));
                }
                let parsed = ManipulateHeader::decode(&pkt.payload)?;
                if parsed.processor != requested_processor {
                    return Err(Error::Kd(format!(
                        "reply processor mismatch: expected {}, got {}",
                        requested_processor, parsed.processor
                    )));
                }
                let reply_header = pkt.payload[..MANIPULATE_HEADER_SIZE].to_vec();
                let reply_data = pkt.payload[MANIPULATE_HEADER_SIZE..].to_vec();
                return Ok((parsed, reply_header, reply_data));
            }
            PACKET_TYPE_KD_DEBUG_IO => {
                // Debug print emitted mid-request
                handle_debug_io(framing, &pkt.payload, false)?;
                continue;
            }
            PACKET_TYPE_KD_FILE_IO => {
                handle_file_io(framing, &pkt.payload)?;
                continue;
            }
            other => {
                return Err(Error::Kd(format!(
                    "unexpected packet type while awaiting manipulate reply: {}",
                    other
                )));
            }
        }
    }
}

/// Send a manipulate-state request and wait for the matching reply
fn send_manipulate(
    framing: &mut KdFraming<impl Read + Write>,
    header: &[u8; MANIPULATE_HEADER_SIZE],
    data: &[u8],
) -> Result<(ManipulateHeader, Vec<u8>, Vec<u8>)> {
    let requested_processor = read_u16(header, 6);
    let mut payload = Vec::with_capacity(MANIPULATE_HEADER_SIZE + data.len());
    payload.extend_from_slice(header);
    payload.extend_from_slice(data);
    framing.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &payload)?;
    recv_manipulate_reply(framing, requested_processor)
}

fn check_status(header: &ManipulateHeader, api: u32) -> Result<()> {
    if header.api_number != api {
        return Err(Error::Kd(format!(
            "reply api mismatch: expected {:#x}, got {:#x}",
            api, header.api_number
        )));
    }
    if (header.return_status & 0x8000_0000) != 0 {
        return Err(Error::KdStatus {
            ntstatus: header.return_status,
            api,
        });
    }
    Ok(())
}

pub fn recv_packet<T: Read + Write>(framing: &mut KdFraming<T>) -> Result<DataPacket> {
    framing.recv_data()
}

#[derive(Debug, Clone, Copy)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub protocol_version: u8,
    pub kd_secondary_version: u8,
    pub flags: u16,
    pub machine_type: u16,
    pub max_packet_type: u8,
    pub max_state_change: u8,
    pub max_manipulate: u8,
    pub simulation: u8,
    pub kern_base: u64,
    pub ps_loaded_module_list: u64,
    pub debugger_data_list: u64,
}

pub fn get_version<T: Read + Write>(framing: &mut KdFraming<T>, processor: u16) -> Result<Version> {
    let header = make_header(DBGKD_GET_VERSION, processor);
    let (parsed, reply_header, _) = send_manipulate(framing, &header, &[])?;
    check_status(&parsed, DBGKD_GET_VERSION)?;

    let u = UNION_OFFSET;
    Ok(Version {
        major: read_u16(&reply_header, u),
        minor: read_u16(&reply_header, u + 2),
        protocol_version: reply_header[u + 4],
        kd_secondary_version: reply_header[u + 5],
        flags: read_u16(&reply_header, u + 6),
        machine_type: read_u16(&reply_header, u + 8),
        max_packet_type: reply_header[u + 10],
        max_state_change: reply_header[u + 11],
        max_manipulate: reply_header[u + 12],
        simulation: reply_header[u + 13],
        kern_base: read_u64(&reply_header, u + 16),
        ps_loaded_module_list: read_u64(&reply_header, u + 24),
        debugger_data_list: read_u64(&reply_header, u + 32),
    })
}

/// `DbgKdReadMachineSpecificRegister` (`rdmsr` in WinDbg).
///
/// On ARM64, `register` is the Windows KD encoding of an AArch64 system
/// register rather than an x86 MSR number.
pub fn read_machine_specific_register<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    register: u32,
) -> Result<u64> {
    let mut header = make_header(DBGKD_READ_MACHINE_SPECIFIC_REGISTER, processor);
    write_u32(&mut header, UNION_OFFSET, register);
    let (parsed, reply_header, _) = send_manipulate(framing, &header, &[])?;
    check_status(&parsed, DBGKD_READ_MACHINE_SPECIFIC_REGISTER)?;
    let low = read_u32(&reply_header, UNION_OFFSET + 4) as u64;
    let high = read_u32(&reply_header, UNION_OFFSET + 8) as u64;
    Ok(low | high << 32)
}

pub fn get_context<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    context_flags: u32,
) -> Result<Vec<u8>> {
    let mut header = make_header(DBGKD_GET_CONTEXT, processor);
    write_u32(&mut header, UNION_OFFSET, context_flags);
    let (parsed, _, data) = send_manipulate(framing, &header, &[])?;
    check_status(&parsed, DBGKD_GET_CONTEXT)?;
    Ok(data)
}

/// Send one `DbgKdSetContextExApi` chunk.
///
/// Windows interprets `BytesCopied` in the request as the total staged context
/// size, not the current transfer length. It commits the staged context only
/// when `offset + data.len() == total_size`.
fn set_context_ex_chunk<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    offset: u32,
    total_size: u32,
    data: &[u8],
) -> Result<()> {
    let byte_count = u32::try_from(data.len())
        .map_err(|_| Error::Kd("context chunk exceeds KD's 32-bit length field".into()))?;
    let end = offset
        .checked_add(byte_count)
        .ok_or_else(|| Error::Kd("context chunk range overflow".into()))?;
    if byte_count == 0
        || offset >= total_size
        || end > total_size
        || total_size > CONTEXT_EX_MAX_SIZE
    {
        return Err(Error::Kd(format!(
            "invalid context chunk: offset={offset:#x}, len={byte_count:#x}, total={total_size:#x}"
        )));
    }

    let mut header = make_header(DBGKD_SET_CONTEXT_EX, processor);
    write_u32(&mut header, UNION_OFFSET, offset);
    write_u32(&mut header, UNION_OFFSET + 4, byte_count);
    write_u32(&mut header, UNION_OFFSET + 8, total_size);
    let (parsed, reply_header, _) = send_manipulate(framing, &header, data)?;
    check_status(&parsed, DBGKD_SET_CONTEXT_EX).map_err(|error| {
        Error::Kd(format!(
            "context-chunk write offset={offset:#x} len={byte_count:#x} total={total_size:#x} failed: {error}"
        ))
    })?;
    let bytes_copied = read_u32(&reply_header, UNION_OFFSET + 8);
    if bytes_copied != byte_count {
        return Err(Error::Kd(format!(
            "short context-chunk write: wrote {bytes_copied} of {byte_count} bytes at {offset:#x}"
        )));
    }
    Ok(())
}

/// Write a complete CONTEXT through bounded `DbgKdSetContextExApi` chunks.
///
/// Windows stages every chunk and atomically copies the context into the
/// selected processor when the final chunk reaches `total_size`.
pub fn set_context_chunked<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    context: &[u8],
) -> Result<()> {
    let total_size = u32::try_from(context.len())
        .map_err(|_| Error::Kd("CONTEXT exceeds KD's 32-bit length field".into()))?;
    if context.is_empty() || total_size > CONTEXT_EX_MAX_SIZE {
        return Err(Error::Kd(format!(
            "invalid CONTEXT size for chunked write: {total_size:#x}"
        )));
    }
    for (index, chunk) in context.chunks(CONTEXT_EX_CHUNK_SIZE).enumerate() {
        let offset = u32::try_from(index * CONTEXT_EX_CHUNK_SIZE)
            .map_err(|_| Error::Kd("context chunk offset exceeds 32 bits".into()))?;
        set_context_ex_chunk(framing, processor, offset, total_size, chunk)?;
    }
    Ok(())
}

/// `DbgKdReadVirtualMemoryApi`
pub fn read_virtual_memory<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    addr: u64,
    len: u32,
) -> Result<Vec<u8>> {
    let mut header = make_header(DBGKD_READ_VIRTUAL_MEMORY, processor);
    write_u64(&mut header, UNION_OFFSET, addr);
    write_u32(&mut header, UNION_OFFSET + 8, len);
    let (parsed, reply_header, data) = send_manipulate(framing, &header, &[])?;
    check_status(&parsed, DBGKD_READ_VIRTUAL_MEMORY)?;
    let actual = read_u32(&reply_header, UNION_OFFSET + 12);
    if actual > len || data.len() != actual as usize || (len != 0 && actual == 0) {
        return Err(Error::Kd(format!(
            "invalid virtual-memory read at {addr:#x}: received {} bytes, target reported {actual} for request {len}",
            data.len()
        )));
    }
    Ok(data)
}

/// `DbgKdReadPhysicalMemoryApi`
pub fn read_physical_memory<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    addr: u64,
    len: u32,
) -> Result<Vec<u8>> {
    let mut header = make_header(DBGKD_READ_PHYSICAL_MEMORY, processor);
    write_u64(&mut header, UNION_OFFSET, addr);
    write_u32(&mut header, UNION_OFFSET + 8, len);
    let (parsed, reply_header, data) = send_manipulate(framing, &header, &[])?;
    check_status(&parsed, DBGKD_READ_PHYSICAL_MEMORY)?;
    let actual = read_u32(&reply_header, UNION_OFFSET + 12);
    if actual > len || data.len() != actual as usize || (len != 0 && actual == 0) {
        return Err(Error::Kd(format!(
            "invalid physical-memory read at {addr:#x}: received {} bytes, target reported {actual} for request {len}",
            data.len()
        )));
    }
    Ok(data)
}

/// `DbgKdWritePhysicalMemoryApi`
pub fn write_physical_memory<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    addr: u64,
    data: &[u8],
) -> Result<u32> {
    let len = u32::try_from(data.len())
        .map_err(|_| Error::Kd("physical-memory write exceeds KD's length field".into()))?;
    let mut header = make_header(DBGKD_WRITE_PHYSICAL_MEMORY, processor);
    write_u64(&mut header, UNION_OFFSET, addr);
    write_u32(&mut header, UNION_OFFSET + 8, len);
    let (parsed, reply_header, _) = send_manipulate(framing, &header, data)?;
    check_status(&parsed, DBGKD_WRITE_PHYSICAL_MEMORY)?;
    let actual = read_u32(&reply_header, UNION_OFFSET + 12);
    if actual > len || (len != 0 && actual == 0) {
        return Err(Error::Kd(format!(
            "invalid physical-memory write at {addr:#x}: target reported {actual} for request {len}"
        )));
    }
    Ok(actual)
}

/// `DbgKdReadControlSpaceApi`
pub fn read_control_space<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    base: u64,
    len: u32,
) -> Result<Vec<u8>> {
    let mut header = make_header(DBGKD_READ_CONTROL_SPACE, processor);
    write_u64(&mut header, UNION_OFFSET, base);
    write_u32(&mut header, UNION_OFFSET + 8, len);
    let (parsed, _, data) = send_manipulate(framing, &header, &[])?;
    check_status(&parsed, DBGKD_READ_CONTROL_SPACE)?;
    Ok(data)
}

/// `DbgKdWriteControlSpaceApi`
pub fn write_control_space<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    base: u64,
    data: &[u8],
) -> Result<u32> {
    let mut header = make_header(DBGKD_WRITE_CONTROL_SPACE, processor);
    write_u64(&mut header, UNION_OFFSET, base);
    write_u32(&mut header, UNION_OFFSET + 8, data.len() as u32);
    let (parsed, reply_header, _) = send_manipulate(framing, &header, data)?;
    check_status(&parsed, DBGKD_WRITE_CONTROL_SPACE)?;
    Ok(read_u32(&reply_header, UNION_OFFSET + 12))
}

/// `DbgKdWriteVirtualMemoryApi`
pub fn write_virtual_memory<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    addr: u64,
    data: &[u8],
) -> Result<u32> {
    let mut header = make_header(DBGKD_WRITE_VIRTUAL_MEMORY, processor);
    write_u64(&mut header, UNION_OFFSET, addr);
    write_u32(&mut header, UNION_OFFSET + 8, data.len() as u32);
    let (parsed, reply_header, _) = send_manipulate(framing, &header, data)?;
    check_status(&parsed, DBGKD_WRITE_VIRTUAL_MEMORY)?;
    Ok(read_u32(&reply_header, UNION_OFFSET + 12))
}

/// `DbgKdWriteBreakPointApi`
pub fn write_breakpoint<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    addr: u64,
) -> Result<u32> {
    let mut header = make_header(DBGKD_WRITE_BREAKPOINT, processor);
    write_u64(&mut header, UNION_OFFSET, addr);
    let (parsed, reply_header, _) = send_manipulate(framing, &header, &[])?;
    check_status(&parsed, DBGKD_WRITE_BREAKPOINT)?;
    Ok(read_u32(&reply_header, UNION_OFFSET + 8))
}

/// Receive a late `DbgKdWriteBreakPointApi` reply after the original wait
/// timed out. Used by the KD backend to complete an in-flight breakpoint install
/// without sending a duplicate request.
pub fn recv_write_breakpoint_reply<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
) -> Result<u32> {
    let (parsed, reply_header, _) = recv_manipulate_reply(framing, processor)?;
    check_status(&parsed, DBGKD_WRITE_BREAKPOINT)?;
    Ok(read_u32(&reply_header, UNION_OFFSET + 8))
}

/// `DbgKdRestoreBreakPointApi`
pub fn restore_breakpoint<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    handle: u32,
) -> Result<()> {
    let mut header = make_header(DBGKD_RESTORE_BREAKPOINT, processor);
    write_u32(&mut header, UNION_OFFSET, handle);
    let (parsed, _, _) = send_manipulate(framing, &header, &[])?;
    check_status(&parsed, DBGKD_RESTORE_BREAKPOINT)?;
    Ok(())
}

/// `DbgKdContinueApi2`
pub fn continue_api2<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    continue_status: u32,
    trace: bool,
    dr7: u64,
) -> Result<()> {
    let mut header = make_header(DBGKD_CONTINUE_API2, processor);
    // Packed AMD64_DBGKD_CONTROL_SET follows ContinueStatus:
    // TraceFlag (u32), Dr7 (u64), CurrentSymbolStart/End (u64 each).
    write_u32(&mut header, UNION_OFFSET, continue_status);
    write_u32(&mut header, UNION_OFFSET + 4, if trace { 1 } else { 0 });
    write_u64(&mut header, UNION_OFFSET + 8, dr7);
    let payload_len = MANIPULATE_HEADER_SIZE;
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&header);
    framing.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &payload)?;
    Ok(())
}

/// `DbgKdContinueApi2` for ARM64 targets. `ARM64_DBGKD_CONTROL_SET` packs
/// { ContinueStatus u32, TraceFlag u32, CurrentSymbolStart u64,
///   CurrentSymbolEnd u64 } — there is no Dr7 field (AArch64 has no x86-style
/// debug registers; watchpoints use DBGWCR/DBGWVR). The kernel performs
/// single-stepping via MDSCR_EL1 when TraceFlag is set.
pub fn continue_api2_arm64<T: Read + Write>(
    framing: &mut KdFraming<T>,
    processor: u16,
    continue_status: u32,
    trace: bool,
) -> Result<()> {
    let mut header = make_header(DBGKD_CONTINUE_API2, processor);
    write_u32(&mut header, UNION_OFFSET, continue_status);
    write_u32(&mut header, UNION_OFFSET + 4, if trace { 1 } else { 0 });
    // CurrentSymbolStart/End stay zero.
    let payload_len = MANIPULATE_HEADER_SIZE;
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&header);
    framing.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &payload)?;
    Ok(())
}

/// `DbgKdSwitchProcessor`: switch which processor subsequent register /
/// memory operations target. The kernel does *not* send a reply; it expects
/// the host to pick a different processor and resume the manipulate loop
pub fn switch_processor<T: Read + Write>(framing: &mut KdFraming<T>, target: u16) -> Result<()> {
    let header = make_header(DBGKD_SWITCH_PROCESSOR, target);
    framing.send_data(PACKET_TYPE_KD_STATE_MANIPULATE, &header)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

    use crate::kd::context;
    use crate::kd::framing::{
        KdFraming, PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_STATE_MANIPULATE,
    };

    #[test]
    fn continuation_disposition_selects_distinct_kd_wire_status() {
        for (disposition, expected_status) in [
            (ContinueDisposition::Handled, DBG_CONTINUE),
            (ContinueDisposition::NotHandled, DBG_EXCEPTION_NOT_HANDLED),
        ] {
            let ack = {
                let outbound_id = (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID;
                let mut header = [0u8; 16];
                header[0..4].copy_from_slice(&0x6969_6969u32.to_le_bytes());
                header[4..6].copy_from_slice(&PACKET_TYPE_KD_ACKNOWLEDGE.to_le_bytes());
                header[8..12].copy_from_slice(&outbound_id.to_le_bytes());
                header.to_vec()
            };
            let mut framing = KdFraming::new(Loopback::new(ack));
            continue_api2(
                &mut framing,
                0,
                status_for_disposition(disposition),
                false,
                0,
            )
            .unwrap();

            let outbound = &framing.transport_ref().outbound;
            let request = &outbound[16..16 + MANIPULATE_HEADER_SIZE];
            assert_eq!(read_u32(request, UNION_OFFSET), expected_status);
        }
    }

    struct Loopback {
        inbound: Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }

    impl Loopback {
        fn new(inbound: Vec<u8>) -> Self {
            Self {
                inbound: Cursor::new(inbound),
                outbound: Vec::new(),
            }
        }
    }

    impl Read for Loopback {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inbound.read(buf)
        }
    }

    impl Write for Loopback {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.outbound.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Compose a packet stream consisting of an ACK followed by a data
    /// packet; what we get back after sending a manipulate request that
    /// expects a reply
    fn ack_then_reply(outbound_id: u32, reply_id: u32, reply_payload: &[u8]) -> Vec<u8> {
        let mut stream = Vec::new();

        // ACK control packet
        let ack_hdr = [
            // control leader
            0x69,
            0x69,
            0x69,
            0x69,
            // packet type
            PACKET_TYPE_KD_ACKNOWLEDGE.to_le_bytes()[0],
            PACKET_TYPE_KD_ACKNOWLEDGE.to_le_bytes()[1],
            // byte count
            0,
            0,
            // packet id
            outbound_id.to_le_bytes()[0],
            outbound_id.to_le_bytes()[1],
            outbound_id.to_le_bytes()[2],
            outbound_id.to_le_bytes()[3],
            // checksum
            0,
            0,
            0,
            0,
        ];
        stream.extend_from_slice(&ack_hdr);

        // Data packet (reply)
        let checksum: u32 = reply_payload
            .iter()
            .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
        let mut data_hdr = [0u8; 16];
        data_hdr[0..4].copy_from_slice(&0x30303030u32.to_le_bytes());
        data_hdr[4..6].copy_from_slice(&PACKET_TYPE_KD_STATE_MANIPULATE.to_le_bytes());
        data_hdr[6..8].copy_from_slice(&(reply_payload.len() as u16).to_le_bytes());
        data_hdr[8..12].copy_from_slice(&reply_id.to_le_bytes());
        data_hdr[12..16].copy_from_slice(&checksum.to_le_bytes());
        stream.extend_from_slice(&data_hdr);
        stream.extend_from_slice(reply_payload);
        stream.push(0xAA);

        stream
    }

    fn build_reply(api: u32, processor: u16, union_body: &[u8], data: &[u8]) -> Vec<u8> {
        let mut payload = vec![0u8; MANIPULATE_HEADER_SIZE];
        write_u32(&mut payload, 0, api);
        write_u16(&mut payload, 6, processor);
        // ReturnStatus = 0 (success)
        let end = (UNION_OFFSET + union_body.len()).min(payload.len());
        payload[UNION_OFFSET..end].copy_from_slice(&union_body[..end - UNION_OFFSET]);
        payload.extend_from_slice(data);
        payload
    }

    const INITIAL_PACKET_ID: u32 = 0x80800000;
    const SYNC_PACKET_ID: u32 = 0x00000800;

    #[test]
    fn make_header_sets_fixed_prefix() {
        let h = make_header(0x3132, 2);
        assert_eq!(read_u32(&h, 0), 0x3132);
        assert_eq!(read_u16(&h, 6), 2);
        assert_eq!(h.len(), MANIPULATE_HEADER_SIZE);
    }

    #[test]
    fn get_version_round_trip() {
        // Reply union: GetVersion64 starting at UNION_OFFSET
        let mut union_body = vec![0u8; 40];
        union_body[0..2].copy_from_slice(&10u16.to_le_bytes()); // major
        union_body[2..4].copy_from_slice(&0u16.to_le_bytes()); // minor
        union_body[4] = 6; // protocol_version
        union_body[5] = 0; // secondary
        union_body[8..10].copy_from_slice(&0x8664u16.to_le_bytes()); // machine_type
        union_body[16..24].copy_from_slice(&0xfffff80012345000u64.to_le_bytes()); // kern_base
        union_body[24..32].copy_from_slice(&0xfffff80087654321u64.to_le_bytes()); // ps loaded
        union_body[32..40].copy_from_slice(&0xfffff800deadbeefu64.to_le_bytes()); // dbg data

        let reply = build_reply(DBGKD_GET_VERSION, 0, &union_body, &[]);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );

        let mut framing = KdFraming::new(Loopback::new(stream));
        let v = get_version(&mut framing, 0).unwrap();
        assert_eq!(v.major, 10);
        assert_eq!(v.protocol_version, 6);
        assert_eq!(v.machine_type, 0x8664);
        assert_eq!(v.kern_base, 0xfffff80012345000);
        assert_eq!(v.ps_loaded_module_list, 0xfffff80087654321);
        assert_eq!(v.debugger_data_list, 0xfffff800deadbeef);
    }

    #[test]
    fn read_machine_specific_register_round_trip() {
        let mut union_body = [0u8; 12];
        write_u32(&mut union_body, 0, 0x0003_0201);
        write_u32(&mut union_body, 4, 0x80d4_5800);
        write_u32(&mut union_body, 8, 0x0040_0000);
        let reply = build_reply(DBGKD_READ_MACHINE_SPECIFIC_REGISTER, 3, &union_body, &[]);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );
        let mut framing = KdFraming::new(Loopback::new(stream));

        let value = read_machine_specific_register(&mut framing, 3, 0x0003_0201).unwrap();

        assert_eq!(value, 0x0040_0000_80d4_5800);
        let request = &framing.transport_ref().outbound[16..16 + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(request, 0), DBGKD_READ_MACHINE_SPECIFIC_REGISTER);
        assert_eq!(read_u16(request, 6), 3);
        assert_eq!(read_u32(request, UNION_OFFSET), 0x0003_0201);
    }

    #[test]
    fn get_context_returns_reply_data() {
        let ctx_bytes: Vec<u8> = (0..1232u32).map(|i| (i & 0xff) as u8).collect();
        let reply = build_reply(DBGKD_GET_CONTEXT, 0, &[], &ctx_bytes);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );

        let mut framing = KdFraming::new(Loopback::new(stream));
        let ctx = get_context(&mut framing, 0, context::CONTEXT_ALL).unwrap();
        assert_eq!(ctx, ctx_bytes);

        let out = &framing.transport_ref().outbound;
        let req_header = &out[16..16 + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(req_header, UNION_OFFSET), context::CONTEXT_ALL);
    }

    #[test]
    fn set_context_ex_chunk_encodes_transfer_and_total_sizes() {
        let mut union_body = [0u8; 12];
        write_u32(&mut union_body, 8, 8);
        let reply = build_reply(DBGKD_SET_CONTEXT_EX, 1, &union_body, &[]);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );
        let mut framing = KdFraming::new(Loopback::new(stream));
        let rip = 0xffff_f801_a732_a0a1u64.to_le_bytes();

        set_context_ex_chunk(
            &mut framing,
            1,
            context::OFFSET_RIP as u32,
            context::CONTEXT_SIZE as u32,
            &rip,
        )
        .unwrap();

        let outbound = &framing.transport_ref().outbound;
        assert_eq!(
            read_u16(outbound, 6) as usize,
            MANIPULATE_HEADER_SIZE + rip.len()
        );
        let request = &outbound[16..16 + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(request, 0), DBGKD_SET_CONTEXT_EX);
        assert_eq!(read_u16(request, 6), 1);
        assert_eq!(read_u32(request, UNION_OFFSET), context::OFFSET_RIP as u32);
        assert_eq!(read_u32(request, UNION_OFFSET + 4), rip.len() as u32);
        assert_eq!(
            read_u32(request, UNION_OFFSET + 8),
            context::CONTEXT_SIZE as u32
        );
        assert_eq!(
            &outbound[16 + MANIPULATE_HEADER_SIZE..16 + MANIPULATE_HEADER_SIZE + rip.len()],
            &rip
        );
    }

    #[test]
    fn set_context_chunked_sends_ordered_chunks_and_commits_at_total_size() {
        let context: Vec<u8> = (0..context::CONTEXT_SIZE)
            .map(|index| (index & 0xff) as u8)
            .collect();
        let chunk_lengths: Vec<usize> = context
            .chunks(CONTEXT_EX_CHUNK_SIZE)
            .map(<[u8]>::len)
            .collect();
        let mut inbound = Vec::new();
        for (index, &chunk_len) in chunk_lengths.iter().enumerate() {
            let packet_id = INITIAL_PACKET_ID ^ (index as u32 & 1);
            let mut union_body = [0u8; 12];
            write_u32(&mut union_body, 8, chunk_len as u32);
            let reply = build_reply(DBGKD_SET_CONTEXT_EX, 1, &union_body, &[]);
            inbound.extend(ack_then_reply(packet_id, packet_id, &reply));
        }
        let mut framing = KdFraming::new(Loopback::new(inbound));

        set_context_chunked(&mut framing, 1, &context).unwrap();

        let outbound = &framing.transport_ref().outbound;
        let mut cursor = 0usize;
        let mut transferred = 0usize;
        for &chunk_len in &chunk_lengths {
            let request = &outbound[cursor + 16..cursor + 16 + MANIPULATE_HEADER_SIZE];
            assert_eq!(read_u32(request, 0), DBGKD_SET_CONTEXT_EX);
            assert_eq!(read_u32(request, UNION_OFFSET), transferred as u32);
            assert_eq!(read_u32(request, UNION_OFFSET + 4), chunk_len as u32);
            assert_eq!(read_u32(request, UNION_OFFSET + 8), context.len() as u32);
            let data_start = cursor + 16 + MANIPULATE_HEADER_SIZE;
            assert_eq!(
                &outbound[data_start..data_start + chunk_len],
                &context[transferred..transferred + chunk_len]
            );
            transferred += chunk_len;
            cursor = data_start + chunk_len + 1 + 16;
        }
        assert_eq!(transferred, context.len());
        assert_eq!(cursor, outbound.len());
    }
    #[test]
    fn physical_memory_read_validates_and_returns_reply_data() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let mut union_body = [0u8; 16];
        write_u64(&mut union_body, 0, 0x1234_5000);
        write_u32(&mut union_body, 8, data.len() as u32);
        write_u32(&mut union_body, 12, data.len() as u32);
        let reply = build_reply(DBGKD_READ_PHYSICAL_MEMORY, 2, &union_body, &data);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );
        let mut framing = KdFraming::new(Loopback::new(stream));

        let actual = read_physical_memory(&mut framing, 2, 0x1234_5000, data.len() as u32).unwrap();

        assert_eq!(actual, data);
        let request = &framing.transport_ref().outbound[16..16 + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(request, 0), DBGKD_READ_PHYSICAL_MEMORY);
        assert_eq!(read_u16(request, 6), 2);
        assert_eq!(read_u64(request, UNION_OFFSET), 0x1234_5000);
        assert_eq!(read_u32(request, UNION_OFFSET + 8), data.len() as u32);
    }

    #[test]
    fn physical_memory_write_sends_data_and_checks_count() {
        let data = [1, 2, 3, 4];
        let mut union_body = [0u8; 16];
        write_u64(&mut union_body, 0, 0x2000);
        write_u32(&mut union_body, 8, data.len() as u32);
        write_u32(&mut union_body, 12, data.len() as u32);
        let reply = build_reply(DBGKD_WRITE_PHYSICAL_MEMORY, 1, &union_body, &[]);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );
        let mut framing = KdFraming::new(Loopback::new(stream));

        write_physical_memory(&mut framing, 1, 0x2000, &data).unwrap();

        let outbound = &framing.transport_ref().outbound;
        let request = &outbound[16..16 + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(request, 0), DBGKD_WRITE_PHYSICAL_MEMORY);
        assert_eq!(read_u16(request, 6), 1);
        assert_eq!(read_u64(request, UNION_OFFSET), 0x2000);
        assert_eq!(read_u32(request, UNION_OFFSET + 8), data.len() as u32);
        assert_eq!(
            &outbound[16 + MANIPULATE_HEADER_SIZE..16 + MANIPULATE_HEADER_SIZE + data.len()],
            &data
        );
    }

    #[test]
    fn read_control_space_returns_reply_data() {
        let special_bytes: Vec<u8> = (0..168u32).map(|i| (255 - (i & 0xff)) as u8).collect();
        let reply = build_reply(DBGKD_READ_CONTROL_SPACE, 1, &[], &special_bytes);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );

        let mut framing = KdFraming::new(Loopback::new(stream));
        let data = read_control_space(&mut framing, 1, 2, 168).unwrap();
        assert_eq!(data, special_bytes);

        let out = &framing.transport_ref().outbound;
        let req_header = &out[16..16 + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(req_header, 0), DBGKD_READ_CONTROL_SPACE);
        assert_eq!(read_u16(req_header, 6), 1);
        assert_eq!(read_u64(req_header, UNION_OFFSET), 2);
        assert_eq!(read_u32(req_header, UNION_OFFSET + 8), 168);
    }

    #[test]
    fn write_control_space_sends_special_registers() {
        let data: Vec<u8> = (0..168u32).map(|i| (i & 0xff) as u8).collect();
        let mut union_body = vec![0u8; 16];
        union_body[0..8].copy_from_slice(&2u64.to_le_bytes());
        union_body[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        union_body[12..16].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let reply = build_reply(DBGKD_WRITE_CONTROL_SPACE, 2, &union_body, &[]);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );

        let mut framing = KdFraming::new(Loopback::new(stream));
        let actual = write_control_space(&mut framing, 2, 2, &data).unwrap();
        assert_eq!(actual, data.len() as u32);

        let out = &framing.transport_ref().outbound;
        let payload_start = 16;
        let req_header = &out[payload_start..payload_start + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(req_header, 0), DBGKD_WRITE_CONTROL_SPACE);
        assert_eq!(read_u16(req_header, 6), 2);
        assert_eq!(read_u64(req_header, UNION_OFFSET), 2);
        assert_eq!(read_u32(req_header, UNION_OFFSET + 8), data.len() as u32);
        assert_eq!(
            &out[payload_start + MANIPULATE_HEADER_SIZE
                ..payload_start + MANIPULATE_HEADER_SIZE + data.len()],
            data
        );
    }

    #[test]
    fn write_breakpoint_returns_handle() {
        // Reply union: BreakPointAddress (echoed) + BreakPointHandle = 7
        let mut union_body = vec![0u8; 12];
        union_body[0..8].copy_from_slice(&0xfffff80000123456u64.to_le_bytes());
        union_body[8..12].copy_from_slice(&7u32.to_le_bytes());

        let reply = build_reply(DBGKD_WRITE_BREAKPOINT, 0, &union_body, &[]);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );

        let mut framing = KdFraming::new(Loopback::new(stream));
        let handle = write_breakpoint(&mut framing, 0, 0xfffff80000123456).unwrap();
        assert_eq!(handle, 7);

        // Verify the request we emitted encoded the address correctly
        let out = &framing.transport_ref().outbound;
        // header(16) + payload (>= MANIPULATE_HEADER_SIZE) + trailer(1)
        let payload_start = 16;
        let req_header = &out[payload_start..payload_start + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(req_header, 0), DBGKD_WRITE_BREAKPOINT);
        assert_eq!(read_u64(req_header, UNION_OFFSET), 0xfffff80000123456);
    }

    #[test]
    fn continue_api2_sends_request_without_waiting_for_reply() {
        // No reply needed; continue_api2 only waits for the framing ACK
        let ack = {
            let outbound_id = (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID;
            let mut hdr = [0u8; 16];
            hdr[0..4].copy_from_slice(&0x69696969u32.to_le_bytes());
            hdr[4..6].copy_from_slice(&PACKET_TYPE_KD_ACKNOWLEDGE.to_le_bytes());
            hdr[8..12].copy_from_slice(&outbound_id.to_le_bytes());
            hdr.to_vec()
        };
        let mut framing = KdFraming::new(Loopback::new(ack));
        continue_api2(&mut framing, 0, DBG_CONTINUE, false, 0x0000_0400).unwrap();

        let out = &framing.transport_ref().outbound;
        let req_header = &out[16..16 + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(req_header, 0), DBGKD_CONTINUE_API2);
        assert_eq!(read_u32(req_header, UNION_OFFSET), DBG_CONTINUE);
        assert_eq!(read_u32(req_header, UNION_OFFSET + 4), 0); // trace flag
        assert_eq!(read_u64(req_header, UNION_OFFSET + 8), 0x0000_0400);
    }

    #[test]
    fn continue_api2_with_trace_sets_trace_flag() {
        let ack = {
            let outbound_id = (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID;
            let mut hdr = [0u8; 16];
            hdr[0..4].copy_from_slice(&0x69696969u32.to_le_bytes());
            hdr[4..6].copy_from_slice(&PACKET_TYPE_KD_ACKNOWLEDGE.to_le_bytes());
            hdr[8..12].copy_from_slice(&outbound_id.to_le_bytes());
            hdr.to_vec()
        };
        let mut framing = KdFraming::new(Loopback::new(ack));
        continue_api2(&mut framing, 0, DBG_CONTINUE, true, 0xdead_beef).unwrap();

        let out = &framing.transport_ref().outbound;
        let req_header = &out[16..16 + MANIPULATE_HEADER_SIZE];
        assert_eq!(read_u32(req_header, UNION_OFFSET + 4), 1);
        assert_eq!(read_u64(req_header, UNION_OFFSET + 8), 0xdead_beef);
    }

    #[test]
    fn manipulate_reply_rejects_wrong_processor() {
        let reply = build_reply(DBGKD_GET_CONTEXT, 1, &[], &[]);
        let stream = ack_then_reply(
            (INITIAL_PACKET_ID | SYNC_PACKET_ID) & !SYNC_PACKET_ID,
            INITIAL_PACKET_ID,
            &reply,
        );

        let mut framing = KdFraming::new(Loopback::new(stream));
        let err = get_context(&mut framing, 0, context::CONTEXT_ALL).unwrap_err();
        match err {
            Error::Kd(msg) => assert!(msg.contains("processor mismatch")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn check_status_rejects_negative_ntstatus() {
        let h = ManipulateHeader {
            api_number: DBGKD_GET_CONTEXT,
            processor: 0,
            return_status: 0xC000_0005, // STATUS_ACCESS_VIOLATION
        };
        let err = check_status(&h, DBGKD_GET_CONTEXT).unwrap_err();
        match err {
            Error::KdStatus { ntstatus, api } => {
                assert_eq!(ntstatus, 0xC000_0005);
                assert_eq!(api, DBGKD_GET_CONTEXT);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn check_status_rejects_api_mismatch() {
        let h = ManipulateHeader {
            api_number: DBGKD_GET_VERSION,
            processor: 0,
            return_status: STATUS_SUCCESS,
        };
        assert!(check_status(&h, DBGKD_GET_CONTEXT).is_err());
    }
}
