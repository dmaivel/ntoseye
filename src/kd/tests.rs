use super::*;

use std::io::{Cursor, Read, Write};
use std::os::unix::net::UnixStream;
use std::thread::{JoinHandle, spawn};

use crate::kd::connect::MEMORY_OVER_KD_CHOSEN;
use crate::kd::framing::{
    HEADER_SIZE, Header, INITIAL_PACKET_ID, PACKET_TYPE_KD_ACKNOWLEDGE,
    PACKET_TYPE_KD_STATE_MANIPULATE, control_packet, data_packet,
};
use crate::kd::memory::{KD_REMOTE_MEMORY_CHUNK, LineCache};
use crate::kd::registers::{AMD64_DEBUG_CONTROL_SPACE_KSPECIAL, KSPECIAL_REGISTERS_MIN_SIZE};

mod breakpoints;
mod connect;
mod debug_io;
mod event_loop;
mod exit;
mod file_io;
mod memory;
mod pump;
mod registers;
mod run;

#[test]
fn kd_memory_source_parses_supported_values() {
    assert_eq!("auto".parse(), Ok(KdMemorySource::Auto));
    assert_eq!("host".parse(), Ok(KdMemorySource::Host));
    assert_eq!("kd".parse(), Ok(KdMemorySource::Kd));
    assert!("remote".parse::<KdMemorySource>().is_err());
}

#[test]
fn arm64_capabilities_include_debug_breakpoints() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.arch = Arch::Arm64;

    for capability in [
        DebugCapability::UserModeBreakpoints,
        DebugCapability::Watchpoints,
    ] {
        assert!(
            backend
                .capabilities()
                .iter()
                .any(|entry| { entry.capability == capability && entry.supported })
        );
    }
}

struct Loopback {
    inbound: Cursor<Vec<u8>>,
    outbound: Vec<u8>,
}

impl Loopback {
    fn new() -> Self {
        Self {
            inbound: Cursor::new(Vec::new()),
            outbound: Vec::new(),
        }
    }

    fn with_inbound(inbound: Vec<u8>) -> Self {
        Self {
            inbound: Cursor::new(inbound),
            outbound: Vec::new(),
        }
    }
}

impl Read for Loopback {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Read::read(&mut self.inbound, buf)
    }
}

impl Write for Loopback {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outbound.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn debug_io_print_payload(text: &[u8]) -> Vec<u8> {
    let mut payload = vec![0u8; DBGKD_DEBUG_IO_HEADER_SIZE];
    payload[0..4].copy_from_slice(&DBGKD_PRINT_STRING_API.to_le_bytes());
    payload[8..12].copy_from_slice(&(text.len() as u32).to_le_bytes());
    payload.extend_from_slice(text);
    payload
}

#[test]
fn thread_id_uses_one_based_hex() {
    assert_eq!(thread_id_for(0), "p1.1");
    assert_eq!(thread_id_for(3), "p1.4");
    assert_eq!(thread_id_for(15), "p1.10");
}

#[test]
fn parse_thread_id_rejects_garbage() {
    assert!(parse_thread_id("p2.1").is_err()); // wrong pid
    assert!(parse_thread_id("p1.zz").is_err()); // not hex
    assert!(parse_thread_id("garbage").is_err());
    assert!(parse_thread_id("p1.0").is_err()); // zero index reserved
}

#[test]
fn parse_thread_id_for_processor_count_rejects_out_of_range() {
    assert_eq!(parse_thread_id_for_processor_count("p1.4", 4).unwrap(), 3);
    assert!(parse_thread_id_for_processor_count("p1.5", 4).is_err());
}

fn wire_header(packet: &[u8]) -> Header {
    Header::peek(packet).expect("packet holds a KD header")
}

/// Read one whole packet, header through trailer, off the host's side of the wire.
fn try_read_wire_packet(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut packet = vec![0u8; HEADER_SIZE];
    stream.read_exact(&mut packet)?;
    packet.resize(wire_header(&packet).packet_len(), 0);
    stream.read_exact(&mut packet[HEADER_SIZE..])?;
    Ok(packet)
}

fn read_wire_packet(stream: &mut UnixStream) -> Vec<u8> {
    try_read_wire_packet(stream).unwrap()
}

/// ACK and return the payload of the host's next data packet, skipping the
/// host's ACKs of our replies; `None` once the host hangs up.
fn recv_host_request(kernel: &mut UnixStream) -> Option<Vec<u8>> {
    loop {
        let packet = try_read_wire_packet(kernel).ok()?;
        let header = wire_header(&packet);
        if !header.is_data() {
            continue;
        }
        kernel
            .write_all(&control_packet(
                PACKET_TYPE_KD_ACKNOWLEDGE,
                header.packet_id,
            ))
            .unwrap();
        return Some(packet[HEADER_SIZE..packet.len() - 1].to_vec());
    }
}

fn state_change_payload(new_state: u32, pc: u64) -> Vec<u8> {
    let mut payload = vec![0u8; 56];
    payload[0..4].copy_from_slice(&new_state.to_le_bytes());
    payload[8..12].copy_from_slice(&1u32.to_le_bytes()); // NumberProcessors
    payload[24..32].copy_from_slice(&pc.to_le_bytes());
    payload[32..36].copy_from_slice(&STATUS_BREAKPOINT.to_le_bytes());
    payload
}

fn exception_state_change_payload(pc: u64) -> Vec<u8> {
    state_change_payload(DBG_KD_EXCEPTION_STATE_CHANGE, pc)
}

fn kd_backend_with_pump(pump: PumpHandle, breakin_clone: UnixStream) -> KdBackend {
    KdBackend {
        link: Link::RunningPumped(pump),
        breakin_clone: breakin_clone.into(),
        backend_name: "kd",
        register_map: context::build_register_map(),
        arch: Arch::Amd64,
        kernel_dtb_override: 0,
        processor_count: 1,
        current_processor: 0,
        last_stop_processor: 0,
        last_exception_code: 0,
        last_rip: 0,
        reconnect_assist_after_continue: None,
        bp_handles: HashMap::new(),
        managed_bp_addresses: HashSet::new(),
        breakin_addresses: HashSet::new(),
        late_breakin: false,
        pending_write_breakpoint: None,
        registers: HaltRegisters::default(),
        stop_was_managed_breakpoint: false,
        surface_break_at: None,
        special_registers_unsupported: false,
        efer_cache: HashMap::new(),
        virtual_lines: LineCache::default(),
        table_lines: LineCache::default(),
        virtual_fill_cap: KD_REMOTE_MEMORY_CHUNK,
        exit_prepared: false,
        debug_log: DebugLog::new(DEBUG_LOG_CAPACITY),
        translations: Arc::new(TranslationCache::default()),
        notices: Vec::new(),
        released_handles: HashSet::new(),
        running_reason: MEMORY_OVER_KD_CHOSEN,
    }
}

/// Replies a scripted target hands back, in request order.
fn scripted_target(replies: &[Vec<u8>]) -> Vec<u8> {
    let mut stream = Vec::new();
    for (index, reply) in replies.iter().enumerate() {
        let id = INITIAL_PACKET_ID ^ (index as u32 & 1);
        stream.extend_from_slice(&api::test_wire::ack_then_reply(id, id, reply));
    }
    stream
}

fn kd_backend_with_framing(host: UnixStream) -> KdBackend {
    let breakin_clone = host.try_clone().unwrap();
    KdBackend {
        link: Link::RunningInline(KdFraming::new(host.into())),
        breakin_clone: breakin_clone.into(),
        backend_name: "kd",
        register_map: context::build_register_map(),
        arch: Arch::Amd64,
        kernel_dtb_override: 0,
        processor_count: 1,
        current_processor: 0,
        last_stop_processor: 0,
        last_exception_code: 0,
        last_rip: 0,
        reconnect_assist_after_continue: None,
        bp_handles: HashMap::new(),
        managed_bp_addresses: HashSet::new(),
        breakin_addresses: HashSet::new(),
        late_breakin: false,
        pending_write_breakpoint: None,
        registers: HaltRegisters::default(),
        stop_was_managed_breakpoint: false,
        surface_break_at: None,
        special_registers_unsupported: false,
        efer_cache: HashMap::new(),
        virtual_lines: LineCache::default(),
        table_lines: LineCache::default(),
        virtual_fill_cap: KD_REMOTE_MEMORY_CHUNK,
        exit_prepared: false,
        debug_log: DebugLog::new(DEBUG_LOG_CAPACITY),
        translations: Arc::new(TranslationCache::default()),
        notices: Vec::new(),
        released_handles: HashSet::new(),
        running_reason: MEMORY_OVER_KD_CHOSEN,
    }
}

fn manipulate_reply_payload(api_number: u32, processor: u16, union_body: &[u8]) -> Vec<u8> {
    const MANIPULATE_UNION_OFFSET: usize = 16;

    let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE];
    payload[0..4].copy_from_slice(&api_number.to_le_bytes());
    payload[6..8].copy_from_slice(&processor.to_le_bytes());
    let end = (MANIPULATE_UNION_OFFSET + union_body.len()).min(payload.len());
    payload[MANIPULATE_UNION_OFFSET..end]
        .copy_from_slice(&union_body[..end - MANIPULATE_UNION_OFFSET]);
    payload
}

/// A halted fake kernel answering breakpoint APIs from an ordered
/// `(api, status, handle)` script. The handle rides in the manipulate
/// header union, where `DbgKdWriteBreakPointApi` returns it, rather than in
/// trailing data. Yields the `(api, union)` pairs the host actually sent -
/// a breakpoint address for a write, a table handle for a restore.
fn serve_breakpoints(
    mut kernel: UnixStream,
    script: Vec<(u32, u32, u32)>,
) -> JoinHandle<Vec<(u32, u64)>> {
    const UNION: usize = 16;
    spawn(move || {
        let mut kernel_id = INITIAL_PACKET_ID;
        let mut script = script.into_iter();
        let mut seen = Vec::new();
        loop {
            let Some(request) = recv_host_request(&mut kernel) else {
                assert!(script.next().is_none(), "missing breakpoint request");
                return seen;
            };

            let api_number = u32::from_le_bytes(request[0..4].try_into().unwrap());
            seen.push((api_number, bytes::read_u64(&request, UNION)));

            let (expected_api, status, handle) =
                script.next().expect("unexpected breakpoint request");
            assert_eq!(api_number, expected_api);
            let mut reply = vec![0u8; api::MANIPULATE_HEADER_SIZE];
            reply[0..4].copy_from_slice(&api_number.to_le_bytes());
            reply[8..12].copy_from_slice(&status.to_le_bytes());
            reply[UNION + 8..UNION + 12].copy_from_slice(&handle.to_le_bytes());
            kernel
                .write_all(&data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    kernel_id,
                    &reply,
                ))
                .unwrap();
            kernel_id ^= 1;
        }
    })
}

fn read_special_registers_reply_payload(processor: u16) -> Vec<u8> {
    const MANIPULATE_UNION_OFFSET: usize = 16;

    let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE + KSPECIAL_REGISTERS_MIN_SIZE];
    payload[0..4].copy_from_slice(&api::DBGKD_READ_CONTROL_SPACE.to_le_bytes());
    payload[6..8].copy_from_slice(&processor.to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET..MANIPULATE_UNION_OFFSET + 8]
        .copy_from_slice(&AMD64_DEBUG_CONTROL_SPACE_KSPECIAL.to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET + 8..MANIPULATE_UNION_OFFSET + 12]
        .copy_from_slice(&(KSPECIAL_REGISTERS_MIN_SIZE as u32).to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET + 12..MANIPULATE_UNION_OFFSET + 16]
        .copy_from_slice(&(KSPECIAL_REGISTERS_MIN_SIZE as u32).to_le_bytes());
    payload
}
