use super::*;
const ARM64_KSPECIAL_REGISTERS_TPIDR_EL0_OFFSET: usize = 0x10;
use crate::guest::{Guest, WinObject};
use crate::kd::framing::{
    PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_DEBUG_IO, PACKET_TYPE_KD_FILE_IO,
    PACKET_TYPE_KD_RESET, PACKET_TYPE_KD_STATE_CHANGE64, PACKET_TYPE_KD_STATE_MANIPULATE,
};
use crate::phys::PhysMem;
use crate::symbols::{FieldInfo, ParsedType, SymbolStore, TypeInfo};
use std::io::{Cursor, Read, Write};
use std::time::Instant;

#[test]
fn kd_detects_amd64_and_arm64_machine_types() {
    assert_eq!(detect_arch(0x8664).unwrap(), Arch::Amd64);
    assert_eq!(detect_arch(0xaa64).unwrap(), Arch::Arm64);
    let error = detect_arch(0x014c).unwrap_err();
    assert!(error.to_string().contains("I386 KD target"));
}

#[test]
fn kd_memory_source_parses_supported_values() {
    assert_eq!("auto".parse(), Ok(KdMemorySource::Auto));
    assert_eq!("host".parse(), Ok(KdMemorySource::Host));
    assert_eq!("kd".parse(), Ok(KdMemorySource::Kd));
    assert!("remote".parse::<KdMemorySource>().is_err());
}

#[test]
fn arm64_ttbr1_normalizes_to_combined_page_table_page() {
    // Windows commonly places TTBR0 and TTBR1 in the lower/upper 0x800
    // halves of one page. Strip both that offset and the full 16-bit ASID.
    assert_eq!(
        normalize_kernel_dtb(Arch::Arm64, 0x004f_0000_80d4_5800),
        0x80d4_5000
    );
}

#[test]
fn arm64_target_hints_read_ttbr1_through_kd() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.arch = Arch::Arm64;
    backend.register_map = context_arm64::build_register_map();
    backend.link.set_inline_running(false);
    backend.exit_prepared = true;
    let kernel_base = 0xffff_f802_4e80_0000u64;
    let module_list = 0xffff_f802_4f4d_aed0u64;

    let worker = spawn(move || {
        let version_request = read_wire_packet(&mut kernel);
        let version_id = u32::from_le_bytes(version_request[8..12].try_into().unwrap());
        assert_eq!(
            u32::from_le_bytes(version_request[16..20].try_into().unwrap()),
            api::DBGKD_GET_VERSION
        );
        kernel
            .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, version_id))
            .unwrap();
        let mut version_union = [0u8; 40];
        version_union[8..10].copy_from_slice(&0xaa64u16.to_le_bytes());
        version_union[16..24].copy_from_slice(&kernel_base.to_le_bytes());
        version_union[24..32].copy_from_slice(&module_list.to_le_bytes());
        let version_reply = manipulate_reply_payload(api::DBGKD_GET_VERSION, 0, &version_union);
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                WIRE_FIRST_PACKET_ID,
                &version_reply,
            ))
            .unwrap();
        let _version_ack = read_wire_packet(&mut kernel);

        let ttbr_request = read_wire_packet(&mut kernel);
        let ttbr_id = u32::from_le_bytes(ttbr_request[8..12].try_into().unwrap());
        assert_eq!(
            u32::from_le_bytes(ttbr_request[16..20].try_into().unwrap()),
            api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER
        );
        assert_eq!(
            u32::from_le_bytes(ttbr_request[32..36].try_into().unwrap()),
            ARM64_WINDBG_TTBR1_EL1
        );
        kernel
            .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, ttbr_id))
            .unwrap();
        let ttbr = 0x0040_0000_80d4_5800u64;
        let mut ttbr_union = [0u8; 12];
        ttbr_union[0..4].copy_from_slice(&ARM64_WINDBG_TTBR1_EL1.to_le_bytes());
        ttbr_union[4..8].copy_from_slice(&(ttbr as u32).to_le_bytes());
        ttbr_union[8..12].copy_from_slice(&((ttbr >> 32) as u32).to_le_bytes());
        let ttbr_reply =
            manipulate_reply_payload(api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER, 0, &ttbr_union);
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                WIRE_FIRST_PACKET_ID ^ 1,
                &ttbr_reply,
            ))
            .unwrap();
        let _ttbr_ack = read_wire_packet(&mut kernel);
    });

    let hints = backend.target_hints().unwrap();

    worker.join().unwrap();
    assert_eq!(hints.arch, Arch::Arm64);
    assert_eq!(hints.kernel_dtb, 0x80d4_5000);
    assert_eq!(hints.kernel_base, VirtAddr(kernel_base));
    assert_eq!(hints.ps_loaded_module_list, VirtAddr(module_list));
}

#[test]
fn transparent_arm64_state_change_uses_arm64_continue_layout() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let stop = StateChange {
        processor: 2,
        number_processors: 4,
        new_state: DBG_KD_LOAD_SYMBOLS_STATE_CHANGE,
        exception_code: 0,
        exception_first_chance: None,
        exception_address: None,
        program_counter: 0xffff_f800_1234_5678,
        kernel_base_hint: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        assisted_breakin: false,
        control_report: None,
    };
    let handle = spawn(move || {
        let mut framing = KdFraming::new(host.into());
        continue_transparent_state_change(&mut framing, Arch::Arm64, &stop)
    });

    let packet = read_wire_packet(&mut kernel);
    let packet_id = u32::from_le_bytes(packet[8..12].try_into().unwrap());
    let request = &packet[WIRE_HEADER_SIZE..];
    assert_eq!(
        u32::from_le_bytes(request[0..4].try_into().unwrap()),
        api::DBGKD_CONTINUE_API2
    );
    assert_eq!(
        u32::from_le_bytes(request[16..20].try_into().unwrap()),
        api::DBG_CONTINUE
    );
    assert_eq!(&request[20..24], &[0; 4]);
    assert_eq!(&request[24..40], &[0; 16]);

    kernel
        .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, packet_id))
        .unwrap();
    kernel.flush().unwrap();
    handle.join().unwrap().unwrap();
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
fn parse_state_change_extracts_processor_and_pc() {
    let mut payload = vec![0u8; 64];
    payload[0..4].copy_from_slice(&DBG_KD_EXCEPTION_STATE_CHANGE.to_le_bytes()); // NewState
    payload[6..8].copy_from_slice(&2u16.to_le_bytes()); // Processor = 2
    payload[8..12].copy_from_slice(&4u32.to_le_bytes()); // NumberProcessors
    payload[24..32].copy_from_slice(&0xfffff800deadbeefu64.to_le_bytes());
    payload[32..36].copy_from_slice(&STATUS_BREAKPOINT.to_le_bytes());

    let s = parse_state_change(&payload).unwrap();
    assert_eq!(s.processor, 2);
    assert_eq!(s.number_processors, 4);
    assert_eq!(s.new_state, DBG_KD_EXCEPTION_STATE_CHANGE);
    assert_eq!(s.exception_code, STATUS_BREAKPOINT);
    assert_eq!(s.program_counter, 0xfffff800deadbeef);
}

#[test]
fn parse_state_change_extracts_exception_record_metadata() {
    let mut payload = vec![0u8; 188];
    payload[0..4].copy_from_slice(&DBG_KD_EXCEPTION_STATE_CHANGE.to_le_bytes());
    payload[32..36].copy_from_slice(&0xc000_0005u32.to_le_bytes());
    payload[48..56].copy_from_slice(&0xfffff800_12345678u64.to_le_bytes());
    payload[184..188].copy_from_slice(&1u32.to_le_bytes());

    let first = parse_state_change(&payload).unwrap();
    assert_eq!(first.exception_address, Some(0xfffff800_12345678));
    assert_eq!(first.exception_first_chance, Some(true));

    payload[184..188].copy_from_slice(&0u32.to_le_bytes());
    let second = parse_state_change(&payload).unwrap();
    assert_eq!(second.exception_first_chance, Some(false));
}

#[test]
fn parse_load_symbols_state_change_extracts_base_hint() {
    let mut payload = vec![0u8; 64];
    payload[0..4].copy_from_slice(&DBG_KD_LOAD_SYMBOLS_STATE_CHANGE.to_le_bytes());
    payload[8..12].copy_from_slice(&1u32.to_le_bytes());
    payload[24..32].copy_from_slice(&0xfffff800004f9325u64.to_le_bytes());
    payload[40..48].copy_from_slice(&0xfffff80000000000u64.to_le_bytes());

    let s = parse_state_change(&payload).unwrap();

    assert_eq!(s.program_counter, 0xfffff800004f9325);
    assert_eq!(s.kernel_base_hint, Some(VirtAddr(0xfffff80000000000)));
}

/// A real 240-byte AMD64 exception state change, captured from a Windows 11
/// target stopping on an `int3` we had written into `user32!PeekMessageW`.
///
/// The control report's offsets are the reason an absorbed hit can skip a
/// register fetch, and nothing else validates them: a wrong offset would
/// read some neighbouring field as RFLAGS, conclude a single step left no
/// trap flag behind, and resume a thread that then single-steps forever.
const CAPTURED_BREAKPOINT_STATE_CHANGE: &str = "\
     30300000060000000400000000000000\
     8010af5985aaffffe017c57cfa7f0000\
     03000080000000000000000000000000\
     e017c57cfa7f000001000000fa010000\
     00000000000000008010af5985aaffff\
     46020000000000008010af5985aaffff\
     201dc632fa01000020fbfcc58bd8ffff\
     dc0100000000000000000000fa7f0000\
     03000000fa7f0000f1d61ac709000000\
     0000000000000000db34b6d782de1b43\
     00000000000000000000000000000000\
     015f1032fa0100000100000000000000\
     f00fffff000000000004000000000000\
     4602000010000300cc895c240848896c\
     241048897424185733002b002b005300";

#[test]
fn state_change_carries_the_amd64_control_report() {
    let payload: Vec<u8> = CAPTURED_BREAKPOINT_STATE_CHANGE
        .split_whitespace()
        .collect::<String>()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(payload.len(), 240, "captured AMD64 state change");

    let stop = parse_state_change(&payload).unwrap();
    assert_eq!(stop.program_counter, 0x7ffa_7cc5_17e0);
    assert_eq!(stop.exception_code, STATUS_BREAKPOINT);

    let report = stop.control_report.expect("240 bytes carry a report");
    let trap = report.amd64_trap_state().expect("AMD64 report");
    assert_eq!(trap.eflags, 0x246, "RFLAGS: IF | PF | reserved");
    assert_eq!(trap.dr6, 0xffff_0ff0, "DR6 with no breakpoint status set");
    assert_eq!(report.amd64_dr7(), Some(0x400));
    assert!(
        trap.is_clean(),
        "an int3 stop has neither a trap flag nor DR6 status to clear"
    );
}

#[test]
fn stop_event_flags_surfaced_load_symbols_as_bugcheck() {
    let stop = StateChange {
        processor: 0,
        number_processors: 1,
        new_state: DBG_KD_LOAD_SYMBOLS_STATE_CHANGE,
        exception_code: 0,
        exception_first_chance: None,
        exception_address: None,
        program_counter: 0xfffff8007faf9325,
        kernel_base_hint: Some(VirtAddr(0xfffff8007f600000)),
        is_bugcheck: true,
        bugcheck: None,
        target_reloaded: false,
        assisted_breakin: false,
        control_report: None,
    };

    let event = stop_event(stop);
    assert!(event.is_bugcheck);
    assert_eq!(event.exception_code, None);
    assert_eq!(event.program_counter, Some(0xfffff8007faf9325));
    assert_eq!(
        event.target_kernel_base_hint,
        Some(VirtAddr(0xfffff8007f600000))
    );
    assert!(event.bugcheck.is_none());
}

#[test]
fn bugcheck_capture_extracts_fatal_error_and_driver() {
    let mut capture = BugcheckCapture::default();
    capture.observe_debug_text(
        b"\r\n*** Fatal System Error: 0x000000d1\r\n                       (0xFFFFB90641184010,0x0000000000000002,0x0000000000000000,0xFFFFF8016E151730)\r\n",
    );
    capture.observe_debug_text(b"Driver at fault: myfault.sys.\r\n");

    let info = capture.finish().unwrap();
    assert_eq!(info.code, 0xd1);
    assert_eq!(
        info.parameters,
        [
            0xffff_b906_4118_4010,
            0x0000_0000_0000_0002,
            0x0000_0000_0000_0000,
            0xffff_f801_6e15_1730,
        ]
    );
    assert_eq!(info.driver.as_deref(), Some("myfault.sys"));
}

#[test]
fn captured_bugcheck_debug_io_can_be_suppressed() {
    let payload = debug_io_print_payload(
        b"\r\n*** Fatal System Error: 0x000000d1\r\n                       (0x1,0x2,0x0,0x4)\r\n",
    );
    let mut framing = KdFraming::new(Loopback::new());
    let mut capture = BugcheckCapture::default();
    let mut output = Vec::new();
    let debug_log = DebugLog::new(DEBUG_LOG_CAPACITY);

    let saw_refresh = handle_debug_io_with_output(
        &mut framing,
        &payload,
        true,
        Some(&mut capture),
        true,
        Some(&debug_log),
        &mut output,
    )
    .unwrap();

    assert!(!saw_refresh);
    assert!(output.is_empty());
    assert_eq!(capture.finish().unwrap().code, 0xd1);
    let page = debug_log.read_since(0);
    assert!(
        page.lines
            .iter()
            .any(|line| line.text.contains("Fatal System Error"))
    );
}

#[test]
fn parse_debug_io_print_extracts_string() {
    let payload = debug_io_print_payload(b"hello");

    match parse_debug_io(&payload).unwrap() {
        DebugIo::PrintString { text } => assert_eq!(text, b"hello"),
        DebugIo::GetString { .. } => panic!("expected print-string debug I/O"),
    }
}

#[test]
fn debug_io_refresh_message_is_reported_when_waiting_for_stop() {
    let payload = debug_io_print_payload(b"KDTARGET: Refreshing KD connection\n");
    let mut framing = KdFraming::new(Loopback::new());
    let mut output = Vec::new();

    let saw_refresh =
        handle_debug_io_with_output(&mut framing, &payload, true, None, false, None, &mut output)
            .unwrap();

    assert!(saw_refresh);
    assert_eq!(output, b"KDTARGET: Refreshing KD connection\n");
    assert!(framing.transport_ref().outbound.is_empty());
}

#[test]
fn debug_io_refresh_message_is_passive_during_manipulate_requests() {
    let payload = debug_io_print_payload(b"KDTARGET: Refreshing KD connection\n");
    let mut framing = KdFraming::new(Loopback::new());
    let mut output = Vec::new();

    let saw_refresh = handle_debug_io_with_output(
        &mut framing,
        &payload,
        false,
        None,
        false,
        None,
        &mut output,
    )
    .unwrap();

    assert!(!saw_refresh);
    assert_eq!(output, b"KDTARGET: Refreshing KD connection\n");
    assert!(framing.transport_ref().outbound.is_empty());
}

#[test]
fn parse_debug_io_print_accepts_legacy_short_header() {
    let mut payload = vec![0u8; DBGKD_DEBUG_IO_MIN_HEADER_SIZE];
    payload[0..4].copy_from_slice(&DBGKD_PRINT_STRING_API.to_le_bytes());
    payload[8..12].copy_from_slice(&5u32.to_le_bytes());
    payload.extend_from_slice(b"hello");

    match parse_debug_io(&payload).unwrap() {
        DebugIo::PrintString { text } => assert_eq!(text, b"hello"),
        DebugIo::GetString { .. } => panic!("expected print-string debug I/O"),
    }
}

#[test]
fn parse_debug_io_get_string_reads_full_header() {
    let mut payload = vec![0u8; DBGKD_DEBUG_IO_HEADER_SIZE];
    payload[0..4].copy_from_slice(&DBGKD_GET_STRING_API.to_le_bytes());
    payload[4..6].copy_from_slice(&0x33u16.to_le_bytes());
    payload[6..8].copy_from_slice(&2u16.to_le_bytes());
    payload[8..12].copy_from_slice(&7u32.to_le_bytes());
    payload[12..16].copy_from_slice(&0x100u32.to_le_bytes());
    payload.extend_from_slice(b"prompt>");

    match parse_debug_io(&payload).unwrap() {
        DebugIo::GetString {
            processor_level,
            processor,
            prompt,
        } => {
            assert_eq!(processor_level, 0x33);
            assert_eq!(processor, 2);
            assert_eq!(prompt, b"prompt>");
        }
        DebugIo::PrintString { .. } => panic!("expected get-string debug I/O"),
    }
}

#[test]
fn parse_debug_io_print_rejects_other_api() {
    let mut payload = vec![0u8; DBGKD_DEBUG_IO_MIN_HEADER_SIZE];
    payload[0..4].copy_from_slice(&0xdeadbeefu32.to_le_bytes());
    assert!(parse_debug_io(&payload).is_none());
}

#[test]
fn parse_state_change_rejects_short_payload() {
    let err = parse_state_change(&[0u8; 10]).unwrap_err();
    match err {
        Error::Kd(msg) => assert!(msg.contains("too short")),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn initial_handshake_breaks_in_immediately_then_resets() {
    assert_eq!(
        initial_handshake_stimulus(0),
        InitialHandshakeStimulus::BreakIn
    );
    assert_eq!(
        initial_handshake_stimulus(1),
        InitialHandshakeStimulus::Reset
    );
    assert_eq!(
        initial_handshake_stimulus(2),
        InitialHandshakeStimulus::BreakIn
    );
    assert_eq!(
        initial_handshake_stimulus(3),
        InitialHandshakeStimulus::Reset
    );
}

#[test]
fn kd_initial_timeout_accepts_positive_seconds() {
    assert_eq!(
        parse_kd_initial_timeout(Some("12")).unwrap(),
        Duration::from_secs(12)
    );
}

#[test]
fn kd_initial_timeout_rejects_invalid_values() {
    assert!(parse_kd_initial_timeout(Some("0")).is_err());
    assert!(parse_kd_initial_timeout(Some("meow")).is_err());
}

#[test]
fn context_payload_rejects_short_buffers() {
    let short = vec![0u8; context::CONTEXT_SIZE - 1];
    assert!(context_payload(&short).is_err());
}

#[test]
fn append_control_registers_extends_context() {
    let mut ctx = vec![0u8; context::CONTEXT_SIZE];
    let mut special = vec![0u8; KSPECIAL_REGISTERS_MIN_SIZE];
    special[KSPECIAL_REGISTERS_CR0_OFFSET..KSPECIAL_REGISTERS_CR0_OFFSET + 8]
        .copy_from_slice(&0x8005_0033u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_CR2_OFFSET..KSPECIAL_REGISTERS_CR2_OFFSET + 8]
        .copy_from_slice(&0x1111_2222u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_CR3_OFFSET..KSPECIAL_REGISTERS_CR3_OFFSET + 8]
        .copy_from_slice(&0x1234_5000u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_CR4_OFFSET..KSPECIAL_REGISTERS_CR4_OFFSET + 8]
        .copy_from_slice(&0x350ef8u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_CR8_OFFSET..KSPECIAL_REGISTERS_CR8_OFFSET + 8]
        .copy_from_slice(&2u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_GDTR_OFFSET + 6..KSPECIAL_REGISTERS_GDTR_OFFSET + 8]
        .copy_from_slice(&0x1234u16.to_le_bytes());
    special[KSPECIAL_REGISTERS_GDTR_OFFSET + 8..KSPECIAL_REGISTERS_GDTR_OFFSET + 16]
        .copy_from_slice(&0xffff_f800_0000_1000u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_IDTR_OFFSET + 6..KSPECIAL_REGISTERS_IDTR_OFFSET + 8]
        .copy_from_slice(&0x5678u16.to_le_bytes());
    special[KSPECIAL_REGISTERS_IDTR_OFFSET + 8..KSPECIAL_REGISTERS_IDTR_OFFSET + 16]
        .copy_from_slice(&0xffff_f800_0000_2000u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_TR_OFFSET..KSPECIAL_REGISTERS_TR_OFFSET + 2]
        .copy_from_slice(&0x40u16.to_le_bytes());
    special[KSPECIAL_REGISTERS_LDTR_OFFSET..KSPECIAL_REGISTERS_LDTR_OFFSET + 2]
        .copy_from_slice(&0x48u16.to_le_bytes());
    special[KSPECIAL_REGISTERS_DR0_OFFSET..KSPECIAL_REGISTERS_DR0_OFFSET + 8]
        .copy_from_slice(&0xffff_f804_1234_5678u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_DR6_OFFSET..KSPECIAL_REGISTERS_DR6_OFFSET + 8]
        .copy_from_slice(&5u64.to_le_bytes());
    special[KSPECIAL_REGISTERS_DR7_OFFSET..KSPECIAL_REGISTERS_DR7_OFFSET + 8]
        .copy_from_slice(&0x402u64.to_le_bytes());

    append_control_registers_from_special(&mut ctx, &special).unwrap();
    let map = context::build_register_map();

    assert_eq!(ctx.len(), context::REGISTER_BUFFER_SIZE);
    assert_eq!(map.read_u64("cr0", &ctx).unwrap(), 0x8005_0033);
    assert_eq!(map.read_u64("cr2", &ctx).unwrap(), 0x1111_2222);
    assert_eq!(map.read_u64("cr3", &ctx).unwrap(), 0x1234_5000);
    assert_eq!(map.read_u64("cr4", &ctx).unwrap(), 0x350ef8);
    assert_eq!(map.read_u64("dr0", &ctx).unwrap(), 0xffff_f804_1234_5678);
    assert_eq!(map.read_u64("dr6", &ctx).unwrap(), 5);
    assert_eq!(map.read_u64("dr7", &ctx).unwrap(), 0x402);
    assert_eq!(map.read_u64("cr8", &ctx).unwrap(), 2);
    assert_eq!(map.read_u64("gdtr", &ctx).unwrap(), 0xffff_f800_0000_1000);
    assert_eq!(map.read_u64("gdtr_limit", &ctx).unwrap(), 0x1234);
    assert_eq!(map.read_u64("idtr", &ctx).unwrap(), 0xffff_f800_0000_2000);
    assert_eq!(map.read_u64("idtr_limit", &ctx).unwrap(), 0x5678);
    assert_eq!(map.read_u64("tr", &ctx).unwrap(), 0x40);
    assert_eq!(map.read_u64("ldtr", &ctx).unwrap(), 0x48);
}

#[test]
fn context_debug_registers_update_special_registers() {
    let mut ctx = vec![0u8; context::REGISTER_BUFFER_SIZE];
    let mut special = vec![0xa5; KSPECIAL_REGISTERS_MIN_SIZE];
    let map = context::build_register_map();
    map.write_u64("dr0", &mut ctx, 0xffff_f804_1234_5678)
        .unwrap();
    map.write_u64("dr6", &mut ctx, 3).unwrap();
    map.write_u64("dr7", &mut ctx, 0xd0402).unwrap();

    update_special_debug_registers_from_context(&mut special, &ctx).unwrap();

    assert_eq!(
        wire::read_u64(&special, KSPECIAL_REGISTERS_DR0_OFFSET),
        0xffff_f804_1234_5678
    );
    assert_eq!(wire::read_u64(&special, KSPECIAL_REGISTERS_DR6_OFFSET), 3);
    assert_eq!(
        wire::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET),
        0xd0402
    );
    assert_eq!(
        wire::read_u64(&special, KSPECIAL_REGISTERS_CR0_OFFSET),
        0xa5a5_a5a5_a5a5_a5a5,
        "non-debug special registers must remain untouched"
    );
}

#[test]
fn arm64_context_debug_registers_update_special_registers() {
    let mut ctx = vec![0u8; context_arm64::CONTEXT_SIZE];
    let mut special = vec![0xa5; ARM64_KSPECIAL_REGISTERS_MIN_SIZE];
    let map = context_arm64::build_register_map();
    map.write_u64("bvr0", &mut ctx, 0x4000).unwrap();
    map.write_u64("bcr0", &mut ctx, 0xe9e1).unwrap();
    map.write_u64("wvr1", &mut ctx, 0x5000).unwrap();
    map.write_u64("wcr1", &mut ctx, 0x0000_e9e1).unwrap();

    update_arm64_debug_registers_from_context(&mut special, &ctx).unwrap();

    assert_eq!(
        wire::read_u64(&special, ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET),
        0x4000
    );
    assert_eq!(
        wire::read_u32(&special, ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET),
        0xe9e1
    );
    assert_eq!(
        wire::read_u64(&special, ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET + 8),
        0x5000
    );
    assert_eq!(
        wire::read_u32(&special, ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET + 4),
        0x0000_e9e1
    );
    assert_eq!(
        wire::read_u64(&special, ARM64_KSPECIAL_REGISTERS_TPIDR_EL0_OFFSET),
        0xa5a5_a5a5_a5a5_a5a5,
        "non-debug special registers must remain untouched"
    );
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

const WIRE_DATA_LEADER: u32 = 0x3030_3030;
const WIRE_CONTROL_LEADER: u32 = 0x6969_6969;
const WIRE_HEADER_SIZE: usize = 16;
const WIRE_TRAILER: u8 = 0xAA;
const WIRE_FIRST_PACKET_ID: u32 = 0x8080_0000;

fn wire_control_packet(packet_type: u16, packet_id: u32) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&WIRE_CONTROL_LEADER.to_le_bytes());
    pkt.extend_from_slice(&packet_type.to_le_bytes());
    pkt.extend_from_slice(&0u16.to_le_bytes());
    pkt.extend_from_slice(&packet_id.to_le_bytes());
    pkt.extend_from_slice(&0u32.to_le_bytes());
    pkt
}

fn wire_data_packet(packet_type: u16, packet_id: u32, payload: &[u8]) -> Vec<u8> {
    let checksum = payload.iter().fold(0u32, |a, &b| a.wrapping_add(b as u32));
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&WIRE_DATA_LEADER.to_le_bytes());
    pkt.extend_from_slice(&packet_type.to_le_bytes());
    pkt.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    pkt.extend_from_slice(&packet_id.to_le_bytes());
    pkt.extend_from_slice(&checksum.to_le_bytes());
    pkt.extend_from_slice(payload);
    pkt.push(WIRE_TRAILER);
    pkt
}

fn read_wire_packet(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0u8; WIRE_HEADER_SIZE];
    stream.read_exact(&mut header).unwrap();
    let mut pkt = header.to_vec();
    let leader = u32::from_le_bytes(header[0..4].try_into().unwrap());
    if leader == WIRE_DATA_LEADER {
        let len = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
        let mut rest = vec![0u8; len + 1];
        stream.read_exact(&mut rest).unwrap();
        pkt.extend_from_slice(&rest);
    }
    pkt
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

#[test]
fn file_io_create_file_gets_explicit_failure_reply() {
    let mut payload = vec![0u8; DBGKD_FILE_IO_HEADER_SIZE];
    payload[0..4].copy_from_slice(&DBGKD_CREATE_FILE_API.to_le_bytes());
    let ack = wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, WIRE_FIRST_PACKET_ID);
    let mut framing = KdFraming::new(Loopback::with_inbound(ack));

    handle_file_io(&mut framing, &payload).unwrap();

    let out = &framing.transport_ref().outbound;
    assert_eq!(out.len(), WIRE_HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE + 1);
    assert_eq!(
        u32::from_le_bytes(out[0..4].try_into().unwrap()),
        WIRE_DATA_LEADER
    );
    assert_eq!(
        u16::from_le_bytes(out[4..6].try_into().unwrap()),
        PACKET_TYPE_KD_FILE_IO
    );
    assert_eq!(
        u16::from_le_bytes(out[6..8].try_into().unwrap()) as usize,
        DBGKD_FILE_IO_HEADER_SIZE
    );
    assert_eq!(
        u32::from_le_bytes(out[8..12].try_into().unwrap()),
        WIRE_FIRST_PACKET_ID
    );
    let reply = &out[WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE];
    assert_eq!(
        u32::from_le_bytes(reply[0..4].try_into().unwrap()),
        DBGKD_CREATE_FILE_API
    );
    assert_eq!(
        u32::from_le_bytes(reply[4..8].try_into().unwrap()),
        STATUS_UNSUCCESSFUL
    );
    assert_eq!(
        out[WIRE_HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE],
        WIRE_TRAILER
    );
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
        pending_write_breakpoint: None,
        special_register_cache: HashMap::new(),
        stop_control_report: None,
        stop_was_managed_breakpoint: false,
        context_cache: HashMap::new(),
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
        let id = api::test_wire::INITIAL_PACKET_ID ^ (index as u32 & 1);
        stream.extend_from_slice(&api::test_wire::ack_then_reply(id, id, reply));
    }
    stream
}

fn refused_reply(api_number: u32) -> Vec<u8> {
    let mut reply = api::test_wire::build_reply(api_number, 0, &[], &[]);
    reply[8..12].copy_from_slice(&0xc000_0005u32.to_le_bytes());
    reply
}

#[test]
fn resume_does_not_step_past_a_breakpoint_it_does_not_own() {
    const PC: u64 = 0xffff_f800_0011_2233;

    for owned_by_us in [true, false] {
        let register_map = context::build_register_map();
        let mut guest_context = vec![0u8; context::CONTEXT_SIZE];
        register_map
            .write_u64("rip", &mut guest_context, PC)
            .unwrap();
        let mut replies = vec![api::test_wire::build_reply(
            api::DBGKD_GET_CONTEXT,
            0,
            &[],
            &guest_context,
        )];
        if !owned_by_us {
            replies.push(refused_reply(api::DBGKD_READ_VIRTUAL_MEMORY));
        }
        // Enough of an advance to complete if the resume wrongly attempts
        // one, so a regression trips the assertion below instead of
        // timing out on an unanswered request.
        replies.push(api::test_wire::build_reply(
            api::DBGKD_GET_CONTEXT,
            0,
            &[],
            &guest_context,
        ));
        for chunk in guest_context.chunks(512) {
            let mut union = [0u8; 12];
            wire::write_u32(&mut union, 8, chunk.len() as u32);
            replies.push(api::test_wire::build_reply(
                api::DBGKD_SET_CONTEXT_EX,
                0,
                &union,
                &[],
            ));
        }

        let (host, target) = UnixStream::pair().unwrap();
        (&target).write_all(&scripted_target(&replies)).unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.last_exception_code = STATUS_BREAKPOINT;
        backend.last_stop_processor = 0;
        backend.last_rip = PC;
        if owned_by_us {
            backend.managed_bp_addresses.insert(PC);
        }
        // Hold every table handle, so the resume has no stranded entry to
        // reclaim and the only requests on the wire are its own decision.
        for handle in 1..=KD_BREAKPOINT_TABLE_SIZE {
            backend
                .bp_handles
                .insert(0xdead_0000 + handle as u64, handle);
        }

        let outcome = backend.skip_hardcoded_breakpoint(0);
        target.set_nonblocking(true).unwrap();
        let mut sent = Vec::new();
        let _ = (&target).read_to_end(&mut sent);
        assert!(
            !sent
                .windows(4)
                .any(|word| wire::read_u32(word, 0) == api::DBGKD_SET_CONTEXT_EX),
            "resume stepped the PC past an int3 it does not own (owned_by_us={owned_by_us})"
        );
        outcome.unwrap();
    }
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
        pending_write_breakpoint: None,
        special_register_cache: HashMap::new(),
        stop_control_report: None,
        stop_was_managed_breakpoint: false,
        context_cache: HashMap::new(),
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

fn write_breakpoint_reply_payload(processor: u16, addr: u64, handle: u32) -> Vec<u8> {
    const MANIPULATE_UNION_OFFSET: usize = 16;

    let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE];
    payload[0..4].copy_from_slice(&api::DBGKD_WRITE_BREAKPOINT.to_le_bytes());
    payload[6..8].copy_from_slice(&processor.to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET..MANIPULATE_UNION_OFFSET + 8]
        .copy_from_slice(&addr.to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET + 8..MANIPULATE_UNION_OFFSET + 12]
        .copy_from_slice(&handle.to_le_bytes());
    payload
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

fn physical_memory_reply_payload(processor: u16, addr: u64, data: &[u8]) -> Vec<u8> {
    const MANIPULATE_UNION_OFFSET: usize = 16;

    let mut payload = vec![0u8; api::MANIPULATE_HEADER_SIZE];
    payload[0..4].copy_from_slice(&api::DBGKD_READ_PHYSICAL_MEMORY.to_le_bytes());
    payload[6..8].copy_from_slice(&processor.to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET..MANIPULATE_UNION_OFFSET + 8]
        .copy_from_slice(&addr.to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET + 8..MANIPULATE_UNION_OFFSET + 12]
        .copy_from_slice(&(data.len() as u32).to_le_bytes());
    payload[MANIPULATE_UNION_OFFSET + 12..MANIPULATE_UNION_OFFSET + 16]
        .copy_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(data);
    payload
}

#[test]
fn kd_memory_reads_physical_bytes_through_shared_backend() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.set_inline_running(false);
    backend.exit_prepared = true;
    let inner = Arc::new(Mutex::new(backend));
    let memory = KdMemory {
        inner: Arc::clone(&inner),
        translations: Arc::new(TranslationCache::default()),
    };
    let expected = [0xde, 0xad, 0xbe, 0xef];

    let worker = spawn(move || {
        let request = read_wire_packet(&mut kernel);
        let packet_id = u32::from_le_bytes(request[8..12].try_into().unwrap());
        assert_eq!(
            u32::from_le_bytes(request[16..20].try_into().unwrap()),
            api::DBGKD_READ_PHYSICAL_MEMORY
        );
        assert_eq!(
            u64::from_le_bytes(request[32..40].try_into().unwrap()),
            0x1234_5000
        );
        kernel
            .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, packet_id))
            .unwrap();
        let reply = physical_memory_reply_payload(0, 0x1234_5000, &expected);
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                WIRE_FIRST_PACKET_ID,
                &reply,
            ))
            .unwrap();
        let ack = read_wire_packet(&mut kernel);
        assert_eq!(
            u16::from_le_bytes(ack[4..6].try_into().unwrap()),
            PACKET_TYPE_KD_ACKNOWLEDGE
        );
    });

    let mut actual = [0u8; 4];
    memory.read_bytes(0x1234_5000, &mut actual).unwrap();
    worker.join().unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn kd_memory_rejects_reads_while_target_runs() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.exit_prepared = true;
    let memory = KdMemory {
        inner: Arc::new(Mutex::new(backend)),
        translations: Arc::new(TranslationCache::default()),
    };
    let error = memory.read_bytes(0x1000, &mut [0u8; 8]).unwrap_err();
    assert!(matches!(error, Error::TargetRunning(_)), "{error}");
}

/// A halted fake kernel serving `DbgKd{Read,Write}VirtualMemory` and
/// `DbgKdReadPhysicalMemory` from one map of regions (a region's address
/// is whichever kind the request names) until the host hangs up; returns
/// the request count so tests can assert how many round trips a guest
/// walk costs.
/// Like a real one it answers a request that touches mapped memory in
/// full, with zeros where no region says otherwise, and refuses one that
/// touches none.
fn serve_virtual_memory(kernel: UnixStream, regions: Vec<(u64, Vec<u8>)>) -> JoinHandle<usize> {
    serve_virtual_memory_capped(kernel, regions, usize::MAX)
}

/// [`serve_virtual_memory`] over a transport whose reply carries at most
/// `reply_cap` bytes of data, as a KDNET datagram does.
fn serve_virtual_memory_capped(
    mut kernel: UnixStream,
    mut regions: Vec<(u64, Vec<u8>)>,
    reply_cap: usize,
) -> JoinHandle<usize> {
    const UNION: usize = 16;
    spawn(move || {
        let mut kernel_id = WIRE_FIRST_PACKET_ID;
        let mut served = 0usize;
        loop {
            let mut header = [0u8; WIRE_HEADER_SIZE];
            if kernel.read_exact(&mut header).is_err() {
                return served;
            }
            if u32::from_le_bytes(header[0..4].try_into().unwrap()) != WIRE_DATA_LEADER {
                continue; // host ACK of our last reply
            }
            let len = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
            let mut request = vec![0u8; len + 1];
            kernel.read_exact(&mut request).unwrap();
            let host_id = u32::from_le_bytes(header[8..12].try_into().unwrap());
            kernel
                .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, host_id))
                .unwrap();

            let api_number = u32::from_le_bytes(request[0..4].try_into().unwrap());
            let addr = u64::from_le_bytes(request[UNION..UNION + 8].try_into().unwrap());
            let wanted =
                u32::from_le_bytes(request[UNION + 8..UNION + 12].try_into().unwrap()) as usize;
            served += 1;

            let mut reply = vec![0u8; api::MANIPULATE_HEADER_SIZE];
            reply[0..4].copy_from_slice(&api_number.to_le_bytes());
            reply[UNION..UNION + 8].copy_from_slice(&addr.to_le_bytes());
            reply[UNION + 8..UNION + 12].copy_from_slice(&(wanted as u32).to_le_bytes());
            if api_number == api::DBGKD_WRITE_VIRTUAL_MEMORY {
                let payload = &request[api::MANIPULATE_HEADER_SIZE..][..wanted];
                for (base, bytes) in &mut regions {
                    if let Some(start) = addr.checked_sub(*base)
                        && let Some(slot) = bytes.get_mut(start as usize..start as usize + wanted)
                    {
                        slot.copy_from_slice(payload);
                    }
                }
                reply[UNION + 12..UNION + 16].copy_from_slice(&(wanted as u32).to_le_bytes());
                kernel
                    .write_all(&wire_data_packet(
                        PACKET_TYPE_KD_STATE_MANIPULATE,
                        kernel_id,
                        &reply,
                    ))
                    .unwrap();
                kernel_id ^= 1;
                continue;
            }
            assert!(matches!(
                api_number,
                api::DBGKD_READ_VIRTUAL_MEMORY | api::DBGKD_READ_PHYSICAL_MEMORY
            ));
            let mut data = vec![0u8; wanted];
            let mut mapped = false;
            for (base, bytes) in &regions {
                let start = (*base).max(addr);
                let end = (*base + bytes.len() as u64).min(addr + wanted as u64);
                if start < end {
                    mapped = true;
                    let from = (start - *base) as usize;
                    let to = (start - addr) as usize;
                    let len = (end - start) as usize;
                    data[to..to + len].copy_from_slice(&bytes[from..from + len]);
                }
            }
            if mapped {
                let sent = wanted.min(reply_cap);
                reply[UNION + 12..UNION + 16].copy_from_slice(&(sent as u32).to_le_bytes());
                reply.extend_from_slice(&data[..sent]);
            } else {
                reply[8..12].copy_from_slice(&0xC000_0005u32.to_le_bytes());
            }
            kernel
                .write_all(&wire_data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    kernel_id,
                    &reply,
                ))
                .unwrap();
            kernel_id ^= 1;
        }
    })
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
        let mut kernel_id = WIRE_FIRST_PACKET_ID;
        let mut script = script.into_iter();
        let mut seen = Vec::new();
        loop {
            let mut header = [0u8; WIRE_HEADER_SIZE];
            if kernel.read_exact(&mut header).is_err() {
                assert!(script.next().is_none(), "missing breakpoint request");
                return seen;
            }
            if u32::from_le_bytes(header[0..4].try_into().unwrap()) != WIRE_DATA_LEADER {
                continue; // host ACK of our last reply
            }
            let len = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
            let mut request = vec![0u8; len + 1];
            kernel.read_exact(&mut request).unwrap();
            let host_id = u32::from_le_bytes(header[8..12].try_into().unwrap());
            kernel
                .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, host_id))
                .unwrap();

            let api_number = u32::from_le_bytes(request[0..4].try_into().unwrap());
            seen.push((api_number, wire::read_u64(&request, UNION)));

            let (expected_api, status, handle) =
                script.next().expect("unexpected breakpoint request");
            assert_eq!(api_number, expected_api);
            let mut reply = vec![0u8; api::MANIPULATE_HEADER_SIZE];
            reply[0..4].copy_from_slice(&api_number.to_le_bytes());
            reply[8..12].copy_from_slice(&status.to_le_bytes());
            reply[UNION + 8..UNION + 12].copy_from_slice(&handle.to_le_bytes());
            kernel
                .write_all(&wire_data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    kernel_id,
                    &reply,
                ))
                .unwrap();
            kernel_id ^= 1;
        }
    })
}

#[test]
fn breakpoint_install_reclaims_slots_stranded_by_a_dead_session() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.set_inline_running(false);
    backend.exit_prepared = true;
    backend.bp_handles.insert(0xfffff80000001000, 3);

    let mut script = vec![(api::DBGKD_WRITE_BREAKPOINT, STATUS_UNSUCCESSFUL, 0)];
    for handle in 1..=KD_BREAKPOINT_TABLE_SIZE {
        if handle == 3 {
            continue;
        }
        // Only slot 7 still holds a stranded entry; a free slot refuses
        // the handle, which is the answer for every other one.
        let status = if handle == 7 {
            api::STATUS_SUCCESS
        } else {
            STATUS_UNSUCCESSFUL
        };
        script.push((api::DBGKD_RESTORE_BREAKPOINT, status, 0));
    }
    script.push((api::DBGKD_WRITE_BREAKPOINT, api::STATUS_SUCCESS, 9));
    let worker = serve_breakpoints(kernel, script);

    backend.set_breakpoint(0xfffff80000002000).unwrap();

    assert_eq!(backend.bp_handles.get(&0xfffff80000002000), Some(&9));
    assert_eq!(backend.bp_handles.get(&0xfffff80000001000), Some(&3));
    drop(backend);
    let requests = worker.join().unwrap();
    let released: Vec<u64> = requests
        .iter()
        .filter(|(api_number, _)| *api_number == api::DBGKD_RESTORE_BREAKPOINT)
        .map(|(_, handle)| *handle)
        .collect();
    assert!(
        !released.contains(&3),
        "reclaim released a handle this session still owns: {released:?}"
    );
    assert_eq!(released.len(), KD_BREAKPOINT_TABLE_SIZE as usize - 1);
}

#[test]
fn a_refused_restore_keeps_a_site_that_still_holds_a_breakpoint() {
    const ADDR: u64 = 0xffff_f800_0001_2000;

    let mut refused = api::test_wire::build_reply(api::DBGKD_RESTORE_BREAKPOINT, 0, &[], &[]);
    refused[8..12].copy_from_slice(&STATUS_UNSUCCESSFUL.to_le_bytes());
    let mut probe = vec![0u8; api::MANIPULATE_HEADER_SIZE];
    wire::write_u32(&mut probe, 0, api::DBGKD_READ_VIRTUAL_MEMORY);
    wire::write_u64(&mut probe, 16, ADDR);
    wire::write_u32(&mut probe, 16 + 8, 1);
    wire::write_u32(&mut probe, 16 + 12, 1);
    probe.push(0xcc);

    let (host, target) = UnixStream::pair().unwrap();
    (&target)
        .write_all(&scripted_target(&[refused, probe]))
        .unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.bp_handles.insert(ADDR, 1);
    backend.managed_bp_addresses.insert(ADDR);

    let error = backend.remove_breakpoint(ADDR).unwrap_err();

    assert!(
        error.to_string().contains("still holds a breakpoint"),
        "unexpected error: {error}"
    );
    assert_eq!(backend.bp_handles.get(&ADDR), Some(&1));
    assert!(
        backend.managed_bp_addresses.contains(&ADDR),
        "an armed site was disowned, so a resume would step its program counter"
    );
}

#[test]
fn exit_restores_breakpoints_the_host_left_installed() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.set_inline_running(false);
    backend.bp_handles.insert(0xfffff80000003000, 4);
    backend.managed_bp_addresses.insert(0xfffff80000003000);

    let worker = serve_breakpoints(
        kernel,
        vec![(api::DBGKD_RESTORE_BREAKPOINT, api::STATUS_SUCCESS, 0)],
    );

    backend.prepare_for_exit(false).unwrap();

    assert!(backend.bp_handles.is_empty());
    assert!(backend.managed_bp_addresses.is_empty());
    drop(backend);
    assert_eq!(
        worker.join().unwrap(),
        vec![(api::DBGKD_RESTORE_BREAKPOINT, 4)]
    );
}

/// A halted fake kernel answering manipulate requests from an ordered
/// `(api, status, data)` script, asserting each request's API number.
fn serve_manipulate(mut kernel: UnixStream, script: Vec<(u32, u32, Vec<u8>)>) -> JoinHandle<()> {
    const UNION: usize = 16;
    spawn(move || {
        let mut kernel_id = WIRE_FIRST_PACKET_ID;
        let mut script = script.into_iter();
        loop {
            let mut header = [0u8; WIRE_HEADER_SIZE];
            if kernel.read_exact(&mut header).is_err() {
                assert!(script.next().is_none(), "missing manipulate request");
                return;
            }
            if u32::from_le_bytes(header[0..4].try_into().unwrap()) != WIRE_DATA_LEADER {
                continue; // host ACK of our last reply
            }
            let len = u16::from_le_bytes(header[6..8].try_into().unwrap()) as usize;
            let mut request = vec![0u8; len + 1];
            kernel.read_exact(&mut request).unwrap();
            let host_id = u32::from_le_bytes(header[8..12].try_into().unwrap());
            kernel
                .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, host_id))
                .unwrap();

            let (api_number, status, data) = script.next().expect("unexpected manipulate request");
            assert_eq!(
                u32::from_le_bytes(request[0..4].try_into().unwrap()),
                api_number
            );
            let mut reply = vec![0u8; api::MANIPULATE_HEADER_SIZE];
            reply[0..4].copy_from_slice(&api_number.to_le_bytes());
            reply[8..12].copy_from_slice(&status.to_le_bytes());
            reply[UNION + 12..UNION + 16].copy_from_slice(&(data.len() as u32).to_le_bytes());
            reply.extend_from_slice(&data);
            kernel
                .write_all(&wire_data_packet(
                    PACKET_TYPE_KD_STATE_MANIPULATE,
                    kernel_id,
                    &reply,
                ))
                .unwrap();
            kernel_id ^= 1;
        }
    })
}

#[test]
fn arm64_registers_survive_refused_control_space() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.arch = Arch::Arm64;
    backend.register_map = context_arm64::build_register_map();
    backend.link.set_inline_running(false);
    backend.exit_prepared = true;

    let mut ctx = vec![0u8; context_arm64::CONTEXT_SIZE];
    wire::write_u64(&mut ctx, context_arm64::OFFSET_PC, 0xffff_f800_1234_5678);
    wire::write_u64(&mut ctx, context_arm64::OFFSET_BVR0, 0xffff_f800_dead_0000);
    wire::write_u32(&mut ctx, context_arm64::OFFSET_BCR0, 0x1e5);
    let expected = ctx.clone();

    let worker = serve_manipulate(
        kernel,
        vec![
            (api::DBGKD_GET_CONTEXT, api::STATUS_SUCCESS, ctx),
            (
                api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER,
                0xc000_0001,
                Vec::new(),
            ),
            (api::DBGKD_READ_CONTROL_SPACE, 0xc000_0001, Vec::new()),
        ],
    );

    let regs = backend.read_registers().unwrap();

    assert_eq!(&regs[..context_arm64::CONTEXT_SIZE], &expected[..]);
    assert_eq!(
        backend.register_map.read_u64("bvr0", &regs).unwrap(),
        0xffff_f800_dead_0000
    );
    // A second read must not retry the refused control-space request, and
    // the halt's context is memoized, so it must not reach the wire at all:
    // the target above is scripted for exactly one fetch.
    assert_eq!(backend.read_registers().unwrap(), regs);
    drop(backend);
    worker.join().unwrap();
}

const FAKE_KERNEL_DTB: u64 = 0x1ad000;
const FAKE_KERNEL_BASE: u64 = 0xffff_f800_0000_0000;
const FAKE_GUID: u128 = 0x51;

fn field(offset: u32, size: u64, type_data: ParsedType) -> FieldInfo {
    FieldInfo {
        offset,
        size,
        type_data,
    }
}

fn primitive(offset: u32, size: u64) -> FieldInfo {
    field(offset, size, ParsedType::Primitive("u".into()))
}

fn layout(name: &str, size: usize, fields: &[(&str, FieldInfo)]) -> TypeInfo {
    TypeInfo {
        name: name.to_string(),
        pointer_size: 8,
        size,
        fields: fields
            .iter()
            .map(|(name, info)| (name.to_string(), info.clone()))
            .collect(),
    }
}

/// Build a halted KD-backed guest over `regions` with `types` and
/// `symbols` standing in for the kernel PDB. The backend is returned so a
/// test can resume it; the join handle yields the request count.
fn synthetic_guest(
    regions: Vec<(u64, Vec<u8>)>,
    types: Vec<TypeInfo>,
    symbols: &[(&str, u32)],
) -> (Guest, Arc<Mutex<KdBackend>>, JoinHandle<usize>) {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.set_inline_running(false);
    backend.exit_prepared = true;
    backend.kernel_dtb_override = FAKE_KERNEL_DTB;
    let translations = Arc::clone(&backend.translations);
    let inner = Arc::new(Mutex::new(backend));
    let phys = Arc::new(PhysMem::remote(KdMemory {
        inner: Arc::clone(&inner),
        translations,
    }));
    let store = Arc::new(SymbolStore::new());
    store.inject_module_for_test(FAKE_GUID, types, symbols);
    let mut ntoskrnl = WinObject::new_with_arch(
        phys,
        store,
        FAKE_KERNEL_DTB,
        VirtAddr(FAKE_KERNEL_BASE),
        Arch::Amd64,
    );
    ntoskrnl.guid = Some(FAKE_GUID);
    let worker = serve_virtual_memory(kernel, regions);
    (Guest::from_kernel(ntoskrnl), inner, worker)
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn resume_and_halt(backend: &Arc<Mutex<KdBackend>>) {
    let mut backend = backend.lock().unwrap();
    backend.record_running();
    backend.link.set_inline_running(false);
}

#[test]
fn process_walk_reads_one_span_per_process_and_memoizes_per_halt() {
    const PID: u32 = 0x440;
    const LINKS: u32 = 0x448;
    const NAME: u32 = 0x5a8;
    const DTB: u32 = 0x28;
    let eprocess = layout(
        "_EPROCESS",
        0x600,
        &[
            (
                "Pcb",
                field(0, 0x438, ParsedType::Struct("_KPROCESS".into())),
            ),
            ("UniqueProcessId", primitive(PID, 8)),
            ("ActiveProcessLinks", primitive(LINKS, 16)),
            ("ImageFileName", primitive(NAME, 15)),
        ],
    );
    let kprocess = layout(
        "_KPROCESS",
        0x438,
        &[("DirectoryTableBase", primitive(DTB, 8))],
    );

    let head = FAKE_KERNEL_BASE + 0x1008;
    let system = 0xffff_e000_0001_0000u64;
    let smss = 0xffff_e000_0002_0000u64;
    let mut nt = vec![0u8; 0x2000];
    put_u64(&mut nt, 0x1000, system);
    put_u64(&mut nt, 0x1008, system + LINKS as u64);
    let process = |pid: u64, dtb: u64, name: &[u8], next: u64| {
        let mut bytes = vec![0u8; 0x600];
        put_u64(&mut bytes, PID as usize, pid);
        put_u64(&mut bytes, DTB as usize, dtb);
        put_u64(&mut bytes, LINKS as usize, next + LINKS as u64);
        bytes[NAME as usize..NAME as usize + name.len()].copy_from_slice(name);
        bytes
    };
    let regions = vec![
        (FAKE_KERNEL_BASE, nt),
        (system, process(4, 0x1ad000, b"System", smss)),
        (
            smss,
            process(0x1d8, 0x2be000, b"smss.exe", head - LINKS as u64),
        ),
    ];
    let (guest, backend, worker) = synthetic_guest(
        regions,
        vec![eprocess, kprocess],
        &[
            ("PsInitialSystemProcess", 0x1000),
            ("PsActiveProcessHead", 0x1008),
        ],
    );

    let first = guest.enumerate_processes().unwrap();
    let names: Vec<_> = first.iter().map(|p| (p.name.as_str(), p.pid)).collect();
    assert_eq!(names, [("System", 4), ("smss.exe", 0x1d8)]);
    assert_eq!(first[1].dtb, 0x2be000);

    let second = guest.enumerate_processes().unwrap();
    assert_eq!(second.len(), 2);
    let one = guest.process_at(VirtAddr(smss)).unwrap();
    assert_eq!(
        (one.name.as_str(), one.pid, one.dtb),
        ("smss.exe", 0x1d8, 0x2be000)
    );

    resume_and_halt(&backend);
    assert_eq!(guest.enumerate_processes().unwrap().len(), 2);

    drop(guest);
    drop(backend);
    // The list head and each process span are one fill apiece, the
    // single-process lookup is served from the halt's lines, and the
    // resume drops them: three fills per halt.
    assert_eq!(worker.join().unwrap(), 3 + 3);
}

#[test]
fn user_space_of_the_current_process_is_read_in_one_request() {
    const USER_VA: u64 = 0x7ff6_1234_5000;
    const CURRENT_CR3: u64 = 0x2be000;
    let regions = vec![(USER_VA, b"PEB!".to_vec())];
    let (guest, backend, worker) = synthetic_guest(regions, Vec::new(), &[]);
    {
        let mut backend = backend.lock().unwrap();
        let mut special = vec![0u8; KSPECIAL_REGISTERS_MIN_SIZE];
        // PCID bits in CR3 do not distinguish roots.
        put_u64(
            &mut special,
            KSPECIAL_REGISTERS_CR3_OFFSET,
            CURRENT_CR3 | 0x1,
        );
        let processor = backend.current_processor;
        backend.special_register_cache.insert(processor, special);

        let mut out = [0u8; 4];
        // Another process's user space still needs the host walk.
        assert!(
            backend
                .read_virtual_direct(VirtAddr(USER_VA), 0x3cf000, &mut out)
                .is_none()
        );
        backend
            .read_virtual_direct(VirtAddr(USER_VA), CURRENT_CR3, &mut out)
            .unwrap()
            .unwrap();
        assert_eq!(&out, b"PEB!");
    }
    drop(guest);
    drop(backend);
    assert_eq!(worker.join().unwrap(), 1);
}

#[test]
fn kernel_module_walk_prefetches_each_record() {
    const DLL_BASE: u32 = 0x30;
    const SIZE: u32 = 0x40;
    const NAME: u32 = 0x58;
    const TIME_DATE_STAMP: u32 = 0x9c;
    const CHECK_SUM: u32 = 0x100;
    let entry = layout(
        "_KLDR_DATA_TABLE_ENTRY",
        0x120,
        &[
            ("InLoadOrderLinks", primitive(0, 16)),
            ("DllBase", primitive(DLL_BASE, 8)),
            ("SizeOfImage", primitive(SIZE, 4)),
            (
                "BaseDllName",
                field(NAME, 16, ParsedType::Struct("_UNICODE_STRING".into())),
            ),
            ("TimeDateStamp", primitive(TIME_DATE_STAMP, 4)),
            ("CheckSum", primitive(CHECK_SUM, 4)),
        ],
    );
    let unicode = layout(
        "_UNICODE_STRING",
        16,
        &[("Length", primitive(0, 2)), ("Buffer", primitive(8, 8))],
    );

    let head = FAKE_KERNEL_BASE + 0x2000;
    let names = 0xffff_e000_0009_0000u64;
    let entries = 0xffff_e000_000a_0000u64;
    let mut nt = vec![0u8; 0x3000];
    put_u64(&mut nt, 0x2000, entries);
    let name_bytes: Vec<u8> = "ntoskrnl.exe\0\0\0\0hal.dll"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut records = vec![0u8; 0x240];
    let mut record = |at: usize, next: u64, base: u64, name_off: u64, name_len: u16| {
        put_u64(&mut records, at, next);
        put_u64(&mut records, at + DLL_BASE as usize, base);
        records[at + SIZE as usize..at + SIZE as usize + 4]
            .copy_from_slice(&0x1000u32.to_le_bytes());
        records[at + NAME as usize..at + NAME as usize + 2]
            .copy_from_slice(&name_len.to_le_bytes());
        put_u64(&mut records, at + NAME as usize + 8, names + name_off);
    };
    record(0, entries + 0x120, FAKE_KERNEL_BASE, 0, 24);
    record(0x120, head, 0xffff_f800_1000_0000, 32, 14);
    let regions = vec![
        (FAKE_KERNEL_BASE, nt),
        (names, name_bytes),
        (entries, records),
    ];
    let (guest, backend, worker) = synthetic_guest(
        regions,
        vec![entry, unicode],
        &[("PsLoadedModuleList", 0x2000)],
    );

    let modules = guest.kernel_modules().unwrap();
    let seen: Vec<_> = modules
        .iter()
        .map(|m| (m.name.as_str(), m.base_address.0))
        .collect();
    assert_eq!(
        seen,
        [
            ("ntoskrnl.exe", FAKE_KERNEL_BASE),
            ("hal.dll", 0xffff_f800_1000_0000)
        ]
    );
    assert_eq!(guest.kernel_modules().unwrap().len(), 2);

    drop(guest);
    drop(backend);
    // The list head; the first record and both names fill their lines,
    // and the second record's tail spills into one more.
    assert_eq!(worker.join().unwrap(), 1 + 2 + 1);
}

#[test]
fn virtual_lines_serve_a_halt_and_drop_on_write_and_resume() {
    const FIELD: u64 = FAKE_KERNEL_BASE + 0x1010;
    let mut nt = vec![0u8; 0x2000];
    put_u64(&mut nt, 0x1010, 0x1111);
    put_u64(&mut nt, 0x1018, 0x2222);
    let (guest, backend, worker) = synthetic_guest(vec![(FAKE_KERNEL_BASE, nt)], Vec::new(), &[]);
    let read = |at: u64| {
        let mut out = [0u8; 8];
        backend
            .lock()
            .unwrap()
            .read_virtual_bytes(VirtAddr(at), &mut out)
            .unwrap();
        u64::from_le_bytes(out)
    };

    // Two fields of one line: one request.
    assert_eq!(read(FIELD), 0x1111);
    assert_eq!(read(FIELD + 8), 0x2222);
    // A debugger write is visible to the next read.
    backend
        .lock()
        .unwrap()
        .write_virtual_bytes(VirtAddr(FIELD), &0x3333u64.to_le_bytes())
        .unwrap();
    assert_eq!(read(FIELD), 0x3333);
    // A line does not outlive the halt.
    resume_and_halt(&backend);
    assert_eq!(read(FIELD + 8), 0x2222);
    // A read past the last line is refused, not served with a hole.
    let mut out = [0u8; 8];
    let error = backend
        .lock()
        .unwrap()
        .read_virtual_bytes(VirtAddr(FAKE_KERNEL_BASE + 0x2000), &mut out)
        .unwrap_err();
    assert!(matches!(error, Error::BadVirtualAddress(_)), "{error}");

    drop(guest);
    drop(backend);
    // read, write, read, read, refused read
    assert_eq!(worker.join().unwrap(), 5);
}

#[test]
fn page_table_lines_serve_a_halt_and_drop_on_write_and_resume() {
    const TABLE: u64 = 0x1ad000;
    let mut table = vec![0u8; PAGE_SIZE];
    put_u64(&mut table, 0x10, 0x1111);
    put_u64(&mut table, 0x18, 0x2222);
    put_u64(&mut table, 0x800, 0x3333);
    let (guest, backend, worker) = synthetic_guest(vec![(TABLE, table)], Vec::new(), &[]);
    let read = |at: u64| {
        let mut out = [0u8; 8];
        backend
            .lock()
            .unwrap()
            .read_page_table_bytes(at, &mut out)
            .unwrap();
        u64::from_le_bytes(out)
    };

    // Two entries of one line: one request; another line: one more.
    assert_eq!(read(TABLE + 0x10), 0x1111);
    assert_eq!(read(TABLE + 0x18), 0x2222);
    assert_eq!(read(TABLE + 0x800), 0x3333);
    // A virtual write may land in a table: the lines are dropped.
    backend
        .lock()
        .unwrap()
        .write_virtual_bytes(VirtAddr(FAKE_KERNEL_BASE), &[0u8; 8])
        .unwrap();
    assert_eq!(read(TABLE + 0x10), 0x1111);
    resume_and_halt(&backend);
    assert_eq!(read(TABLE + 0x18), 0x2222);

    drop(guest);
    drop(backend);
    // two lines, write, line, line
    assert_eq!(worker.join().unwrap(), 5);
}

#[test]
fn truncated_fills_keep_whole_lines_and_finish_the_read() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.set_inline_running(false);
    backend.exit_prepared = true;
    let bytes: Vec<u8> = (0..0x1000u32).map(|i| i as u8 ^ (i >> 8) as u8).collect();
    let worker =
        serve_virtual_memory_capped(kernel, vec![(FAKE_KERNEL_BASE, bytes.clone())], 0x300);

    let mut out = vec![0u8; 0x800];
    backend
        .read_virtual_bytes(VirtAddr(FAKE_KERNEL_BASE), &mut out)
        .unwrap();
    assert_eq!(out, bytes[..0x800]);
    // The tail of the truncated reply was not kept as a short line.
    let mut tail = [0u8; 8];
    backend
        .read_virtual_bytes(VirtAddr(FAKE_KERNEL_BASE + 0x2f8), &mut tail)
        .unwrap();
    assert_eq!(tail, bytes[0x2f8..0x300]);
    // Later fills stay within what the transport returns.
    assert_eq!(backend.virtual_fill_cap, KD_VIRTUAL_LINE);

    drop(backend);
    // 0x800 asked and 0x300 answered, then one line per request.
    assert_eq!(worker.join().unwrap(), 1 + 3);
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

#[test]
fn known_breakin_stop_is_marked_assisted_unless_managed() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let breakin_clone = host.try_clone().unwrap();
    let pump_host = host.try_clone().unwrap();
    let pump = PumpHandle {
        join: spawn(move || KdFraming::new(pump_host.into())),
        stop_rx: mpsc::channel().1,
        shutdown: Arc::new(AtomicBool::new(false)),
        reported_stop: Arc::new(AtomicBool::new(false)),
        breakin_requested: Arc::new(AtomicBool::new(false)),
    };
    let mut backend = kd_backend_with_pump(pump, breakin_clone);
    let pc = 0xfffff800_deadbeef;
    backend.breakin_addresses.insert(pc);

    let stop = StateChange {
        processor: 0,
        number_processors: 1,
        new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
        exception_code: STATUS_BREAKPOINT,
        exception_first_chance: Some(true),
        exception_address: Some(pc),
        program_counter: pc,
        kernel_base_hint: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        assisted_breakin: false,
        control_report: None,
    };

    assert!(
        backend
            .mark_known_breakin_stop(stop.clone())
            .assisted_breakin
    );
    backend.managed_bp_addresses.insert(pc);
    assert!(!backend.mark_known_breakin_stop(stop).assisted_breakin);
}

#[test]
fn continue_drains_in_place_rebreak_and_stale_breakin() {
    let resumed_from = 0xffff_f800_0013_40c4;
    let breakin = 0xffff_f800_002f_90d0;
    let drain = |managed: &[u64]| {
        ContinueDrain::new(
            resumed_from,
            managed.iter().copied().collect(),
            HashSet::from([breakin]),
            context::build_register_map(),
        )
    };

    let stop_at = |code: u32, pc: u64| StateChange {
        processor: 0,
        number_processors: 1,
        new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
        exception_code: code,
        exception_first_chance: Some(true),
        exception_address: Some(pc),
        program_counter: pc,
        kernel_base_hint: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        assisted_breakin: false,
        control_report: None,
    };

    assert!(drain(&[]).is_spurious(&stop_at(STATUS_BREAKPOINT, resumed_from)));
    assert!(drain(&[]).is_spurious(&stop_at(STATUS_BREAKPOINT, breakin)));

    assert!(!drain(&[breakin]).is_spurious(&stop_at(STATUS_BREAKPOINT, breakin)));

    assert!(!drain(&[]).is_spurious(&stop_at(STATUS_BREAKPOINT, 0xdead_0000)));
    assert!(!drain(&[]).is_spurious(&stop_at(STATUS_SINGLE_STEP, resumed_from)));

    let mut assisted = stop_at(STATUS_BREAKPOINT, breakin);
    assisted.assisted_breakin = true;
    assert!(!drain(&[]).is_spurious(&assisted));
    let mut reloaded = stop_at(STATUS_BREAKPOINT, resumed_from);
    reloaded.target_reloaded = true;
    assert!(!drain(&[]).is_spurious(&reloaded));

    let interrupted = drain(&[]);
    interrupted.interrupt_flag().store(true, Ordering::SeqCst);
    assert!(!interrupted.is_spurious(&stop_at(STATUS_BREAKPOINT, resumed_from)));
}

#[test]
fn pending_write_breakpoint_retry_completes_late_reply_without_resend() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut backend = kd_backend_with_framing(host);
    let addr = 0xfffff800_12345678;
    let handle = 7;
    backend.pending_write_breakpoint = Some(PendingWriteBreakpoint { addr, processor: 0 });

    let payload = write_breakpoint_reply_payload(0, addr, handle);
    kernel
        .write_all(&wire_data_packet(
            PACKET_TYPE_KD_STATE_MANIPULATE,
            WIRE_FIRST_PACKET_ID,
            &payload,
        ))
        .unwrap();
    kernel.flush().unwrap();

    backend.set_breakpoint(addr).unwrap();

    assert_eq!(backend.bp_handles.get(&addr), Some(&handle));
    assert!(backend.managed_bp_addresses.contains(&addr));
    assert!(backend.pending_write_breakpoint.is_none());

    let ack = read_wire_packet(&mut kernel);
    assert_eq!(
        u32::from_le_bytes(ack[0..4].try_into().unwrap()),
        WIRE_CONTROL_LEADER
    );
    assert_eq!(
        u16::from_le_bytes(ack[4..6].try_into().unwrap()),
        PACKET_TYPE_KD_ACKNOWLEDGE
    );
    assert_eq!(
        u32::from_le_bytes(ack[8..12].try_into().unwrap()),
        WIRE_FIRST_PACKET_ID
    );

    let mut extra = [0u8; 1];
    match kernel.read(&mut extra) {
        Err(e) if is_temporary_io_error(e.kind()) => {}
        Ok(0) => {}
        Ok(n) => panic!("unexpected duplicate KD request: read {n} byte(s)"),
        Err(e) => panic!("unexpected socket read error: {e}"),
    }
}

#[test]
fn pending_write_breakpoint_blocks_unrelated_kd_requests() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    let addr = 0xfffff800_12345678;
    backend.pending_write_breakpoint = Some(PendingWriteBreakpoint { addr, processor: 0 });

    let err = backend
        .set_breakpoint(addr + 1)
        .expect_err("different breakpoint should be rejected while install is pending");
    let message = err.to_string();
    assert!(message.contains("breakpoint install at 0xfffff80012345678 is pending"));
    assert!(message.contains("retry the same bp command"));

    let err = backend
        .target_kernel_base_hint()
        .expect_err("other KD requests should be rejected while install is pending");
    assert!(err.to_string().contains("retry the same bp command"));
}

#[test]
fn pump_services_state_change_and_returns_framing() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };

    let pc = 0xfffff800_deadbeef;
    let pkt = wire_data_packet(
        PACKET_TYPE_KD_STATE_CHANGE64,
        WIRE_FIRST_PACKET_ID,
        &exception_state_change_payload(pc),
    );
    kernel.write_all(&pkt).unwrap();
    kernel.flush().unwrap();

    let stop = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("pump reported no stop")
        .expect("pump reported an error");
    assert_eq!(stop.program_counter, pc);
    assert_eq!(stop.exception_code, STATUS_BREAKPOINT);

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
}

#[test]
fn exit_resume_consumes_pump_stop_before_final_continue() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let breakin_clone = host.try_clone().unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let join = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };
    let pump = PumpHandle {
        join,
        stop_rx: rx,
        shutdown,
        reported_stop: Arc::new(AtomicBool::new(false)),
        breakin_requested: Arc::new(AtomicBool::new(false)),
    };
    let mut backend = kd_backend_with_pump(pump, breakin_clone);
    let (continue_tx, continue_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let kernel_thread = spawn(move || {
        let pc = 0xfffff800_deadbeef;
        let mut payload = exception_state_change_payload(pc);
        payload[32..36].copy_from_slice(&0xc000_0005u32.to_le_bytes());
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_CHANGE64,
                WIRE_FIRST_PACKET_ID,
                &payload,
            ))
            .unwrap();
        kernel.flush().unwrap();

        let ack = read_wire_packet(&mut kernel);
        assert_eq!(
            u32::from_le_bytes(ack[0..4].try_into().unwrap()),
            WIRE_CONTROL_LEADER
        );
        assert_eq!(
            u16::from_le_bytes(ack[4..6].try_into().unwrap()),
            PACKET_TYPE_KD_ACKNOWLEDGE
        );

        let read_special_packet = read_wire_packet(&mut kernel);
        let read_special_request =
            &read_special_packet[WIRE_HEADER_SIZE..WIRE_HEADER_SIZE + api::MANIPULATE_HEADER_SIZE];
        assert_eq!(
            u32::from_le_bytes(read_special_request[0..4].try_into().unwrap()),
            api::DBGKD_READ_CONTROL_SPACE
        );
        let read_special_id = u32::from_le_bytes(read_special_packet[8..12].try_into().unwrap());
        kernel
            .write_all(&wire_control_packet(
                PACKET_TYPE_KD_ACKNOWLEDGE,
                read_special_id,
            ))
            .unwrap();
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                WIRE_FIRST_PACKET_ID ^ 1,
                &read_special_registers_reply_payload(0),
            ))
            .unwrap();
        kernel.flush().unwrap();

        let read_special_ack = read_wire_packet(&mut kernel);
        assert_eq!(
            u16::from_le_bytes(read_special_ack[4..6].try_into().unwrap()),
            PACKET_TYPE_KD_ACKNOWLEDGE
        );

        let continue_packet = read_wire_packet(&mut kernel);
        let continue_id = u32::from_le_bytes(continue_packet[8..12].try_into().unwrap());
        continue_tx.send(continue_packet).unwrap();
        kernel
            .write_all(&wire_control_packet(
                PACKET_TYPE_KD_ACKNOWLEDGE,
                continue_id,
            ))
            .unwrap();
        kernel.flush().unwrap();
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    });

    backend.prepare_for_exit(true).unwrap();
    done_tx.send(()).unwrap();
    kernel_thread.join().expect("kernel thread panicked");
    let continue_packet = continue_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("kernel thread did not capture continue packet");

    assert!(matches!(backend.link, Link::RunningInline(_)));
    assert!(backend.exit_prepared);
    assert_eq!(
        u32::from_le_bytes(continue_packet[0..4].try_into().unwrap()),
        WIRE_DATA_LEADER
    );
    assert_eq!(
        u16::from_le_bytes(continue_packet[4..6].try_into().unwrap()),
        PACKET_TYPE_KD_STATE_MANIPULATE
    );
    let request = &continue_packet[WIRE_HEADER_SIZE..];
    assert_eq!(
        u32::from_le_bytes(request[0..4].try_into().unwrap()),
        api::DBGKD_CONTINUE_API2
    );
    assert_eq!(
        u32::from_le_bytes(request[16..20].try_into().unwrap()),
        api::DBG_CONTINUE
    );
}

#[test]
fn explicit_halted_exit_suppresses_drop_resume() {
    let (host, _kernel) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.set_inline_running(false);

    backend.prepare_for_exit(false).unwrap();
    let needs_drop_cleanup = backend.needs_drop_cleanup();
    backend.link.set_inline_running(true);

    assert!(backend.exit_prepared);
    assert!(!needs_drop_cleanup);
}

#[test]
fn pump_shutdown_without_a_pump_keeps_the_framing() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.set_inline_running(false);

    assert!(backend.shutdown_pump_with_stop().unwrap().is_none());
    assert!(matches!(backend.link, Link::Halted(_)));
    backend.reclaim_framing();
    assert!(matches!(backend.link, Link::Halted(_)));
    assert!(backend.framing().is_ok());

    backend.link.set_inline_running(true);
}

#[test]
fn exit_classifies_stray_single_step_but_spares_real_stops() {
    let pc = 0xfffff800_deadbeef;
    let mut managed = HashSet::new();
    let stop_at = |code: Option<u32>, pc: Option<u64>, is_bugcheck: bool| StopEvent {
        thread_id: None,
        exception_code: code,
        first_chance: code.map(|_| true),
        exception_address: pc,
        program_counter: pc,
        is_bugcheck,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: false,
        assisted_breakin: false,
    };

    assert!(exit_stop_is_stray_single_step(
        &stop_at(Some(STATUS_SINGLE_STEP), Some(pc), false),
        &managed,
    ));
    assert!(exit_stop_is_stray_single_step(
        &stop_at(Some(STATUS_SINGLE_STEP), None, false),
        &managed,
    ));

    managed.insert(pc);
    assert!(!exit_stop_is_stray_single_step(
        &stop_at(Some(STATUS_SINGLE_STEP), Some(pc), false),
        &managed,
    ));

    assert!(!exit_stop_is_stray_single_step(
        &stop_at(Some(STATUS_BREAKPOINT), Some(0x1000), false),
        &managed,
    ));
    assert!(!exit_stop_is_stray_single_step(
        &stop_at(Some(STATUS_SINGLE_STEP), Some(0x1000), true),
        &managed,
    ));
}

#[test]
fn has_pending_stop_flags_undrained_pump_stop_until_consumed() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let breakin_clone = host.try_clone().unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let reported_stop = Arc::new(AtomicBool::new(false));
    let join = {
        let shutdown = Arc::clone(&shutdown);
        let reported_stop = Arc::clone(&reported_stop);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop,
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };
    let pump = PumpHandle {
        join,
        stop_rx: rx,
        shutdown,
        reported_stop,
        breakin_requested: Arc::new(AtomicBool::new(false)),
    };
    let mut backend = kd_backend_with_pump(pump, breakin_clone);

    assert!(backend.is_running());
    assert!(!backend.has_pending_stop());

    let pc = 0xfffff800_deadbeef;
    let mut payload = exception_state_change_payload(pc);
    payload[32..36].copy_from_slice(&STATUS_BREAKPOINT.to_le_bytes());
    kernel
        .write_all(&wire_data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            WIRE_FIRST_PACKET_ID,
            &payload,
        ))
        .unwrap();
    kernel.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !backend.has_pending_stop() {
        assert!(
            Instant::now() < deadline,
            "pump never flagged the reported stop"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    assert!(backend.is_running());
    assert!(backend.has_pending_stop());

    let stop = backend
        .take_pump_stop(Some(Duration::from_secs(5)))
        .unwrap()
        .expect("pump reported no stop");
    assert_eq!(stop.program_counter, pc);
    assert!(matches!(backend.link, Link::RunningInline(_)));
    assert!(!backend.has_pending_stop());
    backend.record_stop(&stop);
    assert!(matches!(backend.link, Link::Halted(_)));
    backend.exit_prepared = true;
}

#[test]
fn pump_absorbs_rebreak_after_continue_and_reports_real_stop() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let framing = KdFraming::new(host.into());
    let resumed_from = 0xfffff800_deadbeef;
    let real_stop = 0xfffff800_cafe0000;
    let drain = ContinueDrain::new(
        resumed_from,
        HashSet::new(),
        HashSet::new(),
        context::build_register_map(),
    );
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                Some(drain),
            )
        })
    };

    let mut kernel_id = WIRE_FIRST_PACKET_ID;
    let mut send = |kernel: &mut UnixStream, packet_type: u16, payload: &[u8]| {
        kernel
            .write_all(&wire_data_packet(packet_type, kernel_id, payload))
            .unwrap();
        kernel.flush().unwrap();
        kernel_id ^= 1;
    };

    send(
        &mut kernel,
        PACKET_TYPE_KD_STATE_CHANGE64,
        &exception_state_change_payload(resumed_from),
    );

    let mut context_written = 0usize;
    loop {
        let packet = read_wire_packet(&mut kernel);
        if u32::from_le_bytes(packet[0..4].try_into().unwrap()) == WIRE_CONTROL_LEADER {
            continue;
        }
        let host_id = u32::from_le_bytes(packet[8..12].try_into().unwrap());
        let request = &packet[WIRE_HEADER_SIZE..packet.len() - 1];
        let api_number = u32::from_le_bytes(request[0..4].try_into().unwrap());
        kernel
            .write_all(&wire_control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, host_id))
            .unwrap();
        let reply = match api_number {
            api::DBGKD_GET_CONTEXT => {
                let mut context = vec![0u8; context::CONTEXT_SIZE];
                context[context::OFFSET_RIP..context::OFFSET_RIP + 8]
                    .copy_from_slice(&resumed_from.to_le_bytes());
                let mut reply = manipulate_reply_payload(api_number, 0, &[]);
                reply.extend_from_slice(&context);
                reply
            }
            api::DBGKD_SET_CONTEXT_EX => {
                let chunk = &request[api::MANIPULATE_HEADER_SIZE..];
                context_written += chunk.len();
                let mut union = [0u8; 12];
                union[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
                manipulate_reply_payload(api_number, 0, &union)
            }
            api::DBGKD_READ_VIRTUAL_MEMORY => {
                // The absorbed re-break sits on a break-in `int3`, which
                // the pump confirms before stepping the PC past it.
                let mut union = [0u8; 16];
                union[12..16].copy_from_slice(&1u32.to_le_bytes());
                let mut reply = manipulate_reply_payload(api_number, 0, &union);
                reply.push(0xcc);
                reply
            }
            api::DBGKD_READ_CONTROL_SPACE => read_special_registers_reply_payload(0),
            api::DBGKD_CONTINUE_API2 => break,
            other => panic!("unexpected request {other:#x} while absorbing a re-break"),
        };
        send(&mut kernel, PACKET_TYPE_KD_STATE_MANIPULATE, &reply);
    }
    assert_eq!(
        context_written,
        context::CONTEXT_SIZE,
        "the pump must write back the whole advanced context"
    );
    assert!(
        rx.try_recv().is_err(),
        "an absorbed re-break must not be reported"
    );

    send(
        &mut kernel,
        PACKET_TYPE_KD_STATE_CHANGE64,
        &exception_state_change_payload(real_stop),
    );
    let stop = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("pump reported no stop")
        .expect("pump reported an error");
    assert_eq!(stop.program_counter, real_stop);

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
}

#[test]
fn pump_sends_breakin_after_peer_reset_while_waiting_for_reconnect() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };

    kernel
        .write_all(&wire_control_packet(PACKET_TYPE_KD_RESET, 0))
        .unwrap();
    kernel.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_breakin = false;
    let mut buf = [0u8; 64];
    while Instant::now() < deadline && !saw_breakin {
        match kernel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                saw_breakin = buf[..n].contains(&BREAKIN_BYTE);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("failed to read pump output: {e}"),
        }
    }
    assert!(saw_breakin, "pump should assist reboot reconnects");

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
    assert!(
        rx.try_recv().is_err(),
        "reset alone should not report a stop"
    );
}

#[test]
fn pump_tags_stop_after_assisted_reconnect_breakin() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };

    kernel
        .write_all(&wire_control_packet(PACKET_TYPE_KD_RESET, 0))
        .unwrap();
    kernel.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_breakin = false;
    let mut buf = [0u8; 64];
    while Instant::now() < deadline && !saw_breakin {
        match kernel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                saw_breakin = buf[..n].contains(&BREAKIN_BYTE);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("failed to read pump output: {e}"),
        }
    }
    assert!(saw_breakin, "pump should send reconnect break-in");

    let pc = 0xfffff800_deadbeef;
    kernel
        .write_all(&wire_data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            WIRE_FIRST_PACKET_ID,
            &exception_state_change_payload(pc),
        ))
        .unwrap();
    kernel.flush().unwrap();

    let stop = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("pump reported no stop")
        .expect("pump reported an error");
    assert_eq!(stop.program_counter, pc);
    assert!(stop.target_reloaded);
    assert!(stop.assisted_breakin);

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
}

#[test]
fn pump_surfaces_reloaded_transparent_state_change() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };

    kernel
        .write_all(&wire_control_packet(PACKET_TYPE_KD_RESET, 0))
        .unwrap();
    let pc = 0xfffff800_feedface;
    kernel
        .write_all(&wire_data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            WIRE_FIRST_PACKET_ID,
            &state_change_payload(DBG_KD_LOAD_SYMBOLS_STATE_CHANGE, pc),
        ))
        .unwrap();
    kernel.flush().unwrap();

    let stop = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("pump reported no stop")
        .expect("pump reported an error");
    assert_eq!(stop.new_state, DBG_KD_LOAD_SYMBOLS_STATE_CHANGE);
    assert_eq!(stop.program_counter, pc);
    assert!(stop.target_reloaded);

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
}

#[test]
fn pump_surfaces_load_symbols_as_a_module_change_stop() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };

    let pc = 0xfffff800_cafebabe;
    kernel
        .write_all(&wire_data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            WIRE_FIRST_PACKET_ID,
            &state_change_payload(DBG_KD_LOAD_SYMBOLS_STATE_CHANGE, pc),
        ))
        .unwrap();
    kernel.flush().unwrap();

    let stop = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("pump reported no load-symbols notification")
        .expect("pump reported an error");
    assert_eq!(stop.new_state, DBG_KD_LOAD_SYMBOLS_STATE_CHANGE);
    assert_eq!(stop.program_counter, pc);
    assert!(stop_event(stop).modules_changed);

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
}

#[test]
fn pump_sends_breakin_when_started_in_reconnect_assist_mode() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                Some(Duration::ZERO),
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_breakin = false;
    let mut buf = [0u8; 64];
    while Instant::now() < deadline && !saw_breakin {
        match kernel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                saw_breakin = buf[..n].contains(&BREAKIN_BYTE);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("failed to read pump output: {e}"),
        }
    }
    assert!(
        saw_breakin,
        "post-bugcheck reconnect assist should not require a reset packet first"
    );

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
    assert!(
        rx.try_recv().is_err(),
        "assist alone should not report a stop"
    );
}

#[test]
fn pump_does_not_send_delayed_reconnect_assist_before_delay() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, _rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                Some(Duration::from_secs(60)),
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };

    let deadline = Instant::now() + Duration::from_millis(200);
    let mut saw_breakin = false;
    let mut buf = [0u8; 64];
    while Instant::now() < deadline {
        match kernel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if buf[..n].contains(&BREAKIN_BYTE) {
                    saw_breakin = true;
                    break;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => panic!("failed to read pump output: {e}"),
        }
    }
    assert!(
        !saw_breakin,
        "delayed post-bugcheck reconnect assist should not fire immediately"
    );

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
}

#[test]
fn await_refresh_sets_flag_without_breakin() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let handle = spawn(move || {
        let mut framing = KdFraming::new(host.into());
        let mut saw_refresh = false;
        let stop = await_state_change(
            &mut framing,
            AwaitStateOptions {
                arch: Arch::Amd64,
                saw_kd_refresh: Some(&mut saw_refresh),
                surface_all: false,
                bugcheck: None,
                bugcheck_capture: None,
                deadline: None,
                debug_log: None,
            },
        )
        .expect("await_state_change failed");
        (saw_refresh, stop)
    });

    let refresh = debug_io_print_payload(KD_REFRESH_MESSAGE);
    kernel
        .write_all(&wire_data_packet(
            PACKET_TYPE_KD_DEBUG_IO,
            WIRE_FIRST_PACKET_ID,
            &refresh,
        ))
        .unwrap();
    kernel.flush().unwrap();

    let mut outbound = Vec::new();
    let mut buf = [0u8; 64];
    while outbound.len() < WIRE_HEADER_SIZE {
        match kernel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => outbound.extend_from_slice(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(e) => panic!("failed to read ACK: {e}"),
        }
    }
    assert!(
        outbound.len() >= WIRE_HEADER_SIZE,
        "refresh packet should be ACKed"
    );
    assert!(
        !outbound.contains(&BREAKIN_BYTE),
        "refresh ACK should not include a break-in"
    );

    let immediate_window = Instant::now() + Duration::from_millis(30);
    while Instant::now() < immediate_window {
        match kernel.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                assert!(
                    !buf[..n].contains(&BREAKIN_BYTE),
                    "plain KD refresh should not trigger an immediate break-in"
                );
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break;
            }
            Err(e) => panic!("failed to read post-refresh output: {e}"),
        }
    }

    let pc = 0xfffff800_deadbeef;
    kernel
        .write_all(&wire_data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            WIRE_FIRST_PACKET_ID ^ 1,
            &exception_state_change_payload(pc),
        ))
        .unwrap();
    kernel.flush().unwrap();

    let (saw_refresh, stop) = handle.join().expect("await thread panicked");
    assert!(saw_refresh);
    assert_eq!(stop.program_counter, pc);
}

/// Drive `await_state_change` in bugcheck-aware mode: the fake kernel sends
/// `prints` then an exception state-change, ACKing whatever comes back.
fn await_bugcheck_aware(prints: &[&[u8]], pc: u64) -> StateChange {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let handle = spawn(move || {
        let mut framing = KdFraming::new(host.into());
        let mut bugcheck = false;
        let mut capture = BugcheckCapture::default();
        await_state_change(
            &mut framing,
            AwaitStateOptions {
                arch: Arch::Amd64,
                saw_kd_refresh: None,
                surface_all: false,
                bugcheck: Some(&mut bugcheck),
                bugcheck_capture: Some(&mut capture),
                deadline: None,
                debug_log: None,
            },
        )
        .expect("await_state_change failed")
    });

    let mut packet_id = WIRE_FIRST_PACKET_ID;
    let mut buf = [0u8; 128];
    for text in prints {
        kernel
            .write_all(&wire_data_packet(
                PACKET_TYPE_KD_DEBUG_IO,
                packet_id,
                &debug_io_print_payload(text),
            ))
            .unwrap();
        kernel.flush().unwrap();
        let _ = kernel.read(&mut buf);
        packet_id ^= 1;
    }
    kernel
        .write_all(&wire_data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            packet_id,
            &exception_state_change_payload(pc),
        ))
        .unwrap();
    kernel.flush().unwrap();
    handle.join().expect("await thread panicked")
}

#[test]
fn refresh_print_alone_does_not_mark_the_next_stop_as_a_bugcheck() {
    // The kernel prints the refresh at boot and whenever it re-probes the
    // debugger; only the fatal-error print means a crash is in progress.
    let stop = await_bugcheck_aware(&[KD_REFRESH_MESSAGE], 0xffff_f800_0000_1000);
    assert!(!stop.is_bugcheck);
    assert!(stop.bugcheck.is_none());
}

#[test]
fn fatal_system_error_print_marks_the_next_stop_with_captured_bugcheck() {
    let stop = await_bugcheck_aware(
        &[
            KD_REFRESH_MESSAGE,
            b"\r\n*** Fatal System Error: 0x000000d1\r\n                       (0x1,0x2,0x0,0x4)\r\n",
            b"Driver at fault: myfault.sys.\r\n",
        ],
        0xffff_f800_0000_1000,
    );
    assert!(stop.is_bugcheck);
    let info = stop.bugcheck.expect("captured bugcheck");
    assert_eq!(info.code, 0xd1);
    assert_eq!(info.parameters, [1, 2, 0, 4]);
    assert_eq!(info.driver.as_deref(), Some("myfault.sys"));
}

#[test]
fn only_exception_state_changes_surface_as_breaks() {
    assert!(!is_transparent_state_change(DBG_KD_EXCEPTION_STATE_CHANGE));
    assert!(!is_transparent_state_change(0xdead_beef));
    assert!(is_transparent_state_change(
        DBG_KD_LOAD_SYMBOLS_STATE_CHANGE
    ));
    assert!(is_transparent_state_change(
        DBG_KD_COMMAND_STRING_STATE_CHANGE
    ));
}

#[test]
fn pump_exits_on_shutdown_when_idle() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let handle = {
        let shutdown = Arc::clone(&shutdown);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop: Arc::new(AtomicBool::new(false)),
                },
                None,
                DebugLog::new(DEBUG_LOG_CAPACITY),
                None,
            )
        })
    };

    shutdown.store(true, Ordering::SeqCst);
    let _framing = handle.join().expect("pump thread panicked");
    assert!(rx.try_recv().is_err(), "idle pump should report no stop");
}
