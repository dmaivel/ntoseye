//! Tests for debug I/O parsing and bugcheck capture.

use super::*;

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
