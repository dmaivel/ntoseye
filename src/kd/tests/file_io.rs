//! Tests for target file I/O replies.

use super::*;

use crate::kd::framing::{
    DATA_PACKET_LEADER, HEADER_SIZE, INITIAL_PACKET_ID, PACKET_TRAILING_BYTE,
    PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_FILE_IO, control_packet,
};

#[test]
fn file_io_create_file_gets_explicit_failure_reply() {
    let mut payload = vec![0u8; DBGKD_FILE_IO_HEADER_SIZE];
    payload[0..4].copy_from_slice(&DBGKD_CREATE_FILE_API.to_le_bytes());
    let ack = control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, INITIAL_PACKET_ID);
    let mut framing = KdFraming::new(Loopback::with_inbound(ack));

    handle_file_io(&mut framing, &payload).unwrap();

    let out = &framing.transport_ref().outbound;
    assert_eq!(out.len(), HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE + 1);
    assert_eq!(wire_header(out).leader, DATA_PACKET_LEADER);
    assert_eq!(wire_header(out).packet_type, PACKET_TYPE_KD_FILE_IO);
    assert_eq!(
        wire_header(out).byte_count as usize,
        DBGKD_FILE_IO_HEADER_SIZE
    );
    assert_eq!(wire_header(out).packet_id, INITIAL_PACKET_ID);
    let reply = &out[HEADER_SIZE..HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE];
    assert_eq!(
        u32::from_le_bytes(reply[0..4].try_into().unwrap()),
        DBGKD_CREATE_FILE_API
    );
    assert_eq!(
        u32::from_le_bytes(reply[4..8].try_into().unwrap()),
        STATUS_UNSUCCESSFUL
    );
    assert_eq!(
        out[HEADER_SIZE + DBGKD_FILE_IO_HEADER_SIZE],
        PACKET_TRAILING_BYTE
    );
}
