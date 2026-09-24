//! Tests for software breakpoints in the target's breakpoint table.

use super::*;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use crate::kd::breakpoints::{KD_BREAKPOINT_TABLE_SIZE, PendingWriteBreakpoint};
use crate::kd::framing::{
    CONTROL_PACKET_LEADER, INITIAL_PACKET_ID, PACKET_TYPE_KD_ACKNOWLEDGE,
    PACKET_TYPE_KD_STATE_MANIPULATE, data_packet,
};

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

#[test]
fn breakpoint_install_reclaims_slots_stranded_by_a_dead_session() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
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
    bytes::write_u32(&mut probe, 0, api::DBGKD_READ_VIRTUAL_MEMORY);
    bytes::write_u64(&mut probe, 16, ADDR);
    bytes::write_u32(&mut probe, 16 + 8, 1);
    bytes::write_u32(&mut probe, 16 + 12, 1);
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
        .write_all(&data_packet(
            PACKET_TYPE_KD_STATE_MANIPULATE,
            INITIAL_PACKET_ID,
            &payload,
        ))
        .unwrap();
    kernel.flush().unwrap();

    backend.set_breakpoint(addr).unwrap();

    assert_eq!(backend.bp_handles.get(&addr), Some(&handle));
    assert!(backend.managed_bp_addresses.contains(&addr));
    assert!(backend.pending_write_breakpoint.is_none());

    let ack = read_wire_packet(&mut kernel);
    assert_eq!(wire_header(&ack).leader, CONTROL_PACKET_LEADER);
    assert_eq!(wire_header(&ack).packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);
    assert_eq!(wire_header(&ack).packet_id, INITIAL_PACKET_ID);

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
        .target_kernel_location()
        .expect_err("other KD requests should be rejected while install is pending");
    assert!(err.to_string().contains("retry the same bp command"));
}
