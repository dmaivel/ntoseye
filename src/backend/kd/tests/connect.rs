//! Tests for attach-time target identification.

use super::*;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::thread::spawn;

use crate::backend::kd::connect::{detect_arch, normalize_kernel_dtb};
use crate::backend::kd::framing::{
    INITIAL_PACKET_ID, PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_STATE_MANIPULATE, control_packet,
    data_packet,
};
use crate::backend::kd::registers::ARM64_WINDBG_TTBR1_EL1;

#[test]
fn explicit_kdnet_handshake_timeout_is_used_for_the_initial_wait() {
    let mut progress = Vec::new();
    let error = KdBackend::connect_net("127.0.0.1:0", "1.2.3.4", Some(1), &mut |line| {
        progress.push(line.to_string())
    })
    .err()
    .unwrap();
    assert!(progress.iter().any(|line| line.ends_with("(timeout 1s)")));
    assert!(error.to_string().contains("no UDP datagrams within 1s"));
}

#[test]
fn kd_connections_reject_invalid_handshake_timeouts_before_opening_a_transport() {
    for seconds in [0, u64::MAX] {
        assert!(matches!(
            KdBackend::connect("", Some(seconds), &mut |_| {}),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            KdBackend::connect_net("", "", Some(seconds), &mut |_| {}),
            Err(Error::InvalidArgument(_))
        ));
    }
}

#[test]
fn kd_detects_amd64_and_arm64_machine_types() {
    assert_eq!(detect_arch(0x8664).unwrap(), Arch::Amd64);
    assert_eq!(detect_arch(0xaa64).unwrap(), Arch::Arm64);
    let error = detect_arch(0x014c).unwrap_err();
    assert!(error.to_string().contains("I386 KD target"));
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
    backend.register_map = Arch::Arm64.register_map().clone();
    backend.link.halt();
    backend.exit_prepared = true;
    let kernel_base = 0xffff_f802_4e80_0000u64;
    let module_list = 0xffff_f802_4f4d_aed0u64;

    let worker = spawn(move || {
        let version_request = read_wire_packet(&mut kernel);
        let version_id = wire_header(&version_request).packet_id;
        assert_eq!(
            u32::from_le_bytes(version_request[16..20].try_into().unwrap()),
            api::DBGKD_GET_VERSION
        );
        kernel
            .write_all(&control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, version_id))
            .unwrap();
        let mut version_union = [0u8; 40];
        version_union[8..10].copy_from_slice(&0xaa64u16.to_le_bytes());
        version_union[16..24].copy_from_slice(&kernel_base.to_le_bytes());
        version_union[24..32].copy_from_slice(&module_list.to_le_bytes());
        let version_reply = manipulate_reply_payload(api::DBGKD_GET_VERSION, 0, &version_union);
        kernel
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                INITIAL_PACKET_ID,
                &version_reply,
            ))
            .unwrap();
        let _version_ack = read_wire_packet(&mut kernel);

        let ttbr_request = read_wire_packet(&mut kernel);
        let ttbr_id = wire_header(&ttbr_request).packet_id;
        assert_eq!(
            u32::from_le_bytes(ttbr_request[16..20].try_into().unwrap()),
            api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER
        );
        assert_eq!(
            u32::from_le_bytes(ttbr_request[32..36].try_into().unwrap()),
            ARM64_WINDBG_TTBR1_EL1
        );
        kernel
            .write_all(&control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, ttbr_id))
            .unwrap();
        let ttbr = 0x0040_0000_80d4_5800u64;
        let mut ttbr_union = [0u8; 12];
        ttbr_union[0..4].copy_from_slice(&ARM64_WINDBG_TTBR1_EL1.to_le_bytes());
        ttbr_union[4..8].copy_from_slice(&(ttbr as u32).to_le_bytes());
        ttbr_union[8..12].copy_from_slice(&((ttbr >> 32) as u32).to_le_bytes());
        let ttbr_reply =
            manipulate_reply_payload(api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER, 0, &ttbr_union);
        kernel
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                INITIAL_PACKET_ID ^ 1,
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

/// A reply the target sent a debugger that went away (here to a
/// RestoreBreakPoint) and sends again to the next is passed over: the
/// request's own reply follows it.
#[test]
fn a_stale_reply_before_the_requested_one_is_passed_over() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    let kernel_base = 0xffff_f802_4e80_0000u64;

    let worker = spawn(move || {
        let request = read_wire_packet(&mut kernel);
        kernel
            .write_all(&control_packet(
                PACKET_TYPE_KD_ACKNOWLEDGE,
                wire_header(&request).packet_id,
            ))
            .unwrap();
        let stale = manipulate_reply_payload(api::DBGKD_RESTORE_BREAKPOINT, 0, &[0u8; 40]);
        kernel
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                INITIAL_PACKET_ID,
                &stale,
            ))
            .unwrap();
        let _stale_ack = read_wire_packet(&mut kernel);
        let mut version_union = [0u8; 40];
        version_union[16..24].copy_from_slice(&kernel_base.to_le_bytes());
        let reply = manipulate_reply_payload(api::DBGKD_GET_VERSION, 0, &version_union);
        kernel
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                INITIAL_PACKET_ID ^ 1,
                &reply,
            ))
            .unwrap();
        let _ack = read_wire_packet(&mut kernel);
    });

    let version = api::get_version(backend.framing().unwrap(), 0).unwrap();
    worker.join().unwrap();
    assert_eq!(version.kern_base, kernel_base);
}
