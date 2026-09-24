//! Tests for register and control-space access.

use super::*;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::thread::{JoinHandle, spawn};

use crate::kd::framing::{INITIAL_PACKET_ID, PACKET_TYPE_KD_STATE_MANIPULATE, data_packet};
use crate::kd::registers::{
    ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET, ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET,
    ARM64_KSPECIAL_REGISTERS_MIN_SIZE, ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET,
    ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET, KSPECIAL_REGISTERS_CR0_OFFSET,
    KSPECIAL_REGISTERS_CR2_OFFSET, KSPECIAL_REGISTERS_CR3_OFFSET, KSPECIAL_REGISTERS_CR4_OFFSET,
    KSPECIAL_REGISTERS_CR8_OFFSET, KSPECIAL_REGISTERS_DR0_OFFSET, KSPECIAL_REGISTERS_DR6_OFFSET,
    KSPECIAL_REGISTERS_DR7_OFFSET, KSPECIAL_REGISTERS_GDTR_OFFSET, KSPECIAL_REGISTERS_IDTR_OFFSET,
    KSPECIAL_REGISTERS_LDTR_OFFSET, KSPECIAL_REGISTERS_MIN_SIZE, KSPECIAL_REGISTERS_TR_OFFSET,
    append_control_registers_from_special, context_payload,
    update_arm64_debug_registers_from_context, update_special_debug_registers_from_context,
};

const ARM64_KSPECIAL_REGISTERS_TPIDR_EL0_OFFSET: usize = 0x10;

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
        bytes::read_u64(&special, KSPECIAL_REGISTERS_DR0_OFFSET),
        0xffff_f804_1234_5678
    );
    assert_eq!(bytes::read_u64(&special, KSPECIAL_REGISTERS_DR6_OFFSET), 3);
    assert_eq!(
        bytes::read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET),
        0xd0402
    );
    assert_eq!(
        bytes::read_u64(&special, KSPECIAL_REGISTERS_CR0_OFFSET),
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
        bytes::read_u64(&special, ARM64_KSPECIAL_REGISTERS_BVR0_OFFSET),
        0x4000
    );
    assert_eq!(
        bytes::read_u32(&special, ARM64_KSPECIAL_REGISTERS_BCR0_OFFSET),
        0xe9e1
    );
    assert_eq!(
        bytes::read_u64(&special, ARM64_KSPECIAL_REGISTERS_WVR0_OFFSET + 8),
        0x5000
    );
    assert_eq!(
        bytes::read_u32(&special, ARM64_KSPECIAL_REGISTERS_WCR0_OFFSET + 4),
        0x0000_e9e1
    );
    assert_eq!(
        bytes::read_u64(&special, ARM64_KSPECIAL_REGISTERS_TPIDR_EL0_OFFSET),
        0xa5a5_a5a5_a5a5_a5a5,
        "non-debug special registers must remain untouched"
    );
}

/// A halted fake kernel answering manipulate requests from an ordered
/// `(api, status, data)` script, asserting each request's API number.
fn serve_manipulate(mut kernel: UnixStream, script: Vec<(u32, u32, Vec<u8>)>) -> JoinHandle<()> {
    const UNION: usize = 16;
    spawn(move || {
        let mut kernel_id = INITIAL_PACKET_ID;
        let mut script = script.into_iter();
        loop {
            let Some(request) = recv_host_request(&mut kernel) else {
                assert!(script.next().is_none(), "missing manipulate request");
                return;
            };

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

#[test]
fn arm64_registers_survive_refused_control_space() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.arch = Arch::Arm64;
    backend.register_map = context_arm64::build_register_map();
    backend.link.halt();
    backend.exit_prepared = true;

    let mut ctx = vec![0u8; context_arm64::CONTEXT_SIZE];
    bytes::write_u64(&mut ctx, context_arm64::OFFSET_PC, 0xffff_f800_1234_5678);
    bytes::write_u64(&mut ctx, context_arm64::OFFSET_BVR0, 0xffff_f800_dead_0000);
    bytes::write_u32(&mut ctx, context_arm64::OFFSET_BCR0, 0x1e5);
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
