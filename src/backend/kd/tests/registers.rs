//! Tests for register and control-space access.

use super::*;
use crate::base::bytes;

use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::thread::{JoinHandle, spawn};

use crate::backend::dbg_backend::ThreadLayout;
use crate::backend::kd::framing::{
    INITIAL_PACKET_ID, PACKET_TYPE_KD_STATE_MANIPULATE, data_packet,
};
use crate::backend::kd::registers::{
    Arm64X18Source, arm64_x18, context_into_special, context_payload, special_into_context,
};

/// Write `value`'s little-endian bytes at `offset`, where Windows'
/// `KSPECIAL_REGISTERS` definition puts the field.
fn put(buffer: &mut [u8], offset: usize, value: &[u8]) {
    buffer[offset..offset + value.len()].copy_from_slice(value);
}

#[test]
fn amd64_hardware_slots_remain_four_shared_slots() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.exit_prepared = true;

    assert_eq!(backend.hardware_breakpoint_slots(), 4);
    for access in [
        HwBreakpointAccess::Write,
        HwBreakpointAccess::ReadWrite,
        HwBreakpointAccess::Execute,
    ] {
        assert_eq!(backend.hardware_slot_range(access), 0..4);
    }
}

#[test]
fn arm64_hardware_slots_are_the_implemented_ones_of_the_context_slots() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.arch = Arch::Arm64;
    backend.register_map = Arch::Arm64.register_map().clone();
    backend.exit_prepared = true;

    // Slots stay numbered as the CONTEXT's registers.
    assert_eq!(backend.hardware_breakpoint_slots(), 10);
    // Unread, only the architecture's two of each are certain.
    assert_eq!(backend.hardware_slot_range(HwBreakpointAccess::Write), 0..2);
    assert_eq!(
        backend.hardware_slot_range(HwBreakpointAccess::Execute),
        2..4
    );

    // Six breakpoints and four watchpoints, of which the CONTEXT holds two.
    backend.debug_features = Some(0x1030_5106);
    assert_eq!(
        backend.hardware_slot_range(HwBreakpointAccess::ReadWrite),
        0..2
    );
    assert_eq!(
        backend.hardware_slot_range(HwBreakpointAccess::Execute),
        2..8
    );
}

#[test]
fn oversized_hardware_slot_ids_are_rejected_without_packets() {
    for arch in [Arch::Amd64, Arch::Arm64] {
        let (mut kernel, host) = UnixStream::pair().unwrap();
        // An accidental physical-slot request must fail promptly, not wait for a reply.
        kernel.shutdown(Shutdown::Write).unwrap();
        kernel.set_nonblocking(true).unwrap();
        let mut backend = kd_backend_with_framing(host);
        backend.arch = arch;
        backend.link.halt();
        backend.exit_prepared = true;

        for slot in [256, usize::MAX] {
            let error = backend
                .set_hardware_breakpoint(slot, 0x4000, HwBreakpointAccess::Execute, 1)
                .unwrap_err();
            assert!(
                matches!(error, Error::Kd(_)),
                "{arch:?} set slot {slot}: {error}"
            );
            let error = backend.clear_hardware_breakpoint(slot).unwrap_err();
            assert!(
                matches!(error, Error::Kd(_)),
                "{arch:?} clear slot {slot}: {error}"
            );
        }

        let mut byte = [0u8; 1];
        assert_eq!(
            kernel.read(&mut byte).unwrap_err().kind(),
            ErrorKind::WouldBlock,
            "{arch:?} oversized slot IDs must not send packets"
        );
    }
}

#[test]
fn context_payload_rejects_short_buffers() {
    let short = vec![0u8; amd64::CONTEXT_SIZE - 1];
    assert!(context_payload(Arch::Amd64, &short).is_err());
}

#[test]
fn special_registers_fill_the_amd64_control_slots() {
    let mut ctx = vec![0u8; amd64::CONTEXT_SIZE];
    let mut special = vec![0u8; 0xa8];
    put(&mut special, 0x00, &0x8005_0033u64.to_le_bytes());
    put(&mut special, 0x08, &0x1111_2222u64.to_le_bytes());
    put(&mut special, 0x10, &0x1234_5000u64.to_le_bytes());
    put(&mut special, 0x18, &0x350ef8u64.to_le_bytes());
    put(&mut special, 0x20, &0xffff_f804_1234_5678u64.to_le_bytes());
    put(&mut special, 0x40, &5u64.to_le_bytes());
    put(&mut special, 0x48, &0x402u64.to_le_bytes());
    // KDESCRIPTOR: Pad[3], Limit, Base.
    put(&mut special, 0x56, &0x1234u16.to_le_bytes());
    put(&mut special, 0x58, &0xffff_f800_0000_1000u64.to_le_bytes());
    put(&mut special, 0x66, &0x5678u16.to_le_bytes());
    put(&mut special, 0x68, &0xffff_f800_0000_2000u64.to_le_bytes());
    put(&mut special, 0x70, &0x40u16.to_le_bytes());
    put(&mut special, 0x72, &0x48u16.to_le_bytes());
    put(&mut special, 0xa0, &2u64.to_le_bytes());

    special_into_context(Arch::Amd64, &mut ctx, &special).unwrap();
    let map = Arch::Amd64.register_map();

    assert_eq!(ctx.len(), amd64::REGISTER_BUFFER_SIZE);
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
fn short_special_registers_are_rejected() {
    for (arch, size) in [(Arch::Amd64, 0xa8), (Arch::Arm64, 0xa0)] {
        let mut ctx = vec![0u8; arch.context_size()];
        assert!(special_into_context(arch, &mut ctx, &vec![0u8; size - 1]).is_err());
        assert!(special_into_context(arch, &mut ctx, &vec![0u8; size]).is_ok());
    }
}

#[test]
fn context_debug_registers_update_special_registers() {
    let mut ctx = vec![0u8; amd64::REGISTER_BUFFER_SIZE];
    let mut special = vec![0xa5; 0xa8];
    let map = Arch::Amd64.register_map();
    map.write_u64("dr0", &mut ctx, 0xffff_f804_1234_5678)
        .unwrap();
    map.write_u64("dr6", &mut ctx, 3).unwrap();
    map.write_u64("dr7", &mut ctx, 0xd0402).unwrap();
    map.write_u64("cr0", &mut ctx, 0x8005_0033).unwrap();

    context_into_special(Arch::Amd64, &mut special, &ctx).unwrap();

    assert_eq!(bytes::read_u64(&special, 0x20), 0xffff_f804_1234_5678);
    assert_eq!(bytes::read_u64(&special, 0x40), 3);
    assert_eq!(bytes::read_u64(&special, 0x48), 0xd0402);
    assert_eq!(
        bytes::read_u64(&special, 0x00),
        0xa5a5_a5a5_a5a5_a5a5,
        "registers the CONTEXT does not carry must remain untouched"
    );
}

#[test]
fn arm64_context_debug_registers_update_special_registers() {
    let mut ctx = vec![0u8; arm64::CONTEXT_SIZE];
    let mut special = vec![0xa5; 0xa0];
    let map = Arch::Arm64.register_map();
    map.write_u64("bvr0", &mut ctx, 0x4000).unwrap();
    map.write_u64("bcr0", &mut ctx, 0xe9e1).unwrap();
    map.write_u64("wvr1", &mut ctx, 0x5000).unwrap();
    map.write_u64("wcr1", &mut ctx, 0x0000_e9e1).unwrap();

    context_into_special(Arch::Arm64, &mut special, &ctx).unwrap();

    assert_eq!(bytes::read_u64(&special, 0x28), 0x4000);
    assert_eq!(bytes::read_u32(&special, 0x68), 0xe9e1);
    assert_eq!(bytes::read_u64(&special, 0x90), 0x5000);
    assert_eq!(bytes::read_u32(&special, 0x9c), 0x0000_e9e1);
    assert_eq!(
        bytes::read_u64(&special, 0x10),
        0xa5a5_a5a5_a5a5_a5a5,
        "TPIDR_EL0 is no debug register and must remain untouched"
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
            // Windows answers in the request it received.
            let mut reply = request[..api::MANIPULATE_HEADER_SIZE].to_vec();
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
    backend.register_map = Arch::Arm64.register_map().clone();
    backend.link.halt();
    backend.exit_prepared = true;

    let mut ctx = vec![0u8; arm64::CONTEXT_SIZE];
    bytes::write_u64(&mut ctx, arm64::OFFSET_PC, 0xffff_f800_1234_5678);
    bytes::write_u64(&mut ctx, arm64::OFFSET_BVR0, 0xffff_f800_dead_0000);
    bytes::write_u32(&mut ctx, arm64::OFFSET_BCR0, 0x1e5);
    let expected = ctx.clone();

    let worker = serve_manipulate(
        kernel,
        vec![
            (api::DBGKD_GET_CONTEXT, api::STATUS_SUCCESS, ctx),
            // TTBR0, ESR and FAR of the processor that stopped the target.
            (
                api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER,
                0xc000_0001,
                Vec::new(),
            ),
            (
                api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER,
                0xc000_0001,
                Vec::new(),
            ),
            (
                api::DBGKD_READ_MACHINE_SPECIFIC_REGISTER,
                0xc000_0001,
                Vec::new(),
            ),
            (api::DBGKD_READ_CONTROL_SPACE, 0xc000_0001, Vec::new()),
        ],
    );

    let regs = backend.read_registers().unwrap();

    assert_eq!(&regs[..arm64::CONTEXT_SIZE], &expected[..]);
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

/// A halted AMD64 processor whose first register read the kernel answers
/// with an empty `CONTEXT` and `special` control space, EFER already known.
fn amd64_backend_reading(host: UnixStream) -> KdBackend {
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    backend.efer_cache.insert(0, 0xd01);
    backend
}

/// A slot armed during a halt shows in the registers read after it, though
/// the halt's registers were read before: the write keeps nothing that
/// described them.
#[test]
fn registers_read_after_arming_a_slot_show_it() {
    const ADDRESS: u64 = 0xffff_f800_1234_5000;
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = amd64_backend_reading(host);
    let context = vec![0u8; amd64::CONTEXT_SIZE];
    let special_map = Arch::Amd64.special_register_map();
    let mut special = vec![0u8; special_map.extent()];
    special_map.write_u64("dr7", &mut special, 0x400).unwrap();
    let worker = serve_manipulate(
        kernel,
        vec![
            (api::DBGKD_GET_CONTEXT, api::STATUS_SUCCESS, context.clone()),
            (
                api::DBGKD_READ_CONTROL_SPACE,
                api::STATUS_SUCCESS,
                special.clone(),
            ),
            // Arming slot 0: its state for a rollback, then the
            // read-modify-write.
            (
                api::DBGKD_READ_CONTROL_SPACE,
                api::STATUS_SUCCESS,
                special.clone(),
            ),
            (
                api::DBGKD_READ_CONTROL_SPACE,
                api::STATUS_SUCCESS,
                special.clone(),
            ),
            (api::DBGKD_WRITE_CONTROL_SPACE, api::STATUS_SUCCESS, special),
            (api::DBGKD_GET_CONTEXT, api::STATUS_SUCCESS, context),
        ],
    );
    let map = backend.register_map.clone();

    let before = backend.read_registers().unwrap();
    assert_eq!(map.read_u64("dr7", &before).unwrap(), 0x400);
    backend
        .set_hardware_breakpoint(0, ADDRESS, HwBreakpointAccess::Execute, 1)
        .unwrap();
    let after = backend.read_registers().unwrap();

    assert_eq!(map.read_u64("dr0", &after).unwrap(), ADDRESS);
    assert_eq!(
        map.read_u64("dr7", &after).unwrap() & 0b11,
        0b10,
        "G0 enables slot 0"
    );
    drop(backend);
    worker.join().unwrap();
}

/// An MSR written during a halt shows in the registers read after it.
#[test]
fn registers_read_after_an_msr_write_show_it() {
    const MSR_EFER: u32 = 0xc000_0080;
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = amd64_backend_reading(host);
    let context = vec![0u8; amd64::CONTEXT_SIZE];
    let special = vec![0u8; Arch::Amd64.special_register_map().extent()];
    let worker = serve_manipulate(
        kernel,
        vec![
            (api::DBGKD_GET_CONTEXT, api::STATUS_SUCCESS, context.clone()),
            (
                api::DBGKD_READ_CONTROL_SPACE,
                api::STATUS_SUCCESS,
                special.clone(),
            ),
            (
                api::DBGKD_WRITE_MACHINE_SPECIFIC_REGISTER,
                api::STATUS_SUCCESS,
                Vec::new(),
            ),
            (api::DBGKD_GET_CONTEXT, api::STATUS_SUCCESS, context),
            (api::DBGKD_READ_CONTROL_SPACE, api::STATUS_SUCCESS, special),
        ],
    );
    let map = backend.register_map.clone();

    let before = backend.read_registers().unwrap();
    assert_eq!(map.read_u64("efer", &before).unwrap(), 0xd01);
    backend.write_msr(0, MSR_EFER, 0x501).unwrap();
    let after = backend.read_registers().unwrap();

    assert_eq!(map.read_u64("efer", &after).unwrap(), 0x501);
    drop(backend);
    worker.join().unwrap();
}

/// The trap flag and DR6 a stop reported stop answering for the processor
/// once the host writes its registers: serving them after the write would
/// clear or keep a trap flag the written state no longer has.
#[test]
fn a_register_write_drops_the_stop_report() {
    use crate::backend::kd::amd64::{CONTROL_EFLAGS_OFFSET, CONTROL_REPORT_SIZE};
    const TF: u32 = 1 << 8;
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = amd64_backend_reading(host);
    let mut report = vec![0u8; CONTROL_REPORT_SIZE];
    bytes::write_u32(&mut report, CONTROL_EFLAGS_OFFSET, TF | 0x246);
    backend.registers.stopped(0, Some(ControlReport(report)));
    let special = vec![0u8; Arch::Amd64.special_register_map().extent()];
    let worker = serve_manipulate(
        kernel,
        vec![
            // Refusing `SetContextEx` sends the CONTEXT whole, in one reply.
            (api::DBGKD_SET_CONTEXT_EX, 0xc000_0001, Vec::new()),
            (api::DBGKD_SET_CONTEXT, api::STATUS_SUCCESS, Vec::new()),
            // Mirroring the debug registers into the special registers.
            (
                api::DBGKD_READ_CONTROL_SPACE,
                api::STATUS_SUCCESS,
                special.clone(),
            ),
            (api::DBGKD_WRITE_CONTROL_SPACE, api::STATUS_SUCCESS, special),
        ],
    );
    assert_eq!(
        backend.stop_trap_state().map(|trap| trap.eflags),
        Some(u64::from(TF | 0x246))
    );

    backend
        .write_registers(&vec![0u8; amd64::REGISTER_BUFFER_SIZE])
        .unwrap();

    assert!(
        backend.stop_trap_state().is_none(),
        "the stop's TF and DR6 described the registers before the write"
    );
    drop(backend);
    worker.join().unwrap();
}

/// Windows' KD does not return an ARM64 thread's `x18`. In kernel mode it is
/// the KPCR, whatever KD reported (seen: 0, and the KPRCB); in user mode it
/// is the TEB, read through the KPCR's current thread, and KD reports 0. A
/// user-mode `x18` KD did report is kept.
#[test]
fn an_arm64_context_gets_its_real_x18() {
    const EL1H: u32 = 0b0101;
    const EL0T: u32 = 0b0000;
    const KPCR: u64 = 0xffff_f800_a1b7_0000;
    const THREAD: u64 = 0xffff_ba87_e0ab_3080;
    const TEB: u64 = 0x0000_00c8_4ac8_e000;
    const PATH: ThreadLayout = ThreadLayout {
        current_thread: 0x988,
        teb: 0xf0,
        process: 0xb8,
        directory_table_base: 0x28,
    };
    struct Guest(Option<u64>);
    impl Arm64X18Source for Guest {
        fn kpcr(&mut self) -> Option<u64> {
            self.0
        }
        fn read_pointer(&mut self, address: u64) -> Option<u64> {
            match address {
                a if a == KPCR + 0x988 => Some(THREAD),
                a if a == THREAD + 0xf0 => Some(TEB),
                _ => None,
            }
        }
    }
    let context = |cpsr: u32, x18: u64| {
        let mut bytes = vec![0u8; arm64::CONTEXT_SIZE];
        bytes[arm64::OFFSET_CPSR..arm64::OFFSET_CPSR + 4].copy_from_slice(&cpsr.to_le_bytes());
        let at = arm64::OFFSET_X0 + 18 * 8;
        bytes[at..at + 8].copy_from_slice(&x18.to_le_bytes());
        bytes
    };
    let x18 = |cpsr, x18, path| arm64_x18(&context(cpsr, x18), path, &mut Guest(Some(KPCR)));

    assert_eq!(x18(EL1H, 0, Some(PATH)), Some(KPCR));
    assert_eq!(x18(EL1H, KPCR + 0x980, None), Some(KPCR));
    assert_eq!(x18(EL0T, 0, Some(PATH)), Some(TEB));
    assert_eq!(x18(EL0T, TEB, Some(PATH)), None);
    assert_eq!(x18(EL0T, 0, None), None);
    assert_eq!(
        arm64_x18(&context(EL1H, 0), Some(PATH), &mut Guest(None)),
        None
    );
}
