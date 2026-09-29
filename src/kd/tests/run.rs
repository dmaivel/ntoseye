//! Tests for run control and stop recording.

use super::*;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread::{JoinHandle, spawn};

use crate::kd::breakpoints::KD_BREAKPOINT_TABLE_SIZE;
use crate::kd::framing::PACKET_TYPE_KD_STATE_CHANGE64;

const STATUS_WAKE_SYSTEM_DEBUGGER: u32 = 0x8000_0007;
/// `DBGKD_MANIPULATE_STATE64` union offset; `ContinueApi2` puts `TraceFlag`
/// at +4 and `Dr7` at +8.
const MANIPULATE_UNION: usize = 16;

#[test]
fn a_stop_report_answers_for_the_trap_state_until_the_target_runs() {
    const TF: u64 = 1 << 8;
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);

    let mut report = vec![0u8; AMD64_CONTROL_REPORT_SIZE];
    bytes::write_u64(&mut report, AMD64_CONTROL_DR6_OFFSET, 0xffff_0ff0 | 0x4000);
    bytes::write_u32(
        &mut report,
        AMD64_CONTROL_EFLAGS_OFFSET,
        (TF | 0x246) as u32,
    );
    let stop = StateChange {
        processor: 0,
        number_processors: 1,
        new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
        exception_code: STATUS_SINGLE_STEP,
        exception_first_chance: Some(true),
        exception_address: None,
        program_counter: 0xffff_f800_0011_2233,
        kernel_base_hint: None,
        unload_symbols: false,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        assisted_breakin: false,
        control_report: Some(ControlReport(report)),
    };

    // The socket has no reader, so anything that reached for a CONTEXT here
    // would block rather than answer.
    backend.record_stop(&stop);
    let trap = backend
        .stop_trap_state()
        .expect("the stop reported TF and DR6");
    assert_eq!(trap.eflags, TF | 0x246);
    assert_eq!(trap.dr6, 0xffff_0ff0 | 0x4000);
    assert!(!trap.is_clean(), "a single-step stop has residue to clear");

    backend.record_running();
    assert!(
        backend.stop_trap_state().is_none(),
        "a running target has no reported state to serve"
    );
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
            bytes::write_u32(&mut union, 8, chunk.len() as u32);
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
                .any(|word| bytes::read_u32(word, 0) == api::DBGKD_SET_CONTEXT_EX),
            "resume stepped the PC past an int3 it does not own (owned_by_us={owned_by_us})"
        );
        outcome.unwrap();
    }
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
        unload_symbols: false,
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
fn a_breakin_answered_by_another_stop_is_absorbed_when_it_arrives_late() {
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
    // The break-in landed while the target was reporting a module load, so
    // it answered with that notification and still holds the break-in.
    backend.late_breakin = true;
    let breakin_pc = 0xffff_f800_0000_dfb0;
    let late = StateChange {
        processor: 0,
        number_processors: 1,
        new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
        exception_code: STATUS_BREAKPOINT,
        exception_first_chance: Some(true),
        exception_address: Some(breakin_pc),
        program_counter: breakin_pc,
        kernel_base_hint: None,
        unload_symbols: false,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        assisted_breakin: false,
        control_report: None,
    };

    let late = backend.mark_known_breakin_stop(late);
    assert!(late.assisted_breakin);
    backend.record_stop(&late);

    // Consumed: a later `int 3` elsewhere is the guest's own again.
    let guest_int3 = StateChange {
        program_counter: 0xffff_f800_1234_0000,
        exception_address: Some(0xffff_f800_1234_0000),
        assisted_breakin: false,
        ..late
    };
    assert!(!backend.mark_known_breakin_stop(guest_int3).assisted_breakin);
}

/// An exception state change from `processor` of four at `pc`, whose
/// control report carries `dr7`.
fn processor_report(processor: u16, code: u32, pc: u64, dr7: u64) -> Vec<u8> {
    let mut payload = vec![0u8; CONTROL_REPORT_OFFSET + AMD64_CONTROL_REPORT_SIZE];
    bytes::write_u32(&mut payload, 0, DBG_KD_EXCEPTION_STATE_CHANGE);
    bytes::write_u16(&mut payload, 6, processor);
    bytes::write_u32(&mut payload, 8, 4);
    bytes::write_u64(&mut payload, 24, pc);
    bytes::write_u32(&mut payload, 32, code);
    bytes::write_u64(
        &mut payload,
        CONTROL_REPORT_OFFSET + AMD64_CONTROL_DR7_OFFSET,
        dr7,
    );
    payload
}

/// A halted fake kernel that answers each host request with the next state
/// change in `reports`, and hands back every request it received once the
/// host hangs up.
fn serve_state_changes(mut kernel: UnixStream, reports: Vec<Vec<u8>>) -> JoinHandle<Vec<Vec<u8>>> {
    spawn(move || {
        let mut kernel_id = INITIAL_PACKET_ID;
        let mut reports = reports.into_iter();
        let mut requests = Vec::new();
        while let Some(request) = recv_host_request(&mut kernel) {
            requests.push(request);
            if let Some(report) = reports.next() {
                kernel
                    .write_all(&data_packet(
                        PACKET_TYPE_KD_STATE_CHANGE64,
                        kernel_id,
                        &report,
                    ))
                    .unwrap();
                kernel_id ^= 1;
            }
        }
        requests
    })
}

/// Each request's API, processor, `TraceFlag` and `Dr7`.
fn continue_fields(requests: &[Vec<u8>]) -> Vec<(u32, u16, u32, u64)> {
    requests
        .iter()
        .map(|request| {
            (
                bytes::read_u32(request, 0),
                bytes::read_u16(request, 6),
                bytes::read_u32(request, MANIPULATE_UNION + 4),
                bytes::read_u64(request, MANIPULATE_UNION + 8),
            )
        })
        .collect()
}

#[test]
fn a_step_on_another_processor_switches_to_it_and_resumes_through_the_one_that_stopped() {
    const STEPPED_DR7: u64 = 0x0404;
    const OWNER_DR7: u64 = 0x0401;
    let (kernel, host) = UnixStream::pair().unwrap();
    let worker = serve_state_changes(
        kernel,
        vec![
            processor_report(
                2,
                STATUS_WAKE_SYSTEM_DEBUGGER,
                0xffff_f800_0000_2000,
                STEPPED_DR7,
            ),
            processor_report(0, STATUS_BREAKPOINT, 0xffff_f800_0000_1001, OWNER_DR7),
        ],
    );
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    backend.processor_count = 4;
    backend.set_current_thread("p1.3").unwrap();

    backend.single_step().unwrap();
    assert!(backend.link.is_running());
    drop(backend);

    // Each continue carries the DR7 of the processor it answers, so neither
    // processor's hardware breakpoints move to the other.
    assert_eq!(
        continue_fields(&worker.join().unwrap()),
        vec![
            (api::DBGKD_SWITCH_PROCESSOR, 2, 0, 0),
            (api::DBGKD_CONTINUE_API2, 2, 1, STEPPED_DR7),
            (api::DBGKD_CONTINUE_API2, 0, 0, OWNER_DR7),
        ]
    );
}

#[test]
fn a_switch_answered_by_another_processor_leaves_that_processor_holding_the_target() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let worker = serve_state_changes(
        kernel,
        vec![processor_report(
            1,
            STATUS_BREAKPOINT,
            0xffff_f800_0000_3000,
            0x0400,
        )],
    );
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    backend.processor_count = 4;
    backend.set_current_thread("p1.3").unwrap();

    assert!(backend.single_step().is_err());
    assert!(!backend.link.is_running());
    // The next resume answers the processor that reported.
    assert_eq!(backend.last_stop_processor, 1);
    assert_eq!(backend.last_rip, 0xffff_f800_0000_3000);
    drop(backend);

    let requests = worker.join().unwrap();
    assert_eq!(
        continue_fields(&requests),
        vec![(api::DBGKD_SWITCH_PROCESSOR, 2, 0, 0)]
    );
}

/// An ARM64 target never delivers the step of a processor it switched to, so
/// a step there would wait forever on a running target.
#[test]
fn an_arm64_step_on_another_processor_fails_without_resuming() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let worker = serve_state_changes(kernel, Vec::new());
    let mut backend = kd_backend_with_framing(host);
    backend.arch = Arch::Arm64;
    backend.register_map = context_arm64::build_register_map();
    backend.link.halt();
    backend.exit_prepared = true;
    backend.processor_count = 4;
    backend.set_current_thread("p1.3").unwrap();

    assert!(backend.single_step().is_err());
    assert!(!backend.link.is_running());
    drop(backend);

    assert!(worker.join().unwrap().is_empty());
}
