//! Tests for run control and stop recording.

use super::*;
use crate::base::bytes;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread::{JoinHandle, spawn};

use crate::backend::kd::amd64::{
    CONTROL_DR6_OFFSET, CONTROL_DR7_OFFSET, CONTROL_EFLAGS_OFFSET,
    CONTROL_INSTRUCTION_COUNT_OFFSET, CONTROL_REPORT_SIZE,
};
use crate::backend::kd::breakpoints::KD_BREAKPOINT_TABLE_SIZE;
use crate::backend::kd::framing::PACKET_TYPE_KD_STATE_CHANGE64;

const STATUS_WAKE_SYSTEM_DEBUGGER: u32 = 0x8000_0007;
/// `DBGKD_MANIPULATE_STATE64` union offset; `ContinueApi2` puts `TraceFlag`
/// at +4 and `Dr7` at +8.
const MANIPULATE_UNION: usize = 16;

#[test]
fn a_stop_report_answers_for_the_trap_state_until_the_target_runs() {
    const TF: u64 = 1 << 8;
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);

    let mut report = vec![0u8; CONTROL_REPORT_SIZE];
    bytes::write_u64(&mut report, CONTROL_DR6_OFFSET, 0xffff_0ff0 | 0x4000);
    bytes::write_u32(&mut report, CONTROL_EFLAGS_OFFSET, (TF | 0x246) as u32);
    let stop = StateChange {
        processor: 0,
        number_processors: 1,
        new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
        exception_code: STATUS_SINGLE_STEP,
        exception_first_chance: Some(true),
        exception_address: None,
        program_counter: 0xffff_f800_0011_2233,
        kernel_base_hint: None,
        load_symbols: None,
        exception_record: None,
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

/// A virtual-memory read of `len` bytes at `addr` that the target refused.
/// The reply echoes the request's address and length, as the target's does;
/// without them it would be dropped as another request's.
fn refused_read_reply(addr: u64, len: u32) -> Vec<u8> {
    let mut union = [0u8; 12];
    bytes::write_u64(&mut union, 0, addr);
    bytes::write_u32(&mut union, 8, len);
    let mut reply = api::test_wire::build_reply(api::DBGKD_READ_VIRTUAL_MEMORY, 0, &union, &[]);
    reply[8..12].copy_from_slice(&0xc000_0005u32.to_le_bytes());
    reply
}

#[test]
fn resume_does_not_step_past_a_breakpoint_it_does_not_own() {
    const PC: u64 = 0xffff_f800_0011_2233;

    for owned_by_us in [true, false] {
        let register_map = Arch::Amd64.register_map();
        let mut guest_context = vec![0u8; amd64::CONTEXT_SIZE];
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
            let int3_len = Arch::Amd64.breakpoint_instruction().len() as u32;
            replies.push(refused_read_reply(PC, int3_len));
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
        absorbed_windows: Arc::default(),
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
        load_symbols: None,
        exception_record: None,
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
        absorbed_windows: Arc::default(),
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
        load_symbols: None,
        exception_record: None,
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

#[test]
fn a_break_at_the_named_breakin_site_is_noise_after_a_connect_that_stopped_elsewhere() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let breakin_clone = host.try_clone().unwrap();
    let pump_host = host.try_clone().unwrap();
    let pump = PumpHandle {
        join: spawn(move || KdFraming::new(pump_host.into())),
        stop_rx: mpsc::channel().1,
        shutdown: Arc::new(AtomicBool::new(false)),
        reported_stop: Arc::new(AtomicBool::new(false)),
        breakin_requested: Arc::new(AtomicBool::new(false)),
        absorbed_windows: Arc::default(),
    };
    let mut backend = kd_backend_with_pump(pump, breakin_clone);
    // The connect found the target halted at a user-mode `int 3` of its own
    // and took that for the break-in's address; the kernel still holds the
    // break-in the connect sent.
    let guest_int3 = 0x7fff_a087_3122;
    backend.breakin_addresses.insert(guest_int3);
    let site = 0xffff_f805_7f50_e4e0;
    let held = StateChange {
        processor: 0,
        number_processors: 1,
        new_state: DBG_KD_EXCEPTION_STATE_CHANGE,
        exception_code: STATUS_BREAKPOINT,
        exception_first_chance: Some(true),
        exception_address: Some(site),
        program_counter: site,
        kernel_base_hint: None,
        load_symbols: None,
        exception_record: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        assisted_breakin: false,
        control_report: None,
    };
    assert!(
        !backend
            .mark_known_breakin_stop(held.clone())
            .assisted_breakin,
        "nothing has named the site yet"
    );

    backend.note_breakin_site(site);
    assert!(
        backend
            .mark_known_breakin_stop(held.clone())
            .assisted_breakin
    );
    let elsewhere = StateChange {
        program_counter: 0xffff_f800_1234_0000,
        exception_address: Some(0xffff_f800_1234_0000),
        ..held
    };
    assert!(!backend.mark_known_breakin_stop(elsewhere).assisted_breakin);
}

/// An exception state change from `processor` of four at `pc`, whose
/// control report carries `dr7` and the whole instruction stream from `pc`.
fn processor_report(processor: u16, code: u32, pc: u64, dr7: u64) -> Vec<u8> {
    let mut payload = vec![0u8; CONTROL_REPORT_OFFSET + CONTROL_REPORT_SIZE];
    bytes::write_u32(&mut payload, 0, DBG_KD_EXCEPTION_STATE_CHANGE);
    bytes::write_u16(&mut payload, 6, processor);
    bytes::write_u32(&mut payload, 8, 4);
    bytes::write_u64(&mut payload, 24, pc);
    bytes::write_u32(&mut payload, 32, code);
    bytes::write_u64(
        &mut payload,
        CONTROL_REPORT_OFFSET + CONTROL_DR7_OFFSET,
        dr7,
    );
    bytes::write_u16(
        &mut payload,
        CONTROL_REPORT_OFFSET + CONTROL_INSTRUCTION_COUNT_OFFSET,
        api::DBGKD_MAXSTREAM as u16,
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
    backend.register_map = Arch::Arm64.register_map().clone();
    backend.link.halt();
    backend.exit_prepared = true;
    backend.processor_count = 4;
    backend.set_current_thread("p1.3").unwrap();

    assert!(backend.single_step().is_err());
    assert!(!backend.link.is_running());
    drop(backend);

    assert!(worker.join().unwrap().is_empty());
}

/// The wake report and the repeated report of a switched step each delete
/// the breakpoint-table entries in their windows, so the step's stop must
/// report those sites as dropped, or they stay unarmed for good.
#[test]
fn a_switched_step_reports_the_sites_its_extra_reports_dropped() {
    const WAKE_PC: u64 = 0xffff_f800_0000_2000;
    const OWNER_PC: u64 = 0xffff_f800_0000_1001;
    const STEP_PC: u64 = 0xffff_f800_0000_5000;
    let (kernel, host) = UnixStream::pair().unwrap();
    let worker = serve_state_changes(
        kernel,
        vec![
            processor_report(2, STATUS_WAKE_SYSTEM_DEBUGGER, WAKE_PC, 0x400),
            processor_report(0, STATUS_BREAKPOINT, OWNER_PC, 0x400),
        ],
    );
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    backend.processor_count = 4;
    backend.bp_handles.insert(OWNER_PC, 1);
    backend.bp_handles.insert(WAKE_PC + 4, 2);
    backend.bp_handles.insert(0xffff_f800_0000_9000, 3);
    backend.set_current_thread("p1.3").unwrap();

    backend.single_step().unwrap();
    let step =
        parse_state_change(&processor_report(2, STATUS_SINGLE_STEP, STEP_PC, 0x400)).unwrap();
    backend.record_stop(&step);

    let mut dropped = backend.sites_dropped_by_stop();
    dropped.sort_unstable();
    assert_eq!(dropped, vec![OWNER_PC, WAKE_PC + 4]);
    drop(backend);
    worker.join().unwrap();
}

/// A stop frees the handles of the sites its report deleted, and the next
/// install is handed one of them; lifting a dropped site by its old handle
/// would delete that new entry instead (a breakpoint set at a module-load
/// stop was lost when the load trap was lifted on resume).
#[test]
fn lifting_a_site_a_stop_dropped_leaves_the_entry_that_reused_its_handle() {
    const TRAP: u64 = 0xffff_f800_0000_1000;
    const NEW: u64 = 0xffff_f800_0000_7000;
    let (kernel, host) = UnixStream::pair().unwrap();
    let worker = serve_breakpoints(
        kernel,
        vec![(api::DBGKD_WRITE_BREAKPOINT, api::STATUS_SUCCESS, 1)],
    );
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
    backend.exit_prepared = true;
    backend.bp_handles.insert(TRAP, 1);
    backend.managed_bp_addresses.insert(TRAP);
    let stop = parse_state_change(&processor_report(0, STATUS_BREAKPOINT, TRAP, 0x400)).unwrap();
    backend.record_stop(&stop);

    backend.set_breakpoint(NEW).unwrap();
    assert_eq!(backend.sites_dropped_by_stop(), vec![TRAP]);
    backend.remove_breakpoint(TRAP).unwrap();

    assert_eq!(backend.bp_handles.get(&NEW), Some(&1));
    assert!(backend.sites_dropped_by_stop().is_empty());
    drop(backend);
    let requests = worker.join().unwrap();
    assert_eq!(requests, vec![(api::DBGKD_WRITE_BREAKPOINT, NEW)]);
}

/// A stop whose instruction stream runs into an unreadable page reports
/// fewer bytes, and the target deletes the entries in just those: one
/// past them survives, still ours to restore by its handle.
#[test]
fn a_stop_drops_only_the_sites_in_the_stream_it_reported() {
    const PC: u64 = 0xffff_f800_0000_1ffc;
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.exit_prepared = true;
    backend.bp_handles.insert(PC + 2, 1);
    backend.bp_handles.insert(PC + 4, 2);
    let mut report = processor_report(0, STATUS_BREAKPOINT, PC, 0x400);
    bytes::write_u16(
        &mut report,
        CONTROL_REPORT_OFFSET + CONTROL_INSTRUCTION_COUNT_OFFSET,
        4,
    );

    backend.record_stop(&parse_state_change(&report).unwrap());

    assert_eq!(backend.sites_dropped_by_stop(), vec![PC + 2]);
    assert_eq!(backend.bp_handles.get(&(PC + 4)), Some(&2));
}
