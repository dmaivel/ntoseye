//! Tests for detaching from the target.

use super::*;

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread::spawn;

use crate::kd::exit::exit_stop_is_stray_single_step;
use crate::kd::framing::{
    CONTROL_PACKET_LEADER, DATA_PACKET_LEADER, HEADER_SIZE, INITIAL_PACKET_ID,
    PACKET_TYPE_KD_ACKNOWLEDGE, PACKET_TYPE_KD_STATE_CHANGE64, PACKET_TYPE_KD_STATE_MANIPULATE,
    control_packet, data_packet,
};

#[test]
fn exit_restores_breakpoints_the_host_left_installed() {
    let (kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();
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
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_CHANGE64,
                INITIAL_PACKET_ID,
                &payload,
            ))
            .unwrap();
        kernel.flush().unwrap();

        let ack = read_wire_packet(&mut kernel);
        assert_eq!(wire_header(&ack).leader, CONTROL_PACKET_LEADER);
        assert_eq!(wire_header(&ack).packet_type, PACKET_TYPE_KD_ACKNOWLEDGE);

        let read_special_packet = read_wire_packet(&mut kernel);
        let read_special_request =
            &read_special_packet[HEADER_SIZE..HEADER_SIZE + api::MANIPULATE_HEADER_SIZE];
        assert_eq!(
            u32::from_le_bytes(read_special_request[0..4].try_into().unwrap()),
            api::DBGKD_READ_CONTROL_SPACE
        );
        let read_special_id = wire_header(&read_special_packet).packet_id;
        kernel
            .write_all(&control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, read_special_id))
            .unwrap();
        kernel
            .write_all(&data_packet(
                PACKET_TYPE_KD_STATE_MANIPULATE,
                INITIAL_PACKET_ID ^ 1,
                &read_special_registers_reply_payload(0),
            ))
            .unwrap();
        kernel.flush().unwrap();

        let read_special_ack = read_wire_packet(&mut kernel);
        assert_eq!(
            wire_header(&read_special_ack).packet_type,
            PACKET_TYPE_KD_ACKNOWLEDGE
        );

        let continue_packet = read_wire_packet(&mut kernel);
        let continue_id = wire_header(&continue_packet).packet_id;
        continue_tx.send(continue_packet).unwrap();
        kernel
            .write_all(&control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, continue_id))
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
    assert_eq!(wire_header(&continue_packet).leader, DATA_PACKET_LEADER);
    assert_eq!(
        wire_header(&continue_packet).packet_type,
        PACKET_TYPE_KD_STATE_MANIPULATE
    );
    let request = &continue_packet[HEADER_SIZE..];
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
    backend.link.halt();

    backend.prepare_for_exit(false).unwrap();
    let needs_drop_cleanup = backend.needs_drop_cleanup();
    backend.link.resume(&mut backend.registers);

    assert!(backend.exit_prepared);
    assert!(!needs_drop_cleanup);
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
        watchpoint_address: None,
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
