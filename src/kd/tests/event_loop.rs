//! Tests for state-change parsing, the initial handshake and the pump.

use super::*;

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread::spawn;
use std::time::Instant;

use crate::kd::framing::{
    BREAKIN_BYTE, HEADER_SIZE, INITIAL_PACKET_ID, PACKET_TYPE_KD_ACKNOWLEDGE,
    PACKET_TYPE_KD_DEBUG_IO, PACKET_TYPE_KD_RESET, PACKET_TYPE_KD_STATE_CHANGE64,
    PACKET_TYPE_KD_STATE_MANIPULATE, control_packet, data_packet,
};
use crate::kd::run::stop_event;

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
    let packet_id = wire_header(&packet).packet_id;
    let request = &packet[HEADER_SIZE..];
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
        .write_all(&control_packet(PACKET_TYPE_KD_ACKNOWLEDGE, packet_id))
        .unwrap();
    kernel.flush().unwrap();
    handle.join().unwrap().unwrap();
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
fn continue_drains_in_place_rebreak_and_stale_breakin() {
    let resumed_from = 0xffff_f800_0013_40c4;
    let breakin = 0xffff_f800_002f_90d0;
    let drain = |managed: &[u64]| {
        ContinueDrain::new(
            resumed_from,
            managed.iter().copied().collect(),
            HashSet::from([breakin]),
            context::build_register_map(),
            None,
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
    let pkt = data_packet(
        PACKET_TYPE_KD_STATE_CHANGE64,
        INITIAL_PACKET_ID,
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
        None,
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

    let mut kernel_id = INITIAL_PACKET_ID;
    let mut send = |kernel: &mut UnixStream, packet_type: u16, payload: &[u8]| {
        kernel
            .write_all(&data_packet(packet_type, kernel_id, payload))
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
        let request = recv_host_request(&mut kernel).expect("host hung up");
        let api_number = u32::from_le_bytes(request[0..4].try_into().unwrap());
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
        .write_all(&control_packet(PACKET_TYPE_KD_RESET, 0))
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
        .write_all(&control_packet(PACKET_TYPE_KD_RESET, 0))
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
        .write_all(&data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
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
        .write_all(&control_packet(PACKET_TYPE_KD_RESET, 0))
        .unwrap();
    let pc = 0xfffff800_feedface;
    kernel
        .write_all(&data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
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
        .write_all(&data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
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
                filter: StateChangeFilter::Runtime,
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
        .write_all(&data_packet(
            PACKET_TYPE_KD_DEBUG_IO,
            INITIAL_PACKET_ID,
            &refresh,
        ))
        .unwrap();
    kernel.flush().unwrap();

    let mut outbound = Vec::new();
    let mut buf = [0u8; 64];
    while outbound.len() < HEADER_SIZE {
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
        outbound.len() >= HEADER_SIZE,
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
        .write_all(&data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID ^ 1,
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
                filter: StateChangeFilter::Runtime,
                bugcheck: Some(&mut bugcheck),
                bugcheck_capture: Some(&mut capture),
                deadline: None,
                debug_log: None,
            },
        )
        .expect("await_state_change failed")
    });

    let mut packet_id = INITIAL_PACKET_ID;
    let mut buf = [0u8; 128];
    for text in prints {
        kernel
            .write_all(&data_packet(
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
        .write_all(&data_packet(
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
