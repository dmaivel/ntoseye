//! Tests for handing the transport to and from the pump.

use super::*;

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::thread::spawn;
use std::time::Instant;

use crate::kd::framing::{
    BREAKIN_BYTE, INITIAL_PACKET_ID, PACKET_TYPE_KD_STATE_CHANGE64, data_packet,
};

#[test]
fn pump_shutdown_without_a_pump_keeps_the_framing() {
    let (_kernel, host) = UnixStream::pair().unwrap();
    let mut backend = kd_backend_with_framing(host);
    backend.link.halt();

    assert!(backend.shutdown_pump_with_stop().unwrap().is_none());
    assert!(matches!(backend.link, Link::Halted(_)));
    backend.reclaim_framing();
    assert!(matches!(backend.link, Link::Halted(_)));
    assert!(backend.framing().is_ok());

    backend.link.resume(&mut backend.registers);
}

#[test]
fn pump_shutdown_reclaims_framing_after_reported_error() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    kernel
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let breakin_clone = host.try_clone().unwrap();
    let (stop_tx, stop_rx) = mpsc::channel();
    // Queue the failure before shutdown so the early receive must see it.
    stop_tx.send(Err("injected pump failure".into())).unwrap();
    let pump = PumpHandle {
        join: spawn(move || KdFraming::new(host.into())),
        stop_rx,
        shutdown: Arc::new(AtomicBool::new(false)),
        reported_stop: Arc::new(AtomicBool::new(true)),
        breakin_requested: Arc::new(AtomicBool::new(false)),
    };
    let mut backend = kd_backend_with_pump(pump, breakin_clone);
    backend.exit_prepared = true;

    assert!(matches!(
        backend.shutdown_pump_with_stop(),
        Err(Error::Kd(_))
    ));
    // The error must not strand the socket: the foreground can still use it.
    backend
        .link
        .framing("test")
        .unwrap()
        .transport_mut()
        .write_all(&[BREAKIN_BYTE])
        .unwrap();
    let mut received = [0];
    kernel.read_exact(&mut received).unwrap();
    assert_eq!(received, [BREAKIN_BYTE]);
}

#[test]
fn has_pending_stop_flags_undrained_pump_stop_until_consumed() {
    let (mut kernel, host) = UnixStream::pair().unwrap();
    let breakin_clone = host.try_clone().unwrap();
    let framing = KdFraming::new(host.into());
    let (tx, rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let reported_stop = Arc::new(AtomicBool::new(false));
    let join = {
        let shutdown = Arc::clone(&shutdown);
        let reported_stop = Arc::clone(&reported_stop);
        spawn(move || {
            run_pump(
                framing,
                Arch::Amd64,
                PumpLink {
                    stop_tx: tx,
                    shutdown,
                    reported_stop,
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
        reported_stop,
        breakin_requested: Arc::new(AtomicBool::new(false)),
    };
    let mut backend = kd_backend_with_pump(pump, breakin_clone);

    assert!(backend.is_running());
    assert!(!backend.has_pending_stop());

    let pc = 0xfffff800_deadbeef;
    let mut payload = exception_state_change_payload(pc);
    payload[32..36].copy_from_slice(&STATUS_BREAKPOINT.to_le_bytes());
    kernel
        .write_all(&data_packet(
            PACKET_TYPE_KD_STATE_CHANGE64,
            INITIAL_PACKET_ID,
            &payload,
        ))
        .unwrap();
    kernel.flush().unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    while !backend.has_pending_stop() {
        assert!(
            Instant::now() < deadline,
            "pump never flagged the reported stop"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    assert!(backend.is_running());
    assert!(backend.has_pending_stop());

    let stop = backend
        .take_pump_stop(Some(Duration::from_secs(5)))
        .unwrap()
        .expect("pump reported no stop");
    assert_eq!(stop.program_counter, pc);
    assert!(matches!(backend.link, Link::RunningInline(_)));
    assert!(!backend.has_pending_stop());
    backend.record_stop(&stop);
    assert!(matches!(backend.link, Link::Halted(_)));
    backend.exit_prepared = true;
}
