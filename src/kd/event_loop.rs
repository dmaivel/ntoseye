use std::env::VarError;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use owo_colors::OwoColorize;

use super::transport::KdTransport;
use crate::dbg_backend::DebugLog;
use crate::error::{Error, Result};
use crate::kd::api;
use crate::kd::framing::{
    KdFraming, PACKET_TYPE_KD_DEBUG_IO, PACKET_TYPE_KD_FILE_IO, PACKET_TYPE_KD_STATE_CHANGE64,
};
use crate::kd::trace_enabled;
use crate::kd::wire::{read_u16, read_u32, read_u64};
use crate::types::{Arch, VirtAddr};

use super::{
    AMD64_DEBUG_CONTROL_SPACE_KSPECIAL, BUGCHECK_MANUALLY_INITIATED_CRASH,
    BUGCHECK_REFRESH_ASSIST_GRACE, BugcheckCapture, DBG_KD_COMMAND_STRING_STATE_CHANGE,
    DBG_KD_EXCEPTION_STATE_CHANGE, DBG_KD_LOAD_SYMBOLS_STATE_CHANGE, KD_INITIAL_PROBE_TIMEOUT,
    KD_INITIAL_PROGRESS_INTERVAL, KD_INITIAL_TIMEOUT_DEFAULT, KD_INITIAL_TIMEOUT_ENV,
    KD_REFRESH_BREAKIN_INTERVAL, KD_REFRESH_BREAKIN_TRACE_EVERY, KD_REQUEST_TIMEOUT,
    KSPECIAL_REGISTERS_DR7_OFFSET, KSPECIAL_REGISTERS_MIN_SIZE, PUMP_POLL, StateChange,
    handle_debug_io_with_output, handle_file_io,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialHandshakeStimulus {
    BreakIn,
    Reset,
}

pub fn initial_handshake_stimulus(attempt: u32) -> InitialHandshakeStimulus {
    if attempt.is_multiple_of(2) {
        InitialHandshakeStimulus::BreakIn
    } else {
        InitialHandshakeStimulus::Reset
    }
}

pub fn initial_handshake_stimulus_for_transport(
    attempt: u32,
    is_network: bool,
) -> InitialHandshakeStimulus {
    if is_network {
        InitialHandshakeStimulus::BreakIn
    } else {
        initial_handshake_stimulus(attempt)
    }
}

pub fn parse_state_change(payload: &[u8]) -> Result<StateChange> {
    // DBGKD_ANY_WAIT_STATE_CHANGE on x64 starts with:
    //   ULONG NewState         @ 0
    //   USHORT ProcessorLevel  @ 4
    //   USHORT Processor       @ 6
    //   ULONG NumberProcessors @ 8
    //   <4 bytes pad to 8-byte align>
    //   ULONG64 Thread         @ 16
    //   ULONG64 ProgramCounter @ 24
    //   <union starts at 32>:
    //     DBGKM_EXCEPTION64.ExceptionRecord.ExceptionCode    @ 32
    //     DBGKM_EXCEPTION64.ExceptionRecord.ExceptionAddress @ 48
    //     DBGKM_EXCEPTION64.FirstChance                       @ 184
    //
    // EXCEPTION_RECORD64 is 0x98 bytes: its 15 ULONG64 information
    // parameters end at offset 0x98. DBGKM_EXCEPTION64 then stores the ULONG
    // FirstChance field immediately after it. These are the windbgkd.h wire
    // structure offsets, not host Rust layout.
    if payload.len() < 32 {
        return Err(Error::Kd(format!(
            "state-change payload too short: {} bytes",
            payload.len()
        )));
    }
    let new_state = read_u32(payload, 0);
    let exception_code = if new_state == DBG_KD_EXCEPTION_STATE_CHANGE && payload.len() >= 36 {
        read_u32(payload, 32)
    } else {
        0
    };
    let exception_address = if new_state == DBG_KD_EXCEPTION_STATE_CHANGE && payload.len() >= 56 {
        Some(read_u64(payload, 48))
    } else {
        None
    };
    let exception_first_chance =
        if new_state == DBG_KD_EXCEPTION_STATE_CHANGE && payload.len() >= 188 {
            Some(read_u32(payload, 184) != 0)
        } else {
            None
        };
    let kernel_base_hint = if new_state == DBG_KD_LOAD_SYMBOLS_STATE_CHANGE && payload.len() >= 48 {
        let base = read_u64(payload, 40);
        (base != 0).then_some(VirtAddr(base))
    } else {
        None
    };
    let number_processors_u32 = read_u32(payload, 8);
    Ok(StateChange {
        new_state,
        processor: read_u16(payload, 6),
        number_processors: number_processors_u32.min(u16::MAX as u32) as u16,
        exception_code,
        exception_first_chance,
        exception_address,
        program_counter: read_u64(payload, 24),
        kernel_base_hint,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        assisted_breakin: false,
    })
}

pub fn kd_socket_connect_error(socket_path: &str, err: std::io::Error) -> Error {
    let message = match err.kind() {
        ErrorKind::NotFound => format!(
            "KD serial socket '{socket_path}' does not exist.\n\
             Start the VM with a Unix serial socket at this path, or pass --connect <path>.\n\
             If this guest is not configured for Windows KD, use --backend gdb or --backend memory."
        ),
        ErrorKind::ConnectionRefused => format!(
            "KD serial socket '{socket_path}' exists but is not accepting connections.\n\
             Start or restart the VM so QEMU owns the socket, or pass --connect <path>.\n\
             If this guest is not configured for Windows KD, use --backend gdb or --backend memory."
        ),
        ErrorKind::PermissionDenied => format!(
            "permission denied connecting to KD serial socket '{socket_path}'.\n\
             Check the socket owner/mode or run ntoseye with sufficient permissions."
        ),
        _ => format!("failed to connect to KD serial socket '{socket_path}': {err}"),
    };
    Error::Kd(message)
}

pub fn parse_kd_initial_timeout(value: Option<&str>) -> Result<Duration> {
    let Some(value) = value else {
        return Ok(KD_INITIAL_TIMEOUT_DEFAULT);
    };
    let value = value.trim();
    let seconds = value.parse::<u64>().map_err(|_| {
        Error::Kd(format!(
            "invalid {KD_INITIAL_TIMEOUT_ENV}='{value}': expected positive integer seconds"
        ))
    })?;
    if seconds == 0 {
        return Err(Error::Kd(format!(
            "invalid {KD_INITIAL_TIMEOUT_ENV}=0: expected positive integer seconds"
        )));
    }
    Ok(Duration::from_secs(seconds))
}

pub fn kd_initial_timeout() -> Result<Duration> {
    match std::env::var(KD_INITIAL_TIMEOUT_ENV) {
        Ok(value) => parse_kd_initial_timeout(Some(&value)),
        Err(VarError::NotPresent) => parse_kd_initial_timeout(None),
        Err(VarError::NotUnicode(_)) => Err(Error::Kd(format!(
            "{KD_INITIAL_TIMEOUT_ENV} must be valid UTF-8 integer seconds"
        ))),
    }
}

/// Initial break-in: send break-in first, then alternate RESET and break-in
pub fn poll_for_initial_break(
    framing: &mut KdFraming<KdTransport>,
    budget: Duration,
) -> Result<StateChange> {
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);
    let deadline = Instant::now() + budget;

    framing
        .transport_mut()
        .set_read_timeout(Some(ATTEMPT_TIMEOUT))?;
    let is_network = framing
        .transport_mut()
        .network_datagrams_received()
        .is_some();

    let mut attempts = 0u32;
    let mut next_progress_at = Instant::now() + KD_INITIAL_PROGRESS_INTERVAL;
    loop {
        match initial_handshake_stimulus_for_transport(attempts, is_network) {
            InitialHandshakeStimulus::BreakIn => framing.send_breakin()?,
            InitialHandshakeStimulus::Reset => {
                framing.send_reset()?;
                kd_trace!("kd: RESET sent during initial handshake");
            }
        }
        attempts += 1;

        // Initial handshake: surface whatever state-change arrives first
        // The architecture is not known yet; `surface_all` guarantees this
        // path never sends an architecture-specific continue request.
        match await_state_change(
            framing,
            AwaitStateOptions {
                arch: Arch::Amd64,
                saw_kd_refresh: None,
                surface_all: true,
                bugcheck: None,
                bugcheck_capture: None,
                deadline: None,
                debug_log: None,
            },
        ) {
            Ok(stop) => break Ok(stop),
            Err(Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                let elapsed =
                    budget.saturating_sub(deadline.saturating_duration_since(Instant::now()));
                let now = Instant::now();
                if now >= next_progress_at {
                    eprintln!(
                        "{}",
                        format!("kd: no response after {}s", elapsed.as_secs()).bright_black()
                    );
                    next_progress_at += KD_INITIAL_PROGRESS_INTERVAL;
                }
                if now >= deadline {
                    let message = match framing.transport_mut().network_datagrams_received() {
                        Some(0) => format!(
                            "KDNET listener received no UDP datagrams within {}s.\n\
                             Check:\n\
                               - Windows has `bcdedit /debug on` enabled\n\
                               - `bcdedit /dbgsettings net hostip:HOST port:PORT` matches this listener\n\
                               - the guest was rebooted after changing BCD settings\n\
                               - the host firewall permits inbound UDP on the KDNET port\n\
                               - the guest debug NIC and its `busparams` are supported and correct",
                            budget.as_secs()
                        ),
                        Some(received) => format!(
                            "KDNET listener received {received} UDP datagram(s), but none contained a usable target packet within {}s.\n\
                             Check that Windows targets this UDP port and that `--kdnet-key` exactly matches the key printed by bcdedit",
                            budget.as_secs()
                        ),
                        None => format!(
                            "host serial socket is connected, but Windows KD did not send packets within {}s.\n\
                             Check:\n\
                               - Windows has `bcdedit /debug on` enabled\n\
                               - `bcdedit /dbgsettings serial debugport:N baudrate:115200` matches the QEMU serial port\n\
                               - the guest was rebooted after changing BCD settings\n\
                               - the VM is not paused or suspended\n\
                               - virt-manager/libvirt may reserve COM1 for its console serial; use debugport:2 if KD is wired as COM2\n\
                               - set NTOSEYE_KD_TIMEOUT=<seconds> if the guest is unusually slow to reach KD\n\
                               - use `--backend gdb` for gdbstub guests, or `--backend memory` for passive memory introspection",
                            budget.as_secs()
                        ),
                    };
                    break Err(Error::Kd(message));
                }
            }
            Err(e) => break Err(e),
        }
    }
}

/// Send one break-in byte and wait for the resulting state-change
pub fn breakin_and_wait(
    framing: &mut KdFraming<KdTransport>,
    arch: Arch,
    budget: Duration,
) -> Result<StateChange> {
    framing.send_breakin()?;
    framing.transport_mut().set_read_timeout(Some(budget))?;
    match await_state_change(
        framing,
        AwaitStateOptions {
            arch,
            saw_kd_refresh: None,
            surface_all: false,
            bugcheck: None,
            bugcheck_capture: None,
            deadline: None,
            debug_log: None,
        },
    ) {
        Ok(stop) => Ok(stop),
        Err(Error::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            Err(Error::Kd(format!(
                "no break-in response within {}s",
                budget.as_secs()
            )))
        }
        Err(e) => Err(e),
    }
}

pub fn is_temporary_io_error(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Run a KD request under `timeout`, then leave the socket with that timeout
/// still set. The restore-to-blocking `setsockopt(SO_RCVTIMEO)` is
/// deliberately NOT performed: on macOS, a second `SO_RCVTIMEO` setsockopt
/// while the peer concurrently writes (which is inherent to KD — the kernel
/// streams replies/prints) intermittently fails with EINVAL, and every
/// subsequent operation sets its own timeout before reading anyway. Blocking
/// waits set an explicit long timeout ([`blocking_read_timeout`]).
pub fn with_framing_read_timeout_raw<R>(
    framing: &mut KdFraming<KdTransport>,
    timeout: Duration,
    f: impl FnOnce(&mut KdFraming<KdTransport>) -> Result<R>,
) -> Result<R> {
    framing.transport_mut().set_read_timeout(Some(timeout))?;
    f(framing)
}

/// Long-enough read timeout to behave like a blocking read (an hour; never
/// fires in practice). Used where the KD protocol wants an unbounded wait
/// (`wait_for_stop`) without the macOS-racy restore dance.
pub const fn blocking_read_timeout() -> Duration {
    Duration::from_secs(3600)
}

pub fn with_framing_read_timeout<R>(
    framing: &mut KdFraming<KdTransport>,
    timeout: Duration,
    f: impl FnOnce(&mut KdFraming<KdTransport>) -> Result<R>,
) -> Result<R> {
    match with_framing_read_timeout_raw(framing, timeout, f) {
        Err(Error::Io(e)) if is_temporary_io_error(e.kind()) => Err(Error::Kd(format!(
            "KD request timed out after {}s",
            timeout.as_secs()
        ))),
        other => other,
    }
}

pub fn is_initial_resync_error(error: &Error) -> bool {
    match error {
        Error::Io(e) => is_temporary_io_error(e.kind()),
        Error::Kd(message) => message == "send exceeded retry budget",
        _ => false,
    }
}

pub fn probe_initial_request(
    framing: &mut KdFraming<KdTransport>,
    processor: u16,
) -> Result<api::Version> {
    with_framing_read_timeout_raw(framing, KD_INITIAL_PROBE_TIMEOUT, |framing| {
        api::get_version(framing, processor)
    })
}

/// Whether a wait-state-change is a transparent notification (symbol load/unload
/// or command string) the debugger acknowledges and continues past, rather than
/// surfacing as a user break. Unknown kinds are treated as breaks to be safe
pub fn is_transparent_state_change(new_state: u32) -> bool {
    matches!(
        new_state,
        DBG_KD_LOAD_SYMBOLS_STATE_CHANGE | DBG_KD_COMMAND_STRING_STATE_CHANGE
    )
}

/// Acknowledge a non-exception wait-state-change (load-symbols / command-string)
/// by sending a continue, so the kernel resumes past it. The request timeout is
/// set for the exchange and left in place (restoring is macOS-racy; the next
/// operation re-establishes its own timeout).
pub fn continue_transparent_state_change(
    framing: &mut KdFraming<KdTransport>,
    arch: Arch,
    stop: &StateChange,
) -> Result<()> {
    framing
        .transport_mut()
        .set_read_timeout(Some(KD_REQUEST_TIMEOUT))?;
    match arch {
        Arch::Amd64 => continue_preserving_dr7(framing, stop.processor, api::DBG_CONTINUE, false),
        Arch::Arm64 => api::continue_api2_arm64(framing, stop.processor, api::DBG_CONTINUE, false),
    }
}

/// Read `KernelDr7` from the processor's `KSPECIAL_REGISTERS` and continue
/// with it preserved, so existing data watchpoints keep firing across a
/// transparent state change. The pump holds only the framing (no backend
/// cache), hence the extra wire read; `KdBackend::continue_preserving_dr7`
/// is the cached equivalent.
fn continue_preserving_dr7(
    framing: &mut KdFraming<KdTransport>,
    processor: u16,
    continue_status: u32,
    trace: bool,
) -> Result<()> {
    let special = api::read_control_space(
        framing,
        processor,
        AMD64_DEBUG_CONTROL_SPACE_KSPECIAL,
        KSPECIAL_REGISTERS_MIN_SIZE as u32,
    )?;
    if special.len() < KSPECIAL_REGISTERS_DR7_OFFSET + 8 {
        return Err(Error::Kd(format!(
            "KSPECIAL_REGISTERS buffer too short for KernelDr7: {} bytes",
            special.len()
        )));
    }
    let dr7 = read_u64(&special, KSPECIAL_REGISTERS_DR7_OFFSET);
    api::continue_api2(framing, processor, continue_status, trace, dr7)
}

pub struct AwaitStateOptions<'a> {
    pub arch: Arch,
    pub saw_kd_refresh: Option<&'a mut bool>,
    pub surface_all: bool,
    pub bugcheck: Option<&'a mut bool>,
    pub bugcheck_capture: Option<&'a mut BugcheckCapture>,
    pub deadline: Option<Instant>,
    pub debug_log: Option<&'a DebugLog>,
}

/// Receive packets until a state-change we should surface arrives.
///
/// - `surface_all`: return the first state-change of any kind (initial handshake)
/// - `bugcheck`: when `Some`, run in bugcheck-aware mode; the refresh message
///   sets the flag, after which the next state-change is surfaced rather than
///   continued, so the user catches the (frozen) bugcheck instead of riding its
///   symbol-unload teardown to reboot. The flag is the caller's so it survives
///   poll timeouts between the refresh print and the state-change
/// - otherwise: continue load-symbols / command-string notifications
///   transparently (like WinDbg) and surface only exception breaks
///
/// `deadline` bounds the *total* time servicing transparent traffic: when it is
/// reached between packets, the call returns a [`ErrorKind::TimedOut`] error so
/// the caller treats it like an idle gap (hand the socket to the pump, schedule
/// an assist poke, …). Without it, an uninterrupted stream of boot-time
/// load-symbols / file-I/O packets keeps `recv_data` returning forever and
/// starves the caller's own timeout, what used to pin the foreground actor for
/// minutes after a reboot. `None` waits indefinitely for a surfaceable change.
pub fn await_state_change(
    framing: &mut KdFraming<KdTransport>,
    options: AwaitStateOptions<'_>,
) -> Result<StateChange> {
    let AwaitStateOptions {
        arch,
        mut saw_kd_refresh,
        surface_all,
        mut bugcheck,
        mut bugcheck_capture,
        deadline,
        debug_log,
    } = options;
    let mut target_reloaded = false;
    loop {
        if let Some(deadline) = deadline
            && Instant::now() >= deadline
        {
            return Err(Error::Io(std::io::Error::from(ErrorKind::TimedOut)));
        }
        let pkt = framing.recv_data()?;
        match pkt.packet_type {
            PACKET_TYPE_KD_STATE_CHANGE64 => {
                if trace_enabled() {
                    eprintln!("kd: state-change payload ({} bytes):", pkt.payload.len());
                    for chunk in pkt.payload.chunks(16) {
                        eprintln!(
                            "    {}",
                            chunk
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        );
                    }
                }
                let mut stop = parse_state_change(&pkt.payload)?;
                target_reloaded |= framing.take_peer_reset_seen();
                stop.target_reloaded = target_reloaded;
                let in_bugcheck = bugcheck.as_deref().copied().unwrap_or(false);
                // Surface exception breaks (and anything unrecognised); during a
                // bugcheck, surface even the notification kinds. Otherwise the
                // load-symbols / command-string notifications are continued
                if surface_all
                    || target_reloaded
                    || in_bugcheck
                    || !is_transparent_state_change(stop.new_state)
                {
                    if in_bugcheck {
                        stop.is_bugcheck = true;
                        stop.bugcheck = bugcheck_capture
                            .as_ref()
                            .and_then(|capture| capture.finish());
                    }
                    return Ok(stop);
                }
                // a load-symbols notification means a kernel image (driver)
                // loaded or unloaded, record it so the foreground can refresh
                // module-dependent caches (driver completions) on the next stop
                if stop.new_state == DBG_KD_LOAD_SYMBOLS_STATE_CHANGE {
                    framing.note_modules_changed();
                }
                kd_trace!(
                    "kd: await: transparent state-change new_state={:#x} at {:#x}, continuing",
                    stop.new_state,
                    stop.program_counter
                );
                continue_transparent_state_change(framing, arch, &stop)?;
            }
            PACKET_TYPE_KD_DEBUG_IO => {
                let detect = saw_kd_refresh.is_some() || bugcheck.is_some();
                let saw_refresh = handle_debug_io_with_output(
                    framing,
                    &pkt.payload,
                    detect,
                    bugcheck_capture.as_deref_mut(),
                    bugcheck.as_deref().copied().unwrap_or(false),
                    debug_log,
                    &mut std::io::stderr(),
                )?;
                if saw_refresh {
                    if let Some(flag) = bugcheck.as_deref_mut() {
                        // Bugcheck starting: stop riding the teardown, surface
                        // the next state-change so the crash can be inspected.
                        // Do not break in immediately here: Windows often emits
                        // the fatal-system-error packet before a separate
                        // "Driver at fault" packet, and an eager break-in stops
                        // in the middle of that print sequence.
                        *flag = true;
                        kd_trace!(
                            "kd: await: bugcheck refresh seen, will surface next state-change"
                        );
                    } else if let Some(flag) = saw_kd_refresh.as_deref_mut() {
                        *flag = true;
                    }
                }
            }
            PACKET_TYPE_KD_FILE_IO => {
                handle_file_io(framing, &pkt.payload)?;
            }
            _ => {
                // Orphan packet, likely a manipulate reply from a previous
                // session. Discard and keep listening
            }
        }
    }
}

pub fn pump_assist_breakin(
    framing: &mut KdFraming<KdTransport>,
    next_breakin: &mut Instant,
    breakin_count: &mut u32,
    reason: &str,
) -> Result<()> {
    let now = Instant::now();
    if now < *next_breakin {
        return Ok(());
    }

    framing.send_breakin()?;
    *next_breakin = now + KD_REFRESH_BREAKIN_INTERVAL;
    *breakin_count = breakin_count.saturating_add(1);
    if *breakin_count == 1 || breakin_count.is_multiple_of(KD_REFRESH_BREAKIN_TRACE_EVERY) {
        kd_trace!("kd: pump: sent {} break-in #{}", reason, *breakin_count);
    }
    Ok(())
}

/// Handle to the background servicing pump (see [`run_pump`])
pub struct PumpHandle {
    pub join: JoinHandle<KdFraming<KdTransport>>,
    pub stop_rx: Receiver<std::result::Result<StateChange, String>>,
    pub shutdown: Arc<AtomicBool>,
    /// Set by the pump the instant it places a result in `stop_rx` and exits.
    /// Lets the foreground tell "running" from "stopped but not yet drained"
    /// without consuming the result (see `KdBackend::has_pending_stop`).
    pub reported_stop: Arc<AtomicBool>,
}

/// Background servicing pump. While the VM runs this thread owns the framing
/// and is the *sole* socket reader: it ACKs and prints debug I/O as it arrives,
/// which keeps the connection live so the kernel never marks the debugger absent
/// (`KdDebuggerNotPresent`). It reports the first state-change to the foreground
/// before exiting, handing the framing back via its join value.
///
/// Break-in bytes for an explicit interrupt are written from the foreground via
/// a cloned socket fd, so they don't need the framing this thread holds
pub fn run_pump(
    mut framing: KdFraming<KdTransport>,
    arch: Arch,
    stop_tx: mpsc::Sender<std::result::Result<StateChange, String>>,
    shutdown: Arc<AtomicBool>,
    reported_stop: Arc<AtomicBool>,
    reconnect_assist_delay: Option<Duration>,
    debug_log: DebugLog,
) -> KdFraming<KdTransport> {
    // Flag the result the moment it lands in the channel, before we exit, so a
    // concurrent foreground `is_running()`/status read sees "stopped, undrained"
    // rather than the stale running value.
    let report = |result| {
        reported_stop.store(true, Ordering::SeqCst);
        let _ = stop_tx.send(result);
    };
    let _ = framing.transport_mut().set_read_timeout(Some(PUMP_POLL));
    // Persists across poll iterations: once the bugcheck refresh is seen, the
    // next state-change is surfaced even if a timeout intervened first
    let mut bugcheck = false;
    let reconnect_assist_at = reconnect_assist_delay.map(|delay| Instant::now() + delay);
    let mut bugcheck_refresh_seen_at = None;
    let mut bugcheck_capture = BugcheckCapture::default();
    let mut next_assist_breakin = Instant::now();
    let mut assist_breakin_count = 0u32;
    let mut assisted_breakin_pending = false;
    while !shutdown.load(Ordering::SeqCst) {
        // Bound each await to a poll interval so assist-poke scheduling runs on
        // time even while boot traffic streams in continuously (otherwise the
        // WouldBlock branch below, where assists are sent, never runs).
        match await_state_change(
            &mut framing,
            AwaitStateOptions {
                arch,
                saw_kd_refresh: None,
                surface_all: false,
                bugcheck: Some(&mut bugcheck),
                bugcheck_capture: Some(&mut bugcheck_capture),
                deadline: Some(Instant::now() + PUMP_POLL),
                debug_log: Some(&debug_log),
            },
        ) {
            Ok(mut stop) => {
                stop.assisted_breakin = assisted_breakin_pending;
                report(Ok(stop));
                break;
            }
            Err(Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                // Idle gap between packets. After a reboot/reset, KDCOM may be
                // waiting for the debugger to break in before it emits the
                // state-change we need to rediscover the new kernel.
                let now = Instant::now();
                let bugcheck_needs_assist = if bugcheck {
                    let bugcheck_refresh_seen_at = *bugcheck_refresh_seen_at.get_or_insert(now);
                    now.duration_since(bugcheck_refresh_seen_at) >= BUGCHECK_REFRESH_ASSIST_GRACE
                        && !matches!(
                            bugcheck_capture.code(),
                            Some(code) if code != BUGCHECK_MANUALLY_INITIATED_CRASH
                        )
                } else {
                    false
                };
                let reconnect_assist_ready =
                    reconnect_assist_at.is_some_and(|assist_at| now >= assist_at);
                let assist_reason = if bugcheck_needs_assist {
                    Some("refresh")
                } else if reconnect_assist_ready || framing.peer_reset_seen() {
                    Some("reconnect")
                } else {
                    None
                };
                if let Some(reason) = assist_reason {
                    if let Err(e) = pump_assist_breakin(
                        &mut framing,
                        &mut next_assist_breakin,
                        &mut assist_breakin_count,
                        reason,
                    ) {
                        report(Err(e.to_string()));
                        break;
                    }
                    assisted_breakin_pending = true;
                } else {
                    next_assist_breakin = Instant::now();
                    assist_breakin_count = 0;
                }
            }
            Err(e) => {
                report(Err(e.to_string()));
                break;
            }
        }
    }
    framing
}
