//! GDB Remote Serial Protocol server over one kernel-debugging session.
//!
//! Any GDB-protocol client (IDA, Binary Ninja, lldb, and gdb, which Ghidra
//! drives) controls the target: registers, memory, software and hardware
//! breakpoints, and run control, with `monitor` running ntoseye's own
//! commands. It also publishes what a hypervisor stub cannot: the
//! loaded-module list, so a client can rebase its database, and a memory map,
//! so it knows which addresses to show.
//!
//! RSP threads are vCPUs, and every stop halts the whole target, as in the DAP
//! server. The session stays on the serving thread; clients are served one
//! at a time, and each one's breakpoints are removed when it leaves.

mod layout;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

use gdbstub::arch::{Arch as GdbArch, RegId, Registers};
use gdbstub::common::{Pid, Signal, Tid};
use gdbstub::conn::{Connection, ConnectionExt};
use gdbstub::stub::state_machine::GdbStubStateMachine;
use gdbstub::stub::{DisconnectReason, GdbStub, MultiThreadStopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::multithread::{
    MultiThreadBase, MultiThreadResume, MultiThreadResumeOps, MultiThreadSchedulerLocking,
    MultiThreadSchedulerLockingOps, MultiThreadSingleStep, MultiThreadSingleStepOps,
};
use gdbstub::target::ext::base::single_register_access::{
    SingleRegisterAccess, SingleRegisterAccessOps,
};
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, HwBreakpoint, HwBreakpointOps, HwWatchpoint, HwWatchpointOps,
    SwBreakpoint, SwBreakpointOps, WatchKind,
};
use gdbstub::target::ext::exec_file::{ExecFile, ExecFileOps};
use gdbstub::target::ext::host_io::{
    FsKind, HostIo, HostIoClose, HostIoCloseOps, HostIoErrno, HostIoError, HostIoFstat,
    HostIoFstatOps, HostIoOpen, HostIoOpenFlags, HostIoOpenMode, HostIoOpenOps, HostIoOps,
    HostIoPread, HostIoPreadOps, HostIoResult, HostIoSetfs, HostIoSetfsOps, HostIoStat,
};
use gdbstub::target::ext::libraries::{Libraries, LibrariesOps};
use gdbstub::target::ext::memory_map::{MemoryMap, MemoryMapOps};
use gdbstub::target::ext::monitor_cmd::{ConsoleOutput, MonitorCmd, MonitorCmdOps};
use gdbstub::target::ext::section_offsets::{Offsets, SectionOffsets, SectionOffsetsOps};
use gdbstub::target::ext::target_description_xml_override::{
    TargetDescriptionXmlOverride, TargetDescriptionXmlOverrideOps,
};
use gdbstub::target::{Target, TargetError, TargetResult};
use libc::EFAULT;
use pelite::PeView;

use crate::TargetSpec;
use crate::backend::MemoryOps;
use crate::dbg_backend::{DebugCapability, HwBreakpointAccess, WatchpointAccess};
use crate::error::{Error, Result};
use crate::gdb::{BreakpointConfig, trace_packet};
use crate::guest::{ModuleInfo, image_base};
use crate::output;
use crate::repl::{
    DispatchContext, Flow, RemoteClient, ReplState, ReplStore, STATUS_BREAKPOINT,
    supports_capability,
};
use crate::session::{ContinueOutcome, Session, VcpuInfo};
use crate::termination;
use crate::triage_report::exception_code_name;
use crate::types::{Arch, VirtAddr};

use layout::Layout;

/// Where the server listens unless told otherwise. QEMU's own stub owns
/// `:1234`, which the `gdb` backend may be using, so this takes gdbserver's
/// conventional port instead.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:2345";

/// How long a blocking read or accept waits before checking for a
/// termination signal and servicing a halted target's transport.
const IDLE_POLL: Duration = Duration::from_millis(50);
/// How long each wait for a stop runs before checking the client socket.
const RUN_POLL: Duration = Duration::from_millis(50);
/// Largest packet the client may send or receive. Memory reads are chunked
/// to fit, so this bounds round trips for large reads.
const PACKET_SIZE: usize = 0x4000;
/// Console text carried per `O` packet, before hex encoding.
const CONSOLE_CHUNK: usize = 1024;
/// The thread-list transfer gdbstub does not implement, answered here.
const THREADS_XFER: &[u8] = b"qXfer:threads:read::";
/// Appended to gdbstub's `qSupported` reply so clients ask for it.
const THREADS_FEATURE: &[u8] = b";qXfer:threads:read+";
const STATUS_SINGLE_STEP: u32 = 0x8000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000_001D;
const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xC000_008E;
const STATUS_FLOAT_INVALID_OPERATION: u32 = 0xC000_0090;
const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC000_0094;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC000_0096;

/// Attach to `spec` and serve GDB clients on `listen` until a termination
/// signal arrives, then release the target.
pub fn run(spec: TargetSpec, listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .map_err(|error| Error::DebugInfo(format!("failed to bind {listen}: {error}")))?;
    let addr = listener
        .local_addr()
        .map_err(|error| Error::DebugInfo(error.to_string()))?;
    let mut session = Session::open_with_progress(&spec, &mut |line| eprintln!("{line}"))?;
    // IDA opens the kernel's file over the connection on every attach and
    // waits one second for the answer, so have it cached before a client
    // asks: a download inside that request would time the client out.
    match session.target.module_image_or_fetch_later("nt") {
        Ok(Some(_)) => {}
        Ok(None) => eprintln!("ntoseye-gdbserver: fetching the kernel image in the background"),
        Err(error) => eprintln!("ntoseye-gdbserver: kernel image unavailable: {error}"),
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let terminating = termination::install(&cancel);
    eprintln!("ntoseye-gdbserver: listening on {addr}");
    serve(&mut session, &listener, &cancel, &terminating)?;
    eprintln!("ntoseye-gdbserver: shutting down; releasing the target");
    session.cleanup_for_exit()
}

/// Accept clients one at a time until `terminating` is raised.
fn serve(
    session: &mut Session,
    listener: &TcpListener,
    cancel: &Arc<AtomicBool>,
    terminating: &Arc<AtomicBool>,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .map_err(|error| Error::DebugInfo(error.to_string()))?;
    while !terminating.load(Ordering::SeqCst) {
        let (stream, peer) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                sleep(IDLE_POLL);
                continue;
            }
            Err(error) => return Err(Error::DebugInfo(format!("accept failed: {error}"))),
        };
        eprintln!("ntoseye-gdbserver: client connected from {peer}");
        let client = Client::new(stream, Arc::clone(terminating))
            .map_err(|error| Error::DebugInfo(error.to_string()))?;
        match serve_client(session, client, cancel, terminating) {
            Ok(reason) => eprintln!("ntoseye-gdbserver: client {peer} {reason}"),
            Err(error) => eprintln!("ntoseye-gdbserver: client {peer} dropped: {error}"),
        }
    }
    Ok(())
}

/// Serve one client until it detaches or disconnects, then remove its
/// breakpoints and let the guest run, as a detaching gdb would.
fn serve_client(
    session: &mut Session,
    client: Client,
    cancel: &Arc<AtomicBool>,
    terminating: &Arc<AtomicBool>,
) -> Result<&'static str> {
    // A GDB client attaches to a stopped target: it reads registers before it
    // resumes anything. A passive backend cannot stop the guest, so its
    // client inspects memory live.
    if session.backend.is_running()
        && supports_capability(&session.capabilities(), DebugCapability::InterruptTarget)
        && let Err(error) = session.interrupt_outcome()
    {
        eprintln!("ntoseye-gdbserver: could not halt the target for the client: {error}");
    }
    let mut target = GdbTarget::new(session, Arc::clone(cancel), Arc::clone(terminating));
    let result = drive(&mut target, client);
    target.release();
    result
}

/// Run the protocol state machine. Owning the loop, rather than using
/// gdbstub's blocking one, lets an idle wait keep a halted target's
/// transport serviced and notice a termination signal.
fn drive(target: &mut GdbTarget<'_>, client: Client) -> Result<&'static str> {
    let stub = GdbStub::builder(client)
        .packet_buffer_size(PACKET_SIZE)
        .build()
        .map_err(|error| Error::DebugInfo(error.to_string()))?;
    let mut machine = stub.run_state_machine(target).map_err(protocol_error)?;
    loop {
        machine = match machine {
            GdbStubStateMachine::Idle(mut idle) => match idle.borrow_conn().read_byte(IDLE_POLL) {
                Ok(Some(b'$')) => {
                    let client = idle.borrow_conn();
                    let (body, raw) = client.read_packet().map_err(connection_error)?;
                    trace_packet("client", "<-", &raw);
                    match body.strip_prefix(THREADS_XFER) {
                        Some(window) => {
                            let reply = target.threads_xfer(window, client.multiprocess);
                            client.reply(&reply).map_err(connection_error)?;
                            GdbStubStateMachine::Idle(idle)
                        }
                        None => {
                            client.observe(&body);
                            let packet = match current_thread_step(&body) {
                                Some(step) => {
                                    let mut packet = Vec::new();
                                    frame(&mut packet, step);
                                    packet
                                }
                                None => raw,
                            };
                            feed(GdbStubStateMachine::Idle(idle), target, &packet)?
                        }
                    }
                }
                Ok(Some(byte)) => idle.incoming_data(target, byte).map_err(protocol_error)?,
                Ok(None) => {
                    if target.terminating() {
                        return Ok("released by a termination signal");
                    }
                    target.session.service_idle();
                    GdbStubStateMachine::Idle(idle)
                }
                Err(error) => return Err(connection_error(error)),
            },
            GdbStubStateMachine::Running(mut running) => match target.wait(running.borrow_conn()) {
                Ok(Wait::Stopped(reason)) => running
                    .report_stop(target, reason)
                    .map_err(protocol_error)?,
                Ok(Wait::Data(byte)) => running
                    .incoming_data(target, byte)
                    .map_err(protocol_error)?,
                Ok(Wait::Terminating) => return Ok("released by a termination signal"),
                Err(error) => return Err(connection_error(error)),
            },
            GdbStubStateMachine::CtrlCInterrupt(interrupt) => {
                let reason = target.interrupt();
                interrupt
                    .interrupt_handled(target, reason)
                    .map_err(protocol_error)?
            }
            GdbStubStateMachine::Disconnected(disconnected) => {
                return Ok(match disconnected.get_reason() {
                    DisconnectReason::Kill => "killed the session (the guest keeps running)",
                    _ => "detached",
                });
            }
        };
    }
}

fn protocol_error(error: impl std::fmt::Display) -> Error {
    Error::DebugInfo(format!("protocol error: {error}"))
}

/// The `s`/`S<sig>` packet for a `vCont` whose first action steps with no
/// thread id. Binary Ninja steps that way; such an action applies to every
/// thread, which gdbstub rejects and drops the client for. Only the current
/// thread can step here anyway (the others stay stopped), and that thread is
/// what the plain packet steps.
fn current_thread_step(body: &[u8]) -> Option<&[u8]> {
    let action = body
        .strip_prefix(b"vCont;")?
        .split(|byte| *byte == b';')
        .next()?;
    match action {
        [b's'] => Some(action),
        [b'S', signal @ ..] if !signal.is_empty() && signal.iter().all(u8::is_ascii_hexdigit) => {
            Some(action)
        }
        _ => None,
    }
}

/// Pass a packet the server did not answer itself on to gdbstub, byte by
/// byte, as if it had just arrived.
fn feed<'t>(
    mut machine: GdbStubStateMachine<'static, GdbTarget<'t>, Client>,
    target: &mut GdbTarget<'t>,
    bytes: &[u8],
) -> Result<GdbStubStateMachine<'static, GdbTarget<'t>, Client>> {
    for &byte in bytes {
        machine = match machine {
            GdbStubStateMachine::Idle(idle) => idle.incoming_data(target, byte),
            GdbStubStateMachine::Running(running) => running.incoming_data(target, byte),
            // A packet is only acted on at its last byte.
            other => return Ok(other),
        }
        .map_err(protocol_error)?;
    }
    Ok(machine)
}

fn connection_error(error: io::Error) -> Error {
    Error::DebugInfo(format!("connection lost: {error}"))
}

/// A client socket. Writes are buffered until gdbstub ends a packet, and a
/// blocking read gives up periodically so the caller can do other work.
struct Client {
    stream: TcpStream,
    out: Vec<u8>,
    inbox: Vec<u8>,
    next: usize,
    /// The client turned off acknowledgments (`QStartNoAckMode`).
    no_ack: bool,
    /// A `qSupported` went to gdbstub, whose reply must advertise the
    /// thread-list transfer the server answers itself.
    advertise_threads: bool,
    /// The client negotiated `multiprocess+`, so thread ids carry a pid.
    multiprocess: bool,
    terminating: Arc<AtomicBool>,
}

impl Client {
    fn new(stream: TcpStream, terminating: Arc<AtomicBool>) -> io::Result<Self> {
        // The listener is non-blocking so accept can poll; the client is not.
        stream.set_nonblocking(false)?;
        Ok(Self {
            stream,
            out: Vec::new(),
            inbox: Vec::new(),
            next: 0,
            no_ack: false,
            advertise_threads: false,
            multiprocess: false,
            terminating,
        })
    }

    /// The rest of a packet whose `$` was just read: its body, and the whole
    /// packet as received.
    fn read_packet(&mut self) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut raw = vec![b'$'];
        loop {
            let byte = ConnectionExt::read(self)?;
            raw.push(byte);
            if byte == b'#' {
                break;
            }
        }
        for _ in 0..2 {
            raw.push(ConnectionExt::read(self)?);
        }
        let body = raw[1..raw.len() - 3].to_vec();
        Ok((body, raw))
    }

    /// Track what a packet headed for gdbstub changes about framing.
    fn observe(&mut self, body: &[u8]) {
        if body.starts_with(b"qSupported") {
            self.advertise_threads = true;
            self.multiprocess = body
                .split(|byte| matches!(byte, b':' | b';'))
                .any(|feature| feature == b"multiprocess+");
        }
        if body == b"QStartNoAckMode" {
            self.no_ack = true;
        }
    }

    /// Answer a packet the server handled itself.
    fn reply(&mut self, body: &[u8]) -> io::Result<()> {
        if !self.no_ack {
            self.out.push(b'+');
        }
        frame(&mut self.out, body);
        Connection::flush(self)
    }

    /// Refill the inbox from the socket, waiting at most `timeout` (`None`:
    /// not at all). Returns whether a byte is available.
    fn fill(&mut self, timeout: Option<Duration>) -> io::Result<bool> {
        if self.next < self.inbox.len() {
            return Ok(true);
        }
        match timeout {
            Some(timeout) => {
                self.stream.set_nonblocking(false)?;
                self.stream.set_read_timeout(Some(timeout))?;
            }
            None => self.stream.set_nonblocking(true)?,
        }
        self.inbox.resize(PACKET_SIZE, 0);
        self.next = 0;
        // gdbstub implements its own `Connection` for `TcpStream`, so the
        // socket's `io` methods are named explicitly.
        let read = match Read::read(&mut self.stream, &mut self.inbox) {
            Ok(0) => {
                self.inbox.clear();
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                0
            }
            Err(error) => {
                self.inbox.clear();
                return Err(error);
            }
        };
        self.inbox.truncate(read);
        Ok(read > 0)
    }

    /// One byte, or `None` when nothing arrived within `timeout`.
    fn read_byte(&mut self, timeout: Duration) -> io::Result<Option<u8>> {
        if !self.fill(Some(timeout))? {
            return Ok(None);
        }
        let byte = self.inbox[self.next];
        self.next += 1;
        Ok(Some(byte))
    }

    /// Send console text as `O` packets, which a client shows while the
    /// target runs. The client's acknowledgment (in ack mode) is a bare `+`
    /// that gdbstub skips as noise.
    fn console(&mut self, text: &str) -> io::Result<()> {
        for chunk in text.as_bytes().chunks(CONSOLE_CHUNK) {
            let mut body = String::with_capacity(chunk.len() * 2 + 1);
            body.push('O');
            for byte in chunk {
                let _ = write!(body, "{byte:02x}");
            }
            frame(&mut self.out, body.as_bytes());
        }
        Connection::flush(self)
    }
}

/// Append `body` as a `$body#checksum` packet.
fn frame(out: &mut Vec<u8>, body: &[u8]) {
    let checksum = body.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    out.push(b'$');
    out.extend_from_slice(body);
    out.extend_from_slice(format!("#{checksum:02x}").as_bytes());
}

/// Append `feature` to the `qSupported` reply packet in `out`, fixing its
/// checksum. `None` when `out` holds no such reply.
fn advertise(out: &[u8], feature: &[u8]) -> Option<Vec<u8>> {
    let start = out
        .windows(12)
        .position(|window| window == b"$PacketSize=")?;
    let hash = start + out[start..].iter().position(|byte| *byte == b'#')?;
    let digits = std::str::from_utf8(out.get(hash + 1..hash + 3)?).ok()?;
    let checksum = u8::from_str_radix(digits, 16).ok()?;
    let checksum = feature
        .iter()
        .fold(checksum, |sum, byte| sum.wrapping_add(*byte));
    let mut rewritten = out[..hash].to_vec();
    rewritten.extend_from_slice(feature);
    rewritten.extend_from_slice(format!("#{checksum:02x}").as_bytes());
    rewritten.extend_from_slice(&out[hash + 3..]);
    Some(rewritten)
}

/// The `offset,length` (hex) of a `qXfer` read.
fn xfer_window(window: &[u8]) -> Option<(usize, usize)> {
    let (offset, length) = std::str::from_utf8(window).ok()?.split_once(',')?;
    Some((
        usize::from_str_radix(offset, 16).ok()?,
        usize::from_str_radix(length, 16).ok()?,
    ))
}

/// A `qXfer` read reply for `[offset, offset + length)` of `data`: `m` when
/// more follows, `l` at the end, with the binary escapes the protocol needs.
fn xfer_reply(data: &[u8], offset: usize, length: usize) -> Vec<u8> {
    let start = offset.min(data.len());
    let end = start.saturating_add(length).min(data.len());
    let mut reply = vec![if end < data.len() { b'm' } else { b'l' }];
    for &byte in &data[start..end] {
        if matches!(byte, b'#' | b'$' | b'}' | b'*') {
            reply.extend_from_slice(&[b'}', byte ^ 0x20]);
        } else {
            reply.push(byte);
        }
    }
    reply
}

/// `<threads>` for a thread-list transfer; `core` is the processor number.
/// Ids must match the stop replies: `p1.<tid>` once the client negotiated
/// multiprocess (gdb, lldb), plain hex otherwise, which is also the only
/// form IDA parses.
fn thread_list_xml<'n>(names: impl IntoIterator<Item = &'n str>, multiprocess: bool) -> String {
    let mut xml = String::from("<?xml version=\"1.0\"?>\n<threads>\n");
    // gdbstub reports every thread under pid 1 without extended mode.
    let pid = if multiprocess { "p1." } else { "" };
    for (index, name) in names.into_iter().enumerate() {
        let _ = writeln!(
            xml,
            "<thread id=\"{pid}{:x}\" core=\"{index}\" name=\"{}\"/>",
            index + 1,
            xml_escape(name)
        );
    }
    xml.push_str("</threads>\n");
    xml
}

impl Connection for Client {
    type Error = io::Error;

    fn write(&mut self, byte: u8) -> io::Result<()> {
        self.out.push(byte);
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.out.extend_from_slice(buf);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.advertise_threads
            && let Some(rewritten) = advertise(&self.out, THREADS_FEATURE)
        {
            self.out = rewritten;
            self.advertise_threads = false;
        }
        trace_packet("client", "->", &self.out);
        self.stream.set_nonblocking(false)?;
        Write::write_all(&mut self.stream, &self.out)?;
        self.out.clear();
        Write::flush(&mut self.stream)
    }

    fn on_session_start(&mut self) -> io::Result<()> {
        self.stream.set_nodelay(true)
    }
}

impl ConnectionExt for Client {
    fn read(&mut self) -> io::Result<u8> {
        loop {
            if self.terminating.load(Ordering::SeqCst) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "termination signal received",
                ));
            }
            if let Some(byte) = self.read_byte(IDLE_POLL)? {
                return Ok(byte);
            }
        }
    }

    fn peek(&mut self) -> io::Result<Option<u8>> {
        Ok(self.fill(None)?.then(|| self.inbox[self.next]))
    }
}

/// What a wait for the target produced.
enum Wait {
    Stopped(MultiThreadStopReason<u64>),
    /// The client sent something (typically the `0x03` interrupt byte).
    Data(u8),
    Terminating,
}

/// The register file on the wire, in target-description order. `None` bytes
/// are registers the transport does not carry.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WireRegisters(Vec<Option<u8>>);

impl Registers for WireRegisters {
    type ProgramCounter = u64;

    /// gdbstub never asks for the pc; clients find it in the description.
    fn pc(&self) -> u64 {
        0
    }

    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        for byte in &self.0 {
            write_byte(*byte);
        }
    }

    fn gdb_deserialize(&mut self, bytes: &[u8]) -> std::result::Result<(), ()> {
        self.0 = bytes.iter().copied().map(Some).collect();
        Ok(())
    }
}

/// A register's position in the target description. Widths come from the
/// description, which is only known at runtime.
#[derive(Debug)]
pub struct WireRegId(usize);

impl RegId for WireRegId {
    fn from_raw_id(id: usize) -> Option<(Self, Option<NonZeroUsize>)> {
        Some((Self(id), None))
    }
}

/// The protocol-facing architecture. The real one (AMD64 or ARM64) is chosen
/// at attach and published through the target description override.
pub enum WireArch {}

impl GdbArch for WireArch {
    type Usize = u64;
    type Registers = WireRegisters;
    type BreakpointKind = usize;
    type RegId = WireRegId;
}

/// A breakpoint the client planted, and the session breakpoint behind it.
struct Planted {
    kind: PlantedKind,
    address: u64,
    id: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PlantedKind {
    Software,
    Hardware,
    Watch { len: u64, kind: WatchKind },
}

struct GdbTarget<'a> {
    session: &'a mut Session,
    arch: Arch,
    layout: Layout,
    /// The REPL state `monitor` commands run in, kept between commands so
    /// aliases, the radix, and caches persist.
    repl: Option<ReplStore>,
    /// Backend vCPU ids; RSP thread `n` is `threads[n - 1]`.
    threads: Vec<String>,
    planted: Vec<Planted>,
    /// The vCPU the client asked to single-step on the next resume.
    step_thread: Option<Tid>,
    /// A stop that already happened (a completed step, a refused resume),
    /// reported by the next wait.
    pending: Option<ContinueOutcome>,
    /// Console lines for the client, sent before the next stop report.
    notes: Vec<String>,
    debug_seq: u64,
    /// The last library list served, so a client reading it in chunks sees
    /// one snapshot. Rebuilt whenever a read starts over at offset zero.
    libraries: RefCell<Vec<u8>>,
    /// The last memory map served, snapshotted the same way.
    memory_map: RefCell<Vec<u8>>,
    /// The last thread list served, snapshotted the same way.
    thread_list: Vec<u8>,
    /// Files the client opened with `vFile:open`, by descriptor.
    files: HashMap<u32, OpenFile>,
    next_fd: u32,
    cancel: Arc<AtomicBool>,
    terminating: Arc<AtomicBool>,
}

impl<'a> GdbTarget<'a> {
    fn new(
        session: &'a mut Session,
        cancel: Arc<AtomicBool>,
        terminating: Arc<AtomicBool>,
    ) -> Self {
        let arch = session.target.arch();
        let layout = Layout::new(arch, &session.register_map);
        let debug_seq = session.read_debug_output(u64::MAX).next_seq;
        let mut target = Self {
            session,
            arch,
            layout,
            repl: None,
            threads: Vec::new(),
            planted: Vec::new(),
            step_thread: None,
            pending: None,
            notes: Vec::new(),
            debug_seq,
            libraries: RefCell::new(Vec::new()),
            memory_map: RefCell::new(Vec::new()),
            thread_list: Vec::new(),
            files: HashMap::new(),
            next_fd: 0,
            cancel,
            terminating,
        };
        target.sync_threads();
        target
    }

    fn terminating(&self) -> bool {
        self.terminating.load(Ordering::SeqCst)
    }

    /// Remove the client's breakpoints and resume a halted guest: what a
    /// detaching gdb leaves behind. The session and its own breakpoints
    /// (set through `monitor`) stay for the next client.
    fn release(&mut self) {
        let ids: Vec<u32> = self.planted.drain(..).map(|planted| planted.id).collect();
        if !ids.is_empty() {
            let removed = self.session.with_target_halted(|session| {
                for id in ids {
                    let _ = session.remove_breakpoint(id);
                }
                Ok(())
            });
            if let Err(error) = removed {
                eprintln!("ntoseye-gdbserver: could not remove the client's breakpoints: {error}");
            }
        }
        if self.terminating() || self.session.backend.is_running() {
            return;
        }
        if supports_capability(
            &self.session.capabilities(),
            DebugCapability::ExecutionControl,
        ) && let Err(error) = self.session.resume()
        {
            eprintln!("ntoseye-gdbserver: could not resume the guest: {error}");
        }
    }

    fn sync_threads(&mut self) {
        self.threads = match self.session.backend.thread_list() {
            Ok(threads) if !threads.is_empty() => threads,
            _ => vec![self.session.current_thread.clone()],
        };
    }

    fn tid_of(&self, backend_id: &str) -> Tid {
        let index = self
            .threads
            .iter()
            .position(|id| id == backend_id)
            .unwrap_or(0);
        NonZeroUsize::new(index + 1).expect("index + 1 is never zero")
    }

    fn current_tid(&self) -> Tid {
        self.tid_of(&self.session.current_thread)
    }

    /// Make `tid` the vCPU register reads and steps apply to.
    fn select(&mut self, tid: Tid) -> Result<()> {
        if self.threads.is_empty() {
            self.sync_threads();
        }
        let id = self
            .threads
            .get(tid.get() - 1)
            .cloned()
            .ok_or_else(|| Error::InvalidArgument(format!("no thread {tid}")))?;
        if self.session.current_thread != id {
            self.session.set_current_thread(&id)?;
        }
        Ok(())
    }

    /// Run `access` against `tid`'s registers, then give ntoseye's current
    /// vCPU back. A client reads every thread's registers to list them, and
    /// `monitor` commands must keep acting on the stopped vCPU (or the one
    /// chosen with `monitor ~<n>s`) regardless.
    fn with_thread<T>(
        &mut self,
        tid: Tid,
        access: impl FnOnce(&mut Session, &Layout) -> Result<T>,
    ) -> Result<T> {
        let previous = self.session.current_thread.clone();
        self.select(tid)?;
        let result = access(self.session, &self.layout);
        if self.session.current_thread != previous {
            self.session.set_current_thread(&previous)?;
        }
        result
    }

    fn note(&mut self, text: impl Into<String>) {
        self.notes.push(text.into());
    }

    /// Send queued notes, guest `DbgPrint` output, and session notices to the
    /// client's console.
    fn flush_console(&mut self, client: &mut Client) -> io::Result<()> {
        let mut text = String::new();
        for notice in self.session.take_notices() {
            text.push_str(&notice);
            text.push('\n');
        }
        let page = self.session.read_debug_output(self.debug_seq);
        self.debug_seq = page.next_seq;
        if page.dropped {
            text.push_str("guest debug output overflowed; lines were dropped\n");
        }
        for line in page.lines {
            text.push_str(&line.text);
            text.push('\n');
        }
        for note in self.notes.drain(..) {
            text.push_str("ntoseye: ");
            text.push_str(&note);
            text.push('\n');
        }
        if text.is_empty() {
            return Ok(());
        }
        client.console(&text)
    }

    /// Wait for the resumed target to stop, for the client to send
    /// something, or for a termination signal.
    fn wait(&mut self, client: &mut Client) -> io::Result<Wait> {
        loop {
            if let Some(outcome) = self.pending.take()
                && let Some(reason) = self.stop_reason(outcome, false)
            {
                self.flush_console(client)?;
                return Ok(Wait::Stopped(reason));
            }
            if self.terminating() {
                return Ok(Wait::Terminating);
            }
            if let Some(byte) = client.peek()? {
                client.next += 1;
                trace_packet("client", "<-", &[byte]);
                return Ok(Wait::Data(byte));
            }
            let outcome = self
                .session
                .wait_for_stop_bounded(Some(RUN_POLL), &self.cancel);
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(error) => {
                    // Report a stop rather than leave the client waiting on a
                    // run that can never end.
                    self.note(format!("target wait failed: {error}"));
                    ContinueOutcome::Halted { rip: 0 }
                }
            };
            self.flush_console(client)?;
            if let Some(reason) = self.stop_reason(outcome, false) {
                self.flush_console(client)?;
                return Ok(Wait::Stopped(reason));
            }
        }
    }

    /// Break in for the client's interrupt.
    fn interrupt(&mut self) -> Option<MultiThreadStopReason<u64>> {
        self.cancel.store(false, Ordering::SeqCst);
        let outcome = self.session.interrupt_outcome().unwrap_or_else(|error| {
            self.note(format!("break-in failed: {error}"));
            ContinueOutcome::Halted { rip: 0 }
        });
        // Nothing to report if the target kept running; the client keeps
        // waiting and may interrupt again.
        self.stop_reason(outcome, true)
    }

    /// Translate a session stop into a stop reply, or `None` when the target
    /// is still running (a breakpoint action resumed it). `interrupted` marks
    /// the break-in the client asked for, which gdb expects as `SIGINT`.
    fn stop_reason(
        &mut self,
        outcome: ContinueOutcome,
        interrupted: bool,
    ) -> Option<MultiThreadStopReason<u64>> {
        let signal = match outcome {
            ContinueOutcome::Running => return None,
            ContinueOutcome::Breakpoint {
                id,
                symbol,
                rip,
                action,
                condition_error,
                ..
            } => {
                if let Some(error) = condition_error {
                    self.note(format!("breakpoint {id} condition failed: {error}"));
                }
                if let Some(action) = action
                    && self.run_breakpoint_action(&action)
                {
                    return None;
                }
                self.sync_threads();
                let tid = self.current_tid();
                if let Some(planted) = self.planted.iter().find(|planted| planted.id == id) {
                    return Some(match planted.kind {
                        PlantedKind::Software => MultiThreadStopReason::SwBreak(tid),
                        PlantedKind::Hardware => MultiThreadStopReason::HwBreak(tid),
                        PlantedKind::Watch { kind, .. } => MultiThreadStopReason::Watch {
                            tid,
                            kind,
                            addr: planted.address,
                        },
                    });
                }
                // Set with `monitor bp`: the client has no record of it.
                let place = symbol.unwrap_or_else(|| format!("{rip:#x}"));
                self.note(format!("breakpoint {id} hit at {place}"));
                Signal::SIGTRAP
            }
            ContinueOutcome::Step { .. } => Signal::SIGTRAP,
            ContinueOutcome::Halted { .. } if interrupted => Signal::SIGINT,
            ContinueOutcome::Halted { .. } => Signal::SIGTRAP,
            ContinueOutcome::Stopped {
                rip,
                exception_code,
                first_chance,
                ..
            } => match exception_code {
                None | Some(STATUS_BREAKPOINT) if interrupted => Signal::SIGINT,
                None => Signal::SIGTRAP,
                Some(code) => {
                    let chance = match first_chance {
                        Some(true) => " (first chance)",
                        Some(false) => " (second chance)",
                        None => "",
                    };
                    let name = exception_code_name(code);
                    self.note(format!("{name} ({code:#010x}){chance} at {rip:#x}"));
                    exception_signal(code)
                }
            },
            ContinueOutcome::Bugcheck { rip, info } => {
                let detail = match info {
                    Some(info) => format!(
                        "bugcheck {:#x} ({:#x}, {:#x}, {:#x}, {:#x})",
                        info.code,
                        info.parameters[0],
                        info.parameters[1],
                        info.parameters[2],
                        info.parameters[3]
                    ),
                    None => "bugcheck (code unavailable from the transport)".to_string(),
                };
                match rip {
                    Some(rip) => self.note(format!("{detail} at {rip:#x}")),
                    None => self.note(detail),
                }
                self.note("run `monitor !analyze -v` for the full triage");
                Signal::SIGABRT
            }
            ContinueOutcome::TargetReloaded {
                kernel_base,
                coherent,
                ..
            } => {
                let base = kernel_base
                    .map(|base| format!("{base:#x}"))
                    .unwrap_or_else(|| "unknown".to_string());
                let early = if coherent {
                    ""
                } else {
                    " (early boot: modules and processes are not available yet)"
                };
                self.note(format!("target rebooted; nt base {base}{early}"));
                // Every breakpoint the client planted belonged to the old boot.
                self.planted.clear();
                Signal::SIGTRAP
            }
        };
        self.sync_threads();
        Some(MultiThreadStopReason::SignalWithThread {
            tid: self.current_tid(),
            signal,
        })
    }

    /// Run a `bp ... do "..."` action set through `monitor`. Returns whether
    /// it resumed the target (a trailing `gc`), in which case the stop is not
    /// reported.
    fn run_breakpoint_action(&mut self, action: &str) -> bool {
        let store = ReplStore::new(self.session, DispatchContext::BreakpointAction);
        let mut state = ReplState::attach(self.session, store);
        state.line = action.to_string();
        let (result, text) = output::capture(|| state.dispatch_breakpoint_action(action));
        drop(state.detach());
        if !text.is_empty() {
            self.notes.push(text.trim_end().to_string());
        }
        match result {
            Ok(true) => match self.session.resume() {
                Ok(()) => true,
                Err(error) => {
                    self.note(format!(
                        "breakpoint action could not resume the target: {error}"
                    ));
                    false
                }
            },
            Ok(false) => false,
            Err(error) => {
                self.note(format!("breakpoint action failed: {error}"));
                false
            }
        }
    }

    /// Plant a client breakpoint, halting a running target for the edit.
    fn plant(&mut self, kind: PlantedKind, address: u64) -> TargetResult<bool, Self> {
        if self
            .planted
            .iter()
            .any(|planted| planted.kind == kind && planted.address == address)
        {
            return Ok(true);
        }
        let config = BreakpointConfig::default();
        let added = self.session.with_target_halted(|session| match kind {
            PlantedKind::Software => session.add_breakpoint(VirtAddr(address), None, config),
            PlantedKind::Hardware => session.breakpoints.add_hardware_configured(
                session.backend.as_mut(),
                &session.target,
                VirtAddr(address),
                HwBreakpointAccess::Execute,
                1,
                None,
                config,
            ),
            PlantedKind::Watch { len, kind } => {
                let len = u8::try_from(len).map_err(|_| {
                    Error::InvalidArgument(format!("watch length {len} is too large"))
                })?;
                // x86 has no read-only data watch; a read watch also traps
                // writes, as the DAP server's does.
                let access = match kind {
                    WatchKind::Write => WatchpointAccess::Write,
                    WatchKind::Read | WatchKind::ReadWrite => WatchpointAccess::ReadWrite,
                };
                session.add_watchpoint(VirtAddr(address), access, len, None, config)
            }
        });
        match added {
            Ok(id) => {
                self.planted.push(Planted { kind, address, id });
                Ok(true)
            }
            Err(error) => {
                eprintln!("ntoseye-gdbserver: breakpoint at {address:#x} refused: {error}");
                Err(TargetError::NonFatal)
            }
        }
    }

    fn unplant(&mut self, kind: PlantedKind, address: u64) -> TargetResult<bool, Self> {
        let Some(index) = self
            .planted
            .iter()
            .position(|planted| planted.kind == kind && planted.address == address)
        else {
            return Ok(false);
        };
        let id = self.planted.remove(index).id;
        let removed = self
            .session
            .with_target_halted(|session| session.remove_breakpoint(id));
        if let Err(error) = removed {
            eprintln!("ntoseye-gdbserver: removing breakpoint at {address:#x} failed: {error}");
            return Err(TargetError::NonFatal);
        }
        Ok(true)
    }

    /// The images published as libraries: kernel modules, plus the current
    /// process's modules once `.process` selects one.
    fn published_modules(&self) -> Vec<ModuleInfo> {
        let target = &self.session.target;
        let mut modules = target.kernel_modules().unwrap_or_default();
        if target.current_process_info.is_some() {
            modules.extend(target.modules().unwrap_or_default());
        }
        modules
    }

    fn libraries_xml(&self) -> Vec<u8> {
        let modules = self.published_modules();
        let entries = modules
            .iter()
            .map(|module| (module.name.as_str(), module.base_address.0));
        library_list_xml(self.arch, entries).into_bytes()
    }

    fn current_memory_map(&self) -> Vec<u8> {
        let modules = self.published_modules();
        let images = image_spans(&modules);
        memory_map_xml(&address_layout(self.arch, &images)).into_bytes()
    }

    fn current_proc_maps(&self) -> Vec<u8> {
        let modules = self.published_modules();
        let images = image_spans(&modules);
        proc_maps(&address_layout(self.arch, &images)).into_bytes()
    }

    /// Answer `qXfer:threads:read` for `window` (`offset,length`), naming each
    /// vCPU by what it runs. A read starting at zero takes a new snapshot.
    fn threads_xfer(&mut self, window: &[u8], multiprocess: bool) -> Vec<u8> {
        let Some((offset, length)) = xfer_window(window) else {
            return b"E00".to_vec();
        };
        if offset == 0 {
            let names = match self.session.vcpus() {
                Ok(vcpus) => vcpus.iter().map(VcpuInfo::label).collect(),
                Err(_) => {
                    self.sync_threads();
                    self.threads.clone()
                }
            };
            self.thread_list =
                thread_list_xml(names.iter().map(String::as_str), multiprocess).into_bytes();
        }
        xfer_reply(&self.thread_list, offset, length)
    }

    fn kernel_image_name(&self) -> String {
        let target = &self.session.target;
        target
            .kernel_base()
            .and_then(|base| {
                target
                    .kernel_modules()
                    .ok()?
                    .into_iter()
                    .find(|module| module.base_address == base)
            })
            .map(|module| module.name)
            .unwrap_or_else(|| "ntoskrnl.exe".to_string())
    }

    /// The live kernel base minus the preferred base in the kernel's PE file.
    /// The file is the only source: the loader rewrites `ImageBase` in the
    /// mapped headers to the address it relocated the image to.
    fn kernel_slide(&self) -> Option<u64> {
        let target = &self.session.target;
        let base = target.kernel_base()?;
        let image = target
            .module_image_or_fetch_later(&self.kernel_image_name())
            .ok()??;
        let mut headers = [0u8; 0x1000];
        let read = File::open(image).ok()?.read_at(&mut headers, 0).ok()?;
        let view = PeView::from_bytes(&headers[..read]).ok()?;
        Some(base.0.wrapping_sub(image_base(&view)))
    }

    /// Hold `file` open for the client under a new descriptor.
    fn add_file(&mut self, file: OpenFile) -> u32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.files.insert(fd, file);
        fd
    }
}

/// The signal gdb shows for a Windows exception. Anything without a closer
/// POSIX match is a trap; the console note names the real status.
fn exception_signal(code: u32) -> Signal {
    match code {
        STATUS_BREAKPOINT | STATUS_SINGLE_STEP => Signal::SIGTRAP,
        STATUS_ACCESS_VIOLATION | STATUS_IN_PAGE_ERROR => Signal::SIGSEGV,
        STATUS_ILLEGAL_INSTRUCTION | STATUS_PRIVILEGED_INSTRUCTION => Signal::SIGILL,
        STATUS_FLOAT_DIVIDE_BY_ZERO
        | STATUS_FLOAT_INVALID_OPERATION
        | STATUS_INTEGER_DIVIDE_BY_ZERO
        | STATUS_INTEGER_OVERFLOW => Signal::SIGFPE,
        _ => Signal::SIGTRAP,
    }
}

/// One stretch of the address space as clients are shown it: RAM between
/// module images, or one image with its file name.
#[derive(Debug, PartialEq, Eq)]
struct Span<'m> {
    start: u64,
    end: u64,
    image: Option<&'m str>,
}

/// The user and kernel halves of the canonical address space, cut around
/// the published module images (`base`, `size`, file name), in address
/// order. A client shows memory only inside its map, and reads of unmapped
/// pages within it simply fail, so the halves are all it needs. The kernel
/// half stops a page short of the top so its end fits in 64 bits. Empty
/// stretches are left out: a zero-length region is malformed to IDA.
fn address_layout<'m>(arch: Arch, images: &[(u64, u64, &'m str)]) -> Vec<Span<'m>> {
    let (user_len, kernel_start) = match arch {
        Arch::Amd64 => (0x0000_8000_0000_0000u64, 0xFFFF_8000_0000_0000u64),
        Arch::Arm64 => (0x0001_0000_0000_0000, 0xFFFF_0000_0000_0000),
    };
    let kernel_end = 0u64.wrapping_sub(0x1000);
    let mut images: Vec<(u64, u64, &str)> = images
        .iter()
        .filter(|(_, size, _)| *size != 0)
        .map(|&(base, size, name)| (base, base.saturating_add(size), name))
        .collect();
    images.sort_unstable();

    let mut spans = Vec::new();
    let ram = |spans: &mut Vec<Span<'m>>, start: u64, end: u64| {
        if end > start {
            spans.push(Span {
                start,
                end,
                image: None,
            });
        }
    };
    for (start, end) in [(0, user_len), (kernel_start, kernel_end)] {
        let mut cursor = start;
        for &(base, image_end, name) in &images {
            if image_end <= cursor || base >= end {
                continue;
            }
            ram(&mut spans, cursor, base.min(end));
            spans.push(Span {
                start: base.max(cursor),
                end: image_end.min(end),
                image: Some(name),
            });
            cursor = cursor.max(image_end);
        }
        ram(&mut spans, cursor, end);
    }
    spans
}

/// The memory-map XML, one region per stretch. gdb reads only inside the
/// map, so the images must be in it. They are their own regions because IDA
/// lays out a module's segments first and drops every map region that
/// overlaps one: a region spanning a whole half would take the kernel with it.
fn memory_map_xml(layout: &[Span<'_>]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n\
         <!DOCTYPE memory-map PUBLIC \"+//IDN gnu.org//DTD GDB Memory Map V1.0//EN\" \
         \"http://sourceware.org/gdb/gdb-memory-map.dtd\">\n\
         <memory-map>\n",
    );
    for span in layout {
        let _ = writeln!(
            xml,
            "<memory type=\"ram\" start=\"{:#x}\" length=\"{:#x}\"/>",
            span.start,
            span.end - span.start
        );
    }
    xml.push_str("</memory-map>\n");
    xml
}

/// The layout in Linux `/proc/<pid>/maps` form, the only place Binary
/// Ninja's GDB adapter looks for modules and memory regions. An image is a
/// line whose path is `/` and its file name, which is how the adapter names
/// the module and matches it to the open database by base name; RAM is a line
/// with no path.
fn proc_maps(layout: &[Span<'_>]) -> String {
    let mut maps = String::new();
    for span in layout {
        let perms = if span.image.is_some() { "r-xp" } else { "rw-p" };
        let _ = write!(
            maps,
            "{:x}-{:x} {perms} 00000000 00:00 0",
            span.start, span.end
        );
        if let Some(name) = span.image {
            let _ = write!(maps, " {}", remote_path(name));
        }
        maps.push('\n');
    }
    maps
}

/// The `(base, size, file name)` of each module, for [`address_layout`].
fn image_spans(modules: &[ModuleInfo]) -> Vec<(u64, u64, &str)> {
    modules
        .iter()
        .map(|module| {
            (
                module.base_address.0,
                u64::from(module.size),
                module.name.as_str(),
            )
        })
        .collect()
}

/// Whether a remote path names a process's memory map, `/proc/<pid>/maps`.
fn is_proc_maps(path: &str) -> bool {
    path.strip_prefix("/proc/")
        .and_then(|rest| rest.strip_suffix("/maps"))
        .is_some_and(|pid| {
            pid == "self" || (!pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// A Windows-style library list. Each name is rooted ([`remote_path`]). For
/// AMD64 a segment address is the image base plus 0x1000, the first section's
/// address, which is how gdb reads it for PE images and what IDA subtracts
/// before rebasing; for ARM64 IDA takes the address as the image base.
fn library_list_xml<'m>(arch: Arch, modules: impl IntoIterator<Item = (&'m str, u64)>) -> String {
    let bias = match arch {
        Arch::Amd64 => 0x1000,
        Arch::Arm64 => 0,
    };
    let mut xml = String::from("<?xml version=\"1.0\"?>\n<library-list>\n");
    for (name, base) in modules {
        let _ = writeln!(
            xml,
            "<library name=\"{}\"><segment address=\"{:#x}\"/></library>",
            xml_escape(&remote_path(name)),
            base.wrapping_add(bias)
        );
    }
    xml.push_str("</library-list>\n");
    xml
}

/// The path a module's image is reported under: its file name at the root.
/// gdb fetches a file through the server (`target:`) only when its path is
/// absolute, and looks for a bare name on the host instead. The server serves
/// any path by its file name, and clients match modules by base name, so no
/// directory is needed.
fn remote_path(name: &str) -> String {
    format!("/{name}")
}

fn xml_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// Copy the window `[offset, offset + length)` of `data` into `buf`, as a
/// `qXfer` read wants it. Zero means the object ended.
fn copy_window(data: &[u8], offset: u64, length: usize, buf: &mut [u8]) -> usize {
    let Some(rest) = usize::try_from(offset)
        .ok()
        .and_then(|start| data.get(start..))
    else {
        return 0;
    };
    let len = rest.len().min(length).min(buf.len());
    buf[..len].copy_from_slice(&rest[..len]);
    len
}

/// A session failure the client can recover from: it gets an error reply and
/// the connection stays up.
fn nonfatal<T>(result: Result<T>) -> std::result::Result<T, TargetError<Error>> {
    result.map_err(|_| TargetError::NonFatal)
}

impl Target for GdbTarget<'_> {
    type Arch = WireArch;
    type Error = Error;

    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::MultiThread(self)
    }

    /// The layout is chosen at runtime, so lldb must read it from the
    /// description rather than from `qRegisterInfo`.
    fn use_lldb_register_info(&self) -> bool {
        false
    }

    /// Replies go out unencoded. Run-length encoding is optional, and Binary
    /// Ninja's GDB adapter does not decode it in `vFile` replies, so an
    /// encoded `/proc/<pid>/maps` reached it garbled and no module matched.
    fn use_rle(&self) -> bool {
        false
    }

    /// Fork events are meaningless for a kernel target.
    fn use_fork_stop_reason(&self) -> bool {
        false
    }

    fn use_vfork_stop_reason(&self) -> bool {
        false
    }

    fn use_vforkdone_stop_reason(&self) -> bool {
        false
    }

    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }

    fn support_monitor_cmd(&mut self) -> Option<MonitorCmdOps<'_, Self>> {
        Some(self)
    }

    fn support_target_description_xml_override(
        &mut self,
    ) -> Option<TargetDescriptionXmlOverrideOps<'_, Self>> {
        Some(self)
    }

    fn support_memory_map(&mut self) -> Option<MemoryMapOps<'_, Self>> {
        Some(self)
    }

    fn support_libraries(&mut self) -> Option<LibrariesOps<'_, Self>> {
        Some(self)
    }

    fn support_exec_file(&mut self) -> Option<ExecFileOps<'_, Self>> {
        Some(self)
    }

    fn support_host_io(&mut self) -> Option<HostIoOps<'_, Self>> {
        Some(self)
    }

    fn support_section_offsets(&mut self) -> Option<SectionOffsetsOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadBase for GdbTarget<'_> {
    fn read_registers(&mut self, regs: &mut WireRegisters, tid: Tid) -> TargetResult<(), Self> {
        regs.0 = nonfatal(self.with_thread(tid, |session, layout| {
            let file = session.read_registers()?;
            Ok(layout.encode(&session.register_map, &file))
        }))?;
        Ok(())
    }

    fn write_registers(&mut self, regs: &WireRegisters, tid: Tid) -> TargetResult<(), Self> {
        let wire: Vec<u8> = regs.0.iter().map(|byte| byte.unwrap_or(0)).collect();
        nonfatal(self.with_thread(tid, |session, layout| {
            session.patch_registers(|map, file| layout.decode(map, file, &wire))
        }))
    }

    fn support_single_register_access(&mut self) -> Option<SingleRegisterAccessOps<'_, Tid, Self>> {
        Some(self)
    }

    fn read_addrs(
        &mut self,
        start_addr: u64,
        data: &mut [u8],
        _tid: Tid,
    ) -> TargetResult<usize, Self> {
        // Memory follows the inspection context (`monitor .process`), not
        // the thread: kernel space is the same on every vCPU.
        match self.session.read_masked_partial(VirtAddr(start_addr), data) {
            0 if !data.is_empty() => Err(TargetError::Errno(EFAULT as u8)),
            read => Ok(read),
        }
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
        let written = self
            .session
            .target
            .current_process()
            .and_then(|process| process.memory().write_bytes(VirtAddr(start_addr), data));
        written.map_err(|_| TargetError::Errno(EFAULT as u8))
    }

    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(Tid),
    ) -> std::result::Result<(), Self::Error> {
        if self.threads.is_empty() {
            self.sync_threads();
        }
        // The stopped vCPU first: a client's `?` reports the first thread.
        let current = self.current_tid();
        thread_is_active(current);
        for index in 0..self.threads.len() {
            let tid = NonZeroUsize::new(index + 1).expect("index + 1 is never zero");
            if tid != current {
                thread_is_active(tid);
            }
        }
        Ok(())
    }

    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl SingleRegisterAccess<Tid> for GdbTarget<'_> {
    fn read_register(
        &mut self,
        tid: Tid,
        reg_id: WireRegId,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let value = nonfatal(self.with_thread(tid, |session, layout| {
            let file = session.read_registers()?;
            layout
                .encode_one(reg_id.0, &session.register_map, &file)
                .ok_or(Error::NotSupported)
        }))?;
        let slot = buf.get_mut(..value.len()).ok_or(TargetError::NonFatal)?;
        slot.copy_from_slice(&value);
        Ok(value.len())
    }

    fn write_register(
        &mut self,
        tid: Tid,
        reg_id: WireRegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        nonfatal(self.with_thread(tid, |session, layout| {
            session.patch_registers(|map, file| layout.decode_one(reg_id.0, map, file, val))
        }))
    }
}

impl MultiThreadResume for GdbTarget<'_> {
    fn resume(&mut self) -> std::result::Result<(), Self::Error> {
        self.cancel.store(false, Ordering::SeqCst);
        // A failed resume is reported as a stop, so the client sees the
        // reason instead of waiting forever or dropping the connection.
        let outcome = match self.step_thread.take() {
            Some(tid) => self
                .select(tid)
                .and_then(|()| self.session.step())
                .map(|rip| Some(ContinueOutcome::Step { rip })),
            None => self.session.resume().map(|()| None),
        };
        self.pending = match outcome {
            Ok(pending) => pending,
            Err(error) => {
                self.note(format!("the target cannot run: {error}"));
                Some(ContinueOutcome::Halted { rip: 0 })
            }
        };
        Ok(())
    }

    fn clear_resume_actions(&mut self) -> std::result::Result<(), Self::Error> {
        self.step_thread = None;
        Ok(())
    }

    /// All-stop: a continue resumes every vCPU, whichever thread it names.
    fn set_resume_action_continue(
        &mut self,
        _tid: Tid,
        _signal: Option<Signal>,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        Some(self)
    }

    fn support_scheduler_locking(&mut self) -> Option<MultiThreadSchedulerLockingOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadSingleStep for GdbTarget<'_> {
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        _signal: Option<Signal>,
    ) -> std::result::Result<(), Self::Error> {
        self.step_thread = Some(tid);
        Ok(())
    }
}

/// A step already runs one vCPU with the others frozen, so locking the
/// scheduler to the stepped thread is what happens anyway.
impl MultiThreadSchedulerLocking for GdbTarget<'_> {
    fn set_resume_action_scheduler_lock(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

impl Breakpoints for GdbTarget<'_> {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_breakpoint(&mut self) -> Option<HwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_watchpoint(&mut self) -> Option<HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

impl SwBreakpoint for GdbTarget<'_> {
    fn add_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.plant(PlantedKind::Software, addr)
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.unplant(PlantedKind::Software, addr)
    }
}

impl HwBreakpoint for GdbTarget<'_> {
    fn add_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.plant(PlantedKind::Hardware, addr)
    }

    fn remove_hw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.unplant(PlantedKind::Hardware, addr)
    }
}

impl HwWatchpoint for GdbTarget<'_> {
    fn add_hw_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        self.plant(PlantedKind::Watch { len, kind }, addr)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> TargetResult<bool, Self> {
        self.unplant(PlantedKind::Watch { len, kind }, addr)
    }
}

impl MonitorCmd for GdbTarget<'_> {
    fn handle_monitor_cmd(
        &mut self,
        cmd: &[u8],
        mut out: ConsoleOutput<'_>,
    ) -> std::result::Result<(), Self::Error> {
        let line = String::from_utf8_lossy(cmd).trim().to_string();
        let store = self.repl.take().unwrap_or_else(|| {
            ReplStore::new(self.session, DispatchContext::Remote(RemoteClient::Gdb))
        });
        let mut state = ReplState::attach(self.session, store);
        state.line = line.clone();
        let (result, mut text) = output::capture(|| state.dispatch_line(&line));
        self.repl = Some(state.detach());
        match result {
            Ok(Flow::Denied) if text.is_empty() => {
                text = "this command would move the target; use the client's controls\n".into();
            }
            Err(error) => text.push_str(&format!("{error}\n")),
            Ok(_) => {}
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        out.write_raw(text.as_bytes());
        Ok(())
    }
}

impl TargetDescriptionXmlOverride for GdbTarget<'_> {
    fn target_description_xml(
        &self,
        annex: &[u8],
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        if annex != b"target.xml" {
            return Err(TargetError::NonFatal);
        }
        Ok(copy_window(
            self.layout.target_xml().as_bytes(),
            offset,
            length,
            buf,
        ))
    }
}

impl MemoryMap for GdbTarget<'_> {
    fn memory_map_xml(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let mut snapshot = self.memory_map.borrow_mut();
        if offset == 0 {
            *snapshot = self.current_memory_map();
        }
        Ok(copy_window(&snapshot, offset, length, buf))
    }
}

impl Libraries for GdbTarget<'_> {
    fn get_libraries(
        &self,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let mut snapshot = self.libraries.borrow_mut();
        if offset == 0 {
            *snapshot = self.libraries_xml();
        }
        Ok(copy_window(&snapshot, offset, length, buf))
    }
}

/// The kernel image is the "program": a client that opened `ntoskrnl.exe`
/// matches it by name and rebases its database to the live kernel, and gdb
/// fetches it from the server when it has no file of its own.
impl ExecFile for GdbTarget<'_> {
    fn get_exec_file(
        &self,
        _pid: Option<Pid>,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        Ok(copy_window(
            remote_path(&self.kernel_image_name()).as_bytes(),
            offset,
            length,
            buf,
        ))
    }
}

/// How far the program (the kernel image) sits from its preferred base, so
/// gdb relocates a kernel file it loaded itself (`file ntoskrnl.exe`, or the
/// image Ghidra launches gdb with) onto the live kernel. Zero, which gdb takes
/// as "not relocated", while the image is not in the symbol cache.
impl SectionOffsets for GdbTarget<'_> {
    fn get_section_offsets(&mut self) -> std::result::Result<Offsets<u64>, Self::Error> {
        let slide = self.kernel_slide().unwrap_or(0);
        Ok(Offsets::Sections {
            text: slide,
            data: slide,
            bss: None,
        })
    }
}

/// A file served through `vFile`: a module image from the symbol cache, or
/// text generated when it was opened.
enum OpenFile {
    Image(File),
    Generated(Vec<u8>),
}

impl OpenFile {
    /// Zero bytes at and past the end: IDA sizes a file by probing one-byte
    /// reads for where they stop.
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self {
            Self::Image(file) => file.read_at(buf, offset),
            Self::Generated(bytes) => {
                let rest = usize::try_from(offset)
                    .ok()
                    .and_then(|start| bytes.get(start..))
                    .unwrap_or_default();
                let len = rest.len().min(buf.len());
                buf[..len].copy_from_slice(&rest[..len]);
                Ok(len)
            }
        }
    }

    fn len(&self) -> io::Result<u64> {
        match self {
            Self::Image(file) => Ok(file.metadata()?.len()),
            Self::Generated(bytes) => Ok(bytes.len() as u64),
        }
    }
}

/// Remote file access, read-only: a client opening a path gets the PE file
/// of the loaded module with that file name, from the symbol cache. An image
/// not cached yet is downloaded in the background and the open fails until it
/// arrives. IDA started with `-rgdb@host:port ntoskrnl.exe` loads its input
/// this way, and gdb fetches the reported program file the same way, so either
/// gets the exact build that is running without copying anything. The one
/// other path served is `/proc/<pid>/maps`, generated from the module list,
/// which is where Binary Ninja's GDB adapter reads modules from.
impl HostIo for GdbTarget<'_> {
    fn support_open(&mut self) -> Option<HostIoOpenOps<'_, Self>> {
        Some(self)
    }

    fn support_close(&mut self) -> Option<HostIoCloseOps<'_, Self>> {
        Some(self)
    }

    fn support_pread(&mut self) -> Option<HostIoPreadOps<'_, Self>> {
        Some(self)
    }

    fn support_fstat(&mut self) -> Option<HostIoFstatOps<'_, Self>> {
        Some(self)
    }

    fn support_setfs(&mut self) -> Option<HostIoSetfsOps<'_, Self>> {
        Some(self)
    }
}

impl HostIoOpen for GdbTarget<'_> {
    fn open(
        &mut self,
        filename: &[u8],
        flags: HostIoOpenFlags,
        _mode: HostIoOpenMode,
    ) -> HostIoResult<u32, Self> {
        let writes = HostIoOpenFlags::O_WRONLY
            | HostIoOpenFlags::O_RDWR
            | HostIoOpenFlags::O_APPEND
            | HostIoOpenFlags::O_CREAT
            | HostIoOpenFlags::O_TRUNC;
        if flags.intersects(writes) {
            return Err(HostIoError::Errno(HostIoErrno::EROFS));
        }
        let path = String::from_utf8_lossy(filename);
        if is_proc_maps(&path) {
            let maps = self.current_proc_maps();
            return Ok(self.add_file(OpenFile::Generated(maps)));
        }
        // Clients send whatever path they hold: a host path, a guest path,
        // or a bare name. The file name is what identifies the module.
        let name = path.rsplit(['/', '\\']).next().unwrap_or(&path);
        // Never download here: the client is waiting on this reply with a
        // short timeout, and a late reply knocks every later one out of step.
        let image = match self.session.target.module_image_or_fetch_later(name) {
            Ok(Some(image)) => image,
            Ok(None) => {
                eprintln!(
                    "ntoseye-gdbserver: {name} is being downloaded; it can be opened once that \
                     finishes"
                );
                return Err(HostIoError::Errno(HostIoErrno::ENOENT));
            }
            Err(error) => {
                eprintln!("ntoseye-gdbserver: cannot serve {path}: {error}");
                return Err(HostIoError::Errno(HostIoErrno::ENOENT));
            }
        };
        let file = File::open(&image)?;
        Ok(self.add_file(OpenFile::Image(file)))
    }
}

impl HostIoClose for GdbTarget<'_> {
    fn close(&mut self, fd: u32) -> HostIoResult<(), Self> {
        self.files
            .remove(&fd)
            .map(drop)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))
    }
}

impl HostIoPread for GdbTarget<'_> {
    fn pread(
        &mut self,
        fd: u32,
        count: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> HostIoResult<usize, Self> {
        let file = self
            .files
            .get(&fd)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))?;
        let len = count.min(buf.len());
        Ok(file.read_at(&mut buf[..len], offset)?)
    }
}

impl HostIoFstat for GdbTarget<'_> {
    fn fstat(&mut self, fd: u32) -> HostIoResult<HostIoStat, Self> {
        let file = self
            .files
            .get(&fd)
            .ok_or(HostIoError::Errno(HostIoErrno::EBADF))?;
        let size = file.len()?;
        Ok(HostIoStat {
            st_dev: 0,
            st_ino: 0,
            st_mode: HostIoOpenMode::S_IFREG
                | HostIoOpenMode::S_IRUSR
                | HostIoOpenMode::S_IRGRP
                | HostIoOpenMode::S_IROTH,
            st_nlink: 1,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_size: size,
            st_blksize: 4096,
            st_blocks: size.div_ceil(512),
            st_atime: 0,
            st_mtime: 0,
            st_ctime: 0,
        })
    }
}

/// There is one filesystem: the module images. gdb selects it by process
/// before opening the program file.
impl HostIoSetfs for GdbTarget<'_> {
    fn setfs(&mut self, _fs: FsKind) -> HostIoResult<(), Self> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
