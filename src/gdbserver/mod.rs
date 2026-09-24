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

mod access;
mod breakpoints;
mod connection;
mod host_io;
mod layout;
mod metadata;
mod monitor;
mod run_control;

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::TcpListener;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

use gdbstub::arch::{Arch as GdbArch, RegId, Registers};
use gdbstub::common::Tid;
use gdbstub::stub::state_machine::GdbStubStateMachine;
use gdbstub::stub::{DisconnectReason, GdbStub};
use gdbstub::target::Target;
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::breakpoints::{BreakpointsOps, WatchKind};
use gdbstub::target::ext::exec_file::ExecFileOps;
use gdbstub::target::ext::host_io::HostIoOps;
use gdbstub::target::ext::libraries::LibrariesOps;
use gdbstub::target::ext::memory_map::MemoryMapOps;
use gdbstub::target::ext::monitor_cmd::MonitorCmdOps;
use gdbstub::target::ext::section_offsets::SectionOffsetsOps;
use gdbstub::target::ext::target_description_xml_override::TargetDescriptionXmlOverrideOps;

use crate::TargetSpec;
use crate::dbg_backend::DebugCapability;
use crate::error::{Error, Result};
use crate::gdb::{append_packet, trace_packet};
use crate::repl::{ReplStore, supports_capability};
use crate::session::{ContinueOutcome, Session};
use crate::termination;
use crate::types::Arch;

use connection::{Client, connection_error};
use host_io::OpenFile;
use layout::Layout;
use run_control::Wait;

/// Where the server listens unless told otherwise. QEMU's own stub owns
/// `:1234`, which the `gdb` backend may be using, so this takes gdbserver's
/// conventional port instead.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:2345";
/// How long a blocking read or accept waits before checking for a
/// termination signal and servicing a halted target's transport.
const IDLE_POLL: Duration = Duration::from_millis(50);
/// Largest packet the client may send or receive. Memory reads are chunked
/// to fit, so this bounds round trips for large reads.
const PACKET_SIZE: usize = 0x4000;
/// The thread-list transfer gdbstub does not implement, answered here.
const THREADS_XFER: &[u8] = b"qXfer:threads:read::";

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
                                    append_packet(&mut packet, step);
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

#[cfg(test)]
mod tests {
    use super::current_thread_step;

    /// A step with no thread id (Binary Ninja's `vCont;s`) becomes a plain
    /// current-thread step instead of a protocol error that drops the client;
    /// a step naming its thread (IDA, gdb) must reach gdbstub unchanged.
    #[test]
    fn only_thread_less_steps_become_current_thread_steps() {
        assert_eq!(current_thread_step(b"vCont;s"), Some(&b"s"[..]));
        assert_eq!(current_thread_step(b"vCont;S05"), Some(&b"S05"[..]));
        assert_eq!(current_thread_step(b"vCont;s;c"), Some(&b"s"[..]));
        assert_eq!(current_thread_step(b"vCont;s:p1.3;c"), None);
        assert_eq!(current_thread_step(b"vCont;c"), None);
        assert_eq!(current_thread_step(b"vCont;S"), None);
    }
}
