use std::borrow::Cow;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use gdb_remote::Request;
use gdb_remote::features::{self, Feature, Support};
use gdb_remote::frame::{self, Corruption, Decoder, Frame, Kind};
use gdb_remote::hex;
use gdb_remote::reply::{
    ErrorCode, ResumeActions, Status, ThreadList, XferChunk, parse_current_thread,
};
use gdb_remote::request::{Action, Breakpoint, BreakpointType, ThreadAction, ThreadOp, XferRead};
use gdb_remote::stop::{Reason, StopReply};
use gdb_remote::target::{Description, g_layout};
use gdb_remote::thread::{Id, ThreadId};

use crate::arch::{
    Arch, Family, HwBreakpointAccess, RegisterInfo, RegisterMap, registers::push_synonyms,
};
use crate::backend::dbg_backend::{
    DebugBackend, PciConfigAddress, STEP_UNDER_WINDOWS_HYPERVISOR, StopEvent,
};
use crate::backend::phys::HaltClock;
use crate::base::env::Trace;
use crate::base::error::{Error, Result};

/// Bytes of a packet shown per trace line.
const TRACE_BYTES: usize = 200;

/// When the packet trace started: [`trace_packet`] stamps each line with the
/// time since.
static TRACE_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// What `frames`, the start of what the stub sent, say of a stop reply:
/// `Some(true)` at a stop reply past acks and console output (`O`),
/// `Some(false)` at any other packet, `None` when they end before either.
fn stop_reply_among(frames: impl IntoIterator<Item = Frame>) -> Option<bool> {
    for frame in frames {
        let body = match frame {
            Frame::Packet(body) => body,
            // A stop reply garbled on the way is still one: the wait that
            // reads it asks for it again.
            Frame::Corrupt(Corruption::Checksum {
                kind: Kind::Packet,
                body,
                ..
            }) => body,
            Frame::Corrupt(Corruption::Digits | Corruption::RunLength | Corruption::TooLong) => {
                return Some(false);
            }
            Frame::Ack
            | Frame::Nack
            | Frame::Interrupt
            | Frame::Notification(_)
            | Frame::Corrupt(Corruption::Checksum {
                kind: Kind::Notification,
                ..
            }) => continue,
        };
        match StopReply::parse(&body) {
            Ok(StopReply::Output(_)) => {}
            Ok(_) => return Some(true),
            Err(_) => return Some(false),
        }
    }
    None
}

/// Trace one packet on stderr, under [`Trace::Gdb`]: every RSP packet on
/// both of ntoseye's GDB connections, timestamped on one clock. `stub` lines
/// are the `gdb` backend's conversation with the hypervisor's stub; `client`
/// lines are the GDB server's with its client. One capture lines a client's
/// request up against what the backend did to answer it. `direction` is
/// `->` for bytes ntoseye sends to `peer` and `<-` for bytes it receives.
pub fn trace_packet(peer: &str, direction: &str, bytes: &[u8]) {
    if !Trace::Gdb.enabled() {
        return;
    }
    let shown = trace_text(bytes);
    let elapsed = TRACE_START.elapsed().as_secs_f64();
    eprintln!("gdb {elapsed:9.3} {peer:<6} {direction} {shown}");
}

/// `bytes` as a trace line shows them: printable ASCII as is, anything else
/// as `\xNN`, and a packet past [`TRACE_BYTES`] cut there and its length
/// given.
pub fn trace_text(bytes: &[u8]) -> String {
    let mut shown = String::new();
    for &byte in bytes.iter().take(TRACE_BYTES) {
        match byte {
            b' '..=b'~' => shown.push(byte as char),
            _ => shown.push_str(&format!("\\x{byte:02x}")),
        }
    }
    if bytes.len() > TRACE_BYTES {
        shown.push_str(&format!("... ({} bytes)", bytes.len()));
    }
    shown
}

#[derive(Debug, Default, Clone)]
struct StubFeatures {
    no_ack_mode: bool,
    qxfer_features_read: bool,
    /// The `vCont` actions the stub supports (`vCont?`): `s` steps one
    /// thread, `c` continues the threads named.
    actions: ResumeActions,
}

#[derive(Debug)]
enum AckResult {
    Ack,
    Nack,
    ReplyStarted,
}

/// The signal a stub reports for a pause the host asked for: QEMU's for an
/// interrupt.
const SIGINT: u8 = 0x02;

/// The stop event a stop reply describes: the stopped thread, the address
/// that fired a watchpoint, and whether the host asked for the stop.
///
/// The signal byte is deliberately not turned into an exception code. A stub
/// reports `SIGTRAP` for a breakpoint, a watchpoint, and a completed step
/// alike, so inventing `STATUS_BREAKPOINT` from it would drive the shared
/// `int3` rewind over stops that never executed one.
///
/// The signal only separates a requested pause (`SIGINT`, 0x02, which QEMU
/// reports for an interrupt) from a trap the guest took (`SIGTRAP`, 0x05).
///
/// `S` carries only the signal, and `W`/`X`/`w`/`N` do not describe a
/// stopped thread, so they describe nothing else.
fn stop_event(reply: &[u8]) -> StopEvent {
    let (thread, watchpoint_address, break_in) = match StopReply::parse(reply) {
        Ok(StopReply::Signal(signalled)) => (
            signalled.thread,
            match signalled.reason {
                // The three watch kinds differ only in which access trapped,
                // which the breakpoint already records.
                Some(
                    Reason::Watch(address)
                    | Reason::ReadWatch(address)
                    | Reason::AccessWatch(address),
                ) => Some(address),
                _ => None,
            },
            signalled.signal == SIGINT,
        ),
        _ => (None, None, false),
    };
    StopEvent {
        thread_id: thread.as_ref().map(thread_name),
        watchpoint_address,
        exception_code: None,
        first_chance: None,
        exception_address: None,
        program_counter: None,
        is_bugcheck: false,
        bugcheck: None,
        target_reloaded: false,
        target_kernel_base_hint: None,
        modules_changed: false,
        module_event: None,
        assisted_breakin: false,
        break_in,
        process_exit: None,
    }
}

/// The thread a stop reply names.
fn stopped_thread(reply: &[u8]) -> Option<ThreadId> {
    match StopReply::parse(reply) {
        Ok(StopReply::Signal(signalled)) => signalled.thread,
        _ => None,
    }
}

/// The name a stub's thread has outside this client: its id as the
/// protocol writes it (`p1.2`), as the KD backend names its processors.
fn thread_name(thread: &ThreadId) -> String {
    let mut name = Vec::new();
    thread.write(&mut name);
    String::from_utf8_lossy(&name).into_owned()
}

/// The thread a name from [`thread_name`] gives.
fn parse_thread(name: &str) -> Result<ThreadId> {
    ThreadId::parse(name.as_bytes())
        .map_err(|_| Error::InvalidArgument(format!("`{name}` is not a GDB stub's thread id")))
}

/// A reply as text, for an error message.
fn reply_text(reply: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(reply)
}

/// Whether a reply is an error (`E<nn>` or `E.<text>`).
fn is_error(reply: &[u8]) -> bool {
    matches!(Status::parse(reply), Some(Status::Error(_)))
}

/// The bytes of a `g` or `p` reply. A byte the stub cannot read (`xx`) is
/// an error: nothing here can stand in for it.
fn register_bytes(reply: &[u8]) -> Result<Vec<u8>> {
    let mut value = Vec::new();
    hex::read_register(&mut value, reply)
        .map_err(|error| Error::Rsp(format!("{error} from stub: {}", reply_text(reply))))?;
    value
        .into_iter()
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| {
            Error::Rsp(format!(
                "the stub has no value for part of a register: {}",
                reply_text(reply)
            ))
        })
}

/// The architecture a target description declares the stub is debugging.
fn description_arch(description: &Description) -> Result<Arch> {
    let Some(architecture) = description.architecture.as_deref() else {
        return Err(Error::UnsupportedArchitecture(
            "the stub's target description declares no architecture".into(),
        ));
    };
    Arch::from_gdb_architecture(architecture).ok_or_else(|| {
        Error::UnsupportedArchitecture(format!(
            "{architecture}; ntoseye debugs AMD64 and ARM64 Windows"
        ))
    })
}

/// The register map a target description lays out: each register at its
/// number's place in the `g` packet, which packs registers in ascending
/// number whatever order the XML lists them in.
fn description_registers(description: &Description) -> Result<RegisterMap> {
    let numbered = description.registers().ok_or_else(|| {
        Error::Rsp("the stub's target description includes a document not read".into())
    })?;
    let mut registers = Vec::with_capacity(numbered.len());
    for slot in g_layout(&numbered) {
        let register = slot.register.register;
        if register.bitsize == 0 || !register.bitsize.is_multiple_of(8) {
            return Err(Error::Rsp(format!(
                "invalid register bitsize '{}' in target XML",
                register.bitsize
            )));
        }
        let regnum = usize::try_from(slot.register.number).map_err(|_| {
            Error::Rsp(format!(
                "register regnum '{}' overflows in target XML",
                slot.register.number
            ))
        })?;
        registers.push(RegisterInfo {
            name: register.name.clone(),
            offset: slot.offset,
            size: slot.size,
            regnum,
        });
    }
    Ok(RegisterMap::from_registers(registers))
}

/// System registers ntoseye needs, spelled the way it spells them elsewhere.
/// `cr3` is the kernel page-table root on both architectures, so the ARM64
/// map answers it with TTBR1_EL1 exactly as KD's does.
const ARM64_SYSTEM_REGISTERS: [(&str, &str); 4] = [
    ("cr3", "TTBR1_EL1"),
    ("ttbr0", "TTBR0_EL1"),
    ("esr", "ESR_EL1"),
    ("far", "FAR_EL1"),
];

/// A register the stub keeps out of its `g` packet. A target description
/// splits into features, and a stub answers `g` with the core one alone, so
/// everything past it has to be asked for one register at a time.
#[derive(Debug, Clone, Copy)]
struct ExtraRegister {
    regnum: usize,
}

/// A hardware breakpoint as the stub knows it. RSP addresses one by type,
/// address, and length rather than by slot, so removing it means replaying
/// exactly what installed it.
#[derive(Debug, Clone, Copy)]
struct HardwareSite {
    ty: BreakpointType,
    addr: u64,
    len: u8,
}

impl HardwareSite {
    /// The breakpoint as `Z` and `z` name it.
    fn breakpoint(self) -> Breakpoint<'static> {
        Breakpoint {
            ty: self.ty,
            address: self.addr,
            kind: u64::from(self.len),
            rest: &[],
        }
    }
}

/// The `Z`/`z` breakpoint type for an access mode. `Z3` (read-only watch)
/// is never used: the x86 debug registers cannot express one, so a read
/// watch is the read/write `Z4`.
fn hardware_breakpoint_type(access: HwBreakpointAccess) -> BreakpointType {
    match access {
        HwBreakpointAccess::Execute => BreakpointType::Hardware,
        HwBreakpointAccess::Write => BreakpointType::WriteWatch,
        HwBreakpointAccess::ReadWrite => BreakpointType::AccessWatch,
    }
}

pub struct GdbClient {
    /// The connection to the stub. The packet parser takes replies a byte at
    /// a time; buffered, a reply costs one `recv` rather than one per byte,
    /// which was most of what a `g` reply (over a kilobyte) took.
    stream: BufReader<TcpStream>,
    features: StubFeatures,
    /// Frames what the stub sends; a read that times out can leave it
    /// inside a packet.
    decoder: Decoder,
    /// A reply read while waiting for the ack of its request, which the
    /// stub sent without one.
    unread: Option<Frame>,
    no_ack_mode: bool,
    arch: Arch,
    register_map: RegisterMap,
    /// Whether the target runs, shared with the host memory this client's
    /// session reads, which memoizes guest lists per halt.
    halts: Arc<HaltClock>,
    hardware_sites: Vec<Option<HardwareSite>>,
    extra_registers: Vec<ExtraRegister>,
    /// The stop reply that left the target halted: the one to the initial
    /// `?`, then each stop read since, for the stopped thread. Asking again
    /// is not an option: QEMU treats `?` as a debugger's initial connect and
    /// removes every breakpoint, including ones this client still counts as
    /// installed.
    last_stop: Vec<u8>,
    /// `last_stop` is kept for the next wait (see
    /// [`DebugBackend::keep_last_stop`]); resumes until then send nothing.
    kept_stop: bool,
    /// The thread the last `Hc` selected; `None` after a continue reset it
    /// to all threads.
    control_thread: Option<ThreadId>,
    /// The NT kernel's page-table root, for planting breakpoints while the
    /// halted vCPU is in another address space; see
    /// [`GdbClient::software_breakpoint_packet`].
    kernel_dtb: Option<u64>,
    /// Windows runs nested under its own hypervisor, so single steps are
    /// refused; see [`STEP_UNDER_WINDOWS_HYPERVISOR`].
    windows_hypervisor: bool,
    halt_cache: HaltCache,
    /// The thread [`HaltCache::thread`] held when the target was last
    /// resumed, for the halt that resume ends (see [`Self::note_halt`]).
    resumed_selected: Option<ThreadId>,
}

/// What the stub has answered during one halt, so asking again costs no
/// round trip. Every resume starts a new halt epoch and drops it: the stub
/// then picks its own thread, and the vCPUs have moved. Only the selection
/// can outlive a resume, when the stop names the thread selected (see
/// [`GdbClient::note_halt`]).
#[derive(Default)]
struct HaltCache {
    epoch: Option<u64>,
    /// The thread `Hg` and `Hc` both select, when this client selected it.
    thread: Option<ThreadId>,
    /// The register file [`GdbClient::read_registers`] returned for
    /// `thread`; dropped by any register write.
    registers: Option<Vec<u8>>,
}

/// What a wait on an already halted target reports: a stop with no fields,
/// which is what the stub's `?` answered before this client stopped asking
/// (see [`GdbClient::last_stop`]). No fields, so a stop the caller already
/// handled is not handled again.
const HALTED_NO_NEW_STOP: &[u8] = b"S05";

/// Why a request cannot be served right now, for [`Error::TargetRunning`].
const GDB_STUB_NEEDS_HALT: &str = "the GDB stub serves no requests while the target runs.";

/// Bytes per `m` packet in physical-memory mode; the reply is twice that in
/// hex, inside QEMU's 4 KiB packet buffer.
const PHYSICAL_READ_CHUNK: usize = 0x400;

/// The read timeout of a wait asked not to wait: a socket refuses zero.
const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

fn gdb_connect_error(addr: &str, err: io::Error) -> Error {
    let message = match err.kind() {
        io::ErrorKind::ConnectionRefused => format!(
            "GDB stub at '{addr}' is not accepting connections.\n\
             Start the VM with QEMU gdbstub enabled (-s -S), or pass --connect <addr> if the stub listens elsewhere.\n\
             For supported hypervisors, run `ntoseye configure` and choose GDB.\n\
             If this guest is configured for Windows KD instead, use the default KD backend."
        ),
        io::ErrorKind::TimedOut => format!(
            "timed out connecting to GDB stub at '{addr}'.\n\
             Check that the VM is running with QEMU gdbstub enabled (-s -S), or pass --connect <addr> if the stub listens elsewhere."
        ),
        _ => format!(
            "failed to connect to GDB stub at '{addr}': {err}.\n\
             Start the VM with QEMU gdbstub enabled (-s -S), or pass --connect <addr> if the stub listens elsewhere."
        ),
    };
    Error::DebugInfo(message)
}

impl GdbClient {
    pub fn connect(addr: &str, halts: Arc<HaltClock>) -> Result<Self> {
        let stream = TcpStream::connect(addr).map_err(|err| gdb_connect_error(addr, err))?;
        // Every exchange is a small request, a one-byte ack, and a small
        // reply; with Nagle on, each ack waits out the peer's delayed ACK
        // (~40 ms) before it leaves.
        stream.set_nodelay(true)?;

        let mut client = GdbClient {
            stream: BufReader::new(stream),
            features: StubFeatures::default(),
            decoder: Decoder::new(),
            unread: None,
            no_ack_mode: false,
            // Replaced from the target description below, before anything
            // reads it: the handshake packets before it are the same for
            // every architecture.
            arch: Arch::Amd64,
            register_map: RegisterMap::default(),
            // Resuming the VM from outside (a hypervisor GUI) goes unseen here.
            halts,
            hardware_sites: Vec::new(),
            extra_registers: Vec::new(),
            last_stop: Vec::new(),
            kept_stop: false,
            control_thread: None,
            kernel_dtb: None,
            windows_hypervisor: false,
            halt_cache: HaltCache::default(),
            resumed_selected: None,
        };

        client.force_stop_and_resync()?;

        let ours = ["multiprocess", "swbreak", "qRelocInsn", "vContSupported"]
            .into_iter()
            .map(|name| Feature {
                name,
                support: Support::Yes,
            })
            .collect();
        let reply = client.send_packet(&Request::Supported(ours))?;
        // A reply that lists no features (empty, an error) offers none.
        let supported = features::parse_list(&reply).unwrap_or_default();
        client.features.no_ack_mode = features::supports(&supported, "QStartNoAckMode");
        client.features.qxfer_features_read = features::supports(&supported, "qXfer:features:read");
        let actions = client.send_packet(&Request::SupportedActions)?;
        client.features.actions = ResumeActions::parse(&actions).unwrap_or_default();

        if client.features.no_ack_mode {
            let _ = client.enable_no_ack_mode();
        }

        // The one `?` this client sends: nothing is planted yet for QEMU to
        // clear, and the reply is the halt reason until the next stop.
        client.last_stop = client.send_packet(&Request::HaltReason)?;

        let description = client.fetch_target_description()?;
        client.arch = description_arch(&description)?;
        client.register_map = client.build_register_map(&description_registers(&description)?)?;

        Ok(client)
    }

    fn force_stop_and_resync(&mut self) -> Result<()> {
        self.stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(100)))?;
        self.decoder = Decoder::new();
        self.unread = None;

        trace_packet("stub", "->", &[frame::INTERRUPT]);
        self.write_bytes(&[frame::INTERRUPT])?;

        while self.read_response_packet().is_ok() {}

        self.stream.get_ref().set_read_timeout(None)?;
        self.decoder = Decoder::new();
        self.unread = None;

        self.halts.set_running(false);

        Ok(())
    }

    /// Send a request and read its reply.
    ///
    /// A stub in all-stop mode services nothing but an interrupt while the
    /// target runs, so a request sent then would block on a reply that is
    /// never coming. Refusing it keeps a running target from wedging the
    /// debugger; `Self::interrupt` is the way through, and it writes the
    /// break byte directly rather than through here.
    pub fn send_packet(&mut self, request: &Request<'_>) -> Result<Vec<u8>> {
        if self.halts.is_running() {
            return Err(Error::TargetRunning(GDB_STUB_NEEDS_HALT));
        }
        self.send_raw_command(request)?;
        self.read_response_packet()
    }

    fn enable_no_ack_mode(&mut self) -> Result<()> {
        let response = self.send_packet(&Request::StartNoAckMode)?;
        if Status::parse(&response) == Some(Status::Ok) {
            self.no_ack_mode = true;
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }

    /// Send `request` as one packet, resending it until the stub
    /// acknowledges it unless no-ack mode is on.
    fn send_raw_command(&mut self, request: &Request<'_>) -> Result<()> {
        let mut body = Vec::new();
        request.write(&mut body);
        let mut packet = Vec::new();
        frame::write_packet(&mut packet, &body);
        trace_packet("stub", "->", &packet);
        loop {
            self.write_bytes(&packet)?;

            if self.no_ack_mode {
                return Ok(());
            }

            match self.wait_for_ack()? {
                AckResult::Ack => return Ok(()),
                AckResult::Nack => continue,
                AckResult::ReplyStarted => return Ok(()),
            }
        }
    }

    /// Write `bytes` to the stub.
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let stream = self.stream.get_mut();
        stream.write_all(bytes)?;
        stream.flush()?;
        Ok(())
    }

    fn wait_for_ack(&mut self) -> Result<AckResult> {
        loop {
            match self.read_frame()? {
                Frame::Ack => return Ok(AckResult::Ack),
                Frame::Nack => return Ok(AckResult::Nack),
                reply @ (Frame::Packet(_) | Frame::Corrupt(_)) => {
                    self.unread = Some(reply);
                    return Ok(AckResult::ReplyStarted);
                }
                Frame::Interrupt | Frame::Notification(_) => {}
            }
        }
    }

    /// The next frame from the stub. Bytes past it stay buffered, for
    /// [`DebugBackend::has_pending_stop`] to look at.
    fn read_frame(&mut self) -> Result<Frame> {
        if let Some(frame) = self.unread.take() {
            return Ok(frame);
        }
        loop {
            let buffered = match self.stream.fill_buf() {
                Ok(buffered) => buffered,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if buffered.is_empty() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            let mut used = 0;
            let mut frame = None;
            for &byte in buffered {
                used += 1;
                frame = self.decoder.push(byte);
                if frame.is_some() {
                    break;
                }
            }
            self.stream.consume(used);
            if let Some(frame) = frame {
                return Ok(frame);
            }
        }
    }

    fn read_response_packet(&mut self) -> Result<Vec<u8>> {
        loop {
            let body = match self.read_frame()? {
                Frame::Packet(body) => body,
                Frame::Corrupt(Corruption::Checksum {
                    kind: Kind::Packet,
                    sent,
                    computed,
                    ..
                }) => {
                    if self.no_ack_mode {
                        return Err(Error::Rsp(format!(
                            "bad checksum from stub: expected {sent:02x}, got {computed:02x}"
                        )));
                    }
                    self.write_bytes(&[frame::NACK])?;
                    continue;
                }
                Frame::Corrupt(Corruption::Digits) => {
                    return Err(Error::Rsp("invalid checksum digits from stub".into()));
                }
                Frame::Corrupt(Corruption::RunLength) => {
                    return Err(Error::Rsp("invalid run-length packet data".into()));
                }
                Frame::Corrupt(Corruption::TooLong) => {
                    return Err(Error::Rsp(format!(
                        "packet from stub longer than {} bytes",
                        frame::DEFAULT_LIMIT
                    )));
                }
                Frame::Ack
                | Frame::Nack
                | Frame::Interrupt
                | Frame::Notification(_)
                | Frame::Corrupt(Corruption::Checksum {
                    kind: Kind::Notification,
                    ..
                }) => continue,
            };

            if !self.no_ack_mode {
                self.write_bytes(&[frame::ACK])?;
            }

            trace_packet("stub", "<-", &body);
            return Ok(body);
        }
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        let response = self.software_breakpoint_packet(Request::InsertBreakpoint, addr)?;
        match Status::parse(&response) {
            Some(Status::Ok) => Ok(()),
            Some(Status::Unsupported) => Err(Error::NotSupported),
            Some(Status::Error(_)) | None => Err(Error::Rsp(format!(
                "failed to set breakpoint at {:#x}: {}",
                addr,
                reply_text(&response)
            ))),
        }
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        let response = self.software_breakpoint_packet(Request::RemoveBreakpoint, addr)?;
        match Status::parse(&response) {
            Some(Status::Ok) => Ok(()),
            Some(Status::Unsupported) => Err(Error::NotSupported),
            Some(Status::Error(_)) | None => Err(Error::Rsp(format!(
                "failed to remove breakpoint at {:#x}: {}",
                addr,
                reply_text(&response)
            ))),
        }
    }

    /// Send `Z0`/`z0` (`op`) for a kernel code site, reaching it through the
    /// NT kernel's page tables when the halted vCPU's own tables miss it.
    ///
    /// QEMU plants and lifts a software breakpoint by reading and writing the
    /// site through the control vCPU's *current* CR3, and answers `E22` when
    /// that translation fails. Under VBS an idle vCPU halts inside the
    /// Windows hypervisor (or in VTL1), whose tables do not map NT, so the
    /// same packet succeeded or failed depending on where the vCPU happened
    /// to stop. The stub keys the site by virtual address alone, which is
    /// what a later `#BP` in NT is matched against, and its software
    /// breakpoints are global to the VM. So the packet is first retried
    /// through another vCPU that halted in NT, which writes no register;
    /// only when every vCPU is outside NT does it borrow the kernel root.
    fn software_breakpoint_packet(
        &mut self,
        op: fn(Breakpoint<'static>) -> Request<'static>,
        addr: u64,
    ) -> Result<Vec<u8>> {
        let packet = op(Breakpoint {
            ty: BreakpointType::Software,
            address: addr,
            kind: u64::from(self.arch.breakpoint_size()),
            rest: &[],
        });
        let response = self.send_packet(&packet)?;
        let borrows_kernel_root = self.arch.family() == Family::X86;
        if !is_error(&response)
            || !borrows_kernel_root
            || addr < self.arch.paging().system_range_start()
        {
            return Ok(response);
        }
        if let Some(response) = self.through_another_vcpu(&packet)? {
            return Ok(response);
        }
        let (Some(root), Some(regnum)) = (self.kernel_dtb, self.register_number("cr3")) else {
            return Ok(response);
        };
        self.with_cr3(regnum, root, |client| client.send_packet(&packet))
    }

    /// Send `packet` with each other vCPU as the control vCPU until one's
    /// page tables serve it, then make the selected vCPU the control vCPU
    /// again (a plain `s` steps the control vCPU). `None` when none did.
    fn through_another_vcpu(&mut self, packet: &Request<'_>) -> Result<Option<Vec<u8>>> {
        self.forget_halt_cache();
        let Some(selected) = self
            .control_thread
            .or_else(|| stopped_thread(&self.last_stop))
        else {
            return Ok(None);
        };
        let Ok(threads) = self.thread_list() else {
            return Ok(None);
        };
        let mut planted = None;
        for thread in threads.into_iter().filter(|thread| *thread != selected) {
            let select = Request::SetThread {
                op: ThreadOp::Resume,
                thread,
            };
            if Status::parse(&self.send_packet(&select)?) != Some(Status::Ok) {
                continue;
            }
            let response = self.send_packet(packet)?;
            if !is_error(&response) {
                planted = Some(response);
                break;
            }
        }
        let restored = self.send_packet(&Request::SetThread {
            op: ThreadOp::Resume,
            thread: selected,
        })?;
        if Status::parse(&restored) != Some(Status::Ok) {
            return Err(Error::Rsp(format!(
                "failed to reselect vCPU {} after planting a breakpoint through another vCPU: {}",
                thread_name(&selected),
                reply_text(&restored)
            )));
        }
        Ok(planted)
    }

    /// Run `op` with the selected vCPU's CR3 temporarily set to `root`, as
    /// the stub's own debugger memory walk sees it, and put it back.
    fn with_cr3<T>(
        &mut self,
        regnum: usize,
        root: u64,
        op: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        // Breakpoints act on the control vCPU and `P` on the general one;
        // pin both to the vCPU the debugger has selected.
        if let Some(thread) = self
            .control_thread
            .or_else(|| stopped_thread(&self.last_stop))
        {
            self.set_current_thread(thread)?;
        }
        // `P`/`p` use QEMU's copy of the vCPU as-is; `g` is what pulls it in
        // from the hypervisor and marks it for write-back on resume, so the
        // restored value is the one the vCPU resumes with.
        let synced = self.send_packet(&Request::ReadRegisters)?;
        if is_error(&synced) {
            return Err(Error::Rsp(format!(
                "failed to read registers: {}",
                reply_text(&synced)
            )));
        }
        let original = self.read_register_bytes(regnum)?;
        let mut borrowed = original.clone();
        let width = borrowed.len().min(8);
        borrowed[..width].copy_from_slice(&root.to_le_bytes()[..width]);
        self.write_register_bytes(regnum, &borrowed)?;
        let result = op(self);
        if let Err(error) = self.write_register_bytes(regnum, &original) {
            return Err(Error::Rsp(format!(
                "failed to restore CR3 after planting a breakpoint through the kernel's page \
                 tables ({error}); the vCPU would resume in the wrong address space, so do not \
                 resume it"
            )));
        }
        result
    }

    fn register_number(&self, name: &str) -> Option<usize> {
        self.register_map
            .registers()
            .iter()
            .find(|register| register.name == name)
            .map(|register| register.regnum)
    }

    /// This halt's [`HaltCache`]; `None` while the target runs.
    fn halt_cache(&mut self) -> Option<&mut HaltCache> {
        let epoch = self.halts.epoch()?;
        if self.halt_cache.epoch != Some(epoch) {
            self.halt_cache = HaltCache {
                epoch: Some(epoch),
                ..HaltCache::default()
            };
        }
        Some(&mut self.halt_cache)
    }

    /// Drop the [`HaltCache`] before a request that changes what it holds
    /// in a way the halt epoch does not see.
    fn forget_halt_cache(&mut self) {
        self.halt_cache = HaltCache::default();
    }

    /// The thread `Hg` and `Hc` both select in this halt, when this client
    /// selected it (see [`HaltCache::thread`]).
    fn selected_thread(&mut self) -> Option<ThreadId> {
        self.halt_cache().and_then(|cache| cache.thread)
    }

    /// The slot's record, or an error naming the slot a caller invented.
    /// Indexing would panic, and a debugger has no business dying over one.
    fn hardware_slot(&self, slot: usize) -> Result<Option<HardwareSite>> {
        let count = self.hardware_breakpoint_slots();
        if slot >= count {
            return Err(Error::InvalidArgument(format!(
                "hardware breakpoint slot {slot} does not exist; {count} slots are available"
            )));
        }
        Ok(self.hardware_sites.get(slot).copied().flatten())
    }

    fn set_hardware_site(&mut self, slot: usize, site: HardwareSite) -> Result<()> {
        self.clear_hardware_site(slot)?;

        let response = self.send_packet(&Request::InsertBreakpoint(site.breakpoint()))?;
        match Status::parse(&response) {
            Some(Status::Ok) => {
                self.hardware_sites
                    .resize(self.hardware_sites.len().max(slot + 1), None);
                self.hardware_sites[slot] = Some(site);
                Ok(())
            }
            // An empty reply is RSP for "I do not implement this packet".
            Some(Status::Unsupported) => Err(Error::NotSupported),
            Some(Status::Error(ErrorCode::Number(_))) => Err(Error::HardwareBreakpointRefused {
                address: site.addr,
                response: reply_text(&response).into_owned(),
            }),
            Some(Status::Error(ErrorCode::Text(_))) | None => Err(Error::Rsp(format!(
                "unexpected reply to hardware breakpoint at {:#x}: {}",
                site.addr,
                reply_text(&response)
            ))),
        }
    }

    fn clear_hardware_site(&mut self, slot: usize) -> Result<()> {
        let Some(site) = self.hardware_slot(slot)? else {
            return Ok(());
        };

        let response = self.send_packet(&Request::RemoveBreakpoint(site.breakpoint()))?;
        if Status::parse(&response) != Some(Status::Ok) {
            // Leave the slot recorded: the stub still holds it, and naming it
            // again needs the same three values.
            return Err(Error::Rsp(format!(
                "failed to remove the hardware breakpoint at {:#x}: {}",
                site.addr,
                reply_text(&response)
            )));
        }
        self.hardware_sites[slot] = None;
        Ok(())
    }

    /// Read guest-physical memory through the stub rather than the host
    /// mapping, in QEMU's physical-memory mode (`Qqemu.PhyMemMode`): the
    /// stub reads through the machine's address space, so device registers
    /// (the PCI ECAM window) answer as they do to the guest, where the host
    /// mapping holds only RAM.
    fn read_physical_through_stub(&mut self, address: u64, buf: &mut [u8]) -> Result<()> {
        let reply = self.send_packet(&Request::Unknown(b"Qqemu.PhyMemMode:1"))?;
        if Status::parse(&reply) != Some(Status::Ok) {
            return Err(Error::Rsp(format!(
                "the GDB stub has no physical-memory mode (QEMU's Qqemu.PhyMemMode answered \
                 {:?}), which device registers are read through",
                reply_text(&reply)
            )));
        }
        let mut read = || -> Result<()> {
            let mut next = address;
            for chunk in buf.chunks_mut(PHYSICAL_READ_CHUNK) {
                let reply = self.send_packet(&Request::ReadMemory {
                    address: next,
                    length: chunk.len() as u64,
                })?;
                let mut bytes = Vec::with_capacity(chunk.len());
                if Status::parse(&reply).is_some()
                    || hex::read_bytes(&mut bytes, &reply).is_err()
                    || bytes.len() != chunk.len()
                {
                    return Err(Error::Rsp(format!(
                        "failed to read {:#x} physical bytes at {next:#x}: {}",
                        chunk.len(),
                        reply_text(&reply)
                    )));
                }
                chunk.copy_from_slice(&bytes);
                next += chunk.len() as u64;
            }
            Ok(())
        };
        let result = read();
        let restored = self.send_packet(&Request::Unknown(b"Qqemu.PhyMemMode:0"))?;
        if Status::parse(&restored) != Some(Status::Ok) {
            return Err(Error::Rsp(format!(
                "failed to leave the GDB stub's physical-memory mode: {}",
                reply_text(&restored)
            )));
        }
        result
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        if let Some(registers) = self.halt_cache().and_then(|cache| cache.registers.clone()) {
            return Ok(registers);
        }
        let response = self.send_packet(&Request::ReadRegisters)?;

        if is_error(&response) {
            return Err(Error::Rsp(format!(
                "failed to read registers: {}",
                reply_text(&response)
            )));
        }

        let mut bytes = register_bytes(&response)?;
        for index in 0..self.extra_registers.len() {
            let regnum = self.extra_registers[index].regnum;
            let value = self.read_one_register(regnum)?;
            bytes.extend_from_slice(&value);
        }
        if let Some(cache) = self.halt_cache() {
            cache.registers = Some(bytes.clone());
        }
        Ok(bytes)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        if let Some(cache) = self.halt_cache() {
            cache.registers = None;
        }
        // `G` takes back exactly what `g` gave. The system registers appended
        // behind it are not part of that reply, and the stub serves them
        // read-only anyway.
        let data = &data[..data.len().saturating_sub(self.extra_registers.len() * 8)];
        let response = self.send_packet(&Request::WriteRegisters(data.to_vec()))?;

        if Status::parse(&response) == Some(Status::Ok) {
            Ok(())
        } else {
            Err(Error::Rsp(format!(
                "failed to write registers: {}",
                reply_text(&response)
            )))
        }
    }

    fn send_command_no_reply(&mut self, request: &Request<'_>) -> Result<()> {
        self.send_raw_command(request)
    }

    fn continue_execution(&mut self) -> Result<()> {
        if self.kept_stop {
            self.halts.set_running(true);
            return Ok(());
        }
        self.resumed_selected = None;
        self.forget_halt_cache();
        let _ = self.send_packet(&Request::SetThread {
            op: ThreadOp::Resume,
            thread: ThreadId::thread(Id::All),
        })?;
        self.control_thread = None;
        self.send_command_no_reply(&Request::Continue(None))?;
        self.halts.set_running(true);
        Ok(())
    }

    /// Single-step the selected thread with every other one held. A plain
    /// `s` resumes all of QEMU's vCPUs (only the selected one steps), so
    /// another vCPU's breakpoint hit could be reported as the step.
    fn step(&mut self) -> Result<()> {
        if self.windows_hypervisor {
            return Err(Error::DebugInfo(STEP_UNDER_WINDOWS_HYPERVISOR.to_string()));
        }
        if self.kept_stop {
            self.halts.set_running(true);
            return Ok(());
        }
        self.resumed_selected = self.selected_thread();
        self.forget_halt_cache();
        match self.control_thread {
            Some(thread) if self.features.actions.supports(Action::Step) => {
                self.send_command_no_reply(&Request::Resume(vec![ThreadAction {
                    action: Action::Step,
                    thread: Some(thread),
                }]))?;
            }
            _ => self.send_command_no_reply(&Request::Step(None))?,
        }
        self.halts.set_running(true);
        Ok(())
    }

    /// Resume the selected thread alone (see [`Self::continue_threads`]).
    fn continue_current_thread(&mut self) -> Result<()> {
        let Some(thread) = self.control_thread else {
            return Err(Error::DebugInfo(
                "no vCPU is selected to resume on its own".to_string(),
            ));
        };
        self.continue_threads(&[thread])
    }

    /// Resume `threads` alone; QEMU leaves every vCPU a `vCont` names no
    /// action for stopped.
    fn continue_threads(&mut self, threads: &[ThreadId]) -> Result<()> {
        if !self.features.actions.supports(Action::Continue) {
            return Err(Error::NotSupported);
        }
        if threads.is_empty() {
            return Err(Error::DebugInfo("no vCPU is named to resume".to_string()));
        }
        if self.kept_stop {
            self.halts.set_running(true);
            return Ok(());
        }
        self.resumed_selected = self.selected_thread();
        self.forget_halt_cache();
        let actions = threads
            .iter()
            .map(|&thread| ThreadAction {
                action: Action::Continue,
                thread: Some(thread),
            })
            .collect();
        self.send_command_no_reply(&Request::Resume(actions))?;
        self.halts.set_running(true);
        Ok(())
    }

    fn wait_for_stop(&mut self) -> Result<Vec<u8>> {
        if self.kept_stop {
            return Ok(self.report_kept_stop());
        }
        if !self.halts.is_running() {
            return Ok(HALTED_NO_NEW_STOP.to_vec());
        }

        let response = self.read_stop_reply()?;
        self.note_halt(&response);
        Ok(response)
    }

    fn try_wait_for_stop(&mut self) -> Result<Option<Vec<u8>>> {
        if self.kept_stop {
            return Ok(Some(self.report_kept_stop()));
        }
        if !self.halts.is_running() {
            return Ok(Some(HALTED_NO_NEW_STOP.to_vec()));
        }

        match self.read_stop_reply() {
            Ok(response) => {
                self.note_halt(&response);
                Ok(Some(response))
            }
            Err(Error::Io(ref e))
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn read_stop_reply(&mut self) -> Result<Vec<u8>> {
        loop {
            let response = self.read_response_packet()?;
            let output =
                StopReply::parse(&response).map(|reply| matches!(reply, StopReply::Output(_)));
            match output {
                Ok(false) => {
                    self.last_stop.clone_from(&response);
                    return Ok(response);
                }
                Ok(true) => continue,
                Err(_) if response.starts_with(b"F") => {
                    return Err(Error::Rsp(
                        "remote file I/O packets are unsupported while waiting for stop".into(),
                    ));
                }
                Err(_) if is_error(&response) => {
                    return Err(Error::Rsp(format!(
                        "run-control command failed: {}",
                        reply_text(&response)
                    )));
                }
                Err(_) => {
                    return Err(Error::Rsp(format!(
                        "unexpected packet while waiting for stop: {}",
                        reply_text(&response)
                    )));
                }
            }
        }
    }

    fn interrupt(&mut self) -> Result<Vec<u8>> {
        if self.kept_stop {
            return Ok(self.report_kept_stop());
        }
        if !self.halts.is_running() {
            return Ok(Vec::new());
        }

        trace_packet("stub", "->", &[frame::INTERRUPT]);
        self.write_bytes(&[frame::INTERRUPT])?;

        let stop = self.read_stop_reply()?;

        self.note_halt(&stop);

        Ok(stop)
    }

    /// Begin the halt that `reply`, a stop the stub reported, ended a run
    /// with. In all-stop mode a stub makes the thread a stop names its
    /// current one: GDB records it as the general thread, and reads its
    /// registers next without selecting it, and QEMU makes it the control
    /// thread too. A run of the thread both selected that stops on that
    /// thread leaves both selecting it, whatever the stub does with the
    /// control thread, so the halt starts with it selected, and the next
    /// selection of it, after each instruction run past, costs nothing.
    fn note_halt(&mut self, reply: &[u8]) {
        self.halts.set_running(false);
        let resumed = self.resumed_selected.take();
        if let Some(thread) = resumed.filter(|thread| stopped_thread(reply) == Some(*thread))
            && let Some(cache) = self.halt_cache()
        {
            cache.thread = Some(thread);
        }
    }

    /// The stop kept for this wait (see [`DebugBackend::keep_last_stop`]),
    /// at which the target was left halted.
    fn report_kept_stop(&mut self) -> Vec<u8> {
        self.kept_stop = false;
        self.halts.set_running(false);
        self.last_stop.clone()
    }

    fn thread_list(&mut self) -> Result<Vec<ThreadId>> {
        let mut threads = Vec::new();
        let mut response = self.send_packet(&Request::FirstThreads)?;

        loop {
            if is_error(&response) {
                return Err(Error::Rsp(format!(
                    "failed to enumerate threads: {}",
                    reply_text(&response)
                )));
            }
            let list = ThreadList::parse(&response).map_err(|_| {
                Error::Rsp(format!(
                    "unexpected qThreadInfo response: {}",
                    reply_text(&response)
                ))
            })?;
            threads.extend(list.threads);
            if !list.more {
                break;
            }

            response = self.send_packet(&Request::NextThreads)?;
        }

        Ok(threads)
    }

    fn set_current_thread(&mut self, thread: ThreadId) -> Result<()> {
        if self
            .halt_cache()
            .is_some_and(|cache| cache.thread == Some(thread))
        {
            return Ok(());
        }
        if let Some(cache) = self.halt_cache() {
            cache.thread = None;
            cache.registers = None;
        }
        let resp_g = self.send_packet(&Request::SetThread {
            op: ThreadOp::General,
            thread,
        })?;
        if Status::parse(&resp_g) != Some(Status::Ok) {
            return Err(Error::Rsp(format!(
                "failed to set general thread: {}",
                reply_text(&resp_g)
            )));
        }

        let resp_c = self.send_packet(&Request::SetThread {
            op: ThreadOp::Resume,
            thread,
        })?;
        if Status::parse(&resp_c) != Some(Status::Ok) {
            return Err(Error::Rsp(format!(
                "failed to set control thread: {}",
                reply_text(&resp_c)
            )));
        }
        self.control_thread = Some(thread);
        if let Some(cache) = self.halt_cache() {
            cache.thread = Some(thread);
        }

        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<ThreadId> {
        if let Some(thread) = stopped_thread(&self.last_stop) {
            return Ok(thread);
        }

        // QEMU's initial stop reply names a core, not a thread.
        let response = self.send_packet(&Request::CurrentThread)?;
        if let Ok(thread) = parse_current_thread(&response) {
            return Ok(thread);
        }

        Err(Error::Rsp(
            "could not determine thread from stop reply".into(),
        ))
    }

    /// The stub's full target description, with every `<xi:include>`
    /// resolved.
    fn fetch_target_description(&mut self) -> Result<Description> {
        if !self.features.qxfer_features_read {
            return Err(Error::NotSupported);
        }

        let mut description = self.fetch_feature_file("target.xml")?;
        loop {
            let Some(href) = description.includes().next().map(str::to_string) else {
                break;
            };
            let included = self.fetch_feature_file(&href)?;
            description.include(&href, included);
        }
        Ok(description)
    }

    /// Turn a target description into the register map the debugger reads.
    ///
    /// Only the registers the `g` packet actually carries can be addressed by
    /// offset into its reply, so the description is cut to that length and
    /// the few system registers ntoseye needs are appended behind it, read
    /// individually. Each register also answers to its synonyms.
    fn build_register_map(&mut self, description: &RegisterMap) -> Result<RegisterMap> {
        let g_bytes = GdbClient::read_registers(self)?.len();
        let mut registers: Vec<RegisterInfo> = description
            .registers()
            .iter()
            .filter(|reg| reg.offset + reg.size <= g_bytes)
            .cloned()
            .collect();
        push_synonyms(&mut registers, self.arch.register_synonyms()).map_err(|missing| {
            Error::UnsupportedArchitecture(format!(
                "the stub's {} description has no `{missing}` register",
                self.arch.label()
            ))
        })?;

        match self.arch {
            Arch::Amd64 => {}
            Arch::Arm64 => {
                let mut offset = g_bytes;
                for (name, system_register) in ARM64_SYSTEM_REGISTERS {
                    let Some(source) = description
                        .registers()
                        .iter()
                        .find(|reg| reg.name == system_register)
                    else {
                        return Err(Error::UnsupportedArchitecture(format!(
                            "the stub's AArch64 description has no `{system_register}`, \
                         which ntoseye needs to follow the guest's page tables"
                        )));
                    };
                    self.extra_registers.push(ExtraRegister {
                        regnum: source.regnum,
                    });
                    registers.push(RegisterInfo {
                        name: name.to_string(),
                        offset,
                        size: 8,
                        regnum: source.regnum,
                    });
                    offset += 8;
                }
            }
        }

        Ok(RegisterMap::from_registers(registers))
    }

    /// Read one register by its target-description number.
    fn read_one_register(&mut self, regnum: usize) -> Result<[u8; 8]> {
        let bytes = self.read_register_bytes(regnum)?;
        let mut value = [0u8; 8];
        let len = bytes.len().min(value.len());
        value[..len].copy_from_slice(&bytes[..len]);
        Ok(value)
    }

    /// One register's bytes at the width the stub reports it.
    fn read_register_bytes(&mut self, regnum: usize) -> Result<Vec<u8>> {
        let response = self.send_packet(&Request::ReadRegister(regnum as u64))?;
        if Status::parse(&response).is_some() {
            return Err(Error::Rsp(format!(
                "failed to read register {regnum}: {}",
                reply_text(&response)
            )));
        }
        register_bytes(&response)
    }

    fn write_register_bytes(&mut self, regnum: usize, bytes: &[u8]) -> Result<()> {
        if let Some(cache) = self.halt_cache() {
            cache.registers = None;
        }
        let response = self.send_packet(&Request::WriteRegister {
            number: regnum as u64,
            value: bytes.to_vec(),
        })?;
        if Status::parse(&response) == Some(Status::Ok) {
            Ok(())
        } else {
            Err(Error::Rsp(format!(
                "failed to write register {regnum}: {}",
                reply_text(&response)
            )))
        }
    }

    /// One document of the stub's target description (`target.xml` or one
    /// it includes), read a chunk at a time.
    fn fetch_feature_file(&mut self, annex: &str) -> Result<Description> {
        let mut xml = Vec::new();
        loop {
            let read = XferRead {
                object: "features",
                annex,
                offset: xml.len() as u64,
                length: 0xfff,
            };
            let response = self.send_packet(&Request::XferRead(read))?;

            if Status::parse(&response) == Some(Status::Unsupported) {
                return Err(Error::NotSupported);
            }

            let chunk = XferChunk::parse(&response).map_err(|_| {
                Error::Rsp(format!(
                    "unexpected qXfer response for {annex}: {}",
                    reply_text(&response)
                ))
            })?;
            xml.extend_from_slice(&chunk.data);
            if !chunk.more {
                break;
            }
        }

        let xml = String::from_utf8(xml)
            .map_err(|error| Error::Rsp(format!("the stub's {annex} is not UTF-8: {error}")))?;
        Description::parse(&xml)
            .map_err(|error| Error::Rsp(format!("{error} in the stub's {annex}")))
    }
}

impl DebugBackend for GdbClient {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn name(&self) -> &'static str {
        "gdb"
    }

    fn set_kernel_dtb(&mut self, dtb: u64) {
        self.kernel_dtb = Some(dtb);
    }

    fn set_windows_hypervisor(&mut self, running: bool) {
        self.windows_hypervisor = running;
    }

    fn halts_in_windows_hypervisor(&self) -> bool {
        self.windows_hypervisor
    }

    fn single_step_unsafe(&self) -> bool {
        self.windows_hypervisor
    }

    fn continue_current_thread(&mut self) -> Result<()> {
        GdbClient::continue_current_thread(self)
    }

    fn continue_threads(&mut self, threads: &[String]) -> Result<()> {
        let threads = threads
            .iter()
            .map(|thread| parse_thread(thread))
            .collect::<Result<Vec<_>>>()?;
        GdbClient::continue_threads(self, &threads)
    }

    fn keep_last_stop(&mut self) -> Result<()> {
        self.kept_stop = true;
        Ok(())
    }

    fn stop_kept(&self) -> bool {
        self.kept_stop
    }

    /// A stop kept and never collected leaves the target halted at it, while
    /// a resume since counts it running: drop it, so that leaving the target
    /// running resumes it for real.
    fn prepare_for_exit(&mut self, leave_running: bool) -> Result<()> {
        if std::mem::take(&mut self.kept_stop) {
            self.halts.set_running(false);
        }
        if leave_running && !self.halts.is_running() {
            GdbClient::continue_execution(self)?;
        }
        Ok(())
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        GdbClient::read_registers(self)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        GdbClient::write_registers(self, data)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        GdbClient::set_breakpoint(self, addr)
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        GdbClient::remove_breakpoint(self, addr)
    }

    /// A dead session's `int3` in kernel code survives the next client's
    /// connect under VBS, although QEMU drops its breakpoints then: it most
    /// likely writes the original back through the halted vCPU's page tables,
    /// the Windows hypervisor's, which do not map NT (as `Z0` does; see
    /// [`GdbClient::software_breakpoint_packet`]).
    fn reclaims_abandoned_breakpoints(&self) -> bool {
        false
    }

    /// KVM takes a guest-debug breakpoint's `#DB` itself and reports it here,
    /// whatever VTL the vCPU was running.
    fn hardware_breakpoints_trap_in_host(&self) -> bool {
        true
    }

    /// The stub traps these on every processor without patching guest memory.
    fn supports_watchpoints(&self) -> bool {
        true
    }

    /// RSP sites have no physical slot number. Keep spare records for steps
    /// and new breakpoints; the stub enforces its own limit (none on QEMU TCG).
    fn hardware_breakpoint_slots(&self) -> usize {
        const SPARE_SITES: usize = 4;
        self.hardware_sites.len() + SPARE_SITES
    }

    fn set_hardware_breakpoint(
        &mut self,
        slot: usize,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        let site = HardwareSite {
            ty: hardware_breakpoint_type(access),
            addr,
            len,
        };
        GdbClient::set_hardware_site(self, slot, site)
    }

    fn clear_hardware_breakpoint(&mut self, slot: usize) -> Result<()> {
        GdbClient::clear_hardware_site(self, slot)
    }

    fn continue_execution(&mut self) -> Result<()> {
        GdbClient::continue_execution(self)
    }

    fn step(&mut self) -> Result<()> {
        GdbClient::step(self)
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        let response = GdbClient::interrupt(self)?;
        Ok(stop_event(&response))
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        let response = GdbClient::wait_for_stop(self)?;
        Ok(stop_event(&response))
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        // The session polls once without waiting when its deadline is
        // reached, and a socket refuses a zero read timeout: the shortest
        // one it takes is that poll.
        let timeout = timeout.max(MIN_READ_TIMEOUT);
        self.stream.get_ref().set_read_timeout(Some(timeout))?;
        let result = GdbClient::try_wait_for_stop(self);
        let _ = self.stream.get_ref().set_read_timeout(None);
        Ok(result?.map(|response| stop_event(&response)))
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        Ok(GdbClient::thread_list(self)?
            .iter()
            .map(thread_name)
            .collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        GdbClient::set_current_thread(self, parse_thread(thread_id)?)
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        GdbClient::stopped_thread_id(self).map(|thread| thread_name(&thread))
    }

    fn is_running(&self) -> bool {
        self.halts.is_running()
    }

    /// A stop reply waiting to be read while the target runs. The stub sends
    /// it unprompted and nothing reads it until the next wait, so without
    /// this check a target that hit a breakpoint between waits reads as
    /// running, and a hit that should be absorbed (another process's, a pass
    /// count, a false condition) leaves it frozen until a host waits. Only a
    /// whole stop packet counts, past any console output (`O`) before it: that
    /// is no stop, and draining it with a blocking wait would hang until a
    /// real one.
    fn has_pending_stop(&self) -> bool {
        if !self.halts.is_running() {
            return false;
        }
        // Read on from where the client's own reads stopped, without moving
        // them: the frame they are inside continues in the buffer, and the
        // buffer on the socket.
        let mut decoder = self.decoder.clone();
        let read = self
            .unread
            .iter()
            .cloned()
            .chain(decoder.decode(self.stream.buffer()));
        if let Some(stop) = stop_reply_among(read) {
            return stop;
        }
        let socket = self.stream.get_ref();
        if socket.set_nonblocking(true).is_err() {
            return false;
        }
        let mut head = [0u8; 512];
        let peeked = socket.peek(&mut head);
        let _ = socket.set_nonblocking(false);
        matches!(peeked, Ok(len) if stop_reply_among(decoder.decode(&head[..len])) == Some(true))
    }

    fn supports_pci_config(&self) -> bool {
        true
    }

    /// Through the function's ECAM page, the only configuration mechanism
    /// that is memory the stub can read.
    fn read_pci_config(
        &mut self,
        function: PciConfigAddress,
        offset: u16,
        buf: &mut [u8],
    ) -> Result<()> {
        let Some(page) = function.ecam else {
            return Err(Error::DebugInfo(format!(
                "no ECAM window (ACPI MCFG entry) covers segment {} bus {:#x}; the GDB stub \
                 reaches configuration space only through ECAM",
                function.segment, function.bus
            )));
        };
        self.read_physical_through_stub(page + u64::from(offset), buf)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use gdb_remote::frame::{self, Decoder, Frame};
    use gdb_remote::reply::ResumeActions;
    use gdb_remote::request::ActionKind;
    use gdb_remote::target::Description;
    use gdb_remote::thread::ThreadId;
    use parking_lot::Mutex;

    use super::{
        GdbClient, HaltCache, RegisterMap, StubFeatures, description_arch, description_registers,
        stop_event, stop_reply_among,
    };
    use crate::arch::{Arch, HwBreakpointAccess, RegisterInfo};
    use crate::backend::dbg_backend::DebugBackend;
    use crate::backend::phys::HaltClock;
    use crate::base::error::Error;
    use crate::base::types::VirtAddr;
    use crate::nt::breakpoints::{BreakpointConfig, BreakpointManager};
    use crate::session::{hits::hardware_breakpoint_hit, session_over_memory};

    /// A running target behind a stub that answers the break byte with a stop
    /// on `p01.02`, each packet with `answer(packet, times seen before)`, and
    /// records every packet it is sent.
    fn client_over_stub(answer: fn(&str, usize) -> String) -> (GdbClient, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&received);
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let reply = |stream: &mut TcpStream, body: &str| {
                let mut packet = Vec::new();
                frame::write_packet(&mut packet, body.as_bytes());
                stream.write_all(&packet).unwrap();
            };
            let mut decoder = Decoder::new();
            let mut bytes = [0u8; 4096];
            while let Ok(len @ 1..) = stream.read(&mut bytes) {
                for frame in decoder.decode(&bytes[..len]) {
                    match frame {
                        Frame::Interrupt => reply(&mut stream, "T02thread:p01.02;"),
                        Frame::Packet(body) => {
                            let body = String::from_utf8(body).unwrap();
                            let seen = {
                                let mut log = log.lock();
                                let seen = log.iter().filter(|previous| **previous == body).count();
                                log.push(body.clone());
                                seen
                            };
                            reply(&mut stream, &answer(&body, seen));
                        }
                        _ => {}
                    }
                }
            }
        });
        let halts = Arc::new(HaltClock::default());
        halts.set_running(true);
        let client = GdbClient {
            stream: BufReader::new(TcpStream::connect(addr).unwrap()),
            features: StubFeatures::default(),
            decoder: Decoder::new(),
            unread: None,
            no_ack_mode: true,
            arch: Arch::Amd64,
            register_map: RegisterMap::default(),
            halts,
            hardware_sites: Vec::new(),
            extra_registers: Vec::new(),
            last_stop: Vec::new(),
            kept_stop: false,
            control_thread: None,
            kernel_dtb: None,
            windows_hypervisor: false,
            halt_cache: HaltCache::default(),
            resumed_selected: None,
        };
        (client, received)
    }

    fn running_client_over_recording_stub() -> (GdbClient, Arc<Mutex<Vec<String>>>) {
        client_over_stub(|packet, _| {
            match packet {
                "?" => "T05core:01;",
                "qC" => "QCp01.01",
                _ => "",
            }
            .to_string()
        })
    }

    /// A halted client stopped on `p01.02` that knows the kernel root, with
    /// `cr3` as register 0x43, as in QEMU's x86-64 description.
    fn halted_client_over_stub(
        answer: fn(&str, usize) -> String,
    ) -> (GdbClient, Arc<Mutex<Vec<String>>>) {
        let (mut client, received) = client_over_stub(answer);
        client.halts.set_running(false);
        client.last_stop = b"T05thread:p01.02;".to_vec();
        client.kernel_dtb = Some(0x1ae000);
        client.register_map = RegisterMap::from_registers(vec![RegisterInfo {
            name: "cr3".to_string(),
            offset: 0,
            size: 8,
            regnum: 0x43,
        }]);
        (client, received)
    }

    fn thread(name: &str) -> ThreadId {
        ThreadId::parse(name.as_bytes()).unwrap()
    }

    /// The stub runs the threads `vCont` names to continue.
    fn continues_threads(client: &mut GdbClient) {
        client.features.actions = ResumeActions::of(&[ActionKind::Continue]);
    }

    #[test]
    fn hardware_breakpoints_are_not_limited_to_debug_register_slots() {
        let (mut client, received) = halted_client_over_stub(|packet, _| {
            match packet {
                "g" => "",
                _ => "OK",
            }
            .to_string()
        });
        let session = session_over_memory(0x1000, &[0u8; 0x200]);
        let mut manager = BreakpointManager::new();
        for index in 0..300 {
            let id = manager
                .add_hardware_configured(
                    &mut client,
                    &session.target,
                    VirtAddr(0x1000 + index),
                    HwBreakpointAccess::Execute,
                    1,
                    None,
                    BreakpointConfig::default(),
                )
                .unwrap();
            assert_eq!(
                manager
                    .hardware_breakpoint_for_slot(index as usize)
                    .unwrap()
                    .id,
                id
            );
        }
        let mut event = stop_event(b"S05");
        event.program_counter = Some(0x112b);
        let map = RegisterMap::default();
        let hit = hardware_breakpoint_hit(&mut client, &map, &manager, &event, Arch::Amd64)
            .unwrap()
            .unwrap();
        assert_eq!(hit.hardware.unwrap().slot, 299);
        manager.remove_all(&mut client, &session.target).unwrap();
        assert!(client.hardware_sites.iter().all(Option::is_none));
        let packets = received.lock();
        assert_eq!(
            packets
                .iter()
                .filter(|packet| packet.starts_with("Z1,"))
                .count(),
            300
        );
        assert_eq!(
            packets
                .iter()
                .filter(|packet| packet.starts_with("z1,"))
                .count(),
            300
        );
        assert!(!packets.iter().any(|packet| packet.starts_with("Z0,")));
    }

    #[test]
    fn a_refused_hardware_breakpoint_does_not_claim_a_slot() {
        let (mut client, received) = halted_client_over_stub(|packet, _| {
            match packet {
                "Z1,1004,1" => "E22",
                _ => "OK",
            }
            .to_string()
        });
        let session = session_over_memory(0x1000, &[0u8; 0x10]);
        let mut manager = BreakpointManager::new();
        for index in 0..4 {
            manager
                .add_hardware_configured(
                    &mut client,
                    &session.target,
                    VirtAddr(0x1000 + index),
                    HwBreakpointAccess::Execute,
                    1,
                    None,
                    BreakpointConfig::default(),
                )
                .unwrap();
        }
        let error = manager
            .add_hardware_configured(
                &mut client,
                &session.target,
                VirtAddr(0x1004),
                HwBreakpointAccess::Execute,
                1,
                None,
                BreakpointConfig::default(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("E22"));
        assert!(manager.hardware_breakpoint_for_slot(4).is_none());
        assert_eq!(client.hardware_sites.len(), 4);
        manager.remove(&mut client, &session.target, 1).unwrap();
        let id = manager
            .add_hardware_configured(
                &mut client,
                &session.target,
                VirtAddr(0x1005),
                HwBreakpointAccess::Execute,
                1,
                None,
                BreakpointConfig::default(),
            )
            .unwrap();
        assert_eq!(manager.hardware_breakpoint_for_slot(1).unwrap().id, id);
        assert!(received.lock().iter().any(|packet| packet == "Z1,1004,1"));
    }

    #[test]
    fn disabled_hardware_breakpoints_keep_their_logical_slot() {
        let (mut client, _) = halted_client_over_stub(|_, _| "OK".to_string());
        let session = session_over_memory(0x1000, &[0u8; 0x200]);
        let mut manager = BreakpointManager::new();
        for index in 0..300 {
            manager
                .add_hardware_configured(
                    &mut client,
                    &session.target,
                    VirtAddr(0x1000 + index),
                    HwBreakpointAccess::Execute,
                    1,
                    None,
                    BreakpointConfig::default(),
                )
                .unwrap();
        }
        manager.disable(&mut client, &session.target, 299).unwrap();
        let id = manager
            .add_hardware_configured(
                &mut client,
                &session.target,
                VirtAddr(0x2000),
                HwBreakpointAccess::Write,
                4,
                None,
                BreakpointConfig::default(),
            )
            .unwrap();
        assert_eq!(manager.hardware_breakpoint_for_slot(300).unwrap().id, id);
        manager.enable(&mut client, &session.target, 299).unwrap();
        assert_eq!(client.hardware_sites[299].unwrap().addr, 0x112b);
        let event = stop_event(b"T05watch:2002;");
        let hit = hardware_breakpoint_hit(
            &mut client,
            &RegisterMap::default(),
            &manager,
            &event,
            Arch::Amd64,
        )
        .unwrap()
        .unwrap();
        assert_eq!(hit.id, id);
        manager.remove_all(&mut client, &session.target).unwrap();
        assert!(client.hardware_sites.iter().all(Option::is_none));
    }

    #[test]
    fn hardware_refusals_are_distinct_from_protocol_errors() {
        let (mut client, _) = halted_client_over_stub(|packet, _| {
            match packet {
                "Z1,1000,1" => "",
                "Z1,1001,1" => "E22",
                "Z1,1003,1" => "E",
                "Z1,1004,1" => "E2",
                "Z1,1005,1" => "Ezz",
                "Z1,1006,1" => "E220",
                _ => "invalid",
            }
            .to_string()
        });
        assert!(matches!(
            client.set_hardware_breakpoint(0, 0x1000, HwBreakpointAccess::Execute, 1),
            Err(Error::NotSupported)
        ));
        assert!(matches!(
            client.set_hardware_breakpoint(0, 0x1001, HwBreakpointAccess::Execute, 1),
            Err(Error::HardwareBreakpointRefused { .. })
        ));
        for address in 0x1002..=0x1006 {
            assert!(matches!(
                client.set_hardware_breakpoint(0, address, HwBreakpointAccess::Execute, 1),
                Err(Error::Rsp(_))
            ));
        }
        assert!(client.hardware_sites.is_empty());
    }

    #[test]
    fn a_failed_hardware_removal_keeps_the_record_for_retry() {
        let (mut client, received) = halted_client_over_stub(|packet, seen| {
            match (packet, seen) {
                ("z1,112b,1", 0) => "E22",
                _ => "OK",
            }
            .to_string()
        });
        for slot in 0..300 {
            client
                .set_hardware_breakpoint(slot, 0x1000 + slot as u64, HwBreakpointAccess::Execute, 1)
                .unwrap();
        }
        assert!(client.clear_hardware_breakpoint(299).is_err());
        assert_eq!(client.hardware_sites[299].unwrap().addr, 0x112b);
        client.clear_hardware_breakpoint(299).unwrap();
        assert!(client.hardware_sites[299].is_none());
        client
            .set_hardware_breakpoint(299, 0x2000, HwBreakpointAccess::ReadWrite, 8)
            .unwrap();
        client.clear_hardware_breakpoint(299).unwrap();
        let packets = received.lock();
        assert_eq!(
            packets
                .iter()
                .filter(|packet| *packet == "z1,112b,1")
                .count(),
            2
        );
        assert_eq!(&packets[packets.len() - 2..], ["Z4,2000,8", "z4,2000,8"]);
    }

    /// A stop the stub sent while the target ran is pending before anything
    /// waits for it, even behind console output; console output alone is
    /// not, and a halted target has none.
    #[test]
    fn a_stop_reply_waiting_on_the_socket_is_pending() {
        let (mut client, _) = client_over_stub(|packet, _| {
            match packet {
                "console" => "O6869",
                _ => "T05thread:p01.02;",
            }
            .to_string()
        });
        let prompt = |client: &mut GdbClient, body: &str| {
            let mut packet = Vec::new();
            frame::write_packet(&mut packet, body.as_bytes());
            client.stream.get_mut().write_all(&packet).unwrap();
            thread::sleep(Duration::from_millis(100));
        };
        assert!(!client.has_pending_stop());
        prompt(&mut client, "console");
        assert!(!client.has_pending_stop(), "console output is no stop");
        prompt(&mut client, "stop");
        assert!(client.has_pending_stop());
        client.halts.set_running(false);
        assert!(!client.has_pending_stop());
    }

    #[test]
    fn a_stop_reply_is_found_past_acks_and_whole_console_packets_only() {
        let packets = |bodies: &[&str]| {
            let mut bytes = Vec::new();
            for body in bodies {
                frame::write_packet(&mut bytes, body.as_bytes());
            }
            bytes
        };
        let holds_stop_reply =
            |bytes: &[u8]| stop_reply_among(Decoder::new().decode(bytes)) == Some(true);
        let mut acked = b"+".to_vec();
        acked.extend(packets(&["T05thread:p01.02;"]));
        assert!(holds_stop_reply(&acked));
        assert!(holds_stop_reply(&packets(&["O6869", "S05"])));
        assert!(!holds_stop_reply(&packets(&["O6869"])));
        // A console packet still arriving hides what follows it.
        assert!(!holds_stop_reply(b"$O6869"));
        // So does a stop reply still arriving.
        assert!(!holds_stop_reply(b"$T05thread:p01.02;"));
        assert!(!holds_stop_reply(&packets(&["E01", "S05"])));
        assert!(!holds_stop_reply(b""));
    }

    /// Within one halt a thread is selected and its registers read once; a
    /// register write reads them again, and after a resume the stub has
    /// picked its own thread and the vCPU has moved.
    #[test]
    fn a_halt_selects_its_thread_and_reads_its_registers_once() {
        let (mut client, received) = halted_client_over_stub(|packet, _| {
            match packet {
                "g" => "0100000000000000",
                _ => "OK",
            }
            .to_string()
        });
        for _ in 0..2 {
            DebugBackend::set_current_thread(&mut client, "p01.02").unwrap();
            client.read_registers().unwrap();
        }
        client.write_register_bytes(0x43, &[0; 8]).unwrap();
        client.read_registers().unwrap();
        client.halts.set_running(true);
        client.halts.set_running(false);
        DebugBackend::set_current_thread(&mut client, "p01.02").unwrap();
        client.read_registers().unwrap();
        assert_eq!(
            *received.lock(),
            [
                "Hgp1.2",
                "Hcp1.2",
                "g",
                "P43=0000000000000000",
                "g",
                "Hgp1.2",
                "Hcp1.2",
                "g",
            ]
        );
    }

    /// A run of the selected thread that stops on that thread leaves it
    /// selected, as the stub does, so the instruction-by-instruction runs
    /// past of a step under the Windows hypervisor select nothing; the
    /// vCPU moved, so its registers are read again. A stop on another
    /// thread, or after a resume of every thread (`Hc-1`), selects it again.
    #[test]
    fn a_stop_on_the_thread_run_keeps_it_selected() {
        let (mut client, received) = halted_client_over_stub(|packet, seen| {
            match packet {
                "g" => "0100000000000000",
                "vCont;c:p1.2" if seen == 1 => "T05thread:p01.01;",
                "vCont;c:p1.2" | "c" => "T05thread:p01.02;",
                _ => "OK",
            }
            .to_string()
        });
        continues_threads(&mut client);
        let select = |client: &mut GdbClient| {
            DebugBackend::set_current_thread(client, "p01.02").unwrap();
            client.read_registers().unwrap();
        };
        select(&mut client);
        for _ in 0..2 {
            DebugBackend::continue_current_thread(&mut client).unwrap();
            DebugBackend::wait_for_stop(&mut client).unwrap();
            select(&mut client);
        }
        DebugBackend::continue_execution(&mut client).unwrap();
        DebugBackend::wait_for_stop(&mut client).unwrap();
        select(&mut client);
        assert_eq!(
            *received.lock(),
            [
                "Hgp1.2",
                "Hcp1.2",
                "g",
                "vCont;c:p1.2",
                "g",
                "vCont;c:p1.2",
                "Hgp1.2",
                "Hcp1.2",
                "g",
                "Hc-1",
                "c",
                "Hgp1.2",
                "Hcp1.2",
                "g",
            ]
        );
    }

    /// Under VBS a vCPU can halt in the Windows hypervisor, whose page tables
    /// do not map NT, and QEMU plants `Z0` through them. Another vCPU halted
    /// in NT plants the same (VM-wide) breakpoint without any register
    /// write, and the selected vCPU must be the control vCPU again after.
    #[test]
    fn a_kernel_breakpoint_is_planted_through_a_vcpu_halted_in_nt() {
        let (mut client, received) = halted_client_over_stub(|packet, seen| {
            match packet {
                "Z0,fffff800e1a5d130,1" if seen == 0 => "E22",
                "qfThreadInfo" => "mp01.01,p01.02",
                "qsThreadInfo" => "l",
                _ => "OK",
            }
            .to_string()
        });
        client.set_breakpoint(0xfffff800e1a5d130).unwrap();
        assert_eq!(
            *received.lock(),
            [
                "Z0,fffff800e1a5d130,1",
                "qfThreadInfo",
                "qsThreadInfo",
                "Hcp1.1",
                "Z0,fffff800e1a5d130,1",
                "Hcp1.2",
            ]
        );
    }

    /// With every vCPU outside NT, the retry goes through the kernel root on
    /// the selected vCPU and must always put that vCPU's own CR3 back, or it
    /// resumes in the wrong address space.
    #[test]
    fn a_kernel_breakpoint_no_vcpu_can_map_is_planted_through_the_kernel_root() {
        let (mut client, received) = halted_client_over_stub(|packet, seen| {
            match packet {
                "Z0,fffff800e1a5d130,1" if seen < 2 => "E22",
                "qfThreadInfo" => "mp01.01,p01.02",
                "qsThreadInfo" => "l",
                "p43" => "00501f1501000000",
                _ => "OK",
            }
            .to_string()
        });
        client.set_breakpoint(0xfffff800e1a5d130).unwrap();
        assert_eq!(
            *received.lock(),
            [
                "Z0,fffff800e1a5d130,1",
                "qfThreadInfo",
                "qsThreadInfo",
                "Hcp1.1",
                "Z0,fffff800e1a5d130,1",
                "Hcp1.2",
                "Hgp1.2",
                "Hcp1.2",
                "g",
                "p43",
                "P43=00e01a0000000000",
                "Z0,fffff800e1a5d130,1",
                "P43=00501f1501000000",
            ]
        );
    }

    #[test]
    fn a_failed_retry_still_restores_cr3_and_reports_the_failure() {
        let (mut client, received) = halted_client_over_stub(|packet, _| {
            match packet {
                "z0,fffff800e1a5d130,1" => "E22",
                "p43" => "00501f1501000000",
                _ => "OK",
            }
            .to_string()
        });
        assert!(client.remove_breakpoint(0xfffff800e1a5d130).is_err());
        assert_eq!(
            received.lock().last().map(String::as_str),
            Some("P43=00501f1501000000")
        );
    }

    /// Under the Windows hypervisor a KVM step can finish inside it and leave
    /// the trap to Windows, so no step packet may reach the stub; running
    /// past a breakpoint resumes the selected vCPU alone instead.
    #[test]
    fn under_the_windows_hypervisor_steps_are_refused_and_one_vcpu_resumes_alone() {
        let (mut client, received) = halted_client_over_stub(|_, _| "OK".to_string());
        continues_threads(&mut client);
        client.control_thread = Some(thread("p01.02"));
        client.set_windows_hypervisor(true);
        assert!(DebugBackend::single_step_unsafe(&client));
        assert!(DebugBackend::step(&mut client).is_err());
        DebugBackend::continue_current_thread(&mut client).unwrap();
        // The continue is fire-and-forget; give the stub a moment to log it.
        thread::sleep(Duration::from_millis(50));
        assert_eq!(*received.lock(), ["vCont;c:p1.2"]);
    }

    /// A run that holds some vCPUs resumes each of the others by name in one
    /// packet; QEMU leaves the vCPUs it names no action for stopped.
    #[test]
    fn a_run_of_some_vcpus_names_each_one_it_resumes() {
        let (mut client, received) = halted_client_over_stub(|_, _| "OK".to_string());
        continues_threads(&mut client);
        let threads = ["p01.01".to_string(), "p01.03".to_string()];
        DebugBackend::continue_threads(&mut client, &threads).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(*received.lock(), ["vCont;c:p1.1;c:p1.3"]);
        assert!(DebugBackend::is_running(&client));
    }

    /// A kept stop comes back from the next wait with the resume before it
    /// never sent: the target stays halted at the stop, so the stopped
    /// vCPU's registers are still those of its hit. The resume after that
    /// goes out.
    #[test]
    fn a_kept_stop_comes_back_without_the_target_resuming() {
        let (mut client, received) = halted_client_over_stub(|_, _| "OK".to_string());
        continues_threads(&mut client);
        client.control_thread = Some(thread("p01.02"));
        client.last_stop = b"T05watch:ffffcc0c31caf204;thread:p01.03;".to_vec();

        DebugBackend::keep_last_stop(&mut client).unwrap();
        DebugBackend::continue_execution(&mut client).unwrap();
        assert!(DebugBackend::stop_kept(&client));
        let event = DebugBackend::wait_for_stop(&mut client).unwrap();
        assert_eq!(event.thread_id.as_deref(), Some("p1.3"));
        assert_eq!(event.watchpoint_address, Some(0xffff_cc0c_31ca_f204));
        assert!(!DebugBackend::is_running(&client));
        assert!(!DebugBackend::stop_kept(&client));

        DebugBackend::continue_current_thread(&mut client).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(*received.lock(), ["vCont;c:p1.2"]);
    }

    /// An exit that leaves the target running resumes it even when a stop
    /// kept for a wait that never came holds it, after a resume that sent
    /// nothing.
    #[test]
    fn leaving_the_target_running_resumes_past_a_kept_stop() {
        let (mut client, received) = halted_client_over_stub(|_, _| "OK".to_string());
        DebugBackend::keep_last_stop(&mut client).unwrap();
        DebugBackend::continue_execution(&mut client).unwrap();

        DebugBackend::prepare_for_exit(&mut client, true).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(*received.lock(), ["Hc-1", "c"]);
        assert!(DebugBackend::is_running(&client));
    }

    /// The kernel root cannot map a user-half address any better than the
    /// vCPU's own tables, so the vCPU is left alone.
    #[test]
    fn a_user_address_failure_is_reported_without_touching_cr3() {
        let (mut client, received) = halted_client_over_stub(|_, _| "E22".to_string());
        assert!(client.set_breakpoint(0x7ff6_0000_1000).is_err());
        assert_eq!(*received.lock(), ["Z0,7ff600001000,1"]);
    }

    /// QEMU answers `?` by removing every breakpoint, as for a debugger's
    /// first connect. Asked mid-session (listing vCPUs, a halted wait), it
    /// silently dropped the bugcheck trap and any user breakpoint, which
    /// then failed to come out at exit with the guest left halted. The
    /// stopped thread and a halted wait must come from what the client
    /// already read.
    #[test]
    fn stopped_thread_and_halted_waits_never_ask_the_stub_again() {
        let (mut client, received) = running_client_over_recording_stub();

        DebugBackend::interrupt(&mut client).unwrap();
        assert_eq!(
            DebugBackend::stopped_thread_id(&mut client).unwrap(),
            "p1.2"
        );
        let halted = DebugBackend::try_wait_for_stop(&mut client, Duration::from_millis(10))
            .unwrap()
            .unwrap();
        assert!(halted.thread_id.is_none() && halted.watchpoint_address.is_none());
        DebugBackend::wait_for_stop(&mut client).unwrap();

        assert!(!received.lock().iter().any(|packet| packet == "?"));
    }

    /// A wait whose deadline is reached polls once without waiting, as the
    /// run driver asks with a zero timeout, which a socket refuses as its
    /// read timeout: a running target with no stop is `None`, not an error.
    #[test]
    fn a_zero_timeout_wait_polls_a_running_target() {
        let (mut client, _) = running_client_over_recording_stub();

        let polled = DebugBackend::try_wait_for_stop(&mut client, Duration::ZERO);

        assert!(matches!(polled, Ok(None)), "{polled:?}");
        assert!(DebugBackend::is_running(&client));
    }

    #[test]
    fn accepts_the_architectures_ntoseye_debugs() {
        let describe = |arch: &str| {
            description_arch(
                &Description::parse(&format!(
                    "<target><architecture>{arch}</architecture></target>"
                ))
                .unwrap(),
            )
        };
        assert_eq!(describe("i386:x86-64").unwrap(), Arch::Amd64);
        assert_eq!(describe("aarch64").unwrap(), Arch::Arm64);
        // A 32-bit stub has no Windows kernel ntoseye can read.
        assert!(describe("i386").is_err());
        assert!(description_arch(&Description::parse("<target></target>").unwrap()).is_err());
    }

    /// Registers are packed in regnum order, so a register listed first
    /// with a later regnum still lands behind the ones numbered before it,
    /// and one without a regnum takes the number after the one listed
    /// before it.
    #[test]
    fn registers_are_packed_in_regnum_order() {
        let description = Description::parse(
            r#"<target><feature name="core">
            <reg name="rip" bitsize="64" regnum="1"/>
            <reg name="eflags" bitsize="32"/>
            <reg name="rax" bitsize="64" regnum="0"/>
        </feature></target>"#,
        )
        .unwrap();
        let map = description_registers(&description).unwrap();

        let offsets: Vec<_> = map
            .registers()
            .iter()
            .map(|reg| (reg.name.as_str(), reg.offset, reg.size, reg.regnum))
            .collect();
        assert_eq!(
            offsets,
            [("rax", 0, 8, 0), ("rip", 8, 8, 1), ("eflags", 16, 4, 2)]
        );
    }

    /// The description is read a chunk at a time, each from where the data
    /// so far ends, with its includes read the same way in their place.
    #[test]
    fn a_target_description_is_read_in_chunks_with_its_includes() {
        let (mut client, received) = halted_client_over_stub(|packet, _| {
            match packet {
                "qXfer:features:read:target.xml:0,fff" => {
                    "m<target><architecture>aarch64</architecture>"
                }
                "qXfer:features:read:target.xml:2c,fff" => {
                    "l<xi:include href=\"core.xml\"/></target>"
                }
                "qXfer:features:read:core.xml:0,fff" => {
                    "l<feature name=\"core\"><reg name=\"x0\" bitsize=\"64\"/>\
                     <reg name=\"x1\" bitsize=\"64\"/></feature>"
                }
                _ => "",
            }
            .to_string()
        });
        client.features.qxfer_features_read = true;

        let description = client.fetch_target_description().unwrap();

        assert_eq!(description_arch(&description).unwrap(), Arch::Arm64);
        let map = description_registers(&description).unwrap();
        assert_eq!(
            map.read_u64("x1", &[0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0])
                .unwrap(),
            7
        );
        assert_eq!(
            *received.lock(),
            [
                "qXfer:features:read:target.xml:0,fff",
                "qXfer:features:read:target.xml:2c,fff",
                "qXfer:features:read:core.xml:0,fff",
            ]
        );
    }

    #[test]
    fn a_stop_event_takes_the_thread_and_watch_address_of_a_stop_reply() {
        // QEMU's own shape: padded thread id, then the trapping address.
        let event = stop_event(b"T05thread:p01.02;watch:fffff80012345678;");
        assert_eq!(event.thread_id.as_deref(), Some("p1.2"));
        assert_eq!(event.watchpoint_address, Some(0xffff_f800_1234_5678));
    }

    #[test]
    fn parses_read_and_access_watch_fields() {
        assert_eq!(
            stop_event(b"T05thread:p01.01;rwatch:1000;").watchpoint_address,
            Some(0x1000)
        );
        assert_eq!(
            stop_event(b"T05thread:p01.01;awatch:1000;").watchpoint_address,
            Some(0x1000)
        );
    }

    #[test]
    fn ignores_fields_that_are_not_a_thread_or_a_watch() {
        // The initial `?` reply names a core and no thread; register fields
        // are `<hex regnum>:<value>` and must not be mistaken for either.
        let event = stop_event(b"T05core:01;10:0000000000000000;");
        assert_eq!(event.thread_id, None);
        assert_eq!(event.watchpoint_address, None);
    }

    #[test]
    fn parses_stop_replies_that_describe_no_stopped_thread_as_empty() {
        // `S` carries no fields at all, and `W`/`X` report an exit.
        for reply in [&b"S05"[..], b"W00", b"X09"] {
            let event = stop_event(reply);
            assert_eq!(event.thread_id, None);
            assert_eq!(event.watchpoint_address, None);
            assert!(!event.break_in);
        }
    }

    #[test]
    fn only_a_sigint_stop_reply_is_a_break_in() {
        assert!(stop_event(b"T02thread:p1.1;").break_in);
        assert!(!stop_event(b"T05thread:p1.1;").break_in);
        assert!(stop_event(b"S02").break_in);
        assert!(!stop_event(b"W02").break_in);
    }
}
