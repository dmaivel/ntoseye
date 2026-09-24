use std::io::{self, Read, Write};
use std::mem;
use std::net::TcpStream;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use crate::dbg_backend::{DebugBackend, HW_BREAKPOINT_SLOTS, HwBreakpointAccess, StopEvent};
use crate::error::{Error, Result};

pub mod breakpoints;
pub mod registers;

pub use breakpoints::{
    BreakpointConfig, BreakpointHitDisposition, BreakpointHitResult, BreakpointManager,
    BreakpointSpec,
};
pub use registers::{RegisterInfo, RegisterMap};

/// Bytes of a packet shown per trace line.
const TRACE_BYTES: usize = 200;

/// Packet trace on stderr, gated on `NTOSEYE_GDB_TRACE`: every RSP packet on
/// both of ntoseye's GDB connections, timestamped on one clock. `stub` lines
/// are the `gdb` backend's conversation with the hypervisor's stub; `client`
/// lines are the GDB server's with its client. One capture lines a client's
/// request up against what the backend did to answer it.
static TRACE: LazyLock<bool> = LazyLock::new(|| std::env::var_os("NTOSEYE_GDB_TRACE").is_some());
static TRACE_START: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Trace one packet. `direction` is `->` for bytes ntoseye sends to `peer`
/// and `<-` for bytes it receives.
pub fn trace_packet(peer: &str, direction: &str, bytes: &[u8]) {
    if !*TRACE {
        return;
    }
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
    let elapsed = TRACE_START.elapsed().as_secs_f64();
    eprintln!("gdb {elapsed:9.3} {peer:<6} {direction} {shown}");
}

#[derive(Debug, Default, Clone)]
struct StubFeatures {
    no_ack_mode: bool,
    qxfer_features_read: bool,
    /// `vCont;s:<thread>` is supported (`vCont?` lists `s`).
    thread_step: bool,
}

#[derive(Debug, Default)]
enum PacketReadState {
    #[default]
    SeekingStart,
    ReadingData(Vec<u8>),
    ReadingChecksum {
        data: Vec<u8>,
        checksum: [u8; 2],
        len: usize,
    },
}

#[derive(Debug)]
enum AckResult {
    Ack,
    Nack,
    ReplyStarted,
}

#[derive(Debug)]
struct RawPacket {
    data: Vec<u8>,
    checksum: [u8; 2],
}

/// The fields of an RSP stop reply this client acts on.
///
/// The signal byte is deliberately not turned into an exception code. A stub
/// reports `SIGTRAP` for a breakpoint, a watchpoint, and a completed step
/// alike, so inventing `STATUS_BREAKPOINT` from it would drive the shared
/// `int3` rewind over stops that never executed one.
#[derive(Debug, Default, PartialEq, Eq)]
struct StopReply {
    thread_id: Option<String>,
    /// Address from `watch:`/`rwatch:`/`awatch:`: the data address that made
    /// a hardware watchpoint fire.
    watch_address: Option<u64>,
}

impl StopReply {
    /// Parse `T<sig>[<name>:<value>;]...`. `S<sig>` carries no fields, and
    /// `W`/`X`/`N` do not describe a stopped thread, so all of them parse
    /// empty.
    fn parse(response: &str) -> Self {
        let mut reply = StopReply::default();
        let Some(fields) = response.strip_prefix('T').and_then(|body| body.get(2..)) else {
            return reply;
        };

        for field in fields.split(';') {
            let Some((name, value)) = field.split_once(':') else {
                continue;
            };
            match name {
                "thread" => reply.thread_id = Some(value.to_string()),
                // The three watch kinds differ only in which access trapped,
                // which the breakpoint already records.
                "watch" | "rwatch" | "awatch" => {
                    reply.watch_address = u64::from_str_radix(value, 16).ok();
                }
                _ => {}
            }
        }

        reply
    }

    fn into_event(self) -> StopEvent {
        StopEvent {
            thread_id: self.thread_id,
            watchpoint_address: self.watch_address,
            exception_code: None,
            first_chance: None,
            exception_address: None,
            program_counter: None,
            is_bugcheck: false,
            bugcheck: None,
            target_reloaded: false,
            target_kernel_base_hint: None,
            modules_changed: false,
            assisted_breakin: false,
        }
    }
}

/// What the target description says the stub is debugging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetArch {
    Amd64,
    Arm64,
}

impl TargetArch {
    fn from_description(xml: &str) -> Result<Self> {
        let Some(architecture) = RegisterMap::target_architecture(xml) else {
            return Err(Error::UnsupportedArchitecture(
                "the stub's target description declares no architecture".into(),
            ));
        };
        match architecture {
            "i386:x86-64" => Ok(Self::Amd64),
            "aarch64" => Ok(Self::Arm64),
            other => Err(Error::UnsupportedArchitecture(format!(
                "{other}; ntoseye debugs AMD64 and ARM64 Windows"
            ))),
        }
    }

    /// How far the program counter moves when the arch's breakpoint
    /// instruction executes, which is also the `Z0` packet's kind.
    fn breakpoint_step_size(self) -> u8 {
        match self {
            Self::Amd64 => 1,
            Self::Arm64 => 4,
        }
    }
}

/// Names the rest of the debugger reads, mapped onto what an AArch64 target
/// description calls them. KD's ARM64 register map carries the same aliases.
const ARM64_ALIASES: [(&str, &str); 5] = [
    ("rip", "pc"),
    ("rsp", "sp"),
    ("fp", "x29"),
    ("lr", "x30"),
    ("pstate", "cpsr"),
];

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
    kind: u8,
    addr: u64,
    len: u8,
}

/// The `Z`/`z` packet type for an access mode. `Z3` (read-only watch) is
/// never used: the x86 debug registers cannot express one, so a read watch is
/// the read/write `Z4`.
fn hardware_packet_kind(access: HwBreakpointAccess) -> u8 {
    match access {
        HwBreakpointAccess::Execute => 1,
        HwBreakpointAccess::Write => 2,
        HwBreakpointAccess::ReadWrite => 4,
    }
}

impl StubFeatures {
    fn parse(response: &str) -> Self {
        let mut features = StubFeatures::default();

        for item in response.split(';') {
            match item {
                "QStartNoAckMode+" => features.no_ack_mode = true,
                "qXfer:features:read+" => features.qxfer_features_read = true,
                _ => {}
            }
        }

        features
    }
}

pub struct GdbClient {
    stream: TcpStream,
    features: StubFeatures,
    rx_state: PacketReadState,
    no_ack_mode: bool,
    register_map: RegisterMap,
    is_running: bool,
    hardware_sites: [Option<HardwareSite>; HW_BREAKPOINT_SLOTS as usize],
    extra_registers: Vec<ExtraRegister>,
    /// The stop reply that left the target halted: the one to the initial
    /// `?`, then each stop read since, for the stopped thread. Asking again
    /// is not an option: QEMU treats `?` as a debugger's initial connect and
    /// removes every breakpoint, including ones this client still counts as
    /// installed.
    last_stop: String,
    /// The thread the last `Hc` selected; `None` after a continue reset it
    /// to all threads.
    control_thread: Option<String>,
}

/// What a wait on an already halted target reports: a stop with no fields,
/// which is what the stub's `?` answered before this client stopped asking
/// (see [`GdbClient::last_stop`]). No fields, so a stop the caller already
/// handled is not handled again.
const HALTED_NO_NEW_STOP: &str = "S05";

/// Why a request cannot be served right now, for [`Error::TargetRunning`].
const GDB_STUB_NEEDS_HALT: &str = "the GDB stub serves no requests while the target runs.";

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
    pub fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).map_err(|err| gdb_connect_error(addr, err))?;
        // Every exchange is a small request, a one-byte ack, and a small
        // reply; with Nagle on, each ack waits out the peer's delayed ACK
        // (~40 ms) before it leaves.
        stream.set_nodelay(true)?;

        let mut client = GdbClient {
            stream,
            features: StubFeatures::default(),
            rx_state: PacketReadState::default(),
            no_ack_mode: false,
            register_map: RegisterMap::default(),
            is_running: false, // NOTE if the user toys with VM via GUI, this value goes bad
            hardware_sites: [None; HW_BREAKPOINT_SLOTS as usize],
            extra_registers: Vec::new(),
            last_stop: String::new(),
            control_thread: None,
        };

        client.force_stop_and_resync()?;

        let supported =
            client.send_packet("qSupported:multiprocess+;swbreak+;qRelocInsn+;vContSupported+")?;
        client.features = StubFeatures::parse(&supported);
        client.features.thread_step = client
            .send_packet("vCont?")?
            .split(';')
            .any(|action| action == "s");

        if client.features.no_ack_mode {
            let _ = client.enable_no_ack_mode();
        }

        // The one `?` this client sends: nothing is planted yet for QEMU to
        // clear, and the reply is the halt reason until the next stop.
        client.last_stop = client.send_packet("?")?;

        let description = client.fetch_target_description()?;
        let arch = TargetArch::from_description(&description)?;
        client.register_map =
            client.build_register_map(&RegisterMap::parse_target_xml(&description), arch)?;

        Ok(client)
    }

    fn force_stop_and_resync(&mut self) -> Result<()> {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))?;
        self.rx_state = PacketReadState::default();

        trace_packet("stub", "->", &[0x03]);
        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        while self.read_response_packet().is_ok() {}

        self.stream.set_read_timeout(None)?;
        self.rx_state = PacketReadState::default();

        self.is_running = false;

        Ok(())
    }

    /// Send a request and read its reply.
    ///
    /// A stub in all-stop mode services nothing but an interrupt while the
    /// target runs, so a request sent then would block on a reply that is
    /// never coming. Refusing it keeps a running target from wedging the
    /// debugger; [`Self::interrupt`] is the way through, and it writes the
    /// break byte directly rather than through here.
    pub fn send_packet(&mut self, data: &str) -> Result<String> {
        if self.is_running {
            return Err(Error::TargetRunning(GDB_STUB_NEEDS_HALT));
        }
        let packet = Self::encode_packet(data);
        self.send_raw_command(&packet)?;
        self.read_response_packet()
    }

    fn enable_no_ack_mode(&mut self) -> Result<()> {
        let response = self.send_packet("QStartNoAckMode")?;
        if response == "OK" {
            self.no_ack_mode = true;
            Ok(())
        } else {
            Err(Error::NotSupported)
        }
    }

    fn encode_packet(data: &str) -> Vec<u8> {
        let checksum: u8 = data.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
        format!("${}#{:02x}", data, checksum).into_bytes()
    }

    fn send_raw_command(&mut self, packet: &[u8]) -> Result<()> {
        trace_packet("stub", "->", packet);
        loop {
            self.stream.write_all(packet)?;
            self.stream.flush()?;

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

    fn wait_for_ack(&mut self) -> Result<AckResult> {
        let mut buf = [0u8; 1];

        loop {
            self.stream.read_exact(&mut buf)?;
            match buf[0] {
                b'+' => return Ok(AckResult::Ack),
                b'-' => return Ok(AckResult::Nack),
                b'$' => {
                    self.rx_state = PacketReadState::ReadingData(Vec::new());
                    return Ok(AckResult::ReplyStarted);
                }
                _ => continue,
            }
        }
    }

    fn read_response_packet(&mut self) -> Result<String> {
        loop {
            let packet = self.read_raw_packet()?;
            let expected = Self::parse_checksum(packet.checksum)?;
            let actual = packet
                .data
                .iter()
                .fold(0u8, |acc, byte| acc.wrapping_add(*byte));

            if actual != expected {
                if self.no_ack_mode {
                    return Err(Error::Rsp(format!(
                        "bad checksum from stub: expected {:02x}, got {:02x}",
                        expected, actual
                    )));
                }

                self.stream.write_all(b"-")?;
                self.stream.flush()?;
                continue;
            }

            if !self.no_ack_mode {
                self.stream.write_all(b"+")?;
                self.stream.flush()?;
            }

            let decoded = Self::decode_packet_data(&packet.data)?;
            trace_packet("stub", "<-", &decoded);
            let response = String::from_utf8(decoded)
                .map_err(|e| Error::Rsp(format!("non-utf8 packet payload: {}", e)))?;
            return Ok(response);
        }
    }

    fn read_raw_packet(&mut self) -> Result<RawPacket> {
        loop {
            let mut buf = [0u8; 1];
            self.stream.read_exact(&mut buf)?;
            if let Some(packet) = self.consume_packet_byte(buf[0])? {
                return Ok(packet);
            }
        }
    }

    fn consume_packet_byte(&mut self, byte: u8) -> Result<Option<RawPacket>> {
        match &mut self.rx_state {
            PacketReadState::SeekingStart => {
                if byte == b'$' {
                    self.rx_state = PacketReadState::ReadingData(Vec::new());
                }
                Ok(None)
            }
            PacketReadState::ReadingData(data) => {
                if byte == b'#' {
                    let raw_data = mem::take(data);
                    self.rx_state = PacketReadState::ReadingChecksum {
                        data: raw_data,
                        checksum: [0u8; 2],
                        len: 0,
                    };
                } else {
                    data.push(byte);
                }
                Ok(None)
            }
            PacketReadState::ReadingChecksum {
                data,
                checksum,
                len,
            } => {
                checksum[*len] = byte;
                *len += 1;

                if *len == 2 {
                    let raw_data = mem::take(data);
                    let raw_checksum = *checksum;
                    self.rx_state = PacketReadState::SeekingStart;
                    return Ok(Some(RawPacket {
                        data: raw_data,
                        checksum: raw_checksum,
                    }));
                }

                Ok(None)
            }
        }
    }

    fn parse_checksum(checksum: [u8; 2]) -> Result<u8> {
        let checksum_str = std::str::from_utf8(&checksum)
            .map_err(|e| Error::Rsp(format!("invalid checksum encoding: {}", e)))?;
        u8::from_str_radix(checksum_str, 16)
            .map_err(|e| Error::Rsp(format!("invalid checksum value '{}': {}", checksum_str, e)))
    }

    fn decode_packet_data(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoded = Vec::with_capacity(data.len());
        let mut index = 0;

        while index < data.len() {
            match data[index] {
                b'}' => {
                    index += 1;
                    if index >= data.len() {
                        return Err(Error::Rsp("truncated escaped packet data".into()));
                    }
                    decoded.push(data[index] ^ 0x20);
                    index += 1;
                }
                b'*' => {
                    let Some(last) = decoded.last().copied() else {
                        return Err(Error::Rsp("invalid run-length packet data".into()));
                    };
                    index += 1;
                    if index >= data.len() {
                        return Err(Error::Rsp("truncated run-length packet data".into()));
                    }
                    let repeat_count = data[index]
                        .checked_sub(29)
                        .ok_or_else(|| Error::Rsp("invalid run-length repeat count".into()))?;
                    decoded.extend(std::iter::repeat_n(last, repeat_count as usize));
                    index += 1;
                }
                byte => {
                    decoded.push(byte);
                    index += 1;
                }
            }
        }

        Ok(decoded)
    }

    fn set_breakpoint(&mut self, addr: u64) -> Result<()> {
        let kind = self.register_map.breakpoint_step_size();
        let response = self.send_packet(&format!("Z0,{:x},{}", addr, kind))?;
        if response == "OK" {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to set breakpoint at {:#x}: {}",
                addr, response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    fn remove_breakpoint(&mut self, addr: u64) -> Result<()> {
        let kind = self.register_map.breakpoint_step_size();
        let response = self.send_packet(&format!("z0,{:x},{}", addr, kind))?;
        if response == "OK" {
            Ok(())
        } else if response.starts_with('E') {
            Err(Error::Rsp(format!(
                "failed to remove breakpoint at {:#x}: {}",
                addr, response
            )))
        } else {
            Err(Error::NotSupported)
        }
    }

    /// The slot's record, or an error naming the slot a caller invented.
    /// Indexing would panic, and a debugger has no business dying over one.
    fn hardware_slot(&mut self, slot: u8) -> Result<&mut Option<HardwareSite>> {
        let count = self.hardware_sites.len();
        self.hardware_sites
            .get_mut(usize::from(slot))
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "hardware breakpoint slot {slot} does not exist; the stub has {count}"
                ))
            })
    }

    fn set_hardware_site(&mut self, slot: u8, site: HardwareSite) -> Result<()> {
        self.clear_hardware_site(slot)?;

        let response = self.send_packet(&format!("Z{},{:x},{}", site.kind, site.addr, site.len))?;
        if response == "OK" {
            *self.hardware_slot(slot)? = Some(site);
            return Ok(());
        }
        // An empty reply is RSP for "I do not implement this packet".
        if response.is_empty() {
            return Err(Error::NotSupported);
        }
        Err(Error::Rsp(format!(
            "stub refused a hardware breakpoint at {:#x}: {}.\n\
             The hypervisor programs these with the processor's debug registers and may have none left.",
            site.addr, response
        )))
    }

    fn clear_hardware_site(&mut self, slot: u8) -> Result<()> {
        let Some(site) = *self.hardware_slot(slot)? else {
            return Ok(());
        };

        let response = self.send_packet(&format!("z{},{:x},{}", site.kind, site.addr, site.len))?;
        if response != "OK" {
            // Leave the slot recorded: the stub still holds it, and naming it
            // again needs the same three values.
            return Err(Error::Rsp(format!(
                "failed to remove the hardware breakpoint at {:#x}: {}",
                site.addr, response
            )));
        }
        *self.hardware_slot(slot)? = None;
        Ok(())
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        let response = self.send_packet("g")?;

        if response.starts_with('E') {
            return Err(Error::Rsp(format!(
                "failed to read registers: {}",
                response
            )));
        }

        let mut bytes = hex::decode(&response)?;
        for index in 0..self.extra_registers.len() {
            let regnum = self.extra_registers[index].regnum;
            let value = self.read_one_register(regnum)?;
            bytes.extend_from_slice(&value);
        }
        Ok(bytes)
    }

    fn write_registers(&mut self, data: &[u8]) -> Result<()> {
        // `G` takes back exactly what `g` gave. The system registers appended
        // behind it are not part of that reply, and the stub serves them
        // read-only anyway.
        let data = &data[..data.len().saturating_sub(self.extra_registers.len() * 8)];
        let response = self.send_packet(&format!("G{}", hex::encode(data)))?;

        if response == "OK" {
            Ok(())
        } else {
            Err(Error::Rsp(format!(
                "failed to write registers: {}",
                response
            )))
        }
    }

    fn send_command_no_reply(&mut self, data: &str) -> Result<()> {
        let packet = Self::encode_packet(data);
        self.send_raw_command(&packet)
    }

    fn continue_execution(&mut self) -> Result<()> {
        let _ = self.send_packet("Hc-1")?;
        self.control_thread = None;
        self.send_command_no_reply("c")?;
        self.is_running = true;
        Ok(())
    }

    /// Single-step the selected thread with every other one held. A plain
    /// `s` resumes all of QEMU's vCPUs (only the selected one steps), so
    /// another vCPU's breakpoint hit could be reported as the step.
    fn step(&mut self) -> Result<()> {
        match &self.control_thread {
            Some(thread) if self.features.thread_step => {
                let packet = format!("vCont;s:{thread}");
                self.send_command_no_reply(&packet)?;
            }
            _ => self.send_command_no_reply("s")?,
        }
        self.is_running = true;
        Ok(())
    }

    fn wait_for_stop(&mut self) -> Result<String> {
        if !self.is_running {
            return Ok(HALTED_NO_NEW_STOP.to_string());
        }

        let response = self.read_stop_reply()?;
        self.is_running = false;
        Ok(response)
    }

    fn try_wait_for_stop(&mut self) -> Result<Option<String>> {
        if !self.is_running {
            return Ok(Some(HALTED_NO_NEW_STOP.to_string()));
        }

        match self.read_stop_reply() {
            Ok(response) => {
                self.is_running = false;
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

    fn read_stop_reply(&mut self) -> Result<String> {
        loop {
            let response = self.read_response_packet()?;
            match response.as_bytes().first().copied() {
                Some(b'S' | b'T' | b'W' | b'X' | b'N') => {
                    self.last_stop.clone_from(&response);
                    return Ok(response);
                }
                Some(b'O') => continue,
                Some(b'F') => {
                    return Err(Error::Rsp(
                        "remote file I/O packets are unsupported while waiting for stop".into(),
                    ));
                }
                Some(b'E') => {
                    return Err(Error::Rsp(format!(
                        "run-control command failed: {}",
                        response
                    )));
                }
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected packet while waiting for stop: {}",
                        response
                    )));
                }
            }
        }
    }

    fn interrupt(&mut self) -> Result<String> {
        if !self.is_running {
            return Ok(String::new());
        }

        trace_packet("stub", "->", &[0x03]);
        self.stream.write_all(&[0x03])?;
        self.stream.flush()?;

        let stop = self.read_stop_reply()?;

        self.is_running = false;

        Ok(stop)
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        let mut threads = Vec::new();
        let mut response = self.send_packet("qfThreadInfo")?;

        loop {
            if response == "l" {
                break;
            }

            if let Some(list) = response.strip_prefix('m') {
                for id in list.split(',') {
                    if !id.is_empty() {
                        threads.push(id.to_string());
                    }
                }
            } else if response.starts_with('E') {
                return Err(Error::Rsp(format!(
                    "failed to enumerate threads: {}",
                    response
                )));
            } else {
                return Err(Error::Rsp(format!(
                    "unexpected qThreadInfo response: {}",
                    response
                )));
            }

            response = self.send_packet("qsThreadInfo")?;
        }

        Ok(threads)
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        let resp_g = self.send_packet(&format!("Hg{}", thread_id))?;
        if resp_g != "OK" {
            return Err(Error::Rsp(format!(
                "failed to set general thread: {}",
                resp_g
            )));
        }

        let resp_c = self.send_packet(&format!("Hc{}", thread_id))?;
        if resp_c != "OK" {
            return Err(Error::Rsp(format!(
                "failed to set control thread: {}",
                resp_c
            )));
        }
        self.control_thread = Some(thread_id.to_string());

        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        if let Some(thread_id) = StopReply::parse(&self.last_stop).thread_id {
            return Ok(thread_id);
        }

        // QEMU's initial stop reply names a core, not a thread.
        let response = self.send_packet("qC")?;
        if let Some(thread_id) = response.strip_prefix("QC") {
            return Ok(thread_id.to_string());
        }

        Err(Error::Rsp(
            "could not determine thread from stop reply".into(),
        ))
    }

    /// The stub's full target description, with every `<xi:include>`
    /// resolved.
    fn fetch_target_description(&mut self) -> Result<String> {
        if !self.features.qxfer_features_read {
            return Err(Error::NotSupported);
        }

        let mut xml = String::new();
        let mut offset = 0;

        loop {
            let query = format!("qXfer:features:read:target.xml:{:x},fff", offset);
            let response = self.send_packet(&query)?;

            if response.is_empty() {
                return Err(Error::NotSupported);
            }

            let (marker, data) = response.split_at(1);
            xml.push_str(data);
            offset += data.len();

            match marker {
                "l" => break,    // last chunk
                "m" => continue, // more data
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected qXfer response: {}",
                        response
                    )));
                }
            }
        }

        self.resolve_xml_includes(&xml)
    }

    /// Turn a target description into the register map the debugger reads.
    ///
    /// Only the registers the `g` packet actually carries can be addressed by
    /// offset into its reply, so the description is cut to that length and
    /// the few system registers ntoseye needs are appended behind it, read
    /// individually. ARM64 also gets the x64 spellings the shared code uses.
    fn build_register_map(
        &mut self,
        description: &RegisterMap,
        arch: TargetArch,
    ) -> Result<RegisterMap> {
        let g_bytes = GdbClient::read_registers(self)?.len();
        let mut registers: Vec<RegisterInfo> = description
            .registers()
            .iter()
            .filter(|reg| reg.offset + reg.size <= g_bytes)
            .cloned()
            .collect();

        if arch == TargetArch::Arm64 {
            for (alias, source) in ARM64_ALIASES {
                let Some(register) = registers.iter().find(|reg| reg.name == source) else {
                    return Err(Error::UnsupportedArchitecture(format!(
                        "the stub's AArch64 description has no `{source}` register"
                    )));
                };
                let mut register = register.clone();
                register.name = alias.to_string();
                registers.push(register);
            }

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

        let mut map = RegisterMap::from_registers(registers);
        map.set_breakpoint_step_size(arch.breakpoint_step_size());
        Ok(map)
    }

    /// Read one register by its target-description number.
    fn read_one_register(&mut self, regnum: usize) -> Result<[u8; 8]> {
        let response = self.send_packet(&format!("p{regnum:x}"))?;
        if response.is_empty() || response.starts_with('E') {
            return Err(Error::Rsp(format!(
                "failed to read register {regnum}: {response}"
            )));
        }
        let bytes = hex::decode(&response)?;
        let mut value = [0u8; 8];
        let len = bytes.len().min(value.len());
        value[..len].copy_from_slice(&bytes[..len]);
        Ok(value)
    }

    fn resolve_xml_includes(&mut self, xml: &str) -> Result<String> {
        let mut result = xml.to_string();

        while let Some(start) = result.find("<xi:include") {
            let end = match result[start..].find("/>") {
                Some(e) => start + e + 2,
                None => break,
            };

            let element = &result[start..end];
            let href = RegisterMap::extract_attr(element, "href");

            if let Some(filename) = href {
                let included_xml = self.fetch_feature_file(filename)?;
                result = format!("{}{}{}", &result[..start], included_xml, &result[end..]);
            } else {
                result = format!("{}{}", &result[..start], &result[end..]);
            }
        }

        Ok(result)
    }

    fn fetch_feature_file(&mut self, filename: &str) -> Result<String> {
        let mut xml = String::new();
        let mut offset = 0;

        loop {
            let query = format!("qXfer:features:read:{}:{:x},fff", filename, offset);
            let response = self.send_packet(&query)?;

            if response.is_empty() {
                return Err(Error::NotSupported);
            }

            let (marker, data) = response.split_at(1);
            xml.push_str(data);
            offset += data.len();

            match marker {
                "l" => break,
                "m" => continue,
                _ => {
                    return Err(Error::Rsp(format!(
                        "unexpected qXfer response for {}: {}",
                        filename, response
                    )));
                }
            }
        }

        Ok(xml)
    }
}

impl DebugBackend for GdbClient {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn name(&self) -> &'static str {
        "gdb"
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

    /// A stub programs these with the processor's debug registers, so they
    /// trap on every processor and leave guest memory untouched.
    fn supports_watchpoints(&self) -> bool {
        true
    }

    fn set_hardware_breakpoint(
        &mut self,
        slot: u8,
        addr: u64,
        access: HwBreakpointAccess,
        len: u8,
    ) -> Result<()> {
        let site = HardwareSite {
            kind: hardware_packet_kind(access),
            addr,
            len,
        };
        GdbClient::set_hardware_site(self, slot, site)
    }

    fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
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
        Ok(StopReply::parse(&response).into_event())
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        let response = GdbClient::wait_for_stop(self)?;
        Ok(StopReply::parse(&response).into_event())
    }

    fn try_wait_for_stop(&mut self, timeout: Duration) -> Result<Option<StopEvent>> {
        self.stream.set_read_timeout(Some(timeout))?;
        let result = GdbClient::try_wait_for_stop(self);
        let _ = self.stream.set_read_timeout(None);
        Ok(result?.map(|response| StopReply::parse(&response).into_event()))
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        GdbClient::thread_list(self)
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        GdbClient::set_current_thread(self, thread_id)
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        GdbClient::stopped_thread_id(self)
    }

    fn is_running(&self) -> bool {
        self.is_running
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use super::{
        GdbClient, HW_BREAKPOINT_SLOTS, PacketReadState, RegisterMap, StopReply, StubFeatures,
        TargetArch,
    };
    use crate::dbg_backend::DebugBackend;

    /// A running target behind a stub that answers the break byte with a stop
    /// on `p01.02` and records every packet it is sent.
    fn running_client_over_recording_stub() -> (GdbClient, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&received);
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let reply = |stream: &mut TcpStream, body: &str| {
                let sum = body.bytes().fold(0u8, |a, b| a.wrapping_add(b));
                stream
                    .write_all(format!("${body}#{sum:02x}").as_bytes())
                    .unwrap();
            };
            let mut packet = Vec::new();
            let mut byte = [0u8];
            while stream.read_exact(&mut byte).is_ok() {
                match byte[0] {
                    0x03 => reply(&mut stream, "T02thread:p01.02;"),
                    b'$' => packet.clear(),
                    b'#' => {
                        let mut checksum = [0u8; 2];
                        stream.read_exact(&mut checksum).unwrap();
                        let body = String::from_utf8(packet.clone()).unwrap();
                        log.lock().unwrap().push(body.clone());
                        let answer = match body.as_str() {
                            "?" => "T05core:01;",
                            "qC" => "QCp01.01",
                            _ => "",
                        };
                        reply(&mut stream, answer);
                    }
                    other => packet.push(other),
                }
            }
        });
        let client = GdbClient {
            stream: TcpStream::connect(addr).unwrap(),
            features: StubFeatures::default(),
            rx_state: PacketReadState::default(),
            no_ack_mode: true,
            register_map: RegisterMap::default(),
            is_running: true,
            hardware_sites: [None; HW_BREAKPOINT_SLOTS as usize],
            extra_registers: Vec::new(),
            last_stop: String::new(),
            control_thread: None,
        };
        (client, received)
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
            "p01.02"
        );
        let halted = DebugBackend::try_wait_for_stop(&mut client, Duration::from_millis(10))
            .unwrap()
            .unwrap();
        assert!(halted.thread_id.is_none() && halted.watchpoint_address.is_none());
        DebugBackend::wait_for_stop(&mut client).unwrap();

        assert!(!received.lock().unwrap().iter().any(|packet| packet == "?"));
    }

    #[test]
    fn accepts_the_architectures_ntoseye_debugs() {
        let describe = |arch: &str| {
            TargetArch::from_description(&format!(
                "<target><architecture>{arch}</architecture></target>"
            ))
        };
        assert_eq!(describe("i386:x86-64").unwrap(), TargetArch::Amd64);
        assert_eq!(describe("aarch64").unwrap(), TargetArch::Arm64);
        // A 32-bit stub has no Windows kernel ntoseye can read.
        assert!(describe("i386").is_err());
        assert!(TargetArch::from_description("<target></target>").is_err());
    }

    #[test]
    fn decodes_escaped_and_run_length_packet_data() {
        let decoded = GdbClient::decode_packet_data(b"A* }\x03").unwrap();
        assert_eq!(decoded, b"AAAA#");
    }

    #[test]
    fn rejects_truncated_escape_sequences() {
        let err = GdbClient::decode_packet_data(b"}").unwrap_err();
        assert!(err.to_string().contains("truncated escaped packet data"));
    }

    #[test]
    fn parses_stub_features_from_qsupported() {
        let features = StubFeatures::parse(
            "PacketSize=1000;QStartNoAckMode+;multiprocess+;qXfer:features:read+",
        );
        assert!(features.no_ack_mode);
        assert!(features.qxfer_features_read);
    }

    #[test]
    fn parses_thread_and_watch_fields_from_a_stop_reply() {
        // QEMU's own shape: padded thread id, then the trapping address.
        let reply = StopReply::parse("T05thread:p01.02;watch:fffff80012345678;");
        assert_eq!(reply.thread_id.as_deref(), Some("p01.02"));
        assert_eq!(reply.watch_address, Some(0xffff_f800_1234_5678));
    }

    #[test]
    fn parses_read_and_access_watch_fields() {
        assert_eq!(
            StopReply::parse("T05thread:p01.01;rwatch:1000;").watch_address,
            Some(0x1000)
        );
        assert_eq!(
            StopReply::parse("T05thread:p01.01;awatch:1000;").watch_address,
            Some(0x1000)
        );
    }

    #[test]
    fn ignores_fields_that_are_not_a_thread_or_a_watch() {
        // The initial `?` reply names a core and no thread; register fields
        // are `<hex regnum>:<value>` and must not be mistaken for either.
        let reply = StopReply::parse("T05core:01;10:0000000000000000;");
        assert_eq!(reply, StopReply::default());
    }

    #[test]
    fn parses_stop_replies_that_describe_no_stopped_thread_as_empty() {
        // `S` carries no fields at all, and `W`/`X` report an exit.
        assert_eq!(StopReply::parse("S05"), StopReply::default());
        assert_eq!(StopReply::parse("W00"), StopReply::default());
    }
}
