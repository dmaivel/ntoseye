//! Each request answered: parsed, handed to the server, and its reply
//! written. A request the server does not know gets the empty reply, and a
//! known one whose fields do not read gets an error.

use std::fmt::Display;
use std::io;

use gdb_remote::Request;
use gdb_remote::features::{self, Feature, Support};
use gdb_remote::hex;
use gdb_remote::lldb::KeyValues;
use gdb_remote::reply::{
    BinaryUpload, ErrorCode, ResumeActions, Status, ThreadList, write_binary_memory,
    write_current_thread,
};
use gdb_remote::request::{ActionKind, ThreadOp};

use crate::arch::HwBreakpointAccess;
use crate::base::error::Result;

use super::connection::Connection;
use super::run_control::Resume;
use super::{PACKET_SIZE, Server};

/// The error number of a memory access that failed (`EFAULT`).
const EFAULT: u8 = 14;
/// The error number of a request whose fields do not read, or that names
/// what does not exist (`EINVAL`).
const EINVAL: u8 = 22;
/// The error number of anything else the target refused (`EREMOTEIO`).
const EREMOTEIO: u8 = 121;

/// Where the conversation is after a request.
pub(super) enum Flow {
    /// The target stays halted; the next request follows.
    Halted,
    /// The target was resumed; its stop is the next reply.
    Running,
    /// The client is done, for this reason.
    Leave(&'static str),
}

/// How the server answers a request.
enum Answer {
    Reply(Vec<u8>),
    Resume(Resume),
    /// End the session after `reply`, if the request has one.
    Leave(&'static str, Option<Vec<u8>>),
}

fn status_reply(status: Status<'_>) -> Vec<u8> {
    let mut reply = Vec::new();
    status.write(&mut reply);
    reply
}

fn status(status: Status<'_>) -> Answer {
    Answer::Reply(status_reply(status))
}

fn error(number: u8) -> Answer {
    status(Status::Error(ErrorCode::Number(number)))
}

/// `OK`, or the error `number` for a failure, which the server's console
/// explains as `what` (formatted only then).
fn done(result: Result<()>, number: u8, what: impl Display) -> Answer {
    match result {
        Ok(()) => status(Status::Ok),
        Err(failure) => {
            eprintln!("ntoseye-gdbserver: {what}: {failure}");
            error(number)
        }
    }
}

fn written(write: impl FnOnce(&mut Vec<u8>)) -> Answer {
    let mut reply = Vec::new();
    write(&mut reply);
    Answer::Reply(reply)
}

/// The features the server's `qSupported` reply lists.
fn supported() -> Vec<u8> {
    let size = format!("{PACKET_SIZE:x}");
    let mut list = vec![Feature {
        name: "PacketSize",
        support: Support::Value(&size),
    }];
    list.extend(
        [
            "vContSupported",
            "multiprocess",
            "QStartNoAckMode",
            "swbreak",
            "hwbreak",
            "qXfer:features:read",
            "qXfer:memory-map:read",
            "qXfer:exec-file:read",
            "qXfer:libraries:read",
            "qXfer:threads:read",
            "qXfer:osdata:read",
        ]
        .into_iter()
        .map(|name| Feature {
            name,
            support: Support::Yes,
        }),
    );
    let mut reply = Vec::new();
    features::write_list(&mut reply, &list);
    reply
}

impl Server<'_> {
    /// Answer the request `body`.
    pub(super) fn handle(&mut self, connection: &mut Connection, body: &[u8]) -> io::Result<Flow> {
        let request = match Request::parse(body) {
            Ok(request) => request,
            Err(malformed) => {
                eprintln!("ntoseye-gdbserver: {malformed}");
                connection.send(&status_reply(Status::Error(ErrorCode::Number(EINVAL))))?;
                return Ok(Flow::Halted);
            }
        };
        let no_ack = matches!(request, Request::StartNoAckMode);
        match self.answer(connection, request)? {
            Answer::Reply(reply) => {
                connection.send(&reply)?;
                if no_ack {
                    connection.stop_acknowledging();
                }
                Ok(Flow::Halted)
            }
            Answer::Resume(resume) => {
                self.resume(resume);
                Ok(Flow::Running)
            }
            Answer::Leave(reason, reply) => {
                if let Some(reply) = reply {
                    connection.send(&reply)?;
                }
                Ok(Flow::Leave(reason))
            }
        }
    }

    fn answer(&mut self, connection: &mut Connection, request: Request<'_>) -> io::Result<Answer> {
        Ok(match request {
            Request::Supported(features) => {
                self.multiprocess = features::supports(&features, "multiprocess");
                Answer::Reply(supported())
            }
            Request::StartNoAckMode | Request::ExtendedMode => {
                self.extended |= matches!(request, Request::ExtendedMode);
                status(Status::Ok)
            }
            Request::HaltReason => Answer::Reply(self.halt_reply()),
            Request::ReadRegisters => match self.read_registers() {
                Ok(wire) => written(|reply| hex::write_register(reply, &wire)),
                Err(failure) => done(Err(failure), EREMOTEIO, "reading registers"),
            },
            Request::WriteRegisters(wire) => {
                done(self.write_registers(&wire), EREMOTEIO, "writing registers")
            }
            Request::ReadRegister(regnum) => match self.read_register(regnum) {
                // lldb, the client that reads registers one at a time,
                // takes `xx` for bytes 0xcc and shows them as a value; an
                // error leaves the register out, as unavailable. Part of a
                // register unavailable is `xx`, as in `g`.
                Ok(Some(value)) if value.iter().all(Option::is_none) => error(EREMOTEIO),
                Ok(Some(value)) => written(|reply| hex::write_register(reply, &value)),
                Ok(None) => error(EINVAL),
                Err(failure) => done(Err(failure), EREMOTEIO, "reading a register"),
            },
            Request::WriteRegister { number, value } => done(
                self.write_register(number, &value),
                EREMOTEIO,
                "writing a register",
            ),
            Request::ReadMemory { address, length } => match self.read_memory(address, length) {
                Some(data) => written(|reply| hex::write_bytes(reply, &data)),
                None => error(EFAULT),
            },
            // LLDB's way, which needs no feature: GDB reads with `x` only
            // from a server advertising `binary-upload+`.
            Request::ReadMemoryBinary { address, length } => {
                match self.read_memory(address, length) {
                    Some(data) => {
                        written(|reply| write_binary_memory(reply, &data, BinaryUpload::Lldb))
                    }
                    None => error(EFAULT),
                }
            }
            Request::WriteMemory { address, data }
            | Request::WriteMemoryBinary { address, data } => {
                if data.is_empty() {
                    status(Status::Ok)
                } else {
                    done(
                        self.write_memory(address, &data),
                        EFAULT,
                        format_args!("writing memory at {address:#x}"),
                    )
                }
            }
            Request::InsertBreakpoint(breakpoint) => done(
                self.plant(&breakpoint),
                EREMOTEIO,
                format_args!("breakpoint at {:#x} refused", breakpoint.address),
            ),
            Request::RemoveBreakpoint(breakpoint) => done(
                self.unplant(&breakpoint),
                EREMOTEIO,
                format_args!("removing breakpoint at {:#x} failed", breakpoint.address),
            ),
            Request::SupportedActions => written(|reply| {
                ResumeActions::of(&[
                    ActionKind::Continue,
                    ActionKind::ContinueSignal,
                    ActionKind::Step,
                    ActionKind::StepSignal,
                ])
                .write(reply);
            }),
            Request::Resume(actions) => match self.resume_for(&actions) {
                Some(resume) => Answer::Resume(resume),
                None => error(EINVAL),
            },
            Request::Continue(None) => Answer::Resume(Resume::Continue),
            Request::Step(None) => Answer::Resume(Resume::Step(self.resume_index(None))),
            // Resuming elsewhere than where the thread stopped.
            Request::Continue(Some(_)) | Request::Step(Some(_)) => error(EINVAL),
            Request::SetThread { op, thread } => match self.resolve(thread) {
                Some(index) => {
                    match op {
                        ThreadOp::General => self.general_thread = index,
                        ThreadOp::Resume => self.resume_thread = index,
                    }
                    status(Status::Ok)
                }
                None => error(EINVAL),
            },
            Request::FirstThreads => {
                self.sync_threads();
                let threads = (0..self.threads.len())
                    .map(|index| self.thread_id(index))
                    .collect();
                written(|reply| {
                    ThreadList {
                        more: true,
                        threads,
                    }
                    .write(reply)
                })
            }
            Request::NextThreads => written(|reply| {
                ThreadList {
                    more: false,
                    threads: Vec::new(),
                }
                .write(reply);
            }),
            Request::CurrentThread => {
                let thread = self.thread_id(self.current_index());
                written(|reply| write_current_thread(reply, &thread))
            }
            Request::ThreadAlive(thread) => match self.resolve(thread) {
                Some(Some(_)) => status(Status::Ok),
                Some(None) | None => error(EINVAL),
            },
            Request::XferRead(read) => match self.xfer(&read) {
                Some(Ok(chunk)) => written(|reply| chunk.write(reply)),
                Some(Err(failure)) => done(Err(failure), EINVAL, "qXfer read"),
                None => status(Status::Unsupported),
            },
            Request::Monitor(command) => {
                let text = self.monitor(&command);
                connection.console(&text)?;
                status(Status::Ok)
            }
            Request::Offsets => written(|reply| self.offsets().write(reply)),
            // The target was there before the client: detaching must not
            // kill it.
            Request::Attached(_) => Answer::Reply(b"1".to_vec()),
            Request::Detach(_) if self.extended => {
                // Extended mode: the client stays connected, and may attach
                // again; the guest runs on, as after any detach.
                if self.forget_process() {
                    self.resume_guest();
                }
                status(Status::Ok)
            }
            Request::Detach(_) => Answer::Leave("detached", Some(b"OK".to_vec())),
            Request::Kill => Answer::Leave("killed the session (the guest keeps running)", None),
            Request::MustReplyEmpty => status(Status::Unsupported),
            Request::Attach(pid) => match self.attach(pid) {
                Ok(reply) => Answer::Reply(reply),
                Err(failure) => done(Err(failure), EREMOTEIO, "attach"),
            },
            // gdb's `kill` with `multiprocess+`, outside extended mode: the
            // client is done, as after `k`.
            Request::KillProcess(_) if !self.extended => Answer::Leave(
                "killed the session (the guest keeps running)",
                Some(b"OK".to_vec()),
            ),
            // Nothing is killed: the client forgets the process, and the
            // server its breakpoints and context. A breakpoint that could not
            // be removed fails the request, and stays the client's.
            Request::KillProcess(pid) if pid == self.pid => {
                if self.forget_process() {
                    status(Status::Ok)
                } else {
                    error(EREMOTEIO)
                }
            }
            Request::KillProcess(_) => error(EINVAL),
            Request::TibAddress(thread) => match self.resolve(thread) {
                Some(index) => {
                    let index = index.unwrap_or_else(|| self.current_index());
                    match self.tib_address(index) {
                        Some(Ok(address)) => written(|reply| hex::write_number(reply, address)),
                        Some(Err(failure)) => done(Err(failure), EREMOTEIO, "TIB address"),
                        None => status(Status::Unsupported),
                    }
                }
                None => error(EINVAL),
            },
            Request::HostInfo => written(|reply| self.target_info(false).write(reply)),
            Request::ProcessInfo => written(|reply| self.target_info(true).write(reply)),
            Request::MemoryRegionInfo(address) => {
                written(|reply| self.memory_region(address).write(reply))
            }
            Request::ThreadStopInfo(thread) => match self.thread_stop_reply(thread) {
                Some(reply) => Answer::Reply(reply),
                None => error(EINVAL),
            },
            Request::WatchpointSupportInfo => {
                let slots = self
                    .arch
                    .debug_registers()
                    .slots_for(HwBreakpointAccess::Write)
                    .len();
                let mut info = KeyValues::default();
                info.push("num", &slots.to_string());
                written(|reply| info.write(reply))
            }
            Request::File(file) => written(|reply| self.file(file).write(reply)),
            Request::Unknown(_) => status(Status::Unsupported),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::Duration;

    use gdb_remote::Request;
    use gdb_remote::features;
    use gdb_remote::frame::{Decoder, Frame};
    use gdb_remote::lldb::MemoryRegion;
    use gdb_remote::reply::XferChunk;
    use gdb_remote::xfer::Osdata;

    use super::super::connection::Connection;
    use super::super::run_control::Resume;
    use super::Flow;
    use crate::session::{Session, session_over_memory};

    use super::super::Server;

    /// Where the test session's one page of memory is.
    const PAGE: u64 = 0xffff_f800_0010_0000;

    struct Client {
        connection: Connection,
        peer: TcpStream,
    }

    impl Client {
        fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            peer.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            let (stream, _) = listener.accept().unwrap();
            let mut connection = Connection::new(stream, Arc::default()).unwrap();
            connection.stop_acknowledging();
            Self { connection, peer }
        }

        /// Send `request`; what the server did, and the packets it sent.
        fn ask(&mut self, server: &mut Server<'_>, request: &[u8]) -> (Flow, Vec<Vec<u8>>) {
            let flow = server.handle(&mut self.connection, request).unwrap();
            let mut decoder = Decoder::new();
            let mut packets = Vec::new();
            let mut buffer = [0u8; 0x10000];
            while let Ok(read @ 1..) = self.peer.read(&mut buffer) {
                packets.extend(
                    decoder
                        .decode(&buffer[..read])
                        .filter_map(|frame| match frame {
                            Frame::Packet(body) => Some(body),
                            _ => None,
                        }),
                );
            }
            (flow, packets)
        }

        /// The one reply to `request`.
        fn reply(&mut self, server: &mut Server<'_>, request: &[u8]) -> Vec<u8> {
            let (_, mut packets) = self.ask(server, request);
            assert_eq!(packets.len(), 1, "{packets:?}");
            packets.remove(0)
        }
    }

    fn session() -> Session {
        let memory: Vec<u8> = (0..0x1000u32).map(|n| n as u8).collect();
        session_over_memory(PAGE, &memory)
    }

    fn server(session: &mut Session) -> Server<'_> {
        Server::new(session, Arc::default(), Arc::default())
    }

    /// A request the server does not know gets the empty reply, which
    /// tells the client it is unsupported; a known one that does not read
    /// gets an error, not silence or a dropped connection.
    #[test]
    fn unknown_requests_are_empty_and_malformed_ones_errors() {
        let mut session = session();
        let mut server = server(&mut session);
        let mut client = Client::new();
        assert_eq!(client.reply(&mut server, b"qTStatus"), b"");
        assert_eq!(client.reply(&mut server, b"vMustReplyEmpty"), b"");
        assert_eq!(client.reply(&mut server, b"m10"), b"E16");
        assert_eq!(client.reply(&mut server, b"Z9,1,1"), b"E16");
    }

    /// A read running into unreadable memory returns what lies before it,
    /// so a client does not retry byte by byte; one that starts there
    /// fails. lldb's `x` returns the same bytes, raw.
    #[test]
    fn memory_reads_return_the_readable_prefix() {
        let mut session = session();
        let mut server = server(&mut session);
        let mut client = Client::new();
        let request = format!("m{:x},20", PAGE + 0xff0);
        assert_eq!(
            client.reply(&mut server, request.as_bytes()),
            b"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        );
        let past = format!("m{:x},4", PAGE + 0x1000);
        assert_eq!(client.reply(&mut server, past.as_bytes()), b"E0e");

        assert_eq!(client.reply(&mut server, b"x0,0"), b"OK");
        let binary = format!("x{:x},4", PAGE + 0x21);
        // `!"#$`: the last two escaped.
        assert_eq!(
            client.reply(&mut server, binary.as_bytes()),
            b"!\"}\x03}\x04"
        );
    }

    /// lldb asks what is at an address. In the hole between the canonical
    /// halves there is nothing: no permissions, and the region runs to the
    /// kernel half, so lldb's walk over regions moves on instead of failing.
    #[test]
    fn memory_regions_cover_the_gaps_without_permissions() {
        let mut session = session();
        let mut server = server(&mut session);
        let mut client = Client::new();
        let hole =
            MemoryRegion::parse(&client.reply(&mut server, b"qMemoryRegionInfo:900000000000"))
                .unwrap();
        assert_eq!(hole.start, 0x8000_0000_0000);
        assert_eq!(hole.size, 0xffff_8000_0000_0000 - 0x8000_0000_0000);
        assert_eq!(hole.permissions, None);
        let top =
            MemoryRegion::parse(&client.reply(&mut server, b"qMemoryRegionInfo:fffffffffffff800"))
                .unwrap();
        assert_eq!((top.start, top.size), (0xffff_ffff_ffff_f000, 0x1000));
        let kernel = MemoryRegion::parse(&client.reply(
            &mut server,
            format!("qMemoryRegionInfo:{PAGE:x}").as_bytes(),
        ))
        .unwrap();
        assert!(kernel.permissions.is_some_and(|allowed| allowed.read));
        assert!((kernel.start..kernel.start.wrapping_add(kernel.size)).contains(&PAGE));
    }

    /// Thread ids carry the process once the client negotiated
    /// `multiprocess+`, and not before: IDA reads only plain ones.
    #[test]
    fn thread_ids_follow_multiprocess() {
        let mut session = session();
        let mut server = server(&mut session);
        let mut client = Client::new();
        assert_eq!(client.reply(&mut server, b"?"), b"T05thread:1;");
        assert_eq!(client.reply(&mut server, b"qC"), b"QC1");
        let supported = client.reply(&mut server, b"qSupported:multiprocess+;swbreak+");
        let offered = features::parse_list(&supported).unwrap();
        for feature in ["multiprocess", "qXfer:osdata:read", "qXfer:threads:read"] {
            assert!(
                features::supports(&offered, feature),
                "{feature} not offered"
            );
        }
        // GDB reads memory with `x` only from a server offering this.
        assert!(!features::supports(&offered, "binary-upload"));
        assert_eq!(client.reply(&mut server, b"?"), b"T05thread:p1.1;");
        assert_eq!(client.reply(&mut server, b"qfThreadInfo"), b"mp1.1");
        assert_eq!(client.reply(&mut server, b"qsThreadInfo"), b"l");
    }

    /// A step naming no thread (Binary Ninja's `vCont;s`) steps the stopped
    /// vCPU; actions the server does not offer, or a thread that does not
    /// exist, are refused rather than run as something else.
    #[test]
    fn vcont_steps_one_thread_or_continues_all() {
        let mut session = session();
        let server = server(&mut session);
        let actions = |body: &[u8]| match Request::parse(body).unwrap() {
            Request::Resume(actions) => server.resume_for(&actions),
            other => panic!("{other:?}"),
        };
        assert_eq!(actions(b"vCont;s"), Some(Resume::Step(0)));
        assert_eq!(actions(b"vCont;c"), Some(Resume::Continue));
        assert_eq!(actions(b"vCont;s:1;c"), Some(Resume::Step(0)));
        assert_eq!(actions(b"vCont;s:9;c"), None);
        assert_eq!(actions(b"vCont;t"), None);
    }

    /// In extended mode a detach leaves the client connected, so it can
    /// attach again; otherwise the client is done.
    #[test]
    fn only_extended_mode_keeps_a_detached_client() {
        let mut session = session();
        let mut server = server(&mut session);
        let mut client = Client::new();
        assert!(matches!(client.ask(&mut server, b"D").0, Flow::Leave(_)));
        assert_eq!(client.reply(&mut server, b"!"), b"OK");
        let (flow, packets) = client.ask(&mut server, b"D;1");
        assert!(matches!(flow, Flow::Halted));
        assert_eq!(packets, [b"OK".to_vec()]);
    }

    /// gdb's `kill` with `multiprocess+` is `vKill`: outside extended mode
    /// the client is done with the session, as after `k`; in it, the client
    /// stays, and only the process it names can be killed.
    #[test]
    fn vkill_ends_the_session_only_outside_extended_mode() {
        let mut session = session();
        let mut server = server(&mut session);
        let mut client = Client::new();
        let (flow, packets) = client.ask(&mut server, b"vKill;1");
        assert!(matches!(flow, Flow::Leave(_)));
        assert_eq!(packets, [b"OK".to_vec()]);

        assert_eq!(client.reply(&mut server, b"!"), b"OK");
        assert_eq!(client.reply(&mut server, b"vKill;8"), b"E16");
        let (flow, packets) = client.ask(&mut server, b"vKill;1");
        assert!(matches!(flow, Flow::Halted));
        assert_eq!(packets, [b"OK".to_vec()]);
    }

    /// The objects that take no annex refuse one, rather than keeping a
    /// copy of themselves under every name a client sends.
    #[test]
    fn documents_without_annexes_refuse_one() {
        let mut session = session();
        let mut server = server(&mut session);
        let mut client = Client::new();
        assert_eq!(
            client.reply(&mut server, b"qXfer:memory-map:read:x:0,fff"),
            b"E16"
        );
        assert!(server.snapshots.is_empty());
        let whole = client.reply(&mut server, b"qXfer:memory-map:read::0,fff");
        assert!(XferChunk::parse(&whole).is_ok_and(|chunk| !chunk.data.is_empty()));
    }

    /// `info os` reads the table of tables, then `info os processes` the
    /// processes; an unknown table is an error.
    #[test]
    fn osdata_lists_its_tables() {
        let mut session = session();
        let mut server = server(&mut session);
        let mut client = Client::new();
        let reply = client.reply(&mut server, b"qXfer:osdata:read::0,fff");
        let chunk = XferChunk::parse(&reply).unwrap();
        assert!(!chunk.more);
        let types = Osdata::parse(std::str::from_utf8(&chunk.data).unwrap()).unwrap();
        assert_eq!(types.kind, "types");
        assert_eq!(
            types
                .items
                .iter()
                .map(|item| item.column("Type"))
                .collect::<Vec<_>>(),
            [Some("processes")]
        );
        assert_eq!(
            client.reply(&mut server, b"qXfer:osdata:read:files:0,fff"),
            b"E16"
        );
    }
}
