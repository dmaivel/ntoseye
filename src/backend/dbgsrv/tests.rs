//! The DbgRpc client against a process server that speaks the bytes itself:
//! the handshake, every call the client makes, and the debug events it is
//! handed.
//!
//! The fake server reads and writes the wire by offset, the way the C server
//! does, rather than through [`super::layout`]: a client bug in a layout must
//! fail here, not be mirrored by the fixture.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use zerocopy::FromBytes;

use crate::arch::Arch;
use crate::base::error::{Error, Result};
use crate::base::ntstatus::STATUS_BREAKPOINT;

use super::backend::{DbgsrvBackend, DbgsrvTarget};
use super::client::DbgSrvClient;
use super::events::{DEBUG_EVENT_SIZE, DebugEventName, ExceptionDebugInfo, ExceptionRecord64};
use super::layout;
use super::service::{
    CLOSE_PROC_THREAD_HANDLES, DEBUG_PROCESS_ONLY_THIS_PROCESS, GENERIC_CODE_BREAKPOINTS,
    GENERIC_DATA_BREAKPOINTS, ProcessServer, TargetInfo, ThreadRecord,
};
use super::wire::{
    CALL_RETURN, Call, Handshake, IID_USER_DEBUG_SERVICES, PROTOCOL_VERSION, SIGNATURE, method,
    stub_index,
};

/// The object id the fake server hands out in its handshake.
const OBJECT: u64 = 0xdead_beef;
/// The fake process id.
pub(crate) const PID: u32 = 42;
/// The fake process handle.
const PROCESS: u64 = 0x1000;
/// The fake thread id and handle.
pub(crate) const TID: u32 = 0x1234;
const THREAD: u64 = 0x2000;
/// Where the fake process's `_PEB` and the thread's `_TEB` are.
const PEB: u64 = 0x7ff0_0000;
const TEB: u64 = 0x7ff0_1000;
/// The fake `CONTEXT`'s instruction pointer, and where the socket maps it.
pub(crate) const RIP: u64 = 0x0040_1000;

/// A `CONTEXT` the fake server hands back: only the instruction pointer is
/// set, which is what the backend reads.
fn fake_context(arch: Arch) -> Vec<u8> {
    let mut context = vec![0u8; arch.context_size()];
    let layout = arch.register_map();
    let flags = arch.context_flags();
    context[flags.offset..flags.offset + 4].copy_from_slice(&flags.all.to_le_bytes());
    let _ = layout.write_u64(arch.pc_register(), &mut context, RIP);
    context
}

/// One `DEBUG_EVENT` for `code`, holding `payload` in its union.
fn debug_event(code: u32, process_id: u32, thread_id: u32, payload: &[u8]) -> Vec<u8> {
    let name = DebugEventName {
        code,
        process_id,
        thread_id,
        alignment: 0,
    };
    let mut bytes = vec![0u8; DEBUG_EVENT_SIZE];
    bytes[..16].copy_from_slice(zerocopy::IntoBytes::as_bytes(&name));
    let at = 16;
    bytes[at..at + payload.len()].copy_from_slice(payload);
    bytes
}

/// The exception event the fake server reports for a breakpoint.
fn breakpoint_event() -> Vec<u8> {
    let mut parameters = [0u64; 15];
    parameters[0] = 0;
    let info = ExceptionDebugInfo {
        record: ExceptionRecord64 {
            code: STATUS_BREAKPOINT,
            flags: 0,
            record: 0,
            address: RIP,
            number_parameters: 0,
            alignment: 0,
            parameters,
        },
        first_chance: 1,
        alignment: 0,
    };
    debug_event(
        super::events::EXCEPTION_DEBUG_EVENT,
        PID,
        TID,
        zerocopy::IntoBytes::as_bytes(&info),
    )
}

/// Every call a client made, as `(stub index, request body)`, shared with the
/// test that drives it.
type CallLog = Arc<Mutex<Vec<(u16, Vec<u8>)>>>;

/// Every `CONTEXT` a client wrote, as `(thread handle, context)`, shared with
/// the test that reads the debug registers back.
type ContextLog = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;

/// The fake process server, and what it answers.
pub(crate) struct FakeServer {
    /// Bytes the client may read through `ReadVirtual`, by address.
    memory: Mutex<HashMap<u64, u8>>,
    /// The event queue `WaitForEvent` hands out, in order.
    events: Mutex<Vec<Vec<u8>>>,
    /// Every call the client made, as `(stub index, request body)`.
    pub(crate) calls: CallLog,
    /// Set when the client asks for a break-in.
    break_in: Arc<AtomicBool>,
    /// The `DBGSVC_*` flags `Initialize` reports.
    flags: u32,
    /// Whether the server implements code breakpoints or the client patches
    /// them (`DBGSVC_GENERIC_CODE_BREAKPOINTS`).
    generic_code_breakpoints: bool,
    /// Whether `InsertCodeBreakpoint` was called.
    inserted: Arc<AtomicBool>,
    /// Every `CONTEXT` the client wrote, by the thread handle it named.
    contexts: ContextLog,
}

impl FakeServer {
    pub(crate) fn new(arch: Arch) -> Self {
        let mut memory = HashMap::new();
        for (offset, byte) in b"hello, memory".iter().enumerate() {
            memory.insert(RIP + offset as u64, *byte);
        }
        let _ = arch;
        Self {
            memory: Mutex::new(memory),
            events: Mutex::new(vec![
                // The process's creation is the stop an attach lands on.
                debug_event(
                    super::events::CREATE_PROCESS_DEBUG_EVENT,
                    PID,
                    TID,
                    zerocopy::IntoBytes::as_bytes(&super::events::CreateProcessDebugInfo {
                        file: 0,
                        process_handle: PROCESS,
                        thread_handle: THREAD,
                        image_base: 0x0040_0000,
                        debug_info_offset: 0,
                        debug_info_size: 0,
                        teb: TEB,
                        start_address: RIP,
                        image_name: 0,
                        image_name_wide: 0,
                        alignment: [0; 6],
                    }),
                ),
                breakpoint_event(),
            ]),
            calls: Arc::new(Mutex::new(Vec::new())),
            break_in: Arc::new(AtomicBool::new(false)),
            flags: CLOSE_PROC_THREAD_HANDLES | GENERIC_DATA_BREAKPOINTS | GENERIC_CODE_BREAKPOINTS,
            generic_code_breakpoints: true,
            inserted: Arc::new(AtomicBool::new(false)),
            contexts: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn with_generic_code_breakpoints(mut self, generic: bool) -> Self {
        if generic {
            self.flags |= GENERIC_CODE_BREAKPOINTS;
        } else {
            self.flags &= !GENERIC_CODE_BREAKPOINTS;
        }
        self.generic_code_breakpoints = generic;
        self
    }

    /// The reply body for one call, filled to `out_size` bytes.
    fn reply(&self, stub: u16, body: &[u8], out_size: usize) -> Vec<u8> {
        let called = stub & 0xff;
        let mut out = vec![0u8; out_size];
        let u32_at = |bytes: &[u8], at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let u64_at = |bytes: &[u8], at: usize| {
            let mut value = [0u8; 8];
            value.copy_from_slice(&bytes[at..at + 8]);
            u64::from_le_bytes(value)
        };
        match called {
            // QueryInterface: the revision must be the one this client
            // speaks, and the reply names the object the calls go to.
            method::QUERY_INTERFACE => {
                assert_eq!(
                    body.len(),
                    core::mem::size_of::<super::wire::Guid>()
                        + core::mem::size_of::<layout::InterfaceVersion>(),
                    "IID + revision code"
                );
                assert_eq!(
                    u32_at(body, core::mem::size_of::<super::wire::Guid>()),
                    super::wire::UNIQUE_USER_DEBUG_SERVICES,
                    "the client's revision"
                );
                out[0..8].copy_from_slice(&OBJECT.to_le_bytes());
            }
            // Initialize.
            method::INITIALIZE => out[0..4].copy_from_slice(&self.flags.to_le_bytes()),
            // GetConnectionInfo: the machine name, then the transport, as
            // UTF-16 with no trailer.
            method::GET_CONNECTION_INFO => {
                let mut write = |at: usize, text: &str| {
                    for (index, unit) in text.encode_utf16().enumerate() {
                        let offset = at + index * 2;
                        if offset + 2 <= out.len() {
                            out[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
                        }
                    }
                };
                write(0, "TESTBOX");
                write(16, "");
                write(16, "tcp");
            }
            // GetTargetInfo: eight ULONGs, the two (empty) version strings,
            // then three more.
            method::GET_TARGET_INFO => {
                for (index, value) in [0x8664u32, 32, 2, 10, 0, 26_100, 0, 0, 1, 0x100, 0]
                    .into_iter()
                    .enumerate()
                {
                    out[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
                }
            }
            // GetProcessIds.
            method::GET_PROCESS_IDS => {
                let count = u32_at(body, 0) as usize;
                out[0..4].copy_from_slice(&PID.to_le_bytes());
                let actual = count * 4;
                out[actual..actual + 4].copy_from_slice(&1u32.to_le_bytes());
            }
            // GetProcessInfo: handle, then the 16-aligned thread array, then
            // the count.
            method::GET_PROCESS_INFO => {
                let count = u32_at(
                    body,
                    core::mem::offset_of!(layout::GetProcessInfoArgs, info_count),
                ) as usize;
                out[0..8].copy_from_slice(&PROCESS.to_le_bytes());
                // The array starts on a 16-byte boundary, after the handle.
                let at = 16;
                out[at..at + 8].copy_from_slice(&THREAD.to_le_bytes());
                out[at + 8..at + 12].copy_from_slice(&TID.to_le_bytes());
                let record = core::mem::size_of::<layout::UserThreadInfo>();
                let actual = at + count * record;
                out[actual..actual + 4].copy_from_slice(&1u32.to_le_bytes());
            }
            // AttachProcess.
            method::ATTACH_PROCESS => {
                out[0..8].copy_from_slice(&PROCESS.to_le_bytes());
                out[8..12].copy_from_slice(&DEBUG_PROCESS_ONLY_THIS_PROCESS.to_le_bytes());
            }
            // CreateProcessW.
            method::CREATE_PROCESS_W => {
                out[0..4].copy_from_slice(&PID.to_le_bytes());
                out[4..8].copy_from_slice(&TID.to_le_bytes());
                out[8..16].copy_from_slice(&PROCESS.to_le_bytes());
                out[16..24].copy_from_slice(&THREAD.to_le_bytes());
            }
            // GetProcessExitCode.
            method::GET_PROCESS_EXIT_CODE => out[0..4].copy_from_slice(&0u32.to_le_bytes()),
            // GetProcessDebugObject.
            method::GET_PROCESS_DEBUG_OBJECT => out[0..8].copy_from_slice(&0x5000u64.to_le_bytes()),
            // ReadVirtual, QueryVirtual: the buffer, then the byte count.
            method::READ_VIRTUAL | method::QUERY_VIRTUAL => {
                let address = u64_at(body, 8);
                let size = u32_at(body, 16) as usize;
                let memory = self.memory.lock().unwrap();
                for (offset, byte) in out[..size].iter_mut().enumerate() {
                    *byte = memory.get(&(address + offset as u64)).copied().unwrap_or(0);
                }
                let at = (size + 3) & !3;
                out[at..at + 4].copy_from_slice(&(size as u32).to_le_bytes());
            }
            // WriteVirtual.
            method::WRITE_VIRTUAL => {
                let size = u32_at(body, 16) as usize;
                let mut memory = self.memory.lock().unwrap();
                let address = u64_at(body, 8);
                for offset in 0..size {
                    memory.insert(address + offset as u64, body[20 + offset]);
                }
                out[0..4].copy_from_slice(&(size as u32).to_le_bytes());
            }
            // SuspendThreads, ResumeThreads.
            method::SUSPEND_THREADS | method::RESUME_THREADS => {
                let count = u32_at(body, 0) as usize;
                for index in 0..count {
                    out[index * 4..index * 4 + 4].copy_from_slice(&1u32.to_le_bytes());
                }
            }
            // GetThreadBasicInfo: `_DEBUG_THREAD_BASIC_INFORMATION`, whose
            // start offset is the thread's start address.
            method::GET_THREAD_BASIC_INFO => {
                let at = core::mem::offset_of!(layout::ThreadBasicInformation, start_offset);
                out[at..at + 8].copy_from_slice(&RIP.to_le_bytes());
            }
            method::GET_PROCESS_DATA_OFFSET => out[0..8].copy_from_slice(&PEB.to_le_bytes()),
            method::GET_THREAD_DATA_OFFSET => out[0..8].copy_from_slice(&TEB.to_le_bytes()),
            // GetContext.
            method::GET_CONTEXT => {
                let size = u32_at(body, 16) as usize;
                let context = fake_context(Arch::Amd64);
                out[..context.len()].copy_from_slice(&context);
                let at = (size + 3) & !3;
                out[at..at + 4].copy_from_slice(&(context.len() as u32).to_le_bytes());
            }
            // SetContext: keep the thread and the context, which a test reads
            // the debug registers back from.
            method::SET_CONTEXT => {
                let size = u32_at(body, 8) as usize;
                let thread = u64_at(body, 0);
                let context = body
                    .get(core::mem::size_of::<layout::HandleArg>() + 4..)
                    .map(|bytes| bytes[..size.min(bytes.len())].to_vec())
                    .unwrap_or_default();
                self.contexts.lock().unwrap().push((thread, context));
                out[0..4].copy_from_slice(&(size as u32).to_le_bytes());
            }
            // WaitForEvent: the event, then the bytes it used.
            method::WAIT_FOR_EVENT => {
                let size = u32_at(body, 4) as usize;
                let event = {
                    let mut events = self.events.lock().unwrap();
                    if events.is_empty() {
                        None
                    } else {
                        Some(events.remove(0))
                    }
                };
                match event {
                    Some(event) => {
                        let used = event.len().min(size);
                        out[..used].copy_from_slice(&event[..used]);
                        let at = (size + 3) & !3;
                        out[at..at + 4].copy_from_slice(&(used as u32).to_le_bytes());
                    }
                    // S_FALSE: a timeout.
                    None => return Vec::new(),
                }
            }
            // InsertCodeBreakpoint.
            method::INSERT_CODE_BREAKPOINT => {
                self.inserted.store(true, Ordering::SeqCst);
                // A storage blob the client hands back on removal.
                for (index, byte) in out.iter_mut().enumerate() {
                    *byte = index as u8;
                }
            }
            // GetLastDataBreakpointHit.
            method::GET_LAST_DATA_BREAKPOINT_HIT => {
                out[0..8].copy_from_slice(&RIP.to_le_bytes());
                out[8..12].copy_from_slice(&1u32.to_le_bytes());
            }
            // Everything else (DetachProcess, CloseHandle, ContinueEvent,
            // RemoveCodeBreakpoint, the option setters) has an empty reply.
            _ => {
                assert!(
                    out_size == 0
                        || matches!(
                            called,
                            method::CLOSE_HANDLE
                                | method::SET_PROCESS_OPTIONS
                                | method::SET_DEBUG_OBJECT_OPTIONS
                        ),
                    "the fake server has no reply for method {called} (stub {stub:#x})"
                );
            }
        }
        out
    }
}

/// Serve one client connection of `server`.
pub(crate) fn serve(listener: TcpListener, server: Arc<FakeServer>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a client connects");
        // The handshake, then the fixed-length identity that follows it.
        let mut handshake = vec![0u8; core::mem::size_of::<Handshake>()];
        stream.read_exact(&mut handshake).expect("a handshake");
        let handshake = Handshake::read_from_bytes(&handshake).expect("a handshake decodes");
        assert_eq!(handshake.signature, SIGNATURE);
        assert_eq!(handshake.protocol_version, PROTOCOL_VERSION);
        assert_eq!(handshake.desired_object, IID_USER_DEBUG_SERVICES);
        let mut identity = vec![0u8; handshake.identity_length as usize];
        stream.read_exact(&mut identity).expect("an identity");
        let reply = Handshake {
            remote_object: OBJECT,
            ..handshake
        };
        stream
            .write_all(zerocopy::IntoBytes::as_bytes(&reply))
            .expect("the handshake reply");
        loop {
            let mut header = vec![0u8; core::mem::size_of::<Call>()];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            let call = Call::read_from_bytes(&header).expect("a call header decodes");
            let mut body = vec![0u8; call.in_size as usize];
            if !body.is_empty() {
                stream.read_exact(&mut body).expect("a call body");
            }
            server
                .calls
                .lock()
                .unwrap()
                .push((call.stub_index, body.clone()));
            if call.stub_index & 0xff == method::REQUEST_BREAK_IN {
                server.break_in.store(true, Ordering::SeqCst);
            }
            if call.flags & super::wire::CALL_NO_RETURN != 0 {
                continue;
            }
            let out = server.reply(call.stub_index, &body, call.out_size as usize);
            let reply = Call {
                object_id: call.object_id,
                stub_index: call.stub_index,
                flags: CALL_RETURN,
                in_size: 0,
                out_size: out.len() as u32,
                status: 0,
                sequence: call.sequence,
                reserved1: 0,
            };
            stream
                .write_all(zerocopy::IntoBytes::as_bytes(&reply))
                .expect("a reply header");
            if !out.is_empty() {
                stream.write_all(&out).expect("a reply body");
            }
        }
    })
}

/// The endpoint string of `listener`.
pub(crate) fn endpoint(listener: &TcpListener) -> String {
    let address = listener.local_addr().expect("a bound address");
    format!("tcp:server=127.0.0.1,port={}", address.port())
}

/// A client connected to a fake server, with the thread serving it.
fn connect(server: Arc<FakeServer>) -> (DbgSrvClient, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let endpoint = endpoint(&listener);
    let handle = serve(listener, Arc::clone(&server));
    let client = DbgSrvClient::connect(&endpoint, &mut |_| {}).expect("a connection");
    (client, handle)
}

#[test]
fn the_handshake_and_call_header_are_the_proxys_bytes() {
    let handshake = Handshake::client(IID_USER_DEBUG_SERVICES);
    let bytes = zerocopy::IntoBytes::as_bytes(&handshake);
    assert_eq!(bytes.len(), 128, "sizeof(DbgRpcHandshake)");
    // `'CPRD'` as a multi-character `ULONG` is `0x43505244`, which a
    // little-endian write turns into "DRPC". Captured from `cdb` 10.0.26100
    // against `dbgsrv` of the same build, which the server accepts.
    assert_eq!(&bytes[0..4], b"DRPC");
    assert_eq!(&bytes[4..8], &2u32.to_le_bytes(), "protocol version");
    // `IID_IUserDebugServices` in Windows' GUID layout: `a7ba24c4-e4fb-4625-
    // a8fc-b1cb1fd51f53`, its first three fields little-endian.
    assert_eq!(
        &bytes[8..24],
        &[
            0xc4, 0x24, 0xba, 0xa7, 0xfb, 0xe4, 0x25, 0x46, 0xa8, 0xfc, 0xb1, 0xcb, 0x1f, 0xd5,
            0x1f, 0x53,
        ]
    );
    assert_eq!(&bytes[24..32], &0u64.to_le_bytes(), "remote object unknown");
    assert_eq!(&bytes[32..36], &128u32.to_le_bytes(), "identity length");
    assert_eq!(&bytes[36..40], &0u32.to_le_bytes(), "no password");
    // `DBGRPC_SHAKE_FULL_REMOTE_UNKNOWN` plus the bit `cdb` also sets.
    assert_eq!(&bytes[40..44], &3u32.to_le_bytes(), "client flags");

    let call = Call {
        object_id: 0x1122_3344_5566_7788,
        stub_index: 0xc019,
        flags: super::wire::CALL_LOCKED,
        in_size: 20,
        out_size: 8,
        status: 0,
        sequence: 7,
        reserved1: 0,
    };
    let bytes = zerocopy::IntoBytes::as_bytes(&call);
    assert_eq!(bytes.len(), 32, "sizeof(DbgRpcCall)");
    assert_eq!(
        bytes,
        &[
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // ObjectId
            0x19, 0xc0, // StubIndex
            0x04, 0x00, // Flags (DBGRPC_LOCKED)
            0x14, 0x00, 0x00, 0x00, // InSize
            0x08, 0x00, 0x00, 0x00, // OutSize
            0x00, 0x00, 0x00, 0x00, // Status
            0x07, 0x00, 0x00, 0x00, // Sequence
            0x00, 0x00, 0x00, 0x00, // Reserved1
        ]
    );
}

#[test]
fn a_client_attaches_reads_memory_and_takes_a_breakpoint_stop() {
    use crate::backend::dbg_backend::DebugBackend;

    let server = Arc::new(FakeServer::new(Arch::Amd64));
    let (client, handle) = connect(Arc::clone(&server));
    let client = Arc::new(client);
    assert_eq!(client.arch(), Arch::Amd64);
    assert!(client.generic_code_breakpoints());
    assert!(client.closes_handles());

    let mut backend = super::backend::DbgsrvBackend::connect(
        Arc::clone(&client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    assert_eq!(backend.pid(), PID);
    assert_eq!(backend.process_handle(), PROCESS);
    let live = backend.live_process();
    assert_eq!(live.peb, PEB);
    assert_eq!(live.threads.len(), 1);
    assert_eq!(live.threads[0].tid, TID);
    assert_eq!(live.threads[0].teb, TEB);
    assert_eq!(live.selected_tid, Some(TID));
    // The attach stopped at the process's creation.
    assert!(!backend.is_running());
    assert_eq!(
        backend.thread_list().unwrap(),
        vec![DbgsrvBackend::backend_thread_id(TID)]
    );

    // Every thread's registers come back as a `CONTEXT` whose pc the socket
    // named.
    let registers = backend.read_registers().expect("a context");
    let map = backend.register_map().clone();
    assert_eq!(map.read_u64("rip", &registers).unwrap(), RIP);

    // Memory is the process's, through the server.
    let mut buf = [0u8; 13];
    client.read_virtual(PROCESS, RIP, &mut buf).expect("a read");
    assert_eq!(&buf, b"hello, memory");

    // A generic-code site is patched into the process by the debugger, and
    // the server's own breakpoint call is never made.
    backend.set_breakpoint(RIP).expect("a patched site");
    assert!(!server.inserted.load(Ordering::SeqCst));
    let mut patched = [0u8; 1];
    client.read_virtual(PROCESS, RIP, &mut patched).unwrap();
    assert_eq!(patched[0], 0xcc, "int3");
    backend.remove_breakpoint(RIP).expect("the site lifted");
    client.read_virtual(PROCESS, RIP, &mut patched).unwrap();
    assert_eq!(patched[0], b'h');

    // Running reaches the exception the server queued.
    backend.continue_execution().expect("a resume");
    assert!(backend.is_running());
    let stop = backend.wait_for_stop().expect("a stop");
    assert!(!backend.is_running());
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert_eq!(stop.first_chance, Some(true));
    assert_eq!(stop.thread_id.as_deref(), Some("1234"));
    assert_eq!(stop.program_counter, Some(RIP));

    // While stopped, the stop is what an interrupt answers with.
    let again = backend.interrupt().expect("the kept stop");
    assert_eq!(again.exception_code, stop.exception_code);

    // Leaving puts the process back and detaches.
    backend.prepare_for_exit(false).expect("a detach");
    drop(backend);
    // The connection is one per server here: the test's own handle must go
    // before the server thread sees the end of the stream.
    drop(client);
    handle.join().expect("the server thread");
    let calls = server.calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .any(|(stub, _)| *stub == stub_index(method::DETACH_PROCESS)),
        "DetachProcess"
    );
    assert!(
        calls
            .iter()
            .any(|(stub, _)| *stub == stub_index(method::CONTINUE_EVENT)),
        "ContinueEvent"
    );
}

#[test]
fn a_server_that_implements_code_breakpoints_gets_the_breakpoint_calls() {
    use crate::backend::dbg_backend::DebugBackend;

    let server = Arc::new(FakeServer::new(Arch::Amd64).with_generic_code_breakpoints(false));
    let (client, handle) = connect(Arc::clone(&server));
    let mut backend = super::backend::DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    assert!(!backend.client().generic_code_breakpoints());
    backend.set_breakpoint(RIP).expect("a server site");
    assert!(server.inserted.load(Ordering::SeqCst));
    backend.remove_breakpoint(RIP).expect("the site lifted");
    backend.prepare_for_exit(false).expect("a detach");
    drop(backend);
    handle.join().expect("the server thread");
    let calls = server.calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .any(|(stub, _)| *stub == stub_index(method::INSERT_CODE_BREAKPOINT)),
        "InsertCodeBreakpoint"
    );
    assert!(
        calls
            .iter()
            .any(|(stub, _)| *stub == stub_index(method::REMOVE_CODE_BREAKPOINT)),
        "RemoveCodeBreakpoint"
    );
}

#[test]
fn interrupting_a_running_process_asks_the_server_to_break_in() {
    use crate::backend::dbg_backend::DebugBackend;

    // Only the process's creation is queued: the interrupt has to ask the
    // server to break the process in before anything else arrives.
    let server = Arc::new(FakeServer::new(Arch::Amd64));
    server.events.lock().unwrap().pop();
    let (client, handle) = connect(Arc::clone(&server));
    let mut backend = super::backend::DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    backend.continue_execution().expect("a resume");
    assert!(backend.is_running());
    // The break-in lands as the exception it raises.
    server.events.lock().unwrap().push(breakpoint_event());
    let stop = backend.interrupt().expect("a break-in stop");
    assert!(!backend.is_running());
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert!(server.break_in.load(Ordering::SeqCst));
    let _ = backend.prepare_for_exit(false);
    drop(backend);
    handle.join().expect("the server thread");
}

/// `Create` starts the process under the debugger and reads its creation as
/// the initial stop.
#[test]
fn creating_a_process_uses_the_create_call_and_its_creation_stop() {
    let server = Arc::new(FakeServer::new(Arch::Amd64));
    {
        let mut events = server.events.lock().unwrap();
        events.clear();
        events.push(debug_event(
            super::events::CREATE_PROCESS_DEBUG_EVENT,
            PID,
            TID,
            zerocopy::IntoBytes::as_bytes(&super::events::CreateProcessDebugInfo {
                file: 0,
                process_handle: PROCESS,
                thread_handle: THREAD,
                image_base: 0x0040_0000,
                debug_info_offset: 0,
                debug_info_size: 0,
                teb: TEB,
                start_address: RIP,
                image_name: 0,
                image_name_wide: 0,
                alignment: [0; 6],
            }),
        ));
    }
    let (client, _handle) = connect(Arc::clone(&server));
    let backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Create {
            command_line: "notepad.exe".to_string(),
        },
        &mut |_| {},
    )
    .expect("a create");
    assert_eq!(backend.pid(), PID);
    let calls = server.calls.lock().unwrap();
    let create = calls
        .iter()
        .find(|(stub, _)| *stub == stub_index(method::CREATE_PROCESS_W))
        .expect("CreateProcessW");
    // The request is the command line, then `_DEBUG_CREATE_PROCESS_OPTIONS`
    // (whose first field carries the flags), then the current directory and
    // the environment as length-prefixed UTF-16 — both empty here.
    let body = &create.1;
    let utf16_length = {
        let mut length = 0;
        while u16::from_le_bytes([body[length], body[length + 1]]) != 0 {
            length += 2;
        }
        length + 2
    };
    assert_eq!(
        &body[..utf16_length],
        &"notepad.exe"
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()[..]
    );
    let options = &body[utf16_length..];
    assert_eq!(options.len(), 16 + 4 + 4, "options, then two empty strings");
    assert_eq!(
        u32::from_le_bytes([options[0], options[1], options[2], options[3]]),
        DEBUG_PROCESS_ONLY_THIS_PROCESS,
        "CreateFlags"
    );
    assert!(
        options[4..16].iter().all(|byte| *byte == 0),
        "no engine or verifier flags"
    );
    assert!(
        options[16..].iter().all(|byte| *byte == 0),
        "no current directory and no environment block"
    );
}

#[test]
fn a_server_that_refuses_the_handshake_is_reported_by_name() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let endpoint = endpoint(&listener);
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a client");
        let mut handshake = vec![0u8; 128];
        stream.read_exact(&mut handshake).expect("a handshake");
        let mut identity = vec![0u8; 128];
        stream.read_exact(&mut identity).expect("an identity");
        // A different protocol version: the client must refuse it.
        let mut reply = vec![0u8; 128];
        reply[0..4].copy_from_slice(super::wire::SIGNATURE.as_slice());
        reply[4..8].copy_from_slice(&3u32.to_le_bytes());
        stream.write_all(&reply).expect("a reply");
    });
    let error = DbgSrvClient::connect(&endpoint, &mut |_| {}).expect_err("a version mismatch");
    assert!(error.to_string().contains("version mismatch"), "{error}");
    handle.join().expect("the server thread");
}

/// The mock server the logic tests drive directly.
struct MockServer {
    info: TargetInfo,
    threads: Vec<ThreadRecord>,
    inserted: bool,
    break_in: bool,
    resumed: bool,
}

impl ProcessServer for MockServer {
    fn initialize(&mut self) -> Result<u32> {
        Ok(GENERIC_CODE_BREAKPOINTS | GENERIC_DATA_BREAKPOINTS)
    }
    fn connection_info(&mut self) -> Result<super::service::ConnectionInfo> {
        Ok(super::service::ConnectionInfo {
            machine: "TESTBOX".to_string(),
            transport: "tcp".to_string(),
        })
    }
    fn uninitialize(&mut self, _global: bool) -> Result<()> {
        Ok(())
    }
    fn target_info(&mut self) -> Result<TargetInfo> {
        Ok(self.info)
    }
    fn process_ids(&mut self) -> Result<Vec<u32>> {
        Ok(vec![PID])
    }
    fn process_info(
        &mut self,
        _pid: u32,
        _flags: u32,
        count: u32,
    ) -> Result<(u64, Vec<ThreadRecord>, u32)> {
        let total = self.threads.len() as u32;
        let threads = self.threads.iter().copied().take(count as usize).collect();
        Ok((PROCESS, threads, total))
    }
    fn attach_process(
        &mut self,
        _pid: u32,
        _flags: u32,
    ) -> Result<super::service::AttachedProcess> {
        Ok(super::service::AttachedProcess {
            handle: PROCESS,
            options: 0,
        })
    }
    fn detach_process(&mut self, _pid: u32) -> Result<()> {
        Ok(())
    }
    fn create_process(
        &mut self,
        _command_line: &str,
        _flags: u32,
        _inherit_handles: bool,
        _current_dir: Option<&str>,
    ) -> Result<super::service::CreatedProcess> {
        Ok(super::service::CreatedProcess {
            pid: PID,
            tid: TID,
            process_handle: PROCESS,
            thread_handle: THREAD,
        })
    }
    fn process_exit_code(&mut self, _process: u64) -> Result<u32> {
        Ok(0)
    }
    fn close_handle(&mut self, _handle: u64) -> Result<()> {
        Ok(())
    }
    fn set_process_options(&mut self, _process: u64, _options: u32) -> Result<()> {
        Ok(())
    }
    fn set_debug_object_options(&mut self, _object: u64, _options: u32) -> Result<()> {
        Ok(())
    }
    fn process_debug_object(&mut self, _process: u64) -> Result<u64> {
        Ok(0)
    }
    fn read_virtual(&mut self, _process: u64, address: u64, buf: &mut [u8]) -> Result<usize> {
        for (index, byte) in buf.iter_mut().enumerate() {
            *byte = (address as usize + index) as u8;
        }
        Ok(buf.len())
    }
    fn write_virtual(&mut self, _process: u64, _address: u64, buf: &[u8]) -> Result<usize> {
        Ok(buf.len())
    }
    fn query_virtual(
        &mut self,
        _process: u64,
        _address: u64,
        _size: u32,
    ) -> Result<(Vec<u8>, u32)> {
        Ok((
            vec![0; crate::backend::userlive::MemoryBasicInformation::SIZE],
            48,
        ))
    }
    fn suspend_threads(&mut self, threads: &[u64]) -> Result<Vec<u32>> {
        Ok(vec![1; threads.len()])
    }
    fn resume_threads(&mut self, threads: &[u64]) -> Result<Vec<u32>> {
        Ok(vec![0; threads.len()])
    }
    fn thread_start_address(&mut self, _process: u64, _thread: u64) -> Result<u64> {
        Ok(RIP)
    }
    fn get_context(
        &mut self,
        _thread: u64,
        _flags: u32,
        _flags_offset: u32,
        size: u32,
    ) -> Result<(Vec<u8>, u32)> {
        Ok((fake_context(Arch::Amd64), size))
    }
    fn set_context(&mut self, _thread: u64, context: &[u8]) -> Result<u32> {
        Ok(context.len() as u32)
    }
    fn process_data_offset(&mut self, _process: u64) -> Result<u64> {
        Ok(PEB)
    }
    fn thread_data_offset(&mut self, _thread: u64) -> Result<u64> {
        Ok(TEB)
    }
    fn request_break_in(&mut self, _process: u64) -> Result<()> {
        self.break_in = true;
        Ok(())
    }
    fn wait_for_event(&mut self, _timeout_ms: u32) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn continue_event(&mut self, _status: u32) -> Result<()> {
        self.resumed = true;
        Ok(())
    }
    fn insert_code_breakpoint(
        &mut self,
        _process: u64,
        _address: u64,
        _machine_type: u32,
    ) -> Result<Vec<u8>> {
        self.inserted = true;
        Ok(vec![0; 32])
    }
    fn remove_code_breakpoint(
        &mut self,
        _process: u64,
        _address: u64,
        _machine_type: u32,
        _storage: &[u8],
    ) -> Result<()> {
        Ok(())
    }
    fn insert_data_breakpoint(
        &mut self,
        _process: u64,
        _thread: u64,
        _address: u64,
        _length: u32,
        _access: u32,
        _machine_type: u32,
    ) -> Result<()> {
        Ok(())
    }
    fn remove_data_breakpoint(
        &mut self,
        _process: u64,
        _thread: u64,
        _address: u64,
        _length: u32,
        _access: u32,
        _machine_type: u32,
    ) -> Result<()> {
        Ok(())
    }
    fn last_data_breakpoint_hit(&mut self, _process: u64, _thread: u64) -> Result<(u64, u32)> {
        Ok((RIP, 1))
    }
}

#[test]
fn a_mock_server_drives_the_backend_without_a_socket() {
    let server = Box::new(MockServer {
        info: TargetInfo {
            machine_type: 0x8664,
            processors: 1,
            ..TargetInfo::default()
        },
        threads: vec![ThreadRecord {
            handle: THREAD,
            tid: TID,
        }],
        inserted: false,
        break_in: false,
        resumed: false,
    });
    let client = Arc::new(
        DbgSrvClient::with_server(
            server,
            TargetInfo {
                machine_type: 0x8664,
                processors: 1,
                ..TargetInfo::default()
            },
        )
        .expect("a client"),
    );
    assert_eq!(client.arch(), Arch::Amd64);
    // Without an event the attach refuses rather than hanging: a server that
    // answers nothing has produced no initial debug event.
    let error = DbgsrvBackend::connect(client, &DbgsrvTarget::Attach { pid: PID }, &mut |_| {})
        .err()
        .expect("no initial event");
    assert!(
        error.to_string().contains("no initial debug event"),
        "{error}"
    );
}

#[test]
fn machine_types_map_to_architectures_and_i386_is_refused() {
    for (machine, expected) in [(0x8664u32, Some(Arch::Amd64)), (0xaa64, Some(Arch::Arm64))] {
        let client = DbgSrvClient::with_server(
            Box::new(MockServer {
                info: TargetInfo {
                    machine_type: machine,
                    processors: 4,
                    ..TargetInfo::default()
                },
                threads: Vec::new(),
                inserted: false,
                break_in: false,
                resumed: false,
            }),
            TargetInfo {
                machine_type: machine,
                processors: 4,
                ..TargetInfo::default()
            },
        );
        assert_eq!(client.ok().map(|client| client.arch()), expected);
    }
    // x86/WOW64 has no context layout here, and is named as unsupported.
    let error = DbgSrvClient::with_server(
        Box::new(MockServer {
            info: TargetInfo {
                machine_type: 0x014c,
                ..TargetInfo::default()
            },
            threads: Vec::new(),
            inserted: false,
            break_in: false,
            resumed: false,
        }),
        TargetInfo {
            machine_type: 0x014c,
            ..TargetInfo::default()
        },
    )
    .expect_err("i386 is refused");
    assert!(
        matches!(error, Error::DebugInfo(ref message) if message.contains("x86/WOW64")),
        "{error}"
    );
}

/// The fixture's own guards: a reply the client never asked for must not be
/// trusted, and a process's thread array must not be sized by a number the
/// server names.
#[test]
fn an_oversized_reply_and_an_endless_thread_list_are_refused() {
    use crate::base::error::Error;

    // A server that answers every call with a body far larger than the
    // client asked for is corrupt, not chatty.
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let endpoint = endpoint(&listener);
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a client");
        let mut handshake = vec![0u8; core::mem::size_of::<Handshake>()];
        stream.read_exact(&mut handshake).expect("a handshake");
        let identity_length =
            u32::from_le_bytes([handshake[32], handshake[33], handshake[34], handshake[35]])
                as usize;
        let mut identity = vec![0u8; identity_length];
        stream.read_exact(&mut identity).expect("an identity");
        let mut reply = vec![0u8; core::mem::size_of::<Handshake>()];
        reply[0..4].copy_from_slice(&SIGNATURE);
        reply[4..8].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        reply[8..24].copy_from_slice(&handshake[8..24]);
        reply[24..32].copy_from_slice(&OBJECT.to_le_bytes());
        stream.write_all(&reply).expect("a reply");
        // One call, answered with a header naming a gigabyte of body — and
        // no body at all, so a client that trusted the size would block.
        let mut header = vec![0u8; core::mem::size_of::<Call>()];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let call = Call::read_from_bytes(&header).expect("a call header");
        let answer = Call {
            object_id: call.object_id,
            stub_index: call.stub_index,
            flags: CALL_RETURN,
            in_size: 0,
            out_size: 1 << 30,
            status: 0,
            sequence: call.sequence,
            reserved1: 0,
        };
        stream
            .write_all(zerocopy::IntoBytes::as_bytes(&answer))
            .expect("a reply header");
        // Stay connected until the client gives up, so the reply is not
        // racing a close: the client must refuse it on its own.
        let mut discard = [0u8; 64];
        while stream.read(&mut discard).is_ok_and(|read| read != 0) {}
    });
    let error =
        DbgSrvClient::connect(&endpoint, &mut |_| {}).expect_err("the oversized reply is refused");
    assert!(
        matches!(error, Error::DebugInfo(ref text) if text.contains("more than")),
        "{error}"
    );
    handle.join().expect("the server thread");

    // A thread count beyond what a process can have is clamped, not
    // allocated for: the request stays within one reply.
    let server = Arc::new(FakeServer::new(Arch::Amd64));
    let (client, _handle) = connect(Arc::clone(&server));
    let (_, _, total) = client
        .server()
        .process_info(PID, 1, super::service::MAX_PROCESS_THREADS)
        .expect("a thread list");
    assert!(total <= super::service::MAX_PROCESS_THREADS, "{total}");
}

/// Every request the fake server sees is one the client built from the
/// protocol tables: the stub index and body sizes are the ones `wire` and
/// `layout` name, not numbers that happened to match.
#[test]
fn every_call_is_the_protocol_table_its_shape() {
    let server = Arc::new(FakeServer::new(Arch::Amd64));
    let (client, handle) = connect(Arc::clone(&server));
    let client = Arc::new(client);
    use crate::backend::dbg_backend::DebugBackend;

    let mut backend = DbgsrvBackend::connect(
        Arc::clone(&client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    // Leaving detaches, which is the last call the table names.
    backend.prepare_for_exit(false).expect("a detach");
    drop(backend);
    drop(client);
    handle.join().expect("the server thread");

    let calls = server.calls.lock().unwrap();
    let body_size = |stub: u16| -> Option<usize> {
        calls
            .iter()
            .find(|(s, _)| *s == stub)
            .map(|(_, body)| body.len())
    };
    assert_eq!(
        body_size(stub_index(method::QUERY_INTERFACE)),
        Some(
            core::mem::size_of::<super::wire::Guid>()
                + core::mem::size_of::<layout::InterfaceVersion>()
        )
    );
    assert_eq!(body_size(stub_index(method::INITIALIZE)), Some(0));
    assert_eq!(
        body_size(stub_index(method::GET_CONNECTION_INFO)),
        Some(core::mem::size_of::<layout::GetConnectionInfoArgs>())
    );
    assert_eq!(
        body_size(stub_index(method::GET_TARGET_INFO)),
        Some(core::mem::size_of::<layout::GetTargetInfoArgs>())
    );
    assert_eq!(
        body_size(stub_index(method::ATTACH_PROCESS)),
        Some(core::mem::size_of::<layout::AttachProcessArgs>())
    );
    assert_eq!(
        body_size(stub_index(method::GET_PROCESS_INFO)),
        Some(core::mem::size_of::<layout::GetProcessInfoArgs>())
    );
    assert_eq!(
        body_size(stub_index(method::GET_PROCESS_DATA_OFFSET)),
        Some(core::mem::size_of::<layout::HandleArg>())
    );
    assert_eq!(
        body_size(stub_index(method::GET_THREAD_BASIC_INFO)),
        Some(2 * core::mem::size_of::<layout::HandleArg>())
    );
    assert_eq!(
        body_size(stub_index(method::GET_THREAD_DATA_OFFSET)),
        Some(core::mem::size_of::<layout::HandleArg>())
    );
    assert_eq!(
        body_size(stub_index(method::WAIT_FOR_EVENT)),
        Some(core::mem::size_of::<layout::WaitForEventArgs>())
    );
    assert_eq!(
        body_size(stub_index(method::DETACH_PROCESS)),
        Some(core::mem::size_of::<layout::DetachProcessArgs>())
    );
}

/// A data watchpoint is programmed into every thread's `CONTEXT`, and cleared
/// from them: the debug registers are per thread, and a process server hands
/// out no watchpoint of its own when it reports
/// `DBGSVC_GENERIC_DATA_BREAKPOINTS`.
#[test]
fn a_data_watchpoint_is_programmed_into_every_thread_and_cleared() {
    use crate::arch::HwBreakpointAccess;
    use crate::backend::dbg_backend::DebugBackend;

    const ADDRESS: u64 = 0x7ff6_0000_1000;

    let server = Arc::new(FakeServer::new(Arch::Amd64));
    let (client, handle) = connect(Arc::clone(&server));
    let mut backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    // The server reports generic data breakpoints, so the debugger owns the
    // registers; there are four slots.
    assert!(backend.supports_watchpoints());
    assert_eq!(backend.hardware_breakpoint_slots(), 4);

    let registers = backend.register_map().clone();
    let dr = |context: &[u8], name: &str| registers.read_u64(name, context).unwrap();

    backend
        .set_hardware_breakpoint(0, ADDRESS, HwBreakpointAccess::Write, 8)
        .expect("a watchpoint");
    // Every thread of the process got it.
    {
        let contexts = server.contexts.lock().unwrap();
        assert_eq!(contexts.len(), 1, "one thread in the fixture");
        let (thread, context) = &contexts[0];
        assert_eq!(*thread, THREAD);
        assert_eq!(dr(context, "dr0"), ADDRESS);
        // The family's encoder enables a slot globally (DR7 bit 1), which
        // survives the context switches a process makes.
        assert_ne!(dr(context, "dr7") & 0b11, 0, "slot 0 enabled");
    }

    backend
        .clear_hardware_breakpoint(0)
        .expect("the watchpoint lifted");
    {
        let contexts = server.contexts.lock().unwrap();
        let (_, context) = contexts.last().expect("the clearing write");
        assert_eq!(dr(context, "dr0"), 0);
        assert_eq!(dr(context, "dr7") & 0b11, 0, "slot 0 disabled");
    }

    // A watch the debug registers cannot express is refused, not armed.
    assert!(
        backend
            .set_hardware_breakpoint(0, ADDRESS + 1, HwBreakpointAccess::Write, 8)
            .is_err(),
        "a misaligned watch"
    );

    backend.prepare_for_exit(false).expect("a detach");
    drop(backend);
    handle.join().expect("the server thread");
}
