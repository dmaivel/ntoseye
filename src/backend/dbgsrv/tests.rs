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

use zerocopy::{FromBytes, IntoBytes};

use crate::arch::{
    Arch, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
};
use crate::backend::dbg_backend::DebugBackend;
use crate::backend::userlive::{MemoryBasicInformation, backend_thread_id};
use crate::base::bytes::{read_u32, read_u64, write_u32, write_u64};
use crate::base::error::{Error, Result};
use crate::base::ntstatus::STATUS_BREAKPOINT;

use super::backend::{DbgsrvBackend, DbgsrvTarget};
use super::client::DbgsrvClient;
use super::events::{
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, CreateProcessDebugInfo,
    CreateThreadDebugInfo, DEBUG_EVENT_HEADER_SIZE, DEBUG_EVENT_SIZE, DebugEventName,
    EXCEPTION_DEBUG_EVENT, EXCEPTION_MAXIMUM_PARAMETERS, EXIT_PROCESS_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, ExceptionDebugInfo, ExceptionRecord64, ExitDebugInfo,
    OUTPUT_DEBUG_STRING_EVENT, OutputDebugStringInfo,
};
use super::layout;
use super::service::{
    AttachedProcess, CLOSE_PROC_THREAD_HANDLES, ConnectionInfo, CreatedProcess,
    DEBUG_PROCESS_ONLY_THIS_PROCESS, E_ACCESSDENIED, E_INVALIDARG, GENERIC_CODE_BREAKPOINTS,
    GENERIC_DATA_BREAKPOINTS, MAX_PROCESS_THREADS, ProcessServer, TargetInfo, ThreadRecord,
};
use super::wire::{
    CALL_LOCKED, CALL_NO_RETURN, CALL_RETURN, Call, Guid, Handshake, IID_USER_DEBUG_SERVICES,
    Method, PROTOCOL_VERSION, SIGNATURE, UNIQUE_USER_DEBUG_SERVICES, stub_index,
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
/// The fake `CONTEXT`'s instruction pointer.
pub(crate) const RIP: u64 = 0x0040_1000;

/// A `CONTEXT` the fake server hands back: only the instruction pointer is
/// set, which is what the backend reads.
fn fake_context(arch: Arch) -> Vec<u8> {
    let mut context = vec![0u8; arch.context_size()];
    let layout = arch.register_map();
    let flags = arch.context_flags();
    write_u32(&mut context, flags.offset, flags.all);
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
    bytes[..DEBUG_EVENT_HEADER_SIZE].copy_from_slice(name.as_bytes());
    bytes[DEBUG_EVENT_HEADER_SIZE..DEBUG_EVENT_HEADER_SIZE + payload.len()]
        .copy_from_slice(payload);
    bytes
}

/// The exception event the fake server reports for a breakpoint.
fn breakpoint_event() -> Vec<u8> {
    let info = ExceptionDebugInfo {
        record: ExceptionRecord64 {
            code: STATUS_BREAKPOINT,
            flags: 0,
            record: 0,
            address: RIP,
            number_parameters: 0,
            alignment: 0,
            parameters: [0; EXCEPTION_MAXIMUM_PARAMETERS],
        },
        first_chance: 1,
        alignment: 0,
    };
    debug_event(EXCEPTION_DEBUG_EVENT, PID, TID, info.as_bytes())
}

/// Every call a client made, as `(stub index, request body)`.
type CallLog = Arc<Mutex<Vec<(u16, Vec<u8>)>>>;

/// Every `CONTEXT` a client wrote, as `(thread handle, context)`.
type ContextLog = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;

/// The fake process server, and what it answers.
pub(crate) struct FakeServer {
    arch: Arch,
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
        Self {
            arch,
            memory: Mutex::new(memory),
            events: Mutex::new(vec![
                // The process's creation is the stop an attach lands on.
                debug_event(
                    CREATE_PROCESS_DEBUG_EVENT,
                    PID,
                    TID,
                    CreateProcessDebugInfo {
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
                    }
                    .as_bytes(),
                ),
                breakpoint_event(),
            ]),
            calls: Arc::new(Mutex::new(Vec::new())),
            break_in: Arc::new(AtomicBool::new(false)),
            flags: CLOSE_PROC_THREAD_HANDLES | GENERIC_DATA_BREAKPOINTS | GENERIC_CODE_BREAKPOINTS,
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
        self
    }

    /// The reply body for one call, filled to `out_size` bytes.
    fn reply(&self, stub: u16, body: &[u8], out_size: usize) -> Vec<u8> {
        let mut out = vec![0u8; out_size];
        match stub {
            s if s == stub_index(Method::QueryInterface) => {
                assert_eq!(
                    body.len(),
                    core::mem::size_of::<Guid>() + core::mem::size_of::<u32>(),
                    "IID + revision code"
                );
                assert_eq!(
                    read_u32(body, core::mem::size_of::<Guid>()),
                    UNIQUE_USER_DEBUG_SERVICES,
                    "the client's revision"
                );
                write_u64(&mut out, 0, OBJECT);
            }
            s if s == stub_index(Method::Initialize) => write_u32(&mut out, 0, self.flags),
            s if s == stub_index(Method::GetConnectionInfo) => {
                let mut write = |at: usize, text: &str| {
                    for (index, unit) in text.encode_utf16().enumerate() {
                        let offset = at + index * 2;
                        if offset + 2 <= out.len() {
                            out[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
                        }
                    }
                };
                write(0, "TESTBOX");
                write(16, "tcp");
            }
            s if s == stub_index(Method::GetTargetInfo) => {
                let machine = u32::from(self.arch.machine_type());
                for (index, value) in [machine, 32, 2, 10, 0, 26_100, 0, 0, 1, 0x100, 0]
                    .into_iter()
                    .enumerate()
                {
                    write_u32(&mut out, index * 4, value);
                }
            }
            s if s == stub_index(Method::GetProcessInfo) => {
                let count = read_u32(
                    body,
                    core::mem::offset_of!(layout::GetProcessInfoArgs, info_count),
                ) as usize;
                write_u64(&mut out, 0, PROCESS);
                let record = core::mem::size_of::<layout::UserThreadInfo>();
                let at = record;
                write_u64(&mut out, at, THREAD);
                write_u32(&mut out, at + 8, TID);
                write_u32(&mut out, at + count * record, 1);
            }
            s if s == stub_index(Method::AttachProcess) => {
                write_u64(&mut out, 0, PROCESS);
                write_u32(&mut out, 8, DEBUG_PROCESS_ONLY_THIS_PROCESS);
            }
            s if s == stub_index(Method::CreateProcessW) => {
                write_u32(&mut out, 0, PID);
                write_u32(&mut out, 4, TID);
                write_u64(&mut out, 8, PROCESS);
                write_u64(&mut out, 16, THREAD);
            }
            s if s == stub_index(Method::ReadVirtual) || s == stub_index(Method::QueryVirtual) => {
                let address = read_u64(body, 8);
                let size = read_u32(body, 16) as usize;
                let memory = self.memory.lock().unwrap();
                for (offset, byte) in out[..size].iter_mut().enumerate() {
                    *byte = memory.get(&(address + offset as u64)).copied().unwrap_or(0);
                }
                let at = (size + 3) & !3;
                write_u32(&mut out, at, size as u32);
            }
            s if s == stub_index(Method::WriteVirtual) => {
                let address = read_u64(body, 8);
                let size = read_u32(body, 16) as usize;
                let mut memory = self.memory.lock().unwrap();
                for offset in 0..size {
                    memory.insert(address + offset as u64, body[20 + offset]);
                }
                write_u32(&mut out, 0, size as u32);
            }
            s if s == stub_index(Method::GetThreadBasicInfo) => {
                let at = core::mem::offset_of!(layout::ThreadBasicInformation, start_offset);
                write_u64(&mut out, at, RIP);
            }
            s if s == stub_index(Method::GetProcessDataOffset) => write_u64(&mut out, 0, PEB),
            s if s == stub_index(Method::GetThreadDataOffset) => write_u64(&mut out, 0, TEB),
            s if s == stub_index(Method::GetContext) => {
                let size = read_u32(body, 16) as usize;
                let context = fake_context(self.arch);
                out[..context.len()].copy_from_slice(&context);
                let at = (size + 3) & !3;
                write_u32(&mut out, at, context.len() as u32);
            }
            s if s == stub_index(Method::SetContext) => {
                let thread = read_u64(body, 0);
                let size = read_u32(body, 8) as usize;
                let context = body
                    .get(12..)
                    .map(|bytes| bytes[..size.min(bytes.len())].to_vec())
                    .unwrap_or_default();
                self.contexts.lock().unwrap().push((thread, context));
                write_u32(&mut out, 0, size as u32);
            }
            s if s == stub_index(Method::WaitForEvent) => {
                let size = read_u32(body, 4) as usize;
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
                        write_u32(&mut out, at, used as u32);
                    }
                    // S_FALSE: a timeout.
                    None => return Vec::new(),
                }
            }
            s if s == stub_index(Method::InsertCodeBreakpoint) => {
                self.inserted.store(true, Ordering::SeqCst);
                for (index, byte) in out.iter_mut().enumerate() {
                    *byte = index as u8;
                }
            }
            _ => {
                assert_eq!(
                    out_size, 0,
                    "the fake server has no reply for stub {stub:#x}"
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
        let mut handshake = [0u8; core::mem::size_of::<Handshake>()];
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
            .write_all(reply.as_bytes())
            .expect("the handshake reply");
        loop {
            let mut header = [0u8; core::mem::size_of::<Call>()];
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
            if call.stub_index == stub_index(Method::RequestBreakIn) {
                server.break_in.store(true, Ordering::SeqCst);
            }
            if call.flags & CALL_NO_RETURN != 0 {
                continue;
            }
            let out = server.reply(call.stub_index, &body, call.out_size as usize);
            let status = if call.stub_index == stub_index(Method::WaitForEvent) && out.is_empty() {
                1 // S_FALSE
            } else {
                0
            };
            let reply = Call {
                object_id: call.object_id,
                stub_index: call.stub_index,
                flags: CALL_RETURN,
                in_size: 0,
                out_size: out.len() as u32,
                status,
                sequence: call.sequence,
                reserved1: 0,
            };
            stream.write_all(reply.as_bytes()).expect("a reply header");
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
fn connect(server: Arc<FakeServer>) -> (DbgsrvClient, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let endpoint = endpoint(&listener);
    let handle = serve(listener, Arc::clone(&server));
    let client = DbgsrvClient::connect(&endpoint, &mut |_| {}).expect("a connection");
    (client, handle)
}

#[test]
fn the_handshake_and_call_header_are_the_proxys_bytes() {
    let handshake = Handshake::client(IID_USER_DEBUG_SERVICES);
    let bytes = handshake.as_bytes();
    assert_eq!(bytes.len(), 128, "sizeof(DbgRpcHandshake)");
    assert_eq!(&bytes[0..4], b"DRPC");
    assert_eq!(&bytes[4..8], &2u32.to_le_bytes(), "protocol version");
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
    assert_eq!(&bytes[40..44], &3u32.to_le_bytes(), "client flags");

    let call = Call {
        object_id: 0x1122_3344_5566_7788,
        stub_index: 0xc019,
        flags: CALL_LOCKED,
        in_size: 20,
        out_size: 8,
        status: 0,
        sequence: 7,
        reserved1: 0,
    };
    let bytes = call.as_bytes();
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
    let server = Arc::new(FakeServer::new(Arch::Amd64));
    let (client, handle) = connect(Arc::clone(&server));
    let client = Arc::new(client);
    assert_eq!(client.arch(), Arch::Amd64);
    assert!(client.generic_code_breakpoints());
    assert!(client.closes_handles());

    let mut backend = DbgsrvBackend::connect(
        Arc::clone(&client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    assert_eq!(backend.pid(), PID);
    assert_eq!(backend.process_handle(), PROCESS);
    let live = backend.live_state().snapshot();
    assert_eq!(live.peb, Some(PEB));
    assert_eq!(live.threads.len(), 1);
    assert_eq!(live.threads[0].tid, TID);
    assert_eq!(live.threads[0].teb, Some(TEB));
    assert_eq!(backend.selected_tid(), Some(TID));
    assert!(!backend.is_running());
    assert_eq!(backend.thread_list().unwrap(), vec![backend_thread_id(TID)]);

    let registers = backend.read_registers().expect("a context");
    let map = backend.register_map().clone();
    assert_eq!(map.read_u64("rip", &registers).unwrap(), RIP);

    let mut buf = [0u8; 13];
    client.read_virtual(PROCESS, RIP, &mut buf).expect("a read");
    assert_eq!(&buf, b"hello, memory");

    backend.set_breakpoint(RIP).expect("a patched site");
    assert!(!server.inserted.load(Ordering::SeqCst));
    let mut patched = [0u8; 1];
    client.read_virtual(PROCESS, RIP, &mut patched).unwrap();
    assert_eq!(patched[0], 0xcc, "int3");
    backend.remove_breakpoint(RIP).expect("the site lifted");
    client.read_virtual(PROCESS, RIP, &mut patched).unwrap();
    assert_eq!(patched[0], b'h');

    backend.continue_execution().expect("a resume");
    assert!(backend.is_running());
    let stop = backend.wait_for_stop().expect("a stop");
    assert!(!backend.is_running());
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert_eq!(stop.first_chance, Some(true));
    assert_eq!(stop.thread_id.as_deref(), Some("1234"));
    assert_eq!(stop.program_counter, Some(RIP));
    // `.exr -1` reads the recorded exception record.
    let exr = backend
        .last_exception_record()
        .expect("exception record recorded");
    assert_eq!(exr.code, STATUS_BREAKPOINT);
    assert_eq!(exr.address, RIP);

    let again = backend.interrupt().expect("the kept stop");
    assert_eq!(again.exception_code, stop.exception_code);

    backend.prepare_for_exit(false).expect("a detach");
    drop(backend);
    drop(client);
    handle.join().expect("the server thread");
    let calls = server.calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .any(|(stub, _)| *stub == stub_index(Method::DetachProcess)),
        "DetachProcess"
    );
    assert!(
        calls
            .iter()
            .any(|(stub, _)| *stub == stub_index(Method::ContinueEvent)),
        "ContinueEvent"
    );
}

#[test]
fn a_server_that_implements_code_breakpoints_removes_them_on_exit() {
    let server = Arc::new(FakeServer::new(Arch::Amd64).with_generic_code_breakpoints(false));
    let (client, handle) = connect(Arc::clone(&server));
    let mut backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    assert!(!backend.client().generic_code_breakpoints());
    backend.set_breakpoint(RIP).expect("a server site");
    assert!(server.inserted.load(Ordering::SeqCst));
    // Leaving without explicit removal must still lift server-planted sites.
    backend.prepare_for_exit(false).expect("a detach");
    drop(backend);
    handle.join().expect("the server thread");
    let calls = server.calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .any(|(stub, _)| *stub == stub_index(Method::InsertCodeBreakpoint)),
        "InsertCodeBreakpoint"
    );
    assert!(
        calls
            .iter()
            .any(|(stub, _)| *stub == stub_index(Method::RemoveCodeBreakpoint)),
        "RemoveCodeBreakpoint on prepare_for_exit"
    );
}

#[test]
fn absorbed_events_continue_the_debuggee_and_sync_live_threads() {
    const EXTRA_TID: u32 = 0x2222;
    const EXTRA_HANDLE: u64 = 0x2200;
    const MSG_ADDR: u64 = 0x0050_0000;

    let server = Arc::new(FakeServer::new(Arch::Amd64));
    {
        let mut memory = server.memory.lock().unwrap();
        for (offset, byte) in b"hello\n".iter().enumerate() {
            memory.insert(MSG_ADDR + offset as u64, *byte);
        }
        let mut events = server.events.lock().unwrap();
        events.truncate(1); // keep CreateProcess
        events.push(debug_event(
            CREATE_THREAD_DEBUG_EVENT,
            PID,
            EXTRA_TID,
            CreateThreadDebugInfo {
                handle: EXTRA_HANDLE,
                teb: TEB + 0x1000,
                start_address: RIP,
            }
            .as_bytes(),
        ));
        events.push(breakpoint_event());
        events.push(debug_event(
            OUTPUT_DEBUG_STRING_EVENT,
            PID,
            EXTRA_TID,
            OutputDebugStringInfo {
                address: MSG_ADDR,
                wide: 0,
                length: 6,
                alignment: 0,
            }
            .as_bytes(),
        ));
        events.push(debug_event(
            EXIT_THREAD_DEBUG_EVENT,
            PID,
            EXTRA_TID,
            ExitDebugInfo { exit_code: 0 }.as_bytes(),
        ));
        events.push(breakpoint_event());
    }
    let (client, handle) = connect(Arc::clone(&server));
    let mut backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    let shared_state = backend.live_state();

    // Resume across CreateThread into the first breakpoint: CreateThread is
    // absorbed and continued automatically while syncing shared live threads.
    backend
        .continue_execution()
        .expect("resume across create thread");
    let stop = backend.wait_for_stop().expect("first breakpoint stop");
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert_eq!(shared_state.snapshot().threads.len(), 2);

    // Resume across OutputDebugString + ExitThread into the second breakpoint:
    // both absorbed events must issue ContinueEvent, ExitThread must close its
    // handle, and shared state drops the exited thread.
    backend
        .continue_execution()
        .expect("resume across absorbed");
    let stop = backend.wait_for_stop().expect("second breakpoint stop");
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert_eq!(shared_state.snapshot().threads.len(), 1);
    let page = backend.read_debug_output(0);
    assert_eq!(page.lines.len(), 1);
    assert_eq!(page.lines[0].text, "hello");

    backend.prepare_for_exit(false).expect("detach");
    drop(backend);
    handle.join().expect("server thread");

    let calls = server.calls.lock().unwrap();
    let continues = calls
        .iter()
        .filter(|(stub, _)| *stub == stub_index(Method::ContinueEvent))
        .count();
    // 2 explicit resumes + 3 absorbed events (CreateThread, OutputDebugString, ExitThread).
    assert_eq!(continues, 5, "absorbed events must be continued");
    assert!(
        calls
            .iter()
            .any(|(stub, body)| *stub == stub_index(Method::CloseHandle)
                && read_u64(body, 0) == EXTRA_HANDLE),
        "ExitThread should close the thread handle when CLOSE_PROC_THREAD_HANDLES is set"
    );
}

#[test]
fn another_processes_creation_handles_are_closed() {
    const OTHER_PID: u32 = 0x999;
    const OTHER_PROCESS: u64 = 0x7000;
    const OTHER_THREAD: u64 = 0x7001;

    let server = Arc::new(FakeServer::new(Arch::Amd64));
    {
        let mut events = server.events.lock().unwrap();
        events.truncate(1); // keep the CreateProcess stop
        // The server also debugs another process (another session's): its
        // creation events are continued, and the handles it hands out are
        // closed because this client does not track that process.
        events.push(debug_event(
            CREATE_PROCESS_DEBUG_EVENT,
            OTHER_PID,
            OTHER_THREAD as u32,
            CreateProcessDebugInfo {
                file: 0,
                process_handle: OTHER_PROCESS,
                thread_handle: OTHER_THREAD,
                image_base: 0x0040_0000,
                debug_info_offset: 0,
                debug_info_size: 0,
                teb: 0,
                start_address: 0,
                image_name: 0,
                image_name_wide: 0,
                alignment: [0; 6],
            }
            .as_bytes(),
        ));
        events.push(debug_event(
            CREATE_THREAD_DEBUG_EVENT,
            OTHER_PID,
            OTHER_THREAD as u32 + 1,
            CreateThreadDebugInfo {
                handle: OTHER_THREAD + 1,
                teb: 0,
                start_address: 0,
            }
            .as_bytes(),
        ));
        events.push(breakpoint_event());
    }
    let (client, handle) = connect(Arc::clone(&server));
    let mut backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    backend.continue_execution().expect("resume");
    let stop = backend.wait_for_stop().expect("the breakpoint after them");
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    backend.prepare_for_exit(false).expect("detach");
    drop(backend);
    handle.join().expect("the server thread");
    let handles: Vec<u64> = server
        .calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(stub, _)| *stub == stub_index(Method::CloseHandle))
        .map(|(_, body)| read_u64(body, 0))
        .collect();
    for handle in [OTHER_PROCESS, OTHER_THREAD, OTHER_THREAD + 1] {
        assert!(handles.contains(&handle), "{handle:#x} in {handles:?}");
    }
}

#[test]
fn interrupting_a_running_process_asks_the_server_to_break_in() {
    let server = Arc::new(FakeServer::new(Arch::Amd64));
    server.events.lock().unwrap().pop();
    let (client, handle) = connect(Arc::clone(&server));
    let mut backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    backend.continue_execution().expect("a resume");
    assert!(backend.is_running());
    server.events.lock().unwrap().push(breakpoint_event());
    let stop = backend.interrupt().expect("a break-in stop");
    assert!(!backend.is_running());
    assert_eq!(stop.exception_code, Some(STATUS_BREAKPOINT));
    assert!(server.break_in.load(Ordering::SeqCst));
    let _ = backend.prepare_for_exit(false);
    drop(backend);
    handle.join().expect("the server thread");
}

#[test]
fn creating_a_process_uses_the_create_call_and_its_creation_stop() {
    let server = Arc::new(FakeServer::new(Arch::Amd64));
    server.events.lock().unwrap().truncate(1);
    let (client, handle) = connect(Arc::clone(&server));
    let backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Create {
            command_line: "notepad.exe".to_string(),
        },
        &mut |_| {},
    )
    .expect("a create");
    assert_eq!(backend.pid(), PID);
    drop(backend);
    handle.join().expect("the server thread");
    let calls = server.calls.lock().unwrap();
    let create = calls
        .iter()
        .find(|(stub, _)| *stub == stub_index(Method::CreateProcessW))
        .expect("CreateProcessW");
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
    assert_eq!(read_u32(options, 0), DEBUG_PROCESS_ONLY_THIS_PROCESS);
    assert!(options[4..16].iter().all(|byte| *byte == 0));
    assert!(options[16..].iter().all(|byte| *byte == 0));
}

#[test]
fn arm64_target_connects_and_reads_pc() {
    let server = Arc::new(FakeServer::new(Arch::Arm64));
    let (client, handle) = connect(Arc::clone(&server));
    assert_eq!(client.arch(), Arch::Arm64);
    let mut backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an ARM64 attach");
    let registers = backend.read_registers().expect("an ARM64 context");
    assert_eq!(
        backend.register_map().read_u64("pc", &registers).unwrap(),
        RIP
    );
    backend.prepare_for_exit(false).expect("a detach");
    drop(backend);
    handle.join().expect("the server thread");
}

#[test]
fn a_server_that_refuses_the_handshake_is_reported_by_name() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let endpoint = endpoint(&listener);
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a client");
        let mut handshake = [0u8; 128];
        stream.read_exact(&mut handshake).expect("a handshake");
        let mut identity = [0u8; 128];
        stream.read_exact(&mut identity).expect("an identity");
        let mut reply = [0u8; 128];
        reply[0..4].copy_from_slice(SIGNATURE.as_slice());
        reply[4..8].copy_from_slice(&3u32.to_le_bytes());
        stream.write_all(&reply).expect("a reply");
    });
    let error = DbgsrvClient::connect(&endpoint, &mut |_| {}).expect_err("a version mismatch");
    assert!(error.to_string().contains("version mismatch"), "{error}");
    handle.join().expect("the server thread");
}

/// The mock server the logic tests drive directly.
struct MockServer {
    info: TargetInfo,
    threads: Vec<ThreadRecord>,
    flags: u32,
    attach_status: Option<u32>,
    events: Vec<Vec<u8>>,
    closed: Arc<Mutex<Vec<u64>>>,
    writes: Arc<Mutex<Vec<u64>>>,
}

impl MockServer {
    fn new(info: TargetInfo, threads: Vec<ThreadRecord>) -> Self {
        Self {
            info,
            threads,
            flags: CLOSE_PROC_THREAD_HANDLES | GENERIC_CODE_BREAKPOINTS | GENERIC_DATA_BREAKPOINTS,
            attach_status: None,
            events: Vec::new(),
            closed: Arc::new(Mutex::new(Vec::new())),
            writes: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl ProcessServer for MockServer {
    fn initialize(&mut self) -> Result<u32> {
        Ok(self.flags)
    }
    fn connection_info(&mut self) -> Result<ConnectionInfo> {
        Ok(ConnectionInfo {
            machine: "TESTBOX".to_string(),
            transport: "tcp".to_string(),
        })
    }
    fn target_info(&mut self) -> Result<TargetInfo> {
        Ok(self.info)
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
    fn attach_process(&mut self, _pid: u32, _flags: u32) -> Result<AttachedProcess> {
        if let Some(status) = self.attach_status {
            return Err(Error::DbgsrvStatus {
                method: Method::AttachProcess.name(),
                stub: Method::AttachProcess.stub_index(),
                status,
            });
        }
        Ok(AttachedProcess {
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
    ) -> Result<CreatedProcess> {
        Ok(CreatedProcess {
            pid: PID,
            tid: TID,
            process_handle: PROCESS,
            thread_handle: THREAD,
        })
    }
    fn close_handle(&mut self, handle: u64) -> Result<()> {
        self.closed.lock().unwrap().push(handle);
        Ok(())
    }
    fn read_virtual(&mut self, _process: u64, address: u64, buf: &mut [u8]) -> Result<usize> {
        for (index, byte) in buf.iter_mut().enumerate() {
            *byte = (address as usize + index) as u8;
        }
        Ok(buf.len())
    }
    fn write_virtual(&mut self, _process: u64, address: u64, buf: &[u8]) -> Result<usize> {
        self.writes.lock().unwrap().push(address);
        Ok(buf.len())
    }
    fn query_virtual(
        &mut self,
        _process: u64,
        _address: u64,
        _size: u32,
    ) -> Result<(Vec<u8>, u32)> {
        Ok((
            vec![0; MemoryBasicInformation::SIZE],
            MemoryBasicInformation::SIZE as u32,
        ))
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
        Ok(())
    }
    fn wait_for_event(&mut self, _timeout_ms: u32) -> Result<Option<Vec<u8>>> {
        Ok(if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        })
    }
    fn continue_event(&mut self, _status: u32) -> Result<()> {
        Ok(())
    }
    fn insert_code_breakpoint(
        &mut self,
        _process: u64,
        _address: u64,
        _machine_type: u32,
    ) -> Result<Vec<u8>> {
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
}

#[test]
fn a_mock_server_drives_the_backend_without_a_socket() {
    let info = TargetInfo {
        machine_type: u32::from(IMAGE_FILE_MACHINE_AMD64),
        processors: 1,
        ..TargetInfo::default()
    };
    let server = Box::new(MockServer::new(
        info,
        vec![ThreadRecord {
            handle: THREAD,
            tid: TID,
        }],
    ));
    let client = Arc::new(DbgsrvClient::with_server(server, info).expect("a client"));
    assert_eq!(client.arch(), Arch::Amd64);
    let error = DbgsrvBackend::connect(client, &DbgsrvTarget::Attach { pid: PID }, &mut |_| {})
        .err()
        .expect("no initial event");
    assert!(
        error.to_string().contains("no initial debug event"),
        "{error}"
    );
}

#[test]
fn watchpoints_require_generic_data_breakpoints_flag() {
    use crate::arch::HwBreakpointAccess;

    let info = TargetInfo {
        machine_type: u32::from(IMAGE_FILE_MACHINE_AMD64),
        processors: 1,
        ..TargetInfo::default()
    };
    let mut server = MockServer::new(
        info,
        vec![ThreadRecord {
            handle: THREAD,
            tid: TID,
        }],
    );
    server.flags = GENERIC_CODE_BREAKPOINTS;
    server.events.push(breakpoint_event());
    let client = Arc::new(DbgsrvClient::with_server(Box::new(server), info).expect("a client"));
    let mut backend =
        DbgsrvBackend::connect(client, &DbgsrvTarget::Attach { pid: PID }, &mut |_| {})
            .expect("attach");
    assert!(!backend.supports_watchpoints());
    assert!(matches!(
        backend.set_hardware_breakpoint(0, RIP, HwBreakpointAccess::Write, 8),
        Err(Error::NotSupported)
    ));
}

#[test]
fn attach_errors_distinguish_missing_process_and_access_denied() {
    let info = TargetInfo {
        machine_type: u32::from(IMAGE_FILE_MACHINE_AMD64),
        processors: 1,
        ..TargetInfo::default()
    };
    for (status, expected) in [
        (E_INVALIDARG, "not found"),
        (E_ACCESSDENIED, "access denied"),
        (0x8000_4005, "AttachProcess"),
    ] {
        let mut server = MockServer::new(info, Vec::new());
        server.attach_status = Some(status);
        let client = Arc::new(DbgsrvClient::with_server(Box::new(server), info).expect("a client"));
        let error = DbgsrvBackend::connect(client, &DbgsrvTarget::Attach { pid: PID }, &mut |_| {})
            .err()
            .expect("attach error");
        assert!(
            error.to_string().contains(expected),
            "status {status:#010x}: {error}"
        );
    }
}

#[test]
fn exit_process_reports_process_exit_instead_of_exception() {
    use crate::backend::userlive::UserLiveMemory;

    let info = TargetInfo {
        machine_type: u32::from(IMAGE_FILE_MACHINE_AMD64),
        processors: 1,
        ..TargetInfo::default()
    };
    let mut server = MockServer::new(
        info,
        vec![ThreadRecord {
            handle: THREAD,
            tid: TID,
        }],
    );
    server.events.push(breakpoint_event());
    server.events.push(debug_event(
        EXIT_PROCESS_DEBUG_EVENT,
        PID,
        TID,
        ExitDebugInfo { exit_code: 0x2a }.as_bytes(),
    ));
    let closed = Arc::clone(&server.closed);
    let writes = Arc::clone(&server.writes);
    let client = Arc::new(DbgsrvClient::with_server(Box::new(server), info).expect("a client"));
    let mut backend =
        DbgsrvBackend::connect(client, &DbgsrvTarget::Attach { pid: PID }, &mut |_| {})
            .expect("attach");
    let memory = backend.user_memory();
    backend.set_breakpoint(RIP).expect("plant breakpoint");
    assert_eq!(writes.lock().unwrap().len(), 1);

    backend.continue_execution().expect("resume");
    let stop = backend.wait_for_stop().expect("exit stop");
    assert_eq!(stop.process_exit, Some(0x2a));
    assert_eq!(stop.exception_code, None);

    // Registers and memory reads/writes/queries all report ProcessExited.
    let reg_err = backend.read_registers().expect_err("exited registers");
    assert!(matches!(reg_err, Error::ProcessExited(0x2a)), "{reg_err}");
    assert_eq!(reg_err.to_string(), "the process exited (0x2a)");
    let mut buf = [0u8; 4];
    assert!(matches!(
        memory.read(RIP, &mut buf),
        Err(Error::ProcessExited(0x2a))
    ));
    assert!(matches!(
        memory.write(RIP, &[0x90]),
        Err(Error::ProcessExited(0x2a))
    ));
    assert!(matches!(memory.query(RIP), Err(Error::ProcessExited(0x2a))));

    // Only the process handle is closed immediately on ExitProcess; surviving
    // thread handles are deferred to prepare_for_exit / Drop.
    assert_eq!(*closed.lock().unwrap(), vec![PROCESS]);
    backend.prepare_for_exit(false).expect("prepare_for_exit");
    assert_eq!(*closed.lock().unwrap(), vec![PROCESS, THREAD]);
    // prepare_for_exit must not try to restore breakpoints on an exited process.
    assert_eq!(writes.lock().unwrap().len(), 1);
    drop(backend);
    assert_eq!(*closed.lock().unwrap(), vec![PROCESS, THREAD]);
}

#[test]
fn handles_are_closed_on_replacement_duplicate_and_drop() {
    const EVENT_PROCESS: u64 = 0x5555;
    const DUP_THREAD: u64 = 0x6666;

    let info = TargetInfo {
        machine_type: u32::from(IMAGE_FILE_MACHINE_AMD64),
        processors: 1,
        ..TargetInfo::default()
    };
    let mut server = MockServer::new(
        info,
        vec![ThreadRecord {
            handle: THREAD,
            tid: TID,
        }],
    );
    server.events.push(debug_event(
        CREATE_PROCESS_DEBUG_EVENT,
        PID,
        TID,
        CreateProcessDebugInfo {
            file: 0,
            process_handle: EVENT_PROCESS,
            thread_handle: DUP_THREAD,
            image_base: 0x0040_0000,
            debug_info_offset: 0,
            debug_info_size: 0,
            teb: TEB,
            start_address: RIP,
            image_name: 0,
            image_name_wide: 0,
            alignment: [0; 6],
        }
        .as_bytes(),
    ));
    let closed = Arc::clone(&server.closed);
    let client = Arc::new(DbgsrvClient::with_server(Box::new(server), info).expect("a client"));
    let backend = DbgsrvBackend::connect(client, &DbgsrvTarget::Attach { pid: PID }, &mut |_| {})
        .expect("attach");
    // CreateProcess replaced PROCESS with EVENT_PROCESS and saw duplicate TID handle DUP_THREAD.
    assert_eq!(*closed.lock().unwrap(), vec![PROCESS, DUP_THREAD]);
    // Dropping without prepare_for_exit closes the remaining tracked handles.
    drop(backend);
    assert_eq!(
        *closed.lock().unwrap(),
        vec![PROCESS, DUP_THREAD, THREAD, EVENT_PROCESS]
    );
}

#[test]
fn process_handle_adopted_from_zero_closes_on_drop() {
    use super::client::ProcessHandle;

    const ADOPTED: u64 = 0x7777;
    let info = TargetInfo {
        machine_type: u32::from(IMAGE_FILE_MACHINE_AMD64),
        processors: 1,
        ..TargetInfo::default()
    };
    let server = MockServer::new(info, Vec::new());
    let closed = Arc::clone(&server.closed);
    let client = Arc::new(DbgsrvClient::with_server(Box::new(server), info).expect("a client"));
    let handle = ProcessHandle::new(client, 0);
    handle.adopt(ADOPTED);
    drop(handle);
    assert_eq!(*closed.lock().unwrap(), vec![ADOPTED]);
}

#[test]
fn machine_types_map_to_architectures_and_i386_is_refused() {
    for (machine, expected) in [
        (u32::from(IMAGE_FILE_MACHINE_AMD64), Some(Arch::Amd64)),
        (u32::from(IMAGE_FILE_MACHINE_ARM64), Some(Arch::Arm64)),
    ] {
        let info = TargetInfo {
            machine_type: machine,
            processors: 4,
            ..TargetInfo::default()
        };
        let client = DbgsrvClient::with_server(Box::new(MockServer::new(info, Vec::new())), info);
        assert_eq!(client.ok().map(|client| client.arch()), expected);
    }
    let info = TargetInfo {
        machine_type: u32::from(IMAGE_FILE_MACHINE_I386),
        ..TargetInfo::default()
    };
    let error = DbgsrvClient::with_server(Box::new(MockServer::new(info, Vec::new())), info)
        .expect_err("i386 is refused");
    assert!(
        matches!(error, Error::Dbgsrv(ref message) if message.contains("x86/WOW64")),
        "{error}"
    );
}

#[test]
fn an_oversized_reply_and_an_endless_thread_list_are_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
    let endpoint = endpoint(&listener);
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a client");
        let mut handshake = [0u8; core::mem::size_of::<Handshake>()];
        stream.read_exact(&mut handshake).expect("a handshake");
        let identity_length = read_u32(&handshake, 32) as usize;
        let mut identity = vec![0u8; identity_length];
        stream.read_exact(&mut identity).expect("an identity");
        let mut reply = [0u8; core::mem::size_of::<Handshake>()];
        reply[0..4].copy_from_slice(&SIGNATURE);
        reply[4..8].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        reply[8..24].copy_from_slice(&handshake[8..24]);
        write_u64(&mut reply, 24, OBJECT);
        stream.write_all(&reply).expect("a reply");
        let mut header = [0u8; core::mem::size_of::<Call>()];
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
        stream.write_all(answer.as_bytes()).expect("a reply header");
        let mut discard = [0u8; 64];
        while stream.read(&mut discard).is_ok_and(|read| read != 0) {}
    });
    let error =
        DbgsrvClient::connect(&endpoint, &mut |_| {}).expect_err("the oversized reply is refused");
    assert!(
        matches!(error, Error::Dbgsrv(ref text) if text.contains("more than")),
        "{error}"
    );
    handle.join().expect("the server thread");

    let server = Arc::new(FakeServer::new(Arch::Amd64));
    let (client, handle) = connect(Arc::clone(&server));
    let (_, _, total) = client
        .server()
        .process_info(PID, 1, MAX_PROCESS_THREADS)
        .expect("a thread list");
    assert!(total <= MAX_PROCESS_THREADS, "{total}");
    drop(client);
    handle.join().expect("the server thread");
}

#[test]
fn every_call_is_the_protocol_table_its_shape() {
    let server = Arc::new(FakeServer::new(Arch::Amd64));
    let (client, handle) = connect(Arc::clone(&server));
    let client = Arc::new(client);

    let mut backend = DbgsrvBackend::connect(
        Arc::clone(&client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    backend.prepare_for_exit(false).expect("a detach");
    drop(backend);
    drop(client);
    handle.join().expect("the server thread");

    let calls = server.calls.lock().unwrap();
    let body_size = |method: Method| -> Option<usize> {
        let stub = stub_index(method);
        calls
            .iter()
            .find(|(s, _)| *s == stub)
            .map(|(_, body)| body.len())
    };
    assert_eq!(
        body_size(Method::QueryInterface),
        Some(core::mem::size_of::<Guid>() + core::mem::size_of::<u32>())
    );
    assert_eq!(body_size(Method::Initialize), Some(0));
    assert_eq!(
        body_size(Method::GetConnectionInfo),
        Some(core::mem::size_of::<layout::GetConnectionInfoArgs>())
    );
    assert_eq!(
        body_size(Method::GetTargetInfo),
        Some(core::mem::size_of::<layout::GetTargetInfoArgs>())
    );
    assert_eq!(
        body_size(Method::AttachProcess),
        Some(core::mem::size_of::<layout::AttachProcessArgs>())
    );
    assert_eq!(
        body_size(Method::GetProcessInfo),
        Some(core::mem::size_of::<layout::GetProcessInfoArgs>())
    );
    assert_eq!(
        body_size(Method::GetProcessDataOffset),
        Some(core::mem::size_of::<u64>())
    );
    assert_eq!(
        body_size(Method::GetThreadBasicInfo),
        Some(2 * core::mem::size_of::<u64>())
    );
    assert_eq!(
        body_size(Method::GetThreadDataOffset),
        Some(core::mem::size_of::<u64>())
    );
    assert_eq!(
        body_size(Method::WaitForEvent),
        Some(core::mem::size_of::<layout::WaitForEventArgs>())
    );
    assert_eq!(
        body_size(Method::DetachProcess),
        Some(core::mem::size_of::<u32>())
    );
}

#[test]
fn a_data_watchpoint_is_programmed_into_every_thread_and_cleared_on_exit() {
    use crate::arch::HwBreakpointAccess;

    const ADDRESS: u64 = 0x7ff6_0000_1000;

    let server = Arc::new(FakeServer::new(Arch::Amd64));
    let (client, handle) = connect(Arc::clone(&server));
    let mut backend = DbgsrvBackend::connect(
        Arc::new(client),
        &DbgsrvTarget::Attach { pid: PID },
        &mut |_| {},
    )
    .expect("an attach");
    assert!(backend.supports_watchpoints());
    assert_eq!(backend.hardware_breakpoint_slots(), 4);

    let registers = backend.register_map().clone();
    let dr = |context: &[u8], name: &str| registers.read_u64(name, context).unwrap();

    backend
        .set_hardware_breakpoint(0, ADDRESS, HwBreakpointAccess::Write, 8)
        .expect("a watchpoint");
    {
        let contexts = server.contexts.lock().unwrap();
        assert_eq!(contexts.len(), 1, "one thread in the fixture");
        let (thread, context) = &contexts[0];
        assert_eq!(*thread, THREAD);
        assert_eq!(dr(context, "dr0"), ADDRESS);
        assert_ne!(dr(context, "dr7") & 0b11, 0, "slot 0 enabled");
    }

    assert!(
        backend
            .set_hardware_breakpoint(0, ADDRESS + 1, HwBreakpointAccess::Write, 8)
            .is_err(),
        "a misaligned watch"
    );

    // Leaving clears armed hardware watchpoints so the detached process won't
    // take stale #DB traps.
    backend.prepare_for_exit(false).expect("a detach");
    {
        let contexts = server.contexts.lock().unwrap();
        let (_, context) = contexts.last().expect("the clearing write on exit");
        assert_eq!(dr(context, "dr0"), 0);
        assert_eq!(dr(context, "dr7") & 0b11, 0, "slot 0 disabled");
    }

    drop(backend);
    handle.join().expect("the server thread");
}
