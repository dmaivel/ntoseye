//! The `IUserDebugServices` process-server client: the method subset ntoseye
//! drives a live user-mode target with, and the DbgRpc encoding of each.
//!
//! [`ProcessServer`] is the interface the backend talks to, so tests drive a
//! mock; [`RpcService`] is the one that puts the bytes on the wire. Each call
//! body is its [`super::layout`] structures plus the variable-length buffers
//! between them, in the order the generated proxy sends them.

use zerocopy::{FromBytes, IntoBytes};

use crate::base::error::{Error, Result};

use super::layout;
use super::transport::{DbgsrvEndpoint, TcpTransport, parse_endpoint};
use super::wire::{
    CALL_LOCKED, CALL_NO_RETURN, Call, Handshake, IDENTITY_LENGTH, IID_USER_DEBUG_SERVICES, Reader,
    UNIQUE_USER_DEBUG_SERVICES, Writer, method, stub_index, succeeded,
};

/// `DBGSVC_GENERIC_CODE_BREAKPOINTS`: the server has no code-breakpoint
/// implementation, so the debugger patches the instruction itself.
pub const GENERIC_CODE_BREAKPOINTS: u32 = 0x0000_0001;
/// `DBGSVC_CLOSE_PROC_THREAD_HANDLES`: the handles a debug event hands out are
/// not closed for the debugger, which must close them.
pub const CLOSE_PROC_THREAD_HANDLES: u32 = 0x0000_0002;
/// `DBGSVC_GENERIC_DATA_BREAKPOINTS`: the server has no data-breakpoint
/// implementation, so the debugger programs the thread's own registers.
pub const GENERIC_DATA_BREAKPOINTS: u32 = 0x0000_0004;
/// `DBGSVC_PROC_INFO_NO_SUSPEND`: list the process's threads without
/// suspending them.
pub const PROC_INFO_NO_SUSPEND: u32 = 0x0000_0001;

/// `DEBUG_PROCESS_ONLY_THIS_PROCESS`.
pub const DEBUG_PROCESS_ONLY_THIS_PROCESS: u32 = 0x0000_0002;
/// `DEBUG_CREATE_PROCESS_INHERIT_HANDLES`.
pub const DEBUG_CREATE_PROCESS_INHERIT_HANDLES: u32 = 0x0000_0002;

/// `DBG_CONTINUE`.
pub const DBG_CONTINUE: u32 = 0x0001_0002;
/// `DBG_EXCEPTION_NOT_HANDLED`.
pub const DBG_EXCEPTION_NOT_HANDLED: u32 = 0x8001_0001;

/// `S_FALSE`: the server's "nothing yet" for a timed-out wait.
const S_FALSE: u32 = 0x0000_0001;

/// Bytes of a 64-bit Windows `DEBUG_EVENT`: what the server requires the
/// caller's buffer to hold.
pub const DEBUG_EVENT_SIZE: u32 = super::events::DEBUG_EVENT_SIZE as u32;

/// `IMAGE_FILE_MACHINE_AMD64`.
pub const IMAGE_FILE_MACHINE_AMD64: u32 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`.
pub const IMAGE_FILE_MACHINE_ARM64: u32 = 0xaa64;
/// `IMAGE_FILE_MACHINE_I386`.
pub const IMAGE_FILE_MACHINE_I386: u32 = 0x014c;

/// The `MEMORY_BASIC_INFORMATION` bytes a `VirtualQuery` fills.
pub const MEMORY_BASIC_INFORMATION_SIZE: u32 = 48;

/// The largest reply body this client accepts. Every reply it asks for is
/// smaller (a `CONTEXT` is about 1.2 KiB, a page an event), so a header naming
/// more is corrupt rather than a large answer.
const MAX_REPLY_BYTES: u32 = 16 * 1024 * 1024;

/// How many threads one process may report, which bounds the array a
/// `GetProcessInfo` retry asks for.
pub const MAX_PROCESS_THREADS: u32 = 65_536;

/// What the server reports about the machine the target runs on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TargetInfo {
    /// `IMAGE_FILE_MACHINE_*`.
    pub machine_type: u32,
    pub processors: u32,
    pub platform_id: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub checked_build: u32,
    pub product_type: u32,
    pub suite_mask: u32,
}

/// One thread of a process, as `GetProcessInfo` lists it
/// (`USER_THREAD_INFO`): the server's handle to it, and its id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRecord {
    pub handle: u64,
    pub tid: u32,
}

/// What `AttachProcess` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachedProcess {
    pub handle: u64,
    /// The `DEBUG_*` options the process was created with.
    pub options: u32,
}

/// What `CreateProcessW` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatedProcess {
    pub pid: u32,
    pub tid: u32,
    pub process_handle: u64,
    pub thread_handle: u64,
}

/// The names the server reports about a connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// The machine the target runs on.
    pub machine: String,
    /// How the client reached it, as the server names the transport.
    pub transport: String,
}

/// The `IUserDebugServices` subset ntoseye uses, one method per server call.
///
/// Every method returns the service's own result: a failed `HRESULT` is an
/// error, and the caller decides what a partial success means.
pub trait ProcessServer: Send {
    fn initialize(&mut self) -> Result<u32>;
    /// Tell the server which names to report, and read them back: it must
    /// happen before a process is attached.
    fn connection_info(&mut self) -> Result<ConnectionInfo>;
    fn uninitialize(&mut self, global: bool) -> Result<()>;
    fn target_info(&mut self) -> Result<TargetInfo>;
    fn process_ids(&mut self) -> Result<Vec<u32>>;
    /// The process's handle, its threads, and how many it has in total.
    fn process_info(
        &mut self,
        pid: u32,
        flags: u32,
        count: u32,
    ) -> Result<(u64, Vec<ThreadRecord>, u32)>;
    fn attach_process(&mut self, pid: u32, flags: u32) -> Result<AttachedProcess>;
    fn detach_process(&mut self, pid: u32) -> Result<()>;
    fn create_process(
        &mut self,
        command_line: &str,
        flags: u32,
        inherit_handles: bool,
        current_dir: Option<&str>,
    ) -> Result<CreatedProcess>;
    fn process_exit_code(&mut self, process: u64) -> Result<u32>;
    fn close_handle(&mut self, handle: u64) -> Result<()>;
    fn set_process_options(&mut self, process: u64, options: u32) -> Result<()>;
    fn set_debug_object_options(&mut self, object: u64, options: u32) -> Result<()>;
    fn process_debug_object(&mut self, process: u64) -> Result<u64>;
    /// Read into `buf`; returns the bytes the server read.
    fn read_virtual(&mut self, process: u64, address: u64, buf: &mut [u8]) -> Result<usize>;
    /// Write `buf`; returns the bytes the server wrote.
    fn write_virtual(&mut self, process: u64, address: u64, buf: &[u8]) -> Result<usize>;
    /// `VirtualQuery` at `address` into a buffer of `size` bytes, with the
    /// bytes the query used (`MEMORY_BASIC_INFORMATION`).
    fn query_virtual(&mut self, process: u64, address: u64, size: u32) -> Result<(Vec<u8>, u32)>;
    fn suspend_threads(&mut self, threads: &[u64]) -> Result<Vec<u32>>;
    fn resume_threads(&mut self, threads: &[u64]) -> Result<Vec<u32>>;
    /// The address the thread's function starts at, from
    /// `GetThreadBasicInfo`, whose arguments are the process's handle and
    /// then the thread's.
    fn thread_start_address(&mut self, process: u64, thread: u64) -> Result<u64>;
    /// The thread's raw `CONTEXT`, with `flags` written at `flags_offset`.
    fn get_context(
        &mut self,
        thread: u64,
        flags: u32,
        flags_offset: u32,
        size: u32,
    ) -> Result<(Vec<u8>, u32)>;
    fn set_context(&mut self, thread: u64, context: &[u8]) -> Result<u32>;
    fn process_data_offset(&mut self, process: u64) -> Result<u64>;
    fn thread_data_offset(&mut self, thread: u64) -> Result<u64>;
    /// Ask the server to break the process in; it answers nothing.
    fn request_break_in(&mut self, process: u64) -> Result<()>;
    /// The next debug event, `None` when none arrived within `timeout_ms`.
    fn wait_for_event(&mut self, timeout_ms: u32) -> Result<Option<Vec<u8>>>;
    fn continue_event(&mut self, status: u32) -> Result<()>;
    fn insert_code_breakpoint(
        &mut self,
        process: u64,
        address: u64,
        machine_type: u32,
    ) -> Result<Vec<u8>>;
    fn remove_code_breakpoint(
        &mut self,
        process: u64,
        address: u64,
        machine_type: u32,
        storage: &[u8],
    ) -> Result<()>;
    fn insert_data_breakpoint(
        &mut self,
        process: u64,
        thread: u64,
        address: u64,
        length: u32,
        access: u32,
        machine_type: u32,
    ) -> Result<()>;
    fn remove_data_breakpoint(
        &mut self,
        process: u64,
        thread: u64,
        address: u64,
        length: u32,
        access: u32,
        machine_type: u32,
    ) -> Result<()>;
    /// The data address and access type of the last data breakpoint hit.
    fn last_data_breakpoint_hit(&mut self, process: u64, thread: u64) -> Result<(u64, u32)>;
}

/// The storage the server may fill for one code breakpoint. dbgeng only uses
/// it when [`GENERIC_CODE_BREAKPOINTS`] is clear; 32 bytes covers every
/// architecture's.
const CODE_BREAKPOINT_STORAGE: u32 = 32;

/// `size` padded up to four bytes, as the proxy pads a buffer before the
/// `ULONG` that reports how many bytes of it it used.
fn padded(size: u32) -> u32 {
    size.saturating_add(3) & !3
}

/// A method's name, for the error a failed call reports.
fn method_name(method: u16) -> &'static str {
    match method {
        method::QUERY_INTERFACE => "QueryInterface",
        method::INITIALIZE => "Initialize",
        method::UNINITIALIZE => "Uninitialize",
        method::GET_TARGET_INFO => "GetTargetInfo",
        method::GET_CONNECTION_INFO => "GetConnectionInfo",
        method::GET_PROCESS_IDS => "GetProcessIds",
        method::GET_PROCESS_INFO => "GetProcessInfo",
        method::ATTACH_PROCESS => "AttachProcess",
        method::DETACH_PROCESS => "DetachProcess",
        method::CREATE_PROCESS_W => "CreateProcessW",
        method::GET_PROCESS_EXIT_CODE => "GetProcessExitCode",
        method::CLOSE_HANDLE => "CloseHandle",
        method::SET_PROCESS_OPTIONS => "SetProcessOptions",
        method::SET_DEBUG_OBJECT_OPTIONS => "SetDebugObjectOptions",
        method::GET_PROCESS_DEBUG_OBJECT => "GetProcessDebugObject",
        method::READ_VIRTUAL => "ReadVirtual",
        method::WRITE_VIRTUAL => "WriteVirtual",
        method::QUERY_VIRTUAL => "QueryVirtual",
        method::SUSPEND_THREADS => "SuspendThreads",
        method::RESUME_THREADS => "ResumeThreads",
        method::GET_THREAD_BASIC_INFO => "GetThreadBasicInfo",
        method::GET_CONTEXT => "GetContext",
        method::SET_CONTEXT => "SetContext",
        method::GET_PROCESS_DATA_OFFSET => "GetProcessDataOffset",
        method::GET_THREAD_DATA_OFFSET => "GetThreadDataOffset",
        method::REQUEST_BREAK_IN => "RequestBreakIn",
        method::WAIT_FOR_EVENT => "WaitForEvent",
        method::CONTINUE_EVENT => "ContinueEvent",
        method::INSERT_CODE_BREAKPOINT => "InsertCodeBreakpoint",
        method::REMOVE_CODE_BREAKPOINT => "RemoveCodeBreakpoint",
        method::INSERT_DATA_BREAKPOINT => "InsertDataBreakpoint",
        method::REMOVE_DATA_BREAKPOINT => "RemoveDataBreakpoint",
        method::GET_LAST_DATA_BREAKPOINT_HIT => "GetLastDataBreakpointHit",
        _ => "unknown method",
    }
}

/// The identity a connection announces: `MACHINE\user`, as UTF-16 like
/// DbgRpc's own client sends it. The server only reports it onward, so an
/// unknown machine or user name falls back to `ntoseye`.
fn identity() -> [u8; IDENTITY_LENGTH] {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "ntoseye".to_string());
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "debugger".to_string());
    let text = format!("{host}\\{user}");
    let mut identity = [0u8; IDENTITY_LENGTH];
    // Room for the terminator: 63 UTF-16 units.
    for (index, unit) in text.encode_utf16().take(63).enumerate() {
        identity[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    identity
}

/// A live DbgRpc connection: the transport, the process server object the
/// handshake returned, and the call sequence.
pub struct RpcService {
    transport: TcpTransport,
    /// The `IUserDebugServices` object sitting on the server.
    object: u64,
    sequence: u32,
}

impl RpcService {
    /// Connect `endpoint` and hand it to the `IUserDebugServices` server it
    /// names.
    pub fn connect(endpoint: &str, progress: &mut dyn FnMut(&str)) -> Result<Self> {
        let endpoint = parse_endpoint(endpoint)?;
        let DbgsrvEndpoint::Tcp { server, port } = &endpoint;
        progress(&format!("dbgsrv: connecting to {server}:{port}"));
        let transport = endpoint.connect()?;
        Self::handshake(transport, progress)
    }

    fn handshake(mut transport: TcpTransport, progress: &mut dyn FnMut(&str)) -> Result<Self> {
        let identity = identity();
        let request = Handshake::client(IID_USER_DEBUG_SERVICES);
        transport.write_all(request.as_bytes())?;
        transport.write_all(&identity)?;
        let mut reply = vec![0u8; core::mem::size_of::<Handshake>()];
        transport.read_exact(&mut reply)?;
        let reply = Handshake::parse(&reply)?;
        if reply.remote_object == 0 {
            return Err(Error::DebugInfo(
                "dbgsrv: the server refused the connection: its handshake names no object".into(),
            ));
        }
        // Every call is answered, so a read only ever waits for a call this
        // side has already sent.
        transport.set_read_timeout(None)?;
        let mut service = Self {
            transport,
            object: reply.remote_object,
            sequence: 0,
        };
        // The interface's revision is checked before any method whose layout
        // could differ: a server built against another `dbgsvc.h` must be
        // refused, not decoded with the wrong field order.
        service.query_interface()?;
        progress(&format!(
            "dbgsrv: IUserDebugServices revision {UNIQUE_USER_DEBUG_SERVICES} on object {:#x}",
            service.object
        ));
        Ok(service)
    }

    /// `QueryInterface` for this client's revision of `IUserDebugServices`,
    /// which becomes the object every later call names.
    fn query_interface(&mut self) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&IID_USER_DEBUG_SERVICES);
        body.segment(&layout::InterfaceVersion {
            code: UNIQUE_USER_DEBUG_SERVICES,
        });
        let (status, data) = self.call(method::QUERY_INTERFACE, body, 8, false)?;
        if !succeeded(status) {
            return Err(Error::DebugInfo(format!(
                "dbgsrv: the process server speaks a different IUserDebugServices revision than \
                 this build of ntoseye: it refused revision {UNIQUE_USER_DEBUG_SERVICES} with \
                 HRESULT {status:#010x}. ntoseye implements the revision described by the \
                 Windows Server 2003 SDK's dbgsvc.h; a server built against another one needs \
                 that interface definition"
            )));
        }
        let object: layout::OffsetRet =
            Reader::new(&data, method_name(method::QUERY_INTERFACE)).take()?;
        if object.offset != 0 {
            self.object = object.offset;
        }
        Ok(())
    }

    /// The endpoint this is connected to, for messages.
    pub fn describe(&self) -> &str {
        self.transport.describe()
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1);
        self.sequence
    }

    /// Send one call and read its reply: the status the server answered with
    /// and the reply body.
    fn call(
        &mut self,
        method: u16,
        body: Writer,
        out_size: u32,
        no_return: bool,
    ) -> Result<(u32, Vec<u8>)> {
        let body = body.into_inner();
        let sequence = self.next_sequence();
        let call = Call {
            object_id: self.object,
            stub_index: stub_index(method),
            flags: if no_return {
                CALL_NO_RETURN
            } else {
                CALL_LOCKED
            },
            in_size: body.len() as u32,
            out_size: if no_return { 0 } else { out_size },
            status: 0,
            sequence,
            reserved1: 0,
        };
        let name = method_name(method);
        self.transport.write_all(call.as_bytes())?;
        if !body.is_empty() {
            self.transport.write_all(&body)?;
        }
        if no_return {
            return Ok((0, Vec::new()));
        }
        let mut header = vec![0u8; core::mem::size_of::<Call>()];
        self.transport.read_exact(&mut header)?;
        let reply = Call::read_from_bytes(&header)
            .map_err(|_| Error::DebugInfo(format!("dbgsrv {name}: undecodable reply header")))?;
        if !reply.is_return() {
            return Err(Error::DebugInfo(format!(
                "dbgsrv {name}: the server sent a call instead of a reply"
            )));
        }
        if reply.sequence != sequence || reply.stub_index != call.stub_index {
            return Err(Error::DebugInfo(format!(
                "dbgsrv {name}: expected reply {sequence} to stub {:#x}, got reply {} to stub \
                 {:#x}",
                call.stub_index, reply.sequence, reply.stub_index
            )));
        }
        if reply.out_size > MAX_REPLY_BYTES {
            return Err(Error::DebugInfo(format!(
                "dbgsrv {name}: the server named a {} byte reply, more than the \
                 {MAX_REPLY_BYTES} accepted",
                reply.out_size
            )));
        }
        let mut data = vec![0u8; reply.out_size as usize];
        if !data.is_empty() {
            self.transport.read_exact(&mut data)?;
        }
        // `S_FALSE` is a reply with nothing in it (a timed-out wait), so
        // only a call that succeeded outright must fill the size asked for.
        if reply.status == 0 && reply.out_size != out_size {
            return Err(Error::DebugInfo(format!(
                "dbgsrv {name}: reply holds {} bytes, {out_size} expected",
                reply.out_size
            )));
        }
        Ok((reply.status, data))
    }

    /// [`Self::call`] for a method that must succeed.
    fn call_ok(&mut self, method: u16, body: Writer, out_size: u32) -> Result<Vec<u8>> {
        let (status, data) = self.call(method, body, out_size, false)?;
        if !succeeded(status) {
            return Err(self.failure(method, status));
        }
        Ok(data)
    }

    fn failure(&self, method: u16, status: u32) -> Error {
        Error::DebugInfo(format!(
            "dbgsrv {}(stub {:#x}) failed: HRESULT {status:#010x}",
            method_name(method),
            stub_index(method)
        ))
    }

    /// One of the two names `GetConnectionInfo` reports: the machine's, at
    /// offset zero, or the transport's, with the machine's field zero bytes
    /// wide. The server ends a name it wrote; a buffer it only partly filled
    /// ends at the first byte that is not a printable character.
    fn connection_name(
        &mut self,
        machine_size: u32,
        transport_size: u32,
        transport: bool,
    ) -> Result<String> {
        let (machine, transport_field) = if transport {
            (0, transport_size)
        } else {
            (machine_size, 0)
        };
        let mut body = Writer::new();
        body.segment(&layout::GetConnectionInfoArgs {
            machine_name_size: machine,
            client_identity_size: 0,
            transport_identity_size: transport_field,
        });
        let data = self.call_ok(
            method::GET_CONNECTION_INFO,
            body,
            2 * (machine + transport_field),
        )?;
        let units: Vec<u16> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .take_while(|unit| *unit != 0 && (0x20..0x7f).contains(unit))
            .collect();
        Ok(String::from_utf16_lossy(&units))
    }

    /// `SuspendThreads`/`ResumeThreads`, whose layouts are identical: the
    /// count, the `size_is` count, the handles, and each thread's suspend
    /// count in the reply.
    fn thread_counts(&mut self, method: u16, threads: &[u64]) -> Result<Vec<u32>> {
        let count = u32::try_from(threads.len()).map_err(|_| {
            Error::InvalidArgument("dbgsrv thread count does not fit in a u32".to_string())
        })?;
        let mut body = Writer::new();
        body.segment(&layout::ThreadCountArgs {
            count,
            array_count: count,
        });
        body.align(8);
        for thread in threads {
            body.segment(thread);
        }
        let data = self.call_ok(method, body, count * 4)?;
        let mut reader = Reader::new(&data, method_name(method));
        reader.take_array(count as usize)
    }

    /// The arguments of a call that names one address in one process: the
    /// process and the address, then the size of the buffer that follows.
    fn address_args(process: u64, offset: u64, size: u32) -> Writer {
        let mut body = Writer::new();
        body.segment(&layout::AddressArgs { process, offset });
        body.segment(&layout::SizeArg { size });
        body
    }
}

impl ProcessServer for RpcService {
    fn initialize(&mut self) -> Result<u32> {
        let data = self.call_ok(method::INITIALIZE, Writer::new(), 4)?;
        let ret: layout::InitializeRet =
            Reader::new(&data, method_name(method::INITIALIZE)).take()?;
        Ok(ret.flags)
    }

    fn connection_info(&mut self) -> Result<ConnectionInfo> {
        // One name per call: the reply has no "used" lengths, so a buffer
        // holding two names leaves whatever the server did not write between
        // them, and only the name at offset zero is unambiguous.
        const MACHINE: u32 = 64;
        const TRANSPORT: u32 = 256;
        let machine = self
            .connection_name(MACHINE, TRANSPORT, false)
            .unwrap_or_default();
        let transport = self
            .connection_name(MACHINE, TRANSPORT, true)
            .unwrap_or_default();
        Ok(ConnectionInfo { machine, transport })
    }

    fn uninitialize(&mut self, global: bool) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::BoolArg {
            value: u32::from(global),
        });
        self.call_ok(method::UNINITIALIZE, body, 0).map(drop)
    }

    fn target_info(&mut self) -> Result<TargetInfo> {
        // No CSD or build strings: nothing here reads them, and their sizes
        // shape the reply body.
        let mut body = Writer::new();
        body.segment(&layout::GetTargetInfoArgs {
            csd_string_size: 0,
            build_string_size: 0,
        });
        let data = self.call_ok(
            method::GET_TARGET_INFO,
            body,
            core::mem::size_of::<layout::TargetInfoRet>() as u32,
        )?;
        let ret: layout::TargetInfoRet =
            Reader::new(&data, method_name(method::GET_TARGET_INFO)).take()?;
        Ok(TargetInfo {
            machine_type: ret.machine_type,
            processors: ret.number_processors,
            platform_id: ret.platform_id,
            major_version: ret.major_version,
            minor_version: ret.minor_version,
            build_number: ret.build_number,
            checked_build: ret.checked_build,
            product_type: ret.product_type,
            suite_mask: ret.suite_mask,
        })
    }

    fn process_ids(&mut self) -> Result<Vec<u32>> {
        /// How many processes one request asks for before growing it.
        const START: u32 = 256;

        let mut body = Writer::new();
        body.segment(&layout::GetProcessIdsArgs { count: START });
        let data = self.call_ok(method::GET_PROCESS_IDS, body, START * 4 + 4)?;
        let mut reader = Reader::new(&data, method_name(method::GET_PROCESS_IDS));
        let ids = reader.take_array::<layout::ProcessId>(START as usize)?;
        let actual: layout::ActualCountRet = reader.take()?;
        let ids: Vec<u32> = ids.into_iter().map(|id| id.process_id).collect();
        if actual.actual <= START {
            return Ok(ids.into_iter().take(actual.actual as usize).collect());
        }
        // More processes than the array held: ask for all of them.
        let count = actual.actual;
        let mut body = Writer::new();
        body.segment(&layout::GetProcessIdsArgs { count });
        let data = self.call_ok(method::GET_PROCESS_IDS, body, count * 4 + 4)?;
        let mut reader = Reader::new(&data, method_name(method::GET_PROCESS_IDS));
        let ids = reader.take_array::<layout::ProcessId>(count as usize)?;
        let total: layout::ActualCountRet = reader.take()?;
        Ok(ids
            .into_iter()
            .map(|id| id.process_id)
            .take(total.actual as usize)
            .collect())
    }

    fn process_info(
        &mut self,
        pid: u32,
        flags: u32,
        count: u32,
    ) -> Result<(u64, Vec<ThreadRecord>, u32)> {
        let count = count.min(MAX_PROCESS_THREADS);
        let record = core::mem::size_of::<layout::UserThreadInfo>() as u32;
        let mut body = Writer::new();
        body.segment(&layout::GetProcessInfoArgs {
            process_id: pid,
            flags,
            info_count: count,
        });
        // The handle, then the thread array aligned to its record, then the
        // count: the handle's eight bytes are padded to sixteen.
        let out_size = count
            .checked_mul(record)
            .and_then(|bytes| bytes.checked_add(16 + 4))
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "dbgsrv GetProcessInfo cannot describe {count} threads in one reply"
                ))
            })?;
        let data = self.call_ok(method::GET_PROCESS_INFO, body, out_size)?;
        let mut reader = Reader::new(&data, method_name(method::GET_PROCESS_INFO));
        let handle: layout::HandleArg = reader.take()?;
        reader.align(16);
        let threads = reader.take_array::<layout::UserThreadInfo>(count as usize)?;
        let total: layout::ActualCountRet = reader.take()?;
        let threads = threads
            .into_iter()
            .take((total.actual as usize).min(count as usize))
            .map(|thread| ThreadRecord {
                handle: thread.handle,
                tid: thread.id,
            })
            .collect();
        Ok((handle.handle, threads, total.actual))
    }

    fn attach_process(&mut self, pid: u32, flags: u32) -> Result<AttachedProcess> {
        let mut body = Writer::new();
        body.segment(&layout::AttachProcessArgs {
            process_id: pid,
            attach_flags: flags,
        });
        let data = self.call_ok(method::ATTACH_PROCESS, body, 12)?;
        let mut reader = Reader::new(&data, method_name(method::ATTACH_PROCESS));
        let handle: layout::HandleArg = reader.take()?;
        let options: layout::ProcessOptionsRet = reader.take()?;
        Ok(AttachedProcess {
            handle: handle.handle,
            options: options.options,
        })
    }

    fn detach_process(&mut self, pid: u32) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::DetachProcessArgs { process_id: pid });
        self.call_ok(method::DETACH_PROCESS, body, 0).map(drop)
    }

    fn create_process(
        &mut self,
        command_line: &str,
        flags: u32,
        inherit_handles: bool,
        current_dir: Option<&str>,
    ) -> Result<CreatedProcess> {
        // The request is the command line, then `_DEBUG_CREATE_PROCESS_OPTIONS`,
        // then two length-prefixed strings (the current directory and the
        // environment), each aligned to four bytes.
        let wide = |value: &str| -> Vec<u8> {
            value
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect()
        };
        let command_line = wide(command_line);
        let current_dir = current_dir.map(wide).unwrap_or_default();
        for (what, bytes) in [
            ("command line", &command_line),
            ("current directory", &current_dir),
        ] {
            if u32::try_from(bytes.len()).is_err() {
                return Err(Error::InvalidArgument(format!(
                    "the {what} is too long for a process server request"
                )));
            }
        }
        let mut create_flags = flags;
        if inherit_handles {
            create_flags |= DEBUG_CREATE_PROCESS_INHERIT_HANDLES;
        }
        let mut body = Writer::new();
        body.buffer(&command_line, 2);
        body.align(4);
        body.segment(&layout::CreateProcessOptions {
            create_flags,
            eng_create_flags: 0,
            verifier_flags: 0,
            reserved: 0,
        });
        body.segment(&layout::SizeArg {
            size: current_dir.len() as u32,
        });
        body.buffer(&current_dir, 1);
        body.align(4);
        body.segment(&layout::SizeArg { size: 0 }); // no environment block
        let data = self.call_ok(
            method::CREATE_PROCESS_W,
            body,
            core::mem::size_of::<layout::CreatedProcessRet>() as u32,
        )?;
        let created: layout::CreatedProcessRet =
            Reader::new(&data, method_name(method::CREATE_PROCESS_W)).take()?;
        Ok(CreatedProcess {
            pid: created.process_id,
            tid: created.thread_id,
            process_handle: created.process_handle,
            thread_handle: created.thread_handle,
        })
    }

    fn process_exit_code(&mut self, process: u64) -> Result<u32> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: process });
        let data = self.call_ok(method::GET_PROCESS_EXIT_CODE, body, 4)?;
        let ret: layout::ExitCodeRet =
            Reader::new(&data, method_name(method::GET_PROCESS_EXIT_CODE)).take()?;
        Ok(ret.exit_code)
    }

    fn close_handle(&mut self, handle: u64) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle });
        self.call_ok(method::CLOSE_HANDLE, body, 0).map(drop)
    }

    fn set_process_options(&mut self, process: u64, options: u32) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: process });
        body.segment(&layout::OptionsArg { options });
        self.call_ok(method::SET_PROCESS_OPTIONS, body, 0).map(drop)
    }

    fn set_debug_object_options(&mut self, object: u64, options: u32) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: object });
        body.segment(&layout::OptionsArg { options });
        self.call_ok(method::SET_DEBUG_OBJECT_OPTIONS, body, 0)
            .map(drop)
    }

    fn process_debug_object(&mut self, process: u64) -> Result<u64> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: process });
        let data = self.call_ok(method::GET_PROCESS_DEBUG_OBJECT, body, 8)?;
        let ret: layout::OffsetRet =
            Reader::new(&data, method_name(method::GET_PROCESS_DEBUG_OBJECT)).take()?;
        Ok(ret.offset)
    }

    fn read_virtual(&mut self, process: u64, address: u64, buf: &mut [u8]) -> Result<usize> {
        let size = u32::try_from(buf.len()).map_err(|_| {
            Error::InvalidArgument(format!(
                "dbgsrv ReadVirtual cannot read {} bytes in one call",
                buf.len()
            ))
        })?;
        let data = self.call_ok(
            method::READ_VIRTUAL,
            Self::address_args(process, address, size),
            padded(size) + 4,
        )?;
        let mut reader = Reader::new(&data, method_name(method::READ_VIRTUAL));
        let bytes = reader.bytes(size as usize, 1)?;
        buf.copy_from_slice(bytes);
        // The proxy aligns the trailer to four bytes after the buffer.
        let ret: layout::UsedRet = reader.align(4).take()?;
        Ok(ret.used as usize)
    }

    fn write_virtual(&mut self, process: u64, address: u64, buf: &[u8]) -> Result<usize> {
        let size = u32::try_from(buf.len()).map_err(|_| {
            Error::InvalidArgument(format!(
                "dbgsrv WriteVirtual cannot write {} bytes in one call",
                buf.len()
            ))
        })?;
        let mut body = Self::address_args(process, address, size);
        body.buffer(buf, 1);
        body.tail(&layout::SizeArg { size }, 4);
        let data = self.call_ok(method::WRITE_VIRTUAL, body, 4)?;
        let ret: layout::UsedRet = Reader::new(&data, method_name(method::WRITE_VIRTUAL)).take()?;
        Ok(ret.used as usize)
    }

    fn query_virtual(&mut self, process: u64, address: u64, size: u32) -> Result<(Vec<u8>, u32)> {
        let data = self.call_ok(
            method::QUERY_VIRTUAL,
            Self::address_args(process, address, size),
            padded(size) + 4,
        )?;
        let mut reader = Reader::new(&data, method_name(method::QUERY_VIRTUAL));
        let bytes = reader.bytes(size as usize, 1)?.to_vec();
        let ret: layout::UsedRet = reader.align(4).take()?;
        Ok((bytes, ret.used))
    }

    fn suspend_threads(&mut self, threads: &[u64]) -> Result<Vec<u32>> {
        self.thread_counts(method::SUSPEND_THREADS, threads)
    }

    fn resume_threads(&mut self, threads: &[u64]) -> Result<Vec<u32>> {
        self.thread_counts(method::RESUME_THREADS, threads)
    }

    fn thread_start_address(&mut self, process: u64, thread: u64) -> Result<u64> {
        // The modern interface has no `GetThreadStartAddress`: the thread's
        // basic information carries the address its function starts at. Its
        // arguments are `(Process, Thread)`: the server asks the process for
        // its priority class and the thread for its start address.
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: process });
        body.segment(&layout::HandleArg { handle: thread });
        let data = self.call_ok(
            method::GET_THREAD_BASIC_INFO,
            body,
            core::mem::size_of::<layout::ThreadBasicInformation>() as u32,
        )?;
        let info: layout::ThreadBasicInformation =
            Reader::new(&data, method_name(method::GET_THREAD_BASIC_INFO)).take()?;
        Ok(info.start_offset)
    }

    fn get_context(
        &mut self,
        thread: u64,
        flags: u32,
        flags_offset: u32,
        size: u32,
    ) -> Result<(Vec<u8>, u32)> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: thread });
        body.segment(&layout::GetContextArgs {
            flags,
            flags_offset,
            context_size: size,
        });
        let data = self.call_ok(method::GET_CONTEXT, body, padded(size) + 4)?;
        let mut reader = Reader::new(&data, method_name(method::GET_CONTEXT));
        let context = reader.bytes(size as usize, 1)?.to_vec();
        let ret: layout::UsedRet = reader.align(4).take()?;
        Ok((context, ret.used))
    }

    fn set_context(&mut self, thread: u64, context: &[u8]) -> Result<u32> {
        let size = u32::try_from(context.len()).map_err(|_| {
            Error::InvalidArgument(format!(
                "dbgsrv SetContext cannot write {} bytes in one call",
                context.len()
            ))
        })?;
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: thread });
        body.segment(&layout::SizeArg { size });
        body.buffer(context, 1);
        body.tail(&layout::SizeArg { size }, 4);
        let data = self.call_ok(method::SET_CONTEXT, body, 4)?;
        let ret: layout::UsedRet = Reader::new(&data, method_name(method::SET_CONTEXT)).take()?;
        Ok(ret.used)
    }

    fn process_data_offset(&mut self, process: u64) -> Result<u64> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: process });
        let data = self.call_ok(method::GET_PROCESS_DATA_OFFSET, body, 8)?;
        let ret: layout::OffsetRet =
            Reader::new(&data, method_name(method::GET_PROCESS_DATA_OFFSET)).take()?;
        Ok(ret.offset)
    }

    fn thread_data_offset(&mut self, thread: u64) -> Result<u64> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: thread });
        let data = self.call_ok(method::GET_THREAD_DATA_OFFSET, body, 8)?;
        let ret: layout::OffsetRet =
            Reader::new(&data, method_name(method::GET_THREAD_DATA_OFFSET)).take()?;
        Ok(ret.offset)
    }

    fn request_break_in(&mut self, process: u64) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: process });
        self.call(method::REQUEST_BREAK_IN, body, 0, true).map(drop)
    }

    fn wait_for_event(&mut self, timeout_ms: u32) -> Result<Option<Vec<u8>>> {
        let mut body = Writer::new();
        body.segment(&layout::WaitForEventArgs {
            timeout: timeout_ms,
            buffer_size: DEBUG_EVENT_SIZE,
        });
        let (status, data) =
            self.call(method::WAIT_FOR_EVENT, body, DEBUG_EVENT_SIZE + 4, false)?;
        if status == S_FALSE {
            return Ok(None);
        }
        if !succeeded(status) {
            return Err(self.failure(method::WAIT_FOR_EVENT, status));
        }
        let mut reader = Reader::new(&data, method_name(method::WAIT_FOR_EVENT));
        let event = reader.bytes(DEBUG_EVENT_SIZE as usize, 1)?.to_vec();
        let used: layout::UsedRet = reader.align(4).take()?;
        let used = (used.used as usize).min(event.len());
        Ok(Some(event[..used].to_vec()))
    }

    fn continue_event(&mut self, status: u32) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::ContinueEventArgs { status });
        self.call_ok(method::CONTINUE_EVENT, body, 0).map(drop)
    }

    fn insert_code_breakpoint(
        &mut self,
        process: u64,
        address: u64,
        machine_type: u32,
    ) -> Result<Vec<u8>> {
        let mut body = Writer::new();
        body.segment(&layout::CodeBreakpointArgs {
            process,
            offset: address,
            machine_type,
            storage_size: CODE_BREAKPOINT_STORAGE,
        });
        self.call_ok(
            method::INSERT_CODE_BREAKPOINT,
            body,
            CODE_BREAKPOINT_STORAGE,
        )
    }

    fn remove_code_breakpoint(
        &mut self,
        process: u64,
        address: u64,
        machine_type: u32,
        storage: &[u8],
    ) -> Result<()> {
        let size = storage.len() as u32;
        let mut body = Writer::new();
        body.segment(&layout::CodeBreakpointArgs {
            process,
            offset: address,
            machine_type,
            storage_size: size,
        });
        body.buffer(storage, 1);
        body.tail(&layout::SizeArg { size }, 4);
        self.call_ok(method::REMOVE_CODE_BREAKPOINT, body, 0)
            .map(drop)
    }

    fn insert_data_breakpoint(
        &mut self,
        process: u64,
        thread: u64,
        address: u64,
        length: u32,
        access: u32,
        machine_type: u32,
    ) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::WatchedAddressArgs {
            process,
            thread,
            offset: address,
        });
        body.segment(&layout::WatchArgs {
            access_length: length,
            access_type: access,
            machine_type,
        });
        self.call_ok(method::INSERT_DATA_BREAKPOINT, body, 0)
            .map(drop)
    }

    fn remove_data_breakpoint(
        &mut self,
        process: u64,
        thread: u64,
        address: u64,
        length: u32,
        access: u32,
        machine_type: u32,
    ) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&layout::WatchedAddressArgs {
            process,
            thread,
            offset: address,
        });
        body.segment(&layout::WatchArgs {
            access_length: length,
            access_type: access,
            machine_type,
        });
        self.call_ok(method::REMOVE_DATA_BREAKPOINT, body, 0)
            .map(drop)
    }

    fn last_data_breakpoint_hit(&mut self, process: u64, thread: u64) -> Result<(u64, u32)> {
        let mut body = Writer::new();
        body.segment(&layout::HandleArg { handle: process });
        body.segment(&layout::HandleArg { handle: thread });
        let data = self.call_ok(method::GET_LAST_DATA_BREAKPOINT_HIT, body, 12)?;
        let mut reader = Reader::new(&data, method_name(method::GET_LAST_DATA_BREAKPOINT_HIT));
        let address: layout::OffsetRet = reader.take()?;
        let access: layout::AccessTypeRet = reader.take()?;
        Ok((address.offset, access.access_type))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_indices_are_the_interface_shifted_over_the_method() {
        assert_eq!(stub_index(method::QUERY_INTERFACE), 0xc000);
        assert_eq!(stub_index(method::INITIALIZE), 0xc002);
        assert_eq!(stub_index(method::ATTACH_PROCESS), 0xc00f);
        assert_eq!(stub_index(method::WAIT_FOR_EVENT), 0xc030);
        assert_eq!(method_name(method::READ_VIRTUAL), "ReadVirtual");
    }
}
