//! The `IUserDebugServices` process-server client: the method subset ntoseye
//! drives a live user-mode target with, and the DbgRpc encoding of each.
//!
//! [`ProcessServer`] is the interface the backend talks to, so tests drive a
//! mock; [`RpcService`] is the one that puts the bytes on the wire.

use zerocopy::{FromBytes, IntoBytes};

use crate::base::error::{Error, Result};

use super::layout;
use super::transport::{DbgsrvEndpoint, TcpTransport, parse_endpoint};
use super::wire::{
    CALL_LOCKED, CALL_NO_RETURN, Call, Handshake, IDENTITY_LENGTH, IID_USER_DEBUG_SERVICES, Method,
    Reader, UNIQUE_USER_DEBUG_SERVICES, Writer, align_up_u32, size_of_wire,
    sized_buffer_reply_size, succeeded,
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

/// `S_FALSE`: the server's "nothing yet" for a timed-out wait.
const S_FALSE: u32 = 0x0000_0001;

/// `HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)`.
pub const E_ACCESSDENIED: u32 = 0x8007_0005;

/// `HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER)`: what `AttachProcess` returns
/// when no process has the requested PID.
pub const E_INVALIDARG: u32 = 0x8007_0057;

/// Bytes of a 64-bit Windows `DEBUG_EVENT`: what the server requires the
/// caller's buffer to hold.
pub const DEBUG_EVENT_SIZE: u32 = super::events::DEBUG_EVENT_SIZE as u32;

/// The largest reply body this client accepts. Every reply it asks for is
/// smaller, so a header naming more is corrupt rather than a large answer.
const MAX_REPLY_BYTES: u32 = 16 * 1024 * 1024;

/// How many threads one process may report, which bounds the array a
/// `GetProcessInfo` retry asks for.
pub const MAX_PROCESS_THREADS: u32 = 65_536;

/// The storage the server may fill for one code breakpoint when
/// [`GENERIC_CODE_BREAKPOINTS`] is clear; 32 bytes covers every architecture.
const CODE_BREAKPOINT_STORAGE: u32 = 32;

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

/// One thread of a process, as `GetProcessInfo` lists it (`USER_THREAD_INFO`).
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
    fn target_info(&mut self) -> Result<TargetInfo>;
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
    fn close_handle(&mut self, handle: u64) -> Result<()>;
    /// Read into `buf`; returns the bytes the server read.
    fn read_virtual(&mut self, process: u64, address: u64, buf: &mut [u8]) -> Result<usize>;
    /// Write `buf`; returns the bytes the server wrote.
    fn write_virtual(&mut self, process: u64, address: u64, buf: &[u8]) -> Result<usize>;
    /// `VirtualQuery` at `address` into a buffer of `size` bytes, with the
    /// bytes the query used (`MEMORY_BASIC_INFORMATION`).
    fn query_virtual(&mut self, process: u64, address: u64, size: u32) -> Result<(Vec<u8>, u32)>;
    /// The address the thread's function starts at, from `GetThreadBasicInfo`.
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
}

/// The identity a connection announces: `MACHINE\user`, as UTF-16 like
/// DbgRpc's own client sends it.
fn identity() -> [u8; IDENTITY_LENGTH] {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "ntoseye".to_string());
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "debugger".to_string());
    let text = format!("{host}\\{user}");
    let mut identity = [0u8; IDENTITY_LENGTH];
    // Reserve one UTF-16 code unit for the NUL terminator.
    let max_units = (IDENTITY_LENGTH / 2) - 1;
    for (index, unit) in text.encode_utf16().take(max_units).enumerate() {
        identity[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    identity
}

/// Encode `text` as a NUL-terminated UTF-16LE byte vector.
fn encode_utf16_nul(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// Decode a connection name from an uninitialized UTF-16LE reply buffer: stops
/// at NUL or the first non-printable ASCII code unit left by the server.
fn decode_connection_name(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0 && (0x20..0x7f).contains(unit))
        .collect();
    String::from_utf16_lossy(&units)
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
        let mut reply = [0u8; core::mem::size_of::<Handshake>()];
        transport.read_exact(&mut reply)?;
        let reply = Handshake::parse(&reply)?;
        if reply.remote_object == 0 {
            return Err(Error::Dbgsrv(
                "the server refused the connection: its handshake names no object".into(),
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
        // Check the interface revision before issuing any method whose field
        // layout could differ across `dbgsvc.h` versions.
        service.query_interface()?;
        progress(&format!(
            "dbgsrv: IUserDebugServices revision {UNIQUE_USER_DEBUG_SERVICES:#x} on object {:#x}",
            service.object
        ));
        Ok(service)
    }

    /// `QueryInterface` for this client's revision of `IUserDebugServices`,
    /// which becomes the object every later call names.
    fn query_interface(&mut self) -> Result<()> {
        let mut body = Writer::new();
        body.segment(&IID_USER_DEBUG_SERVICES)
            .write_u32(UNIQUE_USER_DEBUG_SERVICES);
        let (status, data) =
            self.call(Method::QueryInterface, body, size_of_wire::<u64>(), false)?;
        if !succeeded(status) {
            return Err(Error::Dbgsrv(format!(
                "the process server speaks a different IUserDebugServices revision than \
                 this build of ntoseye: it refused revision {UNIQUE_USER_DEBUG_SERVICES:#x} with \
                 HRESULT {status:#010x}"
            )));
        }
        let object = Reader::new(&data, Method::QueryInterface).read_u64()?;
        if object != 0 {
            self.object = object;
        }
        Ok(())
    }

    fn next_sequence(&mut self) -> u32 {
        self.sequence = self.sequence.wrapping_add(1);
        self.sequence
    }

    /// Send one call and read its reply: the status the server answered with
    /// and the reply body.
    fn call(
        &mut self,
        method: Method,
        body: Writer,
        out_size: u32,
        no_return: bool,
    ) -> Result<(u32, Vec<u8>)> {
        let body = body.into_inner();
        let sequence = self.next_sequence();
        let call = Call {
            object_id: self.object,
            stub_index: method.stub_index(),
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
        let name = method.name();
        self.transport.write_all(call.as_bytes())?;
        if !body.is_empty() {
            self.transport.write_all(&body)?;
        }
        if no_return {
            return Ok((0, Vec::new()));
        }
        let mut header = [0u8; core::mem::size_of::<Call>()];
        self.transport.read_exact(&mut header)?;
        let reply = Call::read_from_bytes(&header)
            .map_err(|_| Error::Dbgsrv(format!("{name}: undecodable reply header")))?;
        if !reply.is_return() {
            return Err(Error::Dbgsrv(format!(
                "{name}: the server sent a call instead of a reply"
            )));
        }
        if reply.sequence != sequence || reply.stub_index != call.stub_index {
            return Err(Error::Dbgsrv(format!(
                "{name}: expected reply {sequence} to stub {:#x}, got reply {} to stub {:#x}",
                call.stub_index, reply.sequence, reply.stub_index
            )));
        }
        if reply.out_size > MAX_REPLY_BYTES {
            return Err(Error::Dbgsrv(format!(
                "{name}: the server named a {} byte reply, more than the {MAX_REPLY_BYTES} \
                 accepted",
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
            return Err(Error::Dbgsrv(format!(
                "{name}: reply holds {} bytes, {out_size} expected",
                reply.out_size
            )));
        }
        Ok((reply.status, data))
    }

    /// [`Self::call`] for a method that must succeed.
    fn call_ok(&mut self, method: Method, body: Writer, out_size: u32) -> Result<Vec<u8>> {
        let (status, data) = self.call(method, body, out_size, false)?;
        if !succeeded(status) {
            return Err(self.failure(method, status));
        }
        Ok(data)
    }

    fn failure(&self, method: Method, status: u32) -> Error {
        Error::DbgsrvStatus {
            method: method.name(),
            stub: method.stub_index(),
            status,
        }
    }

    /// Issue a call taking one 64-bit handle and returning one 64-bit value.
    fn call_handle_u64(&mut self, method: Method, handle: u64) -> Result<u64> {
        let mut body = Writer::new();
        body.write_u64(handle);
        let data = self.call_ok(method, body, size_of_wire::<u64>())?;
        Reader::new(&data, method).read_u64()
    }

    /// Issue a call returning a `size`-byte output buffer and its `used` count.
    fn call_sized_buffer(
        &mut self,
        method: Method,
        body: Writer,
        size: u32,
    ) -> Result<(Vec<u8>, u32)> {
        let data = self.call_ok(method, body, sized_buffer_reply_size(size))?;
        let mut reader = Reader::new(&data, method);
        let (bytes, used) = reader.sized_bytes(size as usize)?;
        Ok((bytes.to_vec(), used))
    }

    /// One name from `GetConnectionInfo`: pass non-zero width for either
    /// `machine` or `transport` so the returned name starts at offset zero.
    fn connection_name(&mut self, machine: u32, transport: u32) -> Result<String> {
        let mut body = Writer::new();
        body.segment(&layout::GetConnectionInfoArgs {
            machine_name_size: machine,
            client_identity_size: 0,
            transport_identity_size: transport,
        });
        let data = self.call_ok(Method::GetConnectionInfo, body, 2 * (machine + transport))?;
        Ok(decode_connection_name(&data))
    }

    /// Arguments for a call naming `(process, offset, size)`.
    fn address_args(process: u64, offset: u64, size: u32) -> Writer {
        let mut body = Writer::new();
        body.segment(&layout::AddressArgs { process, offset })
            .write_u32(size);
        body
    }
}

impl ProcessServer for RpcService {
    fn initialize(&mut self) -> Result<u32> {
        let data = self.call_ok(Method::Initialize, Writer::new(), size_of_wire::<u32>())?;
        Reader::new(&data, Method::Initialize).read_u32()
    }

    fn connection_info(&mut self) -> Result<ConnectionInfo> {
        // One name per call: the reply has no "used" lengths, so asking for
        // one field at a time guarantees it starts at offset zero.
        const MACHINE_UNITS: u32 = 64;
        const TRANSPORT_UNITS: u32 = 256;
        let machine = self.connection_name(MACHINE_UNITS, 0).unwrap_or_default();
        let transport = self.connection_name(0, TRANSPORT_UNITS).unwrap_or_default();
        Ok(ConnectionInfo { machine, transport })
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
            Method::GetTargetInfo,
            body,
            size_of_wire::<layout::TargetInfoRet>(),
        )?;
        let ret: layout::TargetInfoRet = Reader::new(&data, Method::GetTargetInfo).take()?;
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

    fn process_info(
        &mut self,
        pid: u32,
        flags: u32,
        count: u32,
    ) -> Result<(u64, Vec<ThreadRecord>, u32)> {
        let count = count.min(MAX_PROCESS_THREADS);
        let record_size = size_of_wire::<layout::UserThreadInfo>();
        let mut body = Writer::new();
        body.segment(&layout::GetProcessInfoArgs {
            process_id: pid,
            flags,
            info_count: count,
        });
        // The process handle (8 bytes) is padded to `sizeof(USER_THREAD_INFO)`
        // (16 bytes) before the thread array, followed by the actual count.
        let array_offset = align_up_u32(size_of_wire::<u64>(), record_size);
        let out_size = count
            .checked_mul(record_size)
            .and_then(|bytes| bytes.checked_add(array_offset + size_of_wire::<u32>()))
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "dbgsrv GetProcessInfo cannot describe {count} threads in one reply"
                ))
            })?;
        let data = self.call_ok(Method::GetProcessInfo, body, out_size)?;
        let mut reader = Reader::new(&data, Method::GetProcessInfo);
        let handle = reader.read_u64()?;
        reader.align(record_size as usize);
        let threads = reader.take_array::<layout::UserThreadInfo>(count as usize)?;
        let total = reader.read_u32()?;
        let threads = threads
            .into_iter()
            .take((total as usize).min(count as usize))
            .map(|thread| ThreadRecord {
                handle: thread.handle,
                tid: thread.id,
            })
            .collect();
        Ok((handle, threads, total))
    }

    fn attach_process(&mut self, pid: u32, flags: u32) -> Result<AttachedProcess> {
        let mut body = Writer::new();
        body.segment(&layout::AttachProcessArgs {
            process_id: pid,
            attach_flags: flags,
        });
        let out_size = size_of_wire::<u64>() + size_of_wire::<u32>();
        let data = self.call_ok(Method::AttachProcess, body, out_size)?;
        let mut reader = Reader::new(&data, Method::AttachProcess);
        let handle = reader.read_u64()?;
        let options = reader.read_u32()?;
        Ok(AttachedProcess { handle, options })
    }

    fn detach_process(&mut self, pid: u32) -> Result<()> {
        let mut body = Writer::new();
        body.write_u32(pid);
        self.call_ok(Method::DetachProcess, body, 0).map(drop)
    }

    fn create_process(
        &mut self,
        command_line: &str,
        flags: u32,
        inherit_handles: bool,
        current_dir: Option<&str>,
    ) -> Result<CreatedProcess> {
        let command_line = encode_utf16_nul(command_line);
        let current_dir = current_dir.map(encode_utf16_nul).unwrap_or_default();
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
        // The request is the command line, then `_DEBUG_CREATE_PROCESS_OPTIONS`,
        // then two length-prefixed strings (the current directory and the
        // environment), each aligned to four bytes.
        let mut body = Writer::new();
        body.buffer(&command_line, 2)
            .align(4)
            .segment(&layout::CreateProcessOptions {
                create_flags,
                eng_create_flags: 0,
                verifier_flags: 0,
                reserved: 0,
            })
            .write_u32(current_dir.len() as u32)
            .buffer(&current_dir, 1)
            .align(4)
            .write_u32(0); // no environment block
        let data = self.call_ok(
            Method::CreateProcessW,
            body,
            size_of_wire::<layout::CreatedProcessRet>(),
        )?;
        let created: layout::CreatedProcessRet =
            Reader::new(&data, Method::CreateProcessW).take()?;
        Ok(CreatedProcess {
            pid: created.process_id,
            tid: created.thread_id,
            process_handle: created.process_handle,
            thread_handle: created.thread_handle,
        })
    }

    fn close_handle(&mut self, handle: u64) -> Result<()> {
        let mut body = Writer::new();
        body.write_u64(handle);
        self.call_ok(Method::CloseHandle, body, 0).map(drop)
    }

    fn read_virtual(&mut self, process: u64, address: u64, buf: &mut [u8]) -> Result<usize> {
        let size = u32::try_from(buf.len()).map_err(|_| {
            Error::InvalidArgument(format!(
                "dbgsrv ReadVirtual cannot read {} bytes in one call",
                buf.len()
            ))
        })?;
        let data = self.call_ok(
            Method::ReadVirtual,
            Self::address_args(process, address, size),
            sized_buffer_reply_size(size),
        )?;
        let mut reader = Reader::new(&data, Method::ReadVirtual);
        let (bytes, used) = reader.sized_bytes(size as usize)?;
        buf.copy_from_slice(bytes);
        Ok(used as usize)
    }

    fn write_virtual(&mut self, process: u64, address: u64, buf: &[u8]) -> Result<usize> {
        let size = u32::try_from(buf.len()).map_err(|_| {
            Error::InvalidArgument(format!(
                "dbgsrv WriteVirtual cannot write {} bytes in one call",
                buf.len()
            ))
        })?;
        let mut body = Self::address_args(process, address, size);
        body.sized_buffer(buf, size);
        let data = self.call_ok(Method::WriteVirtual, body, size_of_wire::<u32>())?;
        Ok(Reader::new(&data, Method::WriteVirtual).read_u32()? as usize)
    }

    fn query_virtual(&mut self, process: u64, address: u64, size: u32) -> Result<(Vec<u8>, u32)> {
        self.call_sized_buffer(
            Method::QueryVirtual,
            Self::address_args(process, address, size),
            size,
        )
    }

    fn thread_start_address(&mut self, process: u64, thread: u64) -> Result<u64> {
        let mut body = Writer::new();
        body.write_u64(process).write_u64(thread);
        let data = self.call_ok(
            Method::GetThreadBasicInfo,
            body,
            size_of_wire::<layout::ThreadBasicInformation>(),
        )?;
        let info: layout::ThreadBasicInformation =
            Reader::new(&data, Method::GetThreadBasicInfo).take()?;
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
        body.write_u64(thread).segment(&layout::GetContextArgs {
            flags,
            flags_offset,
            context_size: size,
        });
        self.call_sized_buffer(Method::GetContext, body, size)
    }

    fn set_context(&mut self, thread: u64, context: &[u8]) -> Result<u32> {
        let size = u32::try_from(context.len()).map_err(|_| {
            Error::InvalidArgument(format!(
                "dbgsrv SetContext cannot write {} bytes in one call",
                context.len()
            ))
        })?;
        let mut body = Writer::new();
        body.write_u64(thread)
            .write_u32(size)
            .sized_buffer(context, size);
        let data = self.call_ok(Method::SetContext, body, size_of_wire::<u32>())?;
        Reader::new(&data, Method::SetContext).read_u32()
    }

    fn process_data_offset(&mut self, process: u64) -> Result<u64> {
        self.call_handle_u64(Method::GetProcessDataOffset, process)
    }

    fn thread_data_offset(&mut self, thread: u64) -> Result<u64> {
        self.call_handle_u64(Method::GetThreadDataOffset, thread)
    }

    fn request_break_in(&mut self, process: u64) -> Result<()> {
        let mut body = Writer::new();
        body.write_u64(process);
        self.call(Method::RequestBreakIn, body, 0, true).map(drop)
    }

    fn wait_for_event(&mut self, timeout_ms: u32) -> Result<Option<Vec<u8>>> {
        let mut body = Writer::new();
        body.segment(&layout::WaitForEventArgs {
            timeout: timeout_ms,
            buffer_size: DEBUG_EVENT_SIZE,
        });
        let (status, data) = self.call(
            Method::WaitForEvent,
            body,
            sized_buffer_reply_size(DEBUG_EVENT_SIZE),
            false,
        )?;
        if status == S_FALSE {
            return Ok(None);
        }
        if !succeeded(status) {
            return Err(self.failure(Method::WaitForEvent, status));
        }
        let mut reader = Reader::new(&data, Method::WaitForEvent);
        let (event, used) = reader.sized_bytes(DEBUG_EVENT_SIZE as usize)?;
        let used = (used as usize).min(event.len());
        Ok(Some(event[..used].to_vec()))
    }

    fn continue_event(&mut self, status: u32) -> Result<()> {
        let mut body = Writer::new();
        body.write_u32(status);
        self.call_ok(Method::ContinueEvent, body, 0).map(drop)
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
        self.call_ok(Method::InsertCodeBreakpoint, body, CODE_BREAKPOINT_STORAGE)
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
        })
        .sized_buffer(storage, size);
        self.call_ok(Method::RemoveCodeBreakpoint, body, 0)
            .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::dbgsrv::wire::stub_index;

    #[test]
    fn stub_indices_are_the_interface_shifted_over_the_method() {
        assert_eq!(stub_index(Method::QueryInterface), 0xc000);
        assert_eq!(stub_index(Method::Initialize), 0xc002);
        assert_eq!(stub_index(Method::AttachProcess), 0xc00f);
        assert_eq!(stub_index(Method::WaitForEvent), 0xc030);
        assert_eq!(Method::ReadVirtual.name(), "ReadVirtual");
    }
}
