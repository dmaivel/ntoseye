//! The DbgRpc wire format: the handshake, the call header, and the cursors
//! every call body is written and read with.
//!
//! Each C structure is a `#[repr(C)]` type whose field order and types are
//! the generated proxy's, so the compiler lays the bytes out and the
//! `const` sizes are the proof. `dbgrpc/dbgrpc.hpp`, `dbgrpc/dbgrpc.cpp` and
//! the proxy `rremgen.pl` generates from `dbgsvc/dbgsvc.h` are the
//! authorities; the wire is little-endian, as every host ntoseye runs on is.
//!
//! Call bodies are not one structure: the proxy aligns each argument to its
//! own size, and a variable-length buffer sits between fixed arguments. Those
//! are written as a sequence of [`Writer::segment`]s and padded where the
//! proxy pads.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::base::error::{Error, Result};

/// Declares a wire structure with its C layout, and fails the build when the
/// compiler lays out any other size.
macro_rules! wire_struct {
    (
        $(#[$doc:meta])*
        $vis:vis struct $name:ident {
            $( $(#[$field_doc:meta])* $field:ident: $ty:ty ),* $(,)?
        } = $size:expr
    ) => {
        $(#[$doc])*
        #[repr(C)]
        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            zerocopy::FromBytes,
            zerocopy::IntoBytes,
            zerocopy::Immutable,
            zerocopy::KnownLayout,
        )]
        $vis struct $name {
            $( $(#[$field_doc])* pub $field: $ty ),*
        }

        const _: () = assert!(
            core::mem::size_of::<$name>() == $size,
            concat!(stringify!($name), " is not its C size")
        );
    };
}

pub(crate) use wire_struct;

/// `DBGRPC_SIGNATURE` as it reaches the wire. The C constant is the
/// multi-character literal `'CPRD'`, whose value is `0x43505244`, so a
/// little-endian `ULONG` writes the bytes `DRPC`: a client that sends the
/// characters in reading order is refused by the server's handshake check
/// (measured against `dbgsrv.exe` 10.0.26100 and `cdb`).
pub const SIGNATURE: [u8; 4] = *b"DRPC";
/// `DBGRPC_PROTOCOL_VERSION`.
pub const PROTOCOL_VERSION: u32 = 2;

/// `DBGRPC_UNIQUE_IUserDebugServicesN`: the revision of `IUserDebugServicesN`
/// this client speaks, which the server checks in `QueryInterface`. The
/// generator derives it from the interface's methods and parameters, so a
/// server built against a different `dbgsvc.h` refuses it with
/// `RPC_E_VERSION_MISMATCH`, and its calls would otherwise be decoded with
/// the wrong field order.
///
/// Measured from `dbgeng.dll` 10.0.26100 (`IUserDebugServicesN`, whose proxy
/// `ProxyIUserDebugServicesN` was read out of its PDB) and confirmed against
/// `dbgsrv.exe` of the same build: `QueryInterface` accepts this code and
/// refuses the older `0x737fe`.
pub const UNIQUE_USER_DEBUG_SERVICES: u32 = 0x9_FB38;

/// `DBGRPC_SIF_IUserDebugServices`: the interface index every stub index of
/// this interface is built from. The server indexes its tables with it, so it
/// must stay constant.
pub const INTERFACE_INDEX: u16 = 192;

/// The stub index of method `method` of `IUserDebugServices`
/// (`DBGRPC_STUB_INDEX(DBGRPC_SIF_IUserDebugServices, method)`).
pub const fn stub_index(method: u16) -> u16 {
    (INTERFACE_INDEX << 8) | method
}

/// `DBGRPC_SMTH_IUserDebugServices_*`: the method's index in the interface's
/// vtable, which numbers `QueryInterface` from zero and skips `AddRef` (the
/// generator does not remote it).
pub mod method {
    /// `QueryInterface`, the only way to learn which revision of the
    /// interface the server implements.
    pub const QUERY_INTERFACE: u16 = 0;
    pub const INITIALIZE: u16 = 2;
    pub const UNINITIALIZE: u16 = 3;
    pub const GET_TARGET_INFO: u16 = 4;
    /// `GetConnectionInfo`: what the server must be told before it will
    /// attach a process (the names it reports onward).
    pub const GET_CONNECTION_INFO: u16 = 5;
    pub const GET_PROCESS_IDS: u16 = 11;
    pub const GET_PROCESS_INFO: u16 = 14;
    pub const ATTACH_PROCESS: u16 = 15;
    pub const DETACH_PROCESS: u16 = 16;
    pub const CREATE_PROCESS_W: u16 = 17;
    pub const GET_PROCESS_EXIT_CODE: u16 = 20;
    pub const CLOSE_HANDLE: u16 = 21;
    pub const SET_PROCESS_OPTIONS: u16 = 22;
    pub const SET_DEBUG_OBJECT_OPTIONS: u16 = 23;
    pub const GET_PROCESS_DEBUG_OBJECT: u16 = 24;
    pub const READ_VIRTUAL: u16 = 26;
    pub const WRITE_VIRTUAL: u16 = 27;
    pub const QUERY_VIRTUAL: u16 = 28;
    pub const SUSPEND_THREADS: u16 = 33;
    pub const RESUME_THREADS: u16 = 34;
    /// `GetThreadBasicInfo`: the modern interface's replacement for
    /// `GetThreadStartAddress`, which is gone.
    pub const GET_THREAD_BASIC_INFO: u16 = 35;
    pub const GET_CONTEXT: u16 = 36;
    pub const SET_CONTEXT: u16 = 37;
    pub const GET_PROCESS_DATA_OFFSET: u16 = 38;
    pub const GET_THREAD_DATA_OFFSET: u16 = 39;
    pub const REQUEST_BREAK_IN: u16 = 47;
    pub const WAIT_FOR_EVENT: u16 = 48;
    pub const CONTINUE_EVENT: u16 = 49;
    pub const INSERT_CODE_BREAKPOINT: u16 = 50;
    pub const REMOVE_CODE_BREAKPOINT: u16 = 51;
    pub const INSERT_DATA_BREAKPOINT: u16 = 52;
    pub const REMOVE_DATA_BREAKPOINT: u16 = 53;
    pub const GET_LAST_DATA_BREAKPOINT_HIT: u16 = 54;
}

/// `DBGRPC_RETURN`: the call header carries a reply.
pub const CALL_RETURN: u16 = 0x0001;
/// `DBGRPC_NO_RETURN`: the server must not reply.
pub const CALL_NO_RETURN: u16 = 0x0002;
/// `DBGRPC_LOCKED`: the connection may be read from a thread that does not
/// own it, as a higher-level lock orders the stream.
pub const CALL_LOCKED: u16 = 0x0004;

/// `DBGRPC_MAX_IDENTITY`, the fixed length of the client identity the
/// handshake announces and then sends.
pub const IDENTITY_LENGTH: usize = 128;

/// `DBGRPC_SHAKE_FULL_REMOTE_UNKNOWN`.
pub const SHAKE_FULL_REMOTE_UNKNOWN: u32 = 0x0000_0001;

/// The `Flags` a client sends. Besides
/// [`SHAKE_FULL_REMOTE_UNKNOWN`], current debuggers set bit 1, which the
/// server this was measured against (`dbgsrv.exe` 10.0.26100) accepts and an
/// older one ignores (§the header only defines bit 0).
pub const SHAKE_CLIENT_FLAGS: u32 = SHAKE_FULL_REMOTE_UNKNOWN | 0x0000_0002;

wire_struct! {
    /// A COM interface id in Windows' `GUID` layout: `Data1`, `Data2` and
    /// `Data3` little-endian, `Data4` as its bytes.
    pub struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    } = 16
}

/// `IID_IUserDebugServices`: `a7ba24c4-e4fb-4625-a8fc-b1cb1fd51f53`.
pub const IID_USER_DEBUG_SERVICES: Guid = Guid {
    data1: 0xa7ba_24c4,
    data2: 0xe4fb,
    data3: 0x4625,
    data4: [0xa8, 0xfc, 0xb1, 0xcb, 0x1f, 0xd5, 0x1f, 0x53],
};

wire_struct! {
    /// `DbgRpcHandshake`: the 128 bytes each side sends first.
    pub struct Handshake {
        /// `DBGRPC_SIGNATURE` as the `ULONG` it is written as.
        signature: [u8; 4],
        protocol_version: u32,
        desired_object: Guid,
        /// The server's object id, in its reply.
        remote_object: u64,
        identity_length: u32,
        password_length: u32,
        flags: u32,
        reserved1: u32,
        reserved2: [u64; 10],
    } = 128
}

impl Handshake {
    /// The handshake a client sends for `object`: the full identity buffer,
    /// no password, and the remote object unknown.
    pub fn client(object: Guid) -> Self {
        Self {
            signature: SIGNATURE,
            protocol_version: PROTOCOL_VERSION,
            desired_object: object,
            remote_object: 0,
            identity_length: IDENTITY_LENGTH as u32,
            password_length: 0,
            flags: SHAKE_CLIENT_FLAGS,
            reserved1: 0,
            reserved2: [0; 10],
        }
    }

    /// Decode a server's handshake, checking the signature and version first:
    /// a mismatched reply means the endpoint is not the process server this
    /// speaks to.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let handshake = Self::read_from_bytes(bytes).map_err(|_| {
            Error::DebugInfo(format!(
                "dbgsrv handshake is {} bytes, {} expected",
                bytes.len(),
                core::mem::size_of::<Self>()
            ))
        })?;
        if handshake.signature != SIGNATURE {
            return Err(Error::DebugInfo(format!(
                "dbgsrv handshake signature is {:02x?}, expected {:02x?}; the endpoint is not a \
                 DbgRpc process server",
                handshake.signature, SIGNATURE
            )));
        }
        if handshake.protocol_version != PROTOCOL_VERSION {
            return Err(Error::DebugInfo(format!(
                "dbgsrv protocol version mismatch: expected {PROTOCOL_VERSION}, got {}",
                handshake.protocol_version
            )));
        }
        Ok(handshake)
    }
}

wire_struct! {
    /// `DbgRpcCall`: the 32-byte header in front of every call and reply
    /// body.
    pub struct Call {
        object_id: u64,
        stub_index: u16,
        flags: u16,
        in_size: u32,
        out_size: u32,
        /// An `HRESULT`; meaningful in a reply.
        status: u32,
        sequence: u32,
        reserved1: u32,
    } = 32
}

impl Call {
    /// Whether this is a reply (`DBGRPC_RETURN`).
    pub fn is_return(&self) -> bool {
        self.flags & CALL_RETURN != 0
    }
}

/// Builds a call body the way the generated proxy does: fixed arguments as
/// their own structures, a variable-length buffer padded to its own
/// alignment, and padding wherever the proxy aligns the next argument.
#[derive(Debug, Default)]
pub struct Writer {
    buffer: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pad up to `align` (`INT_ALIGN2`), a power of two.
    pub fn align(&mut self, align: usize) -> &mut Self {
        while !self.buffer.len().is_multiple_of(align) {
            self.buffer.push(0);
        }
        self
    }

    /// One fixed argument, or the run of them before a buffer.
    pub fn segment(&mut self, value: &(impl IntoBytes + Immutable)) -> &mut Self {
        self.buffer.extend_from_slice(value.as_bytes());
        self
    }

    /// A variable-length argument, whose length the interface sent as a
    /// separate `ULONG`, aligned where the proxy aligns it.
    pub fn buffer(&mut self, bytes: &[u8], align: usize) -> &mut Self {
        self.align(align);
        self.buffer.extend_from_slice(bytes);
        self
    }

    /// A fixed argument after a variable-length buffer, aligned like one.
    pub fn tail(&mut self, value: &(impl IntoBytes + Immutable), align: usize) -> &mut Self {
        self.align(align);
        self.segment(value)
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buffer
    }
}

/// Reads a reply body the way the generated proxy does.
#[derive(Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    method: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], method: &'static str) -> Self {
        Self {
            bytes,
            position: 0,
            method,
        }
    }

    /// Pad up to `align`, as the proxy does before the next argument.
    pub fn align(&mut self, align: usize) -> &mut Self {
        while !self.position.is_multiple_of(align) {
            self.position += 1;
        }
        self
    }

    /// One fixed field or structure.
    pub fn take<T: FromBytes + KnownLayout + IntoBytes>(&mut self) -> Result<T> {
        let size = core::mem::size_of::<T>();
        let bytes = self.next(size)?;
        T::read_from_bytes(bytes).map_err(|_| {
            Error::DebugInfo(format!(
                "dbgsrv {}: reply holds no {} at offset {}",
                self.method,
                std::any::type_name::<T>(),
                self.position - size
            ))
        })
    }

    /// `count` of the same fixed structure, which the proxy marshals as one
    /// aligned array.
    pub fn take_array<T: FromBytes + KnownLayout + IntoBytes>(
        &mut self,
        count: usize,
    ) -> Result<Vec<T>> {
        (0..count).map(|_| self.take()).collect()
    }

    /// A variable-length argument, aligned where the proxy aligns it.
    pub fn bytes(&mut self, length: usize, align: usize) -> Result<&'a [u8]> {
        self.align(align);
        self.next(length)
    }

    fn next(&mut self, length: usize) -> Result<&'a [u8]> {
        let bytes = self
            .bytes
            .get(self.position..self.position + length)
            .ok_or_else(|| {
                Error::DebugInfo(format!(
                    "dbgsrv {}: reply body is {} bytes, {length} more expected at offset {}",
                    self.method,
                    self.bytes.len(),
                    self.position
                ))
            })?;
        self.position += length;
        Ok(bytes)
    }
}

/// A reply status as the proxy reports it: `SUCCEEDED(status)` is a
/// non-negative `HRESULT`.
pub fn succeeded(status: u32) -> bool {
    (status as i32) >= 0
}
