//! The connection a live user-mode target is debugged over: one process
//! server, the architecture it reports, and the virtual-memory adapter bound
//! to the attached process handle.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::arch::{Arch, IMAGE_FILE_MACHINE_I386};
use crate::backend::userlive::{MemoryBasicInformation, UserLiveMemory};
use crate::base::error::{Error, Result};

use super::service::{
    CLOSE_PROC_THREAD_HANDLES, GENERIC_CODE_BREAKPOINTS, GENERIC_DATA_BREAKPOINTS, ProcessServer,
    RpcService, TargetInfo,
};

/// A DbgRpc process server connection.
///
/// Every call goes through one lock: DbgRpc's stream has no framing of its
/// own, so a call's header and body cannot interleave with another's. The
/// target is halted while a call is made, so there is nothing to poll in the
/// background; `WaitForEvent` polls with a short timeout instead, which lets
/// the same thread service a break-in request.
pub struct DbgsrvClient {
    server: Mutex<Box<dyn ProcessServer>>,
    endpoint: String,
    /// `DBGSVC_*` flags `Initialize` returned.
    flags: u32,
    info: TargetInfo,
    arch: Arch,
}

impl DbgsrvClient {
    /// Connect `endpoint`, initialize the server, and read the machine it
    /// debugs.
    pub fn connect(endpoint: &str, progress: &mut dyn FnMut(&str)) -> Result<Self> {
        let mut server: Box<dyn ProcessServer> = Box::new(RpcService::connect(endpoint, progress)?);
        let flags = server.initialize()?;
        // The server must be told which connection it serves before it will
        // attach a process.
        let connection = server.connection_info()?;
        let info = server.target_info()?;
        let arch = arch_for(info.machine_type)?;
        let machine = if connection.machine.is_empty() {
            "the remote machine"
        } else {
            &connection.machine
        };
        let transport = if connection.transport.is_empty() {
            String::new()
        } else {
            format!(" ({})", connection.transport)
        };
        let checked = if info.checked_build != 0 {
            " (checked)"
        } else {
            ""
        };
        progress(&format!(
            "dbgsrv: {} target on {machine}{transport}, {} processor(s), Windows {}.{}.{}{checked}",
            arch.label(),
            info.processors,
            info.major_version,
            info.minor_version,
            info.build_number,
        ));
        Ok(Self {
            server: Mutex::new(server),
            endpoint: endpoint.to_string(),
            flags,
            info,
            arch,
        })
    }

    /// Build a client over a pre-constructed server, for tests.
    pub fn with_server(mut server: Box<dyn ProcessServer>, info: TargetInfo) -> Result<Self> {
        let arch = arch_for(info.machine_type)?;
        let flags = server.initialize()?;
        Ok(Self {
            server: Mutex::new(server),
            endpoint: "mock".to_string(),
            flags,
            info,
            arch,
        })
    }

    /// The server, for one call. Held for the length of that call.
    pub fn server(&self) -> MutexGuard<'_, Box<dyn ProcessServer>> {
        self.server.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The `DBGSVC_*` flags `Initialize` reported.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn info(&self) -> &TargetInfo {
        &self.info
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    pub fn processors(&self) -> u16 {
        self.info.processors.min(u32::from(u16::MAX)) as u16
    }

    /// Whether the debugger patches code breakpoints into the process itself,
    /// because the server has no implementation of its own.
    pub fn generic_code_breakpoints(&self) -> bool {
        self.flags & GENERIC_CODE_BREAKPOINTS != 0
    }

    /// Whether the debugger programs data breakpoints in the thread's own
    /// registers, because the server has no implementation of its own.
    pub fn generic_data_breakpoints(&self) -> bool {
        self.flags & GENERIC_DATA_BREAKPOINTS != 0
    }

    /// Whether the debugger owns the process and thread handles a debug event
    /// hands out, and must close them (`DBGSVC_CLOSE_PROC_THREAD_HANDLES`).
    pub fn closes_handles(&self) -> bool {
        self.flags & CLOSE_PROC_THREAD_HANDLES != 0
    }

    pub fn read_virtual(&self, process: u64, address: u64, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let read = self.server().read_virtual(process, address, buf)?;
        if read != buf.len() {
            return Err(Error::PartialRead(read));
        }
        Ok(())
    }

    pub fn write_virtual(&self, process: u64, address: u64, buf: &[u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let written = self.server().write_virtual(process, address, buf)?;
        if written != buf.len() {
            return Err(Error::PartialWrite(written));
        }
        Ok(())
    }

    /// `VirtualQuery` at `address`: the decoded `MEMORY_BASIC_INFORMATION`.
    pub fn query_virtual(&self, process: u64, address: u64) -> Result<MemoryBasicInformation> {
        let (bytes, used) =
            self.server()
                .query_virtual(process, address, MemoryBasicInformation::SIZE as u32)?;
        let used = (used as usize).min(bytes.len());
        MemoryBasicInformation::decode(&bytes[..used])
    }
}

/// Flag bit set in [`ProcessHandle::exit`] once the process has exited,
/// distinguishing exit code 0 from a live process.
const EXIT_RECORDED: u64 = 1 << 32;

/// Shared process handle and exit status between [`super::DbgsrvBackend`] and
/// [`DbgsrvUserMemory`].
pub(super) struct ProcessHandle {
    handle: AtomicU64,
    exit: AtomicU64,
}

impl ProcessHandle {
    pub(super) fn new(handle: u64) -> Self {
        Self {
            handle: AtomicU64::new(handle),
            exit: AtomicU64::new(0),
        }
    }

    pub(super) fn handle(&self) -> u64 {
        self.handle.load(Ordering::Acquire)
    }

    pub(super) fn swap_handle(&self, handle: u64) -> u64 {
        self.handle.swap(handle, Ordering::AcqRel)
    }

    pub(super) fn exit_code(&self) -> Option<u32> {
        let raw = self.exit.load(Ordering::Acquire);
        (raw & EXIT_RECORDED != 0).then_some(raw as u32)
    }

    pub(super) fn set_exited(&self, code: u32) {
        self.exit
            .store(EXIT_RECORDED | u64::from(code), Ordering::Release);
    }

    pub(super) fn require_alive(&self) -> Result<u64> {
        if let Some(code) = self.exit_code() {
            return Err(Error::ProcessExited(code));
        }
        Ok(self.handle())
    }
}

/// The memory of the attached process behind a [`DbgsrvClient`], holding the
/// shared process handle internally so layers above never see server handles.
pub struct DbgsrvUserMemory {
    client: Arc<DbgsrvClient>,
    process: Arc<ProcessHandle>,
}

impl DbgsrvUserMemory {
    pub(super) fn new(client: Arc<DbgsrvClient>, process: Arc<ProcessHandle>) -> Self {
        Self { client, process }
    }
}

impl UserLiveMemory for DbgsrvUserMemory {
    fn read(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        let process = self.process.require_alive()?;
        self.client.read_virtual(process, address, buf)
    }

    fn write(&self, address: u64, buf: &[u8]) -> Result<()> {
        let process = self.process.require_alive()?;
        self.client.write_virtual(process, address, buf)
    }

    fn query(&self, address: u64) -> Result<MemoryBasicInformation> {
        let process = self.process.require_alive()?;
        self.client.query_virtual(process, address)
    }
}

/// Map a Windows `IMAGE_FILE_MACHINE_*` value to an [`Arch`], naming x86/WOW64
/// explicitly as unsupported.
fn arch_for(machine_type: u32) -> Result<Arch> {
    if let Ok(machine) = u16::try_from(machine_type) {
        if let Some(arch) = Arch::from_machine_type(machine) {
            return Ok(arch);
        }
        if machine == IMAGE_FILE_MACHINE_I386 {
            return Err(Error::Dbgsrv(
                "x86/WOW64 targets are not supported by ntoseye's current register model"
                    .to_string(),
            ));
        }
    }
    Err(Error::Dbgsrv(format!(
        "the server reports machine type {machine_type:#06x}, which is neither AMD64 nor ARM64"
    )))
}

impl std::fmt::Debug for DbgsrvClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbgsrvClient")
            .field("endpoint", &self.endpoint)
            .field("arch", &self.arch)
            .field("flags", &self.flags)
            .finish()
    }
}
