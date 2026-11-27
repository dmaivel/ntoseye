//! The connection a live user-mode target is debugged over: one process
//! server, one process, and the architecture the server reports.

use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::arch::Arch;
use crate::base::error::{Error, Result};

use super::service::{
    CLOSE_PROC_THREAD_HANDLES, GENERIC_CODE_BREAKPOINTS, GENERIC_DATA_BREAKPOINTS,
    IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386, ProcessServer,
    RpcService, TargetInfo,
};

/// A DbgRpc process server connection.
///
/// Every call goes through one lock: DbgRpc's stream has no framing of its
/// own, so a call's header and body cannot interleave with another's. The
/// target is halted while a call is made, so there is nothing to poll in the
/// background; `WaitForEvent` polls with a short timeout instead, which lets
/// the same thread service a break-in request.
pub struct DbgSrvClient {
    server: Mutex<Box<dyn ProcessServer>>,
    endpoint: String,
    /// `DBGSVC_*` flags `Initialize` returned.
    flags: u32,
    info: TargetInfo,
    arch: Arch,
}

impl DbgSrvClient {
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
        progress(&format!(
            "dbgsrv: {} target on {}{}, {} processor(s), Windows {}.{}.{}{}",
            arch.label(),
            if connection.machine.is_empty() {
                "the remote machine".to_string()
            } else {
                connection.machine.clone()
            },
            if connection.transport.is_empty() {
                String::new()
            } else {
                format!(" ({})", connection.transport)
            },
            info.processors,
            info.major_version,
            info.minor_version,
            info.build_number,
            if info.checked_build != 0 {
                " (checked)"
            } else {
                ""
            }
        ));
        Ok(Self {
            server: Mutex::new(server),
            endpoint: endpoint.to_string(),
            flags,
            info,
            arch,
        })
    }

    /// Build a client over an already-initialized server, for tests.
    pub fn with_server(server: Box<dyn ProcessServer>, info: TargetInfo) -> Result<Self> {
        let arch = arch_for(info.machine_type)?;
        Ok(Self {
            server: Mutex::new(server),
            endpoint: "mock".to_string(),
            flags: GENERIC_CODE_BREAKPOINTS | GENERIC_DATA_BREAKPOINTS,
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

    /// `VirtualQuery` at `address`: the `MEMORY_BASIC_INFORMATION` bytes and
    /// how many of them the query filled.
    pub fn query_virtual(&self, process: u64, address: u64) -> Result<(Vec<u8>, u32)> {
        self.server().query_virtual(
            process,
            address,
            crate::backend::userlive::MemoryBasicInformation::SIZE as u32,
        )
    }
}

/// The architecture a target machine type debugs: AMD64 or ARM64, the two
/// ntoseye's register model has a context layout for.
fn arch_for(machine_type: u32) -> Result<Arch> {
    match machine_type {
        IMAGE_FILE_MACHINE_AMD64 => Ok(Arch::Amd64),
        IMAGE_FILE_MACHINE_ARM64 => Ok(Arch::Arm64),
        IMAGE_FILE_MACHINE_I386 => Err(Error::DebugInfo(
            "dbgsrv x86/WOW64 targets are not supported by ntoseye's current register model"
                .to_string(),
        )),
        other => Err(Error::DebugInfo(format!(
            "dbgsrv: the server reports machine type {other:#06x}, which is neither AMD64 nor \
             ARM64"
        ))),
    }
}

impl std::fmt::Debug for DbgSrvClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbgSrvClient")
            .field("endpoint", &self.endpoint)
            .field("arch", &self.arch)
            .field("flags", &self.flags)
            .finish()
    }
}
