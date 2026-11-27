pub mod backend;
pub mod client;
pub mod events;
pub mod layout;
pub mod service;
pub mod transport;
pub mod wire;

#[cfg(test)]
pub(crate) mod tests;

pub use self::backend::{DbgsrvBackend, DbgsrvTarget};
pub use client::DbgSrvClient;
pub use events::{DebugEvent, decode as decode_event};
pub use service::{
    CLOSE_PROC_THREAD_HANDLES, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DEBUG_EVENT_SIZE,
    DEBUG_PROCESS_ONLY_THIS_PROCESS, GENERIC_CODE_BREAKPOINTS, GENERIC_DATA_BREAKPOINTS,
    PROC_INFO_NO_SUSPEND, ProcessServer, RpcService, TargetInfo, ThreadRecord,
};
pub use transport::{DbgsrvEndpoint, parse_endpoint};
pub use wire::{method, stub_index};

/// The memory of the process a client is attached to, which the target reads
/// through as the process's address space.
pub struct DbgSrvUserMemory {
    client: std::sync::Arc<DbgSrvClient>,
    process: u64,
}

impl DbgSrvUserMemory {
    pub fn new(client: std::sync::Arc<DbgSrvClient>, process: u64) -> Self {
        Self { client, process }
    }
}

impl crate::backend::userlive::UserLiveMemory for DbgSrvUserMemory {
    fn read(&self, process: u64, address: u64, buf: &mut [u8]) -> crate::base::error::Result<()> {
        let process = if process == 0 { self.process } else { process };
        self.client.read_virtual(process, address, buf)
    }

    fn write(&self, process: u64, address: u64, buf: &[u8]) -> crate::base::error::Result<()> {
        let process = if process == 0 { self.process } else { process };
        self.client.write_virtual(process, address, buf)
    }

    fn query(
        &self,
        process: u64,
        address: u64,
    ) -> crate::base::error::Result<crate::backend::userlive::MemoryBasicInformation> {
        let process = if process == 0 { self.process } else { process };
        let (bytes, used) = self.client.query_virtual(process, address)?;
        let used = (used as usize).min(bytes.len());
        crate::backend::userlive::MemoryBasicInformation::decode(&bytes[..used])
    }
}
