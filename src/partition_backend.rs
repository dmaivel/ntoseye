//! The backend of a view of a guest partition of the Windows hypervisor (a
//! Windows Sandbox, a Hyper-V VM) that runs inside the target (`.partition`):
//! its virtual processors are the threads, with the registers they had when
//! the target halted, and nothing runs or changes through it. The target
//! itself is controlled by the backend the view replaced.

use std::time::Duration;

use crate::dbg_backend::{BackendCapability, DebugBackend, DebugCapability, StopEvent};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;

/// One VP of the partition: its thread ID (`p<partition>.<VP index + 1>`,
/// so its processor number is its VP index, as the guest numbers its
/// processors) and its register file in `register_map`'s layout.
pub struct PartitionVp {
    pub id: String,
    pub registers: Vec<u8>,
}

pub struct PartitionBackend {
    register_map: RegisterMap,
    vps: Vec<PartitionVp>,
    selected: usize,
}

impl PartitionBackend {
    pub fn new(register_map: RegisterMap, vps: Vec<PartitionVp>) -> Self {
        Self {
            register_map,
            vps,
            selected: 0,
        }
    }

    /// The refusal of `operation`, which a partition view does not support.
    pub fn read_only(operation: &str) -> Error {
        Error::DebugInfo(format!(
            "a partition view does not support {operation}: it shows the partition read-only as the target halted; selecting the root partition (1) returns to the target"
        ))
    }
}

impl DebugBackend for PartitionBackend {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }

    fn name(&self) -> &'static str {
        "partition"
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        let mut capabilities = vec![
            BackendCapability::supported(DebugCapability::MemoryIntrospection),
            BackendCapability::supported(DebugCapability::ReadRegisters),
            BackendCapability::supported(DebugCapability::ThreadList),
            BackendCapability::supported(DebugCapability::ThreadSelection),
        ];
        capabilities.extend(
            [
                DebugCapability::ExecutionControl,
                DebugCapability::InterruptTarget,
                DebugCapability::SingleStep,
                DebugCapability::WriteRegisters,
                DebugCapability::KernelBreakpoints,
                DebugCapability::UserModeBreakpoints,
                DebugCapability::Watchpoints,
            ]
            .into_iter()
            .map(BackendCapability::unsupported),
        );
        capabilities
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        Ok(self.vps[self.selected].registers.clone())
    }

    fn write_registers(&mut self, _data: &[u8]) -> Result<()> {
        Err(Self::read_only("register writes"))
    }

    fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Self::read_only("breakpoints"))
    }

    fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Self::read_only("breakpoints"))
    }

    fn continue_execution(&mut self) -> Result<()> {
        Err(Self::read_only("running the target"))
    }

    fn step(&mut self) -> Result<()> {
        Err(Self::read_only("single steps"))
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        Err(Self::read_only("breaking in"))
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        Err(Self::read_only("waiting for stops"))
    }

    fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
        Ok(None)
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        Ok(self.vps.iter().map(|vp| vp.id.clone()).collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        self.selected = self
            .vps
            .iter()
            .position(|vp| vp.id == thread_id)
            .ok_or_else(|| {
                Error::InvalidArgument(format!("the partition has no VP {thread_id}"))
            })?;
        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        Ok(self.vps[self.selected].id.clone())
    }

    fn is_running(&self) -> bool {
        false
    }
}
