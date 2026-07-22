use std::time::Duration;

use crate::dbg_backend::{BackendCapability, DebugBackend, DebugCapability, StopEvent};
use crate::error::{Error, Result};
use crate::gdb::RegisterMap;
use crate::types::VirtAddr;

#[derive(Default)]
pub struct MemoryBackend {
    register_map: RegisterMap,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            register_map: RegisterMap::default(),
        }
    }

    fn unsupported(operation: &str) -> Error {
        Error::DebugInfo(format!(
            "memory backend does not support {operation}; use KDCOM or gdb for target control"
        ))
    }
}

impl DebugBackend for MemoryBackend {
    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }
    fn name(&self) -> &'static str {
        "mem"
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        vec![
            BackendCapability::supported(DebugCapability::MemoryIntrospection),
            BackendCapability::unsupported(DebugCapability::ExecutionControl),
            BackendCapability::unsupported(DebugCapability::InterruptTarget),
            BackendCapability::unsupported(DebugCapability::SingleStep),
            BackendCapability::unsupported(DebugCapability::ReadRegisters),
            BackendCapability::unsupported(DebugCapability::WriteRegisters),
            BackendCapability::unsupported(DebugCapability::ThreadList),
            BackendCapability::unsupported(DebugCapability::ThreadSelection),
            BackendCapability::unsupported(DebugCapability::KernelBreakpoints),
            BackendCapability::unsupported(DebugCapability::UserModeBreakpoints),
            BackendCapability::unsupported(DebugCapability::TargetReloadDetection),
            BackendCapability::unsupported(DebugCapability::KernelBaseHint),
            BackendCapability::unsupported(DebugCapability::BugcheckDetection),
            BackendCapability::unsupported(DebugCapability::BugcheckDetails),
            BackendCapability::unsupported(DebugCapability::DebugOutput),
        ]
    }

    fn read_registers(&mut self) -> Result<Vec<u8>> {
        Err(Self::unsupported("register reads"))
    }

    fn write_registers(&mut self, _data: &[u8]) -> Result<()> {
        Err(Self::unsupported("register writes"))
    }

    fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Self::unsupported("kernel breakpoints"))
    }

    fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Self::unsupported("kernel breakpoints"))
    }

    fn continue_execution(&mut self) -> Result<()> {
        Err(Self::unsupported("continue"))
    }

    fn step(&mut self) -> Result<()> {
        Err(Self::unsupported("single-step"))
    }

    fn interrupt(&mut self) -> Result<StopEvent> {
        Err(Self::unsupported("target interrupt"))
    }

    fn wait_for_stop(&mut self) -> Result<StopEvent> {
        Err(Self::unsupported("waiting for target stops"))
    }

    fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
        Ok(None)
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        Err(Self::unsupported("context enumeration"))
    }

    fn set_current_thread(&mut self, _thread_id: &str) -> Result<()> {
        Err(Self::unsupported("context selection"))
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        Err(Self::unsupported("stopped-context queries"))
    }

    fn target_kernel_base_hint(&mut self) -> Result<Option<VirtAddr>> {
        Ok(None)
    }

    fn is_running(&self) -> bool {
        true
    }
}
