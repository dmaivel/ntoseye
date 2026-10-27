use std::time::Duration;

use crate::arch::RegisterMap;
use crate::backend::dbg_backend::{
    BackendCapability, DebugBackend, DebugCapability, StopEvent,
    processor_index_from_backend_thread_id,
};
use crate::base::error::{Error, Result};

/// Reads guest memory from the host while the guest runs. It has no
/// registers, but lists the kernel's processors so that one can be selected
/// for what is read from its PRCB (`~1s` then `!idt`).
#[derive(Default)]
pub struct MemoryBackend {
    register_map: RegisterMap,
    processors: u16,
    selected: u16,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// The id the processor at `index` is listed by, as the other backends
    /// list theirs (see [`processor_index_from_backend_thread_id`]).
    fn processor_id(index: u16) -> String {
        format!("p1.{:x}", index + 1)
    }

    fn unsupported(operation: &str) -> Error {
        Error::DebugInfo(format!(
            "memory backend does not support {operation}; use KD (KDCOM or KDNET) or gdb for target control"
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
            BackendCapability::supported(DebugCapability::ThreadList),
            BackendCapability::supported(DebugCapability::ThreadSelection),
            BackendCapability::unsupported(DebugCapability::KernelBreakpoints),
            BackendCapability::unsupported(DebugCapability::UserModeBreakpoints),
            BackendCapability::unsupported(DebugCapability::Watchpoints),
            BackendCapability::unsupported(DebugCapability::TargetReloadDetection),
            BackendCapability::unsupported(DebugCapability::KernelBaseHint),
            BackendCapability::unsupported(DebugCapability::BugcheckDetection),
            BackendCapability::unsupported(DebugCapability::BugcheckDetails),
            BackendCapability::unsupported(DebugCapability::ModuleLoadEvents),
            BackendCapability::unsupported(DebugCapability::DebugOutput),
            BackendCapability::unsupported(DebugCapability::Msr),
            BackendCapability::unsupported(DebugCapability::IoPorts),
            BackendCapability::unsupported(DebugCapability::PciConfig),
            BackendCapability::unsupported(DebugCapability::TargetControl),
            BackendCapability::unsupported(DebugCapability::TargetFileIo),
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

    fn set_processor_count(&mut self, count: u16) {
        self.processors = count;
        self.selected = 0;
    }

    fn thread_list(&mut self) -> Result<Vec<String>> {
        if self.processors == 0 {
            return Err(Self::unsupported("context enumeration"));
        }
        Ok((0..self.processors).map(Self::processor_id).collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        match processor_index_from_backend_thread_id(thread_id) {
            Some(index) if index < self.processors => {
                self.selected = index;
                Ok(())
            }
            _ => Err(Error::DebugInfo(format!("no processor {thread_id}"))),
        }
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        Err(Self::unsupported("stopped-context queries"))
    }

    fn is_running(&self) -> bool {
        true
    }
}
