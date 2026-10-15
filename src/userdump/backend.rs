//! The backend over a user-mode minidump: one register context per captured
//! thread, selected by thread id. Nothing runs, so execution, breakpoints,
//! and register writes are refused.

use std::time::Duration;

use super::{UserDumpInfo, register_buffer};
use crate::dbg_backend::{
    BackendCapability, DebugBackend, DebugCapability, RegisterMap, StopEvent,
};
use crate::error::{Error, Result};
use crate::kd::{context, context_arm64};
use crate::notice::Notice;
use crate::types::Arch;

/// A captured thread as the backend selects it.
struct DumpThread {
    /// [`UserDumpInfo::backend_thread_id`].
    id: String,
    tid: u32,
    /// The register buffer, or why the thread has none.
    registers: std::result::Result<Vec<u8>, String>,
}

pub struct UserDumpBackend {
    register_map: RegisterMap,
    threads: Vec<DumpThread>,
    current: usize,
    notices: Vec<Notice>,
}

impl UserDumpBackend {
    /// A backend over `info`'s threads, starting on the exception's thread
    /// when the dump records one, else on the first thread.
    pub fn new(info: &UserDumpInfo) -> Self {
        let register_map = match info.arch {
            Arch::Amd64 => context::build_register_map(),
            Arch::Arm64 => context_arm64::build_register_map(),
        };
        let threads: Vec<DumpThread> = info
            .threads
            .iter()
            .map(|thread| DumpThread {
                id: info.backend_thread_id(thread.tid),
                tid: thread.tid,
                registers: thread
                    .context
                    .as_ref()
                    .map(|raw| register_buffer(info.arch, raw))
                    .map_err(Clone::clone),
            })
            .collect();
        let mut notices: Vec<Notice> = info
            .threads
            .iter()
            .filter_map(|thread| {
                let reason = thread.context.as_ref().err()?;
                Some(Notice::warning(format!(
                    "thread {:#x} has no usable register context: {reason}",
                    thread.tid
                )))
            })
            .collect();
        let exception_thread = info.exception.as_ref().map(|exception| exception.thread_id);
        let current = match exception_thread {
            Some(tid) => match threads.iter().position(|thread| thread.tid == tid) {
                Some(index) => index,
                None => {
                    notices.push(Notice::warning(format!(
                        "the exception names thread {tid:#x}, which the thread list does not hold"
                    )));
                    0
                }
            },
            None => 0,
        };
        Self {
            register_map,
            threads,
            current,
            notices,
        }
    }

    fn unsupported(operation: &str) -> Error {
        Error::DebugInfo(format!(
            "a user-mode minidump is a static snapshot; {operation} is not available"
        ))
    }
}

impl DebugBackend for UserDumpBackend {
    fn name(&self) -> &'static str {
        "minidump"
    }

    fn registers_are_context(&self) -> bool {
        true
    }

    fn take_notices(&mut self) -> Vec<Notice> {
        std::mem::take(&mut self.notices)
    }

    fn register_map(&self) -> &RegisterMap {
        &self.register_map
    }

    fn capabilities(&self) -> Vec<BackendCapability> {
        vec![
            BackendCapability::supported(DebugCapability::MemoryIntrospection),
            BackendCapability::supported(DebugCapability::ReadRegisters),
            BackendCapability::unsupported(DebugCapability::ExecutionControl),
            BackendCapability::unsupported(DebugCapability::InterruptTarget),
            BackendCapability::unsupported(DebugCapability::SingleStep),
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
        let thread = self
            .threads
            .get(self.current)
            .ok_or_else(|| Error::DebugInfo("the minidump records no threads".into()))?;
        thread.registers.clone().map_err(|reason| {
            Error::DebugInfo(format!(
                "thread {:#x} has no usable register context: {reason}",
                thread.tid
            ))
        })
    }

    fn write_registers(&mut self, _data: &[u8]) -> Result<()> {
        Err(Self::unsupported("register writes"))
    }

    fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Self::unsupported("breakpoints"))
    }

    fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
        Err(Self::unsupported("breakpoints"))
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
        Ok(self
            .threads
            .iter()
            .map(|thread| thread.id.clone())
            .collect())
    }

    fn set_current_thread(&mut self, thread_id: &str) -> Result<()> {
        self.current = self
            .threads
            .iter()
            .position(|thread| thread.id.eq_ignore_ascii_case(thread_id))
            .ok_or_else(|| Error::DebugInfo(format!("the minidump has no thread {thread_id}")))?;
        Ok(())
    }

    fn stopped_thread_id(&mut self) -> Result<String> {
        self.threads
            .get(self.current)
            .map(|thread| thread.id.clone())
            .ok_or_else(|| Error::DebugInfo("the minidump records no threads".into()))
    }

    fn is_running(&self) -> bool {
        false
    }

    // The default tries to leave the target running, which a snapshot
    // cannot (and need not) do.
    fn prepare_for_exit(&mut self, _leave_running: bool) -> Result<()> {
        Ok(())
    }
}
