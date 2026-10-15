//! A target over a Windows user-mode minidump: one captured process, its
//! modules from the dump's module list, and its threads. There is no kernel
//! (`Target::guest` stays `None`), and one fixed address space whose root is
//! [`DTB_IDENTITY`](crate::memory::DTB_IDENTITY): the dump's memory is keyed by virtual address and
//! served without a page walk, so no root names anything else.

use std::collections::HashMap;

use super::Target;
use crate::{
    backend::MemoryOps,
    dbg_backend::RegisterMap,
    error::{Error, Result},
    guest::ModuleInfo,
    ntstatus::ntstatus_name,
    types::{Arch, VirtAddr},
    unwind::{format_symbol, resolve_thread_trace_context},
    userdump::{UserDump, UserDumpInfo, UserException, UserThread, context_registers},
};

/// What a target inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A Windows kernel: a live machine, a kernel crash dump, or a triage
    /// minidump.
    Kernel,
    /// One process captured by a user-mode minidump.
    UserDump,
}

/// `_TEB.ProcessEnvironmentBlock` in a 64-bit TEB, on AMD64 and ARM64 alike:
/// it follows the 0x38-byte `NT_TIB`, `EnvironmentPointer`, `ClientId`,
/// `ActiveRpcHandle`, and `ThreadLocalStoragePointer`.
const TEB64_PEB: u64 = 0x60;

/// The captured process a user-dump target inspects.
pub struct UserProcess {
    /// The dump's module list, as the target lists modules.
    pub modules: Vec<ModuleInfo>,
    /// The thread selected for inspection (`~Ns`), by thread id.
    pub thread: Option<u32>,
}

impl Target {
    pub fn kind(&self) -> TargetKind {
        if self.phys.is_user_dump() {
            TargetKind::UserDump
        } else {
            TargetKind::Kernel
        }
    }

    /// The user-mode minidump this target inspects, `None` for a kernel
    /// target.
    pub fn user_dump(&self) -> Option<&UserDump> {
        self.phys.user_dump()
    }

    /// What the user-mode minidump records, `None` for a kernel target.
    pub fn user_dump_info(&self) -> Option<&UserDumpInfo> {
        self.phys.user_dump().map(UserDump::info)
    }

    /// Refuse a kernel operation on a user-mode minidump.
    pub fn require_kernel(&self) -> Result<()> {
        match self.kind() {
            TargetKind::Kernel => Ok(()),
            TargetKind::UserDump => Err(Error::KernelRequired),
        }
    }

    /// The captured thread selected for inspection.
    pub fn user_thread(&self) -> Option<&UserThread> {
        let tid = self.user_process.as_ref()?.thread?;
        self.user_dump_info()?.thread(tid)
    }

    /// Select the captured thread a backend id names (see
    /// [`UserDumpInfo::backend_thread_id`]); an id no thread has clears the
    /// selection.
    pub fn select_user_thread(&mut self, backend_id: &str) {
        let tid = self
            .user_dump_info()
            .and_then(|info| info.thread_for_backend_id(backend_id))
            .map(|thread| thread.tid);
        if let Some(process) = &mut self.user_process {
            process.thread = tid;
        }
    }

    /// The exception the dump was written for, `None` when it records none.
    pub fn user_exception(&self) -> Option<&UserException> {
        self.user_dump_info()?.exception.as_ref()
    }

    /// The dump's exception in one line: `0xc0000005 (STATUS_ACCESS_VIOLATION)
    /// at app!Fault+0x12 on thread 1f40.1a2c`.
    pub fn user_exception_summary(&self) -> Option<String> {
        let info = self.user_dump_info()?;
        let exception = info.exception.as_ref()?;
        let trace = resolve_thread_trace_context(self, 0);
        let name = ntstatus_name(exception.code)
            .map(|name| format!(" ({name})"))
            .unwrap_or_default();
        Some(format!(
            "{:#010x}{name} at {} on thread {}",
            exception.code,
            format_symbol(self, &trace, exception.address),
            info.backend_thread_id(exception.thread_id)
        ))
    }

    /// The register values of the exception's CONTEXT, which the dump stores
    /// beside the exception record (not in process memory).
    pub fn user_exception_registers(
        &self,
        register_map: &RegisterMap,
    ) -> Result<HashMap<String, u64>> {
        let info = self
            .user_dump_info()
            .ok_or_else(|| Error::DebugInfo("this target is not a user-mode minidump".into()))?;
        let exception = info
            .exception
            .as_ref()
            .ok_or_else(|| Error::DebugInfo("the minidump records no exception".into()))?;
        let raw = exception.context.as_ref().map_err(|reason| {
            Error::DebugInfo(format!("the exception's context is unusable: {reason}"))
        })?;
        Ok(context_registers(info.arch, register_map, raw))
    }

    /// A user-dump pseudo-register: the selected thread's `$teb`, `$tid`, and
    /// the process's `$peb`, `$pid`/`$tpid`. `None` for any other name or on
    /// a kernel target; `Some(None)` when the dump lacks the value.
    pub fn user_dump_pseudo_register(&self, name: &str) -> Option<Option<u64>> {
        let info = self.user_dump_info()?;
        let thread = self.user_thread();
        Some(match name {
            "teb" => thread.map(|thread| thread.teb).filter(|teb| *teb != 0),
            "tid" => thread.map(|thread| u64::from(thread.tid)),
            "pid" | "tpid" => info.process_id.map(u64::from),
            "peb" => thread
                .map(|thread| thread.teb)
                .filter(|teb| *teb != 0)
                .and_then(|teb| {
                    self.context_memory()
                        .read::<u64>(VirtAddr(teb + TEB64_PEB))
                        .ok()
                })
                .filter(|peb| *peb != 0),
            _ => return None,
        })
    }

    /// The user-dump module list, `None` for a kernel target.
    pub fn user_modules(&self) -> Option<&[ModuleInfo]> {
        self.user_process
            .as_ref()
            .map(|process| process.modules.as_slice())
    }

    /// The architecture a user-mode minidump declares.
    pub fn user_dump_arch(&self) -> Option<Arch> {
        self.user_dump_info().map(|info| info.arch)
    }
}

impl Target {
    /// The named values of a register buffer: on a user-mode minidump only
    /// the registers its CONTEXT records (see [`context_registers`]), so the
    /// empty control-register slots past it are not shown as zeroes;
    /// elsewhere every register the map names.
    pub fn register_values(
        &self,
        register_map: &RegisterMap,
        registers: &[u8],
    ) -> HashMap<String, u64> {
        match self.user_dump_info() {
            Some(info) => context_registers(info.arch, register_map, registers),
            None => register_map.to_hashmap(registers),
        }
    }
}
