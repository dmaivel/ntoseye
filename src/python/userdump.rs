//! A user-mode minidump's own surface (`dbg.user_dump`): the one captured
//! process, its threads by thread id, and what the dump records beside its
//! memory. The dump has no kernel, so these carry no EPROCESS or ETHREAD:
//! the kernel's `Process` and `Thread` handles refuse on it instead.

use ntoseye_macros::{collection, handle};
use pyo3::prelude::*;

use super::args::AddressArg;
use super::command::{CommandHost, HostSession};
use super::context::{Context, Space};
use super::handle::Owner;
use super::memory::Memory;
use super::module::Modules;
use super::record::Typed;
use super::thread::{Frame, Registers};
use super::types::Struct;
use super::{err, raise};
use crate::session::Session;
use crate::target::userdump::UserExceptionDetail;
use crate::target::usermode::address::UserRegion;
use crate::userdump::{UnloadedModule, UserDumpInfo, UserHandle, UserProcessInfo, UserThreadInfo};

/// Why a user-dump handle cannot be served: the debugger's target is not
/// one (a borrowed debugger whose REPL opened something else).
fn info(session: &Session) -> PyResult<&UserDumpInfo> {
    session
        .target
        .user_dump_info()
        .ok_or_else(|| raise("the target is not a user-mode minidump"))
}

/// A user-mode minidump (`dbg.user_dump`): the captured process, its
/// threads, the exception the dump was written for, and the handle,
/// memory-region, and unloaded-module records the dump holds. The system
/// it ran on and when it was written are `dbg.inspect.version()` and
/// `dbg.inspect.time()`.
#[pyclass(module = "ntoseye")]
pub struct UserDump {
    pub owner: Owner,
}

impl CommandHost for UserDump {
    fn session(&self) -> HostSession<'_> {
        HostSession::Owner(&self.owner)
    }
}

impl UserDump {
    /// `f` over the dump's records.
    fn read<R: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&Session, &UserDumpInfo) -> PyResult<R> + Send,
    ) -> PyResult<R> {
        self.owner.with(py, |session| f(session, info(session)?))
    }

    fn thread_where(
        &self,
        py: Python<'_>,
        pick: impl FnOnce(&Session, &UserDumpInfo) -> Option<usize> + Send,
    ) -> PyResult<Option<UserThread>> {
        let owner = self.owner.derive(py);
        let thread = self.read(py, |session, info| {
            Ok(pick(session, info).map(|index| UserThread::listed(info, index)))
        })?;
        Ok(thread.map(|thread| thread(owner)))
    }
}

#[pymethods]
impl UserDump {
    /// The captured process.
    #[getter]
    fn process(&self, py: Python<'_>) -> PyResult<UserProcess> {
        let info = self.read(py, |_, info| Ok(info.process()))?;
        Ok(UserProcess {
            owner: self.owner.derive(py),
            info,
        })
    }

    /// The captured threads, by thread id: `threads[tid]`, iteration in the
    /// dump's order.
    #[getter]
    fn threads(&self, py: Python<'_>) -> PyResult<UserThreads> {
        self.owner.check(py)?;
        Ok(UserThreads {
            owner: self.owner.derive(py),
        })
    }

    /// The thread selected for inspection, which a debugger opens on the
    /// exception's thread when the dump records an exception.
    #[getter]
    fn current_thread(&self, py: Python<'_>) -> PyResult<Option<UserThread>> {
        self.thread_where(py, |session, info| {
            info.thread_for_backend_id(&session.current_thread)
                .and_then(|thread| info.thread_index(thread.tid))
        })
    }

    /// The exception the dump was written for, or `None` when it records
    /// none.
    #[getter]
    fn exception<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Option<UserExceptionDetail>>> {
        let exception = self.read(py, |session, _| Ok(session.target.user_exception_detail()))?;
        Typed::new(py, exception)
    }

    /// The thread that raised the dump's exception, or `None` when the dump
    /// records no exception (or its thread is not in the thread list).
    #[getter]
    fn exception_thread(&self, py: Python<'_>) -> PyResult<Option<UserThread>> {
        self.thread_where(py, |_, info| {
            let exception = info.exception.as_ref()?;
            info.thread_index(exception.thread_id)
        })
    }

    /// The registers at the exception (`.ecxr`), from the CONTEXT the dump
    /// stores beside the exception record, as a read-only `Frame`. Raises
    /// `NtoseyeError` when the dump records no exception or its context is
    /// unusable.
    fn exception_context(&self, py: Python<'_>) -> PyResult<Frame> {
        let owner = self.owner.derive(py);
        let registers = self.owner.with(py, |session| {
            session
                .target
                .user_exception_registers(&session.register_map)
                .map_err(err)
        })?;
        let ip = registers
            .get("rip")
            .or_else(|| registers.get("pc"))
            .copied()
            .unwrap_or(0);
        let sp = registers
            .get("rsp")
            .or_else(|| registers.get("sp"))
            .copied()
            .unwrap_or(0);
        Frame::new(py, owner, None, 0, ip, sp, None, None, registers)
    }

    /// The handles the process held, as the dump records them, or `None`
    /// when the dump has no handle data.
    #[getter]
    fn handles<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Option<Vec<UserHandle>>>> {
        let handles = self.read(py, |_, info| Ok(info.handles.clone()))?;
        Typed::new(py, handles)
    }

    /// The regions of the process's address space, by base, each with what
    /// uses it (`!address`), or `None` when the dump has no memory-info list.
    /// A region's bytes read only where the dump captured them.
    #[getter]
    fn regions<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Option<Vec<UserRegion>>>> {
        let regions = self.read(py, |session, info| {
            if info.regions.is_none() {
                return Ok(None);
            }
            let map = session.target.user_address_map().map_err(err)?;
            Ok(Some(map.regions.clone()))
        })?;
        Typed::new(py, regions)
    }

    /// The region holding `address`, or `None` when no region holds it or
    /// the dump has no memory-info list.
    fn region<'py>(
        &self,
        py: Python<'py>,
        address: AddressArg,
    ) -> PyResult<Typed<'py, Option<UserRegion>>> {
        let address = address.resolve(py, &self.owner, &Context::default())?.0;
        let region = self.read(py, |session, info| {
            if info.regions.is_none() {
                return Ok(None);
            }
            let map = session.target.user_address_map().map_err(err)?;
            Ok(map.region_at(address).cloned())
        })?;
        Typed::new(py, region)
    }

    /// The modules the process had unloaded.
    #[getter]
    fn unloaded_modules<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<UnloadedModule>>> {
        let modules = self.read(py, |_, info| Ok(info.unloaded_modules.clone()))?;
        Typed::new(py, modules)
    }

    /// What ntoseye dropped or cut short while reading the dump, and why.
    #[getter]
    fn notes(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        self.read(py, |_, info| Ok(info.notes.clone()))
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        self.read(py, |_, info| {
            Ok(format!(
                "<UserDump {}, {} threads, {} modules>",
                info.process_label(),
                info.threads.len(),
                info.modules.len()
            ))
        })
    }
}

/// The process a user-mode minidump captured (`dbg.user_dump.process`). It
/// is the only one, so it has no EPROCESS or page-table root; `memory`,
/// `modules`, and `threads` are the dump's.
#[handle(record = UserProcessInfo, key = pid, impl)]
pub struct UserProcess {
    pub owner: Owner,
    pub info: UserProcessInfo,
}

#[handle]
impl UserProcess {
    /// The `ntdll!_PEB` cursor, found through the selected thread's TEB, or
    /// `None` when the dump holds neither.
    #[getter]
    fn peb(&self, py: Python<'_>) -> PyResult<Option<Struct>> {
        let address = self.owner.with(py, |session| {
            info(session)?;
            Ok(session.target.user_dump_pseudo_register("peb").flatten())
        })?;
        address
            .map(|address| Struct::new(py, &self.owner, Space::Kernel, "ntdll!_PEB", address))
            .transpose()
    }

    /// The process's memory: every captured range, by virtual address.
    #[getter]
    fn memory(&self, py: Python<'_>) -> PyResult<Memory> {
        self.owner.check(py)?;
        Ok(Memory::new(self.owner.clone_ref(py), Space::Kernel))
    }

    /// The modules the dump lists.
    #[getter]
    fn modules(&self, py: Python<'_>) -> PyResult<Modules> {
        self.owner.check(py)?;
        Ok(Modules::kernel(self.owner.clone_ref(py)))
    }

    /// The captured threads.
    #[getter]
    fn threads(&self, py: Python<'_>) -> PyResult<UserThreads> {
        self.owner.check(py)?;
        Ok(UserThreads {
            owner: self.owner.clone_ref(py),
        })
    }

    fn __repr__(&self) -> String {
        let pid = self
            .info
            .pid
            .map_or_else(|| "None".to_string(), |pid| pid.to_string());
        let name = self.info.name.as_deref().unwrap_or("None");
        format!("UserProcess(pid={pid}, name={name:?})")
    }
}

/// The threads of a user-mode minidump (`dbg.user_dump.threads`), by
/// thread id, in the dump's order.
#[pyclass(module = "ntoseye")]
pub struct UserThreads {
    pub owner: Owner,
}

#[collection(records)]
impl UserThreads {
    fn enumerate(&self, py: Python<'_>) -> PyResult<Vec<UserThread>> {
        let owner = self.owner.derive(py);
        let threads = self.owner.with(py, |session| {
            let info = info(session)?;
            Ok((0..info.threads.len())
                .map(|index| UserThread::listed(info, index))
                .collect::<Vec<_>>())
        })?;
        Ok(threads
            .into_iter()
            .map(|thread| thread(owner.clone_ref(py)))
            .collect())
    }

    /// The thread with a TID.
    fn lookup(&self, py: Python<'_>, tid: &u64) -> PyResult<Option<UserThread>> {
        Ok(self
            .enumerate(py)?
            .into_iter()
            .find(|thread| u64::from(thread.info.tid) == *tid))
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("UserThreads(len={})", self.enumerate(py)?.len()))
    }
}

/// One thread a user-mode minidump captured, identified by its thread id.
/// Its registers are the context the dump recorded for it; nothing about it
/// can be changed.
#[handle(record = UserThreadInfo, key = tid, context = self.context(), impl)]
pub struct UserThread {
    owner: Owner,
    info: UserThreadInfo,
    /// The backend's id for the thread (`<pid>.<tid>` in hex), which
    /// selects it.
    id: String,
    index: usize,
    exception: bool,
}

impl UserThread {
    /// The thread at `index` in the dump's list, for an owner.
    fn listed(
        info: &UserDumpInfo,
        index: usize,
    ) -> impl FnOnce(Owner) -> UserThread + Send + use<> {
        let thread = info.threads[index].clone();
        let id = info.backend_thread_id(thread.tid);
        let exception = info
            .exception
            .as_ref()
            .is_some_and(|exception| exception.thread_id == thread.tid);
        move |owner| UserThread {
            owner,
            info: thread,
            id,
            index,
            exception,
        }
    }

    fn context(&self) -> Context {
        Context::vcpu(self.id.clone())
    }
}

#[handle]
impl UserThread {
    /// The thread's position in the dump's thread list, which `~N` names.
    #[getter]
    fn index(&self, py: Python<'_>) -> PyResult<usize> {
        self.owner.check(py)?;
        Ok(self.index)
    }

    /// Whether this thread raised the exception the dump was written for.
    #[getter]
    fn exception(&self, py: Python<'_>) -> PyResult<bool> {
        self.owner.check(py)?;
        Ok(self.exception)
    }

    /// The `ntdll!_TEB` cursor, or `None` when the dump records no TEB.
    #[getter]
    fn teb(&self, py: Python<'_>) -> PyResult<Option<Struct>> {
        self.owner.check(py)?;
        if self.info.teb == 0 {
            return Ok(None);
        }
        Struct::new(py, &self.owner, Space::Kernel, "ntdll!_TEB", self.info.teb).map(Some)
    }

    /// The registers the dump recorded for the thread, read-only. Reading
    /// one raises `NtoseyeError` when the thread's context is unusable.
    #[getter]
    fn registers(&self, py: Python<'_>) -> PyResult<Registers> {
        self.owner.check(py)?;
        Ok(Registers::new(
            self.owner.clone_ref(py),
            self.context(),
            None,
        ))
    }

    /// Recover the thread's stack from its recorded registers.
    #[pyo3(signature = (limit=64))]
    fn backtrace(&self, py: Python<'_>, limit: usize) -> PyResult<Vec<Frame>> {
        let (frames, live) = self.owner.with_in(py, &self.context(), |session| {
            let (trace, _, live) = session
                .recovered_backtrace(limit.clamp(1, 4096))
                .map_err(err)?;
            Ok((trace.frames, live))
        })?;
        let owner = self.owner.derive(py);
        Ok(frames
            .into_iter()
            .enumerate()
            .map(|(index, frame)| {
                Frame::from_recovered(
                    owner.clone_ref(py),
                    None,
                    None,
                    Some(self.id.clone()),
                    index,
                    frame,
                    live,
                )
            })
            .collect())
    }

    fn __repr__(&self) -> String {
        match &self.info.name {
            Some(name) => format!("UserThread(tid={:#x}, name={name:?})", self.info.tid),
            None => format!("UserThread(tid={:#x})", self.info.tid),
        }
    }
}
