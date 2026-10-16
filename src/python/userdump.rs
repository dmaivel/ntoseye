//! A user-mode minidump's own surface (`dbg.user_dump`): the one captured
//! process, its threads by thread id, and what the dump records beside its
//! memory. The dump has no kernel, so these carry no EPROCESS or ETHREAD:
//! the kernel's `Process` and `Thread` handles refuse on it instead.

use pyo3::exceptions::PyKeyError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use super::context::{Context, Space};
use super::handle::Owner;
use super::iter::UserThreadIterator;
use super::memory::Memory;
use super::module::Modules;
use super::record::PlainDict;
use super::thread::{Frame, Registers};
use super::types::Struct;
use super::{err, raise};
use crate::session::Session;
use crate::userdump::{UserDumpInfo, UserThread as DumpThread, UserThreadInfo};
use crate::view;
use crate::view::record::Typed;

/// Why a user-dump handle cannot be served: the debugger's target is not
/// one (a borrowed debugger whose REPL opened something else).
fn info(session: &Session) -> PyResult<&UserDumpInfo> {
    session
        .target
        .user_dump_info()
        .ok_or_else(|| raise("the target is not a user-mode minidump"))
}

/// What a [`UserThread`] handle holds: the captured thread and where the
/// dump lists it.
struct Captured {
    /// The backend's id for the thread (`<pid>.<tid>` in hex), which
    /// selects it.
    id: String,
    index: usize,
    exception: bool,
    thread: DumpThread,
}

impl Captured {
    fn of(info: &UserDumpInfo, index: usize) -> Self {
        let thread = info.threads[index].clone();
        Captured {
            id: info.backend_thread_id(thread.tid),
            index,
            exception: info
                .exception
                .as_ref()
                .is_some_and(|exception| exception.thread_id == thread.tid),
            thread,
        }
    }
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
        let captured = self.read(py, |session, info| {
            Ok(pick(session, info).map(|index| Captured::of(info, index)))
        })?;
        Ok(captured.map(|captured| UserThread::new(self.owner.derive(py), captured)))
    }
}

#[pymethods]
impl UserDump {
    /// The captured process.
    #[getter]
    fn process(&self, py: Python<'_>) -> PyResult<UserProcess> {
        self.owner.check(py)?;
        Ok(UserProcess {
            owner: self.owner.derive(py),
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
    fn exception<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, Option<view::userdump::UserDumpException>>> {
        let exception = self.read(py, |session, info| {
            Ok(info
                .exception
                .as_ref()
                .map(|exception| view::userdump::exception(&session.target, exception)))
        })?;
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
    fn handles<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, Option<Vec<view::userdump::UserDumpHandle>>>> {
        let handles = self.read(py, |_, info| {
            Ok(info
                .handles
                .as_ref()
                .map(|handles| handles.iter().map(view::userdump::handle).collect()))
        })?;
        Typed::new(py, handles)
    }

    /// The regions of the process's address space, by base, each with what
    /// uses it (`!address`), or `None` when the dump has no memory-info list.
    /// A region's bytes read only where the dump captured them.
    #[getter]
    fn regions<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, Option<Vec<view::userdump::UserDumpRegion>>>> {
        let regions = self.read(py, |session, info| {
            if info.regions.is_none() {
                return Ok(None);
            }
            let map = session.target.user_address_map().map_err(err)?;
            Ok(Some(
                map.regions.iter().map(view::userdump::region).collect(),
            ))
        })?;
        Typed::new(py, regions)
    }

    /// The region holding `address`, or `None` when no region holds it or
    /// the dump has no memory-info list.
    fn region<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, Option<view::userdump::UserDumpRegion>>> {
        let region = self.read(py, |session, info| {
            if info.regions.is_none() {
                return Ok(None);
            }
            let map = session.target.user_address_map().map_err(err)?;
            Ok(map.region_at(address).map(view::userdump::region))
        })?;
        Typed::new(py, region)
    }

    /// The modules the process had unloaded.
    #[getter]
    fn unloaded_modules<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, Vec<view::userdump::UserDumpUnloadedModule>>> {
        let modules = self.read(py, |_, info| {
            Ok(info
                .unloaded_modules
                .iter()
                .map(view::userdump::unloaded_module)
                .collect())
        })?;
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
#[pyclass(module = "ntoseye")]
pub struct UserProcess {
    pub owner: Owner,
}

impl UserProcess {
    fn read<R: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&UserDumpInfo) -> R + Send,
    ) -> PyResult<R> {
        self.owner.with(py, |session| Ok(f(info(session)?)))
    }
}

#[pymethods]
impl UserProcess {
    /// The process id, when the dump records it.
    #[getter]
    fn pid(&self, py: Python<'_>) -> PyResult<Option<u32>> {
        self.read(py, |info| info.process_id)
    }

    /// The executable's file name, from the first module the dump lists.
    #[getter]
    fn name(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.read(py, |info| info.process_name().map(str::to_string))
    }

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

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let (pid, name, threads, modules) = self.read(py, |info| {
            (
                info.process_id,
                info.process_name().map(str::to_string),
                info.threads.len(),
                info.modules.len(),
            )
        })?;
        let dict = PyDict::new(py);
        dict.set_item("pid", pid)?;
        dict.set_item("name", name)?;
        dict.set_item("threads", threads)?;
        dict.set_item("modules", modules)?;
        Ok(PlainDict(dict))
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        self.read(py, |info| {
            let pid = info
                .process_id
                .map_or_else(|| "None".to_string(), |pid| pid.to_string());
            let name = info.process_name().unwrap_or("None");
            format!("UserProcess(pid={pid}, name={name:?})")
        })
    }
}

/// The threads of a user-mode minidump (`dbg.user_dump.threads`), by
/// thread id.
#[pyclass(module = "ntoseye")]
pub struct UserThreads {
    pub owner: Owner,
}

impl UserThreads {
    fn by_tid(&self, py: Python<'_>, tid: u64) -> PyResult<Option<UserThread>> {
        let captured = self.owner.with(py, |session| {
            let info = info(session)?;
            let index = u32::try_from(tid)
                .ok()
                .and_then(|tid| info.thread_index(tid));
            Ok(index.map(|index| Captured::of(info, index)))
        })?;
        Ok(captured.map(|captured| UserThread::new(self.owner.derive(py), captured)))
    }

    fn handles(&self, py: Python<'_>) -> PyResult<Vec<UserThread>> {
        let captured = self.owner.with(py, |session| {
            let info = info(session)?;
            Ok((0..info.threads.len())
                .map(|index| Captured::of(info, index))
                .collect::<Vec<_>>())
        })?;
        let owner = self.owner.derive(py);
        Ok(captured
            .into_iter()
            .map(|captured| UserThread::new(owner.clone_ref(py), captured))
            .collect())
    }
}

#[pymethods]
impl UserThreads {
    /// Get the thread with a TID, or raise `KeyError` if no thread has that
    /// TID.
    fn __getitem__(&self, py: Python<'_>, tid: u64) -> PyResult<UserThread> {
        self.by_tid(py, tid)?
            .ok_or_else(|| PyKeyError::new_err(tid))
    }

    /// Get the thread with a TID, or `None` if no thread has that TID.
    fn get(&self, py: Python<'_>, tid: u64) -> PyResult<Option<UserThread>> {
        self.by_tid(py, tid)
    }

    fn __contains__(&self, py: Python<'_>, tid: u64) -> PyResult<bool> {
        Ok(self.by_tid(py, tid)?.is_some())
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        self.owner
            .with(py, |session| Ok(info(session)?.threads.len()))
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<UserThreadIterator> {
        Ok(UserThreadIterator::new(self.handles(py)?))
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("UserThreads(len={})", self.__len__(py)?))
    }
}

/// One thread a user-mode minidump captured, identified by its thread id.
/// Its registers are the context the dump recorded for it; nothing about it
/// can be changed.
#[pyclass(module = "ntoseye")]
pub struct UserThread {
    owner: Owner,
    id: String,
    index: usize,
    exception: bool,
    thread: DumpThread,
}

impl UserThread {
    fn new(owner: Owner, captured: Captured) -> Self {
        let Captured {
            id,
            index,
            exception,
            thread,
        } = captured;
        UserThread {
            owner,
            id,
            index,
            exception,
            thread,
        }
    }

    pub fn context(&self) -> Context {
        Context::vcpu(self.id.clone())
    }

    /// The backend's id for the thread, which selects it.
    pub fn backend_id(&self) -> &str {
        &self.id
    }

    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    fn times(&self) -> Option<&UserThreadInfo> {
        self.thread.info.as_ref()
    }
}

#[pymethods]
impl UserThread {
    /// The thread id.
    #[getter]
    fn tid(&self, py: Python<'_>) -> PyResult<u32> {
        self.owner.check(py)?;
        Ok(self.thread.tid)
    }

    /// The backend's id for the thread, `<pid>.<tid>` in hex as WinDbg
    /// writes it (just `<tid>` when the dump records no process id).
    #[getter]
    fn id(&self, py: Python<'_>) -> PyResult<String> {
        self.owner.check(py)?;
        Ok(self.id.clone())
    }

    /// The thread's position in the dump's thread list, which `~N` names.
    #[getter]
    fn index(&self, py: Python<'_>) -> PyResult<usize> {
        self.owner.check(py)?;
        Ok(self.index)
    }

    /// The thread's description (`SetThreadDescription`), when the dump
    /// records one.
    #[getter]
    fn name(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.owner.check(py)?;
        Ok(self.thread.name.clone())
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
        if self.thread.teb == 0 {
            return Ok(None);
        }
        Struct::new(
            py,
            &self.owner,
            Space::Kernel,
            "ntdll!_TEB",
            self.thread.teb,
        )
        .map(Some)
    }

    /// The captured stack as `(start, size)`, or `None` when the dump holds
    /// none of it.
    #[getter]
    fn stack(&self, py: Python<'_>) -> PyResult<Option<(u64, u64)>> {
        self.owner.check(py)?;
        Ok(self.thread.stack)
    }

    #[getter]
    fn suspend_count(&self, py: Python<'_>) -> PyResult<u32> {
        self.owner.check(py)?;
        Ok(self.thread.suspend_count)
    }

    #[getter]
    fn priority(&self, py: Python<'_>) -> PyResult<u32> {
        self.owner.check(py)?;
        Ok(self.thread.priority)
    }

    #[getter]
    fn priority_class(&self, py: Python<'_>) -> PyResult<u32> {
        self.owner.check(py)?;
        Ok(self.thread.priority_class)
    }

    /// The thread's start address, when the dump records thread info.
    #[getter]
    fn start_address(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.times().map(|info| info.start_address))
    }

    /// When the thread started, as a FILETIME, when the dump records thread
    /// info.
    #[getter]
    fn create_time(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.times().map(|info| info.create_time))
    }

    /// When the thread exited, as a FILETIME (0 while it runs), when the
    /// dump records thread info.
    #[getter]
    fn exit_time(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.times().map(|info| info.exit_time))
    }

    /// The thread's exit status, when the dump records thread info.
    #[getter]
    fn exit_status(&self, py: Python<'_>) -> PyResult<Option<u32>> {
        self.owner.check(py)?;
        Ok(self.times().map(|info| info.exit_status))
    }

    /// Kernel-mode time the thread had run, in 100 ns units, when the dump
    /// records thread info.
    #[getter]
    fn kernel_time(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.times().map(|info| info.kernel_time))
    }

    /// User-mode time the thread had run, in 100 ns units, when the dump
    /// records thread info.
    #[getter]
    fn user_time(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.times().map(|info| info.user_time))
    }

    /// The thread's processor affinity mask, when the dump records thread
    /// info.
    #[getter]
    fn affinity(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.times().map(|info| info.affinity))
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
        let frames = self.owner.with_in(py, &self.context(), |session| {
            let (trace, _, live) = session
                .recovered_backtrace(limit.clamp(1, 4096))
                .map_err(err)?;
            Ok((trace.frames, live))
        })?;
        let (frames, live) = frames;
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

    /// The thread as a plain `dict`.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        let thread = &self.thread;
        let dict = PyDict::new(py);
        dict.set_item("tid", thread.tid)?;
        dict.set_item("id", &self.id)?;
        dict.set_item("index", self.index)?;
        dict.set_item("name", &thread.name)?;
        dict.set_item("exception", self.exception)?;
        dict.set_item("teb", (thread.teb != 0).then_some(thread.teb))?;
        dict.set_item("stack", thread.stack)?;
        dict.set_item("suspend_count", thread.suspend_count)?;
        dict.set_item("priority", thread.priority)?;
        dict.set_item("priority_class", thread.priority_class)?;
        dict.set_item("start_address", self.times().map(|info| info.start_address))?;
        dict.set_item("create_time", self.times().map(|info| info.create_time))?;
        dict.set_item("exit_time", self.times().map(|info| info.exit_time))?;
        dict.set_item("exit_status", self.times().map(|info| info.exit_status))?;
        dict.set_item("kernel_time", self.times().map(|info| info.kernel_time))?;
        dict.set_item("user_time", self.times().map(|info| info.user_time))?;
        dict.set_item("affinity", self.times().map(|info| info.affinity))?;
        dict.set_item("context_error", thread.context.as_ref().err())?;
        Ok(PlainDict(dict))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, UserThread>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner) && self.thread.tid == other.thread.tid
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(self.thread.tid)
    }

    fn __repr__(&self) -> String {
        match &self.thread.name {
            Some(name) => format!("UserThread(tid={:#x}, name={name:?})", self.thread.tid),
            None => format!("UserThread(tid={:#x})", self.thread.tid),
        }
    }
}
