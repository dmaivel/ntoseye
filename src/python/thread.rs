//! Windows-thread, stack-frame, register, and vCPU handles.

use std::collections::HashMap;

use indexmap::IndexMap;

use pyo3::exceptions::{PyAttributeError, PyIndexError, PyKeyError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyInt};

use super::context::{Context, Space};
use super::handle::{Owner, require_halted};
use super::iter::{CpuIterator, NameIterator, ThreadIterator};
use super::process::Process;
use super::record::{PlainDict, Record};
use super::types::{Struct, enum_value};
use super::{err, view_dict, view_record};
use crate::guest::ProcessInfo;
use crate::session::{Session, VcpuInfo, processor_index_from_backend_thread_id};
use crate::target::sched::ApcSelector;
use crate::target::{SelectedFrame, Target, ThreadInfo, cpu};
use crate::trapframe::read_ktrap_frame_at_or_current;
use crate::types::VirtAddr;
use crate::unwind::{RecoveredFrame, StackFrame};
use crate::view;

/// A thread collection: `dbg.threads` (all) or `proc.threads`.
#[pyclass(module = "ntoseye")]
pub struct Threads {
    pub owner: Owner,
    pub process: Option<ProcessInfo>,
}

impl Threads {
    pub fn all(owner: Owner) -> Threads {
        Threads {
            owner,
            process: None,
        }
    }

    /// `owner` should be the process handle's (stamped) owner.
    pub fn of_process(owner: Owner, info: ProcessInfo) -> Threads {
        Threads {
            owner,
            process: Some(info),
        }
    }

    fn snapshot(&self, py: Python<'_>) -> PyResult<Vec<ThreadInfo>> {
        let context = self
            .process
            .clone()
            .map_or_else(Context::default, Context::process);
        self.owner
            .with_in(py, &context, |session| match &self.process {
                Some(process) => session
                    .target
                    .enumerate_threads_for_process_info(process)
                    .map_err(err),
                None => session
                    .windows_threads()
                    .map(|(threads, _)| threads)
                    .map_err(err),
            })
    }

    fn by_tid(&self, py: Python<'_>, tid: u64) -> PyResult<Option<Thread>> {
        let Some(info) = self
            .snapshot(py)?
            .into_iter()
            .find(|thread| thread.tid == Some(tid))
        else {
            return Ok(None);
        };
        Ok(Some(Thread::from_owner(self.owner.derive(py), info)))
    }

    fn handles(&self, py: Python<'_>) -> PyResult<Vec<Py<Thread>>> {
        let infos = self.snapshot(py)?;
        let owner = self.owner.derive(py);
        infos
            .into_iter()
            .map(|info| Py::new(py, Thread::from_owner(owner.clone_ref(py), info)))
            .collect()
    }
}

#[pymethods]
impl Threads {
    /// Resolve a TID, raising `KeyError` when it is not present.
    fn __getitem__(&self, py: Python<'_>, tid: u64) -> PyResult<Thread> {
        self.by_tid(py, tid)?
            .ok_or_else(|| PyKeyError::new_err(tid))
    }

    /// Resolve a TID, returning `None` when it is not present.
    fn get(&self, py: Python<'_>, tid: u64) -> PyResult<Option<Thread>> {
        self.by_tid(py, tid)
    }

    /// Resolve an ETHREAD or KTHREAD address.
    fn at(&self, py: Python<'_>, address: u64) -> PyResult<Thread> {
        let info = self
            .snapshot(py)?
            .into_iter()
            .find(|thread| thread.ethread.0 == address || thread.kthread.0 == address)
            .ok_or_else(|| PyKeyError::new_err(format!("{address:#x}")))?;
        Ok(Thread::from_owner(self.owner.derive(py), info))
    }

    fn __contains__(&self, py: Python<'_>, tid: u64) -> PyResult<bool> {
        Ok(self.by_tid(py, tid)?.is_some())
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.snapshot(py)?.len())
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<ThreadIterator> {
        Ok(ThreadIterator::new(self.handles(py)?))
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let count = self.snapshot(py)?.len();
        Ok(match &self.process {
            Some(process) => format!("Threads(pid={}, len={count})", process.pid),
            None => format!("Threads(len={count})"),
        })
    }
}

/// One Windows thread. The ETHREAD address is its identity within a debugger.
#[pyclass(module = "ntoseye")]
pub struct Thread {
    pub owner: Owner,
    pub info: ThreadInfo,
}

impl Thread {
    /// A handle for `info` under an already stamped `owner`.
    pub fn from_owner(owner: Owner, info: ThreadInfo) -> Thread {
        Thread { owner, info }
    }

    fn cpu_id(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.owner.with(py, |session| {
            Ok(session
                .active_thread_map()
                .get(&self.info.ethread.0)
                .map(|(vcpu, _)| vcpu.clone()))
        })
    }

    fn process_info(&self, py: Python<'_>) -> PyResult<Option<ProcessInfo>> {
        self.owner
            .with(py, |session| process_for_thread(session, &self.info))
    }

    fn context(&self, process: Option<ProcessInfo>) -> Context {
        Context {
            process,
            thread: Some(self.info.clone()),
            ..Context::default()
        }
    }
}

#[pymethods]
impl Thread {
    /// The thread id (`None` for a thread that has none, like idle threads).
    #[getter]
    fn tid(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.info.tid)
    }

    /// The owning process's id.
    #[getter]
    fn pid(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        self.owner.check(py)?;
        Ok(self.info.pid)
    }

    /// The `_ETHREAD` address: the thread's identity.
    #[getter]
    fn ethread(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.ethread.0)
    }

    /// The `_KTHREAD` address.
    #[getter]
    fn kthread(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.kthread.0)
    }

    /// The owning process.
    #[getter]
    fn process(&self, py: Python<'_>) -> PyResult<Option<Process>> {
        let Some(info) = self.process_info(py)? else {
            return Ok(None);
        };
        Ok(Some(Process::from_owner(self.owner.derive(py), info)))
    }

    /// The scheduler state, a `_KTHREAD_STATE` member (`IntEnum`).
    #[getter]
    fn state<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyInt>>> {
        self.owner.check(py)?;
        optional_enum(py, &self.owner, "_KTHREAD_STATE", self.info.state)
    }

    /// Why the thread waits, a `_KWAIT_REASON` member (`IntEnum`).
    #[getter]
    fn wait_reason<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyInt>>> {
        self.owner.check(py)?;
        optional_enum(py, &self.owner, "_KWAIT_REASON", self.info.wait_reason)
    }

    /// The processor the thread is running on, or `None` when it is not running.
    #[getter]
    fn cpu(&self, py: Python<'_>) -> PyResult<Option<Cpu>> {
        let Some(id) = self.cpu_id(py)? else {
            return Ok(None);
        };
        Ok(Some(Cpu::from_owner(self.owner.derive(py), id)))
    }

    /// The typed `_ETHREAD` object.
    #[getter]
    fn object(&self, py: Python<'_>) -> PyResult<Struct> {
        self.owner.check(py)?;
        Struct::new(
            py,
            &self.owner,
            Space::Kernel,
            "_ETHREAD",
            self.info.ethread.0,
        )
    }

    /// The process-bound `_TEB`, or `None` for kernel threads.
    #[getter]
    fn teb(&self, py: Python<'_>) -> PyResult<Option<Struct>> {
        let Some(address) = self.info.teb else {
            self.owner.check(py)?;
            return Ok(None);
        };
        let Some(process) = self.process_info(py)? else {
            return Ok(None);
        };
        Struct::new(py, &self.owner, Space::Process(process), "_TEB", address.0).map(Some)
    }

    /// Recover this thread's stack from live registers or its parked context.
    #[pyo3(signature = (limit=64))]
    fn backtrace(&self, py: Python<'_>, limit: usize) -> PyResult<Vec<Frame>> {
        let process = self.process_info(py)?;
        let context = self.context(process.clone());
        let (frames, live_thread) = self.owner.with_in(py, &context, |session| {
            let (trace, _) = session
                .recovered_backtrace(limit.clamp(1, 4096))
                .map_err(err)?;
            Ok((trace.frames, session.parked_windows_thread().is_none()))
        })?;
        let owner = self.owner.derive(py);
        Ok(frames
            .into_iter()
            .enumerate()
            .map(|(index, frame)| {
                Frame::from_recovered(
                    owner.clone_ref(py),
                    Some(self.info.clone()),
                    process.clone(),
                    index,
                    frame,
                    live_thread,
                )
            })
            .collect())
    }

    /// Decode this thread's APC lists (`!apc`).
    fn apcs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let context = self.context(self.process_info(py)?);
        let detail = self.owner.with_in(py, &context, |session| {
            session
                .inspect_apcs(ApcSelector::Thread(self.info.ethread))
                .map_err(err)
        })?;
        view_record(py, &view::sched::apcs(&detail))
    }

    /// Decode the saved `_KTRAP_FRAME` (`!trap`).
    fn trap_frame<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let context = self.context(self.process_info(py)?);
        let view = self.owner.with_in(py, &context, |session| {
            trap_frame_view(&session.target, self.info.trap_frame)
        })?;
        view_record(py, &view)
    }

    /// Decode the thread's Win32 last-error and NTSTATUS values (`!gle`).
    fn last_error<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let context = self.context(self.process_info(py)?);
        let view = self.owner.with_in(py, &context, |session| {
            let detail = session.target.last_error().map_err(err)?;
            Ok(view::usermode::last_error(&detail))
        })?;
        view_record(py, &view)
    }

    /// Thread summary and saved scheduling details (`!thread`).
    fn inspect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let active = self.cpu_id(py)?;
        view_record(py, &view::thread(&self.info, active.as_deref()))
    }

    /// The thread as a plain `dict`, the shape MCP renders.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let active = self.cpu_id(py)?;
        view_dict(py, &view::thread(&self.info, active.as_deref()))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Thread>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner) && self.info.ethread == other.info.ethread
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(self.info.ethread)
    }

    fn __repr__(&self) -> String {
        format!(
            "Thread(tid={}, ethread={:#x})",
            self.info
                .tid
                .map_or_else(|| "None".to_string(), |tid| tid.to_string()),
            self.info.ethread.0
        )
    }
}

/// One recovered stack frame with the register context used for locals.
#[pyclass(module = "ntoseye")]
pub struct Frame {
    owner: Owner,
    thread_info: Option<ThreadInfo>,
    process_info: Option<ProcessInfo>,
    index: usize,
    ip: u64,
    sp: u64,
    symbol: Option<String>,
    source: Option<String>,
    registers: HashMap<String, u64>,
    frame_base: Option<u64>,
    live_thread: bool,
    writable: bool,
}

impl Frame {
    /// Construct a frame-like register context (used for decoded CONTEXTs).
    pub fn new(
        py: Python<'_>,
        owner: Owner,
        thread: Option<ThreadInfo>,
        index: usize,
        ip: u64,
        sp: u64,
        symbol: Option<String>,
        source: Option<String>,
        registers: HashMap<String, u64>,
    ) -> PyResult<Frame> {
        owner.check(py)?;
        Ok(Frame {
            owner,
            thread_info: thread,
            process_info: None,
            index,
            ip,
            sp,
            symbol,
            source,
            registers,
            frame_base: None,
            live_thread: false,
            writable: false,
        })
    }

    fn from_recovered(
        owner: Owner,
        thread_info: Option<ThreadInfo>,
        process_info: Option<ProcessInfo>,
        index: usize,
        recovered: RecoveredFrame,
        live_thread: bool,
    ) -> Frame {
        let frame: StackFrame = recovered.frame;
        Frame {
            owner,
            thread_info,
            process_info,
            index,
            ip: frame.ip,
            sp: frame.sp,
            symbol: (!frame.symbol.is_empty()).then_some(frame.symbol),
            source: Some(frame.source.as_str().to_string()),
            registers: recovered.registers,
            frame_base: recovered.frame_base,
            live_thread,
            writable: live_thread && index == 0,
        }
    }

    fn ethread(&self) -> Option<VirtAddr> {
        self.thread_info.as_ref().map(|thread| thread.ethread)
    }

    fn context(&self) -> Context {
        Context {
            process: self.process_info.clone(),
            vcpu: None,
            thread: self.thread_info.clone(),
            frame: (self.live_thread && self.thread_info.is_some()).then_some(self.index),
        }
    }

    fn selected_frame(&self) -> SelectedFrame {
        SelectedFrame {
            index: self.index,
            ip: self.ip,
            sp: self.sp,
            frame_base: self.frame_base,
            registers: self.registers.clone(),
            seed_registers: self.registers.clone(),
            seed_live: self.writable,
        }
    }
}

#[pymethods]
impl Frame {
    /// The frame's position, 0 being the innermost.
    #[getter]
    fn index(&self, py: Python<'_>) -> PyResult<usize> {
        self.owner.check(py)?;
        Ok(self.index)
    }

    /// The frame's instruction pointer.
    #[getter]
    fn ip(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.ip)
    }

    /// The frame's stack pointer.
    #[getter]
    fn sp(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.sp)
    }

    /// The symbol at `ip`, if one resolved.
    #[getter]
    fn symbol(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.owner.check(py)?;
        Ok(self.symbol.clone())
    }

    /// How the frame was recovered (unwind data, frame pointer, ...).
    #[getter]
    fn source(&self, py: Python<'_>) -> PyResult<Option<String>> {
        self.owner.check(py)?;
        Ok(self.source.clone())
    }

    /// The thread this stack belongs to.
    #[getter]
    fn thread(&self, py: Python<'_>) -> PyResult<Option<Thread>> {
        self.owner.check(py)?;
        Ok(self
            .thread_info
            .clone()
            .map(|info| Thread::from_owner(self.owner.derive(py), info)))
    }

    /// The frame's registers: the live file for the innermost frame of a running
    /// thread (writable), otherwise the recovered subset (read-only).
    #[getter]
    fn registers(&self, py: Python<'_>) -> PyResult<Registers> {
        self.owner.check(py)?;
        Ok(Registers {
            owner: self.owner.derive(py),
            context: self.context(),
            values: (!self.writable).then(|| self.registers.clone()),
        })
    }

    /// Local variables evaluated in this frame's recovered context.
    #[getter]
    fn locals(&self, py: Python<'_>) -> PyResult<IndexMap<String, Option<u64>>> {
        self.owner.check(py)?;
        if self.thread_info.is_none() {
            return Ok(IndexMap::new());
        }
        let context = self.context();
        self.owner.with_in(py, &context, |session| {
            // Parked stacks have recovered registers but no selectable live
            // frame; install that plain Rust context only for this operation.
            if !self.live_thread {
                session.select_frame(self.selected_frame());
            }
            let locals = session
                .target
                .procedure_locals(VirtAddr(self.ip))
                .map_err(err)?;
            Ok(locals
                .iter()
                .flat_map(|locals| locals.iter())
                .map(|local| {
                    let value = session
                        .target
                        .resolve_procedure_local_value(VirtAddr(self.ip), local);
                    (local.name.clone(), value)
                })
                .collect())
        })
    }

    /// Resolve a local variable by name.
    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<Option<u64>> {
        self.locals(py)?
            .swap_remove(name)
            .ok_or_else(|| PyKeyError::new_err(name.to_string()))
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        let dict = PyDict::new(py);
        dict.set_item("index", self.index)?;
        dict.set_item("ip", self.ip)?;
        dict.set_item("sp", self.sp)?;
        dict.set_item("symbol", self.symbol.as_deref())?;
        dict.set_item("source", self.source.as_deref())?;
        dict.set_item(
            "thread",
            self.thread_info.as_ref().map(|thread| thread.ethread.0),
        )?;
        dict.set_item("registers", register_map(&self.registers))?;
        Ok(PlainDict(dict))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Frame>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner)
                && self.ethread() == other.ethread()
                && self.index == other.index
                && self.ip == other.ip
        })
    }

    fn __hash__(&self) -> isize {
        self.owner
            .identity_hash((self.ethread(), self.index, self.ip))
    }

    fn __repr__(&self) -> String {
        match &self.symbol {
            Some(symbol) => format!(
                "Frame(index={}, ip={:#x}, symbol={symbol:?})",
                self.index, self.ip
            ),
            None => format!("Frame(index={}, ip={:#x})", self.index, self.ip),
        }
    }
}

/// A register file bound to a vCPU or recovered frame context.
#[pyclass(module = "ntoseye")]
pub struct Registers {
    owner: Owner,
    context: Context,
    values: Option<HashMap<String, u64>>,
}

impl Registers {
    /// Register values by name. A live file adds 128-bit registers at full
    /// width (`xmm0`, `v0`) beside their 64-bit halves; a recovered frame
    /// holds only what unwinding recovered.
    fn values(&self, py: Python<'_>) -> PyResult<HashMap<String, u128>> {
        self.owner.check(py)?;
        if let Some(values) = &self.values {
            return Ok(values
                .iter()
                .map(|(name, value)| (name.clone(), u128::from(*value)))
                .collect());
        }
        self.owner.with_in(py, &self.context, |session| {
            require_halted(session, "registers")?;
            let bytes = session.read_registers().map_err(err)?;
            let map = &session.register_map;
            Ok(map
                .to_hashmap(&bytes)
                .into_iter()
                .map(|(name, value)| (name, u128::from(value)))
                .chain(map.wide_values(&bytes))
                .collect())
        })
    }

    fn value(&self, py: Python<'_>, name: &str) -> PyResult<u128> {
        let values = self.values(py)?;
        register_value(&values, name).ok_or_else(|| PyKeyError::new_err(name.to_string()))
    }

    fn set_value(&self, py: Python<'_>, name: &str, value: u64) -> PyResult<()> {
        self.owner.check(py)?;
        if self.values.is_some() {
            return Err(PyTypeError::new_err("this register file is read-only"));
        }
        self.owner.with_in(py, &self.context, |session| {
            require_halted(session, "register write")?;
            session.write_register(name, value).map_err(err)
        })?;
        Ok(())
    }
}

#[pymethods]
impl Registers {
    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<u128> {
        let values = self.values(py)?;
        register_value(&values, name)
            .ok_or_else(|| PyAttributeError::new_err(format!("register '{name}' is not available")))
    }

    fn __setattr__(&self, py: Python<'_>, name: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        self.set_value(py, name, value.extract()?)
    }

    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<u128> {
        self.value(py, name)
    }

    fn __setitem__(&self, py: Python<'_>, name: &str, value: u64) -> PyResult<()> {
        self.set_value(py, name, value)
    }

    fn __contains__(&self, py: Python<'_>, name: &str) -> PyResult<bool> {
        Ok(self
            .values(py)?
            .keys()
            .any(|key| key.eq_ignore_ascii_case(name)))
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<NameIterator> {
        let names = sorted_registers(&self.values(py)?)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        Ok(NameIterator::new(names))
    }

    /// The register names, sorted.
    fn keys(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        Ok(sorted_registers(&self.values(py)?)
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    /// `(name, value)` pairs, sorted by name.
    fn items(&self, py: Python<'_>) -> PyResult<Vec<(String, u128)>> {
        Ok(sorted_registers(&self.values(py)?))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.values(py)?.len())
    }

    /// The registers as a plain `dict`, sorted by name.
    fn to_dict(&self, py: Python<'_>) -> PyResult<IndexMap<String, u128>> {
        Ok(register_map(&self.values(py)?))
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("Registers({})", self.values(py)?.len()))
    }
}

/// The target's processors, in backend vCPU order (`dbg.cpus`); listing
/// them needs a halted target.
#[pyclass(module = "ntoseye")]
pub struct Cpus {
    pub owner: Owner,
}

impl Cpus {
    pub fn new(owner: Owner) -> Cpus {
        Cpus { owner }
    }

    fn ids(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        self.owner.with(py, |session| {
            require_halted(session, "vcpus")?;
            Ok(session
                .vcpus()
                .map_err(err)?
                .into_iter()
                .map(|cpu| cpu.id)
                .collect())
        })
    }

    fn handles(&self, py: Python<'_>) -> PyResult<Vec<Py<Cpu>>> {
        let ids = self.ids(py)?;
        let owner = self.owner.derive(py);
        ids.into_iter()
            .map(|id| Py::new(py, Cpu::from_owner(owner.clone_ref(py), id)))
            .collect()
    }
}

#[pymethods]
impl Cpus {
    fn __getitem__(&self, py: Python<'_>, index: isize) -> PyResult<Cpu> {
        self.get(py, index)?
            .ok_or_else(|| PyIndexError::new_err(index))
    }

    fn get(&self, py: Python<'_>, index: isize) -> PyResult<Option<Cpu>> {
        let mut ids = self.ids(py)?;
        let Some(index) = sequence_index(index, ids.len()) else {
            return Ok(None);
        };
        let id = ids.swap_remove(index);
        Ok(Some(Cpu::from_owner(self.owner.derive(py), id)))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.ids(py)?.len())
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<CpuIterator> {
        Ok(CpuIterator::new(self.handles(py)?))
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("Cpus(len={})", self.ids(py)?.len()))
    }
}

/// One processor, identified by its backend vCPU id (such as `"p1.1"`).
#[pyclass(module = "ntoseye")]
pub struct Cpu {
    pub owner: Owner,
    pub id: String,
}

impl Cpu {
    /// A handle for vCPU `id` under an already stamped `owner`.
    pub fn from_owner(owner: Owner, id: String) -> Cpu {
        Cpu { owner, id }
    }

    pub fn processor(&self) -> PyResult<u16> {
        processor_index_from_backend_thread_id(&self.id)
            .ok_or_else(|| PyValueError::new_err(format!("invalid vCPU id: {}", self.id)))
    }

    fn context(&self) -> Context {
        Context::vcpu(self.id.clone())
    }

    fn current_info(&self, py: Python<'_>) -> PyResult<VcpuInfo> {
        self.owner.with(py, |session| {
            require_halted(session, "vcpus")?;
            session
                .vcpus()
                .map_err(err)?
                .into_iter()
                .find(|cpu| cpu.id == self.id)
                .ok_or_else(|| PyKeyError::new_err(self.id.clone()))
        })
    }
}

#[pymethods]
impl Cpu {
    /// The backend vCPU id.
    #[getter]
    fn id(&self, py: Python<'_>) -> PyResult<String> {
        self.owner.check(py)?;
        Ok(self.id.clone())
    }

    /// The instruction pointer (needs a halted target).
    #[getter]
    fn rip(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        Ok(self.current_info(py)?.rip)
    }

    /// The symbol at `rip`, if one resolved.
    #[getter]
    fn symbol(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self.current_info(py)?.symbol)
    }

    /// The process whose page tables are loaded on this processor.
    #[getter]
    fn process(&self, py: Python<'_>) -> PyResult<Option<Process>> {
        let context = self.context();
        let info = self.owner.with_in(py, &context, |session| {
            require_halted(session, "cpu.process")?;
            let registers = session.read_registers().map_err(err)?;
            let name = session.target.arch().dtb_register();
            let dtb = session
                .register_map
                .read_u64(name, &registers)
                .map_err(err)?;
            Ok(session
                .target
                .process_for_cr3(dtb & session.target.arch().dtb_page_mask()))
        })?;
        Ok(info.map(|info| Process::from_owner(self.owner.derive(py), info)))
    }

    /// The Windows thread running on this processor.
    #[getter]
    fn thread(&self, py: Python<'_>) -> PyResult<Option<Thread>> {
        let info = self.owner.with(py, |session| {
            Ok(session
                .active_thread_map()
                .into_values()
                .find(|(vcpu, _)| vcpu == &self.id)
                .map(|(_, thread)| thread))
        })?;
        Ok(info.map(|info| Thread::from_owner(self.owner.derive(py), info)))
    }

    /// This processor's live register file (writable while halted).
    #[getter]
    fn registers(&self, py: Python<'_>) -> PyResult<Registers> {
        self.owner.check(py)?;
        Ok(Registers {
            owner: self.owner.derive(py),
            context: self.context(),
            values: None,
        })
    }

    /// Model-specific registers: `cpu.msr[0xC0000082]`, `cpu.msr["IA32_LSTAR"]`.
    #[getter]
    fn msr(&self, py: Python<'_>) -> PyResult<Msrs> {
        self.owner.check(py)?;
        Ok(Msrs {
            owner: self.owner.derive(py),
            vcpu: self.id.clone(),
            processor: self.processor()?,
        })
    }

    /// Decode this processor's KPCR and KPRCB essentials (`!pcr`).
    fn pcr<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor()?;
        let context = self.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.inspect_pcr(processor).map_err(err)
        })?;
        view_record(py, &view::cpu::pcr(&detail))
    }

    /// Decode this processor's `_KPRCB` (`!prcb`).
    fn prcb<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor()?;
        let context = self.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.target.inspect_prcb(processor).map_err(err)
        })?;
        view_record(py, &view::cpu::prcb(&detail))
    }

    /// Read this processor's current IRQL (`!irql`).
    fn irql<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor()?;
        let context = self.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.target.inspect_irql(processor).map_err(err)
        })?;
        view_record(py, &view::cpu::irql(&detail))
    }

    /// Decode one IDT vector, or the bounded full table (`!idt`).
    #[pyo3(signature = (vector=None))]
    fn idt<'py>(&self, py: Python<'py>, vector: Option<u16>) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor()?;
        let context = self.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.inspect_idt(processor, vector).map_err(err)
        })?;
        view_record(py, &view::cpu::idt(&detail))
    }

    /// Decode this processor's GDT (`!gdt`).
    fn gdt<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor()?;
        let context = self.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.inspect_gdt(processor).map_err(err)
        })?;
        view_record(py, &view::cpu::gdt(&detail))
    }

    /// Read processor vendor, family, model, speed, and feature bits (`!cpuinfo`).
    fn info<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor()?;
        let context = self.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.target.inspect_cpuinfo(processor).map_err(err)
        })?;
        view_record(py, &view::cpu::cpuinfo(&detail))
    }

    /// The processor as a plain `dict`, the shape MCP renders.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        view_dict(py, &view::vcpu(&self.current_info(py)?))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other
            .extract::<PyRef<'_, Cpu>>()
            .is_ok_and(|other| self.owner.same_debugger(&other.owner) && self.id == other.id)
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(&self.id)
    }

    fn __repr__(&self) -> String {
        format!("Cpu(id={:?})", self.id)
    }
}

/// Model-specific registers on one processor (`rdmsr`/`wrmsr`, KD only).
#[pyclass(module = "ntoseye")]
pub struct Msrs {
    owner: Owner,
    vcpu: String,
    processor: u16,
}

impl Msrs {
    fn context(&self) -> Context {
        Context::vcpu(self.vcpu.clone())
    }
}

#[pymethods]
impl Msrs {
    fn __getitem__(&self, py: Python<'_>, key: MsrKey) -> PyResult<u64> {
        let context = self.context();
        let processor = self.processor;
        self.owner.with_in(py, &context, move |session| {
            require_halted(session, "msr read")?;
            let msr = key.index()?;
            session.read_msr(processor, msr).map_err(err)
        })
    }

    fn __setitem__(&self, py: Python<'_>, key: MsrKey, value: u64) -> PyResult<()> {
        let context = self.context();
        let processor = self.processor;
        self.owner.with_in(py, &context, move |session| {
            require_halted(session, "msr write")?;
            let msr = key.index()?;
            session.write_msr(processor, msr, value).map_err(err)
        })
    }

    fn __repr__(&self) -> String {
        format!("Msrs(cpu={:?})", self.vcpu)
    }
}

pub fn process_for_thread(session: &Session, thread: &ThreadInfo) -> PyResult<Option<ProcessInfo>> {
    let Some(guest) = session.target.guest.as_ref() else {
        return Ok(None);
    };
    if let Some(eprocess) = thread.eprocess
        && let Ok(process) = guest.process_at(eprocess)
    {
        return Ok(Some(process));
    }
    let Some(pid) = thread.pid else {
        return Ok(None);
    };
    Ok(guest
        .enumerate_processes()
        .map_err(err)?
        .into_iter()
        .find(|process| process.pid == pid))
}

pub fn trap_frame_view(target: &Target, address: Option<VirtAddr>) -> PyResult<view::View> {
    let frame = read_ktrap_frame_at_or_current(target, address).map_err(err)?;
    let symbol = target.closest_symbol_current_context(VirtAddr(frame.instruction_pointer()));
    Ok(view::trap_frame(&frame, symbol))
}

/// A `u8` enum field as its PDB `IntEnum` member (an `int`), or `None`.
fn optional_enum<'py>(
    py: Python<'py>,
    owner: &Owner,
    name: &str,
    value: Option<u8>,
) -> PyResult<Option<Bound<'py, PyInt>>> {
    value
        .map(|value| {
            let member = enum_value(py, owner, &Space::Kernel, name, u64::from(value))?;
            Ok(member.into_bound(py).cast_into::<PyInt>()?)
        })
        .transpose()
}

fn register_map<V: Copy>(values: &HashMap<String, V>) -> IndexMap<String, V> {
    sorted_registers(values).into_iter().collect()
}

fn register_value<V: Copy>(values: &HashMap<String, V>, name: &str) -> Option<V> {
    values
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(*value))
}

fn sorted_registers<V: Copy>(values: &HashMap<String, V>) -> Vec<(String, V)> {
    let mut values: Vec<_> = values
        .iter()
        .map(|(name, value)| (name.clone(), *value))
        .collect();
    values.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    values
}

/// An MSR by number or by `IA32_*` name.
#[derive(FromPyObject)]
pub enum MsrKey {
    Index(u32),
    Name(String),
}

impl MsrKey {
    fn index(self) -> PyResult<u32> {
        match self {
            MsrKey::Index(index) => Ok(index),
            MsrKey::Name(name) => {
                cpu::parse_msr_name(&name).ok_or_else(|| PyKeyError::new_err(name))
            }
        }
    }
}

/// A Python sequence index (negative counts from the end) into `len` items.
fn sequence_index(index: isize, len: usize) -> Option<usize> {
    let index = if index < 0 {
        len.checked_sub(index.unsigned_abs())?
    } else {
        index.unsigned_abs()
    };
    (index < len).then_some(index)
}

#[cfg(test)]
mod tests {
    use super::sequence_index;

    #[test]
    fn sequence_index_counts_negative_indexes_from_the_end() {
        assert_eq!(sequence_index(0, 4), Some(0));
        assert_eq!(sequence_index(3, 4), Some(3));
        assert_eq!(sequence_index(-1, 4), Some(3));
        assert_eq!(sequence_index(-4, 4), Some(0));
        assert_eq!(sequence_index(4, 4), None);
        assert_eq!(sequence_index(-5, 4), None);
        assert_eq!(sequence_index(0, 0), None);
    }
}
