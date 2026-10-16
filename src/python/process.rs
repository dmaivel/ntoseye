//! Processes (`dbg.processes`) and the views bound to one process's address
//! space: memory, symbols, types, modules, threads, regions, and heaps.

use pyo3::exceptions::PyKeyError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

use super::context::{Context, Space};
use super::handle::Owner;
use super::iter::{HeapIterator, MemoryRegionIterator, ProcessIterator};
use super::memory::Memory;
use super::module::Modules;
use super::record::PlainDict;
use super::symbols::{self, Symbols};
use super::thread::Threads;
use super::types::{Struct, Types};
use super::{err, plain_dict};
use crate::guest::{ProcessInfo, ProcessInfoPy};
use crate::target::mm::{MemoryRegionInfo, MemoryRegionInfoPy};
use crate::types::VirtAddr;

/// The running processes, with their PIDs as keys (`dbg.processes`). Each
/// iteration reads the process list again, and `find(name)` matches image
/// names. A `ProcessInfo` record (`stop.process`) is a key too: it gives the
/// handle of the process it describes, listed or not (the idle process is
/// not).
#[pyclass(module = "ntoseye")]
pub struct Processes {
    pub owner: Owner,
}

/// A key of `dbg.processes`: a PID, or a `ProcessInfo` record, which holds
/// all a handle needs.
#[derive(FromPyObject)]
pub enum ProcessKey<'py> {
    Pid(u64),
    Info(Bound<'py, ProcessInfoPy>),
}

/// A [`ProcessKey`] read out of Python.
enum ProcessMatch {
    Pid(u64),
    Info(ProcessInfo),
}

impl ProcessKey<'_> {
    fn resolve(&self) -> PyResult<ProcessMatch> {
        let record = match self {
            ProcessKey::Pid(pid) => return Ok(ProcessMatch::Pid(*pid)),
            ProcessKey::Info(record) => record,
        };
        let field = |name: &str| record.getattr(name);
        Ok(ProcessMatch::Info(ProcessInfo {
            pid: field("pid")?.extract()?,
            name: field("name")?.extract()?,
            dtb: field("dtb")?.extract()?,
            eprocess: VirtAddr(field("eprocess")?.extract()?),
            wow64_peb: field("wow64_peb")?.extract::<Option<u64>>()?.map(VirtAddr),
        }))
    }
}

impl Processes {
    pub fn new(owner: Owner) -> Processes {
        Processes { owner }
    }

    /// The process `wanted` names: a listed one by PID, or the one a record
    /// describes.
    fn lookup(&self, py: Python<'_>, wanted: ProcessMatch) -> PyResult<Option<Process>> {
        match wanted {
            ProcessMatch::Pid(pid) => Ok(self
                .snapshot(py)?
                .into_iter()
                .find(|process| process.info.pid == pid)),
            ProcessMatch::Info(info) => {
                self.owner.check(py)?;
                Ok(Some(Process::from_owner(self.owner.derive(py), info)))
            }
        }
    }

    fn snapshot(&self, py: Python<'_>) -> PyResult<Vec<Process>> {
        let infos = self.owner.with(py, |session| {
            session.target.matching_processes(None).map_err(err)
        })?;
        let owner = self.owner.derive(py);
        Ok(infos
            .into_iter()
            .map(|info| Process::from_owner(owner.clone_ref(py), info))
            .collect())
    }
}

/// One process, with identity fields and views bound to its address space.
#[pyclass(module = "ntoseye")]
pub struct Process {
    pub owner: Owner,
    pub info: ProcessInfo,
}

impl Process {
    /// A handle for `info` under an already stamped `owner`.
    pub fn from_owner(owner: Owner, info: ProcessInfo) -> Process {
        Process { owner, info }
    }

    fn context(&self) -> Context {
        Context::process(self.info.clone())
    }

    fn space(&self) -> Space {
        Space::Process(self.info.clone())
    }

    fn details(&self, py: Python<'_>) -> PyResult<ProcessDetails> {
        let info = self.info.clone();
        self.owner.with_in(py, &self.context(), |session| {
            let eprocess = session
                .target
                .guest()
                .map_err(err)?
                .ntoskrnl
                .types_in(info.dtb)
                .struct_at("_EPROCESS", info.eprocess)
                .map_err(err)?;
            let ppid = session.target.process_parent_pid(&info).map_err(err)?;
            let peb = eprocess.read_field::<VirtAddr>("Peb").map_err(err)?;
            Ok(ProcessDetails {
                ppid,
                session: session.target.process_session_id(info.eprocess),
                peb: (!peb.is_zero()).then_some(peb.0),
            })
        })
    }
}

struct ProcessDetails {
    ppid: u64,
    session: Option<u32>,
    peb: Option<u64>,
}

#[pymethods]
impl Processes {
    /// Find a process by PID, or `None` if no listed process has it. A
    /// `ProcessInfo` record (`stop.process`) gives the process it describes.
    fn get(&self, py: Python<'_>, key: ProcessKey<'_>) -> PyResult<Option<Process>> {
        self.lookup(py, key.resolve()?)
    }

    /// Find all processes whose image name is an exact match, ignoring case.
    fn find(&self, py: Python<'_>, name: &str) -> PyResult<Vec<Process>> {
        Ok(self
            .snapshot(py)?
            .into_iter()
            .filter(|process| process.info.name.eq_ignore_ascii_case(name))
            .collect())
    }

    /// Get a process by PID, or raise `KeyError` if no listed process has
    /// it. A `ProcessInfo` record (`dbg.processes[stop.process]`) gives the
    /// process it describes.
    fn __getitem__(&self, py: Python<'_>, key: ProcessKey<'_>) -> PyResult<Process> {
        let wanted = key.resolve()?;
        let missing = match &wanted {
            ProcessMatch::Pid(pid) => pid.to_string(),
            ProcessMatch::Info(info) => info.pid.to_string(),
        };
        self.lookup(py, wanted)?
            .ok_or_else(|| PyKeyError::new_err(missing))
    }

    /// Whether a process with the PID is listed; for a `ProcessInfo` record,
    /// whether its process (PID and `_EPROCESS`) is.
    fn __contains__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(key) = key.extract::<ProcessKey<'_>>() else {
            return Ok(false);
        };
        let listed = self.snapshot(py)?;
        Ok(match key.resolve()? {
            ProcessMatch::Pid(pid) => listed.iter().any(|process| process.info.pid == pid),
            ProcessMatch::Info(info) => listed.iter().any(|process| {
                process.info.pid == info.pid && process.info.eprocess == info.eprocess
            }),
        })
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<ProcessIterator> {
        Ok(ProcessIterator::new(self.snapshot(py)?))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.snapshot(py)?.len())
    }
}

#[pymethods]
impl Process {
    /// The process identifier.
    #[getter]
    fn pid(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.pid)
    }

    /// The parent process identifier.
    #[getter]
    fn ppid(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.details(py)?.ppid)
    }

    /// The image name.
    #[getter]
    fn name(&self, py: Python<'_>) -> PyResult<String> {
        self.owner.check(py)?;
        Ok(self.info.name.clone())
    }

    /// The `_EPROCESS` virtual address.
    #[getter]
    fn eprocess(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.eprocess.0)
    }

    /// The process page-table root.
    #[getter]
    fn dtb(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.dtb)
    }

    /// The process `_PEB` cursor, or `None` if the process has no PEB.
    #[getter]
    fn peb(&self, py: Python<'_>) -> PyResult<Option<Struct>> {
        let Some(address) = self.details(py)?.peb else {
            return Ok(None);
        };
        Struct::new(py, &self.owner, self.space(), "_PEB", address).map(Some)
    }

    /// The Windows session identifier.
    #[getter]
    fn session(&self, py: Python<'_>) -> PyResult<Option<u32>> {
        Ok(self.details(py)?.session)
    }

    /// True if this process has a WOW64 (32-bit) PEB.
    #[getter]
    fn wow64(&self, py: Python<'_>) -> PyResult<bool> {
        self.owner.check(py)?;
        Ok(self.info.is_wow64())
    }

    /// The process `_EPROCESS` cursor.
    #[getter]
    fn object(&self, py: Python<'_>) -> PyResult<Struct> {
        self.owner.check(py)?;
        Struct::new(
            py,
            &self.owner,
            self.space(),
            "_EPROCESS",
            self.info.eprocess.0,
        )
    }

    /// The virtual memory, through the page tables of this process.
    #[getter]
    fn memory(&self, py: Python<'_>) -> PyResult<Memory> {
        self.owner.check(py)?;
        Ok(Memory::new(self.owner.clone_ref(py), self.space()))
    }

    /// The symbols, resolved in the address space of this process.
    #[getter]
    fn symbols(&self, py: Python<'_>) -> PyResult<Symbols> {
        self.owner.check(py)?;
        Ok(Symbols::new(self.owner.clone_ref(py), self.space()))
    }

    /// The PDB types and cursors, bound to the address space of this process.
    #[getter]
    fn types(&self, py: Python<'_>) -> PyResult<Types> {
        self.owner.check(py)?;
        Ok(Types::new(self.owner.clone_ref(py), self.space()))
    }

    /// The modules from the PEB loader lists of this process.
    #[getter]
    fn modules(&self, py: Python<'_>) -> PyResult<Modules> {
        self.owner.check(py)?;
        Ok(Modules::process(
            self.owner.clone_ref(py),
            self.info.clone(),
        ))
    }

    /// The Windows threads that this process owns.
    #[getter]
    fn threads(&self, py: Python<'_>) -> PyResult<Threads> {
        self.owner.check(py)?;
        Ok(Threads::of_process(
            self.owner.clone_ref(py),
            self.info.clone(),
        ))
    }

    /// The process VAD regions (`!vad` / `vmmap`).
    #[getter]
    fn regions(&self, py: Python<'_>) -> PyResult<Regions> {
        self.owner.check(py)?;
        Ok(Regions {
            owner: self.owner.clone_ref(py),
            info: self.info.clone(),
        })
    }

    /// The heaps in the PEB of this process.
    #[getter]
    fn heaps(&self, py: Python<'_>) -> PyResult<Heaps> {
        self.owner.check(py)?;
        Ok(Heaps {
            owner: self.owner.clone_ref(py),
            info: self.info.clone(),
        })
    }

    /// Evaluate a debugger expression in the symbol scope of this process.
    fn eval(&self, py: Python<'_>, expr: &str) -> PyResult<u64> {
        symbols::eval(py, &self.owner, &self.space(), expr)
    }

    /// Get the process identity as a plain `dict` (`pid`, `name`, `dtb`,
    /// `eprocess`, `wow64_peb`, `wow64`).
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        plain_dict(py, &self.info)
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Process>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner) && self.info.eprocess == other.info.eprocess
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(self.info.eprocess)
    }

    fn __repr__(&self) -> String {
        format!(
            "Process(pid={}, name={:?}, eprocess={:#x})",
            self.info.pid, self.info.name, self.info.eprocess.0
        )
    }
}

/// The VAD regions of a process (`!vad`).
#[pyclass(module = "ntoseye")]
pub struct Regions {
    pub owner: Owner,
    pub info: ProcessInfo,
}

impl Regions {
    fn snapshot(&self, py: Python<'_>) -> PyResult<Vec<MemoryRegionInfo>> {
        let info = &self.info;
        self.owner
            .with_in(py, &Context::process(info.clone()), |session| {
                session
                    .target
                    .enumerate_vad_regions_for_process_info(info)
                    .map_err(err)
            })
    }
}

#[pymethods]
impl Regions {
    /// Find the VAD region that contains `addr`, or return `None`.
    fn at<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Option<Bound<'py, MemoryRegionInfoPy>>> {
        self.snapshot(py)?
            .iter()
            .find(|region| addr >= region.start.0 && addr < region.end.0)
            .map(|region| region.into_class(py))
            .transpose()
    }

    fn __getitem__<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Bound<'py, MemoryRegionInfoPy>> {
        self.at(py, addr)?
            .ok_or_else(|| PyKeyError::new_err(format!("no VAD region contains {addr:#x}")))
    }

    fn __contains__(&self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        Ok(self.at(py, addr)?.is_some())
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<MemoryRegionIterator> {
        let regions = self
            .snapshot(py)?
            .iter()
            .map(|region| region.into_class(py).map(Bound::unbind))
            .collect::<PyResult<_>>()?;
        Ok(MemoryRegionIterator::new(regions))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.snapshot(py)?.len())
    }
}

/// The PEB heap list of a process.
#[pyclass(module = "ntoseye")]
pub struct Heaps {
    pub owner: Owner,
    pub info: ProcessInfo,
}

impl Heaps {
    fn snapshot(&self, py: Python<'_>) -> PyResult<Vec<HeapHandleInfo>> {
        let ctx = Context::process(self.info.clone());
        let summary = self.owner.with_in(py, &ctx, |session| {
            symbols::load_scope_symbols(session, &Space::Process(self.info.clone()))?;
            session.target.heap_summary().map_err(err)
        })?;
        Ok(summary
            .heaps
            .into_iter()
            .map(|heap| HeapHandleInfo {
                index: heap.index,
                address: heap.address,
            })
            .collect())
    }
}

struct HeapHandleInfo {
    index: usize,
    address: VirtAddr,
}

#[pymethods]
impl Heaps {
    fn get(&self, py: Python<'_>, index: usize) -> PyResult<Option<Heap>> {
        let Some(heap) = self
            .snapshot(py)?
            .into_iter()
            .find(|heap| heap.index == index)
        else {
            return Ok(None);
        };
        Ok(Some(Heap {
            owner: self.owner.derive(py),
            info: self.info.clone(),
            index: heap.index,
            address: heap.address,
        }))
    }

    fn __getitem__(&self, py: Python<'_>, index: usize) -> PyResult<Heap> {
        self.get(py, index)?
            .ok_or_else(|| PyKeyError::new_err(index.to_string()))
    }

    fn __contains__(&self, py: Python<'_>, index: usize) -> PyResult<bool> {
        Ok(self.snapshot(py)?.iter().any(|heap| heap.index == index))
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<HeapIterator> {
        let owner = self.owner.derive(py);
        let heaps = self.snapshot(py)?.into_iter().map(|heap| Heap {
            owner: owner.clone_ref(py),
            info: self.info.clone(),
            index: heap.index,
            address: heap.address,
        });
        Ok(HeapIterator::new(heaps.collect()))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.snapshot(py)?.len())
    }
}

/// One heap of a process, from its PEB heap list.
#[pyclass(module = "ntoseye")]
pub struct Heap {
    pub owner: Owner,
    pub info: ProcessInfo,
    pub index: usize,
    pub address: VirtAddr,
}

#[pymethods]
impl Heap {
    /// The index of the heap in the PEB list.
    #[getter]
    fn index(&self, py: Python<'_>) -> PyResult<usize> {
        self.owner.check(py)?;
        Ok(self.index)
    }

    /// The heap address.
    #[getter]
    fn address(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.address.0)
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        let out = PyDict::new(py);
        out.set_item("index", self.index)?;
        out.set_item("address", self.address.0)?;
        Ok(PlainDict(out))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Heap>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner)
                && self.info.eprocess == other.info.eprocess
                && self.address == other.address
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash((self.info.eprocess, self.address))
    }

    fn __repr__(&self) -> String {
        format!("Heap(index={}, address={:#x})", self.index, self.address.0)
    }
}
