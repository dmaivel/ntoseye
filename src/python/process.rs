//! Processes (`dbg.processes`) and the views bound to one process's address
//! space: memory, symbols, types, modules, threads, regions, and heaps.

use pyo3::exceptions::PyKeyError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

use super::context::{Context, Space};
use super::handle::Owner;
use super::iter::{HeapIterator, MemoryRegionIterator, ProcessIterator};
use super::memory::{Memory, MemoryRegion};
use super::module::Modules;
use super::record::{PlainDict, Record};
use super::symbols::{self, Symbols};
use super::thread::Threads;
use super::types::{Struct, Types};
use super::{err, view_dict, view_record};
use crate::guest::ProcessInfo;
use crate::target::heap::HeapSelector;
use crate::target::mm::MemoryRegionInfo;
use crate::target::sched::ApcSelector;
use crate::types::VirtAddr;
use crate::view;

/// Running processes keyed by PID (`dbg.processes`). Iterating walks the
/// process list afresh; `find(name)` matches image names.
#[pyclass(module = "ntoseye")]
pub struct Processes {
    pub owner: Owner,
}

impl Processes {
    pub fn new(owner: Owner) -> Processes {
        Processes { owner }
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

/// One process: identity fields plus views bound to its address space.
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
                .struct_at("_EPROCESS", info.eprocess_va)
                .map_err(err)?;
            let ppid = eprocess
                .read_field::<u64>("InheritedFromUniqueProcessId")
                .map_err(err)?;
            let peb = eprocess.read_field::<VirtAddr>("Peb").map_err(err)?;
            Ok(ProcessDetails {
                ppid,
                session: session.target.process_session_id(info.eprocess_va),
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
    /// Find a process by PID; a missing PID returns `None`.
    fn get(&self, py: Python<'_>, pid: u64) -> PyResult<Option<Process>> {
        Ok(self
            .snapshot(py)?
            .into_iter()
            .find(|process| process.info.pid == pid))
    }

    /// Find every exact image-name match, case-insensitively.
    fn find(&self, py: Python<'_>, name: &str) -> PyResult<Vec<Process>> {
        Ok(self
            .snapshot(py)?
            .into_iter()
            .filter(|process| process.info.name.eq_ignore_ascii_case(name))
            .collect())
    }

    fn __getitem__(&self, py: Python<'_>, pid: u64) -> PyResult<Process> {
        self.get(py, pid)?
            .ok_or_else(|| PyKeyError::new_err(pid.to_string()))
    }

    fn __contains__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(pid) = key.extract::<u64>() else {
            return Ok(false);
        };
        Ok(self
            .snapshot(py)?
            .iter()
            .any(|process| process.info.pid == pid))
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
        Ok(self.info.eprocess_va.0)
    }

    /// The process page-table root.
    #[getter]
    fn dtb(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.dtb)
    }

    /// The process `_PEB` cursor, or `None` when it has no PEB.
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

    /// Whether this process has a WOW64 (32-bit) PEB.
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
            self.info.eprocess_va.0,
        )
    }

    /// Virtual memory through this process's page tables.
    #[getter]
    fn memory(&self, py: Python<'_>) -> PyResult<Memory> {
        self.owner.check(py)?;
        Ok(Memory::new(self.owner.clone_ref(py), self.space()))
    }

    /// Symbols resolved in this process's address space.
    #[getter]
    fn symbols(&self, py: Python<'_>) -> PyResult<Symbols> {
        self.owner.check(py)?;
        Ok(Symbols::new(self.owner.clone_ref(py), self.space()))
    }

    /// PDB types and cursors bound to this process's address space.
    #[getter]
    fn types(&self, py: Python<'_>) -> PyResult<Types> {
        self.owner.check(py)?;
        Ok(Types::new(self.owner.clone_ref(py), self.space()))
    }

    /// Modules from this process's PEB loader lists.
    #[getter]
    fn modules(&self, py: Python<'_>) -> PyResult<Modules> {
        self.owner.check(py)?;
        Ok(Modules::process(
            self.owner.clone_ref(py),
            self.info.clone(),
        ))
    }

    /// Windows threads owned by this process.
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

    /// The heaps in this process's PEB.
    #[getter]
    fn heaps(&self, py: Python<'_>) -> PyResult<Heaps> {
        self.owner.check(py)?;
        Ok(Heaps {
            owner: self.owner.clone_ref(py),
            info: self.info.clone(),
        })
    }

    /// The process token and its security information.
    fn token<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.owner.with_in(py, &self.context(), |session| {
            session.target.inspect_process_token().map_err(err)
        })?;
        view_record(py, &view::token(&detail))
    }

    /// Decode a handle in this process's handle table.
    fn handle<'py>(&self, py: Python<'py>, value: u64) -> PyResult<Bound<'py, Record>> {
        let detail = self.owner.with_in(py, &self.context(), |session| {
            session.target.inspect_handle(value).map_err(err)
        })?;
        view_record(py, &view::handle_entry(&detail))
    }

    /// Enumerate up to `limit` handles in this process's handle table.
    #[pyo3(signature = (limit=256))]
    fn handles<'py>(&self, py: Python<'py>, limit: usize) -> PyResult<Bound<'py, Record>> {
        let summary = self.owner.with_in(py, &self.context(), |session| {
            session.target.enumerate_handles(limit).map_err(err)
        })?;
        view_record(py, &view::handle_table(&summary))
    }

    /// Decode kernel and user APC queues for this process (`!apc`).
    fn apcs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.owner.with_in(py, &self.context(), |session| {
            session
                .inspect_apcs(ApcSelector::Process(self.info.pid))
                .map_err(err)
        })?;
        view_record(py, &view::sched::apcs(&detail))
    }

    /// Evaluate a debugger expression in this process's symbol scope.
    fn eval(&self, py: Python<'_>, expr: &str) -> PyResult<u64> {
        symbols::eval(py, &self.owner, &self.space(), expr)
    }

    /// The process's identity as a plain `dict` (`pid`, `name`, `dtb`,
    /// `eprocess`, `wow64`), the shape MCP renders.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        view_dict(py, &view::process(&self.info))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Process>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner)
                && self.info.eprocess_va == other.info.eprocess_va
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(self.info.eprocess_va)
    }

    fn __repr__(&self) -> String {
        format!(
            "Process(pid={}, name={:?}, eprocess={:#x})",
            self.info.pid, self.info.name, self.info.eprocess_va.0
        )
    }
}

/// A process's VAD region collection (`!vad`).
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
    /// Find the VAD region containing `addr`, or return `None`.
    fn at(&self, py: Python<'_>, addr: u64) -> PyResult<Option<MemoryRegion>> {
        Ok(self
            .snapshot(py)?
            .into_iter()
            .find(|region| addr >= region.start.0 && addr < region.end.0)
            .map(MemoryRegion::from))
    }

    fn __getitem__(&self, py: Python<'_>, addr: u64) -> PyResult<MemoryRegion> {
        self.at(py, addr)?
            .ok_or_else(|| PyKeyError::new_err(format!("no VAD region contains {addr:#x}")))
    }

    fn __contains__(&self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        Ok(self.at(py, addr)?.is_some())
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<MemoryRegionIterator> {
        let regions = self.snapshot(py)?.into_iter().map(MemoryRegion::from);
        Ok(MemoryRegionIterator::new(regions.collect()))
    }

    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.snapshot(py)?.len())
    }
}

/// A process's PEB heap list.
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
    /// Find the heap block containing `addr` (`!heap -x`).
    fn find_block<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        let ctx = Context::process(self.info.clone());
        let detail = self.owner.with_in(py, &ctx, |session| {
            symbols::load_scope_symbols(session, &Space::Process(self.info.clone()))?;
            session.target.find_heap_block(VirtAddr(addr)).map_err(err)
        })?;
        view_record(py, &view::heap::heap_block_search(&detail))
    }

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
    /// The heap's index in the PEB list.
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

    /// Decode this heap (`!heap -h`); `list_entries` materializes entries.
    #[pyo3(signature = (list_entries=false))]
    fn inspect<'py>(&self, py: Python<'py>, list_entries: bool) -> PyResult<Bound<'py, Record>> {
        let ctx = Context::process(self.info.clone());
        let detail = self.owner.with_in(py, &ctx, |session| {
            symbols::load_scope_symbols(session, &Space::Process(self.info.clone()))?;
            session
                .target
                .inspect_heap(HeapSelector::Address(self.address), list_entries)
                .map_err(err)
        })?;
        view_record(py, &view::heap::heap(&detail))
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
                && self.info.eprocess_va == other.info.eprocess_va
                && self.address == other.address
        })
    }

    fn __hash__(&self) -> isize {
        self.owner
            .identity_hash((self.info.eprocess_va, self.address))
    }

    fn __repr__(&self) -> String {
        format!("Heap(index={}, address={:#x})", self.index, self.address.0)
    }
}
