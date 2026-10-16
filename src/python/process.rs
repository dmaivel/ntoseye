//! Processes (`dbg.processes`) and the views bound to one process's address
//! space: memory, symbols, types, modules, threads, regions, and heaps.

use ntoseye_macros::{collection, handle};
use pyo3::prelude::*;

use super::command::{Bind, CommandHost, HostSession};
use super::context::{Context, Space};
use super::err;
use super::handle::Owner;
use super::memory::Memory;
use super::module::Modules;
use super::record::Typed;
use super::symbols::{self, Symbols};
use super::thread::Threads;
use super::types::{Struct, Types};
use crate::guest::ProcessInfo;
use crate::session::Session;
use crate::target::heap::{HeapInfo, HeapSelector};
use crate::target::mm::MemoryRegionInfo;
use crate::types::VirtAddr;

/// The running processes, with their PIDs as keys (`dbg.processes`). Each
/// iteration reads the process list again, and `find(name)` matches image
/// names. A `ProcessInfo` record (`stop.process`) is a key too: it names the
/// listed process it describes.
#[pyclass(module = "ntoseye")]
pub struct Processes {
    pub owner: Owner,
}

impl Processes {
    pub fn new(owner: Owner) -> Processes {
        Processes { owner }
    }
}

#[collection(records)]
impl Processes {
    fn enumerate(&self, py: Python<'_>) -> PyResult<Vec<Process>> {
        let infos = self.owner.with(py, |session| {
            session.target.matching_processes(None).map_err(err)
        })?;
        let owner = self.owner.derive(py);
        Ok(infos
            .into_iter()
            .map(|info| Process::from_owner(owner.clone_ref(py), info))
            .collect())
    }

    /// The process with a PID, or the process a `ProcessInfo` record
    /// describes (`dbg.processes[stop.process]`).
    fn lookup(&self, py: Python<'_>, pid: &u64) -> PyResult<Option<Process>> {
        Ok(self
            .enumerate(py)?
            .into_iter()
            .find(|process| process.info.pid == *pid))
    }

    /// The processes whose image name is an exact match, ignoring case.
    #[collection(find)]
    fn named(process: &Process, name: &str) -> bool {
        process.info.name.eq_ignore_ascii_case(name)
    }
}

/// One process, with identity fields and views bound to its address space.
#[handle(record = ProcessInfo, key = eprocess, context = self.context(), impl)]
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

#[handle]
impl Process {
    /// The parent process identifier.
    #[getter]
    fn ppid(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.details(py)?.ppid)
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

    fn __repr__(&self) -> String {
        format!(
            "Process(pid={}, name={:?}, eprocess={:#x})",
            self.info.pid, self.info.name, self.info.eprocess.0
        )
    }
}

/// The VAD regions of a process (`!vad`), keyed by an address they hold.
#[pyclass(module = "ntoseye")]
pub struct Regions {
    pub owner: Owner,
    pub info: ProcessInfo,
}

impl Regions {
    fn regions(&self, py: Python<'_>) -> PyResult<Vec<MemoryRegionInfo>> {
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

#[collection]
impl Regions {
    fn enumerate<'py>(&self, py: Python<'py>) -> PyResult<Vec<Typed<'py, MemoryRegionInfo>>> {
        self.regions(py)?
            .into_iter()
            .map(|region| Typed::new(py, region))
            .collect()
    }

    /// The VAD region that contains `address`.
    fn lookup<'py>(
        &self,
        py: Python<'py>,
        address: &u64,
    ) -> PyResult<Option<Typed<'py, MemoryRegionInfo>>> {
        self.regions(py)?
            .into_iter()
            .find(|region| *address >= region.start.0 && *address < region.end.0)
            .map(|region| Typed::new(py, region))
            .transpose()
    }
}

/// The PEB heap list of a process.
#[pyclass(module = "ntoseye")]
pub struct Heaps {
    pub owner: Owner,
    pub info: ProcessInfo,
}

/// A process's heap list: its calls run in the process, with its module
/// symbols loaded (the heap decoders read ntdll's).
impl CommandHost for Heaps {
    fn session(&self) -> HostSession<'_> {
        HostSession::Owner(&self.owner)
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Context::process(self.info.clone()))
    }

    fn prepare(&self, session: &mut Session) -> PyResult<()> {
        symbols::load_scope_symbols(session, &Space::Process(self.info.clone()))
    }
}

#[collection(sequence)]
impl Heaps {
    fn enumerate(&self, py: Python<'_>) -> PyResult<Vec<Heap>> {
        let process = self.info.clone();
        let summary = self
            .owner
            .with_in(py, &Context::process(process.clone()), |session| {
                symbols::load_scope_symbols(session, &Space::Process(process.clone()))?;
                session.target.heap_summary().map_err(err)
            })?;
        let owner = self.owner.derive(py);
        Ok(summary
            .heaps
            .into_iter()
            .map(|info| Heap {
                owner: owner.clone_ref(py),
                process: self.info.clone(),
                info,
            })
            .collect())
    }
}

/// One heap of a process, from its PEB heap list.
#[handle(
    record = HeapInfo,
    key = address,
    identity = Heap::identity,
    context = Context::process(self.process.clone()),
    prepare = symbols::load_scope_symbols(session, &Space::Process(self.process.clone())),
    impl
)]
pub struct Heap {
    pub owner: Owner,
    /// The process whose heap it is.
    pub process: ProcessInfo,
    pub info: HeapInfo,
}

impl Heap {
    fn identity(&self) -> (VirtAddr, VirtAddr) {
        (self.process.eprocess, self.info.address)
    }
}

/// A heap is the heap at its address.
impl Bind<HeapSelector> for Heap {
    fn bind(&self) -> HeapSelector {
        HeapSelector::Address(self.info.address)
    }
}

#[handle]
impl Heap {
    fn __repr__(&self) -> String {
        format!(
            "Heap(index={}, address={:#x})",
            self.info.index, self.info.address.0
        )
    }
}
