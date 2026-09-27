use pyo3::PyTypeCheck;
use pyo3::prelude::*;

use super::args::{ApcTarget, DeviceArg, FltFilterArg, LoggerArg, ObjectArg};
use super::context::{Context, in_context};
use super::handle::Owner;
use super::module::Device;
use super::process::Process;
use super::record::Record;
use super::thread::{Frame, Thread, process_for_thread, trap_frame_view};
use super::{err, raise, view_record, view_records};
use crate::bugchecks::{bugcheck_from_dump_info, current_bugcheck};
use crate::error::Error;
use crate::expr::NumberRadix;
use crate::session::Session;
use crate::target::irpfind::{IrpCriteria, IrpPool};
use crate::target::mm::{PfnSelector, PoolType, PoolUsageSort};
use crate::target::pci::{PCI_EXTENDED_CONFIG_SIZE, PciQuery, PciRawRange};
use crate::target::sched::{ApcSelector, UniqStackScope};
use crate::target::zombies::ZombieKinds;
use crate::triage_report::TriageReport;
use crate::types::VirtAddr;
use crate::view::hardware;
use crate::view::sched;
use crate::view::{self, View};

/// System-wide reports and decode-by-address helpers (`dbg.inspect`); the
/// results are `Record`s shaped like the MCP JSON output.
#[pyclass(module = "ntoseye")]
pub struct Inspect {
    pub owner: Owner,
}

impl Inspect {
    pub fn new(owner: Owner) -> Inspect {
        Inspect { owner }
    }

    fn record<'py, T: PyTypeCheck>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<View> + Send,
    ) -> PyResult<Bound<'py, T>> {
        let view = self.owner.with_in(py, &Context::default(), build)?;
        view_record(py, &view)
    }

    fn list<'py, T: PyTypeCheck>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<View> + Send,
    ) -> PyResult<Vec<Bound<'py, T>>> {
        let view = self.owner.with_in(py, &Context::default(), build)?;
        view_records(py, &view)
    }
}

#[pymethods]
impl Inspect {
    fn __repr__(&self) -> String {
        "<Inspect namespace>".to_string()
    }

    /// Decode an in-flight `_IRP` and its current I/O stack location (`!irp`).
    fn irp<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Bound<'py, view::object::py::Irp>> {
        self.record(py, |session| {
            let detail = session.target.inspect_irp(VirtAddr(address)).map_err(err)?;
            Ok(view::object::irp(&detail))
        })
    }

    /// Find in-flight IRPs, optionally filtered by process or driver (`irps`).
    #[pyo3(signature = (filter=None))]
    fn irps<'py>(
        &self,
        py: Python<'py>,
        filter: Option<&str>,
    ) -> PyResult<Vec<Bound<'py, view::object::py::InFlightIrp>>> {
        self.list(py, |session| {
            let hits = session.target.discover_irps(filter).map_err(err)?;
            Ok(View::List(hits.iter().map(view::object::irp_hit).collect()))
        })
    }

    /// Find IRPs by scanning pool for `IoAllocateIrp`'s allocations
    /// (`!irpfind`). `pool_type` is `"nonpaged"` or `"paged"`; `restart`
    /// resumes from an address; `criteria` is one of WinDbg's (`"arg"`,
    /// `"device"`, `"fileobject"`, `"mdlprocess"`, `"thread"`, `"userevent"`)
    /// matched against `value`.
    #[pyo3(signature = (pool_type="nonpaged", restart=None, criteria=None, value=0))]
    fn irp_find<'py>(
        &self,
        py: Python<'py>,
        pool_type: &str,
        restart: Option<u64>,
        criteria: Option<&str>,
        value: u64,
    ) -> PyResult<Bound<'py, view::object::py::IrpFindResult>> {
        let pool = match pool_type {
            "nonpaged" => IrpPool::NonPaged,
            "paged" => IrpPool::Paged,
            other => {
                return Err(raise(format!(
                    "unknown pool type '{other}' (nonpaged, paged)"
                )));
            }
        };
        let criteria = criteria
            .map(|name| IrpCriteria::parse(name, value))
            .transpose()
            .map_err(err)?;
        self.record(py, |session| {
            let detail = session
                .target
                .irp_find(pool, restart.map(VirtAddr), criteria)
                .map_err(err)?;
            Ok(view::object::irp_find(&detail))
        })
    }

    /// Decode an ALPC port (`!alpc /p`): its kind, owner, connection, state,
    /// queues, and a connection port's connections. `address` is the port
    /// object's body or header.
    fn alpc_port<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Bound<'py, view::object::py::AlpcPort>> {
        self.record(py, |session| {
            let port = session.target.alpc_port(VirtAddr(address)).map_err(err)?;
            Ok(view::object::alpc_port(&port))
        })
    }

    /// Decode an ALPC message, a `_KALPC_MESSAGE` (`!alpc /m`).
    fn alpc_message<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Bound<'py, view::object::py::AlpcMessage>> {
        self.record(py, |session| {
            let message = session
                .target
                .alpc_message(VirtAddr(address))
                .map_err(err)?;
            Ok(view::object::alpc_message(&message))
        })
    }

    /// The ALPC ports a process holds handles to (`!alpc /lpp`): the
    /// connection ports it owns with their connections, and the client ports
    /// it is connected through. `process` defaults to the current process.
    #[pyo3(signature = (process=None))]
    fn alpc_process_ports<'py>(
        &self,
        py: Python<'py>,
        process: Option<PyRef<'py, Process>>,
    ) -> PyResult<Bound<'py, view::object::py::AlpcProcessPorts>> {
        let process = match process {
            Some(process) => {
                process
                    .owner
                    .require_argument_of(py, &self.owner, "process")?;
                Some(process.info.clone())
            }
            None => None,
        };
        self.record(py, |session| {
            let target = &session.target;
            let process = match process {
                Some(process) => process,
                None => target.selected_process_info().map_err(err)?,
            };
            let ports = target.alpc_process_ports(process).map_err(err)?;
            Ok(view::object::alpc_process_ports(&ports))
        })
    }

    /// Decode `nt!NtGlobalFlag` and the current process's
    /// `_PEB.NtGlobalFlag` by the GFlags names (`!gflag`).
    fn global_flags<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, view::process::py::GlobalFlags>> {
        self.record(py, |session| {
            let detail = session.target.global_flags().map_err(err)?;
            Ok(view::process::global_flags(&detail))
        })
    }

    /// Decode a job object: its accounting, limits, flags, nesting, and the
    /// processes assigned to it (`!job`). `address` is the job, or a process
    /// or thread whose job to decode; `None` is the current process's job.
    #[pyo3(signature = (address=None))]
    fn job<'py>(
        &self,
        py: Python<'py>,
        address: Option<u64>,
    ) -> PyResult<Bound<'py, view::process::py::Job>> {
        self.record(py, |session| {
            let target = &session.target;
            let job = target.job_address(address.map(VirtAddr)).map_err(err)?;
            let detail = target.inspect_job(job).map_err(err)?;
            Ok(view::process::job(&detail))
        })
    }

    /// Exited processes and terminated threads whose objects are still
    /// referenced, found by scanning nonpaged pool (`!zombies`). `flags`: 1
    /// processes, 2 threads, 3 both.
    #[pyo3(signature = (flags=1))]
    fn zombies<'py>(
        &self,
        py: Python<'py>,
        flags: u64,
    ) -> PyResult<Bound<'py, view::process::py::Zombies>> {
        let kinds = ZombieKinds::from_flags(flags).map_err(err)?;
        self.record(py, |session| {
            let detail = session.target.zombies(kinds).map_err(err)?;
            Ok(view::process::zombies(&detail))
        })
    }

    /// Decode an executive object header and resolve its type and name, and
    /// list a directory's entries (`!object`). `object` is the object's
    /// address, or its path in the object namespace (`"\\Driver\\ACPI"`).
    fn object<'py>(
        &self,
        py: Python<'py>,
        object: ObjectArg,
    ) -> PyResult<Bound<'py, view::object::py::ExecutiveObject>> {
        self.record(py, |session| {
            let address = match object {
                ObjectArg::Address(address) => VirtAddr(address),
                ObjectArg::Path(path) => session.target.object_at_path(&path).map_err(err)?,
            };
            let detail = session.target.inspect_object(address).map_err(err)?;
            Ok(view::object::object(&detail))
        })
    }

    /// Decode a `_FILE_OBJECT` (`!fileobj`).
    fn file_object<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Bound<'py, view::object::py::FileObject>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_file_object(VirtAddr(address))
                .map_err(err)?;
            Ok(view::object::file_object(&detail))
        })
    }

    /// Decode an executive resource (`!locks address`).
    fn resource<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Bound<'py, view::object::py::ExecutiveResource>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_resource(VirtAddr(address))
                .map_err(err)?;
            Ok(view::object::resource(&detail))
        })
    }

    /// Enumerate the symbol-backed executive-resource list (`!locks`).
    #[pyo3(signature = (limit=256))]
    fn resources<'py>(
        &self,
        py: Python<'py>,
        limit: usize,
    ) -> PyResult<Bound<'py, view::object::py::ResourceList>> {
        self.record(py, |session| {
            let detail = session.target.enumerate_resources(limit).map_err(err)?;
            Ok(view::object::resource_list(&detail))
        })
    }

    /// Return bounded system and per-process memory-use counters (`!memusage`).
    #[pyo3(signature = (process_limit=64))]
    fn memusage<'py>(&self, py: Python<'py>, process_limit: usize) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .memory_use_summary(process_limit)
                .map_err(err)?;
            Ok(view::mm::memory_usage(&detail))
        })
    }

    /// Enumerate process, thread, and image notification callbacks.
    fn callbacks<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Vec<Bound<'py, view::object::py::NotifyCallback>>> {
        self.list(py, |session| {
            let callbacks = session.target.enumerate_notify_callbacks().map_err(err)?;
            let dtb = session.target.guest().map_err(err)?.ntoskrnl.dtb();
            Ok(View::List(
                callbacks
                    .iter()
                    .map(|callback| {
                        let symbol = session
                            .target
                            .symbols
                            .format_closest_symbol_for_address(dtb, callback.function);
                        view::object::notify_callback(callback, symbol)
                    })
                    .collect(),
            ))
        })
    }

    /// Dump the kernel SSDT and initialized win32k shadow table (`!ssdt`).
    fn ssdt<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, view::object::py::SsdtTable>>> {
        self.list(py, |session| {
            let tables = session.target.dump_ssdt().map_err(err)?;
            Ok(View::List(
                tables.iter().map(view::object::ssdt_table).collect(),
            ))
        })
    }

    /// Report current, next, and idle threads on each processor (`!running`).
    #[pyo3(signature = (include_idle=false, include_stacks=false))]
    fn running<'py>(
        &self,
        py: Python<'py>,
        include_idle: bool,
        include_stacks: bool,
    ) -> PyResult<Bound<'py, sched::py::RunningProcessors>> {
        self.record(py, |session| {
            let detail = session
                .inspect_running(include_idle, include_stacks)
                .map_err(err)?;
            Ok(view::sched::running(&detail))
        })
    }

    /// Read bounded dispatcher-ready queues for every processor or one (`!ready`).
    #[pyo3(signature = (processor=None))]
    fn ready<'py>(
        &self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Bound<'py, sched::py::ReadyQueues>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_ready_queues(processor)
                .map_err(err)?;
            Ok(view::sched::ready_queues(&detail))
        })
    }

    /// Report DPCs queued on each processor (`!dpcs`).
    fn dpcs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, sched::py::DpcQueues>> {
        self.record(py, |session| {
            let detail = session.target.inspect_dpc_queues().map_err(err)?;
            Ok(view::sched::dpc_queues(&detail))
        })
    }

    /// Report which processors own or wait for each numbered queued spinlock
    /// (`!qlocks`).
    fn queued_locks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.queued_locks().map_err(err)?;
            Ok(view::hardware::queued_locks(&detail))
        })
    }

    /// Report interprocessor-interrupt state for every processor or one
    /// (`!ipi`).
    #[pyo3(signature = (processor=None))]
    fn ipi<'py>(&self, py: Python<'py>, processor: Option<u16>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.ipi_state(processor).map_err(err)?;
            Ok(view::hardware::ipi(&detail))
        })
    }

    /// Report the PCI bus hierarchy pci.sys tracks (`!pcitree`).
    fn pci_tree<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, hardware::py::PciTree>> {
        self.record(py, |session| {
            let tree = session.target.pci_tree().map_err(err)?;
            Ok(view::hardware::pci_tree(&tree))
        })
    }

    /// Read and decode PCI configuration space (`!pci`): the functions on
    /// `bus` (through `last_bus`), or one `device` and `function`. Each
    /// function's 4 KiB is read, extended capabilities included; `raw` adds
    /// it as hex. Needs a backend that reaches configuration space (kd/kdnet,
    /// or gdb on QEMU) and a halted target.
    #[pyo3(signature = (bus=0, device=None, function=None, *, last_bus=None, raw=false))]
    fn pci<'py>(
        &self,
        py: Python<'py>,
        bus: u8,
        device: Option<u8>,
        function: Option<u8>,
        last_bus: Option<u8>,
        raw: bool,
    ) -> PyResult<Bound<'py, hardware::py::PciScan>> {
        self.record(py, |session| {
            let query = PciQuery {
                segment: 0,
                first_bus: bus,
                last_bus: last_bus.unwrap_or(bus),
                device,
                function,
                size: PCI_EXTENDED_CONFIG_SIZE,
            };
            let scan = session.scan_pci(&query).map_err(err)?;
            let raw = raw.then_some(PciRawRange {
                start: 0,
                end: PCI_EXTENDED_CONFIG_SIZE,
                dwords: false,
            });
            Ok(view::hardware::pci(&scan, raw))
        })
    }

    /// Report the executive worker queues, their pending work items, and
    /// worker threads (`!exqueue`). `include_stacks` adds each worker's stack;
    /// `queue_types` (`"critical"`, `"delayed"`, `"hypercritical"`) restricts
    /// the listed items to those types' priorities.
    #[pyo3(signature = (include_stacks=false, queue_types=None))]
    fn work_queues<'py>(
        &self,
        py: Python<'py>,
        include_stacks: bool,
        queue_types: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, sched::py::WorkQueues>> {
        let mut flags = if include_stacks { 0x4 } else { 0 };
        for name in queue_types.unwrap_or_default() {
            flags |= match name.as_str() {
                "critical" => 0x10,
                "delayed" => 0x20,
                "hypercritical" => 0x40,
                other => {
                    return Err(raise(format!(
                        "unknown work queue type '{other}' (critical, delayed, hypercritical)"
                    )));
                }
            };
        }
        self.record(py, |session| {
            let detail = session.inspect_work_queues(flags).map_err(err)?;
            Ok(view::sched::work_queues(&detail))
        })
    }

    /// Read bounded kernel timer-table entries and their DPCs (`!timer`).
    fn timers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, sched::py::TimerTable>> {
        self.record(py, |session| {
            let detail = session.target.timer_list().map_err(err)?;
            Ok(view::sched::timer_list(&detail))
        })
    }

    /// Decode a `_KTIMER` and its DPC (`!timer address`).
    fn timer<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Bound<'py, sched::py::KernelTimer>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_timer(VirtAddr(address))
                .map_err(err)?;
            Ok(view::sched::timer(&detail))
        })
    }

    /// Decode kernel and user APC queues for all threads, a process, or a thread (`!apc`).
    #[pyo3(signature = (target=None))]
    fn apcs<'py>(
        &self,
        py: Python<'py>,
        target: Option<ApcTarget<'_>>,
    ) -> PyResult<Bound<'py, sched::py::ApcQueues>> {
        let selector = match target {
            None => ApcSelector::All,
            Some(ApcTarget::Process(process)) => {
                process
                    .owner
                    .require_argument_of(py, &self.owner, "process")?;
                ApcSelector::Process(process.info.pid)
            }
            Some(ApcTarget::Thread(thread)) => {
                thread
                    .owner
                    .require_argument_of(py, &self.owner, "thread")?;
                ApcSelector::Thread(thread.info.ethread)
            }
            Some(ApcTarget::Ethread(address)) => ApcSelector::Thread(VirtAddr(address)),
        };
        self.record(py, |session| {
            let detail = session.inspect_apcs(selector).map_err(err)?;
            Ok(view::sched::apcs(&detail))
        })
    }

    /// Report thread states, wait reasons, and bounded stacks (`!stacks`).
    #[pyo3(signature = (level=0, filter=None))]
    fn stacks<'py>(
        &self,
        py: Python<'py>,
        level: u8,
        filter: Option<&str>,
    ) -> PyResult<Bound<'py, sched::py::ThreadStacks>> {
        self.record(py, |session| {
            let detail = session.inspect_stacks(level, filter).map_err(err)?;
            Ok(view::sched::stacks(&detail))
        })
    }

    /// List the threads whose stack has a frame matching a symbol or module
    /// (`!findstack`): `module!prefix`, a bare module or function prefix, or
    /// globs with `*`/`?`. `level` 0 counts the matching frames, 1 lists
    /// them, 2 adds the whole stack.
    #[pyo3(signature = (symbol, level=1))]
    fn findstack<'py>(
        &self,
        py: Python<'py>,
        symbol: &str,
        level: u8,
    ) -> PyResult<Bound<'py, sched::py::FindStack>> {
        self.record(py, |session| {
            let detail = session.inspect_findstack(symbol, level).map_err(err)?;
            Ok(view::sched::findstack(&detail))
        })
    }

    /// Group threads by identical call stacks, one process's or, by
    /// default, every thread's (`!uniqstack`).
    #[pyo3(signature = (process=None))]
    fn uniqstack<'py>(
        &self,
        py: Python<'py>,
        process: Option<PyRef<'_, Process>>,
    ) -> PyResult<Bound<'py, sched::py::UniqStacks>> {
        let scope = match process {
            None => UniqStackScope::AllThreads,
            Some(process) => {
                process
                    .owner
                    .require_argument_of(py, &self.owner, "process")?;
                UniqStackScope::Process {
                    pid: process.info.pid,
                    name: process.info.name.clone(),
                }
            }
        };
        self.record(py, |session| {
            let detail = session.inspect_uniqstack(scope).map_err(err)?;
            Ok(view::sched::uniqstack(&detail))
        })
    }

    /// Decode a process PEB and its parameters and loader-list heads (`!peb`).
    #[pyo3(signature = (process, address=None))]
    fn peb<'py>(
        &self,
        py: Python<'py>,
        process: PyRef<'_, Process>,
        address: Option<u64>,
    ) -> PyResult<Bound<'py, view::usermode::py::Peb>> {
        process
            .owner
            .require_argument_of(py, &self.owner, "process")?;
        let context = Context::process(process.info.clone());
        let detail = self.owner.with_in(py, &context, |session| {
            session
                .target
                .inspect_peb(address.map(VirtAddr))
                .map(|detail| view::usermode::peb(&detail))
                .map_err(err)
        })?;
        view_record(py, &detail)
    }

    /// Decode a thread TEB and its WOW64 companion (`!teb`).
    #[pyo3(signature = (thread, address=None))]
    fn teb<'py>(
        &self,
        py: Python<'py>,
        thread: PyRef<'_, Thread>,
        address: Option<u64>,
    ) -> PyResult<Bound<'py, view::usermode::py::Teb>> {
        thread
            .owner
            .require_argument_of(py, &self.owner, "thread")?;
        let info = thread.info.clone();
        let detail = self.owner.with(py, |session| {
            let process = process_for_thread(session, &info)?
                .ok_or_else(|| raise("thread has no associated process"))?;
            let context = Context {
                process: Some(process),
                thread: Some(info.clone()),
                ..Context::default()
            };
            in_context(session, &context, |session| {
                session
                    .target
                    .inspect_teb(address.map(VirtAddr))
                    .map(|detail| view::usermode::teb(&detail))
                    .map_err(err)
            })
        })?;
        view_record(py, &detail)
    }

    /// Decode a `_KTRAP_FRAME` at `address` (`.trap`).
    fn trap_frame<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            trap_frame_view(&session.target, Some(VirtAddr(address)))
        })
    }

    /// Return a handle for the `_DEVICE_OBJECT` at `address` (`!devobj`).
    fn device(&self, py: Python<'_>, address: u64) -> PyResult<Device> {
        let owner = self.owner.derive(py);
        Ok(Device::new(owner, address))
    }

    /// Decode the device stack containing a device object or devnode (`!devstack`).
    fn device_stack<'py>(
        &self,
        py: Python<'py>,
        device_or_node: DeviceArg<'_>,
    ) -> PyResult<Bound<'py, Record>> {
        let address = match device_or_node {
            DeviceArg::Device(device) => {
                device
                    .owner
                    .require_argument_of(py, &self.owner, "device")?;
                device.address
            }
            DeviceArg::Address(address) => address,
        };
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_device_stack(VirtAddr(address))
                .map_err(err)?;
            Ok(view::pnp::device_stack(&detail))
        })
    }

    /// Decode a CONTEXT record and return its register set as a `Frame` (`.cxr`).
    fn context_record(&self, py: Python<'_>, address: u64) -> PyResult<Frame> {
        let registers = self.owner.with_in(py, &Context::default(), |session| {
            session.read_context_record(VirtAddr(address)).map_err(err)
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
        Frame::new(
            py,
            self.owner.derive(py),
            None,
            0,
            ip,
            sp,
            None,
            None,
            registers,
        )
    }

    /// Decode an `EXCEPTION_RECORD64` (`.exr`).
    fn exception_record<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let record = session
                .read_exception_record(VirtAddr(address))
                .map_err(err)?;
            Ok(view::bugcheck::exception_record(Some(address), &record))
        })
    }

    /// Decode a section's `_CONTROL_AREA`, its segment, and its subsections
    /// (`!ca`).
    fn control_area<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_control_area(VirtAddr(address))
                .map_err(err)?;
            Ok(view::fs::control_area(&detail))
        })
    }

    /// Decode a volume parameter block (`!vpb`).
    fn vpb<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.inspect_vpb(VirtAddr(address)).map_err(err)?;
            Ok(view::fs::vpb(&detail))
        })
    }

    /// The cache manager's mapped views per file, from its VACB arrays
    /// (`!filecache`).
    fn file_cache<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.file_cache().map_err(err)?;
            Ok(view::fs::file_cache(&detail))
        })
    }

    /// The registered minifilters of each filter manager frame, with their
    /// instances (`!fltkd.filters`).
    fn flt_filters<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.flt_filters().map_err(err)?;
            Ok(view::fs::flt_filters(&detail))
        })
    }

    /// Minifilter instances with their filter and volume, all or those of
    /// one filter named by name or `_FLT_FILTER` address
    /// (`!fltkd.instances`).
    #[pyo3(signature = (filter=None))]
    fn flt_instances<'py>(
        &self,
        py: Python<'py>,
        filter: Option<FltFilterArg>,
    ) -> PyResult<Bound<'py, Record>> {
        let (text, address) = match filter {
            Some(FltFilterArg::Address(address)) => (Some(format!("{address:#x}")), Some(address)),
            Some(FltFilterArg::Name(name)) => (Some(name), None),
            None => (None, None),
        };
        self.record(py, |session| {
            let detail = session
                .target
                .flt_instances(text.as_deref(), |_| {
                    address
                        .map(VirtAddr)
                        .ok_or_else(|| Error::InvalidArgument("not a filter address".into()))
                })
                .map_err(err)?;
            Ok(view::fs::flt_instances(&detail))
        })
    }

    /// The volumes of each filter manager frame, with the instances on them
    /// (`!fltkd.volumes`).
    fn flt_volumes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.flt_volumes().map_err(err)?;
            Ok(view::fs::flt_volumes(&detail))
        })
    }

    /// Report system memory, pool, PTE, and page-file counters (`!vm`).
    #[pyo3(signature = (include_processes=true))]
    fn vm<'py>(&self, py: Python<'py>, include_processes: bool) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.inspect_vm(include_processes).map_err(err)?;
            Ok(view::mm::vm(&detail))
        })
    }

    /// Decode an `_MMPFN` by page-frame number or physical address (`!pfn`).
    #[pyo3(signature = (value, physical_address=false))]
    fn pfn<'py>(
        &self,
        py: Python<'py>,
        value: u64,
        physical_address: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let selector = if physical_address {
            PfnSelector::PhysicalAddress(value)
        } else {
            PfnSelector::Pfn(value)
        };
        self.record(py, |session| {
            let detail = session.target.inspect_pfn(selector).map_err(err)?;
            Ok(view::mm::pfn(&detail))
        })
    }

    /// Decode the pool page or big-pool allocation containing `address` (`!pool`).
    fn pool<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_pool(VirtAddr(address))
                .map_err(err)?;
            Ok(view::mm::pool_page(&detail))
        })
    }

    /// Check the block headers of the pool page containing `address` and
    /// report the first inconsistency (`!poolval`).
    fn pool_validate<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .validate_pool(VirtAddr(address))
                .map_err(err)?;
            Ok(view::mm::pool_validation(&detail))
        })
    }

    /// Aggregate pool tracker usage by tag (`!poolused`).
    #[pyo3(signature = (tag=None, *, sort="tag", include_counts=false))]
    fn pool_usage<'py>(
        &self,
        py: Python<'py>,
        tag: Option<&str>,
        sort: &str,
        include_counts: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let sort = match sort {
            "tag" => PoolUsageSort::Tag,
            "nonpaged" => PoolUsageSort::NonPagedBytes,
            "paged" => PoolUsageSort::PagedBytes,
            other => {
                return Err(raise(format!(
                    "unknown pool_usage sort '{other}' (tag, nonpaged, paged)"
                )));
            }
        };
        self.record(py, |session| {
            let detail = session
                .target
                .pool_usage(sort, tag, include_counts)
                .map_err(err)?;
            Ok(view::mm::pool_usage(&detail))
        })
    }

    /// Find pool allocations by tag, optionally restricted to a pool type (`!poolfind`).
    #[pyo3(signature = (tag, pool_type=None))]
    fn pool_find<'py>(
        &self,
        py: Python<'py>,
        tag: &str,
        pool_type: Option<&str>,
    ) -> PyResult<Bound<'py, Record>> {
        let pool_type = match pool_type {
            None => None,
            Some("nonpaged") => Some(PoolType::NonPaged),
            Some("paged") => Some(PoolType::Paged),
            Some(other) => {
                return Err(raise(format!(
                    "unknown pool type '{other}' (nonpaged, paged)"
                )));
            }
        };
        self.record(py, |session| {
            let detail = session.target.pool_find(tag, pool_type).map_err(err)?;
            Ok(view::mm::pool_find(&detail))
        })
    }

    /// List exported nonpaged and paged `GENERAL_LOOKASIDE` lists (`!lookaside`).
    fn lookasides<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.lookaside_lists().map_err(err)?;
            Ok(view::mm::lookaside_lists(&detail))
        })
    }

    /// Decode one `GENERAL_LOOKASIDE` (`!lookaside address`).
    fn lookaside<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_lookaside(VirtAddr(address))
                .map_err(err)?;
            Ok(view::mm::lookaside(&detail))
        })
    }

    /// Decode an `_MDL` and the page frames after its header (`!mdl`).
    /// `pfn_count` overrides the count `ByteCount` spans from `ByteOffset`.
    #[pyo3(signature = (address, pfn_count=None))]
    fn mdl<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        pfn_count: Option<u64>,
    ) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_mdl(VirtAddr(address), pfn_count)
                .map_err(err)?;
            Ok(view::mm::mdl(&detail))
        })
    }

    /// Report system PTE usage from each `_MI_SYSTEM_PTE_TYPE` bitmap
    /// allocator (`!sysptes`); `free_runs` lists each allocator's free blocks.
    #[pyo3(signature = (free_runs=false))]
    fn system_ptes<'py>(&self, py: Python<'py>, free_runs: bool) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .system_ptes(u64::from(free_runs))
                .map_err(err)?;
            Ok(view::mm::system_ptes(&detail))
        })
    }

    /// Decode a security descriptor, including owner/group SIDs and ACLs (`!sd`).
    #[pyo3(signature = (address, annotate_well_known=false))]
    fn security_descriptor<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        annotate_well_known: bool,
    ) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_security_descriptor(VirtAddr(address), annotate_well_known)
                .map_err(err)?;
            Ok(view::security::security_descriptor(&detail))
        })
    }

    /// Decode an ACL and its ACEs (`!acl`).
    fn acl<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.inspect_acl(VirtAddr(address)).map_err(err)?;
            Ok(view::security::acl(&detail))
        })
    }

    /// Decode a SID to its string form, authority, and well-known name (`!sid`).
    fn sid<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.inspect_sid(VirtAddr(address)).map_err(err)?;
            Ok(view::security::sid(&detail))
        })
    }

    /// Decode the security descriptor referenced by an object's header (`!objsd`).
    fn object_security<'py>(&self, py: Python<'py>, object: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_object_security(VirtAddr(object))
                .map_err(err)?;
            Ok(view::security::object_security(&detail))
        })
    }

    /// List sessions and their processes, optionally selecting one (`!session`).
    #[pyo3(signature = (session=None))]
    fn sessions<'py>(&self, py: Python<'py>, session: Option<i64>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session_state| {
            let detail = session_state.target.sessions(session).map_err(err)?;
            Ok(view::security::sessions(&detail))
        })
    }

    /// List the active ETW trace sessions (`!wmitrace.strdump`).
    fn etw_loggers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let table = session.target.etw_loggers().map_err(err)?;
            Ok(view::etw::logger_table(&table))
        })
    }

    /// Decode one ETW trace session's `_WMI_LOGGER_CONTEXT`
    /// (`!wmitrace.logger`). `logger` is its logger id or context address,
    /// or its session name.
    fn etw_logger<'py>(&self, py: Python<'py>, logger: LoggerArg) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .etw_logger(&logger.text(), NumberRadix::Hexadecimal)
                .map_err(err)?;
            Ok(view::etw::logger(&detail))
        })
    }

    /// List the trace buffers on an ETW trace session's GlobalList
    /// (`!wmitrace.strdump logger`).
    fn etw_buffers<'py>(&self, py: Python<'py>, logger: LoggerArg) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .etw_logger_buffers(&logger.text(), NumberRadix::Hexadecimal)
                .map_err(err)?;
            Ok(view::etw::logger_buffers(&detail))
        })
    }

    /// Decode the events still in an ETW trace session's buffers, oldest
    /// first (`!wmitrace.logdump`); `count` keeps only the most recent.
    #[pyo3(signature = (logger, count=None))]
    fn etw_events<'py>(
        &self,
        py: Python<'py>,
        logger: LoggerArg,
        count: Option<usize>,
    ) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let dump = session
                .target
                .etw_log_dump(&logger.text(), NumberRadix::Hexadecimal, count)
                .map_err(err)?;
            Ok(view::etw::event_dump(&dump))
        })
    }

    /// Decode a PnP device node and optionally its bounded subtree (`!devnode`).
    #[pyo3(signature = (node=None, recurse=false))]
    fn devnode<'py>(
        &self,
        py: Python<'py>,
        node: Option<u64>,
        recurse: bool,
    ) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_devnode(node.map(VirtAddr), recurse)
                .map_err(err)?;
            Ok(view::pnp::devnode(&detail))
        })
    }

    /// Report device nodes with PnP problems (`!pnptriage`).
    fn pnp_triage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.pnp_triage().map_err(err)?;
            Ok(view::pnp::pnp_triage(&detail))
        })
    }

    /// Report Driver Verifier configuration and statistics (`!verifier`).
    fn verifier<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.verifier_status().map_err(err)?;
            Ok(view::meta::verifier(&detail))
        })
    }

    /// Target, kernel, symbol, processor, and debugger version information (`vertarget`).
    fn version<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target_version().map_err(err)?;
            Ok(view::meta::target_version(&detail))
        })
    }

    /// Report target system time and uptime (`.time`).
    fn time<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.target_time().map_err(err)?;
            Ok(view::meta::target_time(&detail))
        })
    }

    /// Analyze the current bugcheck, or return `None` when the target is not bugchecking.
    fn bugcheck<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        let detail = self.owner.with_in(py, &Context::default(), |session| {
            Ok(current_bugcheck(&session.target)
                .or_else(|| bugcheck_from_dump_info(&session.target))
                .map(|analysis| view::bugcheck::bugcheck(&analysis)))
        })?;
        detail
            .as_ref()
            .map(|view| view_record(py, view))
            .transpose()
    }

    /// Build the structured one-shot crash/debug report (`!analyze`).
    fn triage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let report = TriageReport::build(session);
            Ok(view::triage::triage_report(&report, usize::MAX))
        })
    }
}
