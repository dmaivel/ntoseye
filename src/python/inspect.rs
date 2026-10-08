use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::args::{ApcTarget, DeviceArg, FltFilterArg, LoggerArg, ObjectArg};
use super::context::{Context, in_context};
use super::handle::Owner;
use super::module::Device;
use super::process::Process;
use super::thread::{Frame, Thread, process_for_thread, trap_frame_view};
use super::{err, raise};
use crate::bugchecks::{bugcheck_from_dump_info, current_bugcheck};
use crate::error::Error;
use crate::expr::NumberRadix;
use crate::session::Session;
use crate::target::etw::parse_guid;
use crate::target::irpfind::{IrpCriteria, IrpPool};
use crate::target::mm::{PfnSelector, PoolType, PoolUsageSort};
use crate::target::pci::{PCI_EXTENDED_CONFIG_SIZE, PciQuery, PciRawRange};
use crate::target::sched::{ApcSelector, UniqStackScope};
use crate::target::zombies::ZombieKinds;
use crate::triage_report::TriageReport;
use crate::types::VirtAddr;
use crate::view::hardware;
use crate::view::mm;
use crate::view::sched;
use crate::view::shape::{Typed, ViewValue};
use crate::view::{self};

/// System-wide reports and helpers that decode an object at an address
/// (`dbg.inspect`). The results are typed `Record`s.
#[pyclass(module = "ntoseye")]
pub struct Inspect {
    pub owner: Owner,
}

impl Inspect {
    pub fn new(owner: Owner) -> Inspect {
        Inspect { owner }
    }

    /// Run `build` in the session and return its result as the SDK does.
    fn typed<'py, T: ViewValue>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<T::Source> + Send,
    ) -> PyResult<Typed<'py, T>>
    where
        T::Source: Send,
    {
        let value = self.owner.with_in(py, &Context::default(), build)?;
        Typed::new(py, value)
    }
}

#[pymethods]
impl Inspect {
    fn __repr__(&self) -> String {
        "<Inspect namespace>".to_string()
    }

    /// Decode an in-flight `_IRP` and its I/O stack locations (`!irp`).
    fn irp<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Typed<'py, view::object::Irp>> {
        self.typed(py, |session| {
            let detail = session.target.inspect_irp(VirtAddr(address)).map_err(err)?;
            Ok(view::object::irp(&detail))
        })
    }

    /// Find in-flight IRPs, with an optional filter by process or driver
    /// (`irps`).
    #[pyo3(signature = (filter=None))]
    fn irps<'py>(
        &self,
        py: Python<'py>,
        filter: Option<&str>,
    ) -> PyResult<Typed<'py, Vec<view::object::InFlightIrp>>> {
        self.typed(py, |session| {
            let hits = session.target.discover_irps(filter).map_err(err)?;
            Ok(hits.iter().map(view::object::irp_hit).collect::<Vec<_>>())
        })
    }

    /// Find IRPs by scanning pool for the allocations of `IoAllocateIrp`
    /// (`!irpfind`). `pool_type` is `"nonpaged"` or `"paged"`, and `restart`
    /// continues the scan from an address. `criteria` is one of the WinDbg
    /// criteria (`"arg"`, `"device"`, `"fileobject"`, `"mdlprocess"`,
    /// `"thread"`, `"userevent"`), which the scan matches against `value`.
    #[pyo3(signature = (pool_type="nonpaged", restart=None, criteria=None, value=0))]
    fn irp_find<'py>(
        &self,
        py: Python<'py>,
        pool_type: &str,
        restart: Option<u64>,
        criteria: Option<&str>,
        value: u64,
    ) -> PyResult<Typed<'py, view::object::IrpFindResult>> {
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
        self.typed(py, |session| {
            let detail = session
                .target
                .irp_find(pool, restart.map(VirtAddr), criteria)
                .map_err(err)?;
            Ok(view::object::irp_find(&detail))
        })
    }

    /// Decode an ALPC port (`!alpc /p`). The result has the port kind, owner,
    /// connection, state, and queues, and for a connection port also its
    /// connections. `address` is the body or the header of the port object.
    fn alpc_port<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, view::object::AlpcPort>> {
        self.typed(py, |session| {
            let port = session.target.alpc_port(VirtAddr(address)).map_err(err)?;
            Ok(view::object::alpc_port(&port))
        })
    }

    /// Decode an ALPC message, a `_KALPC_MESSAGE` (`!alpc /m`).
    fn alpc_message<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, view::object::AlpcMessage>> {
        self.typed(py, |session| {
            let message = session
                .target
                .alpc_message(VirtAddr(address))
                .map_err(err)?;
            Ok(view::object::alpc_message(&message))
        })
    }

    /// Get the ALPC ports to which a process has handles (`!alpc /lpp`). The
    /// result has the connection ports that the process owns, with their
    /// connections, and the client ports through which the process is
    /// connected. `process` defaults to the current process.
    #[pyo3(signature = (process=None))]
    fn alpc_process_ports<'py>(
        &self,
        py: Python<'py>,
        process: Option<PyRef<'py, Process>>,
    ) -> PyResult<Typed<'py, view::object::AlpcProcessPorts>> {
        let process = match process {
            Some(process) => {
                process
                    .owner
                    .require_argument_of(py, &self.owner, "process")?;
                Some(process.info.clone())
            }
            None => None,
        };
        self.typed(py, |session| {
            let target = &session.target;
            let process = match process {
                Some(process) => process,
                None => target.selected_process_info().map_err(err)?,
            };
            let ports = target.alpc_process_ports(process).map_err(err)?;
            Ok(view::object::alpc_process_ports(&ports))
        })
    }

    /// Decode `nt!NtGlobalFlag` and the `_PEB.NtGlobalFlag` of the current
    /// process into GFlags names (`!gflag`).
    fn global_flags<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, view::process::GlobalFlags>> {
        self.typed(py, |session| {
            let detail = session.target.global_flags().map_err(err)?;
            Ok(view::process::global_flags(&detail))
        })
    }

    /// Decode a job object (`!job`). The result has the accounting, limits,
    /// flags, nesting, and the processes that are assigned to the job.
    /// `address` is the job or a process or thread whose job to decode, and
    /// `None` selects the job of the current process.
    #[pyo3(signature = (address=None))]
    fn job<'py>(
        &self,
        py: Python<'py>,
        address: Option<u64>,
    ) -> PyResult<Typed<'py, view::process::Job>> {
        self.typed(py, |session| {
            let target = &session.target;
            let job = target.job_address(address.map(VirtAddr)).map_err(err)?;
            let detail = target.inspect_job(job).map_err(err)?;
            Ok(view::process::job(&detail))
        })
    }

    /// Scan nonpaged pool for exited processes and terminated threads whose
    /// objects still have references (`!zombies`). `flags` is 1 for
    /// processes, 2 for threads, or 3 for both.
    #[pyo3(signature = (flags=1))]
    fn zombies<'py>(
        &self,
        py: Python<'py>,
        flags: u64,
    ) -> PyResult<Typed<'py, view::process::Zombies>> {
        let kinds = ZombieKinds::from_flags(flags).map_err(err)?;
        self.typed(py, |session| {
            let detail = session.target.zombies(kinds).map_err(err)?;
            Ok(view::process::zombies(&detail))
        })
    }

    /// Decode an executive object header and resolve the type and name of the
    /// object, also listing the entries of a directory (`!object`). `object` is
    /// the address of the object, or its path in the object namespace
    /// (`"\\Driver\\ACPI"`).
    fn object<'py>(
        &self,
        py: Python<'py>,
        object: ObjectArg,
    ) -> PyResult<Typed<'py, view::object::ExecutiveObject>> {
        self.typed(py, |session| {
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
    ) -> PyResult<Typed<'py, view::object::FileObject>> {
        self.typed(py, |session| {
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
    ) -> PyResult<Typed<'py, view::object::ExecutiveResource>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_resource(VirtAddr(address))
                .map_err(err)?;
            Ok(view::object::resource(&detail))
        })
    }

    /// List the entries of the symbol-backed executive-resource list
    /// (`!locks`).
    #[pyo3(signature = (limit=256))]
    fn resources<'py>(
        &self,
        py: Python<'py>,
        limit: usize,
    ) -> PyResult<Typed<'py, view::object::ResourceList>> {
        self.typed(py, |session| {
            let detail = session.target.enumerate_resources(limit).map_err(err)?;
            Ok(view::object::resource_list(&detail))
        })
    }

    /// Get the memory-use counters of the system and of each process, up to a
    /// limit (`!memusage`).
    #[pyo3(signature = (process_limit=64))]
    fn memusage<'py>(
        &self,
        py: Python<'py>,
        process_limit: usize,
    ) -> PyResult<Typed<'py, mm::SystemMemoryUsage>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .memory_use_summary(process_limit)
                .map_err(err)?;
            Ok(view::mm::memory_usage(&detail))
        })
    }

    /// List the process, thread, and image notification callbacks.
    fn callbacks<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, Vec<view::object::NotifyCallback>>> {
        self.typed(py, |session| {
            let callbacks = session.target.enumerate_notify_callbacks().map_err(err)?;
            let dtb = session.target.guest().map_err(err)?.ntoskrnl.dtb();
            Ok(callbacks
                .iter()
                .map(|callback| {
                    let symbol = session.target.format_code_address(dtb, callback.function);
                    view::object::notify_callback(callback, symbol)
                })
                .collect::<Vec<_>>())
        })
    }

    /// Get the kernel SSDT, and the win32k shadow table if it is initialized
    /// (`!ssdt`).
    fn ssdt<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<view::object::SsdtTable>>> {
        self.typed(py, |session| {
            let tables = session.target.dump_ssdt().map_err(err)?;
            Ok(tables
                .iter()
                .map(view::object::ssdt_table)
                .collect::<Vec<_>>())
        })
    }

    /// Get the current, next, and idle threads on each processor (`!running`).
    #[pyo3(signature = (include_idle=false, include_stacks=false))]
    fn running<'py>(
        &self,
        py: Python<'py>,
        include_idle: bool,
        include_stacks: bool,
    ) -> PyResult<Typed<'py, sched::RunningProcessors>> {
        self.typed(py, |session| {
            let detail = session
                .inspect_running(include_idle, include_stacks)
                .map_err(err)?;
            Ok(view::sched::running(&detail))
        })
    }

    /// Read the dispatcher ready queues, up to a limit, for all processors or
    /// for one processor (`!ready`).
    #[pyo3(signature = (processor=None))]
    fn ready<'py>(
        &self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Typed<'py, sched::ReadyQueues>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_ready_queues(processor)
                .map_err(err)?;
            Ok(view::sched::ready_queues(&detail))
        })
    }

    /// Get the DPCs that are queued on each processor (`!dpcs`).
    fn dpcs<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, sched::DpcQueues>> {
        self.typed(py, |session| {
            let detail = session.target.inspect_dpc_queues().map_err(err)?;
            Ok(view::sched::dpc_queues(&detail))
        })
    }

    /// Get the processors that own or wait for each numbered queued spinlock
    /// (`!qlocks`).
    fn queued_locks<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, hardware::QueuedLocks>> {
        self.typed(py, |session| {
            let detail = session.target.queued_locks().map_err(err)?;
            Ok(view::hardware::queued_locks(&detail))
        })
    }

    /// Get the interprocessor-interrupt state of all processors or of one
    /// processor (`!ipi`).
    #[pyo3(signature = (processor=None))]
    fn ipi<'py>(
        &self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Typed<'py, hardware::IpiState>> {
        self.typed(py, |session| {
            let detail = session.target.ipi_state(processor).map_err(err)?;
            Ok(view::hardware::ipi(&detail))
        })
    }

    /// Get the PCI bus hierarchy that pci.sys tracks (`!pcitree`).
    fn pci_tree<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, hardware::PciTree>> {
        self.typed(py, |session| {
            let tree = session.target.pci_tree().map_err(err)?;
            Ok(view::hardware::pci_tree(&tree))
        })
    }

    /// Read and decode PCI configuration space (`!pci`) for the functions on
    /// `bus` (through `last_bus`), or for one `device` and `function`. It reads
    /// all 4 KiB of each function, with the extended capabilities, and `raw`
    /// adds the data as hex. This needs a halted target and a backend that can
    /// get to configuration space (kd/kdnet, or gdb on QEMU).
    #[pyo3(signature = (bus=0, device=None, function=None, *, last_bus=None, raw=false))]
    fn pci<'py>(
        &self,
        py: Python<'py>,
        bus: u8,
        device: Option<u8>,
        function: Option<u8>,
        last_bus: Option<u8>,
        raw: bool,
    ) -> PyResult<Typed<'py, hardware::PciScan>> {
        self.typed(py, |session| {
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

    /// Get the executive worker queues, their pending work items, and their
    /// worker threads (`!exqueue`). `include_stacks` adds the stack of each
    /// worker, and `queue_types` (`"critical"`, `"delayed"`, `"hypercritical"`)
    /// limits the listed items to the priorities of those types.
    #[pyo3(signature = (include_stacks=false, queue_types=None))]
    fn work_queues<'py>(
        &self,
        py: Python<'py>,
        include_stacks: bool,
        queue_types: Option<Vec<String>>,
    ) -> PyResult<Typed<'py, sched::WorkQueues>> {
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
        self.typed(py, |session| {
            let detail = session.inspect_work_queues(flags).map_err(err)?;
            Ok(view::sched::work_queues(&detail))
        })
    }

    /// Read the kernel timer-table entries, up to a limit, and their DPCs
    /// (`!timer`).
    fn timers<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, sched::TimerTable>> {
        self.typed(py, |session| {
            let detail = session.target.timer_list().map_err(err)?;
            Ok(view::sched::timer_list(&detail))
        })
    }

    /// Decode a `_KTIMER` and its DPC (`!timer address`).
    fn timer<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, sched::KernelTimer>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_timer(VirtAddr(address))
                .map_err(err)?;
            Ok(view::sched::timer(&detail))
        })
    }

    /// Decode the kernel and user APC queues of all threads, of a process, or
    /// of a thread (`!apc`).
    #[pyo3(signature = (target=None))]
    fn apcs<'py>(
        &self,
        py: Python<'py>,
        target: Option<ApcTarget<'_>>,
    ) -> PyResult<Typed<'py, sched::ApcQueues>> {
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
        self.typed(py, |session| {
            let detail = session.inspect_apcs(selector).map_err(err)?;
            Ok(view::sched::apcs(&detail))
        })
    }

    /// Get the thread states, wait reasons, and stacks, up to a limit
    /// (`!stacks`).
    #[pyo3(signature = (level=0, filter=None))]
    fn stacks<'py>(
        &self,
        py: Python<'py>,
        level: u8,
        filter: Option<&str>,
    ) -> PyResult<Typed<'py, sched::ThreadStacks>> {
        self.typed(py, |session| {
            let detail = session.inspect_stacks(level, filter).map_err(err)?;
            Ok(view::sched::stacks(&detail))
        })
    }

    /// List the threads that have a stack frame that matches a symbol or module
    /// (`!findstack`). The pattern is `module!prefix`, a module or function
    /// prefix alone, or a glob with `*`/`?`. `level` 0 counts the matching
    /// frames, 1 lists them, and 2 adds the full stack.
    #[pyo3(signature = (symbol, level=1))]
    fn findstack<'py>(
        &self,
        py: Python<'py>,
        symbol: &str,
        level: u8,
    ) -> PyResult<Typed<'py, sched::FindStack>> {
        self.typed(py, |session| {
            let detail = session.inspect_findstack(symbol, level).map_err(err)?;
            Ok(view::sched::findstack(&detail))
        })
    }

    /// Group threads by identical call stacks (`!uniqstack`), using all threads
    /// unless `process` limits it to the threads of one process.
    #[pyo3(signature = (process=None))]
    fn uniqstack<'py>(
        &self,
        py: Python<'py>,
        process: Option<PyRef<'_, Process>>,
    ) -> PyResult<Typed<'py, sched::UniqStacks>> {
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
        self.typed(py, |session| {
            let detail = session.inspect_uniqstack(scope).map_err(err)?;
            Ok(view::sched::uniqstack(&detail))
        })
    }

    /// Decode the PEB of a process, with its parameters and loader-list heads
    /// (`!peb`).
    #[pyo3(signature = (process, address=None))]
    fn peb<'py>(
        &self,
        py: Python<'py>,
        process: PyRef<'_, Process>,
        address: Option<u64>,
    ) -> PyResult<Typed<'py, view::usermode::Peb>> {
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
        Typed::new(py, detail)
    }

    /// Decode the TEB of a thread and its WOW64 companion (`!teb`).
    #[pyo3(signature = (thread, address=None))]
    fn teb<'py>(
        &self,
        py: Python<'py>,
        thread: PyRef<'_, Thread>,
        address: Option<u64>,
    ) -> PyResult<Typed<'py, view::usermode::Teb>> {
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
        Typed::new(py, detail)
    }

    /// Decode a `_KTRAP_FRAME` at `address` (`.trap`).
    fn trap_frame<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, view::bugcheck::TrapFrame>> {
        self.typed(py, |session| {
            trap_frame_view(&session.target, Some(VirtAddr(address)))
        })
    }

    /// Return a handle for the `_DEVICE_OBJECT` at `address` (`!devobj`).
    fn device(&self, py: Python<'_>, address: u64) -> PyResult<Device> {
        let owner = self.owner.derive(py);
        Ok(Device::new(owner, address))
    }

    /// Decode the device stack that contains a device object or devnode
    /// (`!devstack`).
    fn device_stack<'py>(
        &self,
        py: Python<'py>,
        device_or_node: DeviceArg<'_>,
    ) -> PyResult<Typed<'py, view::pnp::DeviceStack>> {
        let address = match device_or_node {
            DeviceArg::Device(device) => {
                device
                    .owner
                    .require_argument_of(py, &self.owner, "device")?;
                device.address
            }
            DeviceArg::Address(address) => address,
        };
        self.typed(py, |session| {
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
    fn exception_record<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, view::bugcheck::ExceptionRecord>> {
        self.typed(py, |session| {
            let record = session
                .read_exception_record(VirtAddr(address))
                .map_err(err)?;
            Ok(view::bugcheck::exception_record(Some(address), &record))
        })
    }

    /// Decode the `_CONTROL_AREA` of a section, with its segment and its
    /// subsections (`!ca`).
    fn control_area<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, view::fs::ControlArea>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_control_area(VirtAddr(address))
                .map_err(err)?;
            Ok(view::fs::control_area(&detail))
        })
    }

    /// Decode a volume parameter block (`!vpb`).
    fn vpb<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Typed<'py, view::fs::Vpb>> {
        self.typed(py, |session| {
            let detail = session.target.inspect_vpb(VirtAddr(address)).map_err(err)?;
            Ok(view::fs::vpb(&detail))
        })
    }

    /// Get the mapped views of the cache manager for each file, from its VACB
    /// arrays (`!filecache`).
    fn file_cache<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::fs::FileCache>> {
        self.typed(py, |session| {
            let detail = session.target.file_cache().map_err(err)?;
            Ok(view::fs::file_cache(&detail))
        })
    }

    /// Get the registered minifilters of each filter manager frame, with their
    /// instances (`!fltkd.filters`).
    fn flt_filters<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::fs::FltFilters>> {
        self.typed(py, |session| {
            let detail = session.target.flt_filters().map_err(err)?;
            Ok(view::fs::flt_filters(&detail))
        })
    }

    /// Get minifilter instances with their filter and volume
    /// (`!fltkd.instances`): all instances, or the instances of one filter
    /// given by name or by `_FLT_FILTER` address.
    #[pyo3(signature = (filter=None))]
    fn flt_instances<'py>(
        &self,
        py: Python<'py>,
        filter: Option<FltFilterArg>,
    ) -> PyResult<Typed<'py, view::fs::FltInstances>> {
        let (text, address) = match filter {
            Some(FltFilterArg::Address(address)) => (Some(format!("{address:#x}")), Some(address)),
            Some(FltFilterArg::Name(name)) => (Some(name), None),
            None => (None, None),
        };
        self.typed(py, |session| {
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

    /// Get the volumes of each filter manager frame, with the instances on them
    /// (`!fltkd.volumes`).
    fn flt_volumes<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::fs::FltVolumes>> {
        self.typed(py, |session| {
            let detail = session.target.flt_volumes().map_err(err)?;
            Ok(view::fs::flt_volumes(&detail))
        })
    }

    /// Get the KMDF client drivers on the driver list of
    /// `Wdf01000!FxLibraryGlobals` (`!wdfkd.wdfldr`).
    fn wdf_loader<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::wdf::WdfLoader>> {
        self.typed(py, |session| {
            let detail = session.target.wdf_loader().map_err(err)?;
            Ok(view::wdf::loader(&detail))
        })
    }

    /// Get a KMDF client driver and its device objects, with the WDFDEVICEs
    /// behind them (`!wdfkd.wdfdriverinfo`). Use the driver name that
    /// `wdf_loader` shows, in any case and with or without `.sys`.
    fn wdf_driver_info<'py>(
        &self,
        py: Python<'py>,
        driver: &str,
    ) -> PyResult<Typed<'py, view::wdf::WdfDriverInfo>> {
        self.typed(py, |session| {
            let detail = session.target.wdf_driver_info(driver).map_err(err)?;
            Ok(view::wdf::driver_info(&detail))
        })
    }

    /// Decode a WDF handle and the object that it identifies
    /// (`!wdfkd.wdfhandle`), or raise an exception if the value is not the
    /// handle of a live KMDF object.
    fn wdf_handle<'py>(
        &self,
        py: Python<'py>,
        handle: u64,
    ) -> PyResult<Typed<'py, view::wdf::WdfHandle>> {
        self.typed(py, |session| {
            let detail = session.target.wdf_handle(handle).map_err(err)?;
            Ok(view::wdf::handle(&detail))
        })
    }

    /// Get the device objects, state machines, and queues of a WDFDEVICE
    /// (`!wdfkd.wdfdevice`).
    fn wdf_device<'py>(
        &self,
        py: Python<'py>,
        handle: u64,
    ) -> PyResult<Typed<'py, view::wdf::WdfDevice>> {
        self.typed(py, |session| {
            let detail = session.target.wdf_device(handle).map_err(err)?;
            Ok(view::wdf::device(&detail))
        })
    }

    /// Get the configuration, state, callbacks, and requests of a WDFQUEUE
    /// (`!wdfkd.wdfqueue`).
    fn wdf_queue<'py>(
        &self,
        py: Python<'py>,
        handle: u64,
    ) -> PyResult<Typed<'py, view::wdf::WdfQueue>> {
        self.typed(py, |session| {
            let detail = session.target.wdf_queue(handle).map_err(err)?;
            Ok(view::wdf::queue(&detail))
        })
    }

    /// Get the In-Flight Recorder log of a KMDF client driver, oldest record
    /// first (`!wdfkd.wdflogdump`). A record whose TMF message a loaded PDB
    /// declares is formatted from that message.
    fn wdf_log<'py>(
        &self,
        py: Python<'py>,
        driver: &str,
    ) -> PyResult<Typed<'py, view::wdf::WdfLog>> {
        self.typed(py, |session| {
            let detail = session.target.wdf_log_dump(driver).map_err(err)?;
            Ok(view::wdf::log(&detail))
        })
    }

    /// Get the system memory, pool, PTE, and page-file counters (`!vm`).
    #[pyo3(signature = (include_processes=true))]
    fn vm<'py>(
        &self,
        py: Python<'py>,
        include_processes: bool,
    ) -> PyResult<Typed<'py, mm::VmStatistics>> {
        self.typed(py, |session| {
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
    ) -> PyResult<Typed<'py, mm::Pfn>> {
        let selector = if physical_address {
            PfnSelector::PhysicalAddress(value)
        } else {
            PfnSelector::Pfn(value)
        };
        self.typed(py, |session| {
            let detail = session.target.inspect_pfn(selector).map_err(err)?;
            Ok(view::mm::pfn(&detail))
        })
    }

    /// Decode the pool page or big-pool allocation that contains `address`
    /// (`!pool`).
    fn pool<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Typed<'py, mm::PoolPage>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_pool(VirtAddr(address))
                .map_err(err)?;
            Ok(view::mm::pool_page(&detail))
        })
    }

    /// Check the block headers of the pool page that contains `address`, and
    /// return the first inconsistency (`!poolval`).
    fn pool_validate<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, mm::PoolValidation>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .validate_pool(VirtAddr(address))
                .map_err(err)?;
            Ok(view::mm::pool_validation(&detail))
        })
    }

    /// Add up pool tracker usage by tag (`!poolused`).
    #[pyo3(signature = (tag=None, *, sort="tag", include_counts=false))]
    fn pool_usage<'py>(
        &self,
        py: Python<'py>,
        tag: Option<&str>,
        sort: &str,
        include_counts: bool,
    ) -> PyResult<Typed<'py, mm::PoolUsage>> {
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
        self.typed(py, |session| {
            let detail = session
                .target
                .pool_usage(sort, tag, include_counts)
                .map_err(err)?;
            Ok(view::mm::pool_usage(&detail))
        })
    }

    /// Find pool allocations by tag (`!poolfind`), optionally in one pool type
    /// only.
    #[pyo3(signature = (tag, pool_type=None))]
    fn pool_find<'py>(
        &self,
        py: Python<'py>,
        tag: &str,
        pool_type: Option<&str>,
    ) -> PyResult<Typed<'py, mm::PoolSearch>> {
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
        self.typed(py, |session| {
            let detail = session.target.pool_find(tag, pool_type).map_err(err)?;
            Ok(view::mm::pool_find(&detail))
        })
    }

    /// List exported nonpaged and paged `GENERAL_LOOKASIDE` lists (`!lookaside`).
    fn lookasides<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, mm::LookasideLists>> {
        self.typed(py, |session| {
            let detail = session.target.lookaside_lists().map_err(err)?;
            Ok(view::mm::lookaside_lists(&detail))
        })
    }

    /// Decode one `GENERAL_LOOKASIDE` (`!lookaside address`).
    fn lookaside<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, mm::LookasideList>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_lookaside(VirtAddr(address))
                .map_err(err)?;
            Ok(view::mm::lookaside(&detail))
        })
    }

    /// Decode an `_MDL` and the page frames after its header (`!mdl`).
    /// `pfn_count` replaces the page count that `ByteCount` spans from
    /// `ByteOffset`.
    #[pyo3(signature = (address, pfn_count=None))]
    fn mdl<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        pfn_count: Option<u64>,
    ) -> PyResult<Typed<'py, mm::Mdl>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_mdl(VirtAddr(address), pfn_count)
                .map_err(err)?;
            Ok(view::mm::mdl(&detail))
        })
    }

    /// Get the system PTE usage from each `_MI_SYSTEM_PTE_TYPE` bitmap
    /// allocator (`!sysptes`). `free_runs` lists the free blocks of each
    /// allocator.
    #[pyo3(signature = (free_runs=false))]
    fn system_ptes<'py>(
        &self,
        py: Python<'py>,
        free_runs: bool,
    ) -> PyResult<Typed<'py, mm::SystemPtes>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .system_ptes(u64::from(free_runs))
                .map_err(err)?;
            Ok(view::mm::system_ptes(&detail))
        })
    }

    /// Decode a security descriptor, with its owner and group SIDs and its ACLs
    /// (`!sd`).
    #[pyo3(signature = (address, annotate_well_known=false))]
    fn security_descriptor<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        annotate_well_known: bool,
    ) -> PyResult<Typed<'py, view::security::SecurityDescriptor>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_security_descriptor(VirtAddr(address), annotate_well_known)
                .map_err(err)?;
            Ok(view::security::security_descriptor(&detail))
        })
    }

    /// Decode an ACL and its ACEs (`!acl`).
    fn acl<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Typed<'py, view::security::Acl>> {
        self.typed(py, |session| {
            let detail = session.target.inspect_acl(VirtAddr(address)).map_err(err)?;
            Ok(view::security::acl(&detail))
        })
    }

    /// Decode a SID into its string form, authority, and well-known name
    /// (`!sid`).
    fn sid<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Typed<'py, view::security::Sid>> {
        self.typed(py, |session| {
            let detail = session.target.inspect_sid(VirtAddr(address)).map_err(err)?;
            Ok(view::security::sid(&detail))
        })
    }

    /// Decode the security descriptor that the header of an object references
    /// (`!objsd`).
    fn object_security<'py>(
        &self,
        py: Python<'py>,
        object: u64,
    ) -> PyResult<Typed<'py, view::security::ObjectSecurity>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_object_security(VirtAddr(object))
                .map_err(err)?;
            Ok(view::security::object_security(&detail))
        })
    }

    /// List sessions, or one selected session, and their processes
    /// (`!session`).
    #[pyo3(signature = (session=None))]
    fn sessions<'py>(
        &self,
        py: Python<'py>,
        session: Option<i64>,
    ) -> PyResult<Typed<'py, view::security::Sessions>> {
        self.typed(py, |session_state| {
            let detail = session_state.target.sessions(session).map_err(err)?;
            Ok(view::security::sessions(&detail))
        })
    }

    /// List the active ETW trace sessions (`!wmitrace.strdump`).
    fn etw_loggers<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::etw::EtwLoggerTable>> {
        self.typed(py, |session| {
            let table = session.target.etw_loggers().map_err(err)?;
            Ok(view::etw::logger_table(&table))
        })
    }

    /// Decode the `_WMI_LOGGER_CONTEXT` of one ETW trace session
    /// (`!wmitrace.logger`). `logger` is the logger ID, the context address, or
    /// the session name.
    fn etw_logger<'py>(
        &self,
        py: Python<'py>,
        logger: LoggerArg,
    ) -> PyResult<Typed<'py, view::etw::EtwLogger>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .etw_logger(&logger.text(), NumberRadix::Hexadecimal)
                .map_err(err)?;
            Ok(view::etw::logger(&detail))
        })
    }

    /// List the trace buffers on the GlobalList of an ETW trace session
    /// (`!wmitrace.strdump logger`).
    fn etw_buffers<'py>(
        &self,
        py: Python<'py>,
        logger: LoggerArg,
    ) -> PyResult<Typed<'py, view::etw::EtwLoggerBuffers>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .etw_logger_buffers(&logger.text(), NumberRadix::Hexadecimal)
                .map_err(err)?;
            Ok(view::etw::logger_buffers(&detail))
        })
    }

    /// Decode the events that are still in the buffers of an ETW trace session,
    /// oldest first (`!wmitrace.logdump`). `count` keeps only the most recent
    /// events. For a WPP message, `message.text` is the message rendered from
    /// the TMF that a loaded PDB declares, and the raw `payload` is always
    /// kept.
    #[pyo3(signature = (logger, count=None))]
    fn etw_events<'py>(
        &self,
        py: Python<'py>,
        logger: LoggerArg,
        count: Option<usize>,
    ) -> PyResult<Typed<'py, view::etw::EtwEventDump>> {
        self.typed(py, |session| {
            let dump = session
                .target
                .etw_log_dump(&logger.text(), NumberRadix::Hexadecimal, count)
                .map_err(err)?;
            Ok(view::etw::event_dump(&dump))
        })
    }

    /// Decode a PnP device node (`!devnode`), and optionally its subtree up to
    /// a limit.
    #[pyo3(signature = (node=None, recurse=false))]
    fn devnode<'py>(
        &self,
        py: Python<'py>,
        node: Option<u64>,
        recurse: bool,
    ) -> PyResult<Typed<'py, view::pnp::DevNode>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_devnode(node.map(VirtAddr), recurse)
                .map_err(err)?;
            Ok(view::pnp::devnode(&detail))
        })
    }

    /// Get the device nodes that have PnP problems (`!pnptriage`).
    fn pnp_triage<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::pnp::PnpTriage>> {
        self.typed(py, |session| {
            let detail = session.target.pnp_triage().map_err(err)?;
            Ok(view::pnp::pnp_triage(&detail))
        })
    }

    /// Get the Driver Verifier configuration and statistics (`!verifier`).
    fn verifier<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::meta::Verifier>> {
        self.typed(py, |session| {
            let detail = session.target.verifier_status().map_err(err)?;
            Ok(view::meta::verifier(&detail))
        })
    }

    /// Get the target, kernel, symbol, processor, and debugger version
    /// information (`vertarget`).
    fn version<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::meta::TargetVersion>> {
        self.typed(py, |session| {
            let detail = session.target_version().map_err(err)?;
            Ok(view::meta::target_version(&detail))
        })
    }

    /// Get the target system time and uptime (`.time`).
    fn time<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::meta::TargetTime>> {
        self.typed(py, |session| {
            let detail = session.target.target_time().map_err(err)?;
            Ok(view::meta::target_time(&detail))
        })
    }

    /// Analyze the current bugcheck, or return `None` if no bugcheck is in
    /// progress on the target.
    fn bugcheck<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, Option<view::bugcheck::Bugcheck>>> {
        let detail = self.owner.with_in(py, &Context::default(), |session| {
            Ok(current_bugcheck(&session.target)
                .or_else(|| bugcheck_from_dump_info(&session.target))
                .map(|analysis| view::bugcheck::bugcheck(&analysis)))
        })?;
        Typed::new(py, detail)
    }

    /// Make the structured one-shot crash and debug report (`!analyze`).
    fn triage<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::triage::TriageReport>> {
        self.typed(py, |session| {
            let report = TriageReport::build(session);
            Ok(view::triage::triage_report(&report, usize::MAX))
        })
    }

    /// List the virtio PCI functions (`!virtio`), with the state of each
    /// queue where the driver's private PDB types it. A queue's `progress`
    /// counters only grow, so two calls show what moved in between.
    fn virtio<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, Vec<view::virtio::VirtioDevice>>> {
        self.typed(py, |session| {
            let functions = session.target.virtio_functions().map_err(err)?;
            Ok(view::virtio::virtio_devices(&functions))
        })
    }

    /// Read the virtio-win virtqueue at `address` (`!vring`): its ring, the
    /// buffers the device holds or returned, and the request each carries.
    /// `module` names the driver whose PDB types it, by default the one its
    /// `add_buf` routine is in.
    #[pyo3(signature = (address, module=None))]
    fn vring<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        module: Option<String>,
    ) -> PyResult<Typed<'py, view::virtio::VirtioRing>> {
        self.typed(py, move |session| {
            let target = &session.target;
            let queue = target
                .virtqueue_at(module.as_deref(), VirtAddr(address))
                .map_err(err)?;
            let device = target.virtqueue_device(queue.address);
            Ok(view::virtio::virtio_ring(target, &queue, device))
        })
    }

    /// Read the data of the crash dump's block tagged `tag` (`.enumtag`), a
    /// GUID with or without braces, such as the one a driver passes to
    /// `KeRegisterBugCheckReasonCallback` for its secondary dump data.
    /// `target.dump.tagged_blocks` lists the blocks.
    fn read_tagged<'py>(&self, py: Python<'py>, tag: &str) -> PyResult<Bound<'py, PyBytes>> {
        let Some(guid) = parse_guid(tag) else {
            return Err(raise(format!("{tag:?} is not a GUID")));
        };
        let data = self.owner.with_in(py, &Context::default(), |session| {
            let dump = session
                .target
                .phys
                .dmp_info()
                .ok_or_else(|| raise("tagged data is in crash dumps; this target is live"))?;
            dump.tagged_blocks
                .iter()
                .find(|block| block.tag == guid)
                .map(|block| Arc::clone(&block.data))
                .ok_or_else(|| raise(format!("the dump has no block tagged {tag}")))
        })?;
        Ok(PyBytes::new(py, &data))
    }
}
