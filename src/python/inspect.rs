use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::args::{ApcTarget, DeviceArg};
use super::command::admit;
use super::context::Context;
use super::handle::Owner;
use super::module::Device;
use super::process::Process;
use super::thread::{Frame, trap_frame_view};
use super::{err, raise};
use crate::bugchecks::{bugcheck_from_dump_info, current_bugcheck};
use crate::session::Session;
use crate::session::effects::Effects;
use crate::target::alpc::{AlpcMessage, AlpcPort, AlpcProcessPorts};
use crate::target::etw::parse_guid;
use crate::target::object::{ExecutiveResource, ResourceList};
use crate::target::pci::{PCI_EXTENDED_CONFIG_SIZE, PciQuery, PciScan};
use crate::target::registry::{CellLocation, HiveList, RegKey, RegValue, names_equal};
use crate::target::sched::{
    ApcQueues, ApcSelector, KernelTimer, TimerTable, UniqStackScope, UniqStacks,
};
use crate::target::workqueue::WorkQueues;
use crate::triage_report::TriageReport;
use crate::types::VirtAddr;
use crate::view::record::{ToView, Typed};
use crate::view::{self};

/// System-wide reports and helpers that decode an object at an address
/// (`dbg.inspect`). The results are typed `Record`s. On a user-mode
/// minidump, which has no kernel, only `version`, `time`, `triage`,
/// `bugcheck`, `exception_record`, and `context_record` apply; the others
/// raise `NtoseyeError`.
#[pyclass(module = "ntoseye")]
pub struct Inspect {
    pub owner: Owner,
}

impl Inspect {
    pub fn new(owner: Owner) -> Inspect {
        Inspect { owner }
    }

    /// Run `build` in the session and return its result as the SDK does. It
    /// reads the kernel, so a user-mode minidump refuses it.
    fn typed<'py, T: ToView<M> + Send, M>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<T> + Send,
    ) -> PyResult<Typed<'py, T, M>> {
        self.typed_any(py, |session| {
            admit(session, &Effects::KERNEL, "Inspect")?;
            build(session)
        })
    }

    /// [`Self::typed`] for a report that applies to every target.
    fn typed_any<'py, T: ToView<M> + Send, M>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<T> + Send,
    ) -> PyResult<Typed<'py, T, M>> {
        let value = self.owner.with_in(py, &Context::default(), build)?;
        Typed::new(py, value)
    }
}

#[pymethods]
impl Inspect {
    fn __repr__(&self) -> String {
        "<Inspect namespace>".to_string()
    }

    /// Decode an ALPC port (`!alpc /p`). The result has the port kind, owner,
    /// connection, state, and queues, and for a connection port also its
    /// connections. `address` is the body or the header of the port object.
    fn alpc_port<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Typed<'py, AlpcPort>> {
        self.typed(py, |session| {
            session.target.alpc_port(VirtAddr(address)).map_err(err)
        })
    }

    /// Decode an ALPC message, a `_KALPC_MESSAGE` (`!alpc /m`).
    fn alpc_message<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, AlpcMessage>> {
        self.typed(py, |session| {
            session.target.alpc_message(VirtAddr(address)).map_err(err)
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
    ) -> PyResult<Typed<'py, AlpcProcessPorts>> {
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
            target.alpc_process_ports(process).map_err(err)
        })
    }

    /// Decode an executive resource (`!locks address`).
    fn resource<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Typed<'py, ExecutiveResource>> {
        self.typed(py, |session| {
            session
                .target
                .inspect_resource(VirtAddr(address))
                .map_err(err)
        })
    }

    /// List the entries of the symbol-backed executive-resource list
    /// (`!locks`).
    #[pyo3(signature = (limit=256))]
    fn resources<'py>(&self, py: Python<'py>, limit: usize) -> PyResult<Typed<'py, ResourceList>> {
        self.typed(py, |session| {
            session.target.enumerate_resources(limit).map_err(err)
        })
    }

    /// Read and decode PCI configuration space (`!pci`) for the functions on
    /// `bus` (through `last_bus`), or for one `device` and `function`. It reads
    /// all 4 KiB of each function, with the extended capabilities, as `config`.
    /// This needs a halted target and a backend that can get to configuration
    /// space (kd/kdnet, or gdb on QEMU).
    #[pyo3(signature = (bus=0, device=None, function=None, *, last_bus=None))]
    fn pci<'py>(
        &self,
        py: Python<'py>,
        bus: u8,
        device: Option<u8>,
        function: Option<u8>,
        last_bus: Option<u8>,
    ) -> PyResult<Typed<'py, PciScan>> {
        self.typed(py, |session| {
            let query = PciQuery {
                segment: 0,
                first_bus: bus,
                last_bus: last_bus.unwrap_or(bus),
                device,
                function,
                size: PCI_EXTENDED_CONFIG_SIZE,
            };
            session.scan_pci(&query).map_err(err)
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
    ) -> PyResult<Typed<'py, WorkQueues>> {
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
            Ok(detail)
        })
    }

    /// Read the kernel timer-table entries, up to a limit, and their DPCs
    /// (`!timer`).
    fn timers<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, TimerTable>> {
        self.typed(py, |session| {
            let detail = session.target.timer_list().map_err(err)?;
            Ok(detail)
        })
    }

    /// Decode a `_KTIMER` and its DPC (`!timer address`).
    fn timer<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Typed<'py, KernelTimer>> {
        self.typed(py, |session| {
            let detail = session
                .target
                .inspect_timer(VirtAddr(address))
                .map_err(err)?;
            Ok(detail)
        })
    }

    /// Decode the kernel and user APC queues of all threads, of a process, or
    /// of a thread (`!apc`).
    #[pyo3(signature = (target=None))]
    fn apcs<'py>(
        &self,
        py: Python<'py>,
        target: Option<ApcTarget<'_>>,
    ) -> PyResult<Typed<'py, ApcQueues>> {
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
            Ok(detail)
        })
    }

    /// Group threads by identical call stacks (`!uniqstack`), using all threads
    /// unless `process` limits it to the threads of one process.
    #[pyo3(signature = (process=None))]
    fn uniqstack<'py>(
        &self,
        py: Python<'py>,
        process: Option<PyRef<'_, Process>>,
    ) -> PyResult<Typed<'py, UniqStacks>> {
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
            Ok(detail)
        })
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
        self.typed_any(py, |session| {
            let record = session
                .read_exception_record(VirtAddr(address))
                .map_err(err)?;
            Ok(view::bugcheck::exception_record(Some(address), &record))
        })
    }

    /// Get the system power action in progress, the power IRPs the power
    /// manager has allocated, and its IRP worker threads (`!poaction`).
    fn power_action<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::power::PowerAction>> {
        self.typed(py, |session| {
            let detail = session.target.power_action().map_err(err)?;
            Ok(view::power::power_action(&detail))
        })
    }

    /// Get a device object's power state and the power IRPs sent to its
    /// stack (`!podev`).
    fn device_power<'py>(
        &self,
        py: Python<'py>,
        device: DeviceArg<'_>,
    ) -> PyResult<Typed<'py, view::power::DevicePower>> {
        let address = match device {
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
                .device_power(VirtAddr(address))
                .map_err(err)?;
            Ok(view::power::device_power(&detail))
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
        self.typed_any(py, |session| {
            let detail = session.target_version().map_err(err)?;
            Ok(view::meta::target_version(&detail))
        })
    }

    /// Get the target system time and uptime (`.time`).
    fn time<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, view::meta::TargetTime>> {
        self.typed_any(py, |session| {
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
        self.typed_any(py, |session| {
            let report = TriageReport::build(session);
            Ok(view::triage::triage_report(&report, usize::MAX))
        })
    }

    /// List the registry hives loaded in kernel memory, with where each is
    /// mounted and the file it was loaded from (`!reg hivelist`).
    fn registry_hives<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, HiveList>> {
        self.typed(py, |session| session.target.registry_hives().map_err(err))
    }

    /// Read the registry key at `path`, a full path such as
    /// `HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip` or
    /// `\\REGISTRY\\MACHINE\\...`, with its subkeys and its values, each
    /// value's data typed by its type (`!reg querykey`).
    fn registry_key<'py>(&self, py: Python<'py>, path: String) -> PyResult<Typed<'py, RegKey>> {
        self.typed(py, move |session| {
            session.target.registry_key(&path).map_err(err)
        })
    }

    /// Read the value `name` of the registry key at `path`; `""` names the
    /// key's default value. Its `data` is a `str`, a `list[str]`, an `int`,
    /// or `bytes`, by the value's type (`!reg querykey <path> -v <name>`).
    fn registry_value<'py>(
        &self,
        py: Python<'py>,
        path: String,
        name: String,
    ) -> PyResult<Typed<'py, RegValue>> {
        self.typed(py, move |session| {
            let key = session.target.registry_key(&path).map_err(err)?;
            key.values
                .iter()
                .flatten()
                .find(|value| names_equal(&value.name, &name))
                .cloned()
                .ok_or_else(|| raise(format!("{} has no readable value named {name:?}", key.path)))
        })
    }

    /// Read the registry key whose key node (`_CM_KEY_NODE`) is at `node`
    /// in the hive at `hive` (`!reg keyinfo`).
    fn registry_key_at<'py>(
        &self,
        py: Python<'py>,
        hive: u64,
        node: u64,
    ) -> PyResult<Typed<'py, RegKey>> {
        self.typed(py, move |session| {
            session
                .target
                .registry_key_at(VirtAddr(hive), VirtAddr(node))
                .map_err(err)
        })
    }

    /// Find where cell index `cell` of the hive at `hive` is, through the
    /// hive's cell map (`!reg cellindex`).
    fn registry_cell<'py>(
        &self,
        py: Python<'py>,
        hive: u64,
        cell: u32,
    ) -> PyResult<Typed<'py, CellLocation>> {
        self.typed(py, move |session| {
            session
                .target
                .registry_cell(VirtAddr(hive), cell)
                .map_err(err)
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
            admit(session, &Effects::KERNEL, "Inspect.read_tagged")?;
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
