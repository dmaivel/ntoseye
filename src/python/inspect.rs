use pyo3::prelude::*;

use super::args::{ApcTarget, DeviceArg};
use super::context::{Context, in_context};
use super::handle::Owner;
use super::module::Device;
use super::process::Process;
use super::record::Record;
use super::thread::{Frame, Thread, process_for_thread, trap_frame_view};
use super::{err, raise, view_record, view_records};
use crate::bugchecks::{bugcheck_from_dump_info, current_bugcheck};
use crate::session::Session;
use crate::target::mm::{PfnSelector, PoolType, PoolUsageSort};
use crate::target::sched::ApcSelector;
use crate::triage_report::TriageReport;
use crate::types::VirtAddr;
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

    fn record<'py>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<View> + Send,
    ) -> PyResult<Bound<'py, Record>> {
        let view = self.owner.with_in(py, &Context::default(), build)?;
        view_record(py, &view)
    }

    fn list<'py>(
        &self,
        py: Python<'py>,
        build: impl FnOnce(&mut Session) -> PyResult<View> + Send,
    ) -> PyResult<Vec<Bound<'py, Record>>> {
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
    fn irp<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.inspect_irp(VirtAddr(address)).map_err(err)?;
            Ok(view::irp(&detail))
        })
    }

    /// Find in-flight IRPs, optionally filtered by process or driver (`irps`).
    #[pyo3(signature = (filter=None))]
    fn irps<'py>(
        &self,
        py: Python<'py>,
        filter: Option<&str>,
    ) -> PyResult<Vec<Bound<'py, Record>>> {
        self.list(py, |session| {
            let hits = session.target.discover_irps(filter).map_err(err)?;
            Ok(View::List(hits.iter().map(view::irp_hit).collect()))
        })
    }

    /// Decode an executive object header and resolve its type and name (`!object`).
    fn object<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_object_header(VirtAddr(address))
                .map_err(err)?;
            Ok(view::object_header(&detail))
        })
    }

    /// Decode a `_FILE_OBJECT` (`!fileobj`).
    fn file_object<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_file_object(VirtAddr(address))
                .map_err(err)?;
            Ok(view::file_object(&detail))
        })
    }

    /// Decode an executive resource (`!locks address`).
    fn resource<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_resource(VirtAddr(address))
                .map_err(err)?;
            Ok(view::resource(&detail))
        })
    }

    /// Enumerate the symbol-backed executive-resource list (`!locks`).
    #[pyo3(signature = (limit=256))]
    fn resources<'py>(&self, py: Python<'py>, limit: usize) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.enumerate_resources(limit).map_err(err)?;
            Ok(view::resource_list(&detail))
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
            Ok(view::memory_usage(&detail))
        })
    }

    /// Enumerate process, thread, and image notification callbacks.
    fn callbacks<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, Record>>> {
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
                        view::notify_callback(callback, symbol)
                    })
                    .collect(),
            ))
        })
    }

    /// Dump the kernel SSDT and initialized win32k shadow table (`!ssdt`).
    fn ssdt<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, Record>>> {
        self.list(py, |session| {
            let tables = session.target.dump_ssdt().map_err(err)?;
            Ok(View::List(tables.iter().map(view::ssdt_table).collect()))
        })
    }

    /// Report current, next, and idle threads on each processor (`!running`).
    #[pyo3(signature = (include_idle=false, include_stacks=false))]
    fn running<'py>(
        &self,
        py: Python<'py>,
        include_idle: bool,
        include_stacks: bool,
    ) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .inspect_running(include_idle, include_stacks)
                .map_err(err)?;
            Ok(view::sched::running(&detail))
        })
    }

    /// Read bounded dispatcher-ready queues for every processor or one (`!ready`).
    #[pyo3(signature = (processor=None))]
    fn ready<'py>(&self, py: Python<'py>, processor: Option<u16>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session
                .target
                .inspect_ready_queues(processor)
                .map_err(err)?;
            Ok(view::sched::ready_queues(&detail))
        })
    }

    /// Report DPCs queued on each processor (`!dpcs`).
    fn dpcs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.inspect_dpc_queues().map_err(err)?;
            Ok(view::sched::dpc_queues(&detail))
        })
    }

    /// Read bounded kernel timer-table entries and their DPCs (`!timer`).
    fn timers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.target.timer_list().map_err(err)?;
            Ok(view::sched::timer_list(&detail))
        })
    }

    /// Decode a `_KTIMER` and its DPC (`!timer address`).
    fn timer<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
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
    ) -> PyResult<Bound<'py, Record>> {
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
    ) -> PyResult<Bound<'py, Record>> {
        self.record(py, |session| {
            let detail = session.inspect_stacks(level, filter).map_err(err)?;
            Ok(view::sched::stacks(&detail))
        })
    }

    /// Decode a process PEB and its parameters and loader-list heads (`!peb`).
    #[pyo3(signature = (process, address=None))]
    fn peb<'py>(
        &self,
        py: Python<'py>,
        process: PyRef<'_, Process>,
        address: Option<u64>,
    ) -> PyResult<Bound<'py, Record>> {
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
    ) -> PyResult<Bound<'py, Record>> {
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
            Ok(view::exception_record(Some(address), &record))
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
                .map(|analysis| view::bugcheck(&analysis)))
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
            Ok(view::triage_report(&report, usize::MAX))
        })
    }
}
