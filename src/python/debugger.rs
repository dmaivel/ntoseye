//! `Debugger`'s Python surface: the namespaces, run control, and session
//! lifecycle. Areas with their own module (run control, the command runner,
//! symbols) are delegated there; this file only wires them onto the class.

use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::{PyTraverseError, PyVisit};

use super::breakpoints::{Breakpoints, Exceptions};
use super::command::admit;
use super::context::Space;
use super::handle::{Debugger, Owner};
use super::hypervisor::HypervisorPartition;
use super::inspect::Inspect;
use super::memory::Memory;
use super::module::{Drivers, Modules};
use super::process::Processes;
use super::record::Typed;
use super::secure::SecureKernel;
use super::symbols::{self, Symbols};
use super::thread::{Cpus, Threads};
use super::types::Types;
use super::userdump::UserDump;
use super::{err, runcontrol, runner};
use crate::dbg_backend::{BackendCapability, DebugOutputPage};
use crate::notice::Notice;
use crate::session::Stop;
use crate::session::effects::Effects;

fn namespace_owner(slf: &Bound<'_, Debugger>) -> Owner {
    Owner::unstamped(slf.py(), slf.as_unbound())
}

#[pymethods]
impl Debugger {
    /// Kernel virtual memory, read through the page tables of the kernel. User
    /// addresses are not mapped here, so read them through `process.memory`.
    /// On a user-mode minidump, the captured process's memory.
    #[getter]
    fn memory(slf: &Bound<'_, Self>) -> Memory {
        Memory::new(namespace_owner(slf), Space::Kernel)
    }

    /// Guest-physical memory, without address translation. A user-mode
    /// minidump has none, and its reads raise `NtoseyeError`.
    #[getter]
    fn physical(slf: &Bound<'_, Self>) -> Memory {
        Memory::new(namespace_owner(slf), Space::Physical)
    }

    /// Kernel-scope symbols: `symbols["nt!KeBugCheckEx"]`, `nearest(addr)`,
    /// `search(query)`, and the symbol and source paths. On a user-mode
    /// minidump, the symbols of the dump's modules.
    #[getter]
    fn symbols(slf: &Bound<'_, Self>) -> Symbols {
        Symbols::new(namespace_owner(slf), Space::Kernel)
    }

    /// Kernel-scope PDB types: `types["_EPROCESS"].at(addr)`. On a user-mode
    /// minidump, the types of the dump's modules' PDBs (`types["ntdll!_PEB"]`).
    #[getter]
    fn types(slf: &Bound<'_, Self>) -> Types {
        Types::new(namespace_owner(slf), Space::Kernel)
    }

    /// Loaded kernel modules: `modules["nt"]`, iteration, `.at(addr)`. On a
    /// user-mode minidump, the modules the dump lists.
    #[getter]
    fn modules(slf: &Bound<'_, Self>) -> Modules {
        Modules::kernel(namespace_owner(slf))
    }

    /// The process, threads, and exception a user-mode minidump captured,
    /// or `None` on a kernel target. A user-mode minidump has no kernel, so
    /// `processes`, `threads`, `cpus`, `drivers`, `physical`, and the
    /// kernel's `inspect` reports raise `NtoseyeError` on it.
    #[getter]
    fn user_dump(slf: &Bound<'_, Self>) -> PyResult<Option<UserDump>> {
        let owner = namespace_owner(slf);
        let user_dump = slf
            .get()
            .with_session(|session| Ok(session.target.user_dump().is_some()))?;
        Ok(user_dump.then_some(UserDump { owner }))
    }

    /// The VBS secure kernel (VTL1), with read-only `memory`, `symbols`,
    /// `types`, `modules`, and `trustlets`. ntoseye finds it in host memory on
    /// first use and raises `NtoseyeError` if VBS is not running or the backend
    /// cannot read host memory. This feature is experimental.
    #[getter]
    fn secure_kernel(slf: &Bound<'_, Self>) -> PyResult<SecureKernel> {
        let py = slf.py();
        SecureKernel::discover(py, namespace_owner(slf).derive(py))
    }

    /// The partitions of the Windows hypervisor, root first, with their
    /// virtual processors, as `!hvpartitions` and `!hvvps` list them. Each
    /// call walks them again. This needs the VM's `hv-evmcs` enlightenment or
    /// a vCPU stopped in the hypervisor, and an Intel host. Raises
    /// `NtoseyeError` if ntoseye does not recognize the layout of this
    /// hypervisor build. This feature is experimental.
    fn hypervisor_partitions(slf: &Bound<'_, Self>) -> PyResult<Vec<HypervisorPartition>> {
        let py = slf.py();
        let owner = namespace_owner(slf);
        let partitions = owner.with(py, |session| {
            session.target.hypervisor_partitions().map_err(err)
        })?;
        Ok(partitions
            .into_iter()
            .map(|info| HypervisorPartition::new(owner.clone_ref(py), info))
            .collect())
    }

    /// The ID of the hypervisor partition inspected in place of the target
    /// (see `select_partition`), or `None` while the target is.
    #[getter]
    fn partition(slf: &Bound<'_, Self>) -> PyResult<Option<u64>> {
        let py = slf.py();
        namespace_owner(slf).with(py, |session| Ok(session.partition()))
    }

    /// Running processes, keyed by PID: `processes[4]`, `.find(name)`.
    #[getter]
    fn processes(slf: &Bound<'_, Self>) -> Processes {
        Processes::new(namespace_owner(slf))
    }

    /// All Windows threads, keyed by TID: `threads[tid]`, `.at(ethread)`.
    #[getter]
    fn threads(slf: &Bound<'_, Self>) -> Threads {
        Threads::all(namespace_owner(slf))
    }

    /// The processors (vCPUs) of the target: `cpus[0].registers.rip`.
    #[getter]
    fn cpus(slf: &Bound<'_, Self>) -> Cpus {
        Cpus::new(namespace_owner(slf))
    }

    /// Driver objects from the `Driver` directory of the object manager:
    /// `drivers["Disk"]`, `.at(addr)`.
    #[getter]
    fn drivers(slf: &Bound<'_, Self>) -> Drivers {
        Drivers::new(namespace_owner(slf))
    }

    /// Code breakpoints and data watchpoints: `.add(...)`, `.watch(...)`,
    /// iteration, `[id]`.
    #[getter]
    fn breakpoints(slf: &Bound<'_, Self>) -> Breakpoints {
        Breakpoints::new(namespace_owner(slf))
    }

    /// Exception stop policies (`sx*`): `.set(code, mode)`, iteration, `.reset()`.
    #[getter]
    fn exceptions(slf: &Bound<'_, Self>) -> Exceptions {
        Exceptions::new(namespace_owner(slf))
    }

    /// System-wide reports and helpers that decode an object at an address
    /// (`!vm`, `!pool`, ...).
    #[getter]
    fn inspect(slf: &Bound<'_, Self>) -> Inspect {
        Inspect::new(namespace_owner(slf))
    }

    /// The current stop when the target is halted. `None` when the target runs.
    #[getter]
    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Option<Stop>>> {
        runcontrol::current_stop(py, self)
    }

    /// False after a reboot until the module list of the kernel exists. During
    /// that period kernel symbols and breakpoints work, but process and module
    /// enumeration do not work yet.
    #[getter]
    fn coherent(&self) -> PyResult<bool> {
        self.with_session(|session| Ok(session.kernel_coherent()))
    }

    /// The number of times ntoseye has rebuilt its view of the guest, for
    /// example after a reboot. Handles from an older generation raise
    /// `StaleHandleError`, so keep this value with raw addresses to know when
    /// they become stale.
    #[getter(generation)]
    fn generation_attr(&self) -> u64 {
        self.generation()
    }

    /// The capability matrix of the backend, which shows the operations that
    /// the transport supports.
    #[getter]
    fn capabilities<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<BackendCapability>>> {
        let rows = self.with_session(|session| Ok(session.capabilities()))?;
        Typed::new(py, rows)
    }

    /// Evaluate a debugger (MASM) expression in kernel scope to an integer,
    /// using the registers of the stopped vCPU (on a user-mode minidump, of
    /// the selected thread).
    fn eval(slf: &Bound<'_, Self>, expr: &str) -> PyResult<u64> {
        symbols::eval(slf.py(), &namespace_owner(slf), &Space::Kernel, expr)
    }

    /// Run a REPL command line and return its text output without styling. If a
    /// command resumes the target, this waits up to `timeout` seconds for the
    /// next stop, which then becomes `dbg.stop`. Command loops and `.sleep`
    /// also end when `timeout` elapses.
    #[pyo3(signature = (line, timeout=None))]
    fn command(slf: &Bound<'_, Self>, line: &str, timeout: Option<f64>) -> PyResult<String> {
        runner::command(slf, line, timeout)
    }

    /// Wait for the next stop without resuming. If the target is already
    /// halted, return the current stop immediately, and return `None` if the
    /// target is still running after `timeout`.
    #[pyo3(signature = (timeout=None))]
    fn wait<'py>(
        &self,
        py: Python<'py>,
        timeout: Option<f64>,
    ) -> PyResult<Typed<'py, Option<Stop>>> {
        runcontrol::wait(py, self, timeout)
    }

    /// Break into the running target and return the stop that results. On a
    /// halted target, return the stop it is halted at (`break` refuses it).
    fn interrupt<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Stop>> {
        runcontrol::interrupt(py, self)
    }

    /// Rebuild the guest state now (find the kernel again). Stops already do
    /// this when the backend reports a reload, and this function forces a
    /// rebuild. A user-mode minidump has no kernel to find, and raises
    /// `NtoseyeError`.
    fn reload(&self) -> PyResult<()> {
        self.with_session(|session| {
            admit(session, &Effects::KERNEL, "Debugger.reload")?;
            session.reload().map_err(err)
        })
    }

    /// Captured guest debug output (DbgPrint) since sequence `since`. To poll
    /// only for new lines, pass the previous `next_seq`.
    #[pyo3(signature = (since=0))]
    fn debug_log<'py>(&self, py: Python<'py>, since: u64) -> PyResult<Typed<'py, DebugOutputPage>> {
        let page = self.with_session(|session| Ok(session.read_debug_output(since)))?;
        Typed::new(py, page)
    }

    /// Remove and return what the debugger reported since the last call, in
    /// order. Each notice has a `level`: `"warning"` for something that did
    /// not work as it should, such as a breakpoint that failed to re-arm or
    /// host memory that no longer matched after a reload, or `"info"` for
    /// status, such as a background symbol fetch finishing, a breakpoint
    /// slot that was reclaimed, or the `ModLoad:` line of an `sxn ld` filter.
    fn notices<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<Notice>>> {
        let notices = self.with_session(|session| Ok(session.take_notices()))?;
        Typed::new(py, notices)
    }

    /// Remove all breakpoints, let the target run, and end the session. This
    /// releases the connection and the single-instance lock of the target, so
    /// you can attach to the target again. After this call, this debugger and
    /// its handles raise an exception, and a second call does nothing. If
    /// closing fails, the target stays halted, the session stays open, and the
    /// error is raised. A borrowed debugger (from a REPL command) does not own
    /// the session and leaves it unchanged.
    fn close(&self) -> PyResult<()> {
        if !self.is_owned() || self.is_closed() {
            return Ok(());
        }
        self.with_session(|session| session.cleanup_for_exit().map_err(err))?;
        self.shutdown();
        Ok(())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        self.close()?;
        Ok(false)
    }

    fn __repr__(&self) -> String {
        if self.is_closed() {
            return "<ntoseye.Debugger closed>".to_string();
        }
        match self.with_session(|session| {
            Ok((
                session.backend.is_running(),
                session.current_thread.clone(),
                session
                    .target
                    .user_dump_info()
                    .map(|info| info.process_label()),
            ))
        }) {
            Ok((true, _, _)) => "<ntoseye.Debugger running>".to_string(),
            Ok((false, thread, Some(process))) => {
                format!("<ntoseye.Debugger user dump {process} thread={thread}>")
            }
            Ok((false, vcpu, None)) => format!("<ntoseye.Debugger halted vcpu={vcpu}>"),
            Err(_) => "<ntoseye.Debugger>".to_string(),
        }
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        if let Some(conditions) = self.conditions.try_lock() {
            for callable in conditions.values() {
                visit.call(callable)?;
            }
        }
        Ok(())
    }

    fn __clear__(&self) {
        if let Some(mut conditions) = self.conditions.try_lock() {
            conditions.clear();
        }
    }
}
