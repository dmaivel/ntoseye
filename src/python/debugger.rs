//! `Debugger`'s Python surface: the namespaces, run control, and session
//! lifecycle. Areas with their own module (run control, the command runner,
//! symbols) are delegated there; this file only wires them onto the class.

use std::sync::atomic::Ordering;

use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::{PyTraverseError, PyVisit};

use super::args::{Disposition, Step, Until};
use super::breakpoints::{Breakpoints, Exceptions};
use super::context::Space;
use super::handle::{Debugger, Owner, require_halted};
use super::hypervisor::HypervisorPartition;
use super::inspect::Inspect;
use super::memory::Memory;
use super::module::{Drivers, Modules};
use super::process::Processes;
use super::secure::SecureKernel;
use super::stop::Stop;
use super::symbols::Location;
use super::symbols::{self, Symbols};
use super::thread::{Cpus, Threads};
use super::types::Types;
use super::{err, raise, runcontrol, runner};
use crate::dbg_backend::ContinueDisposition;
use crate::dump_writer::{collect_dump_metadata, write_kernel_dump};
use crate::view;
use crate::view::shape::Typed;

fn namespace_owner(slf: &Bound<'_, Debugger>) -> Owner {
    Owner::unstamped(slf.py(), slf.as_unbound())
}

#[pymethods]
impl Debugger {
    /// Kernel virtual memory, read through the page tables of the kernel. User
    /// addresses are not mapped here, so read them through `process.memory`.
    #[getter]
    fn memory(slf: &Bound<'_, Self>) -> Memory {
        Memory::new(namespace_owner(slf), Space::Kernel)
    }

    /// Guest-physical memory, without address translation.
    #[getter]
    fn physical(slf: &Bound<'_, Self>) -> Memory {
        Memory::new(namespace_owner(slf), Space::Physical)
    }

    /// Kernel-scope symbols: `symbols["nt!KeBugCheckEx"]`, `nearest(addr)`,
    /// `search(query)`, and the symbol and source paths.
    #[getter]
    fn symbols(slf: &Bound<'_, Self>) -> Symbols {
        Symbols::new(namespace_owner(slf), Space::Kernel)
    }

    /// Kernel-scope PDB types: `types["_EPROCESS"].at(addr)`.
    #[getter]
    fn types(slf: &Bound<'_, Self>) -> Types {
        Types::new(namespace_owner(slf), Space::Kernel)
    }

    /// Loaded kernel modules: `modules["nt"]`, iteration, `.at(addr)`.
    #[getter]
    fn modules(slf: &Bound<'_, Self>) -> Modules {
        Modules::kernel(namespace_owner(slf))
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

    /// Inspect the Windows guest that hypervisor partition `partition_id`
    /// runs (a Windows Sandbox, a Hyper-V VM) in place of the target, as
    /// `.partition` does: `memory`, `processes`, `modules`, `symbols`,
    /// `types` and `threads` then read that guest, through its EPT, and the
    /// vCPUs are its VPs, with their VTL0 registers. The target stays
    /// halted. `memory.write` writes the guest's memory through its EPT, and
    /// a register write goes to the target's vCPU that runs the selected VP at
    /// the stop; a VP no vCPU runs has its registers in the hypervisor's
    /// memory, and raises `NtoseyeError`. `breakpoints.add(..., hardware=True)`
    /// and `breakpoints.watch` set the partition's breakpoints, which stop
    /// only on its VPs (`processor=` names one) and need the gdb backend;
    /// software breakpoints raise. `run` leaves the view and runs the
    /// target, and a hit of the partition's breakpoint returns in its view,
    /// on the VP that hit it. `step`, `step_over` and `step_out` step the
    /// thread of the selected VP, and `run_to` runs until any of its VPs
    /// reaches an address, each a run of the target to a breakpoint of the
    /// partition's; `step(until=...)` and `trace_calls` raise. The root
    /// partition's ID (1) returns to the
    /// target. Handles minted on either side of a switch go stale
    /// (`generation` advances). The target must be halted. This feature is
    /// experimental.
    fn select_partition(slf: &Bound<'_, Self>, partition_id: u64) -> PyResult<()> {
        let py = slf.py();
        namespace_owner(slf).with(py, |session| {
            require_halted(session, "Debugger.select_partition")?;
            session.enter_partition(partition_id).map_err(err)
        })
    }

    /// The ID of the hypervisor partition inspected in place of the target
    /// (see `select_partition`), or `None` while the target is.
    #[getter]
    fn partition(slf: &Bound<'_, Self>) -> PyResult<Option<u64>> {
        let py = slf.py();
        namespace_owner(slf).with(py, |session| Ok(session.partition()))
    }

    /// The Windows hypervisor's hypercall table, one entry per call code, as
    /// `!hvcalls -a` lists it. Needs the VM's `hv-evmcs` enlightenment or a
    /// vCPU stopped in the hypervisor. This feature is experimental.
    fn hypercalls<'py>(
        slf: &Bound<'py, Self>,
    ) -> PyResult<Typed<'py, Vec<view::hypervisor::Hypercall>>> {
        let py = slf.py();
        let owner = namespace_owner(slf);
        let (_, table) = owner.with(py, |session| session.target.hypercalls().map_err(err))?;
        let unassigned = table.first().map(|entry| entry.handler);
        // Each entry's code is its index, a u16.
        Typed::new(
            py,
            table
                .iter()
                .zip(0..=u16::MAX)
                .map(|(entry, code)| view::hypervisor::hypercall(code, entry, unassigned))
                .collect(),
        )
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
    fn stop(slf: &Bound<'_, Self>) -> PyResult<Option<Py<Stop>>> {
        runcontrol::current_stop(slf)
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
    fn capabilities<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, Vec<view::backend::BackendCapability>>> {
        let rows = self.with_session(|session| Ok(session.capabilities()))?;
        Typed::new(
            py,
            rows.iter()
                .map(view::backend::capability)
                .collect::<Vec<_>>(),
        )
    }

    /// Evaluate a debugger (MASM) expression in kernel scope to an integer,
    /// using the registers of the stopped vCPU.
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

    /// Resume the target without a wait, and acknowledge the current exception
    /// as `handled` or `not_handled` (KD only).
    #[pyo3(signature = (disposition=Disposition(ContinueDisposition::Handled)))]
    fn cont(slf: &Bound<'_, Self>, disposition: Disposition) -> PyResult<()> {
        runcontrol::cont(slf, disposition.0)
    }

    /// Resume and wait for the next stop, resuming again automatically after a
    /// hit in the wrong process or a hit with a false condition. Returns the
    /// `Stop`, or `None` if the target is still running after `timeout`
    /// seconds.
    #[pyo3(signature = (timeout=None, *, disposition=Disposition(ContinueDisposition::Handled)))]
    fn run(
        slf: &Bound<'_, Self>,
        timeout: Option<f64>,
        disposition: Disposition,
    ) -> PyResult<Option<Py<Stop>>> {
        runcontrol::run(slf, timeout, disposition.0)
    }

    /// Wait for the next stop without resuming. If the target is already
    /// halted, return the current stop immediately, and return `None` if the
    /// target is still running after `timeout`.
    #[pyo3(signature = (timeout=None))]
    fn wait(slf: &Bound<'_, Self>, timeout: Option<f64>) -> PyResult<Option<Py<Stop>>> {
        runcontrol::wait(slf, timeout)
    }

    /// Run until execution reaches `target` (`g <addr>`), which is an address
    /// or a symbolic `module!name[+off]`. With `step="over"`/`"into"`,
    /// single-step to it (`pa`/`ta`). Other stops on the way are returned as
    /// they are. With `timeout`, if execution does not reach `target` in time,
    /// the target is interrupted where it is, and the stop is a
    /// `Stop.Interrupt`.
    #[pyo3(signature = (target, timeout=None, *, step=None))]
    fn run_to(
        slf: &Bound<'_, Self>,
        target: Location,
        timeout: Option<f64>,
        step: Option<Step>,
    ) -> PyResult<Option<Py<Stop>>> {
        runcontrol::run_to(slf, target, timeout, step.map(|Step(mode)| mode))
    }

    /// Single-step one instruction. With `until` ("call", "ret", "branch"),
    /// step into instructions until the next instruction of that kind
    /// (`tc`/`tt`/`th`). With `timeout` (seconds), an `until` walk that does
    /// not end in time is interrupted where it is, and the stop is a
    /// `Stop.Interrupt`: a `Stop.Step` always ends a walk where it was going.
    /// Under VBS on the gdb backend, the other vCPUs can run while the step's
    /// vCPU waits on them; a watchpoint hit one of them makes meanwhile ends
    /// the step, and is returned instead.
    #[pyo3(signature = (until=None, timeout=None))]
    fn step(
        slf: &Bound<'_, Self>,
        until: Option<Until>,
        timeout: Option<f64>,
    ) -> PyResult<Py<Stop>> {
        runcontrol::step(slf, until.map(|Until(flow)| flow), timeout)
    }

    /// Step over the current instruction. With `until`, step over instructions
    /// until the next call, ret, or branch (`pc`/`pt`/`ph`). Stepping over a
    /// call runs the target until the stepping thread returns from it. With
    /// `timeout` (seconds), a run or walk that does not end in time is
    /// interrupted where it is, and the stop is a `Stop.Interrupt`.
    #[pyo3(signature = (until=None, timeout=None))]
    fn step_over(
        slf: &Bound<'_, Self>,
        until: Option<Until>,
        timeout: Option<f64>,
    ) -> PyResult<Py<Stop>> {
        runcontrol::step_over(slf, until.map(|Until(flow)| flow), timeout)
    }

    /// Run until the stepping thread returns from the current function (`gu`).
    /// With `timeout` (seconds), the thread is interrupted where it is if it
    /// does not return in time, and the stop is a `Stop.Interrupt`.
    #[pyo3(signature = (timeout=None))]
    fn step_out(slf: &Bound<'_, Self>, timeout: Option<f64>) -> PyResult<Py<Stop>> {
        runcontrol::step_out(slf, timeout)
    }

    /// Trace calls until the current function returns (`wt`), single-stepping
    /// at most `limit` instructions. Returns `{end, error, instructions,
    /// root}`, where `root` is the call tree and `end` gives the reason that
    /// tracing stopped. With `timeout` (seconds), a trace that is still
    /// running then ends as `interrupted`, halted where it got to: a step
    /// that follows the traced thread waits for it to run the instruction,
    /// which can take long when other threads keep reaching it first.
    #[pyo3(signature = (limit=10_000, timeout=None))]
    fn trace_calls<'py>(
        slf: &Bound<'py, Self>,
        limit: usize,
        timeout: Option<f64>,
    ) -> PyResult<Typed<'py, view::execution::CallTrace>> {
        runcontrol::trace_calls(slf, limit, timeout)
    }

    /// Break into the running target and return the stop that results.
    fn interrupt(slf: &Bound<'_, Self>) -> PyResult<Py<Stop>> {
        runcontrol::interrupt(slf)
    }

    /// Reboot the target (`.reboot`). The next stop is a `Stop.Reboot`.
    fn reboot(slf: &Bound<'_, Self>) -> PyResult<()> {
        runcontrol::reboot(slf)
    }

    /// Crash the target on purpose (`.crash`), which causes a bugcheck stop.
    fn crash(slf: &Bound<'_, Self>) -> PyResult<()> {
        runcontrol::crash(slf)
    }

    /// Rebuild the guest state now (find the kernel again). Stops already do
    /// this when the backend reports a reload, and this function forces a
    /// rebuild.
    fn reload(&self) -> PyResult<()> {
        self.with_session(|session| session.reload().map_err(err))
    }

    /// Write a full `PAGEDU64` kernel dump of the halted target to `path`
    /// (`.dump /f`). Returns the number of unreadable pages that were filled
    /// with zeros.
    fn write_dump(&self, path: &str) -> PyResult<u64> {
        self.with_session(|session| {
            require_halted(session, "write_dump")?;
            if session.target.phys.is_dump() {
                return Err(raise("write_dump is not applicable to a static crash dump"));
            }
            let metadata = collect_dump_metadata(session).map_err(err)?;
            let cancel = &session.target.interrupt;
            write_kernel_dump(
                path,
                &session.target.phys,
                &metadata,
                || cancel.load(Ordering::Relaxed),
                || {},
            )
            .map_err(err)
        })
    }

    /// Captured guest debug output (DbgPrint) since sequence `since`. To poll
    /// only for new lines, pass the previous `next_seq`.
    #[pyo3(signature = (since=0))]
    fn debug_log<'py>(
        &self,
        py: Python<'py>,
        since: u64,
    ) -> PyResult<Typed<'py, view::backend::DebugLog>> {
        let page = self.with_session(|session| Ok(session.read_debug_output(since)))?;
        Typed::new(py, view::backend::debug_log(&page))
    }

    /// Remove and return what the debugger reported since the last call, in
    /// order. Each notice has a `level`: `"warning"` for something that did
    /// not work as it should, such as a breakpoint that failed to re-arm or
    /// host memory that no longer matched after a reload, or `"info"` for
    /// status, such as a background symbol fetch finishing, a breakpoint
    /// slot that was reclaimed, or the `ModLoad:` line of an `sxn ld` filter.
    fn notices<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<view::backend::Notice>>> {
        let notices = self.with_session(|session| Ok(session.take_notices()))?;
        Typed::new(py, notices.iter().map(view::backend::notice).collect())
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
            Ok((session.backend.is_running(), session.current_thread.clone()))
        }) {
            Ok((true, _)) => "<ntoseye.Debugger running>".to_string(),
            Ok((false, vcpu)) => format!("<ntoseye.Debugger halted vcpu={vcpu}>"),
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
