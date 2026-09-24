//! `Debugger`'s Python surface: the namespaces, run control, and session
//! lifecycle. Areas with their own module (run control, the command runner,
//! symbols) are delegated there; this file only wires them onto the class.

use std::sync::atomic::Ordering;

use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::{PyTraverseError, PyVisit};

use super::args::{Disposition, StepMode, Until};
use super::breakpoints::{Breakpoints, Exceptions};
use super::context::Space;
use super::handle::{Debugger, Owner, require_halted};
use super::inspect::Inspect;
use super::memory::Memory;
use super::module::{Drivers, Modules};
use super::process::Processes;
use super::record::Record;
use super::stop::Stop;
use super::symbols::Location;
use super::symbols::{self, Symbols};
use super::thread::{Cpus, Threads};
use super::types::Types;
use super::{err, raise, runcontrol, runner, view_record, view_records};
use crate::dbg_backend::ContinueDisposition;
use crate::dump_writer::{collect_dump_metadata, write_kernel_dump};
use crate::phys::PhysMem;
use crate::view;

fn namespace_owner(slf: &Bound<'_, Debugger>) -> Owner {
    Owner::unstamped(slf.py(), slf.as_unbound())
}

#[pymethods]
impl Debugger {
    /// Kernel virtual memory: the kernel's own page tables. User addresses
    /// are not mapped here; read them through `process.memory`.
    #[getter]
    fn memory(slf: &Bound<'_, Self>) -> Memory {
        Memory::new(namespace_owner(slf), Space::Kernel)
    }

    /// Guest-physical memory, untranslated.
    #[getter]
    fn physical(slf: &Bound<'_, Self>) -> Memory {
        Memory::new(namespace_owner(slf), Space::Physical)
    }

    /// Kernel-scope symbols: `symbols["nt!KeBugCheckEx"]`, `nearest(addr)`,
    /// `search(query)`, the symbol and source paths.
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

    /// Running processes keyed by PID: `processes[4]`, `.find(name)`.
    #[getter]
    fn processes(slf: &Bound<'_, Self>) -> Processes {
        Processes::new(namespace_owner(slf))
    }

    /// Every Windows thread keyed by TID: `threads[tid]`, `.at(ethread)`.
    #[getter]
    fn threads(slf: &Bound<'_, Self>) -> Threads {
        Threads::all(namespace_owner(slf))
    }

    /// The target's processors (vCPUs): `cpus[0].registers.rip`.
    #[getter]
    fn cpus(slf: &Bound<'_, Self>) -> Cpus {
        Cpus::new(namespace_owner(slf))
    }

    /// Driver objects from the object manager's `Driver` directory:
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

    /// System-wide reports and decode-by-address helpers (`!vm`, `!pool`, ...).
    #[getter]
    fn inspect(slf: &Bound<'_, Self>) -> Inspect {
        Inspect::new(namespace_owner(slf))
    }

    /// The current stop while the target is halted, `None` while it runs.
    #[getter]
    fn stop(slf: &Bound<'_, Self>) -> PyResult<Option<Py<Stop>>> {
        runcontrol::current_stop(slf)
    }

    /// False after a reboot until the kernel's module list exists: kernel
    /// symbols and breakpoints work, process/module enumeration does not yet.
    #[getter]
    fn coherent(&self) -> PyResult<bool> {
        self.with_session(|session| Ok(session.kernel_coherent()))
    }

    /// How many times the guest has been rebuilt (reboots). Handles from an
    /// older generation raise `StaleHandleError`; cache this beside raw
    /// addresses to know when they went stale.
    #[getter(generation)]
    fn generation_attr(&self) -> u64 {
        self.generation()
    }

    /// The backend's capability matrix as `{capability, label, supported}`
    /// records: which operations the transport supports.
    #[getter]
    fn capabilities<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, Record>>> {
        let rows = self.with_session(|session| Ok(session.capabilities()))?;
        view_records(
            py,
            &view::View::List(rows.iter().map(view::capability).collect()),
        )
    }

    /// Evaluate a debugger (MASM) expression in kernel scope to an integer;
    /// registers are the stopped vCPU's.
    fn eval(slf: &Bound<'_, Self>, expr: &str) -> PyResult<u64> {
        symbols::eval(slf.py(), &namespace_owner(slf), &Space::Kernel, expr)
    }

    /// Run a REPL command line and return its text output (styling stripped).
    /// Commands that resume the target wait for the next stop, up to
    /// `timeout` seconds; the stop is then `dbg.stop`.
    #[pyo3(signature = (line, timeout=None))]
    fn command(slf: &Bound<'_, Self>, line: &str, timeout: Option<f64>) -> PyResult<String> {
        runner::command(slf, line, timeout)
    }

    /// Resume without waiting, acknowledging the current exception as
    /// `handled` or `not_handled` (KD only).
    #[pyo3(signature = (disposition=Disposition(ContinueDisposition::Handled)))]
    fn cont(slf: &Bound<'_, Self>, disposition: Disposition) -> PyResult<()> {
        runcontrol::cont(slf, disposition.0)
    }

    /// Resume and wait for the next stop, auto-resuming past wrong-process and
    /// false-conditional hits. Returns the `Stop`, or `None` if the target is
    /// still running after `timeout` seconds.
    #[pyo3(signature = (timeout=None, *, disposition=Disposition(ContinueDisposition::Handled)))]
    fn run(
        slf: &Bound<'_, Self>,
        timeout: Option<f64>,
        disposition: Disposition,
    ) -> PyResult<Option<Py<Stop>>> {
        runcontrol::run(slf, timeout, disposition.0)
    }

    /// Wait for the next stop without resuming. Returns the current stop at
    /// once when already halted, `None` if still running after `timeout`.
    #[pyo3(signature = (timeout=None))]
    fn wait(slf: &Bound<'_, Self>, timeout: Option<f64>) -> PyResult<Option<Py<Stop>>> {
        runcontrol::wait(slf, timeout)
    }

    /// Run until `target` (an address, or a symbolic `module!name[+off]`) is
    /// reached (`g <addr>`), or with `step="over"`/`"into"` single-step there
    /// (`pa`/`ta`). Other stops en route are returned as they are; with
    /// `timeout`, an unreached target is interrupted where it is.
    #[pyo3(signature = (target, timeout=None, *, step=None))]
    fn run_to(
        slf: &Bound<'_, Self>,
        target: Location,
        timeout: Option<f64>,
        step: Option<StepMode>,
    ) -> PyResult<Option<Py<Stop>>> {
        runcontrol::run_to(slf, target, timeout, step.map(|StepMode(over)| over))
    }

    /// Single-step one instruction, or with `until` ("call", "ret", "branch")
    /// step into until the next such instruction (`tc`/`tt`/`th`).
    #[pyo3(signature = (until=None))]
    fn step(slf: &Bound<'_, Self>, until: Option<Until>) -> PyResult<Py<Stop>> {
        runcontrol::step(slf, until.map(|Until(flow)| flow))
    }

    /// Step over the current instruction, or with `until` step over until the
    /// next call/ret/branch (`pc`/`pt`/`ph`).
    #[pyo3(signature = (until=None))]
    fn step_over(slf: &Bound<'_, Self>, until: Option<Until>) -> PyResult<Py<Stop>> {
        runcontrol::step_over(slf, until.map(|Until(flow)| flow))
    }

    /// Run until the current function returns (`gu`).
    fn step_out(slf: &Bound<'_, Self>) -> PyResult<Py<Stop>> {
        runcontrol::step_out(slf)
    }

    /// Trace calls until the current function returns (`wt`), single-stepping
    /// at most `limit` instructions: `{end, error, instructions, root}`, where
    /// `root` is the call tree and `end` says why tracing stopped.
    #[pyo3(signature = (limit=10_000))]
    fn trace_calls<'py>(slf: &Bound<'py, Self>, limit: usize) -> PyResult<Bound<'py, Record>> {
        runcontrol::trace_calls(slf, limit)
    }

    /// Break into the running target and return the resulting stop.
    fn interrupt(slf: &Bound<'_, Self>) -> PyResult<Py<Stop>> {
        runcontrol::interrupt(slf)
    }

    /// Reboot the target (`.reboot`). The next stop is a `Stop.Reboot`.
    fn reboot(slf: &Bound<'_, Self>) -> PyResult<()> {
        runcontrol::reboot(slf)
    }

    /// Crash the target on purpose (`.crash`), producing a bugcheck stop.
    fn crash(slf: &Bound<'_, Self>) -> PyResult<()> {
        runcontrol::crash(slf)
    }

    /// Rebuild guest state now (rediscover the kernel). Stops already do this
    /// when the backend reports a reload; this forces it.
    fn reload(&self) -> PyResult<()> {
        self.with_session(|session| session.reload().map_err(err))
    }

    /// Write a full `PAGEDU64` kernel dump of the halted target to `path`
    /// (`.dump /f`). Returns the number of unreadable pages zero-filled.
    fn write_dump(&self, path: &str) -> PyResult<u64> {
        self.with_session(|session| {
            require_halted(session, "write_dump")?;
            if matches!(&*session.target.phys, PhysMem::Dmp(_)) {
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

    /// Captured guest debug output (DbgPrint) since sequence `since`:
    /// `{lines: [{seq, timestamp_ms, text}], next_seq, dropped}`. Pass the
    /// previous `next_seq` to poll only new lines.
    #[pyo3(signature = (since=0))]
    fn debug_log<'py>(&self, py: Python<'py>, since: u64) -> PyResult<Bound<'py, Record>> {
        let page = self.with_session(|session| Ok(session.read_debug_output(since)))?;
        view_record(py, &view::debug_log(&page))
    }

    /// Drain the diagnostics the debugger raised since the last call (a
    /// breakpoint that failed to re-arm, a reclaimed breakpoint slot, host
    /// memory that stopped matching after a reload).
    fn notices(&self) -> PyResult<Vec<String>> {
        self.with_session(|session| Ok(session.take_notices()))
    }

    /// Remove every breakpoint, leave the target running, and end the
    /// session: the connection and the target's single-instance lock are
    /// released, so the target can be attached again, and this debugger and
    /// its handles raise from then on. Closing again does nothing. On failure
    /// the target is left halted, the session stays open, and the error is
    /// raised. A borrowed (REPL command) debugger does not own the session
    /// and leaves it alone.
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
