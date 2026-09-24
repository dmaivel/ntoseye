//! Breakpoints and watchpoints (`dbg.breakpoints`) and exception stop
//! policies (`dbg.exceptions`).

use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;

use super::args::{
    CpuArg, Disposition, ExceptionCode, PolicyMode, ProcessArg, ThreadArg, WatchAccess,
    WhenCallback,
};
use super::handle::{Debugger, Owner, require_halted};
use super::iter::{BreakpointIterator, RecordIterator};
use super::process::Process;
use super::record::PlainDict;
use super::runcontrol::reject_condition_mutation;
use super::symbols::Location;
use super::thread::Thread;
use super::{err, raise, symbol_not_found, view_dict, view_record};
use crate::dbg_backend::WatchpointAccess;
use crate::exception_policy::{ExceptionPolicyFinalAction, parse_exception_code};
use crate::gdb::breakpoints::{Breakpoint as CoreBreakpoint, BreakpointConfig, BreakpointScope};
use crate::session::Session;
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};
use crate::view;

/// Code breakpoints and data watchpoints, keyed by id (`dbg.breakpoints`).
#[pyclass(module = "ntoseye")]
pub struct Breakpoints {
    pub owner: Owner,
}

impl Breakpoints {
    pub fn new(owner: Owner) -> Breakpoints {
        Breakpoints { owner }
    }

    fn snapshot(&self, py: Python<'_>) -> PyResult<Vec<CoreBreakpoint>> {
        self.owner.with(py, |session| {
            Ok(session.list_breakpoints().into_iter().cloned().collect())
        })
    }
}

/// Per-exception stop policies (`dbg.exceptions`, `sx*`).
#[pyclass(module = "ntoseye")]
pub struct Exceptions {
    pub owner: Owner,
}

impl Exceptions {
    pub fn new(owner: Owner) -> Exceptions {
        Exceptions { owner }
    }
}

/// A breakpoint handle. Breakpoints outlive target rebuilds (symbolic ones
/// re-resolve after a reboot), so the handle is not generation-stamped; it
/// goes invalid only when the breakpoint is deleted.
#[pyclass(subclass, module = "ntoseye")]
pub struct Breakpoint {
    owner: Owner,
    id: u32,
}

impl Breakpoint {
    fn snapshot(&self, py: Python<'_>) -> PyResult<Option<CoreBreakpoint>> {
        self.owner
            .with(py, |session| Ok(session.breakpoints.get(self.id).cloned()))
    }

    fn require_snapshot(&self, py: Python<'_>) -> PyResult<CoreBreakpoint> {
        self.snapshot(py)?
            .ok_or_else(|| invalid_breakpoint(self.id))
    }

    fn mutate(
        &self,
        py: Python<'_>,
        operation: &str,
        change: impl FnOnce(&mut Session) -> PyResult<()> + Send,
    ) -> PyResult<()> {
        reject_condition_mutation()?;
        self.owner.with(py, |session| {
            require_halted(session, operation)?;
            if session.breakpoints.get(self.id).is_none() {
                return Err(invalid_breakpoint(self.id));
            }
            change(session)
        })
    }
}

/// A hardware data watchpoint.
#[pyclass(extends = Breakpoint, module = "ntoseye")]
pub struct Watchpoint {
    access: String,
    length: u8,
}

#[pymethods]
impl Watchpoint {
    /// Data access type (`"write"` or `"read_write"`).
    #[getter]
    fn access(&self) -> &str {
        &self.access
    }

    /// Width of the watched memory access in bytes.
    #[getter]
    fn length(&self) -> u8 {
        self.length
    }
}

#[pymethods]
impl Breakpoints {
    /// Number of live breakpoints.
    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        Ok(self.snapshot(py)?.len())
    }

    /// Iterate a fresh snapshot of breakpoint handles.
    fn __iter__(&self, py: Python<'_>) -> PyResult<BreakpointIterator> {
        let items = self
            .snapshot(py)?
            .iter()
            .map(|bp| handle(py, self.owner.dbg(), bp))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(BreakpointIterator::new(items))
    }

    /// Look up a breakpoint id, raising `KeyError` when it is absent.
    fn __getitem__(&self, py: Python<'_>, id: u32) -> PyResult<Py<Breakpoint>> {
        self.get(py, id)?.ok_or_else(|| PyKeyError::new_err(id))
    }

    /// Look up a breakpoint id, returning `None` when it is absent.
    fn get(&self, py: Python<'_>, id: u32) -> PyResult<Option<Py<Breakpoint>>> {
        let Some(bp) = self
            .owner
            .with(py, |session| Ok(session.breakpoints.get(id).cloned()))?
        else {
            return Ok(None);
        };
        Ok(Some(handle(py, self.owner.dbg(), &bp)?))
    }

    fn __contains__(&self, py: Python<'_>, id: u32) -> PyResult<bool> {
        self.owner
            .with(py, |session| Ok(session.breakpoints.get(id).is_some()))
    }

    /// Add a code breakpoint at an address or symbolic spec.
    #[pyo3(signature = (target, condition=None, *, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None))]
    fn add(
        &self,
        py: Python<'_>,
        target: Location,
        condition: Option<String>,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        process: Option<ProcessArg<'_>>,
        thread: Option<ThreadArg<'_>>,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
    ) -> PyResult<Py<Breakpoint>> {
        reject_condition_mutation()?;
        let (config, callback) = build_config(
            py,
            &self.owner,
            condition,
            when,
            pass_count,
            one_shot,
            process,
            thread,
            processor,
            action,
        )?;
        let bp = self.owner.with(py, |session| {
            require_halted(session, "breakpoints.add")?;
            let id = match target {
                Location::Address(address) => session
                    .add_breakpoint(VirtAddr(address), None, config.clone())
                    .map_err(err)?,
                Location::Symbol(spec) => {
                    let id = session
                        .add_symbol_breakpoint(spec.clone(), config.clone())
                        .map_err(err)?;
                    let live = session.breakpoint(id).cloned();
                    let deferred_module = spec
                        .split_once('!')
                        .map(|(module, _)| {
                            let dtb = scope_dtb(&session.target, config.scope.as_ref());
                            session
                                .target
                                .symbols
                                .module_base_by_name(dtb, module)
                                .is_none()
                        })
                        .unwrap_or(false);
                    if live.as_ref().is_none_or(|bp| !bp.resolved) && !deferred_module {
                        session.remove_breakpoint(id).map_err(err)?;
                        return Err(symbol_not_found(&spec));
                    }
                    id
                }
            };
            session
                .breakpoint(id)
                .cloned()
                .ok_or_else(|| raise(format!("new breakpoint #{id} disappeared during creation")))
        })?;
        store_condition(py, self.owner.dbg(), bp.id, callback);
        handle(py, self.owner.dbg(), &bp)
    }

    /// Add symbol-identity breakpoints for matching glob names (`bm`).
    #[pyo3(signature = (pattern, condition=None, *, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None, limit=256))]
    fn add_pattern(
        &self,
        py: Python<'_>,
        pattern: &str,
        condition: Option<String>,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        process: Option<ProcessArg<'_>>,
        thread: Option<ThreadArg<'_>>,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
        limit: usize,
    ) -> PyResult<Vec<Py<Breakpoint>>> {
        reject_condition_mutation()?;
        let (config, callback) = build_config(
            py,
            &self.owner,
            condition,
            when,
            pass_count,
            one_shot,
            process,
            thread,
            processor,
            action,
        )?;
        let (breakpoints, errors) = self.owner.with(py, |session| {
            require_halted(session, "breakpoints.add_pattern")?;
            let (ids, errors) = session
                .add_pattern_breakpoints(pattern, config.clone(), limit.clamp(1, 4096))
                .map_err(err)?;
            let breakpoints = ids
                .into_iter()
                .map(|id| {
                    session
                        .breakpoints
                        .get(id)
                        .cloned()
                        .ok_or_else(|| raise(format!("new breakpoint #{id} disappeared")))
                })
                .collect::<PyResult<Vec<_>>>()?;
            Ok((breakpoints, errors))
        })?;
        if let Some(first) = errors.first() {
            return Err(raise(format!(
                "{} of {} matching symbols failed to install (first: {first})",
                errors.len(),
                errors.len() + breakpoints.len()
            )));
        }
        if breakpoints.is_empty() {
            return Err(raise(format!("no symbols match '{pattern}'")));
        }
        make_handles(py, self.owner.dbg(), breakpoints, callback.as_ref())
    }

    /// Add source breakpoints for every address matching `file:line`.
    #[pyo3(signature = (file, line, condition=None, *, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None))]
    fn add_source(
        &self,
        py: Python<'_>,
        file: &str,
        line: u32,
        condition: Option<String>,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        process: Option<ProcessArg<'_>>,
        thread: Option<ThreadArg<'_>>,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
    ) -> PyResult<Vec<Py<Breakpoint>>> {
        reject_condition_mutation()?;
        let source = format!("{file}:{line}");
        let (config, callback) = build_config(
            py,
            &self.owner,
            condition,
            when,
            pass_count,
            one_shot,
            process,
            thread,
            processor,
            action,
        )?;
        let breakpoints = self.owner.with(py, |session| {
            require_halted(session, "breakpoints.add_source")?;
            let ids = session
                .add_source_breakpoint(source, config.clone())
                .map_err(err)?;
            ids.into_iter()
                .map(|id| {
                    session
                        .breakpoints
                        .get(id)
                        .cloned()
                        .ok_or_else(|| raise(format!("new breakpoint #{id} disappeared")))
                })
                .collect::<PyResult<Vec<_>>>()
        })?;
        make_handles(py, self.owner.dbg(), breakpoints, callback.as_ref())
    }

    /// Add a hardware data watchpoint.
    #[pyo3(signature = (target, *, access=WatchAccess(WatchpointAccess::Write), length=1, condition=None, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None))]
    fn watch(
        &self,
        py: Python<'_>,
        target: Location,
        access: WatchAccess,
        length: u8,
        condition: Option<String>,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        process: Option<ProcessArg<'_>>,
        thread: Option<ThreadArg<'_>>,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
    ) -> PyResult<Py<Watchpoint>> {
        reject_condition_mutation()?;
        let WatchAccess(access) = access;
        let (config, callback) = build_config(
            py,
            &self.owner,
            condition,
            when,
            pass_count,
            one_shot,
            process,
            thread,
            processor,
            action,
        )?;
        let bp = self.owner.with(py, |session| {
            require_halted(session, "breakpoints.watch")?;
            let dtb = scope_dtb(&session.target, config.scope.as_ref());
            let address = target.resolve(session, dtb)?;
            let symbol = match target {
                Location::Symbol(spec) => Some(spec),
                Location::Address(_) => None,
            };
            let id = session
                .add_watchpoint(VirtAddr(address), access, length, symbol, config)
                .map_err(err)?;
            session
                .breakpoint(id)
                .cloned()
                .ok_or_else(|| raise(format!("new watchpoint #{id} disappeared during creation")))
        })?;
        store_condition(py, self.owner.dbg(), bp.id, callback);
        watchpoint_handle(py, self.owner.dbg(), &bp)?
            .ok_or_else(|| raise(format!("breakpoint #{} is not a watchpoint", bp.id)))
    }
}

#[pymethods]
impl Breakpoint {
    /// Stable breakpoint id.
    #[getter]
    fn id(&self, py: Python<'_>) -> PyResult<u32> {
        self.require_snapshot(py)?;
        Ok(self.id)
    }

    /// Address of the latest resolution.
    #[getter]
    fn address(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.require_snapshot(py)?.address.0)
    }

    /// Resolved display symbol, if known.
    #[getter]
    fn symbol(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self.require_snapshot(py)?.symbol)
    }

    /// Processor filter, if any.
    #[getter]
    fn processor(&self, py: Python<'_>) -> PyResult<Option<u16>> {
        Ok(self.require_snapshot(py)?.processor)
    }

    /// Number of physical hits.
    #[getter]
    fn hit_count(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.require_snapshot(py)?.hit_count)
    }

    /// Hits remaining before this breakpoint surfaces.
    #[getter]
    fn remaining_pass_count(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.require_snapshot(py)?.remaining_pass_count)
    }

    /// Optional command action (`do` in WinDbg).
    #[getter]
    fn action(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self.require_snapshot(py)?.action)
    }

    /// Whether this is a temporary run-to breakpoint.
    #[getter]
    fn temporary(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.require_snapshot(py)?.temporary)
    }

    /// Optional expression condition.
    #[getter]
    fn condition(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self.require_snapshot(py)?.condition)
    }

    /// Assigning an expression while a `when=` callback is attached raises
    /// `ValueError`, as passing both to `add()` does.
    #[setter]
    fn set_condition(&self, py: Python<'_>, condition: Option<String>) -> PyResult<()> {
        if condition.is_some()
            && self
                .owner
                .dbg()
                .get()
                .conditions
                .lock()
                .contains_key(&self.id)
        {
            return Err(PyValueError::new_err(
                "this breakpoint has a when= callback; condition and when are mutually exclusive",
            ));
        }
        self.mutate(py, "breakpoint.condition", |session| {
            session
                .set_breakpoint_condition(self.id, condition)
                .map_err(err)
        })
    }

    /// Requested hit count before surfacing.
    #[getter]
    fn pass_count(&self, py: Python<'_>) -> PyResult<u64> {
        Ok(self.require_snapshot(py)?.pass_count)
    }

    #[setter]
    fn set_pass_count(&self, py: Python<'_>, pass_count: u64) -> PyResult<()> {
        self.mutate(py, "breakpoint.pass_count", |session| {
            session
                .breakpoints
                .set_pass_count(self.id, pass_count)
                .map_err(err)
        })
    }

    /// Whether the breakpoint is removed after its first surfaced hit.
    #[getter]
    fn one_shot(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.require_snapshot(py)?.one_shot)
    }

    #[setter]
    fn set_one_shot(&self, py: Python<'_>, one_shot: bool) -> PyResult<()> {
        self.mutate(py, "breakpoint.one_shot", |session| {
            session
                .breakpoints
                .set_one_shot(self.id, one_shot)
                .map_err(err)
        })
    }

    /// Whether this breakpoint is enabled.
    #[getter]
    fn enabled(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.require_snapshot(py)?.enabled)
    }

    #[setter]
    fn set_enabled(&self, py: Python<'_>, enabled: bool) -> PyResult<()> {
        self.mutate(py, "breakpoint.enabled", |session| {
            if enabled {
                session.enable_breakpoint(self.id).map_err(err)
            } else {
                session.disable_breakpoint(self.id).map_err(err)
            }
        })
    }

    /// Symbol or source identity used to create this breakpoint.
    #[getter]
    fn specification(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self
            .require_snapshot(py)?
            .specification()
            .map(str::to_string))
    }

    /// Whether the site is armed at an address. A symbolic breakpoint whose
    /// module is not loaded yet stays unresolved until it loads.
    #[getter]
    fn resolved(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.require_snapshot(py)?.resolved)
    }

    /// Whether the breakpoint is still present in this session.
    #[getter]
    fn valid(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.snapshot(py)?.is_some())
    }

    /// Process restriction, if the breakpoint is process-scoped.
    #[getter]
    fn process(&self, py: Python<'_>) -> PyResult<Option<Process>> {
        let info = self.owner.with(py, |session| {
            let bp = session
                .breakpoints
                .get(self.id)
                .ok_or_else(|| invalid_breakpoint(self.id))?;
            let BreakpointScope::Process { pid, .. } = &bp.scope else {
                return Ok(None);
            };
            let info = session
                .target
                .guest()
                .map_err(err)?
                .enumerate_processes()
                .map_err(err)?
                .into_iter()
                .find(|process| process.pid == *pid);
            Ok(info)
        })?;
        Ok(info.map(|info| Process::from_owner(self.owner.derive(py), info)))
    }

    /// Windows thread restriction, if present.
    #[getter]
    fn thread(&self, py: Python<'_>) -> PyResult<Option<Thread>> {
        let info = self.owner.with(py, |session| {
            let bp = session
                .breakpoints
                .get(self.id)
                .ok_or_else(|| invalid_breakpoint(self.id))?;
            let Some(thread) = &bp.thread else {
                return Ok(None);
            };
            Ok(session.target.thread_info_from_ethread(thread.ethread).ok())
        })?;
        Ok(info.map(|info| Thread::from_owner(self.owner.derive(py), info)))
    }

    /// Remove this breakpoint.
    fn delete(&self, py: Python<'_>) -> PyResult<()> {
        self.mutate(py, "breakpoint.delete", |session| {
            session.remove_breakpoint(self.id).map_err(err)
        })?;
        self.owner.dbg().get().conditions.lock().remove(&self.id);
        Ok(())
    }

    /// The breakpoint's state as a plain `dict`, the shape MCP renders.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        view_dict(
            py,
            &view::execution::breakpoint(&self.require_snapshot(py)?),
        )
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        match self.snapshot(py)? {
            Some(bp) => Ok(format!(
                "<{} #{} {}{}>",
                if bp.watchpoint().is_some() {
                    "Watchpoint"
                } else {
                    "Breakpoint"
                },
                bp.id,
                bp.symbol.as_deref().unwrap_or(""),
                if bp.resolved {
                    format!(" at {:#x}", bp.address.0)
                } else {
                    " (deferred)".to_string()
                }
            )),
            None => Ok(format!("<Breakpoint #{} deleted>", self.id)),
        }
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other
            .extract::<PyRef<'_, Breakpoint>>()
            .is_ok_and(|other| self.owner.same_debugger(&other.owner) && self.id == other.id)
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(self.id)
    }
}

#[pymethods]
impl Exceptions {
    /// Configure an exception's stop policy (`sxe`/`sxd`/`sxn`/`sxi`).
    #[pyo3(signature = (code, mode, *, disposition=None))]
    fn set(
        &self,
        py: Python<'_>,
        code: ExceptionCode,
        mode: PolicyMode,
        disposition: Option<Disposition>,
    ) -> PyResult<()> {
        let code = exception_code(code)?;
        let PolicyMode(mode) = mode;
        let final_action = disposition
            .map(|Disposition(disposition)| ExceptionPolicyFinalAction::Continue(disposition));
        self.owner.with(py, |session| {
            session
                .exception_policies
                .set_with_options(code, mode, None, final_action);
            Ok(())
        })
    }

    /// Iterate configured exception-policy records.
    fn __iter__(&self, py: Python<'_>) -> PyResult<RecordIterator> {
        let rows = self.owner.with(py, |session| {
            Ok(session
                .exception_policies
                .entries()
                .map(|(code, policy)| view::execution::exception_policy(code, policy))
                .collect::<Vec<_>>())
        })?;
        let records = rows
            .iter()
            .map(|row| view_record(py, row).map(Bound::unbind))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(RecordIterator::new(records))
    }

    /// Number of configured policies.
    fn __len__(&self, py: Python<'_>) -> PyResult<usize> {
        self.owner.with(py, |session| {
            Ok(session.exception_policies.entries().count())
        })
    }

    /// Remove all configured policies; ordinary exceptions break by default.
    fn reset(&self, py: Python<'_>) -> PyResult<()> {
        self.owner.with(py, |session| {
            session.exception_policies.reset();
            Ok(())
        })
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!("<Exceptions {} configured>", self.__len__(py)?))
    }
}

/// The live handle for a core breakpoint: a `Breakpoint`, or a `Watchpoint`
/// for data watchpoints.
pub fn handle(py: Python<'_>, dbg: &Py<Debugger>, bp: &CoreBreakpoint) -> PyResult<Py<Breakpoint>> {
    match watchpoint_handle(py, dbg, bp)? {
        Some(watchpoint) => Ok(watchpoint.into_bound(py).into_super().unbind()),
        None => Py::new(
            py,
            Breakpoint {
                owner: Owner::unstamped(py, dbg),
                id: bp.id,
            },
        ),
    }
}

/// The `Watchpoint` handle for a data watchpoint; `None` for a code breakpoint.
fn watchpoint_handle(
    py: Python<'_>,
    dbg: &Py<Debugger>,
    bp: &CoreBreakpoint,
) -> PyResult<Option<Py<Watchpoint>>> {
    let Some((access, length)) = bp.watchpoint() else {
        return Ok(None);
    };
    let base = Breakpoint {
        owner: Owner::unstamped(py, dbg),
        id: bp.id,
    };
    let watchpoint = Watchpoint {
        access: access.name().to_string(),
        length,
    };
    Py::new(py, (watchpoint, base)).map(Some)
}

fn build_config(
    py: Python<'_>,
    owner: &Owner,
    condition: Option<String>,
    when: Option<WhenCallback>,
    pass_count: u64,
    one_shot: bool,
    process: Option<ProcessArg<'_>>,
    thread: Option<ThreadArg<'_>>,
    processor: Option<CpuArg<'_>>,
    action: Option<String>,
) -> PyResult<(BreakpointConfig, Option<Py<PyAny>>)> {
    if condition.is_some() && when.is_some() {
        return Err(PyValueError::new_err(
            "condition and when are mutually exclusive",
        ));
    }
    let callback = when.map(|WhenCallback(callback)| callback);
    let pid = process
        .map(|value| process_argument(py, owner, value))
        .transpose()?;
    let ethread = thread
        .map(|value| thread_argument(py, owner, value))
        .transpose()?;
    let processor = processor
        .map(|value| processor_argument(py, owner, value))
        .transpose()?;
    let mut config = BreakpointConfig {
        condition,
        pass_count,
        one_shot,
        action,
        ..BreakpointConfig::default()
    };
    owner.dbg().get().with_session(|session| {
        config.scope = pid
            .map(|pid| session.breakpoint_scope_for_pid(pid).map_err(err))
            .transpose()?;
        config.thread = ethread
            .map(|ethread| session.breakpoint_thread_for_ethread(ethread).map_err(err))
            .transpose()?;
        config.processor = processor;
        Ok(())
    })?;
    Ok((config, callback))
}

fn process_argument(py: Python<'_>, dbg: &Owner, value: ProcessArg<'_>) -> PyResult<u64> {
    match value {
        ProcessArg::Pid(pid) => Ok(pid),
        ProcessArg::Handle(process) => {
            process.owner.require_argument_of(py, dbg, "process")?;
            Ok(process.info.pid)
        }
    }
}

fn thread_argument(py: Python<'_>, dbg: &Owner, value: ThreadArg<'_>) -> PyResult<u64> {
    match value {
        ThreadArg::Ethread(ethread) => Ok(ethread),
        ThreadArg::Handle(thread) => {
            thread.owner.require_argument_of(py, dbg, "thread")?;
            Ok(thread.info.ethread.0)
        }
    }
}

fn processor_argument(py: Python<'_>, dbg: &Owner, value: CpuArg<'_>) -> PyResult<u16> {
    match value {
        CpuArg::Index(index) => Ok(index),
        CpuArg::Handle(cpu) => {
            cpu.owner.require_argument_of(py, dbg, "CPU")?;
            cpu.processor()
        }
    }
}

fn invalid_breakpoint(id: u32) -> pyo3::PyErr {
    raise(format!("breakpoint #{id} is no longer valid"))
}

fn scope_dtb(target: &Target, scope: Option<&BreakpointScope>) -> Dtb {
    match scope {
        Some(BreakpointScope::Process { dtb, .. }) => *dtb,
        Some(BreakpointScope::Kernel) => target.kernel_dtb(),
        None => target.current_dtb(),
    }
}

fn store_condition(py: Python<'_>, dbg: &Py<Debugger>, id: u32, callback: Option<Py<PyAny>>) {
    if let Some(callback) = callback {
        dbg.bind(py).get().conditions.lock().insert(id, callback);
    }
}

fn make_handles(
    py: Python<'_>,
    dbg: &Py<Debugger>,
    breakpoints: Vec<CoreBreakpoint>,
    callback: Option<&Py<PyAny>>,
) -> PyResult<Vec<Py<Breakpoint>>> {
    breakpoints
        .iter()
        .map(|bp| {
            store_condition(py, dbg, bp.id, callback.map(|value| value.clone_ref(py)));
            handle(py, dbg, bp)
        })
        .collect()
}

fn exception_code(code: ExceptionCode) -> PyResult<u32> {
    match code {
        ExceptionCode::Code(code) => u32::try_from(code).map_err(|_| {
            PyValueError::new_err(format!("exception code {code:#x} does not fit in 32 bits"))
        }),
        ExceptionCode::Alias(alias) => parse_exception_code(&alias).map_err(PyValueError::new_err),
    }
}
