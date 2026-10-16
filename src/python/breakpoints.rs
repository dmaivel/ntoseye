//! Breakpoints and watchpoints (`dbg.breakpoints`) and exception stop
//! policies (`dbg.exceptions`).

use ntoseye_macros::{collection, handle};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyAny;

use super::args::{CpuArg, HypercallArg, ProcessArg, ThreadArg, WhenCallback};
use super::command::{CommandHost, HostSession};
use super::handle::{Debugger, Owner, require_halted};
use super::process::Process;
use super::record::Typed;
use super::runcontrol::reject_condition_mutation;
use super::symbols::Location;
use super::thread::Thread;
use super::{err, raise, symbol_not_found};
use crate::breakpoints::{BreakpointConfig, BreakpointInfo, BreakpointScope, HypercallFilter};
use crate::dbg_backend::{HwBreakpointAccess, WatchpointAccess};
use crate::exception_policy::{ExceptionPolicy, ModuleEventPolicy};
use crate::guest::hypercalls::hypercall_code;
use crate::guest::vm_exits::{self, ExitFilter};
use crate::session::Session;
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};

/// The code breakpoints and data watchpoints, with their IDs as keys
/// (`dbg.breakpoints`).
#[pyclass(module = "ntoseye")]
pub struct Breakpoints {
    pub owner: Owner,
}

impl CommandHost for Breakpoints {
    fn session(&self) -> HostSession<'_> {
        HostSession::Owner(&self.owner)
    }
}

impl Breakpoints {
    pub fn new(owner: Owner) -> Breakpoints {
        Breakpoints { owner }
    }

    /// The handle of the listed breakpoint numbered `id`.
    fn listed(&self, py: Python<'_>, id: u32) -> PyResult<Option<Breakpoint>> {
        let serial = self.owner.with(py, |session| {
            Ok(session.breakpoints.listed(id).map(|bp| bp.serial))
        })?;
        Ok(serial.map(|serial| Breakpoint::new(py, self.owner.dbg(), id, serial)))
    }
}

/// The stop policy for each exception (`dbg.exceptions`, `sx*`).
#[pyclass(module = "ntoseye")]
pub struct Exceptions {
    pub owner: Owner,
}

impl CommandHost for Exceptions {
    fn session(&self) -> HostSession<'_> {
        HostSession::Owner(&self.owner)
    }
}

impl Exceptions {
    pub fn new(owner: Owner) -> Exceptions {
        Exceptions { owner }
    }
}

/// A breakpoint handle. Because a breakpoint stays when ntoseye builds the
/// target again, and a symbolic breakpoint resolves again after a reboot, the
/// handle has no generation stamp and becomes invalid only when the breakpoint
/// is deleted, or, for a one-shot breakpoint, once it fired. Its properties
/// are the breakpoint's state now, as `bl` lists it; a data watchpoint's
/// `watch_access` and `watch_length` say what it watches.
#[handle(
    record = BreakpointInfo,
    key = id,
    fetch = Breakpoint::snapshot,
    identity = Breakpoint::serial,
    impl
)]
pub struct Breakpoint {
    owner: Owner,
    id: u32,
    /// The core breakpoint's [`BreakpointInfo::serial`]: a later breakpoint
    /// that reuses `id` is not this one.
    serial: u64,
}

impl Breakpoint {
    fn new(py: Python<'_>, dbg: &Py<Debugger>, id: u32, serial: u64) -> Self {
        Breakpoint {
            owner: Owner::unstamped(py, dbg),
            id,
            serial,
        }
    }

    /// The breakpoint's ID, whether or not it still exists.
    pub fn raw_id(&self) -> u32 {
        self.id
    }

    fn serial(&self) -> u64 {
        self.serial
    }

    /// The breakpoint's state, or `None` once it is gone: deleted, or a
    /// one-shot breakpoint that fired.
    fn live(&self, py: Python<'_>) -> PyResult<Option<BreakpointInfo>> {
        self.owner.with(py, |session| {
            Ok(session.breakpoints.live(self.id, self.serial).cloned())
        })
    }

    fn snapshot(&self, py: Python<'_>) -> PyResult<BreakpointInfo> {
        self.live(py)?.ok_or_else(|| invalid_breakpoint(self.id))
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
            if session.breakpoints.live(self.id, self.serial).is_none() {
                return Err(invalid_breakpoint(self.id));
            }
            change(session)
        })
    }
}

#[collection]
impl Breakpoints {
    fn enumerate(&self, py: Python<'_>) -> PyResult<Vec<Breakpoint>> {
        let listed = self.owner.with(py, |session| {
            Ok(session
                .list_breakpoints()
                .into_iter()
                .map(|bp| (bp.id, bp.serial))
                .collect::<Vec<_>>())
        })?;
        Ok(listed
            .into_iter()
            .map(|(id, serial)| Breakpoint::new(py, self.owner.dbg(), id, serial))
            .collect())
    }

    /// The breakpoint with an ID.
    fn lookup(&self, py: Python<'_>, id: &u32) -> PyResult<Option<Breakpoint>> {
        self.listed(py, *id)
    }

    /// Add a code breakpoint at an address or a symbolic spec.
    ///
    /// `hardware=True` sets a debug-register execute breakpoint instead of
    /// patching code. The target resolves to an address once, when you call
    /// this method, and does not resolve again after a module reload or a
    /// reboot. The secure kernel (VTL1) accepts only this kind of breakpoint,
    /// for example `add(dbg.secure_kernel.symbols["securekernel!Func"],
    /// hardware=True)`.
    #[pyo3(signature = (target, condition=None, *, hardware=false, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None))]
    fn add(
        &self,
        py: Python<'_>,
        target: Location,
        condition: Option<String>,
        hardware: bool,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        process: Option<ProcessArg<'_>>,
        thread: Option<ThreadArg<'_>>,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
    ) -> PyResult<Breakpoint> {
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
                target if hardware => add_hardware_execute(session, target, config.clone())?,
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
        Ok(handle(py, self.owner.dbg(), &bp))
    }

    /// Add symbol-identity breakpoints for the names that match a glob (`bm`).
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
    ) -> PyResult<Vec<Breakpoint>> {
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
            let set = session
                .add_pattern_breakpoints(pattern, config.clone(), limit.clamp(1, 4096))
                .map_err(err)?;
            let errors = set.errors;
            let breakpoints = set
                .ids
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
            return Err(raise(format!("no code symbols match '{pattern}'")));
        }
        Ok(make_handles(
            py,
            self.owner.dbg(),
            breakpoints,
            callback.as_ref(),
        ))
    }

    /// Add a source breakpoint at each address that matches `file:line`.
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
    ) -> PyResult<Vec<Breakpoint>> {
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
        Ok(make_handles(
            py,
            self.owner.dbg(),
            breakpoints,
            callback.as_ref(),
        ))
    }

    /// Add a hardware data watchpoint.
    #[pyo3(signature = (target, *, access=WatchpointAccess::Write, length=1, condition=None, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None))]
    fn watch(
        &self,
        py: Python<'_>,
        target: Location,
        access: WatchpointAccess,
        length: u8,
        condition: Option<String>,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        process: Option<ProcessArg<'_>>,
        thread: Option<ThreadArg<'_>>,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
    ) -> PyResult<Breakpoint> {
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
        Ok(handle(py, self.owner.dbg(), &bp))
    }

    /// Add a hypercall breakpoint, as `!hvbp` does: a debug-register execute
    /// breakpoint on the Windows hypervisor's handler of `call`, a call code
    /// or a name (`"HvCallPostMessage"`, or `"HvCall0004"` as `x hv!*` names
    /// a code the TLFS does not), that stops only when the caller made that
    /// call, and, with `partition` (a partition ID) and `vp` (a VP index in
    /// it), only when the caller is that partition or VP. ntoseye resumes
    /// the other hits without a stop, before any `when=` callback runs. A
    /// hit whose caller ntoseye cannot tell stops. A `condition` sees the
    /// caller's registers at its VMCALL (`"rdx == 0xfb"`), not the
    /// hypervisor's at the handler, and reads the caller's memory: the `$p`
    /// operators its guest physical memory (`"$pqwo(rdx+8) == 1"` tests a
    /// slow call's input), the others its virtual memory. Needs the gdb
    /// backend and the VM's hv-evmcs enlightenment. This feature is
    /// experimental.
    #[pyo3(signature = (call, partition=None, vp=None, *, condition=None, when=None, pass_count=0, one_shot=false, processor=None, action=None))]
    fn add_hypercall(
        &self,
        py: Python<'_>,
        call: HypercallArg,
        partition: Option<u64>,
        vp: Option<u32>,
        condition: Option<String>,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
    ) -> PyResult<Breakpoint> {
        reject_condition_mutation()?;
        let code = match call {
            HypercallArg::Code(code) => code,
            HypercallArg::Name(name) => hypercall_code(&name)
                .ok_or_else(|| PyValueError::new_err(format!("unknown hypercall {name:?}")))?,
        };
        let (config, callback) = build_config(
            py,
            &self.owner,
            condition,
            when,
            pass_count,
            one_shot,
            None,
            None,
            processor,
            action,
        )?;
        let filter = HypercallFilter {
            code,
            partition,
            vp,
        };
        let bp = self.owner.with(py, |session| {
            require_halted(session, "breakpoints.add_hypercall")?;
            let id = session
                .add_hypercall_breakpoint(filter, config)
                .map_err(err)?;
            session
                .breakpoint(id)
                .cloned()
                .ok_or_else(|| raise(format!("new breakpoint #{id} disappeared during creation")))
        })?;
        store_condition(py, self.owner.dbg(), bp.id, callback);
        Ok(handle(py, self.owner.dbg(), &bp))
    }

    /// Add a VM-exit breakpoint, as `!hvexit` does: a debug-register execute
    /// breakpoint on the Windows hypervisor's VM-exit entry point that stops
    /// only for an exit with basic exit `reason` (Intel SDM Appendix C), a
    /// number or a name (`"cpuid"`, `"rdmsr"`, `"ept_violation"`), and, with
    /// `partition` and `vp`, only from that partition or VP. Every exit
    /// enters there, so the guest runs far slower while it is set; ntoseye
    /// resumes the other exits without a stop, before any `when=` callback
    /// runs. A hit whose caller or exit ntoseye cannot tell stops. A
    /// `condition` sees the caller's registers at its exit and reads its
    /// memory, as for `add_hypercall()`. Needs the gdb backend and the VM's
    /// hv-evmcs enlightenment. This feature is experimental.
    #[pyo3(signature = (reason, partition=None, vp=None, *, condition=None, when=None, pass_count=0, one_shot=false, processor=None, action=None))]
    fn add_exit(
        &self,
        py: Python<'_>,
        reason: HypercallArg,
        partition: Option<u64>,
        vp: Option<u32>,
        condition: Option<String>,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
    ) -> PyResult<Breakpoint> {
        reject_condition_mutation()?;
        let reason = match reason {
            HypercallArg::Code(reason) => reason,
            HypercallArg::Name(name) => vm_exits::parse_reason(&name)
                .map_err(|error| PyValueError::new_err(error.to_string()))?,
        };
        let (config, callback) = build_config(
            py,
            &self.owner,
            condition,
            when,
            pass_count,
            one_shot,
            None,
            None,
            processor,
            action,
        )?;
        let filter = ExitFilter {
            reason,
            partition,
            vp,
        };
        let bp = self.owner.with(py, |session| {
            require_halted(session, "breakpoints.add_exit")?;
            let id = session.add_exit_breakpoint(filter, config).map_err(err)?;
            session
                .breakpoint(id)
                .cloned()
                .ok_or_else(|| raise(format!("new breakpoint #{id} disappeared during creation")))
        })?;
        store_condition(py, self.owner.dbg(), bp.id, callback);
        Ok(handle(py, self.owner.dbg(), &bp))
    }
}

#[handle]
impl Breakpoint {
    /// The breakpoint's ID, which `bl` and `dbg.breakpoints` use; readable
    /// after the breakpoint is gone.
    #[getter]
    fn id(&self) -> u32 {
        self.id
    }

    /// Assigning an expression raises `ValueError` while a `when=` callback is
    /// attached, and `add()` also raises it if you give both.
    #[setter]
    fn set_condition(&self, py: Python<'_>, condition: Option<String>) -> PyResult<()> {
        self.snapshot(py)?;
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

    #[setter]
    fn set_pass_count(&self, py: Python<'_>, pass_count: u64) -> PyResult<()> {
        self.mutate(py, "breakpoint.pass_count", |session| {
            session
                .breakpoints
                .set_pass_count(self.id, pass_count)
                .map_err(err)
        })
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

    /// True while the breakpoint exists in this session: False once it is
    /// deleted, and for a one-shot breakpoint once its hit stopped the
    /// target. The other properties raise `NtoseyeError` once it is False.
    #[getter]
    fn valid(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.live(py)?.is_some())
    }

    /// The process restriction, if the breakpoint has a process scope.
    #[getter]
    fn process(&self, py: Python<'_>) -> PyResult<Option<Process>> {
        let info = self.owner.with(py, |session| {
            let bp = session
                .breakpoints
                .live(self.id, self.serial)
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

    /// The Windows thread restriction, if any.
    #[getter]
    fn thread(&self, py: Python<'_>) -> PyResult<Option<Thread>> {
        let info = self.owner.with(py, |session| {
            let bp = session
                .breakpoints
                .live(self.id, self.serial)
                .ok_or_else(|| invalid_breakpoint(self.id))?;
            let Some(thread) = &bp.thread else {
                return Ok(None);
            };
            Ok(session.target.thread_info_from_ethread(thread.ethread).ok())
        })?;
        Ok(info.map(|info| Thread::from_owner(self.owner.derive(py), info)))
    }

    /// Remove this breakpoint. A breakpoint that is already gone, deleted or
    /// a one-shot breakpoint whose hit stopped the target, is left as it is,
    /// so deleting after the hit works.
    fn delete(&self, py: Python<'_>) -> PyResult<()> {
        if self.live(py)?.is_none() {
            // The id's `when=` callback belongs to whichever breakpoint now
            // holds the id, if one does.
            let reused = self.owner.with(py, |session| {
                Ok(session.breakpoints.listed(self.id).is_some())
            })?;
            if !reused {
                self.owner.dbg().get().conditions.lock().remove(&self.id);
            }
            return Ok(());
        }
        self.mutate(py, "breakpoint.delete", |session| {
            session.remove_breakpoint(self.id).map_err(err)
        })?;
        self.owner.dbg().get().conditions.lock().remove(&self.id);
        Ok(())
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        match self.live(py)? {
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
}

#[collection]
impl Exceptions {
    fn enumerate<'py>(&self, py: Python<'py>) -> PyResult<Vec<Typed<'py, ExceptionPolicy>>> {
        let rows = self.owner.with(py, |session| {
            Ok(session
                .exception_policies
                .entries()
                .cloned()
                .collect::<Vec<_>>())
        })?;
        rows.into_iter().map(|row| Typed::new(py, row)).collect()
    }

    /// The module load and unload filters (`sx* ld[:<module>]` and
    /// `sx* ud[:<module>]`), in the order that you set them. Iterating over
    /// `dbg.exceptions` gives only the exception policies.
    #[getter]
    fn module_events<'py>(&self, py: Python<'py>) -> PyResult<Typed<'py, Vec<ModuleEventPolicy>>> {
        let rows = self.owner.with(py, |session| {
            Ok(session
                .exception_policies
                .module_event_entries()
                .cloned()
                .collect::<Vec<_>>())
        })?;
        Typed::new(py, rows)
    }

    /// Remove all configured policies and module load and unload filters, so
    /// ordinary exceptions break by default and module loads and unloads do
    /// not stop.
    fn reset(&self, py: Python<'_>) -> PyResult<()> {
        self.owner.with(py, |session| {
            session.exception_policies.reset();
            Ok(())
        })
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        Ok(format!(
            "<Exceptions {} configured>",
            self.enumerate(py)?.len()
        ))
    }
}

/// The handle of a core breakpoint.
fn handle(py: Python<'_>, dbg: &Py<Debugger>, bp: &BreakpointInfo) -> Breakpoint {
    Breakpoint::new(py, dbg, bp.id, bp.serial)
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
    // The session runs an action when the hit surfaces, before a `when=`
    // callback could decline it; the callback can act itself.
    if action.is_some() && when.is_some() {
        return Err(PyValueError::new_err(
            "action and when are mutually exclusive; act in the when callback",
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

/// Arm a one-byte debug-register execute breakpoint at `target`, resolved in
/// the breakpoint's scope. A hardware site is an address, not a symbol
/// identity, so a spec is kept only as its display symbol. Set in a
/// partition view, it is the partition's (see
/// [`Session::add_hardware_breakpoint`]).
fn add_hardware_execute(
    session: &mut Session,
    target: Location,
    config: BreakpointConfig,
) -> PyResult<u32> {
    let dtb = scope_dtb(&session.target, config.scope.as_ref());
    let address = target.resolve(session, dtb)?;
    let symbol = match target {
        Location::Symbol(spec) => Some(spec),
        Location::Address(_) => None,
    };
    session
        .add_hardware_breakpoint(
            VirtAddr(address),
            HwBreakpointAccess::Execute,
            1,
            symbol,
            config,
        )
        .map_err(err)
}

fn store_condition(py: Python<'_>, dbg: &Py<Debugger>, id: u32, callback: Option<Py<PyAny>>) {
    // A new breakpoint can reuse the id of one deleted outside the SDK
    // (`bc` through `command()`), whose `when=` must not carry over.
    let mut conditions = dbg.bind(py).get().conditions.lock();
    match callback {
        Some(callback) => conditions.insert(id, callback),
        None => conditions.remove(&id),
    };
}

fn make_handles(
    py: Python<'_>,
    dbg: &Py<Debugger>,
    breakpoints: Vec<BreakpointInfo>,
    callback: Option<&Py<PyAny>>,
) -> Vec<Breakpoint> {
    breakpoints
        .iter()
        .map(|bp| {
            store_condition(py, dbg, bp.id, callback.map(|value| value.clone_ref(py)));
            handle(py, dbg, bp)
        })
        .collect()
}
