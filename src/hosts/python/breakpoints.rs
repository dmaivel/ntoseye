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
use crate::arch::HwBreakpointAccess;
use crate::backend::dbg_backend::WatchpointAccess;
use crate::base::notice::Notice;
use crate::base::types::VirtAddr;
use crate::nt::breakpoints::{
    BreakpointConfig, BreakpointInfo, BreakpointManager, BreakpointScope, HypercallFilter,
};
use crate::nt::guest::hypercalls::hypercall_code;
use crate::nt::guest::vm_exits::{self, ExitFilter};
use crate::session::Session;
use crate::session::exception_policy::{ExceptionPolicy, ModuleEventPolicy};

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

    pub fn serial(&self) -> u64 {
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
    /// An instruction must start at the breakpoint, which ntoseye checks as
    /// `bp` and `bu` do: it raises `NtoseyeError` for an address inside an
    /// instruction, and when nothing says where instructions start there, it
    /// sets the breakpoint and adds a warning to `dbg.notices()`.
    /// `unchecked=True` skips the check (`bp /a`).
    ///
    /// `hardware=True` sets a debug-register execute breakpoint instead of
    /// patching code. The target resolves to an address once, when you call
    /// this method, and does not resolve again after a module reload or a
    /// reboot. The secure kernel (VTL1) accepts only this kind of breakpoint,
    /// for example `add(dbg.secure_kernel.symbols["securekernel!Func"],
    /// hardware=True)`.
    #[pyo3(signature = (target, *, condition=None, hardware=false, unchecked=false, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None))]
    fn add(
        &self,
        py: Python<'_>,
        target: Location,
        condition: Option<String>,
        hardware: bool,
        unchecked: bool,
        when: Option<WhenCallback>,
        pass_count: u64,
        one_shot: bool,
        process: Option<ProcessArg<'_>>,
        thread: Option<ThreadArg<'_>>,
        processor: Option<CpuArg<'_>>,
        action: Option<String>,
    ) -> PyResult<Breakpoint> {
        reject_condition_mutation()?;
        if hardware && unchecked {
            return Err(PyValueError::new_err(
                "unchecked applies to a software breakpoint, whose site must start an instruction",
            ));
        }
        let (mut config, callback) = build_config(
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
        config.unchecked = unchecked;
        let bp = self.owner.with(py, |session| {
            require_halted(session, "breakpoints.add")?;
            let dtb = BreakpointManager::resolution_dtb(&session.target, config.scope.as_ref());
            if hardware {
                let address = session
                    .resolve_in_breakpoint_scope(config.scope.as_ref(), |context| {
                        target.resolve(context)
                    })
                    .map_err(err)?;
                let id = session
                    .set_hardware_breakpoint(address, HwBreakpointAccess::Execute, 1, config)
                    .map_err(err)?;
                return created(session, id);
            }
            let set = match target {
                Location::Address(address) => session
                    .set_code_breakpoint(VirtAddr(address), config)
                    .map_err(err)?,
                Location::Symbol(spec) => {
                    // A spec whose module is loaded but which does not
                    // resolve is a typo, not a deferred breakpoint.
                    let module_loaded = spec.split_once('!').is_none_or(|(module, _)| {
                        session
                            .target
                            .symbols
                            .module_base_by_name(dtb, module)
                            .is_some()
                    });
                    let set = session
                        .set_symbolic_breakpoint(spec.clone(), config)
                        .map_err(err)?;
                    let resolved = session.breakpoint(set.id).is_some_and(|bp| bp.resolved);
                    if !resolved && module_loaded {
                        session.remove_breakpoint(set.id).map_err(err)?;
                        return Err(symbol_not_found(&spec));
                    }
                    set
                }
            };
            if let Some(warning) = set.warning {
                session.push_notice(Notice::warning(warning));
            }
            created(session, set.id)
        })?;
        store_condition(py, self.owner.dbg(), &bp, callback);
        Ok(handle(py, self.owner.dbg(), &bp))
    }

    /// Add symbol-identity breakpoints for the names that match a glob (`bm`).
    #[pyo3(signature = (pattern, *, condition=None, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None, limit=256))]
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
                .map(|id| created(session, id))
                .collect::<PyResult<Vec<_>>>()?;
            Ok((breakpoints, errors))
        })?;
        let installed = breakpoints.len();
        // The installed breakpoints stay on a partial failure, so they get
        // their `when=` callback before the error is raised.
        let handles = make_handles(py, self.owner.dbg(), breakpoints, callback.as_ref());
        if let Some(first) = errors.first() {
            return Err(raise(format!(
                "{} of {} matching symbols failed to install (first: {first})",
                errors.len(),
                errors.len() + installed
            )));
        }
        if handles.is_empty() {
            return Err(raise(format!("no code symbols match '{pattern}'")));
        }
        Ok(handles)
    }

    /// Add a source breakpoint at each address that matches `file:line`.
    #[pyo3(signature = (file, line, *, condition=None, when=None, pass_count=0, one_shot=false, process=None, thread=None, processor=None, action=None))]
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
                .map(|id| created(session, id))
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
            let address = session
                .resolve_in_breakpoint_scope(config.scope.as_ref(), |context| {
                    target.resolve(context)
                })
                .map_err(err)?;
            let id = session
                .set_hardware_breakpoint(address, access.into(), length, config)
                .map_err(err)?;
            created(session, id)
        })?;
        store_condition(py, self.owner.dbg(), &bp, callback);
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
            created(session, id)
        })?;
        store_condition(py, self.owner.dbg(), &bp, callback);
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
            created(session, id)
        })?;
        store_condition(py, self.owner.dbg(), &bp, callback);
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
                .get(&self.id)
                .is_some_and(|&(serial, _)| serial == self.serial)
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
                .edit()
                .set_pass_count(self.id, pass_count)
                .map_err(err)
        })
    }

    #[setter]
    fn set_one_shot(&self, py: Python<'_>, one_shot: bool) -> PyResult<()> {
        self.mutate(py, "breakpoint.one_shot", |session| {
            session
                .breakpoints
                .edit()
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
        if self.live(py)?.is_some() {
            self.mutate(py, "breakpoint.delete", |session| {
                session.remove_breakpoint(self.id).map_err(err)
            })?;
        }
        // A callback under this id belongs to a later breakpoint that reused
        // it, if its serial is not this one's.
        let mut conditions = self.owner.dbg().get().conditions.lock();
        if conditions
            .get(&self.id)
            .is_some_and(|&(serial, _)| serial == self.serial)
        {
            conditions.remove(&self.id);
        }
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

/// The breakpoint `id` a method just set.
fn created(session: &Session, id: u32) -> PyResult<BreakpointInfo> {
    session
        .breakpoint(id)
        .cloned()
        .ok_or_else(|| raise(format!("new breakpoint #{id} disappeared during creation")))
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

fn store_condition(
    py: Python<'_>,
    dbg: &Py<Debugger>,
    bp: &BreakpointInfo,
    callback: Option<Py<PyAny>>,
) {
    // A new breakpoint can reuse the id of one deleted outside the SDK
    // (`bc` through `command()`), whose `when=` must not carry over.
    let mut conditions = dbg.bind(py).get().conditions.lock();
    match callback {
        Some(callback) => conditions.insert(bp.id, (bp.serial, callback)),
        None => conditions.remove(&bp.id),
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
            store_condition(py, dbg, bp, callback.map(|value| value.clone_ref(py)));
            handle(py, dbg, bp)
        })
        .collect()
}
