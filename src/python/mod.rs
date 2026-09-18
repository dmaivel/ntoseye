use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pyo3::IntoPyObjectExt;
use pyo3::class::basic::CompareOp;
use pyo3::exceptions::{PyAttributeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyList};

use record::{Diagnostic, Record};

use crate::backend::MemoryOps;
use crate::bugchecks::{analyze_bugcheck, bugcheck_from_dump_info, current_bugcheck};
use crate::dbg_backend::{ContinueDisposition, WatchpointAccess};
use crate::dump_writer::{collect_dump_metadata, write_kernel_dump};
use crate::error::Error;
use crate::exception_policy::{
    ExceptionPolicyFinalAction, ExceptionPolicyMode, exception_alias, parse_exception_code,
};
use crate::expr::Expr;
use crate::gdb::breakpoints::{Breakpoint as CoreBreakpoint, BreakpointConfig};
use crate::guest::ProcessInfo;
use crate::kd::KdMemorySource;
use crate::output;
use crate::phys::PhysMem;
use crate::repl::ReplState;
use crate::session::{ContinueOutcome, Session, processor_index_from_backend_thread_id};
use crate::symbols::{
    FieldValue, ParsedType, TypeInfo, le_uint, parse_source_paths, parse_symbol_sources,
};
use crate::target::MemorySearchMatch as CoreMemorySearchMatch;
use crate::target::cpu::parse_msr_name;
use crate::target::heap::HeapSelector;
use crate::target::meta::decode_error_code;
use crate::target::mm::{AddressModule as CoreAddressModule, MemoryRegionInfo};
use crate::target::mm::{PfnSelector, PoolType, PoolUsageSort};
use crate::target::sched::ApcSelector;
use crate::target::{SelectedFrame, ThreadInfo};
use crate::trapframe::read_ktrap_frame_at_or_current;
use crate::triage_report::TriageReport;
use crate::types::VirtAddr;
use crate::view::{self, View};
use crate::{Backend, TargetSpec};

pub mod embed;
pub mod record;

/// Cancel flag for the SDK's blocking waits: Python drives them in bounded
/// slices and checks for `KeyboardInterrupt` between them, so the in-loop
/// flag never needs to fire.
static NEVER_CANCEL: AtomicBool = AtomicBool::new(false);

/// Sanity caps for the raw byte APIs. The SDK is local and trusted, but an
/// accidental huge length (a typo like `read(addr, 10**12)`) would allocate
/// before the read and OOM the interpreter; reject it as a clean error instead.
const MAX_READ_LEN: usize = 1 << 28; // 256 MiB
const MAX_SEARCH_LEN: usize = 1 << 30; // 1 GiB scanned per call

// Typed exception hierarchy: an `NtoseyeError` base plus a `MemoryAccessError`
// subclass, so introspection loops can `except MemoryAccessError: continue` on
// unmapped pages without swallowing real bugs.
pyo3::create_exception!(_ntoseye, NtoseyeError, pyo3::exceptions::PyException);
pyo3::create_exception!(_ntoseye, MemoryAccessError, NtoseyeError);

/// Map a core debugger error to a Python exception: the memory-access fault
/// cluster becomes `MemoryAccessError`, everything else `NtoseyeError`. Used by
/// the `.map_err(err)` call sites whose source is the core `Error`.
fn err(e: Error) -> PyErr {
    let msg = e.to_string();
    match e {
        Error::BadVirtualAddress(_)
        | Error::AddressNotInDump(_)
        | Error::BadPhysicalAddress(_)
        | Error::PartialRead(_)
        | Error::PartialWrite(_)
        | Error::BufferNotEnough
        | Error::InvalidRange => MemoryAccessError::new_err(msg),
        _ => NtoseyeError::new_err(msg),
    }
}

/// Raise an `NtoseyeError` from a message (SDK-level errors, not core faults).
fn raise(msg: impl std::fmt::Display) -> PyErr {
    NtoseyeError::new_err(msg.to_string())
}

/// Decode an inline C string buffer (a CHAR/UCHAR array, e.g.
/// `_EPROCESS.ImageFileName`) to a `String`: cut at the first NUL and map each
/// byte to a codepoint (latin-1, lossless, process names are ANSI, not UTF-8).
fn decode_c_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf[..end].iter().map(|&b| b as char).collect()
}

/// Walk an intrusive `_LIST_ENTRY` from `head` (the list-head address),
/// returning each record's base (`link_addr - link_offset`). Thin wrapper over
/// the shared core walk ([`crate::target::Target::walk_list`]) so the SDK and
/// the engine can't diverge.
fn walk_list_bases(dbg: &Debugger, head: u64, link_offset: u64) -> PyResult<Vec<u64>> {
    dbg.inner
        .target
        .walk_list(VirtAddr(head), link_offset)
        .map_err(err)
}

/// Render a neutral [`view::View`] object into a [`Record`] (the shared shape
/// with the MCP surface; here addresses come through as ints, there as hex).
fn view_record<'py>(py: Python<'py>, v: &view::View) -> PyResult<Bound<'py, Record>> {
    view::to_py(py, v)?
        .cast_into::<Record>()
        .map_err(|e| raise(e.to_string()))
}

/// Render a neutral [`view::View`] list into a Python `list`.
fn view_list<'py>(py: Python<'py>, v: &view::View) -> PyResult<Bound<'py, PyList>> {
    view::to_py(py, v)?
        .cast_into::<PyList>()
        .map_err(|e| raise(e.to_string()))
}

fn breakpoint_id_arg(value: &Bound<'_, PyAny>, session_id: usize) -> PyResult<u32> {
    if let Ok(bp) = value.extract::<PyRef<'_, Breakpoint>>() {
        if bp.session_id != session_id {
            return Err(raise(
                "breakpoint handle belongs to a different debugger session",
            ));
        }
        return Ok(bp.id());
    }
    value
        .extract::<u32>()
        .map_err(|_| PyTypeError::new_err("expected a breakpoint id or ntoseye.Breakpoint handle"))
}

fn breakpoint_target_arg(
    dbg: &Debugger,
    target: &Bound<'_, PyAny>,
) -> PyResult<(u64, Option<String>)> {
    if let Ok(addr) = target.extract::<u64>() {
        return Ok((addr, None));
    }
    if let Ok(expr) = target.extract::<String>() {
        let addr = Expr::eval(&expr, &dbg.inner.target).map_err(err)?.0;
        return Ok((addr, Some(expr)));
    }
    Err(PyTypeError::new_err(
        "expected a breakpoint address or debugger expression",
    ))
}

/// The breakpoint options every `breakpoint()`/`watchpoint()` form shares,
/// mapped onto the core [`BreakpointConfig`] (`bp /1 /p <pid> <target>
/// <passes> if <cond> do <action>`).
fn breakpoint_config_arg(
    dbg: &Debugger,
    condition: Option<String>,
    pass_count: u64,
    one_shot: bool,
    process: Option<u64>,
    action: Option<String>,
) -> PyResult<BreakpointConfig> {
    let scope = process
        .map(|pid| dbg.inner.breakpoint_scope_for_pid(pid))
        .transpose()
        .map_err(err)?;
    Ok(BreakpointConfig {
        condition,
        condition_expr: None,
        pass_count,
        one_shot,
        action,
        scope,
        skip_prologue: false,
    })
}

/// An exception code argument: an NTSTATUS int, or a WinDbg alias / numeric
/// string (`"av"`, `"0xc0000005"`).
fn exception_code_arg(value: &Bound<'_, PyAny>) -> PyResult<u32> {
    if let Ok(code) = value.extract::<u64>() {
        return u32::try_from(code)
            .map_err(|_| raise(format!("exception code {code:#x} does not fit in 32 bits")));
    }
    let text: String = value
        .extract()
        .map_err(|_| PyTypeError::new_err("expected an exception code (int) or alias (str)"))?;
    parse_exception_code(&text).map_err(raise)
}

/// An MSR argument: a number or an `IA32_*`/`MSR_*` name.
fn msr_arg(value: &Bound<'_, PyAny>) -> PyResult<u32> {
    if let Ok(number) = value.extract::<u64>() {
        return u32::try_from(number)
            .map_err(|_| raise(format!("MSR {number:#x} does not fit in 32 bits")));
    }
    let text: String = value
        .extract()
        .map_err(|_| PyTypeError::new_err("expected an MSR number or IA32_* name"))?;
    parse_msr_name(&text).ok_or_else(|| raise(format!("unknown MSR name '{text}'")))
}

fn selected_frame_record<'py>(
    py: Python<'py>,
    frame: &SelectedFrame,
) -> PyResult<Bound<'py, Record>> {
    view_record(
        py,
        &View::Object(vec![
            ("index", View::Num(frame.index as u64)),
            ("ip", View::Hex(frame.ip)),
            ("sp", View::Hex(frame.sp)),
        ]),
    )
}

/// A live debugging session. `unsendable`: the session is single-threaded.
/// An owned session's single-instance lock is released on drop, not `close()`;
/// a borrowed handle holds no lock.
#[pyclass(unsendable)]
pub struct Debugger {
    inner: SessionHandle,
}

/// The `Session` a [`Debugger`] drives: one it owns (from [`attach`]) or one it
/// borrows for the duration of a REPL command ([`Debugger::from_session_ref`]).
enum SessionHandle {
    Owned(Box<Session>),
    /// A session owned by the REPL. The pointer is only valid while `valid`
    /// reads true; the dispatcher flips it false when the command returns, so a
    /// stashed handle panics instead of dereferencing a dangling session.
    Borrowed {
        ptr: NonNull<Session>,
        valid: Arc<AtomicBool>,
    },
}

impl SessionHandle {
    fn is_owned(&self) -> bool {
        matches!(self, SessionHandle::Owned(_))
    }
}

/// Panic message when a borrowed handle is used after its command returned.
const STALE_BORROW: &str = "ntoseye: use of a Debugger (or a Struct/Type derived from it) after the REPL command \
     that created it returned; borrowed handles are valid only inside that command and must \
     not be stashed across calls";

impl Deref for SessionHandle {
    type Target = Session;
    fn deref(&self) -> &Session {
        match self {
            SessionHandle::Owned(s) => s,
            // SAFETY: `valid` is true only while the dispatcher's borrow is live
            // (it flips false on return, before the REPL touches the session
            // again), so a true reading means the pointee outlives this access.
            SessionHandle::Borrowed { ptr, valid } => {
                assert!(valid.load(Ordering::Relaxed), "{STALE_BORROW}");
                unsafe { ptr.as_ref() }
            }
        }
    }
}

impl DerefMut for SessionHandle {
    fn deref_mut(&mut self) -> &mut Session {
        match self {
            SessionHandle::Owned(s) => s,
            // SAFETY: as above; the &mut is unaliased because pyo3 hands out the
            // owning `Debugger` under the GIL, one call at a time, and the borrow
            // is single-threaded for the command's duration.
            SessionHandle::Borrowed { ptr, valid } => {
                assert!(valid.load(Ordering::Relaxed), "{STALE_BORROW}");
                unsafe { ptr.as_mut() }
            }
        }
    }
}

#[derive(Clone)]
struct BreakpointSnapshot {
    id: u32,
    address: Option<u64>,
    enabled: bool,
    resolved: bool,
    deferred: bool,
    specification: Option<String>,
    symbol: Option<String>,
    scope: String,
    condition: Option<String>,
    pass_count: u64,
    hit_count: u64,
    remaining_pass_count: u64,
    one_shot: bool,
    action: Option<String>,
    temporary: bool,
    watch_access: Option<String>,
    watch_length: Option<u8>,
}

impl BreakpointSnapshot {
    fn from_core(bp: &CoreBreakpoint) -> Self {
        Self {
            id: bp.id,
            address: bp.resolved_address().map(|address| address.0),
            enabled: bp.enabled,
            resolved: bp.resolved,
            deferred: bp.deferred(),
            specification: bp.specification().map(str::to_string),
            symbol: bp.symbol.clone(),
            scope: bp.scope.label(),
            condition: bp.condition.clone(),
            pass_count: bp.pass_count,
            hit_count: bp.hit_count,
            remaining_pass_count: bp.remaining_pass_count,
            one_shot: bp.one_shot,
            action: bp.action.clone(),
            temporary: bp.temporary,
            watch_access: bp.watch_access_name().map(str::to_string),
            watch_length: bp.watch_length(),
        }
    }

    /// What a stop can still report about a breakpoint the manager no longer
    /// holds (a one-shot/temporary site removed at the hit).
    fn placeholder(id: u32, address: u64, symbol: Option<String>, temporary: bool) -> Self {
        Self {
            id,
            address: Some(address),
            enabled: true,
            resolved: true,
            deferred: false,
            specification: None,
            symbol,
            scope: "unknown".to_string(),
            condition: None,
            pass_count: 0,
            hit_count: 0,
            remaining_pass_count: 0,
            one_shot: false,
            action: None,
            temporary,
            watch_access: None,
            watch_length: None,
        }
    }
}

/// A live code-breakpoint or data-watchpoint handle. Equality is debugger
/// session + stop-point id, so a handle returned from `dbg.breakpoint(...)`
/// compares equal to the handle surfaced later in `outcome.breakpoints`.
#[pyclass(unsendable)]
pub struct Breakpoint {
    dbg: Option<Py<Debugger>>,
    session_id: usize,
    snapshot: BreakpointSnapshot,
}

impl Breakpoint {
    fn live_snapshot(&self, py: Python<'_>) -> Option<BreakpointSnapshot> {
        let dbg = self.dbg.as_ref()?.borrow(py);
        if dbg.session_id() != self.session_id {
            return None;
        }
        dbg.inner
            .breakpoint(self.snapshot.id)
            .map(BreakpointSnapshot::from_core)
    }
    /// Read from the live breakpoint when the session still has it, else from
    /// the snapshot taken at install.
    fn with_current<T>(&self, py: Python<'_>, read: impl FnOnce(&BreakpointSnapshot) -> T) -> T {
        match self.live_snapshot(py) {
            Some(live) => read(&live),
            None => read(&self.snapshot),
        }
    }

    fn require_live_debugger<'py>(&'py self, py: Python<'py>) -> PyResult<PyRefMut<'py, Debugger>> {
        let Some(dbg) = &self.dbg else {
            return Err(raise(
                "breakpoint handle is not attached to a live debugger",
            ));
        };
        let dbg = dbg.borrow_mut(py);
        if dbg.session_id() != self.session_id {
            return Err(raise(
                "breakpoint handle belongs to a different debugger session",
            ));
        }
        Ok(dbg)
    }
}

#[pymethods]
impl Breakpoint {
    #[getter]
    fn id(&self) -> u32 {
        self.snapshot.id
    }

    #[getter]
    fn address(&self, py: Python<'_>) -> Option<u64> {
        self.with_current(py, |bp| bp.address)
    }

    #[getter]
    fn symbol(&self, py: Python<'_>) -> Option<String> {
        self.with_current(py, |bp| bp.symbol.clone())
    }

    #[getter]
    fn scope(&self, py: Python<'_>) -> String {
        self.with_current(py, |bp| bp.scope.clone())
    }

    #[getter]
    fn condition(&self, py: Python<'_>) -> Option<String> {
        self.with_current(py, |bp| bp.condition.clone())
    }

    #[getter]
    fn resolved(&self, py: Python<'_>) -> bool {
        self.with_current(py, |bp| bp.resolved)
    }

    #[getter]
    fn deferred(&self, py: Python<'_>) -> bool {
        self.with_current(py, |bp| bp.deferred)
    }

    #[getter]
    fn specification(&self, py: Python<'_>) -> Option<String> {
        self.with_current(py, |bp| bp.specification.clone())
    }

    #[getter]
    fn pass_count(&self, py: Python<'_>) -> u64 {
        self.with_current(py, |bp| bp.pass_count)
    }

    #[getter]
    fn hit_count(&self, py: Python<'_>) -> u64 {
        self.with_current(py, |bp| bp.hit_count)
    }

    #[getter]
    fn remaining_pass_count(&self, py: Python<'_>) -> u64 {
        self.with_current(py, |bp| bp.remaining_pass_count)
    }

    #[getter]
    fn one_shot(&self, py: Python<'_>) -> bool {
        self.with_current(py, |bp| bp.one_shot)
    }

    #[getter]
    fn action(&self, py: Python<'_>) -> Option<String> {
        self.with_current(py, |bp| bp.action.clone())
    }

    #[getter]
    fn temporary(&self, py: Python<'_>) -> bool {
        self.with_current(py, |bp| bp.temporary)
    }

    /// Whether this stop point watches data access rather than code execution.
    #[getter]
    fn watchpoint(&self, py: Python<'_>) -> bool {
        self.with_current(py, |bp| bp.watch_access.is_some())
    }

    /// Watched access (`"write"` or `"read_write"`), or `None` for a code breakpoint.
    #[getter]
    fn watch_access(&self, py: Python<'_>) -> Option<String> {
        self.with_current(py, |bp| bp.watch_access.clone())
    }

    /// Watched byte width, or `None` for a code breakpoint.
    #[getter]
    fn watch_length(&self, py: Python<'_>) -> Option<u8> {
        self.with_current(py, |bp| bp.watch_length)
    }

    #[getter]
    fn valid(&self, py: Python<'_>) -> bool {
        self.live_snapshot(py).is_some()
    }

    fn is_valid(&self, py: Python<'_>) -> bool {
        self.valid(py)
    }

    #[getter]
    fn enabled(&self, py: Python<'_>) -> bool {
        self.live_snapshot(py).map(|bp| bp.enabled).unwrap_or(false)
    }

    #[setter]
    fn set_enabled(&self, py: Python<'_>, enabled: bool) -> PyResult<()> {
        if enabled {
            self.enable(py)
        } else {
            self.disable(py)
        }
    }

    /// Replace the break condition (`None` clears it), like `bpc`. Takes
    /// effect at the next hit; no target write is involved.
    #[setter]
    fn set_condition(&self, py: Python<'_>, condition: Option<String>) -> PyResult<()> {
        let mut dbg = self.require_live_debugger(py)?;
        dbg.inner
            .set_breakpoint_condition(self.snapshot.id, condition)
            .map_err(err)
    }

    /// Reset the pass count (`bpp`): the hit number to break on; 0 and 1
    /// both break on the next hit. GDB calls this the ignore count.
    #[setter]
    fn set_pass_count(&self, py: Python<'_>, pass_count: u64) -> PyResult<()> {
        let mut dbg = self.require_live_debugger(py)?;
        dbg.inner
            .breakpoints
            .set_pass_count(self.snapshot.id, pass_count)
            .map_err(err)
    }

    /// Set or clear the REPL command string run at each hit (`bs`). A
    /// trailing `gc` continues after it; scripts that own the loop usually
    /// inspect the `StopOutcome` instead.
    #[setter]
    fn set_action(&self, py: Python<'_>, action: Option<String>) -> PyResult<()> {
        let mut dbg = self.require_live_debugger(py)?;
        dbg.inner
            .breakpoints
            .set_action(self.snapshot.id, action)
            .map_err(err)
    }

    /// Make the breakpoint clear itself after its next reported hit (`/1`).
    #[setter]
    fn set_one_shot(&self, py: Python<'_>, one_shot: bool) -> PyResult<()> {
        let mut dbg = self.require_live_debugger(py)?;
        dbg.inner
            .breakpoints
            .set_one_shot(self.snapshot.id, one_shot)
            .map_err(err)
    }

    /// Remove this breakpoint from the target.
    fn clear(&self, py: Python<'_>) -> PyResult<()> {
        let mut dbg = self.require_live_debugger(py)?;
        dbg.require_halted("breakpoint.clear")?;
        dbg.inner.remove_breakpoint(self.snapshot.id).map_err(err)
    }

    /// Alias for `clear()`, matching GDB's breakpoint object vocabulary.
    fn delete(&self, py: Python<'_>) -> PyResult<()> {
        self.clear(py)
    }

    /// Re-enable this breakpoint.
    fn enable(&self, py: Python<'_>) -> PyResult<()> {
        let mut dbg = self.require_live_debugger(py)?;
        dbg.require_halted("breakpoint.enable")?;
        dbg.inner.enable_breakpoint(self.snapshot.id).map_err(err)
    }

    /// Disable this breakpoint without deleting it.
    fn disable(&self, py: Python<'_>) -> PyResult<()> {
        let mut dbg = self.require_live_debugger(py)?;
        dbg.require_halted("breakpoint.disable")?;
        dbg.inner.disable_breakpoint(self.snapshot.id).map_err(err)
    }

    /// The canonical breakpoint state. `address` is `None` while a symbolic or
    /// source breakpoint is deferred; `resolved` distinguishes that state from
    /// a deliberately disabled breakpoint.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let enabled = self.enabled(py);
        self.with_current(py, |snapshot| {
            let d = PyDict::new(py);
            d.set_item("id", snapshot.id)?;
            d.set_item("address", snapshot.address)?;
            d.set_item("enabled", enabled)?;
            d.set_item("resolved", snapshot.resolved)?;
            d.set_item("deferred", snapshot.deferred)?;
            d.set_item("specification", &snapshot.specification)?;
            d.set_item("symbol", &snapshot.symbol)?;
            d.set_item("scope", &snapshot.scope)?;
            d.set_item("condition", &snapshot.condition)?;
            d.set_item("pass_count", snapshot.pass_count)?;
            d.set_item("hit_count", snapshot.hit_count)?;
            d.set_item("remaining_pass_count", snapshot.remaining_pass_count)?;
            d.set_item("one_shot", snapshot.one_shot)?;
            d.set_item("action", &snapshot.action)?;
            d.set_item("temporary", snapshot.temporary)?;
            d.set_item("watchpoint", snapshot.watch_access.is_some())?;
            d.set_item("watch_access", &snapshot.watch_access)?;
            d.set_item("watch_length", snapshot.watch_length)?;
            Ok(d)
        })
    }

    fn __richcmp__(&self, other: PyRef<'_, Breakpoint>, op: CompareOp) -> bool {
        let equal = self.session_id == other.session_id && self.snapshot.id == other.snapshot.id;
        match op {
            CompareOp::Eq => equal,
            CompareOp::Ne => !equal,
            _ => false,
        }
    }

    fn __hash__(&self) -> isize {
        (self.session_id as isize).wrapping_mul(31) ^ self.snapshot.id as isize
    }

    fn __repr__(&self, py: Python<'_>) -> String {
        let state = if self.valid(py) { "valid" } else { "invalid" };
        self.with_current(py, |snapshot| {
            let kind = if snapshot.watch_access.is_some() {
                "Watchpoint"
            } else {
                "Breakpoint"
            };
            let location = snapshot
                .address
                .map(|address| format!("at {address:#x}"))
                .unwrap_or_else(|| "deferred".to_string());
            let symbol = snapshot
                .symbol
                .as_ref()
                .map(|symbol| format!(" {symbol}"))
                .unwrap_or_default();
            format!("<{kind} #{} {location}{symbol} {state}>", snapshot.id)
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum StopKind {
    Breakpoint,
    Watchpoint,
    Bugcheck,
    Exception,
    Step,
    TargetReloaded,
    #[default]
    Running,
    Halted,
}

impl StopKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Breakpoint => "breakpoint",
            Self::Watchpoint => "watchpoint",
            Self::Bugcheck => "bugcheck",
            Self::Exception => "exception",
            Self::Step => "step",
            Self::TargetReloaded => "target_reloaded",
            Self::Running => "running",
            Self::Halted => "halted",
        }
    }
}

/// Everything a [`StopOutcome`] can report; each stop kind fills only the
/// fields that apply and leaves the rest at their `None` default.
#[derive(Default)]
struct StopOutcomeData {
    kind: StopKind,
    rip: Option<u64>,
    symbol: Option<String>,
    attached_process: Option<ProcessInfo>,
    stopped_process: Option<ProcessInfo>,
    stopped_thread: Option<ThreadInfo>,
    breakpoints: Vec<BreakpointSnapshot>,
    address: Option<u64>,
    temporary: Option<bool>,
    condition_error: Option<String>,
    exception_code: Option<u32>,
    first_chance: Option<bool>,
    exception_address: Option<u64>,
    bugcheck_info: Option<Py<PyAny>>,
    kernel_base: Option<u64>,
    coherent: Option<bool>,
}

/// The result of `run()`, `wait_for_stop()`, `step_over()`, or `step_out()`.
/// Use predicate properties for control flow (`running`, `bugcheck`,
/// `target_reloaded`) and `breakpoints` for breakpoint identity.
#[pyclass(unsendable)]
pub struct StopOutcome {
    dbg: Py<Debugger>,
    session_id: usize,
    data: StopOutcomeData,
}

impl StopOutcome {
    fn breakpoint_handles(&self, py: Python<'_>) -> Vec<Breakpoint> {
        self.data
            .breakpoints
            .iter()
            .cloned()
            .map(|snapshot| Breakpoint {
                dbg: Some(self.dbg.clone_ref(py)),
                session_id: self.session_id,
                snapshot,
            })
            .collect()
    }
}

/// Module context for a structured memory-search hit.
#[pyclass(unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct AddressModule {
    name: String,
    base: u64,
    size: u32,
    offset: u64,
}

impl From<CoreAddressModule> for AddressModule {
    fn from(module: CoreAddressModule) -> Self {
        Self {
            name: module.name,
            base: module.base.0,
            size: module.size,
            offset: module.offset,
        }
    }
}

#[pymethods]
impl AddressModule {
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn base(&self) -> u64 {
        self.base
    }

    #[getter]
    fn size(&self) -> u32 {
        self.size
    }

    #[getter]
    fn offset(&self) -> u64 {
        self.offset
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("name", &self.name)?;
        d.set_item("base", self.base)?;
        d.set_item("size", self.size)?;
        d.set_item("offset", self.offset)?;
        Ok(d)
    }

    fn __repr__(&self) -> String {
        format!("<AddressModule {} base={:#x}>", self.name, self.base)
    }
}

/// VAD/context region for a structured memory-search hit.
#[pyclass(unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct MemoryRegion {
    start: u64,
    end: u64,
    protection: Option<u64>,
    vad_type: Option<u64>,
    private_memory: Option<bool>,
    commit_charge: Option<u64>,
    details: Option<String>,
}

impl From<MemoryRegionInfo> for MemoryRegion {
    fn from(region: MemoryRegionInfo) -> Self {
        Self {
            start: region.start.0,
            end: region.end.0,
            protection: region.protection,
            vad_type: region.vad_type,
            private_memory: region.private_memory,
            commit_charge: region.commit_charge,
            details: region.details,
        }
    }
}

#[pymethods]
impl MemoryRegion {
    #[getter]
    fn start(&self) -> u64 {
        self.start
    }

    #[getter]
    fn end(&self) -> u64 {
        self.end
    }

    #[getter]
    fn protection(&self) -> Option<u64> {
        self.protection
    }

    #[getter]
    fn vad_type(&self) -> Option<u64> {
        self.vad_type
    }

    #[getter]
    fn private_memory(&self) -> Option<bool> {
        self.private_memory
    }

    #[getter]
    fn commit_charge(&self) -> Option<u64> {
        self.commit_charge
    }

    #[getter]
    fn details(&self) -> Option<String> {
        self.details.clone()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("start", self.start)?;
        d.set_item("end", self.end)?;
        d.set_item("protection", self.protection)?;
        d.set_item("vad_type", self.vad_type)?;
        d.set_item("private_memory", self.private_memory)?;
        d.set_item("commit_charge", self.commit_charge)?;
        d.set_item("details", self.details.clone())?;
        Ok(d)
    }

    fn __repr__(&self) -> String {
        format!("<MemoryRegion {:#x}..{:#x}>", self.start, self.end)
    }
}

/// A memory-search hit with symbol and location context.
#[pyclass(unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct MemorySearchMatch {
    address: u64,
    offset: u64,
    symbol: Option<String>,
    kind: String,
    module: Option<AddressModule>,
    section: Option<String>,
    va_type: Option<String>,
    region: Option<MemoryRegion>,
}

impl MemorySearchMatch {
    fn from_core(hit: CoreMemorySearchMatch) -> Self {
        Self {
            address: hit.address.0,
            offset: hit.offset,
            symbol: hit.symbol,
            kind: hit.description.kind.to_string(),
            module: hit.description.module.map(AddressModule::from),
            section: hit.description.section,
            va_type: hit.description.va_type,
            region: hit.description.region.map(MemoryRegion::from),
        }
    }
}

#[pymethods]
impl MemorySearchMatch {
    #[getter]
    fn address(&self) -> u64 {
        self.address
    }

    #[getter]
    fn offset(&self) -> u64 {
        self.offset
    }

    #[getter]
    fn symbol(&self) -> Option<String> {
        self.symbol.clone()
    }

    #[getter]
    fn kind(&self) -> &str {
        &self.kind
    }

    #[getter]
    fn module(&self) -> Option<AddressModule> {
        self.module.clone()
    }

    #[getter]
    fn section(&self) -> Option<String> {
        self.section.clone()
    }

    #[getter]
    fn va_type(&self) -> Option<String> {
        self.va_type.clone()
    }

    #[getter]
    fn region(&self) -> Option<MemoryRegion> {
        self.region.clone()
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("address", self.address)?;
        d.set_item("offset", self.offset)?;
        d.set_item("symbol", self.symbol.clone())?;
        d.set_item("kind", &self.kind)?;
        if let Some(module) = &self.module {
            d.set_item("module", module.to_dict(py)?)?;
        } else {
            d.set_item("module", py.None())?;
        }
        d.set_item("section", self.section.clone())?;
        d.set_item("va_type", self.va_type.clone())?;
        if let Some(region) = &self.region {
            d.set_item("region", region.to_dict(py)?)?;
        } else {
            d.set_item("region", py.None())?;
        }
        Ok(d)
    }

    fn __repr__(&self) -> String {
        match &self.symbol {
            Some(symbol) => format!("<MemorySearchMatch {:#x} {}>", self.address, symbol),
            None => format!("<MemorySearchMatch {:#x}>", self.address),
        }
    }
}

#[pymethods]
impl StopOutcome {
    #[getter]
    fn reason(&self) -> &'static str {
        self.data.kind.as_str()
    }

    #[getter]
    fn running(&self) -> bool {
        self.data.kind == StopKind::Running
    }

    #[getter]
    fn breakpoint_stop(&self) -> bool {
        matches!(self.data.kind, StopKind::Breakpoint | StopKind::Watchpoint)
    }

    #[getter]
    fn watchpoint(&self) -> bool {
        self.data.kind == StopKind::Watchpoint
    }

    #[getter]
    fn exception(&self) -> bool {
        self.data.kind == StopKind::Exception
    }

    #[getter]
    fn step(&self) -> bool {
        self.data.kind == StopKind::Step
    }

    #[getter]
    fn bugcheck(&self) -> bool {
        self.data.kind == StopKind::Bugcheck
    }

    #[getter]
    fn target_reloaded(&self) -> bool {
        self.data.kind == StopKind::TargetReloaded
    }

    #[getter]
    fn halted(&self) -> bool {
        self.data.kind == StopKind::Halted
    }

    #[getter]
    fn terminal(&self) -> bool {
        self.bugcheck() || self.target_reloaded()
    }

    #[getter]
    fn rip(&self) -> Option<u64> {
        self.data.rip
    }

    #[getter]
    fn symbol(&self) -> Option<String> {
        self.data.symbol.clone()
    }

    /// The inspection scope at the stop as `{pid, name, dtb, eprocess}`, or
    /// `None` in the kernel context. This is the operator's selection
    /// (`.process`) and persists across resumes, so it is not necessarily what
    /// the guest was executing: for that, see `stopped_process`.
    #[getter]
    fn attached_process<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        self.data
            .attached_process
            .as_ref()
            .map(|p| view_record(py, &view::process(p)))
            .transpose()
    }

    /// The process whose page tables the stopped vCPU had loaded, as
    /// `{pid, name, dtb, eprocess}`. Resolved from CR3 at the stop.
    #[getter]
    fn stopped_process<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        self.data
            .stopped_process
            .as_ref()
            .map(|p| view_record(py, &view::process(p)))
            .transpose()
    }

    /// The Windows thread the stopped vCPU was running, walked from its KPRCB.
    /// Its owner can differ from `stopped_process` when the thread is attached
    /// to another address space.
    #[getter]
    fn stopped_thread<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        self.data
            .stopped_thread
            .as_ref()
            .map(|t| view_record(py, &view::thread(t, None)))
            .transpose()
    }

    #[getter]
    fn breakpoints(&self, py: Python<'_>) -> Vec<Breakpoint> {
        self.breakpoint_handles(py)
    }

    #[getter]
    fn breakpoint(&self, py: Python<'_>) -> Option<Breakpoint> {
        self.breakpoint_handles(py).into_iter().next()
    }

    #[getter]
    fn breakpoint_ids(&self) -> Vec<u32> {
        self.data.breakpoints.iter().map(|bp| bp.id).collect()
    }

    #[getter]
    fn breakpoint_id(&self) -> Option<u32> {
        self.data.breakpoints.first().map(|bp| bp.id)
    }

    #[getter]
    fn address(&self) -> Option<u64> {
        self.data.address
    }

    #[getter]
    fn temporary(&self) -> Option<bool> {
        self.data.temporary
    }

    /// Error from evaluating a breakpoint/watchpoint condition. Such a stop is
    /// surfaced rather than silently skipped.
    #[getter]
    fn condition_error(&self) -> Option<String> {
        self.data.condition_error.clone()
    }

    #[getter]
    fn exception_code(&self) -> Option<u32> {
        self.data.exception_code
    }

    /// Whether this was the exception's first debugger notification.
    #[getter]
    fn first_chance(&self) -> Option<bool> {
        self.data.first_chance
    }

    #[getter]
    fn exception_address(&self) -> Option<u64> {
        self.data.exception_address
    }

    #[getter]
    fn bugcheck_info(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.data
            .bugcheck_info
            .as_ref()
            .map(|info| info.clone_ref(py))
    }

    #[getter]
    fn kernel_base(&self) -> Option<u64> {
        self.data.kernel_base
    }

    #[getter]
    fn coherent(&self) -> Option<bool> {
        self.data.coherent
    }

    fn __repr__(&self) -> String {
        match self.data.rip {
            Some(rip) => format!("<StopOutcome {} rip={:#x}>", self.reason(), rip),
            None => format!("<StopOutcome {}>", self.reason()),
        }
    }
}

#[pymethods]
impl Debugger {
    /// Read `len` bytes of guest virtual memory from the current address space.
    /// Our own breakpoint `int3` bytes are masked back to the original code, so a
    /// script sees the same bytes as `read_memory` over MCP and our `disassemble`.
    fn read<'py>(&self, py: Python<'py>, addr: u64, len: usize) -> PyResult<Bound<'py, PyBytes>> {
        if len > MAX_READ_LEN {
            return Err(raise(format!(
                "read length {len} exceeds cap {MAX_READ_LEN} (0x{MAX_READ_LEN:x})"
            )));
        }
        let mut buf = vec![0u8; len];
        self.inner
            .read_masked(VirtAddr(addr), &mut buf)
            .map_err(err)?;
        Ok(PyBytes::new(py, &buf))
    }

    /// Search `length` bytes starting at `start` for a byte `pattern`; returns
    /// the addresses of all (overlapping) matches.
    fn search(&self, start: u64, pattern: &[u8], length: usize) -> PyResult<Vec<u64>> {
        if length > MAX_SEARCH_LEN {
            return Err(raise(format!(
                "search length {length} exceeds cap {MAX_SEARCH_LEN} (0x{MAX_SEARCH_LEN:x})"
            )));
        }
        self.inner
            .target
            .search(VirtAddr(start), pattern, length)
            .map_err(err)
    }

    /// Search memory and return typed rows with address, offset, nearest symbol,
    /// and module/region context. `search` is the cheaper address-only variant.
    fn search_details(
        &self,
        start: u64,
        pattern: &[u8],
        length: usize,
    ) -> PyResult<Vec<MemorySearchMatch>> {
        if length > MAX_SEARCH_LEN {
            return Err(raise(format!(
                "search length {length} exceeds cap {MAX_SEARCH_LEN} (0x{MAX_SEARCH_LEN:x})"
            )));
        }
        self.inner
            .target
            .search_details(VirtAddr(start), pattern, length)
            .map(|matches| {
                matches
                    .into_iter()
                    .map(MemorySearchMatch::from_core)
                    .collect()
            })
            .map_err(err)
    }

    /// Write bytes to guest virtual memory. Works while the guest runs (writes go
    /// through the hypervisor's RAM mapping, like reads); `interrupt()` first only
    /// if the guest may be concurrently touching the same bytes (torn write).
    fn write(&self, addr: u64, data: &[u8]) -> PyResult<()> {
        self.inner
            .target
            .current_process()
            .map_err(err)?
            .memory()
            .write_bytes(VirtAddr(addr), data)
            .map_err(err)
    }

    fn read_u8(&self, addr: u64) -> PyResult<u8> {
        Ok(self.read_fixed::<1>(addr)?[0])
    }

    fn read_u16(&self, addr: u64) -> PyResult<u16> {
        Ok(u16::from_le_bytes(self.read_fixed::<2>(addr)?))
    }

    fn read_u32(&self, addr: u64) -> PyResult<u32> {
        Ok(u32::from_le_bytes(self.read_fixed::<4>(addr)?))
    }

    fn read_u64(&self, addr: u64) -> PyResult<u64> {
        Ok(u64::from_le_bytes(self.read_fixed::<8>(addr)?))
    }

    /// Write a little-endian integer (typed counterparts to `write`, so scripts
    /// don't pack bytes themselves).
    fn write_u8(&self, addr: u64, value: u8) -> PyResult<()> {
        self.write(addr, &value.to_le_bytes())
    }

    fn write_u16(&self, addr: u64, value: u16) -> PyResult<()> {
        self.write(addr, &value.to_le_bytes())
    }

    fn write_u32(&self, addr: u64, value: u32) -> PyResult<()> {
        self.write(addr, &value.to_le_bytes())
    }

    fn write_u64(&self, addr: u64, value: u64) -> PyResult<()> {
        self.write(addr, &value.to_le_bytes())
    }

    /// The target's pointer width in bytes (`$ptrsize`): 8, both supported
    /// architectures are LP64. 32-bit WOW64 layouts are read through their
    /// own `ntdll32!` types, whose pointer fields are 4 bytes.
    #[getter]
    fn pointer_size(&self) -> u64 {
        8
    }

    /// Read a pointer-sized value at `addr` (`poi`).
    fn read_pointer(&self, addr: u64) -> PyResult<u64> {
        self.read_u64(addr)
    }

    /// Read a NUL-terminated ANSI string at `addr` (`da`), at most `max_len`
    /// bytes.
    #[pyo3(signature = (addr, max_len=256))]
    fn read_string(&self, addr: u64, max_len: usize) -> PyResult<String> {
        self.inner
            .target
            .read_c_string(VirtAddr(addr), max_len)
            .map_err(err)
    }

    /// Read a NUL-terminated UTF-16 string at `addr` (`du`), at most
    /// `max_len` characters.
    #[pyo3(signature = (addr, max_len=256))]
    fn read_wstring(&self, addr: u64, max_len: usize) -> PyResult<String> {
        let mut units = Vec::with_capacity(max_len.min(256));
        let mut cursor = addr;
        while units.len() < max_len {
            let unit = self.read_u16(cursor)?;
            if unit == 0 {
                break;
            }
            units.push(unit);
            cursor += 2;
        }
        Ok(String::from_utf16_lossy(&units))
    }

    /// Decode the `_UNICODE_STRING` descriptor at `addr` (`dS`).
    fn read_unicode_string(&self, addr: u64) -> PyResult<String> {
        self.inner
            .target
            .read_unicode_string(VirtAddr(addr))
            .map_err(err)
    }

    /// Decode the `_STRING`/`ANSI_STRING` descriptor at `addr` (`ds`).
    fn read_ansi_string(&self, addr: u64) -> PyResult<String> {
        let length = self.read_u16(addr)?;
        let buffer = self.read_pointer(addr + 8)?;
        if length == 0 || buffer == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; usize::from(length)];
        self.inner
            .read_masked(VirtAddr(buffer), &mut buf)
            .map_err(err)?;
        Ok(buf.iter().map(|&b| b as char).collect())
    }

    /// Evaluate a debugger expression (symbols, registers, arithmetic) to an
    /// address/integer.
    fn eval(&self, expr: &str) -> PyResult<u64> {
        Expr::eval(expr, &self.inner.target)
            .map(|v| v.0)
            .map_err(err)
    }

    /// Read a single register by name from the current thread context. Requires
    /// the VM halted (a running guest has no coherent register file).
    fn read_register(&mut self, name: &str) -> PyResult<u64> {
        self.require_halted("read_register")?;
        let regs = self.inner.read_registers().map_err(err)?;
        self.inner.register_map.read_u64(name, &regs).map_err(err)
    }

    /// Read all registers as a `{name: value}` dict. Requires the VM halted (a
    /// running guest has no coherent register file).
    fn registers(&mut self) -> PyResult<HashMap<String, u64>> {
        self.require_halted("registers")?;
        let regs = self.inner.read_registers().map_err(err)?;
        Ok(self.inner.register_map.to_hashmap(&regs))
    }

    /// Set a single register on the current thread (read-modify-write of the
    /// register file). Halt the VM first (`interrupt()` or be stopped at a
    /// breakpoint); a running guest has no coherent register file to patch.
    fn write_register(&mut self, name: &str, value: u64) -> PyResult<()> {
        self.require_halted("write_register")?;
        self.inner.write_register(name, value).map_err(err)
    }

    /// Resume the VM with an explicit exception acknowledgment. `not_handled`
    /// requires native transport support (currently KD). Steps past a
    /// breakpoint at RIP first and re-arms breakpoints.
    #[pyo3(signature = (disposition = "handled"))]
    fn cont(&mut self, disposition: &str) -> PyResult<()> {
        let disposition = disposition.parse::<ContinueDisposition>().map_err(err)?;
        self.inner.resume_with_disposition(disposition).map_err(err)
    }

    /// Wait for the next stop WITHOUT resuming, up to `timeout_ms` (None blocks,
    /// polling for KeyboardInterrupt between 1s slices). Returns a
    /// [`StopOutcome`]. Since it does not resume, a VM already halted at a stop
    /// is reported in place; use `cont()` (or `run()`) to advance.
    #[pyo3(signature = (timeout_ms=None))]
    fn wait_for_stop<'py>(
        slf: Bound<'py, Self>,
        py: Python<'py>,
        timeout_ms: Option<u64>,
    ) -> PyResult<StopOutcome> {
        Self::stop_outcome(slf, py, |dbg| match timeout_ms {
            Some(ms) => dbg
                .inner
                .wait_for_stop_bounded(Some(Duration::from_millis(ms)), &NEVER_CANCEL)
                .map_err(err),
            None => Self::wait_until_stop(py, |slice| {
                dbg.inner
                    .wait_for_stop_bounded(Some(slice), &NEVER_CANCEL)
                    .map_err(err)
            }),
        })
    }

    /// Resume the VM and wait for the next meaningful stop, returning a
    /// [`StopOutcome`].
    ///
    /// This is the scope-aware run-control loop shared with the REPL and MCP: it
    /// silently steps over and resumes past wrong-process int3 hits (a breakpoint
    /// scoped to one process whose `int3` lives on a shared page) and false
    /// conditional breakpoints, so only the relevant hit surfaces. A condition
    /// evaluation error surfaces the stop with [`StopOutcome::condition_error`].
    /// With `timeout_ms` it returns an outcome with `running` true if nothing
    /// stopped in that window (poll again); with `timeout_ms=None` it blocks until
    /// a stop, checking for Ctrl+C between polls.
    /// `not_handled` requires native transport support (currently KD).
    #[pyo3(signature = (timeout_ms=None, *, disposition = "handled"))]
    fn run<'py>(
        slf: Bound<'py, Self>,
        py: Python<'py>,
        timeout_ms: Option<u64>,
        disposition: &str,
    ) -> PyResult<StopOutcome> {
        let disposition = disposition.parse::<ContinueDisposition>().map_err(err)?;
        Self::stop_outcome(slf, py, |dbg| match timeout_ms {
            Some(ms) => dbg
                .inner
                .continue_until_break(Some(Duration::from_millis(ms)), &NEVER_CANCEL, disposition)
                .map_err(err),
            None => Self::wait_until_stop(py, |slice| {
                dbg.inner
                    .continue_until_break(Some(slice), &NEVER_CANCEL, disposition)
                    .map_err(err)
            }),
        })
    }

    /// Single-step one instruction (issues the step, waits for the stop, clears
    /// the trap flag, re-arms breakpoints, and re-selects the stopped thread).
    /// Returns a [`StopOutcome`] (a `step` stop at the landed-on instruction),
    /// matching `step_over()`/`step_out()`. Requires the VM halted.
    fn step<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<StopOutcome> {
        Self::stop_outcome(slf, py, |dbg| {
            dbg.require_halted("step")?;
            dbg.inner.step().map_err(err)?;
            let regs = dbg.inner.read_registers().map_err(err)?;
            let rip = dbg.inner.register_map.read_u64("rip", &regs).map_err(err)?;
            Ok(ContinueOutcome::Step { rip })
        })
    }

    /// Step over the current instruction: if it's a `call`, run to its return
    /// site, otherwise single-step. Blocks until the step completes (or a
    /// breakpoint/bugcheck/exception is hit en route). Returns a
    /// [`StopOutcome`]. Requires the VM halted (`interrupt()` first, or be at a
    /// breakpoint).
    fn step_over<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<StopOutcome> {
        Self::stop_outcome(slf, py, |dbg| {
            dbg.require_halted("step_over")?;
            dbg.inner.step_over(&NEVER_CANCEL).map_err(err)
        })
    }

    /// Step out of the current function: run to the caller's return address.
    /// Blocks until reached (or a breakpoint/bugcheck/exception en route).
    /// Returns a [`StopOutcome`]. Requires the VM halted.
    fn step_out<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<StopOutcome> {
        Self::stop_outcome(slf, py, |dbg| {
            dbg.require_halted("step_out")?;
            dbg.inner.step_out(&NEVER_CANCEL).map_err(err)
        })
    }

    /// Pause the VM, adopting the stopped thread as the current one.
    fn interrupt(&mut self) -> PyResult<()> {
        self.inner.interrupt().map(|_| ()).map_err(err)
    }

    /// Make `addr` resident by asking the guest's debugger worker to fault it
    /// in (`.pagein`). `process` is an `EPROCESS` the worker attaches to
    /// first, which user-space addresses need.
    ///
    /// The worker is a guest thread, so this resumes the target and returns
    /// with it halted at `nt!DbgBreakPointWithStatus` rather than wherever it
    /// was. Returns whether `addr` reads back afterwards; a page that was
    /// never backed stays unreadable.
    #[pyo3(signature = (addr, process=None))]
    fn page_in(&mut self, addr: u64, process: Option<u64>) -> PyResult<bool> {
        self.require_halted("page_in")?;
        let report = self.inner.page_in(VirtAddr(addr), process).map_err(err)?;
        if !report.from_worker {
            return Err(err(Error::DebugInfo(
                "the target stopped for another reason before the worker reported".into(),
            )));
        }
        Ok(report.resident)
    }

    /// Select the current inspection thread (a vCPU id) so
    /// `read_register`/`registers`/`backtrace`/`step` operate on it.
    fn set_current_thread(&mut self, thread: &str) -> PyResult<()> {
        self.inner.set_current_thread(thread).map_err(err)
    }

    /// The currently selected inspection thread id.
    #[getter]
    fn current_thread(&self) -> String {
        self.inner.current_thread.clone()
    }

    /// Select a Windows thread (`.thread`) by thread id, ETHREAD, or KTHREAD
    /// address as the inspection context. A thread that is on a vCPU switches
    /// the live register context to it and returns that vCPU id; any other
    /// thread is parked (stack and metadata only, no register file) and
    /// returns `None`. `select_thread(None)` returns to the backend's current
    /// vCPU. Requires the VM halted.
    #[pyo3(signature = (thread))]
    fn select_thread(&mut self, thread: Option<u64>) -> PyResult<Option<String>> {
        self.require_halted("select_thread")?;
        let Some(value) = thread else {
            self.inner.reset_windows_thread().map_err(err)?;
            return Ok(None);
        };
        let info = self.inner.find_windows_thread(value).map_err(err)?;
        self.inner.select_windows_thread(&info).map_err(err)
    }

    /// The selected Windows thread as a dict (`threads()` shape), or `None`
    /// when no `.thread` selection is in effect.
    fn selected_thread<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        self.inner
            .target
            .windows_thread_selection
            .as_ref()
            .map(|thread| view_record(py, &view::thread(thread, None)))
            .transpose()
    }

    /// Resolve a thread id / ETHREAD / KTHREAD to its `_ETHREAD` cursor, the
    /// thread counterpart of `process()`.
    fn thread(slf: Bound<'_, Self>, thread: u64) -> PyResult<Struct> {
        let (info, ethread) = {
            let mut dbg = slf.borrow_mut();
            let found = dbg.inner.find_windows_thread(thread).map_err(err)?;
            (dbg.resolve_type("_ETHREAD")?, found.ethread.0)
        };
        Ok(Struct {
            dbg: slf.unbind(),
            name: "_ETHREAD".to_string(),
            info,
            base: ethread,
        })
    }

    /// Select stack frame `index` (`.frame N`, zero-based) of the current
    /// live thread, so `registers()`, `procedure_locals()`, and expressions
    /// use that frame's recovered register file; returns `{index, ip, sp}`.
    /// `select_frame(None)` returns to the live register file. Requires a
    /// halted VM and a live (not parked) thread.
    #[pyo3(signature = (index))]
    fn select_frame<'py>(
        &mut self,
        py: Python<'py>,
        index: Option<usize>,
    ) -> PyResult<Option<Bound<'py, Record>>> {
        self.require_halted("select_frame")?;
        let Some(index) = index else {
            self.inner.clear_selected_frame();
            return Ok(None);
        };
        let frame = self.inner.select_frame_index(index).map_err(err)?;
        Ok(Some(selected_frame_record(py, &frame)?))
    }

    /// The selected frame as `{index, ip, sp}`, or `None` at the live frame.
    fn selected_frame<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        self.inner
            .target
            .selected_frame
            .as_ref()
            .map(|frame| selected_frame_record(py, frame))
            .transpose()
    }

    /// Walk the call stack of any Windows thread by thread id / ETHREAD /
    /// KTHREAD without selecting it: a parked thread's saved kernel stack, or
    /// the live trace when the thread is on a vCPU. Same frame shape as
    /// `backtrace()` plus `source` naming how the stack was recovered.
    #[pyo3(signature = (thread, limit=64))]
    fn backtrace_thread<'py>(
        &mut self,
        py: Python<'py>,
        thread: u64,
        limit: usize,
    ) -> PyResult<Bound<'py, Record>> {
        let info = self.inner.find_windows_thread(thread).map_err(err)?;
        let trace = self
            .inner
            .backtrace_thread(&info, limit.clamp(1, 4096))
            .map_err(err)?;
        let frames = View::List(
            trace
                .stacktrace
                .frames
                .iter()
                .map(view::stack_frame)
                .collect(),
        );
        view_record(
            py,
            &View::Object(vec![
                ("ethread", View::Hex(info.ethread.0)),
                ("tid", View::OptNum(info.tid)),
                (
                    "source",
                    View::Str(format!("{:?}", trace.source).to_ascii_lowercase()),
                ),
                ("frames", frames),
            ]),
        )
    }

    /// Run until `target` (an address or expression) is reached, like `g
    /// <address>`/`pa`: a temporary breakpoint is planted there and removed
    /// afterwards. Any other breakpoint, exception, or bugcheck en route is
    /// returned as-is. With `timeout_ms` set and the address not reached in
    /// time, the target is interrupted where it is, the temporary site is
    /// removed, and the outcome is `halted`; with `None`, blocks until a stop.
    /// Requires the VM halted.
    #[pyo3(signature = (target, timeout_ms=None))]
    fn run_to<'py>(
        slf: Bound<'py, Self>,
        py: Python<'py>,
        target: &Bound<'_, PyAny>,
        timeout_ms: Option<u64>,
    ) -> PyResult<StopOutcome> {
        let (addr, _) = breakpoint_target_arg(&slf.borrow(), target)?;
        Self::stop_outcome(slf, py, |dbg| {
            dbg.require_halted("run_to")?;
            match timeout_ms {
                Some(ms) => {
                    let deadline = std::time::Instant::now() + Duration::from_millis(ms);
                    let cancel = AtomicBool::new(false);

                    std::thread::scope(|scope| {
                        // `run_to` blocks until a stop; flip its cancel flag
                        // from a helper thread when the budget elapses.
                        let cancel_ref = &cancel;
                        let handle = scope.spawn(move || {
                            while std::time::Instant::now() < deadline {
                                std::thread::sleep(Duration::from_millis(20));
                                if cancel_ref.load(Ordering::Relaxed) {
                                    return;
                                }
                            }
                            cancel_ref.store(true, Ordering::Relaxed);
                        });
                        let outcome = dbg.inner.run_to(VirtAddr(addr), &cancel).map_err(err);
                        cancel.store(true, Ordering::Relaxed);
                        let _ = handle.join();
                        match outcome {
                            Ok(ContinueOutcome::Running) if !dbg.inner.backend.is_running() => {
                                let rip = dbg
                                    .inner
                                    .read_registers()
                                    .ok()
                                    .and_then(|r| dbg.inner.register_map.read_u64("rip", &r).ok())
                                    .unwrap_or(0);
                                Ok(ContinueOutcome::Halted { rip })
                            }
                            other => other,
                        }
                    })
                }
                None => dbg.inner.run_to(VirtAddr(addr), &NEVER_CANCEL).map_err(err),
            }
        })
    }

    /// Set the stop policy for an exception code (`sxe`/`sxd`/`sxn`/`sxi`),
    /// the analogue of GDB's `handle`. `code` is a numeric NTSTATUS or a
    /// WinDbg alias (`"av"`, `"sse"`, `"ii"`, ...). `mode` is `"break"`
    /// (stop on every chance), `"second_chance"` (pass first-chance, stop on
    /// second), `"notify"`, or `"ignore"` (both continue without stopping;
    /// `notify` only differs in the REPL, which prints a line). `disposition`
    /// (`"handled"`/`"not_handled"`) fixes how a continued exception is
    /// acknowledged, like `-f gh`/`-f gn`. Policies apply to `run()`,
    /// `wait_for_stop()`, and `run_to()`.
    #[pyo3(signature = (code, mode, *, disposition=None))]
    fn set_exception_policy(
        &mut self,
        code: &Bound<'_, PyAny>,
        mode: &str,
        disposition: Option<&str>,
    ) -> PyResult<()> {
        let code = exception_code_arg(code)?;
        let mode = match mode {
            "break" => ExceptionPolicyMode::Break,
            "second_chance" => ExceptionPolicyMode::SecondChance,
            "notify" => ExceptionPolicyMode::Notify,
            "ignore" => ExceptionPolicyMode::Ignore,
            other => {
                return Err(raise(format!(
                    "unknown exception policy mode '{other}' (break, second_chance, notify, ignore)"
                )));
            }
        };
        let final_action = disposition
            .map(|text| text.parse::<ContinueDisposition>().map_err(err))
            .transpose()?
            .map(ExceptionPolicyFinalAction::Continue);
        self.inner
            .exception_policies
            .set_with_options(code, mode, None, final_action);
        Ok(())
    }

    /// The configured exception policies as `{code, alias, mode, disposition,
    /// command}` dicts (`sx`). Unlisted codes break by default.
    fn exception_policies<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let rows = self
            .inner
            .exception_policies
            .entries()
            .map(|(code, policy)| {
                let mode = match policy.mode {
                    ExceptionPolicyMode::Break => "break",
                    ExceptionPolicyMode::SecondChance => "second_chance",
                    ExceptionPolicyMode::Notify => "notify",
                    ExceptionPolicyMode::Ignore => "ignore",
                };
                let disposition = match policy.final_action {
                    Some(ExceptionPolicyFinalAction::Continue(disposition)) => {
                        Some(disposition.name().to_string())
                    }
                    Some(ExceptionPolicyFinalAction::Break) => Some("break".to_string()),
                    None => None,
                };
                View::Object(vec![
                    ("code", View::Hex(u64::from(code))),
                    (
                        "alias",
                        View::OptStr(exception_alias(code).map(str::to_string)),
                    ),
                    ("mode", View::Str(mode.to_string())),
                    ("disposition", View::OptStr(disposition)),
                    ("command", View::OptStr(policy.command.clone())),
                ])
            })
            .collect();
        view_list(py, &View::List(rows))
    }

    /// Forget every exception policy (`sxr`); ordinary exceptions break again.
    fn reset_exception_policies(&mut self) {
        self.inner.exception_policies.reset();
    }

    /// Whether the VM is currently running.
    fn is_running(&self) -> bool {
        self.inner.backend.is_running()
    }

    /// Read-only run-control snapshot (where am I): dict `{running, current_thread,
    /// rip, symbol, attached_process: {pid, name, eprocess}|None, stopped_process:
    /// {pid, name, eprocess}|None, stopped_thread|None, coherent, kernel_base}`.
    /// `attached_process` is the inspection scope (`.process`), which persists
    /// across resumes; `stopped_process` owns the page tables the stopped vCPU has
    /// loaded and `stopped_thread` is the Windows thread it is running.
    /// `rip`/`symbol` are None while running. `coherent` is False when the guest
    /// rebooted and rediscovery is still pending, so process/module enumeration
    /// is not yet meaningful; wait for it rather than reading stale state.
    fn status<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        view_record(py, &view::run_status(&self.inner.run_status()))
    }

    /// Analyze the current bugcheck (BSOD) by reading `nt!KiBugCheckData` from
    /// the frozen guest. Returns a dict `{code, code_hex, name, description,
    /// driver, args: [{index, value, description}], fault: {ip, symbol, driver},
    /// trap_frames: [{address, rip_symbol, frame, error}], source}` where each
    /// `frame` is the decoded `_KTRAP_FRAME` registers, or `None` with `error`
    /// explaining why decoding failed. Returns `None` if the guest is not
    /// bugchecking.
    fn bugcheck<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        match current_bugcheck(&self.inner.target)
            .or_else(|| bugcheck_from_dump_info(&self.inner.target))
        {
            Some(analysis) => Ok(Some(view_record(py, &view::bugcheck(&analysis))?)),
            None => Ok(None),
        }
    }

    /// Build the same structured one-shot crash/debug report as MCP `triage`.
    fn triage<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let report = TriageReport::build(&mut self.inner);
        view_record(py, &view::triage_report(&report, usize::MAX))
    }

    /// Rebuild guest state after a reboot/reload (drops breakpoints and
    /// rediscovers the kernel). `wait_for_stop`/`run` already do this
    /// automatically when the backend flags a target reload; call this to force
    /// it (e.g. after attaching to a guest that rebooted).
    fn reload(&mut self) -> PyResult<()> {
        self.inner.reload().map_err(err)
    }

    /// The ordered symbol sources (`.sympath`): `cache*<dir>`, local
    /// directories, and `http(s)://` servers, as strings.
    #[getter]
    fn symbol_path(&self) -> Vec<String> {
        self.inner
            .target
            .symbols
            .symbol_sources()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Replace the symbol sources (`.sympath <entries>`); each entry uses the
    /// same syntax as the REPL (`;`-separated is accepted too).
    #[setter]
    fn set_symbol_path(&self, sources: Vec<String>) {
        self.inner
            .target
            .symbols
            .set_symbol_sources(parse_symbol_sources(&sources));
    }

    /// Append a symbol source (`.sympath+`).
    fn add_symbol_path(&self, source: &str) {
        for source in parse_symbol_sources(&[source]) {
            self.inner.target.symbols.append_symbol_source(source);
        }
    }

    /// Restore the default symbol sources (`.symfix`).
    fn reset_symbol_path(&self) {
        self.inner.target.symbols.reset_symbol_sources();
    }

    /// The ordered source-path mappings (`.srcpath`): `<local-root>` or
    /// `<recorded-prefix>=<local-root>` strings.
    #[getter]
    fn source_path(&self) -> Vec<String> {
        self.inner
            .target
            .symbols
            .source_paths()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Replace the source-path mappings (`.srcpath <entries>`).
    #[setter]
    fn set_source_path(&self, paths: Vec<String>) {
        self.inner
            .target
            .symbols
            .set_source_paths(parse_source_paths(&paths));
    }

    /// Append a source-path mapping (`.srcpath+`).
    fn add_source_path(&self, mapping: &str) {
        for mapping in parse_source_paths(&[mapping]) {
            self.inner.target.symbols.append_source_path(mapping);
        }
    }

    /// Reload symbols for one module or, with `None`, every module in the
    /// current scope (`.reload`), then re-resolve symbolic breakpoints.
    /// Returns `{loaded, failed, skipped}` module-name lists.
    #[pyo3(signature = (module=None))]
    fn reload_symbols<'py>(
        &mut self,
        py: Python<'py>,
        module: Option<&str>,
    ) -> PyResult<Bound<'py, Record>> {
        let report = self
            .inner
            .target
            .reload_module_symbols(module)
            .map_err(err)?;
        let session: &mut Session = &mut self.inner;
        session
            .breakpoints
            .resolve_symbolic(session.backend.as_mut(), &session.target)
            .map_err(err)?;
        view_record(py, &view::module_symbol_report(&report))
    }

    /// Write a full `PAGEDU64` kernel dump of the halted target to `path`
    /// (`.dump /f`). Streams every physical page; returns the number of
    /// unreadable pages that were zero-filled. Requires memory introspection
    /// (not a dump-file session) and the VM halted.
    fn write_dump(&mut self, py: Python<'_>, path: &str) -> PyResult<u64> {
        self.require_halted("write_dump")?;
        if matches!(&*self.inner.target.phys, PhysMem::Dmp(_)) {
            return Err(raise("write_dump is not applicable to a static crash dump"));
        }
        let metadata = collect_dump_metadata(&mut self.inner).map_err(err)?;
        let memory = &*self.inner.target.phys;
        let interrupted = AtomicBool::new(false);
        let unreadable = py.detach(|| {
            write_kernel_dump(
                path,
                memory,
                &metadata,
                || interrupted.load(Ordering::Relaxed),
                || {},
            )
        });
        unreadable.map_err(err)
    }

    /// List running processes as `_EPROCESS` cursors. Read fields straight off
    /// each one (`proc.UniqueProcessId`, `proc.ImageFileName`, `proc.addr` (the
    /// EPROCESS VA)) or `proc.threads()` to walk its threads. `filter` (numeric
    /// = exact pid, else case-insensitive name substring) narrows the list.
    #[pyo3(signature = (filter=None))]
    fn processes(slf: Bound<'_, Self>, filter: Option<String>) -> PyResult<Vec<Struct>> {
        let (info, addrs) = {
            let dbg = slf.borrow();
            let info = dbg.resolve_type("_EPROCESS")?;
            let addrs: Vec<u64> = dbg
                .inner
                .target
                .matching_processes(filter.as_deref())
                .map_err(err)?
                .iter()
                .map(|p| p.eprocess_va.0)
                .collect();
            (info, addrs)
        };
        Ok(addrs
            .into_iter()
            .map(|base| Struct {
                dbg: slf.clone().unbind(),
                name: "_EPROCESS".to_string(),
                info: Arc::clone(&info),
                base,
            })
            .collect())
    }

    /// Resolve a single process by pid or name substring to its `_EPROCESS`
    /// cursor. Raises if nothing matches or a name is ambiguous; use
    /// `processes(filter)` when you want the whole matching list.
    fn process(slf: Bound<'_, Self>, target: &str) -> PyResult<Struct> {
        let mut matches = Self::processes(slf, Some(target.to_string()))?;
        match matches.len() {
            0 => Err(raise(format!("no process matches '{target}'"))),
            1 => Ok(matches.pop().unwrap()),
            n => Err(raise(format!(
                "'{target}' is ambiguous ({n} matches); use a pid or processes(filter)"
            ))),
        }
    }

    /// Return every exact PDB symbol identity matching `name`, retaining
    /// module, visibility, and private-compiland provenance.
    fn symbol_candidates<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyList>> {
        let rows = self
            .inner
            .target
            .symbol_candidates(name)
            .iter()
            .map(view::symbol_candidate)
            .collect();
        view_list(py, &view::View::List(rows))
    }

    /// Return the nearest symbol as `{address,module,name,offset}`.
    fn nearest_symbol<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        let address = VirtAddr(addr);
        view_record(
            py,
            &view::nearest_symbol(
                address,
                self.inner.target.nearest_symbol_current_context(address),
            ),
        )
    }

    /// Fuzzy-search symbols by name; `module!query` scopes one loaded module.
    #[pyo3(signature = (query, limit = 50))]
    fn search_symbols<'py>(
        &self,
        py: Python<'py>,
        query: &str,
        limit: usize,
    ) -> PyResult<Bound<'py, PyList>> {
        if !(1..=500).contains(&limit) {
            return Err(raise("limit must be in range 1-500"));
        }
        let rows = self
            .inner
            .target
            .search_symbols(query, limit)
            .iter()
            .map(view::symbol_search_match)
            .collect();
        view_list(py, &view::View::List(rows))
    }

    /// Resolve an address to PDB source metadata and its remapped local path.
    fn source_location<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Option<Bound<'py, Record>>> {
        self.inner
            .target
            .source_location(VirtAddr(addr))
            .map(|location| view_record(py, &view::source_location(&location)))
            .transpose()
    }

    /// Resolve every loaded address matching a PDB `file` and source `line`.
    fn source_addresses(&self, file: &str, line: u32) -> Vec<u64> {
        self.inner
            .target
            .source_addresses(file, line)
            .into_iter()
            .map(|address| address.0)
            .collect()
    }

    /// Return private locals/parameters in scope at `addr`, defaulting to the
    /// selected frame's IP (`select_frame`) or the halted RIP (`dv`); scalar
    /// `value` is present only when the PDB recipe can be evaluated safely in
    /// the current register context.
    #[pyo3(signature = (addr=None))]
    fn procedure_locals<'py>(
        &mut self,
        py: Python<'py>,
        addr: Option<u64>,
    ) -> PyResult<Bound<'py, PyList>> {
        let address = match addr {
            Some(addr) => VirtAddr(addr),
            None => match self.inner.target.selected_frame.as_ref() {
                Some(frame) => VirtAddr(frame.ip),
                None => {
                    self.require_halted("procedure_locals")?;
                    let regs = self.inner.read_registers().map_err(err)?;
                    VirtAddr(
                        self.inner
                            .register_map
                            .read_u64("rip", &regs)
                            .map_err(err)?,
                    )
                }
            },
        };
        let locals = self
            .inner
            .target
            .procedure_locals(address)
            .map_err(err)?
            .unwrap_or_default();
        let rows = locals
            .iter()
            .map(|local| view::procedure_local(&self.inner.target, address, local))
            .collect();
        view_list(py, &view::View::List(rows))
    }

    /// Size in bytes of a type, searched across loaded modules.
    fn type_size(&self, ty: &str) -> PyResult<u64> {
        Ok(self.resolve_type(ty)?.size as u64)
    }

    /// Byte offset of a field within a type.
    fn offset_of(&self, ty: &str, field: &str) -> PyResult<u64> {
        self.resolve_type(ty)?.field_offset(field).map_err(err)
    }

    /// Field layout of a type as `{name, size, fields: [{name, offset, size,
    /// type}]}` with fields sorted by offset. Use `type(ty)` for a handle that
    /// can also bind to an address.
    fn fields<'py>(&self, py: Python<'py>, ty: &str) -> PyResult<Bound<'py, Record>> {
        let info = self.resolve_type(ty)?;
        view_record(py, &view::type_layout(ty, &info))
    }

    /// Variants `(name, value)` of a PDB enum (e.g. `_MI_SYSTEM_VA_TYPE`,
    /// `_KWAIT_REASON`), in declaration order. Enums aren't structs, so they're
    /// read separately from `type`/`fields`.
    fn enum_values(&self, name: &str) -> PyResult<Vec<(String, i64)>> {
        self.inner
            .target
            .symbols
            .find_enum_across_modules(self.inner.target.current_dtb(), name)
            .ok_or_else(|| raise(format!("unknown enum: {name}")))
    }

    /// Read a struct at `addr` (one memory read) and return `{field: value}`.
    /// Scalar fields (1/2/4/8 bytes) become ints, bitfields are extracted to
    /// their masked value, and sized aggregates (e.g. char arrays) become bytes.
    /// Nested-struct fields that the PDB reports with size 0 are omitted, read
    /// those separately with their own type at `addr + offset_of(...)`.
    fn read_struct<'py>(
        &self,
        py: Python<'py>,
        ty: &str,
        addr: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let info = self.resolve_type(ty)?;
        let mut buf = vec![0u8; info.size];
        self.inner
            .read_masked(VirtAddr(addr), &mut buf)
            .map_err(err)?;

        // Field decoding rules live in core (`TypeInfo::decode_fields`); the SDK
        // only packs the neutral value into Python (pointers stay ints here,
        // unlike the MCP layer which renders them as hex).
        let d = PyDict::new(py);
        for (name, value) in info.decode_fields(&buf) {
            match value {
                FieldValue::Int(n) | FieldValue::Pointer(n) | FieldValue::Bitfield(n) => {
                    d.set_item(name, n)?
                }
                FieldValue::Bytes(b) => d.set_item(name, PyBytes::new(py, &b))?,
            }
        }
        Ok(d)
    }

    /// Resolve a PDB type into a [`Type`] handle. The (expensive) layout scan
    /// happens once here; the returned handle exposes `size`/`offset`/`fields`
    /// and `at(addr)` to bind it to an address as a reflective [`Struct`] cursor
    /// (`proc = dbg.type("_EPROCESS").at(addr); proc.UniqueProcessId`).
    #[pyo3(name = "type")]
    fn py_type(slf: Bound<'_, Self>, name: &str) -> PyResult<Type> {
        let info = slf.borrow().resolve_type(name)?;
        Ok(Type {
            dbg: slf.unbind(),
            name: name.to_string(),
            info,
        })
    }

    /// Walk an intrusive `_LIST_ENTRY` from a bare head address (e.g. a list-head
    /// symbol: `dbg.walk_list(dbg.eval("PsLoadedModuleList"), "_KLDR_DATA_TABLE_ENTRY",
    /// "InLoadOrderLinks")`), returning a [`Struct`] cursor per record. For a list
    /// whose head is a field of a struct, use `Struct.list` instead.
    fn walk_list(
        slf: Bound<'_, Self>,
        record_type: &str,
        link_field: &str,
        head: u64,
    ) -> PyResult<Vec<Struct>> {
        let (record_ti, bases) = {
            let dbg = slf.borrow();
            let record_ti = dbg.resolve_type(record_type)?;
            let link_offset = record_ti.field_offset(link_field).map_err(err)?;
            let bases = walk_list_bases(&dbg, head, link_offset)?;
            (record_ti, bases)
        };
        Ok(bases
            .into_iter()
            .map(|base| Struct {
                dbg: slf.clone().unbind(),
                name: record_type.to_string(),
                info: Arc::clone(&record_ti),
                base,
            })
            .collect())
    }

    /// Disassemble `count` instructions at `addr` in the current address space
    /// as `{ip, hex, asm, comment}` dicts; our own breakpoint `int3` bytes are
    /// masked and branch/rip-relative targets get symbol comments.
    fn disassemble<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
        count: usize,
    ) -> PyResult<Bound<'py, PyList>> {
        let rows = self.inner.disassemble(VirtAddr(addr), count).map_err(err)?;
        view_list(
            py,
            &view::View::List(rows.iter().map(view::disasm_row).collect()),
        )
    }

    /// Decode a `_KTRAP_FRAME` at `address`, or the current Windows
    /// thread's saved trap frame when omitted.
    #[pyo3(signature = (address=None))]
    fn inspect_trap_frame<'py>(
        &self,
        py: Python<'py>,
        address: Option<u64>,
    ) -> PyResult<Bound<'py, Record>> {
        let frame = read_ktrap_frame_at_or_current(&self.inner.target, address.map(VirtAddr))
            .map_err(err)?;
        let rip_symbol = self
            .inner
            .target
            .closest_symbol_current_context(VirtAddr(frame.instruction_pointer()));
        view_record(py, &view::trap_frame(&frame, rip_symbol))
    }

    /// Walk the current thread's call stack. Returns up to `limit` frames
    /// (default 64) as `{ip, sp, symbol, source, source_location}` dicts, where
    /// `source` is `"current"` (the live RIP), `"unwind"` (recovered from PE
    /// unwind data), or `"scan"` (a heuristic return-address scan of the
    /// stack). Requires the VM halted (`interrupt()` first, or be at a
    /// breakpoint).
    #[pyo3(signature = (limit = 64))]
    fn backtrace<'py>(&mut self, py: Python<'py>, limit: usize) -> PyResult<Bound<'py, PyList>> {
        self.require_halted("backtrace")?;
        let trace = self.inner.backtrace(limit).map_err(err)?;
        view_list(
            py,
            &view::View::List(trace.frames.iter().map(view::stack_frame).collect()),
        )
    }

    /// Nearest symbol to an address as `module!name+0x..`, or `None`.
    fn closest_symbol(&self, addr: u64) -> Option<String> {
        self.inner
            .target
            .closest_symbol_current_context(VirtAddr(addr))
    }

    /// Current directory table base (CR3) of the inspection context.
    fn current_dtb(&self) -> u64 {
        self.inner.target.current_dtb()
    }

    /// Walk the page tables for a virtual address. Returns a dict with the input
    /// `address` and a `levels` list (PXE → PPE → PDE → PTE) of per-level dicts:
    /// `level`, `address`, `value` (raw entry), `pfn`, `present`, `large_page`,
    /// `writable`, `user`, `nx`, and a WinDbg-style `flags` string. A large-page
    /// mapping short-circuits, so fewer levels are returned (e.g. a 2 MiB page
    /// stops at PDE).
    fn pte_walk<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        let walk = self
            .inner
            .target
            .pte_traverse(VirtAddr(addr))
            .map_err(err)?;
        view_record(py, &view::pte_walk(&walk))
    }

    /// Describe what `addr` belongs to: the loaded module (and PE section), or
    /// the process VAD region, else unknown. `module`/`section`/`region` are
    /// `None` when not applicable.
    fn describe_address<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        let d = self
            .inner
            .target
            .describe_address(VirtAddr(addr))
            .map_err(err)?;
        view_record(py, &view::address_description(&d))
    }

    /// Inspect the `_IRP` at `addr` and its current `_IO_STACK_LOCATION`.
    /// Returns a dict of decoded fields; `current_stack` is a nested dict, or
    /// `None` when `CurrentLocation` is out of range or the slot is unreadable.
    fn inspect_irp<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        let irp = self.inner.target.inspect_irp(VirtAddr(addr)).map_err(err)?;
        view_record(py, &view::irp(&irp))
    }

    /// Inspect the `_DRIVER_OBJECT` at `addr` (or the pointer it points to),
    /// including its device chain and 28-entry `MajorFunction` dispatch table.
    fn inspect_driver_object<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Bound<'py, Record>> {
        let d = self
            .inner
            .target
            .inspect_driver_object(VirtAddr(addr))
            .map_err(err)?;
        view_record(py, &view::driver_object(&self.inner.target, &d))
    }

    /// Inspect the `_DEVICE_OBJECT` at `addr` (or the pointer it points to) and
    /// its `AttachedDevice` stack.
    fn inspect_device_object<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Bound<'py, Record>> {
        let d = self
            .inner
            .target
            .inspect_device_object(VirtAddr(addr))
            .map_err(err)?;
        view_record(py, &view::device_object(&d))
    }

    /// Inspect the executive `_OBJECT_HEADER` for `addr`, accepting either the
    /// object body or the header; resolves the type and name when present.
    fn inspect_object_header<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Bound<'py, Record>> {
        let o = self
            .inner
            .target
            .inspect_object_header(VirtAddr(addr))
            .map_err(err)?;
        view_record(py, &view::object_header(&o))
    }

    /// Enumerate a bounded window of handles in the selected/current process.
    #[pyo3(signature = (limit = 256))]
    fn handles<'py>(&self, py: Python<'py>, limit: usize) -> PyResult<Bound<'py, Record>> {
        let summary = self.inner.target.enumerate_handles(limit).map_err(err)?;
        view_record(py, &view::handle_table(&summary))
    }

    /// Decode one handle from the selected/current process handle table.
    fn inspect_handle<'py>(&self, py: Python<'py>, handle: u64) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.inspect_handle(handle).map_err(err)?;
        view_record(py, &view::handle_entry(&detail))
    }

    /// Decode the selected/current process primary token.
    fn inspect_process_token<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let token = self.inner.target.inspect_process_token().map_err(err)?;
        view_record(py, &view::token(&token))
    }

    /// Decode a `_FILE_OBJECT` using the loaded kernel PDB layout.
    fn inspect_file_object<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        let file = self
            .inner
            .target
            .inspect_file_object(VirtAddr(addr))
            .map_err(err)?;
        view_record(py, &view::file_object(&file))
    }

    /// Decode one executive resource at an explicit address.
    fn inspect_resource<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        let resource = self
            .inner
            .target
            .inspect_resource(VirtAddr(addr))
            .map_err(err)?;
        view_record(py, &view::resource(&resource))
    }

    /// Enumerate the symbol-backed executive-resource list without scanning memory.
    #[pyo3(signature = (limit = 256))]
    fn resources<'py>(&self, py: Python<'py>, limit: usize) -> PyResult<Bound<'py, Record>> {
        let resources = self.inner.target.enumerate_resources(limit).map_err(err)?;
        view_record(py, &view::resource_list(&resources))
    }

    /// Return bounded system and per-process memory-use counters.
    #[pyo3(signature = (process_limit = 64))]
    fn memory_usage<'py>(
        &self,
        py: Python<'py>,
        process_limit: usize,
    ) -> PyResult<Bound<'py, Record>> {
        let summary = self
            .inner
            .target
            .memory_use_summary(process_limit)
            .map_err(err)?;
        view_record(py, &view::memory_usage(&summary))
    }

    /// Enumerate process/thread/image notification callbacks. Returns a list of
    /// dicts with `kind`, `index`, `function`, `symbol`, `block`, `raw`, `context`.
    fn notify_callbacks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let cbs = self
            .inner
            .target
            .enumerate_notify_callbacks()
            .map_err(err)?;
        let dtb = self.inner.target.guest().map_err(err)?.ntoskrnl.dtb();
        let rows: Vec<view::View> = cbs
            .iter()
            .map(|c| {
                let symbol = self
                    .inner
                    .target
                    .symbols
                    .format_closest_symbol_for_address(dtb, c.function);
                view::notify_callback(c, symbol)
            })
            .collect();
        view_list(py, &view::View::List(rows))
    }

    /// Dump the kernel SSDT and, when initialized, the win32k shadow table.
    /// Returns a list of `{label, base, limit, entries:[{index, target, symbol,
    /// module}]}` table dicts.
    fn ssdt<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let tables = self.inner.target.dump_ssdt().map_err(err)?;
        let rows: Vec<view::View> = tables.iter().map(view::ssdt_table).collect();
        view_list(py, &view::View::List(rows))
    }

    /// Discover in-flight IRPs from thread `IrpList`s and device `CurrentIrp`
    /// fields. `filter` scopes processes (pid or name) and driver names. Returns
    /// a list of dicts with the IRP and the context it was found in.
    fn discover_irps<'py>(
        &self,
        py: Python<'py>,
        filter: Option<String>,
    ) -> PyResult<Bound<'py, PyList>> {
        let hits = self
            .inner
            .target
            .discover_irps(filter.as_deref())
            .map_err(err)?;
        let rows: Vec<view::View> = hits.iter().map(view::irp_hit).collect();
        view_list(py, &view::View::List(rows))
    }

    /// Switch the inspection context to a process by PID, so subsequent memory
    /// reads/searches/`read_struct` target that process's address space. Returns
    /// the process name.
    fn attach_process(&mut self, pid: u64) -> PyResult<String> {
        let name = self.inner.target.attach(pid).map(|r| r.name).map_err(err)?;
        // The attach loaded the process's modules; a `bu /p` that was waiting
        // on one of them can resolve now.
        self.inner.reconcile_breakpoints_if_symbols_changed();
        Ok(name)
    }

    /// Return to the default (kernel) inspection context.
    fn detach(&mut self) {
        self.inner.target.detach();
    }

    /// The currently attached process as `{pid, name, dtb, eprocess}`, or
    /// `None` when inspecting the default kernel context.
    fn current_process<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, Record>>> {
        self.inner
            .target
            .current_process_info
            .as_ref()
            .map(|p| view_record(py, &view::process(p)))
            .transpose()
    }

    /// Virtual address-space map (VAD tree) of process `pid`, or of the
    /// attached process when omitted. Returns a list of dicts with `start`,
    /// `end`, `size`, `protection`, `vad_type`, `private_memory`,
    /// `commit_charge`, `details`.
    #[pyo3(signature = (pid = None))]
    fn memory_map<'py>(&self, py: Python<'py>, pid: Option<u64>) -> PyResult<Bound<'py, PyList>> {
        let process = match pid {
            Some(pid) => self
                .inner
                .target
                .matching_processes(Some(&pid.to_string()))
                .map_err(err)?
                .into_iter()
                .find(|p| p.pid == pid)
                .ok_or_else(|| raise(format!("no process with pid {pid}")))?,
            None => self
                .inner
                .target
                .current_process_info
                .clone()
                .ok_or_else(|| {
                    raise("no process attached; pass pid or call attach_process(pid)")
                })?,
        };
        let regions = self
            .inner
            .target
            .enumerate_vad_regions_for_process_info(&process)
            .map_err(err)?;

        let rows = regions.iter().map(view::memory_region).collect();
        view_list(py, &view::View::List(rows))
    }

    /// Loaded kernel modules as `{name, short_name, base, end, size,
    /// time_date_stamp?, checksum?, file_version?, product_version?}` dicts.
    fn kernel_modules<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let mods = self
            .inner
            .target
            .kernel_modules_with_versions()
            .map_err(err)?;
        view_list(
            py,
            &view::View::List(mods.iter().map(view::module).collect()),
        )
    }

    /// Loaded modules for the current inspection scope, same shape as
    /// `kernel_modules()`: the attached process's user-mode modules when
    /// attached (`attach_process(pid)`), otherwise the kernel module list.
    fn modules<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let mods = self.inner.target.modules_with_versions().map_err(err)?;
        view_list(
            py,
            &view::View::List(mods.iter().map(view::module).collect()),
        )
    }

    /// Driver objects as `{name, object, driver_start, driver_size,
    /// device_object, driver_unload}` dicts.
    fn driver_objects<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let drivers = self.inner.target.enumerate_driver_objects().map_err(err)?;
        view_list(
            py,
            &view::View::List(drivers.iter().map(view::driver_object_info).collect()),
        )
    }

    /// Windows threads as a list of dicts. Each is `{tid, pid, process_name,
    /// ethread, kthread, eprocess, state, state_name, wait_reason,
    /// wait_reason_name, active}` where `active` is the vCPU id currently
    /// running the thread (e.g. `"p1.1"`) or `None`. Merges the thread walk with
    /// the threads currently scheduled on a vCPU and sorts by `(pid, tid)`,
    /// matching the REPL `threads` command.
    fn threads<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let (threads, active) = self.inner.windows_threads().map_err(err)?;
        let rows = threads
            .iter()
            .map(|t| view::thread(t, active.get(&t.ethread.0).map(String::as_str)))
            .collect();
        view_list(py, &view::View::List(rows))
    }

    /// Inspect every vCPU as a list of dicts `{id, rip, context, symbol,
    /// error}`: the address space each is running in (`"kernel"`, a process
    /// name, or `"unknown"`) and the nearest symbol. Requires the VM halted.
    fn vcpus<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        self.require_halted("vcpus")?;
        let rows = self
            .inner
            .vcpus()
            .map_err(err)?
            .iter()
            .map(view::vcpu)
            .collect();
        view_list(py, &view::View::List(rows))
    }

    /// The backend's capability matrix as `{capability, label, supported}`
    /// dicts: which debug operations the current transport supports. Check it
    /// before a state-changing op instead of discovering unsupported ones by
    /// failure.
    fn capabilities<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let rows = self.inner.capabilities();
        view_list(
            py,
            &view::View::List(rows.iter().map(view::capability).collect()),
        )
    }

    /// Read captured guest debug output (DbgPrint / kernel printf). Snapshot+
    /// cursor: pass the previous call's `next_seq` as `since_seq` to poll only
    /// new lines. Returns `{lines: [{seq, timestamp_ms, text}], next_seq,
    /// dropped}`; `dropped` is True when the bounded ring evicted older lines
    /// before you read them. Output is captured only while the target runs
    /// (`cont()`/`run()`), so an empty result is not proof the guest is silent.
    /// Empty on backends without a debug stream (gdb/memory).
    #[pyo3(signature = (since_seq=0))]
    fn debug_log<'py>(&self, py: Python<'py>, since_seq: u64) -> PyResult<Bound<'py, Record>> {
        view_record(
            py,
            &view::debug_log(&self.inner.read_debug_output(since_seq)),
        )
    }

    /// Drain the diagnostics the debugger raised since the last call: a
    /// breakpoint that failed to re-arm at a stop, a stranded breakpoint
    /// table entry it reclaimed, host memory that stopped matching the guest
    /// after a reload. The REPL prints these as warnings; the SDK leaves them
    /// to you. Empty when nothing happened.
    fn notices(&mut self) -> Vec<String> {
        self.inner.take_notices()
    }

    /// Set a code breakpoint from an address or debugger expression, with an
    /// optional break `condition` (normal expression grammar, re-evaluated each
    /// hit; the run loop steps over and keeps going when it is false). Returns
    /// a live breakpoint handle.
    #[pyo3(signature = (target, condition=None, *, pass_count=0, one_shot=false, process=None, action=None))]
    fn breakpoint(
        slf: Bound<'_, Self>,
        target: &Bound<'_, PyAny>,
        condition: Option<String>,
        pass_count: u64,
        one_shot: bool,
        process: Option<u64>,
        action: Option<String>,
    ) -> PyResult<Breakpoint> {
        let id = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("breakpoint")?;
            let (addr, symbol) = breakpoint_target_arg(&dbg, target)?;
            let config =
                breakpoint_config_arg(&dbg, condition, pass_count, one_shot, process, action)?;
            dbg.inner
                .add_breakpoint(VirtAddr(addr), symbol, config)
                .map_err(err)?
        };
        Self::breakpoint_handle(&slf, id)
    }

    /// Set a symbol-identity breakpoint that survives module unload/reload and
    /// may remain deferred until matching symbols are loaded.
    #[pyo3(signature = (symbol, condition=None, *, pass_count=0, one_shot=false, process=None, action=None))]
    fn set_symbol_breakpoint(
        slf: Bound<'_, Self>,
        symbol: String,
        condition: Option<String>,
        pass_count: u64,
        one_shot: bool,
        process: Option<u64>,
        action: Option<String>,
    ) -> PyResult<Breakpoint> {
        let id = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("set_symbol_breakpoint")?;
            let config =
                breakpoint_config_arg(&dbg, condition, pass_count, one_shot, process, action)?;
            dbg.inner
                .add_symbol_breakpoint(symbol, config)
                .map_err(err)?
        };
        Self::breakpoint_handle(&slf, id)
    }

    /// Set one symbol-identity breakpoint per symbol matching a `*`/`?`
    /// glob, optionally `module!`-qualified (`bm`). Returns the handles
    /// created; symbols that failed to install raise after the rest are set.
    #[pyo3(signature = (pattern, condition=None, *, pass_count=0, one_shot=false, process=None, action=None, limit=256))]
    fn set_pattern_breakpoints(
        slf: Bound<'_, Self>,
        pattern: &str,
        condition: Option<String>,
        pass_count: u64,
        one_shot: bool,
        process: Option<u64>,
        action: Option<String>,
        limit: usize,
    ) -> PyResult<Vec<Breakpoint>> {
        let (ids, errors) = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("set_pattern_breakpoints")?;
            let config =
                breakpoint_config_arg(&dbg, condition, pass_count, one_shot, process, action)?;
            dbg.inner
                .add_pattern_breakpoints(pattern, config, limit.clamp(1, 4096))
                .map_err(err)?
        };
        let handles: Vec<Breakpoint> = ids
            .into_iter()
            .map(|id| Self::breakpoint_handle(&slf, id))
            .collect::<PyResult<_>>()?;
        if let Some(first) = errors.first() {
            return Err(raise(format!(
                "{} of {} matching symbols failed to install (first: {first})",
                errors.len(),
                errors.len() + handles.len()
            )));
        }
        if handles.is_empty() {
            return Err(raise(format!("no symbols match '{pattern}'")));
        }
        Ok(handles)
    }

    /// Set source-identity breakpoints for every loaded address matching
    /// `file:line`, or one deferred breakpoint when no module currently matches.
    #[pyo3(signature = (file, line, condition=None, *, pass_count=0, one_shot=false, process=None, action=None))]
    fn set_source_breakpoint(
        slf: Bound<'_, Self>,
        file: &str,
        line: u32,
        condition: Option<String>,
        pass_count: u64,
        one_shot: bool,
        process: Option<u64>,
        action: Option<String>,
    ) -> PyResult<Vec<Breakpoint>> {
        let ids = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("set_source_breakpoint")?;
            let config =
                breakpoint_config_arg(&dbg, condition, pass_count, one_shot, process, action)?;
            dbg.inner
                .add_source_breakpoint(format!("{file}:{line}"), config)
                .map_err(err)?
        };
        ids.into_iter()
            .map(|id| Self::breakpoint_handle(&slf, id))
            .collect()
    }

    /// Watch data access at an address or debugger expression. `access` is
    /// `"write"` or `"read_write"`; x86 cannot trap reads without also
    /// trapping writes. `length` is 1, 2, 4, or 8 and requires natural
    /// alignment. Watches are global across guest address spaces and currently
    /// require KD. Returns a live stop-point handle.
    #[pyo3(signature = (target, *, access="write", length=1, condition=None, pass_count=0, one_shot=false, process=None, action=None))]
    fn watchpoint(
        slf: Bound<'_, Self>,
        target: &Bound<'_, PyAny>,
        access: &str,
        length: u8,
        condition: Option<String>,
        pass_count: u64,
        one_shot: bool,
        process: Option<u64>,
        action: Option<String>,
    ) -> PyResult<Breakpoint> {
        let id = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("watchpoint")?;
            let access = access.parse::<WatchpointAccess>().map_err(err)?;
            let (addr, symbol) = breakpoint_target_arg(&dbg, target)?;
            let config =
                breakpoint_config_arg(&dbg, condition, pass_count, one_shot, process, action)?;
            dbg.inner
                .add_watchpoint(VirtAddr(addr), access, length, symbol, config)
                .map_err(err)?
        };
        Self::breakpoint_handle(&slf, id)
    }

    /// Remove a breakpoint or watchpoint by id or handle.
    fn clear_breakpoint(&mut self, id: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = breakpoint_id_arg(id, self.session_id())?;
        self.require_halted("clear_breakpoint")?;
        self.inner.remove_breakpoint(id).map_err(err)
    }

    /// Re-arm a disabled breakpoint or watchpoint by id or handle.
    fn enable_breakpoint(&mut self, id: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = breakpoint_id_arg(id, self.session_id())?;
        self.require_halted("enable_breakpoint")?;
        self.inner.enable_breakpoint(id).map_err(err)
    }

    /// Disable a breakpoint or watchpoint by id without forgetting it, so it
    /// can be re-enabled later.
    fn disable_breakpoint(&mut self, id: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = breakpoint_id_arg(id, self.session_id())?;
        self.require_halted("disable_breakpoint")?;
        self.inner.disable_breakpoint(id).map_err(err)
    }

    /// List installed code breakpoints and data watchpoints as live
    /// [`Breakpoint`] handles. The same handle type is returned by
    /// `breakpoint()`, `watchpoint()`, and `outcome.breakpoints`; entries can
    /// be cleared/enabled/disabled directly. Inspect `watchpoint`,
    /// `watch_access`, and `watch_length` to distinguish data watches.
    fn breakpoints(slf: Bound<'_, Self>) -> Vec<Breakpoint> {
        let dbg = slf.borrow();
        let session_id = dbg.session_id();
        dbg.inner
            .list_breakpoints()
            .into_iter()
            .map(|b| Breakpoint {
                dbg: Some(slf.clone().unbind()),
                session_id,
                snapshot: BreakpointSnapshot::from_core(b),
            })
            .collect()
    }

    /// KPCR/KPRCB essentials for `processor` (default: the current vCPU's):
    /// thread pointers, descriptor registers (IDTR/GDTR/TSS), and IRQL (`!pcr`).
    #[pyo3(signature = (processor=None))]
    fn inspect_pcr<'py>(
        &mut self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor_arg(processor);
        let detail = self.inner.inspect_pcr(processor).map_err(err)?;
        view_record(py, &view::cpu::pcr(&detail))
    }

    /// `_KPRCB` counters, thread pointers, and processor state for
    /// `processor` (default: current) (`!prcb`).
    #[pyo3(signature = (processor=None))]
    fn inspect_prcb<'py>(
        &self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor_arg(processor);
        let detail = self.inner.target.inspect_prcb(processor).map_err(err)?;
        view_record(py, &view::cpu::prcb(&detail))
    }

    /// The current IRQL and its level name for `processor` (`!irql`). At a KD
    /// break-in this is the debugger-observed IRQL.
    #[pyo3(signature = (processor=None))]
    fn inspect_irql<'py>(
        &self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor_arg(processor);
        let detail = self.inner.target.inspect_irql(processor).map_err(err)?;
        view_record(py, &view::cpu::irql(&detail))
    }

    /// One IDT vector or the bounded 256-entry table with handler symbols, gate
    /// types, non-nt hooks, and `KiIsrThunk` chain hints (`!idt`; AMD64 only).
    #[pyo3(signature = (vector=None, processor=None))]
    fn inspect_idt<'py>(
        &mut self,
        py: Python<'py>,
        vector: Option<u16>,
        processor: Option<u16>,
    ) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor_arg(processor);
        let detail = self.inner.inspect_idt(processor, vector).map_err(err)?;
        view_record(py, &view::cpu::idt(&detail))
    }

    /// The bounded GDT with base/limit/privilege/mode/presence per entry
    /// (`!gdt`; AMD64 only).
    #[pyo3(signature = (processor=None))]
    fn inspect_gdt<'py>(
        &mut self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor_arg(processor);
        let detail = self.inner.inspect_gdt(processor).map_err(err)?;
        view_record(py, &view::cpu::gdt(&detail))
    }

    /// Vendor, family/model/stepping, speed, and feature bits (`!cpuinfo`).
    #[pyo3(signature = (processor=None))]
    fn inspect_cpuinfo<'py>(
        &self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Bound<'py, Record>> {
        let processor = self.processor_arg(processor);
        let detail = self.inner.target.inspect_cpuinfo(processor).map_err(err)?;
        view_record(py, &view::cpu::cpuinfo(&detail))
    }

    /// Read a model-specific register (`rdmsr`); `msr` is a number or an
    /// `IA32_*` name. KD only; requires the VM halted.
    #[pyo3(signature = (msr, processor=None))]
    fn read_msr(&mut self, msr: &Bound<'_, PyAny>, processor: Option<u16>) -> PyResult<u64> {
        let msr = msr_arg(msr)?;
        let processor = self.processor_arg(processor);
        self.inner.read_msr(processor, msr).map_err(err)
    }

    /// Write a model-specific register (`wrmsr`). KD only; requires the VM halted.
    #[pyo3(signature = (msr, value, processor=None))]
    fn write_msr(
        &mut self,
        msr: &Bound<'_, PyAny>,
        value: u64,
        processor: Option<u16>,
    ) -> PyResult<()> {
        let msr = msr_arg(msr)?;
        let processor = self.processor_arg(processor);
        self.inner.write_msr(processor, msr, value).map_err(err)
    }

    /// The current/next/idle thread on each processor, optionally with a short
    /// kernel stack per processor (`!running`).
    #[pyo3(signature = (include_idle=false, include_stacks=false))]
    fn running<'py>(
        &self,
        py: Python<'py>,
        include_idle: bool,
        include_stacks: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .inspect_running(include_idle, include_stacks)
            .map_err(err)?;
        view_record(py, &view::sched::running(&detail))
    }

    /// Bounded dispatcher-ready queues for every processor or one (`!ready`).
    #[pyo3(signature = (processor=None))]
    fn ready_queues<'py>(
        &self,
        py: Python<'py>,
        processor: Option<u16>,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_ready_queues(processor)
            .map_err(err)?;
        view_record(py, &view::sched::ready_queues(&detail))
    }

    /// DPCs queued on each processor's two `_KPRCB.DpcData` queues (`!dpcs`).
    fn dpc_queues<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.inspect_dpc_queues().map_err(err)?;
        view_record(py, &view::sched::dpc_queues(&detail))
    }

    /// Bounded kernel timer-table entries with their DPCs (`!timer`).
    fn timers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.timer_list().map_err(err)?;
        view_record(py, &view::sched::timer_list(&detail))
    }

    /// Decode one `_KTIMER` and its DPC (`!timer <address>`).
    fn inspect_timer<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_timer(VirtAddr(address))
            .map_err(err)?;
        view_record(py, &view::sched::timer(&detail))
    }

    /// Kernel and user APCs (`!apc`): `target=None` is the selected Windows
    /// thread, `"*"` every thread, an int a thread (tid/ETHREAD/KTHREAD) or,
    /// when no thread matches, a process (pid/EPROCESS); a string a process
    /// name substring.
    #[pyo3(signature = (target=None))]
    fn apcs<'py>(
        &mut self,
        py: Python<'py>,
        target: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Bound<'py, Record>> {
        let selector = match target {
            None => ApcSelector::CurrentThread,
            Some(value) => {
                if let Ok(number) = value.extract::<u64>() {
                    if self.inner.find_windows_thread(number).is_ok() {
                        ApcSelector::Thread(VirtAddr(number))
                    } else {
                        ApcSelector::Process(number)
                    }
                } else {
                    let text: String = value.extract().map_err(|_| {
                        PyTypeError::new_err(
                            "apcs target must be None, \"*\", an int, or a process name",
                        )
                    })?;
                    if text == "*" {
                        ApcSelector::All
                    } else if text == "." {
                        ApcSelector::CurrentThread
                    } else {
                        let processes = self
                            .inner
                            .target
                            .matching_processes(Some(&text))
                            .map_err(err)?;
                        match processes.as_slice() {
                            [process] => ApcSelector::Process(process.pid),
                            [] => return Err(raise(format!("no process matches '{text}'"))),
                            many => {
                                return Err(raise(format!(
                                    "ambiguous process '{text}': {} matches",
                                    many.len()
                                )));
                            }
                        }
                    }
                }
            }
        };
        let detail = self.inner.inspect_apcs(selector).map_err(err)?;
        view_record(py, &view::sched::apcs(&detail))
    }

    /// Every thread's state, wait reason, and top stack symbol (`!stacks`);
    /// `level` 1/2 add bounded full stacks, `filter` matches process names or
    /// stack symbols.
    #[pyo3(signature = (level=0, filter=None))]
    fn stacks<'py>(
        &mut self,
        py: Python<'py>,
        level: u8,
        filter: Option<&str>,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.inspect_stacks(level, filter).map_err(err)?;
        view_record(py, &view::sched::stacks(&detail))
    }

    /// Decode the attached process's PEB (or the one at `address`) and its
    /// process parameters and loader-list heads; includes the WOW64 PEB for a
    /// 32-bit process (`!peb`).
    #[pyo3(signature = (address=None))]
    fn inspect_peb<'py>(
        &self,
        py: Python<'py>,
        address: Option<u64>,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_peb(address.map(VirtAddr))
            .map_err(err)?;
        view_record(py, &view::usermode::peb(&detail))
    }

    /// Decode the selected thread's TEB (or the one at `address`), plus the
    /// WOW64 TEB when present (`!teb`).
    #[pyo3(signature = (address=None))]
    fn inspect_teb<'py>(
        &self,
        py: Python<'py>,
        address: Option<u64>,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_teb(address.map(VirtAddr))
            .map_err(err)?;
        view_record(py, &view::usermode::teb(&detail))
    }

    /// Modules from the attached process loader lists, optionally only the one
    /// containing `containing` (`!dlls`).
    #[pyo3(signature = (containing=None))]
    fn loader_modules<'py>(
        &self,
        py: Python<'py>,
        containing: Option<u64>,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .loader_modules(containing.map(VirtAddr))
            .map_err(err)?;
        view_record(py, &view::usermode::loader_modules(&detail))
    }

    /// The selected thread's last Win32 error and NT status with names (`!gle`).
    fn last_error<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.last_error().map_err(err)?;
        view_record(py, &view::usermode::last_error(&detail))
    }

    /// Compare a module's executable sections against the cached on-disk image
    /// after relocation (`!chkimg`): per-section results, mismatch ranges with
    /// kernel self-patches counted separately, and bounded byte diffs when
    /// `include_diffs`.
    #[pyo3(signature = (module, include_diffs=false))]
    fn check_image<'py>(
        &self,
        py: Python<'py>,
        module: &str,
        include_diffs: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .check_image(module, include_diffs)
            .map_err(err)?;
        view_record(py, &view::usermode::image_check(&detail))
    }

    /// Every heap in the attached process PEB with kind and sizes (`!heap`).
    fn heap_summary<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.heap_summary().map_err(err)?;
        view_record(py, &view::heap::heap_summary(&detail))
    }

    /// Decode one NT or segment heap by PEB-list index (when that index
    /// exists) or address (`!heap -h`); `list_entries` materializes every
    /// entry, chunk, and block (`!heap -a`).
    #[pyo3(signature = (heap, list_entries=false))]
    fn inspect_heap<'py>(
        &self,
        py: Python<'py>,
        heap: u64,
        list_entries: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let summary = self.inner.target.heap_summary().map_err(err)?;
        let selector = if (heap as usize) < summary.heaps.len() {
            HeapSelector::Index(heap as usize)
        } else {
            HeapSelector::Address(VirtAddr(heap))
        };
        let detail = self
            .inner
            .target
            .inspect_heap(selector, list_entries)
            .map_err(err)?;
        view_record(py, &view::heap::heap(&detail))
    }

    /// The heap allocation containing `address`, or a not-found result with
    /// per-heap decode errors (`!heap -x`).
    fn find_heap_block<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .find_heap_block(VirtAddr(address))
            .map_err(err)?;
        view_record(py, &view::heap::heap_block_search(&detail))
    }

    /// System memory, pool, PTE, and page-file counters, plus bounded
    /// per-process usage rows unless `include_processes` is false (`!vm`).
    #[pyo3(signature = (include_processes=true))]
    fn inspect_vm<'py>(
        &self,
        py: Python<'py>,
        include_processes: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_vm(include_processes)
            .map_err(err)?;
        view_record(py, &view::mm::vm(&detail))
    }

    /// Decode an `_MMPFN` by page frame number, or by physical address when
    /// `physical_address` is true (`!pfn`).
    #[pyo3(signature = (value, physical_address=false))]
    fn inspect_pfn<'py>(
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
        let detail = self.inner.target.inspect_pfn(selector).map_err(err)?;
        view_record(py, &view::mm::pfn(&detail))
    }

    /// Translate a virtual address to physical through `dtb` (default: the
    /// current context); `None` when not present (`!vtop`).
    #[pyo3(signature = (addr, dtb=None))]
    fn vtop(&self, addr: u64, dtb: Option<u64>) -> PyResult<Option<u64>> {
        self.inner
            .target
            .virt_to_phys(dtb, VirtAddr(addr))
            .map_err(err)
    }

    /// The full translation of `addr` through `dtb` (default: the current
    /// context): every page-table level and the final physical address
    /// (`!vtop`); `pte_walk` is the same for the current context.
    #[pyo3(signature = (addr, dtb=None))]
    fn inspect_translation<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
        dtb: Option<u64>,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .vtop(dtb.unwrap_or(0), VirtAddr(addr))
            .map_err(err)?;
        view_record(py, &view::mm::vtop(&detail))
    }

    /// Bounded reverse walk: the current-DTB virtual mappings of a physical
    /// address (`!ptov`; AMD64 only).
    fn ptov<'py>(&self, py: Python<'py>, physical: u64) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.ptov(physical).map_err(err)?;
        view_record(py, &view::mm::ptov(&detail))
    }

    /// The pool page (or big-pool allocation) containing `address` and every
    /// block on it, marking the one containing the address (`!pool`).
    fn inspect_pool<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_pool(VirtAddr(address))
            .map_err(err)?;
        view_record(py, &view::mm::pool_page(&detail))
    }

    /// Pool tracker usage aggregated by tag (`!poolused`): `sort` is `"tag"`,
    /// `"nonpaged"`, or `"paged"` (bytes); `tag` is a case-sensitive `*`/`?`
    /// glob; `include_counts` adds allocation/free counts.
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
        let detail = self
            .inner
            .target
            .pool_usage(sort, tag, include_counts)
            .map_err(err)?;
        view_record(py, &view::mm::pool_usage(&detail))
    }

    /// Find pool blocks whose tag matches (`!poolfind`); `pool_type` narrows to
    /// `"nonpaged"` or `"paged"`. Bounded scan of the virtual pool ranges and
    /// the big-page table.
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
        let detail = self.inner.target.pool_find(tag, pool_type).map_err(err)?;
        view_record(py, &view::mm::pool_find(&detail))
    }

    /// The exported nonpaged and paged `GENERAL_LOOKASIDE` lists (`!lookaside`).
    fn lookaside_lists<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.lookaside_lists().map_err(err)?;
        view_record(py, &view::mm::lookaside_lists(&detail))
    }

    /// Decode one `GENERAL_LOOKASIDE` (`!lookaside <address>`).
    fn inspect_lookaside<'py>(
        &self,
        py: Python<'py>,
        address: u64,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_lookaside(VirtAddr(address))
            .map_err(err)?;
        view_record(py, &view::mm::lookaside(&detail))
    }

    /// Read `len` bytes of guest-physical memory (`!db`).
    fn read_physical<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
        len: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if len > MAX_READ_LEN {
            return Err(raise(format!(
                "read length {len} exceeds cap {MAX_READ_LEN} (0x{MAX_READ_LEN:x})"
            )));
        }
        let mut buf = vec![0u8; len];
        self.inner
            .target
            .read_physical(addr, &mut buf)
            .map_err(err)?;
        Ok(PyBytes::new(py, &buf))
    }

    /// Write bytes to guest-physical memory (`!eb`).
    fn write_physical(&self, addr: u64, data: &[u8]) -> PyResult<()> {
        self.inner.target.write_physical(addr, data).map_err(err)
    }

    /// Decode a `SECURITY_DESCRIPTOR` (absolute or self-relative) with its
    /// owner/group SIDs and DACL/SACL; `annotate_well_known` names well-known
    /// SIDs (`!sd`).
    #[pyo3(signature = (address, annotate_well_known=false))]
    fn inspect_security_descriptor<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        annotate_well_known: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_security_descriptor(VirtAddr(address), annotate_well_known)
            .map_err(err)?;
        view_record(py, &view::security::security_descriptor(&detail))
    }

    /// Decode an ACL and its ACEs (`!acl`).
    fn inspect_acl<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_acl(VirtAddr(address))
            .map_err(err)?;
        view_record(py, &view::security::acl(&detail))
    }

    /// Decode a SID in guest memory to its string form, authority, and
    /// well-known name (`!sid`).
    fn inspect_sid<'py>(&self, py: Python<'py>, address: u64) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_sid(VirtAddr(address))
            .map_err(err)?;
        view_record(py, &view::security::sid(&detail))
    }

    /// The security descriptor referenced by an object's header (`!objsd`).
    fn inspect_object_security<'py>(
        &self,
        py: Python<'py>,
        object: u64,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_object_security(VirtAddr(object))
            .map_err(err)?;
        view_record(py, &view::security::object_security(&detail))
    }

    /// Sessions and the processes in each (`!session`); `session` selects one
    /// (`-1` = current), `None` lists all.
    #[pyo3(signature = (session=None))]
    fn sessions<'py>(&self, py: Python<'py>, session: Option<i64>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.sessions(session).map_err(err)?;
        view_record(py, &view::security::sessions(&detail))
    }

    /// Processes in a session (`!sprocess`): `session` `None` = the attached
    /// process's session when known, `-1` current, `-4` all; `image_glob`
    /// filters image names case-insensitively.
    #[pyo3(signature = (session=None, detailed=false, image_glob=None))]
    fn session_processes<'py>(
        &self,
        py: Python<'py>,
        session: Option<i64>,
        detailed: bool,
        image_glob: Option<&str>,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .session_processes(session, detailed, image_glob)
            .map_err(err)?;
        view_record(py, &view::security::session_processes(&detail))
    }

    /// Decode a PnP device node (default: the root): instance path, service,
    /// state and history, flags, problem code, pending IRP; `recurse` adds the
    /// bounded flat subtree (`!devnode`).
    #[pyo3(signature = (node=None, recurse=false))]
    fn inspect_devnode<'py>(
        &self,
        py: Python<'py>,
        node: Option<u64>,
        recurse: bool,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_devnode(node.map(VirtAddr), recurse)
            .map_err(err)?;
        view_record(py, &view::pnp::devnode(&detail))
    }

    /// The device stack, top filter down to the PDO, from any device object in
    /// it or its device node, then the PDO's node (`!devstack`).
    fn inspect_device_stack<'py>(
        &self,
        py: Python<'py>,
        device_or_node: u64,
    ) -> PyResult<Bound<'py, Record>> {
        let detail = self
            .inner
            .target
            .inspect_device_stack(VirtAddr(device_or_node))
            .map_err(err)?;
        view_record(py, &view::pnp::device_stack(&detail))
    }

    /// Device nodes with problem codes, not started, or with a pending PnP IRP
    /// (`!pnptriage`).
    fn pnp_triage<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.pnp_triage().map_err(err)?;
        view_record(py, &view::pnp::pnp_triage(&detail))
    }

    /// Driver Verifier level, statistics, verified drivers, and
    /// configured-but-unloaded drivers (`!verifier`).
    fn verifier_status<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.verifier_status().map_err(err)?;
        view_record(py, &view::meta::verifier(&detail))
    }

    /// One verified driver's image, signing level, and verifier counters
    /// (`!verifier <module>`).
    fn verifier_driver<'py>(&self, py: Python<'py>, module: &str) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.verifier_driver(module).map_err(err)?;
        view_record(py, &view::meta::verifier_driver(&detail))
    }

    /// Target, kernel, symbol, processor, and debugger version information
    /// (`vertarget`).
    fn version<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target_version().map_err(err)?;
        view_record(py, &view::meta::target_version(&detail))
    }

    /// Target system time (FILETIME and ISO-8601) and uptime (`.time`).
    fn target_time<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let detail = self.inner.target.target_time().map_err(err)?;
        view_record(py, &view::meta::target_time(&detail))
    }

    /// Decode an NTSTATUS, Win32, or HRESULT code to its name and description
    /// (`!error`). Needs no target.
    #[staticmethod]
    fn decode_error<'py>(py: Python<'py>, code: u64) -> PyResult<Bound<'py, Record>> {
        view_record(py, &view::meta::error_code(&decode_error_code(code)))
    }

    /// Run any REPL command (e.g. `"dt _EPROCESS"`, `"lm"`, `"!analyze"`) and
    /// return its text output with terminal styling stripped. The escape hatch
    /// for commands without a typed method; the typed methods above are the
    /// structured API. Commands that resume the target block until the next
    /// stop, like `cont()`/`run()`.
    fn run_command(&mut self, line: &str) -> PyResult<String> {
        if line.trim().is_empty() {
            return Ok(String::new());
        }
        let mut state = ReplState::for_oneshot(&mut self.inner);
        state.line = line.trim().to_string();
        let (result, text) = output::capture(|| state.dispatch_line(line));
        result.map_err(err)?;
        Ok(text)
    }

    /// Remove all breakpoints and leave the VM running. If restoration fails,
    /// return an error and leave the target halted. Called automatically when
    /// used as a context manager (`with ntoseye.attach() as dbg:`).
    fn close(&mut self) -> PyResult<()> {
        // A borrowed (in-REPL) handle doesn't own the session; closing it must
        // not tear down the REPL's breakpoints. Only an owned session cleans up.
        if self.inner.is_owned() {
            self.inner.cleanup_for_exit().map_err(err)?;
        }
        Ok(())
    }

    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __exit__(
        &mut self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_value: &Bound<'_, PyAny>,
        _traceback: &Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        self.close()?;
        Ok(false)
    }

    fn __repr__(&self) -> String {
        format!("<ntoseye.Debugger thread={}>", self.inner.current_thread)
    }
}

impl Debugger {
    /// Build a `Debugger` that borrows the REPL's live `Session`. The caller
    /// must set `valid` false when the borrow ends; the handle (and any
    /// `Struct`/`Type` derived from it) panics on use after that.
    pub fn from_session_ref(session: &mut Session, valid: Arc<AtomicBool>) -> Self {
        Debugger {
            inner: SessionHandle::Borrowed {
                ptr: NonNull::from(session),
                valid,
            },
        }
    }

    fn session_id(&self) -> usize {
        self.inner.id()
    }

    /// Require a halted target before mutating debugger state that patches guest
    /// memory or backend breakpoint state.
    fn require_halted(&mut self, operation: &str) -> PyResult<()> {
        // KD can leave is_running() stale-true while the VM is physically halted
        // (a caught-but-undrained stop); settle it first, mirroring the MCP guard.
        self.inner.settle_pending_stop().map_err(err)?;
        if self.inner.backend.is_running() {
            Err(raise(format!(
                "{operation} requires the VM to be halted; call interrupt() first"
            )))
        } else {
            Ok(())
        }
    }

    /// Resolve a struct/union layout in the current context, with the shared
    /// "unknown type / is an enum" hint on failure.
    fn resolve_type(&self, name: &str) -> PyResult<Arc<TypeInfo>> {
        let symbols = &self.inner.target.symbols;
        let dtb = self.inner.target.current_dtb();
        symbols
            .find_type_across_modules(dtb, name)
            .ok_or_else(|| raise(symbols.unresolved_type_message(dtb, name)))
    }

    /// `processor` argument default: the current vCPU's processor index.
    fn processor_arg(&self, processor: Option<u16>) -> u16 {
        processor.unwrap_or_else(|| {
            processor_index_from_backend_thread_id(&self.inner.current_thread).unwrap_or(0)
        })
    }

    /// A live handle for breakpoint `id`, snapshotted right after install.
    fn breakpoint_handle(slf: &Bound<'_, Self>, id: u32) -> PyResult<Breakpoint> {
        let dbg = slf.borrow();
        let snapshot = dbg
            .inner
            .breakpoint(id)
            .map(BreakpointSnapshot::from_core)
            .ok_or_else(|| raise(format!("breakpoint {id} disappeared after install")))?;
        Ok(Breakpoint {
            dbg: Some(slf.clone().unbind()),
            session_id: dbg.session_id(),
            snapshot,
        })
    }

    /// Build the Python stop object payload from a [`ContinueOutcome`],
    /// enriching breakpoint/exception stops with resolved symbols and process
    /// context.
    fn continue_outcome_data(
        &mut self,
        py: Python<'_>,
        outcome: ContinueOutcome,
    ) -> PyResult<StopOutcomeData> {
        let (stopped_process, stopped_thread) = self.inner.stopped_context();
        let attached_process = self.inner.target.current_process_info.clone();
        let symbol_at = |rip: u64| {
            self.inner
                .target
                .closest_symbol_current_context(VirtAddr(rip))
        };

        let data = match outcome {
            ContinueOutcome::Breakpoint {
                id,
                address,
                symbol,
                temporary,
                rip,
                condition_error,
                ..
            } => {
                let snapshot = self
                    .inner
                    .breakpoint(id)
                    .map(BreakpointSnapshot::from_core)
                    .unwrap_or_else(|| {
                        BreakpointSnapshot::placeholder(id, address, symbol.clone(), temporary)
                    });
                let kind = if snapshot.watch_access.is_some() {
                    StopKind::Watchpoint
                } else {
                    StopKind::Breakpoint
                };
                StopOutcomeData {
                    kind,
                    rip: Some(rip),
                    symbol: snapshot
                        .symbol
                        .clone()
                        .or_else(|| symbol.or_else(|| symbol_at(rip))),
                    attached_process: attached_process.clone(),
                    stopped_process: stopped_process.clone(),
                    stopped_thread: stopped_thread.clone(),
                    breakpoints: vec![snapshot],
                    address: Some(address),
                    temporary: Some(temporary),
                    condition_error,
                    ..Default::default()
                }
            }
            ContinueOutcome::Bugcheck { rip, info } => {
                let analysis = info
                    .map(|i| analyze_bugcheck(&self.inner.target, &i))
                    .or_else(|| current_bugcheck(&self.inner.target))
                    .or_else(|| bugcheck_from_dump_info(&self.inner.target));
                let bugcheck_info = analysis
                    .map(|a| view_record(py, &view::bugcheck(&a)).map(|d| d.into_any().unbind()))
                    .transpose()?;
                StopOutcomeData {
                    kind: StopKind::Bugcheck,
                    rip,
                    symbol: rip.and_then(symbol_at),
                    bugcheck_info,
                    ..Default::default()
                }
            }
            ContinueOutcome::Stopped {
                rip,
                exception_code,
                first_chance,
                exception_address,
            } => StopOutcomeData {
                kind: StopKind::Exception,
                rip: Some(rip),
                symbol: symbol_at(rip),
                attached_process: attached_process.clone(),
                stopped_process: stopped_process.clone(),
                stopped_thread: stopped_thread.clone(),
                exception_code,
                first_chance,
                exception_address,
                ..Default::default()
            },
            ContinueOutcome::Step { rip } => StopOutcomeData {
                kind: StopKind::Step,
                rip: Some(rip),
                symbol: symbol_at(rip),
                attached_process: attached_process.clone(),
                stopped_process: stopped_process.clone(),
                stopped_thread: stopped_thread.clone(),
                ..Default::default()
            },
            ContinueOutcome::TargetReloaded {
                kernel_base,
                coherent,
            } => StopOutcomeData {
                kind: StopKind::TargetReloaded,
                kernel_base,
                coherent: Some(coherent),
                ..Default::default()
            },
            ContinueOutcome::Running => StopOutcomeData::default(),
            ContinueOutcome::Halted { rip } => StopOutcomeData {
                kind: StopKind::Halted,
                rip: Some(rip),
                symbol: symbol_at(rip),
                ..Default::default()
            },
        };
        Ok(data)
    }

    /// Drive one run-control step under a `&mut` borrow of `slf` and wrap the
    /// outcome as a [`StopOutcome`] that keeps the debugger alive for
    /// breakpoint handles.
    fn stop_outcome(
        slf: Bound<'_, Self>,
        py: Python<'_>,
        advance: impl FnOnce(&mut Debugger) -> PyResult<ContinueOutcome>,
    ) -> PyResult<StopOutcome> {
        let (session_id, data) = {
            let mut dbg = slf.borrow_mut();
            let outcome = advance(&mut dbg)?;
            (dbg.session_id(), dbg.continue_outcome_data(py, outcome)?)
        };
        Ok(StopOutcome {
            dbg: slf.unbind(),
            session_id,
            data,
        })
    }

    /// Repeat a bounded wait in one-second slices until it yields a stop,
    /// checking for a Python `KeyboardInterrupt` between slices so Ctrl+C
    /// breaks an indefinite wait.
    fn wait_until_stop(
        py: Python<'_>,
        mut wait: impl FnMut(Duration) -> PyResult<ContinueOutcome>,
    ) -> PyResult<ContinueOutcome> {
        loop {
            match wait(Duration::from_secs(1))? {
                ContinueOutcome::Running => py.check_signals()?,
                other => return Ok(other),
            }
        }
    }

    /// Read a fixed-size buffer from guest memory. Not exposed to Python; backs
    /// the typed `read_uN` helpers.
    fn read_fixed<const N: usize>(&self, addr: u64) -> PyResult<[u8; N]> {
        let mut buf = [0u8; N];
        self.inner
            .target
            .current_process()
            .map_err(err)?
            .memory()
            .read_bytes(VirtAddr(addr), &mut buf)
            .map_err(err)?;
        Ok(buf)
    }
}

/// A resolved PDB type. The expensive layout scan happened once when this was
/// created (`dbg.type("_EPROCESS")`); querying `size`/`offset`/`fields` is free,
/// and `at(addr)` binds the layout to an address as a reflective [`Struct`].
#[pyclass(unsendable)]
pub struct Type {
    dbg: Py<Debugger>,
    name: String,
    info: Arc<TypeInfo>,
}

#[pymethods]
impl Type {
    /// The type's name (e.g. `_EPROCESS`).
    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    /// Size of the type in bytes.
    #[getter]
    fn size(&self) -> u64 {
        self.info.size as u64
    }

    /// Byte offset of a field within the type.
    fn offset(&self, field: &str) -> PyResult<u64> {
        self.info.field_offset(field).map_err(err)
    }

    /// Field layout as `(name, offset, size, type)` tuples, sorted by offset.
    #[getter]
    fn fields(&self) -> Vec<(String, u64, u64, String)> {
        let mut out: Vec<(String, u64, u64, String)> = self
            .info
            .fields
            .iter()
            .map(|(n, f)| {
                (
                    n.clone(),
                    f.offset as u64,
                    f.size,
                    format!("{}", f.type_data),
                )
            })
            .collect();
        out.sort_by_key(|t| t.1);
        out
    }

    /// Bind this layout to an address, returning a reflective [`Struct`] cursor.
    fn at(&self, py: Python<'_>, addr: u64) -> Struct {
        Struct {
            dbg: self.dbg.clone_ref(py),
            name: self.name.clone(),
            info: self.info.clone(),
            base: addr,
        }
    }

    /// `type["field"]` → `(name, offset, size, type)` for one field.
    fn __getitem__(&self, field: &str) -> PyResult<(String, u64, u64, String)> {
        let f = self
            .info
            .fields
            .get(field)
            .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(field.to_string()))?;
        Ok((
            field.to_string(),
            f.offset as u64,
            f.size,
            format!("{}", f.type_data),
        ))
    }

    fn __repr__(&self) -> String {
        format!("<Type {} size={:#x}>", self.name, self.info.size)
    }
}

/// A PDB type bound to a guest address: a reflective cursor over a struct
/// instance. Field access reads from the *current* inspection context's address
/// space, so attribute access (`proc.UniqueProcessId`), item access
/// (`proc["ImageFileName"]`), and `read_field` all do one targeted read each.
/// Nested struct fields return a child cursor so accesses chain
/// (`proc.Pcb.DirectoryTableBase`); pointer fields return the raw address, with
/// `follow("field")` giving a typed deref.
#[pyclass(unsendable)]
pub struct Struct {
    dbg: Py<Debugger>,
    name: String,
    info: Arc<TypeInfo>,
    base: u64,
}

impl Struct {
    /// Resolve `type_name`'s layout in the current context and open a child
    /// cursor at `base`. Used for nested structs and `follow`.
    fn cursor_at(&self, py: Python<'_>, type_name: &str, base: u64) -> PyResult<Struct> {
        let info = self.dbg.borrow(py).resolve_type(type_name)?;
        Ok(Struct {
            dbg: self.dbg.clone_ref(py),
            name: type_name.to_string(),
            info,
            base,
        })
    }

    /// Decode the `_UNICODE_STRING` at `addr` to a Rust `String` (empty when
    /// null/zero-length), via the core reader shared with the REPL and MCP.
    fn decode_unicode_string_at(&self, py: Python<'_>, addr: u64) -> PyResult<String> {
        self.dbg
            .borrow(py)
            .inner
            .target
            .read_unicode_string(VirtAddr(addr))
            .map_err(err)
    }

    /// An array field as a Python list: struct/union elements become child
    /// cursors (no read); pointers and 1/2/4/8-byte scalars become ints from
    /// one bulk read; anything else becomes per-element `bytes`.
    fn array_field(
        &self,
        py: Python<'_>,
        element: &ParsedType,
        count: u32,
        addr: u64,
        total_size: u64,
    ) -> PyResult<Py<PyAny>> {
        let count = count as usize;
        let stride = (total_size as usize) / count;
        let list = PyList::empty(py);
        if let ParsedType::Struct(sname) | ParsedType::Union(sname) = element {
            let stride = if stride == 0 {
                self.dbg.borrow(py).resolve_type(sname)?.size
            } else {
                stride
            };
            for index in 0..count {
                let child = self.cursor_at(py, sname, addr + (index * stride) as u64)?;
                list.append(Py::new(py, child)?)?;
            }
            return Ok(list.into_any().unbind());
        }
        if stride == 0 {
            return Err(raise(format!(
                "array field at {addr:#x} has zero-sized elements"
            )));
        }
        let mut buf = vec![0u8; stride * count];
        self.dbg
            .borrow(py)
            .inner
            .read_masked(VirtAddr(addr), &mut buf)
            .map_err(err)?;
        let scalar = matches!(element, ParsedType::Pointer(_)) || matches!(stride, 1 | 2 | 4 | 8);
        for chunk in buf.chunks_exact(stride) {
            if scalar {
                list.append(le_uint(chunk))?;
            } else {
                list.append(PyBytes::new(py, chunk))?;
            }
        }
        Ok(list.into_any().unbind())
    }

    /// Write one field. Scalars/pointers take an int (encoded little-endian to
    /// the field's width); bitfields take an int and are written via a
    /// read-modify-write of just their storage span; sized aggregates take
    /// `bytes` of exactly the field size. Nested struct/union fields can't be
    /// assigned wholesale (write their scalar leaves instead).
    fn set_field(&self, py: Python<'_>, name: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let field = self
            .info
            .fields
            .get(name)
            .ok_or_else(|| raise(format!("{} has no field '{}'", self.name, name)))?;
        let addr = self.base + field.offset as u64;
        let dbg = self.dbg.borrow(py);
        let process = dbg.inner.target.current_process().map_err(err)?;
        let mem = process.memory();

        match &field.type_data {
            ParsedType::Struct(_) | ParsedType::Union(_) => Err(raise(format!(
                "cannot assign to nested struct field '{name}'; assign its scalar fields instead"
            ))),
            ParsedType::Bitfield { pos, len, .. } => {
                let v: u64 = value
                    .extract()
                    .map_err(|_| raise(format!("field '{name}' is a bitfield; expected int")))?;
                let (pos, len) = (*pos as u32, *len as u32);
                // Touch only the bytes the bitfield actually spans, so we never
                // clobber neighboring fields that share the storage unit.
                let sz = ((pos + len).div_ceil(8).clamp(1, 8)) as usize;
                let mut buf = vec![0u8; sz];
                mem.read_bytes(VirtAddr(addr), &mut buf).map_err(err)?;
                let mask = if len >= 64 {
                    u64::MAX
                } else {
                    (1u64 << len) - 1
                };
                let raw = (le_uint(&buf) & !(mask << pos)) | ((v & mask) << pos);
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = (raw >> (8 * i)) as u8;
                }
                mem.write_bytes(VirtAddr(addr), &buf).map_err(err)
            }
            ParsedType::Pointer(_) => {
                let v: u64 = value
                    .extract()
                    .map_err(|_| raise(format!("field '{name}' is a pointer; expected int")))?;
                mem.write_bytes(VirtAddr(addr), &v.to_le_bytes())
                    .map_err(err)
            }
            _ => {
                let sz = field.size as usize;
                if matches!(sz, 1 | 2 | 4 | 8)
                    && let Ok(v) = value.extract::<u64>()
                {
                    let bytes = v.to_le_bytes();
                    return mem.write_bytes(VirtAddr(addr), &bytes[..sz]).map_err(err);
                }
                let bytes: Vec<u8> = value.extract().map_err(|_| {
                    raise(format!(
                        "field '{name}' ({sz} bytes): expected int or bytes"
                    ))
                })?;
                if bytes.len() != sz {
                    return Err(raise(format!(
                        "field '{name}' is {sz} bytes; got {} bytes",
                        bytes.len()
                    )));
                }
                mem.write_bytes(VirtAddr(addr), &bytes).map_err(err)
            }
        }
    }

    /// Read one field, decoding by its PDB type: nested struct/union → a child
    /// cursor; pointer → the raw address; bitfield → the masked value; 1/2/4/8-
    /// byte scalars → int; a CHAR/UCHAR array → a NUL-trimmed `str` (e.g.
    /// `_EPROCESS.ImageFileName`); any other array → a list of its elements
    /// decoded by the same rules (struct elements are child cursors); anything
    /// else → bytes.
    fn get_field(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        let field = self
            .info
            .fields
            .get(name)
            .ok_or_else(|| raise(format!("{} has no field '{}'", self.name, name)))?;
        let addr = self.base + field.offset as u64;

        // `_UNICODE_STRING` auto-decodes to a Python `str` (it's the obvious
        // intent; reach the raw struct with `follow`/`read_struct` if needed).
        if matches!(&field.type_data, ParsedType::Struct(s) if s == "_UNICODE_STRING") {
            let s = self.decode_unicode_string_at(py, addr)?;
            return Ok(s.into_bound_py_any(py)?.unbind());
        }

        // Nested struct/union → chainable child cursor (no read here). The PDB
        // reports embedded-struct fields with size 0, so this is gated on the
        // type, not the size; the child cursor resolves its own layout/size.
        if let ParsedType::Struct(sname) | ParsedType::Union(sname) = &field.type_data {
            let child = self.cursor_at(py, sname, addr)?;
            return Ok(Py::new(py, child)?.into_any());
        }

        if let ParsedType::Array(element, count) = &field.type_data
            && field.type_data.c_string_len().is_none()
            && *count > 0
        {
            return self.array_field(py, element, *count, addr, field.size);
        }

        let sz = field.size as usize;
        let mut buf = vec![0u8; sz];
        self.dbg
            .borrow(py)
            .inner
            .read_masked(VirtAddr(addr), &mut buf)
            .map_err(err)?;

        let obj = match &field.type_data {
            ParsedType::Bitfield { pos, len, .. } => {
                let raw = le_uint(&buf);
                let mask = if *len >= 64 {
                    u64::MAX
                } else {
                    (1u64 << len) - 1
                };
                ((raw >> pos) & mask).into_bound_py_any(py)?
            }
            ParsedType::Pointer(_) => le_uint(&buf).into_bound_py_any(py)?,
            // Inline CHAR/UCHAR array → the obvious intent is a C string, so
            // decode it (like _UNICODE_STRING above); reach the raw bytes via
            // read()/dbg.read(addr, n) if needed.
            t if t.c_string_len().is_some() => decode_c_string(&buf).into_bound_py_any(py)?,
            _ => match sz {
                1 | 2 | 4 | 8 => le_uint(&buf).into_bound_py_any(py)?,
                _ => PyBytes::new(py, &buf).into_any(),
            },
        };
        Ok(obj.unbind())
    }
}

#[pymethods]
impl Struct {
    /// The address this cursor sits at.
    #[getter]
    fn addr(&self) -> u64 {
        self.base
    }

    /// The struct's type name.
    #[getter]
    fn type_name(&self) -> &str {
        &self.name
    }

    /// Field names available on this struct (sorted), for explicit listing.
    #[getter]
    fn fields(&self) -> Vec<String> {
        let mut v: Vec<String> = self.info.fields.keys().cloned().collect();
        v.sort();
        v
    }

    /// Explicit field read (same as attribute/item access).
    fn read_field(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        self.get_field(py, name)
    }

    /// Explicit field write; the deliberate counterpart to `proc.name = value`.
    /// Writes guest memory in the current inspection context.
    fn write_field(&self, py: Python<'_>, name: &str, value: Bound<'_, PyAny>) -> PyResult<()> {
        self.set_field(py, name, &value)
    }

    /// `proc.FieldName = value`; reflective field *write* (writes guest memory).
    /// Only PDB fields are assignable; anything else raises `AttributeError`.
    fn __setattr__(&self, py: Python<'_>, name: &str, value: Bound<'_, PyAny>) -> PyResult<()> {
        if !self.info.fields.contains_key(name) {
            return Err(PyAttributeError::new_err(format!(
                "'{}' has no settable field '{}'",
                self.name, name
            )));
        }
        self.set_field(py, name, &value)
    }

    /// Follow a pointer field to a typed child cursor. The target type comes
    /// from the field's own PDB metadata, so the caller never restates it.
    fn follow(&self, py: Python<'_>, name: &str) -> PyResult<Struct> {
        let field = self
            .info
            .fields
            .get(name)
            .ok_or_else(|| raise(format!("{} has no field '{}'", self.name, name)))?;
        let sname = match &field.type_data {
            ParsedType::Pointer(inner) => match inner.as_ref() {
                ParsedType::Struct(s) | ParsedType::Union(s) => s.clone(),
                _ => {
                    return Err(raise(format!(
                        "field '{name}' is not a pointer to a struct"
                    )));
                }
            },
            _ => return Err(raise(format!("field '{name}' is not a pointer"))),
        };
        let addr = self.base + field.offset as u64;
        let target = {
            let dbg = self.dbg.borrow(py);
            let mut b = [0u8; 8];
            dbg.inner
                .target
                .current_process()
                .map_err(err)?
                .memory()
                .read_bytes(VirtAddr(addr), &mut b)
                .map_err(err)?;
            u64::from_le_bytes(b)
        };
        self.cursor_at(py, &sname, target)
    }

    /// Read the whole struct in one shot as a `{field: value}` dict (same
    /// decoding as `Debugger.read_struct`; nested structs are omitted; reach
    /// those via attribute access instead).
    fn read<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dbg = self.dbg.borrow(py);
        dbg.read_struct(py, &self.name, self.base)
    }

    /// Walk an intrusive `_LIST_ENTRY` whose head is the `head_field` of this
    /// struct, returning a `Struct` cursor per record. `record_type`/`link_field`
    /// give the record layout and its embedded link (CONTAINING_RECORD); both are
    /// the one piece the PDB can't supply. Bounded and cycle-stopping.
    fn list(
        &self,
        py: Python<'_>,
        head_field: &str,
        record_type: &str,
        link_field: &str,
    ) -> PyResult<Vec<Struct>> {
        let head = self.base + self.info.field_offset(head_field).map_err(err)?;
        let (record_ti, bases) = {
            let dbg = self.dbg.borrow(py);
            let record_ti = dbg.resolve_type(record_type)?;
            let link_offset = record_ti.field_offset(link_field).map_err(err)?;
            let bases = walk_list_bases(&dbg, head, link_offset)?;
            (record_ti, bases)
        };
        Ok(bases
            .into_iter()
            .map(|base| Struct {
                dbg: self.dbg.clone_ref(py),
                name: record_type.to_string(),
                info: Arc::clone(&record_ti),
                base,
            })
            .collect())
    }

    /// Walk this process's threads (`_EPROCESS.ThreadListHead` → `_ETHREAD`).
    /// Sugar for `list("ThreadListHead", "_ETHREAD", "ThreadListEntry")`; valid
    /// on an `_EPROCESS` cursor.
    fn threads(&self, py: Python<'_>) -> PyResult<Vec<Struct>> {
        self.list(py, "ThreadListHead", "_ETHREAD", "ThreadListEntry")
    }

    /// Decode a `_UNICODE_STRING` field of this struct to a `str`. (Plain
    /// `_UNICODE_STRING` fields already auto-decode via attribute access; this is
    /// for explicitness.)
    fn unicode_string(&self, py: Python<'_>, name: &str) -> PyResult<String> {
        let off = self.info.field_offset(name).map_err(err)?;
        self.decode_unicode_string_at(py, self.base + off)
    }

    /// Decode the `_UNICODE_STRING` this cursor itself points at to a `str`.
    fn read_unicode_string(&self, py: Python<'_>) -> PyResult<String> {
        self.decode_unicode_string_at(py, self.base)
    }

    /// `proc.FieldName`; reflective field access. Missing fields raise
    /// `AttributeError` so `hasattr`/typos behave normally.
    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        if name.starts_with("__") || !self.info.fields.contains_key(name) {
            return Err(PyAttributeError::new_err(format!(
                "'{}' has no field '{}'",
                self.name, name
            )));
        }
        self.get_field(py, name)
    }

    /// `proc["FieldName"]`: collision-proof field access (works even when a
    /// field name shadows a method). `cursor[i]` with an int treats the cursor
    /// as the first element of an array and returns the cursor `i` elements
    /// along (`addr + i * size`), the typed-pointer indexing of `((T*)p)[i]`.
    fn __getitem__(&self, py: Python<'_>, key: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        if let Ok(index) = key.extract::<i64>() {
            let size = self.info.size as i64;
            if size == 0 {
                return Err(raise(format!("{} has no size to index by", self.name)));
            }
            let base = (self.base as i64).wrapping_add(index.wrapping_mul(size)) as u64;
            let sibling = Struct {
                dbg: self.dbg.clone_ref(py),
                name: self.name.clone(),
                info: Arc::clone(&self.info),
                base,
            };
            return Ok(Py::new(py, sibling)?.into_any());
        }
        let name: String = key
            .extract()
            .map_err(|_| PyTypeError::new_err("Struct index must be a field name or an int"))?;
        if !self.info.fields.contains_key(&name) {
            return Err(pyo3::exceptions::PyKeyError::new_err(name));
        }
        self.get_field(py, &name)
    }

    /// Size of the layout in bytes (`sizeof`).
    #[getter]
    fn size(&self) -> u64 {
        self.info.size as u64
    }

    /// Reinterpret this address as another PDB type (`(OTHER*)addr`).
    fn cast(&self, py: Python<'_>, type_name: &str) -> PyResult<Struct> {
        self.cursor_at(py, type_name, self.base)
    }

    /// Expose field names to `dir()` / tab-completion, alongside the methods.
    fn __dir__(&self) -> Vec<String> {
        let mut v: Vec<String> = self.info.fields.keys().cloned().collect();
        v.sort();
        for m in [
            "read",
            "read_field",
            "write_field",
            "follow",
            "list",
            "threads",
            "unicode_string",
            "read_unicode_string",
            "fields",
            "addr",
            "type_name",
            "size",
            "cast",
        ] {
            v.push(m.to_string());
        }
        v
    }

    fn __repr__(&self) -> String {
        format!("<{} @ {:#x}>", self.name, self.base)
    }
}

/// Attach to a guest and return a [`Debugger`].
///
/// `backend` is one of `"kd"` (default), `"kdnet"`, `"gdb"`, `"memory"`, or `"dmp"`.
/// `connect` is the backend target: socket path / address for kd/kdnet/gdb, or
/// dump file path for dmp; the per-backend default is used when omitted
/// (except dmp, which requires a path). `key` is required for kdnet.
/// `memory_source` is `auto`, `host`, or `kd` for KD/KDNET.
///
/// kd/kdnet/gdb take a per-target instance lock before building the backend, so a
/// second live attach against the same target (here or against a running CLI)
/// fails fast rather than racing on the handshake the first session owns;
/// memory/dmp are passive and coexist with anything.
#[pyfunction]
#[pyo3(signature = (backend="kd", connect=None, key=None, memory_source="auto"))]
fn attach(
    backend: &str,
    connect: Option<&str>,
    key: Option<&str>,
    memory_source: &str,
) -> PyResult<Debugger> {
    let memory_source = memory_source
        .parse::<KdMemorySource>()
        .map_err(|error| err(Error::DebugInfo(error)))?;
    let spec = if backend == "dmp" {
        let path = connect.ok_or_else(|| {
            err(Error::DebugInfo(
                "dmp backend requires a dump file path via connect=".into(),
            ))
        })?;
        TargetSpec::Dump(path.into())
    } else {
        let backend = backend.parse::<Backend>().map_err(|error| {
            err(Error::DebugInfo(format!(
                "{error} (or 'dmp' with connect=<path>)"
            )))
        })?;
        TargetSpec::Live {
            backend,
            connect: connect.map(str::to_string),
            kdnet_key: key.map(str::to_string),
            memory_source,
        }
    };
    let inner = Session::open_with_progress(&spec, &mut |line| eprintln!("{line}")).map_err(err)?;
    Ok(Debugger {
        inner: SessionHandle::Owned(Box::new(inner)),
    })
}

/// Populate the `_ntoseye` extension module. The `#[pymodule]` entry point (and
/// thus the exported `PyInit__ntoseye` symbol) lives in the `python/` crate's
/// shim, which calls this; that keeps the symbol in the cdylib where the linker
/// can't strip it, while the actual SDK lives here in core.
pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Debugger>()?;
    m.add_class::<Breakpoint>()?;
    m.add_class::<StopOutcome>()?;
    m.add_class::<AddressModule>()?;
    m.add_class::<MemoryRegion>()?;
    m.add_class::<MemorySearchMatch>()?;
    m.add_class::<Type>()?;
    m.add_class::<Struct>()?;
    m.add_class::<Record>()?;
    m.add_class::<Diagnostic>()?;
    m.add_function(wrap_pyfunction!(attach, m)?)?;
    m.add("NtoseyeError", m.py().get_type::<NtoseyeError>())?;
    m.add("MemoryAccessError", m.py().get_type::<MemoryAccessError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "must not be stashed")]
    fn invalidated_borrow_panics_instead_of_dereferencing() {
        let valid = Arc::new(AtomicBool::new(false));
        let handle = SessionHandle::Borrowed {
            ptr: NonNull::<Session>::dangling(),
            valid,
        };
        let _ = &*handle;
    }

    #[test]
    fn breakpoint_id_arg_rejects_foreign_handles() {
        Python::attach(|py| {
            let bp = Py::new(
                py,
                Breakpoint {
                    dbg: None,
                    session_id: 7,
                    snapshot: BreakpointSnapshot {
                        id: 42,
                        address: Some(0x1000),
                        enabled: true,
                        resolved: true,
                        deferred: false,
                        specification: None,
                        symbol: None,
                        scope: "global".to_string(),
                        condition: None,
                        pass_count: 0,
                        hit_count: 0,
                        remaining_pass_count: 0,
                        one_shot: false,
                        action: None,
                        temporary: false,
                        watch_access: None,
                        watch_length: None,
                    },
                },
            )
            .unwrap();
            let bp = bp.bind(py);

            assert_eq!(breakpoint_id_arg(bp.as_any(), 7).unwrap(), 42);
            let err = breakpoint_id_arg(bp.as_any(), 8).unwrap_err();
            assert!(
                err.to_string()
                    .contains("breakpoint handle belongs to a different debugger session")
            );
        });
    }
}
