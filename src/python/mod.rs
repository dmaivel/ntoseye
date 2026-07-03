use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pyo3::class::basic::CompareOp;
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyAttributeError, PyKeyError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyDict, PyList};

use crate::backend::MemoryOps;
use crate::bugchecks::{analyze_bugcheck, current_bugcheck};
use crate::dbg_backend::DebugBackend;
use crate::error::Error;
use crate::expr::Expr;
use crate::gdb::breakpoints::Breakpoint as CoreBreakpoint;
use crate::gdb::GdbClient;
use crate::kd::KdBackend;
use crate::dmp::DmpBackend;
use crate::memory_backend::MemoryBackend;
use crate::phys::PhysMem;
use crate::repl::ReplState;
use crate::session::{ContinueOutcome, Session, SessionLock};
use crate::symbols::{FieldValue, ParsedType, TypeInfo, le_uint};
use crate::target::{
    AddressModule as CoreAddressModule, MemoryRegionInfo,
    MemorySearchMatch as CoreMemorySearchMatch,
};
use crate::types::VirtAddr;
use crate::view;

pub mod embed;

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
/// the shared core walk ([`Session::walk_list`]) so the SDK and the
/// engine can't diverge.
fn walk_list_bases(dbg: &Debugger, head: u64, link_offset: u64) -> PyResult<Vec<u64>> {
    dbg.inner
        .target
        .walk_list(VirtAddr(head), link_offset)
        .map_err(err)
}

/// Render a neutral [`view::View`] object into a Python `dict` (the shared shape
/// with the MCP surface; here addresses come through as ints, there as hex).
fn view_dict<'py>(py: Python<'py>, v: &view::View) -> PyResult<Bound<'py, PyDict>> {
    view::to_py(py, v)?
        .cast_into::<PyDict>()
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
    value.extract::<u32>().map_err(|_| {
        PyTypeError::new_err("expected a breakpoint id or ntoseye.Breakpoint handle")
    })
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

/// A live debugging session. Owns the engine + backend; drive it from Python.
///
/// `unsendable`: the session (backend channel, KVM handle) is single-threaded,
/// so pyo3 pins it to the creating thread and panics on cross-thread access
/// rather than us pretending it is `Send`/`Sync`.
///
/// An owned session's single-instance lock (so a second `attach()`, here or in
/// a running CLI, fails fast) lives inside `inner`, [`Session::connect`] takes
/// it and releases when this object is dropped, not on `close()`. A borrowed
/// handle holds no lock; the REPL owns the session and its lock.
#[pyclass(unsendable)]
pub struct Debugger {
    inner: SessionHandle,
}

/// The `Session` a [`Debugger`] drives: one it owns (from [`attach`]) or one it
/// borrows for the duration of a call (the in-REPL scripting path, via
/// [`Debugger::from_session_ref`]). `Deref` lets every `Debugger` method reach
/// the `Session` identically regardless of which it holds, so the whole SDK
/// surface serves both entry points unchanged.
enum SessionHandle {
    Owned(Box<Session>),
    /// A live session owned elsewhere (the REPL). The pointer is only valid while
    /// `valid` reads true: the dispatcher flips it false the moment the command
    /// that handed out this handle returns (see [`Debugger::from_session_ref`] and
    /// `embed::dispatch`). A script that stashes the `Debugger` (or any
    /// `Struct`/`Type` derived from it) and reaches back later therefore panics
    /// with a clear message
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
const STALE_BORROW: &str =
    "ntoseye: use of a Debugger (or a Struct/Type derived from it) after the REPL command \
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
    address: u64,
    enabled: bool,
    symbol: Option<String>,
    scope: String,
    condition: Option<String>,
    temporary: bool,
}

impl BreakpointSnapshot {
    fn from_core(bp: &CoreBreakpoint) -> Self {
        Self {
            id: bp.id,
            address: bp.address.0,
            enabled: bp.enabled,
            symbol: bp.symbol.clone(),
            scope: bp.scope.label(),
            condition: bp.condition.clone(),
            temporary: bp.temporary,
        }
    }
}

/// A live breakpoint handle. Equality is debugger-session + breakpoint id, so
/// a handle returned from `dbg.breakpoint(...)` compares equal to the handle
/// surfaced later in `outcome.breakpoints`.
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

    fn require_live_debugger<'py>(
        &'py self,
        py: Python<'py>,
    ) -> PyResult<PyRefMut<'py, Debugger>> {
        let Some(dbg) = &self.dbg else {
            return Err(raise("breakpoint handle is not attached to a live debugger"));
        };
        let dbg = dbg.borrow_mut(py);
        if dbg.session_id() != self.session_id {
            return Err(raise("breakpoint handle belongs to a different debugger session"));
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
    fn address(&self) -> u64 {
        self.snapshot.address
    }

    #[getter]
    fn symbol(&self) -> Option<String> {
        self.snapshot.symbol.clone()
    }

    #[getter]
    fn scope(&self) -> String {
        self.snapshot.scope.clone()
    }

    #[getter]
    fn condition(&self) -> Option<String> {
        self.snapshot.condition.clone()
    }

    #[getter]
    fn temporary(&self) -> bool {
        self.snapshot.temporary
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
        self.live_snapshot(py)
            .map(|bp| bp.enabled)
            .unwrap_or(false)
    }

    #[setter]
    fn set_enabled(&self, py: Python<'_>, enabled: bool) -> PyResult<()> {
        if enabled {
            self.enable(py)
        } else {
            self.disable(py)
        }
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

    /// The flat mapping `{id, address, enabled, symbol, scope, condition,
    /// temporary}` (the shape the breakpoint lister used to return directly).
    /// `enabled` reflects the live state when the handle is still valid.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("id", self.snapshot.id)?;
        d.set_item("address", self.snapshot.address)?;
        d.set_item("enabled", self.enabled(py))?;
        d.set_item("symbol", self.snapshot.symbol.clone())?;
        d.set_item("scope", self.snapshot.scope.clone())?;
        d.set_item("condition", self.snapshot.condition.clone())?;
        d.set_item("temporary", self.snapshot.temporary)?;
        Ok(d)
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
        let symbol = self
            .snapshot
            .symbol
            .as_ref()
            .map(|s| format!(" {s}"))
            .unwrap_or_default();
        format!(
            "<Breakpoint #{} at {:#x}{} {}>",
            self.snapshot.id, self.snapshot.address, symbol, state
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StopKind {
    Breakpoint,
    Bugcheck,
    Exception,
    Step,
    TargetReloaded,
    Running,
    Halted,
}

impl StopKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Breakpoint => "breakpoint",
            Self::Bugcheck => "bugcheck",
            Self::Exception => "exception",
            Self::Step => "step",
            Self::TargetReloaded => "target_reloaded",
            Self::Running => "running",
            Self::Halted => "halted",
        }
    }
}

struct StopOutcomeData {
    kind: StopKind,
    rip: Option<u64>,
    symbol: Option<String>,
    process: Option<(u64, String)>,
    breakpoints: Vec<BreakpointSnapshot>,
    address: Option<u64>,
    temporary: Option<bool>,
    exception_code: Option<u32>,
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
    fn timed_out(&self) -> bool {
        self.running()
    }

    #[getter]
    fn breakpoint_stop(&self) -> bool {
        self.data.kind == StopKind::Breakpoint
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
    fn reload(&self) -> bool {
        self.target_reloaded()
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

    #[getter]
    fn process(&self) -> Option<(u64, String)> {
        self.data.process.clone()
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

    #[getter]
    fn exception_code(&self) -> Option<u32> {
        self.data.exception_code
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

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("stop", self.reason())?;
        match self.data.kind {
            StopKind::Breakpoint => {
                d.set_item("rip", self.data.rip)?;
                if let Some(bp) = self.data.breakpoints.first() {
                    d.set_item("id", bp.id)?;
                    d.set_item("breakpoint", bp.id)?;
                    d.set_item("address", self.data.address.unwrap_or(bp.address))?;
                    d.set_item("symbol", self.data.symbol.clone())?;
                    d.set_item("temporary", self.data.temporary.unwrap_or(bp.temporary))?;
                }
                d.set_item("process", self.data.process.clone())?;
            }
            StopKind::Bugcheck => {
                d.set_item("rip", self.data.rip)?;
                match &self.data.bugcheck_info {
                    Some(info) => d.set_item("bugcheck", info.clone_ref(py))?,
                    None => d.set_item("bugcheck", true)?,
                }
            }
            StopKind::Exception => {
                d.set_item("rip", self.data.rip)?;
                d.set_item("exception_code", self.data.exception_code)?;
                d.set_item("symbol", self.data.symbol.clone())?;
                d.set_item("process", self.data.process.clone())?;
            }
            StopKind::Step => {
                d.set_item("rip", self.data.rip)?;
                d.set_item("symbol", self.data.symbol.clone())?;
                d.set_item("process", self.data.process.clone())?;
            }
            StopKind::TargetReloaded => {
                d.set_item("target_reloaded", true)?;
                d.set_item("kernel_base", self.data.kernel_base)?;
                d.set_item("coherent", self.data.coherent)?;
            }
            StopKind::Running => {}
            StopKind::Halted => {
                d.set_item("rip", self.data.rip)?;
                d.set_item("symbol", self.data.symbol.clone())?;
            }
        }
        Ok(d)
    }

    #[pyo3(signature = (key, default=None))]
    fn get(&self, py: Python<'_>, key: &str, default: Option<Py<PyAny>>) -> PyResult<Py<PyAny>> {
        let d = self.to_dict(py)?;
        match d.get_item(key)? {
            Some(value) => Ok(value.unbind()),
            None => Ok(default.unwrap_or_else(|| py.None())),
        }
    }

    fn __getitem__(&self, py: Python<'_>, key: &str) -> PyResult<Py<PyAny>> {
        let d = self.to_dict(py)?;
        d.get_item(key)?
            .map(|value| value.unbind())
            .ok_or_else(|| PyKeyError::new_err(key.to_string()))
    }

    fn __contains__(&self, py: Python<'_>, key: &str) -> PyResult<bool> {
        self.to_dict(py)?.contains(key)
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
    // --- memory ---

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
        let process = self.inner.target.current_process();
        process
            .memory()
            .read_bytes(VirtAddr(addr), &mut buf)
            .map_err(err)?;
        self.inner
            .breakpoints
            .mask_breakpoint_bytes(VirtAddr(addr), &mut buf, process.dtb());
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
            .map(|matches| matches.into_iter().map(MemorySearchMatch::from_core).collect())
            .map_err(err)
    }

    /// Write bytes to guest virtual memory. Works while the guest runs (writes go
    /// through the hypervisor's RAM mapping, like reads); `interrupt()` first only
    /// if the guest may be concurrently touching the same bytes (torn write).
    fn write(&self, addr: u64, data: &[u8]) -> PyResult<()> {
        self.inner
            .target
            .current_process()
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

    // --- expressions ---

    /// Evaluate a debugger expression (symbols, registers, arithmetic) to an
    /// address/integer.
    fn eval(&self, expr: &str) -> PyResult<u64> {
        Expr::eval(expr, &self.inner.target)
            .map(|v| v.0)
            .map_err(err)
    }

    // --- registers ---

    /// Read a single register by name from the current thread context. Requires
    /// the VM halted (a running guest has no coherent register file).
    fn read_register(&mut self, name: &str) -> PyResult<u64> {
        self.require_halted("read_register")?;
        let regs = self.inner.backend.read_registers().map_err(err)?;
        self.inner.register_map.read_u64(name, &regs).map_err(err)
    }

    /// Read all registers as a `{name: value}` dict. Requires the VM halted (a
    /// running guest has no coherent register file).
    fn registers(&mut self) -> PyResult<HashMap<String, u64>> {
        self.require_halted("registers")?;
        let regs = self.inner.backend.read_registers().map_err(err)?;
        Ok(self.inner.register_map.to_hashmap(&regs))
    }

    /// Set a single register on the current thread (read-modify-write of the
    /// register file). Halt the VM first (`interrupt()` or be stopped at a
    /// breakpoint); a running guest has no coherent register file to patch.
    fn write_register(&mut self, name: &str, value: u64) -> PyResult<()> {
        self.require_halted("write_register")?;
        self.inner.write_register(name, value).map_err(err)
    }

    // --- execution control ---

    /// Resume the VM. Steps past a breakpoint at RIP first and re-arms
    /// breakpoints, so resuming from a breakpoint hit works correctly.
    fn cont(&mut self) -> PyResult<()> {
        self.inner.resume().map_err(err)
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
        let never = std::sync::atomic::AtomicBool::new(false);
        let (session_id, data) = {
            let mut dbg = slf.borrow_mut();
            let outcome = match timeout_ms {
                Some(ms) => dbg
                    .inner
                    .wait_for_stop_bounded(Some(Duration::from_millis(ms)), &never)
                    .map_err(err)?,
                None => loop {
                    match dbg
                        .inner
                        .wait_for_stop_bounded(Some(Duration::from_secs(1)), &never)
                        .map_err(err)?
                    {
                        ContinueOutcome::Running => {
                            py.check_signals()?;
                            continue;
                        }
                        other => break other,
                    }
                },
            };
            (dbg.session_id(), dbg.continue_outcome_data(py, outcome)?)
        };
        Ok(StopOutcome {
            dbg: slf.unbind(),
            session_id,
            data,
        })
    }

    /// Resume the VM and wait for the next meaningful stop, returning a
    /// [`StopOutcome`].
    ///
    /// This is the scope-aware run-control loop shared with the REPL and MCP: it
    /// silently steps over and resumes past wrong-process int3 hits (a breakpoint
    /// scoped to one process whose `int3` lives on a shared page) and false
    /// conditional breakpoints, so only the relevant hit surfaces. With
    /// `timeout_ms` it returns an outcome with `running` true if nothing stopped
    /// in that window (poll again); with `timeout_ms=None` it blocks until a
    /// stop, checking for Ctrl+C between polls.
    #[pyo3(signature = (timeout_ms=None))]
    fn run<'py>(
        slf: Bound<'py, Self>,
        py: Python<'py>,
        timeout_ms: Option<u64>,
    ) -> PyResult<StopOutcome> {
        // Python drives the loop in 1s chunks and checks for KeyboardInterrupt
        // between them, so no in-loop cancellation flag is needed here.
        let never = std::sync::atomic::AtomicBool::new(false);
        let (session_id, data) = {
            let mut dbg = slf.borrow_mut();
            let outcome = match timeout_ms {
                Some(ms) => dbg
                    .inner
                    .continue_until_break(Some(Duration::from_millis(ms)), &never)
                    .map_err(err)?,
                None => loop {
                    match dbg
                        .inner
                        .continue_until_break(Some(Duration::from_secs(1)), &never)
                        .map_err(err)?
                    {
                        ContinueOutcome::Running => {
                            py.check_signals()?; // let a Python KeyboardInterrupt break the wait
                            continue;
                        }
                        other => break other,
                    }
                },
            };
            (dbg.session_id(), dbg.continue_outcome_data(py, outcome)?)
        };
        Ok(StopOutcome {
            dbg: slf.unbind(),
            session_id,
            data,
        })
    }

    /// Single-step one instruction (issues the step, waits for the stop, clears
    /// the trap flag, re-arms breakpoints, and re-selects the stopped thread).
    /// Returns a [`StopOutcome`] (a `step` stop at the landed-on instruction),
    /// matching `step_over()`/`step_out()`. Requires the VM halted.
    fn step<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<StopOutcome> {
        let (session_id, data) = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("step")?;
            dbg.inner.step().map_err(err)?;
            let regs = dbg.inner.backend.read_registers().map_err(err)?;
            let rip = dbg.inner.register_map.read_u64("rip", &regs).map_err(err)?;
            let data = dbg.continue_outcome_data(py, ContinueOutcome::Step { rip })?;
            (dbg.session_id(), data)
        };
        Ok(StopOutcome {
            dbg: slf.unbind(),
            session_id,
            data,
        })
    }

    /// Step over the current instruction: if it's a `call`, run to its return
    /// site, otherwise single-step. Blocks until the step completes (or a
    /// breakpoint/bugcheck/exception is hit en route). Returns a
    /// [`StopOutcome`]. Requires the VM halted (`interrupt()` first, or be at a
    /// breakpoint).
    fn step_over<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<StopOutcome> {
        let never = std::sync::atomic::AtomicBool::new(false);
        let (session_id, data) = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("step_over")?;
            let outcome = dbg.inner.step_over(&never).map_err(err)?;
            (dbg.session_id(), dbg.continue_outcome_data(py, outcome)?)
        };
        Ok(StopOutcome {
            dbg: slf.unbind(),
            session_id,
            data,
        })
    }

    /// Step out of the current function: run to the caller's return address.
    /// Blocks until reached (or a breakpoint/bugcheck/exception en route).
    /// Returns a [`StopOutcome`]. Requires the VM halted.
    fn step_out<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<StopOutcome> {
        let never = std::sync::atomic::AtomicBool::new(false);
        let (session_id, data) = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("step_out")?;
            let outcome = dbg.inner.step_out(&never).map_err(err)?;
            (dbg.session_id(), dbg.continue_outcome_data(py, outcome)?)
        };
        Ok(StopOutcome {
            dbg: slf.unbind(),
            session_id,
            data,
        })
    }

    /// Pause the VM, adopting the stopped thread as the current one.
    fn interrupt(&mut self) -> PyResult<()> {
        self.inner.interrupt().map(|_| ()).map_err(err)
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

    /// Whether the VM is currently running.
    fn is_running(&self) -> bool {
        self.inner.backend.is_running()
    }

    /// Read-only run-control snapshot (where am I): dict `{running, current_thread,
    /// rip, symbol, process: (pid, name, eprocess)|None, coherent}`. `rip`/`symbol`
    /// are None while running. `coherent` is False when the guest rebooted and
    /// rediscovery is still pending, so process/module enumeration is not yet
    /// meaningful; wait for it rather than reading stale state.
    fn status<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = self.inner.run_status();
        let d = PyDict::new(py);
        d.set_item("running", s.running)?;
        d.set_item("current_thread", s.current_thread)?;
        d.set_item("rip", s.rip)?;
        d.set_item("symbol", s.symbol)?;
        d.set_item("process", s.process)?;
        d.set_item("coherent", s.coherent)?;
        d.set_item("kernel_base", s.kernel_base)?;
        Ok(d)
    }

    /// Analyze the current bugcheck (BSOD) by reading `nt!KiBugCheckData` from
    /// the frozen guest. Returns a dict `{code, code_hex, name, description,
    /// driver, args: [{index, value, description}], fault: {ip, symbol, driver},
    /// source}`, or `None` if the guest is not bugchecking.
    fn bugcheck<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>> {
        match current_bugcheck(&self.inner.target) {
            Some(analysis) => Ok(Some(view_dict(py, &view::bugcheck(&analysis))?)),
            None => Ok(None),
        }
    }

    /// Rebuild guest state after a reboot/reload (drops breakpoints and
    /// rediscovers the kernel). `wait_for_stop`/`run` already do this
    /// automatically when the backend flags a target reload; call this to force
    /// it (e.g. after attaching to a guest that rebooted).
    fn reload(&mut self) -> PyResult<()> {
        self.inner.reload().map_err(err)
    }

    // --- enumeration ---

    /// List running processes as `_EPROCESS` cursors. Read fields straight off
    /// each one (`proc.UniqueProcessId`, `proc.ImageFileName`, `proc.addr` (the
    /// EPROCESS VA)) or `proc.threads()` to walk its threads. `filter` (numeric
    /// = exact pid, else case-insensitive name substring) narrows the list.
    #[pyo3(signature = (filter=None))]
    fn processes(slf: Bound<'_, Self>, filter: Option<String>) -> PyResult<Vec<Struct>> {
        let (info, addrs) = {
            let dbg = slf.borrow();
            let dtb = dbg.inner.target.current_dtb();
            let info = dbg
                .inner
                .target
                .symbols
                .find_type_across_modules(dtb, "_EPROCESS")
                .ok_or_else(|| raise("unknown type: _EPROCESS"))?;
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
                info: info.clone(),
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

    // --- symbols & types ---

    /// Size in bytes of a type, searched across loaded modules.
    fn type_size(&self, ty: &str) -> PyResult<u64> {
        let dtb = self.inner.target.current_dtb();
        self.inner
            .target
            .symbols
            .find_type_across_modules(dtb, ty)
            .map(|t| t.size as u64)
            .ok_or_else(|| raise(self.inner.target.symbols.unresolved_type_message(dtb, ty)))
    }

    /// Byte offset of a field within a type.
    fn offset_of(&self, ty: &str, field: &str) -> PyResult<u64> {
        let dtb = self.inner.target.current_dtb();
        let info = self
            .inner
            .target
            .symbols
            .find_type_across_modules(dtb, ty)
            .ok_or_else(|| raise(self.inner.target.symbols.unresolved_type_message(dtb, ty)))?;
        info.field_offset(field).map_err(err)
    }

    /// Field layout of a type: `(name, offset, size, type)` tuples sorted by
    /// offset.
    fn fields(&self, ty: &str) -> PyResult<Vec<(String, u64, u64, String)>> {
        let dtb = self.inner.target.current_dtb();
        let info = self
            .inner
            .target
            .symbols
            .find_type_across_modules(dtb, ty)
            .ok_or_else(|| raise(self.inner.target.symbols.unresolved_type_message(dtb, ty)))?;
        let mut out: Vec<(String, u64, u64, String)> = info
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
        Ok(out)
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
        let dtb = self.inner.target.current_dtb();
        let info = self
            .inner
            .target
            .symbols
            .find_type_across_modules(dtb, ty)
            .ok_or_else(|| raise(self.inner.target.symbols.unresolved_type_message(dtb, ty)))?;

        let mut buf = vec![0u8; info.size];
        self.inner
            .target
            .current_process()
            .memory()
            .read_bytes(VirtAddr(addr), &mut buf)
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
        let info = {
            let d = slf.borrow();
            let dtb = d.inner.target.current_dtb();
            d.inner
                .target
                .symbols
                .find_type_across_modules(dtb, name)
                .ok_or_else(|| raise(d.inner.target.symbols.unresolved_type_message(dtb, name)))?
        };
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
            let dtb = dbg.inner.target.current_dtb();
            let record_ti = dbg
                .inner
                .target
                .symbols
                .find_type_across_modules(dtb, record_type)
                .ok_or_else(|| raise(format!("unknown type: {record_type}")))?;
            let link_offset = record_ti.field_offset(link_field).map_err(err)?;
            let bases = walk_list_bases(&dbg, head, link_offset)?;
            (record_ti, bases)
        };
        Ok(bases
            .into_iter()
            .map(|base| Struct {
                dbg: slf.clone().unbind(),
                name: record_type.to_string(),
                info: record_ti.clone(),
                base,
            })
            .collect())
    }

    /// Disassemble `count` instructions at `addr` in the current address space.
    /// Returns `(ip, hex_bytes, asm, comment)` tuples; our own breakpoint `int3`
    /// bytes are masked and branch/rip-relative targets get symbol comments.
    fn disassemble(
        &self,
        addr: u64,
        count: usize,
    ) -> PyResult<Vec<(u64, String, String, Option<String>)>> {
        let rows = self.inner.disassemble(VirtAddr(addr), count).map_err(err)?;
        Ok(rows
            .into_iter()
            .map(|r| (r.ip, r.hex, r.asm, r.comment))
            .collect())
    }

    /// Walk the current thread's call stack. Returns up to `limit` frames
    /// (default 64) as `(ip, sp, symbol, source)` tuples, where `source` is
    /// `"current"` (the live RIP), `"unwind"` (recovered from PE unwind data),
    /// or `"scan"` (a heuristic return-address scan of the stack). Requires the
    /// VM halted (`interrupt()` first, or be at a breakpoint).
    fn backtrace(
        &mut self,
        limit: Option<usize>,
    ) -> PyResult<Vec<(u64, u64, String, &'static str)>> {
        self.require_halted("backtrace")?;
        let trace = self.inner.backtrace(limit.unwrap_or(64)).map_err(err)?;
        Ok(trace
            .frames
            .into_iter()
            .map(|f| (f.ip, f.sp, f.symbol, f.source.as_str()))
            .collect())
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
    fn pte_walk<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, PyDict>> {
        let t = self
            .inner
            .target
            .pte_traverse(VirtAddr(addr))
            .map_err(err)?;

        let levels = PyList::empty(py);
        levels.append(view::to_py(py, &view::pte_level(&t.pxe))?)?;
        levels.append(view::to_py(py, &view::pte_level(&t.ppe))?)?;
        if let Some(pde) = &t.pde {
            levels.append(view::to_py(py, &view::pte_level(pde))?)?;
        }
        if let Some(pte) = &t.pte {
            levels.append(view::to_py(py, &view::pte_level(pte))?)?;
        }

        let out = PyDict::new(py);
        out.set_item("address", t.address.0)?;
        out.set_item("dtb", t.dtb)?;
        out.set_item("levels", levels)?;
        Ok(out)
    }

    /// Describe what `addr` belongs to: the loaded module (and PE section), or
    /// the process VAD region, else unknown. `module`/`section`/`region` are
    /// `None` when not applicable.
    fn describe_address<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, PyDict>> {
        let d = self
            .inner
            .target
            .describe_address(VirtAddr(addr))
            .map_err(err)?;
        view_dict(py, &view::address_description(&d))
    }

    /// Inspect the `_IRP` at `addr` and its current `_IO_STACK_LOCATION`.
    /// Returns a dict of decoded fields; `current_stack` is a nested dict, or
    /// `None` when `CurrentLocation` is out of range or the slot is unreadable.
    fn inspect_irp<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, PyDict>> {
        let irp = self.inner.target.inspect_irp(VirtAddr(addr)).map_err(err)?;
        view_dict(py, &view::irp(&irp))
    }

    /// Inspect the `_DRIVER_OBJECT` at `addr` (or the pointer it points to),
    /// including its device chain and 28-entry `MajorFunction` dispatch table.
    fn inspect_driver_object<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let d = self
            .inner
            .target
            .inspect_driver_object(VirtAddr(addr))
            .map_err(err)?;
        view_dict(py, &view::driver_object(&self.inner.target, &d))
    }

    /// Inspect the `_DEVICE_OBJECT` at `addr` (or the pointer it points to) and
    /// its `AttachedDevice` stack.
    fn inspect_device_object<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let d = self
            .inner
            .target
            .inspect_device_object(VirtAddr(addr))
            .map_err(err)?;
        view_dict(py, &view::device_object(&d))
    }

    /// Inspect the executive `_OBJECT_HEADER` for `addr`, accepting either the
    /// object body or the header; resolves the type and name when present.
    fn inspect_object_header<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        let o = self
            .inner
            .target
            .inspect_object_header(VirtAddr(addr))
            .map_err(err)?;
        view_dict(py, &view::object_header(&o))
    }

    /// Enumerate process/thread/image notification callbacks. Returns a list of
    /// dicts with `kind`, `index`, `function`, `symbol`, `block`, `raw`, `context`.
    fn notify_callbacks<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let cbs = self
            .inner
            .target
            .enumerate_notify_callbacks()
            .map_err(err)?;
        let dtb = self.inner.target.guest.ntoskrnl.dtb();
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

    // --- process context ---

    /// Switch the inspection context to a process by PID, so subsequent memory
    /// reads/searches/`read_struct` target that process's address space. Returns
    /// the process name.
    fn attach_process(&mut self, pid: u64) -> PyResult<String> {
        self.inner.target.attach(pid).map(|r| r.name).map_err(err)
    }

    /// Return to the default (kernel) inspection context.
    fn detach(&mut self) {
        self.inner.target.detach();
    }

    /// The currently attached process as `(pid, name, eprocess)`, or `None` when
    /// inspecting the default kernel context.
    fn current_process(&self) -> Option<(u64, String, u64)> {
        self.inner
            .target
            .current_process_info
            .as_ref()
            .map(|p| (p.pid, p.name.clone(), p.eprocess_va.0))
    }

    /// Virtual address-space map (VAD tree) of the attached process. Requires
    /// `attach_process(pid)` first. Returns a list of dicts with `start`, `end`,
    /// `size`, `protection`, `vad_type`, `private`, `commit`, `details`.
    fn memory_map<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let process = self
            .inner
            .target
            .current_process_info
            .clone()
            .ok_or_else(|| raise("not attached to a process; call attach_process(pid) first"))?;
        let regions = self
            .inner
            .target
            .enumerate_vad_regions_for_process_info(&process)
            .map_err(err)?;

        let mut out = Vec::with_capacity(regions.len());
        for r in regions {
            let d = PyDict::new(py);
            d.set_item("start", r.start.0)?;
            d.set_item("end", r.end.0)?;
            d.set_item("size", r.size())?;
            d.set_item("protection", r.protection)?;
            d.set_item("vad_type", r.vad_type)?;
            d.set_item("private", r.private_memory)?;
            d.set_item("commit", r.commit_charge)?;
            d.set_item("details", r.details)?;
            out.push(d);
        }
        Ok(out)
    }

    // --- enumeration: modules / drivers / threads ---

    /// Loaded kernel modules as `(name, base, size)` tuples.
    fn kernel_modules(&self) -> PyResult<Vec<(String, u64, u32)>> {
        let mods = self.inner.target.guest.kernel_modules().map_err(err)?;
        Ok(mods
            .into_iter()
            .map(|m| (m.name, m.base_address.0, m.size))
            .collect())
    }

    /// Loaded modules for the current inspection scope as `(name, base, size)`
    /// tuples: the attached process's user-mode modules when attached
    /// (`attach_process(pid)`), otherwise the kernel module list. Use
    /// `kernel_modules()` to list kernel modules regardless of attach state.
    fn modules(&self) -> PyResult<Vec<(String, u64, u32)>> {
        let mods = self.inner.target.modules().map_err(err)?;
        Ok(mods
            .into_iter()
            .map(|m| (m.name, m.base_address.0, m.size))
            .collect())
    }

    /// Driver objects as `(name, object, driver_start, driver_size)` tuples.
    fn driver_objects(&self) -> PyResult<Vec<(String, u64, u64, u64)>> {
        let drivers = self.inner.target.enumerate_driver_objects().map_err(err)?;
        Ok(drivers
            .into_iter()
            .map(|d| (d.name, d.object.0, d.driver_start.0, d.driver_size))
            .collect())
    }

    /// Windows threads as a list of dicts. Each is `{tid, pid, process_name,
    /// ethread, kthread, eprocess, state, wait_reason, active}` where `active`
    /// is the vCPU id currently running the thread (e.g. `"p1.1"`) or `None`.
    /// Merges the thread walk with the threads currently scheduled on a vCPU and
    /// sorts by `(pid, tid)`, matching the REPL `threads` command.
    fn threads<'py>(&mut self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let (threads, active) = self.inner.windows_threads().map_err(err)?;
        let mut out = Vec::with_capacity(threads.len());
        for t in threads {
            let d = PyDict::new(py);
            d.set_item("tid", t.tid)?;
            d.set_item("pid", t.pid)?;
            d.set_item("process_name", t.process_name)?;
            d.set_item("ethread", t.ethread.0)?;
            d.set_item("kthread", t.kthread.0)?;
            d.set_item("eprocess", t.eprocess.map(|a| a.0))?;
            d.set_item("state", t.state)?;
            d.set_item("wait_reason", t.wait_reason)?;
            d.set_item("active", active.get(&t.ethread.0).cloned())?;
            out.push(d);
        }
        Ok(out)
    }

    /// Inspect every vCPU as a list of dicts `{id, rip, context, symbol,
    /// error}`: the address space each is running in (`"kernel"`, a process
    /// name, or `"unknown"`) and the nearest symbol. Requires the VM halted.
    fn vcpus<'py>(&mut self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        self.require_halted("vcpus")?;
        let vcpus = self.inner.vcpus().map_err(err)?;
        let mut out = Vec::with_capacity(vcpus.len());
        for v in vcpus {
            let d = PyDict::new(py);
            d.set_item("id", v.id)?;
            d.set_item("rip", v.rip)?;
            d.set_item("context", v.context)?;
            d.set_item("symbol", v.symbol)?;
            d.set_item("error", v.error)?;
            out.push(d);
        }
        Ok(out)
    }

    /// The backend's capability matrix as `(label, supported)` tuples; which
    /// debug operations the current transport supports. Check it before a
    /// state-changing op instead of discovering unsupported ones by failure.
    fn capabilities(&self) -> Vec<(String, bool)> {
        self.inner
            .capabilities()
            .into_iter()
            .map(|c| (c.capability.label().to_string(), c.supported))
            .collect()
    }

    /// Read captured guest debug output (DbgPrint / kernel printf). Snapshot+
    /// cursor: pass the previous call's `next_seq` as `since_seq` to poll only
    /// new lines. Returns `{lines: [{seq, timestamp_ms, text}], next_seq,
    /// dropped}`; `dropped` is True when the bounded ring evicted older lines
    /// before you read them. Output is captured only while the target runs
    /// (`cont()`/`run()`), so an empty result is not proof the guest is silent.
    /// Empty on backends without a debug stream (gdb/memory).
    #[pyo3(signature = (since_seq=0))]
    fn debug_log<'py>(&self, py: Python<'py>, since_seq: u64) -> PyResult<Bound<'py, PyDict>> {
        let page = self.inner.read_debug_output(since_seq);
        let lines = pyo3::types::PyList::empty(py);
        for line in &page.lines {
            let d = PyDict::new(py);
            d.set_item("seq", line.seq)?;
            d.set_item("timestamp_ms", line.timestamp_ms)?;
            d.set_item("text", &line.text)?;
            lines.append(d)?;
        }
        let out = PyDict::new(py);
        out.set_item("lines", lines)?;
        out.set_item("next_seq", page.next_seq)?;
        out.set_item("dropped", page.dropped)?;
        Ok(out)
    }

    // --- breakpoints ---

    /// Set a code breakpoint at `addr` with an optional break `condition`
    /// (re-evaluated each hit; the run loop steps over and keeps going when it's
    /// false). Returns the breakpoint id.
    #[pyo3(signature = (addr, condition=None))]
    fn set_breakpoint(&mut self, addr: u64, condition: Option<String>) -> PyResult<u32> {
        self.require_halted("set_breakpoint")?;
        self.inner
            .add_breakpoint_with_condition(VirtAddr(addr), condition)
            .map_err(err)
    }

    /// Set a code breakpoint from an address or debugger expression; returns a
    /// live breakpoint handle.
    #[pyo3(signature = (target, condition=None))]
    fn breakpoint(
        slf: Bound<'_, Self>,
        target: &Bound<'_, PyAny>,
        condition: Option<String>,
    ) -> PyResult<Breakpoint> {
        let (session_id, snapshot) = {
            let mut dbg = slf.borrow_mut();
            dbg.require_halted("breakpoint")?;
            let (addr, symbol) = breakpoint_target_arg(&dbg, target)?;
            let id = dbg
                .inner
                .add_breakpoint_with_symbol_condition(VirtAddr(addr), symbol, condition)
                .map_err(err)?;
            let snapshot = dbg
                .inner
                .breakpoint(id)
                .map(BreakpointSnapshot::from_core)
                .ok_or_else(|| raise(format!("breakpoint {id} disappeared after install")))?;
            (dbg.session_id(), snapshot)
        };
        Ok(Breakpoint {
            dbg: Some(slf.unbind()),
            session_id,
            snapshot,
        })
    }

    /// Remove a breakpoint by id or handle.
    fn clear_breakpoint(&mut self, id: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = breakpoint_id_arg(id, self.session_id())?;
        self.require_halted("clear_breakpoint")?;
        self.inner.remove_breakpoint(id).map_err(err)
    }

    /// Re-arm a disabled breakpoint by id or handle (re-patch its `int3`).
    fn enable_breakpoint(&mut self, id: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = breakpoint_id_arg(id, self.session_id())?;
        self.require_halted("enable_breakpoint")?;
        self.inner.enable_breakpoint(id).map_err(err)
    }

    /// Disable a breakpoint by id (restore the original byte) without forgetting
    /// it, so it can be re-enabled later.
    fn disable_breakpoint(&mut self, id: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = breakpoint_id_arg(id, self.session_id())?;
        self.require_halted("disable_breakpoint")?;
        self.inner.disable_breakpoint(id).map_err(err)
    }

    /// List the installed breakpoints as live [`Breakpoint`] handles (the same
    /// handle type `breakpoint()` returns and `outcome.breakpoints` surfaces, so
    /// the listed entries can be cleared/enabled/disabled directly). Inspect a
    /// handle's `id`/`address`/`scope`/etc. properties, or `to_dict()` for the
    /// flat mapping.
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

    /// Run any REPL command (e.g. `"dt _EPROCESS"`, `"lm"`, `"k"`). Output is
    /// printed to stdout, exactly as in the interactive REPL. Useful for quick
    /// one-offs; the typed methods above are the structured API.
    fn run_command(&mut self, line: &str) -> PyResult<()> {
        if line.trim().is_empty() {
            return Ok(());
        }
        let mut state = ReplState::for_oneshot(&mut self.inner);
        state.line = line.trim().to_string();
        state.dispatch_line(line).map(|_| ()).map_err(err)
    }

    /// Remove all breakpoints and leave the VM running. Called automatically
    /// when used as a context manager (`with ntoseye.attach() as dbg:`).
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
    /// Build a `Debugger` that *borrows* an existing live `Session` instead of
    /// owning one: the in-REPL scripting entry point. It is the same SDK
    /// surface (every typed method, `Struct`/`Type`, `run_command`), pointed at
    /// the REPL's session rather than a freshly attached one, so scripts and
    /// interactive commands can't diverge from the engine.
    ///
    /// Invariant the caller must uphold (mirrors LLDB's SB handles): the
    /// returned `Debugger`, and any `Struct`/`Type` derived from it, must not be
    /// used after `valid` is set false. The dispatcher constructs the handle,
    /// runs one synchronous command under the GIL, and flips `valid` false on
    /// return; a stashed handle then panics on next use rather than dereferencing
    /// a dangling session.
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

    /// Build the Python stop object payload from a [`ContinueOutcome`],
    /// enriching breakpoint/exception stops with resolved symbols and process
    /// context.
    /// Not a Python method.
    fn continue_outcome_data(
        &self,
        py: Python<'_>,
        outcome: ContinueOutcome,
    ) -> PyResult<StopOutcomeData> {
        let symbol_at = |rip: u64| {
            self.inner
                .target
                .closest_symbol_current_context(VirtAddr(rip))
        };
        let process = self
            .inner
            .target
            .current_process_info
            .as_ref()
            .map(|p| (p.pid, p.name.clone()));

        let data = match outcome {
            ContinueOutcome::Breakpoint {
                id,
                address,
                symbol,
                temporary,
                rip,
            } => {
                let snapshot = self
                    .inner
                    .breakpoint(id)
                    .map(BreakpointSnapshot::from_core)
                    .unwrap_or(BreakpointSnapshot {
                        id,
                        address,
                        enabled: true,
                        symbol: symbol.clone(),
                        scope: "unknown".to_string(),
                        condition: None,
                        temporary,
                    });
                StopOutcomeData {
                    kind: StopKind::Breakpoint,
                    rip: Some(rip),
                    symbol: snapshot
                        .symbol
                        .clone()
                        .or_else(|| symbol.or_else(|| symbol_at(rip))),
                    process,
                    breakpoints: vec![snapshot],
                    address: Some(address),
                    temporary: Some(temporary),
                    exception_code: None,
                    bugcheck_info: None,
                    kernel_base: None,
                    coherent: None,
                }
            }
            ContinueOutcome::Bugcheck { rip, info } => {
                let analysis = info
                    .map(|i| analyze_bugcheck(&self.inner.target, &i))
                    .or_else(|| current_bugcheck(&self.inner.target));
                let bugcheck_info = match analysis {
                    Some(a) => Some(view_dict(py, &view::bugcheck(&a))?.into_any().unbind()),
                    None => None,
                };
                StopOutcomeData {
                    kind: StopKind::Bugcheck,
                    rip,
                    symbol: rip.and_then(symbol_at),
                    process: None,
                    breakpoints: Vec::new(),
                    address: None,
                    temporary: None,
                    exception_code: None,
                    bugcheck_info,
                    kernel_base: None,
                    coherent: None,
                }
            }
            ContinueOutcome::Stopped {
                rip,
                exception_code,
            } => StopOutcomeData {
                kind: StopKind::Exception,
                rip: Some(rip),
                symbol: symbol_at(rip),
                process,
                breakpoints: Vec::new(),
                address: None,
                temporary: None,
                exception_code,
                bugcheck_info: None,
                kernel_base: None,
                coherent: None,
            },
            ContinueOutcome::Step { rip } => StopOutcomeData {
                kind: StopKind::Step,
                rip: Some(rip),
                symbol: symbol_at(rip),
                process,
                breakpoints: Vec::new(),
                address: None,
                temporary: None,
                exception_code: None,
                bugcheck_info: None,
                kernel_base: None,
                coherent: None,
            },
            ContinueOutcome::TargetReloaded {
                kernel_base,
                coherent,
            } => StopOutcomeData {
                kind: StopKind::TargetReloaded,
                rip: None,
                symbol: None,
                process: None,
                breakpoints: Vec::new(),
                address: None,
                temporary: None,
                exception_code: None,
                bugcheck_info: None,
                kernel_base,
                coherent: Some(coherent),
            },
            ContinueOutcome::Running => StopOutcomeData {
                kind: StopKind::Running,
                rip: None,
                symbol: None,
                process: None,
                breakpoints: Vec::new(),
                address: None,
                temporary: None,
                exception_code: None,
                bugcheck_info: None,
                kernel_base: None,
                coherent: None,
            },
            ContinueOutcome::Halted { rip } => StopOutcomeData {
                kind: StopKind::Halted,
                rip: Some(rip),
                symbol: symbol_at(rip),
                process: None,
                breakpoints: Vec::new(),
                address: None,
                temporary: None,
                exception_code: None,
                bugcheck_info: None,
                kernel_base: None,
                coherent: None,
            },
        };
        Ok(data)
    }

    /// Read a fixed-size buffer from guest memory. Not exposed to Python; backs
    /// the typed `read_uN` helpers.
    fn read_fixed<const N: usize>(&self, addr: u64) -> PyResult<[u8; N]> {
        let mut buf = [0u8; N];
        self.inner
            .target
            .current_process()
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
    info: TypeInfo,
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
    info: TypeInfo,
    base: u64,
}

impl Struct {
    /// Resolve `type_name`'s layout in the current context and open a child
    /// cursor at `base`. Used for nested structs and `follow`.
    fn cursor_at(&self, py: Python<'_>, type_name: &str, base: u64) -> PyResult<Struct> {
        let info = {
            let dbg = self.dbg.borrow(py);
            let dtb = dbg.inner.target.current_dtb();
            dbg.inner
                .target
                .symbols
                .find_type_across_modules(dtb, type_name)
                .ok_or_else(|| {
                    raise(
                        dbg.inner
                            .target
                            .symbols
                            .unresolved_type_message(dtb, type_name),
                    )
                })?
        };
        Ok(Struct {
            dbg: self.dbg.clone_ref(py),
            name: type_name.to_string(),
            info,
            base,
        })
    }

    /// Decode the `_UNICODE_STRING` at `addr` to a Rust `String` (empty when
    /// null/zero-length). `Length`/`Buffer` offsets come from the PDB rather
    /// than being hardcoded; the buffer is read as UTF-16LE.
    fn decode_unicode_string_at(&self, py: Python<'_>, addr: u64) -> PyResult<String> {
        let dbg = self.dbg.borrow(py);
        let dtb = dbg.inner.target.current_dtb();
        let us = dbg
            .inner
            .target
            .symbols
            .find_type_across_modules(dtb, "_UNICODE_STRING")
            .ok_or_else(|| raise("unknown type: _UNICODE_STRING"))?;
        let len_off = us.field_offset("Length").map_err(err)?;
        let buf_off = us.field_offset("Buffer").map_err(err)?;
        let process = dbg.inner.target.current_process();
        let mem = process.memory();

        let mut b2 = [0u8; 2];
        mem.read_bytes(VirtAddr(addr + len_off), &mut b2)
            .map_err(err)?;
        let length = u16::from_le_bytes(b2) as usize;
        let mut b8 = [0u8; 8];
        mem.read_bytes(VirtAddr(addr + buf_off), &mut b8)
            .map_err(err)?;
        let buffer = u64::from_le_bytes(b8);
        if length == 0 || buffer == 0 {
            return Ok(String::new());
        }
        let mut raw = vec![0u8; length];
        mem.read_bytes(VirtAddr(buffer), &mut raw).map_err(err)?;
        let u16s: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&u16s))
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
        let process = dbg.inner.target.current_process();
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
                // clobber neighbouring fields that share the storage unit.
                let sz = (((pos + len + 7) / 8).clamp(1, 8)) as usize;
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
                if matches!(sz, 1 | 2 | 4 | 8) {
                    if let Ok(v) = value.extract::<u64>() {
                        let bytes = v.to_le_bytes();
                        return mem.write_bytes(VirtAddr(addr), &bytes[..sz]).map_err(err);
                    }
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
    /// `_EPROCESS.ImageFileName`); anything else (other arrays, larger
    /// aggregates) → bytes.
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

        let sz = field.size as usize;
        let mut buf = vec![0u8; sz];
        {
            let dbg = self.dbg.borrow(py);
            dbg.inner
                .target
                .current_process()
                .memory()
                .read_bytes(VirtAddr(addr), &mut buf)
                .map_err(err)?;
        }

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
            let dtb = dbg.inner.target.current_dtb();
            let record_ti = dbg
                .inner
                .target
                .symbols
                .find_type_across_modules(dtb, record_type)
                .ok_or_else(|| raise(format!("unknown type: {record_type}")))?;
            let link_offset = record_ti.field_offset(link_field).map_err(err)?;
            let bases = walk_list_bases(&dbg, head, link_offset)?;
            (record_ti, bases)
        };
        Ok(bases
            .into_iter()
            .map(|base| Struct {
                dbg: self.dbg.clone_ref(py),
                name: record_type.to_string(),
                info: record_ti.clone(),
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

    /// `proc["FieldName"]`; collision-proof field access (works even when a
    /// field name shadows a method).
    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        if !self.info.fields.contains_key(name) {
            return Err(pyo3::exceptions::PyKeyError::new_err(name.to_string()));
        }
        self.get_field(py, name)
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
/// `backend` is one of `"kd"` (default), `"gdb"`, `"memory"`, or `"dmp"`.
/// `connect` is the backend target: socket path / address for kd/gdb, or
/// dump file path for dmp; the per-backend default is used when omitted
/// (except dmp, which requires a path).
///
/// kd/gdb take the exclusive control lock before building the backend, so a
/// second live attach (here or against a running CLI) fails fast rather than
/// racing on the handshake the first session owns; memory/dmp are passive and
/// coexist with anything.
#[pyfunction]
#[pyo3(signature = (backend="kd", connect=None))]
fn attach(backend: &str, connect: Option<&str>) -> PyResult<Debugger> {
    let inner = if backend == "dmp" {
        let path = connect.ok_or_else(|| {
            err(Error::DebugInfo(
                "dmp backend requires a dump file path via connect=".into(),
            ))
        })?;
        let phys = Arc::new(PhysMem::dmp(std::path::Path::new(path)).map_err(err)?);
        let info = phys.dmp_info().expect("dmp_info for DMP").clone();
        Session::connect(phys, SessionLock::None, || {
            Ok(Box::new(DmpBackend::new(&info)) as Box<dyn DebugBackend>)
        })
        .map_err(err)?
    } else {
        let lock = match backend {
            "memory" => SessionLock::None,
            _ => SessionLock::Exclusive,
        };
        let phys = Arc::new(PhysMem::kvm().map_err(err)?);
        Session::connect(phys, lock, || {
            let be: Box<dyn DebugBackend> = match backend {
                "gdb" => Box::new(GdbClient::connect(connect.unwrap_or("127.0.0.1:1234"))?),
                "kd" => Box::new(KdBackend::connect(
                    connect.unwrap_or("/tmp/ntoseye-kd.sock"),
                )?),
                "memory" => Box::new(MemoryBackend::new()),
                other => {
                    return Err(Error::DebugInfo(format!(
                        "unknown backend '{other}': expected 'kd', 'gdb', 'memory', or 'dmp'"
                    )));
                }
            };
            Ok(be)
        })
        .map_err(err)?
    };
    Ok(Debugger {
        inner: SessionHandle::Owned(Box::new(inner)),
    })
}

/// Populate the `_ntoseye` extension module. The `#[pymodule]` entry point (and
/// thus the exported `PyInit__ntoseye` symbol) lives in the `ntoseye-py` wheel
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
    m.add_function(wrap_pyfunction!(attach, m)?)?;
    m.add("NtoseyeError", m.py().get_type::<NtoseyeError>())?;
    m.add("MemoryAccessError", m.py().get_type::<MemoryAccessError>())?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Proves the borrowed-handle lifetime guard without a live session: the
    // guard checks the validity flag *before* dereferencing the pointer, so an
    // invalidated handle panics rather than touching the (here dangling)
    // pointer. This is the use-after-return path a stashed `Debugger`/`Struct`
    // hits once its REPL command returns (the dispatcher flips the flag false).
    // The valid-flag path needs a real session and is covered by the
    // `examples/borrow_guard.py` REPL script.
    #[test]
    #[should_panic(expected = "must not be stashed")]
    fn invalidated_borrow_panics_instead_of_dereferencing() {
        let valid = Arc::new(AtomicBool::new(false));
        let handle = SessionHandle::Borrowed {
            // Never read: the assert on `valid` fires first.
            ptr: NonNull::<Session>::dangling(),
            valid,
        };
        // Triggers `Deref`, which must panic on the false flag.
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
                        address: 0x1000,
                        enabled: true,
                        symbol: None,
                        scope: "global".to_string(),
                        condition: None,
                        temporary: false,
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
