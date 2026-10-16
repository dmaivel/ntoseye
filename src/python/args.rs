//! Argument types for SDK methods. Each one parses its Python value once and
//! declares the type it accepts, so the generated stubs say `Literal[...]`,
//! `Process | int`, or `Callable[[Stop], object]` without a hand-written
//! annotation.

use pyo3::exceptions::{PyTypeError, PyValueError};
#[cfg(feature = "python-stubs")]
use pyo3::inspect::{PyStaticConstant, PyStaticExpr};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
#[cfg(feature = "python-stubs")]
use pyo3::{PyTypeInfo, type_hint_identifier, type_hint_subscript};

use super::command::PyArg;
use super::handle::Owner;
use super::process::Process;
use super::thread::{Cpu, Thread};
use crate::Backend;
use crate::dbg_backend::{ContinueDisposition, WatchpointAccess};
use crate::exception_policy::ExceptionPolicyMode;
use crate::guest::ProcessInfo;
use crate::kd::KdMemorySource;
use crate::session::WalkUntil;
#[cfg(feature = "python-stubs")]
use crate::session::driver::StopPy;
use crate::target::ReloadScope;
use crate::target::ThreadInfo;
use crate::target::irpfind::IrpPool;
use crate::target::mm::{PoolType, PoolUsageSort};
use crate::target::object::ObjectName;
use crate::target::sched::{ApcSelector, UniqStackScope};
use crate::target::workqueue::WorkQueueTypes;
use crate::types::VirtAddr;

/// A string argument restricted to fixed spellings, typed as
/// `typing.Literal[...]` in the stubs.
macro_rules! literal_arg {
    ($(#[$doc:meta])* $name:ident($target:ty) { $($text:literal => $value:expr),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy)]
        pub struct $name(pub $target);

        impl<'a, 'py> FromPyObject<'a, 'py> for $name {
            type Error = PyErr;

            #[cfg(feature = "python-stubs")]
            const INPUT_TYPE: PyStaticExpr = type_hint_subscript!(
                type_hint_identifier!("typing", "Literal"),
                $(PyStaticExpr::Constant {
                    value: PyStaticConstant::Str($text),
                }),+
            );

            fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
                let text: std::borrow::Cow<'_, str> = obj.extract()?;
                match &*text {
                    $($text => Ok($name($value)),)+
                    other => Err(PyValueError::new_err(format!(
                        "expected one of '{}', got {other:?}",
                        [$($text),+].join("', '"),
                    ))),
                }
            }
        }
    };
}

literal_arg! {
    /// `attach(backend=...)`: a live transport, or `None` for a crash dump.
    AttachBackend(Option<Backend>) {
        "kd" => Some(Backend::Kd),
        "kdnet" => Some(Backend::KdNet),
        "gdb" => Some(Backend::Gdb),
        "memory" => Some(Backend::Memory),
        "dmp" => None,
    }
}

literal_arg! {
    /// `attach(memory_source=...)`: where KD/KDNET reads guest memory.
    MemorySource(KdMemorySource) {
        "auto" => KdMemorySource::Auto,
        "host" => KdMemorySource::Host,
        "kd" => KdMemorySource::Kd,
    }
}

literal_arg! {
    /// How a resume acknowledges the current exception (KD).
    Disposition(ContinueDisposition) {
        "handled" => ContinueDisposition::Handled,
        "not_handled" => ContinueDisposition::NotHandled,
    }
}

impl PyArg for ContinueDisposition {
    type Py = Disposition;
    fn from_py(value: Disposition) -> Self {
        value.0
    }
}

literal_arg! {
    /// An instruction class a step walk stops before.
    Until(WalkUntil) {
        "call" => WalkUntil::Call,
        "ret" => WalkUntil::Return,
        "branch" => WalkUntil::Branch,
    }
}

/// `step(until=...)`, `step_over(until=...)`: the instruction class the
/// walk stops before (`tc`/`tt`/`th`), or the address it stops at
/// (`ta`/`pa`).
#[derive(FromPyObject)]
pub enum UntilArg {
    Flow(Until),
    Address(u64),
}

impl PyArg for WalkUntil {
    type Py = UntilArg;
    fn from_py(value: UntilArg) -> Self {
        match value {
            UntilArg::Flow(Until(until)) => until,
            UntilArg::Address(address) => WalkUntil::Address(VirtAddr(address)),
        }
    }
}

literal_arg! {
    /// A data watchpoint's access kind.
    WatchAccess(WatchpointAccess) {
        "write" => WatchpointAccess::Write,
        "read_write" => WatchpointAccess::ReadWrite,
    }
}

literal_arg! {
    /// An exception stop policy (`sxe`/`sxd`/`sxn`/`sxi`).
    PolicyMode(ExceptionPolicyMode) {
        "break" => ExceptionPolicyMode::Break,
        "second_chance" => ExceptionPolicyMode::SecondChance,
        "notify" => ExceptionPolicyMode::Notify,
        "ignore" => ExceptionPolicyMode::Ignore,
    }
}

literal_arg! {
    /// `Inspect.pool_usage(sort=...)`: `!poolused`'s order.
    PoolSort(PoolUsageSort) {
        "tag" => PoolUsageSort::Tag,
        "nonpaged" => PoolUsageSort::NonPagedBytes,
        "paged" => PoolUsageSort::PagedBytes,
    }
}

impl PyArg for PoolUsageSort {
    type Py = PoolSort;
    fn from_py(value: PoolSort) -> Self {
        value.0
    }
}

literal_arg! {
    /// `Inspect.pool_find(pool_type=...)`: the pool `!poolfind` searches.
    PoolKind(PoolType) {
        "nonpaged" => PoolType::NonPaged,
        "paged" => PoolType::Paged,
    }
}

impl PyArg for PoolType {
    type Py = PoolKind;
    fn from_py(value: PoolKind) -> Self {
        value.0
    }
}

/// A `bytes` (or `bytearray`) argument, typed `bytes`.
pub struct BytesArg(pub Vec<u8>);

impl<'a, 'py> FromPyObject<'a, 'py> for BytesArg {
    type Error = PyErr;

    #[cfg(feature = "python-stubs")]
    const INPUT_TYPE: PyStaticExpr = type_hint_identifier!("builtins", "bytes");

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(bytes) = obj.cast::<PyBytes>() {
            return Ok(BytesArg(bytes.as_bytes().to_vec()));
        }
        Ok(BytesArg(obj.cast::<PyByteArray>()?.to_vec()))
    }
}

/// A `when=` breakpoint predicate: called with the `Stop`, truthy to stop.
pub struct WhenCallback(pub Py<PyAny>);

impl<'a, 'py> FromPyObject<'a, 'py> for WhenCallback {
    type Error = PyErr;

    #[cfg(feature = "python-stubs")]
    const INPUT_TYPE: PyStaticExpr = type_hint_subscript!(
        type_hint_identifier!("collections.abc", "Callable"),
        PyStaticExpr::List {
            elts: &[<StopPy as PyTypeInfo>::TYPE_HINT]
        },
        type_hint_identifier!("builtins", "object")
    );

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if obj.is_callable() {
            Ok(WhenCallback(obj.to_owned().unbind()))
        } else {
            Err(PyTypeError::new_err("when must be callable"))
        }
    }
}

/// A process by handle or PID.
#[derive(FromPyObject)]
pub enum ProcessArg<'py> {
    Handle(PyRef<'py, Process>),
    Pid(u64),
}

/// A Windows thread by handle or `_ETHREAD` address.
#[derive(FromPyObject)]
pub enum ThreadArg<'py> {
    Handle(PyRef<'py, Thread>),
    Ethread(u64),
}

/// A processor by handle or index.
#[derive(FromPyObject)]
pub enum CpuArg<'py> {
    Handle(PyRef<'py, Cpu>),
    Index(u16),
}

/// Whose APC queues to decode: a process, a thread, or an `_ETHREAD`.
#[derive(FromPyObject)]
pub enum ApcTarget {
    Process(Py<Process>),
    Thread(Py<Thread>),
    Ethread(u64),
}

/// `Inspect.apcs(target=None)`: every thread by default.
impl PyArg for ApcSelector {
    type Py = Option<ApcTarget>;
    fn from_py(value: Self::Py) -> Self {
        Python::attach(|py| match value {
            None => ApcSelector::All,
            Some(ApcTarget::Process(process)) => ApcSelector::Process(process.borrow(py).info.pid),
            Some(ApcTarget::Thread(thread)) => ApcSelector::Thread(thread.borrow(py).info.ethread),
            Some(ApcTarget::Ethread(address)) => ApcSelector::Thread(VirtAddr(address)),
        })
    }

    fn from_py_in(py: Python<'_>, owner: &Owner, value: Self::Py) -> PyResult<Self> {
        Ok(match value {
            None => ApcSelector::All,
            Some(ApcTarget::Process(process)) => {
                ApcSelector::Process(ProcessInfo::from_py_in(py, owner, process)?.pid)
            }
            Some(ApcTarget::Thread(thread)) => {
                ApcSelector::Thread(ThreadInfo::from_py_in(py, owner, thread)?.ethread)
            }
            Some(ApcTarget::Ethread(address)) => ApcSelector::Thread(VirtAddr(address)),
        })
    }
}

/// `Inspect.uniqstack(process=None)`: every thread by default.
impl PyArg for UniqStackScope {
    type Py = Option<Py<Process>>;
    fn from_py(value: Self::Py) -> Self {
        Self::scope(value.map(ProcessInfo::from_py))
    }

    fn from_py_in(py: Python<'_>, owner: &Owner, value: Self::Py) -> PyResult<Self> {
        Ok(Self::scope(Option::<ProcessInfo>::from_py_in(
            py, owner, value,
        )?))
    }
}

impl UniqStackScope {
    fn scope(process: Option<ProcessInfo>) -> Self {
        match process {
            None => UniqStackScope::AllThreads,
            Some(process) => UniqStackScope::Process {
                pid: process.pid,
                name: process.name,
            },
        }
    }
}

literal_arg! {
    /// `Inspect.work_queues(queue_types=[...])`: a `WORK_QUEUE_TYPE` whose
    /// priority `!exqueue` lists (flags 0x10, 0x20, 0x40).
    WorkQueueTypeArg(u64) {
        "critical" => 0x10,
        "delayed" => 0x20,
        "hypercritical" => 0x40,
    }
}

impl PyArg for WorkQueueTypes {
    type Py = Vec<WorkQueueTypeArg>;
    fn from_py(value: Self::Py) -> Self {
        WorkQueueTypes(value.iter().fold(0, |flags, kind| flags | kind.0))
    }
}

/// An exception by NTSTATUS code or WinDbg alias (`av`, `bpe`, ...).
#[derive(FromPyObject)]
pub enum ExceptionCode {
    Code(u64),
    Alias(String),
}

/// A hypercall by call code, or by name: its TLFS name or the name
/// `x hv!*` gives it.
#[derive(FromPyObject)]
pub enum HypercallArg {
    Code(u16),
    Name(String),
}

/// A minifilter by its `_FLT_FILTER` address or its name (`"WdFilter"`).
#[derive(FromPyObject)]
pub enum FltFilterArg {
    Address(u64),
    Name(String),
}

/// An executive object by body or header address, or by object namespace
/// path (`\\Driver\\ACPI`).
#[derive(FromPyObject)]
pub enum ObjectArg {
    Address(u64),
    Path(String),
}

impl PyArg for ObjectName {
    type Py = ObjectArg;
    fn from_py(value: ObjectArg) -> Self {
        match value {
            ObjectArg::Address(address) => ObjectName::Address(VirtAddr(address)),
            ObjectArg::Path(path) => ObjectName::Path(path),
        }
    }
}

literal_arg! {
    /// `irp_find(pool_type=...)`: the pool `!irpfind` scans.
    IrpPoolArg(IrpPool) {
        "nonpaged" => IrpPool::NonPaged,
        "paged" => IrpPool::Paged,
    }
}

impl PyArg for IrpPool {
    type Py = IrpPoolArg;
    fn from_py(value: IrpPoolArg) -> Self {
        value.0
    }
}

literal_arg! {
    /// `Symbols.reload(scope=...)`: whose modules `.reload` reloads.
    ReloadScopeArg(ReloadScope) {
        "current" => ReloadScope::Current,
        "kernel" => ReloadScope::Kernel,
        "user" => ReloadScope::User,
    }
}

impl PyArg for ReloadScope {
    type Py = ReloadScopeArg;
    fn from_py(value: ReloadScopeArg) -> Self {
        value.0
    }
}
