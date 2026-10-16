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

use super::command::{Pending, PyArg, SdkArg};
use super::context::Context;
use super::err;
use super::handle::Owner;
use super::module::{Device, Driver, Module};
use super::process::{Heap, Process};
use super::thread::{Cpu, Thread};
use crate::Backend;
use crate::backend::dbg_backend::ContinueDisposition;
use crate::base::error::Error;
use crate::base::types::VirtAddr;
use crate::nt::expr::NumberRadix;
use crate::nt::guest::{ModuleInfo, ProcessInfo};
use crate::nt::target::ThreadInfo;
use crate::nt::target::etw::EtwLoggerRef;
use crate::nt::target::fltmgr::FltFilterSelector;
use crate::nt::target::gflag::GlobalFlagChange;
use crate::nt::target::heap::HeapInfo;
use crate::nt::target::object::{DriverDeviceLink, DriverObjectInfo, ObjectName};
use crate::nt::target::sched::{ApcSelector, UniqStackScope};
use crate::nt::target::workqueue::WorkQueueTypes;
use crate::session::WalkUntil;
#[cfg(feature = "python-stubs")]
use crate::session::driver::StopPy;
use crate::session::exception_policy::{EventName, ExceptionPolicyFinalAction};

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
    Address(AddressArg),
}

impl SdkArg for Option<WalkUntil> {
    type Py = Option<UntilArg>;

    fn from_sdk(py: Python<'_>, owner: &Owner, value: Option<UntilArg>) -> PyResult<Pending<Self>> {
        match value {
            None => Ok(Pending::Ready(None)),
            Some(UntilArg::Flow(Until(until))) => Ok(Pending::Ready(Some(until))),
            Some(UntilArg::Address(address)) => {
                address.pending(py, owner, |address| Some(WalkUntil::Address(address)))
            }
        }
    }
}

/// An address: an `int`, a debugger expression that the session evaluates
/// as the REPL does (`"nt!KiSystemCall64+0x10"`, `"@rip"`, `"poi(@rsp)"`) in
/// the method's context, or the handle of the object at the address.
#[derive(FromPyObject)]
pub enum AddressArg {
    Value(u64),
    Expression(String),
    Object(AddressObject),
}

/// A handle given for its object's address: a `Process` its `_EPROCESS`, a
/// `Thread` its `_ETHREAD`, a `Module` its base, a `Driver` its
/// `_DRIVER_OBJECT`, a `Device` its `_DEVICE_OBJECT`, a `Heap` its heap.
#[derive(FromPyObject)]
pub enum AddressObject {
    Process(Py<Process>),
    Thread(Py<Thread>),
    Module(Py<Module>),
    Driver(Py<Driver>),
    Device(Py<Device>),
    Heap(Py<Heap>),
}

impl AddressObject {
    /// The object's address; the handle must belong to `owner`'s debugger.
    fn address(self, py: Python<'_>, owner: &Owner) -> PyResult<VirtAddr> {
        fn record<R: PyArg>(py: Python<'_>, owner: &Owner, value: R::Py) -> PyResult<R> {
            R::from_py_in(py, owner, value)
        }
        Ok(match self {
            Self::Process(handle) => record::<ProcessInfo>(py, owner, handle)?.eprocess,
            Self::Thread(handle) => record::<ThreadInfo>(py, owner, handle)?.ethread,
            Self::Module(handle) => record::<ModuleInfo>(py, owner, handle)?.base_address,
            Self::Driver(handle) => record::<DriverObjectInfo>(py, owner, handle)?.object,
            Self::Device(handle) => record::<DriverDeviceLink>(py, owner, handle)?.device,
            Self::Heap(handle) => record::<HeapInfo>(py, owner, handle)?.address,
        })
    }
}

impl AddressArg {
    /// The argument the address gives, through `finish`: an expression is
    /// evaluated later, on the session thread ([`Pending::resolve`]).
    pub fn pending<T>(
        self,
        py: Python<'_>,
        owner: &Owner,
        finish: fn(VirtAddr) -> T,
    ) -> PyResult<Pending<T>> {
        Ok(match self {
            Self::Value(address) => Pending::Ready(finish(VirtAddr(address))),
            Self::Expression(text) => Pending::Expression(text, finish),
            Self::Object(object) => Pending::Ready(finish(object.address(py, owner)?)),
        })
    }

    /// The address, for a hand-written method of an object of `owner`'s
    /// debugger: an expression is evaluated in `context`.
    pub fn resolve(self, py: Python<'_>, owner: &Owner, context: &Context) -> PyResult<VirtAddr> {
        match self.pending(py, owner, |address| address)? {
            Pending::Ready(address) => Ok(address),
            pending => owner.with_in(py, context, |session| pending.resolve(session).map_err(err)),
        }
    }
}

literal_arg! {
    /// An exception policy's explicit final action (`-f`): break, or
    /// continue as handled or not handled.
    FinalAction(ExceptionPolicyFinalAction) {
        "break" => ExceptionPolicyFinalAction::Break,
        "handled" => ExceptionPolicyFinalAction::Continue(ContinueDisposition::Handled),
        "not_handled" => ExceptionPolicyFinalAction::Continue(ContinueDisposition::NotHandled),
    }
}

impl PyArg for ExceptionPolicyFinalAction {
    type Py = FinalAction;
    fn from_py(value: FinalAction) -> Self {
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

impl PyArg for EventName {
    type Py = ExceptionCode;
    fn from_py(value: ExceptionCode) -> Self {
        match value {
            ExceptionCode::Code(code) => EventName::Code(code),
            ExceptionCode::Alias(text) => EventName::Text(text),
        }
    }
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

impl PyArg for FltFilterSelector {
    type Py = FltFilterArg;

    fn from_py(value: FltFilterArg) -> Self {
        match value {
            FltFilterArg::Address(address) => Self {
                name: format!("{address:#x}"),
                address: Some(VirtAddr(address)),
            },
            FltFilterArg::Name(name) => Self {
                name,
                address: None,
            },
        }
    }
}

/// An ETW session as the SDK names it: its logger id or `_WMI_LOGGER_CONTEXT`
/// address, or its name.
#[derive(FromPyObject)]
pub enum EtwLoggerArg {
    Value(u64),
    Name(String),
}

impl PyArg for EtwLoggerRef {
    type Py = EtwLoggerArg;

    /// A value is written in hex, which reads the same in every radix.
    fn from_py(value: EtwLoggerArg) -> Self {
        let text = match value {
            EtwLoggerArg::Value(value) => format!("{value:#x}"),
            EtwLoggerArg::Name(name) => name,
        };
        Self {
            text,
            radix: NumberRadix::Hexadecimal,
        }
    }
}

/// The SDK's `change` argument: a `str` as `!gflag` takes it (`"+ust"`,
/// `"-0x2000000"`, `"400"`), its values hex as in WinDbg.
pub struct GlobalFlagChangeArg(GlobalFlagChange);

impl<'a, 'py> FromPyObject<'a, 'py> for GlobalFlagChangeArg {
    type Error = PyErr;

    #[cfg(feature = "python-stubs")]
    const INPUT_TYPE: PyStaticExpr = type_hint_identifier!("builtins", "str");

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        let text: String = obj.extract()?;
        GlobalFlagChange::parse(&text, |value| {
            let digits = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            u64::from_str_radix(digits, 16)
                .map_err(|_| Error::InvalidArgument(format!("'{value}' is not a hex value")))
        })
        .map(Self)
        .map_err(|error| PyValueError::new_err(error.to_string()))
    }
}

impl PyArg for GlobalFlagChange {
    type Py = GlobalFlagChangeArg;
    fn from_py(value: GlobalFlagChangeArg) -> Self {
        value.0
    }
}

/// An executive object by body or header address, by object namespace
/// path (`\\Driver\\ACPI`), or by the handle of the object (`Process`,
/// `Driver`, ...).
#[derive(FromPyObject)]
pub enum ObjectArg {
    Address(u64),
    Path(String),
    Object(AddressObject),
}

impl ObjectArg {
    fn name(self, py: Python<'_>, owner: &Owner) -> PyResult<ObjectName> {
        Ok(match self {
            ObjectArg::Address(address) => ObjectName::Address(VirtAddr(address)),
            ObjectArg::Path(path) => ObjectName::Path(path),
            ObjectArg::Object(object) => ObjectName::Address(object.address(py, owner)?),
        })
    }
}

impl SdkArg for ObjectName {
    type Py = ObjectArg;

    fn from_sdk(py: Python<'_>, owner: &Owner, value: ObjectArg) -> PyResult<Pending<Self>> {
        value.name(py, owner).map(Pending::Ready)
    }
}
