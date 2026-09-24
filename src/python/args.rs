//! Argument types for SDK methods. Each one parses its Python value once and
//! declares the type it accepts, so the generated stubs say `Literal[...]`,
//! `Process | int`, or `Callable[[Stop], object]` without a hand-written
//! annotation.

use pyo3::exceptions::{PyTypeError, PyValueError};
#[cfg(feature = "python-stubs")]
use pyo3::inspect::{PyStaticConstant, PyStaticExpr};
use pyo3::prelude::*;
#[cfg(feature = "python-stubs")]
use pyo3::{PyTypeInfo, type_hint_identifier, type_hint_subscript};

use super::module::Device;
use super::process::Process;
#[cfg(feature = "python-stubs")]
use super::stop::Stop;
use super::thread::{Cpu, Thread};
use crate::Backend;
use crate::dbg_backend::{ContinueDisposition, WatchpointAccess};
use crate::exception_policy::ExceptionPolicyMode;
use crate::kd::KdMemorySource;
use crate::session::StepMode;

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

/// The instruction class a `step(until=...)` walk stops before.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UntilFlow {
    Call,
    Return,
    Branch,
}

literal_arg! {
    /// `step(until=...)`.
    Until(UntilFlow) {
        "call" => UntilFlow::Call,
        "ret" => UntilFlow::Return,
        "branch" => UntilFlow::Branch,
    }
}

literal_arg! {
    /// `run_to(step=...)`.
    Step(StepMode) {
        "over" => StepMode::Over,
        "into" => StepMode::Into,
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

/// A `when=` breakpoint predicate: called with the `Stop`, truthy to stop.
pub struct WhenCallback(pub Py<PyAny>);

impl<'a, 'py> FromPyObject<'a, 'py> for WhenCallback {
    type Error = PyErr;

    #[cfg(feature = "python-stubs")]
    const INPUT_TYPE: PyStaticExpr = type_hint_subscript!(
        type_hint_identifier!("collections.abc", "Callable"),
        PyStaticExpr::List {
            elts: &[<Stop as PyTypeInfo>::TYPE_HINT]
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
pub enum ApcTarget<'py> {
    Process(PyRef<'py, Process>),
    Thread(PyRef<'py, Thread>),
    Ethread(u64),
}

/// A device object by handle, or a device or devnode address.
#[derive(FromPyObject)]
pub enum DeviceArg<'py> {
    Device(PyRef<'py, Device>),
    Address(u64),
}

/// An exception by NTSTATUS code or WinDbg alias (`av`, `bpe`, ...).
#[derive(FromPyObject)]
pub enum ExceptionCode {
    Code(u64),
    Alias(String),
}
