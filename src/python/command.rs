//! The SDK half of `#[command]`: the objects a command's method can be
//! placed on (`python = Inspect`), how such an object binds a `receiver`
//! argument, how a keyword argument converts ([`SdkArg`], [`PyArg`]), and
//! [`run`], which every generated method calls to admit the command's
//! effects and run it on the session thread. [`admit`] is also what the
//! hand-written methods' `require_halted` and kernel checks go through, so
//! the SDK refuses with the same decision as the REPL.

use pyo3::PyClass;
use pyo3::prelude::*;

use super::args::{AddressArg, BytesArg};
use super::context::{Context, in_context};
use super::handle::Owner;
use super::record::{ToValue, Typed};
use super::{ErrorKind, err, error, raise};
use crate::error::Result;
use crate::expr::Expr;
use crate::session::Session;
use crate::session::effects::{Effects, Refusal, RunState};
use crate::types::VirtAddr;

// The classes `#[command(python = ...)]` names, as the macro spells them.
pub use super::breakpoints::{Breakpoints, Exceptions};
pub use super::handle::Debugger;
pub use super::inspect::Inspect;
pub use super::memory::Memory;
pub use super::module::{Device, Driver, Module};
pub use super::process::{Heap, Heaps, Process};
pub use super::secure::{SecureKernel, Trustlet};
pub use super::symbols::Symbols;
pub use super::thread::{Cpu, Thread};
pub use super::userdump::{UserDump, UserProcess, UserThread};

/// An SDK object a `#[command]` method can be placed on: the debugger it
/// runs in and the context (process, thread) its calls run in.
pub trait CommandHost {
    fn session(&self) -> HostSession<'_>;

    /// The context its calls run in: the kernel's, unless the object has
    /// its own (a process, a thread).
    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Context::default())
    }

    /// Refuse an operation this object cannot run, before it reaches the
    /// session: a `Memory` in VTL1 has no NT state to describe and cannot
    /// be written. `effects` are the command's.
    fn refuse(&self, _operation: &str, _effects: &Effects) -> PyResult<()> {
        Ok(())
    }

    /// Get the session ready for a call admitted on this object, on the
    /// session thread: a `Heap` loads its process's module symbols, as its
    /// decoders need ntdll's.
    fn prepare(&self, _session: &mut Session) -> PyResult<()> {
        Ok(())
    }

    /// The owner a handle argument must belong to: the object's own, or,
    /// for the `Debugger`, the debugger itself.
    fn argument_owner(slf: &Bound<'_, Self>) -> PyResult<Owner>
    where
        Self: PyClass,
    {
        let py = slf.py();
        match slf.borrow().session() {
            HostSession::Owner(owner) => Ok(owner.clone_ref(py)),
            HostSession::Debugger(_) => {
                let debugger = slf.as_any().cast::<Debugger>()?;
                Ok(Owner::unstamped(py, &debugger.clone().unbind()))
            }
        }
    }
}

/// A `#[arg(receiver)]` argument the object supplies: a `Thread` handle is
/// the thread `!thread` inspects.
pub trait Bind<T> {
    fn bind(&self) -> T;
}

/// How a [`CommandHost`] reaches its session.
pub enum HostSession<'a> {
    /// A handle or namespace, through its owner, which a handle argument
    /// must share.
    Owner(&'a Owner),
    /// The debugger itself (`Debugger.write_dump`).
    Debugger(&'a Debugger),
}

impl HostSession<'_> {
    /// Run `f` scoped to `context` on the session thread.
    fn with_in<R: Send>(
        &self,
        py: Python<'_>,
        context: &Context,
        f: impl FnOnce(&mut Session) -> PyResult<R> + Send,
    ) -> PyResult<R> {
        match self {
            Self::Owner(owner) => owner.with_in(py, context, f),
            Self::Debugger(debugger) => {
                debugger.with_session(|session| in_context(session, context, f))
            }
        }
    }
}

/// How a command argument arrives from Python: as `Py`, which the stub
/// types, then converted.
pub trait PyArg: Sized {
    type Py;
    fn from_py(value: Self::Py) -> Self;

    /// [`Self::from_py`] for a method of an object of `owner`'s debugger: a
    /// handle argument (a `Process`) must belong to it.
    fn from_py_in(_py: Python<'_>, _owner: &Owner, value: Self::Py) -> PyResult<Self> {
        Ok(Self::from_py(value))
    }
}

/// How a generated method's argument arrives from Python: as `Py`, which
/// the stub types, then converted before the call, or, for an address
/// given as a debugger expression, on the session thread ([`Pending`]).
/// Every [`PyArg`] is one; an address is one of its own, because only the
/// session can evaluate an expression.
pub trait SdkArg: Sized {
    type Py;

    /// Convert `value` for a method of an object of `owner`'s debugger
    /// ([`CommandHost::argument_owner`]): a handle argument must belong to
    /// it and be current.
    fn from_sdk(py: Python<'_>, owner: &Owner, value: Self::Py) -> PyResult<Pending<Self>>;
}

impl<T: PyArg> SdkArg for T {
    type Py = T::Py;

    fn from_sdk(py: Python<'_>, owner: &Owner, value: Self::Py) -> PyResult<Pending<T>> {
        Ok(Pending::Ready(T::from_py_in(py, owner, value)?))
    }
}

/// An argument as a generated method has it before the call: converted, or
/// a debugger expression for an address, which [`Self::resolve`] evaluates
/// on the session thread, in the method's context once the command is
/// admitted, and `finish`es into the argument.
pub enum Pending<T> {
    Ready(T),
    Expression(String, fn(VirtAddr) -> T),
}

impl<T> Pending<T> {
    /// The argument, an expression evaluated as the REPL evaluates one
    /// (symbols, `module!symbol+0x10`, registers, `poi(...)`), in the
    /// session's current context.
    pub fn resolve(self, session: &Session) -> Result<T> {
        match self {
            Pending::Ready(value) => Ok(value),
            Pending::Expression(text, finish) => Expr::eval(&text, &session.target).map(finish),
        }
    }
}

/// Arguments that arrive as they are.
macro_rules! as_given {
    ($($ty:ty),* $(,)?) => {$(
        impl PyArg for $ty {
            type Py = $ty;
            fn from_py(value: $ty) -> Self {
                value
            }
        }
    )*};
}

as_given!(u8, u16, u32, u64, usize, i64, bool, String, Vec<u64>);

/// `bytes`.
impl PyArg for Vec<u8> {
    type Py = BytesArg;
    fn from_py(value: BytesArg) -> Self {
        value.0
    }
}

/// An address: an `int`, a debugger expression (`"nt!KiSystemCall64"`), or
/// the handle of the object at it (`Process`, `Driver`, ...).
impl SdkArg for VirtAddr {
    type Py = AddressArg;

    fn from_sdk(py: Python<'_>, owner: &Owner, value: AddressArg) -> PyResult<Pending<Self>> {
        value.pending(py, owner, |address| address)
    }
}

impl SdkArg for Option<VirtAddr> {
    type Py = Option<AddressArg>;

    fn from_sdk(
        py: Python<'_>,
        owner: &Owner,
        value: Option<AddressArg>,
    ) -> PyResult<Pending<Self>> {
        value.map_or(Ok(Pending::Ready(None)), |value| {
            value.pending(py, owner, Some)
        })
    }
}

impl<T: PyArg> PyArg for Option<T> {
    type Py = Option<T::Py>;
    fn from_py(value: Self::Py) -> Self {
        value.map(T::from_py)
    }

    fn from_py_in(py: Python<'_>, owner: &Owner, value: Self::Py) -> PyResult<Self> {
        value
            .map(|value| T::from_py_in(py, owner, value))
            .transpose()
    }
}

/// Run a command for the SDK: on the session thread, in `host`'s context,
/// after [`admit`] lets `effects` through; the result is its record class.
/// `operation` (`Inspect.job`) names it in a refusal.
pub fn run<'py, H, T>(
    py: Python<'py>,
    host: &H,
    operation: &str,
    effects: &Effects,
    f: impl FnOnce(&mut Session) -> Result<T> + Send,
) -> PyResult<Typed<'py, T>>
where
    H: CommandHost + Sync,
    T: ToValue + Send,
{
    host.refuse(operation, effects)?;
    let context = host.context(py)?;
    let value = host.session().with_in(py, &context, |session| {
        admit(session, effects, operation)?;
        host.prepare(session)?;
        f(session).map_err(err)
    })?;
    Typed::new(py, value)
}

/// [`Session::admit`] for the SDK: the refusal as the exception the SDK has
/// always raised for it. A halt is settled first, because KD can leave the
/// backend reporting a run after the VM stopped (a caught, undrained stop).
pub fn admit(session: &mut Session, effects: &Effects, operation: &str) -> PyResult<()> {
    if effects.state != RunState::Any {
        session.settle_pending_stop().map_err(err)?;
    }
    session.admit(effects).map_err(|refusal| match refusal {
        Refusal::KernelRequired(core) => err(core),
        Refusal::Running {
            unreachable: Some(reason),
            ..
        } => error(
            ErrorKind::TargetRunning,
            format!("{operation} needs a halted target; {reason}"),
        ),
        Refusal::Running {
            unreachable: None, ..
        } => error(
            ErrorKind::TargetRunning,
            format!("{operation} requires the VM to be halted; call interrupt() first"),
        ),
        Refusal::AlreadyHalted => raise(format!("{operation}: the target is already halted")),
        Refusal::NoExecutionControl { backend } => raise(format!(
            "the {backend} backend cannot run or step the target"
        )),
        Refusal::StaticDump => raise(format!(
            "{operation} is not applicable to a static crash dump"
        )),
        Refusal::Unsupported {
            capability,
            backend,
        } => raise(format!(
            "{operation} needs {} support, which the {backend} backend lacks",
            capability.label()
        )),
        Refusal::Vtl1(refusal) => raise(refusal.message(operation)),
    })
}
