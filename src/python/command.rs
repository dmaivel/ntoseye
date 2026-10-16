//! The SDK half of `#[command]`: the objects a command's method can be
//! placed on (`python = Inspect`), how such an object binds a `receiver`
//! argument, how a keyword argument converts ([`PyArg`]), and [`run`], which
//! every generated method calls to admit the command's effects and run it
//! on the session thread. [`admit`] is also what the hand-written methods'
//! `require_halted` and kernel checks go through, so the SDK refuses with
//! the same decision as the REPL.

use pyo3::prelude::*;

use super::context::Context;
use super::handle::Owner;
use super::{ErrorKind, err, error, raise};
use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::error::Result;
use crate::guest::ProcessInfo;
use crate::session::Session;
use crate::session::effects::{Effects, Refusal, RunState, TargetScope};
use crate::target::cpu::Processor;
use crate::target::{MemoryKind, ThreadInfo};
use crate::types::VirtAddr;
use crate::view::record::{ToView, Typed};

use super::context::Space;
pub use super::inspect::Inspect;
pub use super::memory::Memory;
pub use super::module::{Device, Driver, Module};
pub use super::process::Process;
pub use super::thread::{Cpu, Thread};
pub use super::userdump::{UserProcess, UserThread};

/// An SDK object a `#[command]` method can be placed on: the debugger it
/// runs in and the context (process, thread) its calls run in.
pub trait CommandHost {
    fn owner(&self) -> &Owner;
    fn context(&self, py: Python<'_>) -> PyResult<Context>;

    /// Refuse an operation this object cannot run, before it reaches the
    /// session: a `Memory` in VTL1 has no NT state to describe and cannot
    /// be written. `effects` are the command's.
    fn refuse(&self, _operation: &str, _effects: &Effects) -> PyResult<()> {
        Ok(())
    }
}

/// A `#[arg(receiver)]` argument the object supplies: a `Thread` handle is
/// the thread `!thread` inspects.
pub trait Bind<T> {
    fn bind(&self) -> T;
}

/// How a command argument arrives from Python: as `Py`, which the stub
/// types, then converted.
pub trait PyArg: Sized {
    type Py;
    fn from_py(value: Self::Py) -> Self;
}

impl PyArg for u64 {
    type Py = u64;
    fn from_py(value: u64) -> Self {
        value
    }
}

impl PyArg for u8 {
    type Py = u8;
    fn from_py(value: u8) -> Self {
        value
    }
}

impl PyArg for u16 {
    type Py = u16;
    fn from_py(value: u16) -> Self {
        value
    }
}

impl PyArg for i64 {
    type Py = i64;
    fn from_py(value: i64) -> Self {
        value
    }
}

impl PyArg for bool {
    type Py = bool;
    fn from_py(value: bool) -> Self {
        value
    }
}

impl PyArg for String {
    type Py = String;
    fn from_py(value: String) -> Self {
        value
    }
}

impl PyArg for VirtAddr {
    type Py = u64;
    fn from_py(value: u64) -> Self {
        VirtAddr(value)
    }
}

impl<T: PyArg> PyArg for Option<T> {
    type Py = Option<T::Py>;
    fn from_py(value: Self::Py) -> Self {
        value.map(T::from_py)
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
    H: CommandHost,
    T: ToView + Send,
{
    host.refuse(operation, effects)?;
    let context = host.context(py)?;
    let value = host.owner().with_in(py, &context, |session| {
        admit(session, effects, operation)?;
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
        Refusal::ReadOnlyVtl1 => raise("VTL1 memory is read-only"),
    })
}

impl CommandHost for Inspect {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Context::default())
    }
}

impl CommandHost for Process {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Context::process(self.info.clone()))
    }
}

impl Bind<ProcessInfo> for Process {
    fn bind(&self) -> ProcessInfo {
        self.info.clone()
    }
}

impl CommandHost for Thread {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, py: Python<'_>) -> PyResult<Context> {
        self.thread_context(py)
    }
}

impl Bind<ThreadInfo> for Thread {
    fn bind(&self) -> ThreadInfo {
        self.info.clone()
    }
}

impl CommandHost for Cpu {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Context::vcpu(self.id.clone()))
    }
}

/// A `Cpu` is its processor; an id that names none (not `p<pid>.<tid>`)
/// leaves it to the session, which reads the current vCPU's, the `Cpu`'s
/// own in its context.
impl Bind<Option<Processor>> for Cpu {
    fn bind(&self) -> Option<Processor> {
        processor_index_from_backend_thread_id(&self.id).map(Processor)
    }
}

/// A `Memory` runs a command in its space's context: `proc.memory` in the
/// process's, `dbg.memory` and `dbg.physical` in the kernel's.
impl CommandHost for Memory {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(self.space.context())
    }

    /// A kernel (or NT) command reads NT's state about an address, which
    /// VTL1 and roots outside NT do not have; a write needs a writable space.
    fn refuse(&self, operation: &str, effects: &Effects) -> PyResult<()> {
        if effects.target != TargetScope::Any {
            self.space.require_nt(operation)?;
        }
        if !effects.writes.is_empty() {
            self.space.require_writable()?;
        }
        Ok(())
    }
}

/// Which memory a `Memory` addresses: `dbg.physical` the physical, every
/// other space its virtual addresses.
impl Bind<MemoryKind> for Memory {
    fn bind(&self) -> MemoryKind {
        match self.space {
            Space::Physical => MemoryKind::Physical,
            _ => MemoryKind::Virtual,
        }
    }
}

/// A user-mode minidump's process: the dump's one address space.
impl CommandHost for UserProcess {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Context::default())
    }
}

/// A user-mode minidump's thread: its calls run with it selected.
impl CommandHost for UserThread {
    fn owner(&self) -> &Owner {
        UserThread::owner(self)
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(UserThread::context(self))
    }
}

/// A module: its calls run in the address space it is loaded in.
impl CommandHost for Module {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Module::context(self))
    }
}

/// A module binds its short name (`!chkimg nt`).
impl Bind<String> for Module {
    fn bind(&self) -> String {
        self.info.short_name.clone()
    }
}
