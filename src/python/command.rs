//! The SDK half of `#[command]`: the objects a command's method can be
//! placed on (`python = Inspect`), how such an object binds a `receiver`
//! argument, how a keyword argument converts ([`PyArg`]), and [`run`], which
//! every generated method calls to admit the command's effects and run it
//! on the session thread. [`admit`] is also what the hand-written methods'
//! `require_halted` and kernel checks go through, so the SDK refuses with
//! the same decision as the REPL.

use pyo3::prelude::*;

use super::args::BytesArg;
use super::context::Context;
use super::handle::Owner;
use super::{ErrorKind, err, error, raise};
use crate::dbg_backend::processor_index_from_backend_thread_id;
use crate::error::Result;
use crate::guest::ProcessInfo;
use crate::session::Session;
use crate::session::effects::{Effects, Refusal, RunState, TargetScope};
use crate::target::cpu::Processor;
use crate::target::image::ImageRef;
use crate::target::{MemoryKind, ThreadInfo};
use crate::types::VirtAddr;
use crate::view::record::{ToView, Typed};

use super::context::Space;
pub use super::inspect::Inspect;
pub use super::memory::Memory;
pub use super::module::{Device, Driver, Module};
pub use super::process::{Heap, Heaps, Process};
pub use super::symbols::Symbols;
use super::symbols::load_scope_symbols;
pub use super::thread::{Cpu, Thread};
pub use super::userdump::{UserProcess, UserThread};
use crate::target::heap::HeapSelector;
use crate::target::memory::SearchSpace;

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

    /// Get the session ready for a call admitted on this object, on the
    /// session thread: a `Heap` loads its process's module symbols, as its
    /// decoders need ntdll's.
    fn prepare(&self, _session: &mut Session) -> PyResult<()> {
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

    /// [`Self::from_py`] for a method of an object of `owner`'s debugger: a
    /// handle argument (a `Process`) must belong to it.
    fn from_py_in(_py: Python<'_>, _owner: &Owner, value: Self::Py) -> PyResult<Self> {
        Ok(Self::from_py(value))
    }
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

impl PyArg for u32 {
    type Py = u32;
    fn from_py(value: u32) -> Self {
        value
    }
}

impl PyArg for usize {
    type Py = usize;
    fn from_py(value: usize) -> Self {
        value
    }
}

impl PyArg for Vec<u64> {
    type Py = Vec<u64>;
    fn from_py(value: Vec<u64>) -> Self {
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

/// `bytes`.
impl PyArg for Vec<u8> {
    type Py = BytesArg;
    fn from_py(value: BytesArg) -> Self {
        value.0
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

    fn from_py_in(py: Python<'_>, owner: &Owner, value: Self::Py) -> PyResult<Self> {
        value
            .map(|value| T::from_py_in(py, owner, value))
            .transpose()
    }
}

/// A process handle argument: the process it is.
impl PyArg for ProcessInfo {
    type Py = Py<Process>;
    fn from_py(value: Py<Process>) -> Self {
        Python::attach(|py| value.borrow(py).info.clone())
    }

    fn from_py_in(py: Python<'_>, owner: &Owner, value: Py<Process>) -> PyResult<Self> {
        let process = value.borrow(py);
        process.owner.require_argument_of(py, owner, "process")?;
        Ok(process.info.clone())
    }
}

/// A thread handle argument: the thread it is.
impl PyArg for ThreadInfo {
    type Py = Py<Thread>;
    fn from_py(value: Py<Thread>) -> Self {
        Python::attach(|py| value.borrow(py).info.clone())
    }

    fn from_py_in(py: Python<'_>, owner: &Owner, value: Py<Thread>) -> PyResult<Self> {
        let thread = value.borrow(py);
        thread.owner.require_argument_of(py, owner, "thread")?;
        Ok(thread.info.clone())
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
    T: ToView + Send,
{
    host.refuse(operation, effects)?;
    let context = host.context(py)?;
    let value = host.owner().with_in(py, &context, |session| {
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

/// A process's heap list: its calls run in the process, with its module
/// symbols loaded (the heap decoders read ntdll's).
impl CommandHost for Heaps {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Context::process(self.info.clone()))
    }

    fn prepare(&self, session: &mut Session) -> PyResult<()> {
        load_scope_symbols(session, &Space::Process(self.info.clone()))
    }
}

/// One heap: its calls run in its process, as the heap list's do.
impl CommandHost for Heap {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(Context::process(self.info.clone()))
    }

    fn prepare(&self, session: &mut Session) -> PyResult<()> {
        load_scope_symbols(session, &Space::Process(self.info.clone()))
    }
}

/// A heap is the heap at its address.
impl Bind<HeapSelector> for Heap {
    fn bind(&self) -> HeapSelector {
        HeapSelector::Address(self.address)
    }
}

/// The process a `Memory` addresses: `proc.memory`'s, none for the
/// kernel's and the other spaces.
impl Bind<Option<ProcessInfo>> for Memory {
    fn bind(&self) -> Option<ProcessInfo> {
        match &self.space {
            Space::Process(info) => Some(info.clone()),
            _ => None,
        }
    }
}

/// How a search in a `Memory` describes its matches: NT's region
/// descriptions cover neither VTL1 nor roots outside NT.
impl Bind<SearchSpace> for Memory {
    fn bind(&self) -> SearchSpace {
        match self.space {
            Space::Physical => SearchSpace::Physical,
            Space::Secure(_) => SearchSpace::Virtual(Some("vtl1")),
            Space::Root(_) => SearchSpace::Virtual(Some("foreign")),
            Space::Kernel | Space::Process(_) => SearchSpace::Virtual(None),
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

    /// A kernel command reads NT's state about the module, which a
    /// secure-kernel module does not have (Driver Verifier never tracks one).
    fn refuse(&self, operation: &str, effects: &Effects) -> PyResult<()> {
        if effects.target == TargetScope::Kernel {
            self.space.require_nt(operation)?;
        }
        Ok(())
    }
}

/// A module binds its short name (`!chkimg nt`).
impl Bind<String> for Module {
    fn bind(&self) -> String {
        self.info.short_name.clone()
    }
}

/// A module binds its image (`!dh`, `!lmi`): its base and loader entry, in
/// the address space it was listed in. The kernel's is left to the command,
/// which names it for the session.
impl Bind<ImageRef> for Module {
    fn bind(&self) -> ImageRef {
        ImageRef {
            base: self.info.base_address,
            module: Some(self.info.clone()),
            dtb: match &self.space {
                Space::Process(process) => Some(process.dtb),
                Space::Secure(root) | Space::Root(root) => Some(*root),
                Space::Kernel | Space::Physical => None,
            },
        }
    }
}
