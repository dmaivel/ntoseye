//! The `ntoseye` Python SDK (the `_ntoseye` extension module and the REPL's
//! embedded interpreter): namespaces and typed handles bound to an address
//! space, with no global inspection selection.
//!
//! Every handle reaches the session through [`handle::Owner`] or
//! [`handle::Debugger::with_session`], and scoped work goes through
//! [`context::in_context`], so the user's REPL selection is never disturbed.

#[cfg(all(feature = "cli", feature = "python-extension"))]
use std::ffi::OsString;
use std::time::Duration;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyType};

#[cfg(all(feature = "cli", feature = "python-extension"))]
use crate::cli;
use crate::error::Error;
use crate::kd::KdMemorySource;
use crate::session::Session;
use crate::target::meta::decode_error_code;
use crate::view::shape::{Typed, ViewValue};
use crate::view::{self, PyShape};
use crate::{Backend, TargetSpec};

pub mod args;
pub mod breakpoints;
pub mod context;
pub mod debugger;
pub mod embed;
pub mod handle;
pub mod inspect;
pub mod iter;
pub mod memory;
pub mod module;
pub mod process;
pub mod record;
pub mod runcontrol;
pub mod runner;
pub mod secure;
pub mod stop;
pub mod symbols;
#[cfg(test)]
mod tests;
pub mod thread;
pub mod types;

use args::{AttachBackend, MemorySource};
use handle::Actor;
pub use handle::Debugger;
use record::PlainDict;

/// Sanity caps for the raw byte APIs. The SDK is local and trusted, but an
/// accidental huge length (`read(addr, 10**12)`) would allocate before the
/// read and OOM the interpreter; reject it as a clean error instead.
pub const MAX_READ_LEN: usize = 1 << 28; // 256 MiB

/// The SDK's exception classes. They are declared in the package's own
/// Python (`ntoseye/__init__.py`), which is their one definition for both the
/// runtime and type checkers; this side only looks them up to raise them.
#[derive(Clone, Copy)]
pub enum ErrorKind {
    /// `NtoseyeError`, the base of the others.
    Ntoseye,
    /// `MemoryAccessError`: an unmapped or partially readable range.
    MemoryAccess,
    /// `TargetRunningError`: the operation needs a halted target.
    TargetRunning,
    /// `StaleHandleError`: a handle from before a reboot.
    StaleHandle,
    /// `SymbolNotFoundError`, also a `LookupError`.
    SymbolNotFound,
}

impl ErrorKind {
    /// `SymbolNotFound` is the last variant.
    const COUNT: usize = ErrorKind::SymbolNotFound as usize + 1;

    fn name(self) -> &'static str {
        match self {
            ErrorKind::Ntoseye => "NtoseyeError",
            ErrorKind::MemoryAccess => "MemoryAccessError",
            ErrorKind::TargetRunning => "TargetRunningError",
            ErrorKind::StaleHandle => "StaleHandleError",
            ErrorKind::SymbolNotFound => "SymbolNotFoundError",
        }
    }
}

static ERROR_TYPES: [PyOnceLock<Py<PyType>>; ErrorKind::COUNT] =
    [const { PyOnceLock::new() }; ErrorKind::COUNT];

/// An object the package's own Python declares (`ntoseye/__init__.py`): the
/// exceptions, `Diagnostic` (Python so that it can be generic), and the
/// helpers records share with it.
pub fn package_attr<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    // Embedded, `ntoseye` must be the binary's own package even when one is
    // needed before any script ran: importing it first would load whichever
    // `ntoseye` is on `sys.path` (a checkout or wheel), whose objects scripts
    // never see.
    #[cfg(feature = "python-embed")]
    embed::install_package(py)?;
    py.import("ntoseye")?.getattr(name)
}

/// An SDK exception of `kind` carrying `message`. Callable from the session
/// thread (it takes the GIL to look the class up); a package that failed to
/// import surfaces as that import error instead.
pub fn error(kind: ErrorKind, message: impl std::fmt::Display) -> PyErr {
    let message = message.to_string();
    Python::attach(|py| {
        let class = ERROR_TYPES[kind as usize].get_or_try_init(py, || {
            Ok::<_, PyErr>(
                package_attr(py, kind.name())?
                    .cast_into::<PyType>()?
                    .unbind(),
            )
        });
        match class {
            Ok(class) => PyErr::from_type(class.bind(py).clone(), message),
            Err(error) => error,
        }
    })
}

/// Raise `SymbolNotFoundError(message)`.
pub fn symbol_not_found(message: impl std::fmt::Display) -> PyErr {
    error(ErrorKind::SymbolNotFound, message)
}

/// Map a core error to its Python exception: memory faults become
/// `MemoryAccessError`, a running target `TargetRunningError`, an unresolved
/// symbol `SymbolNotFoundError`, a bad argument `ValueError`, everything else
/// `NtoseyeError`.
pub fn err(core: Error) -> PyErr {
    let kind = match core {
        Error::InvalidArgument(message) => return PyValueError::new_err(message),
        Error::BadVirtualAddress(_)
        | Error::AddressNotInDump(_)
        | Error::BadPhysicalAddress(_)
        | Error::PartialRead(_)
        | Error::PartialWrite(_)
        | Error::BufferNotEnough
        | Error::InvalidRange => ErrorKind::MemoryAccess,
        Error::TargetRunning(_) => ErrorKind::TargetRunning,
        Error::SymbolNotFound(_) => ErrorKind::SymbolNotFound,
        _ => ErrorKind::Ntoseye,
    };
    error(kind, core)
}

/// Raise an `NtoseyeError` from a message (SDK-level errors, not core faults).
pub fn raise(message: impl std::fmt::Display) -> PyErr {
    error(ErrorKind::Ntoseye, message)
}

/// A `timeout` argument: seconds as a float, `None` for no limit.
pub fn timeout_arg(timeout: Option<f64>) -> PyResult<Option<Duration>> {
    match timeout {
        None => Ok(None),
        Some(seconds) if seconds.is_finite() && seconds >= 0.0 => {
            Ok(Some(Duration::from_secs_f64(seconds)))
        }
        Some(seconds) => Err(PyValueError::new_err(format!(
            "timeout must be a non-negative number of seconds, got {seconds}"
        ))),
    }
}

/// A value as a plain `dict`: an entity's `to_dict()` is the shape MCP renders
/// for it.
pub fn view_dict<'py, T: ViewValue<Source = T>>(
    py: Python<'py>,
    value: T,
) -> PyResult<PlainDict<'py>> {
    view::to_py(py, &T::view(value), PyShape::Plain)?
        .cast_into::<PyDict>()
        .map(PlainDict)
        .map_err(|e| raise(e.to_string()))
}

/// Attach to a guest and return a `Debugger`.
///
/// `backend` is one of `"kd"` (default), `"kdnet"`, `"gdb"`, `"memory"`, or
/// `"dmp"`. `connect` is the backend target: a socket path or address for
/// kd/kdnet/gdb, or the dump file path for dmp. Without `connect`, the function
/// uses the default of the backend, but dmp has no default and needs a path.
/// kdnet needs `key`. `memory_source` is `auto`, `host`, or `kd` for KD/KDNET.
///
/// For kd/kdnet/gdb, the function takes an instance lock for the target before
/// it makes the backend, so a second live attach to the same target fails
/// immediately without interfering with the handshake that the first session
/// owns. The memory and dmp backends are passive.
#[pyfunction]
#[pyo3(signature = (
    backend=AttachBackend(Some(Backend::Kd)),
    connect=None,
    key=None,
    memory_source=MemorySource(KdMemorySource::Auto),
))]
fn attach(
    py: Python<'_>,
    backend: AttachBackend,
    connect: Option<&str>,
    key: Option<&str>,
    memory_source: MemorySource,
) -> PyResult<Debugger> {
    let spec = match backend.0 {
        Some(backend) => TargetSpec::Live {
            backend,
            connect: connect.map(str::to_string),
            kdnet_key: key.map(str::to_string),
            memory_source: memory_source.0,
        },
        None => {
            let path = connect.ok_or_else(|| {
                PyValueError::new_err("the dmp backend needs a dump file path: connect=<path>")
            })?;
            TargetSpec::Dump(path.into())
        }
    };
    // Opening can take seconds (symbol downloads); other Python threads run.
    let actor = py
        .detach(|| {
            Actor::spawn(move || {
                Session::open_with_progress(&spec, &mut |line| eprintln!("{line}"))
            })
        })
        .map_err(err)?;
    Ok(Debugger::owned(actor))
}

/// Decode an NTSTATUS, Win32, or HRESULT code into its name and description
/// (`!error`). This function does not need a target.
#[pyfunction]
fn decode_error(py: Python<'_>, code: u64) -> PyResult<Typed<'_, view::meta::ErrorCode>> {
    Typed::new(py, view::meta::error_code(&decode_error_code(code)))
}

/// Run the `ntoseye` command line on `sys.argv` and return its exit status, as
/// the `ntoseye` script of the wheel does. The function releases the GIL for
/// the full session, and custom commands get the GIL again while they run.
#[cfg(all(feature = "cli", feature = "python-extension"))]
#[pyfunction]
#[pyo3(name = "_cli_main")]
fn cli_main(py: Python<'_>) -> PyResult<i32> {
    let argv: Vec<OsString> = py.import("sys")?.getattr("argv")?.extract()?;
    Ok(py.detach(|| cli::run_with_args(argv)))
}

// The one list of what the SDK exports: the wheel's `PyInit__ntoseye`, the
// REPL's embedded interpreter, and PyO3's introspection (the generated
// `_ntoseye.pyi`) all read it. `with_shape_classes!` adds every result class
// the views declare. Exceptions and the package re-exports live in
// `ntoseye/__init__.py`.
crate::view::with_shape_classes! {
/// The native module of the ntoseye SDK. Import from `ntoseye`, which
/// re-exports all of it.
#[pymodule]
pub mod _ntoseye {
    #[pymodule_export]
    use super::breakpoints::{Breakpoint, Breakpoints, Exceptions, Watchpoint};
    #[cfg(all(feature = "cli", feature = "python-extension"))]
    #[pymodule_export]
    use super::cli_main;
    #[pymodule_export]
    use super::handle::Debugger;
    #[pymodule_export]
    use super::inspect::Inspect;
    #[pymodule_export]
    use super::iter::{
        BreakpointIterator, CpuIterator, DriverIterator, ExceptionPolicyIterator, HeapIterator,
        MemoryRegionIterator, ModuleIterator, NameIterator, ProcessIterator, ThreadIterator,
    };
    #[pymodule_export]
    use super::memory::Memory;
    #[pymodule_export]
    use super::module::{Device, Driver, Drivers, Module, Modules};
    #[pymodule_export]
    use super::process::{Heap, Heaps, Process, Processes, Regions};
    #[pymodule_export]
    use super::record::{BaseRecord, Record};
    #[pymodule_export]
    use super::secure::{SecureKernel, Trustlet};
    #[pymodule_export]
    use super::stop::{Stop, StopContext};
    #[pymodule_export]
    use super::symbols::Symbols;
    #[pymodule_export]
    use super::thread::{Cpu, Cpus, Frame, Msrs, Registers, Thread, Threads};
    #[pymodule_export]
    use super::types::{Struct, Type, Types};
    #[pymodule_export]
    use super::{attach, decode_error};

    /// The ntoseye release version of this extension.
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const __version__: &str = env!("CARGO_PKG_VERSION");

    /// The git commit of this extension build (`<commit>`, `<commit>-dirty`, or
    /// `unknown`). Use it to find a stale extension in a long-lived
    /// interpreter.
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const build: &str = env!("NTOSEYE_BUILD");
}
}
