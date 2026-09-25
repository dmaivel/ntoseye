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
use pyo3::types::{PyDict, PyList, PyType};

#[cfg(all(feature = "cli", feature = "python-extension"))]
use crate::cli;
use crate::error::Error;
use crate::kd::KdMemorySource;
use crate::session::Session;
use crate::target::meta::decode_error_code;
use crate::view::{self, PyShape, View};
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
use record::{PlainDict, Record};

/// Sanity caps for the raw byte APIs. The SDK is local and trusted, but an
/// accidental huge length (`read(addr, 10**12)`) would allocate before the
/// read and OOM the interpreter; reject it as a clean error instead.
pub const MAX_READ_LEN: usize = 1 << 28; // 256 MiB
pub const MAX_SEARCH_LEN: usize = 1 << 30; // 1 GiB scanned per call

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

/// An SDK exception of `kind` carrying `message`. Callable from the session
/// thread (it takes the GIL to look the class up); a package that failed to
/// import surfaces as that import error instead.
pub fn error(kind: ErrorKind, message: impl std::fmt::Display) -> PyErr {
    let message = message.to_string();
    Python::attach(|py| {
        let class = ERROR_TYPES[kind as usize].get_or_try_init(py, || {
            Ok::<_, PyErr>(
                py.import("ntoseye")?
                    .getattr(kind.name())?
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

/// Render a neutral [`View`] object into a [`Record`] (the shared shape with
/// the MCP surface; here addresses come through as ints, there as hex).
pub fn view_record<'py>(py: Python<'py>, v: &View) -> PyResult<Bound<'py, Record>> {
    view::to_py(py, v, PyShape::Records)?
        .cast_into::<Record>()
        .map_err(|e| raise(e.to_string()))
}

/// Render a neutral [`View`] object as a plain `dict`: an entity's `to_dict()`
/// is the shape MCP renders for it.
pub fn view_dict<'py>(py: Python<'py>, v: &View) -> PyResult<PlainDict<'py>> {
    view::to_py(py, v, PyShape::Plain)?
        .cast_into::<PyDict>()
        .map(PlainDict)
        .map_err(|e| raise(e.to_string()))
}

/// Render a neutral [`View`] list of objects into [`Record`]s.
pub fn view_records<'py>(py: Python<'py>, v: &View) -> PyResult<Vec<Bound<'py, Record>>> {
    view::to_py(py, v, PyShape::Records)?
        .cast_into::<PyList>()
        .map_err(|e| raise(e.to_string()))?
        .iter()
        .map(|item| item.cast_into::<Record>().map_err(|e| raise(e.to_string())))
        .collect()
}

/// Attach to a guest and return a `Debugger`.
///
/// `backend` is one of `"kd"` (default), `"kdnet"`, `"gdb"`, `"memory"`, or
/// `"dmp"`. `connect` is the backend target: socket path / address for
/// kd/kdnet/gdb, or the dump file path for dmp; the per-backend default is used
/// when omitted (except dmp, which requires a path). `key` is required for
/// kdnet. `memory_source` is `auto`, `host`, or `kd` for KD/KDNET.
///
/// kd/kdnet/gdb take a per-target instance lock before building the backend, so
/// a second live attach against the same target fails fast rather than racing
/// on the handshake the first session owns; memory/dmp are passive.
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

/// Decode an NTSTATUS, Win32, or HRESULT code to its name and description
/// (`!error`). Needs no target.
#[pyfunction]
fn decode_error(py: Python<'_>, code: u64) -> PyResult<Bound<'_, Record>> {
    view_record(py, &view::meta::error_code(&decode_error_code(code)))
}

/// Run the `ntoseye` command line on `sys.argv` and return its exit status:
/// the wheel's `ntoseye` script. The GIL is released for the whole session;
/// custom commands take it back while they run.
#[cfg(all(feature = "cli", feature = "python-extension"))]
#[pyfunction]
#[pyo3(name = "_cli_main")]
fn cli_main(py: Python<'_>) -> PyResult<i32> {
    let argv: Vec<OsString> = py.import("sys")?.getattr("argv")?.extract()?;
    Ok(py.detach(|| cli::run_with_args(argv)))
}

// The one list of what the SDK exports: the wheel's `PyInit__ntoseye`, the
// REPL's embedded interpreter, and PyO3's introspection (the generated
// `_ntoseye.pyi`) all read it. Exceptions and the package re-exports live in
// `ntoseye/__init__.py`.
/// The ntoseye SDK's native module. Import from `ntoseye`, which re-exports
/// all of it.
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
        BreakpointIterator, CpuIterator, DriverIterator, HeapIterator, MemoryRegionIterator,
        ModuleIterator, NameIterator, ProcessIterator, RecordIterator, ThreadIterator,
    };
    #[pymodule_export]
    use super::memory::{AddressModule, Memory, MemoryRegion, MemorySearchMatch};
    #[pymodule_export]
    use super::module::{Device, Driver, Drivers, Export, Module, Modules, Section};
    #[pymodule_export]
    use super::process::{Heap, Heaps, Process, Processes, Regions};
    #[pymodule_export]
    use super::record::{Diagnostic, Record};
    #[pymodule_export]
    use super::secure::{SecureKernel, Trustlet};
    #[pymodule_export]
    use super::stop::{Stop, StopContext};
    #[pymodule_export]
    use super::symbols::{Symbol, Symbols};
    #[pymodule_export]
    use super::thread::{Cpu, Cpus, Frame, Msrs, Registers, Thread, Threads};
    #[pymodule_export]
    use super::types::{Field, Struct, Type, Types};
    #[pymodule_export]
    use super::{attach, decode_error};

    /// The ntoseye release this extension was built as.
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const __version__: &str = env!("CARGO_PKG_VERSION");

    /// The git commit this extension was built from (`<commit>`,
    /// `<commit>-dirty`, or `unknown`), to detect a stale extension in a
    /// long-lived interpreter.
    #[pymodule_export]
    #[allow(non_upper_case_globals)]
    const build: &str = env!("NTOSEYE_BUILD");
}
