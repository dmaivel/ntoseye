use std::ffi::CString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
#[cfg(feature = "python-embed")]
use pyo3::types::PyList;
use pyo3::types::{PyDict, PyModule, PyString, PyTuple};
#[cfg(feature = "python-embed")]
use pyo3::wrap_pymodule;

use crate::diagnostics;
use crate::repl::{CompletionStrategy, commands_dir};
use crate::session::Session;

#[cfg(feature = "python-embed")]
use super::_ntoseye;
use super::Debugger;

/// The package's own Python, run in the embedded interpreter as `ntoseye`
/// and `ntoseye.repl`, so REPL command scripts and the wheel share one copy.
/// `package/` holds symlinks to `python/ntoseye/`: `cargo package` leaves out
/// `python/`, a crate of its own, but copies symlinked files into the crate.
#[cfg(feature = "python-embed")]
const PACKAGE_INIT: &str = include_str!("package/__init__.py");
#[cfg(feature = "python-embed")]
const PACKAGE_REPL: &str = include_str!("package/repl.py");

/// Outcome of loading the python commands dir: names registered, and per-file
/// load failures.
pub struct LoadReport {
    pub loaded: Vec<String>,
    pub failed: Vec<(PathBuf, String)>,
}

/// Print a one-line load summary and any failures (used by `.reload`;
/// startup calls [`print_script_load_failures`] directly).
pub fn print_script_load_report(report: &LoadReport) {
    let mut summary = format!("python: {} loaded", report.loaded.len());
    if !report.failed.is_empty() {
        summary.push_str(&format!(", {} failed", report.failed.len()));
    }
    outln!("{summary}");
    print_script_load_failures(report);
}

/// Print per-file load failures, shared by the reload report and the startup
/// summary line.
pub fn print_script_load_failures(report: &LoadReport) {
    for (path, err) in &report.failed {
        diagnostics::print_error(format!("{}: {}", path.display(), err));
    }
}

struct Registered {
    name: String,
    help: String,
    callable: Py<PyAny>,
    strategies: Vec<CompletionStrategy>,
}

// The interpreter is single-threaded (the REPL thread), but `Py<PyAny>` is
// Send+Sync and a Mutex keeps the registry sound regardless.
static REGISTRY: Mutex<Vec<Registered>> = Mutex::new(Vec::new());

/// Exposed as `ntoseye.repl.register_command`. Scripts usually go through
/// `repl.command`.
#[pyfunction]
#[pyo3(signature = (name, help, callable, strategies=None))]
fn register_command(
    name: String,
    help: String,
    callable: Py<PyAny>,
    strategies: Option<Vec<String>>,
) {
    let strategies = strategies
        .unwrap_or_default()
        .iter()
        .map(|s| CompletionStrategy::from_kebab(s).unwrap_or(CompletionStrategy::None))
        .collect();
    let mut reg = REGISTRY.lock().unwrap();
    // Last registration of a name wins, matching a re-exec on reload.
    reg.retain(|r| r.name != name);
    reg.push(Registered {
        name,
        help,
        callable,
        strategies,
    });
}

/// Make `ntoseye.repl` usable by command scripts, once: the REPL's
/// `register_command` becomes `ntoseye._repl_host`. Run from the wheel's
/// `ntoseye` script, the package is the installed one. An embedding binary
/// installs its own copy over any wheel on the interpreter's `sys.path`, so a
/// script always sees the SDK of the REPL it runs in.
///
/// Runs at most once per process, whichever thread gets there first; the
/// others wait. Running the package's Python can switch threads, so a
/// check-then-install would let a second thread replace a half-installed
/// package, leaving two `ntoseye` modules with distinct exception classes.
fn install_package(py: Python<'_>) -> PyResult<()> {
    static INSTALLED: PyOnceLock<()> = PyOnceLock::new();
    INSTALLED
        .get_or_try_init(py, || {
            let modules = py.import("sys")?.getattr("modules")?;
            let host = PyModule::new(py, "ntoseye._repl_host")?;
            host.add_function(wrap_pyfunction!(register_command, &host)?)?;
            modules.set_item("ntoseye._repl_host", &host)?;
            #[cfg(feature = "python-embed")]
            embed_package(py, &modules)?;
            Ok::<_, PyErr>(())
        })
        .map(|_| ())
}

/// Install the extension module as `ntoseye._ntoseye` and the package's
/// Python sources over it.
#[cfg(feature = "python-embed")]
fn embed_package(py: Python<'_>, modules: &Bound<'_, PyAny>) -> PyResult<()> {
    let native = wrap_pymodule!(_ntoseye)(py);
    modules.set_item("ntoseye._ntoseye", native)?;
    let package = PyModule::new(py, "ntoseye")?;
    package.setattr("__path__", PyList::empty(py))?;
    // Registered before it runs: its relative imports resolve through it.
    modules.set_item("ntoseye", &package)?;
    run_source(&package, PACKAGE_INIT)?;
    let repl = PyModule::new(py, "ntoseye.repl")?;
    run_source(&repl, PACKAGE_REPL)?;
    package.setattr("repl", &repl)?;
    modules.set_item("ntoseye.repl", repl)
}

/// Run `source` as the body of `module`, a module of the `ntoseye` package.
#[cfg(feature = "python-embed")]
fn run_source(module: &Bound<'_, PyModule>, source: &str) -> PyResult<()> {
    module.setattr("__package__", "ntoseye")?;
    run_code(module.py(), source, &module.dict())
}

/// Run `source` with `globals` as its namespace.
fn run_code(py: Python<'_>, source: &str, globals: &Bound<'_, PyDict>) -> PyResult<()> {
    let code = CString::new(source).map_err(|e| PyValueError::new_err(e.to_string()))?;
    py.run(code.as_c_str(), Some(globals), None)
}

/// Drop every registered command (used by `reload` before re-execing scripts).
pub fn clear_commands() {
    REGISTRY.lock().unwrap().clear();
}

/// `(name, help, per-arg completion strategies)` for every registered command,
/// for completion and listing.
pub fn command_list() -> Vec<(String, String, Vec<CompletionStrategy>)> {
    REGISTRY
        .lock()
        .unwrap()
        .iter()
        .map(|r| (r.name.clone(), r.help.clone(), r.strategies.clone()))
        .collect()
}

/// Whether a command name is registered.
pub fn has_command(name: &str) -> bool {
    REGISTRY.lock().unwrap().iter().any(|r| r.name == name)
}

/// Clear the registry and (re-)execute every `*.py` in the python commands dir
/// (`~/.ntoseye/commands/`), returning a load report for the REPL to print.
pub fn load_commands_dir() -> LoadReport {
    clear_commands();
    let mut report = LoadReport {
        loaded: Vec::new(),
        failed: Vec::new(),
    };

    let Some(dir) = commands_dir() else {
        return report;
    };
    if !dir.exists() {
        return report;
    }

    let mut entries: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("py"))
            .collect(),
        Err(_) => return report,
    };
    entries.sort();

    for path in entries {
        let before: Vec<String> = command_list().into_iter().map(|(n, ..)| n).collect();
        match std::fs::read_to_string(&path) {
            Ok(src) => match exec_script(&src, &path.display().to_string()) {
                Ok(()) => {
                    for (name, ..) in command_list() {
                        if !before.contains(&name) {
                            report.loaded.push(name);
                        }
                    }
                }
                Err(e) => report.failed.push((path, e)),
            },
            Err(e) => report.failed.push((path, e.to_string())),
        }
    }
    report
}

/// Execute one script's source. Scripts can import `ntoseye.repl` for command
/// registration.
pub fn exec_script(source: &str, script_name: &str) -> Result<(), String> {
    Python::attach(|py| -> PyResult<()> {
        install_package(py)?;
        run_code(py, source, &PyDict::new(py))
    })
    .map_err(|e| format!("{script_name}: {e}"))
}

/// Flips a borrowed [`Debugger`]'s validity flag false on drop, so the handle is
/// neutered whether the command returns normally, raises, or unwinds.
struct Invalidate(Arc<AtomicBool>);

impl Drop for Invalidate {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

/// Invoke a registered command, passing a `Debugger` borrowing the live session
/// followed by the raw string arguments: `func(dbg, *args)`.
pub fn dispatch(name: &str, args: &[&str], session: &mut Session) -> Result<(), String> {
    Python::attach(|py| -> Result<(), String> {
        let callable = {
            let reg = REGISTRY.lock().unwrap();
            let entry = reg
                .iter()
                .find(|r| r.name == name)
                .ok_or_else(|| format!("no such python command: {name}"))?;
            entry.callable.clone_ref(py)
        };

        // Borrowed for this call only. `valid` neuters the handle the instant we
        // return (via the drop guard below), so even if the script stashes `dbg`
        // (or a Struct/Type from it) in a global, a later use raises rather than
        // dereferencing a session reference that is no longer ours to hold.
        let valid = Arc::new(AtomicBool::new(true));
        let _invalidate = Invalidate(valid.clone());
        let dbg = Bound::new(py, Debugger::from_session_ref(session, valid))
            .map_err(|e| e.to_string())?;

        let mut items: Vec<Bound<'_, PyAny>> = Vec::with_capacity(args.len() + 1);
        items.push(dbg.into_any());
        for a in args {
            items.push(PyString::new(py, a).into_any());
        }
        let call_args = PyTuple::new(py, items).map_err(|e| e.to_string())?;

        callable
            .call1(py, call_args)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_registers_a_command_via_repl_module() {
        clear_commands();
        let src = "import ntoseye.repl as repl\n\
                   @repl.command('pytest_repl_hide', 'help', target=repl.Process)\n\
                   def _h(dbg: repl.Debugger, target=None):\n    return None\n";
        exec_script(src, "repl_module.py").expect("repl module script should execute");
        let entry = command_list()
            .into_iter()
            .find(|(n, ..)| n == "pytest_repl_hide")
            .expect("decorator should register the command");
        assert!(matches!(entry.2.as_slice(), [CompletionStrategy::Process]));
        clear_commands();
    }

    #[test]
    fn scripts_use_explicit_repl_module_imports() {
        clear_commands();
        let src = "def hi(dbg, *args):\n    return None\n\
                   register_command('pytest_hi', 'a help string', hi)\n";
        assert!(exec_script(src, "test.py").is_err());

        assert!(exec_script("def (:\n", "bad.py").is_err());
        clear_commands();
    }
}
