use std::ffi::CString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyString, PyTuple};

use crate::diagnostics;
use crate::repl::CompletionStrategy;
use crate::session::Session;
use crate::symbols::ntoseye_home;

use super::{Debugger, Struct, Type};

/// Module prelude for `ntoseye.repl`: the `command` decorator and the
/// per-argument completion markers (`Process`, `Symbol`, ...). The decorator
/// reads the function signature and binds completion to parameters by name, then
/// calls the low-level `register_command(name, help, fn, strategies)`.
const REPL_MODULE_PRELUDE: &str = r#"
class _Completion:
    __slots__ = ("strat",)
    def __init__(self, strat):
        self.strat = strat

Process = _Completion("process")
Symbol = _Completion("symbol")
Expression = _Completion("expression")
Type = _Completion("type")
Driver = _Completion("driver")
Thread = _Completion("thread")
Vcpu = _Completion("vcpu")
Breakpoint = _Completion("breakpoint")
Alias = _Completion("alias")

def command(name, help, **completions):
    import inspect
    def deco(fn):
        params = list(inspect.signature(fn).parameters)[1:]  # skip dbg
        strats = []
        for p in params:
            c = completions.get(p)
            strats.append(c.strat if isinstance(c, _Completion) else "none")
        register_command(name, help, fn, strats)
        return fn
    return deco
"#;

/// Outcome of loading the python commands dir: names registered, and per-file
/// load failures.
pub struct LoadReport {
    pub loaded: Vec<String>,
    pub failed: Vec<(PathBuf, String)>,
}

/// Print a one-line load summary (and any failures). Quiet on startup when no
/// scripts are installed.
pub fn print_script_load_report(report: &LoadReport, startup_hint: bool) {
    if report.loaded.is_empty() && report.failed.is_empty() {
        if !startup_hint {
            println!("python: 0 loaded");
        }
        return;
    }
    let mut summary = format!("python: {} loaded", report.loaded.len());
    if !report.failed.is_empty() {
        summary.push_str(&format!(", {} failed", report.failed.len()));
    }
    println!("{summary}");
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

/// Install the importable REPL scripting module before a script is executed.
///
/// `ntoseye.repl` is the documented API for command scripts. A synthetic
/// top-level `ntoseye` package is also registered so `import ntoseye.repl` works
/// even when the wheel is not installed in the embedded interpreter's
/// `sys.path`. The top-level module carries the regular SDK type names for
/// annotations; REPL-only command helpers live under `ntoseye.repl`.
fn install_repl_module<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyModule>> {
    let ntoseye = PyModule::new(py, "ntoseye")?;
    ntoseye.add("Debugger", py.get_type::<Debugger>())?;
    ntoseye.add("Struct", py.get_type::<Struct>())?;
    ntoseye.add("Type", py.get_type::<Type>())?;
    ntoseye.add("NtoseyeError", py.get_type::<super::NtoseyeError>())?;
    ntoseye.add("MemoryAccessError", py.get_type::<super::MemoryAccessError>())?;
    ntoseye.add("__version__", env!("CARGO_PKG_VERSION"))?;
    ntoseye.setattr("__path__", PyList::empty(py))?;

    let repl = PyModule::new(py, "ntoseye.repl")?;
    repl.add("Debugger", py.get_type::<Debugger>())?;
    repl.add_function(wrap_pyfunction!(register_command, &repl)?)?;

    let prelude = CString::new(REPL_MODULE_PRELUDE)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    py.run(prelude.as_c_str(), Some(&repl.dict()), None)?;

    ntoseye.add("repl", &repl)?;

    let sys = py.import("sys")?;
    let modules = sys.getattr("modules")?;
    modules.set_item("ntoseye", &ntoseye)?;
    modules.set_item("ntoseye.repl", &repl)?;

    Ok(repl)
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

fn commands_dir() -> Option<PathBuf> {
    ntoseye_home().map(|r| r.join("commands"))
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
        let globals = PyDict::new(py);
        install_repl_module(py)?;
        let code = CString::new(source)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        py.run(code.as_c_str(), Some(&globals), None)?;
        Ok(())
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

        // A syntactically broken script surfaces a stringified error, not a panic.
        assert!(exec_script("def (:\n", "bad.py").is_err());
        clear_commands();
    }
}
