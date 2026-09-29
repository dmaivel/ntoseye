use pyo3::prelude::*;
use pyo3::types::PyDict;

use super::breakpoints::{self, Breakpoint};
use super::context::Space;
use super::handle::{Debugger, Owner};
use super::module::Module;
use super::process::Process;
use super::raise;
use super::record::PlainDict;
use super::thread::{Cpu, Thread};
use crate::breakpoints::Breakpoint as CoreBreakpoint;
use crate::bugchecks::{analyze_bugcheck, bugcheck_from_dump_info, current_bugcheck};
use crate::guest::ProcessInfo;
use crate::session::{ContinueOutcome, ExceptionRecord};
use crate::target::ThreadInfo;
use crate::unwind::try_format_symbol_at;
use crate::view;
use crate::view::shape::Typed;

/// Rust-only snapshot backing the shared properties of a typed stop.
#[pyclass(name = "_StopContext", module = "ntoseye")]
pub struct StopContext {
    owner: Owner,
    rip: Option<u64>,
    symbol: Option<String>,
    process: Option<ProcessInfo>,
    thread: Option<ThreadInfo>,
    cpu_id: String,
    breakpoints: Vec<CoreBreakpoint>,
    record: Option<ExceptionRecord>,
}

/// The reason why the target stopped. Each stop is one of the nested kinds.
/// Use `isinstance(stop, Stop.Breakpoint)` or `match` to test the kind. A stop
/// is bound to the target generation in which it occurred.
#[pyclass(module = "ntoseye")]
pub enum Stop {
    /// A code breakpoint or data-watchpoint hit. If the breakpoint condition
    /// fails to evaluate, ntoseye sets `condition_error`. It then stops on the
    /// hit and does not skip it.
    Breakpoint {
        /// The reason why the breakpoint condition failed to evaluate, if it failed.
        condition_error: Option<String>,
        _context: Py<StopContext>,
    },
    /// A Windows exception. It has the `code` (NTSTATUS), the first-chance
    /// flag, and the faulting address.
    Exception {
        /// The NTSTATUS code of the exception.
        code: u32,
        /// True if this is the first chance. `None` if the backend does not give
        /// this data.
        first_chance: Option<bool>,
        /// The faulting address, if the exception has one.
        address: Option<u64>,
        _context: Py<StopContext>,
    },
    /// A break-in (`interrupt()`), or a different stop that has no exception code.
    Interrupt { _context: Py<StopContext> },
    /// A completed step.
    Step { _context: Py<StopContext> },
    /// A kernel image loaded, and an `"ld"` filter set to `"break"` matched it
    /// (`dbg.exceptions.set("ld:<module>", "break")`, `sxe ld`). The module is
    /// in the module list, and its symbols are loaded. Its breakpoints are set,
    /// and its entry point has not run.
    ModuleLoad {
        /// The loaded kernel module.
        module: Py<Module>,
        _context: Py<StopContext>,
    },
    /// The guest is in a bugcheck (BSOD). `info` is the bugcheck analysis.
    Bugcheck {
        /// The bugcheck analysis: the code, the parameters, and the culprit from
        /// `!analyze`.
        info: Option<Py<view::bugcheck::py::Bugcheck>>,
        _context: Py<StopContext>,
    },
    /// The guest rebooted. All earlier handles are now stale. While `coherent`
    /// is false, the kernel module list does not exist yet. Kernel symbols and
    /// breakpoints work, and `run()` lets the boot continue.
    Reboot {
        /// The base address of the new kernel (KASLR moves it).
        kernel_base: Option<u64>,
        /// True if the kernel module list exists.
        coherent: bool,
        _context: Py<StopContext>,
    },
}

impl Stop {
    fn context(&self) -> &Py<StopContext> {
        match self {
            Self::Breakpoint { _context, .. }
            | Self::Exception { _context, .. }
            | Self::Interrupt { _context }
            | Self::Step { _context }
            | Self::ModuleLoad { _context, .. }
            | Self::Bugcheck { _context, .. }
            | Self::Reboot { _context, .. } => _context,
        }
    }

    /// The variant's name: `Stop.<kind>`, and `to_dict()`'s `kind`.
    fn kind(&self) -> &'static str {
        match self {
            Self::Breakpoint { .. } => "Breakpoint",
            Self::Exception { .. } => "Exception",
            Self::Interrupt { .. } => "Interrupt",
            Self::Step { .. } => "Step",
            Self::ModuleLoad { .. } => "ModuleLoad",
            Self::Bugcheck { .. } => "Bugcheck",
            Self::Reboot { .. } => "Reboot",
        }
    }

    fn check_context<'py>(&self, py: Python<'py>) -> PyResult<PyRef<'py, StopContext>> {
        let context = self.context().bind(py).borrow();
        context.owner.check(py)?;
        Ok(context)
    }
}

#[pymethods]
impl Stop {
    /// The instruction pointer that ntoseye recorded at this stop.
    #[getter]
    fn rip(&self, py: Python<'_>) -> PyResult<Option<u64>> {
        Ok(self.check_context(py)?.rip)
    }

    /// The nearest symbol that ntoseye recorded at this stop, if one resolved.
    #[getter]
    fn symbol(&self, py: Python<'_>) -> PyResult<Option<String>> {
        Ok(self.check_context(py)?.symbol.clone())
    }

    /// The Windows thread that runs on the stopped vCPU, if known.
    #[getter]
    fn thread(&self, py: Python<'_>) -> PyResult<Option<Thread>> {
        let context = self.check_context(py)?;
        Ok(context
            .thread
            .clone()
            .map(|info| Thread::from_owner(context.owner.clone_ref(py), info)))
    }

    /// The process whose page tables were active at this stop, if known.
    #[getter]
    fn process(&self, py: Python<'_>) -> PyResult<Option<Process>> {
        let context = self.check_context(py)?;
        Ok(context
            .process
            .clone()
            .map(|info| Process::from_owner(context.owner.clone_ref(py), info)))
    }

    /// The processor that stopped.
    #[getter]
    fn cpu(&self, py: Python<'_>) -> PyResult<Cpu> {
        let context = self.check_context(py)?;
        Ok(Cpu::from_owner(
            context.owner.clone_ref(py),
            context.cpu_id.clone(),
        ))
    }

    /// The breakpoint or watchpoint handles for this stop. The list is empty
    /// for other kinds of stop. So `bp in stop.breakpoints` works on all
    /// stops.
    #[getter]
    fn breakpoints(&self, py: Python<'_>) -> PyResult<Vec<Py<Breakpoint>>> {
        let context = self.check_context(py)?;
        context
            .breakpoints
            .iter()
            .map(|breakpoint| breakpoints::handle(py, context.owner.dbg(), breakpoint))
            .collect()
    }

    /// Decode the current exception record (`.exr -1`).
    fn record<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Typed<'py, view::bugcheck::ExceptionRecord>> {
        let context = self.check_context(py)?;
        if !matches!(self, Self::Exception { .. }) {
            return Err(raise("record() is only available on Stop.Exception"));
        }
        let record = context
            .record
            .as_ref()
            .ok_or_else(|| raise("no current exception record"))?;
        Typed::new(py, view::bugcheck::exception_record(None, record))
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let context = self.check_context(py)?;
        let location = context
            .rip
            .map(|rip| format!(" rip={rip:#x}"))
            .unwrap_or_default();
        Ok(match self {
            Self::Exception { code, .. } => format!("<Stop.Exception code={code:#x}{location}>"),
            Self::ModuleLoad { module, .. } => format!(
                "<Stop.ModuleLoad module={}{location}>",
                module.bind(py).borrow().info.name
            ),
            _ => format!("<Stop.{}{location}>", self.kind()),
        })
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let context = self.check_context(py)?;
        let dict = PyDict::new(py);
        dict.set_item("kind", self.kind())?;
        dict.set_item("rip", context.rip)?;
        dict.set_item("symbol", &context.symbol)?;
        dict.set_item(
            "process",
            context.process.as_ref().map(|process| process.pid),
        )?;
        dict.set_item(
            "thread",
            context.thread.as_ref().and_then(|thread| thread.tid),
        )?;
        dict.set_item("cpu", &context.cpu_id)?;
        dict.set_item(
            "breakpoints",
            context
                .breakpoints
                .iter()
                .map(|breakpoint| breakpoint.id)
                .collect::<Vec<_>>(),
        )?;
        match self {
            Self::Breakpoint {
                condition_error, ..
            } => {
                dict.set_item("condition_error", condition_error)?;
            }
            Self::Exception {
                code,
                first_chance,
                address,
                ..
            } => {
                dict.set_item("code", code)?;
                dict.set_item("first_chance", first_chance)?;
                dict.set_item("address", address)?;
            }
            Self::Bugcheck { info, .. } => {
                let info = info
                    .as_ref()
                    .map(|info| info.bind(py).as_super().get().to_dict(py))
                    .transpose()?;
                dict.set_item("info", info.map(|info| info.0))?;
            }
            Self::Reboot {
                kernel_base,
                coherent,
                ..
            } => {
                dict.set_item("kernel_base", kernel_base)?;
                dict.set_item("coherent", coherent)?;
            }
            Self::ModuleLoad { module, .. } => {
                let module = module.bind(py).borrow();
                let info = &module.info;
                dict.set_item("module", &info.name)?;
                dict.set_item("base", info.base_address.0)?;
                dict.set_item("size", info.size)?;
            }
            Self::Interrupt { .. } | Self::Step { .. } => {}
        }
        Ok(PlainDict(dict))
    }
}

/// Convert a core execution outcome into its typed Python stop; `None` for a
/// still-running target. The snapshot is stamped at conversion time, after any
/// target reload has rebuilt its generation.
pub fn from_outcome(
    py: Python<'_>,
    dbg: &Py<Debugger>,
    outcome: ContinueOutcome,
) -> PyResult<Option<Py<Stop>>> {
    let debugger = dbg.get();
    let outcome = match outcome {
        ContinueOutcome::Running => return Ok(None),
        // A bare halt (attached halted; nothing stopped it since) reads as a
        // stop without a cause.
        ContinueOutcome::Halted { rip } => ContinueOutcome::Stopped {
            rip,
            exception_code: None,
            first_chance: None,
            exception_address: None,
        },
        outcome => outcome,
    };

    let owner = Owner::stamped(py, dbg);
    let (rip_hint, symbol_hint, breakpoint_id) = match &outcome {
        ContinueOutcome::Breakpoint {
            id, rip, symbol, ..
        } => (Some(*rip), symbol.clone(), Some(*id)),
        ContinueOutcome::Bugcheck { rip, .. } | ContinueOutcome::TargetReloaded { rip, .. } => {
            (*rip, None, None)
        }
        ContinueOutcome::Stopped { rip, .. }
        | ContinueOutcome::Step { rip }
        | ContinueOutcome::ModuleLoad { rip, .. } => (Some(*rip), None, None),
        ContinueOutcome::Running | ContinueOutcome::Halted { .. } => unreachable!(),
    };
    let exception_record_hint = match &outcome {
        ContinueOutcome::Stopped {
            rip,
            exception_code: Some(code),
            exception_address,
            ..
        } => Some(ExceptionRecord {
            code: *code,
            flags: 0,
            nested: 0,
            address: exception_address.unwrap_or(*rip),
            parameters: Vec::new(),
        }),
        _ => None,
    };
    let context_owner = owner.clone_ref(py);
    let snapshot = debugger.with_session(|session| {
        let (process, thread) = session.stopped_context();
        let rip = rip_hint.or_else(|| Some(session.current_rip()).filter(|rip| *rip != 0));
        let symbol = symbol_hint.or_else(|| {
            // Named in the stopped vCPU's own address space, not the
            // inspection scope an attached `.process` keeps across resumes.
            rip.and_then(|ip| {
                let root = session
                    .target
                    .register_value(session.target.arch().dtb_register())?;
                try_format_symbol_at(&session.target, root, ip)
            })
        });
        let breakpoints = breakpoint_id
            .and_then(|id| session.breakpoints.get(id).cloned())
            .into_iter()
            .collect();
        Ok(StopContext {
            owner: context_owner,
            rip,
            symbol,
            process,
            thread,
            cpu_id: session.current_thread.clone(),
            breakpoints,
            record: session.current_exception_record().or(exception_record_hint),
        })
    })?;
    let context = Py::new(py, snapshot)?;

    let stop = match outcome {
        ContinueOutcome::Breakpoint {
            condition_error, ..
        } => Stop::Breakpoint {
            _context: context,
            condition_error,
        },
        ContinueOutcome::Stopped {
            rip: _,
            exception_code: Some(code),
            first_chance,
            exception_address,
        } => Stop::Exception {
            _context: context,
            code,
            first_chance,
            address: exception_address,
        },
        ContinueOutcome::Stopped {
            rip: _,
            exception_code: None,
            ..
        } => Stop::Interrupt { _context: context },
        ContinueOutcome::Step { .. } => Stop::Step { _context: context },
        ContinueOutcome::ModuleLoad { module, .. } => Stop::ModuleLoad {
            module: Py::new(py, Module::new(owner, Space::Kernel, *module))?,
            _context: context,
        },
        ContinueOutcome::Bugcheck { info, .. } => {
            let bugcheck = debugger.with_session(|session| {
                let analysis = info
                    .as_ref()
                    .map(|info| analyze_bugcheck(&session.target, info))
                    .or_else(|| current_bugcheck(&session.target))
                    .or_else(|| bugcheck_from_dump_info(&session.target));
                Ok(analysis.map(|analysis| view::bugcheck::bugcheck(&analysis)))
            })?;
            let info = bugcheck
                .map(|bugcheck| bugcheck.into_class(py).map(Bound::unbind))
                .transpose()?;
            Stop::Bugcheck {
                _context: context,
                info,
            }
        }
        ContinueOutcome::TargetReloaded {
            kernel_base,
            coherent,
            ..
        } => Stop::Reboot {
            _context: context,
            kernel_base,
            coherent,
        },
        ContinueOutcome::Running | ContinueOutcome::Halted { .. } => unreachable!(),
    };
    // Not `Py::new`: that builds the base `Stop`, and `isinstance(stop,
    // Stop.Step)` would fail. The conversion picks the variant's class.
    Ok(Some(stop.into_pyobject(py)?.unbind()))
}
