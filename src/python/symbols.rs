//! Address-space-bound symbol lookup for the Python SDK.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use super::context::Space;
use super::handle::Owner;
use super::record::{PlainDict, Record};
use super::{err, raise, symbol_not_found, view_record, view_records};
use crate::expr::Expr;
use crate::gdb::breakpoints::BreakpointSpec;
use crate::session::Session;
use crate::symbols::{format_symbol_with_offset, parse_source_paths, parse_symbol_sources};
use crate::types::{Dtb, VirtAddr};
use crate::view::{self, View};

/// Symbol lookup scoped to an address space: `dbg.symbols`, `proc.symbols`.
#[pyclass(module = "ntoseye")]
pub struct Symbols {
    pub owner: Owner,
    pub space: Space,
}

impl Symbols {
    pub fn new(owner: Owner, space: Space) -> Symbols {
        Symbols { owner, space }
    }
}

/// A symbol identity nearest to an address.
#[pyclass(frozen, get_all, module = "ntoseye", skip_from_py_object)]
#[derive(Clone)]
pub struct Symbol {
    /// The module the symbol belongs to.
    module: String,
    /// The symbol name.
    name: String,
    /// The symbol's address.
    address: u64,
    /// How far past the symbol the queried address is.
    offset: u32,
}

#[pymethods]
impl Symbol {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let dict = PyDict::new(py);
        dict.set_item("module", &self.module)?;
        dict.set_item("name", &self.name)?;
        dict.set_item("address", self.address)?;
        dict.set_item("offset", self.offset)?;
        Ok(PlainDict(dict))
    }

    fn __str__(&self) -> String {
        format_symbol_with_offset(&self.module, &self.name, self.offset)
    }

    fn __repr__(&self) -> String {
        format!(
            "<Symbol {} address={:#x}>",
            format_symbol_with_offset(&self.module, &self.name, self.offset),
            self.address
        )
    }
}

/// A code or data location argument: an address, or a
/// `[module!]symbol[+offset]` spec.
#[derive(FromPyObject)]
pub enum Location {
    Address(u64),
    Symbol(String),
}

impl Location {
    /// The address in `dtb`'s space; a spec that does not resolve raises
    /// `SymbolNotFoundError`.
    pub fn resolve(&self, session: &Session, dtb: Dtb) -> PyResult<u64> {
        match self {
            Location::Address(address) => Ok(*address),
            Location::Symbol(spec) => {
                BreakpointSpec::resolve_symbol_offset(&session.target, dtb, spec)
                    .map_err(err)?
                    .map(|(address, _)| address.0)
                    .ok_or_else(|| symbol_not_found(spec))
            }
        }
    }
}

#[pymethods]
impl Symbols {
    /// Resolve a symbol to its address, raising `SymbolNotFoundError` when absent.
    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<u64> {
        self.resolve(py, name)?
            .ok_or_else(|| symbol_not_found(name))
    }

    /// Resolve a symbol to its address, or return `None` when absent.
    fn get(&self, py: Python<'_>, name: &str) -> PyResult<Option<u64>> {
        self.resolve(py, name)
    }

    /// Whether at least one symbol candidate has this name.
    fn __contains__(&self, py: Python<'_>, name: &str) -> PyResult<bool> {
        let space = &self.space;
        scoped(py, &self.owner, space, |session| {
            let dtb = space.dtb(&session.target)?;
            Ok(!session
                .target
                .symbols
                .find_symbol_candidates(dtb, name)
                .is_empty())
        })
    }

    /// Return every exact candidate, including module and private-compiland provenance.
    fn candidates<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Vec<Bound<'py, Record>>> {
        let space = &self.space;
        let candidates = scoped(py, &self.owner, space, |session| {
            let dtb = space.dtb(&session.target)?;
            Ok(session.target.symbols.find_symbol_candidates(dtb, name))
        })?;
        view_records(
            py,
            &View::List(candidates.iter().map(view::symbol_candidate).collect()),
        )
    }

    /// Return the nearest symbol identity, or `None` if no symbol covers `addr`.
    fn nearest(&self, py: Python<'_>, addr: u64) -> PyResult<Option<Symbol>> {
        let nearest = scoped(py, &self.owner, &self.space, |session| {
            Ok(session
                .target
                .nearest_symbol_current_context(VirtAddr(addr)))
        })?;
        Ok(nearest.map(|(module, name, offset)| Symbol {
            module,
            name,
            address: addr.saturating_sub(u64::from(offset)),
            offset,
        }))
    }

    /// Fuzzy-search symbol names; `module!query` scopes the search to a module.
    #[pyo3(signature = (query, limit=50))]
    fn search<'py>(
        &self,
        py: Python<'py>,
        query: &str,
        limit: usize,
    ) -> PyResult<Vec<Bound<'py, Record>>> {
        if !(1..=500).contains(&limit) {
            return Err(raise("limit must be in range 1-500"));
        }
        let results = scoped(py, &self.owner, &self.space, |session| {
            Ok(session.target.search_symbols(query, limit))
        })?;
        view_records(
            py,
            &View::List(results.iter().map(view::symbol_search_match).collect()),
        )
    }

    /// Resolve an address to PDB source metadata and its remapped local path.
    fn source_location<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Option<Bound<'py, Record>>> {
        let location = scoped(py, &self.owner, &self.space, |session| {
            Ok(session.target.source_location(VirtAddr(addr)))
        })?;
        location
            .as_ref()
            .map(|location| view_record(py, &view::source_location(location)))
            .transpose()
    }

    /// Resolve a source file and line to every matching loaded address.
    fn source_addresses(&self, py: Python<'_>, file: &str, line: u32) -> PyResult<Vec<u64>> {
        scoped(py, &self.owner, &self.space, |session| {
            Ok(session
                .target
                .source_addresses(file, line)
                .into_iter()
                .map(|address| address.0)
                .collect())
        })
    }

    /// List PDB local/parameter layouts covering `addr`, without evaluating values.
    fn locals_at<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Vec<Bound<'py, Record>>> {
        let rows = scoped(py, &self.owner, &self.space, |session| {
            let locals = session
                .target
                .procedure_locals(VirtAddr(addr))
                .map_err(err)?
                .unwrap_or_default();
            Ok(locals
                .iter()
                .map(view::procedure_local_layout)
                .collect::<Vec<_>>())
        })?;
        view_records(py, &View::List(rows))
    }

    /// Reload symbols in this space and re-resolve symbolic breakpoints.
    fn reload<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, Record>> {
        let report = scoped(py, &self.owner, &self.space, |session| {
            let report = session.target.reload_module_symbols(None).map_err(err)?;
            session
                .breakpoints
                .resolve_symbolic(session.backend.as_mut(), &session.target)
                .map_err(err)?;
            Ok(view::module_symbol_report(&report))
        })?;
        view_record(py, &report)
    }

    /// Ordered symbol sources (`.sympath`); assignment replaces the full path.
    #[getter(path)]
    fn path(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        scoped(py, &self.owner, &self.space, |session| {
            Ok(session
                .target
                .symbols
                .symbol_sources()
                .iter()
                .map(ToString::to_string)
                .collect())
        })
    }

    #[setter(path)]
    fn set_path(&self, py: Python<'_>, sources: Vec<String>) -> PyResult<()> {
        let parsed = parse_symbol_sources(&sources);
        scoped(py, &self.owner, &self.space, move |session| {
            session.target.symbols.set_symbol_sources(parsed);
            Ok(())
        })
    }

    /// Restore the default symbol sources (`.symfix`).
    fn reset_path(&self, py: Python<'_>) -> PyResult<()> {
        scoped(py, &self.owner, &self.space, |session| {
            session.target.symbols.reset_symbol_sources();
            Ok(())
        })
    }

    /// Ordered source-path mappings (`.srcpath`); assignment replaces them.
    #[getter(source_path)]
    fn source_path(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        scoped(py, &self.owner, &self.space, |session| {
            Ok(session
                .target
                .symbols
                .source_paths()
                .iter()
                .map(ToString::to_string)
                .collect())
        })
    }

    #[setter(source_path)]
    fn set_source_path(&self, py: Python<'_>, paths: Vec<String>) -> PyResult<()> {
        let parsed = parse_source_paths(&paths);
        scoped(py, &self.owner, &self.space, move |session| {
            session.target.symbols.set_source_paths(parsed);
            Ok(())
        })
    }
}

impl Symbols {
    fn resolve(&self, py: Python<'_>, name: &str) -> PyResult<Option<u64>> {
        let space = &self.space;
        scoped(py, &self.owner, space, |session| {
            let dtb = space.dtb(&session.target)?;
            session
                .target
                .symbols
                .find_symbol_across_modules(dtb, name)
                .map(|address| address.map(|address| address.0))
                .map_err(err)
        })
    }
}

/// Run `f` in `space` with its symbols loaded before the operation.
pub fn scoped<R: Send>(
    py: Python<'_>,
    owner: &Owner,
    space: &Space,
    f: impl FnOnce(&mut Session) -> PyResult<R> + Send,
) -> PyResult<R> {
    let context = space.context();
    owner.with_in(py, &context, |session| {
        load_scope_symbols(session, space)?;
        f(session)
    })
}

/// Evaluate a MASM expression in `space` (registers: the stopped vCPU's).
pub fn eval(py: Python<'_>, owner: &Owner, space: &Space, expr: &str) -> PyResult<u64> {
    space.require_virtual()?;
    scoped(py, owner, space, |session| {
        Expr::eval(expr, &session.target)
            .map(|value| value.0)
            .map_err(err)
    })
}

/// Load `space`'s module symbols when it is a process (kernel symbols are
/// always loaded). Modules already tried are skipped, so repeat calls only
/// walk the (per-halt memoized) loader list.
pub fn load_scope_symbols(session: &Session, space: &Space) -> PyResult<()> {
    if let Space::Process(info) = space {
        session
            .target
            .load_process_module_symbols(info.pid, info.dtb, None)
            .map_err(err)?;
    }
    Ok(())
}
