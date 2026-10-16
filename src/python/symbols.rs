//! Address-space-bound symbol lookup for the Python SDK.

use pyo3::prelude::*;

use super::command::CommandHost;
use super::context::{Context, Space};
use super::handle::Owner;
use super::{err, raise, symbol_not_found};
use crate::breakpoints::BreakpointSpec;
use crate::expr::Expr;
use crate::session::Session;
use crate::symbols::{
    CodeFrame, ProcedureLocal, SourceLocation, SymbolCandidate, parse_source_paths,
    parse_symbol_sources,
};
use crate::target::SymbolSearchMatch;
use crate::types::{Dtb, VirtAddr};
use crate::view::record::Typed;

/// Symbol lookup in one address space (`dbg.symbols`, `proc.symbols`).
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
    /// Get the address of a symbol, or raise `SymbolNotFoundError` if the symbol is not
    /// found.
    fn __getitem__(&self, py: Python<'_>, name: &str) -> PyResult<u64> {
        self.resolve(py, name)?
            .ok_or_else(|| symbol_not_found(name))
    }

    /// Get the address of a symbol, or `None` if the symbol is not found.
    fn get(&self, py: Python<'_>, name: &str) -> PyResult<Option<u64>> {
        self.resolve(py, name)
    }

    /// True if one or more symbol candidates have this name.
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

    /// Get all exact candidates, with the module and, for private symbols, the compiland.
    fn candidates<'py>(
        &self,
        py: Python<'py>,
        name: &str,
    ) -> PyResult<Typed<'py, Vec<SymbolCandidate>>> {
        let space = &self.space;
        let candidates = scoped(py, &self.owner, space, |session| {
            let dtb = space.dtb(&session.target)?;
            Ok(session.target.symbols.find_symbol_candidates(dtb, name))
        })?;
        Typed::new(py, candidates)
    }

    /// Search symbol names by fuzzy match. Use `module!query` to search in one module.
    #[pyo3(signature = (query, limit=50))]
    fn search<'py>(
        &self,
        py: Python<'py>,
        query: &str,
        limit: usize,
    ) -> PyResult<Typed<'py, Vec<SymbolSearchMatch>>> {
        if !(1..=500).contains(&limit) {
            return Err(raise("limit must be in range 1-500"));
        }
        let results = scoped(py, &self.owner, &self.space, |session| {
            Ok(session.target.search_symbols(query, limit))
        })?;
        Typed::new(py, results)
    }

    /// Get the PDB source metadata and the mapped local path for an address.
    fn source_location<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Typed<'py, Option<SourceLocation>>> {
        let location = scoped(py, &self.owner, &self.space, |session| {
            Ok(session.target.source_location(VirtAddr(addr)))
        })?;
        Typed::new(py, location)
    }

    /// Get all loaded addresses that match a source file and line.
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

    /// List the PDB layouts of the locals and parameters of the innermost frame
    /// at `addr`, which are those of the inlined call if the compiler inlined a
    /// call there. This method does not evaluate the values.
    fn locals_at<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Typed<'py, Vec<ProcedureLocal>>> {
        let rows = scoped(py, &self.owner, &self.space, |session| {
            let locals = session
                .target
                .frame_locals(CodeFrame::at(VirtAddr(addr)))
                .map_err(err)?
                .unwrap_or_default();
            Ok(locals.to_vec())
        })?;
        Typed::new(py, rows)
    }

    /// The ordered symbol sources (`.sympath`). An assignment replaces the full path.
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

    /// Copy a PE file into the symbol cache under the key in its own header, and
    /// return its path in the cache (`.fetchimage /f`). Use it for an image that
    /// no symbol server has, such as the Windows hypervisor's `hvix64.exe`.
    fn import_image(&self, py: Python<'_>, path: String) -> PyResult<String> {
        scoped(py, &self.owner, &self.space, move |session| {
            let imported = session
                .target
                .symbols
                .import_image(std::path::Path::new(&path))
                .map_err(err)?;
            Ok(imported.to_string_lossy().into_owned())
        })
    }

    /// The ordered source-path mappings (`.srcpath`). An assignment replaces all of them.
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

/// Symbol commands (`ln`, `.reload`, `.symfix`) run in the handle's
/// address space, with its module symbols loaded first.
impl CommandHost for Symbols {
    fn owner(&self) -> &Owner {
        &self.owner
    }

    fn context(&self, py: Python<'_>) -> PyResult<Context> {
        scoped(py, &self.owner, &self.space, |_| Ok(()))?;
        Ok(self.space.context())
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
