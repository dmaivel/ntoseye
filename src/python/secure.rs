//! The VBS secure kernel (`dbg.secure_kernel`) and its trustlets: read-only
//! views bound to VTL1 address spaces. VTL1 inspection is experimental; see
//! the REPL's `.vtl` for the same scope.

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};

use super::context::Space;
use super::err;
use super::handle::Owner;
use super::memory::Memory;
use super::module::Modules;
use super::process::Process;
use super::record::PlainDict;
use super::symbols::{self, Symbols};
use super::types::Types;
use crate::guest::TrustletInfo;
use crate::types::Dtb;

/// The secure kernel (`securekernel.exe`) that runs in VTL1. Its views use its
/// system address space and are read-only, so writes raise `NtoseyeError`.
#[pyclass(module = "ntoseye")]
pub struct SecureKernel {
    owner: Owner,
    base: u64,
    root: Dtb,
}

impl SecureKernel {
    /// Discover the secure kernel (once per session) and index its modules'
    /// symbols. `owner` should be stamped: the handle belongs to one boot.
    pub fn discover(py: Python<'_>, owner: Owner) -> PyResult<SecureKernel> {
        let (base, root) = owner.with(py, |session| {
            session.target.load_secure_kernel_symbols().map_err(err)?;
            let secure = session.target.secure_kernel().map_err(err)?;
            Ok((secure.image.base_address.0, secure.image.dtb()))
        })?;
        Ok(SecureKernel { owner, base, root })
    }

    fn space(&self) -> Space {
        Space::Secure(self.root)
    }
}

#[pymethods]
impl SecureKernel {
    /// The base address of `securekernel.exe`.
    #[getter]
    fn base(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.base)
    }

    /// The secure kernel's system page-table root.
    #[getter]
    fn dtb(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.root)
    }

    /// Virtual memory, read through the system page tables of the secure
    /// kernel.
    #[getter]
    fn memory(&self, py: Python<'_>) -> PyResult<Memory> {
        self.owner.check(py)?;
        Ok(Memory::new(self.owner.clone_ref(py), self.space()))
    }

    /// The symbols of the secure kernel's modules (`securekernel!...`). NT
    /// symbols do not resolve here.
    #[getter]
    fn symbols(&self, py: Python<'_>) -> PyResult<Symbols> {
        self.owner.check(py)?;
        Ok(Symbols::new(self.owner.clone_ref(py), self.space()))
    }

    /// PDB types, read through VTL1 memory. The public secure-kernel PDB has no
    /// types, so give NT types with their module name (`nt!_LIST_ENTRY`).
    #[getter]
    fn types(&self, py: Python<'_>) -> PyResult<Types> {
        self.owner.check(py)?;
        Ok(Types::new(self.owner.clone_ref(py), self.space()))
    }

    /// The modules that the secure kernel loaded (`securekernel.exe`,
    /// `skci.dll`, ...).
    #[getter]
    fn modules(&self, py: Python<'_>) -> PyResult<Modules> {
        self.owner.check(py)?;
        Ok(Modules::secure(self.owner.clone_ref(py), self.root))
    }

    /// The processes (trustlets) of the secure kernel. Each access walks the
    /// list again and validates it against the NT process list. Raises
    /// `NtoseyeError` if ntoseye does not recognize the process layout of this
    /// build.
    #[getter]
    fn trustlets(&self, py: Python<'_>) -> PyResult<Vec<Trustlet>> {
        let infos = self
            .owner
            .with(py, |session| session.target.trustlets().map_err(err))?;
        Ok(infos
            .into_iter()
            .map(|info| Trustlet {
                owner: self.owner.clone_ref(py),
                info,
            })
            .collect())
    }

    /// Evaluate a debugger expression in the symbol scope of the secure kernel.
    /// Registers hold VTL0 state, and this method does not accept them.
    fn eval(&self, py: Python<'_>, expr: &str) -> PyResult<u64> {
        symbols::eval(py, &self.owner, &self.space(), expr)
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other
            .extract::<PyRef<'_, SecureKernel>>()
            .is_ok_and(|other| self.owner.same_debugger(&other.owner) && self.root == other.root)
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(("secure_kernel", self.root))
    }

    fn __repr__(&self) -> String {
        format!("SecureKernel(base={:#x}, dtb={:#x})", self.base, self.root)
    }
}

/// An isolated user-mode process (trustlet) in VTL1, such as `LsaIso.exe`. Its
/// read-only views go through the page tables of the trustlet, which map the
/// user half of the trustlet and the secure kernel.
#[pyclass(module = "ntoseye")]
pub struct Trustlet {
    owner: Owner,
    info: TrustletInfo,
}

impl Trustlet {
    fn space(&self) -> Space {
        Space::Secure(self.info.dtb)
    }
}

#[pymethods]
impl Trustlet {
    /// The NT process ID of the trustlet's VTL0 counterpart.
    #[getter]
    fn pid(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.pid)
    }

    /// The image name, from the NT process.
    #[getter]
    fn name(&self, py: Python<'_>) -> PyResult<String> {
        self.owner.check(py)?;
        Ok(self.info.name.clone())
    }

    /// The trustlet ID from its creation attributes (1 for `LsaIso.exe`).
    #[getter]
    fn trustlet_id(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.trustlet_id)
    }

    /// The trustlet's page-table root.
    #[getter]
    fn dtb(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.dtb)
    }

    /// The address of the secure kernel's process object for this trustlet.
    #[getter]
    fn address(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.check(py)?;
        Ok(self.info.process.0)
    }

    /// The NT process (VTL0 side), or `None` after the process exits.
    #[getter]
    fn process(&self, py: Python<'_>) -> PyResult<Option<Process>> {
        let pid = self.info.pid;
        let found = self.owner.with(py, |session| {
            Ok(session
                .target
                .matching_processes(None)
                .map_err(err)?
                .into_iter()
                .find(|process| process.pid == pid))
        })?;
        Ok(found.map(|info| Process::from_owner(self.owner.clone_ref(py), info)))
    }

    /// Virtual memory, read through the page tables of the trustlet.
    #[getter]
    fn memory(&self, py: Python<'_>) -> PyResult<Memory> {
        self.owner.check(py)?;
        Ok(Memory::new(self.owner.clone_ref(py), self.space()))
    }

    /// The symbols of the secure kernel, resolved in the address space of this
    /// trustlet. The user-mode modules of the trustlet are not included.
    #[getter]
    fn symbols(&self, py: Python<'_>) -> PyResult<Symbols> {
        self.owner.check(py)?;
        Ok(Symbols::new(self.owner.clone_ref(py), self.space()))
    }

    /// PDB types, read through the memory of the trustlet (`nt!` types by
    /// name).
    #[getter]
    fn types(&self, py: Python<'_>) -> PyResult<Types> {
        self.owner.check(py)?;
        Ok(Types::new(self.owner.clone_ref(py), self.space()))
    }

    /// Evaluate a debugger expression in this trustlet's address space.
    fn eval(&self, py: Python<'_>, expr: &str) -> PyResult<u64> {
        symbols::eval(py, &self.owner, &self.space(), expr)
    }

    /// Return the identity of the trustlet as a plain `dict` (`pid`, `name`,
    /// `trustlet_id`, `dtb`, `address`). `!trustlets` lists the same fields.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        self.owner.check(py)?;
        let dict = PyDict::new(py);
        dict.set_item("pid", self.info.pid)?;
        dict.set_item("name", &self.info.name)?;
        dict.set_item("trustlet_id", self.info.trustlet_id)?;
        dict.set_item("dtb", self.info.dtb)?;
        dict.set_item("address", self.info.process.0)?;
        Ok(PlainDict(dict))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other.extract::<PyRef<'_, Trustlet>>().is_ok_and(|other| {
            self.owner.same_debugger(&other.owner) && self.info.process == other.info.process
        })
    }

    fn __hash__(&self) -> isize {
        self.owner.identity_hash(self.info.process)
    }

    fn __repr__(&self) -> String {
        format!(
            "Trustlet(pid={}, name={:?}, trustlet_id={}, dtb={:#x})",
            self.info.pid, self.info.name, self.info.trustlet_id, self.info.dtb
        )
    }
}
