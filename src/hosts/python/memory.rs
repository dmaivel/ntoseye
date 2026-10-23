//! Address-space-bound memory operations for the Python SDK.

use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::args::AddressArg;
use super::command::{Bind, CommandHost, HostSession};
use super::context::Context;
use super::context::Space;
use super::handle::Owner;
use super::record::Typed;
use super::symbols::load_scope_symbols;
use super::{MAX_READ_LEN, err, raise};
use crate::arch::Arch;
use crate::base::bytes::utf16le_lossy;
use crate::base::error::Error;
use crate::base::types::VirtAddr;
use crate::nt::guest::ProcessInfo;
use crate::nt::target::MemoryKind;
use crate::nt::target::memory::SearchSpace;
use crate::nt::target::mm::{AddressKind, VtopDetail};
use crate::nt::target::{CODE_BITNESS_X86, StringDescriptor};
use crate::session::Session;
use crate::session::effects::Effects;

/// A guest address space: `dbg.memory` (kernel), `proc.memory`, `cpu.memory`,
/// or `dbg.physical`.
#[pyclass(module = "ntoseye")]
pub struct Memory {
    pub owner: Owner,
    pub space: Space,
}

/// A `Memory` runs a command in its space's context: `proc.memory` in the
/// process's, `dbg.memory` and `dbg.physical` in the kernel's.
impl CommandHost for Memory {
    fn session(&self) -> HostSession<'_> {
        HostSession::Owner(&self.owner)
    }

    fn context(&self, _py: Python<'_>) -> PyResult<Context> {
        Ok(self.space.context())
    }

    /// A kernel (or NT) command reads NT's state about an address, which
    /// VTL1 and roots outside NT do not have; a write needs a writable space.
    fn refuse(&self, operation: &str, effects: &Effects) -> PyResult<()> {
        if effects.target.reads_nt() {
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
            Space::Secure(_) => SearchSpace::Virtual(Some(AddressKind::Vtl1)),
            Space::Root(_) => SearchSpace::Virtual(Some(AddressKind::Foreign)),
            Space::Kernel | Space::Process(_) => SearchSpace::Virtual(None),
        }
    }
}

impl Memory {
    pub fn new(owner: Owner, space: Space) -> Memory {
        Memory { owner, space }
    }

    /// `addr` as this space's address. A handle names a virtual address,
    /// which `dbg.physical` does not take.
    fn address(&self, py: Python<'_>, addr: AddressArg) -> PyResult<u64> {
        if matches!(self.space, Space::Physical) && matches!(addr, AddressArg::Object(_)) {
            return Err(PyTypeError::new_err(
                "a handle gives a virtual address; dbg.physical takes a physical one",
            ));
        }
        Ok(addr.resolve(py, &self.owner, &self.space.context())?.0)
    }

    fn read_bytes(&self, py: Python<'_>, addr: u64, n: usize) -> PyResult<Vec<u8>> {
        check_read_len(n)?;
        let mut bytes = vec![0; n];
        self.read_into(py, addr, &mut bytes)?;
        Ok(bytes)
    }

    fn read_into(&self, py: Python<'_>, addr: u64, buf: &mut [u8]) -> PyResult<()> {
        let context = self.space.context();
        let physical = matches!(self.space, Space::Physical);
        self.owner.with_in(py, &context, |session| {
            if physical {
                session.target.read_physical(addr, buf).map_err(err)
            } else {
                session.read_masked(VirtAddr(addr), buf).map_err(err)
            }
        })
    }

    fn read_fixed<const N: usize>(&self, py: Python<'_>, addr: u64) -> PyResult<[u8; N]> {
        let mut bytes = [0; N];
        self.read_into(py, addr, &mut bytes)?;
        Ok(bytes)
    }

    /// The guest architecture, whose pointer width `$ptrsize` and `poi` use.
    fn arch(&self, py: Python<'_>) -> PyResult<Arch> {
        self.owner.with_in(py, &self.space.context(), |session| {
            Ok(session.target.arch())
        })
    }

    /// Decode the `kind` descriptor at `addr` in the `bits`-wide layout, or
    /// the one `.effmach` selects.
    fn read_descriptor(
        &self,
        py: Python<'_>,
        addr: u64,
        kind: StringDescriptor,
        bits: Option<u32>,
    ) -> PyResult<String> {
        self.space.require_virtual()?;
        self.owner.with_in(py, &self.space.context(), |session| {
            let target = &session.target;
            let bits = bits.unwrap_or_else(|| target.data_bitness());
            if bits == CODE_BITNESS_X86 {
                // The 32-bit layout is WOW64 ntdll's (`ntdll32!`), a
                // process module whose symbols a scope does not load up front.
                load_scope_symbols(session, &self.space)?;
            }
            let text = match kind {
                StringDescriptor::Unicode => target.read_unicode_string(VirtAddr(addr), bits),
                StringDescriptor::Ansi => target.read_ansi_string(VirtAddr(addr), bits),
            };
            text.map_err(err)
        })
    }
}

fn check_read_len(n: usize) -> PyResult<()> {
    if n > MAX_READ_LEN {
        return Err(raise(format!(
            "read length {n} exceeds cap {MAX_READ_LEN} (0x{MAX_READ_LEN:x})"
        )));
    }
    Ok(())
}

/// Refuse a page-table operation on a user-mode minidump, whose memory is
/// keyed by virtual address with no physical address behind it: its
/// translation would name the virtual address itself.
fn require_page_tables(session: &Session) -> PyResult<()> {
    if session.target.user_dump().is_some() {
        return Err(err(Error::NoPhysicalMemory));
    }
    Ok(())
}

#[pymethods]
impl Memory {
    /// Read `size` bytes. A virtual read hides the breakpoint opcodes of this
    /// debugger.
    fn read<'py>(
        &self,
        py: Python<'py>,
        address: AddressArg,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let addr = self.address(py, address)?;
        let bytes = self.read_bytes(py, addr, size)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Read a little-endian byte.
    fn read_u8(&self, py: Python<'_>, address: AddressArg) -> PyResult<u8> {
        let addr = self.address(py, address)?;
        Ok(self.read_fixed::<1>(py, addr)?[0])
    }

    /// Read a little-endian 16-bit integer.
    fn read_u16(&self, py: Python<'_>, address: AddressArg) -> PyResult<u16> {
        let addr = self.address(py, address)?;
        Ok(u16::from_le_bytes(self.read_fixed::<2>(py, addr)?))
    }

    /// Read a little-endian 32-bit integer.
    fn read_u32(&self, py: Python<'_>, address: AddressArg) -> PyResult<u32> {
        let addr = self.address(py, address)?;
        Ok(u32::from_le_bytes(self.read_fixed::<4>(py, addr)?))
    }

    /// Read a little-endian 64-bit integer.
    fn read_u64(&self, py: Python<'_>, address: AddressArg) -> PyResult<u64> {
        let addr = self.address(py, address)?;
        Ok(u64::from_le_bytes(self.read_fixed::<8>(py, addr)?))
    }

    /// The guest pointer width, in bytes (`$ptrsize`).
    #[getter]
    fn pointer_size(&self, py: Python<'_>) -> PyResult<u64> {
        self.space.require_virtual()?;
        Ok(self.arch(py)?.pointer_size())
    }

    /// Read a pointer-sized value at `address` (`poi`).
    fn read_pointer(&self, py: Python<'_>, address: AddressArg) -> PyResult<u64> {
        let addr = self.address(py, address)?;
        let arch = self.arch(py)?;
        let mut bytes = [0; 8];
        let width = arch.pointer_size() as usize;
        self.read_into(py, addr, &mut bytes[..width])?;
        Ok(arch.decode_pointer(&bytes[..width]).0)
    }

    /// Read a NUL-terminated ANSI string at `address` (`da`).
    #[pyo3(signature = (address, *, max_len=256))]
    fn read_string(&self, py: Python<'_>, address: AddressArg, max_len: usize) -> PyResult<String> {
        let addr = self.address(py, address)?;
        self.space.require_virtual()?;
        check_read_len(max_len)?;
        let bytes = self.owner.with_in(py, &self.space.context(), |session| {
            session
                .read_terminated(VirtAddr(addr), max_len, 1)
                .map(|read| read.bytes)
                .map_err(err)
        })?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Read a NUL-terminated UTF-16 string at `address` (`du`).
    #[pyo3(signature = (address, *, max_len=256))]
    fn read_wstring(
        &self,
        py: Python<'_>,
        address: AddressArg,
        max_len: usize,
    ) -> PyResult<String> {
        let addr = self.address(py, address)?;
        self.space.require_virtual()?;
        let byte_len = max_len
            .checked_mul(2)
            .ok_or_else(|| raise("wide-string length overflows"))?;
        check_read_len(byte_len)?;
        let bytes = self.owner.with_in(py, &self.space.context(), |session| {
            session
                .read_terminated(VirtAddr(addr), max_len, 2)
                .map(|read| read.bytes)
                .map_err(err)
        })?;
        Ok(utf16le_lossy(&bytes))
    }

    /// Decode the `_UNICODE_STRING` descriptor at `address` (`dS`). `bits` sets
    /// the layout: 32 for the x86 descriptors of a WOW64 process and 64 for
    /// native descriptors. By default, the `.effmach` setting selects the
    /// layout.
    #[pyo3(signature = (address, *, bits = None))]
    fn read_unicode_string(
        &self,
        py: Python<'_>,
        address: AddressArg,
        bits: Option<u32>,
    ) -> PyResult<String> {
        let addr = self.address(py, address)?;
        self.read_descriptor(py, addr, StringDescriptor::Unicode, bits)
    }

    /// Decode the `_STRING`/`ANSI_STRING` descriptor at `address` (`ds`). `bits`
    /// sets the layout, as in `read_unicode_string`.
    #[pyo3(signature = (address, *, bits = None))]
    fn read_ansi_string(
        &self,
        py: Python<'_>,
        address: AddressArg,
        bits: Option<u32>,
    ) -> PyResult<String> {
        let addr = self.address(py, address)?;
        self.read_descriptor(py, addr, StringDescriptor::Ansi, bits)
    }

    /// Translate a virtual address with the page tables of this space (`!vtop`).
    fn translate(&self, py: Python<'_>, address: AddressArg) -> PyResult<Option<u64>> {
        let addr = self.address(py, address)?;
        self.space.require_virtual()?;
        let context = self.space.context();
        self.owner.with_in(py, &context, |session| {
            require_page_tables(session)?;
            session
                .target
                .virt_to_phys(None, VirtAddr(addr))
                .map_err(err)
        })
    }

    /// Get the page-table walk and the final translation of `address` in this
    /// space's page tables (`!vtop` with this space's DTB). It works in every
    /// virtual space, VTL1 and roots outside NT included.
    fn translation<'py>(
        &self,
        py: Python<'py>,
        address: AddressArg,
    ) -> PyResult<Typed<'py, VtopDetail>> {
        let addr = self.address(py, address)?;
        self.space.require_virtual()?;
        let detail = self.owner.with_in(py, &self.space.context(), |session| {
            require_page_tables(session)?;
            let dtb = self.space.dtb(&session.target)?;
            session.target.vtop(dtb, VirtAddr(addr)).map_err(err)
        })?;
        Typed::new(py, detail)
    }

    /// The directory-table base that this space uses. A user-mode minidump
    /// has none, and raises `NtoseyeError`.
    #[getter]
    fn dtb(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.with_in(py, &self.space.context(), |session| {
            require_page_tables(session)?;
            self.space.dtb(&session.target)
        })
    }
}

const MAX_DISASSEMBLY_INSTRUCTIONS: usize = 4096;

pub fn check_disassembly_count(count: usize) -> PyResult<()> {
    if count > MAX_DISASSEMBLY_INSTRUCTIONS {
        return Err(raise(format!(
            "instruction count must be at most {MAX_DISASSEMBLY_INSTRUCTIONS}"
        )));
    }
    Ok(())
}
