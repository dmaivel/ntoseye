//! Address-space-bound memory operations for the Python SDK.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use super::context::Space;
use super::handle::{Owner, require_halted};
use super::symbols::load_scope_symbols;
use super::{MAX_READ_LEN, err, raise};
use crate::backend::MemoryOps;
use crate::layout::utf16le_lossy;
use crate::memory::pattern_offsets;
use crate::target::MAX_SEARCH_BYTES;
use crate::target::{CODE_BITNESS_X86, StringDescriptor};
use crate::types::VirtAddr;
use crate::view;
use crate::view::shape::Typed;

/// A guest address space: `dbg.memory` (kernel), `proc.memory`, `cpu.memory`,
/// `dbg.physical`.
#[pyclass(module = "ntoseye")]
pub struct Memory {
    pub owner: Owner,
    pub space: Space,
}

impl Memory {
    pub fn new(owner: Owner, space: Space) -> Memory {
        Memory { owner, space }
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

    fn write_bytes(&self, py: Python<'_>, addr: u64, data: &[u8]) -> PyResult<()> {
        self.space.require_writable()?;
        check_read_len(data.len())?;
        let context = self.space.context();
        let physical = matches!(self.space, Space::Physical);
        self.owner.with_in(py, &context, |session| {
            if physical {
                session.target.write_physical(addr, data).map_err(err)
            } else {
                session
                    .target
                    .context_memory()
                    .write_bytes(VirtAddr(addr), data)
                    .map_err(err)
            }
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

fn check_search_len(length: usize) -> PyResult<()> {
    if length > MAX_SEARCH_BYTES {
        return Err(raise(format!(
            "search length {length} exceeds cap {MAX_SEARCH_BYTES} (0x{MAX_SEARCH_BYTES:x})"
        )));
    }
    Ok(())
}

#[pymethods]
impl Memory {
    /// Read `n` bytes; virtual reads mask this debugger's breakpoint opcodes.
    fn read<'py>(&self, py: Python<'py>, addr: u64, n: usize) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.read_bytes(py, addr, n)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Write bytes to this address space.
    fn write(&self, py: Python<'_>, addr: u64, data: &[u8]) -> PyResult<()> {
        self.write_bytes(py, addr, data)
    }

    /// Read one little-endian byte.
    fn read_u8(&self, py: Python<'_>, addr: u64) -> PyResult<u8> {
        Ok(self.read_fixed::<1>(py, addr)?[0])
    }

    /// Read a little-endian 16-bit integer.
    fn read_u16(&self, py: Python<'_>, addr: u64) -> PyResult<u16> {
        Ok(u16::from_le_bytes(self.read_fixed::<2>(py, addr)?))
    }

    /// Read a little-endian 32-bit integer.
    fn read_u32(&self, py: Python<'_>, addr: u64) -> PyResult<u32> {
        Ok(u32::from_le_bytes(self.read_fixed::<4>(py, addr)?))
    }

    /// Read a little-endian 64-bit integer.
    fn read_u64(&self, py: Python<'_>, addr: u64) -> PyResult<u64> {
        Ok(u64::from_le_bytes(self.read_fixed::<8>(py, addr)?))
    }

    /// Write a little-endian byte.
    fn write_u8(&self, py: Python<'_>, addr: u64, value: u8) -> PyResult<()> {
        self.write_bytes(py, addr, &value.to_le_bytes())
    }

    /// Write a little-endian 16-bit integer.
    fn write_u16(&self, py: Python<'_>, addr: u64, value: u16) -> PyResult<()> {
        self.write_bytes(py, addr, &value.to_le_bytes())
    }

    /// Write a little-endian 32-bit integer.
    fn write_u32(&self, py: Python<'_>, addr: u64, value: u32) -> PyResult<()> {
        self.write_bytes(py, addr, &value.to_le_bytes())
    }

    /// Write a little-endian 64-bit integer.
    fn write_u64(&self, py: Python<'_>, addr: u64, value: u64) -> PyResult<()> {
        self.write_bytes(py, addr, &value.to_le_bytes())
    }

    /// The guest pointer width in bytes (`$ptrsize`).
    #[getter]
    fn pointer_size(&self) -> PyResult<u64> {
        self.space.require_virtual()?;
        Ok(8)
    }

    /// Read a pointer-sized value at `addr` (`poi`).
    fn read_pointer(&self, py: Python<'_>, addr: u64) -> PyResult<u64> {
        self.read_u64(py, addr)
    }

    /// Read a NUL-terminated ANSI string at `addr` (`da`).
    #[pyo3(signature = (addr, max_len=256))]
    fn read_string(&self, py: Python<'_>, addr: u64, max_len: usize) -> PyResult<String> {
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

    /// Read a NUL-terminated UTF-16 string at `addr` (`du`).
    #[pyo3(signature = (addr, max_len=256))]
    fn read_wstring(&self, py: Python<'_>, addr: u64, max_len: usize) -> PyResult<String> {
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

    /// Decode the `_UNICODE_STRING` descriptor at `addr` (`dS`). `bits`
    /// selects the layout: 32 for a WOW64 process's x86 descriptors, 64 for
    /// native ones; by default the `.effmach` setting decides.
    #[pyo3(signature = (addr, bits = None))]
    fn read_unicode_string(
        &self,
        py: Python<'_>,
        addr: u64,
        bits: Option<u32>,
    ) -> PyResult<String> {
        self.read_descriptor(py, addr, StringDescriptor::Unicode, bits)
    }

    /// Decode the `_STRING`/`ANSI_STRING` descriptor at `addr` (`ds`). `bits`
    /// selects the layout as for `read_unicode_string`.
    #[pyo3(signature = (addr, bits = None))]
    fn read_ansi_string(&self, py: Python<'_>, addr: u64, bits: Option<u32>) -> PyResult<String> {
        self.read_descriptor(py, addr, StringDescriptor::Ansi, bits)
    }

    /// Find overlapping matches and include symbol/module/VAD context. In a
    /// virtual space unreadable pages are skipped, this session's own
    /// breakpoints read as the code they replaced, and at most 4096 matches
    /// are returned.
    fn search<'py>(
        &self,
        py: Python<'py>,
        pattern: &[u8],
        start: u64,
        length: usize,
    ) -> PyResult<Typed<'py, Vec<view::mm::MemorySearchMatch>>> {
        check_search_len(length)?;
        if pattern.is_empty() || pattern.len() > length {
            return Typed::new(py, Vec::new());
        }
        let context = self.space.context();
        let physical = matches!(self.space, Space::Physical);
        // NT's region descriptions cover neither VTL1 nor roots outside NT.
        let undescribed = match self.space {
            Space::Secure(_) => Some("vtl1"),
            Space::Root(_) => Some("foreign"),
            _ => None,
        };
        let matches = self.owner.with_in(py, &context, move |session| {
            if physical {
                let mut bytes = vec![0; length];
                session
                    .target
                    .read_physical(start, &mut bytes)
                    .map_err(err)?;
                Ok(pattern_offsets(&bytes, pattern)
                    .map(|offset| {
                        view::mm::undescribed_search_match(
                            start.wrapping_add(offset as u64),
                            offset as u64,
                            None,
                            "physical",
                        )
                    })
                    .collect::<Vec<_>>())
            } else {
                let hits = session
                    .search(VirtAddr(start), pattern, length)
                    .map_err(err)?
                    .matches;
                if let Some(kind) = undescribed {
                    return Ok(hits
                        .into_iter()
                        .map(|address| {
                            view::mm::undescribed_search_match(
                                address,
                                address.wrapping_sub(start),
                                session
                                    .target
                                    .closest_symbol_current_context(VirtAddr(address)),
                                kind,
                            )
                        })
                        .collect::<Vec<_>>());
                }
                session
                    .target
                    .describe_search_matches(VirtAddr(start), &hits)
                    .map(|matches| {
                        matches
                            .into_iter()
                            .map(|hit| view::mm::memory_search_match(&hit))
                            .collect::<Vec<_>>()
                    })
                    .map_err(err)
            }
        })?;
        Typed::new(py, matches)
    }

    /// Translate a virtual address through this space's page tables (`!vtop`).
    fn translate(&self, py: Python<'_>, addr: u64) -> PyResult<Option<u64>> {
        self.space.require_virtual()?;
        let context = self.space.context();
        self.owner.with_in(py, &context, |session| {
            session
                .target
                .virt_to_phys(None, VirtAddr(addr))
                .map_err(err)
        })
    }

    /// The full page-table walk and final translation (`!pte` + `!vtop`).
    fn translation<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Typed<'py, view::mm::AddressTranslation>> {
        self.space.require_virtual()?;
        let detail = self.owner.with_in(py, &self.space.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            session.target.vtop(dtb, VirtAddr(addr)).map_err(err)
        })?;
        Typed::new(py, view::mm::vtop(&detail))
    }

    /// Reverse-map a physical address through this space's page tables (`!ptov`).
    fn ptov<'py>(
        &self,
        py: Python<'py>,
        physical: u64,
    ) -> PyResult<Typed<'py, view::mm::ReverseTranslation>> {
        self.space.require_virtual()?;
        self.space.require_nt("ptov")?;
        let context = self.space.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.target.ptov(physical).map_err(err)
        })?;
        Typed::new(py, view::mm::ptov(&detail))
    }

    /// The directory-table base used by this space.
    #[getter]
    fn dtb(&self, py: Python<'_>) -> PyResult<u64> {
        self.owner.with_in(py, &self.space.context(), |session| {
            self.space.dtb(&session.target)
        })
    }

    /// Make `addr` resident with the guest debugger worker (`.pagein`). The
    /// worker resumes the guest and returns with it stopped at its completion;
    /// that stop is reflected by `dbg.stop`.
    fn page_in(&self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        self.space.require_virtual()?;
        let context = self.space.context();
        self.space.require_nt("page_in")?;
        let process = match &self.space {
            Space::Process(info) => Some(info.eprocess_va.0),
            Space::Kernel => None,
            Space::Physical | Space::Secure(_) | Space::Root(_) => unreachable!(),
        };
        self.owner.with_in(py, &context, |session| {
            require_halted(session, "page_in")?;
            let report = session.page_in(VirtAddr(addr), process).map_err(err)?;
            if !report.from_worker {
                return Err(raise(
                    "the target stopped for another reason before the worker reported",
                ));
            }
            Ok(report.resident)
        })
    }

    /// Describe the loaded module, kernel region, or process VAD containing `addr`.
    fn describe<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Typed<'py, view::mm::AddressDescription>> {
        self.space.require_virtual()?;
        self.space.require_nt("describe")?;
        let context = self.space.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.target.describe_address(VirtAddr(addr)).map_err(err)
        })?;
        Typed::new(py, view::mm::address_description(&detail))
    }

    /// Disassemble `count` instructions at `addr` (`u`).
    fn disassemble<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
        count: usize,
    ) -> PyResult<Typed<'py, Vec<view::execution::DisassembledInstruction>>> {
        self.space.require_virtual()?;
        check_disassembly_count(count)?;
        let context = self.space.context();
        let rows = self.owner.with_in(py, &context, |session| {
            session.disassemble(VirtAddr(addr), count).map_err(err)
        })?;
        Typed::new(
            py,
            rows.iter()
                .map(view::execution::disasm_row)
                .collect::<Vec<_>>(),
        )
    }

    /// Disassemble the runtime function containing `addr` (`uf`).
    fn disassemble_function<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Typed<'py, Vec<view::execution::DisassembledInstruction>>> {
        self.space.require_virtual()?;
        let context = self.space.context();
        let (_, _, rows) = self.owner.with_in(py, &context, |session| {
            session.disassemble_function(VirtAddr(addr)).map_err(err)
        })?;
        Typed::new(
            py,
            rows.iter()
                .map(view::execution::disasm_row)
                .collect::<Vec<_>>(),
        )
    }

    /// The function-table entry and unwind info (AMD64 or ARM64) of the
    /// function containing `addr`, chained parents included (`.fnent`).
    fn function_entry<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Typed<'py, view::execution::FunctionEntry>> {
        self.space.require_virtual()?;
        let context = self.space.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.function_entry(VirtAddr(addr)).map_err(err)
        })?;
        Typed::new(py, view::execution::function_entry(&detail))
    }

    /// Disassemble the `count` instructions ending at `addr` (`ub`).
    fn disassemble_back<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
        count: usize,
    ) -> PyResult<Typed<'py, Vec<view::execution::DisassembledInstruction>>> {
        self.space.require_virtual()?;
        check_disassembly_count(count)?;
        let context = self.space.context();
        let rows = self.owner.with_in(py, &context, |session| {
            session.disassemble_back(VirtAddr(addr), count).map_err(err)
        })?;
        Typed::new(
            py,
            rows.iter()
                .map(view::execution::disasm_row)
                .collect::<Vec<_>>(),
        )
    }
}

const MAX_DISASSEMBLY_INSTRUCTIONS: usize = 4096;

fn check_disassembly_count(count: usize) -> PyResult<()> {
    if count > MAX_DISASSEMBLY_INSTRUCTIONS {
        return Err(raise(format!(
            "instruction count must be at most {MAX_DISASSEMBLY_INSTRUCTIONS}"
        )));
    }
    Ok(())
}
