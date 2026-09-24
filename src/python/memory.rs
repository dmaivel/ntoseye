//! Address-space-bound memory operations for the Python SDK.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use super::context::Space;
use super::handle::{Owner, require_halted};
use super::record::{PlainDict, Record};
use super::symbols::load_scope_symbols;
use super::{MAX_READ_LEN, MAX_SEARCH_LEN, err, raise, view_dict, view_record, view_records};
use crate::backend::MemoryOps;
use crate::target::MemorySearchMatch as CoreMemorySearchMatch;
use crate::target::mm::{AddressModule as CoreAddressModule, MemoryRegionInfo};
use crate::target::{CODE_BITNESS_X86, StringDescriptor};
use crate::types::VirtAddr;
use crate::view;

/// A guest address space: `dbg.memory` (kernel), `proc.memory`, `dbg.physical`.
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
    if length > MAX_SEARCH_LEN {
        return Err(raise(format!(
            "search length {length} exceeds cap {MAX_SEARCH_LEN} (0x{MAX_SEARCH_LEN:x})"
        )));
    }
    Ok(())
}

fn matching_offsets<'a>(bytes: &'a [u8], pattern: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    bytes
        .windows(pattern.len())
        .enumerate()
        .filter_map(move |(offset, window)| (window == pattern).then_some(offset))
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
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect();
        Ok(String::from_utf16_lossy(&units))
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

    /// Find overlapping matches and include symbol/module/VAD context.
    fn search(
        &self,
        py: Python<'_>,
        pattern: &[u8],
        start: u64,
        length: usize,
    ) -> PyResult<Vec<MemorySearchMatch>> {
        check_search_len(length)?;
        if pattern.is_empty() || pattern.len() > length {
            return Ok(Vec::new());
        }
        let context = self.space.context();
        let physical = matches!(self.space, Space::Physical);
        self.owner.with_in(py, &context, move |session| {
            let mut bytes = vec![0; length];
            if physical {
                session
                    .target
                    .read_physical(start, &mut bytes)
                    .map_err(err)?;
                Ok(matching_offsets(&bytes, pattern)
                    .map(|offset| MemorySearchMatch::physical(start, offset))
                    .collect())
            } else {
                session
                    .read_masked(VirtAddr(start), &mut bytes)
                    .map_err(err)?;
                let hits = matching_offsets(&bytes, pattern)
                    .map(|offset| start.wrapping_add(offset as u64))
                    .collect::<Vec<_>>();
                session
                    .target
                    .describe_search_matches(VirtAddr(start), &hits)
                    .map(|matches| {
                        matches
                            .into_iter()
                            .map(MemorySearchMatch::from_core)
                            .collect()
                    })
                    .map_err(err)
            }
        })
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
    fn translation<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        self.space.require_virtual()?;
        let detail = self.owner.with_in(py, &self.space.context(), |session| {
            let dtb = self.space.dtb(&session.target)?;
            session.target.vtop(dtb, VirtAddr(addr)).map_err(err)
        })?;
        view_record(py, &view::mm::vtop(&detail))
    }

    /// Reverse-map a physical address through this space's page tables (`!ptov`).
    fn ptov<'py>(&self, py: Python<'py>, physical: u64) -> PyResult<Bound<'py, Record>> {
        self.space.require_virtual()?;
        let context = self.space.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.target.ptov(physical).map_err(err)
        })?;
        view_record(py, &view::mm::ptov(&detail))
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
        let process = match &self.space {
            Space::Process(info) => Some(info.eprocess_va.0),
            Space::Kernel => None,
            Space::Physical => unreachable!(),
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
    fn describe<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, Record>> {
        self.space.require_virtual()?;
        let context = self.space.context();
        let detail = self.owner.with_in(py, &context, |session| {
            session.target.describe_address(VirtAddr(addr)).map_err(err)
        })?;
        view_record(py, &view::address_description(&detail))
    }

    /// Disassemble `count` instructions at `addr` (`u`).
    fn disassemble<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
        count: usize,
    ) -> PyResult<Vec<Bound<'py, Record>>> {
        self.space.require_virtual()?;
        check_disassembly_count(count)?;
        let context = self.space.context();
        let rows = self.owner.with_in(py, &context, |session| {
            session.disassemble(VirtAddr(addr), count).map_err(err)
        })?;
        view_records(
            py,
            &view::View::List(rows.iter().map(view::disasm_row).collect()),
        )
    }

    /// Disassemble the runtime function containing `addr` (`uf`).
    fn disassemble_function<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
    ) -> PyResult<Vec<Bound<'py, Record>>> {
        self.space.require_virtual()?;
        let context = self.space.context();
        let (_, _, rows) = self.owner.with_in(py, &context, |session| {
            session.disassemble_function(VirtAddr(addr)).map_err(err)
        })?;
        view_records(
            py,
            &view::View::List(rows.iter().map(view::disasm_row).collect()),
        )
    }

    /// Disassemble the `count` instructions ending at `addr` (`ub`).
    fn disassemble_back<'py>(
        &self,
        py: Python<'py>,
        addr: u64,
        count: usize,
    ) -> PyResult<Vec<Bound<'py, Record>>> {
        self.space.require_virtual()?;
        check_disassembly_count(count)?;
        let context = self.space.context();
        let rows = self.owner.with_in(py, &context, |session| {
            session.disassemble_back(VirtAddr(addr), count).map_err(err)
        })?;
        view_records(
            py,
            &view::View::List(rows.iter().map(view::disasm_row).collect()),
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

/// One VAD/context region (`proc.regions` items, search-hit context).
#[pyclass(frozen, get_all, module = "ntoseye", skip_from_py_object)]
#[derive(Clone)]
pub struct MemoryRegion {
    /// First address of the region.
    start: u64,
    /// End of the region (exclusive).
    end: u64,
    /// The VAD protection value, when known.
    protection: Option<u64>,
    /// The VAD type, when known.
    vad_type: Option<u64>,
    /// Whether the region is private (not shared or mapped).
    private_memory: Option<bool>,
    /// Committed pages charged to the region.
    commit_charge: Option<u64>,
    /// A description: the mapped file, or the kernel region kind.
    details: Option<String>,
}

impl From<MemoryRegionInfo> for MemoryRegion {
    fn from(region: MemoryRegionInfo) -> Self {
        Self {
            start: region.start.0,
            end: region.end.0,
            protection: region.protection,
            vad_type: region.vad_type,
            private_memory: region.private_memory,
            commit_charge: region.commit_charge,
            details: region.details,
        }
    }
}

#[pymethods]
impl MemoryRegion {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let dict = PyDict::new(py);
        dict.set_item("start", self.start)?;
        dict.set_item("end", self.end)?;
        dict.set_item("protection", self.protection)?;
        dict.set_item("vad_type", self.vad_type)?;
        dict.set_item("private_memory", self.private_memory)?;
        dict.set_item("commit_charge", self.commit_charge)?;
        dict.set_item("details", self.details.clone())?;
        Ok(PlainDict(dict))
    }

    fn __repr__(&self) -> String {
        format!("<MemoryRegion {:#x}..{:#x}>", self.start, self.end)
    }
}

/// Loaded-module context for a structured memory-search hit.
#[pyclass(frozen, get_all, module = "ntoseye", skip_from_py_object)]
#[derive(Clone)]
pub struct AddressModule {
    /// The module's image name.
    name: String,
    /// The module's base address.
    base: u64,
    /// The module's image size.
    size: u32,
    /// The hit's offset from `base`.
    offset: u64,
}

impl From<CoreAddressModule> for AddressModule {
    fn from(module: CoreAddressModule) -> Self {
        Self {
            name: module.name,
            base: module.base.0,
            size: module.size,
            offset: module.offset,
        }
    }
}

#[pymethods]
impl AddressModule {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let module = CoreAddressModule {
            name: self.name.clone(),
            base: VirtAddr(self.base),
            size: self.size,
            offset: self.offset,
        };
        view_dict(py, &view::address_module(&module))
    }

    fn __repr__(&self) -> String {
        format!("<AddressModule {} base={:#x}>", self.name, self.base)
    }
}

/// A memory-search hit with symbol and location context.
#[pyclass(frozen, get_all, module = "ntoseye", skip_from_py_object)]
#[derive(Clone)]
pub struct MemorySearchMatch {
    /// Where the pattern matched.
    address: u64,
    /// The match's offset from the search start.
    offset: u64,
    /// The nearest symbol, if one resolved.
    symbol: Option<String>,
    /// What the address is: a module, a kernel region, a process VAD, or physical memory.
    kind: String,
    /// The module containing the match, if any.
    module: Option<AddressModule>,
    /// The module section containing the match, if any.
    section: Option<String>,
    /// The kernel virtual-address region type, for kernel addresses.
    va_type: Option<String>,
    /// The VAD region containing the match, for process addresses.
    region: Option<MemoryRegion>,
}

impl MemorySearchMatch {
    fn from_core(hit: CoreMemorySearchMatch) -> Self {
        Self {
            address: hit.address.0,
            offset: hit.offset,
            symbol: hit.symbol,
            kind: hit.description.kind.to_string(),
            module: hit.description.module.map(AddressModule::from),
            section: hit.description.section,
            va_type: hit.description.va_type,
            region: hit.description.region.map(MemoryRegion::from),
        }
    }

    fn physical(start: u64, offset: usize) -> Self {
        Self {
            address: start.wrapping_add(offset as u64),
            offset: offset as u64,
            symbol: None,
            kind: "physical".to_string(),
            module: None,
            section: None,
            va_type: None,
            region: None,
        }
    }
}

#[pymethods]
impl MemorySearchMatch {
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<PlainDict<'py>> {
        let dict = PyDict::new(py);
        dict.set_item("address", self.address)?;
        dict.set_item("offset", self.offset)?;
        dict.set_item("symbol", self.symbol.clone())?;
        dict.set_item("kind", &self.kind)?;
        match &self.module {
            Some(module) => dict.set_item("module", module.to_dict(py)?)?,
            None => dict.set_item("module", py.None())?,
        }
        dict.set_item("section", self.section.clone())?;
        dict.set_item("va_type", self.va_type.clone())?;
        match &self.region {
            Some(region) => dict.set_item("region", region.to_dict(py)?)?,
            None => dict.set_item("region", py.None())?,
        }
        Ok(PlainDict(dict))
    }

    fn __repr__(&self) -> String {
        match &self.symbol {
            Some(symbol) => format!("<MemorySearchMatch {:#x} {}>", self.address, symbol),
            None => format!("<MemorySearchMatch {:#x}>", self.address),
        }
    }
}
