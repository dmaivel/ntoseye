//! Reading guest memory in the target's scopes: address spaces and typed
//! views over them, byte-pattern search, fields, and counted and C strings.

use super::{CODE_BITNESS_AMD64, CODE_BITNESS_X86, MemorySearchMatch, StringDescriptor, Target};
use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    layout::{StructRef, TypeInfo, Types},
    memory::{AddressSpace, PAGE_SIZE, pattern_offsets},
    phys::PhysMem,
    types::{Dtb, VirtAddr},
};

impl Target {
    /// An address space rooted at `dtb` in the resolved guest architecture. On
    /// ARM64 the kernel root (TTBR1) is threaded in so kernel-VA reads work
    /// from any space; on AMD64 one CR3 covers both halves.
    pub fn address_space(&self, dtb: Dtb) -> AddressSpace<'_, PhysMem> {
        AddressSpace::for_arch(&self.phys, dtb, self.kernel_dtb(), self.arch())
    }

    /// Kernel-root address space (reads kernel VAs on both arches).
    pub fn kernel_address_space(&self) -> AddressSpace<'_, PhysMem> {
        self.address_space(self.kernel_dtb())
    }

    /// Memory of the module-list scope (see [`Self::process_dtb`]), for
    /// reading the modules that scope lists.
    pub fn process_memory(&self) -> AddressSpace<'_, PhysMem> {
        self.address_space(self.process_dtb())
    }

    /// Memory view for the inspection address space ([`Self::current_dtb`]).
    pub fn context_memory(&self) -> AddressSpace<'_, PhysMem> {
        self.address_space(self.current_dtb())
    }

    /// Kernel types read in the inspection address space
    /// ([`Self::current_dtb`]). Without a discovered kernel only
    /// `module!`-qualified names resolve.
    pub fn context_types(&self) -> Types<'_> {
        self.types_in(self.current_dtb())
    }

    /// Kernel types read through `dtb`'s page tables.
    pub fn types_in(&self, dtb: Dtb) -> Types<'_> {
        match &self.guest {
            Some(guest) => guest.ntoskrnl.types_in(dtb),
            None => Types::new(
                &self.symbols,
                None,
                &self.phys,
                self.arch(),
                self.kernel_dtb(),
                dtb,
            ),
        }
    }

    /// Search `length` bytes from `start` in the current address space for the
    /// byte `pattern`, returning the addresses of all (overlapping) matches.
    pub fn search(&self, start: VirtAddr, pattern: &[u8], length: usize) -> Result<Vec<u64>> {
        if pattern.is_empty() || pattern.len() > length {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; length];
        self.context_memory().read_bytes(start, &mut buf)?;
        Ok(pattern_offsets(&buf, pattern)
            .map(|offset| start.0.wrapping_add(offset as u64))
            .collect())
    }

    /// Add symbol/module/region context to already-computed search hits. Keeping
    /// this separate from `search` lets paged callers enrich only returned rows.
    pub fn describe_search_matches(
        &self,
        start: VirtAddr,
        matches: &[u64],
    ) -> Result<Vec<MemorySearchMatch>> {
        matches
            .iter()
            .copied()
            .map(|addr| {
                let address = VirtAddr(addr);
                Ok(MemorySearchMatch {
                    address,
                    offset: addr.wrapping_sub(start.0),
                    symbol: self.closest_symbol_current_context(address),
                    description: self.describe_address(address)?,
                })
            })
            .collect()
    }

    /// A cursor over the `kind` descriptor at `addr` in the inspection space,
    /// in the layout `bits` selects: the kernel's 64-bit one, or the 32-bit
    /// one from a WOW64 process's x86 ntdll (`ntdll32!`).
    pub fn string_descriptor(
        &self,
        addr: VirtAddr,
        kind: StringDescriptor,
        bits: u32,
    ) -> Result<StructRef<'_>> {
        if !matches!(bits, CODE_BITNESS_X86 | CODE_BITNESS_AMD64) {
            return Err(Error::InvalidArgument(format!(
                "string descriptor width must be 32 or 64 bits, not {bits}"
            )));
        }
        let types = self.context_types();
        let resolve = |name: &str| {
            if bits == CODE_BITNESS_X86 {
                return types.struct_at(&format!("ntdll32!{name}"), addr);
            }
            match types.struct_at(name, addr) {
                // No kernel namespace (a triage dump without ntoskrnl): take
                // the layout from whichever module defines it.
                Err(Error::ExpectedSymbols) => self
                    .symbols
                    .find_type_across_modules(self.kernel_dtb(), name)
                    .map(|layout| types.struct_with_layout(layout, addr))
                    .ok_or(Error::ExpectedSymbols),
                descriptor => descriptor,
            }
        };
        let (name, older_names) = kind.type_names();
        older_names.iter().fold(resolve(name), |found, older| {
            found.or_else(|error| resolve(older).map_err(|_| error))
        })
    }

    /// Decode the `_UNICODE_STRING` at `addr` in the inspection space, in the
    /// `bits`-wide layout (see [`Self::string_descriptor`]). Empty when
    /// null/zero-length. Shared by the SDK and MCP.
    pub fn read_unicode_string(&self, addr: VirtAddr, bits: u32) -> Result<String> {
        self.string_descriptor(addr, StringDescriptor::Unicode, bits)?
            .read_unicode_string()
    }

    /// Decode the `_STRING` at `addr`, one character per byte; the ANSI
    /// counterpart of [`Self::read_unicode_string`].
    pub fn read_ansi_string(&self, addr: VirtAddr, bits: u32) -> Result<String> {
        self.string_descriptor(addr, StringDescriptor::Ansi, bits)?
            .read_ansi_string()
    }

    /// Read a NUL-terminated byte string (`CHAR*`) at `addr` in the current
    /// address space, decoding up to `max_len` bytes as UTF-8 (lossy) and
    /// stopping at the first NUL. Reads are page-bounded, so a string that ends
    /// just before an unmapped page still returns what was readable; only a
    /// completely unmapped start address errors. The `CHAR*` counterpart to
    /// [`read_unicode_string`](Self::read_unicode_string).
    pub fn read_c_string(&self, addr: VirtAddr, max_len: usize) -> Result<String> {
        let mem = self.context_memory();
        let mut bytes = Vec::new();
        while bytes.len() < max_len {
            let cur = addr + bytes.len() as u64;
            let to_page_end = PAGE_SIZE - cur.page_offset() as usize;
            let chunk = to_page_end.min(max_len - bytes.len());
            let mut buf = vec![0u8; chunk];
            match mem.read_bytes(cur, &mut buf) {
                Ok(()) => {}
                // Nothing readable at the very start is a real error; once we
                // have some bytes, a fault just terminates the string.
                Err(_) if !bytes.is_empty() => break,
                Err(e) => return Err(e),
            }
            if let Some(nul) = buf.iter().position(|&b| b == 0) {
                bytes.extend_from_slice(&buf[..nul]);
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.extend_from_slice(&buf);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn read_layout_field<T>(&self, layout: &TypeInfo, base: VirtAddr, name: &str) -> Result<T>
    where
        T: Copy + zerocopy::FromZeros + zerocopy::FromBytes + zerocopy::IntoBytes,
    {
        self.context_memory()
            .read(base + layout.field_offset(name)?)
    }

    pub fn extract_layout_bits(
        &self,
        layout: &TypeInfo,
        base: VirtAddr,
        name: &str,
    ) -> Result<u64> {
        let field = layout.field(name)?;
        let raw: u64 = self.context_memory().read(base + field.offset as u64)?;
        Ok(field.decode(raw))
    }
}
