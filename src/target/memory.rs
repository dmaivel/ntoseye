//! Reading guest memory in the target's scopes: address spaces and typed
//! views over them, byte-pattern search, fields, and counted and C strings.

use super::{CODE_BITNESS_AMD64, CODE_BITNESS_X86, MemorySearchMatch, StringDescriptor, Target};
use std::sync::atomic::Ordering;

use crate::{
    backend::MemoryOps,
    error::{Error, Result},
    layout::{StructRef, TypeInfo, Types},
    memory::{AddressSpace, PAGE_SIZE, pattern_offsets, read_page_chunks},
    phys::PhysMem,
    types::{Dtb, VirtAddr},
};

/// The most bytes one search scans.
pub const MAX_SEARCH_BYTES: usize = 1 << 30;
/// The most matches one search records. A pattern common in the range (a
/// zero byte) would otherwise fill memory with them.
pub const MAX_SEARCH_MATCHES: usize = 4096;
/// Bytes read per step of a search.
const SEARCH_CHUNK: usize = 1 << 20;

/// What [`Target::search`] found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SearchResult {
    /// Where the pattern matched, overlapping matches included, in order.
    pub matches: Vec<u64>,
    /// Bytes of the range that could not be read and were skipped.
    pub unreadable: usize,
    /// The search stopped early: [`MAX_SEARCH_MATCHES`] was reached, or the
    /// host interrupted it.
    pub stopped: Option<SearchStop>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchStop {
    MatchLimit,
    Interrupted,
}

/// What [`Target::compare`] found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CompareResult {
    /// Offsets into both ranges whose bytes differ, with the first range's
    /// byte and the second's, in order.
    pub differences: Vec<(usize, u8, u8)>,
    /// Offsets readable in both ranges whose bytes were compared: fewer than
    /// the length less `unreadable` when the comparison stopped early.
    pub compared: usize,
    /// Offsets at which either range could not be read, and were skipped.
    pub unreadable: usize,
    /// The comparison stopped early: [`MAX_SEARCH_MATCHES`] differences
    /// were found, or the host interrupted it.
    pub stopped: Option<SearchStop>,
}

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

    /// Search `length` bytes from `start` for the byte `pattern`, reading
    /// with `read` (a host's view of the inspection space, with its own
    /// breakpoints masked). Unreadable pages are skipped, and a match must lie
    /// in readable bytes. The range is read a chunk at a time, so it may be
    /// large; see [`SearchResult`] for where it stops.
    pub fn search(
        &self,
        start: VirtAddr,
        pattern: &[u8],
        length: usize,
        read: impl Fn(VirtAddr, &mut [u8]) -> Result<()>,
    ) -> Result<SearchResult> {
        if length > MAX_SEARCH_BYTES {
            return Err(Error::InvalidArgument(format!(
                "search length {length:#x} exceeds the maximum of {MAX_SEARCH_BYTES:#x} bytes"
            )));
        }
        let mut result = SearchResult::default();
        if pattern.is_empty() || pattern.len() > length {
            return Ok(result);
        }
        let mut offset = 0usize;
        while offset + pattern.len() <= length {
            if self.interrupt.load(Ordering::Relaxed) {
                result.stopped = Some(SearchStop::Interrupted);
                break;
            }
            // Each chunk reads on past its end by a pattern less one byte,
            // so a match straddling two chunks is found in the first.
            let starts = SEARCH_CHUNK.min(length - offset - pattern.len() + 1);
            let chunk_len = starts + pattern.len() - 1;
            let chunk_start = VirtAddr(start.0.wrapping_add(offset as u64));
            let (data, valid) = read_page_chunks(chunk_start, chunk_len, &read)?;
            result.unreadable += valid[..starts].iter().filter(|valid| !**valid).count();
            for at in pattern_offsets(&data, pattern).filter(|&at| at < starts) {
                if !valid[at..at + pattern.len()].iter().all(|valid| *valid) {
                    continue;
                }
                if result.matches.len() == MAX_SEARCH_MATCHES {
                    result.stopped = Some(SearchStop::MatchLimit);
                    return Ok(result);
                }
                result.matches.push(chunk_start.0.wrapping_add(at as u64));
            }
            offset += starts;
        }
        Ok(result)
    }

    /// Compare `length` bytes at `first` with as many at `second`, reading
    /// with `read` as [`Self::search`] does. Offsets unreadable in either
    /// range are skipped and counted; see [`CompareResult`] for where it
    /// stops.
    pub fn compare(
        &self,
        first: VirtAddr,
        second: VirtAddr,
        length: usize,
        read: impl Fn(VirtAddr, &mut [u8]) -> Result<()>,
    ) -> Result<CompareResult> {
        if length > MAX_SEARCH_BYTES {
            return Err(Error::InvalidArgument(format!(
                "compare length {length:#x} exceeds the maximum of {MAX_SEARCH_BYTES:#x} bytes"
            )));
        }
        let mut result = CompareResult::default();
        let mut offset = 0usize;
        while offset < length {
            if self.interrupt.load(Ordering::Relaxed) {
                result.stopped = Some(SearchStop::Interrupted);
                break;
            }
            let chunk_len = SEARCH_CHUNK.min(length - offset);
            let at = |start: VirtAddr| VirtAddr(start.0.wrapping_add(offset as u64));
            let (left, left_valid) = read_page_chunks(at(first), chunk_len, &read)?;
            let (right, right_valid) = read_page_chunks(at(second), chunk_len, &read)?;
            for index in 0..chunk_len {
                if !(left_valid[index] && right_valid[index]) {
                    result.unreadable += 1;
                    continue;
                }
                if left[index] != right[index] {
                    if result.differences.len() == MAX_SEARCH_MATCHES {
                        result.stopped = Some(SearchStop::MatchLimit);
                        return Ok(result);
                    }
                    result
                        .differences
                        .push((offset + index, left[index], right[index]));
                }
                result.compared += 1;
            }
            offset += chunk_len;
        }
        Ok(result)
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

    /// [`Self::read_layout_field`] of a kernel structure, read through the
    /// kernel's root: every NT root maps kernel space alike, and one halted
    /// outside NT (the Windows hypervisor, VTL1) maps none of it.
    pub fn read_kernel_layout_field<T>(
        &self,
        layout: &TypeInfo,
        base: VirtAddr,
        name: &str,
    ) -> Result<T>
    where
        T: Copy + zerocopy::FromZeros + zerocopy::FromBytes + zerocopy::IntoBytes,
    {
        self.kernel_address_space()
            .read(base + layout.field_offset(name)?)
    }

    /// [`Self::extract_layout_bits`] of a kernel structure; see
    /// [`Self::read_kernel_layout_field`].
    pub fn extract_kernel_layout_bits(
        &self,
        layout: &TypeInfo,
        base: VirtAddr,
        name: &str,
    ) -> Result<u64> {
        let field = layout.field(name)?;
        let raw: u64 = self
            .kernel_address_space()
            .read(base + field.offset as u64)?;
        Ok(field.decode(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::session_over_memory;

    /// `c` reads a chunk at a time: a difference past the first chunk is
    /// reported at its offset in the range, bytes unreadable in one range are
    /// skipped and counted, and stopping at the difference limit counts only
    /// the bytes it compared.
    #[test]
    fn compare_reports_offsets_across_chunks_and_counts_what_it_compared() {
        const BASE: u64 = 0x10_0000;
        let target = session_over_memory(0x1000, &[0; 0x10]).target;
        // Memory from BASE, with one page of the second range unmapped.
        let compare = |memory: &[u8], hole: u64, second: u64, length| {
            let read = |address: VirtAddr, buf: &mut [u8]| {
                let offset = (address.0 - BASE) as usize;
                match memory.get(offset..offset + buf.len()) {
                    Some(bytes) if address.0 - address.page_offset() != hole => {
                        buf.copy_from_slice(bytes);
                        Ok(())
                    }
                    _ => Err(Error::InvalidArgument("unmapped".into())),
                }
            };
            target
                .compare(VirtAddr(BASE), VirtAddr(BASE + second), length, read)
                .unwrap()
        };

        const LENGTH: usize = SEARCH_CHUNK + 0x40000;
        const SECOND: usize = LENGTH + 0x1000;
        let mut memory = vec![0u8; SECOND + LENGTH];
        memory[0x10] = 0xaa;
        memory[SECOND + 3] = 1;
        memory[SECOND + SEARCH_CHUNK + 5] = 2;
        let hole = BASE + (SECOND + 0x2000) as u64;
        memory[SECOND + 0x2000] = 3;
        let result = compare(&memory, hole, SECOND as u64, LENGTH);
        assert_eq!(
            result.differences,
            [(3, 0, 1), (0x10, 0xaa, 0), (SEARCH_CHUNK + 5, 0, 2)]
        );
        assert_eq!(result.unreadable, PAGE_SIZE);
        assert_eq!(result.compared, LENGTH - PAGE_SIZE);
        assert_eq!(result.stopped, None);

        // 16 equal bytes, then nothing but differences: the comparison stops
        // at the difference past the limit.
        let mut memory = vec![0u8; 0x4000];
        memory[0x2010..].fill(0xff);
        let result = compare(&memory, 0, 0x2000, 0x2000);
        assert_eq!(result.differences.len(), MAX_SEARCH_MATCHES);
        assert_eq!(
            result.differences.last(),
            Some(&(16 + MAX_SEARCH_MATCHES - 1, 0, 0xff))
        );
        assert_eq!(result.compared, 16 + MAX_SEARCH_MATCHES);
        assert_eq!(result.stopped, Some(SearchStop::MatchLimit));
    }
}
