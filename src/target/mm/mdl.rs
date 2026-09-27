//! `_MDL` decoding (`!mdl`): the header and the PFN array after it.

use super::MdlDetail;
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::memory::PAGE_SIZE;
use crate::target::Target;
use crate::types::VirtAddr;

/// `sizeof(PFN_NUMBER)` on 64-bit Windows (a `ULONG_PTR`).
const PFN_NUMBER_SIZE: u64 = 8;

/// The `MDL_*` flag bits from wdm.h, low bit first. 0x0100 is
/// `MDL_LOCKED_PAGE_TABLES`, which wdm.h also names
/// `MDL_PARENT_MAPPED_SYSTEM_VA`; 0x4000 is `MDL_PAGE_CONTENTS_INVARIANT`
/// (`MDL_ALLOCATED_MUST_SUCCEED` in older kits).
const MDL_FLAG_NAMES: [&str; 16] = [
    "MDL_MAPPED_TO_SYSTEM_VA",
    "MDL_PAGES_LOCKED",
    "MDL_SOURCE_IS_NONPAGED_POOL",
    "MDL_ALLOCATED_FIXED_SIZE",
    "MDL_PARTIAL",
    "MDL_PARTIAL_HAS_BEEN_MAPPED",
    "MDL_IO_PAGE_READ",
    "MDL_WRITE_OPERATION",
    "MDL_LOCKED_PAGE_TABLES",
    "MDL_FREE_EXTRA_PTES",
    "MDL_DESCRIBES_AWE",
    "MDL_IO_SPACE",
    "MDL_NETWORK_HEADER",
    "MDL_MAPPING_CAN_FAIL",
    "MDL_PAGE_CONTENTS_INVARIANT",
    "MDL_INTERNAL",
];

/// Names of the `MDL_*` bits set in `flags`.
fn mdl_flag_names(flags: u16) -> Vec<&'static str> {
    MDL_FLAG_NAMES
        .iter()
        .enumerate()
        .filter(|(bit, _)| flags & (1 << bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// `ADDRESS_AND_SIZE_TO_SPAN_PAGES(StartVa + ByteOffset, ByteCount)`: the
/// pages a buffer starting `byte_offset` into its first page covers.
fn mdl_spanned_pages(byte_offset: u32, byte_count: u32) -> u64 {
    let page = PAGE_SIZE as u64;
    (u64::from(byte_offset) % page + u64::from(byte_count)).div_ceil(page)
}

impl Target {
    /// Decode the `_MDL` at `address` and read the PFNs after its header.
    /// `pfn_count` overrides the count the buffer spans; either is bounded by
    /// the slots `Size` holds. A header whose `Size`,
    /// `ByteOffset`, or span cannot describe an MDL is refused rather than
    /// guessed at.
    pub fn inspect_mdl(&self, address: VirtAddr, pfn_count: Option<u64>) -> Result<MdlDetail> {
        let guest = self.guest()?;
        let types = guest.ntoskrnl.types();
        let header_size = types.layout("_MDL")?.size as u64;
        let mdl = types.struct_at("_MDL", address)?.prefetch();
        let size: u16 = mdl.read_field("Size")?;
        let flags: u16 = mdl.read_field("MdlFlags")?;
        let byte_count: u32 = mdl.read_field("ByteCount")?;
        let byte_offset: u32 = mdl.read_field("ByteOffset")?;
        let not_mdl =
            |why: String| Error::DebugInfo(format!("{:#x} is not an _MDL: {why}", address.0));
        let size = u64::from(size);
        if size < header_size || !(size - header_size).is_multiple_of(PFN_NUMBER_SIZE) {
            return Err(not_mdl(format!(
                "Size {size:#x} is not the {header_size:#x}-byte header plus whole PFN slots"
            )));
        }
        if u64::from(byte_offset) >= PAGE_SIZE as u64 {
            return Err(not_mdl(format!(
                "ByteOffset {byte_offset:#x} is not an offset into a page"
            )));
        }
        let capacity = (size - header_size) / PFN_NUMBER_SIZE;
        let spanned_pages = mdl_spanned_pages(byte_offset, byte_count);
        if spanned_pages > capacity {
            return Err(not_mdl(format!(
                "ByteCount {byte_count:#x} at ByteOffset {byte_offset:#x} spans {spanned_pages} \
                 pages, but Size {size:#x} holds {capacity} PFNs"
            )));
        }
        let shown = pfn_count.unwrap_or(spanned_pages).min(capacity);
        let pfn_array = address + header_size;
        let mut raw = vec![0u8; (shown * PFN_NUMBER_SIZE) as usize];
        guest
            .ntoskrnl
            .memory()
            .read_bytes(pfn_array, &mut raw)
            .map_err(|error| {
                Error::DebugInfo(format!(
                    "cannot read the {shown} PFNs at {:#x}: {error}",
                    pfn_array.0
                ))
            })?;
        let pfns = raw
            .as_chunks::<{ PFN_NUMBER_SIZE as usize }>()
            .0
            .iter()
            .map(|chunk| u64::from_le_bytes(*chunk))
            .collect();
        Ok(MdlDetail {
            address,
            next: mdl.read_pointer("Next")?,
            size: size as u16,
            flags,
            flag_names: mdl_flag_names(flags),
            process: mdl.read_pointer("Process")?,
            mapped_system_va: mdl.read_pointer("MappedSystemVa")?,
            start_va: mdl.read_pointer("StartVa")?,
            byte_count,
            byte_offset,
            spanned_pages,
            capacity,
            pfn_array,
            pfns,
            truncated: shown < spanned_pages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_counts_the_pages_an_offset_buffer_touches() {
        // An IOCTL buffer MDL read live from build 26200: 0x27c bytes at
        // page offset 0x980 fit in one page.
        assert_eq!(mdl_spanned_pages(0x980, 0x27c), 1);
        // Crossing a page boundary by one byte takes a second page.
        assert_eq!(mdl_spanned_pages(0xf00, 0x101), 2);
        assert_eq!(mdl_spanned_pages(0, 0x1000), 1);
        assert_eq!(mdl_spanned_pages(0, 0), 0);
    }
}
