//! AMD64 four-level paging: what each entry's hardware bits mean.

use crate::arch::{MappingPermissions, TableEntry};
use crate::base::types::{
    PDE_SHIFT, PDPTE_SHIFT, PFN_MASK, PageTableEntry, PageTableLevel, PteAttributes, PteMarks,
    VirtAddr,
};

impl PageTableEntry {
    pub const fn is_large_page(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// Base of the 1 GiB page a large PDPTE maps. In a large-page entry bit 12
    /// is PAT and the bits below the page size are reserved, not address.
    pub const fn huge_page_frame(self) -> u64 {
        self.0 & PFN_MASK & !((1u64 << PDPTE_SHIFT) - 1)
    }

    /// Base of the 2 MiB page a large PDE maps (see
    /// [`huge_page_frame`](Self::huge_page_frame)).
    pub const fn large_page_frame(self) -> u64 {
        self.0 & PFN_MASK & !((1u64 << PDE_SHIFT) - 1)
    }

    pub const fn is_user(self) -> bool {
        self.0 & 0x4 != 0
    }

    pub const fn is_nx(self) -> bool {
        self.0 & (1 << 63) != 0
    }

    pub const fn is_writable(self) -> bool {
        self.0 & 0x2 != 0
    }
}

/// The kernel half: the canonical upper half.
pub fn is_kernel_address(va: VirtAddr) -> bool {
    va.0 >= 0xffff_8000_0000_0000
}

pub fn decode_entry(level: usize, entry: PageTableEntry) -> TableEntry {
    if !entry.is_present() {
        return TableEntry::Absent;
    }
    match level {
        // PS maps a 1 GiB page in a PDPTE and a 2 MiB page in a PDE.
        1 if entry.is_large_page() => TableEntry::Leaf(entry.huge_page_frame()),
        2 if entry.is_large_page() => TableEntry::Leaf(entry.large_page_frame()),
        3 => TableEntry::Leaf(entry.page_frame()),
        _ => TableEntry::Table(entry.page_frame()),
    }
}

/// Every level restricts what lies below it: a page is user-accessible only
/// if each entry allows it, and no-execute if any entry says so.
pub fn mapping_permissions(path: &[PageTableEntry]) -> MappingPermissions {
    MappingPermissions {
        user: path.iter().all(|entry| entry.is_user()),
        nx: path.iter().any(|entry| entry.is_nx()),
        uxn: false,
    }
}

pub fn entry_attributes(entry: PageTableEntry, level: PageTableLevel) -> PteAttributes {
    let bit = |n: u32| entry.0 & (1 << n) != 0;
    // Bit 7 is PS only above the leaf; in a PTE it is PAT.
    let upper_level = matches!(level, PageTableLevel::Ppe | PageTableLevel::Pde);
    PteAttributes::new(
        entry.is_present(),
        upper_level && entry.is_large_page(),
        entry.is_writable(),
        entry.is_user(),
        entry.is_nx(),
        entry.pfn(),
        PteMarks {
            copy_on_write: bit(9),
            global: bit(8),
            dirty: bit(6),
            accessed: bit(5),
            cache_disable: bit(4),
            write_through: bit(3),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In a large-page entry bit 12 is PAT, not address: reading it as one
    /// resolves every PAT-typed large mapping one page off.
    #[test]
    fn large_page_frames_ignore_the_pat_bit() {
        const PAT: u64 = 1 << 12;
        let pdpte = PageTableEntry(0x4000_0000 | PAT | 0x80 | 0b111);
        assert_eq!(decode_entry(1, pdpte), TableEntry::Leaf(0x4000_0000));
        let pde = PageTableEntry(0x0040_0000 | PAT | 0x80 | 0b111);
        assert_eq!(decode_entry(2, pde), TableEntry::Leaf(0x0040_0000));
    }
}
