//! AMD64 four-level paging: what each entry's hardware bits mean.

use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::Amd64;
use crate::arch::{MappingPermissions, Paging, TableEntry};
use crate::base::types::{
    PDE_SHIFT, PDPTE_SHIFT, PFN_MASK, PageTableEntry, PageTableLevel, PhysAddr, PteAttributes,
    PteMarks, VirtAddr,
};

/// An AMD64 page-table entry, read by its hardware bits.
#[repr(transparent)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct Entry(pub u64);

impl Entry {
    pub const fn is_present(self) -> bool {
        self.0 & 1 != 0
    }

    pub const fn is_writable(self) -> bool {
        self.0 & 0x2 != 0
    }

    pub const fn is_user(self) -> bool {
        self.0 & 0x4 != 0
    }

    /// PS: a PDPTE or PDE maps a 1 GiB or 2 MiB page instead of pointing at
    /// a table. In a PTE bit 7 is PAT.
    pub const fn is_large(self) -> bool {
        self.0 & 0x80 != 0
    }

    pub const fn is_nx(self) -> bool {
        self.0 & (1 << 63) != 0
    }

    /// The table or 4 KiB page the entry points at.
    pub const fn frame(self) -> PhysAddr {
        self.0 & PFN_MASK
    }

    /// Base of the 1 GiB page a large PDPTE maps. In a large-page entry bit
    /// 12 is PAT and the bits below the page size are reserved, not address.
    pub const fn huge_frame(self) -> PhysAddr {
        self.frame() & !((1u64 << PDPTE_SHIFT) - 1)
    }

    /// Base of the 2 MiB page a large PDE maps (see
    /// [`huge_frame`](Self::huge_frame)).
    pub const fn large_frame(self) -> PhysAddr {
        self.frame() & !((1u64 << PDE_SHIFT) - 1)
    }
}

impl Paging for Amd64 {
    /// The canonical upper half.
    fn is_kernel_address(&self, va: VirtAddr) -> bool {
        va.0 >= 0xffff_8000_0000_0000
    }

    fn separate_kernel_root(&self) -> bool {
        false
    }

    fn levels(&self) -> &'static [PageTableLevel] {
        &PageTableLevel::ALL
    }

    fn decode_entry(&self, level: PageTableLevel, entry: PageTableEntry) -> TableEntry {
        let entry = Entry(entry.0);
        if !entry.is_present() {
            return TableEntry::Absent;
        }
        match level {
            PageTableLevel::Ppe if entry.is_large() => TableEntry::Leaf(entry.huge_frame()),
            PageTableLevel::Pde if entry.is_large() => TableEntry::Leaf(entry.large_frame()),
            PageTableLevel::Pte => TableEntry::Leaf(entry.frame()),
            PageTableLevel::Pxe | PageTableLevel::Ppe | PageTableLevel::Pde => {
                TableEntry::Table(entry.frame())
            }
        }
    }

    /// Every level restricts what lies below it: a page is user-accessible
    /// only if each entry allows it, and no-execute if any entry says so.
    fn mapping_permissions(&self, path: &[PageTableEntry], _va: VirtAddr) -> MappingPermissions {
        MappingPermissions {
            user: path.iter().all(|entry| Entry(entry.0).is_user()),
            nx: path.iter().any(|entry| Entry(entry.0).is_nx()),
            uxn: false,
        }
    }

    fn entry_attributes(
        &self,
        entry: PageTableEntry,
        level: PageTableLevel,
        _address: VirtAddr,
    ) -> PteAttributes {
        let entry = Entry(entry.0);
        let bit = |n: u32| entry.0 & (1 << n) != 0;
        let upper_level = matches!(level, PageTableLevel::Ppe | PageTableLevel::Pde);
        PteAttributes::new(
            entry.is_present(),
            upper_level && entry.is_large(),
            entry.is_writable(),
            entry.is_user(),
            entry.is_nx(),
            entry.frame() >> 12,
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
        assert_eq!(
            Amd64.decode_entry(PageTableLevel::Ppe, pdpte),
            TableEntry::Leaf(0x4000_0000)
        );
        let pde = PageTableEntry(0x0040_0000 | PAT | 0x80 | 0b111);
        assert_eq!(
            Amd64.decode_entry(PageTableLevel::Pde, pde),
            TableEntry::Leaf(0x0040_0000)
        );
    }
}
