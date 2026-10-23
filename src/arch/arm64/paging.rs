//! AArch64 stage-1 paging, 4 KiB granule: what each descriptor's bits mean.
//!
//! bits\[1:0\]: 0b00 invalid, 0b01 block (L0-L2), 0b11 table (L0-L2) /
//! page (L3). Block and page descriptors carry AP\[2:1\], PXN, and UXN.
//! Windows disables hierarchical permissions (`TCR_EL1.HPD`), so a table
//! descriptor's APTable/PXNTable/UXNTable bits restrict nothing. Output
//! address bits \[47:12\] support a 48-bit PA space.

use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::Arm64;
use crate::arch::{MappingPermissions, Paging, TableEntry};
use crate::base::types::{
    PDE_SHIFT, PDPTE_SHIFT, PageTableEntry, PageTableLevel, PhysAddr, PteAttributes, PteMarks,
    VirtAddr,
};

/// An AArch64 translation-table descriptor, read by its hardware bits.
#[repr(transparent)]
#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct Descriptor(pub u64);

impl Descriptor {
    /// `0b01` a block, `0b11` a table or page; `0b00` invalid, `0b10`
    /// reserved.
    pub const fn is_valid(self) -> bool {
        self.0 & 0b01 != 0
    }

    pub const fn is_block(self) -> bool {
        self.0 & 0b11 == 0b01
    }

    /// `0b11`: a table descriptor above the last level, a page descriptor at
    /// it.
    pub const fn is_table_or_page(self) -> bool {
        self.0 & 0b11 == 0b11
    }

    /// Output address bits \[47:12\] (48-bit PA space), kept in place.
    pub const fn frame(self) -> PhysAddr {
        self.0 & 0x0000_FFFF_FFFF_F000
    }

    /// Output address of an L1 (1 GiB) block descriptor. The bits below the
    /// block size are not address: bit 16 is `nT`, the rest are RES0.
    pub const fn huge_frame(self) -> PhysAddr {
        self.frame() & !((1u64 << PDPTE_SHIFT) - 1)
    }

    /// Output address of an L2 (2 MiB) block descriptor (see
    /// [`huge_frame`](Self::huge_frame)).
    pub const fn large_frame(self) -> PhysAddr {
        self.frame() & !((1u64 << PDE_SHIFT) - 1)
    }

    /// AP\[1\] (bit 6): EL0 may access the mapping.
    pub const fn is_user(self) -> bool {
        self.0 & (1 << 6) != 0
    }

    /// AP\[2\] (bit 7) clear: the mapping is not read-only.
    pub const fn is_writable(self) -> bool {
        self.0 & (1 << 7) == 0
    }

    /// Privileged execute-never (PXN, bit 53) on a block/page descriptor.
    pub const fn is_pxn(self) -> bool {
        self.0 & (1 << 53) != 0
    }

    /// Unprivileged execute-never (UXN, bit 54) on a block/page descriptor.
    pub const fn is_uxn(self) -> bool {
        self.0 & (1 << 54) != 0
    }
}

impl Paging for Arm64 {
    /// Bit 55, which selects TTBR1.
    fn is_kernel_address(&self, va: VirtAddr) -> bool {
        va.0 & (1 << 55) != 0
    }

    /// 48-bit TTBR0 and TTBR1 ranges.
    fn canonical_halves(&self) -> (u64, u64) {
        (0x0001_0000_0000_0000, 0xffff_0000_0000_0000)
    }

    /// Any value: a return address a pointer-authenticated prolog saved
    /// carries its authentication code in the upper bits.
    fn could_be_pointer(&self, _value: u64) -> bool {
        true
    }

    /// The canonical upper half, as on every 64-bit Windows.
    fn system_range_start(&self) -> u64 {
        0xffff_8000_0000_0000
    }

    fn separate_kernel_root(&self) -> bool {
        true
    }

    fn levels(&self) -> &'static [PageTableLevel] {
        &PageTableLevel::ALL
    }

    fn decode_entry(&self, level: PageTableLevel, entry: PageTableEntry) -> TableEntry {
        let descriptor = Descriptor(entry.0);
        match level {
            _ if !descriptor.is_valid() => TableEntry::Absent,
            // Windows maps no 512 GiB level-0 blocks.
            PageTableLevel::Pxe if descriptor.is_block() => TableEntry::Absent,
            PageTableLevel::Ppe if descriptor.is_block() => {
                TableEntry::Leaf(descriptor.huge_frame())
            }
            PageTableLevel::Pde if descriptor.is_block() => {
                TableEntry::Leaf(descriptor.large_frame())
            }
            // At the last level `0b01` is reserved.
            PageTableLevel::Pte if !descriptor.is_table_or_page() => TableEntry::Absent,
            PageTableLevel::Pte => TableEntry::Leaf(descriptor.frame()),
            PageTableLevel::Pxe | PageTableLevel::Ppe | PageTableLevel::Pde => {
                TableEntry::Table(descriptor.frame())
            }
        }
    }

    /// The mapping descriptor's own permissions: Windows sets `TCR_EL1.HPD`,
    /// so the table descriptors above keep their own bits in
    /// APTable/PXNTable/UXNTable (a user page's level-0 entry has
    /// APTable\[0\] set) and restrict nothing.
    fn mapping_permissions(&self, path: &[PageTableEntry], va: VirtAddr) -> MappingPermissions {
        let leaf = Descriptor(path.last().map_or(0, |entry| entry.0));
        MappingPermissions {
            user: leaf.is_user(),
            nx: if self.is_kernel_address(va) {
                leaf.is_pxn()
            } else {
                leaf.is_uxn()
            },
            uxn: leaf.is_uxn(),
        }
    }

    fn entry_attributes(
        &self,
        entry: PageTableEntry,
        level: PageTableLevel,
        address: VirtAddr,
    ) -> PteAttributes {
        let descriptor = Descriptor(entry.0);
        let bit = |n: u32| entry.0 & (1 << n) != 0;
        let upper_level = matches!(level, PageTableLevel::Ppe | PageTableLevel::Pde);
        let block = upper_level && descriptor.is_block();
        // A block or page descriptor maps; a table descriptor's permission
        // bits are Windows' own (it sets `TCR_EL1.HPD`), so it restricts
        // nothing below it.
        let table = level != PageTableLevel::Pte && !block;
        let kernel = self.is_kernel_address(address);
        let (writable, user, nx) = if table {
            (true, !kernel, false)
        } else {
            (
                descriptor.is_writable(),
                descriptor.is_user(),
                if kernel {
                    descriptor.is_pxn()
                } else {
                    descriptor.is_uxn()
                },
            )
        };
        let present = if level == PageTableLevel::Pte {
            descriptor.is_table_or_page()
        } else {
            descriptor.is_valid()
        };
        // A mapping is global with nG (bit 11) clear, accessed with AF (bit
        // 10) set, and written once writable with DBM (bit 51) set. Table
        // descriptors have none of these.
        let marks = if table {
            PteMarks::default()
        } else {
            PteMarks {
                global: !bit(11),
                dirty: bit(51) && writable,
                accessed: bit(10),
                ..PteMarks::default()
            }
        };
        PteAttributes::new(
            present,
            block,
            writable,
            user,
            nx,
            descriptor.frame() >> 12,
            marks,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block descriptor's bits below the block size are `nT` (bit 16) or
    /// RES0, not output address.
    #[test]
    fn block_frames_ignore_non_address_bits() {
        const NT: u64 = 1 << 16;
        assert_eq!(
            Arm64.decode_entry(PageTableLevel::Ppe, PageTableEntry(0x4000_0000 | NT | 0b01)),
            TableEntry::Leaf(0x4000_0000)
        );
        assert_eq!(
            Arm64.decode_entry(PageTableLevel::Pde, PageTableEntry(0x0060_0000 | NT | 0b01)),
            TableEntry::Leaf(0x0060_0000)
        );
    }
}
