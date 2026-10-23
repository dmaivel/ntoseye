//! AArch64 stage-1 paging, 4 KiB granule: what each descriptor's bits mean.
//!
//! bits\[1:0\]: 0b00 invalid, 0b01 block (L0-L2), 0b11 table (L0-L2) /
//! page (L3). Block and page descriptors carry AP\[2:1\], PXN, and UXN.
//! Windows disables hierarchical permissions (`TCR_EL1.HPD`), so a table
//! descriptor's APTable/PXNTable/UXNTable bits restrict nothing. Output
//! address bits \[47:12\] support a 48-bit PA space.

use crate::arch::{MappingPermissions, TableEntry};
use crate::base::types::{
    PDE_SHIFT, PDPTE_SHIFT, PageTableEntry, PageTableLevel, PteAttributes, PteMarks, VirtAddr,
};

impl PageTableEntry {
    pub const fn arm64_is_valid(self) -> bool {
        // 0b01 block, 0b11 table/page; 0b00 invalid, 0b10 reserved.
        self.0 & 0b01 != 0
    }

    pub const fn arm64_is_block(self) -> bool {
        self.0 & 0b11 == 0b01
    }

    /// Output address bits \[47:12\] (48-bit PA space), kept in place.
    pub const fn arm64_page_frame(self) -> u64 {
        self.0 & 0x0000_FFFF_FFFF_F000
    }

    /// Output address of an L1 (1 GiB) block descriptor. The bits below the
    /// block size are not address: bit 16 is `nT`, the rest are RES0.
    pub const fn arm64_huge_block_frame(self) -> u64 {
        self.arm64_page_frame() & !((1u64 << PDPTE_SHIFT) - 1)
    }

    /// Output address of an L2 (2 MiB) block descriptor (see
    /// [`arm64_huge_block_frame`](Self::arm64_huge_block_frame)).
    pub const fn arm64_large_block_frame(self) -> u64 {
        self.arm64_page_frame() & !((1u64 << PDE_SHIFT) - 1)
    }

    /// AP\[1\] (bit 6): EL0 may access the mapping.
    pub const fn arm64_is_user(self) -> bool {
        self.0 & (1 << 6) != 0
    }

    /// Privileged execute-never (PXN, bit 53) on a block/page descriptor.
    pub const fn arm64_is_pxn(self) -> bool {
        self.0 & (1 << 53) != 0
    }

    /// Unprivileged execute-never (UXN, bit 54) on a block/page descriptor.
    pub const fn arm64_is_uxn(self) -> bool {
        self.0 & (1 << 54) != 0
    }

    /// AP\[2\] (bit 7) clear: the mapping is not read-only.
    pub const fn arm64_is_writable(self) -> bool {
        self.0 & (1 << 7) == 0
    }
}

/// The kernel half: bit 55 selects TTBR1.
pub fn is_kernel_address(va: VirtAddr) -> bool {
    va.0 & (1 << 55) != 0
}

pub fn decode_entry(level: usize, entry: PageTableEntry) -> TableEntry {
    match level {
        _ if !entry.arm64_is_valid() => TableEntry::Absent,
        // Windows maps no 512 GiB level-0 blocks.
        0 if entry.arm64_is_block() => TableEntry::Absent,
        1 if entry.arm64_is_block() => TableEntry::Leaf(entry.arm64_huge_block_frame()),
        2 if entry.arm64_is_block() => TableEntry::Leaf(entry.arm64_large_block_frame()),
        // At the last level only 0b11 is a page descriptor; 0b01 is reserved.
        3 if entry.0 & 0b11 != 0b11 => TableEntry::Absent,
        3 => TableEntry::Leaf(entry.arm64_page_frame()),
        _ => TableEntry::Table(entry.arm64_page_frame()),
    }
}

/// The mapping descriptor's own permissions: Windows sets `TCR_EL1.HPD`, so
/// the table descriptors above keep their own bits in
/// APTable/PXNTable/UXNTable (a user page's level-0 entry has APTable\[0\]
/// set) and restrict nothing.
pub fn mapping_permissions(path: &[PageTableEntry], va: VirtAddr) -> MappingPermissions {
    let leaf = path.last().copied().unwrap_or(PageTableEntry(0));
    MappingPermissions {
        user: leaf.arm64_is_user(),
        nx: if is_kernel_address(va) {
            leaf.arm64_is_pxn()
        } else {
            leaf.arm64_is_uxn()
        },
        uxn: leaf.arm64_is_uxn(),
    }
}

pub fn entry_attributes(
    entry: PageTableEntry,
    level: PageTableLevel,
    address: VirtAddr,
) -> PteAttributes {
    let bit = |n: u32| entry.0 & (1 << n) != 0;
    let upper_level = matches!(level, PageTableLevel::Ppe | PageTableLevel::Pde);
    let block = upper_level && entry.arm64_is_block();
    // A block or page descriptor maps; a table descriptor's permission bits
    // are Windows' own (it sets `TCR_EL1.HPD`), so it restricts nothing
    // below it.
    let table = level != PageTableLevel::Pte && !block;
    let kernel = is_kernel_address(address);
    let (writable, user, nx) = if table {
        (true, !kernel, false)
    } else {
        (
            entry.arm64_is_writable(),
            entry.arm64_is_user(),
            if kernel {
                entry.arm64_is_pxn()
            } else {
                entry.arm64_is_uxn()
            },
        )
    };
    // At the leaf only 0b11 is valid.
    let present = if level == PageTableLevel::Pte {
        entry.0 & 0b11 == 0b11
    } else {
        entry.arm64_is_valid()
    };
    // A mapping is global with nG (bit 11) clear, accessed with AF (bit 10)
    // set, and written once writable with DBM (bit 51) set. Table
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
        entry.arm64_page_frame() >> 12,
        marks,
    )
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
            decode_entry(1, PageTableEntry(0x4000_0000 | NT | 0b01)),
            TableEntry::Leaf(0x4000_0000)
        );
        assert_eq!(
            decode_entry(2, PageTableEntry(0x0060_0000 | NT | 0b01)),
            TableEntry::Leaf(0x0060_0000)
        );
    }
}
