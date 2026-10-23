//! Virtual memory: how an architecture's address space divides and how its
//! page tables translate, behind [`Paging`]. The base's one table walk
//! asks it; each architecture's module implements it over its own entry
//! format.

use crate::base::types::{PageTableEntry, PageTableLevel, PhysAddr, PteAttributes, VirtAddr};

pub trait Paging: Sync {
    /// Whether `va` lies in the kernel half of the address space.
    fn is_kernel_address(&self, va: VirtAddr) -> bool;

    /// The end of the user half and the start of the kernel half of the
    /// canonical address space: the addresses between them no page table
    /// maps.
    fn canonical_halves(&self) -> (u64, u64);

    /// Whether `value` could be a pointer, by its upper bits.
    fn could_be_pointer(&self, value: u64) -> bool;

    /// Where Windows' system address space starts (`MmSystemRangeStart`):
    /// a kernel pointer lies at or above it.
    fn system_range_start(&self) -> u64;

    /// Whether kernel addresses translate through a root of their own
    /// (AArch64's TTBR1) rather than through each address space's.
    fn separate_kernel_root(&self) -> bool;

    /// The levels a walk reads, root first. Each is a table of 512
    /// eight-byte entries indexed by the address bits from
    /// [`PageTableLevel::shift`].
    fn levels(&self) -> &'static [PageTableLevel];

    /// What `entry` means at `level`. At the last level an entry maps a
    /// page or nothing.
    fn decode_entry(&self, level: PageTableLevel, entry: PageTableEntry) -> TableEntry;

    /// The access the mapping of `va` grants, from the entries its walk
    /// read, root first and the mapping entry last.
    fn mapping_permissions(&self, path: &[PageTableEntry], va: VirtAddr) -> MappingPermissions;

    /// `entry` decoded at `level` for `!pte`, on the walk of `address`.
    fn entry_attributes(
        &self,
        entry: PageTableEntry,
        level: PageTableLevel,
        address: VirtAddr,
    ) -> PteAttributes;
}

/// What a page-table entry means at its level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableEntry {
    /// It maps nothing.
    Absent,
    /// It points at the next level's table.
    Table(PhysAddr),
    /// It maps the page or block starting at this frame.
    Leaf(PhysAddr),
}

/// The access a mapping grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingPermissions {
    pub user: bool,
    /// Execute-never for the address's half: AMD64 NX, AArch64 PXN in the
    /// kernel half and UXN in the user half.
    pub nx: bool,
    /// AArch64 UXN; never set on AMD64.
    pub uxn: bool,
}
