use crate::memory::{
    PAGE_SHIFT, PDE_SHIFT, PDPTE_SHIFT, PFN_MASK, PML4E_SHIFT, PT_INDEX_MASK, PTE_SHIFT,
};
use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};
use zerocopy::{FromBytes, Immutable, IntoBytes};

#[derive(
    Default,
    Clone,
    Copy,
    FromBytes,
    IntoBytes,
    Immutable,
    Debug,
    PartialEq,
    Eq,
    Hash,
    derive_more::From,
    derive_more::Into,
    derive_more::BitAnd,
    derive_more::BitOr,
    derive_more::FromStr,
    derive_more::Constructor,
    PartialOrd,
)]
#[repr(transparent)]
pub struct VirtAddr(pub u64);

// Address arithmetic wraps, like pointer arithmetic: an expression the user
// typed or a link a corrupt guest list handed us must produce a (bogus)
// address that then fails to read, never a panic.
impl Add for VirtAddr {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        VirtAddr(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for VirtAddr {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        VirtAddr(self.0.wrapping_sub(rhs.0))
    }
}

impl AddAssign for VirtAddr {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for VirtAddr {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl From<u32> for VirtAddr {
    fn from(value: u32) -> Self {
        VirtAddr::from_u64(value as u64)
    }
}

impl AddAssign<u64> for VirtAddr {
    fn add_assign(&mut self, rhs: u64) {
        *self += VirtAddr(rhs);
    }
}

impl SubAssign<u64> for VirtAddr {
    fn sub_assign(&mut self, rhs: u64) {
        *self -= VirtAddr(rhs);
    }
}

impl Add<u64> for VirtAddr {
    type Output = Self;

    fn add(self, rhs: u64) -> Self::Output {
        self + VirtAddr(rhs)
    }
}

impl Sub<u64> for VirtAddr {
    type Output = Self;

    fn sub(self, rhs: u64) -> Self::Output {
        self - VirtAddr(rhs)
    }
}

impl Add<u32> for VirtAddr {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        self + VirtAddr::from(rhs)
    }
}

impl Sub<u32> for VirtAddr {
    type Output = Self;

    fn sub(self, rhs: u32) -> Self::Output {
        self - VirtAddr::from(rhs)
    }
}

pub type PhysAddr = u64;

pub type Dtb = PhysAddr;

/// Where a kernel image is: its page-table root, base, and architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelLocation {
    pub dtb: Dtb,
    pub base: VirtAddr,
    pub arch: Arch,
}

/// Guest CPU architecture. Determines page-table descriptor interpretation and
/// register-file layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Arch {
    #[default]
    Amd64,
    Arm64,
}

impl Arch {
    pub fn label(self) -> &'static str {
        match self {
            Self::Amd64 => "AMD64",
            Self::Arm64 => "ARM64",
        }
    }

    /// Register holding the current address space's page-table base.
    pub const fn dtb_register(self) -> &'static str {
        match self {
            Self::Amd64 => "cr3",
            Self::Arm64 => "ttbr0",
        }
    }

    /// Bits of the DTB register that select the page-table base frame (PCID,
    /// ASID, and reserved/canonical bits masked out), for comparing address
    /// spaces.
    pub const fn dtb_page_mask(self) -> u64 {
        match self {
            Self::Amd64 => 0x000F_FFFF_FFFF_F000,
            Self::Arm64 => 0x0000_FFFF_FFFF_F000,
        }
    }

    pub fn from_machine_type(machine: u16) -> Option<Self> {
        match machine {
            0x8664 => Some(Self::Amd64),
            0xaa64 => Some(Self::Arm64),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct PageTableEntry(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageTableLevel {
    Pxe,
    Ppe,
    Pde,
    Pte,
}

impl VirtAddr {
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    pub const fn construct(
        pml4_index: usize,
        pdpt_index: usize,
        pd_index: usize,
        pt_index: usize,
    ) -> Self {
        let mut addr = ((pml4_index << PML4E_SHIFT)
            | (pdpt_index << PDPTE_SHIFT)
            | (pd_index << PDE_SHIFT)
            | (pt_index << PTE_SHIFT)) as u64;

        if pml4_index >= 256 {
            addr |= 0xffff_0000_0000_0000;
        }

        Self(addr)
    }

    pub const fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub const fn huge_page_offset(self) -> u64 {
        self.0 & !(!0u64 << 30)
    }

    pub const fn large_page_offset(self) -> u64 {
        self.0 & !(!0u64 << 21)
    }

    pub const fn pml4_index(self) -> usize {
        ((self.0 >> PML4E_SHIFT) & PT_INDEX_MASK) as usize
    }

    pub const fn pdpt_index(self) -> usize {
        ((self.0 >> PDPTE_SHIFT) & PT_INDEX_MASK) as usize
    }

    pub const fn pd_index(self) -> usize {
        ((self.0 >> PDE_SHIFT) & PT_INDEX_MASK) as usize
    }

    pub const fn pt_index(self) -> usize {
        ((self.0 >> PTE_SHIFT) & PT_INDEX_MASK) as usize
    }

    pub const fn page_offset(self) -> u64 {
        self.0 & !(!0 << PAGE_SHIFT)
    }
}

impl PageTableEntry {
    pub const fn is_present(self) -> bool {
        self.0 & 1 != 0
    }

    pub const fn is_large_page(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// A Windows transition PTE: the page is still in physical memory, on the
    /// standby or modified list, but the hardware valid bit is clear so the
    /// next access faults and the kernel can re-attach it.
    ///
    /// The PFN field is a real page frame, which is what separates this from
    /// the other invalid `MMPTE_SOFTWARE` forms: a prototype PTE (bit 10)
    /// stores a pointer to a prototype entry, and a page-file PTE stores an
    /// offset. Reading either as a frame would return unrelated memory, so
    /// both must be excluded.
    pub const fn is_transition(self) -> bool {
        !self.is_present() && self.0 & (1 << 11) != 0 && self.0 & (1 << 10) == 0
    }

    pub const fn page_frame(self) -> u64 {
        self.0 & PFN_MASK
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

    pub const fn pfn(self) -> u64 {
        self.page_frame() >> 12
    }

    pub fn flags(self) -> String {
        // Without a level, render bit 7 as LargePage.
        self.format_flags(true)
    }

    /// Format flags using the WinDbg !pte interpretation for a specific
    /// level.  Bit 7 is LargePage only on PPE/PDE entries; on a leaf PTE it is
    /// the PAT bit and is intentionally not rendered as `L`.
    pub fn flags_for_level(self, level: PageTableLevel) -> String {
        self.format_flags(matches!(level, PageTableLevel::Ppe | PageTableLevel::Pde))
    }

    fn format_flags(self, large_page_level: bool) -> String {
        format!(
            "{}{}{}{}{}{}{}{}{}{}{}",
            if self.0 & (1 << 9) != 0 { 'C' } else { '-' }, // CopyOnWrite
            if self.0 & (1 << 8) != 0 { 'G' } else { '-' }, // Global
            if large_page_level && self.0 & (1 << 7) != 0 {
                'L'
            } else {
                '-'
            }, // LargePage (PAT on leaf PTEs)
            if self.0 & (1 << 6) != 0 { 'D' } else { '-' }, // Dirty
            if self.0 & (1 << 5) != 0 { 'A' } else { '-' }, // Accessed
            if self.0 & (1 << 4) != 0 { 'N' } else { '-' }, // CacheDisable
            if self.0 & (1 << 3) != 0 { 'T' } else { '-' }, // WriteThrough
            if self.0 & (1 << 2) != 0 { 'U' } else { 'K' }, // Owner (User/Kernel)
            if self.is_writable() { 'W' } else { 'R' },
            if self.0 & (1 << 63) != 0 { '-' } else { 'E' }, // NoExecute (inverted)
            if self.0 & 1 != 0 { 'V' } else { '-' },         // Valid
        )
    }

    // --- AArch64 stage-1 descriptor interpretation (4 KiB granule) ---
    //
    // bits[1:0]: 0b00 invalid, 0b01 block (L0-L2), 0b11 table (L0-L2) /
    // page (L3). Leaf descriptors carry AP[2:1], PXN, and UXN; table
    // descriptors carry the hierarchical APTable, PXNTable, and UXNTable
    // restrictions. Output address bits [47:12] support a 48-bit PA space.
    pub const fn arm64_is_valid(self) -> bool {
        // 0b01 block, 0b11 table/page; 0b00 invalid, 0b10 reserved.
        self.0 & 0b01 != 0
    }

    pub const fn arm64_is_block(self) -> bool {
        self.0 & 0b11 == 0b01
    }

    /// Output address bits [47:12] (48-bit PA space), kept in place.
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

    pub const fn arm64_is_user(self) -> bool {
        self.0 & (1 << 7) != 0
    }

    /// Privileged execute-never (PXN, bit 53) on a block/page descriptor.
    pub const fn arm64_is_pxn(self) -> bool {
        self.0 & (1 << 53) != 0
    }

    /// Unprivileged execute-never (UXN, bit 54) on a block/page descriptor.
    pub const fn arm64_is_uxn(self) -> bool {
        self.0 & (1 << 54) != 0
    }

    pub const fn arm64_is_writable(self) -> bool {
        self.0 & (1 << 6) == 0
    }

    /// APTable[0] (bit 61) forbids EL0 access through a child table.
    pub const fn arm64_table_allows_user(self) -> bool {
        self.0 & (1 << 61) == 0
    }

    /// APTable[1] (bit 62) makes child mappings read-only.
    pub const fn arm64_table_allows_write(self) -> bool {
        self.0 & (1 << 62) == 0
    }

    pub const fn arm64_table_is_pxn(self) -> bool {
        self.0 & (1 << 59) != 0
    }

    pub const fn arm64_table_is_uxn(self) -> bool {
        self.0 & (1 << 60) != 0
    }
}

/// Plain forwarding to the inner value's formatting; no styling. Domain types
/// stay presentation-free; all address coloring lives in the `ui` module
/// (`ui::addr`), so a `VirtAddr` formatted with `{:#x}` is just plain hex
macro_rules! impl_plain_fmt {
    ($t:ty, $($trait:path),+) => {
        $(
            impl $trait for $t {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    <_ as $trait>::fmt(&self.0, f)
                }
            }
        )*
    };
}

impl_plain_fmt!(
    VirtAddr,
    fmt::Display,
    fmt::LowerHex,
    fmt::UpperHex,
    fmt::Binary
);
