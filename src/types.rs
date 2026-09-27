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

/// The instruction set a stretch of code is in. It need not be the
/// processor's: ARM64 Windows runs x86 programs under WOW64 and x64 code
/// inside ARM64EC processes by emulation, and an AMD64 processor runs a
/// WOW64 program's x86 code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeMachine {
    X86,
    Amd64,
    Arm64,
}

impl CodeMachine {
    /// The processor's own instruction set.
    pub const fn native(arch: Arch) -> Self {
        match arch {
            Arch::Amd64 => Self::Amd64,
            Arch::Arm64 => Self::Arm64,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::Amd64 => "AMD64",
            Self::Arm64 => "ARM64",
        }
    }

    /// Longest encoded instruction, which bounds a lookbehind window.
    pub const fn max_instruction_bytes(self) -> usize {
        match self {
            Self::X86 | Self::Amd64 => 15,
            Self::Arm64 => 4,
        }
    }
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

    /// Bytes in the software breakpoint instruction (x86 `int3`, AArch64
    /// `brk #0xF000`): how far the program counter must move to step past
    /// one, and the kind an RSP `Z0` packet names.
    pub const fn breakpoint_size(self) -> u8 {
        match self {
            Self::Amd64 => 1,
            Self::Arm64 => 4,
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

/// A page-table entry decoded at its level; see
/// [`PageTableEntry::attributes`]. For an entry pointing at a lower table,
/// `writable`, `user`, and `nx` are the restrictions it places on what lies
/// below.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PteAttributes {
    pub present: bool,
    pub large_page: bool,
    pub writable: bool,
    pub user: bool,
    pub nx: bool,
    pub pfn: u64,
    pub flags: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageTableLevel {
    Pxe,
    Ppe,
    Pde,
    Pte,
}

impl PageTableLevel {
    /// WinDbg's name for an entry at this level.
    pub fn name(self) -> &'static str {
        match self {
            Self::Pxe => "PXE",
            Self::Ppe => "PPE",
            Self::Pde => "PDE",
            Self::Pte => "PTE",
        }
    }
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

    /// This non-present entry with Windows' L1TF swizzle undone: an entry
    /// whose `SwizzleBit` (bit 4) is clear has `mask` set to point it at no
    /// real memory, and its frame is the one with `mask` cleared.
    pub const fn unswizzled(self, mask: u64) -> Self {
        if self.0 & (1 << 4) == 0 {
            Self(self.0 & !mask)
        } else {
            self
        }
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

    /// A Windows prototype PTE (`MMPTE_PROTOTYPE`): the page belongs to a
    /// section, and the section's own PTE for it, shared by every process
    /// mapping it, says where the page is.
    pub const fn is_prototype(self) -> bool {
        !self.is_present() && self.0 & (1 << 10) != 0
    }

    /// The kernel address of the section PTE a prototype PTE points at
    /// (`ProtoAddress`, bits 63:16 sign-extended), or `None` for
    /// `MI_PTE_LOOKUP_NEEDED`, which leaves it to the VAD mapping the page.
    pub const fn prototype_address(self) -> Option<VirtAddr> {
        if self.0 >> 32 == 0xFFFF_FFFF {
            return None;
        }
        Some(VirtAddr(((self.0 as i64) >> 16) as u64))
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

    /// What this entry means at `level` of `arch`'s tables, for an entry
    /// on the walk of `address`. The flags are WinDbg's `!pte` string
    /// (`CGLDANTUWEV`, `-` for each clear bit, `K`/`R` for kernel and
    /// read-only), filled from each architecture's own bits.
    pub fn attributes(self, arch: Arch, level: PageTableLevel, address: VirtAddr) -> PteAttributes {
        let upper_level = matches!(level, PageTableLevel::Ppe | PageTableLevel::Pde);
        let bit = |n: u32| self.0 & (1 << n) != 0;
        let (present, large_page, writable, user, nx, pfn) = match arch {
            // Bit 7 is PS only above the leaf; in a PTE it is PAT.
            Arch::Amd64 => (
                self.is_present(),
                upper_level && self.is_large_page(),
                self.is_writable(),
                self.is_user(),
                self.is_nx(),
                self.pfn(),
            ),
            Arch::Arm64 => {
                let block = upper_level && self.arm64_is_block();
                // A block or page descriptor maps; a table descriptor's
                // permission bits are Windows' own (it sets
                // `TCR_EL1.HPD`), so it restricts nothing below it.
                let table = level != PageTableLevel::Pte && !block;
                let kernel = address.0 & (1 << 55) != 0;
                let (writable, user, nx) = if table {
                    (true, !kernel, false)
                } else {
                    (
                        self.arm64_is_writable(),
                        self.arm64_is_user(),
                        if kernel {
                            self.arm64_is_pxn()
                        } else {
                            self.arm64_is_uxn()
                        },
                    )
                };
                // At the leaf only 0b11 is valid.
                let present = if level == PageTableLevel::Pte {
                    self.0 & 0b11 == 0b11
                } else {
                    self.arm64_is_valid()
                };
                (
                    present,
                    block,
                    writable,
                    user,
                    nx,
                    self.arm64_page_frame() >> 12,
                )
            }
        };
        let (copy_on_write, global, dirty, accessed, cache_disable, write_through) = match arch {
            Arch::Amd64 => (bit(9), bit(8), bit(6), bit(5), bit(4), bit(3)),
            // A mapping is global with nG (bit 11) clear, accessed with AF
            // (bit 10) set, and written once writable with DBM (bit 51)
            // set. Table descriptors have none of these.
            Arch::Arm64 if level == PageTableLevel::Pte || large_page => {
                (false, !bit(11), bit(51) && writable, bit(10), false, false)
            }
            Arch::Arm64 => (false, false, false, false, false, false),
        };
        let flag = |set: bool, letter: char| if set { letter } else { '-' };
        let flags = [
            flag(copy_on_write, 'C'),
            flag(global, 'G'),
            flag(large_page, 'L'),
            flag(dirty, 'D'),
            flag(accessed, 'A'),
            flag(cache_disable, 'N'),
            flag(write_through, 'T'),
            if user { 'U' } else { 'K' },
            if writable { 'W' } else { 'R' },
            flag(!nx, 'E'),
            flag(present, 'V'),
        ]
        .into_iter()
        .collect();
        PteAttributes {
            present,
            large_page,
            writable,
            user,
            nx,
            pfn,
            flags,
        }
    }

    // --- AArch64 stage-1 descriptor interpretation (4 KiB granule) ---
    //
    // bits[1:0]: 0b00 invalid, 0b01 block (L0-L2), 0b11 table (L0-L2) /
    // page (L3). Block and page descriptors carry AP[2:1], PXN, and UXN.
    // Windows disables hierarchical permissions (`TCR_EL1.HPD`), so a table
    // descriptor's APTable/PXNTable/UXNTable bits restrict nothing. Output
    // address bits \[47:12\] support a 48-bit PA space.
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
