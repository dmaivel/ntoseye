use std::fmt;
use std::ops::{Add, AddAssign, Sub, SubAssign};

use crate::arch::Arch;
use ntoseye_macros::record;
use zerocopy::{FromBytes, Immutable, IntoBytes};

/// x64 page-table entry physical-address field: bits 51:12 (MAXPHYADDR = 52).
pub const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;
pub const PAGE_SHIFT: u32 = 12;
pub const PTE_SHIFT: u8 = 12;
pub const PDE_SHIFT: u8 = 21;
pub const PDPTE_SHIFT: u8 = 30;
pub const PML4E_SHIFT: u8 = 39;
pub const PT_INDEX_MASK: u64 = 0x1FF;

/// Upper bound on processor indexes; `KiProcessorBlock` is sized by
/// `MAXIMUM_PROCESSORS`.
pub const MAX_PROCESSORS: u16 = 2048;

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

/// An object whose keys are data, not a schema (registers a state may or may
/// not hold, fields a Windows build may or may not have), in order. In the
/// SDK a `Record`, whose attributes are its keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keyed<T>(pub Vec<(&'static str, T)>);

impl<T> FromIterator<(&'static str, T)> for Keyed<T> {
    fn from_iter<I: IntoIterator<Item = (&'static str, T)>>(fields: I) -> Self {
        Self(fields.into_iter().collect())
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

#[derive(Clone, Copy, FromBytes, IntoBytes, Immutable)]
pub struct PageTableEntry(pub u64);

/// A page-table entry decoded at its level; see
/// [`PageTableEntry::attributes`]. For an entry pointing at a lower table,
/// `writable`, `user`, and `nx` are the restrictions it places on what lies
/// below.
#[record]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PteAttributes {
    pub present: bool,
    /// Whether the entry maps a large page instead of pointing to a lower
    /// table.
    pub large_page: bool,
    pub writable: bool,
    pub user: bool,
    pub nx: bool,
    /// The frame the entry points at.
    #[record(hex)]
    pub pfn: u64,
    /// WinDbg's flag string for the entry.
    pub flags: String,
}

/// The bits of an entry WinDbg's `!pte` flag string shows beyond those
/// [`PteAttributes`] carries.
#[derive(Clone, Copy, Debug, Default)]
pub struct PteMarks {
    pub copy_on_write: bool,
    pub global: bool,
    pub dirty: bool,
    pub accessed: bool,
    pub cache_disable: bool,
    pub write_through: bool,
}

impl PteAttributes {
    /// The attributes with WinDbg's flag string (`CGLDANTUWEV`, `-` for each
    /// clear bit, `K`/`R` for kernel and read-only).
    pub fn new(
        present: bool,
        large_page: bool,
        writable: bool,
        user: bool,
        nx: bool,
        pfn: u64,
        marks: PteMarks,
    ) -> Self {
        let flag = |set: bool, letter: char| if set { letter } else { '-' };
        let flags = [
            flag(marks.copy_on_write, 'C'),
            flag(marks.global, 'G'),
            flag(large_page, 'L'),
            flag(marks.dirty, 'D'),
            flag(marks.accessed, 'A'),
            flag(marks.cache_disable, 'N'),
            flag(marks.write_through, 'T'),
            if user { 'U' } else { 'K' },
            if writable { 'W' } else { 'R' },
            flag(!nx, 'E'),
            flag(present, 'V'),
        ]
        .into_iter()
        .collect();
        Self {
            present,
            large_page,
            writable,
            user,
            nx,
            pfn,
            flags,
        }
    }
}

/// A page-table level, by WinDbg's name for its entries: `PXE`, `PPE`,
/// `PDE`, or `PTE`.
#[record]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PageTableLevel {
    #[record(label = "PXE")]
    Pxe,
    #[record(label = "PPE")]
    Ppe,
    #[record(label = "PDE")]
    Pde,
    #[record(label = "PTE")]
    Pte,
}

impl PageTableLevel {
    /// The levels a walk reads, root first.
    pub const ALL: [Self; 4] = [Self::Pxe, Self::Ppe, Self::Pde, Self::Pte];
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

    pub const fn pfn(self) -> u64 {
        self.page_frame() >> 12
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
