use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::types::*;

// PageFrameNumber
pub const PFN_MASK: u64 = (!0xFu64 << 8) & 0xFFFFFFFFFu64;
pub const PAGE_SIZE: usize = 0x1000; // 4KiB
pub const PAGE_SHIFT: u32 = 12;
pub const PTE_SHIFT: u8 = 12;
pub const PDE_SHIFT: u8 = 21;
pub const PDPTE_SHIFT: u8 = 30;
pub const PML4E_SHIFT: u8 = 39;
pub const PT_INDEX_MASK: u64 = 0x1FF;

/// Sentinel DTB: `AddressSpace` skips page-table translation and treats
/// virtual addresses as physical. Used by triage dumps, which only contain
/// captured virtual memory regions.
pub const DTB_IDENTITY: Dtb = u64::MAX;

// 'a = lifetime of the borrow of the backend
//  B = any type that implements phys mem
pub struct AddressSpace<'a, B: MemoryOps<PhysAddr>> {
    backend: &'a B,
    dtb: Dtb,
    /// AArch64 TTBR1 (kernel-space root). Kernel VAs (bit 55 set) walk this;
    /// `dtb` is the TTBR0/process root for the user half. Ignored on AMD64,
    /// where one CR3 covers both halves.
    kernel_dtb: Option<Dtb>,
    arm64: bool,
}

pub struct Translation {
    pub address: PhysAddr,
    pub large: bool,
    pub writable: bool,
    pub user: bool,
    /// Effective execute-never for the selected address-space half: AMD64 NX,
    /// AArch64 PXN for TTBR1 addresses, or AArch64 UXN for TTBR0 addresses.
    pub nx: bool,
    /// Effective AArch64 UXN, including ancestor UXNTable restrictions.
    /// Always `false` on AMD64.
    pub uxn: bool,
}

impl Translation {
    pub const fn new_huge(pml4e: PageTableEntry, pdpte: PageTableEntry, va: VirtAddr) -> Self {
        Self {
            address: pdpte.page_frame() + va.huge_page_offset(),
            large: true,
            writable: pml4e.is_writable() && pdpte.is_writable(),
            user: pml4e.is_user() && pdpte.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx(),
            uxn: false,
        }
    }

    pub const fn new_large(
        pml4e: PageTableEntry,
        pdpte: PageTableEntry,
        pde: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        Self {
            address: pde.page_frame() + va.large_page_offset(),
            large: true,
            writable: pml4e.is_writable() && pdpte.is_writable() && pde.is_writable(),
            user: pml4e.is_user() && pdpte.is_user() && pde.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx() || pde.is_nx(),
            uxn: false,
        }
    }

    pub const fn new(
        pml4e: PageTableEntry,
        pdpte: PageTableEntry,
        pde: PageTableEntry,
        pte: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        Self {
            address: pte.page_frame() + va.page_offset(),
            large: false,
            writable: pml4e.is_writable()
                && pdpte.is_writable()
                && pde.is_writable()
                && pte.is_writable(),
            user: pml4e.is_user() && pdpte.is_user() && pde.is_user() && pte.is_user(),
            nx: pml4e.is_nx() || pdpte.is_nx() || pde.is_nx() || pte.is_nx(),
            uxn: false,
        }
    }

    /// AArch64 1 GiB block descriptor at level 1.
    pub const fn arm64_huge(l0: PageTableEntry, l1: PageTableEntry, va: VirtAddr) -> Self {
        let pxn = l0.arm64_table_is_pxn() || l1.arm64_is_pxn();
        let uxn = l0.arm64_table_is_uxn() || l1.arm64_is_uxn();
        Self {
            address: l1.arm64_page_frame() + va.huge_page_offset(),
            large: true,
            writable: l0.arm64_table_allows_write() && l1.arm64_is_writable(),
            user: l0.arm64_table_allows_user() && l1.arm64_is_user(),
            nx: if va.0 & (1 << 55) != 0 { pxn } else { uxn },
            uxn,
        }
    }

    /// AArch64 2 MiB block descriptor at level 2.
    pub const fn arm64_large(
        l0: PageTableEntry,
        l1: PageTableEntry,
        l2: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        let pxn = l0.arm64_table_is_pxn() || l1.arm64_table_is_pxn() || l2.arm64_is_pxn();
        let uxn = l0.arm64_table_is_uxn() || l1.arm64_table_is_uxn() || l2.arm64_is_uxn();
        Self {
            address: l2.arm64_page_frame() + va.large_page_offset(),
            large: true,
            writable: l0.arm64_table_allows_write()
                && l1.arm64_table_allows_write()
                && l2.arm64_is_writable(),
            user: l0.arm64_table_allows_user()
                && l1.arm64_table_allows_user()
                && l2.arm64_is_user(),
            nx: if va.0 & (1 << 55) != 0 { pxn } else { uxn },
            uxn,
        }
    }

    /// AArch64 4 KiB page descriptor at level 3.
    pub const fn arm64_page(
        l0: PageTableEntry,
        l1: PageTableEntry,
        l2: PageTableEntry,
        l3: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        let pxn = l0.arm64_table_is_pxn()
            || l1.arm64_table_is_pxn()
            || l2.arm64_table_is_pxn()
            || l3.arm64_is_pxn();
        let uxn = l0.arm64_table_is_uxn()
            || l1.arm64_table_is_uxn()
            || l2.arm64_table_is_uxn()
            || l3.arm64_is_uxn();
        Self {
            address: l3.arm64_page_frame() + va.page_offset(),
            large: false,
            writable: l0.arm64_table_allows_write()
                && l1.arm64_table_allows_write()
                && l2.arm64_table_allows_write()
                && l3.arm64_is_writable(),
            user: l0.arm64_table_allows_user()
                && l1.arm64_table_allows_user()
                && l2.arm64_table_allows_user()
                && l3.arm64_is_user(),
            nx: if va.0 & (1 << 55) != 0 { pxn } else { uxn },
            uxn,
        }
    }
}

impl<'a, B: MemoryOps<PhysAddr>> AddressSpace<'a, B> {
    pub fn new(backend: &'a B, dtb: Dtb) -> Self {
        Self {
            backend,
            dtb,
            kernel_dtb: None,
            arm64: false,
        }
    }

    /// AArch64 address space with separate TTBR0 (user) and TTBR1 (kernel)
    /// roots; the walk selects the root from the VA's bit 55.
    pub fn new_arm64(backend: &'a B, ttbr0: Dtb, ttbr1: Dtb) -> Self {
        Self {
            backend,
            dtb: ttbr0,
            kernel_dtb: Some(ttbr1),
            arm64: true,
        }
    }

    fn read_pt_entry(&self, table_base: PhysAddr, index: usize) -> Result<Option<PageTableEntry>> {
        match self.backend.read(table_base + 8 * index as u64) {
            Ok(entry) => Ok(Some(entry)),
            Err(Error::BadPhysicalAddress(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn virt_to_phys_arm64(&self, va: VirtAddr) -> Result<Option<Translation>> {
        if self.dtb == DTB_IDENTITY {
            return Ok(Some(Translation {
                address: va.0,
                large: false,
                writable: false,
                user: false,
                nx: false,
                uxn: false,
            }));
        }

        // AArch64: bit 55 selects TTBR1 (kernel) vs TTBR0 (user).
        let root = if va.0 & (1 << 55) != 0 {
            self.kernel_dtb.unwrap_or(self.dtb)
        } else {
            self.dtb
        };

        // Level 0 (index bits 47:39 — same 9-bit index math as x64 PML4).
        let Some(l0) = self.read_pt_entry(root, va.pml4_index())? else {
            return Ok(None);
        };
        if !l0.arm64_is_valid() || l0.arm64_is_block() {
            // 512 GiB L0 blocks are not used by Windows; treat as unmapped.
            return Ok(None);
        }

        let Some(l1) = self.read_pt_entry(l0.arm64_page_frame(), va.pdpt_index())? else {
            return Ok(None);
        };
        if !l1.arm64_is_valid() {
            return Ok(None);
        }
        if l1.arm64_is_block() {
            return Ok(Some(Translation::arm64_huge(l0, l1, va)));
        }

        let Some(l2) = self.read_pt_entry(l1.arm64_page_frame(), va.pd_index())? else {
            return Ok(None);
        };
        if !l2.arm64_is_valid() {
            return Ok(None);
        }
        if l2.arm64_is_block() {
            return Ok(Some(Translation::arm64_large(l0, l1, l2, va)));
        }

        let Some(l3) = self.read_pt_entry(l2.arm64_page_frame(), va.pt_index())? else {
            return Ok(None);
        };
        // At L3 only 0b11 is a page descriptor; 0b01 is reserved.
        if l3.0 & 0b11 != 0b11 {
            return Ok(None);
        }
        Ok(Some(Translation::arm64_page(l0, l1, l2, l3, va)))
    }

    pub fn virt_to_phys(&self, va: VirtAddr) -> Result<Option<Translation>> {
        if self.arm64 {
            return self.virt_to_phys_arm64(va);
        }
        if self.dtb == DTB_IDENTITY {
            return Ok(Some(Translation {
                address: va.0,
                large: false,
                writable: false,
                user: false,
                nx: false,
                uxn: false,
            }));
        }

        let Some(pml4e) = self.read_pt_entry(self.dtb, va.pml4_index())? else {
            return Ok(None);
        };

        if !pml4e.is_present() {
            return Ok(None);
        }

        let Some(pdpte) = self.read_pt_entry(pml4e.page_frame(), va.pdpt_index())? else {
            return Ok(None);
        };

        if !pdpte.is_present() {
            return Ok(None);
        }

        if pdpte.is_large_page() {
            return Ok(Some(Translation::new_huge(pml4e, pdpte, va)));
        }

        let Some(pde) = self.read_pt_entry(pdpte.page_frame(), va.pd_index())? else {
            return Ok(None);
        };

        if !pde.is_present() {
            return Ok(None);
        }

        if pde.is_large_page() {
            return Ok(Some(Translation::new_large(pml4e, pdpte, pde, va)));
        }

        let Some(pte) = self.read_pt_entry(pde.page_frame(), va.pt_index())? else {
            return Ok(None);
        };

        if !pte.is_present() {
            return Ok(None);
        }

        Ok(Some(Translation::new(pml4e, pdpte, pde, pte, va)))
    }
}

impl<'a, B: MemoryOps<PhysAddr>> MemoryOps<VirtAddr> for AddressSpace<'a, B> {
    fn read_bytes(&self, addr: VirtAddr, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;

        while offset < buf.len() {
            let curr_vaddr = addr + offset as u64;

            let translation = match self.virt_to_phys(curr_vaddr)? {
                Some(translation) => translation,
                None if offset > 0 => return Err(Error::PartialRead(offset)),
                None => return Err(Error::BadVirtualAddress(curr_vaddr)),
            };

            let bytes_available = PAGE_SIZE - curr_vaddr.page_offset() as usize;
            let chunk_size = (buf.len() - offset).min(bytes_available);

            self.backend
                .read_bytes(translation.address, &mut buf[offset..offset + chunk_size])?;
            offset += chunk_size;
        }

        Ok(())
    }

    fn write_bytes(&self, addr: VirtAddr, buf: &[u8]) -> Result<()> {
        let mut offset = 0;

        while offset < buf.len() {
            let curr_vaddr = addr + offset as u64;

            let translation = match self.virt_to_phys(curr_vaddr)? {
                Some(translation) => translation,
                None => {
                    if offset > 0 {
                        return Err(Error::PartialWrite(offset));
                    } else {
                        return Err(Error::BadVirtualAddress(curr_vaddr));
                    }
                }
            };

            let bytes_available = PAGE_SIZE - curr_vaddr.page_offset() as usize;
            let chunk_size = (buf.len() - offset).min(bytes_available);

            self.backend
                .write_bytes(translation.address, &buf[offset..offset + chunk_size])?;
            offset += chunk_size;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryOps;

    struct FakePhysMem {
        data: Vec<u8>,
    }

    impl MemoryOps<PhysAddr> for FakePhysMem {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            let start = addr as usize;
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(Error::BadPhysicalAddress(addr));
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write_bytes(&self, _addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            Err(Error::BadPhysicalAddress(0))
        }
    }

    #[test]
    fn identity_dtb_skips_page_table_walk() {
        let mut data = vec![0u8; 0x2000];
        // Plant recognizable bytes at VA/PA 0x1000
        data[0x1000..0x1008].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_le_bytes());
        let mem = FakePhysMem { data };
        let space = AddressSpace::new(&mem, DTB_IDENTITY);

        let mut buf = [0u8; 8];
        space.read_bytes(VirtAddr(0x1000), &mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0xDEADBEEFCAFEBABE);
    }

    #[test]
    fn identity_dtb_cross_boundary_read() {
        let mut data = vec![0u8; 0x3000];
        // Span across a 4K boundary: fill 0xFFF..0x1001
        for (i, byte) in data[0xFF0..0x1010].iter_mut().enumerate() {
            *byte = ((0xFF0 + i) & 0xFF) as u8;
        }
        let mem = FakePhysMem { data };
        let space = AddressSpace::new(&mem, DTB_IDENTITY);

        let mut buf = [0u8; 0x20];
        space.read_bytes(VirtAddr(0xFF0), &mut buf).unwrap();
        assert_eq!(buf[0], 0xF0);
        assert_eq!(buf[0x10], 0x00); // 0x1000 & 0xFF
        assert_eq!(buf[0x1F], 0x0F); // 0x100F & 0xFF
    }

    #[test]
    fn arm64_kernel_walk_uses_upper_half_of_combined_root_page() {
        let mut data = vec![0u8; 0x6000];
        let kernel_va = VirtAddr(0xffff_8000_0000_0000);
        let root_page = 0x1000u64;
        data[root_page as usize + kernel_va.pml4_index() * 8
            ..root_page as usize + kernel_va.pml4_index() * 8 + 8]
            .copy_from_slice(&(0x2000u64 | 0b11).to_le_bytes());
        data[0x2000..0x2008].copy_from_slice(&(0x3000u64 | 0b11).to_le_bytes());
        data[0x3000..0x3008].copy_from_slice(&(0x4000u64 | 0b11).to_le_bytes());
        data[0x4000..0x4008].copy_from_slice(&(0x5000u64 | 0b11).to_le_bytes());
        data[0x5000..0x5008].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        let mem = FakePhysMem { data };
        let space = AddressSpace::new_arm64(&mem, root_page, root_page);

        let value: u64 = space.read(kernel_va).unwrap();

        assert_eq!(value, 0xDEAD_BEEF_CAFE_BABE);
    }
    #[test]
    fn arm64_translation_applies_table_attribute_restrictions() {
        let l0 = PageTableEntry(0b11 | (1 << 61) | (1 << 62) | (1 << 60));
        let table = PageTableEntry(0b11);
        let page = PageTableEntry(0b11 | (1 << 7) | 0x1234_5000);

        let translation = Translation::arm64_page(l0, table, table, page, VirtAddr(0x2000));

        assert_eq!(translation.address, 0x1234_5000);
        assert!(!translation.user);
        assert!(!translation.writable);
        assert!(translation.uxn);
        assert!(translation.nx);
    }

    #[test]
    fn arm64_translation_uses_pxn_for_kernel_addresses() {
        let l0 = PageTableEntry(0b11 | (1 << 59));
        let table = PageTableEntry(0b11);
        let page = PageTableEntry(0b11 | 0x1234_5000);

        let translation =
            Translation::arm64_page(l0, table, table, page, VirtAddr(0xffff_f800_0000_2000));

        assert!(translation.nx);
        assert!(!translation.uxn);
    }
}
