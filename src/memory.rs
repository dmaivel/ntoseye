use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::types::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// x64 page-table entry physical-address field: bits 51:12 (MAXPHYADDR = 52).
pub const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;
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

/// Page translations remembered across [`AddressSpace`] instances, which are
/// created per read, for as long as the target's page tables cannot change.
/// Owned by a backend that knows when that is: a KD target clears it on
/// every resume and write.
///
/// It also carries the target's halt epoch: a counter the owning backend
/// advances on every resume, so guest-derived lists (processes, modules,
/// drivers) memoized during one halt are dropped once the target has run.
/// Writes clear translations but do not advance the epoch: a debugger poke
/// (breakpoint install) cannot relink kernel lists.
#[derive(Default)]
pub struct TranslationCache {
    pages: Mutex<HashMap<(Dtb, u64), Translation>>,
    halt_epoch: AtomicU64,
}

impl TranslationCache {
    fn pages(&self) -> MutexGuard<'_, HashMap<(Dtb, u64), Translation>> {
        self.pages.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn get(&self, key: (Dtb, u64)) -> Option<Translation> {
        self.pages().get(&key).copied()
    }

    fn insert(&self, key: (Dtb, u64), translation: Translation) {
        self.pages().insert(key, translation);
    }

    pub fn clear(&self) {
        self.pages().clear();
    }

    /// Drop translations and start a new halt epoch; called when the target
    /// resumes.
    pub fn resume(&self) {
        self.clear();
        self.halt_epoch.fetch_add(1, Ordering::Relaxed);
    }

    pub fn halt_epoch(&self) -> u64 {
        self.halt_epoch.load(Ordering::Relaxed)
    }
}

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

#[derive(Clone, Copy)]
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
    /// The same mapping relocated to `va` within its page.
    fn at_offset(mut self, va: VirtAddr) -> Self {
        self.address = (self.address & !(PAGE_SIZE as u64 - 1)) | va.page_offset();
        self
    }

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

    /// Page-table root that maps `va`: AArch64 selects TTBR1 for the kernel
    /// half by bit 55; one AMD64 CR3 covers both halves.
    fn root_for(&self, va: VirtAddr) -> Dtb {
        if self.arm64 && va.0 & (1 << 55) != 0 {
            self.kernel_dtb.unwrap_or(self.dtb)
        } else {
            self.dtb
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
        let root = self.root_for(va);

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
        let Some(cache) = self.backend.translation_cache() else {
            return self.walk(va);
        };
        let key = (self.root_for(va), va.0 >> PAGE_SHIFT);
        if let Some(translation) = cache.get(key) {
            return Ok(Some(translation.at_offset(va)));
        }
        let translation = self.walk(va)?;
        if let Some(translation) = translation {
            cache.insert(key, translation);
        }
        Ok(translation)
    }

    fn walk(&self, va: VirtAddr) -> Result<Option<Translation>> {
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
        if let Some(result) = self
            .backend
            .read_virtual_direct(addr, self.root_for(addr), buf)
        {
            return result;
        }
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

    struct CachingPhysMem {
        inner: FakePhysMem,
        reads: std::cell::Cell<usize>,
        cache: TranslationCache,
    }

    impl MemoryOps<PhysAddr> for CachingPhysMem {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read_bytes(addr, buf)
        }

        fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
            self.inner.write_bytes(addr, buf)
        }

        fn translation_cache(&self) -> Option<&TranslationCache> {
            Some(&self.cache)
        }
    }

    /// With a cache, a second read in an already translated page costs one
    /// backend read, not five, across separate address-space instances; the
    /// cached mapping is relocated to the new offset within the page.
    #[test]
    fn translation_cache_skips_repeat_walks_across_instances() {
        let mut data = vec![0u8; 0x6000];
        let va = VirtAddr(0x7fff_1234_5000);
        let root = 0x1000usize;
        let mut entry = |table: usize, index: usize, next: u64| {
            data[table + index * 8..table + index * 8 + 8]
                .copy_from_slice(&(next | 0b111).to_le_bytes());
        };
        entry(root, va.pml4_index(), 0x2000);
        entry(0x2000, va.pdpt_index(), 0x3000);
        entry(0x3000, va.pd_index(), 0x4000);
        entry(0x4000, va.pt_index(), 0x5000);
        data[0x5000..0x5008].copy_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        data[0x5010..0x5018].copy_from_slice(&0x5555_6666_7777_8888u64.to_le_bytes());
        let mem = CachingPhysMem {
            inner: FakePhysMem { data },
            reads: std::cell::Cell::new(0),
            cache: TranslationCache::default(),
        };

        let first: u64 = AddressSpace::new(&mem, root as u64).read(va).unwrap();
        assert_eq!(first, 0x1111_2222_3333_4444);
        assert_eq!(mem.reads.get(), 5);

        let second: u64 = AddressSpace::new(&mem, root as u64)
            .read(VirtAddr(va.0 + 0x10))
            .unwrap();
        assert_eq!(second, 0x5555_6666_7777_8888);
        assert_eq!(mem.reads.get(), 6);

        mem.cache.clear();
        let _: u64 = AddressSpace::new(&mem, root as u64).read(va).unwrap();
        assert_eq!(mem.reads.get(), 11);
    }
}
