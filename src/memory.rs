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

/// Trace AArch64 page-table walk failures (`NTOSEYE_MEM_TRACE=1`): prints the
/// VA, the translation root used, and the descriptor chain up to the failing
/// level, so a live target's mapping can be debugged against the walker.
pub fn arm64_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("NTOSEYE_MEM_TRACE").is_some())
}

pub struct Translation {
    #[allow(dead_code)]
    pub address: PhysAddr,
    #[allow(dead_code)]
    pub large: bool,
    #[allow(dead_code)]
    pub writable: bool,
    #[allow(dead_code)]
    pub user: bool,
    /// Execute-never for the CPU privilege level that would actually run the
    /// page: x64 NX for AMD64; on AArch64, EL0-gating UXN (PXN is ignored for
    /// EL1 fetches via TTBR1, so it cannot decide kernel executability).
    pub nx: bool,
    /// AArch64 only: UXN (bit 54), the EL0 execute-never attribute of the
    /// leaf descriptor. `false` on AMD64.
    #[allow(dead_code)]
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
        Self {
            address: l1.arm64_page_frame() + va.huge_page_offset(),
            large: true,
            writable: l0.arm64_is_writable() && l1.arm64_is_writable(),
            user: l0.arm64_is_user() && l1.arm64_is_user(),
            nx: l0.arm64_is_nx() || l1.arm64_is_nx(),
            uxn: l1.arm64_is_uxn(),
        }
    }

    /// AArch64 2 MiB block descriptor at level 2.
    pub const fn arm64_large(
        l0: PageTableEntry,
        l1: PageTableEntry,
        l2: PageTableEntry,
        va: VirtAddr,
    ) -> Self {
        Self {
            address: l2.arm64_page_frame() + va.large_page_offset(),
            large: true,
            writable: l0.arm64_is_writable() && l1.arm64_is_writable() && l2.arm64_is_writable(),
            user: l0.arm64_is_user() && l1.arm64_is_user() && l2.arm64_is_user(),
            nx: l0.arm64_is_nx() || l1.arm64_is_nx() || l2.arm64_is_nx(),
            uxn: l2.arm64_is_uxn(),
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
        Self {
            address: l3.arm64_page_frame() + va.page_offset(),
            large: false,
            writable: l0.arm64_is_writable()
                && l1.arm64_is_writable()
                && l2.arm64_is_writable()
                && l3.arm64_is_writable(),
            user: l0.arm64_is_user() && l1.arm64_is_user() && l2.arm64_is_user() && l3.arm64_is_user(),
            nx: l0.arm64_is_nx() || l1.arm64_is_nx() || l2.arm64_is_nx() || l3.arm64_is_nx(),
            uxn: l3.arm64_is_uxn(),
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
            if arm64_trace_enabled() {
                eprintln!(
                    "arm64-walk: {va:#x} root={root:#x} L0[{}]={:#x} -> unmapped",
                    va.pml4_index(),
                    l0.0
                );
            }
            // 512 GiB L0 blocks are not used by Windows; treat as unmapped.
            return Ok(None);
        }

        let Some(l1) = self.read_pt_entry(l0.arm64_page_frame(), va.pdpt_index())? else {
            return Ok(None);
        };
        if !l1.arm64_is_valid() {
            if arm64_trace_enabled() {
                eprintln!(
                    "arm64-walk: {va:#x} L1[{}]={:#x} -> unmapped (l0={:#x})",
                    va.pdpt_index(),
                    l1.0,
                    l0.0
                );
            }
            return Ok(None);
        }
        if l1.arm64_is_block() {
            return Ok(Some(Translation::arm64_huge(l0, l1, va)));
        }

        let Some(l2) = self.read_pt_entry(l1.arm64_page_frame(), va.pd_index())? else {
            return Ok(None);
        };
        if !l2.arm64_is_valid() {
            if arm64_trace_enabled() {
                eprintln!(
                    "arm64-walk: {va:#x} L2[{}]={:#x} -> unmapped (l0={:#x} l1={:#x})",
                    va.pd_index(),
                    l2.0,
                    l0.0,
                    l1.0
                );
            }
            return Ok(None);
        }
        if l2.arm64_is_block() {
            return Ok(Some(Translation::arm64_large(l0, l1, l2, va)));
        }

        let Some(l3) = self.read_pt_entry(l2.arm64_page_frame(), va.pt_index())? else {
            return Ok(None);
        };
        if !l3.arm64_is_valid() {
            if arm64_trace_enabled() {
                eprintln!(
                    "arm64-walk: {va:#x} L3[{}]={:#x} -> unmapped (l0={:#x} l1={:#x} l2={:#x})",
                    va.pt_index(),
                    l3.0,
                    l0.0,
                    l1.0,
                    l2.0
                );
            }
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
            if arm64_trace_enabled() {
                eprintln!(
                    "mem-walk: {va:#x} dtb={:#x} amd64 PML4[{}]={:#x} -> unmapped",
                    self.dtb,
                    va.pml4_index(),
                    pml4e.0
                );
            }
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
                None => {
                    if arm64_trace_enabled() {
                        eprintln!(
                            "mem-read: {curr_vaddr:#x} arch={} dtb={:#x} kernel_dtb={:#x} -> unmapped",
                            if self.arm64 { "arm64" } else { "amd64" },
                            self.dtb,
                            self.kernel_dtb.unwrap_or(0),
                        );
                    }
                    if offset > 0 {
                        return Err(Error::PartialRead(offset));
                    } else {
                        return Err(Error::BadVirtualAddress(curr_vaddr));
                    }
                }
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
}
