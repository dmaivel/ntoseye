//! Locating the kernel in guest RAM: the kernel page-table root and
//! architecture, and the ntoskrnl image base, for AMD64, ARM64, and triage
//! dumps.

use super::Image;
use crate::{
    backend::MemoryOps,
    error::Result,
    memory::{AddressSpace, PAGE_SIZE},
    phys::PhysMem,
    symbols::SymbolStore,
    types::*,
};
use std::sync::Arc;

fn is_valid_kernel_dtb_amd64(phys: &PhysMem, dtb: Dtb) -> Result<bool> {
    let Ok(kernel_pml4) = phys.read::<[PageTableEntry; 256]>(dtb + 8 * 256) else {
        // Candidate sits outside mapped guest RAM (below the aarch64 RAM
        // base, in an MMIO hole, or past the end): not a kernel root.
        return Ok(false);
    };

    if kernel_pml4
        .into_iter()
        .filter(|e| e.page_frame() == dtb)
        .count()
        != 1
    {
        return Ok(false);
    }

    // Check if use KUSER_SHARED_DATA is mapped
    const KUSER_SHARED_DATA_VA: VirtAddr = VirtAddr::from_u64(0xfffff78000000000);

    let addr_space = AddressSpace::new(phys, dtb);

    if let Some(xlat) = addr_space.virt_to_phys(KUSER_SHARED_DATA_VA)?
        && !xlat.user
        && xlat.nx
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn find_kernel_dtb_amd64(phys: &PhysMem) -> Result<Option<Dtb>> {
    let base = phys.ram_base();
    for dtb in (base + 0x1000..base + 0x1000000).step_by(PAGE_SIZE) {
        if is_valid_kernel_dtb_amd64(phys, dtb)? {
            return Ok(Some(dtb));
        }
    }

    Ok(None)
}

/// AArch64 kernel (TTBR1) root candidate: KUSER_SHARED_DATA must translate to
/// the *actual* shared-data page. Windows maps KUSER user-accessible (AP[2]=1)
/// and with UXN set, so attribute checks can't discriminate a real root from a
/// random table that happens to translate something; the page content can —
/// KUSER carries ImageNumberLow/High 0xaa64 at offset 0x2C and the
/// "C:\Windows" system root at 0x30 (this ARM64 layout differs from x64's
/// 0x20/0x38, so those offsets are checked exactly as observed).
fn is_valid_kernel_dtb_arm64(phys: &PhysMem, dtb: Dtb) -> Result<bool> {
    const KUSER_SHARED_DATA_VA: VirtAddr = VirtAddr::from_u64(0xfffff78000000000);

    let addr_space = AddressSpace::new_arm64(phys, dtb, dtb);
    let Some(xlat) = addr_space.virt_to_phys(KUSER_SHARED_DATA_VA)? else {
        return Ok(false);
    };
    let mut buf = [0u8; 0x40];
    if phys.read_bytes(xlat.address, &mut buf).is_err() {
        return Ok(false);
    }
    Ok(buf[0x2C..0x30] == [0x64, 0xaa, 0x64, 0xaa]
        && buf[0x30] == b'C'
        && buf[0x32] == b':'
        && buf[0x34] == b'\\')
}

/// Read the PE machine type of the kernel image found through `dtb` with the
/// arch's walker, or `None` when no valid PE header is there. This is the
/// definitive architecture check: a kernel image's machine must be 0x8664
/// (AMD64) or 0xaa64 (ARM64), which an accidental page-table false positive
/// cannot satisfy.
fn kernel_machine_at(dtb: Dtb, phys: &PhysMem, arch: Arch) -> Result<Option<u16>> {
    let base = match arch {
        Arch::Amd64 => find_ntoskrnl_va(dtb, phys)?,
        Arch::Arm64 => find_ntoskrnl_va_arm64(dtb, phys)?,
    };
    let Some(base) = base else {
        return Ok(None);
    };
    let space = AddressSpace::for_arch(phys, dtb, dtb, arch);
    // The base must read as a real DOS header ("MZ" + 0x90) through this
    // walker — a page-table false positive cannot satisfy this plus a valid
    // PE signature and matching machine type.
    let mut dos = [0u8; 4];
    if space.read_bytes(base, &mut dos).is_err() || dos != [0x4d, 0x5a, 0x90, 0x00] {
        return Ok(None);
    }
    let lfanew: u32 = match space.read(base + 0x3Cu64) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };
    if lfanew == 0 || lfanew > 0x1000 {
        return Ok(None);
    }
    let mut sig = [0u8; 6];
    if space.read_bytes(base + lfanew as u64, &mut sig).is_err() || &sig[..4] != b"PE\0\0" {
        return Ok(None);
    }
    Ok(Some(u16::from_le_bytes([sig[4], sig[5]])))
}

/// Discover the kernel page-table root and guest architecture. The AMD64
/// descriptor format is tried first (the historical default), but a candidate
/// only counts when the kernel image found through it is genuinely an AMD64
/// PE: an AArch64 guest's TTBR1 tables can false-positive the x64 descriptor
/// checks (Windows maps its own page tables), and the weak MZ+POOLCODE page
/// heuristic can match a data page. The PE machine type is the tie-breaker.
pub(super) fn find_kernel(phys: &PhysMem) -> Result<Option<(Dtb, Arch)>> {
    if let Some(dtb) = find_kernel_dtb_amd64(phys)?
        && matches!(kernel_machine_at(dtb, phys, Arch::Amd64)?, Some(0x8664))
    {
        return Ok(Some((dtb, Arch::Amd64)));
    }
    for dtb in find_kernel_dtb_arm64_candidates(phys)? {
        if matches!(kernel_machine_at(dtb, phys, Arch::Arm64)?, Some(0xaa64)) {
            return Ok(Some((dtb, Arch::Arm64)));
        }
    }
    Ok(None)
}

/// Scan guest RAM for AArch64 TTBR1 roots: page-aligned pages whose L0 entry
/// for KUSER_SHARED_DATA is a table descriptor pointing inside RAM. The full
/// translation must reach a page with the ARM64 KUSER signature; the caller
/// then validates the kernel image's PE machine type.
fn find_kernel_dtb_arm64_candidates(phys: &PhysMem) -> Result<Vec<Dtb>> {
    const KUSER_L0_INDEX: u64 = 495;
    const MAX_CANDIDATES: usize = 32;
    let base = phys.ram_base();
    let ram_end = base.saturating_add(phys.ram_size());
    let mut out = Vec::new();
    for dtb in (base.saturating_add(0x1000)..ram_end).step_by(PAGE_SIZE) {
        let Ok(entry) = phys.read::<PageTableEntry>(dtb + 8 * KUSER_L0_INDEX) else {
            continue;
        };
        // Table descriptor (bits[1:0] = 0b11) whose table lies in RAM.
        if entry.0 & 0b11 != 0b11 {
            continue;
        }
        let frame = entry.arm64_page_frame();
        if frame < base || frame >= ram_end {
            continue;
        }
        if is_valid_kernel_dtb_arm64(phys, dtb)? {
            out.push(dtb);
            if out.len() >= MAX_CANDIDATES {
                break;
            }
        }
    }
    Ok(out)
}

fn is_ntoskrnl_header(header: &[u8]) -> bool {
    header.len() >= 4
        && header[..4] == [0x4d, 0x5a, 0x90, 0x00]
        && header.as_chunks::<8>().0.iter().any(|c| c == b"POOLCODE")
}

/// Whether the kernel-only, no-execute page at `frame` (mapped by `entry`)
/// starts with the ntoskrnl image header.
fn is_ntoskrnl_page(
    phys: &impl MemoryOps<PhysAddr>,
    entry: PageTableEntry,
    frame: PhysAddr,
) -> Result<bool> {
    if entry.is_user() || !entry.is_nx() {
        return Ok(false);
    }

    let Ok(header) = phys.read::<[u8; 0x1000]>(frame) else {
        return Ok(false);
    };
    Ok(is_ntoskrnl_header(&header))
}

pub(super) fn find_ntoskrnl_va(
    kernel_dtb: Dtb,
    phys: &impl MemoryOps<PhysAddr>,
) -> Result<Option<VirtAddr>> {
    const KERNEL_VA_MIN: VirtAddr = VirtAddr::from_u64(0xfffff80000000000);
    const KERNEL_VA_MAX: VirtAddr = VirtAddr::from_u64(0xfffff80800000000);

    let pml4e_count = KERNEL_VA_MAX.pml4_index() - KERNEL_VA_MIN.pml4_index() + 1;

    let Ok(kernel_pml4) = phys.read::<[PageTableEntry; 256]>(kernel_dtb + 8 * 256) else {
        return Ok(None);
    };
    for (rel_pml4_index, pml4e) in kernel_pml4
        .into_iter()
        .enumerate()
        .skip(KERNEL_VA_MIN.pml4_index() - 256)
        .take(pml4e_count)
    {
        let pml4_index = 256 + rel_pml4_index;

        if !pml4e.is_present() {
            continue;
        }
        let Ok(pdpt) = phys.read::<[PageTableEntry; 512]>(pml4e.page_frame()) else {
            continue;
        };

        // The scan ends at KERNEL_VA_MAX (inclusive): each level is clamped
        // only on the path that leads to it.
        let on_last_pml4 = pml4_index == KERNEL_VA_MAX.pml4_index();
        let pdpte_count = if on_last_pml4 {
            KERNEL_VA_MAX.pdpt_index() + 1
        } else {
            512
        };

        for (pdpt_index, pdpte) in pdpt.into_iter().take(pdpte_count).enumerate() {
            if !pdpte.is_present() {
                continue;
            }

            if pdpte.is_large_page() {
                if let Ok(true) = is_ntoskrnl_page(phys, pdpte, pdpte.huge_page_frame()) {
                    return Ok(Some(VirtAddr::construct(pml4_index, pdpt_index, 0, 0)));
                }

                continue;
            }

            let Ok(pd) = phys.read::<[PageTableEntry; 512]>(pdpte.page_frame()) else {
                continue;
            };

            let on_last_pdpt = on_last_pml4 && pdpt_index == KERNEL_VA_MAX.pdpt_index();
            let pde_count = if on_last_pdpt {
                KERNEL_VA_MAX.pd_index() + 1
            } else {
                512
            };

            for (pd_index, pde) in pd.into_iter().take(pde_count).enumerate() {
                if !pde.is_present() {
                    continue;
                }

                if pde.is_large_page() {
                    if let Ok(true) = is_ntoskrnl_page(phys, pde, pde.large_page_frame()) {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index, pdpt_index, pd_index, 0,
                        )));
                    }

                    continue;
                }

                let Ok(pt) = phys.read::<[PageTableEntry; 512]>(pde.page_frame()) else {
                    continue;
                };

                let pte_count = if on_last_pdpt && pd_index == KERNEL_VA_MAX.pd_index() {
                    KERNEL_VA_MAX.pt_index() + 1
                } else {
                    512
                };

                for (pt_index, pte) in pt.into_iter().take(pte_count).enumerate() {
                    if !pte.is_present() {
                        continue;
                    }

                    if let Ok(true) = is_ntoskrnl_page(phys, pte, pte.page_frame()) {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index, pdpt_index, pd_index, pt_index,
                        )));
                    }
                }
            }
        }
    }

    Ok(None)
}

fn is_ntoskrnl_pte_arm64(phys: &PhysMem, pte: PageTableEntry) -> Result<bool> {
    // Kernel code pages: AP[2]=0 (not user), PXN=0 (executable from EL1).
    // (UXN is always set on Windows kernel pages, so it cannot identify code.)
    if pte.arm64_is_user() || !pte.arm64_is_pxn() {
        return Ok(false);
    }

    is_ntoskrnl_header_at(phys, pte.arm64_page_frame())
}

/// Whether the physical page at `frame` holds the ntoskrnl PE header
/// (MZ + POOLCODE marker). Tolerant of unreadable/unmapped frames.
fn is_ntoskrnl_header_at(phys: &PhysMem, frame: u64) -> Result<bool> {
    let Ok(header) = phys.read::<[u8; 0x1000]>(frame) else {
        return Ok(false);
    };
    Ok(is_ntoskrnl_header(&header))
}

/// Same bounded kernel-VA scan as [`find_ntoskrnl_va`] but interpreting
/// AArch64 descriptors (TTBR1 root, 4 KiB granule). The VA index math is
/// identical to x64's four 9-bit levels.
pub(super) fn find_ntoskrnl_va_arm64(kernel_dtb: Dtb, phys: &PhysMem) -> Result<Option<VirtAddr>> {
    // Cover the Windows ARM64 kernel VA range. Unlike the AMD64 scan's narrow
    // low-kernel slot, this includes every populated L0 slot from 496 through
    // the inclusive upper bound.
    const KERNEL_VA_MIN: VirtAddr = VirtAddr::from_u64(0xfffff80000000000);
    const KERNEL_VA_MAX: VirtAddr = VirtAddr::from_u64(0xffffff8000000000);

    let pml4e_count = KERNEL_VA_MAX.pml4_index() - KERNEL_VA_MIN.pml4_index() + 1;

    let Ok(kernel_table) = phys.read::<[PageTableEntry; 256]>(kernel_dtb + 8 * 256) else {
        return Ok(None);
    };
    for (rel_index, l0) in kernel_table
        .into_iter()
        .enumerate()
        .skip(KERNEL_VA_MIN.pml4_index() - 256)
        .take(pml4e_count)
    {
        let pml4_index = 256 + rel_index;

        if !l0.arm64_is_valid() || l0.arm64_is_block() {
            continue;
        }
        let Ok(l1_table) = phys.read::<[PageTableEntry; 512]>(l0.arm64_page_frame()) else {
            continue;
        };

        let on_upper_l0 = pml4_index == KERNEL_VA_MAX.pml4_index();
        let l1_count = if on_upper_l0 {
            KERNEL_VA_MAX.pdpt_index() + 1
        } else {
            512
        };

        for (l1_index, l1) in l1_table.into_iter().take(l1_count).enumerate() {
            if !l1.arm64_is_valid() {
                continue;
            }

            if l1.arm64_is_block() {
                // A 1 GiB block is unlikely for ntoskrnl. Probe each 2 MiB
                // boundary and reconstruct the matching VA at the L2 index.
                let block = l1.arm64_huge_block_frame();
                for l2_index in 0..512u64 {
                    if is_ntoskrnl_header_at(phys, block + l2_index * (2 << 20))? {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index,
                            l1_index,
                            l2_index as usize,
                            0,
                        )));
                    }
                }
                continue;
            }

            let Ok(l2_table) = phys.read::<[PageTableEntry; 512]>(l1.arm64_page_frame()) else {
                continue;
            };

            let on_upper_l1 = on_upper_l0 && l1_index == KERNEL_VA_MAX.pdpt_index();
            let l2_count = if on_upper_l1 {
                KERNEL_VA_MAX.pd_index() + 1
            } else {
                512
            };

            for (l2_index, l2) in l2_table.into_iter().take(l2_count).enumerate() {
                if !l2.arm64_is_valid() {
                    continue;
                }

                if l2.arm64_is_block() {
                    // Probe every 4 KiB page in the 2 MiB block; the PE image
                    // need not begin at the block's first page.
                    let block = l2.arm64_large_block_frame();
                    for pt_index in 0..512u64 {
                        if is_ntoskrnl_header_at(phys, block + pt_index * 0x1000)? {
                            return Ok(Some(VirtAddr::construct(
                                pml4_index,
                                l1_index,
                                l2_index,
                                pt_index as usize,
                            )));
                        }
                    }
                    continue;
                }

                let Ok(l3_table) = phys.read::<[PageTableEntry; 512]>(l2.arm64_page_frame()) else {
                    continue;
                };

                let on_upper_l2 = on_upper_l1 && l2_index == KERNEL_VA_MAX.pd_index();
                let l3_count = if on_upper_l2 {
                    KERNEL_VA_MAX.pt_index() + 1
                } else {
                    512
                };

                for (l3_index, l3) in l3_table.into_iter().take(l3_count).enumerate() {
                    if l3.0 & 0b11 != 0b11 {
                        continue;
                    }

                    if let Ok(true) = is_ntoskrnl_pte_arm64(phys, l3) {
                        return Ok(Some(VirtAddr::construct(
                            pml4_index, l1_index, l2_index, l3_index,
                        )));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Scan captured virtual memory regions for the ntoskrnl PE header.
///
/// Triage dumps have no page tables, so we can't walk the PML4. Instead we
/// probe the identity-mapped virtual memory for the MZ header + POOLCODE
/// marker, the same heuristic `is_ntoskrnl_pte` uses but at the virtual
/// layer.
pub(super) fn find_ntoskrnl_va_triage(kernel_dtb: Dtb, phys: &PhysMem) -> Result<Option<VirtAddr>> {
    let space = AddressSpace::new(phys, kernel_dtb);

    // No PDB yet, so PsLoadedModuleList can't be walked; probe the data
    // blocks for kernel-space PE headers instead.
    if let Some(dmp_info) = phys.dmp_info() {
        // Check triage driver base addresses first — ntoskrnl is typically
        // the first entry and this avoids scanning up to 4096 pages.
        let mut header = vec![0u8; 0x1000];
        for driver in &dmp_info.triage_drivers {
            let candidate = VirtAddr(driver.base);
            if space.read_bytes(candidate, &mut header).is_err() {
                continue;
            }
            if is_ntoskrnl_header(&header) {
                return Ok(Some(candidate));
            }
        }

        // Fallback: scan backwards from PsLoadedModuleList.
        let ps_loaded = dmp_info.ps_loaded_module_list;
        if ps_loaded >= 0xfffff80000000000 {
            let page_base = ps_loaded & !0xFFF;
            for offset in (0..0x100_0000u64).step_by(0x1000) {
                let candidate = page_base - offset;
                if space.read_bytes(VirtAddr(candidate), &mut header).is_err() {
                    continue;
                }
                if is_ntoskrnl_header(&header) {
                    return Ok(Some(VirtAddr(candidate)));
                }
            }
        }
    }

    Ok(None)
}

pub(super) fn find_ntoskrnl(
    phys: Arc<PhysMem>,
    symbols: Arc<SymbolStore>,
) -> Result<Option<Image>> {
    let Some((kernel_dtb, arch)) = find_kernel(&phys)? else {
        return Ok(None);
    };

    let ntoskrnl_va = match arch {
        Arch::Amd64 => find_ntoskrnl_va(kernel_dtb, &phys)?,
        Arch::Arm64 => find_ntoskrnl_va_arm64(kernel_dtb, &phys)?,
    };
    let Some(ntoskrnl_va) = ntoskrnl_va else {
        return Ok(None);
    };

    Ok(Some(Image::new(
        phys,
        symbols,
        kernel_dtb,
        ntoskrnl_va,
        arch,
    )))
}

#[cfg(test)]
mod tests {
    use super::find_ntoskrnl_va;
    use crate::backend::MemoryOps;
    use crate::error::{Error, Result};
    use crate::types::{PhysAddr, VirtAddr};
    use std::collections::HashMap;

    /// Physical memory holding only the 4 KiB pages written to it.
    #[derive(Default)]
    struct SparsePhys(HashMap<u64, Box<[u8; 0x1000]>>);

    impl SparsePhys {
        fn write_u64(&mut self, addr: u64, value: u64) {
            let page = self
                .0
                .entry(addr & !0xfff)
                .or_insert_with(|| Box::new([0; 0x1000]));
            let at = (addr & 0xfff) as usize;
            page[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }

        fn write_ntoskrnl_header(&mut self, frame: u64) {
            self.write_u64(frame, 0x0000_0090_5a4d);
            self.write_u64(frame + 0x200, u64::from_le_bytes(*b"POOLCODE"));
        }
    }

    impl MemoryOps<PhysAddr> for SparsePhys {
        fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
            for (offset, byte) in buf.iter_mut().enumerate() {
                let at = addr + offset as u64;
                let page = self
                    .0
                    .get(&(at & !0xfff))
                    .ok_or(Error::BadPhysicalAddress(at))?;
                *byte = page[(at & 0xfff) as usize];
            }
            Ok(())
        }

        fn write_bytes(&self, addr: PhysAddr, _buf: &[u8]) -> Result<()> {
            Err(Error::BadPhysicalAddress(addr))
        }
    }

    /// The AMD64 kernel-image scan covers `0xffff_f800_0000_0000` through
    /// `0xffff_f808_0000_0000` inclusive: an image mapped at the upper bound is
    /// found, one mapped a slot past it is not.
    #[test]
    fn ntoskrnl_scan_ends_at_its_upper_bound() {
        const DTB: u64 = 0x1000;
        const PDPT: u64 = 0x2000;
        // Present, writable, supervisor, large page, no-execute.
        const KERNEL_LARGE_PAGE: u64 = 0x80 | 0b11 | (1 << 63);
        let upper = VirtAddr(0xffff_f808_0000_0000);
        let mut phys = SparsePhys::default();
        phys.write_u64(DTB + 8 * upper.pml4_index() as u64, PDPT | 0b11);

        let past = upper.pdpt_index() as u64 + 1;
        phys.write_u64(PDPT + 8 * past, 0x8000_0000 | KERNEL_LARGE_PAGE);
        phys.write_ntoskrnl_header(0x8000_0000);
        assert_eq!(find_ntoskrnl_va(DTB, &phys).unwrap(), None);

        let at_bound = upper.pdpt_index() as u64;
        phys.write_u64(PDPT + 8 * at_bound, 0x4000_0000 | KERNEL_LARGE_PAGE);
        phys.write_ntoskrnl_header(0x4000_0000);
        assert_eq!(find_ntoskrnl_va(DTB, &phys).unwrap(), Some(upper));
    }
}
