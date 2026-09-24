//! Physical memory access and page-table translation: `vtop`, the reverse
//! `ptov` walk, and the current-context `pte_traverse` decoder.

use std::collections::HashSet;

use super::{PteLevel, PteWalk, PtovDetail, PtovMapping, VtopDetail, VtopLevel};
use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::memory::{DTB_IDENTITY, PAGE_SIZE, PFN_MASK};
use crate::target::Target;
use crate::types::{Arch, Dtb, PageTableEntry, PageTableLevel, VirtAddr};

const MAX_PTOV_TABLE_PAGES: usize = 65_536;
const MAX_PTOV_RESULTS: usize = 32;
const LARGE_PAGE_1G: u64 = 1 << 30;
const LARGE_PAGE_2M: u64 = 1 << 21;

impl Target {
    /// Read guest-physical memory directly through the target's physical-memory
    /// backend without translating the supplied address.
    pub fn read_physical(&self, address: u64, buf: &mut [u8]) -> Result<()> {
        self.phys.read_bytes(address, buf)
    }

    /// Write guest-physical memory directly through the target's physical-memory
    /// backend without translating the supplied address.
    pub fn write_physical(&self, address: u64, data: &[u8]) -> Result<()> {
        self.phys.write_bytes(address, data)
    }

    /// Translate `address` using `directory_base`, or the current inspection
    /// context when it is `None` (or explicitly zero). Returns `None` when no
    /// present mapping exists.
    pub fn virt_to_phys(
        &self,
        directory_base: Option<u64>,
        address: VirtAddr,
    ) -> Result<Option<u64>> {
        let dtb = directory_base
            .filter(|value| *value != 0)
            .map(|value| value & self.arch().dtb_page_mask())
            .unwrap_or_else(|| self.current_dtb());
        Ok(self
            .address_space(dtb)
            .virt_to_phys(address)?
            .map(|translation| translation.address))
    }

    /// Walk `directory_base` for `address`, reusing the existing current-context
    /// `PteWalk` decoder when the argument is zero. Explicit AMD64 walks retain
    /// each PML4/PDP/PDE/PTE entry; other architectures use the shared translator.
    pub fn vtop(&self, directory_base: u64, address: VirtAddr) -> Result<VtopDetail> {
        let dtb = if directory_base == 0 {
            self.current_dtb()
        } else {
            directory_base & self.arch().dtb_page_mask()
        };
        if directory_base == 0
            && let Ok(walk) = self.pte_traverse(address)
        {
            let physical = self
                .address_space(dtb)
                .virt_to_phys(address)?
                .map(|translation| translation.address);
            let walk_transition = walk
                .pte
                .as_ref()
                .is_some_and(|level| level.value.is_transition());
            let large_entry = walk
                .pde
                .as_ref()
                .or(Some(&walk.ppe))
                .is_some_and(|level| level.value.is_large_page());
            let large = physical.is_some() && large_entry;
            let levels = [Some(walk.pxe), Some(walk.ppe), walk.pde, walk.pte]
                .into_iter()
                .flatten()
                .map(|level| VtopLevel {
                    level: level.level,
                    address: level.address,
                    value: level.value.0,
                })
                .collect();
            return Ok(VtopDetail {
                address,
                dtb,
                levels,
                physical,
                large,
                transition: physical.is_some() && walk_transition,
            });
        }
        if self.arch() != Arch::Amd64 {
            let translation = self.address_space(dtb).virt_to_phys(address)?;
            return Ok(VtopDetail {
                address,
                dtb,
                levels: Vec::new(),
                physical: translation.map(|value| value.address),
                large: translation.is_some_and(|value| value.large),
                transition: translation.is_some_and(|value| value.transition),
            });
        }
        explicit_amd64_walk(self, dtb, address)
    }

    /// Reverse-walk the current AMD64 directory base for mappings of a physical
    /// page. The walk stops at 32 results or 65,536 table pages and records both
    /// bounds and Ctrl-C interruption state.
    pub fn ptov(&self, physical: u64) -> Result<PtovDetail> {
        let dtb = self.current_dtb();
        if dtb == DTB_IDENTITY {
            return Ok(PtovDetail {
                physical,
                dtb,
                mappings: vec![PtovMapping {
                    virtual_address: VirtAddr(physical),
                    large: false,
                }],
                table_pages: 0,
                bounded: false,
                interrupted: false,
            });
        }
        if self.arch() != Arch::Amd64 {
            return Err(Error::DebugInfo(
                "!ptov reverse walking is currently available for AMD64 targets only".to_string(),
            ));
        }
        let mut visited = HashSet::new();
        let mut table_pages = 0usize;
        let mut mappings = Vec::new();
        scan_ptov_table(
            self,
            dtb,
            0,
            [0; 4],
            physical & !(PAGE_SIZE as u64 - 1),
            &mut visited,
            &mut table_pages,
            &mut mappings,
        );
        let interrupted = self.interrupted();
        let bounded = table_pages >= MAX_PTOV_TABLE_PAGES || mappings.len() >= MAX_PTOV_RESULTS;
        Ok(PtovDetail {
            physical,
            dtb,
            mappings: mappings
                .into_iter()
                .map(|(address, large)| PtovMapping {
                    virtual_address: VirtAddr(
                        address.0.wrapping_add(physical & (PAGE_SIZE as u64 - 1)),
                    ),
                    large,
                })
                .collect(),
            table_pages,
            bounded,
            interrupted,
        })
    }

    pub fn pte_traverse(&self, address: VirtAddr) -> Result<PteWalk> {
        // Walk through the current inspection address space so user VAs resolve
        // through the attached process's tables (not the kernel's). MmPteBase is
        // a kernel VA valid in any process context (the recursive PML4 slot).
        let memory = self.context_memory();
        let dtb = self.current_dtb();

        let pte_base: VirtAddr = self.guest()?.ntoskrnl.symbol("MmPteBase")?.read()?;
        let pde_base = pte_base + (pte_base.0 >> 9 & 0x7FFFFFFFFF);
        let ppe_base = pde_base + (pde_base.0 >> 9 & 0x3FFFFFFF);
        let pxe_base = ppe_base + (ppe_base.0 >> 9 & 0x1FFFFF);

        let pxe_address = VirtAddr(pxe_base.0 + (((address.0 >> 39) & 0x1FF) << 3));
        let ppe_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 30) << 3) + ppe_base.0);

        let pxe_value: PageTableEntry = memory.read(pxe_address)?;
        let ppe_value: PageTableEntry = memory.read(ppe_address)?;

        let pxe = PteLevel {
            level: PageTableLevel::Pxe,
            address: pxe_address,
            value: pxe_value,
        };
        let ppe = PteLevel {
            level: PageTableLevel::Ppe,
            address: ppe_address,
            value: ppe_value,
        };

        if ppe_value.is_large_page() {
            return Ok(PteWalk {
                address,
                dtb,
                pxe,
                ppe,
                pde: None,
                pte: None,
            });
        }

        let pde_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 21) << 3) + pde_base.0);
        let pde_value: PageTableEntry = memory.read(pde_address)?;
        let pde = PteLevel {
            level: PageTableLevel::Pde,
            address: pde_address,
            value: pde_value,
        };

        if pde_value.is_large_page() {
            return Ok(PteWalk {
                address,
                dtb,
                pxe,
                ppe,
                pde: Some(pde),
                pte: None,
            });
        }

        let pte_address = VirtAddr(((address.0 & 0xFFFFFFFFFFFF) >> 12) << 3) + pte_base.0;
        let pte_value: PageTableEntry = memory.read(pte_address)?;
        let pte = PteLevel {
            level: PageTableLevel::Pte,
            address: pte_address,
            value: pte_value,
        };

        Ok(PteWalk {
            address,
            dtb,
            pxe,
            ppe,
            pde: Some(pde),
            pte: Some(pte),
        })
    }
}

fn explicit_amd64_walk(target: &Target, dtb: Dtb, va: VirtAddr) -> Result<VtopDetail> {
    if dtb == DTB_IDENTITY {
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels: Vec::new(),
            physical: Some(va.0),
            large: false,
            transition: false,
        });
    }
    let root = dtb & PFN_MASK;
    let memory = &target.phys;
    let mut levels = Vec::with_capacity(4);
    let pml4_address = root
        .checked_add((va.pml4_index() as u64) * 8)
        .ok_or_else(|| Error::DebugInfo("PML4 address overflow".to_string()))?;
    let pml4e: PageTableEntry = memory.read(pml4_address)?;
    levels.push(VtopLevel {
        level: PageTableLevel::Pxe,
        address: VirtAddr(pml4_address),
        value: pml4e.0,
    });
    if !pml4e.is_present() {
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: None,
            large: false,
            transition: false,
        });
    }
    let pdpt_address = pml4e
        .page_frame()
        .checked_add((va.pdpt_index() as u64) * 8)
        .ok_or_else(|| Error::DebugInfo("PDPT address overflow".to_string()))?;
    let pdpte: PageTableEntry = memory.read(pdpt_address)?;
    levels.push(VtopLevel {
        level: PageTableLevel::Ppe,
        address: VirtAddr(pdpt_address),
        value: pdpte.0,
    });
    if !pdpte.is_present() {
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: None,
            large: false,
            transition: false,
        });
    }
    if pdpte.is_large_page() {
        let frame = pdpte.huge_page_frame();
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: frame.checked_add(va.huge_page_offset()),
            large: true,
            transition: false,
        });
    }
    let pde_address = pdpte
        .page_frame()
        .checked_add((va.pd_index() as u64) * 8)
        .ok_or_else(|| Error::DebugInfo("PD address overflow".to_string()))?;
    let pde: PageTableEntry = memory.read(pde_address)?;
    levels.push(VtopLevel {
        level: PageTableLevel::Pde,
        address: VirtAddr(pde_address),
        value: pde.0,
    });
    if !pde.is_present() {
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: None,
            large: false,
            transition: false,
        });
    }
    if pde.is_large_page() {
        let frame = pde.large_page_frame();
        return Ok(VtopDetail {
            address: va,
            dtb,
            levels,
            physical: frame.checked_add(va.large_page_offset()),
            transition: false,
            large: true,
        });
    }
    let pte_address = pde
        .page_frame()
        .checked_add((va.pt_index() as u64) * 8)
        .ok_or_else(|| Error::DebugInfo("PT address overflow".to_string()))?;
    let pte: PageTableEntry = memory.read(pte_address)?;
    levels.push(VtopLevel {
        level: PageTableLevel::Pte,
        address: VirtAddr(pte_address),
        value: pte.0,
    });
    // A transition leaf still names the frame the guest holds, and reads go
    // through it, so reporting it unmapped here would contradict them.
    let transition = pte.is_transition();
    Ok(VtopDetail {
        address: va,
        dtb,
        levels,
        physical: (pte.is_present() || transition).then(|| pte.page_frame() + va.page_offset()),
        large: false,
        transition,
    })
}

fn scan_ptov_table(
    target: &Target,
    table: u64,
    level: u8,
    prefix: [usize; 4],
    wanted_page: u64,
    visited: &mut HashSet<u64>,
    table_pages: &mut usize,
    results: &mut Vec<(VirtAddr, bool)>,
) {
    if *table_pages >= MAX_PTOV_TABLE_PAGES
        || results.len() >= MAX_PTOV_RESULTS
        || target.interrupted()
    {
        return;
    }
    let table = table & PFN_MASK;
    if !visited.insert(table) {
        return;
    }
    *table_pages += 1;
    let entries: [PageTableEntry; 512] = match target.phys.read(table) {
        Ok(entries) => entries,
        Err(_) => {
            visited.remove(&table);
            return;
        }
    };
    for (index, entry) in entries.into_iter().enumerate() {
        if !entry.is_present() || results.len() >= MAX_PTOV_RESULTS {
            continue;
        }
        let mut current = prefix;
        current[level as usize] = index;
        if level == 1 && entry.is_large_page() {
            let frame = entry.huge_page_frame();
            if (frame..frame.saturating_add(LARGE_PAGE_1G)).contains(&wanted_page) {
                let va = VirtAddr::construct(current[0], current[1], 0, 0) + (wanted_page - frame);
                results.push((va, true));
            }
            continue;
        }
        if level == 2 && entry.is_large_page() {
            let frame = entry.large_page_frame();
            if (frame..frame.saturating_add(LARGE_PAGE_2M)).contains(&wanted_page) {
                let va = VirtAddr::construct(current[0], current[1], current[2], 0)
                    + (wanted_page - frame);
                results.push((va, true));
            }
            continue;
        }
        if level == 3 {
            if entry.page_frame() == wanted_page {
                results.push((
                    VirtAddr::construct(current[0], current[1], current[2], current[3]),
                    false,
                ));
            }
            continue;
        }
        scan_ptov_table(
            target,
            entry.page_frame(),
            level + 1,
            current,
            wanted_page,
            visited,
            table_pages,
            results,
        );
    }
    visited.remove(&table);
}
