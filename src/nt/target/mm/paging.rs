//! Physical memory access and page-table translation: `vtop`, the reverse
//! `ptov` walk, and the current-context `pte_traverse` decoder.

use std::collections::HashSet;

use super::{PteLevel, PteWalk, PtovDetail, PtovMapping, VtopDetail};
use crate::arch::{Arch, Paging, TableEntry};
use crate::base::error::{Error, Result};
use crate::base::memory::{AddressSpace, DTB_IDENTITY, MemoryOps, PAGE_SIZE, Residency};
use crate::base::types::{Dtb, PAGE_SHIFT, PFN_MASK, PageTableEntry, PageTableLevel, VirtAddr};
use crate::nt::target::Target;

const MAX_PTOV_TABLE_PAGES: usize = 65_536;
const MAX_PTOV_RESULTS: usize = 32;

/// Bytes in a page-table entry, as [`Paging::levels`] has them.
const ENTRY_SIZE: u64 = 8;

/// NT's page-table self-map: one array of entries per level the
/// architecture's tables have, each array the entries of all the tables at
/// that level, mapped through the root's recursive slot. `MmPteBase` heads
/// the last level's; each level's array is the entries of the one below.
#[derive(Debug, Clone, Copy)]
pub struct PteSelfMap {
    levels: &'static [PageTableLevel],
    /// Each level's array, in the order of `levels`.
    bases: [u64; PageTableLevel::ALL.len()],
    /// The address bits the levels index.
    index_mask: u64,
}

impl PteSelfMap {
    /// The self-map `pte_base` (`MmPteBase`) heads for `paging`'s tables.
    pub fn new(pte_base: u64, paging: &dyn Paging) -> Self {
        let levels = paging.levels();
        // A table indexes 9 bits above its level's shift (512 entries).
        let index_mask = (1u64 << (levels[0].shift() + 9)) - 1;
        let mut bases = [0; PageTableLevel::ALL.len()];
        let mut base = pte_base;
        for slot in bases[..levels.len()].iter_mut().rev() {
            *slot = base;
            // The array above maps this one's pages: their entries in the
            // last level's array.
            base = pte_base + ((base & index_mask) >> PAGE_SHIFT) * ENTRY_SIZE;
        }
        Self {
            levels,
            bases,
            index_mask,
        }
    }

    /// Where the entries mapping `address` sit in the self-map, root first.
    pub fn entries(
        &self,
        address: u64,
    ) -> impl DoubleEndedIterator<Item = (PageTableLevel, VirtAddr)> + '_ {
        let index = address & self.index_mask;
        self.levels
            .iter()
            .zip(self.bases)
            .map(move |(&level, base)| {
                (
                    level,
                    VirtAddr(base + (index >> level.shift()) * ENTRY_SIZE),
                )
            })
    }

    /// The first address of the self-map and its length: the last level's
    /// array, which holds the others.
    pub fn extent(&self) -> (u64, u64) {
        let pte_base = self.bases[self.levels.len() - 1];
        (pte_base, ((self.index_mask + 1) >> PAGE_SHIFT) * ENTRY_SIZE)
    }
}

impl Target {
    /// The kernel's `_MI_VISIBLE_STATE`, `MiState.Vs`: where
    /// `nt!MiVisibleState`, the kernel's own pointer to it, points, else the
    /// PDB's offset in `MiState`. They differ on 19045, whose `MiState` has
    /// 0x40 bytes the PDB does not, between `Hardware` and `Partitions`.
    pub fn visible_state(&self) -> Result<VirtAddr> {
        let ntos = &self.guest()?.ntoskrnl;
        if let Some(pointer) = ntos
            .symbol("MiVisibleState")
            .ok()
            .and_then(|symbol| symbol.read_pointer().ok())
            .filter(|pointer| !pointer.is_zero())
        {
            return Ok(pointer);
        }
        self.pdb_visible_state()
    }

    /// `MiState.Vs` where the PDB places it.
    fn pdb_visible_state(&self) -> Result<VirtAddr> {
        let ntos = &self.guest()?.ntoskrnl;
        Ok(ntos.symbol("MiState")?.address()
            + ntos
                .types()
                .layout("_MI_SYSTEM_INFORMATION")?
                .field_offset("Vs")?)
    }

    /// How far past the PDB's offsets the kernel keeps `MiState`'s later
    /// members (0x40 on 19045, 0 where the two agree), as `MiVisibleState`
    /// shows it.
    pub fn mi_state_displacement(&self) -> u64 {
        match (self.visible_state(), self.pdb_visible_state()) {
            (Ok(kernel), Ok(pdb)) if kernel.0 > pdb.0 && kernel.0 - pdb.0 < 0x1000 => {
                kernel.0 - pdb.0
            }
            _ => 0,
        }
    }

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
    /// present mapping exists. A user-mode minidump has no physical
    /// addresses to translate to.
    pub fn virt_to_phys(
        &self,
        directory_base: Option<u64>,
        address: VirtAddr,
    ) -> Result<Option<u64>> {
        if self.user_dump().is_some() {
            return Err(Error::NoPhysicalMemory);
        }
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
    /// `PteWalk` decoder when the argument is zero, and listing each entry
    /// the walk reads otherwise.
    pub fn vtop(&self, directory_base: u64, address: VirtAddr) -> Result<VtopDetail> {
        let dtb = if directory_base == 0 {
            self.current_dtb()
        } else {
            directory_base & self.arch().dtb_page_mask()
        };
        if directory_base == 0
            && let Ok(walk) = self.pte_traverse(address)
        {
            let translation = self.address_space(dtb).virt_to_phys(address)?;
            let physical = translation.map(|translation| translation.address);
            let walk_transition = walk.levels.last().is_some_and(|level| {
                level.level == PageTableLevel::Pte && PageTableEntry(level.value).is_transition()
            });
            let large_entry = walk.levels.iter().any(|level| level.attributes.large_page);
            let large = physical.is_some() && large_entry;
            let levels = walk.levels;
            return Ok(VtopDetail {
                address,
                dtb,
                levels,
                physical_walk: false,
                physical,
                large,
                transition: physical.is_some() && walk_transition,
                section: translation.is_some_and(|value| value.residency == Residency::Section),
            });
        }
        let arch = self.arch();
        let (steps, translation) = self.address_space(dtb).walk_steps(address)?;
        Ok(VtopDetail {
            address,
            dtb,
            levels: steps
                .into_iter()
                .map(|step| PteLevel {
                    level: step.level,
                    address: VirtAddr(step.address),
                    value: step.entry.0,
                    attributes: arch
                        .paging()
                        .entry_attributes(step.entry, step.level, address),
                })
                .collect(),
            physical_walk: true,
            physical: translation.map(|value| value.address),
            large: translation.is_some_and(|value| value.large),
            transition: translation.is_some_and(|value| value.residency == Residency::Transition),
            section: translation.is_some_and(|value| value.residency == Residency::Section),
        })
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
        match self.arch() {
            Arch::Amd64 => {}
            Arch::Arm64 => {
                return Err(Error::DebugInfo(
                    "!ptov reverse walking is currently available for AMD64 targets only"
                        .to_string(),
                ));
            }
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

    /// The self-map the kernel's PTE base heads.
    pub fn pte_self_map(&self) -> Result<PteSelfMap> {
        let pte_base = self.guest()?.ntoskrnl.pte_base()?;
        Ok(PteSelfMap::new(pte_base.0, self.arch().paging()))
    }

    /// The page-table entries mapping `address`, read through NT's
    /// self-map in the inspection address space, so user VAs resolve through
    /// the selected process's tables. Every NT root maps the self-map; a root
    /// that does not (a stop in the Windows hypervisor or VTL1) is not NT's,
    /// and the walk uses the kernel's instead.
    pub fn pte_traverse(&self, address: VirtAddr) -> Result<PteWalk> {
        // No table maps the hole between the halves; walked anyway, the
        // self-map would fold the address onto one it does map.
        let (user_end, kernel_start) = self.arch().paging().canonical_halves();
        if (user_end..kernel_start).contains(&address.0) {
            return Err(Error::InvalidArgument(format!(
                "{address:#x} is not a canonical address"
            )));
        }
        let current = self.current_dtb();
        match self.pte_traverse_in(current, address) {
            Err(error) if current != self.kernel_dtb() => self
                .pte_traverse_in(self.kernel_dtb(), address)
                .map_err(|_| error),
            walk => walk,
        }
    }

    fn pte_traverse_in(&self, dtb: Dtb, address: VirtAddr) -> Result<PteWalk> {
        // MmPteBase is a kernel VA valid in any NT root (the recursive PML4
        // slot). It maps the root it is read through, so on ARM64, where a
        // process's root is its TTBR1 as well as its TTBR0, the self-map is
        // read through `dtb` for both halves; through the kernel's root it
        // would show the kernel's (empty) user half.
        let memory = AddressSpace::for_arch(&self.phys, dtb, dtb, self.arch());
        let paging = self.arch().paging();
        let mut levels = Vec::new();
        for (level, at) in self.pte_self_map()?.entries(address.0) {
            let value: PageTableEntry = memory.read(at)?;
            let attributes = paging.entry_attributes(value, level, address);
            // The walk ends at an entry that maps (a large page) or maps
            // nothing: the self-map has no table below it to read. A table
            // in transition is still in memory, and the self-map reads it.
            let ends = attributes.large_page || (!attributes.present && !value.is_transition());
            levels.push(PteLevel {
                level,
                address: at,
                value: value.0,
                attributes,
            });
            if ends {
                break;
            }
        }
        Ok(PteWalk {
            address,
            dtb,
            levels,
            non_resident: self.non_resident(dtb, address),
        })
    }
}

fn scan_ptov_table(
    target: &Target,
    table: u64,
    depth: usize,
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
    let paging = target.arch().paging();
    let level = paging.levels()[depth];
    for (index, entry) in entries.into_iter().enumerate() {
        if results.len() >= MAX_PTOV_RESULTS {
            break;
        }
        let mut current = prefix;
        current[depth] = index;
        match paging.decode_entry(level, entry) {
            TableEntry::Absent => {}
            TableEntry::Leaf(frame) => {
                let span = 1u64 << level.shift();
                if (frame..frame.saturating_add(span)).contains(&wanted_page) {
                    let va = VirtAddr::construct(current[0], current[1], current[2], current[3])
                        + (wanted_page - frame);
                    results.push((va, level != PageTableLevel::Pte));
                }
            }
            TableEntry::Table(next) => scan_ptov_table(
                target,
                next,
                depth + 1,
                current,
                wanted_page,
                visited,
                table_pages,
                results,
            ),
        }
    }
    visited.remove(&table);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows 7's fixed x64 self-map, whose bases and entries are well known.
    #[test]
    fn self_map_entries_are_the_recursive_slots_of_each_level() {
        let map = PteSelfMap::new(0xFFFF_F680_0000_0000, Arch::Amd64.paging());
        let entries: Vec<_> = map.entries(0xFFFF_F800_0123_4567).collect();
        assert_eq!(
            entries,
            [
                (PageTableLevel::Pxe, VirtAddr(0xFFFF_F6FB_7DBE_DF80)),
                (PageTableLevel::Ppe, VirtAddr(0xFFFF_F6FB_7DBF_0000)),
                (PageTableLevel::Pde, VirtAddr(0xFFFF_F6FB_7E00_0048)),
                (PageTableLevel::Pte, VirtAddr(0xFFFF_F6FC_0000_91A0)),
            ]
        );
        // A user address indexes from the bottom of each array.
        assert_eq!(
            map.entries(0x1000).next(),
            Some((PageTableLevel::Pxe, VirtAddr(0xFFFF_F6FB_7DBE_D000)))
        );
        assert_eq!(map.extent(), (0xFFFF_F680_0000_0000, 1 << 39));
    }
}
