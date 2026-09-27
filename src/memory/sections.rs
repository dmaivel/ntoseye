//! Pages of mapped views that a process's own page tables do not map.
//!
//! NT fills in a process's PTE for a page of an image or file view only when
//! the process first touches it; until then the PTE is zero (or its page
//! table is absent) or a prototype PTE. The page's frame is recorded once, in
//! the section's prototype PTEs, which every process mapping the section
//! shares, so a DLL page one process never touched is often in memory for
//! another. A module's unwind tables are the typical case: a process that
//! never raised an exception has not touched them.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::backend::MemoryOps;
use crate::types::{Dtb, VirtAddr};

/// Processes walked from `PsActiveProcessHead` before giving up on a cycle.
const MAX_PROCESSES: usize = 16_384;
/// A VAD tree is balanced; far deeper than any real one.
const MAX_VAD_DEPTH: usize = 64;

/// The kernel structure offsets the lookup reads, from the kernel's PDB.
#[derive(Clone, Debug)]
pub struct SectionLayout {
    /// `PsActiveProcessHead`.
    pub process_list_head: VirtAddr,
    /// `_EPROCESS.ActiveProcessLinks`.
    pub active_process_links: u64,
    /// `_EPROCESS.Pcb.DirectoryTableBase`.
    pub directory_table_base: u64,
    /// The bits of `DirectoryTableBase` that locate the root table, which is
    /// what an address space is keyed by.
    pub root_mask: u64,
    /// `_EPROCESS.VadRoot.Root`.
    pub vad_root: u64,
    /// `_RTL_BALANCED_NODE.Left` and `.Right`.
    pub left: u64,
    pub right: u64,
    /// `_MMVAD_SHORT.VadNode`: a VAD is its tree node minus this.
    pub vad_node: u64,
    /// `_MMVAD_SHORT.StartingVpn`/`EndingVpn` (32-bit), and the
    /// `StartingVpnHigh`/`EndingVpnHigh` bytes above them where present.
    pub starting_vpn: u64,
    pub ending_vpn: u64,
    pub starting_vpn_high: Option<u64>,
    pub ending_vpn_high: Option<u64>,
    /// `_MMVAD_SHORT.u.VadFlags` and its `PrivateMemory` bit.
    pub vad_flags: u64,
    pub private_memory_bit: u32,
    /// `_MMVAD.FirstPrototypePte` and `LastContiguousPte`.
    pub first_prototype_pte: u64,
    pub last_contiguous_pte: u64,
}

/// Finds the prototype PTE of a page in a process's mapped view.
pub struct SectionViews {
    layout: SectionLayout,
    processes: Mutex<Processes>,
}

/// Each process's `EPROCESS` by the root of its address space, and roots no
/// process has, so a root that is not a process's (VTL1, the hypervisor)
/// does not cost a walk of the process list per page.
#[derive(Default)]
struct Processes {
    by_root: HashMap<u64, VirtAddr>,
    unknown: HashSet<u64>,
}

impl SectionViews {
    pub fn new(layout: SectionLayout) -> Self {
        Self {
            layout,
            processes: Mutex::new(Processes::default()),
        }
    }

    fn processes(&self) -> MutexGuard<'_, Processes> {
        self.processes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The kernel address of the prototype PTE for user page `va` of the
    /// process whose address space is rooted at `dtb`, read from the VAD that
    /// maps it; `None` when no view maps it (private memory has no prototype
    /// PTEs) or its PTE is outside the view's contiguous run of them.
    /// `kernel` reads kernel addresses.
    pub fn prototype_pte(
        &self,
        kernel: &impl MemoryOps<VirtAddr>,
        dtb: Dtb,
        va: VirtAddr,
    ) -> Option<VirtAddr> {
        let layout = &self.layout;
        let eprocess = self.process(kernel, dtb & layout.root_mask)?;
        let vpn = va.0 >> 12;
        let (vad, start) = self.find_vad(kernel, eprocess, vpn)?;
        let flags: u32 = kernel.read(vad + layout.vad_flags).ok()?;
        if flags >> layout.private_memory_bit & 1 != 0 {
            return None;
        }
        let first: u64 = kernel.read(vad + layout.first_prototype_pte).ok()?;
        let last: u64 = kernel.read(vad + layout.last_contiguous_pte).ok()?;
        let pte = first.checked_add((vpn - start).checked_mul(8)?)?;
        (first != 0 && pte <= last).then_some(VirtAddr(pte))
    }

    /// The `EPROCESS` whose root is `root`, confirmed against the process's
    /// own field, since a root outlives nothing: an exited process's may be
    /// reused.
    fn process(&self, kernel: &impl MemoryOps<VirtAddr>, root: u64) -> Option<VirtAddr> {
        let known = self.processes().by_root.get(&root).copied();
        if let Some(eprocess) = known
            && self.root_of(kernel, eprocess) == Some(root)
        {
            return Some(eprocess);
        }
        if known.is_none() && self.processes().unknown.contains(&root) {
            return None;
        }
        let by_root = self.walk_processes(kernel);
        let mut processes = self.processes();
        processes.by_root = by_root;
        let eprocess = processes.by_root.get(&root).copied();
        if eprocess.is_none() {
            processes.unknown.insert(root);
        }
        eprocess
    }

    fn root_of(&self, kernel: &impl MemoryOps<VirtAddr>, eprocess: VirtAddr) -> Option<u64> {
        let value: u64 = kernel
            .read(eprocess + self.layout.directory_table_base)
            .ok()?;
        Some(value & self.layout.root_mask)
    }

    fn walk_processes(&self, kernel: &impl MemoryOps<VirtAddr>) -> HashMap<u64, VirtAddr> {
        let head = self.layout.process_list_head;
        let mut by_root = HashMap::new();
        let mut link = head;
        for _ in 0..MAX_PROCESSES {
            let Ok(next) = kernel.read::<VirtAddr>(link) else {
                break;
            };
            if next == head || next.is_zero() {
                break;
            }
            let eprocess = VirtAddr(next.0.wrapping_sub(self.layout.active_process_links));
            if let Some(root) = self.root_of(kernel, eprocess) {
                by_root.insert(root, eprocess);
            }
            link = next;
        }
        by_root
    }

    /// The VAD of `eprocess` covering `vpn`, and its first page.
    fn find_vad(
        &self,
        kernel: &impl MemoryOps<VirtAddr>,
        eprocess: VirtAddr,
        vpn: u64,
    ) -> Option<(VirtAddr, u64)> {
        let layout = &self.layout;
        let vpn_at = |vad: VirtAddr, low: u64, high: Option<u64>| -> Option<u64> {
            let low: u32 = kernel.read(vad + low).ok()?;
            let high: u8 = match high {
                Some(offset) => kernel.read(vad + offset).ok()?,
                None => 0,
            };
            Some(u64::from(low) | u64::from(high) << 32)
        };
        let mut node: VirtAddr = kernel.read(eprocess + layout.vad_root).ok()?;
        for _ in 0..MAX_VAD_DEPTH {
            if node.is_zero() {
                return None;
            }
            let vad = VirtAddr(node.0.wrapping_sub(layout.vad_node));
            let start = vpn_at(vad, layout.starting_vpn, layout.starting_vpn_high)?;
            let end = vpn_at(vad, layout.ending_vpn, layout.ending_vpn_high)?;
            let child = if vpn < start {
                layout.left
            } else if vpn > end {
                layout.right
            } else {
                return Some((vad, start));
            };
            node = kernel.read(node + child).ok()?;
        }
        None
    }
}
