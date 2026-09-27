use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::backend::MemoryOps;
use crate::dmp::{DmpInfo, DmpMem};
use crate::error::Result;
use crate::host::VmHandle;
use crate::kd::KdMemory;
use crate::memory::{SectionViews, TranslationCache};
use crate::types::{Dtb, PhysAddr, VirtAddr};

/// Guest physical memory backed by a live VM process, KD transport, or crash
/// dump. Built once at attach and shared via `Arc`; everything above (address
/// spaces, symbol loading, unwinding) reads through it.
pub struct PhysMem {
    source: Source,
    /// The guest kernel's `InvalidPteMask`, set when a kernel is found (see
    /// [`Self::set_invalid_pte_mask`]).
    invalid_pte_mask: AtomicU64,
    /// The guest kernel's `MmPteBase`, 0 until a kernel is found (see
    /// [`Self::set_pte_self_map`]).
    pte_self_map: AtomicU64,
    /// The guest kernel's mapped-view lookup, set when a kernel is found (see
    /// [`Self::set_section_views`]).
    section_views: Mutex<Option<Arc<SectionViews>>>,
}

/// Where [`PhysMem`] reads from. `Dmp` is boxed because it is much larger than
/// the live handle.
enum Source {
    /// Live VM RAM. Reads come straight from the host mapping; writes go
    /// through `mediated` when there is one, because poking a guest frame from
    /// the host bypasses everything the guest's memory manager knows about
    /// that page, including PTE write protection, copy-on-write, residency and
    /// dirty tracking, while a target-mediated write is serviced by the guest's own
    /// debug-memory path.
    ///
    /// Mediation needs a request/reply exchange, so it only applies while the
    /// target is halted. A write to a running guest keeps using the host
    /// mapping: it is the only mechanism left, and such a write is already
    /// best-effort because the guest may be touching the same bytes.
    Live {
        host: VmHandle,
        mediated: Option<KdMemory>,
        /// Halts of the GDB stub controlling the VM, when it is the one.
        halts: Option<Arc<HaltClock>>,
    },
    Dmp(Box<DmpMem>),
    Remote(KdMemory),
}

/// Whether a backend that controls a live VM has it halted, and which halt
/// this is: the resume signal host memory lacks. Shared between the backend,
/// which reports every resume and halt, and [`PhysMem::halt_epoch`].
#[derive(Debug, Default)]
pub struct HaltClock {
    epoch: AtomicU64,
    running: AtomicBool,
}

impl HaltClock {
    /// Record a resume (a new epoch begins) or a halt.
    pub fn set_running(&self, running: bool) {
        if running {
            if !self.running.swap(true, Ordering::AcqRel) {
                self.epoch.fetch_add(1, Ordering::AcqRel);
            }
        } else {
            self.running.store(false, Ordering::Release);
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// The current halt's epoch; `None` while the target runs.
    pub fn epoch(&self) -> Option<u64> {
        (!self.is_running()).then(|| self.epoch.load(Ordering::Acquire))
    }
}

impl PhysMem {
    fn from_source(source: Source) -> Self {
        Self {
            source,
            invalid_pte_mask: AtomicU64::new(0),
            pte_self_map: AtomicU64::new(0),
            section_views: Mutex::new(None),
        }
    }

    pub fn live() -> Result<Self> {
        Ok(Self::from_source(Source::Live {
            host: VmHandle::new()?,
            mediated: None,
            halts: None,
        }))
    }

    /// Hand guest writes to the target while reads keep coming from the host
    /// mapping. A no-op for sources that have no host mapping.
    pub fn with_mediated_writes(self, memory: KdMemory) -> Self {
        match self.source {
            Source::Live { host, halts, .. } => Self::from_source(Source::Live {
                host,
                mediated: Some(memory),
                halts,
            }),
            _ => self,
        }
    }

    /// Take halts from the backend controlling the VM, so guest-derived lists
    /// can be memoized per halt. A no-op for sources that have no host
    /// mapping.
    pub fn with_halt_clock(self, clock: Arc<HaltClock>) -> Self {
        match self.source {
            Source::Live { host, mediated, .. } => Self::from_source(Source::Live {
                host,
                mediated,
                halts: Some(clock),
            }),
            _ => self,
        }
    }

    pub fn dmp(path: &Path) -> Result<Self> {
        Ok(Self::from_source(Source::Dmp(Box::new(DmpMem::open(
            path,
        )?))))
    }

    pub fn remote(memory: KdMemory) -> Self {
        Self::from_source(Source::Remote(memory))
    }

    /// Whether this is a crash dump, which never changes.
    pub fn is_dump(&self) -> bool {
        matches!(self.source, Source::Dmp(_))
    }

    /// Whether this reads a live VM's RAM from the host.
    /// Whether the hypervisor aborts this live VM when a debugger enables
    /// guest debugging (QEMU under HVF); see `VmHandle::guest_debug_aborts_vm`.
    pub fn guest_debug_aborts_vm(&self) -> bool {
        match &self.source {
            Source::Live { host, .. } => host.guest_debug_aborts_vm(),
            Source::Dmp(_) | Source::Remote(_) => false,
        }
    }

    pub fn is_live_host(&self) -> bool {
        matches!(self.source, Source::Live { .. })
    }

    /// Record the guest kernel's `InvalidPteMask` for this boot; see
    /// [`MemoryOps::invalid_pte_mask`].
    pub fn set_invalid_pte_mask(&self, mask: u64) {
        self.invalid_pte_mask.store(mask, Ordering::Release);
    }

    /// Record the guest kernel's `MmPteBase`. The 512 GiB self-map it heads
    /// is kernel space that maps whichever root it is read through, so a
    /// target's virtual-memory API, which reads kernel space through its own
    /// current root, cannot serve it for another root.
    pub fn set_pte_self_map(&self, pte_base: u64) {
        self.pte_self_map.store(pte_base, Ordering::Release);
    }

    fn in_pte_self_map(&self, addr: VirtAddr) -> bool {
        let base = self.pte_self_map.load(Ordering::Acquire);
        base != 0 && addr.0.wrapping_sub(base) < 1 << 39
    }

    /// Record the guest kernel's mapped-view lookup for this boot, or `None`
    /// when its PDB lacks the layout; see [`MemoryOps::section_views`].
    pub fn set_section_views(&self, views: Option<SectionViews>) {
        *self
            .section_views
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = views.map(Arc::new);
    }

    pub fn dmp_info(&self) -> Option<&DmpInfo> {
        match &self.source {
            Source::Dmp(d) => Some(d.info()),
            _ => None,
        }
    }

    /// Guest-physical address where RAM starts (below is firmware/MMIO):
    /// x86 QEMU/VMware: 0; aarch64 QEMU `virt`: 0x4000_0000 (1 GiB).
    pub fn ram_base(&self) -> u64 {
        match &self.source {
            Source::Live { host, .. } => host.ram_base(),
            Source::Dmp(_) | Source::Remote(_) => 0,
        }
    }

    /// The host mapping guest reads come from, for diagnostics. `None` for
    /// sources that are not a live VM process.
    pub fn host_mapping(&self) -> Option<String> {
        match &self.source {
            Source::Live { host, .. } => Some(host.describe()),
            Source::Dmp(_) | Source::Remote(_) => None,
        }
    }

    /// Total mapped guest RAM size.
    pub fn ram_size(&self) -> u64 {
        match &self.source {
            Source::Live { host, .. } => host.ram_size(),
            Source::Dmp(_) | Source::Remote(_) => 0,
        }
    }

    /// Guest-physical RAM as `(base, len)` runs, for memory sources that know
    /// the layout (a live VM process). Empty for KD and dumps, whose callers
    /// take the runs from the guest's own `MmPhysicalMemoryBlock`.
    pub fn ram_runs(&self) -> Vec<(u64, u64)> {
        match &self.source {
            Source::Live { host, .. } => host.ram_runs(),
            Source::Dmp(_) | Source::Remote(_) => Vec::new(),
        }
    }

    /// Identity of the current halt, for memoizing guest-derived lists: equal
    /// values mean the guest has not run in between. A live VM process has no
    /// resume signal of its own; while KD or the GDB stub controls execution
    /// its halts serve, and while the target runs, or with nothing controlling
    /// it, this is `None` and nothing may be memoized. A dump never changes, so
    /// it is one epoch forever.
    pub fn halt_epoch(&self) -> Option<u64> {
        match &self.source {
            Source::Remote(kd) => kd.translation_cache().map(TranslationCache::halt_epoch),
            // KD bumps the epoch when the target resumes, and host reads keep
            // working while it runs: a walk then must not be memoized under
            // the new epoch and served after the next halt.
            Source::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => {
                kd.translation_cache().map(TranslationCache::halt_epoch)
            }
            Source::Live {
                halts: Some(clock), ..
            } => clock.epoch(),
            Source::Dmp(_) => Some(0),
            Source::Live { .. } => None,
        }
    }
}

impl MemoryOps<PhysAddr> for PhysMem {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        match &self.source {
            Source::Live { host, .. } => host.read_bytes(addr, buf),
            Source::Dmp(d) => d.read_bytes(addr, buf),
            Source::Remote(kd) => kd.read_bytes(addr, buf),
        }
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        match &self.source {
            Source::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => kd.write_bytes(addr, buf),
            // The target cannot service a request while it runs, and the host
            // mapping is the only mechanism left. Such a write is already
            // best-effort because the guest may be touching the same bytes,
            // so it stays available rather than requiring an interrupt.
            Source::Live { host, .. } => host.write_bytes(addr, buf),
            Source::Dmp(d) => d.write_bytes(addr, buf),
            Source::Remote(kd) => kd.write_bytes(addr, buf),
        }
    }

    fn read_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &mut [u8]) -> Option<Result<()>> {
        match &self.source {
            Source::Remote(_) if self.in_pte_self_map(addr) => None,
            Source::Remote(kd) => kd.read_virtual_direct(addr, root, buf),
            // A host mapping is there to be read directly; that is the whole
            // point of selecting it.
            Source::Live { .. } | Source::Dmp(_) => None,
        }
    }

    fn write_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &[u8]) -> Option<Result<()>> {
        match &self.source {
            _ if self.in_pte_self_map(addr) => None,
            Source::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => kd.write_virtual_direct(addr, root, buf),
            Source::Remote(kd) => kd.write_virtual_direct(addr, root, buf),
            Source::Live { .. } | Source::Dmp(_) => None,
        }
    }

    fn can_mediate_writes(&self) -> bool {
        match &self.source {
            Source::Live {
                mediated: Some(kd), ..
            }
            | Source::Remote(kd) => kd.can_mediate_writes(),
            Source::Live { .. } | Source::Dmp(_) => false,
        }
    }

    fn translation_cache(&self) -> Option<&TranslationCache> {
        match &self.source {
            Source::Remote(kd) => kd.translation_cache(),
            // Host reads are cheap enough to walk every time, and a mediated
            // write clears the target's own cache.
            Source::Live { .. } | Source::Dmp(_) => None,
        }
    }

    fn read_page_table_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        match &self.source {
            Source::Remote(kd) => kd.read_page_table_bytes(addr, buf),
            Source::Live { .. } | Source::Dmp(_) => self.read_bytes(addr, buf),
        }
    }

    fn invalid_pte_mask(&self) -> u64 {
        self.invalid_pte_mask.load(Ordering::Acquire)
    }

    fn section_views(&self) -> Option<Arc<SectionViews>> {
        self.section_views
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::HaltClock;

    /// Guest lists are memoized under an epoch; one served after the guest
    /// ran would be stale.
    #[test]
    fn a_halt_clock_has_no_epoch_while_running_and_a_new_one_after() {
        let clock = HaltClock::default();
        let first = clock.epoch().expect("halted at attach");

        clock.set_running(true);
        assert_eq!(clock.epoch(), None);
        // A second report of the same run is not another resume.
        clock.set_running(true);
        clock.set_running(false);
        let second = clock.epoch().expect("halted again");
        assert_eq!(second, first + 1);

        // Halting again without running keeps the epoch.
        clock.set_running(false);
        assert_eq!(clock.epoch(), Some(second));
    }
}
