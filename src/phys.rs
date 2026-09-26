use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::backend::MemoryOps;
use crate::dmp::{DmpInfo, DmpMem};
use crate::error::Result;
use crate::host::VmHandle;
use crate::kd::KdMemory;
use crate::memory::TranslationCache;
use crate::types::{Dtb, PhysAddr, VirtAddr};

/// Guest physical memory backed by a live VM process, KD transport, or crash
/// dump. Built once at attach and shared via `Arc`; everything above (address
/// spaces, symbol loading, unwinding) reads through it. `Dmp` is boxed because
/// it is much larger than the live handle.
pub enum PhysMem {
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
    fn epoch(&self) -> Option<u64> {
        (!self.is_running()).then(|| self.epoch.load(Ordering::Acquire))
    }
}

impl PhysMem {
    pub fn live() -> Result<Self> {
        Ok(Self::Live {
            host: VmHandle::new()?,
            mediated: None,
            halts: None,
        })
    }

    /// Hand guest writes to the target while reads keep coming from the host
    /// mapping. A no-op for sources that have no host mapping.
    pub fn with_mediated_writes(self, memory: KdMemory) -> Self {
        match self {
            Self::Live { host, halts, .. } => Self::Live {
                host,
                mediated: Some(memory),
                halts,
            },
            other => other,
        }
    }

    /// Take halts from the backend controlling the VM, so guest-derived lists
    /// can be memoized per halt. A no-op for sources that have no host
    /// mapping.
    pub fn with_halt_clock(self, clock: Arc<HaltClock>) -> Self {
        match self {
            Self::Live { host, mediated, .. } => Self::Live {
                host,
                mediated,
                halts: Some(clock),
            },
            other => other,
        }
    }

    pub fn dmp(path: &Path) -> Result<Self> {
        Ok(Self::Dmp(Box::new(DmpMem::open(path)?)))
    }

    pub fn remote(memory: KdMemory) -> Self {
        Self::Remote(memory)
    }

    pub fn dmp_info(&self) -> Option<&DmpInfo> {
        match self {
            Self::Dmp(d) => Some(d.info()),
            _ => None,
        }
    }

    /// Guest-physical address where RAM starts (below is firmware/MMIO):
    /// x86 QEMU/VMware: 0; aarch64 QEMU `virt`: 0x4000_0000 (1 GiB).
    pub fn ram_base(&self) -> u64 {
        match self {
            Self::Live { host, .. } => host.ram_base(),
            Self::Dmp(_) | Self::Remote(_) => 0,
        }
    }

    /// The host mapping guest reads come from, for diagnostics. `None` for
    /// sources that are not a live VM process.
    pub fn host_mapping(&self) -> Option<String> {
        match self {
            Self::Live { host, .. } => Some(host.describe()),
            Self::Dmp(_) | Self::Remote(_) => None,
        }
    }

    /// Total mapped guest RAM size.
    pub fn ram_size(&self) -> u64 {
        match self {
            Self::Live { host, .. } => host.ram_size(),
            Self::Dmp(_) | Self::Remote(_) => 0,
        }
    }

    /// Guest-physical RAM as `(base, len)` runs, for memory sources that know
    /// the layout (a live VM process). Empty for KD and dumps, whose callers
    /// take the runs from the guest's own `MmPhysicalMemoryBlock`.
    pub fn ram_runs(&self) -> Vec<(u64, u64)> {
        match self {
            Self::Live { host, .. } => host.ram_runs(),
            Self::Dmp(_) | Self::Remote(_) => Vec::new(),
        }
    }

    /// Identity of the current halt, for memoizing guest-derived lists: equal
    /// values mean the guest has not run in between. A live VM process has no
    /// resume signal of its own; while KD or the GDB stub controls execution
    /// its halts serve, and while the target runs, or with nothing controlling
    /// it, this is `None` and nothing may be memoized. A dump never changes, so
    /// it is one epoch forever.
    pub fn halt_epoch(&self) -> Option<u64> {
        match self {
            Self::Remote(kd) => kd.translation_cache().map(TranslationCache::halt_epoch),
            // KD bumps the epoch when the target resumes, and host reads keep
            // working while it runs: a walk then must not be memoized under
            // the new epoch and served after the next halt.
            Self::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => {
                kd.translation_cache().map(TranslationCache::halt_epoch)
            }
            Self::Live {
                halts: Some(clock), ..
            } => clock.epoch(),
            Self::Dmp(_) => Some(0),
            Self::Live { .. } => None,
        }
    }
}

impl MemoryOps<PhysAddr> for PhysMem {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Live { host, .. } => host.read_bytes(addr, buf),
            Self::Dmp(d) => d.read_bytes(addr, buf),
            Self::Remote(kd) => kd.read_bytes(addr, buf),
        }
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        match self {
            Self::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => kd.write_bytes(addr, buf),
            // The target cannot service a request while it runs, and the host
            // mapping is the only mechanism left. Such a write is already
            // best-effort because the guest may be touching the same bytes,
            // so it stays available rather than requiring an interrupt.
            Self::Live { host, .. } => host.write_bytes(addr, buf),
            Self::Dmp(d) => d.write_bytes(addr, buf),
            Self::Remote(kd) => kd.write_bytes(addr, buf),
        }
    }

    fn read_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &mut [u8]) -> Option<Result<()>> {
        match self {
            Self::Remote(kd) => kd.read_virtual_direct(addr, root, buf),
            // A host mapping is there to be read directly; that is the whole
            // point of selecting it.
            Self::Live { .. } | Self::Dmp(_) => None,
        }
    }

    fn write_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &[u8]) -> Option<Result<()>> {
        match self {
            Self::Live {
                mediated: Some(kd), ..
            } if kd.can_mediate_writes() => kd.write_virtual_direct(addr, root, buf),
            Self::Remote(kd) => kd.write_virtual_direct(addr, root, buf),
            Self::Live { .. } | Self::Dmp(_) => None,
        }
    }

    fn can_mediate_writes(&self) -> bool {
        match self {
            Self::Live {
                mediated: Some(kd), ..
            }
            | Self::Remote(kd) => kd.can_mediate_writes(),
            Self::Live { .. } | Self::Dmp(_) => false,
        }
    }

    fn translation_cache(&self) -> Option<&TranslationCache> {
        match self {
            Self::Remote(kd) => kd.translation_cache(),
            // Host reads are cheap enough to walk every time, and a mediated
            // write clears the target's own cache.
            Self::Live { .. } | Self::Dmp(_) => None,
        }
    }

    fn read_page_table_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Remote(kd) => kd.read_page_table_bytes(addr, buf),
            Self::Live { .. } | Self::Dmp(_) => self.read_bytes(addr, buf),
        }
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
