use std::path::Path;

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
    },
    Dmp(Box<DmpMem>),
    Remote(KdMemory),
}

impl PhysMem {
    pub fn live() -> Result<Self> {
        Ok(Self::Live {
            host: VmHandle::new()?,
            mediated: None,
        })
    }

    /// Hand guest writes to the target while reads keep coming from the host
    /// mapping. A no-op for sources that have no host mapping.
    pub fn with_mediated_writes(self, memory: KdMemory) -> Self {
        match self {
            Self::Live { host, .. } => Self::Live {
                host,
                mediated: Some(memory),
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
    /// values mean the guest has not run in between. `None` when this memory
    /// has no resume signal (a live VM process), so nothing may be memoized.
    /// A dump never changes, so it is one epoch forever.
    pub fn halt_epoch(&self) -> Option<u64> {
        match self {
            Self::Remote(kd) => kd.translation_cache().map(TranslationCache::halt_epoch),
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
