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
    Live(VmHandle),
    Dmp(Box<DmpMem>),
    Remote(KdMemory),
}

impl PhysMem {
    pub fn live() -> Result<Self> {
        Ok(Self::Live(VmHandle::new()?))
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
            Self::Live(h) => h.ram_base(),
            Self::Dmp(_) | Self::Remote(_) => 0,
        }
    }

    /// Total mapped guest RAM size.
    pub fn ram_size(&self) -> u64 {
        match self {
            Self::Live(h) => h.ram_size(),
            Self::Dmp(_) | Self::Remote(_) => 0,
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
            Self::Live(_) => None,
        }
    }
}

impl MemoryOps<PhysAddr> for PhysMem {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Live(h) => h.read_bytes(addr, buf),
            Self::Dmp(d) => d.read_bytes(addr, buf),
            Self::Remote(kd) => kd.read_bytes(addr, buf),
        }
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        match self {
            Self::Live(h) => h.write_bytes(addr, buf),
            Self::Dmp(d) => d.write_bytes(addr, buf),
            Self::Remote(kd) => kd.write_bytes(addr, buf),
        }
    }

    fn read_virtual_direct(&self, addr: VirtAddr, root: Dtb, buf: &mut [u8]) -> Option<Result<()>> {
        match self {
            Self::Remote(kd) => kd.read_virtual_direct(addr, root, buf),
            Self::Live(_) | Self::Dmp(_) => None,
        }
    }

    fn translation_cache(&self) -> Option<&TranslationCache> {
        match self {
            Self::Remote(kd) => kd.translation_cache(),
            Self::Live(_) | Self::Dmp(_) => None,
        }
    }
}
