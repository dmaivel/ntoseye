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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmp::{DmpContext, DmpInfo, DmpMem};

    #[test]
    fn dmp_info_exposed_for_dmp_variant() {
        let info = DmpInfo {
            directory_table_base: 0x1ad000,
            bug_check_code: 0x7e,
            bug_check_parameters: [1, 2, 3, 4],
            offset_prcb_context: None,
            number_processors: 1,
            is_triage: false,
            ps_loaded_module_list: 0,
            ps_active_process_head: 0,
            debugger_data_block: None,
            triage_drivers: Vec::new(),
            exception: None,
            system_info: None,
            unloaded_drivers: Vec::new(),
            blackbox_streams: Vec::new(),
            triage_process_snapshot: None,
            triage_thread_snapshot: None,
            triage_prcb_info: None,
            broken_driver: None,
            triage_overflowed: false,
            kern_base: None,
            context: DmpContext {
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                rbp: 0,
                rsp: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: 0,
                eflags: 0,
                cs: 0,
                ds: 0,
                es: 0,
                fs: 0,
                gs: 0,
                ss: 0,
                dr0: 0,
                dr1: 0,
                dr2: 0,
                dr3: 0,
                dr6: 0,
                dr7: 0,
                mxcsr: 0,
                xmm: [0; 16],
                debug_control: 0,
                last_branch_to_rip: 0,
                last_branch_from_rip: 0,
                last_exception_to_rip: 0,
                last_exception_from_rip: 0,
            },
        };

        let phys = PhysMem::Dmp(Box::new(DmpMem::new_for_test(vec![], info)));
        let retrieved = phys.dmp_info().unwrap();
        assert_eq!(retrieved.bug_check_code, 0x7e);
        assert_eq!(retrieved.directory_table_base, 0x1ad000);
    }
}
