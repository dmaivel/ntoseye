use std::path::Path;

use crate::backend::MemoryOps;
use crate::dmp::{DmpInfo, DmpMem};
use crate::error::Result;
use crate::host::KvmHandle;
use crate::types::PhysAddr;

/// Guest physical memory, backed either by a live VM (via /dev/kvm) or by a
/// crash dump file. Built once at attach and shared via `Arc`; everything above
/// (address spaces, symbol loading, unwinding) reads through it. `Dmp` is boxed
/// for the variant size imbalance, not that it matters for a one-off.
pub enum PhysMem {
    Kvm(KvmHandle),
    Dmp(Box<DmpMem>),
}

impl PhysMem {
    pub fn kvm() -> Result<Self> {
        Ok(Self::Kvm(KvmHandle::new()?))
    }

    pub fn dmp(path: &Path) -> Result<Self> {
        Ok(Self::Dmp(Box::new(DmpMem::open(path)?)))
    }

    pub fn dmp_info(&self) -> Option<&DmpInfo> {
        match self {
            Self::Dmp(d) => Some(d.info()),
            _ => None,
        }
    }
}

impl MemoryOps<PhysAddr> for PhysMem {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        match self {
            Self::Kvm(h) => h.read_bytes(addr, buf),
            Self::Dmp(d) => d.read_bytes(addr, buf),
        }
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        match self {
            Self::Kvm(h) => h.write_bytes(addr, buf),
            Self::Dmp(d) => d.write_bytes(addr, buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dmp_info_exposed_for_dmp_variant() {
        let info = crate::dmp::DmpInfo {
            directory_table_base: 0x1ad000,
            bug_check_code: 0x7e,
            bug_check_parameters: [1, 2, 3, 4],
            offset_prcb_context: None,
            number_processors: 1,
            context: crate::dmp::DmpContext {
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
            },
        };

        let phys = PhysMem::Dmp(Box::new(crate::dmp::DmpMem::new_for_test(vec![], info)));
        let retrieved = phys.dmp_info().unwrap();
        assert_eq!(retrieved.bug_check_code, 0x7e);
        assert_eq!(retrieved.directory_table_base, 0x1ad000);
    }
}
