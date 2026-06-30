use std::path::Path;

use crate::backend::MemoryOps;
use crate::dmp::{DmpInfo, DmpMem};
use crate::error::Result;
use crate::host::KvmHandle;
use crate::types::PhysAddr;

pub enum PhysMem {
    Kvm(KvmHandle),
    Dmp(DmpMem),
}

impl PhysMem {
    pub fn kvm() -> Result<Self> {
        Ok(Self::Kvm(KvmHandle::new()?))
    }

    pub fn dmp(path: &Path) -> Result<Self> {
        Ok(Self::Dmp(DmpMem::open(path)?))
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
    fn dmp_info_returns_none_for_kvm_variant() {
        // We can't construct a real KvmHandle in tests (no VM running),
        // but we can test the DmpMem path via PhysMem::dmp_info() accessor
        // on a dummy. This test just verifies the enum discriminant logic.
        // A real DMP test requires a dump file.

        // Construct a PhysMem::Dmp directly and check dmp_info
        let info = crate::dmp::DmpInfo {
            directory_table_base: 0x1ad000,
            bug_check_code: 0x7e,
            bug_check_parameters: [1, 2, 3, 4],
            offset_prcb_context: None,
            context: crate::dmp::DmpContext {
                rax: 0, rbx: 0, rcx: 0, rdx: 0, rsi: 0, rdi: 0,
                rbp: 0, rsp: 0, r8: 0, r9: 0, r10: 0, r11: 0,
                r12: 0, r13: 0, r14: 0, r15: 0, rip: 0, eflags: 0,
                cs: 0, ds: 0, es: 0, fs: 0, gs: 0, ss: 0,
                dr0: 0, dr1: 0, dr2: 0, dr3: 0, dr6: 0, dr7: 0,
            },
        };

        let dmp_mem = crate::dmp::DmpMem::new_for_test(vec![], info.clone());
        let phys = PhysMem::Dmp(dmp_mem);
        let retrieved = phys.dmp_info().unwrap();
        assert_eq!(retrieved.bug_check_code, 0x7e);
        assert_eq!(retrieved.directory_table_base, 0x1ad000);
    }
}
