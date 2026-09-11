//! ARM64 `CONTEXT` offsets. Layout reference: the public `ARM64_NT_CONTEXT`
//! (winnt.h):
//!
//! ```text
//! ContextFlags @ 0x000 (u32), Cpsr @ 0x004 (u32)
//! X[31]        @ 0x008 .. 0x0F8   (X0-X28, Fp=X29, Lr=X30)
//! Sp           @ 0x100
//! Pc           @ 0x108
//! V[32]        @ 0x110 .. 0x30F   (16 bytes each)
//! Fpcr         @ 0x310 (u32), Fpsr @ 0x314 (u32)
//! Bcr[8]       @ 0x318, Bvr[8] @ 0x338, Wcr[2] @ 0x378, Wvr[2] @ 0x380
//! ```
//!
//! The KD transport returns this same layout for `DBGKD_GET_CONTEXT`. A
//! synthetic kernel-DTB slot (TTBR1_EL1, exposed as `cr3`) is appended after
//! the CONTEXT and filled from the session's resolved kernel page-table root,
//! mirroring how the AMD64 map appends CR0-CR8 from KSPECIAL_REGISTERS.

use crate::gdb::{RegisterInfo, RegisterMap};

pub const CONTEXT_SIZE: usize = 0x390; // 912

/// CONTEXT plus the synthetic kernel-DTB slot.
pub const REGISTER_BUFFER_SIZE: usize = CONTEXT_SIZE + 8;

// ContextFlags bits
pub const CONTEXT_ARM64: u32 = 0x0040_0000;
pub const CONTEXT_CONTROL: u32 = CONTEXT_ARM64 | 0x0000_0001;
pub const CONTEXT_INTEGER: u32 = CONTEXT_ARM64 | 0x0000_0002;
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_ARM64 | 0x0000_0004;
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_ARM64 | 0x0000_0008;
pub const CONTEXT_ARM64_X18: u32 = CONTEXT_ARM64 | 0x0000_0010;
pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
pub const CONTEXT_ALL: u32 = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS | CONTEXT_ARM64_X18;

pub const OFFSET_CONTEXT_FLAGS: usize = 0x000;
pub const OFFSET_CPSR: usize = 0x004;
pub const OFFSET_X0: usize = 0x008;
pub const OFFSET_SP: usize = 0x100;
pub const OFFSET_PC: usize = 0x108;
pub const OFFSET_V0: usize = 0x110;
pub const OFFSET_FPCR: usize = 0x310;
pub const OFFSET_FPSR: usize = 0x314;

// Synthetic kernel-DTB slot appended after CONTEXT (TTBR1_EL1)
pub const OFFSET_CR3: usize = CONTEXT_SIZE;

/// Build the KD register map for an ARM64 target.
pub fn build_register_map() -> RegisterMap {
    let mut regnum = 0usize;
    let mut next_reg = |name: &str, offset: usize, size: usize| -> RegisterInfo {
        let info = RegisterInfo {
            name: name.to_string(),
            offset,
            size,
            regnum,
        };
        regnum += 1;
        info
    };

    let mut registers = Vec::new();
    for i in 0..31 {
        registers.push(next_reg(&format!("x{i}"), OFFSET_X0 + i * 8, 8));
    }
    // Aliases upper layers read by x64 names ("rip" everywhere, "rsp" in
    // expr), plus the ABI names for display.
    registers.push(next_reg("fp", OFFSET_X0 + 29 * 8, 8));
    registers.push(next_reg("lr", OFFSET_X0 + 30 * 8, 8));
    registers.push(next_reg("sp", OFFSET_SP, 8));
    registers.push(next_reg("rsp", OFFSET_SP, 8));
    registers.push(next_reg("pc", OFFSET_PC, 8));
    registers.push(next_reg("rip", OFFSET_PC, 8));
    registers.push(next_reg("cpsr", OFFSET_CPSR, 4));
    registers.push(next_reg("pstate", OFFSET_CPSR, 4));
    for i in 0..32 {
        registers.push(next_reg(&format!("v{i}"), OFFSET_V0 + i * 16, 16));
    }
    registers.push(next_reg("fpcr", OFFSET_FPCR, 4));
    registers.push(next_reg("fpsr", OFFSET_FPSR, 4));
    // Synthetic: kernel DTB (TTBR1_EL1), filled by the backend.
    registers.push(next_reg("cr3", OFFSET_CR3, 8));

    let mut map = RegisterMap::from_registers(registers);
    map.set_breakpoint_step_size(4);
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_register_map_reads_known_offsets() {
        let map = build_register_map();
        let mut buf = vec![0u8; REGISTER_BUFFER_SIZE];

        let want_pc: u64 = 0xfffff80012345678;
        buf[OFFSET_PC..OFFSET_PC + 8].copy_from_slice(&want_pc.to_le_bytes());
        assert_eq!(map.read_u64("pc", &buf).unwrap(), want_pc);
        assert_eq!(map.read_u64("rip", &buf).unwrap(), want_pc);

        let want_sp: u64 = 0xfffffa0f6c6b3770;
        buf[OFFSET_SP..OFFSET_SP + 8].copy_from_slice(&want_sp.to_le_bytes());
        assert_eq!(map.read_u64("sp", &buf).unwrap(), want_sp);
        assert_eq!(map.read_u64("rsp", &buf).unwrap(), want_sp);

        let want_x0: u64 = 0x1122334455667788;
        buf[OFFSET_X0..OFFSET_X0 + 8].copy_from_slice(&want_x0.to_le_bytes());
        assert_eq!(map.read_u64("x0", &buf).unwrap(), want_x0);

        let want_fp: u64 = 0xaaaabbbbccccdddd;
        buf[OFFSET_X0 + 29 * 8..OFFSET_X0 + 30 * 8].copy_from_slice(&want_fp.to_le_bytes());
        assert_eq!(map.read_u64("fp", &buf).unwrap(), want_fp);

        let want_cr3: u64 = 0x1234_5000;
        map.write_u64("cr3", &mut buf, want_cr3).unwrap();
        assert_eq!(map.read_u64("cr3", &buf).unwrap(), want_cr3);

        assert_eq!(map.breakpoint_step_size(), 4);
    }
}
