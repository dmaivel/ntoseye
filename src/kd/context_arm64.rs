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
//! synthetic kernel-DTB, process-DTB, ESR, and FAR slots are appended after
//! the CONTEXT. The roots are filled from the session's resolved page-table
//! state and the stopped processor's system registers when available,
//! mirroring how the AMD64 map appends CR0-CR8 from KSPECIAL_REGISTERS.

use crate::gdb::{RegisterInfo, RegisterMap};

pub const CONTEXT_SIZE: usize = 0x390; // 912

/// CONTEXT plus synthetic kernel-DTB, process-DTB, ESR, and FAR slots.
pub const REGISTER_BUFFER_SIZE: usize = CONTEXT_SIZE + 32;

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
pub const OFFSET_BCR0: usize = 0x318;
pub const OFFSET_BVR0: usize = 0x338;
pub const OFFSET_WCR0: usize = 0x378;
pub const OFFSET_WVR0: usize = 0x380;

// Synthetic control-register slots appended after CONTEXT. `cr3` exposes the
// kernel root (TTBR1_EL1); `ttbr0` is the process/user root used for ARM64
// process-scoped breakpoints. ESR/FAR are populated from the stopped
// processor's system registers when available.
pub const OFFSET_CR3: usize = CONTEXT_SIZE;
pub const OFFSET_TTBR0: usize = OFFSET_CR3 + 8;
pub const OFFSET_ESR: usize = OFFSET_TTBR0 + 8;
pub const OFFSET_FAR: usize = OFFSET_ESR + 8;

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
    for i in 0..8 {
        registers.push(next_reg(&format!("bcr{i}"), OFFSET_BCR0 + i * 4, 4));
    }
    for i in 0..8 {
        registers.push(next_reg(&format!("bvr{i}"), OFFSET_BVR0 + i * 8, 8));
    }
    for i in 0..2 {
        registers.push(next_reg(&format!("wcr{i}"), OFFSET_WCR0 + i * 4, 4));
    }
    for i in 0..2 {
        registers.push(next_reg(&format!("wvr{i}"), OFFSET_WVR0 + i * 8, 8));
    }
    // Synthetic: kernel DTB (TTBR1_EL1), filled by the backend.
    registers.push(next_reg("cr3", OFFSET_CR3, 8));
    registers.push(next_reg("ttbr0", OFFSET_TTBR0, 8));
    registers.push(next_reg("esr", OFFSET_ESR, 8));
    registers.push(next_reg("far", OFFSET_FAR, 8));

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

        let want_bcr: u32 = 0x0000_e9e1;
        buf[OFFSET_BCR0..OFFSET_BCR0 + 4].copy_from_slice(&want_bcr.to_le_bytes());
        assert_eq!(map.read_u64("bcr0", &buf).unwrap(), want_bcr as u64);
        let want_wvr: u64 = 0x8877_6655_4433_2211;
        buf[OFFSET_WVR0..OFFSET_WVR0 + 8].copy_from_slice(&want_wvr.to_le_bytes());
        assert_eq!(map.read_u64("wvr0", &buf).unwrap(), want_wvr);

        assert_eq!(map.breakpoint_step_size(), 4);
    }
}
