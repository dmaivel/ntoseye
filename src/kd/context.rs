//! AMD64 `CONTEXT` offsets. Layout reference: ReactOS `sdk/include/xdk/amd64/ke.h`

use crate::gdb::{RegisterInfo, RegisterMap};

pub const CONTEXT_SIZE: usize = 1232;

/// CONTEXT plus synthetic control-register slots
pub const REGISTER_BUFFER_SIZE: usize = CONTEXT_SIZE + 5 * 8;

// ContextFlags bits
pub const CONTEXT_AMD64: u32 = 0x0010_0000;
pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x0000_0001;
pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x0000_0002;
pub const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x0000_0004;
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x0000_0008;
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x0000_0010;
pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
pub const CONTEXT_ALL: u32 = CONTEXT_CONTROL
    | CONTEXT_INTEGER
    | CONTEXT_SEGMENTS
    | CONTEXT_FLOATING_POINT
    | CONTEXT_DEBUG_REGISTERS;

pub const OFFSET_CONTEXT_FLAGS: usize = 0x30;
pub const OFFSET_MX_CSR: usize = 0x34;
pub const OFFSET_SEG_CS: usize = 0x38;
pub const OFFSET_SEG_DS: usize = 0x3A;
pub const OFFSET_SEG_ES: usize = 0x3C;
pub const OFFSET_SEG_FS: usize = 0x3E;
pub const OFFSET_SEG_GS: usize = 0x40;
pub const OFFSET_SEG_SS: usize = 0x42;
pub const OFFSET_EFLAGS: usize = 0x44;
pub const OFFSET_DR0: usize = 0x48;
pub const OFFSET_DR1: usize = 0x50;
pub const OFFSET_DR2: usize = 0x58;
pub const OFFSET_DR3: usize = 0x60;
pub const OFFSET_DR6: usize = 0x68;
pub const OFFSET_DR7: usize = 0x70;
pub const OFFSET_RAX: usize = 0x78;
pub const OFFSET_RCX: usize = 0x80;
pub const OFFSET_RDX: usize = 0x88;
pub const OFFSET_RBX: usize = 0x90;
pub const OFFSET_RSP: usize = 0x98;
pub const OFFSET_RBP: usize = 0xA0;
pub const OFFSET_RSI: usize = 0xA8;
pub const OFFSET_RDI: usize = 0xB0;
pub const OFFSET_R8: usize = 0xB8;
pub const OFFSET_R9: usize = 0xC0;
pub const OFFSET_R10: usize = 0xC8;
pub const OFFSET_R11: usize = 0xD0;
pub const OFFSET_R12: usize = 0xD8;
pub const OFFSET_R13: usize = 0xE0;
pub const OFFSET_R14: usize = 0xE8;
pub const OFFSET_R15: usize = 0xF0;
pub const OFFSET_RIP: usize = 0xF8;
pub const OFFSET_XMM0: usize = 0x1A0;
pub const OFFSET_DEBUG_CONTROL: usize = 0x4A8;
pub const OFFSET_LAST_BRANCH_TO_RIP: usize = 0x4B0;
pub const OFFSET_LAST_BRANCH_FROM_RIP: usize = 0x4B8;
pub const OFFSET_LAST_EXCEPTION_TO_RIP: usize = 0x4C0;
pub const OFFSET_LAST_EXCEPTION_FROM_RIP: usize = 0x4C8;

// Synthetic control-register slots appended after CONTEXT
pub const OFFSET_CR0: usize = CONTEXT_SIZE;
pub const OFFSET_CR2: usize = OFFSET_CR0 + 8;
pub const OFFSET_CR3: usize = OFFSET_CR2 + 8;
pub const OFFSET_CR4: usize = OFFSET_CR3 + 8;
pub const OFFSET_CR8: usize = OFFSET_CR4 + 8;

/// Build the KD register map
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

    let registers = vec![
        next_reg("rax", OFFSET_RAX, 8),
        next_reg("rbx", OFFSET_RBX, 8),
        next_reg("rcx", OFFSET_RCX, 8),
        next_reg("rdx", OFFSET_RDX, 8),
        next_reg("rsi", OFFSET_RSI, 8),
        next_reg("rdi", OFFSET_RDI, 8),
        next_reg("rbp", OFFSET_RBP, 8),
        next_reg("rsp", OFFSET_RSP, 8),
        next_reg("r8", OFFSET_R8, 8),
        next_reg("r9", OFFSET_R9, 8),
        next_reg("r10", OFFSET_R10, 8),
        next_reg("r11", OFFSET_R11, 8),
        next_reg("r12", OFFSET_R12, 8),
        next_reg("r13", OFFSET_R13, 8),
        next_reg("r14", OFFSET_R14, 8),
        next_reg("r15", OFFSET_R15, 8),
        next_reg("rip", OFFSET_RIP, 8),
        // EFlags is 4 bytes in CONTEXT
        next_reg("eflags", OFFSET_EFLAGS, 4),
        next_reg("cs", OFFSET_SEG_CS, 2),
        next_reg("ss", OFFSET_SEG_SS, 2),
        next_reg("ds", OFFSET_SEG_DS, 2),
        next_reg("es", OFFSET_SEG_ES, 2),
        next_reg("fs", OFFSET_SEG_FS, 2),
        next_reg("gs", OFFSET_SEG_GS, 2),
        // Debug registers (native CONTEXT fields; GetContext/SetContext use
        // CONTEXT_ALL, which includes CONTEXT_DEBUG_REGISTERS, so these
        // round-trip). dr6 is the #DB status, dr7 the control word; dr0-dr3
        // hold the linear breakpoint addresses.
        next_reg("dr0", OFFSET_DR0, 8),
        next_reg("dr1", OFFSET_DR1, 8),
        next_reg("dr2", OFFSET_DR2, 8),
        next_reg("dr3", OFFSET_DR3, 8),
        next_reg("dr6", OFFSET_DR6, 8),
        next_reg("dr7", OFFSET_DR7, 8),
        // Control registers come from AMD64 KSpecialRegisters
        next_reg("cr0", OFFSET_CR0, 8),
        next_reg("cr2", OFFSET_CR2, 8),
        next_reg("cr3", OFFSET_CR3, 8),
        next_reg("cr4", OFFSET_CR4, 8),
        next_reg("cr8", OFFSET_CR8, 8),
    ];

    RegisterMap::from_registers(registers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_map_reads_known_offsets() {
        let map = build_register_map();
        let mut buf = vec![0u8; CONTEXT_SIZE];

        let want_rip: u64 = 0xfffff80000123456;
        buf[OFFSET_RIP..OFFSET_RIP + 8].copy_from_slice(&want_rip.to_le_bytes());
        assert_eq!(map.read_u64("rip", &buf).unwrap(), want_rip);

        let want_rsp: u64 = 0xdeadbeef_cafebabe;
        buf[OFFSET_RSP..OFFSET_RSP + 8].copy_from_slice(&want_rsp.to_le_bytes());
        assert_eq!(map.read_u64("rsp", &buf).unwrap(), want_rsp);

        let want_cr3: u64 = 0x1234_5000;
        let mut extended = vec![0u8; REGISTER_BUFFER_SIZE];
        extended[OFFSET_CR3..OFFSET_CR3 + 8].copy_from_slice(&want_cr3.to_le_bytes());
        assert_eq!(map.read_u64("cr3", &extended).unwrap(), want_cr3);
    }

    #[test]
    fn register_map_round_trips_writes() {
        let map = build_register_map();
        let mut buf = vec![0u8; CONTEXT_SIZE];

        map.write_u64("rip", &mut buf, 0x1234_5678_9abc_def0)
            .unwrap();
        assert_eq!(
            &buf[OFFSET_RIP..OFFSET_RIP + 8],
            &0x1234_5678_9abc_def0u64.to_le_bytes()
        );

        buf[OFFSET_EFLAGS + 4] = 0xff;
        map.write_u64("eflags", &mut buf, 0x202).unwrap();
        assert_eq!(
            &buf[OFFSET_EFLAGS..OFFSET_EFLAGS + 4],
            &0x202u32.to_le_bytes()
        );
        assert_eq!(buf[OFFSET_EFLAGS + 4], 0xff, "wrote past register width");
    }
}
