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

use std::ops::Range;

use super::unwind::LR;

pub const CONTEXT_SIZE: usize = 0x390; // 912

/// The hardware breakpoint and watchpoint register pairs a `CONTEXT`
/// carries (`ARM64_MAX_BREAKPOINTS`, `ARM64_MAX_WATCHPOINTS`), part of the
/// Windows ARM64 ABI.
pub const MAX_BREAKPOINTS: usize = 8;
pub const MAX_WATCHPOINTS: usize = 2;

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

/// The general registers in the order the register grid and a step's
/// changed-register line show them, flags last.
pub const GENERAL_REGISTERS: [&str; 34] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "fp", "lr", "sp", "pc", "cpsr",
];

/// The integer registers in the order the instruction set numbers them
/// (x0–x30), which is how unwind codes name them.
pub const ENCODED_REGISTERS: [&str; 31] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30",
];

/// The registers a call clobbers, by their [`ENCODED_REGISTERS`] number:
/// x0–x17 carry arguments, results, and scratch values. x18 is the platform
/// register (the KPCR in kernel mode) and survives calls.
pub const VOLATILE_REGISTERS: Range<usize> = 0..18;

/// The ARM64 register each x64 register lives in during ARM64EC code, by
/// x64 unwind number (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8–r15). rsp
/// is sp, which the walk keeps as `rsp` on either machine.
pub const X64_IN_ARM64: [Option<usize>; 16] = [
    Some(8),
    Some(0),
    Some(1),
    Some(27),
    None,
    Some(29),
    Some(25),
    Some(26),
    Some(2),
    Some(3),
    Some(4),
    Some(5),
    Some(19),
    Some(20),
    Some(21),
    Some(22),
];

/// Whether an x64 frame of ARM64EC code leaves `arm64` (an
/// [`ENCODED_REGISTERS`] number) unknown: a register a call clobbers, or
/// lr, which an x64 frame neither saves nor restores.
pub fn clobbered_by_x64_frame(arm64: usize) -> bool {
    VOLATILE_REGISTERS.contains(&arm64) || arm64 == LR
}
