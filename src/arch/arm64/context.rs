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
