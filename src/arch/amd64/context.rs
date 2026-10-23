//! AMD64 `CONTEXT` offsets. Layout reference: ReactOS `sdk/include/xdk/amd64/ke.h`

pub const CONTEXT_SIZE: usize = 1232;

/// CONTEXT plus synthetic control/special-register slots. The descriptor
/// limits and segment selectors occupy their own 8-byte slots so every
/// synthetic value has a stable, naturally aligned offset in the register
/// buffer even though KD's `KDESCRIPTOR` fields are smaller on the wire.
pub const REGISTER_BUFFER_SIZE: usize = CONTEXT_SIZE + 12 * 8;

// ContextFlags bits
pub const CONTEXT_AMD64: u32 = 0x0010_0000;
pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x0000_0001;
pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x0000_0002;
pub const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x0000_0004;
pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x0000_0008;
pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x0000_0010;
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
pub const OFFSET_GDTR_BASE: usize = OFFSET_CR8 + 8;
pub const OFFSET_GDTR_LIMIT: usize = OFFSET_GDTR_BASE + 8;
pub const OFFSET_IDTR_BASE: usize = OFFSET_GDTR_LIMIT + 8;
pub const OFFSET_IDTR_LIMIT: usize = OFFSET_IDTR_BASE + 8;
pub const OFFSET_TR: usize = OFFSET_IDTR_LIMIT + 8;
pub const OFFSET_LDTR: usize = OFFSET_TR + 8;
pub const OFFSET_EFER: usize = OFFSET_LDTR + 8;

/// The general registers in the order the register grid and a step's
/// changed-register line show them, flags last.
pub const GENERAL_REGISTERS: [&str; 18] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "r8", "r9", "r10", "r11", "r12",
    "r13", "r14", "r15", "eflags",
];

/// The integer registers in the order the instruction set numbers them,
/// which is how unwind codes name them.
pub const ENCODED_REGISTERS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// The registers a call clobbers (rax, rcx, rdx, r8–r11), by their
/// [`ENCODED_REGISTERS`] number.
pub const VOLATILE_REGISTERS: [usize; 7] = [0, 1, 2, 8, 9, 10, 11];
