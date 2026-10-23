//! AMD64 (x64).

mod context;
pub mod debug_registers;
pub mod disasm;
pub mod paging;
pub mod prolog;
pub mod unwind;

pub use context::*;

use std::sync::LazyLock;

use crate::base::types::CodeMachine;

use super::registers::{numbered, push_synonyms};
use super::{
    Architecture, ArgumentLocation, ContextFlags, DebugRegisters, Family, IMAGE_FILE_MACHINE_AMD64,
    Paging, RegisterInfo, RegisterMap, ShownRegister, Subregister,
};

pub struct Amd64;

impl Architecture for Amd64 {
    fn label(&self) -> &'static str {
        "AMD64"
    }

    fn machine_type(&self) -> u16 {
        IMAGE_FILE_MACHINE_AMD64
    }

    fn gdb_architecture(&self) -> &'static str {
        "i386:x86-64"
    }

    fn pointer_size(&self) -> u64 {
        8
    }

    fn breakpoint_instruction(&self) -> &'static [u8] {
        &[0xcc]
    }

    fn dtb_register(&self) -> &'static str {
        "cr3"
    }

    fn dtb_page_mask(&self) -> u64 {
        0x000F_FFFF_FFFF_F000
    }

    fn pc_register(&self) -> &'static str {
        "rip"
    }

    fn sp_register(&self) -> &'static str {
        "rsp"
    }

    fn frame_register(&self) -> &'static str {
        "rbp"
    }

    fn flags_register(&self) -> &'static str {
        "eflags"
    }

    fn general_registers(&self) -> &'static [&'static str] {
        &GENERAL_REGISTERS
    }

    fn encoded_registers(&self) -> &'static [&'static str] {
        &ENCODED_REGISTERS
    }

    fn encoded_sp(&self) -> Option<u8> {
        Some(4)
    }

    fn register_synonyms(&self) -> &'static [(&'static str, &'static str)] {
        &REGISTER_SYNONYMS
    }

    fn context_size(&self) -> usize {
        CONTEXT_SIZE
    }

    fn context_flags(&self) -> ContextFlags {
        ContextFlags {
            offset: OFFSET_CONTEXT_FLAGS,
            architecture: CONTEXT_AMD64,
            control: CONTEXT_CONTROL,
            integer: CONTEXT_INTEGER,
            segments: CONTEXT_SEGMENTS,
            floating_point: CONTEXT_FLOATING_POINT,
            debug_registers: CONTEXT_DEBUG_REGISTERS,
            all: CONTEXT_ALL,
        }
    }

    fn register_buffer_size(&self) -> usize {
        REGISTER_BUFFER_SIZE
    }

    fn kernel_dtb_register(&self) -> &'static str {
        "cr3"
    }

    fn register_map(&self) -> &'static RegisterMap {
        static MAP: LazyLock<RegisterMap> = LazyLock::new(build_register_map);
        &MAP
    }

    fn special_register_map(&self) -> &'static RegisterMap {
        static MAP: LazyLock<RegisterMap> = LazyLock::new(|| {
            RegisterMap::from_layout(
                (0..4).map(|n| (format!("dr{n}"), 0x20 + n * 8, 8)).chain(
                    [
                        ("cr0", 0x00, 8),
                        ("cr2", 0x08, 8),
                        ("cr3", 0x10, 8),
                        ("cr4", 0x18, 8),
                        ("dr6", 0x40, 8),
                        ("dr7", 0x48, 8),
                        // A KDESCRIPTOR is Pad[3], Limit, Base.
                        ("gdtr_limit", 0x56, 2),
                        ("gdtr_base", 0x58, 8),
                        ("idtr_limit", 0x66, 2),
                        ("idtr_base", 0x68, 8),
                        ("tr", 0x70, 2),
                        ("ldtr", 0x72, 2),
                        ("cr8", 0xa0, 8),
                    ]
                    .map(|(name, offset, size)| (name.to_string(), offset, size)),
                ),
            )
        });
        &MAP
    }

    fn context_group(&self, register: &str) -> Option<u32> {
        if ["ds", "es", "fs", "gs"].contains(&register) {
            Some(CONTEXT_SEGMENTS)
        } else if numbered(register, "dr") {
            Some(CONTEXT_DEBUG_REGISTERS)
        } else if numbered(register, "xmm") || register == "mxcsr" {
            Some(CONTEXT_FLOATING_POINT)
        } else {
            None
        }
    }

    fn return_pops_address(&self) -> bool {
        true
    }

    /// The first four in registers; the rest above the return address and
    /// the four registers' shadow space.
    fn argument(&self, index: usize) -> ArgumentLocation {
        match ["rcx", "rdx", "r8", "r9"].get(index) {
            Some(register) => ArgumentLocation::Register(register),
            None => ArgumentLocation::Stack(0x28 + 8 * (index as u64 - 4)),
        }
    }

    fn return_register(&self) -> &'static str {
        "rax"
    }

    fn family(&self) -> Family {
        Family::X86
    }

    fn code_machine(&self) -> CodeMachine {
        CodeMachine::Amd64
    }

    fn compatibility_machine(&self) -> Option<CodeMachine> {
        Some(CodeMachine::X86)
    }

    fn paging(&self) -> &'static dyn Paging {
        &Amd64
    }

    fn debug_registers(&self) -> &'static dyn DebugRegisters {
        &Amd64
    }

    fn runs_code(&self, machine: CodeMachine) -> bool {
        matches!(machine, CodeMachine::Amd64 | CodeMachine::X86)
    }

    fn irql_name(&self, irql: u64) -> &'static str {
        match irql {
            0 => "PASSIVE_LEVEL",
            1 => "APC_LEVEL",
            2 => "DISPATCH_LEVEL",
            5 => "CMCI_LEVEL",
            13 => "CLOCK_LEVEL",
            14 => "IPI_LEVEL",
            15 => "HIGH_LEVEL",
            _ => "DIRQL",
        }
    }

    fn flag_names(&self, flags: u64) -> Vec<&'static str> {
        const FLAGS: [(u64, &str); 16] = [
            (0, "CF"),
            (2, "PF"),
            (4, "AF"),
            (6, "ZF"),
            (7, "SF"),
            (8, "TF"),
            (9, "IF"),
            (10, "DF"),
            (11, "OF"),
            (14, "NT"),
            (16, "RF"),
            (17, "VM"),
            (18, "AC"),
            (19, "VIF"),
            (20, "VIP"),
            (21, "ID"),
        ];
        let mut names: Vec<&str> = FLAGS
            .iter()
            .filter_map(|&(bit, name)| (flags & (1 << bit) != 0).then_some(name))
            .collect();
        // The I/O privilege level is a two-bit field, not a flag.
        match (flags >> 12) & 0x3 {
            0 => {}
            1 => names.push("IOPL1"),
            2 => names.push("IOPL2"),
            _ => names.push("IOPL3"),
        }
        names
    }

    fn register_columns(&self) -> usize {
        3
    }

    fn control_registers(&self) -> &'static [&'static [ShownRegister]] {
        CONTROL_REGISTERS
    }

    fn subregister(&self, name: &str) -> Option<Subregister> {
        if let Some(&(_, register, shift, bits)) =
            SUBREGISTERS.iter().find(|(alias, ..)| *alias == name)
        {
            return Some(Subregister {
                register,
                shift,
                bits,
            });
        }
        // r8d, r8w and r8b through r15.
        let rest = name.strip_prefix('r')?;
        let (number, suffix) = rest.split_at_checked(rest.len().checked_sub(1)?)?;
        let bits = match suffix {
            "d" => 32,
            "w" => 16,
            "b" => 8,
            _ => return None,
        };
        let index = number
            .parse::<usize>()
            .ok()
            .filter(|index| (8..16).contains(index))?;
        Some(Subregister {
            register: ENCODED_REGISTERS[index],
            shift: 0,
            bits,
        })
    }

    fn selector_registers(&self) -> &'static [&'static [ShownRegister]] {
        SELECTOR_REGISTERS
    }
}

/// The named parts of the general registers: `(name, register, shift, bits)`.
const SUBREGISTERS: [(&str, &str, u32, u32); 29] = [
    ("eax", "rax", 0, 32),
    ("ax", "rax", 0, 16),
    ("al", "rax", 0, 8),
    ("ah", "rax", 8, 8),
    ("ebx", "rbx", 0, 32),
    ("bx", "rbx", 0, 16),
    ("bl", "rbx", 0, 8),
    ("bh", "rbx", 8, 8),
    ("ecx", "rcx", 0, 32),
    ("cx", "rcx", 0, 16),
    ("cl", "rcx", 0, 8),
    ("ch", "rcx", 8, 8),
    ("edx", "rdx", 0, 32),
    ("dx", "rdx", 0, 16),
    ("dl", "rdx", 0, 8),
    ("dh", "rdx", 8, 8),
    ("esi", "rsi", 0, 32),
    ("si", "rsi", 0, 16),
    ("sil", "rsi", 0, 8),
    ("edi", "rdi", 0, 32),
    ("di", "rdi", 0, 16),
    ("dil", "rdi", 0, 8),
    ("esp", "rsp", 0, 32),
    ("sp", "rsp", 0, 16),
    ("spl", "rsp", 0, 8),
    ("ebp", "rbp", 0, 32),
    ("bp", "rbp", 0, 16),
    ("bpl", "rbp", 0, 8),
    ("eip", "rip", 0, 32),
];

const CONTROL_REGISTERS: &[&[ShownRegister]] = &[
    &[
        ShownRegister::new("cr0", "cr0", 16),
        ShownRegister::new("cr2", "cr2", 16),
        ShownRegister::new("cr3", "cr3", 16),
    ],
    &[
        ShownRegister::new("cr4", "cr4", 16),
        ShownRegister::new("cr8", "cr8", 16),
    ],
];

/// The segment selectors, 16 bits wide.
const SELECTOR_REGISTERS: &[&[ShownRegister]] = &[
    &[
        ShownRegister::new("cs", "cs", 4),
        ShownRegister::new("ds", "ds", 4),
        ShownRegister::new("es", "es", 4),
    ],
    &[
        ShownRegister::new("fs", "fs", 4),
        ShownRegister::new("gs", "gs", 4),
        ShownRegister::new("ss", "ss", 4),
    ],
];

/// Pairs of names for one register: the one a listing shows, then the one
/// the `CONTEXT` names it by.
const REGISTER_SYNONYMS: [(&str, &str); 1] = [("rfl", "eflags")];

/// The register map over a [`REGISTER_BUFFER_SIZE`] buffer: the CONTEXT's
/// registers, then the synthetic control and descriptor-table slots behind it.
fn build_register_map() -> RegisterMap {
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
        // KDESCRIPTOR values come from KSPECIAL_REGISTERS. Keep WinDbg names
        // alongside the explicit names used by the register display.
        next_reg("gdtr", OFFSET_GDTR_BASE, 8),
        next_reg("gdtr_base", OFFSET_GDTR_BASE, 8),
        next_reg("gdtr_limit", OFFSET_GDTR_LIMIT, 2),
        next_reg("gdtl", OFFSET_GDTR_LIMIT, 2),
        next_reg("idtr", OFFSET_IDTR_BASE, 8),
        next_reg("idtr_base", OFFSET_IDTR_BASE, 8),
        next_reg("idtr_limit", OFFSET_IDTR_LIMIT, 2),
        next_reg("idtl", OFFSET_IDTR_LIMIT, 2),
        next_reg("tr", OFFSET_TR, 2),
        next_reg("ldtr", OFFSET_LDTR, 2),
        // EFER is not part of KSPECIAL_REGISTERS; KD fills this synthetic
        // slot with DbgKdReadMachineSpecificRegister(MSR_EFER).
        next_reg("efer", OFFSET_EFER, 8),
        next_reg("mxcsr", OFFSET_MX_CSR, 4),
    ];

    let mut registers = registers;
    push_synonyms(&mut registers, &REGISTER_SYNONYMS)
        .expect("CONTEXT carries every register with a synonym");
    for i in 0..16 {
        let offset = OFFSET_XMM0 + i * 16;
        registers.push(next_reg(&format!("xmm{i}"), offset, 16));
        registers.push(next_reg(&format!("xmm{i}l"), offset, 8));
        registers.push(next_reg(&format!("xmm{i}h"), offset + 8, 8));
    }

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
