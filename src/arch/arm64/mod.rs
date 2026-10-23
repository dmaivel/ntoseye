//! ARM64 (AArch64).

mod context;
pub mod debug_registers;
pub mod disasm;
pub mod paging;

pub use context::*;

use std::sync::LazyLock;

use crate::base::types::CodeMachine;

use super::registers::{numbered, push_synonyms};
use super::{
    Architecture, ArgumentLocation, ContextFlags, DebugRegisters, Family, IMAGE_FILE_MACHINE_ARM64,
    Paging, RegisterInfo, RegisterMap, ShownRegister, Subregister,
};

pub struct Arm64;

/// The ABI names users type: `fp` and `lr` for `x29` and `x30`, which a
/// listing shows by their ABI names, and `pstate` for `cpsr`.
const REGISTER_SYNONYMS: [(&str, &str); 3] = [("fp", "x29"), ("lr", "x30"), ("cpsr", "pstate")];

impl Architecture for Arm64 {
    fn label(&self) -> &'static str {
        "ARM64"
    }

    fn machine_type(&self) -> u16 {
        IMAGE_FILE_MACHINE_ARM64
    }

    fn gdb_architecture(&self) -> &'static str {
        "aarch64"
    }

    fn pointer_size(&self) -> u64 {
        8
    }

    /// `brk #0xF000`, `0xD43E0000` little-endian.
    fn breakpoint_instruction(&self) -> &'static [u8] {
        &[0x00, 0x00, 0x3e, 0xd4]
    }

    fn dtb_register(&self) -> &'static str {
        "ttbr0"
    }

    fn dtb_page_mask(&self) -> u64 {
        0x0000_FFFF_FFFF_F000
    }

    fn pc_register(&self) -> &'static str {
        "pc"
    }

    fn sp_register(&self) -> &'static str {
        "sp"
    }

    fn frame_register(&self) -> &'static str {
        "fp"
    }

    fn flags_register(&self) -> &'static str {
        "cpsr"
    }

    fn general_registers(&self) -> &'static [&'static str] {
        &GENERAL_REGISTERS
    }

    fn encoded_registers(&self) -> &'static [&'static str] {
        &ENCODED_REGISTERS
    }

    fn encoded_sp(&self) -> Option<u8> {
        None
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
            architecture: CONTEXT_ARM64,
            control: CONTEXT_CONTROL,
            integer: CONTEXT_INTEGER,
            segments: 0,
            floating_point: CONTEXT_FLOATING_POINT,
            debug_registers: CONTEXT_DEBUG_REGISTERS,
            all: CONTEXT_ALL,
        }
    }

    fn register_buffer_size(&self) -> usize {
        REGISTER_BUFFER_SIZE
    }

    /// The synthetic slot KD and dumps fill with TTBR1_EL1, named `cr3` as
    /// on AMD64.
    fn kernel_dtb_register(&self) -> &'static str {
        "cr3"
    }

    fn register_map(&self) -> &'static RegisterMap {
        static MAP: LazyLock<RegisterMap> = LazyLock::new(build_register_map);
        &MAP
    }

    /// `KARM64_SPECIAL_REGISTERS` (160 bytes in the public WoA definition):
    /// the kernel's copies of the hardware breakpoint and watchpoint
    /// registers.
    fn special_register_map(&self) -> &'static RegisterMap {
        static MAP: LazyLock<RegisterMap> = LazyLock::new(|| {
            let bank = |prefix: &'static str, base: usize, size: usize, count: usize| {
                (0..count).map(move |n| (format!("{prefix}{n}"), base + n * size, size))
            };
            RegisterMap::from_layout(
                bank("bvr", 0x28, 8, MAX_BREAKPOINTS)
                    .chain(bank("bcr", 0x68, 4, MAX_BREAKPOINTS))
                    .chain(bank("wvr", 0x88, 8, MAX_WATCHPOINTS))
                    .chain(bank("wcr", 0x98, 4, MAX_WATCHPOINTS)),
            )
        });
        &MAP
    }

    fn context_group(&self, register: &str) -> Option<u32> {
        if numbered(register, "v") || register == "fpcr" || register == "fpsr" {
            Some(CONTEXT_FLOATING_POINT)
        } else if ["bcr", "bvr", "wcr", "wvr"]
            .iter()
            .any(|prefix| numbered(register, prefix))
        {
            Some(CONTEXT_DEBUG_REGISTERS)
        } else {
            None
        }
    }

    fn return_pops_address(&self) -> bool {
        false
    }

    /// The first eight in registers; the rest from the stack pointer up.
    fn argument(&self, index: usize) -> ArgumentLocation {
        match ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"].get(index) {
            Some(register) => ArgumentLocation::Register(register),
            None => ArgumentLocation::Stack(8 * (index as u64 - 8)),
        }
    }

    fn return_register(&self) -> &'static str {
        "x0"
    }

    fn family(&self) -> Family {
        Family::Arm
    }

    fn code_machine(&self) -> CodeMachine {
        CodeMachine::Arm64
    }

    fn compatibility_machine(&self) -> Option<CodeMachine> {
        None
    }

    fn paging(&self) -> &'static dyn Paging {
        &Arm64
    }

    fn debug_registers(&self) -> &'static dyn DebugRegisters {
        &Arm64
    }

    // Windows on ARM runs x64 and x86 code under emulation.
    fn runs_code(&self, machine: CodeMachine) -> bool {
        matches!(
            machine,
            CodeMachine::Arm64 | CodeMachine::Amd64 | CodeMachine::X86
        )
    }

    fn irql_name(&self, irql: u64) -> &'static str {
        match irql {
            0 => "PASSIVE_LEVEL",
            1 => "APC_LEVEL",
            2 => "DISPATCH_LEVEL",
            13 => "CLOCK_LEVEL",
            14 => "IPI_LEVEL",
            15 => "HIGH_LEVEL",
            _ => "DIRQL",
        }
    }

    // The condition flags, then the exception masks.
    fn flag_names(&self, flags: u64) -> Vec<&'static str> {
        const FLAGS: [(u64, &str); 8] = [
            (31, "N"),
            (30, "Z"),
            (29, "C"),
            (28, "V"),
            (9, "D"),
            (8, "A"),
            (7, "I"),
            (6, "F"),
        ];
        FLAGS
            .iter()
            .filter_map(|&(bit, name)| (flags & (1 << bit) != 0).then_some(name))
            .collect()
    }

    fn register_columns(&self) -> usize {
        4
    }

    fn control_registers(&self) -> &'static [&'static [ShownRegister]] {
        CONTROL_REGISTERS
    }

    // w0 through w30, the low halves of x0 through x30.
    fn subregister(&self, name: &str) -> Option<Subregister> {
        let index = name
            .strip_prefix('w')?
            .parse::<usize>()
            .ok()
            .filter(|index| *index < ENCODED_REGISTERS.len())?;
        Some(Subregister {
            register: ENCODED_REGISTERS[index],
            shift: 0,
            bits: 32,
        })
    }

    fn selector_registers(&self) -> &'static [&'static [ShownRegister]] {
        &[]
    }
}

/// The translation table roots, then the fault syndrome and address. The
/// ARM64 maps answer `cr3` with TTBR1_EL1, the kernel's root.
const CONTROL_REGISTERS: &[&[ShownRegister]] = &[
    &[
        ShownRegister::new("ttbr0", "ttbr0", 16),
        ShownRegister::new("ttbr1", "cr3", 16),
    ],
    &[
        ShownRegister::new("esr", "esr", 16),
        ShownRegister::new("far", "far", 16),
    ],
];

/// The register map over a [`REGISTER_BUFFER_SIZE`] buffer: the CONTEXT's
/// registers with their ABI aliases, then the synthetic page-table-root,
/// ESR, and FAR slots behind it.
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

    let mut registers = Vec::new();
    for i in 0..31 {
        registers.push(next_reg(&format!("x{i}"), OFFSET_X0 + i * 8, 8));
    }
    registers.push(next_reg("sp", OFFSET_SP, 8));
    registers.push(next_reg("pc", OFFSET_PC, 8));
    registers.push(next_reg("cpsr", OFFSET_CPSR, 4));
    push_synonyms(&mut registers, &REGISTER_SYNONYMS)
        .expect("CONTEXT carries every register with a synonym");
    for i in 0..32 {
        registers.push(next_reg(&format!("v{i}"), OFFSET_V0 + i * 16, 16));
    }
    registers.push(next_reg("fpcr", OFFSET_FPCR, 4));
    registers.push(next_reg("fpsr", OFFSET_FPSR, 4));
    for i in 0..MAX_BREAKPOINTS {
        registers.push(next_reg(&format!("bcr{i}"), OFFSET_BCR0 + i * 4, 4));
    }
    for i in 0..MAX_BREAKPOINTS {
        registers.push(next_reg(&format!("bvr{i}"), OFFSET_BVR0 + i * 8, 8));
    }
    for i in 0..MAX_WATCHPOINTS {
        registers.push(next_reg(&format!("wcr{i}"), OFFSET_WCR0 + i * 4, 4));
    }
    for i in 0..MAX_WATCHPOINTS {
        registers.push(next_reg(&format!("wvr{i}"), OFFSET_WVR0 + i * 8, 8));
    }
    // Synthetic: kernel DTB (TTBR1_EL1), filled by the backend.
    registers.push(next_reg("cr3", OFFSET_CR3, 8));
    registers.push(next_reg("ttbr0", OFFSET_TTBR0, 8));
    registers.push(next_reg("esr", OFFSET_ESR, 8));
    registers.push(next_reg("far", OFFSET_FAR, 8));

    RegisterMap::from_registers(registers)
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

        let want_sp: u64 = 0xfffffa0f6c6b3770;
        buf[OFFSET_SP..OFFSET_SP + 8].copy_from_slice(&want_sp.to_le_bytes());
        assert_eq!(map.read_u64("sp", &buf).unwrap(), want_sp);

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
    }
}
