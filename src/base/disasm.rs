use std::fmt::Write as _;

use ntoseye_macros::record;

use crate::base::types::CodeMachine;

/// Control-flow class for the instruction at the start of a byte buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlFlow {
    Call,
    Ret,
    Branch,
    Other,
}

/// How code of one instruction set decodes, flows and reads; a
/// [`CodeMachine`] names it. The functions of this module ask it.
pub trait InstructionSet: Sync {
    /// The first instruction's length and control flow, or `None` for
    /// invalid or incomplete bytes.
    fn decode_first(&self, bytes: &[u8]) -> Option<(usize, ControlFlow)>;

    /// The instruction at the start of `bytes`, mapped at `ip`: the address
    /// after it, and how a walk of its function goes on past it.
    fn walk_step(&self, bytes: &[u8], ip: u64) -> Option<(u64, Flow)>;

    /// Up to `limit` instructions of `bytes`, loaded at `ip`, as rows.
    /// `resolve` turns a branch or PC-relative target into a symbol comment.
    fn decode_rows(
        &self,
        bytes: &[u8],
        ip: u64,
        limit: Option<usize>,
        resolve: &dyn Fn(u64) -> String,
    ) -> Vec<DisasmRow>;

    /// The lowercase mnemonic of the instruction `bytes` encode at `ip`,
    /// without prefixes.
    fn mnemonic(&self, bytes: &[u8], ip: u64) -> String;

    /// The explicit operands of the instruction `bytes` encode at `ip`, in
    /// instruction order.
    fn operands(&self, bytes: &[u8], ip: u64) -> Vec<DisasmOperand>;

    /// See [`instruction_containing`].
    fn instruction_containing(&self, bytes: &[u8], start: u64, ip: u64) -> Option<u64>;

    /// See [`decode_preceding`].
    fn decode_preceding(
        &self,
        bytes: &[u8],
        read_start: u64,
        end_addr: u64,
        count: usize,
        resolve: &dyn Fn(u64) -> String,
    ) -> Option<Vec<DisasmRow>>;
}

/// The longest instruction any instruction set encodes (x86's 15 bytes).
const MAX_INSTRUCTION_BYTES: usize = 16;

/// The first instruction's length and control flow, or `None` for invalid
/// or incomplete bytes.
pub fn decode_first(bytes: &[u8], machine: CodeMachine) -> Option<(usize, ControlFlow)> {
    machine.instruction_set().decode_first(bytes)
}

/// Encoded length of the first instruction, or `None` for invalid or incomplete bytes.
pub fn instruction_length(bytes: &[u8], machine: CodeMachine) -> Option<usize> {
    decode_first(bytes, machine).map(|(length, _)| length)
}

/// End of a branch-free instruction range starting at `start`.
/// Input bytes must have debugger breakpoint opcodes masked out.
pub fn fallthrough_run_end(
    bytes: &[u8],
    start: u64,
    end: u64,
    machine: CodeMachine,
) -> Option<u64> {
    if end <= start {
        return None;
    }
    let Ok(window_len) = usize::try_from(end - start) else {
        return None;
    };
    if bytes.len() < window_len {
        return None;
    }

    let mut offset = 0;
    while offset < window_len {
        let boundary = start + offset as u64;
        let Some((length, flow)) = decode_first(&bytes[offset..], machine) else {
            return (offset != 0).then_some(boundary);
        };
        if length == 0 || length > window_len - offset {
            return (offset != 0).then_some(boundary);
        }
        if flow != ControlFlow::Other {
            return (offset != 0).then_some(boundary);
        }
        offset += length;
    }
    Some(end)
}

/// Classify the first instruction in `bytes` as `machine` code.
/// Invalid or incomplete instructions are treated as [`ControlFlow::Other`].
pub fn classify(bytes: &[u8], machine: CodeMachine) -> ControlFlow {
    if bytes.is_empty() {
        return ControlFlow::Other;
    }
    decode_first(bytes, machine).map_or(ControlFlow::Other, |(_, flow)| flow)
}

/// A semantic classification for one disassembly token, assigned by the
/// decoder and turned into color by the presentation layer. Color-agnostic on
/// purpose: core decodes, `ui` owns the palette.
#[derive(Clone, Copy, Debug)]
pub enum AsmKind {
    Mnemonic,
    Register,
    Number,
    Punctuation,
    Keyword,
    Text,
}

/// One formatted token of an instruction: its text and semantic kind.
#[derive(Clone, Debug)]
pub struct AsmToken {
    pub text: String,
    pub kind: AsmKind,
}

/// One decoded instruction. `asm` is its text; `mnemonic` and `operands`
/// describe the same instruction structurally, for code that follows code
/// instead of reading it.
#[record(impl)]
pub struct DisasmRow {
    /// The address of the instruction.
    #[record(hex)]
    pub ip: u64,
    /// The bytes of the instruction, in hex.
    pub hex: String,
    /// The instruction length in bytes.
    pub length: usize,
    /// The asm as semantic tokens, for colored rendering.
    #[record(skip)]
    pub tokens: Vec<AsmToken>,
    /// The resolved branch or rip-relative target, if there is one.
    pub comment: Option<String>,
    /// The machine whose code the row is, and the instruction's bytes,
    /// which its structure is decoded from on demand.
    #[record(skip)]
    machine: CodeMachine,
    #[record(skip)]
    bytes: [u8; MAX_INSTRUCTION_BYTES],
}

/// A disassembled function (`uf`).
#[record]
pub struct FunctionDisassembly {
    /// The symbol at the start of the function.
    pub symbol: String,
    /// The length of the function in bytes.
    pub length: usize,
    /// Its instructions, from its start.
    pub rows: Vec<DisasmRow>,
}

/// What an instruction operand is.
#[record]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperandKind {
    Register,
    Memory,
    Immediate,
    /// A near/far branch or PC-relative label target.
    Branch,
    Other,
}

/// One explicit operand of a decoded instruction. Fields that do not apply
/// to its `kind` are None.
#[record]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisasmOperand {
    /// `register`, `memory`, `immediate`, `branch` (a branch or PC-relative
    /// label target), or `other`.
    pub kind: OperandKind,
    /// The operand as `asm` shows it.
    pub text: String,
    /// A register operand's register as written, lowercase (`r8d`, `w3`).
    pub register: Option<String>,
    /// The architectural register that `register` is part of (`r8` for
    /// `r8d`, `x3` for `w3`; vector registers stay as written).
    pub full_register: Option<String>,
    /// A memory operand's base register, full and lowercase (`rip` when
    /// RIP-relative).
    pub base: Option<String>,
    /// A memory operand's index register, full and lowercase.
    pub index: Option<String>,
    /// The scale of `index`.
    pub scale: Option<u32>,
    /// A memory operand's signed displacement: relative to the next
    /// instruction when RIP-relative, and the writeback offset of an ARM64
    /// post-indexed operand.
    pub displacement: Option<i64>,
    /// A memory operand's access size in bytes, when known (x86 only).
    pub size: Option<u32>,
    /// A memory operand's x86 segment override (`gs`).
    pub segment: Option<String>,
    /// An immediate operand's value (negative when the instruction
    /// sign-extends it), or a branch operand's target address.
    pub immediate: Option<i128>,
}

impl DisasmOperand {
    pub fn new(kind: OperandKind, text: String) -> Self {
        Self {
            kind,
            text,
            register: None,
            full_register: None,
            base: None,
            index: None,
            scale: None,
            displacement: None,
            size: None,
            segment: None,
            immediate: None,
        }
    }
}

impl DisasmRow {
    /// A row for the instruction `bytes` encode at `ip`.
    pub fn new(
        machine: CodeMachine,
        ip: u64,
        bytes: &[u8],
        tokens: Vec<AsmToken>,
        comment: Option<String>,
    ) -> Self {
        let mut stored = [0u8; MAX_INSTRUCTION_BYTES];
        stored[..bytes.len()].copy_from_slice(bytes);
        Self {
            ip,
            hex: hex_bytes(bytes),
            length: bytes.len(),
            tokens,
            comment,
            machine,
            bytes: stored,
        }
    }

    fn instruction_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[record]
impl DisasmRow {
    /// The instruction text.
    #[record(getter)]
    pub fn asm(&self) -> String {
        self.tokens.iter().map(|t| t.text.as_str()).collect()
    }

    /// The lowercase mnemonic, without prefixes (`mov`, `ldr`). `.inst`
    /// for an ARM64 word that encodes no instruction.
    #[record(getter)]
    pub fn mnemonic(&self) -> String {
        self.machine
            .instruction_set()
            .mnemonic(self.instruction_bytes(), self.ip)
    }

    /// The explicit operands, in instruction order.
    #[record(getter)]
    pub fn operands(&self) -> Vec<DisasmOperand> {
        self.machine
            .instruction_set()
            .operands(self.instruction_bytes(), self.ip)
    }
}

/// Instruction bytes as space-separated lowercase hex pairs.
fn hex_bytes(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            hex.push(' ');
        }
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Decode up to `limit` instructions of `machine` code starting at `ip`.
pub fn decode_code(
    bytes: &[u8],
    ip: u64,
    limit: Option<usize>,
    machine: CodeMachine,
    resolve: impl Fn(u64) -> String,
) -> Vec<DisasmRow> {
    machine
        .instruction_set()
        .decode_rows(bytes, ip, limit, &resolve)
}

/// How a [`function_extent`] walk goes on past one instruction.
pub enum Flow {
    /// To the next instruction.
    Next,
    /// To the next instruction and to a branch target.
    Fork(u64),
    /// To a branch target only.
    Jump(u64),
    /// Nowhere: a return, an indirect branch, a trap, or no instruction.
    End,
}

/// The length of the function of `machine` code at the start of `code`,
/// mapped at `start`, by its control flow, as `uf` finds a function no
/// unwind entry describes (a leaf): every instruction reachable from
/// `start` through fall-through and branches, up to the end of the last.
/// `code` reaches no further than the function can (the next symbol), so a
/// branch out of it is a tail call, not followed; calls are not followed.
/// `None` when the first instruction does not decode.
pub fn function_extent(code: &[u8], start: u64, machine: CodeMachine) -> Option<usize> {
    const MAX_INSTRUCTIONS: usize = 1 << 16;
    let end = start + code.len() as u64;
    let instruction_set = machine.instruction_set();
    let flow_at = |ip: u64| -> Option<(u64, Flow)> {
        let bytes = code.get(usize::try_from(ip - start).ok()?..)?;
        instruction_set.walk_step(bytes, ip)
    };
    flow_at(start)?;
    let inside = |ip: u64| (start..end).contains(&ip);
    let mut pending = vec![start];
    let mut seen = std::collections::HashSet::new();
    let mut last = start;
    while let Some(ip) = pending.pop() {
        if !inside(ip) || !seen.insert(ip) || seen.len() > MAX_INSTRUCTIONS {
            continue;
        }
        let Some((next, flow)) = flow_at(ip) else {
            continue;
        };
        last = last.max(next.min(end));
        match flow {
            Flow::Next => pending.push(next),
            Flow::Fork(target) => pending.extend([next, target]),
            Flow::Jump(target) => pending.push(target),
            Flow::End => {}
        }
    }
    usize::try_from(last - start).ok()
}

/// The start of the instruction of `machine` code that contains `ip`,
/// decoding forward from `bytes` at `start`, which is at or before `ip`:
/// `ip` itself when an instruction starts there. `None` when `bytes` ends
/// before decoding gets to `ip`.
pub fn instruction_containing(
    machine: CodeMachine,
    bytes: &[u8],
    start: u64,
    ip: u64,
) -> Option<u64> {
    machine
        .instruction_set()
        .instruction_containing(bytes, start, ip)
}

/// Decode `count` instructions of `machine` code ending exactly at
/// `end_addr`.
///
/// `bytes` spans `read_start..end_addr`. Return `None` if no decoding
/// reaches the end exactly.
pub fn decode_preceding(
    machine: CodeMachine,
    bytes: &[u8],
    read_start: u64,
    end_addr: u64,
    count: usize,
    resolve: impl Fn(u64) -> String,
) -> Option<Vec<DisasmRow>> {
    if bytes.is_empty() || count == 0 {
        return None;
    }
    machine
        .instruction_set()
        .decode_preceding(bytes, read_start, end_addr, count, &resolve)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the SDK sees of a row's structure.
    struct Structure {
        mnemonic: String,
        length: usize,
        operands: Vec<DisasmOperand>,
    }

    fn structure(row: &DisasmRow) -> Structure {
        Structure {
            mnemonic: row.mnemonic(),
            length: row.length,
            operands: row.operands(),
        }
    }

    fn x64_row(bytes: &[u8]) -> Structure {
        let rows = decode_code(bytes, 0x1000, Some(1), CodeMachine::Amd64, |_| {
            String::new()
        });
        assert_eq!(rows.len(), 1);
        structure(&rows[0])
    }

    fn operand(kind: OperandKind, text: &str) -> DisasmOperand {
        DisasmOperand::new(kind, text.to_string())
    }

    fn register(text: &str, full: &str) -> DisasmOperand {
        DisasmOperand {
            register: Some(text.to_string()),
            full_register: Some(full.to_string()),
            ..operand(OperandKind::Register, text)
        }
    }

    fn immediate(text: &str, value: i128) -> DisasmOperand {
        DisasmOperand {
            immediate: Some(value),
            ..operand(OperandKind::Immediate, text)
        }
    }

    /// A breakpoint address inside an instruction is placed in the
    /// instruction it is part of, and one at an instruction's first byte is
    /// its own start, up to and including the end of the bytes decoded.
    #[test]
    fn instruction_containing_finds_the_instruction_an_address_is_part_of() {
        // A prologue like nt!NtClose's: mov [rsp+0x18], rbx (5 bytes), push
        // rbp (1), push r12 (2).
        let prologue = [0x48, 0x89, 0x5c, 0x24, 0x18, 0x55, 0x41, 0x54];
        let containing =
            |bytes: &[u8], ip| instruction_containing(CodeMachine::Amd64, bytes, 0x1000, ip);
        for (ip, start) in [
            (0x1000, 0x1000),
            (0x1001, 0x1000),
            (0x1004, 0x1000),
            (0x1005, 0x1005),
            (0x1006, 0x1006),
            (0x1007, 0x1006),
            (0x1008, 0x1008),
        ] {
            assert_eq!(containing(&prologue, ip), Some(start), "{ip:#x}");
        }
        // Decoding that stops short of the address says nothing about it.
        assert_eq!(containing(&prologue[..5], 0x1006), None);
        assert_eq!(containing(&prologue[..3], 0x1004), None);
        // ARM64 instructions are four aligned bytes.
        assert_eq!(
            instruction_containing(CodeMachine::Arm64, &[], 0x1000, 0x1006),
            Some(0x1004)
        );
    }

    #[test]
    fn x64_operands_describe_registers_memory_and_immediates() {
        let row = x64_row(&[0x48, 0x89, 0x51, 0x10]);
        assert_eq!((row.mnemonic.as_str(), row.length), ("mov", 4));
        assert_eq!(
            row.operands,
            [
                DisasmOperand {
                    base: Some("rcx".into()),
                    displacement: Some(0x10),
                    size: Some(8),
                    ..operand(OperandKind::Memory, "qword [rcx+0x10]")
                },
                register("rdx", "rdx"),
            ]
        );

        let row = x64_row(&[0x44, 0x8b, 0xc6]);
        assert_eq!((row.mnemonic.as_str(), row.length), ("mov", 3));
        assert_eq!(
            row.operands,
            [register("r8d", "r8"), register("esi", "rsi")]
        );

        let row = x64_row(&[0x65, 0x80, 0x24, 0x25, 0x85, 0x00, 0x00, 0x00, 0xf9]);
        assert_eq!((row.mnemonic.as_str(), row.length), ("and", 9));
        assert_eq!(
            row.operands,
            [
                DisasmOperand {
                    displacement: Some(0x85),
                    size: Some(1),
                    segment: Some("gs".into()),
                    ..operand(OperandKind::Memory, "byte [gs:0x85]")
                },
                immediate("0xF9", 0xf9),
            ]
        );

        let row = x64_row(&[0x0f, 0x32]);
        assert_eq!((row.mnemonic.as_str(), row.length), ("rdmsr", 2));
        assert!(row.operands.is_empty());
    }

    #[test]
    fn x64_branch_targets_and_rip_relative_displacements() {
        let row = x64_row(&[0xe8, 0x0b, 0x00, 0x00, 0x00]);
        assert_eq!((row.mnemonic.as_str(), row.length), ("call", 5));
        assert_eq!(
            row.operands,
            [DisasmOperand {
                immediate: Some(0x1010),
                ..operand(OperandKind::Branch, "0x0000000000001010")
            }]
        );

        // mov rax, [rip-0x10]: the displacement is the encoded offset, not
        // the absolute address iced keeps.
        let row = x64_row(&[0x48, 0x8b, 0x05, 0xf0, 0xff, 0xff, 0xff]);
        assert_eq!(row.operands[1].base.as_deref(), Some("rip"));
        assert_eq!(row.operands[1].displacement, Some(-0x10));

        // and rsp, -0x10: a sign-extended immediate is negative.
        let row = x64_row(&[0x48, 0x83, 0xe4, 0xf0]);
        assert_eq!(row.operands[1].immediate, Some(-0x10));
    }

    #[test]
    fn arm64_operands_describe_registers_memory_and_labels() {
        // ldr x0, [x1, #8]; add w3, w4, #1; bl +0x10; an undecodable word.
        let bytes = [
            0x20, 0x04, 0x40, 0xf9, 0x83, 0x04, 0x00, 0x11, 0x04, 0x00, 0x00, 0x94, 0x6c, 0x68,
            0x14, 0x40,
        ];
        let rows: Vec<Structure> =
            decode_code(&bytes, 0x1000, None, CodeMachine::Arm64, |_| String::new())
                .iter()
                .map(structure)
                .collect();
        let listed: Vec<_> = rows
            .iter()
            .map(|row| (row.mnemonic.as_str(), row.length))
            .collect();
        assert_eq!(listed, [("ldr", 4), ("add", 4), ("bl", 4), (".inst", 4)]);

        assert_eq!(
            rows[0].operands,
            [
                register("x0", "x0"),
                DisasmOperand {
                    base: Some("x1".into()),
                    displacement: Some(8),
                    ..operand(OperandKind::Memory, "[x1, #0x8]")
                },
            ]
        );
        assert_eq!(
            rows[1].operands,
            [
                register("w3", "x3"),
                register("w4", "x4"),
                immediate("#0x1", 1),
            ]
        );
        assert_eq!(
            rows[2].operands,
            [DisasmOperand {
                immediate: Some(0x1018),
                ..operand(OperandKind::Branch, "0x1018")
            }]
        );
        assert!(rows[3].operands.is_empty());
    }

    /// A data word among ARM64 code (the HAL's EL2 init slot, a literal)
    /// shows as the word and decoding carries on after it, so `u Ln` still
    /// lists n rows.
    #[test]
    fn an_undecodable_arm64_word_is_shown_and_skipped() {
        // ret; a word no instruction encodes; nop.
        let bytes = [
            0xc0, 0x03, 0x5f, 0xd6, 0x6c, 0x68, 0x14, 0x40, 0x1f, 0x20, 0x03, 0xd5,
        ];
        let rows = decode_code(&bytes, 0x1000, None, CodeMachine::Arm64, |_| String::new());
        let listed: Vec<(u64, String)> = rows.iter().map(|row| (row.ip, row.asm())).collect();
        assert_eq!(
            listed,
            [
                (0x1000, "ret".to_string()),
                (0x1004, ".inst 0x4014686c".to_string()),
                (0x1008, "nop".to_string()),
            ]
        );
    }
    use std::cell::Cell;

    #[test]
    fn classify_control_flow_instructions() {
        assert_eq!(
            classify(&[0xe8, 0, 0, 0, 0], CodeMachine::Amd64),
            ControlFlow::Call
        );
        assert_eq!(classify(&[0xc3], CodeMachine::Amd64), ControlFlow::Ret);
        assert_eq!(
            classify(&[0xeb, 0], CodeMachine::Amd64),
            ControlFlow::Branch
        );
        assert_eq!(classify(&[0x90], CodeMachine::Amd64), ControlFlow::Other);

        assert_eq!(
            classify(&0x94000000u32.to_le_bytes(), CodeMachine::Arm64),
            ControlFlow::Call
        );
        // `blraaz x0` and `blraa x0, x1`: a step over must run past them
        // as past `blr`.
        for pointer_authenticated_call in [0xd63f081fu32, 0xd73f0801] {
            assert_eq!(
                classify(
                    &pointer_authenticated_call.to_le_bytes(),
                    CodeMachine::Arm64
                ),
                ControlFlow::Call
            );
        }
        assert_eq!(
            classify(&0xd65f03c0u32.to_le_bytes(), CodeMachine::Arm64),
            ControlFlow::Ret
        );
        assert_eq!(
            classify(&0x14000000u32.to_le_bytes(), CodeMachine::Arm64),
            ControlFlow::Branch
        );
        assert_eq!(
            classify(&0xd503201fu32.to_le_bytes(), CodeMachine::Arm64),
            ControlFlow::Other
        );
    }

    #[test]
    fn amd64_flow_classification_respects_effective_code_bitness() {
        assert_eq!(
            classify(&[0x48, 0xc3], CodeMachine::X86),
            ControlFlow::Other
        );
        assert_eq!(
            classify(&[0x48, 0xc3], CodeMachine::Amd64),
            ControlFlow::Ret
        );
    }

    #[test]
    fn x86_rows_mask_wrapping_branch_targets() {
        let target = Cell::new(u64::MAX);
        let rows = decode_code(
            &[0xe9, 0x0b, 0x00, 0x00, 0x00],
            0xffff_fff0,
            Some(1),
            CodeMachine::X86,
            |address| {
                target.set(address);
                String::new()
            },
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(target.get(), 0);
    }

    #[test]
    fn x86_rows_crossing_ip_wrap_keep_their_instruction_bytes() {
        let rows = decode_code(&[0x90, 0xc3], 0xffff_ffff, None, CodeMachine::X86, |_| {
            String::new()
        });

        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].ip, rows[0].hex.as_str()), (0xffff_ffff, "90"));
        assert_eq!((rows[1].ip, rows[1].hex.as_str()), (0, "c3"));
    }

    #[test]
    fn amd64_fallthrough_run_end_reaches_exact_window_end() {
        let straight_line = [0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01];
        assert_eq!(
            fallthrough_run_end(
                &straight_line,
                0x1000,
                0x1000 + straight_line.len() as u64,
                CodeMachine::Amd64,
            ),
            Some(0x1000 + straight_line.len() as u64)
        );
    }

    #[test]
    fn amd64_fallthrough_run_end_stops_before_control_flow() {
        let prefix = [0x48, 0x89, 0xc8];
        for control_flow in [vec![0xeb, 0x00], vec![0xe8, 0, 0, 0, 0], vec![0xc3]] {
            let mut window = prefix.to_vec();
            window.extend_from_slice(&control_flow);
            window.extend_from_slice(&[0x90]);
            assert_eq!(
                fallthrough_run_end(
                    &window,
                    0x1000,
                    0x1000 + window.len() as u64,
                    CodeMachine::Amd64,
                ),
                Some(0x1003)
            );
        }
    }

    #[test]
    fn amd64_fallthrough_run_end_returns_none_for_leading_control_flow() {
        assert_eq!(
            fallthrough_run_end(&[0xc3, 0x90], 0x1000, 0x1002, CodeMachine::Amd64),
            None
        );
    }

    #[test]
    fn fallthrough_run_end_stops_at_last_boundary_before_end() {
        let bytes = [0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01];
        assert_eq!(
            fallthrough_run_end(&bytes, 0, 6, CodeMachine::Amd64),
            Some(3)
        );
        assert_eq!(fallthrough_run_end(&bytes, 0, 2, CodeMachine::Amd64), None);
    }

    #[test]
    fn x86_fallthrough_run_end_decodes_32_bit_code() {
        // `dec eax; ret` in 32-bit code, one `ret` with a REX prefix in 64-bit.
        let bytes = [0x48, 0xc3];
        assert_eq!(fallthrough_run_end(&bytes, 0, 2, CodeMachine::X86), Some(1));
        assert_eq!(fallthrough_run_end(&bytes, 0, 2, CodeMachine::Amd64), None);
    }

    #[test]
    fn arm64_fallthrough_run_end_handles_nops_and_leading_branch() {
        let nop = 0xd503201fu32.to_le_bytes();
        let mut nops = Vec::new();
        nops.extend_from_slice(&nop);
        nops.extend_from_slice(&nop);
        assert_eq!(
            fallthrough_run_end(&nops, 0x2000, 0x2008, CodeMachine::Arm64),
            Some(0x2008)
        );

        let branch = 0x14000000u32.to_le_bytes();
        assert_eq!(
            fallthrough_run_end(&branch, 0x2000, 0x2004, CodeMachine::Arm64),
            None
        );
    }

    #[test]
    fn instruction_length_rejects_truncated_encodings() {
        assert_eq!(
            instruction_length(&[0xe8, 0, 0, 0], CodeMachine::Amd64),
            None
        );
        assert_eq!(instruction_length(&[0, 0, 0], CodeMachine::Arm64), None);
    }

    #[test]
    fn function_extent_follows_branches_to_the_last_reachable_instruction() {
        let words = |words: &[u32]| {
            words
                .iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<_>>()
        };
        // nt!KeQueryActiveProcessorCount's shape: a leaf with a forward cbz
        // over its body to its tail, then padding and the next function.
        let leaf = words(&[
            0xb4000080, // cbz x0, +0x10
            0xd2800021, // mov x1, #1
            0xf9000001, // str x1, [x0]
            0x14000001, // b +4 (to the tail)
            0x52800020, // mov w0, #1
            0xd65f03c0, // ret
            0x00000000, // udf #0 (padding)
            0xd503201f, // nop (the next function)
        ]);
        assert_eq!(
            function_extent(&leaf, 0x1000, CodeMachine::Arm64),
            Some(0x18)
        );
        // A branch out of the span is a tail call, and the function ends there.
        let tail = words(&[0xd503201f, 0x14000010]); // nop; b +0x40
        assert_eq!(function_extent(&tail, 0x1000, CodeMachine::Arm64), Some(8));
        // x86: jz over a body to a ret; the int3 padding after it is not code.
        let x86 = [0x74, 0x03, 0x48, 0xff, 0xc0, 0xc3, 0xcc, 0xcc];
        assert_eq!(function_extent(&x86, 0x1000, CodeMachine::Amd64), Some(6));
        assert_eq!(function_extent(&[0x06], 0x1000, CodeMachine::Amd64), None);
    }
}
