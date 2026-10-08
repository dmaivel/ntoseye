use bad64::decode;
use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, FormatMnemonicOptions, Formatter, FormatterOutput,
    FormatterTextKind, Instruction, MemorySizeOptions, Mnemonic, NasmFormatter, OpKind, Register,
};

use std::fmt::Write as _;

use crate::types::{Arch, CodeMachine};

/// Control-flow class for the instruction at the start of a byte buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlFlow {
    Call,
    Ret,
    Branch,
    Other,
}

fn decode_first(bytes: &[u8], arch: Arch, bitness: u32) -> Option<(usize, ControlFlow)> {
    match arch {
        Arch::Amd64 => {
            let mut decoder = Decoder::with_ip(bitness, bytes, 0, DecoderOptions::NONE);
            if !decoder.can_decode() {
                return None;
            }
            let instruction = decoder.decode();
            if instruction.code() == Code::INVALID {
                return None;
            }
            let flow = if instruction.mnemonic() == Mnemonic::Call {
                ControlFlow::Call
            } else if instruction.mnemonic() == Mnemonic::Ret {
                ControlFlow::Ret
            } else if instruction.flow_control() != FlowControl::Next {
                ControlFlow::Branch
            } else {
                ControlFlow::Other
            };
            Some((instruction.len(), flow))
        }
        Arch::Arm64 => {
            if bytes.len() < 4 {
                return None;
            }
            let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let instruction = decode(word, 0).ok()?;
            let mnemonic = instruction.op().mnem();
            // `blraa`/`blrab`/`blraaz`/`blrabz` are pointer-authenticated
            // `blr`; Windows ARM64 kernels emit them.
            let flow = if mnemonic == "bl" || mnemonic.starts_with("blr") {
                ControlFlow::Call
            } else if mnemonic.starts_with("ret") {
                ControlFlow::Ret
            } else if mnemonic == "b"
                || mnemonic.starts_with("b.")
                // `br`, `braa`, `brab`, `braaz`, `brabz`; never `brk`/SVE `brk*`.
                || mnemonic == "br"
                || mnemonic.starts_with("bra")
                || mnemonic == "cbz"
                || mnemonic == "cbnz"
                || mnemonic == "tbz"
                || mnemonic == "tbnz"
            {
                ControlFlow::Branch
            } else {
                ControlFlow::Other
            };
            Some((4, flow))
        }
    }
}

/// Encoded length of the first instruction, or `None` for invalid or incomplete bytes.
/// `bitness` selects 32- or 64-bit AMD64 decoding and is ignored for ARM64.
pub fn instruction_length(bytes: &[u8], arch: Arch, bitness: u32) -> Option<usize> {
    decode_first(bytes, arch, bitness).map(|(length, _)| length)
}

/// End of a branch-free instruction range starting at `start`.
/// Input bytes must have debugger breakpoint opcodes masked out.
pub fn fallthrough_run_end(
    bytes: &[u8],
    start: u64,
    end: u64,
    arch: Arch,
    bitness: u32,
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
        let Some((length, flow)) = decode_first(&bytes[offset..], arch, bitness) else {
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

/// Classify the first instruction in `bytes` for the target architecture and
/// effective code bitness (ignored for ARM64).
/// Invalid or incomplete instructions are treated as [`ControlFlow::Other`].
pub fn classify(bytes: &[u8], arch: Arch, bitness: u32) -> ControlFlow {
    if bytes.is_empty() {
        return ControlFlow::Other;
    }
    decode_first(bytes, arch, bitness).map_or(ControlFlow::Other, |(_, flow)| flow)
}

/// NASM formatter configured for ntoseye's disassembly, so every call site
/// decodes identically.
pub fn disasm_formatter() -> NasmFormatter {
    let mut formatter = NasmFormatter::new();
    let options = formatter.options_mut();
    options.set_space_after_operand_separator(true);
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_first_operand_char_index(5);
    options.set_memory_size_options(MemorySizeOptions::Always);
    options.set_show_branch_size(false);
    options.set_rip_relative_addresses(true);
    formatter
}

/// A semantic classification for one disassembly token, assigned by the
/// decoder and turned into color by the presentation layer. Color-agnostic on
/// purpose: core decodes, `ui` owns the palette.
#[derive(Clone, Copy)]
pub enum AsmKind {
    Mnemonic,
    Register,
    Number,
    Punctuation,
    Keyword,
    Text,
}

/// One formatted token of an instruction: its text and semantic kind.
pub struct AsmToken {
    pub text: String,
    pub kind: AsmKind,
}

/// Collects iced's formatter output into semantic [`AsmToken`]s, mapping the
/// formatter's fine-grained kinds onto our small render palette.
struct TokenSink<'a>(&'a mut Vec<AsmToken>);

impl FormatterOutput for TokenSink<'_> {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let kind = match kind {
            FormatterTextKind::Mnemonic | FormatterTextKind::Prefix => AsmKind::Mnemonic,
            FormatterTextKind::Register => AsmKind::Register,
            FormatterTextKind::Number
            | FormatterTextKind::LabelAddress
            | FormatterTextKind::FunctionAddress
            | FormatterTextKind::SelectorValue => AsmKind::Number,
            FormatterTextKind::Punctuation | FormatterTextKind::Operator => AsmKind::Punctuation,
            FormatterTextKind::Keyword
            | FormatterTextKind::Directive
            | FormatterTextKind::Decorator => AsmKind::Keyword,
            _ => AsmKind::Text,
        };
        self.0.push(AsmToken {
            text: text.to_string(),
            kind,
        });
    }
}

/// One decoded instruction, ready to render: address, space-joined hex bytes,
/// the asm as semantic [`AsmToken`]s, and an optional symbol comment for a
/// branch / rip-relative target. [`Self::mnemonic`] and [`Self::operands`]
/// describe the same instruction structurally, for callers that follow code
/// instead of reading it.
pub struct DisasmRow {
    pub ip: u64,
    pub hex: String,
    /// Encoded length in bytes.
    pub length: usize,
    pub tokens: Vec<AsmToken>,
    pub comment: Option<String>,
    decoded: Decoded,
}

/// The instruction behind a row, kept so that only callers that want its
/// structure pay for it.
enum Decoded {
    X86 {
        instruction: Instruction,
        bitness: u32,
    },
    /// Decoded again on demand, at the row's `ip`.
    Arm64(u32),
}

/// What an instruction operand is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperandKind {
    Register,
    Memory,
    Immediate,
    /// A near/far branch or PC-relative label target.
    Branch,
    Other,
}

impl OperandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Memory => "memory",
            Self::Immediate => "immediate",
            Self::Branch => "branch",
            Self::Other => "other",
        }
    }
}

/// One explicit operand of a decoded instruction. Fields that do not apply to
/// `kind` are `None`; register names are lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisasmOperand {
    pub kind: OperandKind,
    /// The operand as the formatted instruction text shows it.
    pub text: String,
    /// Register operand: the register as written (`r8d`, `w3`).
    pub register: Option<String>,
    /// Register operand: the architectural register it is part of (`r8`, `x3`).
    pub full_register: Option<String>,
    /// Memory operand: full base register (`rip` when RIP-relative).
    pub base: Option<String>,
    /// Memory operand: full index register.
    pub index: Option<String>,
    /// Memory operand: index scale, when there is an index.
    pub scale: Option<u32>,
    /// Memory operand: signed displacement (relative to the next instruction
    /// when RIP-relative).
    pub displacement: Option<i64>,
    /// Memory operand: access size in bytes, when known.
    pub size: Option<u32>,
    /// Memory operand: x86 segment override (`gs`).
    pub segment: Option<String>,
    /// Immediate operand: its value, signed when the instruction sign-extends
    /// it; branch operand: the target address.
    pub immediate: Option<i128>,
}

impl DisasmOperand {
    fn new(kind: OperandKind, text: String) -> Self {
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

fn mask_code_address(bitness: u32, address: u64) -> u64 {
    if bitness == 32 {
        address & u64::from(u32::MAX)
    } else {
        address
    }
}

impl DisasmRow {
    /// Plain instruction text for MCP, Python, and JSON output.
    /// Use `ui::disasm_asm` for colored rendering.
    pub fn asm(&self) -> String {
        self.tokens.iter().map(|t| t.text.as_str()).collect()
    }

    /// The lowercase mnemonic without prefixes, as `asm` shows it (`.inst`
    /// for an ARM64 word that encodes no instruction). `formatter` is a
    /// [`disasm_formatter`], for x86 rows.
    pub fn mnemonic(&self, formatter: &mut NasmFormatter) -> String {
        match &self.decoded {
            Decoded::X86 { instruction, .. } => x86_mnemonic(instruction, formatter),
            Decoded::Arm64(word) => match bad64::decode(*word, self.ip) {
                Ok(instruction) => instruction.op().mnem().to_string(),
                Err(_) => ".inst".to_string(),
            },
        }
    }

    /// The explicit operands, in instruction order, as `asm` shows them.
    /// `formatter` is a [`disasm_formatter`], for x86 rows.
    pub fn operands(&self, formatter: &mut NasmFormatter) -> Vec<DisasmOperand> {
        match &self.decoded {
            Decoded::X86 {
                instruction,
                bitness,
            } => x86_operands(instruction, *bitness, formatter),
            Decoded::Arm64(word) => bad64::decode(*word, self.ip)
                .map(|instruction| {
                    instruction
                        .operands()
                        .iter()
                        .map(|op| {
                            let text = arm64_operand_tokens(op)
                                .iter()
                                .map(|token| token.text.as_str())
                                .collect();
                            arm64_operand(op, text)
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
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

/// The explicit operands of a decoded x86 instruction, one per operand the
/// formatter prints (so the list matches `asm`), in order.
fn x86_operands(
    instruction: &Instruction,
    bitness: u32,
    formatter: &mut NasmFormatter,
) -> Vec<DisasmOperand> {
    let count = formatter.operand_count(instruction);
    let mut operands = Vec::with_capacity(count as usize);
    for operand in 0..count {
        let mut text = String::new();
        if formatter
            .format_operand(instruction, &mut text, operand)
            .is_err()
        {
            continue;
        }
        let mut op = DisasmOperand::new(OperandKind::Other, text);
        if let Ok(Some(index)) = formatter.get_instruction_operand(instruction, operand) {
            x86_fill_operand(&mut op, instruction, index, bitness, formatter);
        }
        operands.push(op);
    }
    operands
}

/// Classify instruction operand `index` into `op`.
fn x86_fill_operand(
    op: &mut DisasmOperand,
    instruction: &Instruction,
    index: u32,
    bitness: u32,
    formatter: &mut NasmFormatter,
) {
    let mut name = |register: Register| {
        (register != Register::None).then(|| formatter.format_register(register).to_string())
    };
    let immediate = |value: i128| (OperandKind::Immediate, Some(value));
    let branch = |target: u64| (OperandKind::Branch, Some(i128::from(target)));
    let (kind, value) = match instruction.op_kind(index) {
        OpKind::Register => {
            let register = instruction.op_register(index);
            op.register = name(register);
            op.full_register = name(x86_full_register(register, bitness));
            (OperandKind::Register, None)
        }
        OpKind::NearBranch16 => branch(u64::from(instruction.near_branch16())),
        OpKind::NearBranch32 => branch(u64::from(instruction.near_branch32())),
        OpKind::NearBranch64 => branch(mask_code_address(bitness, instruction.near_branch64())),
        OpKind::FarBranch16 => branch(u64::from(instruction.far_branch16())),
        OpKind::FarBranch32 => branch(u64::from(instruction.far_branch32())),
        OpKind::Immediate8 => immediate(instruction.immediate8().into()),
        OpKind::Immediate8_2nd => immediate(instruction.immediate8_2nd().into()),
        OpKind::Immediate16 => immediate(instruction.immediate16().into()),
        OpKind::Immediate32 => immediate(instruction.immediate32().into()),
        OpKind::Immediate64 => immediate(instruction.immediate64().into()),
        OpKind::Immediate8to16 => immediate(instruction.immediate8to16().into()),
        OpKind::Immediate8to32 => immediate(instruction.immediate8to32().into()),
        OpKind::Immediate8to64 => immediate(instruction.immediate8to64().into()),
        OpKind::Immediate32to64 => immediate(instruction.immediate32to64().into()),
        OpKind::Memory => {
            let base = instruction.memory_base();
            let index_register = instruction.memory_index();
            op.base = name(x86_full_register(base, bitness));
            op.index = name(x86_full_register(index_register, bitness));
            op.scale = (index_register != Register::None).then(|| instruction.memory_index_scale());
            op.displacement = Some(x86_displacement(instruction, bitness));
            op.segment = name(instruction.segment_prefix());
            op.size = x86_memory_size(instruction);
            (OperandKind::Memory, None)
        }
        // String-instruction operands: `[seg:si]` or `[es:di]` forms.
        kind @ (OpKind::MemorySegSI
        | OpKind::MemorySegESI
        | OpKind::MemorySegRSI
        | OpKind::MemorySegDI
        | OpKind::MemorySegEDI
        | OpKind::MemorySegRDI
        | OpKind::MemoryESDI
        | OpKind::MemoryESEDI
        | OpKind::MemoryESRDI) => {
            let base = match kind {
                OpKind::MemorySegSI => Register::SI,
                OpKind::MemorySegESI => Register::ESI,
                OpKind::MemorySegRSI => Register::RSI,
                OpKind::MemorySegDI | OpKind::MemoryESDI => Register::DI,
                OpKind::MemorySegEDI | OpKind::MemoryESEDI => Register::EDI,
                _ => Register::RDI,
            };
            op.base = name(x86_full_register(base, bitness));
            op.displacement = Some(0);
            // `es:di` is fixed; only the `seg:` forms take an override.
            if !matches!(
                kind,
                OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI
            ) {
                op.segment = name(instruction.segment_prefix());
            }
            op.size = x86_memory_size(instruction);
            (OperandKind::Memory, None)
        }
    };
    op.kind = kind;
    op.immediate = value;
}

/// The register `register` is part of: the 64-bit GPR in 64-bit code (the
/// 32-bit one in 32-bit code); vector registers stay as written (`xmm0`, not
/// `zmm0`).
fn x86_full_register(register: Register, bitness: u32) -> Register {
    if register.is_gpr() {
        if bitness == 64 {
            register.full_register()
        } else {
            register.full_register32()
        }
    } else if register.is_vector_register() {
        register
    } else {
        register.full_register()
    }
}

/// The signed displacement of the memory operand. iced stores a RIP/EIP-
/// relative operand's absolute address, so recover the offset from the next
/// instruction that the text shows; otherwise sign-extend from the address size.
fn x86_displacement(instruction: &Instruction, bitness: u32) -> i64 {
    let displacement = instruction.memory_displacement64();
    let base = instruction.memory_base();
    if base == Register::RIP {
        return displacement.wrapping_sub(instruction.next_ip()) as i64;
    }
    if base == Register::EIP {
        return i64::from(
            instruction
                .memory_displacement32()
                .wrapping_sub(instruction.next_ip32()) as i32,
        );
    }
    let address_size = [base, instruction.memory_index()]
        .into_iter()
        .find(|register| *register != Register::None && register.is_gpr())
        .map_or(bitness as usize / 8, Register::size);
    match address_size {
        2 => i64::from(displacement as u16 as i16),
        4 => i64::from(displacement as u32 as i32),
        _ => displacement as i64,
    }
}

fn x86_memory_size(instruction: &Instruction) -> Option<u32> {
    let size = instruction.memory_size().size();
    (size != 0).then_some(size as u32)
}

/// The lowercase mnemonic of `instruction`, without prefixes, as `asm` shows it.
fn x86_mnemonic(instruction: &Instruction, formatter: &mut NasmFormatter) -> String {
    let mut mnemonic = String::new();
    formatter.format_mnemonic_options(
        instruction,
        &mut mnemonic,
        FormatMnemonicOptions::NO_PREFIXES,
    );
    mnemonic
}

/// Decode `bytes` (loaded at `start_addr`) into rows with the given x86
/// `bitness` (see `Target::code_bitness`), stopping after `limit`
/// instructions when `Some`. `resolve` turns a branch / RIP-relative target
/// into a symbol comment. The caller owns `formatter` (build it once with
/// [`disasm_formatter`]) so it's reused across decode passes.
pub fn decode_rows(
    bytes: &[u8],
    start_addr: u64,
    limit: Option<usize>,
    bitness: u32,
    formatter: &mut NasmFormatter,
    resolve: impl Fn(u64) -> String,
) -> Vec<DisasmRow> {
    let start_ip = mask_code_address(bitness, start_addr);
    let mut decoder = Decoder::with_ip(bitness, bytes, start_ip, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut rows = Vec::new();

    while decoder.can_decode() && limit.is_none_or(|n| rows.len() < n) {
        let byte_start = decoder.position();
        decoder.decode_out(&mut instruction);
        if instruction.code() == Code::INVALID {
            continue;
        }
        let Some(byte_end) = byte_start.checked_add(instruction.len()) else {
            break;
        };
        let Some(instr_bytes) = bytes.get(byte_start..byte_end) else {
            break;
        };
        let mut tokens = Vec::new();
        formatter.format(&instruction, &mut TokenSink(&mut tokens));

        let ip = mask_code_address(bitness, instruction.ip());
        let hex = hex_bytes(instr_bytes);

        let comment = if instruction.is_ip_rel_memory_operand() {
            Some(resolve(mask_code_address(
                bitness,
                instruction.ip_rel_memory_address(),
            )))
        } else if instruction.is_call_near()
            || instruction.is_jmp_near()
            || instruction.is_jcc_near()
        {
            Some(resolve(mask_code_address(
                bitness,
                instruction.near_branch_target(),
            )))
        } else {
            None
        };

        rows.push(DisasmRow {
            ip,
            hex,
            length: instruction.len(),
            tokens,
            comment,
            decoded: Decoded::X86 {
                instruction,
                bitness,
            },
        });
    }

    rows
}

/// Decode AArch64 (`bad64`) instructions into the same [`DisasmRow`] shape the
/// AMD64 decoder produces. AArch64 instructions are fixed 4 bytes; branch and
/// conditional-branch targets get symbol comments.
pub fn decode_rows_arm64(
    bytes: &[u8],
    start_addr: u64,
    limit: Option<usize>,
    resolve: impl Fn(u64) -> String,
) -> Vec<DisasmRow> {
    let mut rows = Vec::new();
    for result in bad64::disasm(bytes, start_addr) {
        if limit.is_some_and(|n| rows.len() >= n) {
            break;
        }
        // A word that encodes no instruction (a literal, a data slot) is
        // shown as the word, as objdump does; the next one starts 4 bytes on.
        let instruction = match result {
            Ok(instruction) => instruction,
            Err(error) => {
                let ip = error.address();
                let start_index = (ip - start_addr) as usize;
                let Some(word) = bytes.get(start_index..start_index + 4) else {
                    break;
                };
                let value = u32::from_le_bytes(word.try_into().expect("4-byte slice"));
                rows.push(DisasmRow {
                    ip,
                    hex: hex_bytes(word),
                    length: 4,
                    tokens: vec![
                        AsmToken {
                            text: ".inst".to_string(),
                            kind: AsmKind::Keyword,
                        },
                        AsmToken {
                            text: format!(" {value:#010x}"),
                            kind: AsmKind::Number,
                        },
                    ],
                    comment: None,
                    decoded: Decoded::Arm64(value),
                });
                continue;
            }
        };
        let ip = instruction.address();
        let start_index = (ip - start_addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + 4];
        let hex = hex_bytes(instr_bytes);

        // The x64 path gets semantic tokens from iced's formatter; bad64 has
        // no formatter callback, but exposes typed operands, so classify those
        // into the same palette while reproducing the decoder's Display text
        // exactly (spaces live inside token text, so `asm()` is unchanged).
        let tokens = arm64_row_tokens(&instruction);

        let comment = arm64_pcrel_comment(&instruction, &resolve);
        rows.push(DisasmRow {
            ip,
            hex,
            length: 4,
            tokens,
            comment,
            decoded: Decoded::Arm64(instruction.opcode()),
        });
    }
    rows
}

/// Build the semantic token stream for a decoded AArch64 instruction:
/// mnemonic plus one classified token group per operand, reproducing bad64's
/// Display text exactly.
fn arm64_row_tokens(instruction: &bad64::Instruction) -> Vec<AsmToken> {
    let text = instruction.to_string();
    let mut tokens = Vec::new();
    match text.split_once(' ') {
        Some((mnem, _)) => {
            tokens.push(AsmToken {
                text: mnem.to_string(),
                kind: AsmKind::Mnemonic,
            });
            for (i, op) in instruction.operands().iter().enumerate() {
                let mut op_tokens = arm64_operand_tokens(op);
                if let Some(first) = op_tokens.first_mut() {
                    let sep = if i == 0 { " " } else { ", " };
                    first.text = format!("{sep}{}", first.text);
                }
                tokens.extend(op_tokens);
            }
        }
        None => tokens.push(AsmToken {
            text,
            kind: AsmKind::Mnemonic,
        }),
    }
    tokens
}

/// Classify one bad64 operand. Post-indexed forms (`[x1], #8`) report the
/// writeback offset as `displacement`/`index`, although the access uses the
/// base alone.
fn arm64_operand(op: &bad64::Operand, text: String) -> DisasmOperand {
    use bad64::Operand;
    let mut out = DisasmOperand::new(OperandKind::Other, text);
    let full = |reg: bad64::Reg| Some(arm64_full_register(reg));
    match *op {
        Operand::Reg { reg, .. } | Operand::ShiftReg { reg, .. } | Operand::QualReg { reg, .. } => {
            out.kind = OperandKind::Register;
            out.register = Some(reg.name().to_string());
            out.full_register = full(reg);
        }
        Operand::SysReg(sr) => {
            out.kind = OperandKind::Register;
            out.register = Some(sr.name().to_string());
            out.full_register = out.register.clone();
        }
        Operand::Imm32 { imm, shift } | Operand::Imm64 { imm, shift } => {
            let value = arm64_imm(imm);
            let value = match shift {
                None => Some(value),
                Some(bad64::Shift::LSL(amount)) => Some(value << amount),
                Some(bad64::Shift::MSL(amount)) => {
                    Some((value << amount) | ((1i128 << amount) - 1))
                }
                Some(_) => None,
            };
            if let Some(value) = value {
                out.kind = OperandKind::Immediate;
                out.immediate = Some(value);
            }
        }
        Operand::MemReg(reg) => {
            out.kind = OperandKind::Memory;
            out.base = full(reg);
        }
        Operand::MemOffset {
            reg,
            offset,
            mul_vl,
            ..
        } => {
            out.kind = OperandKind::Memory;
            out.base = full(reg);
            // `mul vl` scales the offset by the SVE vector length.
            out.displacement = (!mul_vl).then(|| arm64_imm(offset) as i64);
        }
        Operand::MemPreIdx { reg, imm } | Operand::MemPostIdxImm { reg, imm } => {
            out.kind = OperandKind::Memory;
            out.base = full(reg);
            out.displacement = Some(arm64_imm(imm) as i64);
        }
        Operand::MemPostIdxReg([base, index]) => {
            out.kind = OperandKind::Memory;
            out.base = full(base);
            out.index = full(index);
        }
        Operand::MemExt { regs, shift, .. } => {
            out.kind = OperandKind::Memory;
            out.base = full(regs[0]);
            out.index = full(regs[1]);
            out.scale = Some(match shift {
                Some(
                    bad64::Shift::LSL(amount)
                    | bad64::Shift::UXTW(amount)
                    | bad64::Shift::SXTW(amount)
                    | bad64::Shift::UXTX(amount)
                    | bad64::Shift::SXTX(amount),
                ) => 1 << amount,
                _ => 1,
            });
        }
        Operand::Label(imm) => {
            out.kind = OperandKind::Branch;
            out.immediate = Some(i128::from(arm64_imm(imm) as u64));
        }
        _ => {}
    }
    out
}

fn arm64_imm(imm: bad64::Imm) -> i128 {
    match imm {
        bad64::Imm::Signed(value) => value.into(),
        bad64::Imm::Unsigned(value) => value.into(),
    }
}

/// The X register a W register is the low half of (`w3` -> `x3`, `wzr` ->
/// `xzr`, `wsp` -> `sp`); every other register is its own.
fn arm64_full_register(reg: bad64::Reg) -> String {
    let name = reg.name();
    match name.strip_prefix('w') {
        Some("sp") => "sp".to_string(),
        Some(rest) if rest == "zr" || rest.bytes().all(|b| b.is_ascii_digit()) => {
            format!("x{rest}")
        }
        _ => name.to_string(),
    }
}

/// Accumulates [`AsmToken`]s while reproducing bad64's spacing: a space is
/// embedded at the start of the next token when one precedes it in the source.
struct Arm64Tokens {
    items: Vec<AsmToken>,
    space: bool,
}

impl Arm64Tokens {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            space: false,
        }
    }

    fn push(&mut self, text: &str, kind: AsmKind) {
        let text = if self.space && !self.items.is_empty() {
            format!(" {text}")
        } else {
            text.to_string()
        };
        self.items.push(AsmToken { text, kind });
        self.space = false;
    }

    fn space(&mut self) {
        self.space = true;
    }

    fn into_vec(self) -> Vec<AsmToken> {
        self.items
    }
}

/// Register text exactly as bad64 renders it: `reg` plus its arrangement
/// suffix (and element lane when the operand form carries one).
fn arm64_reg_text(reg: bad64::Reg, arrspec: Option<bad64::ArrSpec>, lane: bool) -> String {
    let mut text = reg.to_string();
    if let Some(arsp) = arrspec {
        text.push_str(arsp.suffix(reg));
        if lane && let Some(l) = arsp.lane() {
            text.push_str(&format!("[{l}]"));
        }
    }
    text
}

/// The shift/extend suffix, exactly as bad64 formats it (LSL/LSR/ASR/ROR/MSL
/// always carry an amount; the extend forms print it only when non-zero).
fn arm64_shift_tokens(shift: &bad64::Shift, t: &mut Arm64Tokens) {
    let (name, amount) = match *shift {
        bad64::Shift::LSL(a) => ("lsl", Some(a)),
        bad64::Shift::LSR(a) => ("lsr", Some(a)),
        bad64::Shift::ASR(a) => ("asr", Some(a)),
        bad64::Shift::ROR(a) => ("ror", Some(a)),
        bad64::Shift::UXTW(a) => ("uxtw", (a != 0).then_some(a)),
        bad64::Shift::SXTW(a) => ("sxtw", (a != 0).then_some(a)),
        bad64::Shift::UXTX(a) => ("uxtx", (a != 0).then_some(a)),
        bad64::Shift::SXTX(a) => ("sxtx", (a != 0).then_some(a)),
        bad64::Shift::SXTB(a) => ("sxtb", (a != 0).then_some(a)),
        bad64::Shift::SXTH(a) => ("sxth", (a != 0).then_some(a)),
        bad64::Shift::UXTH(a) => ("uxth", (a != 0).then_some(a)),
        bad64::Shift::UXTB(a) => ("uxtb", (a != 0).then_some(a)),
        bad64::Shift::MSL(a) => ("msl", Some(a)),
    };
    t.push(name, AsmKind::Keyword);
    if let Some(a) = amount {
        t.space();
        t.push(&format!("#{a:#x}"), AsmKind::Number);
    }
}

/// Classify one bad64 [`Operand`] into semantic tokens, the AArch64 analog
/// of the x64 `TokenSink`. Each branch mirrors bad64's `Display` formatting
/// for that variant, so the joined tokens are byte-identical to its output.
fn arm64_operand_tokens(op: &bad64::Operand) -> Vec<AsmToken> {
    let mut t = Arm64Tokens::new();
    match op {
        bad64::Operand::Imm32 { imm, shift } | bad64::Operand::Imm64 { imm, shift } => {
            t.push(&format!("#{imm}"), AsmKind::Number);
            if let Some(shift) = shift {
                t.push(",", AsmKind::Punctuation);
                t.space();
                arm64_shift_tokens(shift, &mut t);
            }
        }
        bad64::Operand::FImm32(ff) => {
            t.push(
                &format!("#{}", f32::from_le_bytes(ff.to_le_bytes())),
                AsmKind::Number,
            );
        }
        bad64::Operand::ShiftReg { reg, shift } => {
            t.push(&reg.to_string(), AsmKind::Register);
            t.push(",", AsmKind::Punctuation);
            t.space();
            arm64_shift_tokens(shift, &mut t);
        }
        bad64::Operand::QualReg { reg, qual } => {
            t.push(&format!("{reg}/{qual}"), AsmKind::Register);
        }
        bad64::Operand::Reg { reg, arrspec } => {
            t.push(&arm64_reg_text(*reg, *arrspec, true), AsmKind::Register);
        }
        bad64::Operand::MultiReg { regs, arrspec } => {
            t.push("{", AsmKind::Punctuation);
            for (i, reg) in regs.iter().flatten().enumerate() {
                if i > 0 {
                    t.push(",", AsmKind::Punctuation);
                    t.space();
                }
                t.push(&arm64_reg_text(*reg, *arrspec, false), AsmKind::Register);
            }
            t.push("}", AsmKind::Punctuation);
            if let Some(lane) = arrspec.and_then(|arsp| arsp.lane()) {
                t.push("[", AsmKind::Punctuation);
                t.push(&lane.to_string(), AsmKind::Number);
                t.push("]", AsmKind::Punctuation);
            }
        }
        bad64::Operand::SysReg(sr) => t.push(&sr.to_string(), AsmKind::Register),
        bad64::Operand::MemReg(reg) => {
            t.push("[", AsmKind::Punctuation);
            t.push(&reg.to_string(), AsmKind::Register);
            t.push("]", AsmKind::Punctuation);
        }
        bad64::Operand::MemPreIdx { reg, imm } => {
            t.push("[", AsmKind::Punctuation);
            t.push(&reg.to_string(), AsmKind::Register);
            t.push(",", AsmKind::Punctuation);
            t.space();
            t.push(&format!("#{imm}"), AsmKind::Number);
            t.push("]", AsmKind::Punctuation);
            t.push("!", AsmKind::Punctuation);
        }
        bad64::Operand::MemPostIdxImm { reg, imm } => {
            t.push("[", AsmKind::Punctuation);
            t.push(&reg.to_string(), AsmKind::Register);
            t.push("]", AsmKind::Punctuation);
            t.push(",", AsmKind::Punctuation);
            t.space();
            t.push(&format!("#{imm}"), AsmKind::Number);
        }
        bad64::Operand::MemPostIdxReg(regs) => {
            t.push("[", AsmKind::Punctuation);
            t.push(&regs[0].to_string(), AsmKind::Register);
            t.push("]", AsmKind::Punctuation);
            t.push(",", AsmKind::Punctuation);
            t.space();
            t.push(&regs[1].to_string(), AsmKind::Register);
        }
        bad64::Operand::MemExt {
            regs,
            shift,
            arrspec,
        } => {
            t.push("[", AsmKind::Punctuation);
            t.push(&arm64_reg_text(regs[0], *arrspec, false), AsmKind::Register);
            t.push(",", AsmKind::Punctuation);
            t.space();
            t.push(&arm64_reg_text(regs[1], *arrspec, false), AsmKind::Register);
            if let Some(shift) = shift {
                t.push(",", AsmKind::Punctuation);
                t.space();
                arm64_shift_tokens(shift, &mut t);
            }
            t.push("]", AsmKind::Punctuation);
        }
        bad64::Operand::MemOffset {
            reg,
            offset,
            arrspec,
            mul_vl,
        } => {
            t.push("[", AsmKind::Punctuation);
            t.push(&arm64_reg_text(*reg, *arrspec, false), AsmKind::Register);
            if !matches!(offset, bad64::Imm::Signed(0) | bad64::Imm::Unsigned(0)) {
                t.push(",", AsmKind::Punctuation);
                t.space();
                t.push(&format!("#{offset}"), AsmKind::Number);
                if *mul_vl {
                    t.push(",", AsmKind::Punctuation);
                    t.space();
                    t.push("mul", AsmKind::Keyword);
                    t.space();
                    t.push("vl", AsmKind::Keyword);
                }
            }
            t.push("]", AsmKind::Punctuation);
        }
        bad64::Operand::SmeTile { .. } => t.push(&op.to_string(), AsmKind::Text),
        bad64::Operand::AccumArray { reg, imm } => {
            t.push("ZA", AsmKind::Text);
            t.push("[", AsmKind::Punctuation);
            t.push(&reg.to_string(), AsmKind::Register);
            t.push(",", AsmKind::Punctuation);
            t.space();
            t.push(&format!("#{imm}"), AsmKind::Number);
            t.push("]", AsmKind::Punctuation);
        }
        bad64::Operand::IndexedElement { regs, arrspec, imm } => {
            t.push(&arm64_reg_text(regs[0], *arrspec, false), AsmKind::Register);
            t.push("[", AsmKind::Punctuation);
            t.push(&regs[1].to_string(), AsmKind::Register);
            if !matches!(imm, bad64::Imm::Signed(0) | bad64::Imm::Unsigned(0)) {
                t.push(",", AsmKind::Punctuation);
                t.space();
                t.push(&format!("#{imm}"), AsmKind::Number);
            }
            t.push("]", AsmKind::Punctuation);
        }
        bad64::Operand::Label(imm) => t.push(&imm.to_string(), AsmKind::Number),
        bad64::Operand::ImplSpec { .. } => t.push(&op.to_string(), AsmKind::Keyword),
        bad64::Operand::Cond(c) => t.push(&c.to_string(), AsmKind::Keyword),
        bad64::Operand::Name(_) => t.push(&op.to_string(), AsmKind::Text),
        bad64::Operand::StrImm { str, imm } => {
            // A NUL-padded ASCII name from the C decoder.
            let end = str.iter().position(|&b| b == 0).unwrap_or(str.len());
            let name = std::str::from_utf8(&str[..end]).unwrap_or("?");
            t.push(name, AsmKind::Text);
            t.space();
            t.push(&format!("#{imm:#x}"), AsmKind::Number);
        }
    }
    t.into_vec()
}

/// Symbol comment for an AArch64 PC-relative target. bad64 represents branch
/// and address-load destinations as `Label` operands with absolute addresses.
fn arm64_pcrel_comment(
    instruction: &bad64::Instruction,
    resolve: impl Fn(u64) -> String,
) -> Option<String> {
    use bad64::{Imm, Operand};
    let target = instruction.operands().iter().find_map(|op| match op {
        Operand::Label(imm) => Some(match imm {
            Imm::Signed(v) => *v,
            Imm::Unsigned(v) => *v as i64,
        }),
        _ => None,
    })?;
    Some(resolve(target as u64))
}

/// Decode up to `limit` instructions of `machine` code starting at `ip`.
pub fn decode_code(
    bytes: &[u8],
    ip: u64,
    limit: Option<usize>,
    machine: CodeMachine,
    resolve: impl Fn(u64) -> String,
) -> Vec<DisasmRow> {
    match x86_bitness(machine) {
        Some(bitness) => {
            let mut formatter = disasm_formatter();
            decode_rows(bytes, ip, limit, bitness, &mut formatter, resolve)
        }
        None => decode_rows_arm64(bytes, ip, limit, resolve),
    }
}

/// The iced decoder bitness for x86-family code; `None` for ARM64.
fn x86_bitness(machine: CodeMachine) -> Option<u32> {
    match machine {
        CodeMachine::X86 => Some(32),
        CodeMachine::Amd64 => Some(64),
        CodeMachine::Arm64 => None,
    }
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
    let Some(bitness) = x86_bitness(machine) else {
        // ARM64 instructions are four aligned bytes.
        return Some(ip & !3);
    };
    let mut decoder = Decoder::with_ip(bitness, bytes, start, DecoderOptions::NONE);
    loop {
        let at = decoder.ip();
        if at == ip {
            return Some(at);
        }
        if !decoder.can_decode() {
            return None;
        }
        let _ = decoder.decode();
        if decoder.ip() > ip {
            return Some(at);
        }
    }
}

/// Decode `count` instructions of `machine` code ending exactly at
/// `end_addr`.
///
/// `bytes` spans `read_start..end_addr`. Try each starting offset because x86
/// cannot decode backwards, preferring streams without invalid instructions.
/// Return `None` if no alignment reaches the end.
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
    let rows = match x86_bitness(machine) {
        Some(bitness) => {
            let offset = preceding_start_offset(bytes, read_start, end_addr, bitness)?;
            let start = read_start + offset as u64;
            let mut decoder =
                Decoder::with_ip(bitness, &bytes[offset..], start, DecoderOptions::NONE);
            let mut instruction_starts = Vec::new();
            while decoder.can_decode() {
                instruction_starts.push(decoder.ip());
                let _ = decoder.decode();
                if decoder.ip() >= end_addr {
                    break;
                }
            }
            let &tail_start =
                instruction_starts.get(instruction_starts.len().saturating_sub(count))?;
            let tail_offset = usize::try_from(tail_start - read_start).unwrap_or(offset);
            let mut formatter = disasm_formatter();
            decode_rows(
                &bytes[tail_offset..],
                tail_start,
                Some(count),
                bitness,
                &mut formatter,
                resolve,
            )
        }
        None => {
            let tail_len = count.saturating_mul(4);
            let tail_offset = bytes.len().saturating_sub(tail_len);
            decode_rows_arm64(
                &bytes[tail_offset..],
                read_start + tail_offset as u64,
                Some(count),
                resolve,
            )
        }
    };

    let ends_at_address = rows.last().is_some_and(|row| match x86_bitness(machine) {
        Some(bitness) => {
            let Ok(offset) = usize::try_from(row.ip.saturating_sub(read_start)) else {
                return false;
            };
            let Some(bytes) = bytes.get(offset..) else {
                return false;
            };
            let mut decoder = Decoder::with_ip(bitness, bytes, row.ip, DecoderOptions::NONE);
            if !decoder.can_decode() {
                return false;
            }
            let instruction = decoder.decode();
            instruction.code() != Code::INVALID && decoder.ip() == end_addr
        }
        None => row.ip.saturating_add(4) == end_addr,
    });
    ends_at_address.then_some(rows)
}

/// Find the byte offset in the lookbehind window whose instruction stream ends
/// exactly at `end_addr`, preferring one that decodes with no invalid
/// instruction along the way.
fn preceding_start_offset(
    bytes: &[u8],
    read_start: u64,
    end_addr: u64,
    bitness: u32,
) -> Option<usize> {
    let mut first_candidate = None;
    for offset in 0..bytes.len() {
        let start = read_start + offset as u64;
        let mut decoder = Decoder::with_ip(bitness, &bytes[offset..], start, DecoderOptions::NONE);
        let mut valid = true;
        while decoder.can_decode() {
            let instruction = decoder.decode();
            valid &= instruction.code() != Code::INVALID;
            let end = decoder.ip();
            if end >= end_addr {
                if end == end_addr {
                    first_candidate.get_or_insert(offset);
                    if valid {
                        return Some(offset);
                    }
                }
                break;
            }
        }
    }
    first_candidate
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
        let mut formatter = disasm_formatter();
        Structure {
            mnemonic: row.mnemonic(&mut formatter),
            length: row.length,
            operands: row.operands(&mut formatter),
        }
    }

    fn x64_row(bytes: &[u8]) -> Structure {
        let mut formatter = disasm_formatter();
        let rows = decode_rows(bytes, 0x1000, Some(1), 64, &mut formatter, |_| {
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
        let rows: Vec<Structure> = decode_rows_arm64(&bytes, 0x1000, None, |_| String::new())
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
        let rows = decode_rows_arm64(&bytes, 0x1000, None, |_| String::new());
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
            classify(&[0xe8, 0, 0, 0, 0], Arch::Amd64, 64),
            ControlFlow::Call
        );
        assert_eq!(classify(&[0xc3], Arch::Amd64, 64), ControlFlow::Ret);
        assert_eq!(classify(&[0xeb, 0], Arch::Amd64, 64), ControlFlow::Branch);
        assert_eq!(classify(&[0x90], Arch::Amd64, 64), ControlFlow::Other);

        assert_eq!(
            classify(&0x94000000u32.to_le_bytes(), Arch::Arm64, 64),
            ControlFlow::Call
        );
        assert_eq!(
            classify(&0xd65f03c0u32.to_le_bytes(), Arch::Arm64, 64),
            ControlFlow::Ret
        );
        assert_eq!(
            classify(&0x14000000u32.to_le_bytes(), Arch::Arm64, 64),
            ControlFlow::Branch
        );
        assert_eq!(
            classify(&0xd503201fu32.to_le_bytes(), Arch::Arm64, 64),
            ControlFlow::Other
        );
    }

    #[test]
    fn amd64_flow_classification_respects_effective_code_bitness() {
        assert_eq!(classify(&[0x48, 0xc3], Arch::Amd64, 32), ControlFlow::Other);
        assert_eq!(classify(&[0x48, 0xc3], Arch::Amd64, 64), ControlFlow::Ret);
    }

    #[test]
    fn x86_rows_mask_wrapping_branch_targets() {
        let target = Cell::new(u64::MAX);
        let mut formatter = disasm_formatter();
        let rows = decode_rows(
            &[0xe9, 0x0b, 0x00, 0x00, 0x00],
            0xffff_fff0,
            Some(1),
            32,
            &mut formatter,
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
        let mut formatter = disasm_formatter();
        let rows = decode_rows(&[0x90, 0xc3], 0xffff_ffff, None, 32, &mut formatter, |_| {
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
                Arch::Amd64,
                64,
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
                    Arch::Amd64,
                    64
                ),
                Some(0x1003)
            );
        }
    }

    #[test]
    fn amd64_fallthrough_run_end_returns_none_for_leading_control_flow() {
        assert_eq!(
            fallthrough_run_end(&[0xc3, 0x90], 0x1000, 0x1002, Arch::Amd64, 64),
            None
        );
    }

    #[test]
    fn fallthrough_run_end_stops_at_last_boundary_before_end() {
        let bytes = [0x48, 0x89, 0xc8, 0x48, 0x83, 0xc0, 0x01];
        assert_eq!(fallthrough_run_end(&bytes, 0, 6, Arch::Amd64, 64), Some(3));
        assert_eq!(fallthrough_run_end(&bytes, 0, 2, Arch::Amd64, 64), None);
    }

    #[test]
    fn x86_fallthrough_run_end_decodes_32_bit_code() {
        // `dec eax; ret` in 32-bit code, one `ret` with a REX prefix in 64-bit.
        let bytes = [0x48, 0xc3];
        assert_eq!(fallthrough_run_end(&bytes, 0, 2, Arch::Amd64, 32), Some(1));
        assert_eq!(fallthrough_run_end(&bytes, 0, 2, Arch::Amd64, 64), None);
    }

    #[test]
    fn arm64_fallthrough_run_end_handles_nops_and_leading_branch() {
        let nop = 0xd503201fu32.to_le_bytes();
        let mut nops = Vec::new();
        nops.extend_from_slice(&nop);
        nops.extend_from_slice(&nop);
        assert_eq!(
            fallthrough_run_end(&nops, 0x2000, 0x2008, Arch::Arm64, 64),
            Some(0x2008)
        );

        let branch = 0x14000000u32.to_le_bytes();
        assert_eq!(
            fallthrough_run_end(&branch, 0x2000, 0x2004, Arch::Arm64, 64),
            None
        );
    }

    #[test]
    fn instruction_length_rejects_truncated_encodings() {
        assert_eq!(instruction_length(&[0xe8, 0, 0, 0], Arch::Amd64, 64), None);
        assert_eq!(instruction_length(&[0, 0, 0], Arch::Arm64, 64), None);
    }

    #[test]
    fn arm64_rows_reproduce_bad64_display() {
        let mut checked = 0;

        let real = [
            0xd43e0000u32, // brk #0xf000
            0xd65f03c0,    // ret
            0xaa0203e3,    // mov x3, x2
            0x79400001,    // ldrh w1, [x0]
            0x17fffd28,    // b (pc-relative)
            0xa9bd7bfd,    // stp x29, x30, [sp, #-0x30]!
            0xf9400020,    // ldr x0, [x1]
            0x91000420,    // add x0, x1, #0x10
        ];
        for (i, word) in real.iter().enumerate() {
            let ins = decode(*word, 0x1000 + 4 * i as u64).expect("real instruction");
            let joined: String = arm64_row_tokens(&ins)
                .iter()
                .map(|t| t.text.as_str())
                .collect();
            assert_eq!(joined, ins.to_string(), "text drift for {word:#010x}");
            checked += 1;
        }

        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for i in 0..65536u64 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let word = (state >> 32) as u32;
            let Ok(ins) = decode(word, 0x2000 + 4 * i) else {
                continue;
            };
            let joined: String = arm64_row_tokens(&ins)
                .iter()
                .map(|t| t.text.as_str())
                .collect();
            assert_eq!(joined, ins.to_string(), "text drift for word {word:#010x}");
            checked += 1;
            if checked >= 500 {
                break;
            }
        }

        assert!(
            checked >= 500,
            "corpus only produced {checked} decodable instructions"
        );
    }

    #[test]
    fn arm64_pcrel_comments_resolve_targets() {
        // b -0x2d8
        let ins = decode(0x17fffd28, 0xfffff8009bb34ff8).unwrap();
        let comment = arm64_pcrel_comment(&ins, |t| format!("SYM:{t:#x}"));
        assert_eq!(comment.as_deref(), Some("SYM:0xfffff8009bb34498"));

        // cbnz w10, label
        let ins = decode(0x35ffffca, 0xfffff8009b40c998).unwrap();
        let comment = arm64_pcrel_comment(&ins, |t| format!("SYM:{t:#x}"));
        assert_eq!(comment.as_deref(), Some("SYM:0xfffff8009b40c990"));

        let ins = decode(0x90000000, 0x1000).unwrap(); // adrp x0, #0
        let comment = arm64_pcrel_comment(&ins, |t| format!("{t:#x}"));
        assert_eq!(comment.as_deref(), Some("0x1000"));

        let ins = decode(0xd65f03c0, 0x1000).unwrap();
        assert!(arm64_pcrel_comment(&ins, |_| String::new()).is_none());

        let ins = decode(0x94000005, 0x2000).unwrap();
        let comment = arm64_pcrel_comment(&ins, |t| format!("{t:#x}"));
        assert_eq!(comment.as_deref(), Some("0x2014"));
    }
}
