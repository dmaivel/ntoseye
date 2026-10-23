//! The x86 instruction set, at 32 or 64 bits, decoded by iced: AMD64's own
//! code, a WOW64 process's x86 code, and the x64 code ARM64 Windows
//! emulates.

use iced_x86::{
    Code, ConditionCode, Decoder, DecoderOptions, FlowControl, FormatMnemonicOptions, Formatter,
    FormatterOutput, FormatterTextKind, Instruction, MemorySizeOptions, Mnemonic, NasmFormatter,
    OpKind, Register,
};

use crate::base::disasm::{
    AsmKind, AsmToken, ControlFlow, DisasmOperand, DisasmRow, Flow, InstructionSet, OperandKind,
};
use crate::base::types::CodeMachine;

/// x86 code at a bitness.
pub struct X86 {
    bitness: u32,
}

impl X86 {
    /// 32-bit x86 code.
    pub const CODE32: Self = Self { bitness: 32 };
    /// 64-bit x64 code.
    pub const CODE64: Self = Self { bitness: 64 };

    /// The instruction at the start of `bytes`, mapped at `ip`.
    fn decode_at(&self, bytes: &[u8], ip: u64) -> Instruction {
        Decoder::with_ip(self.bitness, bytes, ip, DecoderOptions::NONE).decode()
    }
}

/// The machine whose code `bitness` decodes.
fn machine(bitness: u32) -> CodeMachine {
    if bitness == 32 {
        CodeMachine::X86
    } else {
        CodeMachine::Amd64
    }
}

impl InstructionSet for X86 {
    fn decode_first(&self, bytes: &[u8]) -> Option<(usize, ControlFlow)> {
        let mut decoder = Decoder::with_ip(self.bitness, bytes, 0, DecoderOptions::NONE);
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

    fn walk_step(&self, bytes: &[u8], ip: u64) -> Option<(u64, Flow)> {
        let instruction = self.decode_at(bytes, ip);
        if instruction.is_invalid() {
            return None;
        }
        let flow = match instruction.flow_control() {
            FlowControl::ConditionalBranch => Flow::Fork(instruction.near_branch_target()),
            FlowControl::UnconditionalBranch if instruction.is_jmp_short_or_near() => {
                Flow::Jump(instruction.near_branch_target())
            }
            FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => Flow::Next,
            _ => Flow::End,
        };
        Some((instruction.next_ip(), flow))
    }

    fn decode_rows(
        &self,
        bytes: &[u8],
        ip: u64,
        limit: Option<usize>,
        resolve: &dyn Fn(u64) -> String,
    ) -> Vec<DisasmRow> {
        decode_rows(
            bytes,
            ip,
            limit,
            self.bitness,
            &mut disasm_formatter(),
            resolve,
        )
    }

    fn mnemonic(&self, bytes: &[u8], ip: u64) -> String {
        mnemonic_text(&self.decode_at(bytes, ip), &mut disasm_formatter())
    }

    fn operands(&self, bytes: &[u8], ip: u64) -> Vec<DisasmOperand> {
        describe_operands(
            &self.decode_at(bytes, ip),
            self.bitness,
            &mut disasm_formatter(),
        )
    }

    fn instruction_containing(&self, bytes: &[u8], start: u64, ip: u64) -> Option<u64> {
        let mut decoder = Decoder::with_ip(self.bitness, bytes, start, DecoderOptions::NONE);
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

    /// x86 cannot decode backwards, so every starting offset is tried,
    /// preferring a stream without invalid instructions.
    /// `call rel32`, or an indirect `call` through a register or memory.
    fn ends_in_call(&self, before: &[u8]) -> bool {
        let n = before.len();
        if n >= 5 && before[n - 5] == 0xe8 {
            return true;
        }
        (2..=7).any(|length| {
            n >= length && {
                let modrm = match &before[n - length..] {
                    [0x41 | 0x48 | 0x49, 0xff, modrm, ..] | [0xff, modrm, ..] => *modrm,
                    _ => return false,
                };
                (modrm >> 3) & 7 == 2
            }
        })
    }

    fn condition_holds(
        &self,
        bytes: &[u8],
        ip: u64,
        read: &dyn Fn(&str) -> Option<u64>,
    ) -> Option<bool> {
        let instruction = self.decode_at(bytes, ip);
        match instruction.mnemonic() {
            Mnemonic::Jrcxz => return Some(read("rcx")? == 0),
            Mnemonic::Jecxz => return Some(read("rcx")? as u32 == 0),
            Mnemonic::Jcxz => return Some(read("rcx")? as u16 == 0),
            Mnemonic::Loop | Mnemonic::Loope | Mnemonic::Loopne => return None,
            _ => {}
        }
        let flags = read("eflags")?;
        let flag = |bit: u32| flags >> bit & 1 != 0;
        let (cf, pf, zf, sf, of) = (flag(0), flag(2), flag(6), flag(7), flag(11));
        Some(match instruction.condition_code() {
            ConditionCode::o => of,
            ConditionCode::no => !of,
            ConditionCode::b => cf,
            ConditionCode::ae => !cf,
            ConditionCode::e => zf,
            ConditionCode::ne => !zf,
            ConditionCode::be => cf || zf,
            ConditionCode::a => !cf && !zf,
            ConditionCode::s => sf,
            ConditionCode::ns => !sf,
            ConditionCode::p => pf,
            ConditionCode::np => !pf,
            ConditionCode::l => sf != of,
            ConditionCode::ge => sf == of,
            ConditionCode::le => zf || sf != of,
            ConditionCode::g => !zf && sf == of,
            ConditionCode::None => return None,
        })
    }

    fn decode_preceding(
        &self,
        bytes: &[u8],
        read_start: u64,
        end_addr: u64,
        count: usize,
        resolve: &dyn Fn(u64) -> String,
    ) -> Option<Vec<DisasmRow>> {
        let bitness = self.bitness;
        let offset = preceding_start_offset(bytes, read_start, end_addr, bitness)?;
        let start = read_start + offset as u64;
        let mut decoder = Decoder::with_ip(bitness, &bytes[offset..], start, DecoderOptions::NONE);
        let mut instruction_starts = Vec::new();
        while decoder.can_decode() {
            instruction_starts.push(decoder.ip());
            let _ = decoder.decode();
            if decoder.ip() >= end_addr {
                break;
            }
        }
        let &tail_start = instruction_starts.get(instruction_starts.len().saturating_sub(count))?;
        let tail_offset = usize::try_from(tail_start - read_start).unwrap_or(offset);
        let rows = decode_rows(
            &bytes[tail_offset..],
            tail_start,
            Some(count),
            bitness,
            &mut disasm_formatter(),
            resolve,
        );
        let ends_at_address = rows.last().is_some_and(|row| {
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
        });
        ends_at_address.then_some(rows)
    }
}

/// NASM formatter configured for ntoseye's disassembly, so every call site
/// decodes identically.
fn disasm_formatter() -> NasmFormatter {
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

fn mask_code_address(bitness: u32, address: u64) -> u64 {
    if bitness == 32 {
        address & u64::from(u32::MAX)
    } else {
        address
    }
}

/// The explicit operands of a decoded x86 instruction, one per operand the
/// formatter prints (so the list matches `asm`), in order.
fn describe_operands(
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
            fill_operand(&mut op, instruction, index, bitness, formatter);
        }
        operands.push(op);
    }
    operands
}

/// Classify instruction operand `index` into `op`.
fn fill_operand(
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
            op.full_register = name(full_register(register, bitness));
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
            op.base = name(full_register(base, bitness));
            op.index = name(full_register(index_register, bitness));
            op.scale = (index_register != Register::None).then(|| instruction.memory_index_scale());
            op.displacement = Some(memory_displacement(instruction, bitness));
            op.segment = name(instruction.segment_prefix());
            op.size = memory_size(instruction);
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
            op.base = name(full_register(base, bitness));
            op.displacement = Some(0);
            // `es:di` is fixed; only the `seg:` forms take an override.
            if !matches!(
                kind,
                OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI
            ) {
                op.segment = name(instruction.segment_prefix());
            }
            op.size = memory_size(instruction);
            (OperandKind::Memory, None)
        }
    };
    op.kind = kind;
    op.immediate = value;
}

/// The register `register` is part of: the 64-bit GPR in 64-bit code (the
/// 32-bit one in 32-bit code); vector registers stay as written (`xmm0`, not
/// `zmm0`).
fn full_register(register: Register, bitness: u32) -> Register {
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
fn memory_displacement(instruction: &Instruction, bitness: u32) -> i64 {
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

fn memory_size(instruction: &Instruction) -> Option<u32> {
    let size = instruction.memory_size().size();
    (size != 0).then_some(size as u32)
}

/// The lowercase mnemonic of `instruction`, without prefixes, as `asm` shows it.
fn mnemonic_text(instruction: &Instruction, formatter: &mut NasmFormatter) -> String {
    let mut mnemonic = String::new();
    formatter.format_mnemonic_options(
        instruction,
        &mut mnemonic,
        FormatMnemonicOptions::NO_PREFIXES,
    );
    mnemonic
}

/// Decode `bytes` (loaded at `start_addr`) into rows with the given x86
/// `bitness`, stopping after `limit` instructions when `Some`. `resolve`
/// turns a branch / RIP-relative target into a symbol comment.
fn decode_rows(
    bytes: &[u8],
    start_addr: u64,
    limit: Option<usize>,
    bitness: u32,
    formatter: &mut NasmFormatter,
    resolve: &dyn Fn(u64) -> String,
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

        rows.push(DisasmRow::new(
            machine(bitness),
            ip,
            instr_bytes,
            tokens,
            comment,
        ));
    }

    rows
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
