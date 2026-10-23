//! The A64 instruction set, decoded by bad64.

use crate::base::bytes::before_nul;
use crate::base::disasm::{
    AsmKind, AsmToken, ControlFlow, DisasmOperand, DisasmRow, Flow, InstructionSet, OperandKind,
};
use crate::base::types::CodeMachine;

use super::Arm64;

/// The instruction word at the start of `bytes`.
fn word(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

impl InstructionSet for Arm64 {
    fn decode_first(&self, bytes: &[u8]) -> Option<(usize, ControlFlow)> {
        let instruction = bad64::decode(word(bytes)?, 0).ok()?;
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

    fn walk_step(&self, bytes: &[u8], ip: u64) -> Option<(u64, Flow)> {
        let instruction = bad64::decode(word(bytes)?, ip).ok()?;
        let target = instruction.operands().iter().find_map(|op| match op {
            bad64::Operand::Label(imm) => Some(immediate_value(*imm) as u64),
            _ => None,
        });
        let mnemonic = instruction.op().mnem();
        let flow = match (mnemonic, target) {
            ("b", Some(target)) => Flow::Jump(target),
            ("cbz" | "cbnz" | "tbz" | "tbnz", Some(target)) => Flow::Fork(target),
            (_, Some(target)) if mnemonic.starts_with("b.") => Flow::Fork(target),
            _ if mnemonic.starts_with("ret")
                || mnemonic == "br"
                || mnemonic.starts_with("bra")
                || mnemonic.starts_with("eret")
                || mnemonic == "brk"
                || mnemonic == "udf" =>
            {
                Flow::End
            }
            _ => Flow::Next,
        };
        Some((ip + 4, flow))
    }

    fn decode_rows(
        &self,
        bytes: &[u8],
        ip: u64,
        limit: Option<usize>,
        resolve: &dyn Fn(u64) -> String,
    ) -> Vec<DisasmRow> {
        decode_rows(bytes, ip, limit, resolve)
    }

    /// `.inst` for a word that encodes no instruction.
    fn mnemonic(&self, bytes: &[u8], ip: u64) -> String {
        word(bytes)
            .and_then(|word| bad64::decode(word, ip).ok())
            .map_or_else(
                || ".inst".to_string(),
                |instruction| instruction.op().mnem().to_string(),
            )
    }

    fn operands(&self, bytes: &[u8], ip: u64) -> Vec<DisasmOperand> {
        word(bytes)
            .and_then(|word| bad64::decode(word, ip).ok())
            .map(|instruction| {
                instruction
                    .operands()
                    .iter()
                    .map(|op| {
                        let text = operand_tokens(op)
                            .iter()
                            .map(|token| token.text.as_str())
                            .collect();
                        describe_operand(op, text)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Instructions are four aligned bytes.
    fn instruction_containing(&self, _bytes: &[u8], _start: u64, ip: u64) -> Option<u64> {
        Some(ip & !3)
    }

    /// `b.<cond>` on NZCV, `cbz`/`cbnz` on a register, `tbz`/`tbnz` on one
    /// of its bits.
    fn condition_holds(
        &self,
        bytes: &[u8],
        ip: u64,
        read: &dyn Fn(&str) -> Option<u64>,
    ) -> Option<bool> {
        let instruction = bad64::decode(word(bytes)?, ip).ok()?;
        let mnemonic = instruction.op().mnem();
        let operands = self.operands(bytes, ip);
        let register = || -> Option<u64> {
            let operand = operands.first()?;
            let value = read(operand.full_register.as_deref()?)?;
            let narrow = operand
                .register
                .as_deref()
                .is_some_and(|name| name.starts_with('w'));
            Some(if narrow { value & 0xffff_ffff } else { value })
        };
        match mnemonic {
            "cbz" => return Some(register()? == 0),
            "cbnz" => return Some(register()? != 0),
            "tbz" | "tbnz" => {
                let bit = u32::try_from(operands.get(1)?.immediate?).ok()?;
                let set = register()?.checked_shr(bit)? & 1 != 0;
                return Some(set == (mnemonic == "tbnz"));
            }
            _ => {}
        }
        let cpsr = read("cpsr")?;
        let flag = |bit: u32| cpsr >> bit & 1 != 0;
        let (n, z, c, v) = (flag(31), flag(30), flag(29), flag(28));
        Some(match mnemonic.strip_prefix("b.")? {
            "eq" => z,
            "ne" => !z,
            "cs" | "hs" => c,
            "cc" | "lo" => !c,
            "mi" => n,
            "pl" => !n,
            "vs" => v,
            "vc" => !v,
            "hi" => c && !z,
            "ls" => !c || z,
            "ge" => n == v,
            "lt" => n != v,
            "gt" => !z && n == v,
            "le" => z || n != v,
            "al" | "nv" => true,
            _ => return None,
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
        let tail_len = count.saturating_mul(4);
        let tail_offset = bytes.len().saturating_sub(tail_len);
        let rows = decode_rows(
            &bytes[tail_offset..],
            read_start + tail_offset as u64,
            Some(count),
            resolve,
        );
        let ends_at_address = rows
            .last()
            .is_some_and(|row| row.ip.saturating_add(4) == end_addr);
        ends_at_address.then_some(rows)
    }
}

/// Decode AArch64 instructions into rows. They are fixed 4 bytes; branch
/// and conditional-branch targets get symbol comments.
fn decode_rows(
    bytes: &[u8],
    start_addr: u64,
    limit: Option<usize>,
    resolve: &dyn Fn(u64) -> String,
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
                rows.push(DisasmRow::new(
                    CodeMachine::Arm64,
                    ip,
                    word,
                    vec![
                        AsmToken {
                            text: ".inst".to_string(),
                            kind: AsmKind::Keyword,
                        },
                        AsmToken {
                            text: format!(" {value:#010x}"),
                            kind: AsmKind::Number,
                        },
                    ],
                    None,
                ));
                continue;
            }
        };
        let ip = instruction.address();
        let start_index = (ip - start_addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + 4];

        // The x64 path gets semantic tokens from iced's formatter; bad64 has
        // no formatter callback, but exposes typed operands, so classify those
        // into the same palette while reproducing the decoder's Display text
        // exactly (spaces live inside token text, so `asm()` is unchanged).
        let tokens = row_tokens(&instruction);

        let comment = pcrel_comment(&instruction, resolve);
        rows.push(DisasmRow::new(
            CodeMachine::Arm64,
            ip,
            instr_bytes,
            tokens,
            comment,
        ));
    }
    rows
}

/// Build the semantic token stream for a decoded AArch64 instruction:
/// mnemonic plus one classified token group per operand, reproducing bad64's
/// Display text exactly.
fn row_tokens(instruction: &bad64::Instruction) -> Vec<AsmToken> {
    let text = instruction.to_string();
    let mut tokens = Vec::new();
    match text.split_once(' ') {
        Some((mnem, _)) => {
            tokens.push(AsmToken {
                text: mnem.to_string(),
                kind: AsmKind::Mnemonic,
            });
            for (i, op) in instruction.operands().iter().enumerate() {
                let mut op_tokens = operand_tokens(op);
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
fn describe_operand(op: &bad64::Operand, text: String) -> DisasmOperand {
    use bad64::Operand;
    let mut out = DisasmOperand::new(OperandKind::Other, text);
    let full = |reg: bad64::Reg| Some(full_register(reg));
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
            let value = immediate_value(imm);
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
            out.displacement = (!mul_vl).then(|| immediate_value(offset) as i64);
        }
        Operand::MemPreIdx { reg, imm } | Operand::MemPostIdxImm { reg, imm } => {
            out.kind = OperandKind::Memory;
            out.base = full(reg);
            out.displacement = Some(immediate_value(imm) as i64);
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
            out.immediate = Some(i128::from(immediate_value(imm) as u64));
        }
        _ => {}
    }
    out
}

fn immediate_value(imm: bad64::Imm) -> i128 {
    match imm {
        bad64::Imm::Signed(value) => value.into(),
        bad64::Imm::Unsigned(value) => value.into(),
    }
}

/// The X register a W register is the low half of (`w3` -> `x3`, `wzr` ->
/// `xzr`, `wsp` -> `sp`); every other register is its own.
fn full_register(reg: bad64::Reg) -> String {
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
struct Tokens {
    items: Vec<AsmToken>,
    space: bool,
}

impl Tokens {
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
fn register_text(reg: bad64::Reg, arrspec: Option<bad64::ArrSpec>, lane: bool) -> String {
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
fn shift_tokens(shift: &bad64::Shift, t: &mut Tokens) {
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
fn operand_tokens(op: &bad64::Operand) -> Vec<AsmToken> {
    let mut t = Tokens::new();
    match op {
        bad64::Operand::Imm32 { imm, shift } | bad64::Operand::Imm64 { imm, shift } => {
            t.push(&format!("#{imm}"), AsmKind::Number);
            if let Some(shift) = shift {
                t.push(",", AsmKind::Punctuation);
                t.space();
                shift_tokens(shift, &mut t);
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
            shift_tokens(shift, &mut t);
        }
        bad64::Operand::QualReg { reg, qual } => {
            t.push(&format!("{reg}/{qual}"), AsmKind::Register);
        }
        bad64::Operand::Reg { reg, arrspec } => {
            t.push(&register_text(*reg, *arrspec, true), AsmKind::Register);
        }
        bad64::Operand::MultiReg { regs, arrspec } => {
            t.push("{", AsmKind::Punctuation);
            for (i, reg) in regs.iter().flatten().enumerate() {
                if i > 0 {
                    t.push(",", AsmKind::Punctuation);
                    t.space();
                }
                t.push(&register_text(*reg, *arrspec, false), AsmKind::Register);
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
            t.push(&register_text(regs[0], *arrspec, false), AsmKind::Register);
            t.push(",", AsmKind::Punctuation);
            t.space();
            t.push(&register_text(regs[1], *arrspec, false), AsmKind::Register);
            if let Some(shift) = shift {
                t.push(",", AsmKind::Punctuation);
                t.space();
                shift_tokens(shift, &mut t);
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
            t.push(&register_text(*reg, *arrspec, false), AsmKind::Register);
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
            t.push(&register_text(regs[0], *arrspec, false), AsmKind::Register);
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
            let name = std::str::from_utf8(before_nul(str)).unwrap_or("?");
            t.push(name, AsmKind::Text);
            t.space();
            t.push(&format!("#{imm:#x}"), AsmKind::Number);
        }
    }
    t.into_vec()
}

/// Symbol comment for an AArch64 PC-relative target. bad64 represents branch
/// and address-load destinations as `Label` operands with absolute addresses.
fn pcrel_comment(
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

#[cfg(test)]
mod tests {
    use bad64::decode;

    use super::*;

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
            let joined: String = row_tokens(&ins).iter().map(|t| t.text.as_str()).collect();
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
            let joined: String = row_tokens(&ins).iter().map(|t| t.text.as_str()).collect();
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
        let comment = pcrel_comment(&ins, |t| format!("SYM:{t:#x}"));
        assert_eq!(comment.as_deref(), Some("SYM:0xfffff8009bb34498"));

        // cbnz w10, label
        let ins = decode(0x35ffffca, 0xfffff8009b40c998).unwrap();
        let comment = pcrel_comment(&ins, |t| format!("SYM:{t:#x}"));
        assert_eq!(comment.as_deref(), Some("SYM:0xfffff8009b40c990"));

        let ins = decode(0x90000000, 0x1000).unwrap(); // adrp x0, #0
        let comment = pcrel_comment(&ins, |t| format!("{t:#x}"));
        assert_eq!(comment.as_deref(), Some("0x1000"));

        let ins = decode(0xd65f03c0, 0x1000).unwrap();
        assert!(pcrel_comment(&ins, |_| String::new()).is_none());

        let ins = decode(0x94000005, 0x2000).unwrap();
        let comment = pcrel_comment(&ins, |t| format!("{t:#x}"));
        assert_eq!(comment.as_deref(), Some("0x2014"));
    }
}
