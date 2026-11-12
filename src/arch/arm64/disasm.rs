//! The A64 instruction set, decoded by exarmo.

use exarmo_aarch64::{
    BranchKind, Cond, Instruction, Mnemonic, Modifier, ModifierKind, Offset, Operand, Reg, Token,
    TokenKind, decode_word, disassemble,
};

use crate::base::disasm::{
    AsmKind, AsmToken, ControlFlow, DisasmOperand, DisasmRow, Flow, InstructionSet, OperandKind,
};
use crate::base::types::CodeMachine;

use super::Arm64;

/// The instruction word at the start of `bytes`.
pub fn word(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

/// The instruction `bytes` start with.
fn decode(bytes: &[u8]) -> Option<Instruction> {
    decode_word(word(bytes)?).ok()
}

/// The tokens exarmo's formatter writes for `instruction` at `ip`.
fn formatted(instruction: Instruction, ip: u64) -> Vec<Token> {
    let mut tokens = Vec::new();
    // A token sink that allocates cannot fail.
    let _ = instruction.at(ip).write_tokens(&mut tokens);
    tokens
}

/// The mnemonic as the assembly writes it, condition included (`b.eq`); the
/// formatter splits that into `b`, `.` and the condition.
fn mnemonic_text(tokens: &[Token]) -> String {
    tokens
        .iter()
        .filter(|token| token.kind == TokenKind::Mnemonic)
        .map(|token| token.text.as_str())
        .collect()
}

/// One of exarmo's tokens as ntoseye's: the formatter separates the mnemonic
/// from the operands with a tab, where ntoseye writes a space.
fn asm_token(token: &Token) -> AsmToken {
    if token.text == "\t" {
        return AsmToken {
            text: " ".to_string(),
            kind: AsmKind::Text,
        };
    }
    AsmToken {
        text: token.text.clone(),
        kind: token_kind(&token.text, token.kind),
    }
}

/// The palette kind of one token. `Text` holds both the punctuation between
/// operands (`#`, `!`, `,`) and words the template writes (`mul vl`), which
/// are told apart by spelling.
fn token_kind(text: &str, kind: TokenKind) -> AsmKind {
    match kind {
        TokenKind::Mnemonic => AsmKind::Mnemonic,
        TokenKind::Register => AsmKind::Register,
        TokenKind::Symbol => AsmKind::Keyword,
        TokenKind::Immediate(_)
        | TokenKind::Integer(_)
        | TokenKind::Float
        | TokenKind::Address(_) => AsmKind::Number,
        TokenKind::Separator | TokenKind::Bracket => AsmKind::Punctuation,
        TokenKind::Text if text.chars().any(|c| c.is_ascii_alphanumeric()) => AsmKind::Keyword,
        TokenKind::Text => AsmKind::Punctuation,
    }
}

/// Operand `index` as the assembly writes it, from the tokens that belong to
/// it; empty when the assembly does not write it (`ret`'s register).
fn operand_text(tokens: &[Token], index: usize) -> String {
    let index = u8::try_from(index).ok();
    tokens
        .iter()
        .filter(|token| token.operand.is_some() && token.operand == index)
        .map(|token| token.text.as_str())
        .collect::<String>()
        .trim()
        .to_string()
}

/// The semantic token stream for a decoded instruction.
fn row_tokens(tokens: &[Token]) -> Vec<AsmToken> {
    tokens.iter().map(asm_token).collect()
}

impl InstructionSet for Arm64 {
    fn decode_first(&self, bytes: &[u8]) -> Option<(usize, ControlFlow)> {
        let instruction = decode(bytes)?;
        let flow = match instruction.at(0).branch().kind {
            BranchKind::DirectCall | BranchKind::IndirectCall => ControlFlow::Call,
            BranchKind::Return | BranchKind::ExceptionReturn => ControlFlow::Ret,
            BranchKind::Direct | BranchKind::Indirect => ControlFlow::Branch,
            // `brk`, `udf`, `svc`, `hlt`, and everything that does not branch.
            _ => ControlFlow::Other,
        };
        Some((4, flow))
    }

    fn walk_step(&self, bytes: &[u8], ip: u64) -> Option<(u64, Flow)> {
        let instruction = decode(bytes)?;
        let branch = instruction.at(ip).branch();
        let flow = match branch.kind {
            // A conditional branch falls through, an unconditional one does not.
            BranchKind::Direct => match (branch.conditional, branch.target) {
                (true, Some(target)) => Flow::Fork(target),
                (false, Some(target)) => Flow::Jump(target),
                _ => Flow::Next,
            },
            // `ret`, `eret`, `br`, `braa`/`braaz`/…, and `hlt`.
            BranchKind::Return
            | BranchKind::ExceptionReturn
            | BranchKind::Indirect
            | BranchKind::Halt => Flow::End,
            // `brk` and `udf` stop the code that follows them from running.
            BranchKind::Exception => Flow::End,
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
        match decode(bytes) {
            Some(instruction) => mnemonic_text(&formatted(instruction, ip)),
            None => ".inst".to_string(),
        }
    }

    fn operands(&self, bytes: &[u8], ip: u64) -> Vec<DisasmOperand> {
        let Some(instruction) = decode(bytes) else {
            return Vec::new();
        };
        let tokens = formatted(instruction, ip);
        instruction
            .operands()
            .iter()
            .enumerate()
            .filter_map(|(index, operand)| {
                let text = operand_text(&tokens, index);
                // An operand the assembly does not write is not a piece of it.
                (!text.is_empty()).then(|| describe_operand(operand, text, ip))
            })
            .collect()
    }

    /// Instructions are four aligned bytes.
    fn instruction_containing(&self, _bytes: &[u8], _start: u64, ip: u64) -> Option<u64> {
        Some(ip & !3)
    }

    fn ends_in_call(&self, before: &[u8]) -> bool {
        before
            .len()
            .checked_sub(4)
            .and_then(|at| self.decode_first(&before[at..]))
            .is_some_and(|(_, flow)| flow == ControlFlow::Call)
    }

    /// `b.<cond>` on NZCV, `cbz`/`cbnz` on a register, `tbz`/`tbnz` on one
    /// of its bits.
    fn condition_holds(
        &self,
        bytes: &[u8],
        ip: u64,
        read: &dyn Fn(&str) -> Option<u64>,
    ) -> Option<bool> {
        let instruction = decode(bytes)?;
        if !instruction.at(ip).branch().conditional {
            return None;
        }
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
        match instruction.mnemonic() {
            Mnemonic::Cbz => return Some(register()? == 0),
            Mnemonic::Cbnz => return Some(register()? != 0),
            Mnemonic::Tbz | Mnemonic::Tbnz => {
                let bit = u32::try_from(operands.get(1)?.immediate?).ok()?;
                let set = register()?.checked_shr(bit)? & 1 != 0;
                return Some(set == (instruction.mnemonic() == Mnemonic::Tbnz));
            }
            _ => {}
        }
        // A conditional branch writes the condition it tests as an operand.
        let condition = instruction
            .operands()
            .iter()
            .find_map(|operand| match operand {
                Operand::Cond(condition) => Some(*condition),
                _ => None,
            })?;
        let cpsr = read("cpsr")?;
        let flag = |bit: u32| cpsr >> bit & 1 != 0;
        let (n, z, c, v) = (flag(31), flag(30), flag(29), flag(28));
        Some(match condition {
            Cond::Eq => z,
            Cond::Ne => !z,
            Cond::Cs => c,
            Cond::Cc => !c,
            Cond::Mi => n,
            Cond::Pl => !n,
            Cond::Vs => v,
            Cond::Vc => !v,
            Cond::Hi => c && !z,
            Cond::Ls => !c || z,
            Cond::Ge => n == v,
            Cond::Lt => n != v,
            Cond::Gt => !z && n == v,
            Cond::Le => z || n != v,
            Cond::Al | Cond::Nv => true,
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
    for (ip, result) in disassemble(bytes, start_addr) {
        if limit.is_some_and(|n| rows.len() >= n) {
            break;
        }
        // A word that encodes no instruction (a literal, a data slot) is
        // shown as the word, as objdump does; the next one starts 4 bytes on.
        let Ok(instruction) = result else {
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
        };
        let start_index = (ip - start_addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + 4];
        // exarmo writes the instruction as typed tokens, so the row's text
        // and its structure come from one pass over the same formatter.
        let stream = formatted(instruction, ip);
        let comment = pcrel_comment(instruction, ip, resolve);
        rows.push(DisasmRow::new(
            CodeMachine::Arm64,
            ip,
            instr_bytes,
            row_tokens(&stream),
            comment,
        ));
    }
    rows
}

/// Classify one operand. Post-indexed forms (`[x1], #8`) report the
/// writeback offset as `displacement`/`index`, although the access uses the
/// base alone.
fn describe_operand(operand: &Operand, text: String, ip: u64) -> DisasmOperand {
    let mut out = DisasmOperand::new(OperandKind::Other, text);
    match *operand {
        Operand::Reg(reg) => {
            out.kind = OperandKind::Register;
            // The arrangement (`v0.4s`) is in the text; the register is `v0`.
            out.register = Some(reg.reg.to_string());
            out.full_register = Some(full_register(reg.reg));
        }
        Operand::SysReg(sysreg) => {
            out.kind = OperandKind::Register;
            out.register = sysreg.name().map(str::to_string);
            out.full_register = out.register.clone();
        }
        Operand::Imm { value, modifier } => {
            if let Some(value) = shifted_immediate(value, modifier) {
                out.kind = OperandKind::Immediate;
                out.immediate = Some(value);
            }
        }
        Operand::Label { offset, pc } => {
            out.kind = OperandKind::Branch;
            out.immediate = Some(i128::from(pc.target(ip, offset, 64)));
        }
        Operand::Mem(mem) => {
            out.kind = OperandKind::Memory;
            out.base = Some(full_register(mem.base));
            match mem.offset {
                Offset::None => {}
                // `mul vl` scales the offset by the SVE vector length.
                Offset::Imm { value, mul_vl } => {
                    out.displacement = (!mul_vl).then_some(value);
                }
                Offset::Reg { reg, modifier } => {
                    out.index = Some(full_register(reg));
                    out.scale = Some(index_scale(modifier));
                }
                Offset::Vector { reg, modifier, .. } => {
                    out.index = Some(full_register(reg));
                    out.scale = Some(index_scale(modifier));
                }
            }
        }
        _ => out.kind = OperandKind::Other,
    }
    out
}

/// An immediate after the shift the assembly writes on it, or `None` when
/// it is shifted by one this does not model.
fn shifted_immediate(value: i64, modifier: Option<Modifier>) -> Option<i128> {
    let value = i128::from(value);
    match modifier {
        None => Some(value),
        Some(Modifier {
            kind: ModifierKind::Lsl,
            amount,
        }) => value.checked_shl(amount?),
        Some(Modifier {
            kind: ModifierKind::Msl,
            amount,
        }) => {
            let amount = amount?;
            Some((value << amount) | ((1i128 << amount) - 1))
        }
        Some(_) => None,
    }
}

/// How far a register offset is scaled, for the extends the assembly writes
/// on one.
fn index_scale(modifier: Option<Modifier>) -> u32 {
    match modifier {
        Some(Modifier {
            kind:
                ModifierKind::Lsl
                | ModifierKind::Sxtw
                | ModifierKind::Uxtw
                | ModifierKind::Sxtx
                | ModifierKind::Uxtx,
            amount: Some(amount),
        }) => 1 << amount,
        _ => 1,
    }
}

/// The architectural register a written one is part of: `w3` -> `x3`, `wzr`
/// -> `xzr`, `wsp` -> `sp`, and the assembler's names for the frame pointer
/// and link register -> `x29` and `x30`. Only the text keeps the spelling.
fn full_register(reg: Reg) -> String {
    let name = reg.to_string();
    match name.as_str() {
        "fp" => return "x29".to_string(),
        "lr" => return "x30".to_string(),
        _ => {}
    }
    match name.strip_prefix('w') {
        Some("sp") => "sp".to_string(),
        Some(rest) if rest == "zr" || rest.bytes().all(|b| b.is_ascii_digit()) => {
            format!("x{rest}")
        }
        _ => name,
    }
}

/// Symbol comment for an AArch64 PC-relative target: branch destinations and
/// `adrp`'s page are label operands naming an absolute address.
fn pcrel_comment(
    instruction: Instruction,
    ip: u64,
    resolve: impl Fn(u64) -> String,
) -> Option<String> {
    let target = instruction
        .operands()
        .iter()
        .find_map(|operand| match operand {
            Operand::Label { offset, pc } => Some(pc.target(ip, *offset, 64)),
            _ => None,
        })?;
    Some(resolve(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_rows_reproduce_the_decoder_text() {
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
            0x54000061,    // b.ne
            0xf8617820,    // ldr x0, [x1, x1, lsl #3]
            0x4e21b820,    // a SIMD instruction with arrangements
            0xd5380000,    // mrs x0, midr_el1
        ];
        for (i, word) in real.iter().enumerate() {
            let ip = 0x1000 + 4 * i as u64;
            let instruction = decode_word(*word).expect("real instruction");
            let tokens = formatted(instruction, ip);
            let joined: String = row_tokens(&tokens)
                .iter()
                .map(|t| t.text.as_str())
                .collect();
            // The only difference is the formatter's tab after the mnemonic.
            assert_eq!(
                joined,
                instruction.at(ip).to_string().replace('\t', " "),
                "text drift for {word:#010x}"
            );
            assert_eq!(mnemonic_text(&tokens), row_mnemonic(*word), "{word:#010x}");
            checked += 1;
        }

        // A negative immediate reads as one; the decoder writes it that way
        // and the row's text is the decoder's, so this pins the case the
        // previous decoder got wrong (it printed the two's complement).
        for (word, text) in [
            (0xa9bd7bfdu32, "stp fp, lr, [sp, #-0x30]!"),
            (0xf85f83a0, "ldur x0, [fp, #-0x8]"),
        ] {
            let ip = 0x1000;
            let joined: String = row_tokens(&formatted(decode_word(word).unwrap(), ip))
                .iter()
                .map(|t| t.text.as_str())
                .collect();
            assert_eq!(joined, text, "{word:#010x}");
            checked += 1;
        }

        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for i in 0..65536u64 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let word = (state >> 32) as u32;
            let ip = 0x2000 + 4 * i;
            let Ok(instruction) = decode_word(word) else {
                continue;
            };
            let tokens = formatted(instruction, ip);
            let joined: String = row_tokens(&tokens)
                .iter()
                .map(|t| t.text.as_str())
                .collect();
            assert_eq!(
                joined,
                instruction.at(ip).to_string().replace('\t', " "),
                "text drift for word {word:#010x}"
            );
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

    fn row_mnemonic(word: u32) -> String {
        Arm64.mnemonic(&word.to_le_bytes(), 0x1000)
    }

    #[test]
    fn arm64_pcrel_comments_resolve_targets() {
        // b -0x2d8
        let instruction = decode_word(0x17fffd28).unwrap();
        let comment = pcrel_comment(instruction, 0xfffff8009bb34ff8, |t| format!("SYM:{t:#x}"));
        assert_eq!(comment.as_deref(), Some("SYM:0xfffff8009bb34498"));

        // cbnz w10, label
        let instruction = decode_word(0x35ffffca).unwrap();
        let comment = pcrel_comment(instruction, 0xfffff8009b40c998, |t| format!("SYM:{t:#x}"));
        assert_eq!(comment.as_deref(), Some("SYM:0xfffff8009b40c990"));

        // adrp x0, #0 names the page the PC is in
        let instruction = decode_word(0x90000000).unwrap();
        let comment = pcrel_comment(instruction, 0x1000, |t| format!("{t:#x}"));
        assert_eq!(comment.as_deref(), Some("0x1000"));

        let instruction = decode_word(0xd65f03c0).unwrap();
        assert!(pcrel_comment(instruction, 0x1000, |_| String::new()).is_none());

        let instruction = decode_word(0x94000005).unwrap();
        let comment = pcrel_comment(instruction, 0x2000, |t| format!("{t:#x}"));
        assert_eq!(comment.as_deref(), Some("0x2014"));
    }

    /// The tokens split `b.eq` into its mnemonic pieces, and the row's
    /// mnemonic joins them back.
    #[test]
    fn conditional_branches_keep_their_condition_in_the_mnemonic() {
        let tokens = formatted(decode_word(0x54000061).unwrap(), 0x1000);
        assert_eq!(mnemonic_text(&tokens), "b.ne");
    }

    /// An operand the assembly does not write (`ret`'s register) is not one.
    #[test]
    fn implicit_operands_are_left_out() {
        let operands = Arm64.operands(&0xd65f03c0u32.to_le_bytes(), 0x1000);
        assert!(operands.is_empty(), "{operands:?}");
    }

    /// The assembly's `fp`/`lr` are `x29`/`x30` in an operand's structure,
    /// where every consumer of a register already looks, while the text keeps
    /// the spelling.
    #[test]
    fn abi_register_names_stay_canonical_in_the_structure() {
        // stp fp, lr, [sp, #-0x30]!
        let operands = Arm64.operands(&0xa9bd7bfdu32.to_le_bytes(), 0x1000);
        let pairs: Vec<_> = operands
            .iter()
            .map(|operand| (operand.text.as_str(), operand.full_register.as_deref()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("fp", Some("x29")),
                ("lr", Some("x30")),
                ("[sp, #-0x30]!", None),
            ]
        );
        assert_eq!(operands[2].base.as_deref(), Some("sp"));
    }

    /// An arrangement is part of the text, not of the register: `v0.8b` is
    /// `v0`, as every register operand reads.
    #[test]
    fn arranged_registers_report_the_register_without_the_arrangement() {
        // cnt v0.8b, v0.8b
        let operands = Arm64.operands(&0x0e205800u32.to_le_bytes(), 0x1000);
        assert_eq!(operands[0].text, "v0.8b");
        assert_eq!(operands[0].register.as_deref(), Some("v0"));
        assert_eq!(operands[0].full_register.as_deref(), Some("v0"));
    }
}
