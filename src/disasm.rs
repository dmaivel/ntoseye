use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, Instruction,
    MemorySizeOptions, NasmFormatter,
};

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
/// branch / rip-relative target.
pub struct DisasmRow {
    pub ip: u64,
    pub hex: String,
    pub tokens: Vec<AsmToken>,
    pub comment: Option<String>,
}

impl DisasmRow {
    /// The instruction as plain, unstyled text — the form MCP, the Python
    /// binding, and JSON output consume. Colored rendering goes through
    /// `ui::disasm_asm` instead.
    pub fn asm(&self) -> String {
        self.tokens.iter().map(|t| t.text.as_str()).collect()
    }
}

/// Decode `bytes` (loaded at `start_addr`) into rows, stopping after `limit`
/// instructions when `Some`. `resolve` turns a branch / rip-relative target
/// into a symbol comment. The caller owns `formatter` (build it once with
/// [`disasm_formatter`]) so it's reused across decode passes.
pub fn decode_rows(
    bytes: &[u8],
    start_addr: u64,
    limit: Option<usize>,
    formatter: &mut NasmFormatter,
    resolve: impl Fn(u64) -> String,
) -> Vec<DisasmRow> {
    let mut decoder = Decoder::with_ip(64, bytes, start_addr, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut rows = Vec::new();

    while decoder.can_decode() && limit.is_none_or(|n| rows.len() < n) {
        decoder.decode_out(&mut instruction);
        if instruction.code() == Code::INVALID {
            continue;
        }
        let mut tokens = Vec::new();
        formatter.format(&instruction, &mut TokenSink(&mut tokens));

        let ip = instruction.ip();
        let start_index = (ip - start_addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        let hex = instr_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let comment = if instruction.is_ip_rel_memory_operand() {
            Some(resolve(instruction.ip_rel_memory_address()))
        } else if instruction.is_call_near()
            || instruction.is_jmp_near()
            || instruction.is_jcc_near()
        {
            Some(resolve(instruction.near_branch_target()))
        } else {
            None
        };

        rows.push(DisasmRow {
            ip,
            hex,
            tokens,
            comment,
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
        let Ok(instruction) = result else {
            break;
        };
        let ip = instruction.address();
        let start_index = (ip - start_addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + 4];
        let hex = instr_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        // The x64 path gets semantic tokens from iced's formatter; bad64 has
        // no formatter callback, but exposes typed operands, so classify those
        // into the same palette while reproducing the decoder's Display text
        // exactly (spaces live inside token text, so `asm()` is unchanged).
        let tokens = arm64_row_tokens(&instruction);

        let comment = arm64_pcrel_comment(&instruction, &resolve);
        rows.push(DisasmRow {
            ip,
            hex,
            tokens,
            comment,
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
        if lane {
            if let Some(l) = arsp.lane() {
                text.push_str(&format!("[{l}]"));
            }
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

/// Classify one bad64 [`Operand`] into semantic tokens — the AArch64 analogue
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
            let name = unsafe { std::ffi::CStr::from_ptr(str.as_ptr() as _) }
                .to_str()
                .unwrap();
            t.push(name, AsmKind::Text);
            t.space();
            t.push(&format!("#{imm:#x}"), AsmKind::Number);
        }
    }
    t.into_vec()
}

/// Symbol comment for an AArch64 direct branch: `b`/`bl`/`b.cond` with an
/// Symbol comment for an AArch64 PC-relative target. bad64 models every
/// PC-relative destination — branches (`b`/`bl`/`b.cond`), register
/// conditional branches (`cbz`/`cbnz`/`tbz`/`tbnz`), and address loads
/// (`adr`/`adrp`) — as a `Label` operand holding the absolute target, so the
/// operand variant itself identifies the form (the analogue of iced's
/// `near_branch_target`); no mnemonic matching.
fn arm64_pcrel_comment(
    instruction: &bad64::Instruction,
    resolve: impl Fn(u64) -> String,
) -> Option<String> {
    use bad64::{Imm, Operand};
    let target = instruction.operands().iter().find_map(|op| match op {
        Operand::Label(imm) => Some(match imm {
            Imm::Signed(v) => *v as i64,
            Imm::Unsigned(v) => *v as i64,
        }),
        _ => None,
    })?;
    Some(resolve(target as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The joined token text must reproduce bad64's Display exactly — the
    /// plain form is what the Python SDK and MCP consume.
    #[test]
    fn arm64_rows_reproduce_bad64_display() {
        let mut checked = 0;

        // Real instructions from the live session.
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
            let ins = bad64::decode(*word, 0x1000 + 4 * i as u64).expect("real instruction");
            let joined: String = arm64_row_tokens(&ins)
                .iter()
                .map(|t| t.text.as_str())
                .collect();
            assert_eq!(joined, ins.to_string(), "text drift for {word:#010x}");
            checked += 1;
        }

        // Deterministic pseudo-random sweep: check every decodable word.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for i in 0..65536u64 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let word = (state >> 32) as u32;
            let Ok(ins) = bad64::decode(word, 0x2000 + 4 * i) else {
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

    /// PC-relative comments resolve to the absolute destination (bad64 folds
    /// the offset into the Label operand), for every form: branches, register
    /// conditional branches, and address loads. Non-PC-relative instructions
    /// get none.
    #[test]
    fn arm64_pcrel_comments_resolve_targets() {
        // b -0x2d8 at 0xfffff8009bb34ff8 → 0xfffff8009bb34498 (live session).
        let ins = bad64::decode(0x17fffd28, 0xfffff8009bb34ff8).unwrap();
        let comment = arm64_pcrel_comment(&ins, |t| format!("SYM:{t:#x}"));
        assert_eq!(comment.as_deref(), Some("SYM:0xfffff8009bb34498"));

        // cbnz w10, label (live session: the unlabeled break-message case).
        let ins = bad64::decode(0x35ffffca, 0xfffff8009b40c998).unwrap();
        let comment = arm64_pcrel_comment(&ins, |t| format!("SYM:{t:#x}"));
        assert_eq!(comment.as_deref(), Some("SYM:0xfffff8009b40c990"));

        // adrp x0, page → page-aligned absolute target.
        let ins = bad64::decode(0x90000000, 0x1000).unwrap(); // adrp x0, #0
        let comment = arm64_pcrel_comment(&ins, |t| format!("{t:#x}"));
        assert_eq!(comment.as_deref(), Some("0x1000"));

        // ret carries no PC-relative comment.
        let ins = bad64::decode(0xd65f03c0, 0x1000).unwrap();
        assert!(arm64_pcrel_comment(&ins, |_| String::new()).is_none());

        // bl is a branch too (offset 5 << 2 from 0x2000 → 0x2014).
        let ins = bad64::decode(0x94000005, 0x2000).unwrap();
        let comment = arm64_pcrel_comment(&ins, |t| format!("{t:#x}"));
        assert_eq!(comment.as_deref(), Some("0x2014"));
    }
}
