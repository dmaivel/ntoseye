//! Where execution continues past one A64 instruction: the addresses it can
//! go on at, resolved against the registers it branches through, and the
//! lowest stack pointer it can leave. A step walk that loses its thread to a
//! context switch runs to these, bound to that thread and stack.

use std::ops::Deref;

use bad64::{Op, Operand, Reg, Shift, SysReg};

use super::disasm::{immediate_value, word};

/// The bits of a virtual address: Windows translates 48-bit halves (see the
/// paging's canonical halves), and pointer authentication codes sit above
/// them.
const VIRTUAL_ADDRESS_BITS: u32 = 48;

/// Bit 55, which selects the half an address lies in, TTBR1's (the kernel's)
/// when set; pointer authentication leaves it in place.
const HALF_SELECT: u64 = 1 << 55;

/// The addresses execution can continue at past one instruction: one, or a
/// conditional branch's two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Successors {
    addresses: [u64; 2],
    count: usize,
}

impl Successors {
    fn one(address: u64) -> Self {
        Self {
            addresses: [address, 0],
            count: 1,
        }
    }

    /// A branch to the next instruction continues there either way.
    fn either(next: u64, target: u64) -> Self {
        if next == target {
            return Self::one(next);
        }
        Self {
            addresses: [next, target],
            count: 2,
        }
    }
}

impl Deref for Successors {
    type Target = [u64];

    fn deref(&self) -> &[u64] {
        &self.addresses[..self.count]
    }
}

/// Every address the instruction `bytes` at `pc` can continue at, branching
/// through the registers `read` by name (`x8`, `lr`): the next instruction,
/// a branch's target, or both for a conditional branch. `None` when the
/// registers and bytes do not tell: an encoding that does not decode, a
/// branch through a register `read` does not know, or an instruction that
/// raises an exception or returns from one (see [`enters_or_leaves_exception`]),
/// which continues at a vector or a saved state it does not name.
pub fn successors(bytes: &[u8], pc: u64, read: impl Fn(&str) -> Option<u64>) -> Option<Successors> {
    let instruction = bad64::decode(word(bytes)?, pc).ok()?;
    let operands = instruction.operands();
    let target = || {
        operands.iter().find_map(|operand| match *operand {
            Operand::Label(imm) => Some(immediate_value(imm) as u64),
            _ => None,
        })
    };
    let register = || match operands.first() {
        Some(Operand::Reg { reg, .. }) => read(reg.name()),
        _ => None,
    };
    let link = || read(Reg::X30.name());
    let next = pc.wrapping_add(4);
    let op = instruction.op();
    if enters_or_leaves_exception(op) {
        return None;
    }
    let mnemonic = op.mnem();
    Some(match op {
        Op::B | Op::BL | Op::B_AL | Op::B_NV => Successors::one(target()?),
        Op::RET if operands.is_empty() => Successors::one(link()?),
        Op::RET | Op::BR | Op::BLR => Successors::one(register()?),
        // An authenticated branch that does not fault goes to its register's
        // address with the authentication code taken out. The `sppc` returns'
        // operand is the modifier, not the target, which is the link
        // register too.
        Op::RETAA | Op::RETAB | Op::RETAASPPC | Op::RETABSPPC | Op::RETAASPPCR | Op::RETABSPPCR => {
            Successors::one(strip_pointer_authentication(link()?))
        }
        Op::BRAA
        | Op::BRAAZ
        | Op::BRAB
        | Op::BRABZ
        | Op::BLRAA
        | Op::BLRAAZ
        | Op::BLRAB
        | Op::BLRABZ => Successors::one(strip_pointer_authentication(register()?)),
        // `b.<cond>`, and the compare-and-branches: `cbz`/`cbnz` and the
        // `cb<cc>`/`cbb<cc>`/`cbh<cc>` of two registers.
        Op::TBZ | Op::TBNZ => Successors::either(next, target()?),
        _ if mnemonic.starts_with("b.") || mnemonic.starts_with("cb") => {
            Successors::either(next, target()?)
        }
        _ => Successors::one(next),
    })
}

/// The lowest stack pointer an execution at `sp` has once past the
/// instruction `bytes`: `sp` lowered by a writeback to SP (`stp x29, x30,
/// [sp, #-0x10]!`) or a `sub sp, sp, #imm`; `sp` itself for one that raises
/// SP (a post-indexed load, `add sp, sp, #imm`) or leaves it alone. `None`
/// when that is not known from here: an exception or a return from one (see
/// [`enters_or_leaves_exception`]) or a change of the stack selection, which
/// switch stacks, or SP set some other way (`mov sp, x29`, `and sp, ...`, a
/// register amount), or an encoding that does not decode.
pub fn stack_floor(bytes: &[u8], sp: u64) -> Option<u64> {
    let instruction = bad64::decode(word(bytes)?, 0).ok()?;
    let op = instruction.op();
    if enters_or_leaves_exception(op) {
        return None;
    }
    let lowered_by = |delta: i128| Some(sp.wrapping_add_signed(i64::try_from(delta.min(0)).ok()?));
    let operands = instruction.operands();
    for (index, operand) in operands.iter().enumerate() {
        match *operand {
            Operand::MemPreIdx { reg: Reg::SP, imm }
            | Operand::MemPostIdxImm { reg: Reg::SP, imm } => {
                return lowered_by(immediate_value(imm));
            }
            Operand::MemPostIdxReg([Reg::SP, _]) => return None,
            // The structure loads and stores (`ld1`, `st1`, ...) follow their
            // address with the writeback: the transfer size, which raises
            // SP, or a register.
            Operand::MemReg(Reg::SP) => {
                return match operands.get(index + 1) {
                    None | Some(Operand::Imm32 { .. } | Operand::Imm64 { .. }) => Some(sp),
                    Some(_) => None,
                };
            }
            Operand::SysReg(SysReg::PSTATE_SPSEL | SysReg::SP_EL0) if op == Op::MSR => {
                return None;
            }
            _ => {}
        }
    }
    // SP is a destination only as the first operand; `cmp`, `cmn` and `tst`
    // name it there as a source.
    let writes_sp = matches!(
        operands.first(),
        Some(Operand::Reg {
            reg: Reg::SP | Reg::WSP,
            ..
        })
    ) && !matches!(op, Op::CMP | Op::CMN | Op::TST);
    if !writes_sp {
        return Some(sp);
    }
    match (op, &operands[1..]) {
        (
            Op::ADD | Op::SUB,
            [
                Operand::Reg { reg: Reg::SP, .. },
                Operand::Imm64 { imm, shift },
            ],
        ) => {
            let amount = immediate_value(*imm)
                << match shift {
                    None => 0,
                    Some(Shift::LSL(amount)) => *amount,
                    Some(_) => return None,
                };
            lowered_by(if op == Op::SUB { -amount } else { amount })
        }
        _ => None,
    }
}

/// `address` with its pointer authentication code taken out, as `xpaci`
/// does: every bit above the virtual address copies the bit that selects its
/// half, set for a kernel address and clear for a user one.
pub fn strip_pointer_authentication(address: u64) -> u64 {
    let above = u64::MAX << VIRTUAL_ADDRESS_BITS;
    if address & HALF_SELECT != 0 {
        address | above
    } else {
        address & !above
    }
}

/// Whether `op` raises an exception (a system call, hypervisor or monitor
/// call, breakpoint, halt, undefined instruction, debug state change) or
/// returns from one: execution goes on at a vector or a saved state, on that
/// level's stack.
fn enters_or_leaves_exception(op: Op) -> bool {
    matches!(
        op,
        Op::SVC
            | Op::HVC
            | Op::SMC
            | Op::BRK
            | Op::HLT
            | Op::UDF
            | Op::DCPS1
            | Op::DCPS2
            | Op::DCPS3
            | Op::DRPS
            | Op::ERET
            | Op::ERETAA
            | Op::ERETAB
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PC: u64 = 0x1000;
    const SP: u64 = 0x2000;
    /// A kernel and a user return address, and each signed: the
    /// authentication code fills bits 63:56 and 54:48, bit 55 kept.
    const KERNEL: u64 = 0xffff_f803_1234_5678;
    const SIGNED_KERNEL: u64 = 0x9a85_f803_1234_5678;
    const USER: u64 = 0x0000_7ff6_1234_5678;
    const SIGNED_USER: u64 = 0x3a12_7ff6_1234_5678;

    fn successors_of(word: u32, registers: &[(&str, u64)]) -> Option<Vec<u64>> {
        let read = |name: &str| {
            registers
                .iter()
                .find(|(register, _)| *register == name)
                .map(|&(_, value)| value)
        };
        successors(&word.to_le_bytes(), PC, read).map(|successors| successors.to_vec())
    }

    fn floor_of(word: u32) -> Option<u64> {
        stack_floor(&word.to_le_bytes(), SP)
    }

    #[test]
    fn branches_continue_at_their_targets_and_the_next_instruction() {
        // nop; stp x29, x30, [sp, #-0x20]!; ldp x29, x30, [sp], #0x20
        for word in [0xd503_201f, 0xa9be_7bfd, 0xa8c2_7bfd] {
            assert_eq!(successors_of(word, &[]), Some(vec![0x1004]), "{word:#x}");
        }
        // b.eq 0x1010; b.al 0x1010
        assert_eq!(successors_of(0x5400_0080, &[]), Some(vec![0x1004, 0x1010]));
        assert_eq!(successors_of(0x5400_008e, &[]), Some(vec![0x1010]));
        // cbz x0, 0x1008; tbnz w1, #3, 0x100c
        assert_eq!(successors_of(0xb400_0040, &[]), Some(vec![0x1004, 0x1008]));
        assert_eq!(successors_of(0x3718_0061, &[]), Some(vec![0x1004, 0x100c]));
        // b.ne 0x1004: the branch and the fall-through are one address.
        assert_eq!(successors_of(0x5400_0021, &[]), Some(vec![0x1004]));
        // bl 0x1100; bl 0xff8
        assert_eq!(successors_of(0x9400_0040, &[]), Some(vec![0x1100]));
        assert_eq!(successors_of(0x97ff_fffe, &[]), Some(vec![0xff8]));
    }

    #[test]
    fn register_branches_go_where_their_register_points() {
        let registers = [
            ("lr", KERNEL),
            ("fp", USER),
            ("x8", 0x4000),
            ("x16", 0x5000),
        ];
        // ret; ret x29; blr x8; br x16
        assert_eq!(successors_of(0xd65f_03c0, &registers), Some(vec![KERNEL]));
        assert_eq!(successors_of(0xd65f_03a0, &registers), Some(vec![USER]));
        assert_eq!(successors_of(0xd63f_0100, &registers), Some(vec![0x4000]));
        assert_eq!(successors_of(0xd61f_0200, &registers), Some(vec![0x5000]));
        // A register not known leaves the target unknown.
        assert_eq!(successors_of(0xd63f_0100, &[("lr", KERNEL)]), None);
    }

    #[test]
    fn authenticated_branches_go_to_the_stripped_address() {
        let registers = [
            ("lr", SIGNED_KERNEL),
            ("x8", SIGNED_USER),
            ("x16", SIGNED_KERNEL),
            ("x17", 0x1234),
        ];
        // retaa; retab
        assert_eq!(successors_of(0xd65f_0bff, &registers), Some(vec![KERNEL]));
        assert_eq!(
            successors_of(0xd65f_0bff, &[("lr", SIGNED_USER)]),
            Some(vec![USER])
        );
        assert_eq!(successors_of(0xd65f_0fff, &registers), Some(vec![KERNEL]));
        // braa x16, x17; blraaz x8
        assert_eq!(successors_of(0xd71f_0a11, &registers), Some(vec![KERNEL]));
        assert_eq!(successors_of(0xd63f_091f, &registers), Some(vec![USER]));
    }

    #[test]
    fn exceptions_and_their_returns_have_no_known_successor() {
        // svc #0; eret; brk #0xf000; udf #0
        for word in [0xd400_0001, 0xd69f_03e0, 0xd43e_0000, 0x0000_0000] {
            assert_eq!(successors_of(word, &[("lr", KERNEL)]), None, "{word:#x}");
            assert_eq!(floor_of(word), None, "{word:#x}");
        }
        assert_eq!(successors(&[0x1f, 0x20], PC, |_| None), None);
    }

    #[test]
    fn the_floor_is_the_lowest_stack_pointer_the_instruction_leaves() {
        // nop; ldr x0, [sp, #8]; mov x29, sp; cmp sp, #0x10; bl 0x1100; ret;
        // blr x8
        for word in [
            0xd503_201f,
            0xf940_07e0,
            0x9100_03fd,
            0xf100_43ff,
            0x9400_0040,
            0xd65f_03c0,
            0xd63f_0100,
        ] {
            assert_eq!(floor_of(word), Some(SP), "{word:#x}");
        }
        // stp x29, x30, [sp, #-0x20]!; str x0, [sp, #-0x10]!
        assert_eq!(floor_of(0xa9be_7bfd), Some(0x1fe0));
        assert_eq!(floor_of(0xf81f_0fe0), Some(0x1ff0));
        // sub sp, sp, #0x40; sub sp, sp, #1, lsl #12
        assert_eq!(floor_of(0xd101_03ff), Some(0x1fc0));
        assert_eq!(floor_of(0xd140_07ff), Some(0x1000));
        // ldp x29, x30, [sp], #0x20; add sp, sp, #0x40;
        // st1 {v0.2d}, [sp], #0x10
        for word in [0xa8c2_7bfd, 0x9101_03ff, 0x4c9f_7fe0] {
            assert_eq!(floor_of(word), Some(SP), "{word:#x}");
        }
        // mov sp, x29; and sp, x0, #~0xf; sub sp, sp, x15; msr spsel, #1
        for word in [0x9100_03bf, 0x927c_ec1f, 0xcb2f_63ff, 0xd500_41bf] {
            assert_eq!(floor_of(word), None, "{word:#x}");
        }
    }

    #[test]
    fn stripping_restores_the_canonical_address_of_either_half() {
        assert_eq!(strip_pointer_authentication(SIGNED_KERNEL), KERNEL);
        assert_eq!(strip_pointer_authentication(SIGNED_USER), USER);
        assert_eq!(strip_pointer_authentication(KERNEL), KERNEL);
        assert_eq!(strip_pointer_authentication(USER), USER);
    }
}
