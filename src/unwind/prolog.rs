//! Unwinding AMD64 code whose unwind data is not mapped (the Windows
//! hypervisor's, without its file) by reading its functions' prologs.

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register,
};

/// RVAs where functions likely begin in `bytes` (an image laid out by RVA),
/// within the executable `code` ranges, sorted and deduplicated: in a linear
/// decode of the code, the targets of its direct calls, and the 4-byte-aligned
/// code after padding of two or more `int3`s (and any NOPs among them), which
/// the compiler puts between functions, so functions only ever called
/// indirectly are found too. The decode keeps an `e8` byte inside another
/// instruction from passing for a call, and the `cc` bytes of an immediate
/// (`0xcccccccccccccccd`) for padding. A lone `int3` follows a call that does
/// not return, inside its function. Padding after an indirect `jmp` without
/// REX.W aligns a switch's cases, inside its function too: the x64 epilog
/// rules make a jump that leaves a function (a tail call) carry REX.W.
pub fn function_starts(bytes: &[u8], code: &[(u32, u32)]) -> Vec<u32> {
    let inside = |rva: u64| {
        code.iter()
            .any(|&(start, end)| (u64::from(start)..u64::from(end)).contains(&rva))
    };
    let mut starts = Vec::new();
    for &(start, end) in code {
        let Some(range) = bytes.get(start as usize..(end as usize).min(bytes.len())) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, range, u64::from(start), DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let (mut int3s, mut after_switch) = (0u32, false);
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            let ip = instruction.ip();
            if instruction.code() == Code::Int3 {
                int3s += 1;
                continue;
            }
            if int3s > 0 && instruction.mnemonic() == Mnemonic::Nop {
                continue;
            }
            if int3s >= 2 && ip.is_multiple_of(4) && !after_switch {
                starts.push(ip as u32);
            }
            if instruction.code() == Code::Call_rel32_64 && inside(instruction.near_branch_target())
            {
                starts.push(instruction.near_branch_target() as u32);
            }
            int3s = 0;
            after_switch = instruction.code() == Code::Jmp_rm64
                && !(0x48..=0x4f).contains(&range[(ip - u64::from(start)) as usize]);
        }
    }
    starts.sort_unstable();
    starts.dedup();
    starts
}

/// What a function's prolog has done by some point: how far it moved RSP
/// down (`size`, bytes), and where it pushed each register, as
/// `(unwind register number, offset from the current RSP)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrologFrame {
    pub size: u32,
    pub saved: Vec<(usize, u32)>,
}

/// How much of a function's code, from its start, [`analyze_prolog`] needs:
/// a frame further in is past the prolog, which ends well before this.
pub const PROLOG_BYTES: usize = 0x100;

/// Emulate the prolog in `code` (a function's first bytes) up to `offset`,
/// the frame's position in it. A prolog pushes registers (and `pushfq`),
/// subtracts from RSP, directly or by a stack probe (`mov eax, size`, `call
/// __chkstk`, `sub rsp, rax`), copies RSP (`mov rax, rsp`, `mov rbp, rsp`,
/// `lea rbp, [rsp+n]`), and stores registers of any width through RSP or a
/// copy of it (argument homes and saves), none of which moves RSP. The first
/// other instruction ends the prolog: the body runs on the frame it set up.
/// `None` when the body moves RSP to another stack before the frame's
/// position, as assembly that switches stacks does.
///
/// Before the frame begins, a shrink-wrapped function tests its arguments
/// and branches to a return that needs no frame (`test rcx, rcx`, `je
/// out`); the prolog follows the fall-through when the branch jumps past the
/// frame's position, or over a `ret` to code that sets up the frame. `None`
/// for any other branch there, which may lead to the frame by a path that
/// sets up another.
pub fn analyze_prolog(code: &[u8], offset: usize) -> Option<PrologFrame> {
    let code = &code[..offset.min(code.len())];
    let instructions: Vec<Instruction> = Decoder::with_ip(64, code, 0, DecoderOptions::NONE)
        .into_iter()
        .collect();
    let mut size = 0u32;
    let mut pushes: Vec<(usize, u32)> = Vec::new();
    // Registers holding RSP plus a constant, which stores in the prolog
    // address the stack by.
    let mut copies = vec![Register::RSP];
    // The size a stack probe allocates: `mov eax, size` before the call to
    // `__chkstk` and the `sub rsp, rax` after it.
    let mut probe: Option<u32> = None;
    let mut index = 0;
    while let Some(instruction) = instructions.get(index) {
        let next = instructions.get(index + 1);
        let rsp_operand = instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::RSP;
        match instruction.code() {
            Code::Push_r64 => {
                size += 8;
                pushes.push((instruction.op0_register().number(), size));
            }
            // `pushfq; pop reg` reads the flags, in the body
            Code::Pushfq if !next.is_some_and(|next| next.code() == Code::Pop_r64) => size += 8,
            Code::Sub_rm64_imm8 | Code::Sub_rm64_imm32 if rsp_operand => {
                match u32::try_from(instruction.immediate(1) as i64) {
                    Ok(imm) => size += imm,
                    Err(_) => break,
                }
            }
            Code::Mov_r32_imm32 if instruction.op0_register() == Register::EAX => {
                probe = Some(instruction.immediate32());
            }
            Code::Call_rel32_64 if probe.is_some() => {}
            Code::Sub_r64_rm64 | Code::Sub_rm64_r64
                if rsp_operand
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op1_register() == Register::RAX =>
            {
                match probe.take() {
                    Some(probe) => size += probe,
                    None => break,
                }
            }
            Code::Mov_r64_rm64 | Code::Mov_rm64_r64
                if instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op1_register() == Register::RSP =>
            {
                copies.push(instruction.op0_register());
            }
            Code::Lea_r64_m
                if copies.contains(&instruction.memory_base())
                    && instruction.memory_index() == Register::None =>
            {
                copies.push(instruction.op0_register());
            }
            _ if instruction.op0_kind() == OpKind::Memory
                && instruction.op1_kind() == OpKind::Register
                && copies.contains(&instruction.memory_base())
                && instruction.memory_index() == Register::None
                && matches!(
                    instruction.mnemonic(),
                    Mnemonic::Mov
                        | Mnemonic::Movaps
                        | Mnemonic::Movups
                        | Mnemonic::Movdqa
                        | Mnemonic::Movdqu
                ) => {}
            _ if size > 0 => break,
            _ if matches!(instruction.mnemonic(), Mnemonic::Test | Mnemonic::Cmp) => {}
            _ if instruction.flow_control() == FlowControl::ConditionalBranch => {
                let target = instruction.near_branch_target();
                if next.is_some_and(|next| {
                    next.flow_control() == FlowControl::Return && next.next_ip() == target
                }) {
                    index += 1;
                } else if target <= offset as u64 {
                    return None;
                }
            }
            _ => break,
        }
        index += 1;
    }
    // The body runs on the frame the prolog set up, unless it moves RSP
    // elsewhere (a stack switch, `mov rsp, rax`) other than on its way out:
    // an epilog's `lea rsp, [rbp+n]` or `mov rsp, r11` comes right before
    // its pops or its return.
    let mut body = instructions[index..].iter().peekable();
    while let Some(instruction) = body.next() {
        let moves_rsp = instruction.op0_kind() == OpKind::Register
            && instruction.op0_register() == Register::RSP
            && matches!(
                instruction.mnemonic(),
                Mnemonic::Mov | Mnemonic::Lea | Mnemonic::And | Mnemonic::Or | Mnemonic::Xchg
            );
        if moves_rsp
            && body.peek().is_some_and(|next| {
                next.code() != Code::Pop_r64 && next.flow_control() != FlowControl::Return
            })
        {
            return None;
        }
    }
    Some(PrologFrame {
        size,
        saved: pushes
            .into_iter()
            .map(|(reg, depth)| (reg, size - depth))
            .collect(),
    })
}

/// Whether the bytes `before` (ending at a return address) end in a call:
/// `call rel32`, or an indirect `call` through a register or memory.
pub fn follows_call(before: &[u8]) -> bool {
    let n = before.len();
    if n >= 5 && before[n - 5] == 0xe8 {
        return true;
    }
    (2..=7).any(|length| {
        n >= length && {
            let call = &before[n - length..];
            let (op, modrm) = match call {
                [0x41 | 0x48 | 0x49, 0xff, m, ..] => (0xff, *m),
                [0xff, m, ..] => (0xff, *m),
                _ => return false,
            };
            op == 0xff && (modrm >> 3) & 7 == 2
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{PeImage, read_pe_image_from_file};
    use pelite::pe64::{Pe, PeView};
    use std::path::Path;

    /// The frame size a function's unwind codes give past its prolog, or
    /// `None` for one the heuristic is not meant for (chained, a machine
    /// frame) or whose codes do not parse.
    fn unwind_frame_size(image: &PeImage, unwind: u32) -> Option<u32> {
        let header = image.read(unwind as usize, 4)?;
        if header[0] & 0x20 != 0 {
            return None;
        }
        let count = usize::from(header[2]);
        let codes = image.read(unwind as usize + 4, count * 2)?;
        let slot =
            |index: usize| u32::from(u16::from_le_bytes([codes[index * 2], codes[index * 2 + 1]]));
        let (mut size, mut index) = (0u32, 0usize);
        while index < count {
            let (op, info) = (
                codes[index * 2 + 1] & 0xf,
                u32::from(codes[index * 2 + 1] >> 4),
            );
            index += match op {
                0 => {
                    size += 8;
                    1
                }
                1 if info == 0 => {
                    size += slot(index + 1) * 8;
                    2
                }
                1 => {
                    size += slot(index + 1) | slot(index + 2) << 16;
                    3
                }
                2 => {
                    size += info * 8 + 8;
                    1
                }
                3 | 6 => 1,
                4 | 8 => 2,
                5 | 9 => 3,
                _ => return None,
            };
        }
        Some(size)
    }

    /// How often the fallback, which has no `.pdata`, finds the function and
    /// the frame size the real unwind data gives at a call's return address
    /// in each harness image: at every call that a decode of a `.pdata`
    /// function with unwind codes finds past its prolog. A frame the
    /// fallback gets wrong is printed; an undecided one leaves the walk to
    /// the scan. Measured on builds 16299 to 28000: 99.79-99.92% agree, and
    /// 1 to 5 sites wrong, all in assembly: a fragment entered with its
    /// frame set up, and from 22621 functions whose unwind data leaves out
    /// their `sub rsp` (so RSP at the call would be misaligned, and the
    /// prolog is right). 12 to 29 are undecided, most of them in assembly
    /// that switches stacks. The bounds leave room for a new build.
    #[test]
    #[ignore = "needs hvix64 images named by NTOSEYE_HVIX64_IMAGES"]
    fn the_prolog_fallback_agrees_with_the_unwind_data() {
        let paths = std::env::var("NTOSEYE_HVIX64_IMAGES").expect("NTOSEYE_HVIX64_IMAGES");
        for path in paths.lines().filter(|line| !line.is_empty()) {
            let image = read_pe_image_from_file(Path::new(path)).unwrap();
            let view = PeView::from_bytes(image.headers()).unwrap();
            let code: Vec<(u32, u32)> = view
                .section_headers()
                .iter()
                .filter(|section| section.Characteristics & 0x2000_0000 != 0)
                .map(|section| {
                    (
                        section.VirtualAddress,
                        section.VirtualAddress + section.VirtualSize,
                    )
                })
                .collect();
            let end = code.iter().map(|&(_, end)| end).max().unwrap() as usize;
            let bytes = image.read(0, end).unwrap();
            let starts = function_starts(&bytes, &code);
            let directory = view.data_directory()[3];
            let pdata = image
                .read(directory.VirtualAddress as usize, directory.Size as usize)
                .unwrap();
            let (mut tried, mut agreed, mut wrong) = (0u32, 0u32, 0u32);
            for entry in pdata.as_chunks::<12>().0 {
                let word = |at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
                let (begin, finish, unwind) = (word(0), word(4), word(8));
                let Some(expected) = unwind_frame_size(&image, unwind) else {
                    continue;
                };
                let prolog = u32::from(image.read(unwind as usize + 1, 1).unwrap()[0]);
                // The hypercall page's template, which some builds keep in
                // `.data`, has an entry too, but no calls.
                let Some(body) = bytes.get(begin as usize..finish as usize) else {
                    continue;
                };
                let returns = Decoder::with_ip(64, body, u64::from(begin), DecoderOptions::NONE)
                    .into_iter()
                    .filter(|instruction| instruction.mnemonic() == Mnemonic::Call)
                    .map(|instruction| instruction.next_ip() as u32)
                    .filter(|&ret| ret - begin > prolog);
                for ret in returns {
                    tried += 1;
                    let next = starts.partition_point(|&start| start <= ret);
                    let Some(&start) = next.checked_sub(1).and_then(|at| starts.get(at)) else {
                        continue;
                    };
                    let offset = (ret - start) as usize;
                    let code = &bytes[start as usize..][..offset.min(PROLOG_BYTES)];
                    match analyze_prolog(code, offset) {
                        Some(frame) if start == begin && frame.size == expected => agreed += 1,
                        Some(frame) => {
                            wrong += 1;
                            println!(
                                "  wrong at {ret:#x}: {start:#x} +{:#x}, unwind data {begin:#x} +{expected:#x}",
                                frame.size
                            );
                        }
                        None => {}
                    }
                }
            }
            let rate = f64::from(agreed) / f64::from(tried.max(1));
            println!(
                "{path}: {agreed}/{tried} agree ({:.2}%), {wrong} wrong, {} undecided",
                rate * 100.0,
                tried - agreed - wrong
            );
            assert!(
                rate >= 0.995,
                "{path}: the fallback agreed on only {:.2}%",
                rate * 100.0
            );
            assert!(
                wrong <= tried / 1000,
                "{path}: the fallback was wrong at {wrong} of {tried} sites"
            );
        }
    }

    /// `push rbx; push rdi; sub rsp, 0x28`, then the body: anywhere in the
    /// body the frame is 0x38 bytes, rdi at +0x28 and rbx at +0x30 (a push
    /// in the body is no prolog); mid-prolog it is what ran so far.
    #[test]
    fn a_prolog_gives_its_frame_at_each_point() {
        let code = [0x53, 0x57, 0x48, 0x83, 0xec, 0x28, 0x48, 0x31, 0xc0, 0x50];
        let body = PrologFrame {
            size: 0x38,
            saved: vec![(3, 0x30), (7, 0x28)],
        };
        assert_eq!(analyze_prolog(&code, 6), Some(body.clone()));
        assert_eq!(analyze_prolog(&code, 10), Some(body));
        assert_eq!(
            analyze_prolog(&code, 1),
            Some(PrologFrame {
                size: 8,
                saved: vec![(3, 0)]
            })
        );
        assert_eq!(
            analyze_prolog(&[0x48, 0x31, 0xc0], 3).map(|frame| frame.size),
            Some(0),
            "no prolog"
        );
    }

    #[test]
    fn a_frame_pointer_prolog_and_r_pushes_are_followed() {
        let code = [
            0x55, 0x48, 0x8b, 0xec, 0x41, 0x56, 0x48, 0x81, 0xec, 0, 1, 0, 0,
        ];
        assert_eq!(
            analyze_prolog(&code, code.len()),
            Some(PrologFrame {
                size: 0x110,
                saved: vec![(5, 0x108), (14, 0x100)]
            })
        );
    }

    /// A shrink-wrapped function returns early before its frame: past a
    /// branch that skips to the end, or over a `ret` to its frame, the
    /// prolog follows. A branch that may reach the frame by another path
    /// leaves the frame undecided.
    #[test]
    fn a_prolog_after_an_early_return_is_followed() {
        let mut code = vec![
            0x48, 0x85, 0xc9, // test rcx, rcx
            0x74, 0x10, // je out (0x15)
            0x40, 0x53, // push rbx
            0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
            0xe8, 0, 0, 0, 0, // call
        ];
        let frame = Some(PrologFrame {
            size: 0x28,
            saved: vec![(3, 0x20)],
        });
        assert_eq!(analyze_prolog(&code, code.len()), frame);
        code[4] = 0x06; // je to the call
        assert_eq!(analyze_prolog(&code, code.len()), None);
        let code = [
            0x48, 0x3b, 0x0d, 0, 0, 0, 0, // cmp rcx, [rip]
            0x75, 0x01, // jne over the ret
            0xc3, // ret
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
            0xe8, 0, 0, 0, 0, // call
        ];
        assert_eq!(
            analyze_prolog(&code, code.len()).map(|frame| frame.size),
            Some(0x28)
        );
    }

    /// Argument homes of every width, stored through a copy of RSP or RSP
    /// itself, are part of the prolog.
    #[test]
    fn stores_of_narrow_registers_stay_in_the_prolog() {
        let code = [
            0x48, 0x8b, 0xc4, // mov rax, rsp
            0x44, 0x89, 0x40, 0x18, // mov [rax+0x18], r8d
            0x66, 0x89, 0x50, 0x10, // mov [rax+0x10], dx
            0x88, 0x48, 0x08, // mov [rax+8], cl
            0x66, 0x44, 0x89, 0x4c, 0x24, 0x20, // mov [rsp+0x20], r9w
            0x55, // push rbp
            0x57, // push rdi
            0x48, 0x83, 0xec, 0x30, // sub rsp, 0x30
            0x33, 0xc0, // xor eax, eax
        ];
        assert_eq!(
            analyze_prolog(&code, code.len()),
            Some(PrologFrame {
                size: 0x40,
                saved: vec![(5, 0x38), (7, 0x30)]
            })
        );
    }

    /// A frame larger than a page is allocated by a stack probe: `mov eax,
    /// size`, `call __chkstk`, `sub rsp, rax`. In the probe, the frame is
    /// what the pushes made.
    #[test]
    fn a_stack_probe_allocates_its_size() {
        let code = [
            0x40, 0x53, // push rbx
            0xb8, 0x40, 0x18, 0, 0, // mov eax, 0x1840
            0xe8, 0, 0, 0, 0, // call __chkstk
            0x48, 0x2b, 0xe0, // sub rsp, rax
            0x33, 0xf6, // xor esi, esi
        ];
        let size = |offset| analyze_prolog(&code, offset).map(|frame| frame.size);
        assert_eq!(size(code.len()), Some(0x1848));
        assert_eq!(size(12), Some(8));
    }

    #[test]
    fn pushfq_in_a_prolog_allocates_a_slot() {
        let code = [
            0x9c, // pushfq
            0x65, 0x48, 0x8b, 0x0c, 0x25, 0, 0, 0, 0, // mov rcx, gs:[0]
        ];
        assert_eq!(
            analyze_prolog(&code, code.len()),
            Some(PrologFrame {
                size: 8,
                saved: vec![]
            })
        );
    }

    /// Code that moves RSP to another stack leaves no frame the prolog
    /// describes; an epilog's move of RSP, before its pops, does not.
    #[test]
    fn a_body_that_switches_stacks_leaves_its_frame_undecided() {
        let switch = [
            0x48, 0x8b, 0xc4, // mov rax, rsp
            0x48, 0x25, 0x00, 0xf0, 0xff, 0xff, // and rax, -0x1000
            0x48, 0x05, 0xc0, 0x0f, 0, 0, // add rax, 0xfc0
            0x48, 0x8b, 0xe0, // mov rsp, rax
            0xe8, 0, 0, 0, 0, // call
        ];
        assert_eq!(analyze_prolog(&switch, switch.len()), None);
        let early_return = [
            0x57, // push rdi
            0x48, 0x83, 0xec, 0x20, // sub rsp, 0x20
            0x85, 0xc9, // test ecx, ecx
            0x75, 0x0a, // jne over the epilog
            0x4c, 0x8d, 0x5c, 0x24, 0x20, // lea r11, [rsp+0x20]
            0x49, 0x8b, 0xe3, // mov rsp, r11
            0x5f, // pop rdi
            0xc3, // ret
            0xe8, 0, 0, 0, 0, // call
        ];
        assert_eq!(
            analyze_prolog(&early_return, early_return.len()),
            Some(PrologFrame {
                size: 0x28,
                saved: vec![(7, 0x20)]
            })
        );
    }

    #[test]
    fn return_addresses_follow_calls() {
        assert!(follows_call(&[0x90, 0xe8, 1, 2, 3, 4]));
        assert!(follows_call(&[0x90, 0xff, 0xd0]), "call rax");
        assert!(follows_call(&[0x41, 0xff, 0xd3]), "call r11");
        assert!(!follows_call(&[0x90, 0x90, 0xc3]));
    }

    /// The function starts in `pieces` laid end to end from RVA 0.
    fn starts_in(pieces: &[&[u8]]) -> Vec<u32> {
        let bytes = pieces.concat();
        function_starts(&bytes, &[(0, bytes.len() as u32)])
    }

    /// A decoded call's target starts a function, and so does code at a
    /// 4-byte boundary after two or more `int3`s; an `e8` byte inside
    /// another instruction is no call.
    #[test]
    fn call_targets_and_code_after_padding_are_function_starts() {
        let starts = starts_in(&[
            &[0xcc; 4],
            &[0x48, 0xb9, 0xe8, 0x10, 0, 0, 0, 0, 0, 0], // mov rcx, 0x10e8
            &[0xc3],
            &[0xcc; 5],
            &[0xe8, 0x07, 0, 0, 0], // call 0x20
            &[0xc3],
            &[0xcc; 6],
            &[0xc3],
            &[0xcc; 3],
        ]);
        assert_eq!(starts, [0x04, 0x14, 0x20]);
    }

    /// `int3`s inside a function start no function: a lone one after a
    /// call that does not return, the bytes of an immediate, and the
    /// padding that aligns a switch's cases after its `jmp rcx`. Padding
    /// after a tail call through a register (`rex.w jmp rax`) does.
    #[test]
    fn int3s_inside_a_function_start_none() {
        let xors: &[u8] = &[0x31, 0xc0, 0x31, 0xc0, 0x31, 0xc0, 0x31, 0xc0, 0x31, 0xc0];
        let body: &[u8] = &[0x31, 0xc0, 0xc3]; // xor eax, eax; ret
        let call_to_0: &[u8] = &[0xe8, 0xf1, 0xff, 0xff, 0xff]; // at 0xa
        assert_eq!(starts_in(&[xors, call_to_0, &[0xcc], body]), [0]);
        let mov_rax: &[u8] = &[0x48, 0xb8, 0xcd, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc];
        assert!(starts_in(&[&xors[..6], mov_rax, body]).is_empty());
        let jmp_rcx: &[u8] = &[0xff, 0xe1];
        assert!(starts_in(&[xors, jmp_rcx, &[0xcc; 4], body]).is_empty());
        let jmp_rax: &[u8] = &[0x48, 0xff, 0xe0];
        let nop: &[u8] = &[0x90];
        assert_eq!(
            starts_in(&[&xors[..8], nop, jmp_rax, &[0xcc; 4], body]),
            [0x10]
        );
    }
}
