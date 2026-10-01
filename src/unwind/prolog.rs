//! Unwinding AMD64 code whose unwind data is not mapped (the Windows
//! hypervisor's, without its file) by reading its functions' prologs.

/// RVAs where functions likely begin in `bytes` (an image laid out by RVA),
/// within the executable `code` ranges: the targets of direct `call rel32`
/// instructions, and the 16-byte-aligned code after `int3` padding, which
/// the compiler puts between functions (so functions only ever called
/// indirectly are found too), sorted and deduplicated.
pub fn function_starts(bytes: &[u8], code: &[(u32, u32)]) -> Vec<u32> {
    let inside = |rva: u32| code.iter().any(|&(start, end)| (start..end).contains(&rva));
    let mut starts = Vec::new();
    for &(start, end) in code {
        let end = (end as usize).min(bytes.len());
        let mut at = start as usize;
        while at + 5 <= end {
            if bytes[at] == 0xe8 {
                let rel = i32::from_le_bytes(bytes[at + 1..at + 5].try_into().unwrap());
                let target = (at as i64 + 5 + i64::from(rel)) as u32;
                if inside(target) {
                    starts.push(target);
                }
            }
            if at.is_multiple_of(16) && at > 0 && bytes[at - 1] == 0xcc && bytes[at] != 0xcc {
                starts.push(at as u32);
            }
            at += 1;
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

/// Emulate the prolog in `code` (a function's first bytes) up to `offset`,
/// the frame's position in it. The first instruction that is not one a
/// prolog uses ends the prolog: the body runs on the frame it set up.
pub fn analyze_prolog(code: &[u8], offset: usize) -> PrologFrame {
    let mut size = 0u32;
    let mut pushes: Vec<(usize, u32)> = Vec::new();
    let mut at = 0usize;
    while at < offset.min(code.len()) {
        let rest = &code[at..];
        let length = match rest {
            [op @ 0x50..=0x57, ..] => {
                size += 8;
                pushes.push((usize::from(op - 0x50), size));
                1
            }
            // push with a REX prefix: `40` for the low registers (MSVC's
            // `push rbx` is `40 53`), `41` for r8-r15
            [rex @ 0x40..=0x4f, op @ 0x50..=0x57, ..] => {
                size += 8;
                pushes.push((usize::from(op - 0x50) + usize::from(rex & 1) * 8, size));
                2
            }
            [0x48, 0x83, 0xec, imm, ..] => {
                size += u32::from(*imm);
                4
            }
            [0x48, 0x81, 0xec, a, b, c, d, ..] => {
                size += u32::from_le_bytes([*a, *b, *c, *d]);
                7
            }
            // mov rbp, rsp
            [0x48, 0x8b, 0xec, ..] | [0x48, 0x89, 0xe5, ..] => 3,
            // mov rax/r11, rsp: a copy of RSP the next stores address by
            [0x48 | 0x4c, 0x8b, modrm, ..] if modrm & 0xc7 == 0xc4 => 3,
            // mov [reg+disp8], reg through that copy (argument homes)
            [0x48 | 0x49 | 0x4c | 0x4d, 0x89, modrm, _, ..]
                if modrm >> 6 == 1 && modrm & 7 != 4 && modrm & 7 != 5 =>
            {
                4
            }
            // lea rbp, [rsp+disp8]
            [0x48, 0x8d, 0x6c, 0x24, _, ..] => 5,
            // lea rbp, [rsp+disp32]
            [0x48, 0x8d, 0xac, 0x24, _, _, _, _, ..] => 8,
            // lea rbp, [rax+disp8|disp32], after `mov rax, rsp`
            [0x48, 0x8d, 0x68, _, ..] => 4,
            [0x48, 0x8d, 0xa8, _, _, _, _, ..] => 7,
            // mov [rsp+disp8], reg of any size (argument homes): RSP unchanged
            [0x88 | 0x89, modrm, 0x24, _, ..] if modrm & 0xc7 == 0x44 => 4,
            [0x40..=0x4f | 0x66, 0x88 | 0x89, modrm, 0x24, _, ..] if modrm & 0xc7 == 0x44 => 5,
            _ => break,
        };
        at += length;
    }
    PrologFrame {
        size,
        saved: pushes
            .into_iter()
            .map(|(reg, depth)| (reg, size - depth))
            .collect(),
    }
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
    /// in each harness image: every `.pdata` function with unwind codes and
    /// a direct call past its prolog, at its first such call. Measured at
    /// 97.4-97.9% on builds 16299 to 28000; 95% leaves room for a new build.
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
            let (mut tried, mut agreed) = (0u32, 0u32);
            for entry in pdata.as_chunks::<12>().0 {
                let word = |at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().unwrap());
                let (begin, finish, unwind) = (word(0), word(4), word(8));
                let Some(expected) = unwind_frame_size(&image, unwind) else {
                    continue;
                };
                let prolog = u32::from(image.read(unwind as usize + 1, 1).unwrap()[0]);
                let Some(call) = (begin + prolog..finish.saturating_sub(5))
                    .find(|&at| bytes.get(at as usize) == Some(&0xe8))
                else {
                    continue;
                };
                let ret = call + 5;
                tried += 1;
                let next = starts.partition_point(|&start| start <= ret);
                let Some(&start) = next.checked_sub(1).and_then(|at| starts.get(at)) else {
                    continue;
                };
                let frame = analyze_prolog(&bytes[start as usize..], (ret - start) as usize);
                agreed += u32::from(start == begin && frame.size == expected);
            }
            let rate = f64::from(agreed) / f64::from(tried.max(1));
            println!("{path}: {agreed}/{tried} ({:.1}%)", rate * 100.0);
            assert!(
                rate >= 0.95,
                "{path}: the fallback agreed on only {:.1}%",
                rate * 100.0
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
        assert_eq!(analyze_prolog(&code, 6), body);
        assert_eq!(analyze_prolog(&code, 10), body);
        assert_eq!(
            analyze_prolog(&code, 1),
            PrologFrame {
                size: 8,
                saved: vec![(3, 0)]
            }
        );
        assert_eq!(analyze_prolog(&[0x48, 0x31, 0xc0], 3).size, 0, "no prolog");
    }

    #[test]
    fn a_frame_pointer_prolog_and_r_pushes_are_followed() {
        let code = [
            0x55, 0x48, 0x8b, 0xec, 0x41, 0x56, 0x48, 0x81, 0xec, 0, 1, 0, 0,
        ];
        assert_eq!(
            analyze_prolog(&code, code.len()),
            PrologFrame {
                size: 0x110,
                saved: vec![(5, 0x108), (14, 0x100)]
            }
        );
    }

    #[test]
    fn return_addresses_follow_calls() {
        assert!(follows_call(&[0x90, 0xe8, 1, 2, 3, 4]));
        assert!(follows_call(&[0x90, 0xff, 0xd0]), "call rax");
        assert!(follows_call(&[0x41, 0xff, 0xd3]), "call r11");
        assert!(!follows_call(&[0x90, 0x90, 0xc3]));
    }

    /// A call's target starts a function even inside padding, and so does
    /// aligned code after `int3` padding; unaligned code after it does not.
    #[test]
    fn call_targets_and_code_after_padding_are_function_starts() {
        let mut bytes = vec![0xcc; 0x40];
        bytes[0x10..0x15].copy_from_slice(&[0xe8, 0x1b, 0, 0, 0]);
        bytes[0x24] = 0x90;
        assert_eq!(function_starts(&bytes, &[(0, 0x40)]), [0x10, 0x30]);
    }
}
