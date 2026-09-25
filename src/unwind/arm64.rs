//! ARM64 exception-directory unwinding: `.pdata` lookup, packed and `.xdata`
//! unwind codes, and stepping a frame to its caller the way the Windows
//! unwinder does, including partial prologs and epilogs and the kernel's
//! trap, machine, and context frames.

use std::ops::Range;

use super::{RegisterContext, StackTracer, Unwound, exception_directory, image_u32};
use crate::{
    kd::context_arm64::{OFFSET_PC, OFFSET_SP, OFFSET_X0},
    pe::PeImage,
    target::Arm64SavedRegisters,
    trapframe::decode_ktrap_frame_for_thread,
    types::VirtAddr,
};

const FP: usize = 29;
const LR: usize = 30;

/// x0–x17 carry arguments, results, and scratch values a callee may clobber.
/// x18 is the platform register (the KPCR in kernel mode) and survives calls.
const VOLATILE: Range<usize> = 0..18;

/// An ARM64 `.pdata` entry and the function range it covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64Function {
    pub begin: u32,
    pub end: u32,
    pub unwind_data: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Arm64Lookup {
    Found(Arm64Function),
    /// No entry covers the address: a leaf function.
    Missing,
    /// An entry or `.xdata` header the search needed could not be read.
    Unreadable,
}

/// Find the ARM64 runtime-function entry containing `rva` in the exception
/// directory at `pdata`. ARM64 `.pdata` records are sorted 8-byte
/// `{BeginAddress, UnwindData}` pairs; unlike AMD64, the end address must be
/// decoded from packed unwind data or the `.xdata` header.
pub fn lookup_arm64_runtime_function(
    image: &PeImage,
    pdata: Range<usize>,
    rva: u32,
) -> Arm64Lookup {
    let entry = |index: usize| {
        let bytes = image.read(pdata.start + index * 8, 8)?;
        Some((image_u32(&bytes, 0)?, image_u32(&bytes, 4)?))
    };
    let mut low = 0usize;
    let mut high = pdata.len() / 8;
    while low < high {
        let mid = low + (high - low) / 2;
        let Some((begin, _)) = entry(mid) else {
            return Arm64Lookup::Unreadable;
        };
        if begin <= rva {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    let Some(index) = low.checked_sub(1) else {
        return Arm64Lookup::Missing;
    };
    let Some((begin, unwind_data)) = entry(index) else {
        return Arm64Lookup::Unreadable;
    };
    let instructions = match unwind_data & 0b11 {
        0 => match image.read((unwind_data & !0b11) as usize, 4) {
            Some(header) => image_u32(&header, 0).map_or(0, |header| header & 0x3ffff),
            None => return Arm64Lookup::Unreadable,
        },
        1 | 2 => (unwind_data >> 2) & 0x7ff,
        _ => 0,
    };
    match begin.checked_add(instructions * 4) {
        Some(end) if instructions != 0 && rva < end => Arm64Lookup::Found(Arm64Function {
            begin,
            end,
            unwind_data,
        }),
        _ => Arm64Lookup::Missing,
    }
}

/// Strip AArch64 pointer-authentication bits (bits 63:56) from a return
/// address: sign-extend the 56-bit canonical address back to 64 bits.
fn strip_pac(addr: u64) -> u64 {
    ((addr << 8) as i64 >> 8) as u64
}

/// A function's unwind description, read out of the image.
#[derive(Debug)]
enum Program {
    /// Packed `.pdata` data (flags 1 and 2): a canonical prolog and epilog
    /// described by the entry's fields.
    Packed(u32),
    Full(Xdata),
}

#[derive(Debug)]
struct Xdata {
    /// Function length in instructions.
    length: u32,
    epilog_in_header: bool,
    /// With `epilog_in_header`, the index of the lone epilog's first unwind
    /// code; otherwise the number of epilog scopes.
    epilog_count: u32,
    /// Epilog scopes: the start in instructions from the function's start
    /// in the low 18 bits, and the index of its first unwind code in the top
    /// 10 bits.
    scopes: Vec<u32>,
    codes: Vec<u8>,
}

fn read_program(image: &PeImage, unwind_data: u32) -> Option<Program> {
    match unwind_data & 0b11 {
        0 => read_xdata(image, unwind_data as usize).map(Program::Full),
        1 | 2 => Some(Program::Packed(unwind_data)),
        _ => None,
    }
}

fn read_xdata(image: &PeImage, at: usize) -> Option<Xdata> {
    let header = image_u32(&image.read(at, 4)?, 0)?;
    let mut epilog_count = (header >> 22) & 0x1f;
    let mut code_words = header >> 27;
    let mut next = at + 4;
    if epilog_count == 0 && code_words == 0 {
        let extension = image_u32(&image.read(next, 4)?, 0)?;
        epilog_count = extension & 0xffff;
        code_words = (extension >> 16) & 0xff;
        next += 4;
    }
    let epilog_in_header = header & (1 << 21) != 0;
    let mut scopes = Vec::new();
    if !epilog_in_header {
        let bytes = image.read(next, epilog_count as usize * 4)?;
        scopes = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|scope| u32::from_le_bytes(*scope))
            .collect();
        next += bytes.len();
    }
    let codes = image.read(next, code_words as usize * 4)?.into_owned();
    Some(Xdata {
        length: header & 0x3ffff,
        epilog_in_header,
        epilog_count,
        scopes,
        codes,
    })
}

fn push1(codes: &mut Vec<u8>, code: u32) -> Option<()> {
    codes.push(u8::try_from(code).ok()?);
    Some(())
}

fn push2(codes: &mut Vec<u8>, code: u32) -> Option<()> {
    push1(codes, code >> 8)?;
    push1(codes, code & 0xff)
}

/// The fields of a packed `.pdata` entry.
struct Packed {
    flag: u32,
    /// Function length in instructions.
    length: u32,
    reg_f: u32,
    reg_i: u32,
    homes_arguments: bool,
    cr: u32,
    frame_size: u32,
}

impl Packed {
    fn new(unwind_data: u32) -> Self {
        Self {
            flag: unwind_data & 0b11,
            length: (unwind_data >> 2) & 0x7ff,
            reg_f: (unwind_data >> 13) & 0b111,
            reg_i: (unwind_data >> 16) & 0xf,
            homes_arguments: (unwind_data >> 20) & 1 != 0,
            cr: (unwind_data >> 21) & 0b11,
            frame_size: unwind_data >> 23,
        }
    }

    /// The unwind codes of the canonical prolog and epilog the fields
    /// describe, in the order `.xdata` would list them. The epilog omits the
    /// prolog's argument-homing stores.
    fn codes(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let mut int_size = self.reg_i * 8;
        if self.cr == 1 {
            int_size += 8;
        }
        let mut fp_size = self.reg_f * 8;
        if self.reg_f != 0 {
            fp_size += 8;
        }
        let homing_size = if self.homes_arguments { 64 } else { 0 };
        let register_save = (int_size + fp_size + homing_size + 0xf) & !0xf;
        let mut local_size = (self.frame_size * 16).checked_sub(register_save)?;
        let int_regs = int_size / 8;
        let fp_regs = fp_size / 8;
        let saved_regs = register_save / 8;
        let mut homing = self.homes_arguments;
        if homing && self.reg_i == 0 && self.reg_f == 0 && self.cr != 1 {
            local_size += register_save;
            homing = false;
        }

        let mut codes = Vec::new();
        if self.cr == 2 || self.cr == 3 {
            push1(&mut codes, 0xe1)?; // set_fp
            if local_size <= 512 {
                push1(&mut codes, 0x80 | (local_size / 8).checked_sub(1)?)?; // save_fplr_x
            } else {
                push1(&mut codes, 0x40)?; // save_fplr
            }
        }
        if (self.cr <= 1 && local_size > 0) || local_size > 512 {
            if local_size <= 512 {
                push1(&mut codes, local_size / 16)?; // alloc_s
            } else if local_size <= 4080 {
                push2(&mut codes, 0xc000 | (local_size / 16))?; // alloc_m
            } else {
                push1(&mut codes, (local_size - 4080) / 16)?; // alloc_s
                push2(&mut codes, 0xc000 | (4080 / 16))?; // alloc_m
            }
        }
        let homing_at = codes.len();
        if self.reg_f > 0 {
            if self.reg_f.is_multiple_of(2) {
                // save_freg d(8 + RegF)
                push2(
                    &mut codes,
                    0xdc00 | (self.reg_f << 6) | (int_regs + fp_regs - 1),
                )?;
            }
            for pair in (0..self.reg_f.div_ceil(2)).rev() {
                if pair == 0 && int_size == 0 {
                    push2(&mut codes, 0xda00 | (saved_regs - 1))?; // save_fregp_x d8
                } else {
                    // save_fregp d(8 + 2 * pair)
                    push2(
                        &mut codes,
                        0xd800 | ((2 * pair) << 6) | (int_regs + 2 * pair),
                    )?;
                }
            }
        }
        if self.cr == 1 && self.reg_i.is_multiple_of(2) {
            if self.reg_i == 0 {
                push2(&mut codes, 0xd400 | ((30 - 19) << 5) | (saved_regs - 1))?; // save_reg_x lr
            } else {
                push2(&mut codes, 0xd000 | ((30 - 19) << 6) | (int_regs - 1))?; // save_reg lr
            }
        }
        if self.reg_i > 0 {
            if !self.reg_i.is_multiple_of(2) {
                if self.cr == 1 {
                    // save_lrpair x(19 + RegI - 1), lr
                    push2(
                        &mut codes,
                        0xd600 | (((self.reg_i - 1) / 2) << 6) | (int_regs - 2),
                    )?;
                    if self.reg_i == 1 {
                        push1(&mut codes, saved_regs / 2)?; // alloc_s
                    }
                } else if self.reg_i == 1 {
                    push2(&mut codes, 0xd400 | (saved_regs - 1))?; // save_reg_x x19
                } else {
                    // save_reg x(19 + RegI - 1)
                    push2(&mut codes, 0xd000 | ((int_regs - 1) << 6) | (int_regs - 1))?;
                }
            }
            for pair in (0..self.reg_i / 2).rev() {
                if pair == 0 {
                    push2(&mut codes, 0xcc00 | (saved_regs - 1))?; // save_regp_x x19
                } else {
                    // save_regp x(19 + 2 * pair)
                    push2(&mut codes, 0xc800 | ((2 * pair) << 6) | (2 * pair))?;
                }
            }
        }
        if self.cr == 2 {
            push1(&mut codes, 0xfc)?; // pac_sign_lr
        }
        push1(&mut codes, 0xe4)?; // end
        let epilog = codes.clone();
        let mut prolog = codes;
        if homing {
            // The four `stp x0..x7` homing stores sit between the frame
            // allocation and the register saves, and only in the prolog.
            prolog.splice(homing_at..homing_at, [0xe3; 4]);
        }
        Some((prolog, epilog))
    }
}

impl Program {
    /// Undo the part of the function's prolog that has run, or finish the
    /// part of its epilog that has not, for a frame stopped `offset`
    /// instructions into the function.
    fn unwind(
        &self,
        offset: u32,
        context: &mut RegisterContext,
        memory: &impl FrameMemory,
    ) -> Option<Resume> {
        match self {
            Program::Packed(unwind_data) => {
                let packed = Packed::new(*unwind_data);
                let (prolog, epilog) = packed.codes()?;
                if packed.flag == 1
                    && (offset < prolog.len() as u32
                        || offset >= packed.length.saturating_sub(epilog.len() as u32))
                {
                    let len = sequence_len(&prolog);
                    if offset < len {
                        return run_codes(&prolog, len - offset, context, memory);
                    }
                    let len = sequence_len(&epilog);
                    if let Some(start) = packed.length.checked_sub(len + 1)
                        && offset >= start
                    {
                        return run_codes(&epilog, offset - start, context, memory);
                    }
                }
                run_codes(&prolog, 0, context, memory)
            }
            Program::Full(xdata) => {
                let codes = &xdata.codes;
                let code_bytes = codes.len() as u32;
                if offset < code_bytes {
                    let len = sequence_len(codes);
                    if offset < len {
                        return run_codes(codes, len - offset, context, memory);
                    }
                }
                if !xdata.epilog_in_header {
                    for &scope in &xdata.scopes {
                        let start = scope & 0x3ffff;
                        let index = scope >> 22;
                        if offset < start {
                            break;
                        }
                        if code_bytes
                            .checked_sub(index)
                            .is_some_and(|room| offset - start < room)
                        {
                            let epilog = &codes[index as usize..];
                            if offset <= start + sequence_len(epilog) {
                                return run_codes(epilog, offset - start, context, memory);
                            }
                        }
                    }
                } else if let Some(epilog) = codes.get(xdata.epilog_count as usize..)
                    && xdata.length.saturating_sub(offset) <= epilog.len() as u32
                {
                    let len = sequence_len(epilog) + 1;
                    if let Some(start) = xdata.length.checked_sub(len)
                        && offset >= start
                    {
                        return run_codes(epilog, offset - start, context, memory);
                    }
                }
                run_codes(codes, 0, context, memory)
            }
        }
    }

    /// Whether the prolog makes x29 the frame pointer.
    fn sets_frame_pointer(&self) -> bool {
        match self {
            Program::Packed(unwind_data) => matches!(Packed::new(*unwind_data).cr, 2 | 3),
            Program::Full(xdata) => {
                let mut at = 0;
                while let Some(&op) = xdata.codes.get(at) {
                    match op {
                        0xe1 | 0xe2 => return true,
                        0xe4 | 0xe5 => return false,
                        _ => at += code_len(op),
                    }
                }
                false
            }
        }
    }

    /// x29 in the function's body when sp there is `sp` and the body has not
    /// moved sp: the prolog's allocations after it set x29 are undone to
    /// find the sp x29 was set from. `None` when the prolog does not set x29.
    fn frame_pointer_at_body(&self, mut sp: u64) -> Option<u64> {
        let codes = match self {
            Program::Packed(unwind_data) => Packed::new(*unwind_data).codes()?.0,
            Program::Full(xdata) => xdata.codes.clone(),
        };
        let mut at = 0;
        while let Some(&op) = codes.get(at) {
            let second = || codes.get(at + 1).copied().map(u64::from);
            match op {
                0x00..=0x1f => sp = sp.wrapping_add(16 * u64::from(op & 0x1f)),
                0xc0..=0xc7 => {
                    let size = (u64::from(op) << 8 | second()?) & 0x7ff;
                    sp = sp.wrapping_add(16 * size);
                }
                0xe0 => {
                    let size = codes.get(at + 1..at + 4)?;
                    let size =
                        u64::from(size[0]) << 16 | u64::from(size[1]) << 8 | u64::from(size[2]);
                    sp = sp.wrapping_add(16 * size);
                }
                0xe1 => return Some(sp),
                0xe2 => return Some(sp.wrapping_add(8 * second()?)),
                // Saves at a positive offset leave sp where it is.
                0x40..=0x7f
                | 0xc8..=0xcb
                | 0xd0..=0xd3
                | 0xd6..=0xd9
                | 0xdc..=0xdd
                | 0xe3
                | 0xfc => {}
                _ => return None,
            }
            at += code_len(op);
        }
        None
    }
}

/// The return address of the first `bl` to `callee` in `code`, which starts
/// at `start`.
pub fn call_return_address(code: &[u8], start: u64, callee: u64) -> Option<u64> {
    code.as_chunks::<4>()
        .0
        .iter()
        .zip((start..).step_by(4))
        .find_map(|(word, pc)| {
            let word = u32::from_le_bytes(*word);
            if word & 0xfc00_0000 != 0x9400_0000 {
                return None;
            }
            let displacement = i64::from(((word << 6) as i32) >> 6) * 4;
            (pc.wrapping_add_signed(displacement) == callee).then_some(pc + 4)
        })
}

/// Where an unwound frame resumes.
#[derive(Debug, PartialEq, Eq)]
enum Resume {
    /// At the return address in lr: an ordinary return to the caller.
    Return,
    /// At the pc a trap, machine, or context frame held. `full` when that
    /// frame also held the volatile registers.
    Interrupted { full: bool },
}

/// Reads an unwind needs from the stack being walked.
trait FrameMemory {
    fn u64(&self, address: u64) -> Option<u64>;
    /// The registers a `KTRAP_FRAME` at `address` saved.
    fn trap_frame(&self, address: u64) -> Option<Arm64SavedRegisters>;
}

fn code_len(op: u8) -> usize {
    match op {
        0x00..=0xbf => 1,
        0xc0..=0xdf | 0xe2 => 2,
        0xe0 => 4,
        0xe7 => 3,
        _ => 1,
    }
}

/// Instructions the codes up to the sequence's `end` stand for. The custom
/// frame codes describe the stack rather than an instruction.
fn sequence_len(codes: &[u8]) -> u32 {
    let mut instructions = 0;
    let mut at = 0;
    while let Some(&op) = codes.get(at) {
        if op == 0xe4 || op == 0xe5 {
            break;
        }
        if op & 0xf8 != 0xe8 {
            instructions += 1;
        }
        at += code_len(op);
    }
    instructions
}

/// Load `count` registers from `first` at `sp + 8 * pos`. A negative `pos`
/// is a pre-indexed store: the registers sit at `sp`, which then moves up by
/// `-8 * pos`.
fn restore(
    context: &mut RegisterContext,
    memory: &impl FrameMemory,
    first: u32,
    count: u32,
    pos: i64,
) -> Option<()> {
    let offset = pos.max(0) as u64;
    for index in 0..u64::from(count) {
        let slot = usize::try_from(u64::from(first) + index).ok()?;
        if slot > LR {
            return None;
        }
        let address = context.rsp.wrapping_add(8 * (offset + index));
        context.regs[slot] = Some(memory.u64(address)?);
    }
    release_saved(context, pos, 8);
    Some(())
}

/// Step over a save of registers the walk does not track (the FP/SIMD
/// ones), moving sp when the store was pre-indexed.
fn release_saved(context: &mut RegisterContext, pos: i64, unit: u64) {
    if pos < 0 {
        context.rsp = context.rsp.wrapping_add(unit * pos.unsigned_abs());
    }
}

/// Apply the unwind codes in `codes` to `context`, skipping the first `skip`
/// (the instructions that have not run yet in a prolog, or already ran in an
/// epilog).
fn run_codes(
    codes: &[u8],
    mut skip: u32,
    context: &mut RegisterContext,
    memory: &impl FrameMemory,
) -> Option<Resume> {
    let mut at = 0;
    while skip > 0 {
        match codes.get(at) {
            Some(&op) if op != 0xe4 => at += code_len(op),
            _ => break,
        }
        skip -= 1;
    }

    let mut resume = Resume::Return;
    let mut save_next = 2u32;
    while let Some(&op) = codes.get(at) {
        let len = code_len(op);
        let Some(bytes) = codes.get(at..at + len) else {
            break;
        };
        let value = if len > 1 {
            u32::from(bytes[0]) << 8 | u32::from(bytes[1])
        } else {
            u32::from(op)
        };
        let small = i64::from(value & 0x1f);
        let wide = i64::from(value & 0x3f);
        match op {
            0x00..=0x1f => context.rsp = context.rsp.wrapping_add(16 * u64::from(value & 0x1f)), // alloc_s
            0x20..=0x3f => restore(context, memory, 19, save_next, -small)?, // save_r19r20_x
            0x40..=0x7f => restore(context, memory, 29, 2, wide)?,           // save_fplr
            0x80..=0xbf => restore(context, memory, 29, 2, -wide - 1)?,      // save_fplr_x
            0xc0..=0xc7 => context.rsp = context.rsp.wrapping_add(16 * u64::from(value & 0x7ff)), // alloc_m
            0xc8..=0xcb => restore(context, memory, 19 + ((value >> 6) & 0xf), save_next, wide)?, // save_regp
            0xcc..=0xcf => {
                // save_regp_x
                restore(
                    context,
                    memory,
                    19 + ((value >> 6) & 0xf),
                    save_next,
                    -wide - 1,
                )?
            }
            0xd0..=0xd3 => restore(context, memory, 19 + ((value >> 6) & 0xf), 1, wide)?, // save_reg
            0xd4..=0xd5 => restore(context, memory, 19 + ((value >> 5) & 0xf), 1, -small - 1)?, // save_reg_x
            0xd6..=0xd7 => {
                // save_lrpair
                restore(context, memory, 19 + 2 * ((value >> 6) & 0x7), 1, wide)?;
                restore(context, memory, 30, 1, wide + 1)?;
            }
            0xd8..=0xd9 | 0xdc..=0xdd => {} // save_fregp, save_freg
            0xda..=0xdb => release_saved(context, -wide - 1, 8), // save_fregp_x
            0xde => release_saved(context, -small - 1, 8), // save_freg_x
            0xe0 => {
                // alloc_l
                let size =
                    u64::from(bytes[1]) << 16 | u64::from(bytes[2]) << 8 | u64::from(bytes[3]);
                context.rsp = context.rsp.wrapping_add(16 * size);
            }
            0xe1 => context.rsp = context.regs[FP]?, // set_fp
            0xe2 => context.rsp = context.regs[FP]?.wrapping_sub(8 * u64::from(value & 0xff)), // add_fp
            0xe3 | 0xe5 => {} // nop, end_c
            0xe4 => break,    // end
            0xe6 => {
                // save_next widens the register save that follows it
                save_next += 2;
                at += len;
                continue;
            }
            0xe7 => {
                // save_any_reg
                let count = if bytes[1] & 0x40 != 0 { save_next } else { 1 };
                let mut pos = i64::from(bytes[2] & 0x3f);
                if bytes[1] & 0x20 != 0 {
                    pos = -pos - 1;
                }
                let register = u32::from(bytes[1] & 0x1f);
                match bytes[2] >> 6 {
                    0 | 1 => {
                        if count > 1 || pos < 0 {
                            pos *= 2;
                        }
                        if bytes[2] >> 6 == 0 {
                            restore(context, memory, register, count, pos)?;
                        } else {
                            release_saved(context, pos, 8);
                        }
                    }
                    2 => release_saved(context, pos, 16),
                    _ => return None,
                }
            }
            0xe8 => {
                // MSFT_OP_TRAP_FRAME: sp points at a KTRAP_FRAME
                let frame = memory.trap_frame(context.rsp)?;
                for (slot, value) in context.regs.iter_mut().zip(frame.x) {
                    if value.is_some() {
                        *slot = value;
                    }
                }
                context.rip = frame.pc?;
                context.rsp = frame.sp?;
                resume = Resume::Interrupted { full: true };
            }
            0xe9 => {
                // MSFT_OP_MACHINE_FRAME: { sp, pc } at sp
                context.rip = memory.u64(context.rsp.wrapping_add(8))?;
                context.rsp = memory.u64(context.rsp)?;
                resume = Resume::Interrupted { full: false };
            }
            0xea => {
                // MSFT_OP_CONTEXT: an ARM64 CONTEXT at sp
                let base = context.rsp;
                for (index, slot) in context.regs.iter_mut().enumerate() {
                    *slot = Some(memory.u64(base.wrapping_add((OFFSET_X0 + 8 * index) as u64))?);
                }
                context.rip = memory.u64(base.wrapping_add(OFFSET_PC as u64))?;
                context.rsp = memory.u64(base.wrapping_add(OFFSET_SP as u64))?;
                resume = Resume::Interrupted { full: true };
            }
            0xec => {
                // MSFT_OP_CLEAR_UNWOUND_TO_CALL: resume at lr, not after a call
                context.rip = context.regs[LR]?;
                resume = Resume::Interrupted { full: false };
            }
            0xfc => context.regs[LR] = context.regs[LR].map(strip_pac), // pac_sign_lr
            _ => return None,
        }
        save_next = 2;
        at += len;
    }
    Some(resume)
}

/// Resolution of a pc against a module's ARM64 unwind tables.
enum Resolve {
    /// No module or no `.pdata` entry covers the pc.
    Leaf,
    Function {
        base: u64,
        function: Arm64Function,
        program: Program,
    },
    /// The lookup or the unwind data lies in a paged-out hole.
    Holed,
}

fn resolve_in(image: &PeImage, base: u64, pc: u64) -> Resolve {
    let Some(pdata) = exception_directory(image) else {
        return Resolve::Leaf;
    };
    let Ok(rva) = u32::try_from(pc.wrapping_sub(base)) else {
        return Resolve::Leaf;
    };
    match lookup_arm64_runtime_function(image, pdata, rva) {
        Arm64Lookup::Found(function) => match read_program(image, function.unwind_data) {
            Some(program) => Resolve::Function {
                base,
                function,
                program,
            },
            None => Resolve::Holed,
        },
        Arm64Lookup::Missing => Resolve::Leaf,
        Arm64Lookup::Unreadable => Resolve::Holed,
    }
}

impl FrameMemory for StackTracer<'_> {
    fn u64(&self, address: u64) -> Option<u64> {
        self.stack_u64(address).ok()
    }

    fn trap_frame(&self, address: u64) -> Option<Arm64SavedRegisters> {
        decode_ktrap_frame_for_thread(self.target, self.trace.active_dtb, VirtAddr(address))
            .ok()?
            .arm64
    }
}

impl StackTracer<'_> {
    /// Resolve `pc`'s function, upgrading a holed in-memory image to the
    /// on-disk one when that could answer.
    fn resolve_arm64(&mut self, pc: u64) -> Resolve {
        let Some(base) = self
            .module_containing(pc)
            .map(|module| module.info.base_address.0)
        else {
            return Resolve::Leaf;
        };
        let Some(image) = self.module_image(pc) else {
            return Resolve::Holed;
        };
        let resolved = resolve_in(&image, base, pc);
        if matches!(resolved, Resolve::Holed)
            && !image.is_complete()
            && self.upgrade_module_image(pc)
            && let Some(image) = self.module_image(pc)
        {
            return resolve_in(&image, base, pc);
        }
        resolved
    }

    /// Where a frame's function and unwind state are looked up: a frame
    /// returned into is suspended in the call 4 bytes before its pc, and a
    /// call that ends a function returns into the next one.
    fn arm64_lookup_pc(context: &RegisterContext) -> u64 {
        if context.after_call {
            context.rip.wrapping_sub(4)
        } else {
            context.rip
        }
    }

    pub fn unwind_once_arm64(&mut self, context: &mut RegisterContext) -> Unwound {
        let pc = Self::arm64_lookup_pc(context);
        unwind_trace!(
            "unwind: pc={:#x} sp={:#x} after_call={}",
            context.rip,
            context.rsp,
            context.after_call
        );
        let resume = match self.resolve_arm64(pc) {
            Resolve::Function {
                base,
                function,
                program,
            } => {
                let offset = (pc - base) as u32 - function.begin;
                unwind_trace!(
                    "unwind: function {:#x}..{:#x} offset={:#x}",
                    base + u64::from(function.begin),
                    base + u64::from(function.end),
                    offset
                );
                match program.unwind(offset / 4, context, &*self) {
                    Some(resume) => resume,
                    None => {
                        unwind_trace!("unwind: unreadable stack or unsupported code -> stop");
                        return Unwound::Stop;
                    }
                }
            }
            // A function with no unwind data never moves sp or saves lr, so
            // it returns straight through lr. Only the frame a thread stopped
            // in can be one: a caller made a call, which saved lr.
            Resolve::Leaf if !context.after_call => {
                unwind_trace!("unwind: no unwind data -> leaf");
                Resume::Return
            }
            Resolve::Leaf | Resolve::Holed => {
                unwind_trace!("unwind: caller without resident unwind data -> stop");
                return Unwound::Stop;
            }
        };

        match resume {
            Resume::Return => {
                let Some(lr) = context.regs[LR] else {
                    return Unwound::Stop;
                };
                // A thread's initial frame saves a zero lr: the stack ends.
                if lr == 0 {
                    context.rip = 0;
                    return Unwound::Frame {
                        stack_switch: false,
                    };
                }
                let return_address = strip_pac(lr);
                if return_address == context.rip || !self.is_executable_address(return_address) {
                    return Unwound::Stop;
                }
                context.rip = return_address;
                context.after_call = true;
                for index in VOLATILE {
                    context.regs[index] = None;
                }
                Unwound::Frame {
                    stack_switch: false,
                }
            }
            Resume::Interrupted { full } => {
                context.rip = strip_pac(context.rip);
                context.after_call = false;
                if !full {
                    for index in VOLATILE {
                        context.regs[index] = None;
                    }
                }
                Unwound::Frame { stack_switch: true }
            }
        }
    }

    /// The base PDB frame-relative locals are addressed from: x29 in a
    /// function whose prolog establishes it, else sp.
    pub fn frame_base_for_arm64(&mut self, context: &RegisterContext) -> Option<u64> {
        let fallback = (context.rsp != 0).then_some(context.rsp);
        match self.resolve_arm64(Self::arm64_lookup_pc(context)) {
            Resolve::Function { program, .. } if program.sets_frame_pointer() => {
                context.regs[FP].or(fallback)
            }
            _ => fallback,
        }
    }

    /// x29 in the body of the function containing `address` when sp there
    /// is `sp`; see [`Program::frame_pointer_at_body`].
    pub fn frame_pointer_at_body_arm64(&mut self, address: u64, sp: u64) -> Option<u64> {
        match self.resolve_arm64(address) {
            Resolve::Function { program, .. } => program.frame_pointer_at_body(sp),
            Resolve::Leaf | Resolve::Holed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct Stack(HashMap<u64, u64>);

    impl FrameMemory for Stack {
        fn u64(&self, address: u64) -> Option<u64> {
            self.0.get(&address).copied()
        }

        fn trap_frame(&self, _: u64) -> Option<Arm64SavedRegisters> {
            None
        }
    }

    fn stack(slots: &[(u64, u64)]) -> Stack {
        Stack(slots.iter().copied().collect())
    }

    fn frame(sp: u64, fp: u64, lr: u64) -> RegisterContext {
        let mut context = RegisterContext::new(0, sp);
        context.regs[FP] = Some(fp);
        context.regs[LR] = Some(lr);
        context
    }

    fn packed(length: u32, reg_i: u32, cr: u32, frame_size: u32) -> Program {
        Program::Packed(1 | (length << 2) | (reg_i << 16) | (cr << 21) | (frame_size << 23))
    }

    const SP: u64 = 0x1000;

    /// `stp x19, x20, [sp, #-16]!; stp x29, lr, [sp, #-48]!; mov x29, sp`,
    /// then the reverse in the epilog before `ret`, as packed data describes
    /// with RegI = 2, CR = 3, and a 64-byte frame.
    fn packed_frame() -> (Program, Stack) {
        let stack = stack(&[
            (SP, 0xf00d),
            (SP + 8, 0xca11e4),
            (SP + 48, 0x19),
            (SP + 56, 0x20),
        ]);
        (packed(20, 2, 3, 4), stack)
    }

    #[test]
    fn packed_data_unwinds_the_whole_prolog_from_the_body() {
        let (program, stack) = packed_frame();
        let mut context = frame(SP, SP, 0xdead);
        assert_eq!(
            program.unwind(8, &mut context, &stack),
            Some(Resume::Return)
        );
        assert_eq!(context.rsp, SP + 64);
        assert_eq!(context.regs[FP], Some(0xf00d));
        assert_eq!(context.regs[LR], Some(0xca11e4));
        assert_eq!(
            (context.regs[19], context.regs[20]),
            (Some(0x19), Some(0x20))
        );
    }

    #[test]
    fn packed_data_undoes_only_the_prolog_that_ran() {
        let (program, stack) = packed_frame();
        // After `stp x19, x20, [sp, #-16]!` alone: lr is still live and only
        // x19/x20 sit on the stack.
        let mut context = frame(SP + 48, 0xf00d, 0xca11e4);
        assert_eq!(
            program.unwind(1, &mut context, &stack),
            Some(Resume::Return)
        );
        assert_eq!(context.rsp, SP + 64);
        assert_eq!(context.regs[LR], Some(0xca11e4));
        assert_eq!(context.regs[FP], Some(0xf00d));
        assert_eq!(context.regs[19], Some(0x19));

        // At the first instruction nothing has been saved.
        let mut context = frame(SP + 64, 0xf00d, 0xca11e4);
        program.unwind(0, &mut context, &stack);
        assert_eq!(context.rsp, SP + 64);
        assert_eq!(context.regs[19], None);
    }

    #[test]
    fn packed_data_finishes_a_partly_run_epilog() {
        let (program, stack) = packed_frame();
        // `ldp x29, lr, [sp], #48` ran: fp and lr are restored, x19/x20 are
        // not yet.
        let mut context = frame(SP + 48, 0xf00d, 0xca11e4);
        assert_eq!(
            program.unwind(18, &mut context, &stack),
            Some(Resume::Return)
        );
        assert_eq!(context.rsp, SP + 64);
        assert_eq!(context.regs[19], Some(0x19));

        // At `ret` the frame is gone.
        let mut context = frame(SP + 64, 0xf00d, 0xca11e4);
        program.unwind(19, &mut context, &stack);
        assert_eq!(context.rsp, SP + 64);
        assert_eq!(context.regs[19], None);
    }

    /// Prolog: `stp x19, x20, [sp, #-48]!; stp x21, x22, [sp, #16];
    /// stp x29, lr, [sp, #32]; add x29, sp, #32; sub sp, sp, #64`. Epilog at
    /// instruction 0x1b: `add sp, sp, #64; ldp x29, lr, [sp, #32];
    /// ldp x21, x22, [sp, #16]; ldp x19, x20, [sp], #48; ret`.
    fn xdata_frame() -> (Program, Stack) {
        let codes = vec![
            0x04, 0xe2, 0x04, 0x44, 0xe6, 0x26, 0xe4, 0xe3, // prolog
            0x04, 0x44, 0xe6, 0x26, 0xe4, 0xe3, 0xe3, 0xe3, // epilog
        ];
        let program = Program::Full(Xdata {
            length: 0x20,
            epilog_in_header: false,
            epilog_count: 1,
            scopes: vec![0x1b | (8 << 22)],
            codes,
        });
        let frame = SP + 64;
        let stack = stack(&[
            (frame, 0x19),
            (frame + 8, 0x20),
            (frame + 16, 0x21),
            (frame + 24, 0x22),
            (frame + 32, 0xf00d),
            (frame + 40, 0xca11e4),
        ]);
        (program, stack)
    }

    #[test]
    fn xdata_codes_unwind_the_body_through_the_frame_pointer() {
        let (program, stack) = xdata_frame();
        // sp is irrelevant once x29 is set: the body may have moved it.
        let mut context = frame(0x10, SP + 64 + 32, 0xdead);
        assert_eq!(
            program.unwind(0x10, &mut context, &stack),
            Some(Resume::Return)
        );
        assert_eq!(context.rsp, SP + 64 + 48);
        assert_eq!(context.regs[LR], Some(0xca11e4));
        assert_eq!(
            context.regs[19..=22],
            [Some(0x19), Some(0x20), Some(0x21), Some(0x22)]
        );
    }

    #[test]
    fn xdata_codes_undo_a_partial_prolog_with_save_next() {
        let (program, stack) = xdata_frame();
        // Both register-pair stores ran; fp and lr are still live.
        let mut context = frame(SP + 64, 0xf00d, 0xca11e4);
        assert_eq!(
            program.unwind(2, &mut context, &stack),
            Some(Resume::Return)
        );
        assert_eq!(context.rsp, SP + 64 + 48);
        assert_eq!(context.regs[22], Some(0x22));
        assert_eq!(context.regs[FP], Some(0xf00d));
    }

    #[test]
    fn xdata_epilog_scopes_skip_the_instructions_already_run() {
        let (program, stack) = xdata_frame();
        // `add sp` and `ldp x29, lr` ran.
        let mut context = frame(SP + 64, 0xf00d, 0xca11e4);
        assert_eq!(
            program.unwind(0x1d, &mut context, &stack),
            Some(Resume::Return)
        );
        assert_eq!(context.rsp, SP + 64 + 48);
        assert_eq!(context.regs[21], Some(0x21));

        // One instruction before the epilog is still the body.
        let mut context = frame(0x10, SP + 64 + 32, 0xdead);
        program.unwind(0x1a, &mut context, &stack);
        assert_eq!(context.regs[LR], Some(0xca11e4));
    }

    #[test]
    fn a_machine_frame_resumes_at_the_interrupted_pc_and_stack() {
        let program = Program::Full(Xdata {
            length: 4,
            epilog_in_header: true,
            epilog_count: 0,
            scopes: Vec::new(),
            codes: vec![0xe9, 0xe4, 0xe3, 0xe3],
        });
        let stack = stack(&[(SP, 0x8000), (SP + 8, 0xfffff803_12345678)]);
        let mut context = frame(SP, 0, 0);
        assert_eq!(
            program.unwind(2, &mut context, &stack),
            Some(Resume::Interrupted { full: false })
        );
        assert_eq!((context.rip, context.rsp), (0xfffff803_12345678, 0x8000));
    }

    #[test]
    fn the_frame_pointer_at_a_body_undoes_allocations_made_after_it_was_set() {
        // `stp x29, lr, [sp, #0x50]; add x29, sp, #0x50` ends the prolog.
        let program = Program::Full(Xdata {
            length: 0x10,
            epilog_in_header: true,
            epilog_count: 0,
            scopes: Vec::new(),
            codes: vec![0xe2, 0x0a, 0x4a, 0xe4],
        });
        assert_eq!(program.frame_pointer_at_body(SP), Some(SP + 0x50));

        // `mov x29, sp; sub sp, sp, #0x20`: the body's sp is 0x20 below x29.
        let program = Program::Full(Xdata {
            length: 0x10,
            epilog_in_header: true,
            epilog_count: 0,
            scopes: Vec::new(),
            codes: vec![0x02, 0xe1, 0x81, 0xe4],
        });
        assert_eq!(program.frame_pointer_at_body(SP), Some(SP + 0x20));

        // No x29 setup before the pre-indexed save ends the search.
        let (program, _) = packed_frame();
        assert_eq!(packed(20, 2, 0, 2).frame_pointer_at_body(SP), None);
        assert_eq!(program.frame_pointer_at_body(SP), Some(SP));
    }

    #[test]
    fn call_return_address_finds_the_bl_to_the_callee() {
        let start = 0xfffff803_b900c5b0;
        let mut code = Vec::new();
        // A `bl` elsewhere, a `b` to the callee, then `bl SwapContext`
        // (0x2d5db instructions ahead) at +0x1c.
        for word in [0x9400_0010u32, 0xd503_201f, 0x1402_d5e0, 0xd503_201f] {
            code.extend_from_slice(&word.to_le_bytes());
        }
        code.extend_from_slice(&[0; 12]);
        code.extend_from_slice(&0x9402_d5dbu32.to_le_bytes());
        let callee = start + 0x1c + 0x2d5db * 4;
        assert_eq!(
            call_return_address(&code, start, callee),
            Some(start + 0x20)
        );
        // A backward `bl` sign-extends its displacement.
        let backward = (0x9400_0000u32 | (0x03ff_ffff & (-4i32 as u32))).to_le_bytes();
        assert_eq!(
            call_return_address(&backward, start, start - 16),
            Some(start + 4)
        );
        assert_eq!(call_return_address(&code, start, start + 0x08), None);
    }

    #[test]
    fn lookup_arm64_runtime_function_decodes_packed_and_xdata_lengths() {
        let mut image_bytes = vec![0u8; 0x3100];
        // Full .xdata header: low 18 bits are a 0x80-byte function in 4-byte units.
        image_bytes[0x2000..0x2004].copy_from_slice(&(0x80u32 / 4).to_le_bytes());

        let mut pdata = Vec::new();
        // Packed entry: flag 1 and a 0x40-byte function length.
        pdata.extend_from_slice(&0x1000u32.to_le_bytes());
        pdata.extend_from_slice(&(((0x40u32 / 4) << 2) | 1).to_le_bytes());
        // Unpacked entry: flag 0 and an RVA to the .xdata header above.
        pdata.extend_from_slice(&0x1100u32.to_le_bytes());
        pdata.extend_from_slice(&0x2000u32.to_le_bytes());
        image_bytes[0x3000..0x3000 + pdata.len()].copy_from_slice(&pdata);
        let image = PeImage::complete(image_bytes);
        let pdata = 0x3000..0x3000 + pdata.len();
        let range = |rva| match lookup_arm64_runtime_function(&image, pdata.clone(), rva) {
            Arm64Lookup::Found(function) => Some((function.begin, function.end)),
            _ => None,
        };

        assert_eq!(range(0x103c), Some((0x1000, 0x1040)));
        assert_eq!(range(0x1040), None);
        assert_eq!(range(0x117c), Some((0x1100, 0x1180)));
        assert_eq!(range(0x1180), None);
    }
}
