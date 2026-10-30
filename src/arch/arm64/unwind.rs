//! The ARM64 exception-handling data's unwind format: packed unwind data
//! and `.xdata` records, whose unwind codes step a frame to its caller the
//! way the Windows unwinder does, partial prologs and epilogs included, and
//! through the kernel's trap, machine, and context frames.

use ntoseye_macros::record;

use super::{OFFSET_PC, OFFSET_SP, OFFSET_X0};
use crate::arch::unwind::{FrameMemory, FrameRegisters, Unwind, UnwindBytes, UnwindHandler};
use crate::base::bytes::get_u32;

/// The size of an ARM64 `RUNTIME_FUNCTION`: begin and unwind-data offsets;
/// the length is in the packed unwind data or the `.xdata` header.
pub const RUNTIME_FUNCTION_SIZE: usize = 8;

pub const FP: usize = 29;

pub const LR: usize = 30;

/// Strip AArch64 pointer-authentication bits (bits 63:56) from a return
/// address: sign-extend the 56-bit canonical address back to 64 bits.
pub fn strip_pac(addr: u64) -> u64 {
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
    /// The first header word: length, version, and the X and E bits.
    header: u32,
    /// Where the unwind codes end: the exception handler's RVA follows.
    end: usize,
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

fn read_program(image: &impl UnwindBytes, unwind_data: u32) -> Option<Program> {
    match unwind_data & 0b11 {
        0 => read_xdata(image, unwind_data as usize).map(Program::Full),
        1 | 2 => Some(Program::Packed(unwind_data)),
        _ => None,
    }
}

/// A function's ARM64 unwind data: the packed form a `.pdata` entry holds,
/// or the `.xdata` record it points to.
pub struct UnwindData(Program);

impl UnwindData {
    /// The unwind data a `.pdata` entry's `unwind_data` word gives: packed
    /// data, or the RVA of an `.xdata` record in `image`. `None` when the
    /// record cannot be read, or the word has a reserved form.
    pub fn read(image: &impl UnwindBytes, unwind_data: u32) -> Option<Self> {
        read_program(image, unwind_data).map(Self)
    }

    /// Step `context` toward the caller of a frame stopped `offset` bytes
    /// into the function: undo the part of the prolog that has run, or
    /// finish the part of an epilog that has not. `None` when the stack
    /// cannot be read or a code is not supported.
    pub fn step(
        &self,
        offset: u32,
        context: &mut FrameRegisters,
        memory: &impl FrameMemory,
    ) -> Option<Resume> {
        self.0.unwind(offset / 4, context, memory)
    }

    /// Whether the prolog makes x29 the frame pointer.
    pub fn sets_frame_pointer(&self) -> bool {
        self.0.sets_frame_pointer()
    }

    /// x29 in the function's body when sp there is `sp`; `None` when the
    /// prolog does not set x29.
    pub fn frame_pointer_at_body(&self, sp: u64) -> Option<u64> {
        self.0.frame_pointer_at_body(sp)
    }
}

/// Entry `index` of the ARM64 exception directory at `pdata`: the
/// function's begin RVA and its unwind-data word. `None` when it cannot be
/// read.
pub fn runtime_function_at(
    image: &impl UnwindBytes,
    pdata: usize,
    index: usize,
) -> Option<(u32, u32)> {
    let bytes = image.read(pdata + index * RUNTIME_FUNCTION_SIZE, RUNTIME_FUNCTION_SIZE)?;
    Some((get_u32(&bytes, 0)?, get_u32(&bytes, 4)?))
}

/// The length in bytes of the function whose `.pdata` entry holds
/// `unwind_data`: from the packed data, or the header of the `.xdata`
/// record. `None` when that header cannot be read; 0 when the word gives no
/// length.
pub fn function_length(image: &impl UnwindBytes, unwind_data: u32) -> Option<u32> {
    let instructions = match unwind_data & 0b11 {
        0 => {
            let header = image.read((unwind_data & !0b11) as usize, 4)?;
            get_u32(&header, 0).map_or(0, xdata_length)
        }
        1 | 2 => packed_length(unwind_data),
        _ => 0,
    };
    Some(instructions * 4)
}

/// The function length, in instructions, of packed unwind data.
fn packed_length(unwind_data: u32) -> u32 {
    (unwind_data >> 2) & 0x7ff
}

/// The function length, in instructions, an `.xdata` header gives.
fn xdata_length(header: u32) -> u32 {
    header & 0x3ffff
}

fn read_xdata(image: &impl UnwindBytes, at: usize) -> Option<Xdata> {
    let header = get_u32(&image.read(at, 4)?, 0)?;
    let mut epilog_count = (header >> 22) & 0x1f;
    let mut code_words = header >> 27;
    let mut next = at + 4;
    if epilog_count == 0 && code_words == 0 {
        let extension = get_u32(&image.read(next, 4)?, 0)?;
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
        header,
        end: next + codes.len(),
        length: xdata_length(header),
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

/// Encodes a stack allocation of up to 4080 bytes in the shortest code that
/// holds it: `alloc_s` covers only sizes below 512, since its 5-bit field
/// overflows into the `save_r19r20_x` opcode at 512.
fn push_alloc(codes: &mut Vec<u8>, size: u32) -> Option<()> {
    if size < 512 {
        push1(codes, size / 16) // alloc_s
    } else {
        push2(codes, 0xc000 | (size / 16)) // alloc_m
    }
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
            length: packed_length(unwind_data),
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
            if local_size <= 4080 {
                push_alloc(&mut codes, local_size)?;
            } else {
                push_alloc(&mut codes, local_size - 4080)?;
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
        context: &mut FrameRegisters,
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
pub enum Resume {
    /// At the return address in lr: an ordinary return to the caller.
    Return,
    /// At the pc a trap, machine, or context frame held. `full` when that
    /// frame also held the volatile registers.
    Interrupted { full: bool },
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
    context: &mut FrameRegisters,
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
        let address = context.sp.wrapping_add(8 * (offset + index));
        context.regs[slot] = Some(memory.stack_u64(address)?);
    }
    release_saved(context, pos, 8);
    Some(())
}

/// Step over a save of registers the walk does not track (the FP/SIMD
/// ones), moving sp when the store was pre-indexed.
fn release_saved(context: &mut FrameRegisters, pos: i64, unit: u64) {
    if pos < 0 {
        context.sp = context.sp.wrapping_add(unit * pos.unsigned_abs());
    }
}

/// Apply the unwind codes in `codes` to `context`, skipping the first `skip`
/// (the instructions that have not run yet in a prolog, or already ran in an
/// epilog).
fn run_codes(
    codes: &[u8],
    mut skip: u32,
    context: &mut FrameRegisters,
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
            0x00..=0x1f => context.sp = context.sp.wrapping_add(16 * u64::from(value & 0x1f)), // alloc_s
            0x20..=0x3f => restore(context, memory, 19, save_next, -small)?, // save_r19r20_x
            0x40..=0x7f => restore(context, memory, 29, 2, wide)?,           // save_fplr
            0x80..=0xbf => restore(context, memory, 29, 2, -wide - 1)?,      // save_fplr_x
            0xc0..=0xc7 => context.sp = context.sp.wrapping_add(16 * u64::from(value & 0x7ff)), // alloc_m
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
                context.sp = context.sp.wrapping_add(16 * size);
            }
            0xe1 => context.sp = context.regs[FP]?, // set_fp
            0xe2 => context.sp = context.regs[FP]?.wrapping_sub(8 * u64::from(value & 0xff)), // add_fp
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
                let frame = memory.trap_frame(context.sp)?;
                for (slot, value) in context.regs.iter_mut().zip(frame.regs) {
                    if value.is_some() {
                        *slot = value;
                    }
                }
                context.pc = frame.pc;
                context.sp = frame.sp;
                resume = Resume::Interrupted { full: true };
            }
            0xe9 => {
                // MSFT_OP_MACHINE_FRAME: { sp, pc } at sp
                context.pc = memory.stack_u64(context.sp.wrapping_add(8))?;
                context.sp = memory.stack_u64(context.sp)?;
                resume = Resume::Interrupted { full: false };
            }
            0xea => {
                // MSFT_OP_CONTEXT: an ARM64 CONTEXT at sp
                let base = context.sp;
                for (index, slot) in context.regs.iter_mut().enumerate() {
                    *slot =
                        Some(memory.stack_u64(base.wrapping_add((OFFSET_X0 + 8 * index) as u64))?);
                }
                context.pc = memory.stack_u64(base.wrapping_add(OFFSET_PC as u64))?;
                context.sp = memory.stack_u64(base.wrapping_add(OFFSET_SP as u64))?;
                resume = Resume::Interrupted { full: true };
            }
            0xec => {
                // MSFT_OP_CLEAR_UNWOUND_TO_CALL: resume at lr, not after a call
                context.pc = context.regs[LR]?;
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

/// ARM64 unwind data that is packed into the `.pdata` entry (flag 1 or 2).
/// It describes a canonical prolog, and ntoseye lists it as the codes that
/// it represents.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct Arm64PackedUnwind {
    /// 1, or 2 for a function fragment without a prolog.
    pub flag: u32,
    /// The `RegF` field: the saved non-volatile floating-point registers.
    pub reg_f: u32,
    /// The `RegI` field: the saved non-volatile integer registers.
    pub reg_i: u32,
    /// Whether the prolog stores the argument registers in their home
    /// locations.
    pub homes_arguments: bool,
    /// The `CR` field: whether and how the prolog saves the frame chain
    /// and the link register.
    pub cr: u32,
    /// The size of the frame, in bytes.
    pub frame_size: u32,
    pub codes: Vec<Arm64UnwindCode>,
}

#[record]
impl Arm64PackedUnwind {
    /// `packed`.
    #[record(getter)]
    pub fn form(&self) -> &'static str {
        "packed"
    }
}

/// An ARM64 `.xdata` unwind record.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct Arm64XdataUnwind {
    pub version: u32,
    /// The `X` bit: exception data (a handler) follows.
    pub exception_data: bool,
    /// The `E` bit: the header describes a single epilog.
    pub epilog_in_header: bool,
    pub epilog_count: u32,
    /// The number of 32-bit words of unwind codes.
    pub code_words: u32,
    pub epilog_scopes: Vec<Arm64EpilogScope>,
    /// The size of the record in bytes, including the RVA of the handler.
    pub size: usize,
    pub codes: Vec<Arm64UnwindCode>,
    pub handler: Option<UnwindHandler>,
}

#[record]
impl Arm64XdataUnwind {
    /// `xdata`.
    #[record(getter)]
    pub fn form(&self) -> &'static str {
        "xdata"
    }
}

/// One ARM64 epilog scope.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arm64EpilogScope {
    /// The start of the epilog, in bytes from the start of the function.
    #[record(hex)]
    pub start_offset: u32,
    /// The index of the first unwind code of the epilog.
    pub first_code: u32,
}

/// One ARM64 unwind code.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arm64UnwindCode {
    /// The index of its first byte in the code bytes.
    pub index: usize,
    pub bytes: Vec<u8>,
    /// Its name and the prolog instruction that it represents.
    pub description: String,
}

pub fn describe_arm64_unwind(
    image: &impl UnwindBytes,
    unwind_data: u32,
    base: u64,
    symbol: impl Fn(u64) -> String,
) -> Option<Unwind> {
    Some(match read_program(image, unwind_data)? {
        Program::Packed(unwind_data) => {
            let packed = Packed::new(unwind_data);
            let codes = packed
                .codes()
                .map_or_else(Vec::new, |(prolog, _)| describe_arm64_codes(&prolog, 0));
            Unwind::Packed(Arm64PackedUnwind {
                flag: packed.flag,
                reg_f: packed.reg_f,
                reg_i: packed.reg_i,
                homes_arguments: packed.homes_arguments,
                cr: packed.cr,
                frame_size: packed.frame_size * 16,
                codes,
            })
        }
        Program::Full(xdata) => {
            let exception_data = xdata.header & (1 << 20) != 0;
            let handler = if exception_data {
                let rva = get_u32(&image.read(xdata.end, 4)?, 0)?;
                Some(UnwindHandler::new(
                    base,
                    rva,
                    u32::try_from(xdata.end + 4).ok()?,
                    symbol,
                ))
            } else {
                None
            };
            let size = xdata.end - unwind_data as usize + if exception_data { 4 } else { 0 };
            // The last code sequence starts at the prolog's or an epilog's
            // first code; the bytes after its `end` pad the last word.
            let last_sequence = if xdata.epilog_in_header {
                xdata.epilog_count as usize
            } else {
                xdata
                    .scopes
                    .iter()
                    .map(|scope| (scope >> 22) as usize)
                    .max()
                    .unwrap_or(0)
            };
            Unwind::Xdata(Arm64XdataUnwind {
                version: (xdata.header >> 18) & 3,
                exception_data,
                epilog_in_header: xdata.epilog_in_header,
                epilog_count: xdata.epilog_count,
                code_words: (xdata.codes.len() / 4) as u32,
                epilog_scopes: xdata
                    .scopes
                    .iter()
                    .map(|scope| Arm64EpilogScope {
                        start_offset: (scope & 0x3ffff) * 4,
                        first_code: scope >> 22,
                    })
                    .collect(),
                codes: describe_arm64_codes(&xdata.codes, last_sequence),
                handler,
                size,
            })
        }
    })
}

/// Each unwind code in `codes`, framed by its length, up to the `end` of
/// the sequence starting at or after `last_sequence`: what follows it pads
/// the code words.
fn describe_arm64_codes(codes: &[u8], last_sequence: usize) -> Vec<Arm64UnwindCode> {
    let mut described = Vec::new();
    let mut at = 0;
    while let Some(&op) = codes.get(at) {
        if at > last_sequence
            && described
                .last()
                .is_some_and(|code: &Arm64UnwindCode| matches!(code.bytes[0], 0xe4 | 0xe5))
        {
            break;
        }
        let len = code_len(op);
        let Some(bytes) = codes.get(at..at + len) else {
            described.push(Arm64UnwindCode {
                index: at,
                bytes: codes[at..].to_vec(),
                description: "(truncated)".into(),
            });
            break;
        };
        described.push(Arm64UnwindCode {
            index: at,
            bytes: bytes.to_vec(),
            description: describe_arm64_code(bytes),
        });
        at += len;
    }
    described
}

/// An unwind code's name and the prolog instruction it stands for, with
/// the operand fields the Windows ARM64 unwind format gives it.
fn describe_arm64_code(bytes: &[u8]) -> String {
    let op = bytes[0];
    let value = bytes.get(1).map_or(u32::from(op), |&second| {
        u32::from(op) << 8 | u32::from(second)
    });
    let small = value & 0x1f;
    let wide = value & 0x3f;
    let x = |shift: u32, mask: u32| (value >> shift) & mask;
    match op {
        0x00..=0x1f => format!("alloc_s: sub sp, sp, #{:#x}", 16 * small),
        0x20..=0x3f => format!("save_r19r20_x: stp x19, x20, [sp, #-{:#x}]!", 8 * small),
        0x40..=0x7f => format!("save_fplr: stp fp, lr, [sp, #{:#x}]", 8 * wide),
        0x80..=0xbf => format!("save_fplr_x: stp fp, lr, [sp, #-{:#x}]!", 8 * (wide + 1)),
        0xc0..=0xc7 => format!("alloc_m: sub sp, sp, #{:#x}", 16 * (value & 0x7ff)),
        0xc8..=0xcb => {
            let r = 19 + x(6, 0xf);
            format!("save_regp: stp x{r}, x{}, [sp, #{:#x}]", r + 1, 8 * wide)
        }
        0xcc..=0xcf => {
            let r = 19 + x(6, 0xf);
            format!(
                "save_regp_x: stp x{r}, x{}, [sp, #-{:#x}]!",
                r + 1,
                8 * (wide + 1)
            )
        }
        0xd0..=0xd3 => format!("save_reg: str x{}, [sp, #{:#x}]", 19 + x(6, 0xf), 8 * wide),
        0xd4..=0xd5 => format!(
            "save_reg_x: str x{}, [sp, #-{:#x}]!",
            19 + x(5, 0xf),
            8 * (small + 1)
        ),
        0xd6..=0xd7 => format!(
            "save_lrpair: stp x{}, lr, [sp, #{:#x}]",
            19 + 2 * x(6, 0x7),
            8 * wide
        ),
        0xd8..=0xd9 => {
            let d = 8 + x(6, 0x7);
            format!("save_fregp: stp d{d}, d{}, [sp, #{:#x}]", d + 1, 8 * wide)
        }
        0xda..=0xdb => {
            let d = 8 + x(6, 0x7);
            format!(
                "save_fregp_x: stp d{d}, d{}, [sp, #-{:#x}]!",
                d + 1,
                8 * (wide + 1)
            )
        }
        0xdc..=0xdd => format!("save_freg: str d{}, [sp, #{:#x}]", 8 + x(6, 0x7), 8 * wide),
        0xde => format!(
            "save_freg_x: str d{}, [sp, #-{:#x}]!",
            8 + x(5, 0x7),
            8 * (small + 1)
        ),
        0xe0 => {
            let size = bytes[1..]
                .iter()
                .fold(0u32, |size, &byte| size << 8 | u32::from(byte));
            format!("alloc_l: sub sp, sp, #{:#x}", 16 * size)
        }
        0xe1 => "set_fp: mov fp, sp".into(),
        0xe2 => format!("add_fp: add fp, sp, #{:#x}", 8 * (value & 0xff)),
        0xe3 => "nop".into(),
        0xe4 => "end".into(),
        0xe5 => "end_c".into(),
        0xe6 => "save_next".into(),
        0xe7 => "save_any_reg".into(),
        0xe8 => "MSFT_OP_TRAP_FRAME".into(),
        0xe9 => "MSFT_OP_MACHINE_FRAME".into(),
        0xea => "MSFT_OP_CONTEXT".into(),
        0xeb => "MSFT_OP_EC_CONTEXT".into(),
        0xec => "MSFT_OP_CLEAR_UNWOUND_TO_CALL".into(),
        0xfc => "pac_sign_lr".into(),
        _ => "reserved".into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::arch::Arch;

    const SP: u64 = 0x1000;

    struct Stack(HashMap<u64, u64>);

    impl FrameMemory for Stack {
        fn stack_u64(&self, address: u64) -> Option<u64> {
            self.0.get(&address).copied()
        }

        fn trap_frame(&self, _: u64) -> Option<FrameRegisters> {
            None
        }
    }

    fn stack(slots: &[(u64, u64)]) -> Stack {
        Stack(slots.iter().copied().collect())
    }

    fn frame(sp: u64, fp: u64, lr: u64) -> FrameRegisters {
        let mut context = FrameRegisters::new(Arch::Arm64, 0, sp);
        context.regs[FP] = Some(fp);
        context.regs[LR] = Some(lr);
        context
    }

    fn packed(length: u32, reg_i: u32, cr: u32, frame_size: u32) -> Program {
        Program::Packed(1 | (length << 2) | (reg_i << 16) | (cr << 21) | (frame_size << 23))
    }

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
        assert_eq!(context.sp, SP + 64);
        assert_eq!(context.regs[FP], Some(0xf00d));
        assert_eq!(context.regs[LR], Some(0xca11e4));
        assert_eq!(
            (context.regs[19], context.regs[20]),
            (Some(0x19), Some(0x20))
        );
    }

    /// A leaf with no saved registers and a 512-byte frame: one `sub sp`,
    /// which must decode as `alloc_m`, not as the `save_r19r20_x` opcode
    /// that `alloc_s` would overflow into.
    #[test]
    fn packed_data_unwinds_a_512_byte_local_frame() {
        let program = packed(4, 0, 0, 32);
        let mut context = frame(SP, 0xf00d, 0xca11e4);
        assert_eq!(
            program.unwind(2, &mut context, &stack(&[])),
            Some(Resume::Return)
        );
        assert_eq!(context.sp, SP + 512);
        assert_eq!((context.regs[19], context.regs[20]), (None, None));
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
        assert_eq!(context.sp, SP + 64);
        assert_eq!(context.regs[LR], Some(0xca11e4));
        assert_eq!(context.regs[FP], Some(0xf00d));
        assert_eq!(context.regs[19], Some(0x19));

        // At the first instruction nothing has been saved.
        let mut context = frame(SP + 64, 0xf00d, 0xca11e4);
        program.unwind(0, &mut context, &stack);
        assert_eq!(context.sp, SP + 64);
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
        assert_eq!(context.sp, SP + 64);
        assert_eq!(context.regs[19], Some(0x19));

        // At `ret` the frame is gone.
        let mut context = frame(SP + 64, 0xf00d, 0xca11e4);
        program.unwind(19, &mut context, &stack);
        assert_eq!(context.sp, SP + 64);
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
            header: 0,
            end: 0,
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
        assert_eq!(context.sp, SP + 64 + 48);
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
        assert_eq!(context.sp, SP + 64 + 48);
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
        assert_eq!(context.sp, SP + 64 + 48);
        assert_eq!(context.regs[21], Some(0x21));

        // One instruction before the epilog is still the body.
        let mut context = frame(0x10, SP + 64 + 32, 0xdead);
        program.unwind(0x1a, &mut context, &stack);
        assert_eq!(context.regs[LR], Some(0xca11e4));
    }

    #[test]
    fn a_machine_frame_resumes_at_the_interrupted_pc_and_stack() {
        let program = Program::Full(Xdata {
            header: 0,
            end: 0,
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
        assert_eq!((context.pc, context.sp), (0xfffff803_12345678, 0x8000));
    }

    #[test]
    fn the_frame_pointer_at_a_body_undoes_allocations_made_after_it_was_set() {
        // `stp x29, lr, [sp, #0x50]; add x29, sp, #0x50` ends the prolog.
        let program = Program::Full(Xdata {
            header: 0,
            end: 0,
            length: 0x10,
            epilog_in_header: true,
            epilog_count: 0,
            scopes: Vec::new(),
            codes: vec![0xe2, 0x0a, 0x4a, 0xe4],
        });
        assert_eq!(program.frame_pointer_at_body(SP), Some(SP + 0x50));

        // `mov x29, sp; sub sp, sp, #0x20`: the body's sp is 0x20 below x29.
        let program = Program::Full(Xdata {
            header: 0,
            end: 0,
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

    /// Operands come from each code's fields as the format lays them out:
    /// offsets in 8- or 16-byte units, registers from x19 or d8, and the
    /// pre-indexed forms one unit further.
    #[test]
    fn arm64_codes_describe_their_instructions() {
        let codes = [
            0x02, // alloc_s 2
            0x87, // save_fplr_x 7
            0xc8, 0x42, // save_regp x20, 2
            0xd4, 0x21, // save_reg_x x20, 1
            0xc1, 0x00, // alloc_m 0x100
            0xe2, 0x04, // add_fp 4
            0xe0, 0x00, 0x01, 0x00, // alloc_l 0x100
            0xe4, // end
        ];
        let described: Vec<(usize, String)> = describe_arm64_codes(&codes, 0)
            .into_iter()
            .map(|code| (code.index, code.description))
            .collect();
        let expected = [
            (0, "alloc_s: sub sp, sp, #0x20"),
            (1, "save_fplr_x: stp fp, lr, [sp, #-0x40]!"),
            (2, "save_regp: stp x20, x21, [sp, #0x10]"),
            (4, "save_reg_x: str x20, [sp, #-0x10]!"),
            (6, "alloc_m: sub sp, sp, #0x1000"),
            (8, "add_fp: add fp, sp, #0x20"),
            (10, "alloc_l: sub sp, sp, #0x1000"),
            (14, "end"),
        ];
        assert_eq!(
            described,
            expected.map(|(index, text)| (index, text.to_string()))
        );
    }
}
