//! The x64 exception-handling data's unwind format: `UNWIND_INFO` and its
//! unwind codes, which step a frame to its caller by undoing the function's
//! prolog, and the epilogs the codes leave to be recognized by their
//! instructions.

use std::ops::Range;

use pelite::pe64::image::{
    RUNTIME_FUNCTION, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL, UWOP_PUSH_MACHFRAME, UWOP_PUSH_NONVOL, UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR, UWOP_SET_FPREG,
};

use super::ENCODED_REGISTERS;
use crate::arch::unwind::{FrameMemory, FrameRegisters, UnwindBytes, UnwindHandler, Unwound};
use crate::base::bytes::get_u32;
use ntoseye_macros::record;

// cap on chained unwind entries followed per frame, guarding against cyclic or
// corrupt unwind data
pub const MAX_CHAIN_DEPTH: usize = 32;

// version-2 unwind opcodes that pelite 0.10 doesn't define. They describe epilog
// locations and don't affect prolog-based unwinding, but must be counted so the
// code iterator stays aligned with the slot stream
const UWOP_EPILOG: u8 = 6;

const UWOP_SPARE_CODE: u8 = 7;

pub const RUNTIME_FUNCTION_SIZE: usize = 12;

/// Entry `index` of the AMD64 exception directory at `pdata`, `None` when it
/// is paged out.
pub fn runtime_function_at(
    image: &impl UnwindBytes,
    pdata: usize,
    index: usize,
) -> Option<RUNTIME_FUNCTION> {
    let bytes = image.read(pdata + index * RUNTIME_FUNCTION_SIZE, RUNTIME_FUNCTION_SIZE)?;
    Some(RUNTIME_FUNCTION {
        BeginAddress: get_u32(&bytes, 0)?,
        EndAddress: get_u32(&bytes, 4)?,
        UnwindData: get_u32(&bytes, 8)?,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct UnwindCodeSlot {
    code_offset: u8,
    unwind_op: u8,
    op_info: u8,
    raw_op_info: u8,
}

#[derive(Debug, Clone)]
pub struct ParsedUnwindInfo {
    pub version_flags: u8,
    pub size_of_prolog: u8,
    pub frame_register: u8,
    pub frame_offset: u8,
    pub codes: Vec<UnwindCodeSlot>,
    /// Image offset past the code array, where a handler or parent entry is
    pub tail_offset: usize,
    /// Present when this is a chained entry (`UNW_FLAG_CHAININFO`): the parent
    /// RUNTIME_FUNCTION, whose unwind data the walk follows
    pub parent: Option<RUNTIME_FUNCTION>,
}

/// Outcome of applying one frame's unwind codes
enum UnwindStep {
    /// Codes applied; keep going (pop the return address or follow a chain)
    Continue,
    /// A hardware trap/interrupt frame set rip+rsp directly; the frame is complete
    MachineFrame,
}

pub fn parse_unwind_info(image: &impl UnwindBytes, unwind_rva: u32) -> Option<ParsedUnwindInfo> {
    // every read goes through `UnwindBytes::read`, so unwind data that lands in a
    // paged-out hole returns None (fall back to scan) rather than being parsed as
    // zeros and fabricating a frame
    let offset = unwind_rva as usize;
    let header = image.read(offset, 4)?;
    let version_flags = header[0];
    let count_of_codes = header[2] as usize;
    let frame_register_offset = header[3];

    let codes_offset = offset + 4;
    let codes_bytes = image.read(codes_offset, count_of_codes.checked_mul(2)?)?;

    let aligned_code_count = (count_of_codes + 1) & !1;
    let tail_offset = offset + 4 + aligned_code_count * 2;
    let parent = if (version_flags >> 3) & UNW_FLAG_CHAININFO != 0 {
        // a chained entry is followed by the parent RUNTIME_FUNCTION
        Some(runtime_function_at(image, tail_offset, 0)?)
    } else {
        None
    };

    let mut codes = Vec::with_capacity(count_of_codes);
    for raw in codes_bytes.as_chunks::<2>().0 {
        codes.push(UnwindCodeSlot {
            code_offset: raw[0],
            unwind_op: raw[1] & 0x0f,
            op_info: raw[1] >> 4,
            raw_op_info: raw[1],
        });
    }

    Some(ParsedUnwindInfo {
        version_flags,
        size_of_prolog: header[1],
        frame_register: frame_register_offset & 0x0f,
        frame_offset: frame_register_offset >> 4,
        codes,
        tail_offset,
        parent,
    })
}

fn unwind_slot_count(unwind_op: u8, op_info: u8) -> usize {
    match unwind_op {
        UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL | UWOP_SET_FPREG | UWOP_PUSH_MACHFRAME
        | UWOP_EPILOG => 1,
        UWOP_ALLOC_LARGE => {
            if op_info == 0 {
                2
            } else {
                3
            }
        }
        UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => 2,
        UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR | UWOP_SPARE_CODE => 3,
        _ => 0,
    }
}

fn slot_u16(codes: &[UnwindCodeSlot], index: usize) -> Option<u16> {
    let slot = codes.get(index)?;
    Some(u16::from_le_bytes([slot.code_offset, slot.raw_op_info]))
}

/// Step `context` to its caller by the unwind data of its function
/// (`begin..end`, whose `UNWIND_INFO` is at `unwind_data`), its chained
/// parents' included.
pub fn unwind_by_codes(
    memory: &impl FrameMemory,
    context: &mut FrameRegisters,
    image: &impl UnwindBytes,
    base_address: u64,
    mut unwind_data: u32,
    begin: u32,
    end: u32,
) -> Unwound {
    // Walk the function and any chained parents. Only the primary function's
    // codes are gated on the prolog progress at `rip`; chained parents already
    // ran their prologs in full, so all of their codes apply.
    let rva = (context.pc - base_address) as u32;
    let rip_offset = rva.saturating_sub(begin);
    let mut primary = true;

    for _ in 0..MAX_CHAIN_DEPTH {
        let Some(unwind_info) = parse_unwind_info(image, unwind_data) else {
            unwind_trace!(
                "unwind: parse_unwind_info failed/holed at unwind_data={unwind_data:#x} -> stop"
            );
            return Unwound::Stop;
        };

        unwind_trace!(
            "unwind: rva={:#x} begin={:#x} prolog={:#x} codes={} chained={} in_prolog={}",
            rva,
            begin,
            unwind_info.size_of_prolog,
            unwind_info.codes.len(),
            unwind_info.parent.is_some(),
            primary && rip_offset < unwind_info.size_of_prolog as u32,
        );

        let in_prolog = primary && rip_offset < unwind_info.size_of_prolog as u32;
        if primary
            && !in_prolog
            && let Some(epilog) = image
                .read(rva as usize, 32)
                .or_else(|| image.read(rva as usize, 16))
                .and_then(|code| decode_epilog(&code, rva, begin..end))
        {
            return unwind_epilog(memory, context, &epilog);
        }
        match apply_unwind_codes(memory, context, &unwind_info, in_prolog, rip_offset) {
            Some(UnwindStep::Continue) => {}
            Some(UnwindStep::MachineFrame) => {
                unwind_trace!(
                    "unwind: machine frame -> rip={:#x} rsp={:#x}",
                    context.pc,
                    context.sp
                );
                return Unwound::Frame { stack_switch: true };
            }
            None => {
                unwind_trace!("unwind: malformed unwind codes -> stop");
                return Unwound::Stop;
            }
        }

        match unwind_info.parent.map(|parent| parent.UnwindData) {
            Some(next) => {
                unwind_data = next;
                primary = false;
            }
            None => {
                let Some(return_address) = memory.stack_u64(context.sp) else {
                    unwind_trace!(
                        "unwind: return-address read failed at rsp={:#x} -> stop",
                        context.sp
                    );
                    return Unwound::Stop;
                };
                unwind_trace!(
                    "unwind: pop return -> rip={return_address:#x} rsp={:#x}",
                    context.sp.saturating_add(8)
                );
                context.pc = return_address;
                context.sp = context.sp.saturating_add(8);
                return Unwound::Frame {
                    stack_switch: false,
                };
            }
        }
    }

    // chain too deep or cyclic (corrupt unwind data); let the scan take over
    Unwound::Stop
}

/// Apply one frame's unwind codes to `context`, undoing the prolog. Returns
/// `MachineFrame` if a trap/interrupt frame redirected rip+rsp (frame done),
/// `Continue` otherwise, or `None` on malformed codes.
fn apply_unwind_codes(
    memory: &impl FrameMemory,
    context: &mut FrameRegisters,
    unwind_info: &ParsedUnwindInfo,
    in_prolog: bool,
    rip_offset: u32,
) -> Option<UnwindStep> {
    let original_context = context.clone();
    let mut index = 0usize;

    while index < unwind_info.codes.len() {
        let slot = unwind_info.codes[index];
        let slots_used = unwind_slot_count(slot.unwind_op, slot.op_info);
        if slots_used == 0 || index + slots_used > unwind_info.codes.len() {
            return None;
        }

        let executed = !in_prolog || u32::from(slot.code_offset) <= rip_offset;
        if executed
            && let UnwindStep::MachineFrame =
                apply_unwind_code(memory, context, &original_context, unwind_info, index)?
        {
            return Some(UnwindStep::MachineFrame);
        }

        index += slots_used;
    }

    Some(UnwindStep::Continue)
}

fn apply_unwind_code(
    memory: &impl FrameMemory,
    context: &mut FrameRegisters,
    original_context: &FrameRegisters,
    unwind_info: &ParsedUnwindInfo,
    index: usize,
) -> Option<UnwindStep> {
    let slot = unwind_info.codes[index];
    match slot.unwind_op {
        UWOP_PUSH_NONVOL => {
            let saved = memory.stack_u64(context.sp)?;
            context.set(slot.op_info, saved);
            context.sp = context.sp.saturating_add(8);
        }
        UWOP_ALLOC_SMALL => {
            context.sp = context
                .sp
                .saturating_add(((u64::from(slot.op_info) + 1) * 8).max(8));
        }
        UWOP_ALLOC_LARGE => {
            let allocation = if slot.op_info == 0 {
                u64::from(slot_u16(&unwind_info.codes, index + 1)?) * 8
            } else if slot.op_info == 1 {
                u64::from(slot_u16(&unwind_info.codes, index + 1)?)
                    | (u64::from(slot_u16(&unwind_info.codes, index + 2)?) << 16)
            } else {
                return None;
            };
            context.sp = context.sp.saturating_add(allocation);
        }
        UWOP_SET_FPREG => {
            // re-derive RSP from the established frame pointer: the prolog
            // set `fpreg = rsp + frame_offset*16`, so unwinding restores
            // RSP = fpreg - frame_offset*16. This supersedes any earlier
            // ALLOC adjustment, which is the whole point of a frame pointer
            // (the fixed allocation size need not be known to unwind)
            context.sp = frame_base(context, unwind_info)?;
        }
        UWOP_EPILOG | UWOP_SPARE_CODE => {
            // version-2 epilog descriptors: they locate epilogs for the case
            // where the PC is mid-epilog. We unwind from the prolog/body, so
            // there's nothing to apply (their slots are skipped by the caller)
        }
        UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => {
            let offset = if slot.unwind_op == UWOP_SAVE_NONVOL {
                u64::from(slot_u16(&unwind_info.codes, index + 1)?) * 8
            } else {
                u64::from(slot_u16(&unwind_info.codes, index + 1)?) * 16
            };
            if slot.unwind_op == UWOP_SAVE_NONVOL {
                let base = frame_base(original_context, unwind_info)?;
                let saved = memory.stack_u64(base + offset)?;
                context.set(slot.op_info, saved);
            }
        }
        UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR => {
            let offset = u64::from(slot_u16(&unwind_info.codes, index + 1)?)
                | (u64::from(slot_u16(&unwind_info.codes, index + 2)?) << 16);
            let scaled = if slot.unwind_op == UWOP_SAVE_NONVOL_FAR {
                offset
            } else {
                offset * 16
            };
            if slot.unwind_op == UWOP_SAVE_NONVOL_FAR {
                let base = frame_base(original_context, unwind_info)?;
                let saved = memory.stack_u64(base + scaled)?;
                context.set(slot.op_info, saved);
            }
        }
        UWOP_PUSH_MACHFRAME => {
            // a hardware-pushed trap/interrupt frame in iretq layout. op_info
            // == 1 means a CPU error code sits below it, so step over that to
            // reach the record: [+0]=rip [+8]=cs [+16]=eflags [+24]=rsp [+32]=ss
            let base = if slot.op_info == 1 {
                context.sp.saturating_add(8)
            } else {
                context.sp
            };
            let return_rip = memory.stack_u64(base)?;
            let return_rsp = memory.stack_u64(base.saturating_add(24))?;
            context.pc = return_rip;
            context.sp = return_rsp;
            context.machine_frame = Some(base);
            return Some(UnwindStep::MachineFrame);
        }
        _ => return None,
    }

    Some(UnwindStep::Continue)
}

fn frame_base(context: &FrameRegisters, unwind_info: &ParsedUnwindInfo) -> Option<u64> {
    if unwind_info.frame_register == 0 {
        return Some(context.sp);
    }

    let frame_register = context.get(unwind_info.frame_register)?;
    frame_register.checked_sub(u64::from(unwind_info.frame_offset) * 16)
}

/// The value of the register a function's frame is addressed by: its frame
/// register, or RSP when it has none.
pub fn frame_register_value(context: &FrameRegisters, info: &ParsedUnwindInfo) -> Option<u64> {
    if info.frame_register == 0 {
        Some(context.sp)
    } else {
        context.get(info.frame_register)
    }
}

/// How an epilog starts to release the frame before its pops.
#[derive(Debug, PartialEq, Eq)]
pub enum EpilogRelease {
    /// Already at the pops (or the return).
    None,
    /// `add rsp, imm`.
    AddRsp(u32),
    /// `lea rsp, [base + disp]`, restoring a frame-pointer frame.
    LeaRsp { base: usize, disp: i32 },
}

/// The rest of an x64 epilog starting at the current instruction, in the
/// only shape the Windows ABI allows: an optional `add rsp` / `lea rsp`,
/// 8-byte register pops, then a return or a tail-call jump. Unwind codes
/// describe the prolog, so a pc inside an epilog has already undone part of
/// what they would undo again; the unwinder runs the remaining epilog
/// instead, as `RtlVirtualUnwind` does.
#[derive(Debug, PartialEq, Eq)]
pub struct Epilog {
    release: EpilogRelease,
    /// Registers popped, in order, by unwind register number.
    pops: Vec<usize>,
}

pub fn decode_epilog(code: &[u8], code_rva: u32, function: Range<u32>) -> Option<Epilog> {
    let mut at = 0usize;
    let release = match code {
        [0x48, 0x83, 0xc4, imm, ..] => {
            at = 4;
            EpilogRelease::AddRsp(u32::from(*imm))
        }
        [0x48, 0x81, 0xc4, a, b, c, d, ..] => {
            at = 7;
            EpilogRelease::AddRsp(u32::from_le_bytes([*a, *b, *c, *d]))
        }
        [rex @ (0x48 | 0x49), 0x8d, modrm, rest @ ..] if modrm & 0x38 == 0x20 => {
            let base = usize::from(modrm & 7) + if *rex == 0x49 { 8 } else { 0 };
            // rsp/r12 bases need a SIB byte, which an epilog never uses.
            if modrm & 7 == 4 {
                return None;
            }
            match (modrm >> 6, rest) {
                (1, [disp, ..]) => {
                    at = 4;
                    EpilogRelease::LeaRsp {
                        base,
                        disp: i32::from(*disp as i8),
                    }
                }
                (2, [a, b, c, d, ..]) => {
                    at = 7;
                    EpilogRelease::LeaRsp {
                        base,
                        disp: i32::from_le_bytes([*a, *b, *c, *d]),
                    }
                }
                _ => return None,
            }
        }
        _ => EpilogRelease::None,
    };
    let mut pops = Vec::new();
    loop {
        // A jump ends an epilog only as a tail call: after the frame is
        // released, and (when direct) to somewhere outside this function. A
        // bare jump at the pc is ordinary control flow.
        let tail_call = release != EpilogRelease::None || !pops.is_empty();
        match code.get(at..)? {
            [op @ 0x58..=0x5f, ..] => {
                pops.push(usize::from(op - 0x58));
                at += 1;
            }
            [0x41, op @ 0x58..=0x5f, ..] => {
                pops.push(usize::from(op - 0x58) + 8);
                at += 2;
            }
            [0xc3, ..] | [0xc2, _, _, ..] | [0xf3, 0xc3, ..] => {
                return Some(Epilog { release, pops });
            }
            [0xe9, a, b, c, d, ..] if tail_call => {
                let next = code_rva.checked_add(u32::try_from(at).ok()? + 5)?;
                let target = next.wrapping_add_signed(i32::from_le_bytes([*a, *b, *c, *d]));
                return (!function.contains(&target)).then_some(Epilog { release, pops });
            }
            [0x48, 0xff, 0x25, ..] | [0xff, 0x25, ..] if tail_call => {
                return Some(Epilog { release, pops });
            }
            _ => return None,
        }
    }
}

/// Run the remainder of `epilog` against `context`: release the frame,
/// restore the popped registers, and return to the caller.
pub fn unwind_epilog(
    memory: &impl FrameMemory,
    context: &mut FrameRegisters,
    epilog: &Epilog,
) -> Unwound {
    let mut rsp = match epilog.release {
        EpilogRelease::None => context.sp,
        EpilogRelease::AddRsp(imm) => context.sp.wrapping_add(u64::from(imm)),
        EpilogRelease::LeaRsp { base, disp } => match context.regs[base] {
            Some(base) => base.wrapping_add_signed(i64::from(disp)),
            None => return Unwound::Stop,
        },
    };
    for &register in &epilog.pops {
        let Some(value) = memory.stack_u64(rsp) else {
            return Unwound::Stop;
        };
        context.regs[register] = Some(value);
        rsp = rsp.wrapping_add(8);
    }
    let Some(return_address) = memory.stack_u64(rsp) else {
        return Unwound::Stop;
    };
    unwind_trace!(
        "unwind: epilog -> rip={return_address:#x} rsp={:#x}",
        rsp + 8
    );
    context.pc = return_address;
    context.sp = rsp.wrapping_add(8);
    Unwound::Frame {
        stack_switch: false,
    }
}

/// AMD64 `UNWIND_INFO`.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct Amd64UnwindInfo {
    pub version: u8,
    /// `UNW_FLAG_*` bits.
    pub flags: u8,
    /// The size of the prolog, in bytes.
    pub prolog_size: u8,
    /// The number of unwind-code slots.
    pub code_count: u8,
    /// The frame pointer register, if the function sets one up.
    pub frame_register: Option<&'static str>,
    /// The frame pointer's offset from the stack pointer, in bytes.
    pub frame_offset: u32,
    /// The size of the structure in bytes, covering the header, the codes,
    /// and the handler RVA or the chained entry, but not the handler's
    /// data.
    pub size: usize,
    pub codes: Vec<Amd64UnwindCode>,
    /// The exception or termination handler, for `UNW_FLAG_EHANDLER` or
    /// `UNW_FLAG_UHANDLER`.
    pub handler: Option<UnwindHandler>,
}

#[record]
impl Amd64UnwindInfo {
    /// `amd64`.
    #[record(getter)]
    pub fn form(&self) -> &'static str {
        "amd64"
    }
}

/// One AMD64 unwind code.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amd64UnwindCode {
    /// The index of the first slot of the code.
    pub slot: usize,
    /// The prolog offset of the end of the instruction that the code
    /// undoes.
    pub code_offset: u8,
    /// The `UWOP_*` operation.
    pub op: u8,
    /// The info nibble of the operation.
    pub op_info: u8,
    /// The operation and its operands, for example
    /// `UWOP_SAVE_NONVOL rbx at +0x30`.
    pub description: String,
}

/// The `UNWIND_INFO` at `rva`, and the parent entry it chains to; `None`
/// when any of it is unreadable.
pub fn describe_unwind_info(
    image: &impl UnwindBytes,
    rva: u32,
    base: u64,
    symbol: impl Fn(u64) -> String,
) -> Option<(Amd64UnwindInfo, Option<RUNTIME_FUNCTION>)> {
    let parsed = parse_unwind_info(image, rva)?;
    let flags = parsed.version_flags >> 3;
    let tail_offset = parsed.tail_offset;
    let mut size = tail_offset - rva as usize;
    let mut handler = None;
    if parsed.parent.is_some() {
        size += RUNTIME_FUNCTION_SIZE;
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        let handler_rva = get_u32(&image.read(tail_offset, 4)?, 0)?;
        handler = Some(UnwindHandler::new(
            base,
            handler_rva,
            u32::try_from(tail_offset + 4).ok()?,
            symbol,
        ));
        size += 4;
    }
    let info = Amd64UnwindInfo {
        version: parsed.version_flags & 0x7,
        flags,
        prolog_size: parsed.size_of_prolog,
        code_count: u8::try_from(parsed.codes.len()).ok()?,
        frame_register: (parsed.frame_register != 0)
            .then(|| ENCODED_REGISTERS[usize::from(parsed.frame_register)]),
        frame_offset: u32::from(parsed.frame_offset) * 16,
        codes: describe_unwind_codes(&parsed.codes),
        handler,
        size,
    };
    Some((info, parsed.parent))
}

/// Each unwind code with its operands, as the unwinder reads them. A code
/// whose operation is unknown or whose operand slots run past the array
/// ends the list with a note, since the slots after it cannot be framed.
fn describe_unwind_codes(codes: &[UnwindCodeSlot]) -> Vec<Amd64UnwindCode> {
    let register = |number: u8| ENCODED_REGISTERS[usize::from(number & 0xf)];
    let u32_at = |index: usize| {
        Some(u32::from(slot_u16(codes, index)?) | u32::from(slot_u16(codes, index + 1)?) << 16)
    };
    let mut described = Vec::new();
    let mut first_epilog = true;
    let mut index = 0;
    while let Some(code) = codes.get(index) {
        let slots = unwind_slot_count(code.unwind_op, code.op_info);
        let info = code.op_info;
        let description = match code.unwind_op {
            _ if slots == 0 => None,
            UWOP_PUSH_NONVOL => Some(format!("UWOP_PUSH_NONVOL {}", register(info))),
            UWOP_ALLOC_LARGE if info == 0 => slot_u16(codes, index + 1)
                .map(|size| format!("UWOP_ALLOC_LARGE {:#x}", u32::from(size) * 8)),
            UWOP_ALLOC_LARGE => u32_at(index + 1).map(|size| format!("UWOP_ALLOC_LARGE {size:#x}")),
            UWOP_ALLOC_SMALL => Some(format!("UWOP_ALLOC_SMALL {:#x}", u32::from(info) * 8 + 8)),
            UWOP_SET_FPREG => Some("UWOP_SET_FPREG".to_string()),
            UWOP_SAVE_NONVOL => slot_u16(codes, index + 1).map(|offset| {
                format!(
                    "UWOP_SAVE_NONVOL {} at +{:#x}",
                    register(info),
                    u32::from(offset) * 8
                )
            }),
            UWOP_SAVE_NONVOL_FAR => u32_at(index + 1)
                .map(|offset| format!("UWOP_SAVE_NONVOL_FAR {} at +{offset:#x}", register(info))),
            // The first epilog code gives the epilog size, and whether one
            // ends the function; each later one an epilog's distance from the
            // function's end (zero is padding).
            UWOP_EPILOG if std::mem::take(&mut first_epilog) => Some(format!(
                "UWOP_EPILOG size {:#x}{}",
                code.code_offset,
                if info & 1 != 0 {
                    ", one at the end"
                } else {
                    ""
                }
            )),
            UWOP_EPILOG => Some(format!(
                "UWOP_EPILOG at end-{:#x}",
                u16::from(code.code_offset) | u16::from(info) << 8
            )),
            UWOP_SPARE_CODE => Some("UWOP_SPARE_CODE".to_string()),
            UWOP_SAVE_XMM128 => slot_u16(codes, index + 1).map(|offset| {
                format!(
                    "UWOP_SAVE_XMM128 xmm{info} at +{:#x}",
                    u32::from(offset) * 16
                )
            }),
            UWOP_SAVE_XMM128_FAR => u32_at(index + 1)
                .map(|offset| format!("UWOP_SAVE_XMM128_FAR xmm{info} at +{offset:#x}")),
            UWOP_PUSH_MACHFRAME if info == 1 => {
                Some("UWOP_PUSH_MACHFRAME with error code".to_string())
            }
            UWOP_PUSH_MACHFRAME => Some("UWOP_PUSH_MACHFRAME".to_string()),
            _ => None,
        };
        let complete = description.is_some();
        described.push(Amd64UnwindCode {
            slot: index,
            code_offset: code.code_offset,
            op: code.unwind_op,
            op_info: info,
            description: description.unwrap_or_else(|| {
                format!(
                    "unknown or truncated code (op {}); later codes not decoded",
                    code.unwind_op
                )
            }),
        });
        if !complete {
            break;
        }
        index += slots;
    }
    described
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    use crate::arch::Arch;

    /// Unwind data at offset 0 of `self.0`.
    struct Bytes<'a>(&'a [u8]);

    impl UnwindBytes for Bytes<'_> {
        fn read(&self, offset: usize, len: usize) -> Option<Cow<'_, [u8]>> {
            self.0
                .get(offset..offset.checked_add(len)?)
                .map(Cow::Borrowed)
        }
    }

    #[test]
    fn epilogs_decode_from_any_point_up_to_the_return() {
        let function = 0x1000..0x1100;
        // add rsp, 0x28; pop rbx; pop r12; ret
        let code = [0x48, 0x83, 0xc4, 0x28, 0x5b, 0x41, 0x5c, 0xc3];
        let decode = |at: usize| decode_epilog(&code[at..], 0x1080 + at as u32, function.clone());
        assert_eq!(
            decode(0),
            Some(Epilog {
                release: EpilogRelease::AddRsp(0x28),
                pops: vec![3, 12],
            })
        );
        assert_eq!(
            decode(5),
            Some(Epilog {
                release: EpilogRelease::None,
                pops: vec![12],
            })
        );
        assert_eq!(
            decode(7),
            Some(Epilog {
                release: EpilogRelease::None,
                pops: vec![],
            })
        );
    }

    #[test]
    fn a_jump_ends_an_epilog_only_as_a_tail_call_out_of_the_function() {
        let function = 0x1000..0x1100;
        // lea rsp, [rbp+0x10]; pop rbp; jmp +0x100 (past the function's end)
        let tail_call = [0x48, 0x8d, 0x65, 0x10, 0x5d, 0xe9, 0x00, 0x01, 0, 0];
        assert_eq!(
            decode_epilog(&tail_call, 0x1010, function.clone()),
            Some(Epilog {
                release: EpilogRelease::LeaRsp {
                    base: 5,
                    disp: 0x10
                },
                pops: vec![5],
            })
        );
        // The same pop then a jump back into the function is a loop.
        let back_edge = [0x5d, 0xe9, 0xf0, 0xff, 0xff, 0xff];
        assert_eq!(decode_epilog(&back_edge, 0x1010, function.clone()), None);
        // A jump at the pc with nothing released is not an epilog either.
        assert_eq!(
            decode_epilog(&[0xe9, 0x00, 0x10, 0, 0], 0x1010, function.clone()),
            None
        );
        // Body code: add rsp followed by a call, or a pop followed by a move.
        assert_eq!(
            decode_epilog(
                &[0x48, 0x83, 0xc4, 0x28, 0xe8, 0, 0, 0, 0],
                0x1010,
                function.clone()
            ),
            None
        );
        assert_eq!(
            decode_epilog(&[0x5b, 0x48, 0x89, 0xc8], 0x1010, function),
            None
        );
    }

    #[test]
    fn parse_unwind_info_reads_chained_parent() {
        // version 1 with UNW_FLAG_CHAININFO (0x4), no prolog, zero codes; the
        // parent RUNTIME_FUNCTION (begin, end, unwind-data) follows the header
        let blob = [
            0x21, 0x00, 0x00, 0x00, // ver/flags=chaininfo, prolog, count, frame
            0x00, 0x10, 0x00, 0x00, // BeginAddress = 0x1000
            0x00, 0x11, 0x00, 0x00, // EndAddress   = 0x1100
            0x00, 0x20, 0x00, 0x00, // UnwindData   = 0x2000
        ];
        let info = parse_unwind_info(&Bytes(&blob), 0).expect("unwind info parses");
        let parent = info.parent.expect("chained parent");
        assert_eq!(
            (parent.BeginAddress, parent.EndAddress, parent.UnwindData),
            (0x1000, 0x1100, 0x2000)
        );
    }

    #[test]
    fn parse_unwind_info_without_chain_flag_has_no_parent() {
        // version 1, no flags, no codes
        let blob = [0x01, 0x00, 0x00, 0x00];
        let info = parse_unwind_info(&Bytes(&blob), 0).expect("unwind info parses");
        assert!(info.parent.is_none());
    }

    #[test]
    fn slot_count_matches_opcode_encoding() {
        assert_eq!(unwind_slot_count(0, 0), 1);
        assert_eq!(unwind_slot_count(1, 0), 2);
        assert_eq!(unwind_slot_count(1, 1), 3);
        assert_eq!(unwind_slot_count(4, 0), 2);
        assert_eq!(unwind_slot_count(5, 0), 3);
        assert_eq!(unwind_slot_count(6, 0), 1); // UWOP_EPILOG
        assert_eq!(unwind_slot_count(7, 0), 3); // UWOP_SPARE_CODE
    }

    #[test]
    fn frame_base_uses_frame_register_when_present() {
        let mut context = FrameRegisters::new(Arch::Amd64, 0, 0x1800);
        context.regs[5] = Some(0x2000);
        let unwind = ParsedUnwindInfo {
            version_flags: 1,
            size_of_prolog: 0,
            frame_register: 5,
            frame_offset: 2,
            codes: Vec::new(),
            tail_offset: 4,
            parent: None,
        };

        assert_eq!(frame_base(&context, &unwind), Some(0x1fe0));
    }

    #[test]
    fn unwind_codes_frame_multi_slot_operands_and_stop_at_a_truncated_one() {
        let slot = |code_offset: u8, unwind_op: u8, op_info: u8| UnwindCodeSlot {
            code_offset,
            unwind_op,
            op_info,
            raw_op_info: op_info << 4 | unwind_op,
        };
        let operand = |value: u16| {
            let [low, high] = value.to_le_bytes();
            slot(low, high & 0xf, high >> 4)
        };
        let codes = [
            // The first epilog code is a size; later ones count back from the
            // function's end, with op_info as the high byte.
            slot(0x02, UWOP_EPILOG, 1),
            slot(0x10, UWOP_EPILOG, 1),
            // A 32-bit allocation in the next two slots, low half first.
            slot(0x08, UWOP_ALLOC_LARGE, 1),
            operand(0x0000),
            operand(0x0002),
            // Its operand slot is missing.
            slot(0x04, UWOP_SAVE_NONVOL, 3),
        ];
        let described = describe_unwind_codes(&codes);
        let slots: Vec<usize> = described.iter().map(|code| code.slot).collect();
        assert_eq!(slots, [0, 1, 2, 5]);
        assert!(described[0].description.contains("size 0x2"));
        assert!(described[1].description.contains("end-0x110"));
        assert!(described[2].description.contains("0x20000"));
        assert!(described[3].description.contains("truncated"));
    }
}
