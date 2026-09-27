//! AMD64 exception-directory unwinding: `.pdata` lookup, `UNWIND_INFO`
//! parsing, and applying unwind codes to step a frame to its caller.

use std::ops::Range;

use pelite::pe64::image::{
    RUNTIME_FUNCTION, UNW_FLAG_CHAININFO, UNW_FLAG_EHANDLER, UNW_FLAG_UHANDLER, UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL, UWOP_PUSH_MACHFRAME, UWOP_PUSH_NONVOL, UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR, UWOP_SET_FPREG,
};

use super::{
    AMD64_REGISTER_NAMES, RegisterContext, StackTracer, Unwound, image_u32, runtime_functions,
};
use crate::pe::{CodeLayout, PeImage};
use crate::types::CodeMachine;

// cap on chained unwind entries followed per frame, guarding against cyclic or
// corrupt unwind data
const MAX_CHAIN_DEPTH: usize = 32;

// version-2 unwind opcodes that pelite 0.10 doesn't define. They describe epilog
// locations and don't affect prolog-based unwinding, but must be counted so the
// code iterator stays aligned with the slot stream
const UWOP_EPILOG: u8 = 6;
const UWOP_SPARE_CODE: u8 = 7;

#[derive(Debug, Clone, Copy)]
struct UnwindCodeSlot {
    code_offset: u8,
    unwind_op: u8,
    op_info: u8,
    raw_op_info: u8,
}

#[derive(Debug, Clone)]
struct ParsedUnwindInfo {
    version_flags: u8,
    size_of_prolog: u8,
    frame_register: u8,
    frame_offset: u8,
    codes: Vec<UnwindCodeSlot>,
    /// Image offset past the code array, where a handler or parent entry is
    tail_offset: usize,
    /// Present when this is a chained entry (`UNW_FLAG_CHAININFO`): the parent
    /// RUNTIME_FUNCTION, whose unwind data the walk follows
    parent: Option<RUNTIME_FUNCTION>,
}

/// Outcome of applying one frame's unwind codes
enum UnwindStep {
    /// Codes applied; keep going (pop the return address or follow a chain)
    Continue,
    /// A hardware trap/interrupt frame set rip+rsp directly; the frame is complete
    MachineFrame,
}

/// How an epilog starts to release the frame before its pops.
#[derive(Debug, PartialEq, Eq)]
enum EpilogRelease {
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
struct Epilog {
    release: EpilogRelease,
    /// Registers popped, in order, by unwind register number.
    pops: Vec<usize>,
}

fn decode_epilog(code: &[u8], code_rva: u32, function: Range<u32>) -> Option<Epilog> {
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

impl StackTracer<'_> {
    /// The first instruction after the prolog of the function containing
    /// `address`.
    pub fn function_body_amd64(&mut self, address: u64) -> Option<u64> {
        let base = self.module_containing(address)?.info.base_address.0;
        let (mut image, mut layout) = self.module_code(address)?;
        let mut resolved = resolve_function(&image, layout.as_deref(), base, address);
        if matches!(resolved, Resolve::Holed)
            && !image.is_complete()
            && self.upgrade_module_image(address)
        {
            (image, layout) = self.module_code(address)?;
            resolved = resolve_function(&image, layout.as_deref(), base, address);
        }

        let Resolve::Function {
            unwind_data,
            begin,
            end,
        } = resolved
        else {
            return None;
        };
        let unwind = parse_unwind_info(&image, unwind_data)?;
        let body = u64::from(begin) + u64::from(unwind.size_of_prolog);
        (body < u64::from(end)).then_some(base + body)
    }
}

impl StackTracer<'_> {
    pub fn unwind_once_amd64(&mut self, context: &mut RegisterContext) -> Unwound {
        unwind_trace!("unwind: rip={:#x} rsp={:#x}", context.rip, context.rsp);
        let Some(base_address) = self
            .module_containing(context.rip)
            .map(|module| module.info.base_address.0)
        else {
            unwind_trace!("unwind: no module for rip -> leaf");
            return self.unwind_leaf(context);
        };
        let Some((mut image, mut layout)) = self.module_code(context.rip) else {
            return Unwound::Stop;
        };

        // Resolve the function entry. If the lookup or its unwind data lands in a
        // paged-out hole, upgrade to the complete on-disk image and re-resolve so
        // we can unwind through a module whose `.pdata`/`.xdata` isn't resident.
        let mut resolved = resolve_function(&image, layout.as_deref(), base_address, context.rip);
        if matches!(resolved, Resolve::Holed)
            && !image.is_complete()
            && self.upgrade_module_image(context.rip)
        {
            let Some(upgraded) = self.module_code(context.rip) else {
                return Unwound::Stop;
            };
            (image, layout) = upgraded;
            resolved = resolve_function(&image, layout.as_deref(), base_address, context.rip);
        }

        let (mut unwind_data, begin, end) = match resolved {
            Resolve::Function {
                unwind_data,
                begin,
                end,
            } => (unwind_data, begin, end),
            Resolve::Leaf => {
                unwind_trace!("unwind: no unwind info for rip -> leaf (true leaf)");
                return self.unwind_leaf(context);
            }
            Resolve::Holed => {
                unwind_trace!("unwind: unwind data paged out and unrecoverable -> stop");
                return Unwound::Stop;
            }
        };

        // Walk the function and any chained parents. Only the primary function's
        // codes are gated on the prolog progress at `rip`; chained parents already
        // ran their prologs in full, so all of their codes apply.
        let rva = (context.rip - base_address) as u32;
        let rip_offset = rva.saturating_sub(begin);
        let mut primary = true;

        for _ in 0..MAX_CHAIN_DEPTH {
            let Some(unwind_info) = parse_unwind_info(&image, unwind_data) else {
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
                return self.unwind_epilog(context, &epilog);
            }
            match self.apply_unwind_codes(context, &unwind_info, in_prolog, rip_offset) {
                Some(UnwindStep::Continue) => {}
                Some(UnwindStep::MachineFrame) => {
                    unwind_trace!(
                        "unwind: machine frame -> rip={:#x} rsp={:#x}",
                        context.rip,
                        context.rsp
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
                    let Ok(return_address) = self.stack_u64(context.rsp) else {
                        unwind_trace!(
                            "unwind: return-address read failed at rsp={:#x} -> stop",
                            context.rsp
                        );
                        return Unwound::Stop;
                    };
                    unwind_trace!(
                        "unwind: pop return -> rip={return_address:#x} rsp={:#x}",
                        context.rsp.saturating_add(8)
                    );
                    context.rip = return_address;
                    context.rsp = context.rsp.saturating_add(8);
                    return Unwound::Frame {
                        stack_switch: false,
                    };
                }
            }
        }

        // chain too deep or cyclic (corrupt unwind data); let the scan take over
        Unwound::Stop
    }

    /// Run the remainder of `epilog` against `context`: release the frame,
    /// restore the popped registers, and return to the caller.
    fn unwind_epilog(&self, context: &mut RegisterContext, epilog: &Epilog) -> Unwound {
        let mut rsp = match epilog.release {
            EpilogRelease::None => context.rsp,
            EpilogRelease::AddRsp(imm) => context.rsp.wrapping_add(u64::from(imm)),
            EpilogRelease::LeaRsp { base, disp } => match context.regs[base] {
                Some(base) => base.wrapping_add_signed(i64::from(disp)),
                None => return Unwound::Stop,
            },
        };
        for &register in &epilog.pops {
            let Ok(value) = self.stack_u64(rsp) else {
                return Unwound::Stop;
            };
            context.regs[register] = Some(value);
            rsp = rsp.wrapping_add(8);
        }
        let Ok(return_address) = self.stack_u64(rsp) else {
            return Unwound::Stop;
        };
        unwind_trace!(
            "unwind: epilog -> rip={return_address:#x} rsp={:#x}",
            rsp + 8
        );
        context.rip = return_address;
        context.rsp = rsp.wrapping_add(8);
        Unwound::Frame {
            stack_switch: false,
        }
    }

    /// Apply one frame's unwind codes to `context`, undoing the prolog. Returns
    /// `MachineFrame` if a trap/interrupt frame redirected rip+rsp (frame done),
    /// `Continue` otherwise, or `None` on malformed codes.
    fn apply_unwind_codes(
        &self,
        context: &mut RegisterContext,
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
                    self.apply_unwind_code(context, &original_context, unwind_info, index)?
            {
                return Some(UnwindStep::MachineFrame);
            }

            index += slots_used;
        }

        Some(UnwindStep::Continue)
    }

    fn unwind_leaf(&mut self, context: &mut RegisterContext) -> Unwound {
        let Ok(return_address) = self.stack_u64(context.rsp) else {
            return Unwound::Stop;
        };

        if !self.is_executable_address(return_address) {
            return Unwound::Stop;
        }

        context.rip = return_address;
        context.rsp = context.rsp.saturating_add(8);
        Unwound::Frame {
            stack_switch: false,
        }
    }

    fn apply_unwind_code(
        &self,
        context: &mut RegisterContext,
        original_context: &RegisterContext,
        unwind_info: &ParsedUnwindInfo,
        index: usize,
    ) -> Option<UnwindStep> {
        let slot = unwind_info.codes[index];
        match slot.unwind_op {
            UWOP_PUSH_NONVOL => {
                let saved = self.stack_u64(context.rsp).ok()?;
                context.set(slot.op_info, saved);
                context.rsp = context.rsp.saturating_add(8);
            }
            UWOP_ALLOC_SMALL => {
                context.rsp = context
                    .rsp
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
                context.rsp = context.rsp.saturating_add(allocation);
            }
            UWOP_SET_FPREG => {
                // re-derive RSP from the established frame pointer: the prolog
                // set `fpreg = rsp + frame_offset*16`, so unwinding restores
                // RSP = fpreg - frame_offset*16. This supersedes any earlier
                // ALLOC adjustment, which is the whole point of a frame pointer
                // (the fixed allocation size need not be known to unwind)
                context.rsp = frame_base(context, unwind_info)?;
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
                    let saved = self.stack_u64(base + offset).ok()?;
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
                    let saved = self.stack_u64(base + scaled).ok()?;
                    context.set(slot.op_info, saved);
                }
            }
            UWOP_PUSH_MACHFRAME => {
                // a hardware-pushed trap/interrupt frame in iretq layout. op_info
                // == 1 means a CPU error code sits below it, so step over that to
                // reach the record: [+0]=rip [+8]=cs [+16]=eflags [+24]=rsp [+32]=ss
                let base = if slot.op_info == 1 {
                    context.rsp.saturating_add(8)
                } else {
                    context.rsp
                };
                let return_rip = self.stack_u64(base).ok()?;
                let return_rsp = self.stack_u64(base.saturating_add(24)).ok()?;
                context.rip = return_rip;
                context.rsp = return_rsp;
                context.machine_frame = Some(base);
                return Some(UnwindStep::MachineFrame);
            }
            _ => return None,
        }

        Some(UnwindStep::Continue)
    }

    /// Resolve the stack base used by frame-pointer-relative PDB locations for
    /// the function containing `context.rip`. A missing or unreadable unwind
    /// record degrades to the recovered RSP rather than aborting the walk.
    pub fn frame_base_for_amd64(&mut self, context: &RegisterContext) -> Option<u64> {
        let fallback = (context.rsp != 0).then_some(context.rsp);
        let Some(base_address) = self
            .module_containing(context.rip)
            .map(|module| module.info.base_address.0)
        else {
            return fallback;
        };
        let Some((image, layout)) = self.module_code(context.rip) else {
            return fallback;
        };
        let Resolve::Function { unwind_data, .. } =
            resolve_function(&image, layout.as_deref(), base_address, context.rip)
        else {
            return fallback;
        };
        parse_unwind_info(&image, unwind_data)
            .and_then(|info| {
                if info.frame_register == 0 {
                    Some(context.rsp)
                } else {
                    context.get(info.frame_register)
                }
            })
            .or(fallback)
    }
}

/// Resolution of an rip against a module's unwind tables.
enum Resolve {
    /// A genuine leaf: the `.pdata` table is readable but has no entry covering
    /// the rip (a function with no prologue to undo).
    Leaf,
    /// An entry was found and its unwind data is resident.
    Function {
        unwind_data: u32,
        begin: u32,
        end: u32,
    },
    /// The lookup was blocked by a paged-out hole in `.pdata` or `.xdata`; an
    /// on-disk image could recover it.
    Holed,
}

/// Resolve `rip` against the image's unwind tables, distinguishing a true leaf
/// from a paged-out hole so the caller knows whether an on-disk image would help.
fn resolve_function(
    image: &PeImage,
    layout: Option<&CodeLayout>,
    base_address: u64,
    rip: u64,
) -> Resolve {
    let Some(pdata) = runtime_functions(image, layout, CodeMachine::Amd64) else {
        return Resolve::Leaf;
    };

    let rva = (rip - base_address) as u32;
    match lookup_runtime_function(
        pdata.len() / RUNTIME_FUNCTION_SIZE,
        |index| runtime_function_at(image, pdata.start, index),
        rva,
    ) {
        // an entry is only usable if its unwind info (`.xdata`) is resident too
        Lookup::Found(function) if image.is_present(function.UnwindData as usize, 4) => {
            Resolve::Function {
                unwind_data: function.UnwindData,
                begin: function.BeginAddress,
                end: function.EndAddress,
            }
        }
        // the entry exists but its unwind info is paged out, or the table
        // itself is: an on-disk image would answer
        Lookup::Found(_) | Lookup::Unreadable => Resolve::Holed,
        Lookup::Missing => Resolve::Leaf,
    }
}

pub(super) const RUNTIME_FUNCTION_SIZE: usize = 12;

/// Entry `index` of the AMD64 exception directory at `pdata`, `None` when it
/// is paged out.
pub(super) fn runtime_function_at(
    image: &PeImage,
    pdata: usize,
    index: usize,
) -> Option<RUNTIME_FUNCTION> {
    let bytes = image.read(pdata + index * RUNTIME_FUNCTION_SIZE, RUNTIME_FUNCTION_SIZE)?;
    Some(RUNTIME_FUNCTION {
        BeginAddress: image_u32(&bytes, 0)?,
        EndAddress: image_u32(&bytes, 4)?,
        UnwindData: image_u32(&bytes, 8)?,
    })
}

pub(super) enum Lookup {
    Found(RUNTIME_FUNCTION),
    /// No entry covers the address: a leaf function.
    Missing,
    /// An entry the search needed could not be read.
    Unreadable,
}

/// Find the runtime function whose `[BeginAddress, EndAddress)` range covers
/// `rva`, by binary search over the sorted `.pdata` table of `count` entries
/// served by `entry`. Replaces pelite 0.10's `lookup_function_entry`, whose
/// comparator is inverted and misses. The search touches `log2(count)`
/// entries, so a demand-read image fetches only the blocks holding them.
pub(super) fn lookup_runtime_function(
    count: usize,
    entry: impl Fn(usize) -> Option<RUNTIME_FUNCTION>,
    rva: u32,
) -> Lookup {
    let mut low = 0usize;
    let mut high = count;
    while low < high {
        let mid = low + (high - low) / 2;
        let Some(function) = entry(mid) else {
            return Lookup::Unreadable;
        };
        if rva < function.BeginAddress {
            high = mid;
        } else if rva >= function.EndAddress {
            low = mid + 1;
        } else {
            return Lookup::Found(function);
        }
    }
    Lookup::Missing
}

fn parse_unwind_info(image: &PeImage, unwind_rva: u32) -> Option<ParsedUnwindInfo> {
    // every read goes through `PeImage::read`, so unwind data that lands in a
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

fn frame_base(context: &RegisterContext, unwind_info: &ParsedUnwindInfo) -> Option<u64> {
    if unwind_info.frame_register == 0 {
        return Some(context.rsp);
    }

    let frame_register = context.get(unwind_info.frame_register)?;
    frame_register.checked_sub(u64::from(unwind_info.frame_offset) * 16)
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

/// A runtime function and its unwind data, as `.fnent` shows them.
#[derive(Debug, Clone)]
pub struct FunctionEntryDetail {
    pub module: String,
    pub image_base: u64,
    /// The entry covering the address, then each parent its chained unwind
    /// info names, in order.
    pub entries: Vec<RuntimeFunctionDetail>,
    /// Why the chain ends before its last parent, when it does.
    pub incomplete: Option<String>,
}

/// One function-table entry (RVAs) and the unwind data it points at.
#[derive(Debug, Clone)]
pub struct RuntimeFunctionDetail {
    pub begin: u32,
    pub end: u32,
    /// The unwind info's RVA; on ARM64, the packed unwind data itself when
    /// its low two bits (the flag) are not zero.
    pub unwind_data: u32,
    /// The symbol at `begin`.
    pub symbol: String,
    /// `None` when the unwind info is unreadable.
    pub unwind: Option<UnwindDetail>,
}

/// An entry's unwind data, by architecture.
#[derive(Debug, Clone)]
pub enum UnwindDetail {
    Amd64(UnwindInfoDetail),
    Arm64(super::arm64::Arm64UnwindDetail),
}

#[derive(Debug, Clone)]
pub struct UnwindInfoDetail {
    pub version: u8,
    pub flags: u8,
    pub prolog_size: u8,
    pub code_count: u8,
    /// The frame pointer register, when the function establishes one.
    pub frame_register: Option<&'static str>,
    /// The frame pointer's offset from the stack pointer, in bytes.
    pub frame_offset: u32,
    pub codes: Vec<UnwindCodeDetail>,
    /// The exception or termination handler, for `UNW_FLAG_EHANDLER` or
    /// `UNW_FLAG_UHANDLER`.
    pub handler: Option<HandlerDetail>,
    /// Bytes of the structure: header, codes, and the handler RVA or the
    /// chained entry, without the handler's own data.
    pub size: usize,
}

#[derive(Debug, Clone)]
pub struct HandlerDetail {
    pub rva: u32,
    pub symbol: String,
    /// Where the handler's language-specific data starts.
    pub data_rva: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindCodeDetail {
    /// Index of the code's first slot.
    pub slot: usize,
    /// Offset in the prolog of the end of the instruction it undoes.
    pub code_offset: u8,
    pub op: u8,
    pub op_info: u8,
    /// The operation and its operands, e.g. `UWOP_SAVE_NONVOL rbx at +0x30`.
    pub description: String,
}

/// What [`describe_function_entry`] found.
pub enum EntryLookup {
    /// The entry and its chained parents, and why the chain ends early when
    /// it does.
    Found {
        entries: Vec<RuntimeFunctionDetail>,
        incomplete: Option<String>,
    },
    /// No entry covers the address: a leaf function, or not code.
    Leaf,
    /// The lookup hit a paged-out hole an on-disk image could fill.
    Holed,
}

/// The function-table entry covering `address` and its unwind data, chained
/// parents included. `symbol` names an image address.
pub fn describe_function_entry(
    image: &PeImage,
    layout: Option<&CodeLayout>,
    base_address: u64,
    address: u64,
    symbol: impl Fn(u64) -> String,
) -> EntryLookup {
    let (unwind_data, begin, end) = match resolve_function(image, layout, base_address, address) {
        Resolve::Function {
            unwind_data,
            begin,
            end,
        } => (unwind_data, begin, end),
        Resolve::Leaf => return EntryLookup::Leaf,
        Resolve::Holed => return EntryLookup::Holed,
    };
    let mut entries = Vec::new();
    let mut incomplete = None;
    let mut next = Some(RUNTIME_FUNCTION {
        BeginAddress: begin,
        EndAddress: end,
        UnwindData: unwind_data,
    });
    while let Some(function) = next.take() {
        if entries.len() > MAX_CHAIN_DEPTH {
            incomplete = Some(format!("chain not followed past {MAX_CHAIN_DEPTH} parents"));
            break;
        }
        let described = describe_unwind_info(image, function.UnwindData, |rva| {
            symbol(base_address + u64::from(rva))
        });
        if described.is_none() {
            incomplete = Some(format!(
                "unwind info at RVA {:#x} is unreadable",
                function.UnwindData
            ));
        }
        let unwind = described.map(|(info, parent)| {
            next = parent;
            UnwindDetail::Amd64(info)
        });
        entries.push(RuntimeFunctionDetail {
            begin: function.BeginAddress,
            end: function.EndAddress,
            unwind_data: function.UnwindData,
            symbol: symbol(base_address + u64::from(function.BeginAddress)),
            unwind,
        });
    }
    EntryLookup::Found {
        entries,
        incomplete,
    }
}

/// The `UNWIND_INFO` at `rva`, and the parent entry it chains to; `None`
/// when any of it is unreadable.
fn describe_unwind_info(
    image: &PeImage,
    rva: u32,
    symbol: impl Fn(u32) -> String,
) -> Option<(UnwindInfoDetail, Option<RUNTIME_FUNCTION>)> {
    let parsed = parse_unwind_info(image, rva)?;
    let flags = parsed.version_flags >> 3;
    let tail_offset = parsed.tail_offset;
    let mut size = tail_offset - rva as usize;
    let mut handler = None;
    if parsed.parent.is_some() {
        size += RUNTIME_FUNCTION_SIZE;
    } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        let handler_rva = image_u32(&image.read(tail_offset, 4)?, 0)?;
        handler = Some(HandlerDetail {
            rva: handler_rva,
            symbol: symbol(handler_rva),
            data_rva: u32::try_from(tail_offset + 4).ok()?,
        });
        size += 4;
    }
    let info = UnwindInfoDetail {
        version: parsed.version_flags & 0x7,
        flags,
        prolog_size: parsed.size_of_prolog,
        code_count: u8::try_from(parsed.codes.len()).ok()?,
        frame_register: (parsed.frame_register != 0)
            .then(|| AMD64_REGISTER_NAMES[usize::from(parsed.frame_register)]),
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
fn describe_unwind_codes(codes: &[UnwindCodeSlot]) -> Vec<UnwindCodeDetail> {
    let register = |number: u8| AMD64_REGISTER_NAMES[usize::from(number & 0xf)];
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
        described.push(UnwindCodeDetail {
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
    use super::{
        Epilog, EpilogRelease, Lookup, ParsedUnwindInfo, RUNTIME_FUNCTION, UWOP_ALLOC_LARGE,
        UWOP_EPILOG, UWOP_SAVE_NONVOL, UnwindCodeSlot, decode_epilog, describe_unwind_codes,
        frame_base, lookup_runtime_function, parse_unwind_info, unwind_slot_count,
    };
    use crate::pe::PeImage;
    use crate::unwind::RegisterContext;

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
    fn lookup_runtime_function_resolves_across_a_large_sorted_table() {
        let funcs: Vec<RUNTIME_FUNCTION> = (0..64u32)
            .map(|i| RUNTIME_FUNCTION {
                BeginAddress: i * 0x100,
                EndAddress: i * 0x100 + 0x40,
                UnwindData: i,
            })
            .collect();
        let lookup = |rva: u32| match lookup_runtime_function(
            funcs.len(),
            |index| funcs.get(index).copied(),
            rva,
        ) {
            Lookup::Found(function) => Some(function.BeginAddress),
            Lookup::Missing => None,
            Lookup::Unreadable => panic!("table is fully readable"),
        };

        assert_eq!(lookup(0x0), Some(0x0));
        assert_eq!(lookup(0x310), Some(0x300));
        assert_eq!(lookup(0x3f00), Some(0x3f00));
        assert_eq!(lookup(0x350), None);
        assert_eq!(lookup(0x10000), None);

        // An entry the search cannot read is reported, not treated as a leaf.
        assert!(matches!(
            lookup_runtime_function(funcs.len(), |_| None, 0x310),
            Lookup::Unreadable
        ));
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
        let info =
            parse_unwind_info(&PeImage::complete(blob.to_vec()), 0).expect("unwind info parses");
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
        let info =
            parse_unwind_info(&PeImage::complete(blob.to_vec()), 0).expect("unwind info parses");
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
        let mut context = RegisterContext::new(0, 0x1800);
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
