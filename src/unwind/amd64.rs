//! AMD64 exception-directory unwinding: `.pdata` lookup, `UNWIND_INFO`
//! parsing, and applying unwind codes to step a frame to its caller.

use pelite::pe64::image::{
    RUNTIME_FUNCTION, UNW_FLAG_CHAININFO, UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL, UWOP_PUSH_MACHFRAME,
    UWOP_PUSH_NONVOL, UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128,
    UWOP_SAVE_XMM128_FAR, UWOP_SET_FPREG,
};

use super::{
    RegisterContext, StackTracer, ThreadTraceContext, exception_directory, function_range,
    image_u32, resolve_thread_trace_context,
};
use crate::{
    error::{Error, Result},
    pe::PeImage,
    target::Target,
    types::{Dtb, VirtAddr},
};

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
    size_of_prolog: u8,
    frame_register: u8,
    frame_offset: u8,
    codes: Vec<UnwindCodeSlot>,
    /// Present when this is a chained entry (`UNW_FLAG_CHAININFO`): the parent
    /// RUNTIME_FUNCTION's unwind-data RVA, so the walk can follow the chain
    chained_unwind_data: Option<u32>,
}

/// Outcome of applying one frame's unwind codes
enum UnwindStep {
    /// Codes applied; keep going (pop the return address or follow a chain)
    Continue,
    /// A hardware trap/interrupt frame set rip+rsp directly; the frame is complete
    MachineFrame,
}

/// Outcome of unwinding one frame to its caller
pub(super) enum Unwound {
    /// Could not unwind further; the caller falls back to a stack scan
    Stop,
    /// Advanced to the caller. `stack_switch` is set when we crossed a hardware
    /// trap/interrupt frame, where rsp may move to a different stack (e.g. an IST
    /// or the idle stack) and so need not be greater than the previous rsp.
    Frame { stack_switch: bool },
}

fn function_body_address(
    debugger: &Target,
    trace: &ThreadTraceContext,
    address: u64,
) -> Option<u64> {
    let (_, end) = function_range(debugger, trace, address)?;
    let mut tracer = StackTracer::new(debugger, trace);
    let base = tracer.module_containing(address)?.info.base_address.0;
    let mut image = tracer.module_image(address)?;
    let mut resolved = resolve_function(&image, base, address);
    if matches!(resolved, Resolve::Holed)
        && !image.is_complete()
        && tracer.upgrade_module_image(address)
    {
        image = tracer.module_image(address)?;
        resolved = resolve_function(&image, base, address);
    }

    let Resolve::Function { unwind_data, begin } = resolved else {
        return None;
    };
    let unwind = parse_unwind_info(&image, unwind_data)?;
    let body = base
        .checked_add(u64::from(begin))?
        .checked_add(u64::from(unwind.size_of_prolog))?;
    (body < end).then_some(body)
}

/// Recover the build-specific context-switch frame using the matching image's
/// x64 unwind metadata. `KTHREAD.KernelStack` is the RSP saved inside
/// `SwapContext`; no private `_KSWITCH_FRAME` layout or build table is needed.
pub(super) fn recover_context_switch_seed(
    debugger: &Target,
    process_dtb: Dtb,
    kernel_stack: VirtAddr,
) -> Result<RegisterContext> {
    let ntoskrnl = &debugger.guest()?.ntoskrnl;
    let swap_context = ntoskrnl.symbol("SwapContext")?.address().0;
    let ki_swap_context = ntoskrnl.symbol("KiSwapContext")?.address().0;
    let trace = resolve_thread_trace_context(debugger, process_dtb);
    let body_rip = function_body_address(debugger, &trace, swap_context)
        .ok_or_else(|| Error::DebugInfo("SwapContext has no usable PE unwind metadata".into()))?;
    let ki_swap_range = function_range(debugger, &trace, ki_swap_context)
        .ok_or_else(|| Error::DebugInfo("KiSwapContext has no usable PE unwind metadata".into()))?;

    let mut tracer = StackTracer::new(debugger, &trace);
    let mut seed = RegisterContext {
        rip: body_rip,
        rsp: kernel_stack.0,
        regs: [None; 16],
    };
    if !matches!(
        tracer.unwind_once(&mut seed),
        Unwound::Frame {
            stack_switch: false
        }
    ) {
        return Err(Error::DebugInfo(
            "failed to unwind the saved SwapContext frame".into(),
        ));
    }
    if seed.rsp <= kernel_stack.0 || !(ki_swap_range.0..ki_swap_range.1).contains(&seed.rip) {
        return Err(Error::DebugInfo(format!(
            "SwapContext returned outside KiSwapContext ({:#x}, RSP {:#x})",
            seed.rip, seed.rsp
        )));
    }

    // `seed` stays private to the stack walker: it is not a complete register
    // context (volatile registers and RFLAGS are never preserved).
    let mut caller = seed.clone();
    if !matches!(
        tracer.unwind_once(&mut caller),
        Unwound::Frame {
            stack_switch: false
        }
    ) || caller.rsp <= seed.rsp
        || !tracer.is_executable_address(caller.rip)
    {
        return Err(Error::DebugInfo(
            "failed to validate the saved KiSwapContext frame".into(),
        ));
    }

    Ok(seed)
}

impl StackTracer<'_> {
    pub(super) fn unwind_once(&mut self, context: &mut RegisterContext) -> Unwound {
        unwind_trace!("unwind: rip={:#x} rsp={:#x}", context.rip, context.rsp);
        let Some(base_address) = self
            .module_containing(context.rip)
            .map(|module| module.info.base_address.0)
        else {
            unwind_trace!("unwind: no module for rip -> leaf");
            return self.unwind_leaf(context);
        };
        let Some(mut image) = self.module_image(context.rip) else {
            return Unwound::Stop;
        };

        // Resolve the function entry. If the lookup or its unwind data lands in a
        // paged-out hole, upgrade to the complete on-disk image and re-resolve so
        // we can unwind through a module whose `.pdata`/`.xdata` isn't resident.
        let mut resolved = resolve_function(&image, base_address, context.rip);
        if matches!(resolved, Resolve::Holed)
            && !image.is_complete()
            && self.upgrade_module_image(context.rip)
        {
            let Some(upgraded) = self.module_image(context.rip) else {
                return Unwound::Stop;
            };
            image = upgraded;
            resolved = resolve_function(&image, base_address, context.rip);
        }

        let (mut unwind_data, begin) = match resolved {
            Resolve::Function { unwind_data, begin } => (unwind_data, begin),
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
                unwind_info.chained_unwind_data.is_some(),
                primary && rip_offset < unwind_info.size_of_prolog as u32,
            );

            let in_prolog = primary && rip_offset < unwind_info.size_of_prolog as u32;
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

            match unwind_info.chained_unwind_data {
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
                return Some(UnwindStep::MachineFrame);
            }
            _ => return None,
        }

        Some(UnwindStep::Continue)
    }

    /// Resolve the stack base used by frame-pointer-relative PDB locations for
    /// the function containing `context.rip`. A missing or unreadable unwind
    /// record degrades to the recovered RSP rather than aborting the walk.
    pub(super) fn frame_base_for(&mut self, context: &RegisterContext) -> Option<u64> {
        let fallback = (context.rsp != 0).then_some(context.rsp);
        let Some(base_address) = self
            .module_containing(context.rip)
            .map(|module| module.info.base_address.0)
        else {
            return fallback;
        };
        let Some(image) = self.module_image(context.rip) else {
            return fallback;
        };
        let Resolve::Function { unwind_data, .. } =
            resolve_function(&image, base_address, context.rip)
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
    Function { unwind_data: u32, begin: u32 },
    /// The lookup was blocked by a paged-out hole in `.pdata` or `.xdata`; an
    /// on-disk image could recover it.
    Holed,
}

/// Resolve `rip` against the image's unwind tables, distinguishing a true leaf
/// from a paged-out hole so the caller knows whether an on-disk image would help.
fn resolve_function(image: &PeImage, base_address: u64, rip: u64) -> Resolve {
    let Some(pdata) = exception_directory(image) else {
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
    let chained_unwind_data = if (version_flags >> 3) & UNW_FLAG_CHAININFO != 0 {
        // a chained entry is followed by the parent RUNTIME_FUNCTION
        // (BeginAddress, EndAddress, UnwindInfoAddress); only the parent's
        // unwind-data RVA is needed to keep walking the chain
        let tail = image.read(tail_offset, 12)?;
        Some(u32::from_le_bytes([tail[8], tail[9], tail[10], tail[11]]))
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
        size_of_prolog: header[1],
        frame_register: frame_register_offset & 0x0f,
        frame_offset: frame_register_offset >> 4,
        codes,
        chained_unwind_data,
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

#[cfg(test)]
mod tests {
    use super::{
        Lookup, ParsedUnwindInfo, RUNTIME_FUNCTION, frame_base, lookup_runtime_function,
        parse_unwind_info, unwind_slot_count,
    };
    use crate::pe::PeImage;
    use crate::unwind::RegisterContext;

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
        assert_eq!(info.chained_unwind_data, Some(0x2000));
    }

    #[test]
    fn parse_unwind_info_without_chain_flag_has_no_parent() {
        // version 1, no flags, no codes
        let blob = [0x01, 0x00, 0x00, 0x00];
        let info =
            parse_unwind_info(&PeImage::complete(blob.to_vec()), 0).expect("unwind info parses");
        assert_eq!(info.chained_unwind_data, None);
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
        let mut regs = [None; 16];
        regs[5] = Some(0x2000);
        let context = RegisterContext {
            rip: 0,
            rsp: 0x1800,
            regs,
        };
        let unwind = ParsedUnwindInfo {
            size_of_prolog: 0,
            frame_register: 5,
            frame_offset: 2,
            codes: Vec::new(),
            chained_unwind_data: None,
        };

        assert_eq!(frame_base(&context, &unwind), Some(0x1fe0));
    }
}
