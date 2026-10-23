//! Walking ARM64 frames: a pc's function in its image's `.pdata` (or a
//! dynamic function table), the unwind format of
//! [`crate::arch::arm64::unwind`] run against the walked stack, and the
//! frame pointer and frame base a frame's locals are found by.

use std::ops::Range;

use super::amd64::{DynamicCode, EntryLookup, RuntimeFunction};
use super::{FrameRegisters, StackTracer, Unwinder, Unwound, runtime_functions};
use crate::arch::arm64::unwind::{
    FP, LR, RUNTIME_FUNCTION_SIZE, Resume, UnwindData, call_return_address, describe_arm64_unwind,
    function_length, runtime_function_at, strip_pac,
};
use crate::{
    arch::{Arch, arm64::VOLATILE_REGISTERS},
    base::{
        error::{Error, Result},
        memory::MemoryOps,
        types::{CodeMachine, VirtAddr},
    },
    nt::pe::{CodeLayout, PeImage},
};

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
    let entry = |index: usize| runtime_function_at(image, pdata.start, index);
    let mut low = 0usize;
    let mut high = pdata.len() / RUNTIME_FUNCTION_SIZE;
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
    let Some(length) = function_length(image, unwind_data) else {
        return Arm64Lookup::Unreadable;
    };
    match begin.checked_add(length) {
        Some(end) if length != 0 && rva < end => Arm64Lookup::Found(Arm64Function {
            begin,
            end,
            unwind_data,
        }),
        _ => Arm64Lookup::Missing,
    }
}

/// The `.pdata` entry covering `address` and its unwind data. `symbol` names
/// an image address.
pub fn describe_arm64_function_entry(
    image: &PeImage,
    layout: Option<&CodeLayout>,
    base: u64,
    address: u64,
    symbol: impl Fn(u64) -> String,
) -> EntryLookup {
    let Some(pdata) = runtime_functions(image, layout, CodeMachine::Arm64) else {
        return EntryLookup::Leaf;
    };
    let Ok(rva) = u32::try_from(address.wrapping_sub(base)) else {
        return EntryLookup::Leaf;
    };
    let function = match lookup_arm64_runtime_function(image, pdata, rva) {
        Arm64Lookup::Found(function) => function,
        Arm64Lookup::Missing => return EntryLookup::Leaf,
        Arm64Lookup::Unreadable => return EntryLookup::Holed,
    };
    let Some(unwind) = describe_arm64_unwind(image, function.unwind_data, base, &symbol) else {
        return EntryLookup::Holed;
    };
    EntryLookup::Found {
        entries: vec![RuntimeFunction::new(
            base,
            function.begin,
            function.end,
            function.unwind_data,
            &symbol,
            Some(unwind),
        )],
        incomplete: None,
    }
}

/// Resolution of a pc against a module's ARM64 unwind tables.
enum Resolve {
    /// No module or no `.pdata` entry covers the pc.
    Leaf,
    Function {
        base: u64,
        function: Arm64Function,
        unwind: UnwindData,
    },
    /// The lookup or the unwind data lies in a paged-out hole.
    Holed,
}

fn resolve_in(image: &PeImage, layout: Option<&CodeLayout>, base: u64, pc: u64) -> Resolve {
    let Some(pdata) = runtime_functions(image, layout, CodeMachine::Arm64) else {
        return Resolve::Leaf;
    };
    let Ok(rva) = u32::try_from(pc.wrapping_sub(base)) else {
        return Resolve::Leaf;
    };
    match lookup_arm64_runtime_function(image, pdata, rva) {
        Arm64Lookup::Found(function) => match UnwindData::read(image, function.unwind_data) {
            Some(unwind) => Resolve::Function {
                base,
                function,
                unwind,
            },
            None => Resolve::Holed,
        },
        Arm64Lookup::Missing => Resolve::Leaf,
        Arm64Lookup::Unreadable => Resolve::Holed,
    }
}

/// The unwinder for ARM64 Windows code: packed and `.xdata` unwind codes from
/// `.pdata`, the kernel's trap, machine and context frames, and, for x64
/// code an ARM64EC process runs under emulation, the AMD64 unwinder on the
/// x64 registers the emulator keeps.
pub struct Arm64Unwinder;

impl Unwinder for Arm64Unwinder {
    fn unwind_once(&self, tracer: &mut StackTracer<'_>, context: &mut FrameRegisters) -> Unwound {
        match tracer.code_machine_at(StackTracer::arm64_lookup_pc(context)) {
            CodeMachine::Amd64 => tracer.unwind_once_emulated_amd64(context),
            CodeMachine::Arm64 | CodeMachine::X86 => tracer.unwind_once_arm64(context),
        }
    }

    fn frame_base(&self, tracer: &mut StackTracer<'_>, context: &FrameRegisters) -> Option<u64> {
        tracer.frame_base_for_arm64(context)
    }

    // An emulated x64 image, or the x64 ranges of a hybrid one, are AMD64;
    // code outside any image (the emulator's translation cache) is the
    // processor's own.
    fn code_machine_at(&self, tracer: &mut StackTracer<'_>, address: u64) -> CodeMachine {
        let Some(module) = tracer.module_containing(address) else {
            return CodeMachine::Arm64;
        };
        let rva = (address - module.info.base_address.0) as u32;
        module
            .layout
            .as_ref()
            .map_or(CodeMachine::Arm64, |layout| layout.machine_at(rva))
    }

    // KernelStack is sp in KiSwapContext's body, where its prolog saved the
    // nonvolatile registers before it called SwapContext; the thread resumes
    // at that call's return.
    fn context_switch_frame(
        &self,
        tracer: &mut StackTracer<'_>,
        kernel_stack: u64,
        swap_context: u64,
        ki_swap_context: Range<u64>,
    ) -> Result<FrameRegisters> {
        let mut code = vec![0u8; (ki_swap_context.end - ki_swap_context.start) as usize];
        tracer
            .target
            .address_space(tracer.trace.kernel_dtb)
            .read_bytes(VirtAddr(ki_swap_context.start), &mut code)?;
        let resume = call_return_address(&code, ki_swap_context.start, swap_context)
            .ok_or_else(|| Error::DebugInfo("KiSwapContext does not call SwapContext".into()))?;
        let mut seed = FrameRegisters::new(Arch::Arm64, resume, kernel_stack);
        seed.after_call = true;
        seed.regs[FP] = tracer.frame_pointer_at_body_arm64(resume - 4, kernel_stack);
        Ok(seed)
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
            return self.resolve_dynamic_arm64(pc);
        };
        let Some((image, layout)) = self.module_code(pc) else {
            return Resolve::Holed;
        };
        let resolved = resolve_in(&image, layout.as_deref(), base, pc);
        if matches!(resolved, Resolve::Holed)
            && !image.is_complete()
            && self.upgrade_module_image(pc)
            && let Some((image, layout)) = self.module_code(pc)
        {
            return resolve_in(&image, layout.as_deref(), base, pc);
        }
        resolved
    }

    /// `pc` in code no module holds, such as JIT-compiled code, by the user
    /// dump's dynamic function tables, whose unwind data is in process
    /// memory above each table's base.
    fn resolve_dynamic_arm64(&self, pc: u64) -> Resolve {
        let Some((base, function)) = self.dynamic_function(pc) else {
            return Resolve::Leaf;
        };
        unwind_trace!("unwind: dynamic function table base={base:#x}");
        let code = DynamicCode {
            memory: &self.memory,
            base,
        };
        match UnwindData::read(&code, function.unwind_data) {
            Some(unwind) => Resolve::Function {
                base,
                function: Arm64Function {
                    begin: function.begin,
                    end: function.end,
                    unwind_data: function.unwind_data,
                },
                unwind,
            },
            None => Resolve::Holed,
        }
    }

    /// Where a frame's function and unwind state are looked up: a frame
    /// returned into is suspended in the call 4 bytes before its pc, and a
    /// call that ends a function returns into the next one.
    pub(super) fn arm64_lookup_pc(context: &FrameRegisters) -> u64 {
        if context.after_call {
            context.pc.wrapping_sub(4)
        } else {
            context.pc
        }
    }

    pub fn unwind_once_arm64(&mut self, context: &mut FrameRegisters) -> Unwound {
        let pc = Self::arm64_lookup_pc(context);
        let sp = context.sp;
        unwind_trace!(
            "unwind: pc={:#x} sp={:#x} fp={:x?} lr={:x?} after_call={}",
            context.pc,
            context.sp,
            context.regs[FP],
            context.regs[LR],
            context.after_call
        );
        let resume = match self.resolve_arm64(pc) {
            Resolve::Function {
                base,
                function,
                unwind,
            } => {
                let offset = (pc - base) as u32 - function.begin;
                unwind_trace!(
                    "unwind: function {:#x}..{:#x} offset={:#x}",
                    base + u64::from(function.begin),
                    base + u64::from(function.end),
                    offset
                );
                match unwind.step(offset, context, &*self) {
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
                    unwind_trace!("unwind: lr is not known -> stop");
                    return Unwound::Stop;
                };
                // A thread's initial frame saves a zero lr: the stack ends.
                if lr == 0 {
                    context.pc = 0;
                    return Unwound::Frame {
                        stack_switch: false,
                    };
                }
                let return_address = strip_pac(lr);
                // A return to the frame's own address is a recursive call
                // when the unwind moved up the stack, and a walk going
                // nowhere when it did not.
                if return_address == context.pc && context.sp <= sp {
                    unwind_trace!("unwind: returns to its own pc without moving -> stop");
                    return Unwound::Stop;
                }
                if !self.is_executable_address(return_address) {
                    unwind_trace!("unwind: lr {return_address:#x} is no code -> stop");
                    return Unwound::Stop;
                }
                context.pc = return_address;
                context.after_call = true;
                for index in VOLATILE_REGISTERS {
                    context.regs[index] = None;
                }
                Unwound::Frame {
                    stack_switch: false,
                }
            }
            Resume::Interrupted { full } => {
                context.pc = strip_pac(context.pc);
                context.after_call = false;
                if !full {
                    for index in VOLATILE_REGISTERS {
                        context.regs[index] = None;
                    }
                }
                Unwound::Frame { stack_switch: true }
            }
        }
    }

    /// The base PDB frame-relative locals are addressed from: x29 in a
    /// function whose prolog establishes it, else sp.
    pub fn frame_base_for_arm64(&mut self, context: &FrameRegisters) -> Option<u64> {
        let fallback = (context.sp != 0).then_some(context.sp);
        match self.resolve_arm64(Self::arm64_lookup_pc(context)) {
            Resolve::Function { unwind, .. } if unwind.sets_frame_pointer() => {
                context.regs[FP].or(fallback)
            }
            _ => fallback,
        }
    }

    /// x29 in the body of the function containing `address` when sp there
    /// is `sp`; see [`UnwindData::frame_pointer_at_body`].
    pub fn frame_pointer_at_body_arm64(&mut self, address: u64, sp: u64) -> Option<u64> {
        match self.resolve_arm64(address) {
            Resolve::Function { unwind, .. } => unwind.frame_pointer_at_body(sp),
            Resolve::Leaf | Resolve::Holed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
