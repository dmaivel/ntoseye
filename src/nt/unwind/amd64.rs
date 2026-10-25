//! Walking AMD64 frames: a pc's function in its image's `.pdata` (or a
//! dynamic function table), the unwind format of
//! [`crate::arch::amd64::unwind`] run against the walked stack, and the
//! prologs and leaves that have no unwind data to run.

use std::borrow::Cow;
use std::ops::Range;
use std::sync::Arc;

use pelite::pe64::image::RUNTIME_FUNCTION;

use super::{FrameRegisters, StackTracer, Unwinder, Unwound, runtime_functions};
use crate::arch::Arch;
use crate::arch::amd64::VOLATILE_REGISTERS;
use crate::arch::amd64::prolog::{PROLOG_BYTES, analyze_prolog};
use crate::arch::amd64::unwind::{
    MAX_CHAIN_DEPTH, RUNTIME_FUNCTION_SIZE, UnwindInfo, describe_unwind_info, runtime_function_at,
    unwind_by_codes, unwind_if_epilog,
};
use crate::arch::unwind::{Unwind, UnwindBytes};
use crate::backend::phys::PhysMem;
use crate::base::error::{Error, Result};
use crate::base::memory::{AddressSpace, MemoryOps};
use crate::base::types::{CodeMachine, VirtAddr};
use crate::nt::pe::{CodeLayout, PeImage};
use crate::nt::userdump::DynamicFunction;
use ntoseye_macros::record;

impl StackTracer<'_> {
    /// `address` in its module's unwind tables, with the module's base and
    /// the image the tables were read from. When the lookup or the unwind
    /// data lands in a paged-out hole, the complete on-disk image is fetched
    /// and asked instead, so a module whose `.pdata`/`.xdata` isn't resident
    /// still unwinds. `None` when no module holds `address` or its code is
    /// not loaded.
    fn resolve_amd64(&mut self, address: u64) -> Option<(u64, Arc<PeImage>, Resolve)> {
        let base = self.module_containing(address)?.info.base_address.0;
        let (image, layout) = self.module_code(address)?;
        let resolved = resolve_function(&image, layout.as_deref(), base, address);
        if matches!(resolved, Resolve::Holed)
            && !image.is_complete()
            && self.upgrade_module_image(address)
            && let Some((image, layout)) = self.module_code(address)
        {
            let resolved = resolve_function(&image, layout.as_deref(), base, address);
            return Some((base, image, resolved));
        }
        Some((base, image, resolved))
    }

    /// The first instruction after the prolog of the function containing
    /// `address`.
    pub fn function_body_amd64(&mut self, address: u64) -> Option<u64> {
        let (base, image, resolved) = self.resolve_amd64(address)?;
        let Resolve::Function {
            unwind_data,
            begin,
            end,
        } = resolved
        else {
            return None;
        };
        let unwind = UnwindInfo::read(&*image, unwind_data)?;
        let body = u64::from(begin) + u64::from(unwind.prolog_size());
        (body < u64::from(end)).then_some(base + body)
    }
}

impl StackTracer<'_> {
    pub fn unwind_once_amd64(&mut self, context: &mut FrameRegisters) -> Unwound {
        unwind_trace!("unwind: rip={:#x} rsp={:#x}", context.pc, context.sp);
        if self.module_containing(context.pc).is_none() {
            if let Some((base, function)) = self.dynamic_function(context.pc) {
                unwind_trace!("unwind: dynamic function table base={base:#x}");
                let code = DynamicCode {
                    memory: &self.memory,
                    base,
                };
                return unwind_by_codes(
                    &*self,
                    context,
                    &code,
                    base,
                    function.unwind_data,
                    function.begin,
                    function.end,
                );
            }
            unwind_trace!("unwind: no module for rip -> leaf");
            return self.unwind_leaf(context);
        }
        let Some((base_address, image, resolved)) = self.resolve_amd64(context.pc) else {
            return Unwound::Stop;
        };

        let (unwind_data, begin, end) = match resolved {
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
                // The Windows hypervisor maps no `.pdata` at all; without its
                // file, its prologs are all there is to unwind by.
                unwind_trace!("unwind: unwind data paged out and unrecoverable -> prolog");
                return self.unwind_prolog(context, base_address);
            }
        };

        if context.after_call
            && self
                .trace
                .foreign_image
                .as_ref()
                .is_some_and(|hypervisor| hypervisor.contains_address(VirtAddr(context.pc)))
        {
            return self.unwind_hypervisor_caller(
                context,
                &image,
                base_address,
                unwind_data,
                begin,
                end,
            );
        }
        unwind_by_codes(
            &*self,
            context,
            &*image,
            base_address,
            unwind_data,
            begin,
            end,
        )
    }

    /// Step a caller frame of the Windows hypervisor (one stopped at a
    /// return address) by its file's unwind data, unless that data puts the
    /// caller's RSP off the 16-byte alignment that every call has and the
    /// function's prolog keeps it. From build 22621, the unwind data of some
    /// of its assembly leaves out the prolog's `sub rsp` (its external-
    /// interrupt exit handler's, among them), so at a call there the data
    /// would take the return address from the spill area below the real one.
    fn unwind_hypervisor_caller(
        &mut self,
        context: &mut FrameRegisters,
        image: &PeImage,
        base_address: u64,
        unwind_data: u32,
        begin: u32,
        end: u32,
    ) -> Unwound {
        let mut by_codes = context.clone();
        let unwound = unwind_by_codes(
            &*self,
            &mut by_codes,
            image,
            base_address,
            unwind_data,
            begin,
            end,
        );
        if matches!(
            unwound,
            Unwound::Frame {
                stack_switch: false
            }
        ) && context.sp.is_multiple_of(16)
            && !by_codes.sp.is_multiple_of(16)
        {
            let mut by_prolog = context.clone();
            if matches!(
                self.unwind_prolog(&mut by_prolog, base_address),
                Unwound::Prolog
            ) && by_prolog.sp.is_multiple_of(16)
            {
                unwind_trace!(
                    "unwind: unwind data misaligns the caller (rsp={:#x}); prolog -> rsp={:#x}",
                    by_codes.sp,
                    by_prolog.sp
                );
                *context = by_prolog;
                return Unwound::Prolog;
            }
        }
        *context = by_codes;
        unwound
    }

    /// Unwind a frame of the foreign image (the Windows hypervisor's) whose
    /// unwind data is not mapped, by its function's prolog (see
    /// [`crate::arch::amd64::prolog`]). A first frame in an epilog runs the epilog. The
    /// return address must follow a call in the image's code, and the prolog
    /// must decide the frame; otherwise the walk stops and the scan takes
    /// over.
    pub fn unwind_prolog(&mut self, context: &mut FrameRegisters, base: u64) -> Unwound {
        let Some(symbols) = self.trace.hypervisor.clone() else {
            return Unwound::Stop;
        };
        let Some((image, _)) = self.module_code(context.pc) else {
            return Unwound::Stop;
        };
        let rva = (context.pc - base) as u32;
        let Some(function) = symbols.function_at(rva) else {
            return Unwound::Stop;
        };
        if !context.after_call
            && let Some(code) = image.read(rva as usize, 16)
            && let Some(unwound) = unwind_if_epilog(&*self, context, &code, rva, function.clone())
        {
            return match unwound {
                Unwound::Frame { .. } => Unwound::Prolog,
                other => other,
            };
        }
        let offset = (rva - function.start) as usize;
        let Some(code) = image.read(function.start as usize, offset.min(PROLOG_BYTES)) else {
            return Unwound::Stop;
        };
        let Some(frame) = analyze_prolog(&code, offset) else {
            unwind_trace!("unwind: prolog of {:#x} undecided -> stop", function.start);
            return Unwound::Stop;
        };
        let rsp = context.sp.wrapping_add(u64::from(frame.size));
        let Ok(return_address) = self.stack_u64(rsp) else {
            return Unwound::Stop;
        };
        let follows = return_address
            .checked_sub(base)
            .and_then(|ret| image.read((ret as usize).checked_sub(7)?, 7))
            .is_some_and(|before| CodeMachine::Amd64.instruction_set().ends_in_call(&before));
        if !follows || !self.is_executable_address(return_address) {
            return Unwound::Stop;
        }
        for &(register, at) in &frame.saved {
            if let Ok(value) = self.stack_u64(context.sp.wrapping_add(u64::from(at))) {
                context.regs[register] = Some(value);
            }
        }
        context.pc = return_address;
        context.sp = rsp.wrapping_add(8);
        Unwound::Prolog
    }

    fn unwind_leaf(&mut self, context: &mut FrameRegisters) -> Unwound {
        let Ok(return_address) = self.stack_u64(context.sp) else {
            return Unwound::Stop;
        };

        if !self.is_return_address(return_address) {
            return Unwound::Stop;
        }

        context.pc = return_address;
        context.sp = context.sp.saturating_add(8);
        Unwound::Frame {
            stack_switch: false,
        }
    }

    /// Resolve the stack base used by frame-pointer-relative PDB locations for
    /// the function containing `context.rip`. A missing or unreadable unwind
    /// record degrades to the recovered RSP rather than aborting the walk.
    pub fn frame_base_for_amd64(&mut self, context: &FrameRegisters) -> Option<u64> {
        let fallback = (context.sp != 0).then_some(context.sp);
        if self.module_containing(context.pc).is_none() {
            let (base, function) = self.dynamic_function(context.pc)?;
            let code = DynamicCode {
                memory: &self.memory,
                base,
            };
            return UnwindInfo::read(&code, function.unwind_data)
                .and_then(|info| info.frame_register_value(context))
                .or(fallback);
        }
        let Some((_, image, Resolve::Function { unwind_data, .. })) =
            self.resolve_amd64(context.pc)
        else {
            return fallback;
        };
        UnwindInfo::read(&*image, unwind_data)
            .and_then(|info| info.frame_register_value(context))
            .or(fallback)
    }

    /// The entry of the user dump's dynamic function tables covering
    /// `address`, with its table's base: unwind data for code no module
    /// holds, such as JIT-compiled code.
    pub fn dynamic_function(&self, address: u64) -> Option<(u64, DynamicFunction)> {
        self.target.user_dump_info()?.dynamic_function(address)
    }
}

/// The unwinder for AMD64 Windows code: `UNWIND_INFO` from `.pdata`, the
/// prolog of hypervisor code whose tables aren't mapped, and the machine
/// frames of traps and interrupts.
pub struct Amd64Unwinder;

impl Unwinder for Amd64Unwinder {
    fn unwind_once(&self, tracer: &mut StackTracer<'_>, context: &mut FrameRegisters) -> Unwound {
        let unwound = tracer.unwind_once_amd64(context);
        let stack_switch = match unwound {
            Unwound::Frame { stack_switch } => Some(stack_switch),
            Unwound::Prolog => Some(false),
            Unwound::Stop => None,
        };
        if let Some(stack_switch) = stack_switch {
            // Crossing a machine frame lands where an interrupt or trap
            // stopped the code, not after a call.
            context.after_call = !stack_switch;
            for index in VOLATILE_REGISTERS {
                context.regs[index] = None;
            }
        }
        unwound
    }

    fn frame_base(&self, tracer: &mut StackTracer<'_>, context: &FrameRegisters) -> Option<u64> {
        tracer.frame_base_for_amd64(context)
    }

    // A WOW64 process's x86 frames are walked apart, past its 64-bit ones.
    fn code_machine_at(&self, _: &mut StackTracer<'_>, _: u64) -> CodeMachine {
        CodeMachine::Amd64
    }

    // KernelStack is rsp inside SwapContext's body, so one unwind step from
    // there lands in KiSwapContext.
    fn context_switch_frame(
        &self,
        tracer: &mut StackTracer<'_>,
        kernel_stack: u64,
        swap_context: u64,
        ki_swap_context: Range<u64>,
    ) -> Result<FrameRegisters> {
        let body = tracer.function_body_amd64(swap_context).ok_or_else(|| {
            Error::DebugInfo("SwapContext has no usable PE unwind metadata".into())
        })?;
        let mut seed = FrameRegisters::new(Arch::Amd64, body, kernel_stack);
        if !matches!(
            self.unwind_once(tracer, &mut seed),
            Unwound::Frame {
                stack_switch: false
            }
        ) {
            return Err(Error::DebugInfo(
                "failed to unwind the saved SwapContext frame".into(),
            ));
        }
        if seed.sp <= kernel_stack || !ki_swap_context.contains(&seed.pc) {
            return Err(Error::DebugInfo(format!(
                "SwapContext returned outside KiSwapContext ({:#x}, RSP {:#x})",
                seed.pc, seed.sp
            )));
        }
        Ok(seed)
    }
}

/// What a function's unwind data and code are read from, by offset from the
/// base its runtime function is relative to: a module image by RVA, or
/// process memory above a dynamic function table's base.
impl UnwindBytes for PeImage {
    fn read(&self, offset: usize, len: usize) -> Option<Cow<'_, [u8]>> {
        PeImage::read(self, offset, len)
    }
}

/// The code and unwind data of a dynamic function table, read from the
/// address space above the table's base. A read that reaches memory the
/// target cannot serve is `None`, as a paged-out image block is.
pub(super) struct DynamicCode<'s, 'a> {
    pub(super) memory: &'s AddressSpace<'a, PhysMem>,
    pub(super) base: u64,
}

impl UnwindBytes for DynamicCode<'_, '_> {
    fn read(&self, offset: usize, len: usize) -> Option<Cow<'_, [u8]>> {
        let address = self.base.checked_add(u64::try_from(offset).ok()?)?;
        let mut bytes = vec![0u8; len];
        self.memory.read_bytes(VirtAddr(address), &mut bytes).ok()?;
        Some(Cow::Owned(bytes))
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

/// The function-table entry that covers an address, and the entry of each
/// chained parent (`.fnent`).
#[record]
#[derive(Debug, Clone)]
pub struct FunctionEntry {
    /// The module that contains the function.
    pub module: String,
    #[record(hex)]
    pub image_base: u64,
    /// The entry that covers the address, then each parent that its chained
    /// unwind info names, in order.
    pub entries: Vec<RuntimeFunction>,
    /// The reason that the chain ends before its last parent. None if the
    /// chain is complete.
    pub incomplete: Option<String>,
}

/// One function-table entry and its unwind data. Addresses are absolute,
/// and the `*_rva` fields hold the raw image-relative values.
#[record]
#[derive(Debug, Clone)]
pub struct RuntimeFunction {
    #[record(hex)]
    pub begin: u64,
    #[record(hex)]
    pub end: u64,
    #[record(hex)]
    pub begin_rva: u32,
    #[record(hex)]
    pub end_rva: u32,
    /// The address of the unwind info. None for ARM64 packed unwind data.
    #[record(hex)]
    pub unwind_info: Option<u64>,
    /// The raw unwind word of the entry: the RVA of the unwind info, or
    /// the packed unwind data on ARM64 when its low two bits (the flag) are
    /// not zero.
    #[record(hex)]
    pub unwind_data: u32,
    /// The symbol at `begin`.
    pub symbol: String,
    /// The decoded unwind data. None if ntoseye cannot read it.
    pub unwind: Option<Unwind>,
}

impl RuntimeFunction {
    /// The entry `begin..end` (RVAs) of the image at `base`, whose unwind
    /// word is `unwind_data`; `symbol` names an absolute address.
    pub(super) fn new(
        base: u64,
        begin: u32,
        end: u32,
        unwind_data: u32,
        symbol: impl Fn(u64) -> String,
        unwind: Option<Unwind>,
    ) -> Self {
        let va = |rva: u32| base.wrapping_add(u64::from(rva));
        Self {
            begin: va(begin),
            end: va(end),
            begin_rva: begin,
            end_rva: end,
            unwind_info: (!matches!(unwind, Some(Unwind::Packed(_)))).then(|| va(unwind_data)),
            unwind_data,
            symbol: symbol(va(begin)),
            unwind,
        }
    }
}

/// What [`primary_function_begin`] found.
pub enum PrimaryLookup {
    /// The address of the function's first instruction.
    Found(u64),
    /// No entry covers the address, or its chain is unreadable or too deep.
    Missing,
    /// The lookup hit a paged-out hole an on-disk image could fill.
    Holed,
}

/// Where the function whose code covers `address` starts: its function-table
/// entry's begin, or, for a fragment the compiler split off from its
/// function (a cold block, whose unwind info chains to its function's
/// entry), the begin of the last entry of the chain.
pub fn primary_function_begin(
    image: &PeImage,
    layout: Option<&CodeLayout>,
    base_address: u64,
    address: u64,
) -> PrimaryLookup {
    let (mut begin, mut unwind_data) = match resolve_function(image, layout, base_address, address)
    {
        Resolve::Function {
            unwind_data, begin, ..
        } => (begin, unwind_data),
        Resolve::Leaf => return PrimaryLookup::Missing,
        Resolve::Holed => return PrimaryLookup::Holed,
    };
    for _ in 0..=MAX_CHAIN_DEPTH {
        let Some(parsed) = UnwindInfo::read(image, unwind_data) else {
            return PrimaryLookup::Holed;
        };
        match parsed.parent() {
            Some(parent) => (begin, unwind_data) = (parent.BeginAddress, parent.UnwindData),
            None => return PrimaryLookup::Found(base_address + u64::from(begin)),
        }
    }
    PrimaryLookup::Missing
}

/// What [`describe_function_entry`] found.
pub enum EntryLookup {
    /// The entry and its chained parents, and why the chain ends early when
    /// it does.
    Found {
        entries: Vec<RuntimeFunction>,
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
        let described = describe_unwind_info(image, function.UnwindData, base_address, &symbol);
        if described.is_none() {
            incomplete = Some(format!(
                "unwind info at RVA {:#x} is unreadable",
                function.UnwindData
            ));
        }
        let unwind = described.map(|(info, parent)| {
            next = parent;
            Unwind::Amd64(info)
        });
        entries.push(RuntimeFunction::new(
            base_address,
            function.BeginAddress,
            function.EndAddress,
            function.UnwindData,
            &symbol,
            unwind,
        ));
    }
    EntryLookup::Found {
        entries,
        incomplete,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Lookup, PrimaryLookup, RUNTIME_FUNCTION, RUNTIME_FUNCTION_SIZE, lookup_runtime_function,
        primary_function_begin,
    };
    use crate::nt::pe::PeImage;

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

    /// A PE32+ image whose exception directory, in `.rdata` at 0x2000, holds
    /// `functions` (sorted), with `unwind` placed at its RVAs.
    fn image_with_functions(functions: &[RUNTIME_FUNCTION], unwind: &[(usize, &[u8])]) -> PeImage {
        let mut image = vec![0u8; 0x3000];
        let mut put = |at: usize, bytes: &[u8]| image[at..at + bytes.len()].copy_from_slice(bytes);
        let (pe, opt) = (0x80usize, 0x98usize);
        put(0, b"MZ");
        put(0x3c, &(pe as u32).to_le_bytes());
        put(pe, b"PE\0\0");
        put(pe + 4, &0x8664u16.to_le_bytes());
        put(pe + 6, &2u16.to_le_bytes());
        put(pe + 20, &240u16.to_le_bytes());
        put(opt, &0x20bu16.to_le_bytes());
        put(opt + 32, &0x1000u32.to_le_bytes());
        put(opt + 36, &0x200u32.to_le_bytes());
        put(opt + 56, &0x3000u32.to_le_bytes());
        put(opt + 60, &0x1000u32.to_le_bytes());
        put(opt + 108, &16u32.to_le_bytes());
        // The exception directory, data directory entry 3.
        put(opt + 112 + 3 * 8, &0x2000u32.to_le_bytes());
        put(
            opt + 112 + 3 * 8 + 4,
            &((functions.len() * RUNTIME_FUNCTION_SIZE) as u32).to_le_bytes(),
        );
        for (index, (name, va)) in [(b".text\0\0\0", 0x1000u32), (b".rdata\0\0", 0x2000)]
            .into_iter()
            .enumerate()
        {
            let header = opt + 240 + 40 * index;
            put(header, name);
            put(header + 8, &0x1000u32.to_le_bytes());
            put(header + 12, &va.to_le_bytes());
            put(header + 16, &0x1000u32.to_le_bytes());
            put(header + 20, &va.to_le_bytes());
        }
        for (index, function) in functions.iter().enumerate() {
            let at = 0x2000 + index * RUNTIME_FUNCTION_SIZE;
            put(at, &function.BeginAddress.to_le_bytes());
            put(at + 4, &function.EndAddress.to_le_bytes());
            put(at + 8, &function.UnwindData.to_le_bytes());
        }
        for (at, bytes) in unwind {
            put(*at, bytes);
        }
        PeImage::complete(image)
    }

    /// A split-off fragment is named after the function at the end of its
    /// chain, a chain of two included; an entry without a chain is its own
    /// function; code no entry covers has none.
    #[test]
    fn a_chained_fragment_belongs_to_the_last_function_of_its_chain() {
        let function = |begin: u32, end: u32, unwind: u32| RUNTIME_FUNCTION {
            BeginAddress: begin,
            EndAddress: end,
            UnwindData: unwind,
        };
        let chained_to = |parent: RUNTIME_FUNCTION| {
            let mut bytes = vec![0x21, 0, 0, 0];
            for value in [parent.BeginAddress, parent.EndAddress, parent.UnwindData] {
                bytes.extend(value.to_le_bytes());
            }
            bytes
        };
        let primary = function(0x1000, 0x1100, 0x2100);
        let middle = function(0x1400, 0x1480, 0x2130);
        let cold = function(0x1800, 0x1880, 0x2110);
        let image = image_with_functions(
            &[primary, middle, cold],
            &[
                (0x2100, &[0x01, 0, 0, 0]),
                (0x2110, &chained_to(middle)),
                (0x2130, &chained_to(primary)),
            ],
        );
        let base = 0x1_4000_0000;
        let begin = |rva: u64| match primary_function_begin(&image, None, base, base + rva) {
            PrimaryLookup::Found(address) => Some(address - base),
            PrimaryLookup::Missing => None,
            PrimaryLookup::Holed => panic!("the image is complete"),
        };
        assert_eq!(begin(0x1840), Some(0x1000));
        assert_eq!(begin(0x1410), Some(0x1000));
        assert_eq!(begin(0x1050), Some(0x1000));
        assert_eq!(begin(0x1200), None);
    }
}
