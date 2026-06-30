use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

/// Per-frame unwinder diagnostics, gated on `NTOSEYE_UNWIND_TRACE`. Prints which
/// branch each `unwind_once` takes so early bail-outs (no function entry, bad
/// codes, failed reads) can be told apart from a genuine leaf pop.
fn unwind_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("NTOSEYE_UNWIND_TRACE").is_some())
}

macro_rules! unwind_trace {
    ($($arg:tt)*) => {
        if unwind_trace_enabled() {
            eprintln!($($arg)*);
        }
    };
}

use std::cmp::Ordering;

use pelite::pe64::{
    Pe, PeView,
    image::{
        IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_SCN_MEM_EXECUTE, RUNTIME_FUNCTION,
        UNW_FLAG_CHAININFO, UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL, UWOP_PUSH_MACHFRAME,
        UWOP_PUSH_NONVOL, UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR, UWOP_SAVE_XMM128,
        UWOP_SAVE_XMM128_FAR, UWOP_SET_FPREG,
    },
};

use crate::{
    backend::MemoryOps,
    gdb::RegisterMap,
    guest::{ModuleInfo, PeImage, ProcessInfo, read_pe_image, read_pe_image_from_file},
    phys::PhysMem,
    memory::AddressSpace,
    symbols::SymbolStore,
    target::Target,
    types::{Dtb, VirtAddr},
};

const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const STACK_SCAN_BYTES: usize = 0x1000;
// cap on chained unwind entries followed per frame, guarding against cyclic or
// corrupt unwind data
const MAX_CHAIN_DEPTH: usize = 32;
// hard cap on frames walked, so a stack switch (which relaxes the rsp-advances
// guard) can't let a cyclic/corrupt stack spin forever
const MAX_UNWIND_FRAMES: usize = 1024;

// version-2 unwind opcodes that pelite 0.10 doesn't define. They describe epilog
// locations and don't affect prolog-based unwinding, but must be counted so the
// code iterator stays aligned with the slot stream
const UWOP_EPILOG: u8 = 6;
const UWOP_SPARE_CODE: u8 = 7;
const UNWIND_REG_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

#[derive(Debug, Clone)]
pub struct ThreadTraceContext {
    pub description: String,
    pub active_dtb: Dtb,
    pub kernel_dtb: Dtb,
    pub process_dtb: Option<Dtb>,
    pub kernel_modules: Vec<ModuleInfo>,
    pub process_modules: Vec<ModuleInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSource {
    Current,
    Unwind,
    Scan,
}

impl FrameSource {
    /// Stable lowercase tag for how a frame was recovered, surfaced by every
    /// host. Explicit rather than derived from `Debug`, which would drift if a
    /// variant were renamed.
    pub fn as_str(self) -> &'static str {
        match self {
            FrameSource::Current => "current",
            FrameSource::Unwind => "unwind",
            FrameSource::Scan => "scan",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub sp: u64,
    pub ip: u64,
    pub symbol: String,
    pub source: FrameSource,
}

#[derive(Debug, Clone, Default)]
pub struct StackTrace {
    pub frames: Vec<StackFrame>,
    pub truncated: usize,
}

#[derive(Clone, Debug)]
struct RegisterContext {
    rip: u64,
    rsp: u64,
    regs: [Option<u64>; 16],
}

#[derive(Debug, Clone)]
struct CachedModule {
    info: ModuleInfo,
    // Arc so a frame walk can cheaply take its own handle to the image and
    // release the borrow on the cache while parsing unwind data
    image: Arc<PeImage>,
    executable_ranges: Vec<(u32, u32)>,
}

#[derive(Debug, Clone)]
struct OwnedModule {
    info: ModuleInfo,
    dtb: Dtb,
}

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
enum Unwound {
    /// Could not unwind further; the caller falls back to a stack scan
    Stop,
    /// Advanced to the caller. `stack_switch` is set when we crossed a hardware
    /// trap/interrupt frame, where rsp may move to a different stack (e.g. an IST
    /// or the idle stack) and so need not be greater than the previous rsp.
    Frame { stack_switch: bool },
}

struct StackTracer<'a> {
    trace: &'a ThreadTraceContext,
    phys: &'a PhysMem,
    symbols: &'a SymbolStore,
    memory: AddressSpace<'a, PhysMem>,
    modules: HashMap<(Dtb, u64), CachedModule>,
}

pub fn resolve_thread_trace_context(debugger: &Target, cr3: u64) -> ThreadTraceContext {
    let cr3_masked = cr3 & CR3_PAGE_MASK;
    let kernel_dtb = debugger.guest.ntoskrnl.dtb();
    let kernel_dtb_masked = kernel_dtb & CR3_PAGE_MASK;

    if cr3_masked == kernel_dtb_masked {
        return ThreadTraceContext {
            description: "kernel".to_string(),
            active_dtb: kernel_dtb,
            kernel_dtb,
            process_dtb: None,
            kernel_modules: debugger.guest.kernel_modules().unwrap_or_default(),
            process_modules: Vec::new(),
        };
    }

    if let Some(proc_info) = find_process_by_cr3(debugger, cr3_masked) {
        let process_modules = debugger
            .guest
            .process_modules(&proc_info)
            .unwrap_or_default();
        return ThreadTraceContext {
            description: format!("{} ({})", proc_info.name, proc_info.pid),
            active_dtb: cr3_masked,
            kernel_dtb,
            process_dtb: Some(proc_info.dtb),
            kernel_modules: debugger.guest.kernel_modules().unwrap_or_default(),
            process_modules,
        };
    }

    ThreadTraceContext {
        description: "unknown".to_string(),
        active_dtb: cr3_masked,
        kernel_dtb,
        process_dtb: None,
        kernel_modules: debugger.guest.kernel_modules().unwrap_or_default(),
        process_modules: Vec::new(),
    }
}

pub fn format_symbol(debugger: &Target, trace: &ThreadTraceContext, addr: u64) -> String {
    let try_format = |dtb| {
        debugger
            .symbols
            .format_closest_symbol_for_address(dtb, VirtAddr(addr))
    };

    if let Some(module) = trace.module_for_address(addr) {
        return try_format(module.dtb).unwrap_or_else(|| {
            // TODO lazily load module symbols on stop so user return addresses resolve past module+offset.
            let offset = addr.saturating_sub(module.info.base_address.0);
            format!("{}+{:#x}", module.info.short_name, offset)
        });
    }

    if let Some(process_dtb) = trace.process_dtb
        && let Some(symbol) = try_format(process_dtb)
    {
        return symbol;
    }

    if let Some(symbol) = try_format(trace.kernel_dtb) {
        return symbol;
    }

    format!("{:#x}", addr)
}

pub fn preferred_code_dtb(trace: &ThreadTraceContext, addr: u64) -> Dtb {
    trace
        .module_for_address(addr)
        .map(|module| module.dtb)
        .unwrap_or(trace.active_dtb)
}

pub fn build_stacktrace(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    limit: usize,
) -> StackTrace {
    let limit = limit.max(1);
    let rip = register_map.read_u64("rip", regs).unwrap_or(0);
    let rsp = register_map.read_u64("rsp", regs).unwrap_or(0);
    let cr3 = register_map.read_u64("cr3", regs).unwrap_or(0);

    let trace = resolve_thread_trace_context(debugger, cr3);

    // phase 1: walk the stack collecting raw frames (sp, ip, source). Symbols are
    // formatted afterwards so we can first lazily load the modules they land in.
    let mut raw: Vec<(u64, u64, FrameSource)> = vec![(rsp, rip, FrameSource::Current)];
    let mut tracer = StackTracer::new(debugger, &trace);
    let mut context = RegisterContext::from_registers(register_map, regs);
    let mut seen = HashSet::from([rip]);

    // bound on unwind iterations: rsp normally advances every step, but a stack
    // switch across a trap frame relaxes that guard, so cap the walk to stay safe
    // against cyclic/corrupt data
    for _ in 0..MAX_UNWIND_FRAMES {
        let previous_rip = context.rip;
        let previous_rsp = context.rsp;

        let stack_switch = match tracer.unwind_once(&mut context) {
            Unwound::Stop => break,
            Unwound::Frame { stack_switch } => stack_switch,
        };

        if context.rip == 0 || context.rip == previous_rip {
            break;
        }
        // rsp must advance within a stack; a trap/interrupt frame can switch to
        // another stack, where the new rsp is unrelated to the previous one
        if !stack_switch && context.rsp <= previous_rsp {
            break;
        }

        seen.insert(context.rip);
        raw.push((context.rsp, context.rip, FrameSource::Unwind));
    }

    for (sp, ip) in tracer.scan_stack(context.rsp, &seen) {
        raw.push((sp, ip, FrameSource::Scan));
    }

    // phase 2: lazily load symbols for the modules these frames land in, so
    // user-mode frames (e.g. ntdll in a process we never attached to) resolve to
    // `module!symbol` instead of `module+offset`
    ensure_frame_module_symbols(debugger, &trace, raw.iter().map(|(_, ip, _)| *ip));

    // phase 3: format each frame, honouring the display limit
    let mut stacktrace = StackTrace::default();
    for (sp, ip, source) in raw {
        record_stack_frame(
            &mut stacktrace,
            limit,
            StackFrame {
                sp,
                ip,
                symbol: format_symbol(debugger, &trace, ip),
                source,
            },
        );
    }

    stacktrace
}

/// Lazily load symbols for the modules a backtrace touches. Only modules with no
/// prior load attempt are fetched (so kernel modules, loaded on stop, and an
/// attached process's modules are skipped), and each is loaded once per session.
fn ensure_frame_module_symbols(
    debugger: &Target,
    trace: &ThreadTraceContext,
    ips: impl Iterator<Item = u64>,
) {
    let mut by_dtb: HashMap<Dtb, Vec<ModuleInfo>> = HashMap::new();
    let mut seen: HashSet<(Dtb, u64)> = HashSet::new();
    for ip in ips {
        let Some(module) = trace.module_for_address(ip) else {
            continue;
        };
        let key = (module.dtb, module.info.base_address.0);
        if seen.insert(key)
            && debugger
                .symbols
                .module_symbol_status(module.dtb, module.info.base_address)
                .is_none()
        {
            by_dtb.entry(module.dtb).or_default().push(module.info);
        }
    }

    for (dtb, modules) in by_dtb {
        let _ =
            debugger
                .guest
                .load_symbols_for_modules(&debugger.phys, &debugger.symbols, modules, dtb);
    }
}

fn record_stack_frame(stacktrace: &mut StackTrace, limit: usize, frame: StackFrame) {
    if stacktrace.frames.len() < limit {
        stacktrace.frames.push(frame);
    } else {
        stacktrace.truncated += 1;
    }
}

fn find_process_by_cr3(debugger: &Target, cr3_masked: u64) -> Option<ProcessInfo> {
    debugger
        .guest
        .enumerate_processes()
        .ok()?
        .into_iter()
        .find(|proc| (proc.dtb & CR3_PAGE_MASK) == cr3_masked)
}

impl RegisterContext {
    fn from_registers(register_map: &RegisterMap, regs: &[u8]) -> Self {
        let mut register_values = [None; 16];
        for (index, name) in UNWIND_REG_NAMES.iter().enumerate() {
            register_values[index] = register_map.read_u64(*name, regs).ok();
        }

        Self {
            rip: register_map.read_u64("rip", regs).unwrap_or(0),
            rsp: register_map.read_u64("rsp", regs).unwrap_or(0),
            regs: register_values,
        }
    }

    fn get(&self, register: u8) -> Option<u64> {
        match register {
            4 => Some(self.rsp),
            _ => self.regs.get(register as usize).copied().flatten(),
        }
    }

    fn set(&mut self, register: u8, value: u64) {
        if register == 4 {
            self.rsp = value;
        }

        if let Some(slot) = self.regs.get_mut(register as usize) {
            *slot = Some(value);
        }
    }
}

impl ThreadTraceContext {
    fn module_for_address(&self, address: u64) -> Option<OwnedModule> {
        self.kernel_modules
            .iter()
            .find(|module| module.contains_address(VirtAddr(address)))
            .cloned()
            .map(|info| OwnedModule {
                info,
                dtb: self.kernel_dtb,
            })
            .or_else(|| {
                self.process_modules
                    .iter()
                    .find(|module| module.contains_address(VirtAddr(address)))
                    .cloned()
                    .map(|info| OwnedModule {
                        info,
                        dtb: self.process_dtb.unwrap_or(self.active_dtb),
                    })
            })
    }
}

impl<'a> StackTracer<'a> {
    fn new(debugger: &'a Target, trace: &'a ThreadTraceContext) -> Self {
        Self {
            trace,
            phys: &debugger.phys,
            symbols: &debugger.symbols,
            memory: AddressSpace::new(&debugger.phys, trace.active_dtb),
            modules: HashMap::new(),
        }
    }

    fn unwind_once(&mut self, context: &mut RegisterContext) -> Unwound {
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
                    let Ok(return_address) = self.memory.read::<u64>(VirtAddr(context.rsp)) else {
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

    fn unwind_leaf(&self, context: &mut RegisterContext) -> Unwound {
        let Ok(return_address) = self.memory.read::<u64>(VirtAddr(context.rsp)) else {
            return Unwound::Stop;
        };

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
                let saved = self.memory.read::<u64>(VirtAddr(context.rsp)).ok()?;
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
                    let saved = self.memory.read::<u64>(VirtAddr(base + offset)).ok()?;
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
                    let saved = self.memory.read::<u64>(VirtAddr(base + scaled)).ok()?;
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
                let return_rip = self.memory.read::<u64>(VirtAddr(base)).ok()?;
                let return_rsp = self
                    .memory
                    .read::<u64>(VirtAddr(base.saturating_add(24)))
                    .ok()?;
                context.rip = return_rip;
                context.rsp = return_rsp;
                return Some(UnwindStep::MachineFrame);
            }
            _ => return None,
        }

        Some(UnwindStep::Continue)
    }

    fn scan_stack(&mut self, start_rsp: u64, seen: &HashSet<u64>) -> Vec<(u64, u64)> {
        let mut frames = Vec::new();
        let mut failures = 0usize;

        for slot in 0..(STACK_SCAN_BYTES / 8) {
            if failures >= 32 {
                break;
            }

            let sp = start_rsp.saturating_add((slot * 8) as u64);
            let potential_ip = match self.memory.read::<u64>(VirtAddr(sp)) {
                Ok(addr) => {
                    failures = 0;
                    addr
                }
                Err(_) => {
                    failures += 1;
                    continue;
                }
            };

            if seen.contains(&potential_ip) || !self.is_executable_address(potential_ip) {
                continue;
            }

            frames.push((sp, potential_ip));
        }

        frames
    }

    fn is_executable_address(&mut self, address: u64) -> bool {
        let Some(module) = self.module_containing(address) else {
            return false;
        };

        let rva = (address - module.info.base_address.0) as u32;
        module
            .executable_ranges
            .iter()
            .any(|(start, end)| rva >= *start && rva < *end)
    }

    fn module_containing(&mut self, address: u64) -> Option<&CachedModule> {
        let module = self.trace.module_for_address(address)?;

        self.ensure_module_loaded(&module)?;
        self.modules.get(&(module.dtb, module.info.base_address.0))
    }

    /// A cheap clone of the cached image handle for the module containing
    /// `address` (the module must already be loaded).
    fn module_image(&self, address: u64) -> Option<Arc<PeImage>> {
        let module = self.trace.module_for_address(address)?;
        self.modules
            .get(&(module.dtb, module.info.base_address.0))
            .map(|cached| cached.image.clone())
    }

    /// Replace a module's holed in-memory image with the complete on-disk one,
    /// downloading it if needed. Returns whether the cache now holds a complete
    /// image. No-op (false) when the image is already complete or the on-disk
    /// fetch fails (non-Microsoft module, offline); the caller then degrades to
    /// a stack scan.
    fn upgrade_module_image(&mut self, address: u64) -> bool {
        let Some(module) = self.trace.module_for_address(address) else {
            return false;
        };
        let key = (module.dtb, module.info.base_address.0);

        let disk = {
            let Some(cached) = self.modules.get(&key) else {
                return false;
            };
            if cached.image.is_complete() {
                return false;
            }
            self.load_on_disk_image(&cached.image, &module.info)
        };
        let Some(disk) = disk else {
            return false;
        };

        unwind_trace!(
            "unwind: recovered on-disk image for {} (in-memory unwind data paged out)",
            module.info.short_name
        );
        let executable_ranges = executable_ranges(&disk);
        self.modules.insert(
            key,
            CachedModule {
                info: module.info.clone(),
                image: Arc::new(disk),
                executable_ranges,
            },
        );
        true
    }

    fn ensure_module_loaded(&mut self, module: &OwnedModule) -> Option<()> {
        let key = (module.dtb, module.info.base_address.0);
        if self.modules.contains_key(&key) {
            return Some(());
        }

        let image_memory = AddressSpace::new(self.phys, module.dtb);
        let image = read_pe_image(module.info.base_address, &image_memory).ok()?;
        let executable_ranges = executable_ranges(&image);

        self.modules.insert(
            key,
            CachedModule {
                info: module.info.clone(),
                image: Arc::new(image),
                executable_ranges,
            },
        );

        Some(())
    }

    /// Download (if needed) and load the module's complete on-disk PE image,
    /// matched by the in-memory header's TimeDateStamp + SizeOfImage. The caller
    /// re-resolves against it to decide whether it actually recovered anything.
    fn load_on_disk_image(&self, image: &PeImage, info: &ModuleInfo) -> Option<PeImage> {
        let view = PeView::from_bytes(image.as_slice()).ok()?;
        let time_date_stamp = view.file_header().TimeDateStamp;
        let size_of_image = view.optional_header().SizeOfImage;

        let path = self
            .symbols
            .ensure_module_image_on_disk(&info.name, time_date_stamp, size_of_image)
            .ok()?;
        read_pe_image_from_file(&path).ok()
    }
}

/// The `[start, end)` RVA ranges of a module's executable sections (used to
/// validate scan candidates).
fn executable_ranges(image: &PeImage) -> Vec<(u32, u32)> {
    let Ok(view) = PeView::from_bytes(image.as_slice()) else {
        return Vec::new();
    };
    view.section_headers()
        .iter()
        .filter_map(|section| {
            if section.Characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                return None;
            }
            let size = section.VirtualSize.max(section.SizeOfRawData);
            if size == 0 {
                return None;
            }
            Some((
                section.VirtualAddress,
                section.VirtualAddress.saturating_add(size),
            ))
        })
        .collect()
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
    let Ok(view) = PeView::from_bytes(image.as_slice()) else {
        return Resolve::Leaf;
    };
    let Ok(exception) = view.exception() else {
        return Resolve::Leaf;
    };

    let rva = (rip - base_address) as u32;
    match lookup_runtime_function(exception.image(), rva) {
        // an entry is only usable if its unwind info (`.xdata`) is resident too
        Some(function) if image.is_present(function.UnwindData as usize, 4) => Resolve::Function {
            unwind_data: function.UnwindData,
            begin: function.BeginAddress,
        },
        Some(_) => Resolve::Holed,
        None => {
            // no entry: a true leaf if the table is resident, otherwise the table
            // itself is holed
            let pdata_present = view
                .data_directory()
                .get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
                .map(|d| {
                    d.Size == 0 || image.is_present(d.VirtualAddress as usize, d.Size as usize)
                })
                .unwrap_or(true);
            if pdata_present {
                Resolve::Leaf
            } else {
                Resolve::Holed
            }
        }
    }
}

/// Find the runtime function whose `[BeginAddress, EndAddress)` range covers
/// `rva`, by binary search over the (sorted) `.pdata` table. Replaces pelite
/// 0.10's `lookup_function_entry`, whose comparator is inverted and misses.
fn lookup_runtime_function(functions: &[RUNTIME_FUNCTION], rva: u32) -> Option<&RUNTIME_FUNCTION> {
    functions
        .binary_search_by(|rf| {
            if rva < rf.BeginAddress {
                Ordering::Greater
            } else if rva >= rf.EndAddress {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .ok()
        .map(|index| &functions[index])
}

fn parse_unwind_info(image: &PeImage, unwind_rva: u32) -> Option<ParsedUnwindInfo> {
    // every read goes through `present_slice`, so unwind data that lands in a
    // paged-out hole returns None (fall back to scan) rather than being parsed as
    // zeros and fabricating a frame
    let offset = unwind_rva as usize;
    let header = image.present_slice(offset, 4)?;
    let version_flags = header[0];
    let count_of_codes = header[2] as usize;
    let frame_register_offset = header[3];

    let codes_offset = offset + 4;
    let codes_bytes = image.present_slice(codes_offset, count_of_codes.checked_mul(2)?)?;

    let aligned_code_count = (count_of_codes + 1) & !1;
    let tail_offset = offset + 4 + aligned_code_count * 2;
    let chained_unwind_data = if (version_flags >> 3) & UNW_FLAG_CHAININFO != 0 {
        // a chained entry is followed by the parent RUNTIME_FUNCTION
        // (BeginAddress, EndAddress, UnwindInfoAddress); only the parent's
        // unwind-data RVA is needed to keep walking the chain
        let tail = image.present_slice(tail_offset, 12)?;
        Some(u32::from_le_bytes([tail[8], tail[9], tail[10], tail[11]]))
    } else {
        None
    };

    let mut codes = Vec::with_capacity(count_of_codes);
    for raw in codes_bytes.chunks_exact(2) {
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
        FrameSource, ParsedUnwindInfo, PeImage, RUNTIME_FUNCTION, RegisterContext, StackFrame,
        StackTrace, UnwindCodeSlot, frame_base, lookup_runtime_function, parse_unwind_info,
        record_stack_frame, slot_u16, unwind_slot_count,
    };

    #[test]
    fn lookup_runtime_function_resolves_across_a_large_sorted_table() {
        // entries [i*0x100, i*0x100+0x40) with a gap before the next; the
        // lower-half hits are exactly what pelite's inverted comparator missed
        let funcs: Vec<RUNTIME_FUNCTION> = (0..64u32)
            .map(|i| RUNTIME_FUNCTION {
                BeginAddress: i * 0x100,
                EndAddress: i * 0x100 + 0x40,
                UnwindData: i,
            })
            .collect();

        assert_eq!(
            lookup_runtime_function(&funcs, 0x0).unwrap().BeginAddress,
            0x0
        );
        assert_eq!(
            lookup_runtime_function(&funcs, 0x310).unwrap().BeginAddress,
            0x300
        );
        assert_eq!(
            lookup_runtime_function(&funcs, 0x3f00)
                .unwrap()
                .BeginAddress,
            0x3f00
        );
        // an address in the gap between two functions resolves to nothing
        assert!(lookup_runtime_function(&funcs, 0x350).is_none());
        // past the end of the table
        assert!(lookup_runtime_function(&funcs, 0x10000).is_none());
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
    fn slot_u16_reads_little_endian_slot_data() {
        let codes = vec![
            UnwindCodeSlot {
                code_offset: 0x34,
                unwind_op: 0,
                op_info: 0,
                raw_op_info: 0x12,
            },
            UnwindCodeSlot {
                code_offset: 0x78,
                unwind_op: 0,
                op_info: 0,
                raw_op_info: 0x56,
            },
        ];

        assert_eq!(slot_u16(&codes, 0), Some(0x1234));
        assert_eq!(slot_u16(&codes, 1), Some(0x5678));
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

    #[test]
    fn record_stack_frame_counts_truncated_frames() {
        let mut stacktrace = StackTrace::default();

        for ip in [0x1000, 0x2000, 0x3000] {
            record_stack_frame(
                &mut stacktrace,
                2,
                StackFrame {
                    sp: 0,
                    ip,
                    symbol: String::new(),
                    source: FrameSource::Current,
                },
            );
        }

        assert_eq!(stacktrace.frames.len(), 2);
        assert_eq!(stacktrace.truncated, 1);
    }
}
