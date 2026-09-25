use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::{Arc, OnceLock};

use pelite::pe64::{Pe, PeView, image::IMAGE_DIRECTORY_ENTRY_EXCEPTION};

use crate::{
    backend::MemoryOps,
    bugchecks::looks_like_kernel_pointer,
    error::{Error, Result},
    gdb::RegisterMap,
    guest::{Image, ModuleInfo},
    kd::{context, context_arm64},
    memory::{AddressSpace, DTB_IDENTITY},
    pe::PeImage,
    phys::PhysMem,
    symbols::{SourceLocation, SymbolStore},
    target::{
        ForeignModules, KTHREAD_STATE_TERMINATED, SavedThreadRegisters, Target, ThreadInfo,
        lookup_register,
    },
    trapframe::{decode_kswitch_frame_seed, decode_ktrap_frame_for_thread},
    types::{Arch, Dtb, VirtAddr},
};

/// Per-frame unwinder diagnostics, gated on `NTOSEYE_UNWIND_TRACE`. Prints which
/// branch each `unwind_once` takes so early bail-outs (no function entry, bad
/// codes, failed reads) can be told apart from a genuine leaf pop.
fn unwind_trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("NTOSEYE_UNWIND_TRACE").is_some())
}

macro_rules! unwind_trace {
    ($($arg:tt)*) => {
        if $crate::unwind::unwind_trace_enabled() {
            eprintln!($($arg)*);
        }
    };
}

mod amd64;
mod arm64;
mod tracer;
mod walk;

use amd64::{Lookup, RUNTIME_FUNCTION_SIZE, lookup_runtime_function, runtime_function_at};
use arm64::{Arm64Lookup, call_return_address, lookup_arm64_runtime_function};
use walk::build_recovered_stacktrace_seeded;

// hard cap on frames walked, so a stack switch (which relaxes the rsp-advances
// guard) can't let a cyclic/corrupt stack spin forever
const MAX_UNWIND_FRAMES: usize = 1024;
/// x64 general registers in their encoding order, the order unwind codes
/// number them in.
const AMD64_REGISTER_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
/// Registers a call clobbers on x64: rax, rcx, rdx, r8–r11.
const AMD64_VOLATILE: [usize; 7] = [0, 1, 2, 8, 9, 10, 11];
const ARM64_REGISTER_NAMES: [&str; 31] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30",
];
/// ABI names for ARM64 registers, which a frame answers to as well.
const ARM64_REGISTER_ALIASES: [(&str, usize); 2] = [("fp", 29), ("lr", 30)];
/// Register slots a walk tracks: the most any architecture numbers.
const REGISTER_SLOTS: usize = ARM64_REGISTER_NAMES.len();

#[derive(Debug, Clone)]
pub struct ThreadTraceContext {
    pub description: String,
    pub active_dtb: Dtb,
    pub kernel_dtb: Dtb,
    pub process_dtb: Option<Dtb>,
    pub kernel_modules: Vec<ModuleInfo>,
    pub process_modules: Vec<ModuleInfo>,
    /// An image named from memory in a root none of NT's (the hypervisor),
    /// mapped in `active_dtb`. Its frames are labeled and unwound like any
    /// module's, but it is never symbol-fetched: it has no loader entry, and
    /// every vCPU has its own root, so a fetch would repeat per vCPU.
    pub foreign_image: Option<ModuleInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSource {
    Current,
    Seed,
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
            FrameSource::Seed => "seed",
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
    pub source_location: Option<SourceLocation>,
}

#[derive(Debug, Clone, Default)]
pub struct StackTrace {
    pub frames: Vec<StackFrame>,
    pub truncated: usize,
}

/// A stack trace paired with the sparse register values recovered for every
/// frame.
#[derive(Debug, Clone)]
pub struct RecoveredFrame {
    pub frame: StackFrame,
    pub registers: HashMap<String, u64>,
    pub frame_base: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RecoveredStackTrace {
    pub frames: Vec<RecoveredFrame>,
    pub truncated: usize,
    /// The address space the walk read the stack and resolved symbols in
    /// ([`ThreadTraceContext::dtb`]), which is what a frame's locals and
    /// their values live in.
    pub dtb: Dtb,
}

impl RecoveredStackTrace {
    fn new(trace: &ThreadTraceContext) -> Self {
        Self {
            frames: Vec::new(),
            truncated: 0,
            dtb: trace.dtb(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStackSource {
    TrapFrame { address: VirtAddr },
    ContextSwitch { kernel_stack: VirtAddr },
}

impl ThreadStackSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TrapFrame { .. } => "ktrap-frame",
            Self::ContextSwitch { .. } => "kernel-stack",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreadStackTrace {
    pub source: ThreadStackSource,
    pub stacktrace: StackTrace,
}

/// A parked thread's stack paired with the sparse registers recovered for each
/// frame. See [`build_parked_thread_recovered_stack`].
#[derive(Clone, Debug)]
pub struct ThreadRecoveredStack {
    pub source: ThreadStackSource,
    pub stacktrace: RecoveredStackTrace,
}

/// A frame's registers during a walk. `regs` is indexed by architectural
/// number: x64 encoding order (see [`AMD64_REGISTER_NAMES`]) or ARM64 x0–x30.
/// `rip` and `rsp` are the program counter and stack pointer on either.
#[derive(Clone, Debug)]
struct RegisterContext {
    rip: u64,
    rsp: u64,
    regs: [Option<u64>; REGISTER_SLOTS],
    /// `rip` is a return address rather than where the frame was stopped or
    /// interrupted.
    after_call: bool,
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

struct StackTracer<'a> {
    target: &'a Target,
    trace: &'a ThreadTraceContext,
    phys: &'a Arc<PhysMem>,
    symbols: &'a SymbolStore,
    memory: AddressSpace<'a, PhysMem>,
    modules: HashMap<(Dtb, u64), CachedModule>,
    /// Stack pages read during this trace, by page address; `None` is a
    /// page the target refused. Without this every 8-byte slot the walk or
    /// the scan looks at is its own request over the transport.
    stack_pages: RefCell<HashMap<u64, Option<Box<[u8]>>>>,
    /// The kernel object, whose image is shared across traces.
    kernel: Option<&'a Image>,
}

pub fn resolve_thread_trace_context(debugger: &Target, cr3: u64) -> ThreadTraceContext {
    let dtb_mask = debugger.arch().dtb_page_mask();
    let cr3_masked = cr3 & dtb_mask;
    let kernel_dtb = debugger.kernel_dtb();
    let kernel_dtb_masked = kernel_dtb & dtb_mask;

    // Triage dumps use DTB_IDENTITY because page-table walks are impossible,
    // so force the kernel context regardless of the thread's real CR3.
    if kernel_dtb == DTB_IDENTITY || cr3_masked == kernel_dtb_masked {
        return ThreadTraceContext {
            description: "kernel".to_string(),
            active_dtb: kernel_dtb,
            kernel_dtb,
            process_dtb: None,
            kernel_modules: debugger.kernel_modules().unwrap_or_default(),
            process_modules: Vec::new(),
            foreign_image: None,
        };
    }

    if let Some(proc_info) = debugger.process_for_cr3(cr3_masked) {
        let process_modules = debugger
            .guest
            .as_ref()
            .map(|g| g.process_modules(&proc_info).unwrap_or_default())
            .unwrap_or_default();
        return ThreadTraceContext {
            description: format!("{} ({})", proc_info.name, proc_info.pid),
            active_dtb: cr3_masked,
            kernel_dtb,
            process_dtb: Some(proc_info.dtb),
            kernel_modules: debugger.kernel_modules().unwrap_or_default(),
            process_modules,
            foreign_image: None,
        };
    }

    ThreadTraceContext {
        description: UNKNOWN_CONTEXT.to_string(),
        active_dtb: cr3_masked,
        kernel_dtb,
        process_dtb: None,
        kernel_modules: debugger.kernel_modules().unwrap_or_default(),
        process_modules: Vec::new(),
        foreign_image: None,
    }
}

pub fn try_format_symbol(
    debugger: &Target,
    trace: &ThreadTraceContext,
    addr: u64,
) -> Option<String> {
    let try_format = |dtb| {
        debugger
            .symbols
            .format_closest_symbol_for_address(dtb, VirtAddr(addr))
    };

    if let Some(module) = trace.module_for_address(addr) {
        return Some(try_format(module.dtb).unwrap_or_else(|| {
            // The module has no PDB, or ensure_frame_module_symbols has not
            // loaded it yet (a background fetch may still be running).
            let offset = addr.saturating_sub(module.info.base_address.0);
            format!("{}+{:#x}", module.info.short_name, offset)
        }));
    }

    if let Some(process_dtb) = trace.process_dtb
        && let Some(symbol) = try_format(process_dtb)
    {
        return Some(symbol);
    }

    try_format(trace.kernel_dtb)
}

/// The context description for a root that is none of NT's.
pub const UNKNOWN_CONTEXT: &str = "unknown";

/// [`resolve_thread_trace_context`] for a thread stopped at `rip`. A root
/// that is none of NT's is named for the code at `rip` (the Windows
/// hypervisor or VTL1), and that code's modules join the trace, so its
/// frames read `module+offset` (or symbols, for VTL1) rather than raw
/// addresses among NT-looking stack values.
pub fn resolve_thread_trace_context_at(
    debugger: &Target,
    cr3: u64,
    rip: u64,
) -> ThreadTraceContext {
    let mut trace = resolve_thread_trace_context(debugger, cr3);
    if trace.description != UNKNOWN_CONTEXT || try_format_symbol(debugger, &trace, rip).is_some() {
        return trace;
    }
    let Some(code) = debugger.identify_foreign_code(cr3, rip) else {
        return trace;
    };
    trace.description = code.context;
    match code.modules {
        ForeignModules::SecureKernel { root, modules } => {
            trace.kernel_dtb = root;
            trace.kernel_modules = modules;
        }
        ForeignModules::Image(image) => trace.foreign_image = Some(image),
        ForeignModules::None => {}
    }
    trace
}

pub fn format_symbol(debugger: &Target, trace: &ThreadTraceContext, addr: u64) -> String {
    try_format_symbol(debugger, trace, addr).unwrap_or_else(|| format!("{addr:#x}"))
}

pub fn preferred_code_dtb(trace: &ThreadTraceContext, addr: u64) -> Dtb {
    trace
        .module_for_address(addr)
        .map(|module| module.dtb)
        .unwrap_or(trace.active_dtb)
}

fn frame_source_location(
    debugger: &Target,
    trace: &ThreadTraceContext,
    address: u64,
) -> Option<SourceLocation> {
    let module = trace.module_for_address(address)?;
    debugger
        .symbols
        .source_location(module.dtb, VirtAddr(address))
}

fn image_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The exception directory's RVA range, `None` when the image has none.
fn exception_directory(image: &PeImage) -> Option<Range<usize>> {
    let view = PeView::from_bytes(image.headers()).ok()?;
    let directory = view.data_directory().get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)?;
    if directory.Size == 0 {
        return None;
    }
    let start = directory.VirtualAddress as usize;
    Some(start..start.checked_add(directory.Size as usize)?)
}

/// Resolve the runtime-function entry containing `address`.
///
/// PE exception metadata is the authoritative function boundary for `uf`: it
/// remains correct when public symbols are sparse and avoids disassembling into
/// the next function. A paged-out `.pdata` or `.xdata` range is retried against
/// the matched on-disk image through the stack unwinder's image cache.
pub fn function_range(
    debugger: &Target,
    trace: &ThreadTraceContext,
    address: u64,
) -> Option<(u64, u64)> {
    fn range(image: &PeImage, base: u64, address: u64, arch: Arch) -> Option<(u64, u64)> {
        let rva = u32::try_from(address.checked_sub(base)?).ok()?;
        let pdata = exception_directory(image)?;
        let (begin, end) = match arch {
            Arch::Amd64 => {
                let Lookup::Found(function) = lookup_runtime_function(
                    pdata.len() / RUNTIME_FUNCTION_SIZE,
                    |index| runtime_function_at(image, pdata.start, index),
                    rva,
                ) else {
                    return None;
                };
                (function.BeginAddress, function.EndAddress)
            }
            Arch::Arm64 => match lookup_arm64_runtime_function(image, pdata, rva) {
                Arm64Lookup::Found(function) => (function.begin, function.end),
                Arm64Lookup::Missing | Arm64Lookup::Unreadable => return None,
            },
        };
        Some((base + u64::from(begin), base + u64::from(end)))
    }

    let mut tracer = StackTracer::new(debugger, trace);
    let base = tracer.module_containing(address)?.info.base_address.0;
    let arch = debugger.arch();
    let image = tracer.module_image(address)?;
    if let Some(found) = range(&image, base, address, arch) {
        return Some(found);
    }

    if !image.is_complete() && tracer.upgrade_module_image(address) {
        let image = tracer.module_image(address)?;
        return range(&image, base, address, arch);
    }

    None
}

pub fn build_stacktrace(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    limit: usize,
) -> StackTrace {
    let recovered = build_stacktrace_with_context(debugger, register_map, regs, limit);
    StackTrace {
        frames: recovered
            .frames
            .into_iter()
            .map(|frame| frame.frame)
            .collect(),
        truncated: recovered.truncated,
    }
}

/// Build a stack trace while retaining the register values known at every
/// frame. Caller frames intentionally expose only values justified by unwind
/// metadata (plus the address-space CR3), rather than copying volatile values
/// from the stopped frame.
pub fn build_stacktrace_with_context(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    limit: usize,
) -> RecoveredStackTrace {
    let cr3 = register_map
        .read_u64(debugger.arch().dtb_register(), regs)
        .unwrap_or(0);
    let context = RegisterContext::from_lookup(debugger.arch(), |name| {
        register_map.read_u64(name, regs).ok()
    });
    let trace = resolve_thread_trace_context_at(debugger, cr3, context.rip);
    build_recovered_stacktrace_seeded(
        debugger,
        &trace,
        context,
        FrameSource::Current,
        limit,
        register_map.to_hashmap(regs),
    )
}

/// Build a recovered trace from a sparse selected-frame register map. This is
/// used after `.frame`, `.cxr`, or `.trap`, where there is no backend packet to
/// provide the original register byte layout. The fixed scratch buffer covers
/// both architecture-specific CONTEXT maps and their synthetic control slots.
pub fn build_stacktrace_with_register_values(
    debugger: &Target,
    register_map: &RegisterMap,
    values: &HashMap<String, u64>,
    limit: usize,
) -> RecoveredStackTrace {
    let register_buffer_size = match debugger.arch() {
        Arch::Amd64 => context::REGISTER_BUFFER_SIZE,
        Arch::Arm64 => context_arm64::REGISTER_BUFFER_SIZE,
    };
    let mut bytes = vec![0u8; register_buffer_size];
    for (name, value) in values {
        let _ = register_map.write_u64(name, &mut bytes, *value);
    }
    let dtb_name = debugger.arch().dtb_register();
    if lookup_register(values, dtb_name)
        .filter(|dtb| *dtb != 0)
        .is_none()
    {
        let _ = register_map.write_u64(dtb_name, &mut bytes, debugger.current_dtb());
    }
    build_stacktrace_with_context(debugger, register_map, &bytes, limit)
}

/// Resolve the frame-relative local base for a sparse register context. This
/// mirrors the first frame of a recovered trace without requiring a backend
/// register packet, so `dv` uses unwind metadata rather than assuming RBP is a
/// frame pointer.
pub fn frame_base_for_register_values(
    debugger: &Target,
    values: &HashMap<String, u64>,
) -> Option<u64> {
    let lookup = |name: &str| lookup_register(values, name);
    let context = RegisterContext::from_lookup(debugger.arch(), lookup);
    let dtb = lookup(debugger.arch().dtb_register())
        .filter(|dtb| *dtb != 0)
        .unwrap_or_else(|| debugger.current_dtb());
    let trace = resolve_thread_trace_context(debugger, dtb);
    let mut tracer = StackTracer::new(debugger, &trace);
    tracer.frame_base_for(&context)
}

/// The caller's instruction pointer for a sparse register context: WinDbg's
/// `$ra`. One unwind step, so a scope nothing has walked for display still
/// answers `g @$ra`. `None` means the unwind step could not produce a valid
/// executable return address.
pub fn return_address_for_register_values(
    debugger: &Target,
    values: &HashMap<String, u64>,
) -> Option<u64> {
    let lookup = |name: &str| lookup_register(values, name);
    lookup("rip").or_else(|| lookup("pc"))?;
    let mut context = RegisterContext::from_lookup(debugger.arch(), lookup);
    let dtb = lookup(debugger.arch().dtb_register())
        .filter(|dtb| *dtb != 0)
        .unwrap_or_else(|| debugger.current_dtb());
    let trace = resolve_thread_trace_context(debugger, dtb);
    let mut tracer = StackTracer::new(debugger, &trace);
    match tracer.unwind_once(&mut context) {
        Unwound::Frame { .. } => (context.rip != 0).then_some(context.rip),
        Unwound::Stop => None,
    }
}

/// Recover the build-specific context-switch frame using the matching image's
/// unwind metadata. `KTHREAD.KernelStack` is the stack pointer the switch
/// saved; no private `_KSWITCH_FRAME` layout or build table is needed.
fn recover_context_switch_seed(
    debugger: &Target,
    process_dtb: Dtb,
    kernel_stack: VirtAddr,
) -> Result<RegisterContext> {
    let ntoskrnl = &debugger.guest()?.ntoskrnl;
    let swap_context = ntoskrnl.symbol("SwapContext")?.address().0;
    let ki_swap_context = ntoskrnl.symbol("KiSwapContext")?.address().0;
    let trace = resolve_thread_trace_context(debugger, process_dtb);
    let mut tracer = StackTracer::new(debugger, &trace);
    let (ki_swap_start, ki_swap_end) = function_range(debugger, &trace, ki_swap_context)
        .ok_or_else(|| Error::DebugInfo("KiSwapContext has no usable PE unwind metadata".into()))?;

    let seed = match debugger.arch() {
        // KernelStack is rsp inside SwapContext's body, so one unwind step
        // from there lands in KiSwapContext.
        Arch::Amd64 => {
            let body = tracer.function_body_amd64(swap_context).ok_or_else(|| {
                Error::DebugInfo("SwapContext has no usable PE unwind metadata".into())
            })?;
            let mut seed = RegisterContext::new(body, kernel_stack.0);
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
            if seed.rsp <= kernel_stack.0 || !(ki_swap_start..ki_swap_end).contains(&seed.rip) {
                return Err(Error::DebugInfo(format!(
                    "SwapContext returned outside KiSwapContext ({:#x}, RSP {:#x})",
                    seed.rip, seed.rsp
                )));
            }
            seed
        }
        // KernelStack is sp in KiSwapContext's body, where its prolog saved
        // the nonvolatile registers before it called SwapContext; the thread
        // resumes at that call's return.
        Arch::Arm64 => {
            let mut code = vec![0u8; (ki_swap_end - ki_swap_start) as usize];
            debugger
                .address_space(trace.kernel_dtb)
                .read_bytes(VirtAddr(ki_swap_start), &mut code)?;
            let resume =
                call_return_address(&code, ki_swap_start, swap_context).ok_or_else(|| {
                    Error::DebugInfo("KiSwapContext does not call SwapContext".into())
                })?;
            let mut seed = RegisterContext::new(resume, kernel_stack.0);
            seed.after_call = true;
            seed.regs[29] = tracer.frame_pointer_at_body_arm64(resume - 4, kernel_stack.0);
            seed
        }
    };

    // `seed` stays private to the stack walker: it is not a complete register
    // context (volatile registers and flags are never preserved).
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

fn switch_seed_is_plausible(thread: &ThreadInfo, seed: &RegisterContext) -> bool {
    let (Some(kernel_stack), Some(stack_limit), Some(stack_base)) =
        (thread.kernel_stack, thread.stack_limit, thread.stack_base)
    else {
        return false;
    };
    thread.kernel_stack_resident != Some(false)
        && looks_like_kernel_pointer(seed.rip)
        && kernel_stack >= stack_limit
        && kernel_stack < stack_base
        && seed.rsp >= stack_limit.0
        && seed.rsp <= stack_base.0
}

/// Build a non-running Windows thread's kernel stack, keeping the sparse
/// registers recovered for each frame, without manufacturing a persistent
/// register context. A real KTRAP_FRAME is preferred; otherwise the
/// context-switch bootstrap remains private to this stack walk.
///
/// A host that only renders frames wants [`build_parked_thread_stack`]; a host
/// that also selects frames and resolves their locals (the DAP call stack)
/// needs the per-frame registers this returns.
pub fn build_parked_thread_recovered_stack(
    debugger: &Target,
    thread: &ThreadInfo,
    limit: usize,
) -> Result<ThreadRecoveredStack> {
    let process_dtb = debugger.thread_process_dtb(thread).ok_or_else(|| {
        Error::DebugInfo("parked thread owning process DTB is unavailable".into())
    })?;
    let trace = resolve_thread_trace_context(debugger, process_dtb);
    // The trap frame and the context-switch frame both live on the kernel
    // stack: a terminated thread has freed it, and a long wait gets it
    // swapped out. Either way there is nothing to walk.
    if thread.state == Some(KTHREAD_STATE_TERMINATED) {
        return Err(Error::DebugInfo(
            "parked thread stack unavailable: the thread has terminated".into(),
        ));
    }
    if thread.kernel_stack_resident == Some(false) {
        return Err(Error::DebugInfo(
            "parked thread stack unavailable: kernel stack is not resident (swapped out)".into(),
        ));
    }
    let mut failures = Vec::new();

    if let Some(address) = thread.trap_frame {
        match decode_ktrap_frame_for_thread(debugger, process_dtb, address)
            .ok()
            .and_then(|registers| RegisterContext::from_saved(&registers))
        {
            Some(seed) if seed.rip != 0 && seed.rsp != 0 => {
                return Ok(ThreadRecoveredStack {
                    source: ThreadStackSource::TrapFrame { address },
                    stacktrace: build_recovered_stacktrace_seeded(
                        debugger,
                        &trace,
                        seed,
                        FrameSource::Seed,
                        limit,
                        HashMap::from([(debugger.arch().dtb_register().to_string(), process_dtb)]),
                    ),
                });
            }
            _ => failures.push("KTHREAD.TrapFrame is absent or unusable".to_string()),
        }
    } else {
        failures.push("KTHREAD.TrapFrame is not present".to_string());
    }

    if let Some(kernel_stack) = thread.kernel_stack {
        let pdb_seed = decode_kswitch_frame_seed(debugger, process_dtb, kernel_stack)
            .ok()
            .and_then(|registers| RegisterContext::from_saved(&registers));
        let seed = match pdb_seed {
            Some(seed) => Ok(seed),
            None => recover_context_switch_seed(debugger, process_dtb, kernel_stack),
        };
        match seed {
            Ok(seed) if switch_seed_is_plausible(thread, &seed) => {
                return Ok(ThreadRecoveredStack {
                    source: ThreadStackSource::ContextSwitch { kernel_stack },
                    stacktrace: build_recovered_stacktrace_seeded(
                        debugger,
                        &trace,
                        seed,
                        FrameSource::Seed,
                        limit,
                        HashMap::from([(debugger.arch().dtb_register().to_string(), process_dtb)]),
                    ),
                });
            }
            Ok(_) => failures.push(
                "context-switch seed is outside the captured resident kernel stack".to_string(),
            ),
            Err(error) => failures.push(format!("context-switch seed is unavailable: {error}")),
        }
    } else {
        failures.push("KTHREAD.KernelStack is not present".to_string());
    }

    Err(Error::DebugInfo(format!(
        "parked thread stack unavailable: {}",
        failures.join("; ")
    )))
}

/// The frames of a parked thread's stack without the recovered registers, for
/// hosts that only render the walk (`k`, `!thread`, `!stacks`).
pub fn build_parked_thread_stack(
    debugger: &Target,
    thread: &ThreadInfo,
    limit: usize,
) -> Result<ThreadStackTrace> {
    let recovered = build_parked_thread_recovered_stack(debugger, thread, limit)?;
    Ok(ThreadStackTrace {
        source: recovered.source,
        stacktrace: StackTrace {
            frames: recovered
                .stacktrace
                .frames
                .into_iter()
                .map(|frame| frame.frame)
                .collect(),
            truncated: recovered.stacktrace.truncated,
        },
    })
}

impl RegisterContext {
    fn new(rip: u64, rsp: u64) -> Self {
        Self {
            rip,
            rsp,
            regs: [None; REGISTER_SLOTS],
            after_call: false,
        }
    }

    /// The context of a stopped frame whose registers `lookup` answers by
    /// name.
    fn from_lookup(arch: Arch, lookup: impl Fn(&str) -> Option<u64>) -> Self {
        let mut context = Self::new(
            lookup("rip").or_else(|| lookup("pc")).unwrap_or(0),
            lookup("rsp").or_else(|| lookup("sp")).unwrap_or(0),
        );
        match arch {
            Arch::Amd64 => {
                for (slot, name) in context.regs.iter_mut().zip(AMD64_REGISTER_NAMES) {
                    *slot = lookup(name);
                }
            }
            Arch::Arm64 => {
                for (slot, name) in context.regs.iter_mut().zip(ARM64_REGISTER_NAMES) {
                    *slot = lookup(name);
                }
                for (alias, index) in ARM64_REGISTER_ALIASES {
                    if context.regs[index].is_none() {
                        context.regs[index] = lookup(alias);
                    }
                }
            }
        }
        context
    }

    /// Every register the context knows, under each name a host may ask for
    /// it by.
    fn named_values(&self, arch: Arch) -> Vec<(&'static str, u64)> {
        let mut values = Vec::new();
        match arch {
            Arch::Amd64 => {
                for (register, name) in AMD64_REGISTER_NAMES.iter().enumerate() {
                    if let Some(value) = self.get(register as u8) {
                        values.push((*name, value));
                    }
                }
                values.extend([("rip", self.rip), ("rsp", self.rsp)]);
            }
            Arch::Arm64 => {
                for (value, name) in self.regs.iter().zip(ARM64_REGISTER_NAMES) {
                    if let Some(value) = value {
                        values.push((name, *value));
                    }
                }
                for (alias, index) in ARM64_REGISTER_ALIASES {
                    if let Some(value) = self.regs[index] {
                        values.push((alias, value));
                    }
                }
                values.extend([
                    ("pc", self.rip),
                    ("sp", self.rsp),
                    ("rip", self.rip),
                    ("rsp", self.rsp),
                ]);
            }
        }
        values
    }

    fn from_saved(registers: &SavedThreadRegisters) -> Option<Self> {
        if let Some(arm64) = registers.arm64.as_ref() {
            let mut context = Self::new(arm64.pc?, arm64.sp?);
            for (slot, value) in context.regs.iter_mut().zip(arm64.x) {
                *slot = value;
            }
            context.regs[29] = context.regs[29].or(arm64.fp);
            context.regs[30] = context.regs[30].or(arm64.lr);
            return Some(context);
        }
        let mut context = Self::new(registers.rip?, registers.rsp?);
        for (slot, name) in context.regs.iter_mut().zip(AMD64_REGISTER_NAMES) {
            *slot = registers.get(name);
        }
        Some(context)
    }

    /// An x64 register by encoding number; 4 is rsp.
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
    /// The traced thread's address space: its process's page-table root when
    /// the walk identified one, else the root it was given.
    pub fn dtb(&self) -> Dtb {
        self.process_dtb.unwrap_or(self.active_dtb)
    }

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
                        dtb: self.dtb(),
                    })
            })
            .or_else(|| {
                self.foreign_image
                    .as_ref()
                    .filter(|image| image.contains_address(VirtAddr(address)))
                    .map(|info| OwnedModule {
                        info: info.clone(),
                        dtb: self.active_dtb,
                    })
            })
    }
}

impl StackTracer<'_> {
    /// Step `context` to its caller's frame. Registers the caller cannot
    /// rely on (volatile across a call) come back unknown.
    fn unwind_once(&mut self, context: &mut RegisterContext) -> Unwound {
        match self.target.arch() {
            Arch::Amd64 => {
                let unwound = self.unwind_once_amd64(context);
                if matches!(unwound, Unwound::Frame { .. }) {
                    for index in AMD64_VOLATILE {
                        context.regs[index] = None;
                    }
                }
                unwound
            }
            Arch::Arm64 => self.unwind_once_arm64(context),
        }
    }

    /// Resolve the stack base PDB frame-relative locations are addressed from
    /// for the function containing `context.rip`.
    fn frame_base_for(&mut self, context: &RegisterContext) -> Option<u64> {
        match self.target.arch() {
            Arch::Amd64 => self.frame_base_for_amd64(context),
            Arch::Arm64 => self.frame_base_for_arm64(context),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RegisterContext;
    use crate::target::SavedThreadRegisters;

    #[test]
    fn saved_register_context_preserves_missing_values() {
        let registers = SavedThreadRegisters {
            rip: Some(0xffff_f800_1000),
            rsp: Some(0xffff_a000_2000),
            rbp: Some(0xffff_a000_2100),
            ..SavedThreadRegisters::default()
        };
        let context = RegisterContext::from_saved(&registers).unwrap();
        assert_eq!(context.rip, 0xffff_f800_1000);
        assert_eq!(context.rsp, 0xffff_a000_2000);
        assert_eq!(context.get(5), Some(0xffff_a000_2100));
        assert_eq!(context.get(3), None);

        let missing_rsp = SavedThreadRegisters {
            rip: Some(0xffff_f800_1000),
            ..SavedThreadRegisters::default()
        };
        assert!(RegisterContext::from_saved(&missing_rsp).is_none());
    }
}
