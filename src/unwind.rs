use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::{Arc, OnceLock};

use pelite::pe64::{Pe, PeView, image::IMAGE_DIRECTORY_ENTRY_EXCEPTION};

use crate::{
    backend::MemoryOps,
    breakpoints::BreakpointManager,
    bugchecks::looks_like_kernel_pointer,
    error::{Error, Result},
    gdb::RegisterMap,
    guest::{Image, ModuleInfo, ProcessInfo, SecureKernel, hypercalls::HypervisorSymbols},
    memory::{AddressSpace, DTB_IDENTITY},
    pe::{CodeLayout, PeImage},
    phys::PhysMem,
    symbols::{
        CodeFrame, ModuleSymbolStatus, SourceLocation, SymbolStore, format_symbol_with_offset,
    },
    target::{
        ForeignModules, HYPERVISOR_CONTEXT, KTHREAD_STATE_RUNNING, KTHREAD_STATE_TERMINATED,
        SavedThreadRegisters, SavedVtlContext, Target, ThreadInfo, lookup_register,
    },
    trapframe::{decode_kswitch_frame_seed, decode_ktrap_frame_for_thread},
    types::{Arch, CodeMachine, Dtb, VirtAddr},
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
mod arm64ec;
pub mod prolog;
mod tracer;
mod walk;
mod wow64;

pub use amd64::{
    FunctionEntryDetail, HandlerDetail, RuntimeFunctionDetail, UnwindCodeDetail, UnwindDetail,
    UnwindInfoDetail,
};
use amd64::{Lookup, RUNTIME_FUNCTION_SIZE, lookup_runtime_function, runtime_function_at};
pub use arm64::{Arm64CodeDetail, Arm64UnwindDetail};
use arm64::{Arm64Lookup, call_return_address, lookup_arm64_runtime_function};
use walk::{build_recovered_stacktrace_seeded, ensure_module_symbols};

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
    /// When `foreign_image` is the Windows hypervisor's, where its functions
    /// begin and its stacks start, for frames its `.pdata` cannot unwind.
    pub hypervisor: Option<Arc<HypervisorSymbols>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameSource {
    Current,
    Seed,
    Unwind,
    /// Unwound by analyzing its function's prolog, for code whose unwind data
    /// is not mapped (the Windows hypervisor's without its file).
    Prolog,
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
            FrameSource::Prolog => "prolog",
            FrameSource::Scan => "scan",
        }
    }
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub sp: u64,
    pub ip: u64,
    /// `module!procedure+offset` at `ip`; for an inline frame,
    /// `module!function`, the function inlined.
    pub symbol: String,
    pub source: FrameSource,
    /// The frame's source line (see [`SymbolStore::frame_source_location`]).
    pub source_location: Option<SourceLocation>,
    /// The hardware-pushed machine frame the walk crossed to reach this
    /// frame: the trap or interrupt that stopped it here. On Windows it is the
    /// tail of the handler's `_KTRAP_FRAME` (see
    /// [`crate::trapframe::ktrap_frame_at_machine_frame`]).
    pub machine_frame: Option<u64>,
    /// Where the frame is in code, and which of the frames there it is.
    pub code: CodeFrame,
    /// The frame is a call the compiler inlined into the code of the
    /// physical frame after it: it has no stack frame of its own, and shares
    /// that frame's `ip`, `sp`, registers and `machine_frame`.
    pub inline: bool,
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
    /// The parked thread (ETHREAD) whose saved context the walk started
    /// from, `None` for a walk seeded from registers. Selecting another of
    /// its frames walks the thread again, as `k` does, rather than walking
    /// from its first frame's registers, which would miss what only the
    /// thread walk adds (its WOW64 x86 frames).
    pub thread: Option<VirtAddr>,
}

impl RecoveredStackTrace {
    fn new(trace: &ThreadTraceContext) -> Self {
        Self {
            frames: Vec::new(),
            truncated: 0,
            dtb: trace.dtb(),
            thread: None,
        }
    }

    /// The frames alone, for hosts that only render the walk.
    pub fn into_stacktrace(self) -> StackTrace {
        StackTrace {
            frames: self.frames.into_iter().map(|frame| frame.frame).collect(),
            truncated: self.truncated,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadStackSource {
    /// The registers of the vCPU running the thread.
    Live,
    /// The VTL0 state the Windows hypervisor saved for the vCPU running the
    /// thread, which is halted in the hypervisor.
    SavedVtl0,
    TrapFrame {
        address: VirtAddr,
    },
    ContextSwitch {
        kernel_stack: VirtAddr,
    },
}

impl ThreadStackSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::SavedVtl0 => "saved VTL0 context",
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
    /// The hardware-pushed machine frame the last unwind step crossed to
    /// reach this frame (AMD64 `UWOP_PUSH_MACHFRAME`): this frame was
    /// interrupted there rather than called.
    machine_frame: Option<u64>,
}

/// Outcome of unwinding one frame to its caller
enum Unwound {
    /// Could not unwind further; the caller falls back to a stack scan
    Stop,
    /// Advanced to the caller. `stack_switch` is set when we crossed a hardware
    /// trap/interrupt frame, where rsp may move to a different stack (e.g. an IST
    /// or the idle stack) and so need not be greater than the previous rsp.
    Frame { stack_switch: bool },
    /// Advanced to the caller by prolog analysis ([`prolog`]): a frame of
    /// code whose unwind data is not mapped.
    Prolog,
}

#[derive(Debug, Clone)]
struct CachedModule {
    info: ModuleInfo,
    // Arc so a frame walk can cheaply take its own handle to the image and
    // release the borrow on the cache while parsing unwind data
    image: Arc<PeImage>,
    executable_ranges: Vec<(u32, u32)>,
    /// Which instruction set each part of the image is, and where each
    /// one's runtime functions are; `None` for a machine the walk does not
    /// know.
    layout: Option<Arc<CodeLayout>>,
}

#[derive(Debug, Clone)]
struct OwnedModule {
    info: ModuleInfo,
    dtb: Dtb,
}

struct StackTracer<'a> {
    target: &'a Target,
    trace: &'a ThreadTraceContext,
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

/// Whose page-table root a thread runs on.
enum RootOwner {
    Kernel,
    SecureKernel(Arc<SecureKernel>),
    Process(ProcessInfo),
    /// None of NT's: the Windows hypervisor, VTL1 code not yet recognized,
    /// or a root this session cannot place.
    Unknown,
}

/// Whether a thread on root `cr3_masked` runs in the kernel's view.
fn in_kernel_root(debugger: &Target, cr3_masked: u64) -> bool {
    let kernel_dtb = debugger.kernel_dtb();
    // Triage dumps use DTB_IDENTITY because page-table walks are impossible,
    // so force the kernel context regardless of the thread's real CR3.
    kernel_dtb == DTB_IDENTITY || cr3_masked == kernel_dtb & debugger.arch().dtb_page_mask()
}

fn root_owner(debugger: &Target, cr3_masked: u64) -> RootOwner {
    if in_kernel_root(debugger, cr3_masked) {
        return RootOwner::Kernel;
    }
    // A root mapping the secure kernel: its modules and system root, so code
    // reads, symbols and unwinding use the secure kernel, never NT's.
    if debugger.recognize_secure_root(cr3_masked)
        && let Some(secure) = debugger
            .guest
            .as_ref()
            .and_then(|guest| guest.cached_secure_kernel())
    {
        return RootOwner::SecureKernel(secure);
    }
    match debugger.process_for_cr3(cr3_masked) {
        Some(process) => RootOwner::Process(process),
        None => RootOwner::Unknown,
    }
}

/// The root a thread on `cr3` runs in, as [`resolve_thread_trace_context`]
/// reports it (`active_dtb`) without walking any module list: `cr3` without
/// its PCID and flush bits, or the kernel's view on a target that cannot
/// walk page tables.
pub fn thread_root(debugger: &Target, cr3: u64) -> Dtb {
    let cr3_masked = cr3 & debugger.arch().dtb_page_mask();
    if in_kernel_root(debugger, cr3_masked) {
        debugger.kernel_dtb()
    } else {
        cr3_masked
    }
}

pub fn resolve_thread_trace_context(debugger: &Target, cr3: u64) -> ThreadTraceContext {
    thread_trace_context(debugger, cr3, true)
}

/// [`resolve_thread_trace_context`], walking a process root's own module
/// list (its PEB loader list) only when `process_modules` asks for it.
fn thread_trace_context(debugger: &Target, cr3: u64, process_modules: bool) -> ThreadTraceContext {
    let cr3_masked = cr3 & debugger.arch().dtb_page_mask();
    let kernel_dtb = debugger.kernel_dtb();
    match root_owner(debugger, cr3_masked) {
        RootOwner::Kernel => ThreadTraceContext {
            description: "kernel".to_string(),
            active_dtb: kernel_dtb,
            kernel_dtb,
            process_dtb: None,
            kernel_modules: debugger.kernel_modules().unwrap_or_default(),
            process_modules: Vec::new(),
            foreign_image: None,
            hypervisor: None,
        },
        RootOwner::SecureKernel(secure) => ThreadTraceContext {
            description: "VTL1".to_string(),
            active_dtb: cr3_masked,
            kernel_dtb: secure.image.dtb(),
            process_dtb: None,
            kernel_modules: debugger
                .guest
                .as_ref()
                .and_then(|guest| secure.modules(guest).ok())
                .unwrap_or_default(),
            process_modules: Vec::new(),
            foreign_image: None,
            hypervisor: None,
        },
        RootOwner::Process(proc_info) => ThreadTraceContext {
            description: format!("{} ({})", proc_info.name, proc_info.pid),
            active_dtb: cr3_masked,
            kernel_dtb,
            process_dtb: Some(proc_info.dtb),
            kernel_modules: debugger.kernel_modules().unwrap_or_default(),
            process_modules: debugger
                .guest
                .as_ref()
                .filter(|_| process_modules)
                .and_then(|guest| guest.process_modules(&proc_info).ok())
                .unwrap_or_default(),
            foreign_image: None,
            hypervisor: None,
        },
        RootOwner::Unknown => ThreadTraceContext {
            description: UNKNOWN_CONTEXT.to_string(),
            active_dtb: cr3_masked,
            kernel_dtb,
            process_dtb: None,
            kernel_modules: debugger.kernel_modules().unwrap_or_default(),
            process_modules: Vec::new(),
            foreign_image: None,
            hypervisor: None,
        },
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
        let symbol = try_format(module.dtb)
            .or_else(|| {
                ensure_module_symbols(debugger, trace, std::iter::once(addr));
                try_format(module.dtb)
            })
            .or_else(|| {
                split_function(debugger, trace, module.dtb, addr)
                    .map(|(module, name, offset)| format_symbol_with_offset(&module, &name, offset))
            });
        return Some(symbol.unwrap_or_else(|| {
            // The module has no PDB, or its fetch is still running.
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

/// The symbol nearest below `address` in root `dtb`, as `ln` names it: the
/// PDB's, else, for code split off from its function, that function's (see
/// [`split_function`]). `(module, symbol, offset)`.
pub fn nearest_symbol(
    debugger: &Target,
    dtb: Dtb,
    address: VirtAddr,
) -> Option<(String, String, u32)> {
    debugger
        .symbols
        .find_closest_symbol_for_address(dtb, address)
        .or_else(|| {
            let trace = resolve_thread_trace_context(debugger, dtb);
            let module = trace.module_for_address(address.0)?;
            split_function(debugger, &trace, module.dtb, address.0)
        })
}

/// `addr` named after its function when no symbol is near it but its code
/// is a fragment the compiler split off from a function the PDB names, as
/// profile-guided optimization moves cold blocks far from every symbol:
/// its function-table entry chains to that function's
/// (`nt!IopXxxControlFile+0x22bddf`). Only a module whose symbols are
/// loaded is looked at, so frames in modules without a PDB read no unwind
/// data. `(module, symbol, offset)`.
fn split_function(
    debugger: &Target,
    trace: &ThreadTraceContext,
    dtb: Dtb,
    addr: u64,
) -> Option<(String, String, u32)> {
    let mut tracer = StackTracer::new(debugger, trace);
    let base = tracer.module_containing(addr)?.info.base_address;
    if !matches!(
        debugger.symbols.module_symbol_status(dtb, base),
        Some(ModuleSymbolStatus::Loaded)
    ) || tracer.code_machine_at(addr) != CodeMachine::Amd64
    {
        return None;
    }
    let lookup = |tracer: &StackTracer<'_>| {
        let (image, layout) = tracer.module_code(addr)?;
        let found = amd64::primary_function_begin(&image, layout.as_deref(), base.0, addr);
        Some((found, image.is_complete()))
    };
    let (mut found, complete) = lookup(&tracer)?;
    if matches!(found, amd64::PrimaryLookup::Holed)
        && !complete
        && tracer.upgrade_module_image(addr)
    {
        found = lookup(&tracer)?.0;
    }
    let amd64::PrimaryLookup::Found(start) = found else {
        return None;
    };
    // The function must start at the symbol, not somewhere after it.
    let (module, name, offset) = debugger
        .symbols
        .find_closest_symbol_for_address(dtb, VirtAddr(start))?;
    if offset != 0 {
        return None;
    }
    let offset = u32::try_from(addr.checked_sub(start)?).ok()?;
    Some((module, name, offset))
}

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
    code_trace_context_at(debugger, cr3, rip, true)
}

/// [`resolve_thread_trace_context_at`], walking a process root's module
/// list only when `process_modules` asks for it.
fn code_trace_context_at(
    debugger: &Target,
    cr3: u64,
    rip: u64,
    process_modules: bool,
) -> ThreadTraceContext {
    let mut trace = thread_trace_context(debugger, cr3, process_modules);
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
    trace.hypervisor = code.hypervisor;
    trace
}

/// Whether a vCPU at `rip` on root `cr3` is halted in the Windows
/// hypervisor, as [`resolve_thread_trace_context_at`] names it. A root that
/// is NT's never is, so its module lists are not walked to find out.
pub fn halted_in_windows_hypervisor(debugger: &Target, cr3: u64, rip: u64) -> bool {
    matches!(
        root_owner(debugger, cr3 & debugger.arch().dtb_page_mask()),
        RootOwner::Unknown
    ) && resolve_thread_trace_context_at(debugger, cr3, rip).description == HYPERVISOR_CONTEXT
}

/// The guest partition's virtual processor (WSL2, a Hyper-V VM) that a vCPU
/// at `rip` on root `cr3`, on NT processor `processor`, runs because the
/// Windows hypervisor put it on that processor, as `~` names it
/// (`partition 0x6 VP 3`). The vCPU then shows that guest's registers, at
/// code in no root of NT's that is neither the hypervisor's nor VTL1's,
/// and the processor block names the guest's VP current; NT's state there
/// waits in its root VP's saved state until the hypervisor runs that VP
/// again. The partitions are walked only for a vCPU whose code ntoseye
/// cannot place.
pub fn guest_vp_running(
    debugger: &Target,
    cr3: u64,
    rip: u64,
    processor: Option<u16>,
) -> Option<String> {
    if !matches!(
        root_owner(debugger, cr3 & debugger.arch().dtb_page_mask()),
        RootOwner::Unknown
    ) || resolve_thread_trace_context_at(debugger, cr3, rip).description != UNKNOWN_CONTEXT
    {
        return None;
    }
    debugger.guest_vp_label(processor?)
}

/// [`try_format_symbol`] for code a vCPU runs at `rip` with root `cr3`,
/// named in that vCPU's own address space (code outside NT, such as the
/// Windows hypervisor, for what it is) whatever the inspection scope is.
/// Kernel code in an NT root is named from the modules whose symbols are
/// loaded before any module list is walked: the lists are walked again at
/// every halt, which over KD memory costs hundreds of reads a stop.
pub fn try_format_symbol_at(debugger: &Target, cr3: u64, rip: u64) -> Option<String> {
    let kernel = BreakpointManager::is_kernel_space(debugger.arch(), VirtAddr(rip));
    if kernel
        && matches!(
            root_owner(debugger, cr3 & debugger.arch().dtb_page_mask()),
            RootOwner::Kernel | RootOwner::Process(_)
        )
        && let Some(symbol) = debugger
            .symbols
            .format_closest_symbol_for_address(debugger.kernel_dtb(), VirtAddr(rip))
    {
        return Some(symbol);
    }
    try_format_symbol(
        debugger,
        &code_trace_context_at(debugger, cr3, rip, !kernel),
        rip,
    )
}

pub fn format_symbol(debugger: &Target, trace: &ThreadTraceContext, addr: u64) -> String {
    try_format_symbol(debugger, trace, addr).unwrap_or_else(|| format!("{addr:#x}"))
}

/// A VTL state the Windows hypervisor saved, with the symbol where it left
/// off.
#[derive(Debug, Clone)]
pub struct SavedVtl {
    pub context: SavedVtlContext,
    /// The symbol at the saved `rip`, resolved in the state's own address
    /// space.
    pub symbol: Option<String>,
}

impl SavedVtl {
    /// Where the state left off, as `VTL0 nt!HalProcessorIdle+0xf`, marked
    /// when it may describe the exit before the one in progress.
    pub fn describe(&self) -> String {
        let rip = self.context.state.rip;
        let place = match &self.symbol {
            Some(symbol) => format!("VTL{} {symbol}", self.context.vtl),
            None => format!("VTL{} {rip:#x}", self.context.vtl),
        };
        if self.context.may_be_stale {
            format!("{place} (may be one exit behind)")
        } else {
            place
        }
    }

    /// [`Self::describe`] with the hypercall of a VMCALL exit, as one-line
    /// summaries of the vCPU (thread names, the MCP trailer) show it: `VTL0
    /// hvcall!Hypercall (hypercall 0x0003 HvCallFlushVirtualAddressList rep
    /// 0/12)`.
    pub fn summary(&self) -> String {
        match self.context.exit_detail() {
            Some(detail) => format!("{} ({detail})", self.describe()),
            None => self.describe(),
        }
    }

    /// Whether a one-line summary of the vCPU names this state: VTL0's
    /// always, VTL1's when its eVMCS is the current one (the hypervisor was
    /// entered from VTL1, or is about to enter it).
    pub fn summarized(&self) -> bool {
        self.context.vtl == 0 || self.context.state.current
    }
}

/// The VTL states the Windows hypervisor saved for the virtual processor a
/// vCPU halted in it runs, each with its symbol. `cr3` is the vCPU's and
/// `processor` its NT processor, as in [`Target::saved_vtl_contexts`].
pub fn saved_vtls(
    debugger: &Target,
    cr3: u64,
    rip: u64,
    processor: Option<u16>,
) -> Result<Vec<SavedVtl>> {
    Ok(debugger
        .saved_vtl_contexts(cr3, rip, processor)?
        .into_iter()
        .map(|context| {
            let symbol = try_format_symbol_at(debugger, context.state.cr3, context.state.rip);
            SavedVtl { context, symbol }
        })
        .collect())
}

pub fn preferred_code_dtb(trace: &ThreadTraceContext, addr: u64) -> Dtb {
    trace
        .module_for_address(addr)
        .map(|module| module.dtb)
        .unwrap_or(trace.active_dtb)
}

/// The frames the physical frame at `ip` shows as, innermost first: the
/// calls the compiler inlined into its code, then the frame itself.
/// `returned` says `ip` is where a call returns to, so the frame's code is
/// the call's (`ip - 1`) rather than the next instruction's.
fn expand_frame(
    debugger: &Target,
    trace: &ThreadTraceContext,
    ip: u64,
    sp: u64,
    source: FrameSource,
    machine_frame: Option<u64>,
    returned: bool,
) -> Vec<StackFrame> {
    let address = VirtAddr(if returned { ip.wrapping_sub(1) } else { ip });
    let module = trace.module_for_address(address.0);
    let inline = module
        .as_ref()
        .map(|module| debugger.symbols.inline_frames(module.dtb, address))
        .unwrap_or_default();
    let physical = CodeFrame {
        address,
        inline_depth: inline.len(),
    };
    let mut frames: Vec<StackFrame> = inline
        .into_iter()
        .enumerate()
        .map(|(inline_depth, frame)| StackFrame {
            sp,
            ip,
            symbol: frame.symbol,
            source,
            source_location: frame.location,
            machine_frame,
            code: CodeFrame {
                address,
                inline_depth,
            },
            inline: true,
        })
        .collect();
    frames.push(StackFrame {
        sp,
        ip,
        symbol: format_symbol(debugger, trace, ip),
        source,
        source_location: module
            .and_then(|module| debugger.symbols.source_location(module.dtb, address)),
        machine_frame,
        code: physical,
        inline: false,
    });
    frames
}

fn image_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The RVA range of the runtime functions for `image`'s code of `machine`:
/// the exception directory, or in a hybrid image the table for the other
/// instruction set (see [`CodeLayout::runtime_functions`]). `None` when the
/// image has none.
fn runtime_functions(
    image: &PeImage,
    layout: Option<&CodeLayout>,
    machine: CodeMachine,
) -> Option<Range<usize>> {
    let view = PeView::from_bytes(image.headers()).ok()?;
    let exception = view
        .data_directory()
        .get(IMAGE_DIRECTORY_ENTRY_EXCEPTION)
        .map(|directory| (directory.VirtualAddress, directory.Size));
    let (start, size) = match layout {
        Some(layout) => layout.runtime_functions(machine, exception)?,
        None => exception?,
    };
    if size == 0 {
        return None;
    }
    let start = start as usize;
    Some(start..start.checked_add(size as usize)?)
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
    fn range(
        image: &PeImage,
        layout: Option<&CodeLayout>,
        base: u64,
        address: u64,
        machine: CodeMachine,
    ) -> Option<(u64, u64)> {
        let rva = u32::try_from(address.checked_sub(base)?).ok()?;
        let pdata = runtime_functions(image, layout, machine)?;
        let (begin, end) = match machine {
            CodeMachine::Amd64 => {
                let Lookup::Found(function) = lookup_runtime_function(
                    pdata.len() / RUNTIME_FUNCTION_SIZE,
                    |index| runtime_function_at(image, pdata.start, index),
                    rva,
                ) else {
                    return None;
                };
                (function.BeginAddress, function.EndAddress)
            }
            CodeMachine::Arm64 => match lookup_arm64_runtime_function(image, pdata, rva) {
                Arm64Lookup::Found(function) => (function.begin, function.end),
                Arm64Lookup::Missing | Arm64Lookup::Unreadable => return None,
            },
            // x86 code has no runtime functions.
            CodeMachine::X86 => return None,
        };
        Some((base + u64::from(begin), base + u64::from(end)))
    }

    let mut tracer = StackTracer::new(debugger, trace);
    let base = tracer.module_containing(address)?.info.base_address.0;
    let machine = tracer.code_machine_at(address);
    let (image, layout) = tracer.module_code(address)?;
    if let Some(found) = range(&image, layout.as_deref(), base, address, machine) {
        return Some(found);
    }

    if !image.is_complete() && tracer.upgrade_module_image(address) {
        let (image, layout) = tracer.module_code(address)?;
        return range(&image, layout.as_deref(), base, address, machine);
    }

    None
}

/// The function-table entry covering `address` and its unwind data
/// (`.fnent`): AMD64's with its chained parents, or ARM64's packed or
/// `.xdata` form. Paged-out `.pdata` or `.xdata` is read from the matched
/// on-disk image, as the unwinder does.
pub fn function_entry(
    debugger: &Target,
    trace: &ThreadTraceContext,
    address: u64,
) -> Result<FunctionEntryDetail> {
    let mut tracer = StackTracer::new(debugger, trace);
    let Some(module) = tracer.module_containing(address) else {
        return Err(Error::DebugInfo(format!(
            "{address:#x} is not in a loaded module"
        )));
    };
    let (base, module) = (module.info.base_address.0, module.info.short_name.clone());
    let machine = tracer.code_machine_at(address);
    if machine == CodeMachine::X86 {
        return Err(Error::DebugInfo(format!(
            "{address:#x} is x86 code, which has no function table"
        )));
    }
    let symbol = |address| format_symbol(debugger, trace, address);
    let lookup = |tracer: &StackTracer<'_>| {
        let (image, layout) = tracer.module_code(address)?;
        let layout = layout.as_deref();
        let found = if machine == CodeMachine::Arm64 {
            arm64::describe_arm64_function_entry(&image, layout, base, address, symbol)
        } else {
            amd64::describe_function_entry(&image, layout, base, address, symbol)
        };
        Some((found, image.is_complete()))
    };
    let unreadable = || Error::DebugInfo(format!("the image of {module} is unreadable"));
    let (mut found, complete) = lookup(&tracer).ok_or_else(unreadable)?;
    if matches!(found, amd64::EntryLookup::Holed)
        && !complete
        && tracer.upgrade_module_image(address)
    {
        found = lookup(&tracer).ok_or_else(unreadable)?.0;
    }
    match found {
        amd64::EntryLookup::Found {
            entries,
            incomplete,
        } => Ok(FunctionEntryDetail {
            module,
            image_base: base,
            entries,
            incomplete,
        }),
        amd64::EntryLookup::Leaf => Err(Error::DebugInfo(format!(
            "no function table entry in {module} covers {address:#x}; a leaf function has none"
        ))),
        amd64::EntryLookup::Holed => Err(Error::DebugInfo(format!(
            "the function table of {module} is paged out at {address:#x}, and no on-disk image was found"
        ))),
    }
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
    build_stacktrace_from_values(debugger, register_map.to_hashmap(regs), limit)
}

/// [`build_stacktrace_with_context`] for the registers of `thread`, the
/// Windows thread they belong to: a WOW64 thread's walk goes on into its x86
/// frames where it left x86 code (see [`wow64`]).
pub fn build_thread_stacktrace(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    thread: Option<&ThreadInfo>,
    limit: usize,
) -> RecoveredStackTrace {
    let mut stack = build_stacktrace_with_context(debugger, register_map, regs, limit);
    if let Some(thread) = thread {
        let trace = resolve_thread_trace_context(debugger, stack.dtb);
        wow64::add_x86_frames(debugger, &trace, thread, &mut stack, limit);
    }
    stack
}

/// Build a recovered trace from a sparse selected-frame register map. This is
/// used after `.frame`, `.cxr`, `.trap`, or a saved VTL0 state, where there is
/// no backend packet to provide the original register byte layout. A register
/// the context lacks stays unknown to the unwinder and absent from frame 0,
/// rather than reading zero: a frame that unwinds through an unknown frame
/// pointer falls back to scanning instead of following a false one.
pub fn build_stacktrace_with_register_values(
    debugger: &Target,
    register_map: &RegisterMap,
    values: &HashMap<String, u64>,
    limit: usize,
) -> RecoveredStackTrace {
    let mut values = register_map.supplied_values(values);
    let dtb_name = debugger.arch().dtb_register();
    if values.get(dtb_name).is_none_or(|dtb| *dtb == 0) && register_map.contains(dtb_name) {
        values.insert(dtb_name.to_string(), debugger.current_dtb());
    }
    build_stacktrace_from_values(debugger, values, limit)
}

/// Walk from `values`, the registers known at the innermost frame, named as
/// [`RegisterMap::to_hashmap`] names them; absent registers are unknown.
fn build_stacktrace_from_values(
    debugger: &Target,
    values: HashMap<String, u64>,
    limit: usize,
) -> RecoveredStackTrace {
    let cr3 = values
        .get(debugger.arch().dtb_register())
        .copied()
        .unwrap_or(0);
    let context = RegisterContext::from_lookup(debugger.arch(), |name| values.get(name).copied());
    let trace = resolve_thread_trace_context_at(debugger, cr3, context.rip);
    build_recovered_stacktrace_seeded(
        debugger,
        &trace,
        context,
        FrameSource::Current,
        limit,
        values,
    )
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
        Unwound::Frame { .. } | Unwound::Prolog => (context.rip != 0).then_some(context.rip),
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
    looks_like_kernel_pointer(seed.rip)
        && kernel_stack >= stack_limit
        && kernel_stack < stack_base
        && seed.rsp >= stack_limit.0
        && seed.rsp <= stack_base.0
}

/// Build a non-running Windows thread's kernel stack, keeping the sparse
/// registers recovered for each frame, without manufacturing a persistent
/// register context. The walk starts where the thread was switched out (its
/// `KernelStack` context-switch frame), its most recent state; it unwinds
/// through a system call into user mode. `KTHREAD.TrapFrame` is only the
/// fallback: it is older (the system call's entry, or an interrupt taken
/// since), so a walk from it skips the frames above it.
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
    // A running thread's context-switch frame was consumed when it was
    // switched in, and its stack has moved on since; only its processor's
    // registers say where it is.
    if thread.state == Some(KTHREAD_STATE_RUNNING) {
        return Err(Error::DebugInfo(
            "thread stack unavailable: the thread is running, and its processor's registers are unavailable"
                .into(),
        ));
    }
    // The trap frame and the context-switch frame both live on the kernel
    // stack, which a terminated thread has freed. One a long wait swapped out
    // (`KernelStackResident` clear) usually still sits in RAM on the standby
    // list, readable through its transition PTEs, so it is walked anyway.
    if thread.state == Some(KTHREAD_STATE_TERMINATED) {
        return Err(Error::DebugInfo(
            "parked thread stack unavailable: the thread has terminated".into(),
        ));
    }
    let mut failures = Vec::new();
    if thread.kernel_stack_resident == Some(false) {
        failures.push("kernel stack is swapped out".to_string());
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
                let mut stacktrace = build_recovered_stacktrace_seeded(
                    debugger,
                    &trace,
                    seed,
                    FrameSource::Seed,
                    limit,
                    HashMap::from([(debugger.arch().dtb_register().to_string(), process_dtb)]),
                );
                wow64::add_x86_frames(debugger, &trace, thread, &mut stacktrace, limit);
                stacktrace.thread = Some(thread.ethread);
                return Ok(ThreadRecoveredStack {
                    source: ThreadStackSource::ContextSwitch { kernel_stack },
                    stacktrace,
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

    if let Some(address) = thread.trap_frame {
        match decode_ktrap_frame_for_thread(debugger, process_dtb, address)
            .ok()
            .and_then(|registers| RegisterContext::from_saved(&registers))
        {
            Some(seed) if seed.rip != 0 && seed.rsp != 0 => {
                let mut stacktrace = build_recovered_stacktrace_seeded(
                    debugger,
                    &trace,
                    seed,
                    FrameSource::Seed,
                    limit,
                    HashMap::from([(debugger.arch().dtb_register().to_string(), process_dtb)]),
                );
                wow64::add_x86_frames(debugger, &trace, thread, &mut stacktrace, limit);
                stacktrace.thread = Some(thread.ethread);
                return Ok(ThreadRecoveredStack {
                    source: ThreadStackSource::TrapFrame { address },
                    stacktrace,
                });
            }
            _ => failures.push("KTHREAD.TrapFrame is absent or unusable".to_string()),
        }
    } else {
        failures.push("KTHREAD.TrapFrame is not present".to_string());
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
        stacktrace: recovered.stacktrace.into_stacktrace(),
    })
}

impl RegisterContext {
    fn new(rip: u64, rsp: u64) -> Self {
        Self {
            rip,
            rsp,
            regs: [None; REGISTER_SLOTS],
            after_call: false,
            machine_frame: None,
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
        context.machine_frame = None;
        match self.target.arch() {
            Arch::Amd64 => {
                let unwound = self.unwind_once_amd64(context);
                let stack_switch = match unwound {
                    Unwound::Frame { stack_switch } => Some(stack_switch),
                    Unwound::Prolog => Some(false),
                    Unwound::Stop => None,
                };
                if let Some(stack_switch) = stack_switch {
                    // Crossing a machine frame lands where an interrupt or
                    // trap stopped the code, not after a call.
                    context.after_call = !stack_switch;
                    for index in AMD64_VOLATILE {
                        context.regs[index] = None;
                    }
                }
                unwound
            }
            Arch::Arm64 => match self.code_machine_at(Self::arm64_lookup_pc(context)) {
                CodeMachine::Amd64 => self.unwind_once_emulated_amd64(context),
                CodeMachine::Arm64 | CodeMachine::X86 => self.unwind_once_arm64(context),
            },
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
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::{FrameSource, RegisterContext, build_stacktrace_with_register_values};
    use crate::guest::ModuleInfo;
    use crate::guest::hypercalls::HypervisorSymbols;
    use crate::kd::context::build_register_map;
    use crate::session::{Session, session_over_memory};
    use crate::target::{SavedThreadRegisters, SelectedFrame};
    use crate::types::VirtAddr;
    use std::path::Path;

    /// Where the fixture image is loaded, and the stack page after it.
    const IMAGE: u64 = 0x1_4000_0000;
    const IMAGE_SIZE: usize = 0x3000;
    const STACK: u64 = IMAGE + IMAGE_SIZE as u64;
    /// A function that sets up `rbp` as its frame pointer, and its caller.
    const FRAMED: u32 = 0x1100;
    const CALLER: u32 = 0x1200;
    /// Inside `FRAMED`'s body, past its prolog.
    const FRAMED_RIP: u64 = IMAGE + FRAMED as u64 + 0x10;
    /// The call site in `CALLER` that `FRAMED` returns to.
    const RETURN_ADDRESS: u64 = IMAGE + CALLER as u64 + 0x10;
    const FRAMED_RSP: u64 = STACK + 0x800;
    const FRAMED_RBP: u64 = STACK + 0x820;
    /// What `FRAMED` pushed from its caller's `rbp`.
    const CALLER_RBP: u64 = STACK + 0x900;

    /// An AMD64 image whose `.pdata` covers `FRAMED` (prolog `push rbp; mov
    /// rbp, rsp`, unwound through `UWOP_SET_FPREG`) and `CALLER` (no prolog).
    fn frame_pointer_image() -> Vec<u8> {
        let mut image = vec![0u8; IMAGE_SIZE];
        let mut put = |offset: usize, bytes: &[u8]| {
            image[offset..offset + bytes.len()].copy_from_slice(bytes);
        };
        let pe = 0x80;
        put(0, b"MZ");
        put(0x3c, &(pe as u32).to_le_bytes());
        put(pe, b"PE\0\0");
        put(pe + 4, &0x8664u16.to_le_bytes());
        put(pe + 6, &2u16.to_le_bytes());
        put(pe + 20, &240u16.to_le_bytes());
        let optional = pe + 24;
        put(optional, &0x20bu16.to_le_bytes());
        put(optional + 32, &0x1000u32.to_le_bytes());
        put(optional + 36, &0x200u32.to_le_bytes());
        put(optional + 56, &(IMAGE_SIZE as u32).to_le_bytes());
        put(optional + 60, &0x1000u32.to_le_bytes());
        put(optional + 108, &16u32.to_le_bytes());
        // Data directory 3: the exception table (two RUNTIME_FUNCTIONs).
        put(optional + 112 + 3 * 8, &0x2000u32.to_le_bytes());
        put(optional + 112 + 3 * 8 + 4, &24u32.to_le_bytes());
        let sections = optional + 240;
        for (index, (name, rva, characteristics)) in [
            (b".text\0\0\0", 0x1000u32, 0x6000_0020u32),
            (b".rdata\0\0", 0x2000, 0x4000_0040),
        ]
        .into_iter()
        .enumerate()
        {
            let header = sections + 40 * index;
            put(header, name);
            put(header + 8, &0x1000u32.to_le_bytes());
            put(header + 12, &rva.to_le_bytes());
            put(header + 16, &0x1000u32.to_le_bytes());
            put(header + 20, &rva.to_le_bytes());
            put(header + 36, &characteristics.to_le_bytes());
        }
        put(0x1000, &[0xcc; 0x1000]);
        for (index, (begin, unwind_info)) in [(FRAMED, 0x2100u32), (CALLER, 0x2110)]
            .into_iter()
            .enumerate()
        {
            let entry = 0x2000 + 12 * index;
            put(entry, &begin.to_le_bytes());
            put(entry + 4, &(begin + 0x80).to_le_bytes());
            put(entry + 8, &unwind_info.to_le_bytes());
        }
        // Version 1, a 4-byte prolog, two codes, frame register rbp at
        // offset 0; codes: UWOP_SET_FPREG at 4, UWOP_PUSH_NONVOL rbp at 1.
        put(0x2100, &[0x01, 0x04, 0x02, 0x05, 0x04, 0x03, 0x01, 0x50]);
        put(0x2110, &[0x01, 0x00, 0x00, 0x00]);
        image
    }

    /// The fixture image and a stack where `FRAMED` runs with its frame at
    /// `FRAMED_RBP`, called from `CALLER`, which is the thread's first frame.
    fn frame_pointer_session() -> Session {
        frame_pointer_session_with(&[(8, RETURN_ADDRESS)])
    }

    /// [`frame_pointer_session`] with `slots` (offset from `FRAMED_RBP`,
    /// value) written above the saved `rbp` instead of the return address.
    fn frame_pointer_session_with(slots: &[(usize, u64)]) -> Session {
        let mut memory = frame_pointer_image();
        memory.resize(IMAGE_SIZE + 0x2000, 0);
        let stack = |address: u64| (address - IMAGE) as usize;
        memory[stack(FRAMED_RBP)..stack(FRAMED_RBP) + 8].copy_from_slice(&CALLER_RBP.to_le_bytes());
        for &(offset, value) in slots {
            let at = stack(FRAMED_RBP) + offset;
            memory[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut session = session_over_memory(IMAGE, &memory);
        session
            .target
            .set_kernel_modules_for_test(vec![ModuleInfo::new(
                "fixture.sys".to_string(),
                VirtAddr(IMAGE),
                IMAGE_SIZE as u32,
            )]);
        session.register_map = build_register_map();
        session
    }

    fn registers(values: &[(&str, u64)]) -> HashMap<String, u64> {
        values
            .iter()
            .map(|(name, value)| (name.to_string(), *value))
            .collect()
    }

    #[test]
    fn a_known_frame_pointer_unwinds_its_frame() {
        let session = frame_pointer_session();
        let seed = registers(&[
            ("rip", FRAMED_RIP),
            ("rsp", FRAMED_RSP),
            ("rbp", FRAMED_RBP),
        ]);

        let trace =
            build_stacktrace_with_register_values(&session.target, &session.register_map, &seed, 8);

        let frames: Vec<_> = trace
            .frames
            .iter()
            .map(|frame| (frame.frame.ip, frame.frame.source))
            .collect();
        assert_eq!(
            frames,
            [
                (FRAMED_RIP, FrameSource::Current),
                (RETURN_ADDRESS, FrameSource::Unwind)
            ]
        );
        assert_eq!(trace.frames[1].registers.get("rbp"), Some(&CALLER_RBP));
        assert_eq!(trace.frames[1].frame.sp, FRAMED_RBP + 16);
    }

    /// A context without `rbp` (the VTL0 state the Windows hypervisor saves)
    /// cannot unwind a frame-pointer frame; the caller is found by scanning,
    /// rather than lost to a frame pointer taken as zero.
    #[test]
    fn an_unknown_frame_pointer_falls_back_to_scanning() {
        let session = frame_pointer_session();
        let seed = registers(&[("rip", FRAMED_RIP), ("rsp", FRAMED_RSP)]);

        let trace =
            build_stacktrace_with_register_values(&session.target, &session.register_map, &seed, 8);

        let frames: Vec<_> = trace
            .frames
            .iter()
            .map(|frame| (frame.frame.ip, frame.frame.source))
            .collect();
        assert_eq!(
            frames,
            [
                (FRAMED_RIP, FrameSource::Current),
                (RETURN_ADDRESS, FrameSource::Scan)
            ]
        );
    }

    /// A scan lists each return address once: another copy of one higher up
    /// (a spill slot, a frame since popped) is no second frame.
    #[test]
    fn a_scan_lists_a_return_address_once() {
        let session = frame_pointer_session_with(&[(8, RETURN_ADDRESS), (0x18, RETURN_ADDRESS)]);
        let seed = registers(&[("rip", FRAMED_RIP), ("rsp", FRAMED_RSP)]);

        let trace =
            build_stacktrace_with_register_values(&session.target, &session.register_map, &seed, 8);

        let frames: Vec<_> = trace
            .frames
            .iter()
            .map(|frame| (frame.frame.ip, frame.frame.source))
            .collect();
        assert_eq!(
            frames,
            [
                (FRAMED_RIP, FrameSource::Current),
                (RETURN_ADDRESS, FrameSource::Scan)
            ]
        );
    }

    /// On a root none of NT's (the Windows hypervisor's), only its own
    /// image holds return addresses: an NT module's address on its stack is
    /// a guest's value, which the scan does not take for a frame.
    #[test]
    fn a_foreign_root_scan_takes_only_its_own_image() {
        let session = frame_pointer_session();
        let mut trace = super::resolve_thread_trace_context(&session.target, 0);
        trace.foreign_image = Some(ModuleInfo::new(
            "hv".to_string(),
            VirtAddr(0xffff_f847_9860_0000),
            0x40_0000,
        ));

        let walk = super::walk::build_recovered_stacktrace_seeded(
            &session.target,
            &trace,
            RegisterContext::new(FRAMED_RIP, FRAMED_RSP),
            FrameSource::Seed,
            8,
            HashMap::new(),
        );

        let frames: Vec<_> = walk.frames.iter().map(|frame| frame.frame.ip).collect();
        assert_eq!(frames, [FRAMED_RIP]);
    }

    /// Windows hypervisor code whose unwind data leaves out its prolog's
    /// `sub rsp, 0x28`, as some assembly's does from build 22621 (its
    /// external-interrupt exit handler's): at its call, the data's frame
    /// would read the return address from the spill area, where a stale one
    /// lies. The walk takes the prolog's frame, which keeps the caller's RSP
    /// aligned as at every call, and reaches the real caller.
    #[test]
    fn a_hypervisor_frame_whose_unwind_data_misaligns_its_caller_takes_its_prolog() {
        // The handler, the code that calls it, what it calls, and another
        // call site whose return address is the stale one. Each calls with
        // the 5 bytes before its offset 0x10.
        const HANDLER: u32 = 0x1100;
        const ENTRY: u32 = 0x1200;
        const CALLEE: u32 = 0x1300;
        const DECOY: u32 = 0x1400;
        let returns_to = |function: u32| IMAGE + u64::from(function) + 0x10;
        // The handler's RSP at its call, 16-byte aligned as at every call.
        let rsp = STACK + 0x800;

        let mut memory = frame_pointer_image();
        // Four RUNTIME_FUNCTIONs, all with the fixture's unwind data of no
        // codes at 0x2110.
        memory[0x124..0x128].copy_from_slice(&48u32.to_le_bytes());
        for (index, begin) in [HANDLER, ENTRY, CALLEE, DECOY].into_iter().enumerate() {
            let entry = 0x2000 + 12 * index;
            memory[entry..entry + 4].copy_from_slice(&begin.to_le_bytes());
            memory[entry + 4..entry + 8].copy_from_slice(&(begin + 0x80).to_le_bytes());
            memory[entry + 8..entry + 12].copy_from_slice(&0x2110u32.to_le_bytes());
        }
        for (function, target) in [(HANDLER, CALLEE), (ENTRY, HANDLER), (DECOY, CALLEE)] {
            let at = function as usize;
            memory[at..at + 0xb].fill(0x90);
            memory[at + 0xb] = 0xe8;
            let displacement = target.wrapping_sub(function + 0x10);
            memory[at + 0xc..at + 0x10].copy_from_slice(&displacement.to_le_bytes());
        }
        memory[HANDLER as usize..HANDLER as usize + 4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]);
        memory.resize(IMAGE_SIZE + 0x2000, 0);
        for (address, value) in [
            (rsp - 8, returns_to(HANDLER)),
            (rsp, returns_to(DECOY)),
            (rsp + 0x28, returns_to(ENTRY)),
        ] {
            let at = (address - IMAGE) as usize;
            memory[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut session = session_over_memory(IMAGE, &memory);
        session
            .target
            .set_kernel_modules_for_test(vec![ModuleInfo::new(
                "hv".to_string(),
                VirtAddr(IMAGE),
                IMAGE_SIZE as u32,
            )]);
        let mut trace = super::resolve_thread_trace_context(&session.target, 0);
        trace.foreign_image = Some(ModuleInfo::new(
            "hv".to_string(),
            VirtAddr(IMAGE),
            IMAGE_SIZE as u32,
        ));
        trace.hypervisor = Some(Arc::new(HypervisorSymbols {
            names: Vec::new(),
            extents: HashMap::new(),
            starts: vec![HANDLER, ENTRY, CALLEE, DECOY],
            exit_entries: Vec::new(),
        }));

        let walk = super::walk::build_recovered_stacktrace_seeded(
            &session.target,
            &trace,
            RegisterContext::new(IMAGE + u64::from(CALLEE), rsp - 8),
            FrameSource::Seed,
            8,
            HashMap::new(),
        );

        let frames: Vec<_> = walk
            .frames
            .iter()
            .map(|frame| (frame.frame.ip, frame.frame.source))
            .collect();
        assert_eq!(
            frames,
            [
                (IMAGE + u64::from(CALLEE), FrameSource::Seed),
                (returns_to(HANDLER), FrameSource::Unwind),
                (returns_to(ENTRY), FrameSource::Prolog),
            ]
        );
    }

    /// An unwind that lands on a value no code can sit at (the null page, a
    /// non-canonical address) went wrong: it is not listed as a frame, and
    /// the caller is found by scanning above it.
    #[test]
    fn a_return_address_in_the_null_page_is_not_a_frame() {
        let session = frame_pointer_session_with(&[(8, 0x288), (0x18, RETURN_ADDRESS)]);
        let seed = registers(&[
            ("rip", FRAMED_RIP),
            ("rsp", FRAMED_RSP),
            ("rbp", FRAMED_RBP),
        ]);

        let trace =
            build_stacktrace_with_register_values(&session.target, &session.register_map, &seed, 8);

        let frames: Vec<_> = trace
            .frames
            .iter()
            .map(|frame| (frame.frame.ip, frame.frame.source))
            .collect();
        assert_eq!(
            frames,
            [
                (FRAMED_RIP, FrameSource::Current),
                (RETURN_ADDRESS, FrameSource::Scan)
            ]
        );
    }

    /// The fixture image with `DriverEntry` of the inline-frames fixture PDB
    /// (`tests/fixtures/inline_frames.pdb`) at RVA 0x1000..0x1059 instead of
    /// `FRAMED`, unwound as its prolog `sub rsp, 0x10` says, and that PDB
    /// loaded for the image. `returns` are `(offset from FRAMED_RSP, value)`
    /// stack slots.
    fn inline_frames_session(returns: &[(usize, u64)]) -> Session {
        let mut memory = frame_pointer_image();
        memory[0x2000..0x2004].copy_from_slice(&0x1000u32.to_le_bytes());
        memory[0x2004..0x2008].copy_from_slice(&0x1059u32.to_le_bytes());
        memory[0x2008..0x200c].copy_from_slice(&0x2120u32.to_le_bytes());
        // Version 1, a 4-byte prolog, one code: UWOP_ALLOC_SMALL of 16 at 4.
        memory[0x2120..0x2128].copy_from_slice(&[0x01, 0x04, 0x01, 0x00, 0x04, 0x12, 0, 0]);
        memory.resize(IMAGE_SIZE + 0x2000, 0);
        for &(offset, value) in returns {
            let at = (FRAMED_RSP - IMAGE) as usize + offset;
            memory[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut session = session_over_memory(IMAGE, &memory);
        session
            .target
            .set_kernel_modules_for_test(vec![ModuleInfo::new(
                "fixture.sys".to_string(),
                VirtAddr(IMAGE),
                IMAGE_SIZE as u32,
            )]);
        session.register_map = build_register_map();
        let dtb = session.target.kernel_dtb();
        session
            .target
            .symbols
            .load_pdb_for_test(
                Path::new(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/inline_frames.pdb"
                )),
                "fixture",
                dtb,
                VirtAddr(IMAGE),
                IMAGE_SIZE as u32,
            )
            .unwrap();
        session
    }

    /// A physical frame in inlined code shows as the inline frames there,
    /// innermost first, then itself; a caller's frames are those of its call
    /// (the byte before the return address), which here is still in the
    /// inlined `fetch_add` although the return address is past it.
    #[test]
    fn inlined_calls_expand_into_frames_and_a_caller_is_at_its_call() {
        let stopped = IMAGE + 0x101d;
        let returned = IMAGE + 0x1026;
        let session = inline_frames_session(&[(0x10, returned)]);
        let seed = registers(&[("rip", stopped), ("rsp", FRAMED_RSP)]);

        let trace = build_stacktrace_with_register_values(
            &session.target,
            &session.register_map,
            &seed,
            16,
        );

        let frames: Vec<_> = trace
            .frames
            .iter()
            .map(|frame| {
                let frame = &frame.frame;
                let line = frame.source_location.as_ref().map(|location| location.line);
                (frame.ip, frame.inline, frame.symbol.as_str(), line)
            })
            .collect();
        let in_fetch_add = |ip| {
            [
                (
                    ip,
                    true,
                    "fixture!core::sync::atomic::atomic_add",
                    Some(3927),
                ),
                (
                    ip,
                    true,
                    "fixture!core::sync::atomic::Atomic<u32>::fetch_add",
                    Some(3148),
                ),
                (ip, true, "fixture!inline_frames::scale", Some(11)),
                (ip, true, "fixture!inline_frames::accumulate", Some(17)),
            ]
        };
        let mut expected = in_fetch_add(stopped).to_vec();
        expected.push((stopped, false, "fixture!DriverEntry+0x1d", Some(25)));
        expected.extend(in_fetch_add(returned));
        expected.push((returned, false, "fixture!DriverEntry+0x26", Some(25)));
        assert_eq!(frames, expected);

        let codes: Vec<_> = trace.frames.iter().map(|frame| frame.frame.code).collect();
        for (index, code) in codes.iter().enumerate() {
            let (address, depth) = if index < 5 {
                (stopped, index)
            } else {
                (returned - 1, index - 5)
            };
            assert_eq!(code.address, VirtAddr(address));
            assert_eq!(code.inline_depth, depth);
        }
        // The stopped frame's inline frames share its (live) registers; the
        // caller's are recovered.
        assert_eq!(trace.frames[0].registers, trace.frames[4].registers);
        assert_eq!(trace.frames[5].registers, trace.frames[9].registers);
        let selected = |index| SelectedFrame::from_recovered(&trace, index, Some(&seed), true);
        assert!(selected(3).unwrap().is_live());
        assert!(selected(4).unwrap().is_live());
        assert!(!selected(5).unwrap().is_live());
    }

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
