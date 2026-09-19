use std::collections::{HashMap, HashSet};
use std::result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

pub mod cpu;
pub mod heap;
pub mod meta;
pub mod mm;
pub mod object;
pub mod pnp;
pub mod pool;
pub mod sched;
pub mod security;
pub mod usermode;

use self::mm::AddressDescription;
use crate::unwind::{
    RecoveredFrame, frame_base_for_register_values, return_address_for_register_values,
};

use crate::{
    backend::MemoryOps,
    bugchecks::looks_like_kernel_pointer,
    debugger_data::{
        DebuggerDataBlock, DebuggerDataCandidate, MetadataSource, MetadataValue,
        locate_debugger_data_block,
    },
    error::{Error, Result},
    guest::{Guest, ModuleInfo, ModuleSymbolLoadReport, ProcessInfo, WinObject},
    memory::{AddressSpace, DTB_IDENTITY, PAGE_SIZE},
    phys::PhysMem,
    symbols::{
        LocalVariableLocation, ParsedType, ProcedureLocal, SourceLineExtent, SourceLocation,
        SymbolCandidate, SymbolIndex, SymbolStore, TypeInfo, format_symbol_with_offset,
    },
    types::{Arch, Dtb, Value, VirtAddr},
};

pub struct Target {
    pub phys: Arc<PhysMem>,
    pub symbols: Arc<SymbolStore>,
    pub guest: Option<Guest>,
    debugger_data: Option<DebuggerDataBlock>,
    pub current_process: Option<WinObject>,
    pub current_process_info: Option<ProcessInfo>,
    /// Explicit code-machine override (`32` or `64`); `None` follows context.
    pub effmach: Option<u32>,
    /// Bare WinObject for triage dumps without a discovered kernel, providing
    /// identity-mapped memory access so commands like disassemble/search work.
    triage_fallback: Option<WinObject>,
    triage_modules_cache: Option<Vec<ModuleInfo>>,
    context_dtb_override: Option<Dtb>,
    pub registers: Option<HashMap<String, u64>>,
    /// Frontend-selected stack/context frame. The REPL owns the lifetime and
    /// mirrors it into this target so expression and local evaluation see the
    /// same recovered register context across command calls.
    pub selected_frame: Option<SelectedFrame>,
    /// Windows thread metadata selected for inspection. Whether it is live on
    /// the backend vCPU or parked is session state; Target only owns identity
    /// and the corresponding process/address-space view.
    pub windows_thread_selection: Option<ThreadInfo>,
    /// User-defined convenience variables (`$name`), sticky for the session
    pub user_vars: HashMap<String, UserVar>,
    /// Volatile result slots (`$0`, `$1`, ...) repopulated by the most recent
    /// result-producing command (search, ev, ...)
    pub results: Vec<u64>,
    /// The command that produced the current result slots, for `vars`
    pub results_origin: Option<String>,
    /// Exception code of the current stop's exception record, behind
    /// WinDbg's `$exr_code`. Recorded by the session at the one stop-
    /// ingestion boundary so every host sees the same value.
    pub last_exception_code: Option<u32>,
    /// Host interrupt flag. Long scans (pool, heap, list walks) stop early
    /// once it is raised; the host sets it (Ctrl-C in the REPL) and clears it
    /// before the next command.
    pub interrupt: Arc<AtomicBool>,
    /// Diagnostics raised while building or reloading the target (kernel
    /// discovery that fell back to bare memory access). Never printed here;
    /// the session forwards them to the host.
    pub notices: Vec<String>,
}

/// A debugger-selected register context. Register values are kept as a sparse
/// map because unwind metadata can recover only a subset of the full live
/// register file for caller frames; `seed_registers` keeps the original
/// context available when `.frame N` navigates repeatedly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedFrame {
    pub index: usize,
    pub ip: u64,
    pub sp: u64,
    pub frame_base: Option<u64>,
    pub registers: HashMap<String, u64>,
    /// Sparse register context from which this selection's stack walk started.
    /// It remains stable as `.frame N` moves through the recovered trace.
    pub seed_registers: HashMap<String, u64>,
    /// Whether `seed_registers` is the live vCPU register file, as opposed to
    /// a `.cxr`/`.trap` context read from memory. Decides [`Self::is_live`].
    pub seed_live: bool,
}

impl SelectedFrame {
    /// Frame 0 of a walk seeded from the live vCPU register file: the context
    /// the target is halted in, so its registers are the target's and can be
    /// written. Caller frames and `.cxr`/`.trap` contexts are recovered from
    /// memory or unwind metadata and are read-only.
    pub fn is_live(&self) -> bool {
        self.seed_live && self.index == 0
    }

    /// Select frame `index` of a recovered trace, keeping the walk's seed
    /// context so repeated selections stay anchored to the same register file.
    /// `seed_live` says whether that seed was the vCPU's own register file.
    pub fn from_recovered(
        frame: &RecoveredFrame,
        index: usize,
        seed_registers: Option<&HashMap<String, u64>>,
        seed_live: bool,
    ) -> Self {
        Self {
            index,
            ip: frame.frame.ip,
            sp: frame.frame.sp,
            frame_base: frame.frame_base,
            registers: frame.registers.clone(),
            seed_registers: seed_registers
                .filter(|registers| !registers.is_empty())
                .cloned()
                .unwrap_or_else(|| frame.registers.clone()),
            seed_live,
        }
    }

    /// Select a context given only register values (`.cxr`, `.ecxr`, `.trap`),
    /// which carry no unwind metadata and therefore no frame base.
    pub fn from_registers(index: usize, registers: HashMap<String, u64>) -> Self {
        let ip = registers
            .get("rip")
            .copied()
            .or_else(|| registers.get("pc").copied())
            .unwrap_or(0);
        let sp = registers
            .get("rsp")
            .copied()
            .or_else(|| registers.get("sp").copied())
            .unwrap_or(0);
        let seed_registers = registers.clone();
        Self {
            index,
            ip,
            sp,
            frame_base: None,
            registers,
            seed_registers,
            seed_live: false,
        }
    }
}

/// A user-defined convenience variable and the expression it was defined from
#[derive(Debug, Clone)]
pub struct UserVar {
    pub value: u64,
    pub source: String,
}

pub struct BuiltinVar {
    pub name: &'static str,
    pub value: u64,
    pub source: &'static str,
}

pub const CODE_BITNESS_X86: u32 = 32;
pub const CODE_BITNESS_AMD64: u32 = 64;
const COMPATIBILITY_MODE_CS: u64 = 0x23;
const WOW64_ADDRESS_LIMIT: u64 = 1 << 32;

fn decide_bitness(
    effmach: Option<u32>,
    cs: Option<u64>,
    is_wow64: bool,
    modules: &[ModuleInfo],
    address: VirtAddr,
) -> u32 {
    if let Some(effmach) = effmach {
        return if matches!(effmach, CODE_BITNESS_X86 | 0x14c) {
            CODE_BITNESS_X86
        } else {
            CODE_BITNESS_AMD64
        };
    }

    let is_user = !looks_like_kernel_pointer(address.0);
    if is_user && cs == Some(COMPATIBILITY_MODE_CS) {
        return CODE_BITNESS_X86;
    }

    if is_wow64 {
        if modules
            .iter()
            .any(|module| module.is_32bit && module.contains_address(address))
        {
            return CODE_BITNESS_X86;
        }
        if address.0 < WOW64_ADDRESS_LIMIT
            && !modules
                .iter()
                .any(|module| !module.is_32bit && module.contains_address(address))
        {
            return CODE_BITNESS_X86;
        }
    }

    CODE_BITNESS_AMD64
}

/// One memory-search hit, enriched with the same location/symbol context used
/// by the SDK and MCP.
#[derive(Debug, Clone)]
pub struct MemorySearchMatch {
    pub address: VirtAddr,
    pub offset: u64,
    pub symbol: Option<String>,
    pub description: AddressDescription,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolSearchMatch {
    pub name: String,
    pub address: Option<VirtAddr>,
    pub module: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arm64SavedRegisters {
    pub x: [Option<u64>; 31],
    pub sp: Option<u64>,
    pub pc: Option<u64>,
    pub cpsr: Option<u64>,
    pub fp: Option<u64>,
    pub lr: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedThreadRegisters {
    pub rip: Option<u64>,
    pub rsp: Option<u64>,
    pub rax: Option<u64>,
    pub rcx: Option<u64>,
    pub rdx: Option<u64>,
    pub rbx: Option<u64>,
    pub rbp: Option<u64>,
    pub rsi: Option<u64>,
    pub rdi: Option<u64>,
    pub r8: Option<u64>,
    pub r9: Option<u64>,
    pub r10: Option<u64>,
    pub r11: Option<u64>,
    pub r12: Option<u64>,
    pub r13: Option<u64>,
    pub r14: Option<u64>,
    pub r15: Option<u64>,
    pub rflags: Option<u64>,
    pub arm64: Option<Arm64SavedRegisters>,
}

impl SavedThreadRegisters {
    pub fn get(&self, name: &str) -> Option<u64> {
        let name = name.to_ascii_lowercase();
        if let Some(index) = name
            .strip_prefix('x')
            .and_then(|index| index.parse::<usize>().ok())
            .filter(|&index| index < 31)
        {
            return self.arm64.as_ref()?.x[index];
        }
        match name.as_str() {
            "rip" => self.rip,
            "rsp" => self.rsp,
            "rax" => self.rax,
            "rcx" => self.rcx,
            "rdx" => self.rdx,
            "rbx" => self.rbx,
            "rbp" => self.rbp,
            "rsi" => self.rsi,
            "rdi" => self.rdi,
            "r8" => self.r8,
            "r9" => self.r9,
            "r10" => self.r10,
            "r11" => self.r11,
            "r12" => self.r12,
            "r13" => self.r13,
            "r14" => self.r14,
            "r15" => self.r15,
            "rflags" | "eflags" => self.rflags,
            "sp" => self.arm64.as_ref()?.sp,
            "pc" => self.arm64.as_ref()?.pc,
            "cpsr" => self.arm64.as_ref()?.cpsr,
            "fp" => self.arm64.as_ref()?.fp,
            "lr" => self.arm64.as_ref()?.lr,
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ThreadInfo {
    pub ethread: VirtAddr,
    pub kthread: VirtAddr,
    pub tid: Option<u64>,
    pub pid: Option<u64>,
    pub process_name: Option<String>,
    pub eprocess: Option<VirtAddr>,
    pub state: Option<u8>,
    pub wait_reason: Option<u8>,
    pub priority: Option<u8>,
    pub base_priority: Option<u8>,
    pub wait_irql: Option<u8>,
    pub kernel_stack_resident: Option<bool>,
    pub start_address: Option<VirtAddr>,
    pub win32_start_address: Option<VirtAddr>,
    pub teb: Option<VirtAddr>,
    pub kernel_stack: Option<VirtAddr>,
    pub stack_base: Option<VirtAddr>,
    pub stack_limit: Option<VirtAddr>,
    pub trap_frame: Option<VirtAddr>,
    pub pending_irps: Option<Vec<VirtAddr>>,
}

impl ThreadInfo {
    /// A thread pseudo-register: `None` when this thread has no such name,
    /// `Some(None)` when it has the name but not the state behind it (a
    /// kernel thread has no TEB, an unwalked thread no trap frame). Telling
    /// the two apart is what lets the evaluator say "not available here"
    /// instead of "no such register".
    pub fn pseudo_register(&self, name: &str) -> Option<Option<u64>> {
        let value = match name.to_ascii_lowercase().as_str() {
            "thread" | "ethread" => Some(self.ethread.0),
            "kthread" => Some(self.kthread.0),
            "tid" => self.tid,
            "pid" => self.pid,
            "proc" | "process" | "eprocess" => self.eprocess.map(|addr| addr.0),
            "teb" => self.teb.map(|addr| addr.0),
            "threadstart" | "startaddress" => self.start_address.map(|addr| addr.0),
            "win32start" | "win32startaddress" => self.win32_start_address.map(|addr| addr.0),
            "kernelstack" => self.kernel_stack.map(|addr| addr.0),
            "stackbase" => self.stack_base.map(|addr| addr.0),
            "stacklimit" => self.stack_limit.map(|addr| addr.0),
            "trapframe" => self.trap_frame.map(|addr| addr.0),
            "priority" => self.priority.map(u64::from),
            "basepriority" => self.base_priority.map(u64::from),
            "waitirql" => self.wait_irql.map(u64::from),
            "stackresident" | "kernelstackresident" => {
                self.kernel_stack_resident.map(|resident| resident as u64)
            }
            _ => return None,
        };
        Some(value)
    }

    pub fn pseudo_register_value(&self, name: &str) -> Option<u64> {
        self.pseudo_register(name).flatten()
    }
}
fn thread_owner_matches(thread: &ThreadInfo, process: &ProcessInfo) -> bool {
    match thread.eprocess {
        Some(eprocess) => eprocess == process.eprocess_va,
        None => thread.pid.is_some_and(|pid| pid == process.pid),
    }
}

fn select_thread_process_dtb(
    thread: &ThreadInfo,
    current: Option<&ProcessInfo>,
    processes: &[ProcessInfo],
    kernel_dtb: Dtb,
) -> Option<Dtb> {
    if thread.pid == Some(0) {
        return Some(kernel_dtb);
    }
    current
        .filter(|process| thread_owner_matches(thread, process))
        .or_else(|| {
            processes
                .iter()
                .find(|process| thread_owner_matches(thread, process))
        })
        .map(|process| process.dtb)
}

/// Name for an `IRP_MJ_*` major function code (without the `IRP_MJ_` prefix).
pub fn irp_major_function_name(major: u8) -> &'static str {
    match major {
        0x00 => "CREATE",
        0x01 => "CREATE_NAMED_PIPE",
        0x02 => "CLOSE",
        0x03 => "READ",
        0x04 => "WRITE",
        0x05 => "QUERY_INFORMATION",
        0x06 => "SET_INFORMATION",
        0x07 => "QUERY_EA",
        0x08 => "SET_EA",
        0x09 => "FLUSH_BUFFERS",
        0x0a => "QUERY_VOLUME_INFORMATION",
        0x0b => "SET_VOLUME_INFORMATION",
        0x0c => "DIRECTORY_CONTROL",
        0x0d => "FILE_SYSTEM_CONTROL",
        0x0e => "DEVICE_CONTROL",
        0x0f => "INTERNAL_DEVICE_CONTROL",
        0x10 => "SHUTDOWN",
        0x11 => "LOCK_CONTROL",
        0x12 => "CLEANUP",
        0x13 => "CREATE_MAILSLOT",
        0x14 => "QUERY_SECURITY",
        0x15 => "SET_SECURITY",
        0x16 => "POWER",
        0x17 => "SYSTEM_CONTROL",
        0x18 => "DEVICE_CHANGE",
        0x19 => "QUERY_QUOTA",
        0x1a => "SET_QUOTA",
        0x1b => "PNP",
        _ => "?",
    }
}

/// The one process-filter policy shared by `ps` (REPL), the `processes` MCP
/// tool, and the Python SDK: a numeric filter is an exact pid, anything else is
/// a case-insensitive name substring.
pub fn process_matches(process: &ProcessInfo, filter: &str) -> bool {
    match filter.parse::<u64>() {
        Ok(pid) => process.pid == pid,
        Err(_) => process
            .name
            .to_ascii_lowercase()
            .contains(&filter.to_ascii_lowercase()),
    }
}

/// Parse bare decimal digits as a PID, matching display and completion output.
/// Other selectors fall back to radix-sensitive expression evaluation.
pub fn decimal_pid_literal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// `KTHREAD.State` of a thread whose kernel stack has been freed.
pub const KTHREAD_STATE_TERMINATED: u8 = 4;

pub fn kthread_state_name(state: u8) -> &'static str {
    match state {
        0 => "Initialized",
        1 => "Ready",
        2 => "Running",
        3 => "Standby",
        KTHREAD_STATE_TERMINATED => "Terminated",
        5 => "Waiting",
        6 => "Transition",
        7 => "DeferredReady",
        8 => "GateWaitObsolete",
        9 => "WaitingForProcessInSwap",
        _ => "?",
    }
}

/// Case-insensitive lookup, including subregisters named by PDB locations.
/// Never reconstruct a wider register from a narrower recovered value.
pub fn lookup_register(registers: &HashMap<String, u64>, name: &str) -> Option<u64> {
    let direct = |name: &str| {
        registers.get(name).copied().or_else(|| {
            registers
                .iter()
                .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| *value)
        })
    };
    if let Some(value) = direct(name) {
        return Some(value);
    }
    const ALIASES: &[(&str, &str, u32, u32)] = &[
        ("eax", "rax", 0, 32),
        ("ax", "rax", 0, 16),
        ("al", "rax", 0, 8),
        ("ah", "rax", 8, 8),
        ("ebx", "rbx", 0, 32),
        ("bx", "rbx", 0, 16),
        ("bl", "rbx", 0, 8),
        ("bh", "rbx", 8, 8),
        ("ecx", "rcx", 0, 32),
        ("cx", "rcx", 0, 16),
        ("cl", "rcx", 0, 8),
        ("ch", "rcx", 8, 8),
        ("edx", "rdx", 0, 32),
        ("dx", "rdx", 0, 16),
        ("dl", "rdx", 0, 8),
        ("dh", "rdx", 8, 8),
        ("esi", "rsi", 0, 32),
        ("si", "rsi", 0, 16),
        ("sil", "rsi", 0, 8),
        ("edi", "rdi", 0, 32),
        ("di", "rdi", 0, 16),
        ("dil", "rdi", 0, 8),
        ("esp", "rsp", 0, 32),
        ("sp", "rsp", 0, 16),
        ("spl", "rsp", 0, 8),
        ("ebp", "rbp", 0, 32),
        ("bp", "rbp", 0, 16),
        ("bpl", "rbp", 0, 8),
        ("eip", "rip", 0, 32),
    ];
    if let Some((_, parent, shift, width)) = ALIASES
        .iter()
        .find(|(alias, ..)| alias.eq_ignore_ascii_case(name))
    {
        return direct(parent).map(|value| (value >> shift) & ((1u64 << width) - 1));
    }
    // r8d/r8w/r8b through r15, and ARM64 w0 through w30.
    let bytes = name.as_bytes();
    if bytes.len() >= 3 && bytes[0].eq_ignore_ascii_case(&b'r') {
        let suffix = bytes[bytes.len() - 1].to_ascii_lowercase();
        let width = match suffix {
            b'd' => 32,
            b'w' => 16,
            b'b' => 8,
            _ => return None,
        };
        let number = name[1..name.len() - 1].parse::<u8>().ok()?;
        if (8..=15).contains(&number) {
            return direct(&name[..name.len() - 1]).map(|value| value & ((1u64 << width) - 1));
        }
    }
    if bytes.len() >= 2 && bytes[0].eq_ignore_ascii_case(&b'w') {
        let number = name[1..].parse::<u8>().ok()?;
        if number <= 30 {
            return direct(&format!("x{number}")).map(|value| value & 0xffff_ffff);
        }
    }
    None
}

pub fn wait_reason_name(reason: u8) -> &'static str {
    match reason {
        0 => "Executive",
        1 => "FreePage",
        2 => "PageIn",
        3 => "PoolAllocation",
        4 => "DelayExecution",
        5 => "Suspended",
        6 => "UserRequest",
        7 => "WrExecutive",
        8 => "WrFreePage",
        9 => "WrPageIn",
        10 => "WrPoolAllocation",
        11 => "WrDelayExecution",
        12 => "WrSuspended",
        13 => "WrUserRequest",
        14 => "WrEventPair",
        15 => "WrQueue",
        16 => "WrLpcReceive",
        17 => "WrLpcReply",
        18 => "WrVirtualMemory",
        19 => "WrPageOut",
        20 => "WrRendezvous",
        21 => "WrKeyedEvent",
        22 => "WrTerminated",
        23 => "WrProcessInSwap",
        24 => "WrCpuRateControl",
        25 => "WrCalloutStack",
        26 => "WrKernel",
        27 => "WrResource",
        28 => "WrPushLock",
        29 => "WrMutex",
        30 => "WrQuantumEnd",
        31 => "WrDispatchInt",
        32 => "WrPreempted",
        33 => "WrYieldExecution",
        34 => "WrFastMutex",
        35 => "WrGuardedMutex",
        36 => "WrRundown",
        37 => "WrAlertByThreadId",
        38 => "WrDeferredPreempt",
        _ => "?",
    }
}

/// A diagnostic field that can be decoded independently of its siblings.
///
/// Kernel layouts and dump capture are frequently partial.  Keeping the
/// precise failure beside each field lets presentation layers report honest
/// gaps without discarding the rest of a useful diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticValue<T> {
    Available(T),
    Unavailable(String),
}

impl<T> DiagnosticValue<T> {
    fn from_result(result: Result<T>) -> Self {
        match result {
            Ok(value) => Self::Available(value),
            Err(error) => Self::Unavailable(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticMetric<T> {
    pub value: DiagnosticValue<T>,
    pub source: Option<MetadataSource>,
}

impl<T> DiagnosticMetric<T> {
    fn available(value: MetadataValue<T>) -> Self {
        Self {
            value: DiagnosticValue::Available(value.value),
            source: Some(value.source),
        }
    }

    fn unavailable(errors: Vec<String>) -> Self {
        Self {
            value: DiagnosticValue::Unavailable(errors.join("; ")),
            source: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListTermination {
    Head,
    Null,
    Cycle(VirtAddr),
    Bound,
    Corrupt(String),
}

impl ListTermination {
    pub fn diagnostic(&self) -> Option<String> {
        match self {
            Self::Head => None,
            Self::Null => Some("null link".to_string()),
            Self::Cycle(address) => Some(format!("non-head cycle at {:#x}", address.0)),
            Self::Bound => Some("entry bound reached".to_string()),
            Self::Corrupt(error) => Some(format!("unreadable link: {error}")),
        }
    }
}

/// Termination state for walking an intrusive list: bounded, stopping at the
/// head, a null link, or the first link seen twice. The caller supplies each
/// link read after consuming the current entry, so a typed walk can take the
/// next link from the record image it already prefetched.
pub struct ListCursor {
    head: VirtAddr,
    limit: usize,
    current: Option<VirtAddr>,
    visited: HashSet<u64>,
    yielded: usize,
    first_entry: bool,
    termination: Option<ListTermination>,
}

impl ListCursor {
    pub fn new(head: VirtAddr, limit: usize) -> Self {
        Self {
            head,
            limit,
            current: None,
            visited: HashSet::with_capacity(16),
            yielded: 0,
            first_entry: false,
            termination: None,
        }
    }

    /// Construct a cursor over a ring whose first element is `first` itself,
    /// rather than the link stored at a head. The walk ends when it returns
    /// to `first`; commands that treat their address argument as element one
    /// (`dt -l`, `!list`, `dl`) use this.
    pub fn from_first(first: VirtAddr, limit: usize) -> Self {
        Self {
            head: first,
            limit,
            current: Some(first),
            visited: HashSet::with_capacity(16),
            yielded: 0,
            first_entry: true,
            termination: None,
        }
    }

    pub fn take_current(&mut self) -> Option<VirtAddr> {
        if self.termination.is_some() {
            return None;
        }
        let current = self.current.take()?;
        if !self.first_entry && current == self.head {
            self.termination = Some(ListTermination::Head);
            return None;
        }
        if current.is_zero() {
            self.termination = Some(ListTermination::Null);
            return None;
        }
        if !self.visited.insert(current.0) {
            self.termination = Some(ListTermination::Cycle(current));
            return None;
        }
        if self.yielded >= self.limit {
            self.termination = Some(ListTermination::Bound);
            return None;
        }
        self.first_entry = false;
        self.yielded += 1;
        Some(current)
    }

    pub fn advance(&mut self, next: result::Result<VirtAddr, String>) {
        if self.termination.is_some() {
            return;
        }
        self.current = match next {
            Ok(next) => Some(next),
            Err(error) => {
                self.termination = Some(ListTermination::Corrupt(error));
                None
            }
        };
    }

    /// The termination reached; the walk must have been driven to `take_current()`
    /// returning `None`.
    pub fn finish(self) -> ListTermination {
        self.termination
            .expect("ListCursor::finish called before take_current() returned None")
    }
}

pub fn bounded_list_walk<F>(
    head: VirtAddr,
    limit: usize,
    mut read_next: F,
) -> (Vec<VirtAddr>, ListTermination)
where
    F: FnMut(VirtAddr) -> Result<VirtAddr>,
{
    let mut links = Vec::new();
    let mut cursor = ListCursor::new(head, limit);
    cursor.advance(read_next(head).map_err(|error| error.to_string()));
    while let Some(current) = cursor.take_current() {
        links.push(current);
        cursor.advance(read_next(current).map_err(|error| error.to_string()));
    }
    (links, cursor.finish())
}

pub struct StartupMessage {
    pub build_number: Value<u16>,
    pub base_address: VirtAddr,
    pub loaded_module_list: VirtAddr,
}

pub struct ReloadReport {
    pub previous_base_address: VirtAddr,
    pub startup: Option<StartupMessage>,
    pub symbol_report: Option<ModuleSymbolLoadReport>,
    pub symbol_error: Option<String>,
}

pub struct AttachReport {
    pub name: String,
    pub symbol_report: ModuleSymbolLoadReport,
}

/// Kernel discovery found nothing in a live target's memory. Name what was
/// searched: the two causes look identical otherwise, and the numbers tell
/// them apart. A host mapping the size of the guest's configured RAM means
/// the memory is right and the guest simply has not reached its kernel; any
/// other size means the mapped region is not the guest's RAM.
///
/// A target-mediated source reports no size, so it keeps the bare error.
fn no_kernel_in_live_memory(phys: &PhysMem) -> Error {
    let size = phys.ram_size();
    if size == 0 {
        return Error::NtoskrnlNotFound;
    }
    Error::DebugInfo(format!(
        "no Windows kernel in the {} MiB of guest memory mapped at guest-physical {:#x}.\n\
         Either the guest has not reached its kernel yet, or that mapping is not its RAM.",
        size / (1024 * 1024),
        phys.ram_base()
    ))
}

impl Target {
    /// Access the guest, returning `Err(NtoskrnlNotFound)` when no kernel was
    /// discovered (e.g. triage dumps that don't contain the kernel PE header).
    pub fn guest(&self) -> Result<&Guest> {
        self.guest.as_ref().ok_or(Error::NtoskrnlNotFound)
    }

    pub fn kernel_base(&self) -> Option<VirtAddr> {
        self.guest
            .as_ref()
            .map(|g| g.ntoskrnl.base_address)
            .or_else(|| {
                self.triage_modules_cache.as_ref().and_then(|mods| {
                    mods.iter()
                        .find(|m| m.name.to_ascii_lowercase().contains("ntoskrnl"))
                        .map(|m| m.base_address)
                })
            })
    }

    pub fn kernel_dtb(&self) -> Dtb {
        self.guest
            .as_ref()
            .map(|g| g.ntoskrnl.dtb())
            .unwrap_or(DTB_IDENTITY)
    }

    pub fn new() -> Result<Self> {
        Self::with_phys(Arc::new(PhysMem::live()?))
    }

    /// Whether the host has asked long-running work to stop.
    pub fn interrupted(&self) -> bool {
        self.interrupt.load(Ordering::Relaxed)
    }

    pub fn with_phys(phys: Arc<PhysMem>) -> Result<Self> {
        let symbols = Arc::new(SymbolStore::new());
        let mut notices = Vec::new();
        let guest = if let Some(info) = phys.dmp_info() {
            let dtb = if info.is_triage {
                DTB_IDENTITY
            } else {
                info.directory_table_base
            };
            match Guest::new_with_dtb(phys.clone(), symbols.clone(), dtb) {
                Ok(g) => Some(g),
                Err(Error::NtoskrnlNotFound) if info.is_triage => None,
                // Triage degradation must survive any discovery failure
                // (e.g. a symbol download error while offline), not just a
                // missing kernel; identity-mapped access still works.
                Err(e) if info.is_triage => {
                    notices.push(format!(
                        "kernel discovery failed ({e}); continuing without kernel context"
                    ));
                    None
                }
                Err(e) => return Err(e),
            }
        } else {
            match Guest::new(phys.clone(), symbols.clone()) {
                Ok(guest) => Some(guest),
                Err(Error::NtoskrnlNotFound) => return Err(no_kernel_in_live_memory(&phys)),
                Err(e) => return Err(e),
            }
        };

        // Pre-compute the triage module list once for both symbol loading and
        // the cached fallback returned by kernel_modules().
        let triage_modules: Option<Vec<ModuleInfo>> = phys
            .dmp_info()
            .filter(|info| info.is_triage && !info.triage_drivers.is_empty())
            .map(|info| {
                info.triage_drivers
                    .iter()
                    .map(|d| d.to_module_info())
                    .collect()
            });

        if let Some(ref guest) = guest {
            let _ = guest.load_all_kernel_module_symbols(&phys, &symbols);
        } else if let Some(ref modules) = triage_modules {
            let dtb = DTB_IDENTITY;
            let _ = Guest::load_module_symbols(
                &phys,
                &symbols,
                modules.clone(),
                dtb,
                false,
                Arch::Amd64,
            );
        }

        let triage_fallback = if guest.is_none() {
            Some(WinObject::new(
                phys.clone(),
                symbols.clone(),
                DTB_IDENTITY,
                VirtAddr(0),
            ))
        } else {
            None
        };

        let triage_modules_cache = triage_modules;

        Ok(Self {
            phys,
            symbols,
            guest,
            debugger_data: None,
            current_process: None,
            current_process_info: None,
            effmach: None,
            triage_fallback,
            triage_modules_cache,
            context_dtb_override: None,
            registers: None,
            selected_frame: None,
            windows_thread_selection: None,
            user_vars: HashMap::new(),
            results: Vec::new(),
            results_origin: None,
            last_exception_code: None,
            interrupt: Arc::new(AtomicBool::new(false)),
            notices,
        })
    }

    /// Build a target from KD-provided kernel metadata and KD-backed physical
    /// memory. This bypasses host RAM scanning, which is unavailable for remote
    /// or bare-metal targets.
    pub fn with_remote_phys(
        phys: Arc<PhysMem>,
        kernel_dtb: Dtb,
        kernel_base: VirtAddr,
        arch: Arch,
    ) -> Result<Self> {
        let symbols = Arc::new(SymbolStore::new());
        let ntoskrnl =
            WinObject::new_with_arch(phys.clone(), symbols.clone(), kernel_dtb, kernel_base, arch)
                .load_symbols()?;
        ntoskrnl.register_as_kernel();
        let guest = Guest::from_kernel(ntoskrnl);
        let _ = guest.load_all_kernel_module_symbols(&phys, &symbols);

        Ok(Self {
            phys,
            symbols,
            guest: Some(guest),
            debugger_data: None,
            current_process: None,
            current_process_info: None,
            effmach: None,
            triage_fallback: None,
            triage_modules_cache: None,
            context_dtb_override: None,
            registers: None,
            selected_frame: None,
            windows_thread_selection: None,
            user_vars: HashMap::new(),
            results: Vec::new(),
            results_origin: None,
            last_exception_code: None,
            interrupt: Arc::new(AtomicBool::new(false)),
            notices: Vec::new(),
        })
    }

    pub fn current_process(&self) -> Result<&WinObject> {
        match &self.current_process {
            Some(p) => Ok(p),
            None => match &self.guest {
                Some(g) => Ok(&g.ntoskrnl),
                None => self.triage_fallback.as_ref().ok_or(Error::NtoskrnlNotFound),
            },
        }
    }

    pub fn kernel_modules(&self) -> Result<Vec<ModuleInfo>> {
        match self.guest() {
            // The triage snapshot only substitutes when one exists; live
            // enumeration failures propagate instead of being remapped to
            // NtoskrnlNotFound.
            Ok(g) => g.kernel_modules().or_else(|e| {
                if self.triage_modules_cache.is_some() {
                    self.triage_modules()
                } else {
                    Err(e)
                }
            }),
            Err(_) => self.triage_modules(),
        }
    }

    pub fn kernel_modules_with_versions(&self) -> Result<Vec<ModuleInfo>> {
        let mut mods = self.kernel_modules()?;
        if let Ok(g) = self.guest() {
            g.populate_kernel_module_versions(&mut mods);
        }
        Ok(mods)
    }

    /// Loaded modules in the current inspection scope: the attached process's
    /// user-mode modules when attached to a process, otherwise the kernel module
    /// list. Shared by the REPL `lm`, the SDK, and MCP.
    pub fn modules(&self) -> Result<Vec<ModuleInfo>> {
        match &self.current_process_info {
            Some(process) => self.guest()?.process_modules(process),
            None => self.kernel_modules(),
        }
    }

    pub fn modules_with_versions(&self) -> Result<Vec<ModuleInfo>> {
        let mut mods = self.modules()?;
        if let Ok(g) = self.guest() {
            match &self.current_process_info {
                Some(info) => g.populate_process_module_versions(&mut mods, info),
                None => g.populate_kernel_module_versions(&mut mods),
            }
        }
        Ok(mods)
    }

    fn triage_modules(&self) -> Result<Vec<ModuleInfo>> {
        self.triage_modules_cache
            .clone()
            .ok_or(Error::NtoskrnlNotFound)
    }

    /// Search `length` bytes from `start` in the current address space for the
    /// byte `pattern`, returning the addresses of all (overlapping) matches.
    /// Shared by the SDK and MCP `search`.
    pub fn search(&self, start: VirtAddr, pattern: &[u8], length: usize) -> Result<Vec<u64>> {
        if pattern.is_empty() || pattern.len() > length {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; length];
        self.current_process()?
            .memory()
            .read_bytes(start, &mut buf)?;
        Ok((0..=buf.len() - pattern.len())
            .filter(|&i| &buf[i..i + pattern.len()] == pattern)
            .map(|i| start.0.wrapping_add(i as u64))
            .collect())
    }

    /// Add symbol/module/region context to already-computed search hits. Keeping
    /// this separate from `search` lets paged callers enrich only returned rows.
    pub fn describe_search_matches(
        &self,
        start: VirtAddr,
        matches: &[u64],
    ) -> Result<Vec<MemorySearchMatch>> {
        matches
            .iter()
            .copied()
            .map(|addr| {
                let address = VirtAddr(addr);
                Ok(MemorySearchMatch {
                    address,
                    offset: addr.wrapping_sub(start.0),
                    symbol: self.closest_symbol_current_context(address),
                    description: self.describe_address(address)?,
                })
            })
            .collect()
    }

    /// Search memory and return structured rows instead of bare addresses.
    pub fn search_details(
        &self,
        start: VirtAddr,
        pattern: &[u8],
        length: usize,
    ) -> Result<Vec<MemorySearchMatch>> {
        let matches = self.search(start, pattern, length)?;
        self.describe_search_matches(start, &matches)
    }

    /// Walk an intrusive `_LIST_ENTRY` from `head` (the list-head address) in
    /// the current address space, returning each record's base
    /// (`link_addr - link_offset`). Bounded (max 1000) and cycle-stopping,
    /// mirroring the engine's `Types::list_at`; a bad link truncates the walk
    /// rather than discarding the records already collected. Shared by the SDK
    /// and MCP list walking; the typed cursor walk (`StructRef::list`) is the
    /// richer form.
    pub fn walk_list(&self, head: VirtAddr, link_offset: u64) -> Result<Vec<u64>> {
        const MAX: usize = 1000;
        let mem = self.current_process()?.memory();
        let mut cursor = ListCursor::new(head, MAX);
        cursor.advance(Ok(mem.read::<VirtAddr>(head)?));
        let mut out = Vec::new();
        while let Some(current) = cursor.take_current() {
            out.push(current.0.wrapping_sub(link_offset));
            cursor.advance(
                mem.read::<VirtAddr>(current)
                    .map_err(|error| error.to_string()),
            );
        }
        Ok(out)
    }

    /// Decode the `_UNICODE_STRING` at `addr` in the current address space to a
    /// Rust `String` (empty when null/zero-length). `Length`/`Buffer` come from
    /// the PDB layout, not hardcoded offsets. Shared by the SDK and MCP.
    pub fn read_unicode_string(&self, addr: VirtAddr) -> Result<String> {
        let proc = self.current_process()?;
        match proc.types().struct_at("_UNICODE_STRING", addr) {
            Ok(s) => s.read_unicode_string(),
            Err(Error::ExpectedSymbols) => {
                let dtb = self.kernel_dtb();
                let ti = self
                    .symbols
                    .find_type_across_modules(dtb, "_UNICODE_STRING")
                    .ok_or(Error::ExpectedSymbols)?;
                let mem = proc.memory();
                let len_off = ti.field_offset("Length")?;
                let buf_off = ti.field_offset("Buffer")?;
                let length: u16 = mem.read(addr + len_off)?;
                let buffer: VirtAddr = mem.read(addr + buf_off)?;
                if length == 0 || buffer.is_zero() {
                    return Ok(String::new());
                }
                let mut buf = vec![0u8; length as usize];
                mem.read_bytes(buffer, &mut buf)?;
                let u16s: Vec<u16> = buf
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                Ok(String::from_utf16_lossy(&u16s))
            }
            Err(e) => Err(e),
        }
    }

    /// Read a NUL-terminated byte string (`CHAR*`) at `addr` in the current
    /// address space, decoding up to `max_len` bytes as UTF-8 (lossy) and
    /// stopping at the first NUL. Reads are page-bounded, so a string that ends
    /// just before an unmapped page still returns what was readable; only a
    /// completely unmapped start address errors. The `CHAR*` counterpart to
    /// [`read_unicode_string`](Self::read_unicode_string).
    pub fn read_c_string(&self, addr: VirtAddr, max_len: usize) -> Result<String> {
        let mem = self.current_process()?.memory();
        let mut bytes = Vec::new();
        while bytes.len() < max_len {
            let cur = addr + bytes.len() as u64;
            let to_page_end = PAGE_SIZE - cur.page_offset() as usize;
            let chunk = to_page_end.min(max_len - bytes.len());
            let mut buf = vec![0u8; chunk];
            match mem.read_bytes(cur, &mut buf) {
                Ok(()) => {}
                // Nothing readable at the very start is a real error; once we
                // have some bytes, a fault just terminates the string.
                Err(_) if !bytes.is_empty() => break,
                Err(e) => return Err(e),
            }
            if let Some(nul) = buf.iter().position(|&b| b == 0) {
                bytes.extend_from_slice(&buf[..nul]);
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.extend_from_slice(&buf);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn attach(&mut self, pid: u64) -> Result<AttachReport> {
        let processes = self.guest()?.enumerate_processes()?;
        let process_info = processes
            .iter()
            .find(|p| p.pid == pid)
            .ok_or(Error::ProcessNotFound(pid))?
            .clone();

        self.attach_process_info(process_info)
    }

    pub fn attach_process_info(&mut self, process_info: ProcessInfo) -> Result<AttachReport> {
        let name = process_info.name.clone();
        let guest = self.guest.as_ref().ok_or(Error::NtoskrnlNotFound)?;

        let symbol_report =
            guest.load_all_process_module_symbols(&self.phys, &self.symbols, &process_info);

        let winobj = guest.winobj_from_process_info(&process_info)?;

        self.current_process = Some(winobj);
        self.current_process_info = Some(process_info);
        self.selected_frame = None;
        self.clear_context_dtb_override();
        self.clear_current_windows_thread_context();
        Ok(AttachReport {
            name,
            symbol_report: symbol_report?,
        })
    }

    pub fn detach(&mut self) {
        self.selected_frame = None;
        self.clear_context_dtb_override();
        self.clear_current_windows_thread_context();
        self.current_process = None;
        self.current_process_info = None;
    }

    /// Load symbols for one module (by short name, e.g. `user32`) or, with
    /// `None`, every module of process `pid`, without changing the inspection
    /// scope. A process-scoped breakpoint names the address space it wants;
    /// the debugger can read that process's loader list and its PDBs itself
    /// rather than defer until someone runs `.process /p`. Modules already
    /// attempted are left alone. Returns whether any load was attempted.
    pub fn load_process_module_symbols(
        &self,
        pid: u64,
        dtb: Dtb,
        module_short: Option<&str>,
    ) -> Result<bool> {
        let guest = self.guest()?;
        let info = guest
            .enumerate_processes()?
            .into_iter()
            .find(|p| p.pid == pid)
            .ok_or(Error::ProcessNotFound(pid))?;
        let modules: Vec<ModuleInfo> = guest
            .process_modules(&info)?
            .into_iter()
            .filter(|module| {
                module_short.is_none_or(|short| module.short_name.eq_ignore_ascii_case(short))
            })
            .filter(|module| {
                self.symbols
                    .module_symbol_status(dtb, module.base_address)
                    .is_none()
            })
            .collect();
        if modules.is_empty() {
            return Ok(false);
        }
        guest.load_symbols_for_modules(&self.phys, &self.symbols, modules, dtb)?;
        Ok(true)
    }

    pub fn set_context_dtb_override(&mut self, dtb: Dtb) {
        self.context_dtb_override = Some(self.normalize_dtb(dtb));
    }

    pub fn clear_context_dtb_override(&mut self) {
        self.context_dtb_override = None;
    }

    /// Strip everything the architecture's dtb register carries besides the
    /// page-table base frame: a PCID on AMD64, an ASID on ARM64.
    pub fn normalize_dtb(&self, dtb: u64) -> Dtb {
        dtb & self.arch().dtb_page_mask()
    }

    pub fn set_current_windows_thread_context(&mut self, thread: ThreadInfo) {
        self.selected_frame = None;
        self.windows_thread_selection = Some(thread);
    }

    pub fn set_parked_windows_thread(&mut self, thread: ThreadInfo) {
        self.selected_frame = None;
        self.windows_thread_selection = Some(thread);
        // A parked thread has no coherent register file. In particular, do not
        // let expressions reuse registers cached from the still-selected vCPU.
        self.registers = None;
    }

    pub fn clear_current_windows_thread_context(&mut self) {
        self.windows_thread_selection = None;
    }

    pub fn thread_process_dtb(&self, thread: &ThreadInfo) -> Option<Dtb> {
        // A known owning EPROCESS answers with one read; only a thread whose
        // process pointer was unreadable needs the list walk by pid.
        if thread.pid != Some(0)
            && let Some(eprocess) = thread.eprocess
            && let Some(process) = self
                .guest
                .as_ref()
                .and_then(|guest| guest.process_at(eprocess).ok())
            && process.dtb != 0
        {
            return Some(process.dtb);
        }
        let processes = self
            .guest
            .as_ref()
            .and_then(|guest| guest.enumerate_processes().ok())
            .unwrap_or_default();
        select_thread_process_dtb(
            thread,
            self.current_process_info.as_ref(),
            &processes,
            self.kernel_dtb(),
        )
    }

    /// The process whose page-table root is `cr3_masked`. The selected
    /// Windows thread's owner is checked first: at a stop that is almost
    /// always the answer and costs one EPROCESS read, where the fallback walks
    /// the process list.
    pub fn process_for_cr3(&self, cr3_masked: u64) -> Option<ProcessInfo> {
        let guest = self.guest.as_ref()?;
        if let Some(eprocess) = self
            .windows_thread_selection
            .as_ref()
            .and_then(|thread| thread.eprocess)
            && let Ok(process) = guest.process_at(eprocess)
            && (process.dtb & self.arch().dtb_page_mask()) == cr3_masked
        {
            return Some(process);
        }
        guest
            .enumerate_processes()
            .ok()?
            .into_iter()
            .find(|process| (process.dtb & self.arch().dtb_page_mask()) == cr3_masked)
    }

    pub fn current_thread_pseudo_register(&self, name: &str) -> Option<u64> {
        self.current_thread_pseudo_register_slot(name).flatten()
    }

    fn current_thread_pseudo_register_slot(&self, name: &str) -> Option<Option<u64>> {
        let thread = self.windows_thread_selection.as_ref()?;
        thread.pseudo_register(name)
    }

    /// Read a cached register in a case-insensitive manner. The cache is
    /// populated from either the live backend context or a selected frame, so
    /// expression evaluation does not need to know which one is active.
    pub fn register_value(&self, name: &str) -> Option<u64> {
        lookup_register(self.registers.as_ref()?, name)
    }

    pub fn builtin_variable_value(&self, name: &str) -> Option<u64> {
        self.builtin_variable(name).flatten()
    }

    /// A pseudo-register: `None` when no such name exists, `Some(None)` when
    /// the name exists but the state behind it does not (`$process` with no
    /// process context, `$bug_code` outside a bugcheck). The evaluator needs
    /// the distinction to report an unavailable pseudo-register as such rather
    /// than as a register that does not exist.
    pub fn builtin_variable(&self, name: &str) -> Option<Option<u64>> {
        let name = name.trim_start_matches('$').to_ascii_lowercase();
        // A selected thread answers first, but only when it has the value:
        // otherwise the attached inspection context below may still know it.
        let thread = self.current_thread_pseudo_register_slot(&name);
        if let Some(Some(value)) = thread {
            return Some(Some(value));
        }

        let target = match name.as_str() {
            "dtb" => Some(self.current_dtb()),
            // WinDbg's automatic pseudo-registers. Each is an alias for state
            // this target already tracks; a name whose state is unavailable
            // stays `None` so the expression reports an error instead of
            // inventing a number.
            // WinDbg's `$ip` is the whole instruction pointer, not x86's
            // 16-bit IP: `? $ip` on a kernel address must not truncate.
            "ip" => self.register_value(self.instruction_pointer_register()),
            // The caller of the current scope, one unwind step away.
            "ra" => self.scope_return_address(),
            "csp" => self.register_value(self.stack_pointer_register()),
            "retreg" => self.register_value(self.return_value_register()),
            // Both supported architectures are LP64.
            "ptrsize" => Some(8),
            "pagesize" => Some(
                self.debugger_data
                    .as_ref()
                    .and_then(|data| data.mm_page_size())
                    .map(|page_size| page_size.value)
                    .filter(|page_size| *page_size != 0)
                    .unwrap_or(PAGE_SIZE as u64),
            ),
            "tpid" => self.current_thread_pseudo_register("pid"),
            // Frame 0 is the innermost frame, which is also what an
            // unselected context is looking at.
            "frame" => Some(
                self.selected_frame
                    .as_ref()
                    .map(|frame| frame.index as u64)
                    .unwrap_or(0),
            ),
            "scopeip" => self
                .selected_frame
                .as_ref()
                .map(|frame| frame.ip)
                .or_else(|| self.register_value(self.instruction_pointer_register())),
            "exp" => self.results.first().copied(),
            "exr_code" => self.last_exception_code.map(u64::from),
            // `nt!KiBugCheckData` holds the code and its four parameters; the
            // REPL's `!analyze` decodes the same array in detail.
            "bug_code" => self.bugcheck_data(0),
            "bug_param1" => self.bugcheck_data(1),
            "bug_param2" => self.bugcheck_data(2),
            "bug_param3" => self.bugcheck_data(3),
            "bug_param4" => self.bugcheck_data(4),
            "ntbase" | "kernelbase" => self.guest.as_ref().map(|g| g.ntoskrnl.base_address.0),
            "processbase" | "imagebase" => self.current_process.as_ref().map(|p| p.base_address.0),
            "processdtb" => self.current_process_info.as_ref().map(|p| p.dtb),
            "attachedeprocess" | "attachedprocess" => {
                self.current_process_info.as_ref().map(|p| p.eprocess_va.0)
            }
            "attachedpid" => self.current_process_info.as_ref().map(|p| p.pid),
            "eprocess" | "process" => self.current_process_info.as_ref().map(|p| p.eprocess_va.0),
            "peb" => self.current_process_peb(),
            "pid" => self.current_process_info.as_ref().map(|p| p.pid),
            // `$t0`-`$t19` are WinDbg's twenty writable slots. An assigned
            // value already wins in the evaluator's user-variable lookup, so
            // only the documented default of zero belongs here.
            _ => {
                return match Self::user_pseudo_register_slot(&name) {
                    Some(_) => Some(Some(0)),
                    // Not a name either side knows.
                    None => thread.map(|_| None),
                };
            }
        };
        // A named arm with no value knows the name but not the state behind it.
        Some(target)
    }

    /// The stack-pointer register this architecture calls its own, behind
    /// WinDbg's `$csp`.
    pub fn stack_pointer_register(&self) -> &'static str {
        match self.arch() {
            Arch::Amd64 => "rsp",
            Arch::Arm64 => "sp",
        }
    }

    /// Caller of the current scope, behind WinDbg's `$ra`. A selected frame
    /// unwinds from its own recovered context, so `.frame 2` then `$ra`
    /// names frame 3.
    fn scope_return_address(&self) -> Option<u64> {
        let registers = self
            .selected_frame
            .as_ref()
            .map(|frame| &frame.registers)
            .or(self.registers.as_ref())?;
        return_address_for_register_values(self, registers)
    }

    /// `$peb`: the user-mode PEB of the process context, read from its
    /// `_EPROCESS`. A System-context stop has none, which stays `None` so the
    /// expression reports an error rather than handing back zero.
    fn current_process_peb(&self) -> Option<u64> {
        let eprocess_va = self.current_process_info.as_ref()?.eprocess_va;
        let peb: VirtAddr = self
            .guest()
            .ok()?
            .ntoskrnl
            .types_in(self.kernel_dtb())
            .struct_at("_EPROCESS", eprocess_va)
            .ok()?
            .read_field("Peb")
            .ok()?;
        (!peb.is_zero()).then_some(peb.0)
    }

    /// One entry of `nt!KiBugCheckData`: the bugcheck code at index 0 and its
    /// four parameters after it. Zero when the target has not bugchecked,
    /// which is what the array itself reports.
    fn bugcheck_data(&self, index: u64) -> Option<u64> {
        let address = self
            .symbols
            .find_symbol_across_modules(self.kernel_dtb(), "nt!KiBugCheckData")
            .ok()
            .flatten()?;
        self.address_space(self.kernel_dtb())
            .read::<u64>(address + index * 8)
            .ok()
    }

    /// The instruction pointer this architecture calls its own, behind `$ip`
    /// and `$scopeip`.
    pub fn instruction_pointer_register(&self) -> &'static str {
        match self.arch() {
            Arch::Amd64 => "rip",
            Arch::Arm64 => "pc",
        }
    }

    /// The register a function's return value arrives in, behind `$retreg`.
    fn return_value_register(&self) -> &'static str {
        match self.arch() {
            Arch::Amd64 => "rax",
            Arch::Arm64 => "x0",
        }
    }

    /// `t0`..`t19` and nothing else: `t20`, `t007`, and `ta` are not slots.
    fn user_pseudo_register_slot(name: &str) -> Option<u8> {
        let digits = name.strip_prefix('t')?;
        if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
            return None;
        }
        digits.parse::<u8>().ok().filter(|slot| *slot <= 19)
    }

    pub fn builtin_variables(&self) -> Vec<BuiltinVar> {
        let mut vars = vec![BuiltinVar {
            name: "dtb",
            value: self.current_dtb(),
            source: "current address space",
        }];

        for (name, source) in [
            ("ptrsize", "target pointer size"),
            ("pagesize", "target page size"),
            ("frame", "selected frame index"),
            ("csp", "call stack pointer"),
            ("retreg", "return value register"),
            ("scopeip", "local context instruction pointer"),
            ("ip", "instruction pointer"),
            ("exp", "last expression result"),
            ("exr_code", "last exception code"),
            ("tpid", "current Windows PID"),
        ] {
            if let Some(value) = self.builtin_variable_value(name) {
                vars.push(BuiltinVar {
                    name,
                    value,
                    source,
                });
            }
        }

        if let Some(ref guest) = self.guest {
            vars.push(BuiltinVar {
                name: "ntbase",
                value: guest.ntoskrnl.base_address.0,
                source: "kernel base",
            });
        }

        if let Some(process) = &self.current_process_info {
            vars.extend([
                BuiltinVar {
                    name: "processbase",
                    value: self
                        .current_process
                        .as_ref()
                        .map(|p| p.base_address.0)
                        .unwrap_or(0),
                    source: "attached process image base",
                },
                BuiltinVar {
                    name: "processdtb",
                    value: process.dtb,
                    source: "attached process DTB",
                },
                BuiltinVar {
                    name: "attachedeprocess",
                    value: process.eprocess_va.0,
                    source: "attached process EPROCESS",
                },
                BuiltinVar {
                    name: "attachedpid",
                    value: process.pid,
                    source: "attached process PID",
                },
            ]);
            // pid/eprocess fall back to the attached process when no thread
            // context shadows them; keep the listing in sync with evaluation
            if self.windows_thread_selection.is_none() {
                vars.extend([
                    BuiltinVar {
                        name: "eprocess",
                        value: process.eprocess_va.0,
                        source: "attached process EPROCESS",
                    },
                    BuiltinVar {
                        name: "pid",
                        value: process.pid,
                        source: "attached process PID",
                    },
                ]);
            }
        }

        if let Some(thread) = &self.windows_thread_selection {
            let mut push = |name, value: Option<u64>, source| {
                if let Some(value) = value {
                    vars.push(BuiltinVar {
                        name,
                        value,
                        source,
                    });
                }
            };
            push("thread", Some(thread.ethread.0), "current Windows ETHREAD");
            push("ethread", Some(thread.ethread.0), "current Windows ETHREAD");
            push("kthread", Some(thread.kthread.0), "current Windows KTHREAD");
            push("tid", thread.tid, "current Windows TID");
            push("pid", thread.pid, "current Windows PID");
            push(
                "eprocess",
                thread.eprocess.map(|addr| addr.0),
                "current thread EPROCESS",
            );
            push(
                "process",
                thread.eprocess.map(|addr| addr.0),
                "current thread EPROCESS",
            );
            push("teb", thread.teb.map(|addr| addr.0), "current thread TEB");
            push(
                "threadstart",
                thread.start_address.map(|addr| addr.0),
                "current thread start address",
            );
            push(
                "win32start",
                thread.win32_start_address.map(|addr| addr.0),
                "current thread Win32 start address",
            );
            push(
                "kernelstack",
                thread.kernel_stack.map(|addr| addr.0),
                "current thread kernel stack",
            );
            push(
                "stackbase",
                thread.stack_base.map(|addr| addr.0),
                "current thread stack base",
            );
            push(
                "stacklimit",
                thread.stack_limit.map(|addr| addr.0),
                "current thread stack limit",
            );
            push(
                "trapframe",
                thread.trap_frame.map(|addr| addr.0),
                "current thread trap frame",
            );
        }

        vars
    }

    pub fn set_results(&mut self, results: Vec<u64>, origin: impl Into<String>) {
        self.results = results;
        self.results_origin = Some(origin.into());
    }

    pub fn debugger_data(&self) -> Option<&DebuggerDataBlock> {
        self.debugger_data.as_ref()
    }

    /// Refresh the validated kernel debugger-data snapshot from transport,
    /// symbols, or dump metadata, in that order.
    pub fn refresh_debugger_data(&mut self, transport_hint: Option<DebuggerDataCandidate>) {
        let mut candidates = Vec::with_capacity(4);
        if let Some(candidate) = transport_hint {
            candidates.push(candidate);
        }
        if let Some(guest) = &self.guest {
            for symbol in ["KdDebuggerDataBlock", "KdDebuggerDataListHead"] {
                if let Ok(Some(address)) = self
                    .symbols
                    .find_symbol_across_modules(guest.ntoskrnl.dtb(), &format!("nt!{symbol}"))
                {
                    candidates.push(DebuggerDataCandidate {
                        address,
                        source: MetadataSource::KernelSymbol,
                    });
                }
            }
        }
        if let Some(address) = self
            .phys
            .dmp_info()
            .and_then(|info| info.debugger_data_block)
        {
            candidates.push(DebuggerDataCandidate {
                address: VirtAddr(address),
                source: MetadataSource::DumpHeader,
            });
        }

        let expected_kernel_base = self.kernel_base();
        let debugger_data = {
            let memory = self.context_memory();
            locate_debugger_data_block(&memory, candidates, expected_kernel_base)
        };
        self.debugger_data = debugger_data;
    }

    pub fn reload_guest_with_kernel_base_hint(
        &mut self,
        kernel_base_hint: Option<VirtAddr>,
    ) -> Result<ReloadReport> {
        self.debugger_data = None;
        let previous_base_address = self
            .guest
            .as_ref()
            .map(|g| g.ntoskrnl.base_address)
            .unwrap_or(VirtAddr(0));
        let previous_dtb = self.guest.as_ref().map(|g| g.ntoskrnl.dtb());
        let guest = Guest::new_with_kernel_base_hint(
            self.phys.clone(),
            self.symbols.clone(),
            kernel_base_hint,
        )?;
        let new_dtb = guest.ntoskrnl.dtb();

        if let Some(prev_dtb) = previous_dtb {
            self.symbols.clear_modules_for_dtb(prev_dtb);
        }
        self.symbols.clear_modules_for_dtb(new_dtb);

        let (symbol_report, symbol_error) =
            match guest.load_all_kernel_module_symbols(&self.phys, &self.symbols) {
                Ok(report) => (Some(report), None),
                Err(e) => (None, Some(e.to_string())),
            };

        self.guest = Some(guest);
        self.triage_fallback = None;
        self.triage_modules_cache = None;
        self.detach();
        self.clear_context_dtb_override();
        self.registers = None;
        self.clear_current_windows_thread_context();
        let startup = self.startup_message_data().ok();

        Ok(ReloadReport {
            previous_base_address,
            startup,
            symbol_report,
            symbol_error,
        })
    }

    pub fn current_kernel_mapping_is_valid(&self) -> bool {
        if self.triage_fallback.is_some() {
            return true;
        }
        // Triage dumps often lack the ntoskrnl base page, so the MZ check
        // below would fail on a perfectly coherent snapshot.
        if self.phys.dmp_info().is_some_and(|i| i.is_triage) {
            return true;
        }
        let Some(ref guest) = self.guest else {
            return false;
        };
        let memory = guest.ntoskrnl.memory();
        let mut signature = [0u8; 2];
        memory
            .read_bytes(guest.ntoskrnl.base_address, &mut signature)
            .is_ok_and(|()| signature == *b"MZ")
    }

    pub fn rediscovered_kernel_identity_changed(&self) -> Result<bool> {
        let current_guest = self.guest()?;
        let guest = Guest::new(self.phys.clone(), self.symbols.clone())?;
        Ok(
            guest.ntoskrnl.base_address != current_guest.ntoskrnl.base_address
                || guest.ntoskrnl.dtb() != current_guest.ntoskrnl.dtb(),
        )
    }

    pub fn refresh_kernel_module_symbols(&self) -> Result<ModuleSymbolLoadReport> {
        self.guest
            .as_ref()
            .ok_or(Error::NtoskrnlNotFound)?
            .load_missing_kernel_module_symbols(&self.phys, &self.symbols)
    }

    /// Re-run source selection and symbol indexing for all modules in the
    /// current inspection scope, or for one exact module/short name.
    pub fn reload_module_symbols(
        &self,
        module_name: Option<&str>,
    ) -> Result<ModuleSymbolLoadReport> {
        let mut modules = self.modules()?;
        if let Some(name) = module_name {
            modules.retain(|module| {
                module.short_name.eq_ignore_ascii_case(name)
                    || module
                        .name
                        .rsplit(['\\', '/'])
                        .next()
                        .is_some_and(|image| image.eq_ignore_ascii_case(name))
            });
            if modules.is_empty() {
                return Err(Error::DebugInfo(format!("module not found: {name}")));
            }
        }

        let dtb = self
            .current_process_info
            .as_ref()
            .map(|process| process.dtb)
            .unwrap_or_else(|| self.kernel_dtb());
        let bases = modules
            .iter()
            .map(|module| module.base_address)
            .collect::<Vec<_>>();
        self.symbols.invalidate_modules(dtb, &bases);

        match self.guest.as_ref() {
            Some(guest) => guest.load_symbols_for_modules(&self.phys, &self.symbols, modules, dtb),
            None => Guest::load_module_symbols(
                &self.phys,
                &self.symbols,
                modules,
                dtb,
                false,
                self.arch(),
            ),
        }
    }

    pub fn current_dtb(&self) -> Dtb {
        // An explicit process attach is authoritative for the live inspection
        // address space. `context_dtb_override` follows the halted vCPU's CR3
        // only in the unattached case.
        match &self.current_process {
            Some(p) => p.dtb(),
            None => self
                .context_dtb_override
                .unwrap_or_else(|| self.kernel_dtb()),
        }
    }

    /// Memory view for the active inspection address space. An explicit process
    /// attach wins; otherwise this follows the halted thread's CR3.
    pub fn context_memory(&self) -> AddressSpace<'_, PhysMem> {
        self.address_space(self.current_dtb())
    }

    /// Guest architecture (AMD64 until the kernel is discovered).
    pub fn arch(&self) -> Arch {
        self.guest
            .as_ref()
            .map(|g| g.ntoskrnl.arch())
            .unwrap_or(Arch::Amd64)
    }

    /// Select x86 or AMD64 decoding for a code address in the current scope.
    /// Module enumeration is intentionally local to this query so one caller
    /// can reuse the result for every instruction in its decode window.
    pub fn code_bitness(&self, address: VirtAddr) -> u32 {
        if self.effmach.is_some() {
            return decide_bitness(self.effmach, None, false, &[], address);
        }

        let cs = if self
            .selected_frame
            .as_ref()
            .is_some_and(|frame| !frame.is_live())
        {
            None
        } else {
            self.register_value("cs")
        };
        if decide_bitness(None, cs, false, &[], address) == CODE_BITNESS_X86 {
            return CODE_BITNESS_X86;
        }

        let is_wow64 = self
            .current_process_info
            .as_ref()
            .is_some_and(ProcessInfo::is_wow64);
        if !is_wow64 {
            return CODE_BITNESS_AMD64;
        }

        let modules = self.modules().unwrap_or_default();
        decide_bitness(None, cs, true, &modules, address)
    }

    /// An address space rooted at `dtb` in the resolved guest architecture. On
    /// ARM64 the kernel root (TTBR1) is threaded in so kernel-VA reads work
    /// from any space; on AMD64 one CR3 covers both halves.
    pub fn address_space(&self, dtb: Dtb) -> AddressSpace<'_, PhysMem> {
        match self.arch() {
            Arch::Amd64 => AddressSpace::new(&self.phys, dtb),
            Arch::Arm64 => AddressSpace::new_arm64(&self.phys, dtb, self.kernel_dtb()),
        }
    }

    /// Kernel-root address space (reads kernel VAs on both arches).
    pub fn kernel_address_space(&self) -> AddressSpace<'_, PhysMem> {
        self.address_space(self.kernel_dtb())
    }

    /// All matching symbol identities visible from the active address space.
    pub fn symbol_candidates(&self, name: &str) -> Vec<SymbolCandidate> {
        self.symbols
            .find_symbol_candidates(self.current_dtb(), name)
    }

    /// Fuzzy-search the active symbol index and resolve only unambiguous
    /// module/address identities. `module!query` restricts the search.
    pub fn search_symbols(&self, query: &str, limit: usize) -> Vec<SymbolSearchMatch> {
        let dtb = self.current_dtb();
        let names: Vec<String> = match query.split_once('!') {
            Some((module, query)) => self
                .symbols
                .search_symbols_in_module(dtb, module, query, limit)
                .into_iter()
                .map(|name| format!("{module}!{name}"))
                .collect(),
            None => self.current_symbol_index().search(query, limit),
        };
        names
            .into_iter()
            .map(|qualified| {
                let locations: HashSet<(String, u64)> = self
                    .symbol_candidates(&qualified)
                    .into_iter()
                    .map(|candidate| (candidate.module, candidate.address.0))
                    .collect();
                let (resolved_module, address) = if locations.len() == 1 {
                    let (module, address) = locations.into_iter().next().unwrap();
                    (Some(module), Some(VirtAddr(address)))
                } else {
                    (None, None)
                };
                let name = qualified
                    .rsplit_once('!')
                    .map_or(qualified.as_str(), |(_, bare)| bare)
                    .to_string();
                SymbolSearchMatch {
                    name,
                    address,
                    module: resolved_module,
                }
            })
            .collect()
    }
    pub fn nearest_symbol_current_context(
        &self,
        address: VirtAddr,
    ) -> Option<(String, String, u32)> {
        self.symbols
            .find_closest_symbol_for_address(self.current_dtb(), address)
    }

    pub fn closest_symbol_current_context(&self, address: VirtAddr) -> Option<String> {
        self.nearest_symbol_current_context(address)
            .map(|(module, name, offset)| format_symbol_with_offset(&module, &name, offset))
    }

    pub fn source_location(&self, address: VirtAddr) -> Option<SourceLocation> {
        self.symbols.source_location(self.current_dtb(), address)
    }

    /// Resolve the source line and exclusive address extent in the current
    /// inspection context for consumers that step complete source lines.
    pub fn source_line_extent(&self, address: VirtAddr) -> Option<SourceLineExtent> {
        self.symbols.source_line_extent(self.current_dtb(), address)
    }

    /// End of the function's opening source-line range, after the prologue.
    /// Return `None` without private line records or if the next record leaves
    /// the function.
    pub fn post_prologue_address(&self, dtb: Dtb, address: VirtAddr) -> Option<VirtAddr> {
        let end = self.symbols.source_line_extent(dtb, address)?.end?;
        let function = self.symbols.find_closest_symbol_for_address(dtb, address)?;
        let at_end = self.symbols.find_closest_symbol_for_address(dtb, end)?;
        (function.0 == at_end.0
            && function.1 == at_end.1
            && self.symbols.source_line_extent(dtb, end).is_some())
        .then_some(end)
    }

    pub fn source_addresses(&self, file: &str, line: u32) -> Vec<VirtAddr> {
        self.symbols
            .source_addresses(self.current_dtb(), file, line)
    }
    /// Return private procedure locals in scope at `address`.
    pub fn procedure_locals(&self, address: VirtAddr) -> Result<Option<Arc<Vec<ProcedureLocal>>>> {
        self.symbols.procedure_locals(self.current_dtb(), address)
    }

    /// Address of a memory-resident local in the current inspection context
    /// (the selected frame's registers when one is selected, else the live
    /// ones). `None` for register-held locals, unavailable PDB recipes, and
    /// frame-relative locals whose base could not be recovered.
    pub fn procedure_local_address(&self, local: &ProcedureLocal) -> Option<u64> {
        let registers = self.registers.as_ref()?;
        match &local.location {
            LocalVariableLocation::Register { .. } | LocalVariableLocation::Unavailable { .. } => {
                None
            }
            LocalVariableLocation::RegisterRelative { register, offset } => {
                let base = lookup_register(registers, register)?;
                Some(base.wrapping_add_signed(i64::from(*offset)))
            }
            LocalVariableLocation::FrameRelative { offset } => {
                let frame_base = self
                    .selected_frame
                    .as_ref()
                    .and_then(|frame| frame.frame_base)
                    .or_else(|| frame_base_for_register_values(self, registers))
                    .or_else(|| lookup_register(registers, self.stack_pointer_register()))?;
                Some(frame_base.wrapping_add_signed(i64::from(*offset)))
            }
        }
    }

    /// Resolve a scalar local from the current halted register/memory context.
    /// Returns `None` when the PDB recipe is unavailable, the register context
    /// does not correspond to the requested procedure, or the value is wider
    /// than a scalar u64.
    pub fn resolve_procedure_local_value(
        &self,
        address: VirtAddr,
        local: &ProcedureLocal,
    ) -> Option<u64> {
        if self
            .register_value("rip")
            .is_none_or(|rip| rip != address.0)
        {
            return None;
        }
        let size = usize::try_from(local.byte_size?).ok()?;
        if size == 0 || size > 8 {
            return None;
        }
        let registers = self.registers.as_ref()?;
        match &local.location {
            LocalVariableLocation::Register { register } => {
                let value = lookup_register(registers, register)?;
                Some(if size == 8 {
                    value
                } else {
                    value & ((1u64 << (size * 8)) - 1)
                })
            }
            LocalVariableLocation::RegisterRelative { .. }
            | LocalVariableLocation::FrameRelative { .. } => {
                let address = VirtAddr(self.procedure_local_address(local)?);
                let mut bytes = [0u8; 8];
                self.context_memory()
                    .read_bytes(address, &mut bytes[..size])
                    .ok()?;
                Some(u64::from_le_bytes(bytes))
            }
            LocalVariableLocation::Unavailable { .. } => None,
        }
    }

    /// Enumerate processes matching `filter` (see [`process_matches`]); `None`
    /// returns all. The shared list helper behind the SDK/MCP process filters.
    ///
    /// Falls back to the triage EPROCESS snapshot when the full linked-list
    /// walk is unavailable (e.g. triage dumps with limited memory).
    pub fn matching_processes(&self, filter: Option<&str>) -> Result<Vec<ProcessInfo>> {
        let procs = match self.guest().and_then(|g| g.enumerate_processes()) {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => self.triage_process_list().unwrap_or_default(),
            Err(Error::NtoskrnlNotFound) => self.triage_process_list()?,
            Err(e) => return Err(e),
        };
        Ok(match filter {
            None => procs,
            Some(f) => procs
                .into_iter()
                .filter(|p| process_matches(p, f))
                .collect(),
        })
    }

    /// Extract a single-entry process list from the triage EPROCESS snapshot.
    fn triage_process_list(&self) -> Result<Vec<ProcessInfo>> {
        let info = self.phys.dmp_info().ok_or(Error::NtoskrnlNotFound)?;
        let proc_snap = info
            .triage_process_snapshot
            .as_deref()
            .ok_or(Error::NtoskrnlNotFound)?;

        let dtb = self.kernel_dtb();
        let eprocess_layout = self
            .symbols
            .find_type_across_modules(dtb, "_EPROCESS")
            .ok_or(Error::ExpectedSymbols)?;

        let pid = eprocess_layout
            .field_offset("UniqueProcessId")
            .ok()
            .and_then(|off| {
                let off = off as usize;
                if off + 8 <= proc_snap.len() {
                    proc_snap[off..off + 8]
                        .try_into()
                        .ok()
                        .map(u64::from_le_bytes)
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let name = eprocess_layout
            .field_offset("ImageFileName")
            .ok()
            .and_then(|off| {
                let off = off as usize;
                if off + 15 <= proc_snap.len() {
                    let buf = &proc_snap[off..off + 15];
                    let end = buf.iter().position(|&c| c == 0).unwrap_or(15);
                    let s = String::from_utf8_lossy(&buf[..end]).to_string();
                    if s.is_empty() { None } else { Some(s) }
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "<unknown>".to_string());

        Ok(vec![ProcessInfo {
            pid,
            name,
            // The header CR3 is unusable in a triage dump (no page tables
            // captured); reads go through the identity mapping, so report
            // the DTB that actually resolves.
            dtb: self.kernel_dtb(),
            eprocess_va: VirtAddr(0),
            wow64_peb: None,
        }])
    }

    pub fn selected_process_info(&self) -> Result<ProcessInfo> {
        if let Some(process) = self.current_process_info.as_ref() {
            return Ok(process.clone());
        }

        let processes = self.matching_processes(None)?;
        if let Some(thread) = self.windows_thread_selection.as_ref()
            && let Some(process) = processes
                .iter()
                .find(|process| thread_owner_matches(thread, process))
        {
            return Ok(process.clone());
        }
        let dtb = self.current_dtb();
        processes
            .into_iter()
            .find(|process| process.dtb == dtb)
            .ok_or_else(|| {
                Error::DebugInfo(
                    "current process unavailable: select a process or halted Windows thread"
                        .to_string(),
                )
            })
    }

    pub fn read_layout_field<T>(&self, layout: &TypeInfo, base: VirtAddr, name: &str) -> Result<T>
    where
        T: Copy + zerocopy::FromZeros + zerocopy::FromBytes + zerocopy::IntoBytes,
    {
        self.context_memory()
            .read(base + layout.field_offset(name)?)
    }

    pub fn extract_layout_bits(
        &self,
        layout: &TypeInfo,
        base: VirtAddr,
        name: &str,
    ) -> Result<u64> {
        let field = layout
            .fields
            .get(name)
            .ok_or_else(|| Error::FieldNotFound(name.to_string()))?;
        let raw: u64 = self.context_memory().read(base + field.offset as u64)?;
        if let ParsedType::Bitfield { pos, len, .. } = &field.type_data {
            let mask = if *len == 64 {
                u64::MAX
            } else {
                (1u64 << *len) - 1
            };
            Ok((raw >> *pos) & mask)
        } else {
            Ok(raw)
        }
    }

    pub fn current_symbol_index(&self) -> SymbolIndex {
        self.symbols.merged_symbol_index(Some(self.current_dtb()))
    }

    pub fn current_types_index(&self) -> SymbolIndex {
        self.symbols.merged_types_index(Some(self.current_dtb()))
    }

    pub fn current_enums_index(&self) -> SymbolIndex {
        self.symbols.merged_enum_index(Some(self.current_dtb()))
    }

    pub fn startup_message_data(&mut self) -> Result<StartupMessage> {
        // Dumps may not capture these symbols' memory, so they degrade to
        // zeroed fields; live sessions propagate the underlying error.
        let degraded = self.phys.dmp_info().is_some();
        let guest = self.guest()?;
        let build_number: u16 = match guest
            .ntoskrnl
            .symbol("NtBuildNumber")
            .and_then(|s| s.read())
        {
            Ok(v) => v,
            Err(_) if degraded => 0,
            Err(e) => return Err(e),
        };
        let base_address = guest.ntoskrnl.base_address;
        let loaded_module_list = match guest
            .ntoskrnl
            .symbol("PsLoadedModuleList")
            .and_then(|s| s.read())
        {
            Ok(v) => v,
            Err(_) if degraded => VirtAddr(0),
            Err(e) => return Err(e),
        };

        Ok(StartupMessage {
            build_number: Value(build_number),
            base_address,
            loaded_module_list,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CODE_BITNESS_AMD64, CODE_BITNESS_X86, ListTermination, ThreadInfo, bounded_list_walk,
        decide_bitness, select_thread_process_dtb, thread_owner_matches,
    };
    use crate::error::Error;
    use crate::guest::{ModuleInfo, ProcessInfo};
    use crate::session::{Session, session_over_memory};
    use crate::types::VirtAddr;

    /// A target whose only module records `records` as its line table and
    /// `symbols` as its exports, for resolution tests that need private line
    /// information without a PDB.
    fn target_with_lines(symbols: &[(&str, u32)], records: &[(u32, Option<u32>, u32)]) -> Session {
        let session = session_over_memory(0x1000, &[0u8; 0x80]);
        let dtb = session.target.current_dtb();
        session.target.symbols.set_kernel(Some(1), dtb);
        session
            .target
            .symbols
            .inject_module_for_test(1, Vec::new(), symbols);
        session.target.symbols.inject_source_lines_for_test(
            1,
            dtb,
            VirtAddr(0x1000),
            0x1000,
            "driver.c",
            records,
        );
        session
    }

    #[test]
    fn windbg_pseudo_register_slots_and_exception_code() {
        let mut session = session_over_memory(0x1000, &[0u8; 0x80]);
        let target = &session.target;

        // Unassigned slots read zero, as WinDbg documents; names outside the
        // range are not slots at all.
        assert_eq!(target.builtin_variable_value("t0"), Some(0));
        assert_eq!(target.builtin_variable_value("$t19"), Some(0));
        assert_eq!(target.builtin_variable_value("t20"), None);
        assert_eq!(target.builtin_variable_value("t007"), None);
        assert_eq!(target.builtin_variable_value("ta"), None);

        // `$exr_code` follows the recorded stop, so it is absent until one
        // has been observed rather than reading as zero.
        assert_eq!(target.builtin_variable_value("exr_code"), None);
        session.target.last_exception_code = Some(0x8000_0003);
        assert_eq!(
            session.target.builtin_variable_value("exr_code"),
            Some(0x8000_0003)
        );
    }

    #[test]
    fn post_prologue_address_lands_on_the_first_statement() {
        // Line 123 is the opening brace, covering the prologue; line 132 is the
        // first statement, where the arguments are finally where the PDB says.
        let session = target_with_lines(
            &[("DriverEntry", 0)],
            &[(0, Some(0x0e), 123), (0x0e, Some(0x1b), 132)],
        );
        assert_eq!(
            session
                .target
                .post_prologue_address(session.target.current_dtb(), VirtAddr(0x1000)),
            Some(VirtAddr(0x100e))
        );
    }

    #[test]
    fn post_prologue_address_refuses_to_leave_the_function() {
        // The next record belongs to the following function: skipping there
        // would move the breakpoint out of the one that was asked for.
        let session = target_with_lines(
            &[("DriverEntry", 0), ("Unload", 0x10)],
            &[(0, Some(0x10), 123), (0x10, Some(0x20), 200)],
        );
        assert_eq!(
            session
                .target
                .post_prologue_address(session.target.current_dtb(), VirtAddr(0x1000)),
            None
        );

        // No following record at all: nothing to skip to.
        let single = target_with_lines(&[("DriverEntry", 0)], &[(0, None, 123)]);
        assert_eq!(
            single
                .target
                .post_prologue_address(single.target.current_dtb(), VirtAddr(0x1000)),
            None
        );
    }

    fn sample_thread() -> ThreadInfo {
        ThreadInfo {
            ethread: VirtAddr(0xffff_8000_0000_1000),
            kthread: VirtAddr(0xffff_8000_0000_1100),
            tid: Some(0x44),
            pid: Some(0x22),
            process_name: Some("sample.exe".to_string()),
            eprocess: Some(VirtAddr(0xffff_8000_0000_2000)),
            state: Some(5),
            wait_reason: Some(6),
            priority: Some(13),
            base_priority: Some(8),
            wait_irql: Some(2),
            kernel_stack_resident: Some(true),
            start_address: Some(VirtAddr(0x7ff7_0000_1234)),
            win32_start_address: Some(VirtAddr(0x7ff7_0000_5678)),
            teb: Some(VirtAddr(0x0000_0000_0050_0000)),
            kernel_stack: Some(VirtAddr(0xffff_f000_0000_8000)),
            stack_base: Some(VirtAddr(0xffff_f000_0000_a000)),
            stack_limit: Some(VirtAddr(0xffff_f000_0000_6000)),
            trap_frame: Some(VirtAddr(0xffff_f000_0000_7000)),
            pending_irps: Some(vec![VirtAddr(0xffff_8000_0000_3000)]),
        }
    }

    #[test]
    fn thread_pseudo_registers_are_case_insensitive_and_optional() {
        let mut thread = sample_thread();
        assert_eq!(
            thread.pseudo_register_value("TrapFrame"),
            thread.trap_frame.map(|addr| addr.0)
        );
        thread.teb = None;
        assert_eq!(thread.pseudo_register_value("TEB"), None);
        assert_eq!(thread.pseudo_register_value("unknown"), None);
    }

    #[test]
    fn code_bitness_prefers_explicit_context_and_wow64_images() {
        let mut x86 = ModuleInfo::new("wow.dll".into(), VirtAddr(0x400000), 0x1000);
        x86.is_32bit = true;
        let x64 = ModuleInfo::new("native.dll".into(), VirtAddr(0x0000_7ff6_0000_0000), 0x1000);

        assert_eq!(
            decide_bitness(
                Some(CODE_BITNESS_AMD64),
                Some(0x23),
                true,
                &[x86.clone()],
                VirtAddr(0x400100),
            ),
            CODE_BITNESS_AMD64
        );
        assert_eq!(
            decide_bitness(None, Some(0x23), false, &[], VirtAddr(0x7fff_0000),),
            CODE_BITNESS_X86
        );
        assert_eq!(
            decide_bitness(None, None, true, &[x86], VirtAddr(0x400100)),
            CODE_BITNESS_X86
        );
        assert_eq!(
            decide_bitness(None, None, true, &[x64], VirtAddr(0x0000_7ff6_0000_0100)),
            CODE_BITNESS_AMD64
        );
        assert_eq!(
            decide_bitness(None, None, false, &[], VirtAddr(0x7fff_0000)),
            CODE_BITNESS_AMD64
        );
    }

    #[test]
    fn owning_process_selection_prefers_eprocess_identity() {
        let thread = sample_thread();
        let same_pid_wrong_process = ProcessInfo {
            pid: thread.pid.unwrap(),
            name: "reused.exe".into(),
            dtb: 0x1111_0000,
            eprocess_va: VirtAddr(0xffff_8000_0000_9999),
            wow64_peb: None,
        };
        let owner = ProcessInfo {
            pid: 0x99,
            name: "sample.exe".into(),
            dtb: 0x2222_0000,
            eprocess_va: thread.eprocess.unwrap(),
            wow64_peb: None,
        };
        assert!(!thread_owner_matches(&thread, &same_pid_wrong_process));
        assert!(thread_owner_matches(&thread, &owner));
        assert_eq!(
            select_thread_process_dtb(
                &thread,
                Some(&same_pid_wrong_process),
                &[same_pid_wrong_process.clone(), owner.clone()],
                0x3333_0000,
            ),
            Some(0x2222_0000)
        );
    }

    #[test]
    fn diagnostic_list_walk_honors_bound() {
        let (links, termination) =
            bounded_list_walk(VirtAddr(0), 2, |address| Ok(VirtAddr(address.0 + 1)));
        assert_eq!(links, vec![VirtAddr(1), VirtAddr(2)]);
        assert_eq!(termination, ListTermination::Bound);
    }

    #[test]
    fn diagnostic_list_walk_flags_non_head_cycle() {
        let (links, termination) = bounded_list_walk(VirtAddr(0), 8, |address| {
            Ok(match address.0 {
                0 => VirtAddr(1),
                1 => VirtAddr(2),
                _ => VirtAddr(1),
            })
        });
        assert_eq!(links, vec![VirtAddr(1), VirtAddr(2)]);
        assert_eq!(termination, ListTermination::Cycle(VirtAddr(1)));
    }

    #[test]
    fn diagnostic_list_walk_preserves_corrupt_read_error() {
        let (links, termination) = bounded_list_walk(VirtAddr(0), 8, |address| match address.0 {
            0 => Ok(VirtAddr(1)),
            1 => Ok(VirtAddr(2)),
            _ => Err(Error::DebugInfo("synthetic bad flink".into())),
        });
        assert_eq!(links, vec![VirtAddr(1), VirtAddr(2)]);
        assert_eq!(
            termination,
            ListTermination::Corrupt("synthetic bad flink".into())
        );
    }
}
