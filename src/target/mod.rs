use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

mod context;
pub mod cpu;
pub mod heap;
mod lifecycle;
mod list;
mod memory;
pub mod meta;
pub mod mm;
pub mod object;
pub mod pnp;
pub mod pool;
pub mod sched;
pub mod security;
mod symbols;
pub mod usermode;

pub use list::{ListCursor, ListTermination, bounded_list_walk};

use self::mm::AddressDescription;
use crate::unwind::{RecoveredFrame, return_address_for_register_values};

use crate::{
    backend::MemoryOps,
    debugger_data::{DebuggerDataBlock, MetadataSource, MetadataValue},
    dmp::DmpInfo,
    error::{Error, Result},
    guest::{Guest, ModuleInfo, ModuleSymbolLoadReport, ProcessInfo},
    memory::{DTB_IDENTITY, PAGE_SIZE},
    phys::PhysMem,
    symbols::SymbolStore,
    types::{Arch, Dtb, VirtAddr},
};

pub struct Target {
    pub phys: Arc<PhysMem>,
    pub symbols: Arc<SymbolStore>,
    pub guest: Option<Guest>,
    debugger_data: Option<DebuggerDataBlock>,
    /// The attached process (`.process`/`attach`), or `None` for the kernel
    /// scope. Its `dtb` roots the process address space; see
    /// [`Self::process_dtb`].
    process: Option<ProcessInfo>,
    /// Explicit code-machine override (`32` or `64`); `None` follows context.
    pub effmach: Option<u32>,
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
    /// Bumped each time [`Self::reload_guest`] rebuilds the guest. Hosts stamp
    /// the handles they hand out with it, so an address from before a reboot
    /// is refused instead of read through the new kernel's layout.
    generation: Arc<AtomicU64>,
}

/// The inspection scope a host has selected (`.process`, `.context`, `.frame`,
/// `.thread`), moved out whole by [`Target::take_selection`] so a host can run
/// one operation in a scope of its own and put the user's selection back.
pub struct TargetSelection {
    process: Option<ProcessInfo>,
    context_dtb_override: Option<Dtb>,
    selected_frame: Option<SelectedFrame>,
    windows_thread_selection: Option<ThreadInfo>,
    registers: Option<HashMap<String, u64>>,
}

impl TargetSelection {
    fn holds_live_registers(&self) -> bool {
        self.selected_frame
            .as_ref()
            .is_none_or(SelectedFrame::is_live)
    }

    /// Move the register cache out when it holds the live vCPU file rather
    /// than a selected frame's or context record's recovered registers.
    pub fn take_live_registers(&mut self) -> Option<HashMap<String, u64>> {
        if self.holds_live_registers() {
            self.registers.take()
        } else {
            None
        }
    }

    /// Put back a live register cache moved out with
    /// [`Self::take_live_registers`] (as the operation left it).
    pub fn put_live_registers(&mut self, registers: Option<HashMap<String, u64>>) {
        if self.holds_live_registers() {
            self.registers = registers;
        }
    }
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

/// A counted string descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringDescriptor {
    /// `_UNICODE_STRING` (`dS`).
    Unicode,
    /// `_STRING` / `ANSI_STRING` (`ds`).
    Ansi,
}

impl StringDescriptor {
    /// The PDB name, then older spellings to try: some PDBs spell `_STRING`
    /// only as `_ANSI_STRING`.
    fn type_names(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Self::Unicode => ("_UNICODE_STRING", &[]),
            Self::Ansi => ("_STRING", &["_ANSI_STRING"]),
        }
    }
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

#[cfg(test)]
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

impl ThreadInfo {
    /// A thread pseudo-register: `None` when this thread has no such name,
    /// `Some(None)` when it has the name but not the state behind it (a
    /// kernel thread has no TEB, an unwalked thread no trap frame). Telling
    /// the two apart is what lets the evaluator say "not available here"
    /// instead of "no such register".
    pub fn pseudo_register(&self, name: &str) -> Option<Option<u64>> {
        let register = THREAD_PSEUDO_REGISTERS.iter().find(|register| {
            register
                .names
                .iter()
                .any(|known| known.eq_ignore_ascii_case(name))
        })?;
        Some((register.read)(self))
    }

    pub fn pseudo_register_value(&self, name: &str) -> Option<u64> {
        self.pseudo_register(name).flatten()
    }
}

/// A thread pseudo-register: the names it answers to, the `vars` source
/// text, and the thread state it reads.
struct ThreadPseudoRegister {
    names: &'static [&'static str],
    source: &'static str,
    read: fn(&ThreadInfo) -> Option<u64>,
}

const THREAD_PSEUDO_REGISTERS: &[ThreadPseudoRegister] = &[
    ThreadPseudoRegister {
        names: &["thread", "ethread"],
        source: "current Windows ETHREAD",
        read: |thread| Some(thread.ethread.0),
    },
    ThreadPseudoRegister {
        names: &["kthread"],
        source: "current Windows KTHREAD",
        read: |thread| Some(thread.kthread.0),
    },
    ThreadPseudoRegister {
        names: &["tid"],
        source: "current Windows TID",
        read: |thread| thread.tid,
    },
    ThreadPseudoRegister {
        names: &["pid"],
        source: "current Windows PID",
        read: |thread| thread.pid,
    },
    ThreadPseudoRegister {
        names: &["proc", "process", "eprocess"],
        source: "current thread EPROCESS",
        read: |thread| thread.eprocess.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["teb"],
        source: "current thread TEB",
        read: |thread| thread.teb.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["threadstart", "startaddress"],
        source: "current thread start address",
        read: |thread| thread.start_address.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["win32start", "win32startaddress"],
        source: "current thread Win32 start address",
        read: |thread| thread.win32_start_address.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["kernelstack"],
        source: "current thread kernel stack",
        read: |thread| thread.kernel_stack.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["stackbase"],
        source: "current thread stack base",
        read: |thread| thread.stack_base.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["stacklimit"],
        source: "current thread stack limit",
        read: |thread| thread.stack_limit.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["trapframe"],
        source: "current thread trap frame",
        read: |thread| thread.trap_frame.map(|address| address.0),
    },
    ThreadPseudoRegister {
        names: &["priority"],
        source: "current thread priority",
        read: |thread| thread.priority.map(u64::from),
    },
    ThreadPseudoRegister {
        names: &["basepriority"],
        source: "current thread base priority",
        read: |thread| thread.base_priority.map(u64::from),
    },
    ThreadPseudoRegister {
        names: &["waitirql"],
        source: "current thread wait IRQL",
        read: |thread| thread.wait_irql.map(u64::from),
    },
    ThreadPseudoRegister {
        names: &["stackresident", "kernelstackresident"],
        source: "current thread kernel stack residency",
        read: |thread| thread.kernel_stack_resident.map(u64::from),
    },
];
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

/// Object pointer held in an `EX_FAST_REF`; the low four bits carry the
/// cached reference count, not address bits.
pub fn fast_ref_address(raw: u64) -> VirtAddr {
    VirtAddr(raw & !0xf)
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

pub struct StartupMessage {
    pub build_number: u16,
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

    /// Whether the host has asked long-running work to stop.
    pub fn interrupted(&self) -> bool {
        self.interrupt.load(Ordering::Relaxed)
    }

    pub fn current_thread_pseudo_register(&self, name: &str) -> Option<u64> {
        self.current_thread_pseudo_register_slot(name).flatten()
    }

    fn current_thread_pseudo_register_slot(&self, name: &str) -> Option<Option<u64>> {
        let thread = self.windows_thread_selection.as_ref()?;
        thread.pseudo_register(name)
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
            "processbase" | "imagebase" => self.current_process_image_base(),
            "processdtb" => self.process.as_ref().map(|p| p.dtb),
            "attachedeprocess" | "attachedprocess" => {
                self.process.as_ref().map(|p| p.eprocess_va.0)
            }
            "attachedpid" => self.process.as_ref().map(|p| p.pid),
            "eprocess" | "process" => self.process.as_ref().map(|p| p.eprocess_va.0),
            "peb" => self.current_process_peb(),
            "pid" => self.process.as_ref().map(|p| p.pid),
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
        let eprocess_va = self.process.as_ref()?.eprocess_va;
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

    /// `$processbase`: the attached process's main image base, from its PEB's
    /// `ImageBaseAddress`. `None` for a kernel-only process.
    fn current_process_image_base(&self) -> Option<u64> {
        let peb = VirtAddr(self.current_process_peb()?);
        let base: VirtAddr = self
            .types_in(self.process_dtb())
            .struct_at("_PEB", peb)
            .ok()?
            .read_field("ImageBaseAddress")
            .ok()?;
        Some(base.0)
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

        if let Some(process) = &self.process {
            vars.extend([
                BuiltinVar {
                    name: "processbase",
                    value: self.current_process_image_base().unwrap_or(0),
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
            for register in THREAD_PSEUDO_REGISTERS {
                if let Some(value) = (register.read)(thread) {
                    vars.extend(register.names.iter().map(|&name| BuiltinVar {
                        name,
                        value,
                        source: register.source,
                    }));
                }
            }
        }

        vars
    }

    pub fn set_results(&mut self, results: Vec<u64>, origin: impl Into<String>) {
        self.results = results;
        self.results_origin = Some(origin.into());
    }

    /// Guest architecture: the discovered kernel's, else a dump's declared
    /// machine type, else AMD64.
    pub fn arch(&self) -> Arch {
        match &self.guest {
            Some(guest) => guest.ntoskrnl.arch(),
            None => self
                .phys
                .dmp_info()
                .and_then(DmpInfo::arch)
                .unwrap_or(Arch::Amd64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sample_thread;
    use crate::session::session_over_memory;

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
    fn thread_pseudo_register_inventory_matches_lookup_names() {
        const NAMES: &[&str] = &[
            "thread",
            "ethread",
            "kthread",
            "tid",
            "pid",
            "proc",
            "process",
            "eprocess",
            "teb",
            "threadstart",
            "startaddress",
            "win32start",
            "win32startaddress",
            "kernelstack",
            "stackbase",
            "stacklimit",
            "trapframe",
            "priority",
            "basepriority",
            "waitirql",
            "stackresident",
            "kernelstackresident",
        ];
        let thread = sample_thread();
        let mut session = session_over_memory(0x1000, &[0u8; 0x80]);
        session
            .target
            .set_current_windows_thread_context(thread.clone());
        let variables = session.target.builtin_variables();

        for name in NAMES {
            let value = thread
                .pseudo_register_value(name)
                .unwrap_or_else(|| panic!("{name} should resolve for the sample thread"));
            assert_eq!(session.target.builtin_variable_value(name), Some(value));
            assert!(
                variables
                    .iter()
                    .any(|variable| variable.name == *name && variable.value == value),
                "{name} should be listed with its resolved value"
            );
        }
        for variable in variables.iter().filter(|variable| {
            variable.source.starts_with("current Windows")
                || variable.source.starts_with("current thread")
        }) {
            assert_eq!(
                session.target.builtin_variable_value(variable.name),
                Some(variable.value)
            );
        }
    }
}
