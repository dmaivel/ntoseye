use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use crate::{
    backend::MemoryOps,
    bugchecks::looks_like_kernel_pointer,
    debugger_data::{
        DebuggerDataBlock, DebuggerDataCandidate, MetadataSource, MetadataValue,
        locate_debugger_data_block, read_counter_from_getter,
    },
    diagnostics,
    error::{Error, Result},
    guest::{
        Guest, ModuleInfo, ModuleSymbolLoadReport, ProcessInfo, StructRef, WinObject,
        section_name_at,
    },
    memory::{AddressSpace, DTB_IDENTITY, PAGE_SIZE},
    phys::PhysMem,
    symbols::{
        LocalVariableLocation, ParsedType, ProcedureLocal, SourceLocation, SymbolCandidate,
        SymbolIndex, SymbolStore, TypeInfo,
    },
    types::{Arch, Dtb, PageTableEntry, Value, VirtAddr},
};

pub struct Target {
    pub phys: Arc<PhysMem>,
    pub symbols: Arc<SymbolStore>,
    pub guest: Option<Guest>,
    debugger_data: Option<DebuggerDataBlock>,
    pub current_process: Option<WinObject>,
    pub current_process_info: Option<ProcessInfo>,
    /// Bare WinObject for triage dumps without a discovered kernel, providing
    /// identity-mapped memory access so commands like disassemble/search work.
    triage_fallback: Option<WinObject>,
    triage_modules_cache: Option<Vec<ModuleInfo>>,
    context_dtb_override: Option<Dtb>,
    pub registers: Option<HashMap<String, u64>>,
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
}

const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;

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

#[derive(Debug, Clone)]
pub struct DriverObjectInfo {
    pub name: String,
    pub object: VirtAddr,
    pub driver_start: VirtAddr,
    pub driver_size: u64,
    pub device_object: VirtAddr,
    pub driver_unload: VirtAddr,
}

/// A decoded `_IRP` plus its current `_IO_STACK_LOCATION` (when resolvable).
#[derive(Debug, Clone)]
pub struct IrpInfo {
    pub address: VirtAddr,
    pub irp_type: u16,
    pub size: u16,
    pub stack_count: u8,
    pub current_location: u8,
    pub pending_returned: bool,
    pub requestor_mode: u8,
    pub io_status: Option<u32>,
    pub user_event: VirtAddr,
    pub user_buffer: VirtAddr,
    pub mdl_address: VirtAddr,
    pub thread: VirtAddr,
    pub current_stack: Option<IoStackLocationInfo>,
}

#[derive(Debug, Clone)]
pub struct IoStackLocationInfo {
    pub address: VirtAddr,
    pub major_function: u8,
    pub minor_function: u8,
    pub device_object: VirtAddr,
    pub file_object: VirtAddr,
    pub completion_routine: VirtAddr,
    pub context: VirtAddr,
}

/// A decoded `_DRIVER_OBJECT`: header fields, its `DeviceObject`/`NextDevice`
/// chain, and the 28-entry `MajorFunction` dispatch table.
#[derive(Debug, Clone)]
pub struct DriverObjectDetail {
    pub object: VirtAddr,
    /// True when `object` was a pointer to a `_DRIVER_OBJECT` rather than one.
    pub via_pointer: bool,
    pub name: Option<String>,
    pub driver_start: VirtAddr,
    pub driver_size: u64,
    pub driver_section: VirtAddr,
    pub driver_unload: VirtAddr,
    pub device_chain: Vec<DeviceLink>,
    /// `MajorFunction[0..=0x1b]` dispatch routines, indexed by `IRP_MJ_*` code.
    pub dispatch: Vec<VirtAddr>,
}

#[derive(Debug, Clone)]
pub struct DeviceLink {
    pub device: VirtAddr,
    pub device_type: u32,
    pub flags: u32,
    pub characteristics: u32,
    pub attached: VirtAddr,
    pub next: VirtAddr,
}

/// A decoded `_DEVICE_OBJECT` plus its `AttachedDevice` stack.
#[derive(Debug, Clone)]
pub struct DeviceObjectDetail {
    pub object: VirtAddr,
    pub via_pointer: bool,
    pub device_type: u32,
    pub flags: u32,
    pub characteristics: u32,
    pub driver_object: VirtAddr,
    pub attached_device: VirtAddr,
    pub next_device: VirtAddr,
    pub current_irp: VirtAddr,
    pub device_extension: VirtAddr,
    pub attached_stack: Vec<DeviceStackEntry>,
}

#[derive(Debug, Clone)]
pub struct DeviceStackEntry {
    pub device: VirtAddr,
    pub driver_object: VirtAddr,
    pub device_type: u32,
    pub flags: u32,
}

/// A decoded executive `_OBJECT_HEADER` and the body it precedes.
#[derive(Debug, Clone)]
pub struct ObjectHeaderDetail {
    pub input: VirtAddr,
    /// "body" when the input pointed at the object body, "header" when it
    /// pointed at the header itself.
    pub mode: &'static str,
    pub header: VirtAddr,
    pub body: VirtAddr,
    pub pointer_count: i64,
    pub handle_count: i64,
    pub type_index: Option<u64>,
    pub type_object: Option<VirtAddr>,
    pub type_name: Option<String>,
    pub info_mask: Option<u8>,
    pub name_info: Option<VirtAddr>,
    pub name: Option<String>,
}

/// One process/thread/image notification callback registered with the kernel.
#[derive(Debug, Clone)]
pub struct NotifyCallback {
    /// "process", "thread", or "image".
    pub kind: &'static str,
    pub index: usize,
    pub function: VirtAddr,
    pub block: VirtAddr,
    pub raw: VirtAddr,
    pub context: VirtAddr,
}

/// One system-service-table slot resolved to its target routine.
#[derive(Debug, Clone)]
pub struct SsdtEntry {
    pub index: u32,
    pub target: VirtAddr,
    pub symbol: Option<String>,
    pub module: Option<String>,
}

/// A system service descriptor table (the kernel SSDT or the win32k shadow).
#[derive(Debug, Clone)]
pub struct SsdtTable {
    pub label: String,
    pub base: VirtAddr,
    pub limit: u32,
    pub entries: Vec<SsdtEntry>,
}

/// An IRP discovered via an `_ETHREAD` `IrpList` or a `_DEVICE_OBJECT`
/// `CurrentIrp`, with the context it was found in.
#[derive(Debug, Clone)]
pub struct IrpHit {
    pub irp: VirtAddr,
    /// "thread" or "device".
    pub source: &'static str,
    pub stack_count: u8,
    pub current_location: u8,
    pub pid: Option<u64>,
    pub tid: Option<u64>,
    pub ethread: Option<VirtAddr>,
    pub state: Option<u8>,
    pub wait_reason: Option<u8>,
    pub driver: Option<String>,
    pub device: Option<VirtAddr>,
}

/// What an address belongs to: a loaded module (and section), a process VAD
/// region, or nothing recognized. Complements `pte_traverse` (how it's mapped)
/// with where it lives.
#[derive(Debug, Clone)]
pub struct AddressDescription {
    pub address: VirtAddr,
    pub dtb: Dtb,
    /// "kernel-module", "user-image", "kernel-region", "private", "mapped", or
    /// "unknown".
    pub kind: &'static str,
    pub module: Option<AddressModule>,
    pub section: Option<String>,
    /// For a "kernel-region" hit: the `MI_SYSTEM_VA_TYPE` name (e.g.
    /// `KernelStacks`, `PagedPool`, `SystemPtes`).
    pub va_type: Option<String>,
    pub region: Option<MemoryRegionInfo>,
}

#[derive(Debug, Clone)]
pub struct AddressModule {
    pub name: String,
    pub base: VirtAddr,
    pub size: u32,
    pub offset: u64,
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
}

impl SavedThreadRegisters {
    pub fn get(&self, name: &str) -> Option<u64> {
        match name.to_ascii_lowercase().as_str() {
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
    pub fn pseudo_register_value(&self, name: &str) -> Option<u64> {
        match name.to_ascii_lowercase().as_str() {
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
            _ => None,
        }
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

/// `_IRP.Thread` is a direct field on some builds and inside the `Tail.Overlay`
/// union on others; read whichever is present, else null (never fatal).
fn irp_thread(irp: &StructRef) -> VirtAddr {
    if let Ok(t) = irp.read_field::<VirtAddr>("Thread") {
        return t;
    }
    irp.embedded("Tail")
        .and_then(|tail| tail.embedded("Overlay"))
        .and_then(|ov| ov.read_field::<VirtAddr>("Thread"))
        .unwrap_or(VirtAddr(0))
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

pub fn kthread_state_name(state: u8) -> &'static str {
    match state {
        0 => "Initialized",
        1 => "Ready",
        2 => "Running",
        3 => "Standby",
        4 => "Terminated",
        5 => "Waiting",
        6 => "Transition",
        7 => "DeferredReady",
        8 => "GateWaitObsolete",
        9 => "WaitingForProcessInSwap",
        _ => "?",
    }
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

#[derive(Debug, Clone)]
pub struct MemoryRegionInfo {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub protection: Option<u64>,
    pub vad_type: Option<u64>,
    pub private_memory: Option<bool>,
    pub commit_charge: Option<u64>,
    pub details: Option<String>,
}

impl MemoryRegionInfo {
    pub fn size(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
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

#[derive(Debug, Clone)]
pub struct HandleEntryDetail {
    pub handle: u64,
    pub entry: VirtAddr,
    pub object: DiagnosticValue<VirtAddr>,
    pub type_name: DiagnosticValue<Option<String>>,
    pub name: DiagnosticValue<Option<String>>,
    pub granted_access: DiagnosticValue<u32>,
    pub attributes: DiagnosticValue<u32>,
}

#[derive(Debug, Clone)]
pub struct HandleTableSummary {
    pub process: ProcessInfo,
    pub table: VirtAddr,
    pub table_level: u8,
    pub advertised_handles: usize,
    pub scanned_handles: usize,
    pub skipped_entries: usize,
    pub truncated: bool,
    pub entries: Vec<HandleEntryDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidAndAttributes {
    pub sid: String,
    pub attributes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeInfo {
    pub luid: u64,
    pub attributes: u32,
}

const SE_PRIVILEGE_ENABLED_BY_DEFAULT: u32 = 0x1;
const SE_PRIVILEGE_ENABLED: u32 = 0x2;

fn decode_token_privilege_bitmaps(
    present: u64,
    enabled: u64,
    enabled_by_default: u64,
) -> Vec<PrivilegeInfo> {
    let mut remaining = present;
    let mut privileges = Vec::with_capacity(present.count_ones() as usize);
    while remaining != 0 {
        let bit = remaining.trailing_zeros();
        let mask = 1u64 << bit;
        let mut attributes = 0;
        if enabled_by_default & mask != 0 {
            attributes |= SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        }
        if enabled & mask != 0 {
            attributes |= SE_PRIVILEGE_ENABLED;
        }
        privileges.push(PrivilegeInfo {
            luid: u64::from(bit),
            attributes,
        });
        remaining &= remaining - 1;
    }
    privileges
}

#[derive(Debug, Clone)]
pub struct TokenDetail {
    pub process: ProcessInfo,
    pub token: VirtAddr,
    pub token_id: DiagnosticValue<u64>,
    pub authentication_id: DiagnosticValue<u64>,
    pub token_type: DiagnosticValue<u32>,
    pub impersonation_level: DiagnosticValue<u32>,
    pub flags: DiagnosticValue<u32>,
    pub user: DiagnosticValue<Option<SidAndAttributes>>,
    pub groups: DiagnosticValue<Vec<SidAndAttributes>>,
    pub privileges: DiagnosticValue<Vec<PrivilegeInfo>>,
}

#[derive(Debug, Clone)]
pub struct FileObjectDetail {
    pub address: VirtAddr,
    pub file_type: DiagnosticValue<i16>,
    pub size: DiagnosticValue<i16>,
    pub device_object: DiagnosticValue<VirtAddr>,
    pub device_type: DiagnosticValue<u32>,
    pub device_name: DiagnosticValue<Option<String>>,
    pub file_name: DiagnosticValue<String>,
    pub related_file_object: DiagnosticValue<VirtAddr>,
    pub flags: DiagnosticValue<u32>,
    pub current_byte_offset: DiagnosticValue<i64>,
    pub fs_context: DiagnosticValue<VirtAddr>,
    pub fs_context2: DiagnosticValue<VirtAddr>,
    pub section_object_pointer: DiagnosticValue<VirtAddr>,
    pub private_cache_map: DiagnosticValue<VirtAddr>,
    pub final_status: DiagnosticValue<i32>,
    pub lock_operation: DiagnosticValue<bool>,
    pub delete_pending: DiagnosticValue<bool>,
    pub read_access: DiagnosticValue<bool>,
    pub write_access: DiagnosticValue<bool>,
    pub delete_access: DiagnosticValue<bool>,
    pub shared_read: DiagnosticValue<bool>,
    pub shared_write: DiagnosticValue<bool>,
    pub shared_delete: DiagnosticValue<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceOwner {
    pub thread: VirtAddr,
    pub count: i32,
}

#[derive(Debug, Clone)]
pub struct ResourceDetail {
    pub address: VirtAddr,
    pub active_count: DiagnosticValue<i16>,
    pub flags: DiagnosticValue<u16>,
    pub contention_count: DiagnosticValue<u32>,
    pub shared_waiters: DiagnosticValue<u32>,
    pub exclusive_waiters: DiagnosticValue<u32>,
    pub owners: DiagnosticValue<Vec<ResourceOwner>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListTermination {
    Head,
    Null,
    Cycle(VirtAddr),
    Bound,
    Corrupt(String),
}

#[derive(Debug, Clone)]
pub struct ResourceListSummary {
    pub head: VirtAddr,
    pub resources: Vec<ResourceDetail>,
    pub termination: ListTermination,
}

#[derive(Debug, Clone)]
pub struct ProcessMemoryUsage {
    pub process: ProcessInfo,
    pub virtual_size: DiagnosticValue<u64>,
    pub peak_virtual_size: DiagnosticValue<u64>,
    pub working_set_size: DiagnosticValue<u64>,
    pub peak_working_set_size: DiagnosticValue<u64>,
    pub pagefile_usage: DiagnosticValue<u64>,
    pub peak_pagefile_usage: DiagnosticValue<u64>,
    pub private_usage: DiagnosticValue<u64>,
}

#[derive(Debug, Clone)]
pub struct SystemMemorySummary {
    pub physical_pages: DiagnosticMetric<u64>,
    pub available_pages: DiagnosticMetric<u64>,
    pub committed_pages: DiagnosticMetric<u64>,
    pub commit_limit_pages: DiagnosticMetric<u64>,
    pub paged_pool_pages: DiagnosticMetric<u64>,
    pub nonpaged_pool_bytes: DiagnosticMetric<u64>,
    pub processes: Vec<ProcessMemoryUsage>,
    pub process_count: usize,
    pub truncated: bool,
}

fn bounded_list_walk<F>(
    head: VirtAddr,
    limit: usize,
    mut read_next: F,
) -> (Vec<VirtAddr>, ListTermination)
where
    F: FnMut(VirtAddr) -> Result<VirtAddr>,
{
    let mut links = Vec::new();
    let mut visited = HashSet::new();
    let mut current = match read_next(head) {
        Ok(current) => current,
        Err(error) => return (links, ListTermination::Corrupt(error.to_string())),
    };

    loop {
        if current == head {
            return (links, ListTermination::Head);
        }
        if current.is_zero() {
            return (links, ListTermination::Null);
        }
        if !visited.insert(current.0) {
            return (links, ListTermination::Cycle(current));
        }
        if links.len() >= limit {
            return (links, ListTermination::Bound);
        }
        links.push(current);
        current = match read_next(current) {
            Ok(next) => next,
            Err(error) => return (links, ListTermination::Corrupt(error.to_string())),
        };
    }
}

struct ObjectNameLayout {
    body_offset: u64,
    info_mask_offset: u64,
    creator_info_size: Option<u64>,
    name_info_size: u64,
    name_offset: u64,
}

impl ObjectNameLayout {
    fn name_info_address(&self, header: VirtAddr, info_mask: u8) -> Result<Option<VirtAddr>> {
        const CREATOR_INFO_BIT: u8 = 0x01;
        const NAME_INFO_BIT: u8 = 0x02;

        if info_mask & NAME_INFO_BIT == 0 {
            return Ok(None);
        }

        // Optional headers run backwards from OBJECT_HEADER in increasing bit
        // order. NameInfo is therefore displaced only by lower-bit CreatorInfo,
        // never by HandleInfo or any higher-bit header.
        let creator_size = if info_mask & CREATOR_INFO_BIT != 0 {
            self.creator_info_size
                .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER_CREATOR_INFO".to_string()))?
        } else {
            0
        };
        let offset = self
            .name_info_size
            .checked_add(creator_size)
            .ok_or_else(|| Error::DebugInfo("object name-info offset overflow".to_string()))?;
        let address =
            header.0.checked_sub(offset).map(VirtAddr).ok_or_else(|| {
                Error::DebugInfo("object name-info address underflow".to_string())
            })?;
        Ok(Some(address))
    }
}

fn select_object_header_candidate(
    input: VirtAddr,
    body_offset: u64,
    body_candidate: Option<VirtAddr>,
    direct_candidate: Option<VirtAddr>,
    body_has_type: bool,
    direct_has_type: bool,
) -> Option<(VirtAddr, VirtAddr, &'static str)> {
    match (body_candidate, direct_candidate) {
        (Some(header), Some(_)) if body_has_type => Some((header, input, "body")),
        (Some(_), Some(header)) if direct_has_type => {
            Some((header, header + body_offset, "header"))
        }
        // Both locations are readable but neither decodes through the type
        // table. Guessing here would make an arbitrary pool address look valid.
        (Some(_), Some(_)) => None,
        (Some(header), None) => Some((header, input, "body")),
        (None, Some(header)) => Some((header, header + body_offset, "header")),
        (None, None) => None,
    }
}

struct ObjectDirectoryLayout {
    buckets_offset: u64,
    bucket_count: u64,
    chain_offset: u64,
    object_offset: u64,
    name_offset: Option<u64>,
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

pub struct PteLevel {
    pub name: String, // TODO maybe enum instead?
    pub address: VirtAddr,
    pub value: PageTableEntry,
}

pub struct PteWalk {
    pub address: VirtAddr,
    /// The address space the walk was performed in (the attached process DTB
    /// when attached, else the kernel), so callers know what was walked.
    pub dtb: Dtb,
    pub pxe: PteLevel,
    pub ppe: PteLevel,
    pub pde: Option<PteLevel>,
    pub pte: Option<PteLevel>,
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

    pub fn with_phys(phys: Arc<PhysMem>) -> Result<Self> {
        let symbols = Arc::new(SymbolStore::new());
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
                    diagnostics::eprint_warning(format!(
                        "kernel discovery failed ({e}); continuing without kernel context"
                    ));
                    None
                }
                Err(e) => return Err(e),
            }
        } else {
            Some(Guest::new(phys.clone(), symbols.clone())?)
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
            triage_fallback,
            triage_modules_cache,
            context_dtb_override: None,
            registers: None,
            windows_thread_selection: None,
            user_vars: HashMap::new(),
            results: Vec::new(),
            results_origin: None,
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
        let guest = Guest { ntoskrnl };
        let _ = guest.load_all_kernel_module_symbols(&phys, &symbols);

        Ok(Self {
            phys,
            symbols,
            guest: Some(guest),
            debugger_data: None,
            current_process: None,
            current_process_info: None,
            triage_fallback: None,
            triage_modules_cache: None,
            context_dtb_override: None,
            registers: None,
            windows_thread_selection: None,
            user_vars: HashMap::new(),
            results: Vec::new(),
            results_origin: None,
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
    /// mirroring the engine's `Types::list_at`. Shared by the SDK and MCP list
    /// walking; the typed cursor walk (`StructRef::list`) is the richer form.
    pub fn walk_list(&self, head: VirtAddr, link_offset: u64) -> Result<Vec<u64>> {
        const MAX: usize = 1000;
        let mem = self.current_process()?.memory();
        let mut buf = [0u8; 8];
        mem.read_bytes(head, &mut buf)?;
        let mut current = u64::from_le_bytes(buf);
        let mut out = Vec::new();
        let mut count = 0usize;
        while current != 0 && current != head.0 && count < MAX {
            count += 1;
            out.push(current.saturating_sub(link_offset));
            // truncate on a bad link rather than failing the whole walk
            if mem.read_bytes(VirtAddr(current), &mut buf).is_err() {
                break;
            }
            let next = u64::from_le_bytes(buf);
            if next == current {
                break; // self-loop
            }
            current = next;
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
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
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
        self.clear_context_dtb_override();
        self.clear_current_windows_thread_context();
        Ok(AttachReport {
            name,
            symbol_report: symbol_report?,
        })
    }

    pub fn detach(&mut self) {
        self.clear_context_dtb_override();
        self.clear_current_windows_thread_context();
        self.current_process = None;
        self.current_process_info = None;
    }

    pub fn set_context_dtb_override(&mut self, dtb: Dtb) {
        self.context_dtb_override = Some(Self::normalize_cr3(dtb));
    }

    pub fn clear_context_dtb_override(&mut self) {
        self.context_dtb_override = None;
    }

    pub fn normalize_cr3(cr3: u64) -> Dtb {
        cr3 & CR3_PAGE_MASK
    }

    pub fn set_current_windows_thread_context(&mut self, thread: ThreadInfo) {
        self.windows_thread_selection = Some(thread);
    }

    pub fn set_parked_windows_thread(&mut self, thread: ThreadInfo) {
        self.windows_thread_selection = Some(thread);
        // A parked thread has no coherent register file. In particular, do not
        // let expressions reuse registers cached from the still-selected vCPU.
        self.registers = None;
    }

    pub fn clear_current_windows_thread_context(&mut self) {
        self.windows_thread_selection = None;
    }

    pub fn thread_process_dtb(&self, thread: &ThreadInfo) -> Option<Dtb> {
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

    pub fn current_thread_pseudo_register(&self, name: &str) -> Option<u64> {
        let thread = self.windows_thread_selection.as_ref()?;
        thread.pseudo_register_value(name)
    }

    pub fn builtin_variable_value(&self, name: &str) -> Option<u64> {
        let name = name.trim_start_matches('$').to_ascii_lowercase();
        if let Some(value) = self.current_thread_pseudo_register(&name) {
            return Some(value);
        }

        match name.as_str() {
            "dtb" => Some(self.current_dtb()),
            "ntbase" | "kernelbase" => self.guest.as_ref().map(|g| g.ntoskrnl.base_address.0),
            "processbase" | "imagebase" => self.current_process.as_ref().map(|p| p.base_address.0),
            "processdtb" => self.current_process_info.as_ref().map(|p| p.dtb),
            "attachedeprocess" | "attachedprocess" => {
                self.current_process_info.as_ref().map(|p| p.eprocess_va.0)
            }
            "attachedpid" => self.current_process_info.as_ref().map(|p| p.pid),
            "eprocess" | "process" => self.current_process_info.as_ref().map(|p| p.eprocess_va.0),
            "pid" => self.current_process_info.as_ref().map(|p| p.pid),
            _ => None,
        }
    }

    pub fn builtin_variables(&self) -> Vec<BuiltinVar> {
        let mut vars = vec![BuiltinVar {
            name: "dtb",
            value: self.current_dtb(),
            source: "current address space",
        }];

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
        // Triage dumps capture kernel state at bugcheck time — it is
        // coherent by definition.  The MZ check below guards against
        // undetected reboots on live VMs, which can't happen for dumps.
        // The ntoskrnl base page is often not captured in triage dumps,
        // so the MZ read would fail even though the state is valid.
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

    /// Symbol address space for an address in the active inspection context.
    /// Kernel addresses fall back to the kernel DTB when a user process is
    /// selected and owns no module covering the address.
    pub fn symbol_dtb_for_address(&self, address: VirtAddr) -> Dtb {
        let current_dtb = self.current_dtb();
        let kernel_dtb = self.kernel_dtb();
        if !looks_like_kernel_pointer(address.0) || current_dtb == kernel_dtb {
            return current_dtb;
        }
        self.symbols
            .find_module_for_address_in_context(current_dtb, kernel_dtb, address)
            .map(|module| module.dtb)
            .unwrap_or(current_dtb)
    }

    /// Return all matching symbol identities in the active address space,
    /// adding the kernel address space when a user process is selected.
    pub fn symbol_candidates(&self, name: &str) -> Vec<SymbolCandidate> {
        let current_dtb = self.current_dtb();
        let kernel_dtb = self.kernel_dtb();
        let mut candidates = self.symbols.find_symbol_candidates(current_dtb, name);
        if current_dtb != kernel_dtb {
            candidates.extend(self.symbols.find_symbol_candidates(kernel_dtb, name));
        }
        candidates.sort_by(|left, right| {
            left.module
                .to_ascii_lowercase()
                .cmp(&right.module.to_ascii_lowercase())
                .then_with(|| left.address.0.cmp(&right.address.0))
                .then_with(|| left.compiland.cmp(&right.compiland))
        });
        candidates.dedup_by(|left, right| {
            left.module.eq_ignore_ascii_case(&right.module)
                && left.address == right.address
                && left.visibility == right.visibility
                && left.compiland == right.compiland
        });
        candidates
    }

    /// Fuzzy-search the active symbol index and resolve only unambiguous
    /// module/address identities. `module!query` restricts the search.
    pub fn search_symbols(&self, query: &str, limit: usize) -> Vec<SymbolSearchMatch> {
        let dtb = self.current_dtb();
        let (module, names) = match query.split_once('!') {
            Some((module, query)) => (
                Some(module),
                self.symbols
                    .search_symbols_in_module(dtb, module, query, limit),
            ),
            None => (None, self.current_symbol_index().search(query, limit)),
        };
        names
            .into_iter()
            .map(|name| {
                let lookup = module
                    .map(|module| format!("{module}!{name}"))
                    .unwrap_or_else(|| name.clone());
                let locations: HashSet<(String, u64)> = self
                    .symbol_candidates(&lookup)
                    .into_iter()
                    .map(|candidate| (candidate.module, candidate.address.0))
                    .collect();
                let (resolved_module, address) = if locations.len() == 1 {
                    let (module, address) = locations.into_iter().next().unwrap();
                    (Some(module), Some(VirtAddr(address)))
                } else {
                    (None, None)
                };
                SymbolSearchMatch {
                    name,
                    address,
                    module: resolved_module,
                }
            })
            .collect()
    }
    /// Structured nearest-symbol lookup with kernel-address fallback.
    pub fn nearest_symbol_current_context(
        &self,
        address: VirtAddr,
    ) -> Option<(String, String, u32)> {
        let current_dtb = self.current_dtb();
        self.symbols
            .find_closest_symbol_for_address(current_dtb, address)
            .or_else(|| {
                let kernel_dtb = self.kernel_dtb();
                (looks_like_kernel_pointer(address.0) && current_dtb != kernel_dtb)
                    .then(|| {
                        self.symbols
                            .find_closest_symbol_for_address(kernel_dtb, address)
                    })
                    .flatten()
            })
    }

    pub fn closest_symbol_current_context(&self, address: VirtAddr) -> Option<String> {
        self.nearest_symbol_current_context(address)
            .map(|(module, name, offset)| {
                crate::symbols::format_symbol_with_offset(&module, &name, offset)
            })
    }

    /// Resolve cached source information using the active address space with the
    /// same kernel-address fallback as symbol rendering.
    pub fn source_location(&self, address: VirtAddr) -> Option<SourceLocation> {
        let dtb = self.symbol_dtb_for_address(address);
        self.symbols.source_location(dtb, address)
    }

    /// Resolve `file:line` across the active and kernel address spaces.
    pub fn source_addresses(&self, file: &str, line: u32) -> Vec<VirtAddr> {
        let current_dtb = self.current_dtb();
        let kernel_dtb = self.kernel_dtb();
        let mut addresses = self.symbols.source_addresses(current_dtb, file, line);
        if current_dtb != kernel_dtb {
            addresses.extend(self.symbols.source_addresses(kernel_dtb, file, line));
        }
        addresses.sort_by_key(|address| address.0);
        addresses.dedup();
        addresses
    }
    /// Return private procedure locals in scope at `address`.
    pub fn procedure_locals(&self, address: VirtAddr) -> Result<Option<Vec<ProcedureLocal>>> {
        let dtb = self.symbol_dtb_for_address(address);
        self.symbols.procedure_locals(dtb, address)
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
            .registers
            .as_ref()
            .and_then(|registers| registers.get("rip"))
            .is_none_or(|rip| *rip != address.0)
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
                let value = *registers.get(register)?;
                Some(if size == 8 {
                    value
                } else {
                    value & ((1u64 << (size * 8)) - 1)
                })
            }
            LocalVariableLocation::RegisterRelative { register, offset } => {
                let base = *registers.get(register)?;
                let address = VirtAddr(base.wrapping_add_signed(i64::from(*offset)));
                let mut bytes = [0u8; 8];
                self.context_memory()
                    .read_bytes(address, &mut bytes[..size])
                    .ok()?;
                Some(u64::from_le_bytes(bytes))
            }
            LocalVariableLocation::FrameRelative { .. }
            | LocalVariableLocation::Unavailable { .. } => None,
        }
    }

    /// Open a fluent cursor over a kernel struct (ntoskrnl's layout, read
    /// through ntoskrnl's address space).
    fn kernel_struct(&self, name: &str, base: VirtAddr) -> Result<StructRef<'_>> {
        self.guest()?.ntoskrnl.types().struct_at(name, base)
    }

    fn read_kernel_unicode_string(&self, addr: VirtAddr) -> Result<String> {
        self.kernel_struct("_UNICODE_STRING", addr)?
            .read_unicode_string()
    }

    fn object_name_layout(&self) -> Result<ObjectNameLayout> {
        let dtb = self.guest()?.ntoskrnl.dtb();
        let header_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER".to_string()))?;
        let creator_info_size = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER_CREATOR_INFO")
            .map(|ty| ty.size as u64);
        let name_info_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_HEADER_NAME_INFO")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_HEADER_NAME_INFO".to_string()))?;
        Ok(ObjectNameLayout {
            body_offset: header_type.field_offset("Body")?,
            info_mask_offset: header_type.field_offset("InfoMask")?,
            creator_info_size,
            name_info_size: name_info_type.size as u64,
            name_offset: name_info_type.field_offset("Name")?,
        })
    }

    fn read_kernel_object_name(
        &self,
        object: VirtAddr,
        object_name: &ObjectNameLayout,
    ) -> Result<Option<String>> {
        let memory = self.guest()?.ntoskrnl.memory();
        let header = object - object_name.body_offset;
        let info_mask: u8 = memory.read(header + object_name.info_mask_offset)?;
        let Some(name_info) = object_name.name_info_address(header, info_mask)? else {
            return Ok(None);
        };
        Ok(Some(self.read_kernel_unicode_string(
            name_info + object_name.name_offset,
        )?))
    }

    fn object_directory_layout(&self) -> Result<ObjectDirectoryLayout> {
        let dtb = self.guest()?.ntoskrnl.dtb();
        let dir_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_DIRECTORY")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_DIRECTORY".to_string()))?;
        let entry_type = self
            .symbols
            .find_type_across_modules(dtb, "_OBJECT_DIRECTORY_ENTRY")
            .ok_or_else(|| Error::StructNotFound("_OBJECT_DIRECTORY_ENTRY".to_string()))?;
        let buckets = dir_type
            .fields
            .get("HashBuckets")
            .ok_or_else(|| Error::FieldNotFound("HashBuckets".to_string()))?;
        Ok(ObjectDirectoryLayout {
            buckets_offset: buckets.offset as u64,
            bucket_count: (buckets.size / 8).max(1),
            chain_offset: entry_type.field_offset("ChainLink")?,
            object_offset: entry_type.field_offset("Object")?,
            name_offset: entry_type.fields.get("Name").map(|f| f.offset as u64),
        })
    }

    fn enumerate_object_directory(
        &self,
        directory: VirtAddr,
        dir: &ObjectDirectoryLayout,
        object_name: &ObjectNameLayout,
    ) -> Result<Vec<(String, VirtAddr)>> {
        let memory = self.guest()?.ntoskrnl.memory();
        let mut out = Vec::new();
        for bucket in 0..dir.bucket_count {
            let mut entry: VirtAddr = memory.read(directory + dir.buckets_offset + bucket * 8)?;
            for _ in 0..4096 {
                if entry.is_zero() {
                    break;
                }
                let object: VirtAddr = memory.read(entry + dir.object_offset)?;
                if !object.is_zero() {
                    let name = match dir.name_offset {
                        Some(offset) => Some(self.read_kernel_unicode_string(entry + offset)?),
                        None => self.read_kernel_object_name(object, object_name)?,
                    };
                    if let Some(name) = name
                        && !name.is_empty()
                    {
                        out.push((name, object));
                    }
                }
                entry = memory.read(entry + dir.chain_offset)?;
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
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
        }])
    }

    pub fn enumerate_driver_objects(&self) -> Result<Vec<DriverObjectInfo>> {
        let guest = self.guest()?;
        let memory = guest.ntoskrnl.memory();
        let object_name = self.object_name_layout()?;
        let dir = self.object_directory_layout()?;
        let root_ptr = guest.ntoskrnl.symbol("ObpRootDirectoryObject")?.address();
        let root: VirtAddr = memory.read(root_ptr)?;
        let driver_dir = self
            .enumerate_object_directory(root, &dir, &object_name)?
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Driver"))
            .map(|(_, object)| object)
            .ok_or_else(|| Error::DebugInfo("\\Driver object directory not found".to_string()))?;

        let mut drivers = Vec::new();
        for (name, object) in self.enumerate_object_directory(driver_dir, &dir, &object_name)? {
            let driver = self.kernel_struct("_DRIVER_OBJECT", object)?;
            drivers.push(DriverObjectInfo {
                name: format!("\\Driver\\{name}"),
                object,
                driver_start: driver.read_field("DriverStart")?,
                driver_size: driver.read_field::<u32>("DriverSize")? as u64,
                device_object: driver.read_field("DeviceObject")?,
                driver_unload: driver.read_field("DriverUnload")?,
            });
        }
        Ok(drivers)
    }

    /// Decode the `_IRP` at `address` along with its current I/O stack
    /// location. Field widths come from the PDB layout; the current stack slot
    /// is `irp + sizeof(_IRP) + (CurrentLocation - 1) * sizeof(_IO_STACK_LOCATION)`.
    pub fn inspect_irp(&self, address: VirtAddr) -> Result<IrpInfo> {
        let irp = self.kernel_struct("_IRP", address)?;

        let io_status = irp
            .embedded("IoStatus")
            .and_then(|s| s.read_field::<u32>("Status"))
            .ok();

        let current_location: u8 = irp.read_field("CurrentLocation")?;
        let current_stack = self
            .read_current_io_stack(address, current_location)
            .ok()
            .flatten();

        Ok(IrpInfo {
            address,
            irp_type: irp.read_field("Type")?,
            size: irp.read_field("Size")?,
            stack_count: irp.read_field("StackCount")?,
            current_location,
            pending_returned: irp.read_field::<u8>("PendingReturned")? != 0,
            requestor_mode: irp.read_field("RequestorMode")?,
            io_status,
            user_event: irp.read_field("UserEvent")?,
            user_buffer: irp.read_field("UserBuffer")?,
            mdl_address: irp.read_field("MdlAddress")?,
            thread: irp_thread(&irp),
            current_stack,
        })
    }

    fn read_current_io_stack(
        &self,
        irp: VirtAddr,
        current_location: u8,
    ) -> Result<Option<IoStackLocationInfo>> {
        // A valid current location is 1..=StackCount; clamp generously so a
        // garbage value can't compute a wild address.
        if current_location == 0 || current_location as u64 > 0x40 {
            return Ok(None);
        }
        let types = self.guest()?.ntoskrnl.types();
        let irp_size = types.layout("_IRP")?.size as u64;
        let stack_size = types.layout("_IO_STACK_LOCATION")?.size as u64;
        let addr = irp + irp_size + (current_location as u64 - 1) * stack_size;

        let Ok(ios) = self.kernel_struct("_IO_STACK_LOCATION", addr) else {
            return Ok(None);
        };
        Ok(Some(IoStackLocationInfo {
            address: addr,
            major_function: ios.read_field("MajorFunction")?,
            minor_function: ios.read_field("MinorFunction")?,
            device_object: ios.read_field("DeviceObject")?,
            file_object: ios.read_field("FileObject")?,
            completion_routine: ios.read_field("CompletionRoutine")?,
            context: ios.read_field("Context")?,
        }))
    }

    fn read_device_link(&self, device: VirtAddr) -> Result<DeviceLink> {
        let d = self.kernel_struct("_DEVICE_OBJECT", device)?;
        Ok(DeviceLink {
            device,
            device_type: d.read_field("DeviceType")?,
            flags: d.read_field("Flags")?,
            characteristics: d.read_field("Characteristics")?,
            attached: d.read_field("AttachedDevice")?,
            next: d.read_field("NextDevice")?,
        })
    }

    /// Decode a `_DRIVER_OBJECT` at `addr` (or at the pointer `addr` points to),
    /// including its device chain and `MajorFunction` dispatch table.
    pub fn inspect_driver_object(&self, addr: VirtAddr) -> Result<DriverObjectDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_DRIVER_OBJECT")?;
        let size_off = layout.field_offset("Size")?;
        let mf_off = layout.field_offset("MajorFunction")?;
        let name_off = layout.field_offset("DriverName")?;
        let min_size = mf_off + 28 * 8;

        // A `_DRIVER_OBJECT` has Type == 4 (IO_TYPE_DRIVER) and is large enough
        // to hold the dispatch table; use that to tell a direct object from a
        // pointer to one.
        let valid = |a: VirtAddr| -> bool {
            let ty: u16 = match mem.read(a) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let size: u16 = match mem.read(a + size_off) {
                Ok(v) => v,
                Err(_) => return false,
            };
            ty == 4 && size as u64 >= min_size
        };

        let object = if valid(addr) {
            addr
        } else {
            let ptr: VirtAddr = mem.read(addr)?;
            if !ptr.is_zero() && valid(ptr) {
                ptr
            } else {
                return Err(Error::DebugInfo(format!(
                    "{:#x} is not a _DRIVER_OBJECT or a pointer to one",
                    addr.0
                )));
            }
        };

        let drv = self.kernel_struct("_DRIVER_OBJECT", object)?;
        let name = self
            .read_kernel_unicode_string(object + name_off)
            .ok()
            .filter(|s| !s.is_empty());

        let mut device_chain = Vec::new();
        let mut seen = Vec::new();
        let mut cur: VirtAddr = drv.read_field("DeviceObject")?;
        for _ in 0..128 {
            if cur.is_zero() || seen.contains(&cur.0) {
                break;
            }
            seen.push(cur.0);
            let Ok(link) = self.read_device_link(cur) else {
                break;
            };
            let next = link.next;
            device_chain.push(link);
            if next.is_zero() {
                break;
            }
            cur = next;
        }

        let mut dispatch = Vec::with_capacity(28);
        for i in 0..28u64 {
            dispatch.push(
                mem.read::<VirtAddr>(object + mf_off + i * 8)
                    .unwrap_or(VirtAddr(0)),
            );
        }

        Ok(DriverObjectDetail {
            object,
            via_pointer: object != addr,
            name,
            driver_start: drv.read_field("DriverStart")?,
            driver_size: drv.read_field::<u32>("DriverSize")? as u64,
            driver_section: drv.read_field("DriverSection")?,
            driver_unload: drv.read_field("DriverUnload")?,
            device_chain,
            dispatch,
        })
    }

    /// Decode a `_DEVICE_OBJECT` at `addr` (or the pointer `addr` points to) and
    /// walk its `AttachedDevice` stack.
    pub fn inspect_device_object(&self, addr: VirtAddr) -> Result<DeviceObjectDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_DEVICE_OBJECT")?;
        let size_off = layout.field_offset("Size")?;
        let min_size = layout.size as u64;

        let valid = |a: VirtAddr| -> bool {
            let ty: u16 = match mem.read(a) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let size: u16 = match mem.read(a + size_off) {
                Ok(v) => v,
                Err(_) => return false,
            };
            ty == 3 && size as u64 >= min_size
        };

        let object = if valid(addr) {
            addr
        } else {
            let ptr: VirtAddr = mem.read(addr)?;
            if !ptr.is_zero() && valid(ptr) {
                ptr
            } else {
                return Err(Error::DebugInfo(format!(
                    "{:#x} is not a _DEVICE_OBJECT or a pointer to one",
                    addr.0
                )));
            }
        };

        let dev = self.kernel_struct("_DEVICE_OBJECT", object)?;
        let attached_device: VirtAddr = dev.read_field("AttachedDevice")?;

        let mut attached_stack = Vec::new();
        let mut seen = Vec::new();
        let mut cur = attached_device;
        for _ in 0..64 {
            if cur.is_zero() || seen.contains(&cur.0) {
                break;
            }
            seen.push(cur.0);
            let Ok(d) = self.kernel_struct("_DEVICE_OBJECT", cur) else {
                break;
            };
            let next: VirtAddr = d.read_field("AttachedDevice")?;
            attached_stack.push(DeviceStackEntry {
                device: cur,
                driver_object: d.read_field("DriverObject")?,
                device_type: d.read_field("DeviceType")?,
                flags: d.read_field("Flags")?,
            });
            if next.is_zero() {
                break;
            }
            cur = next;
        }

        Ok(DeviceObjectDetail {
            object,
            via_pointer: object != addr,
            device_type: dev.read_field("DeviceType")?,
            flags: dev.read_field("Flags")?,
            characteristics: dev.read_field("Characteristics")?,
            driver_object: dev.read_field("DriverObject")?,
            attached_device,
            next_device: dev.read_field("NextDevice")?,
            current_irp: dev.read_field("CurrentIrp")?,
            device_extension: dev.read_field("DeviceExtension")?,
            attached_stack,
        })
    }

    fn selected_process_info(&self) -> Result<ProcessInfo> {
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

    fn read_layout_field<T>(&self, layout: &TypeInfo, base: VirtAddr, name: &str) -> Result<T>
    where
        T: Copy + zerocopy::FromZeros + zerocopy::FromBytes + zerocopy::IntoBytes,
    {
        self.context_memory()
            .read(base + layout.field_offset(name)?)
    }

    fn read_luid(&self, layout: &TypeInfo, base: VirtAddr) -> Result<u64> {
        let low: u32 = self.read_layout_field(layout, base, "LowPart")?;
        let high: i32 = self.read_layout_field(layout, base, "HighPart")?;
        Ok(((high as u32 as u64) << 32) | u64::from(low))
    }

    fn extract_layout_bits(&self, layout: &TypeInfo, base: VirtAddr, name: &str) -> Result<u64> {
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

    fn handle_entry_address(
        &self,
        table_base: VirtAddr,
        level: u8,
        index: usize,
        entry_size: usize,
    ) -> Result<VirtAddr> {
        let memory = self.context_memory();
        let leaf_entries = PAGE_SIZE / entry_size;
        match level {
            0 => Ok(table_base + (index * entry_size) as u64),
            1 => {
                let leaf: VirtAddr =
                    memory.read(table_base + ((index / leaf_entries) * 8) as u64)?;
                if leaf.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle leaf {} is null",
                        index / leaf_entries
                    )));
                }
                Ok(leaf + ((index % leaf_entries) * entry_size) as u64)
            }
            2 => {
                let middle_index = index / (leaf_entries * 512);
                let leaf_index = (index / leaf_entries) % 512;
                let middle: VirtAddr = memory.read(table_base + (middle_index * 8) as u64)?;
                if middle.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle middle table {middle_index} is null"
                    )));
                }
                let leaf: VirtAddr = memory.read(middle + (leaf_index * 8) as u64)?;
                if leaf.is_zero() {
                    return Err(Error::DebugInfo(format!(
                        "handle leaf {middle_index}:{leaf_index} is null"
                    )));
                }
                Ok(leaf + ((index % leaf_entries) * entry_size) as u64)
            }
            _ => Err(Error::DebugInfo(format!(
                "unsupported HANDLE_TABLE level {level}"
            ))),
        }
    }

    fn decode_handle_entry(
        &self,
        entry_layout: &TypeInfo,
        entry: VirtAddr,
        handle: u64,
    ) -> HandleEntryDetail {
        let object = (|| -> Result<VirtAddr> {
            if entry_layout.fields.contains_key("ObjectPointerBits") {
                let bits = self.extract_layout_bits(entry_layout, entry, "ObjectPointerBits")?;
                let mut pointer = bits << 4;
                if pointer & (1 << 47) != 0 {
                    pointer |= 0xffff_0000_0000_0000;
                }
                return Ok(VirtAddr(pointer));
            }
            let raw = self.extract_layout_bits(entry_layout, entry, "Object")?;
            Ok(VirtAddr(raw & !0xf))
        })();

        let granted_access = ["GrantedAccessBits", "GrantedAccess"]
            .into_iter()
            .find_map(|name| {
                entry_layout
                    .fields
                    .contains_key(name)
                    .then(|| self.extract_layout_bits(entry_layout, entry, name))
            })
            .unwrap_or_else(|| Err(Error::FieldNotFound("GrantedAccessBits".to_string())))
            .map(|value| value as u32);
        let attributes = ["ObAttributes", "Attributes"]
            .into_iter()
            .find_map(|name| {
                entry_layout
                    .fields
                    .contains_key(name)
                    .then(|| self.extract_layout_bits(entry_layout, entry, name))
            })
            .unwrap_or_else(|| Err(Error::FieldNotFound("ObAttributes".to_string())))
            .map(|value| value as u32);

        let header = object
            .as_ref()
            .map_err(|error| Error::DebugInfo(error.to_string()))
            .and_then(|object| {
                if object.is_zero() {
                    Err(Error::DebugInfo("handle entry is free".to_string()))
                } else {
                    self.inspect_object_header(*object)
                }
            });
        let type_name = match &header {
            Ok(header) => DiagnosticValue::Available(header.type_name.clone()),
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };
        let name = match &header {
            Ok(header) => DiagnosticValue::Available(header.name.clone()),
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };

        HandleEntryDetail {
            handle,
            entry,
            object: DiagnosticValue::from_result(object),
            type_name,
            name,
            granted_access: DiagnosticValue::from_result(granted_access),
            attributes: DiagnosticValue::from_result(attributes),
        }
    }

    fn handle_table_context(
        &self,
    ) -> Result<(ProcessInfo, VirtAddr, VirtAddr, u8, usize, TypeInfo)> {
        let process = self.selected_process_info()?;
        let types = self.guest()?.ntoskrnl.types_in(process.dtb);
        let eprocess = types.struct_at("_EPROCESS", process.eprocess_va)?;
        let table: VirtAddr = eprocess.read_field("ObjectTable")?;
        if table.is_zero() {
            return Err(Error::DebugInfo(
                "_EPROCESS.ObjectTable is null".to_string(),
            ));
        }
        let table_layout = types.layout("_HANDLE_TABLE")?;
        let table_code: u64 = self.read_layout_field(&table_layout, table, "TableCode")?;
        let level = (table_code & 3) as u8;
        if level > 2 {
            return Err(Error::DebugInfo(format!(
                "unsupported HANDLE_TABLE level {level}"
            )));
        }
        let next_handle: u64 =
            self.read_layout_field(&table_layout, table, "NextHandleNeedingPool")?;
        let entry_layout = types.layout("_HANDLE_TABLE_ENTRY")?;
        Ok((
            process,
            table,
            VirtAddr(table_code & !3),
            level,
            (next_handle / 4) as usize,
            entry_layout,
        ))
    }

    /// List non-free handles in the selected/current process.  Both page-table
    /// traversal and slot count are bounded by `limit`.
    pub fn enumerate_handles(&self, limit: usize) -> Result<HandleTableSummary> {
        let limit = limit.clamp(1, 4096);
        let (process, table, table_base, level, advertised, entry_layout) =
            self.handle_table_context()?;
        let scanned = advertised.min(limit);
        let mut entries = Vec::new();
        let mut skipped_entries = 0usize;
        for index in 0..scanned {
            let entry = match self.handle_entry_address(table_base, level, index, entry_layout.size)
            {
                Ok(entry) => entry,
                Err(_) => {
                    skipped_entries += 1;
                    continue;
                }
            };
            let decoded = self.decode_handle_entry(&entry_layout, entry, (index as u64) * 4);
            if !matches!(
                decoded.object,
                DiagnosticValue::Available(address) if address.is_zero()
            ) {
                entries.push(decoded);
            }
        }
        Ok(HandleTableSummary {
            process,
            table,
            table_level: level,
            advertised_handles: advertised,
            scanned_handles: scanned,
            skipped_entries,
            truncated: advertised > scanned,
            entries,
        })
    }

    /// Decode one handle from the same selected/current process handle table.
    pub fn inspect_handle(&self, handle: u64) -> Result<HandleEntryDetail> {
        if handle & 3 != 0 {
            return Err(Error::DebugInfo(format!(
                "handle {handle:#x} is not 4-byte aligned"
            )));
        }
        let (_, _, table_base, level, advertised, entry_layout) = self.handle_table_context()?;
        let index = (handle / 4) as usize;
        if index >= advertised {
            return Err(Error::DebugInfo(format!(
                "handle {handle:#x} is beyond NextHandleNeedingPool ({:#x})",
                advertised * 4
            )));
        }
        let entry = self.handle_entry_address(table_base, level, index, entry_layout.size)?;
        Ok(self.decode_handle_entry(&entry_layout, entry, handle))
    }

    fn read_sid(&self, address: VirtAddr) -> Result<String> {
        if address.is_zero() {
            return Err(Error::DebugInfo("SID pointer is null".to_string()));
        }
        let memory = self.context_memory();
        let revision: u8 = memory.read(address)?;
        let count: u8 = memory.read(address + 1u64)?;
        if count > 15 {
            return Err(Error::DebugInfo(format!(
                "SID subauthority count {count} exceeds 15"
            )));
        }
        let mut authority = [0u8; 6];
        memory.read_bytes(address + 2u64, &mut authority)?;
        let authority = authority
            .into_iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(byte));
        let mut sid = format!("S-{revision}-{authority}");
        for index in 0..count {
            let sub: u32 = memory.read(address + 8u64 + u64::from(index) * 4)?;
            sid.push_str(&format!("-{sub}"));
        }
        Ok(sid)
    }

    fn read_token_id_field(
        &self,
        token_layout: &TypeInfo,
        luid_layout: &TypeInfo,
        token: VirtAddr,
        name: &str,
    ) -> Result<u64> {
        self.read_luid(luid_layout, token + token_layout.field_offset(name)?)
    }

    /// Decode the selected/current process primary token.  Independently
    /// unavailable optional fields retain their exact layout/read error.
    pub fn inspect_process_token(&self) -> Result<TokenDetail> {
        const MAX_TOKEN_ITEMS: usize = 256;
        let process = self.selected_process_info()?;
        let types = self.guest()?.ntoskrnl.types_in(process.dtb);
        let eprocess_layout = types.layout("_EPROCESS")?;
        let raw_token: u64 =
            self.read_layout_field(&eprocess_layout, process.eprocess_va, "Token")?;
        let token = VirtAddr(raw_token & !0xf);
        if token.is_zero() {
            return Err(Error::DebugInfo("_EPROCESS.Token is null".to_string()));
        }
        let token_layout = types.layout("_TOKEN")?;
        let luid_layout = types.layout("_LUID")?;

        let token_id = DiagnosticValue::from_result(self.read_token_id_field(
            &token_layout,
            &luid_layout,
            token,
            "TokenId",
        ));
        let authentication_id = DiagnosticValue::from_result(self.read_token_id_field(
            &token_layout,
            &luid_layout,
            token,
            "AuthenticationId",
        ));
        let token_type =
            DiagnosticValue::from_result(self.read_layout_field(&token_layout, token, "TokenType"));
        let impersonation_level = DiagnosticValue::from_result(self.read_layout_field(
            &token_layout,
            token,
            "ImpersonationLevel",
        ));
        let flags = DiagnosticValue::from_result(self.read_layout_field(
            &token_layout,
            token,
            "TokenFlags",
        ));

        let sid_items = (|| -> Result<Vec<SidAndAttributes>> {
            let count: u32 = self.read_layout_field(&token_layout, token, "UserAndGroupCount")?;
            if count as usize > MAX_TOKEN_ITEMS {
                return Err(Error::DebugInfo(format!(
                    "_TOKEN.UserAndGroupCount {count} exceeds bound {MAX_TOKEN_ITEMS}"
                )));
            }
            let array: VirtAddr = self.read_layout_field(&token_layout, token, "UserAndGroups")?;
            if count != 0 && array.is_zero() {
                return Err(Error::DebugInfo(
                    "_TOKEN.UserAndGroups is null with nonzero count".to_string(),
                ));
            }
            let item_layout = types.layout("_SID_AND_ATTRIBUTES")?;
            let mut items = Vec::with_capacity(count as usize);
            for index in 0..count as usize {
                let base = array + (index * item_layout.size) as u64;
                let sid: VirtAddr = self.read_layout_field(&item_layout, base, "Sid")?;
                let attributes: u32 = self.read_layout_field(&item_layout, base, "Attributes")?;
                items.push(SidAndAttributes {
                    sid: self.read_sid(sid)?,
                    attributes,
                });
            }
            Ok(items)
        })();
        let (user, groups) = match sid_items {
            Ok(items) => (
                DiagnosticValue::Available(items.first().cloned()),
                DiagnosticValue::Available(items.into_iter().skip(1).collect()),
            ),
            Err(error) => (
                DiagnosticValue::Unavailable(error.to_string()),
                DiagnosticValue::Unavailable(error.to_string()),
            ),
        };

        let privileges = DiagnosticValue::from_result((|| -> Result<Vec<PrivilegeInfo>> {
            let privileges = token + token_layout.field_offset("Privileges")?;
            let privileges_layout = types.layout("_SEP_TOKEN_PRIVILEGES")?;
            let present: u64 = self.read_layout_field(&privileges_layout, privileges, "Present")?;
            let enabled: u64 = self.read_layout_field(&privileges_layout, privileges, "Enabled")?;
            let enabled_by_default: u64 =
                self.read_layout_field(&privileges_layout, privileges, "EnabledByDefault")?;
            Ok(decode_token_privilege_bitmaps(
                present,
                enabled,
                enabled_by_default,
            ))
        })());

        Ok(TokenDetail {
            process,
            token,
            token_id,
            authentication_id,
            token_type,
            impersonation_level,
            flags,
            user,
            groups,
            privileges,
        })
    }

    /// Decode a `_FILE_OBJECT` strictly from the loaded kernel PDB layout.
    pub fn inspect_file_object(&self, address: VirtAddr) -> Result<FileObjectDetail> {
        let types = self.guest()?.ntoskrnl.types_in(self.current_dtb());
        let layout = types.layout("_FILE_OBJECT")?;
        let read_ptr =
            |name| DiagnosticValue::from_result(self.read_layout_field(&layout, address, name));
        let read_bool = |name| {
            DiagnosticValue::from_result(
                self.read_layout_field::<u8>(&layout, address, name)
                    .map(|value| value != 0),
            )
        };
        let device_object: Result<VirtAddr> =
            self.read_layout_field(&layout, address, "DeviceObject");
        let device_type = match &device_object {
            Ok(device) if !device.is_zero() => DiagnosticValue::from_result(
                self.inspect_device_object(*device)
                    .map(|detail| detail.device_type),
            ),
            Ok(_) => DiagnosticValue::Unavailable("_FILE_OBJECT.DeviceObject is null".to_string()),
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };
        let device_name = match &device_object {
            Ok(device) if !device.is_zero() => DiagnosticValue::from_result(
                self.inspect_object_header(*device)
                    .map(|detail| detail.name),
            ),
            Ok(_) => DiagnosticValue::Unavailable("_FILE_OBJECT.DeviceObject is null".to_string()),
            Err(error) => DiagnosticValue::Unavailable(error.to_string()),
        };

        Ok(FileObjectDetail {
            address,
            file_type: DiagnosticValue::from_result(
                self.read_layout_field(&layout, address, "Type"),
            ),
            size: DiagnosticValue::from_result(self.read_layout_field(&layout, address, "Size")),
            device_object: DiagnosticValue::from_result(device_object),
            device_type,
            device_name,
            file_name: DiagnosticValue::from_result(
                types
                    .struct_at("_FILE_OBJECT", address)?
                    .unicode_string("FileName"),
            ),
            related_file_object: read_ptr("RelatedFileObject"),
            flags: DiagnosticValue::from_result(self.read_layout_field(&layout, address, "Flags")),
            current_byte_offset: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "CurrentByteOffset",
            )),
            fs_context: read_ptr("FsContext"),
            fs_context2: read_ptr("FsContext2"),
            section_object_pointer: read_ptr("SectionObjectPointer"),
            private_cache_map: read_ptr("PrivateCacheMap"),
            final_status: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "FinalStatus",
            )),
            lock_operation: read_bool("LockOperation"),
            delete_pending: read_bool("DeletePending"),
            read_access: read_bool("ReadAccess"),
            write_access: read_bool("WriteAccess"),
            delete_access: read_bool("DeleteAccess"),
            shared_read: read_bool("SharedRead"),
            shared_write: read_bool("SharedWrite"),
            shared_delete: read_bool("SharedDelete"),
        })
    }

    /// Decode one executive resource at an explicit address.
    pub fn inspect_resource(&self, address: VirtAddr) -> Result<ResourceDetail> {
        const MAX_RESOURCE_OWNERS: usize = 64;
        let types = self.guest()?.ntoskrnl.types_in(self.current_dtb());
        let layout = types.layout("_ERESOURCE")?;
        let owner_layout = types.layout("_OWNER_ENTRY")?;
        let owners = DiagnosticValue::from_result((|| -> Result<Vec<ResourceOwner>> {
            let mut owners = Vec::new();
            let owner_entry = address + layout.field_offset("OwnerEntry")?;
            let thread: u64 = self.read_layout_field(&owner_layout, owner_entry, "OwnerThread")?;
            let count: i32 = self.read_layout_field(&owner_layout, owner_entry, "OwnerCount")?;
            if thread & !3 != 0 && count != 0 {
                owners.push(ResourceOwner {
                    thread: VirtAddr(thread & !3),
                    count,
                });
            }

            let table: VirtAddr = self.read_layout_field(&layout, address, "OwnerTable")?;
            if table.is_zero() {
                return Ok(owners);
            }
            let table_size: u32 = self.read_layout_field(&owner_layout, table, "TableSize")?;
            if table_size as usize > MAX_RESOURCE_OWNERS {
                return Err(Error::DebugInfo(format!(
                    "_OWNER_ENTRY.TableSize {table_size} exceeds bound {MAX_RESOURCE_OWNERS}"
                )));
            }
            for index in 1..table_size as usize {
                let entry = table + (index * owner_layout.size) as u64;
                let thread: u64 = self.read_layout_field(&owner_layout, entry, "OwnerThread")?;
                let count: i32 = self.read_layout_field(&owner_layout, entry, "OwnerCount")?;
                if thread & !3 != 0 && count != 0 {
                    owners.push(ResourceOwner {
                        thread: VirtAddr(thread & !3),
                        count,
                    });
                }
            }
            Ok(owners)
        })());

        Ok(ResourceDetail {
            address,
            active_count: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "ActiveCount",
            )),
            flags: DiagnosticValue::from_result(self.read_layout_field(&layout, address, "Flag")),
            contention_count: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "ContentionCount",
            )),
            shared_waiters: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "NumberOfSharedWaiters",
            )),
            exclusive_waiters: DiagnosticValue::from_result(self.read_layout_field(
                &layout,
                address,
                "NumberOfExclusiveWaiters",
            )),
            owners,
        })
    }

    /// Enumerate the kernel-maintained executive-resource list when the private
    /// list-head symbol and `_ERESOURCE.SystemResourcesList` metadata exist.
    /// There is deliberately no memory-scan fallback.
    pub fn enumerate_resources(&self, limit: usize) -> Result<ResourceListSummary> {
        let limit = limit.clamp(1, 1024);
        let guest = self.guest()?;
        let head = guest.ntoskrnl.symbol("ExpSystemResourcesList")?.address();
        let layout = guest.ntoskrnl.types().layout("_ERESOURCE")?;
        let link_offset = layout.field_offset("SystemResourcesList")?;
        let memory = self.context_memory();
        let (links, termination) =
            bounded_list_walk(head, limit, |link| memory.read::<VirtAddr>(link));
        let resources = links
            .into_iter()
            .map(|link| self.inspect_resource(link - link_offset))
            .collect::<Result<Vec<_>>>()?;
        Ok(ResourceListSummary {
            head,
            resources,
            termination,
        })
    }

    fn process_memory_counter(
        &self,
        eprocess_layout: &TypeInfo,
        vm_layout: &TypeInfo,
        eprocess: VirtAddr,
        field: &str,
    ) -> DiagnosticValue<u64> {
        DiagnosticValue::from_result((|| -> Result<u64> {
            let vm = eprocess + eprocess_layout.field_offset("Vm")?;

            if let Ok(value) = self.read_layout_field(vm_layout, vm, field) {
                return Ok(value);
            }
            if let Ok(value) = self.read_layout_field(eprocess_layout, eprocess, field) {
                return Ok(value);
            }

            let types = self.guest()?.ntoskrnl.types();
            for container in ["Instance", "Shared"] {
                let Some(container_field) = vm_layout.fields.get(container) else {
                    continue;
                };
                let (ParsedType::Struct(layout_name) | ParsedType::Union(layout_name)) =
                    &container_field.type_data
                else {
                    continue;
                };
                let Ok(layout) = types.layout(layout_name) else {
                    continue;
                };
                if let Ok(value) =
                    self.read_layout_field(&layout, vm + u64::from(container_field.offset), field)
                {
                    return Ok(value);
                }
            }

            let page_field = match field {
                "PagefileUsage" => Some("CommitCharge"),
                "PeakPagefileUsage" => Some("CommitChargePeak"),
                "PrivateUsage" => Some("NumberOfPrivatePages"),
                _ => None,
            };
            if let Some(page_field) = page_field {
                let pages: u64 = self.read_layout_field(eprocess_layout, eprocess, page_field)?;
                return pages.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
                    Error::DebugInfo(format!("_EPROCESS.{page_field} overflows a byte count"))
                });
            }

            Err(Error::FieldNotFound(field.to_string()))
        })())
    }

    fn debugger_data_counter(
        &self,
        address: Option<MetadataValue<VirtAddr>>,
    ) -> Option<Result<MetadataValue<u64>>> {
        address.map(|address| {
            self.context_memory()
                .read::<u64>(address.value)
                .map(|value| MetadataValue {
                    value,
                    source: address.source,
                })
        })
    }

    fn global_memory_counter(
        &self,
        symbol_name: &str,
        debugger_data_value: Option<Result<MetadataValue<u64>>>,
        getter_name: Option<&str>,
    ) -> DiagnosticMetric<u64> {
        let mut errors = Vec::new();
        match self
            .guest()
            .and_then(|guest| guest.ntoskrnl.symbol(symbol_name))
            .and_then(|symbol| symbol.read())
        {
            Ok(value) => {
                return DiagnosticMetric::available(MetadataValue {
                    value,
                    source: MetadataSource::KernelSymbol,
                });
            }
            Err(error) => errors.push(error.to_string()),
        }

        if let Some(value) = debugger_data_value {
            match value {
                Ok(value) if value.value != 0 => return DiagnosticMetric::available(value),
                Ok(_) => {}
                Err(error) => errors.push(error.to_string()),
            }
        }

        if let Some(getter_name) = getter_name {
            match (|| -> Result<MetadataValue<u64>> {
                let guest = self.guest()?;
                let getter = guest.ntoskrnl.symbol(getter_name)?.address();
                let system_partition = guest.ntoskrnl.symbol("MiSystemPartition")?.address();
                read_counter_from_getter(&self.context_memory(), getter, system_partition)
            })() {
                Ok(value) => return DiagnosticMetric::available(value),
                Err(error) => errors.push(error.to_string()),
            }
        }

        DiagnosticMetric::unavailable(errors)
    }

    /// Build a bounded memory-use summary from exported memory-manager counters
    /// and per-process `_EPROCESS.Vm` fields.  It never scans physical memory or
    /// walks every VAD.
    pub fn memory_use_summary(&self, process_limit: usize) -> Result<SystemMemorySummary> {
        let process_limit = process_limit.clamp(1, 256);
        let all_processes = self.matching_processes(None)?;
        let process_count = all_processes.len();
        let guest = self.guest()?;
        let types = guest.ntoskrnl.types();
        let eprocess_layout = types.layout("_EPROCESS")?;
        let vm_field = eprocess_layout
            .fields
            .get("Vm")
            .ok_or_else(|| Error::FieldNotFound("Vm".to_string()))?;
        let vm_name = match &vm_field.type_data {
            ParsedType::Struct(name) | ParsedType::Union(name) => name,
            _ => {
                return Err(Error::FieldTypeMismatch(
                    "Vm".to_string(),
                    "embedded struct".to_string(),
                ));
            }
        };
        let vm_layout = types.layout(vm_name)?;
        let processes = all_processes
            .into_iter()
            .take(process_limit)
            .map(|process| ProcessMemoryUsage {
                virtual_size: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "VirtualSize",
                ),
                peak_virtual_size: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PeakVirtualSize",
                ),
                working_set_size: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "WorkingSetSize",
                ),
                peak_working_set_size: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PeakWorkingSetSize",
                ),
                pagefile_usage: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PagefileUsage",
                ),
                peak_pagefile_usage: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PeakPagefileUsage",
                ),
                private_usage: self.process_memory_counter(
                    &eprocess_layout,
                    &vm_layout,
                    process.eprocess_va,
                    "PrivateUsage",
                ),
                process,
            })
            .collect();
        let debugger_data = self.debugger_data();
        Ok(SystemMemorySummary {
            physical_pages: self.global_memory_counter(
                "MmNumberOfPhysicalPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_number_of_physical_pages_address),
                ),
                Some("MmGetNumberOfPhysicalPages"),
            ),
            available_pages: self.global_memory_counter(
                "MmAvailablePages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_available_pages_address),
                ),
                Some("MmGetAvailablePages"),
            ),
            committed_pages: self.global_memory_counter(
                "MmTotalCommittedPages",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_committed_pages_address),
                ),
                Some("MmGetTotalCommittedPages"),
            ),
            commit_limit_pages: self.global_memory_counter(
                "MmTotalCommitLimit",
                self.debugger_data_counter(
                    debugger_data.and_then(DebuggerDataBlock::mm_total_commit_limit_address),
                ),
                Some("MmGetTotalCommitLimit"),
            ),
            // KDBG exposes the configured paged-pool virtual range, not current
            // usage, so it is intentionally not substituted here.
            paged_pool_pages: self.global_memory_counter("MmSizeOfPagedPoolInPages", None, None),
            // KDBG exposes the configured maximum nonpaged-pool size, not the
            // current usage requested here, so it is intentionally not substituted.
            nonpaged_pool_bytes: self.global_memory_counter(
                "MmSizeOfNonPagedPoolInBytes",
                None,
                None,
            ),
            processes,
            process_count,
            truncated: process_count > process_limit,
        })
    }

    /// Decode the executive `_OBJECT_HEADER` for `addr`, accepting either the
    /// object body or the header itself, and resolve its type and name.
    pub fn inspect_object_header(&self, addr: VirtAddr) -> Result<ObjectHeaderDetail> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_OBJECT_HEADER")?;
        let header_size = layout.size as u64;
        let body_off = layout.field_offset("Body")?;
        let type_index_off = layout.field_offset("TypeIndex")?;
        let object_name = self.object_name_layout().ok();
        let cookie = match guest.ntoskrnl.symbol("ObHeaderCookie") {
            Ok(symbol) => symbol.read::<u8>()?,
            Err(Error::SymbolNotFound(_)) => 0,
            Err(error) => return Err(error),
        };
        let type_table = guest
            .ntoskrnl
            .symbol("ObTypeIndexTable")
            .ok()
            .map(|symbol| symbol.address());

        let header_ok = |header: VirtAddr| -> bool {
            header_size
                .checked_sub(1)
                .and_then(|last| header.0.checked_add(last))
                .map(VirtAddr)
                .is_some_and(|end| mem.read::<u8>(header).is_ok() && mem.read::<u8>(end).is_ok())
        };
        let candidate_type_object = |header: VirtAddr| -> Option<VirtAddr> {
            let raw: u8 = mem.read(header + type_index_off).ok()?;
            let index = u64::from(raw ^ ((header.0 >> 8) as u8) ^ cookie);
            mem.read::<VirtAddr>(type_table? + index * 8)
                .ok()
                .filter(|object| looks_like_kernel_pointer(object.0))
        };

        // The input is usually the object body. If both possible headers are
        // readable, use the decoded type table to distinguish a real header
        // from unrelated readable pool bytes before it.
        let body_candidate = addr
            .0
            .checked_sub(body_off)
            .map(VirtAddr)
            .filter(|header| header_ok(*header));
        let direct_candidate = header_ok(addr).then_some(addr);
        let body_type = body_candidate.and_then(candidate_type_object);
        let direct_type = direct_candidate.and_then(candidate_type_object);
        let (header, body, mode) = select_object_header_candidate(
            addr,
            body_off,
            body_candidate,
            direct_candidate,
            body_type.is_some(),
            direct_type.is_some(),
        )
        .ok_or_else(|| {
            Error::DebugInfo(format!("no plausible _OBJECT_HEADER for {:#x}", addr.0))
        })?;

        let h = self.kernel_struct("_OBJECT_HEADER", header)?;
        let info_mask: Option<u8> = h.read_field("InfoMask").ok();

        // On Win10+ the stored TypeIndex is obfuscated; the real index is
        // raw ^ (second byte of the header address) ^ nt!ObHeaderCookie. The
        // cookie symbol is absent on older builds (treat as 0 -> raw index).
        let type_index: Option<u64> = h
            .read_field::<u8>("TypeIndex")
            .ok()
            .map(|raw| (raw ^ ((header.0 >> 8) as u8) ^ cookie) as u64);

        // Resolve the type object via ObTypeIndexTable[index] and read its name.
        // ObTypeIndexTable is the array itself, so index it directly.
        let (type_object, type_name) = match (type_table, type_index) {
            (Some(table), Some(index)) => {
                let resolved = mem
                    .read::<VirtAddr>(table + index * 8)
                    .ok()
                    .filter(|object| looks_like_kernel_pointer(object.0));
                let name = resolved.and_then(|t| {
                    let off = guest
                        .ntoskrnl
                        .types()
                        .layout("_OBJECT_TYPE")
                        .ok()?
                        .field_offset("Name")
                        .ok()?;
                    self.read_kernel_unicode_string(t + off)
                        .ok()
                        .filter(|s| !s.is_empty())
                });
                (resolved, name)
            }
            _ => (None, None),
        };

        let name_info = info_mask.and_then(|mask| {
            object_name
                .as_ref()
                .and_then(|layout| layout.name_info_address(header, mask).ok().flatten())
        });
        let name = name_info.and_then(|info| {
            object_name.as_ref().and_then(|layout| {
                self.read_kernel_unicode_string(info + layout.name_offset)
                    .ok()
                    .filter(|name| !name.is_empty())
            })
        });

        Ok(ObjectHeaderDetail {
            input: addr,
            mode,
            header,
            body,
            pointer_count: h.read_field("PointerCount")?,
            handle_count: h.read_field("HandleCount")?,
            type_index,
            type_object,
            type_name,
            info_mask,
            name_info,
            name,
        })
    }

    /// Classify `address`: which loaded module (and PE section) it falls in, or
    /// which process VAD region, else unknown. The shared backend for the REPL
    /// `address` command, the MCP tool, and the SDK.
    pub fn describe_address(&self, address: VirtAddr) -> Result<AddressDescription> {
        let dtb = self.current_dtb();
        let is_kernel = address.0 >= 0xffff_0000_0000_0000;

        // 1. Loaded module containment (kernel list for kernel VAs, else the
        // current scope's user modules).
        let modules = if is_kernel {
            self.kernel_modules()
        } else {
            self.modules()
        };
        if let Ok(mods) = modules
            && let Some(m) = mods.into_iter().find(|m| {
                address.0 >= m.base_address.0 && address.0 < m.base_address.0 + m.size as u64
            })
        {
            let memory = self.current_process()?.memory();
            let section = section_name_at(&memory, m.base_address, address);
            return Ok(AddressDescription {
                address,
                dtb,
                kind: if is_kernel {
                    "kernel-module"
                } else {
                    "user-image"
                },
                module: Some(AddressModule {
                    name: m.name,
                    base: m.base_address,
                    size: m.size,
                    offset: address.0 - m.base_address.0,
                }),
                section,
                va_type: None,
                region: None,
            });
        }

        // 2. Kernel dynamic-VA region (pool, stacks, PTEs, cache, ...) via the
        // MM SystemVaType map.
        if is_kernel && let Some(va_type) = self.kernel_va_region(address) {
            return Ok(AddressDescription {
                address,
                dtb,
                kind: "kernel-region",
                module: None,
                section: None,
                va_type: Some(va_type),
                region: None,
            });
        }

        // 3. Process VAD region (when attached to a process).
        if let Some(p) = self.current_process_info.as_ref()
            && let Ok(regions) = self.enumerate_vad_regions_for_process_info(p)
            && let Some(r) = regions
                .into_iter()
                .find(|r| address.0 >= r.start.0 && address.0 < r.end.0)
        {
            let kind = match r.private_memory {
                Some(true) => "private",
                _ => "mapped",
            };
            return Ok(AddressDescription {
                address,
                dtb,
                kind,
                module: None,
                section: None,
                va_type: None,
                region: Some(r),
            });
        }

        // 4. Nothing recognized.
        Ok(AddressDescription {
            address,
            dtb,
            kind: "unknown",
            module: None,
            section: None,
            va_type: None,
            region: None,
        })
    }

    /// Classify a kernel dynamic-VA address via the MM `SystemVaType` map:
    /// `chunk = (va - MmSystemRangeStart) / granularity`, where the granularity
    /// is the kernel half divided into the 256-entry map. Returns the
    /// `MI_SYSTEM_VA_TYPE` name (sans `MiVa` prefix), read from the PDB enum so
    /// it adapts per build. `MiVisibleState` is a pointer to `_MI_VISIBLE_STATE`.
    fn kernel_va_region(&self, address: VirtAddr) -> Option<String> {
        let ntos = &self.guest.as_ref()?.ntoskrnl;
        let range_start: VirtAddr = ntos.symbol("MmSystemRangeStart").ok()?.read().ok()?;
        if address.0 < range_start.0 {
            return None;
        }
        // Kernel-half size / 256 (512GB on 4-level, 256TB on 5-level).
        let granularity = range_start.0.wrapping_neg() / 256;
        if granularity == 0 {
            return None;
        }
        let chunk = (address.0 - range_start.0) / granularity;
        if chunk >= 256 {
            return None;
        }

        let vs: VirtAddr = ntos.symbol("MiVisibleState").ok()?.read().ok()?;
        let type_off = ntos
            .types()
            .layout("_MI_VISIBLE_STATE")
            .ok()?
            .field_offset("SystemVaType")
            .ok()?;
        let type_byte: u8 = ntos.memory().read(vs + type_off + chunk).ok()?;

        let variants = self
            .symbols
            .find_enum_across_modules(ntos.dtb(), "_MI_SYSTEM_VA_TYPE")?;
        let name = variants
            .into_iter()
            .find(|(_, v)| *v == type_byte as i64)
            .map(|(n, _)| n)?;
        Some(name.strip_prefix("MiVa").unwrap_or(&name).to_string())
    }

    /// Enumerate the process/thread/image notification callbacks registered in
    /// the `Psp*NotifyRoutine` fast-ref arrays.
    pub fn enumerate_notify_callbacks(&self) -> Result<Vec<NotifyCallback>> {
        const MAX_NOTIFY: u64 = 64;
        let sets: [(&str, &str); 3] = [
            ("process", "PspCreateProcessNotifyRoutine"),
            ("thread", "PspCreateThreadNotifyRoutine"),
            ("image", "PspLoadImageNotifyRoutine"),
        ];

        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let ex_callback_size = guest
            .ntoskrnl
            .types()
            .layout("_EX_CALLBACK")
            .ok()
            .map(|l| l.size as u64)
            .filter(|s| (8..=0x40).contains(s))
            .unwrap_or(8);
        let block_layout = guest
            .ntoskrnl
            .types()
            .layout("_EX_CALLBACK_ROUTINE_BLOCK")
            .ok();
        let function_off = block_layout
            .as_ref()
            .and_then(|l| l.field_offset("Function").ok())
            .unwrap_or(8);
        let context_off = block_layout
            .as_ref()
            .and_then(|l| l.field_offset("Context").ok())
            .unwrap_or(16);

        let is_kernel = |a: VirtAddr| a.0 >= 0xffff_0000_0000_0000;
        let mut out = Vec::new();

        for (kind, symbol) in sets {
            let Ok(sym) = guest.ntoskrnl.symbol(symbol) else {
                continue;
            };
            let base = sym.address();
            for i in 0..MAX_NOTIFY {
                let entry = base + i * ex_callback_size;
                let Ok(raw): Result<VirtAddr> = mem.read(entry) else {
                    continue;
                };
                if raw.is_zero() {
                    continue;
                }
                let block = VirtAddr(raw.0 & !0xf);
                if block.is_zero() {
                    continue;
                }
                // Prefer the PDB-described layout; fall back to the stable
                // EX_RUNDOWN_REF / function / context shape when it doesn't
                // point at a kernel routine.
                let mut function = mem
                    .read::<VirtAddr>(block + function_off)
                    .unwrap_or(VirtAddr(0));
                let mut context = mem
                    .read::<VirtAddr>(block + context_off)
                    .unwrap_or(VirtAddr(0));
                if !is_kernel(function) {
                    function = mem.read::<VirtAddr>(block + 8u64).unwrap_or(VirtAddr(0));
                    context = mem.read::<VirtAddr>(block + 16u64).unwrap_or(VirtAddr(0));
                }
                if !is_kernel(function) {
                    continue;
                }
                out.push(NotifyCallback {
                    kind,
                    index: i as usize,
                    function,
                    block,
                    raw,
                    context,
                });
            }
        }

        Ok(out)
    }

    fn dump_ssdt_table(&self, label: &str, base: VirtAddr, limit: u32, guest: &Guest) -> SsdtTable {
        let mem = guest.ntoskrnl.memory();
        let dtb = guest.ntoskrnl.dtb();
        let mut entries = Vec::new();
        // Clamp implausible limits so a garbage descriptor can't spin.
        let limit = limit.min(0x4000);
        for i in 0..limit {
            let Ok(raw) = mem.read::<u32>(base + (i as u64) * 4) else {
                break;
            };
            // Entries encode a signed offset in the high 28 bits: target =
            // base + (entry >> 4) with arithmetic shift.
            let offset = (raw as i32 >> 4) as i64;
            let target = VirtAddr((base.0 as i64 + offset) as u64);
            let resolved = self.symbols.find_closest_symbol_for_address(dtb, target);
            let (symbol, module) = match resolved {
                Some((module, name, off)) => {
                    let sym = if off == 0 {
                        format!("{module}!{name}")
                    } else {
                        format!("{module}!{name}+{off:#x}")
                    };
                    (Some(sym), Some(module))
                }
                None => (None, None),
            };
            entries.push(SsdtEntry {
                index: i,
                target,
                symbol,
                module,
            });
        }
        SsdtTable {
            label: label.to_string(),
            base,
            limit,
            entries,
        }
    }

    /// Dump the kernel SSDT (`KiServiceTable`) and, when initialized, the
    /// win32k shadow table from `KeServiceDescriptorTableShadow`.
    pub fn dump_ssdt(&self) -> Result<Vec<SsdtTable>> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let base = guest.ntoskrnl.symbol("KiServiceTable")?.address();
        let limit = guest.ntoskrnl.symbol("KiServiceLimit")?.read::<u32>()?;
        let mut tables = vec![self.dump_ssdt_table("SSDT", base, limit, guest)];

        // Shadow table: [0] is the kernel SSDT, [1] is win32k. Only present once
        // a GUI thread has initialized it.
        if let Ok(sdt) = guest.ntoskrnl.symbol("KeServiceDescriptorTableShadow") {
            let desc = guest.ntoskrnl.types().layout("_KSERVICE_TABLE_DESCRIPTOR");
            let desc_size = desc.as_ref().ok().map(|l| l.size as u64).unwrap_or(0x20);
            let base_off = desc
                .as_ref()
                .ok()
                .and_then(|l| l.field_offset("Base").ok())
                .unwrap_or(0);
            let limit_off = desc
                .as_ref()
                .ok()
                .and_then(|l| l.field_offset("Limit").ok())
                .unwrap_or(0x10);
            let win32k = sdt.address() + desc_size;
            if let Ok(w_base) = mem.read::<VirtAddr>(win32k + base_off)
                && !w_base.is_zero()
            {
                let w_limit = mem.read::<u32>(win32k + limit_off).unwrap_or(0);
                tables.push(self.dump_ssdt_table("shadow SSDT (win32k)", w_base, w_limit, guest));
            }
        }

        Ok(tables)
    }

    /// Read an `_IRP` only if it looks like one (Type == 6, plausible Size),
    /// returning `(stack_count, current_location)`.
    fn plausible_irp(&self, irp: VirtAddr) -> Option<(u8, u8)> {
        let guest = self.guest.as_ref()?;
        let mem = guest.ntoskrnl.memory();
        let layout = guest.ntoskrnl.types().layout("_IRP").ok()?;
        let ty: u16 = mem.read(irp).ok()?;
        if ty != 6 {
            return None;
        }
        let size: u16 = mem.read(irp + layout.field_offset("Size").ok()?).ok()?;
        if (size as u64) < layout.size as u64 || size > 0x1000 {
            return None;
        }
        let sc = mem
            .read::<u8>(irp + layout.field_offset("StackCount").ok()?)
            .unwrap_or(0);
        let cl = mem
            .read::<u8>(irp + layout.field_offset("CurrentLocation").ok()?)
            .unwrap_or(0);
        Some((sc, cl))
    }

    /// Discover in-flight IRPs by walking each thread's `_ETHREAD.IrpList` and
    /// each device's `_DEVICE_OBJECT.CurrentIrp`. `filter` scopes processes
    /// (pid or name substring) and, for the device sweep, driver names.
    pub fn discover_irps(&self, filter: Option<&str>) -> Result<Vec<IrpHit>> {
        let guest = self.guest()?;
        let mem = guest.ntoskrnl.memory();
        let off = |ty: &str, field: &str| -> Option<u64> {
            guest
                .ntoskrnl
                .types()
                .layout(ty)
                .ok()
                .and_then(|l| l.field_offset(field).ok())
        };
        let read_ptr = |a: VirtAddr| mem.read::<VirtAddr>(a).ok();

        let filter_l = filter.map(|f| f.to_ascii_lowercase());
        let numeric_filter = filter.and_then(|f| f.parse::<u64>().ok());
        let mut out = Vec::new();

        // --- process / thread IrpLists ---
        let procs = guest.enumerate_processes()?;
        let thread_head_off = off("_EPROCESS", "ThreadListHead");
        let thread_link_off = off("_ETHREAD", "ThreadListEntry");
        let irp_list_off = off("_ETHREAD", "IrpList");
        let irp_link_off = off("_IRP", "ThreadListEntry");
        let cid_off = off("_ETHREAD", "Cid");
        let tcb_off = off("_ETHREAD", "Tcb").unwrap_or(0);
        let unique_thread_off = off("_CLIENT_ID", "UniqueThread");
        let state_off = off("_KTHREAD", "State");
        let wait_off = off("_KTHREAD", "WaitReason");

        for p in &procs {
            let matched = match (&filter_l, numeric_filter) {
                (None, _) => true,
                (Some(_), Some(pid)) => p.pid == pid,
                (Some(f), None) => p.name.to_ascii_lowercase().contains(f.as_str()),
            };
            if !matched {
                continue;
            }
            let (Some(head_off), Some(link_off), Some(list_off), Some(rec_off)) =
                (thread_head_off, thread_link_off, irp_list_off, irp_link_off)
            else {
                break;
            };

            // Walk the process thread list (ETHREAD.ThreadListEntry).
            let head = p.eprocess_va + head_off;
            let mut seen_t = Vec::new();
            let mut cur = read_ptr(head);
            for _ in 0..4096 {
                let Some(node) = cur else { break };
                if node.is_zero() || node == head || seen_t.contains(&node.0) {
                    break;
                }
                seen_t.push(node.0);
                let ethread = node - link_off;

                let tid = cid_off
                    .zip(unique_thread_off)
                    .and_then(|(c, u)| mem.read::<u64>(ethread + c + u).ok());
                let state = state_off.and_then(|o| mem.read::<u8>(ethread + tcb_off + o).ok());
                let wait = wait_off.and_then(|o| mem.read::<u8>(ethread + tcb_off + o).ok());

                // Walk this thread's IrpList (IRP.ThreadListEntry).
                let irp_head = ethread + list_off;
                let mut seen_i = Vec::new();
                let mut icur = read_ptr(irp_head);
                for _ in 0..256 {
                    let Some(inode) = icur else { break };
                    if inode.is_zero() || inode == irp_head || seen_i.contains(&inode.0) {
                        break;
                    }
                    seen_i.push(inode.0);
                    let irp = inode - rec_off;
                    if let Some((sc, cl)) = self.plausible_irp(irp) {
                        out.push(IrpHit {
                            irp,
                            source: "thread",
                            stack_count: sc,
                            current_location: cl,
                            pid: Some(p.pid),
                            tid,
                            ethread: Some(ethread),
                            state,
                            wait_reason: wait,
                            driver: None,
                            device: None,
                        });
                    }
                    icur = read_ptr(inode);
                }
                cur = read_ptr(node);
            }
        }

        // --- device CurrentIrp sweep (skipped for a numeric/pid filter) ---
        if numeric_filter.is_none() {
            let current_irp_off = off("_DEVICE_OBJECT", "CurrentIrp");
            let next_off = off("_DEVICE_OBJECT", "NextDevice");
            if let (Some(cur_off), Some(next_off)) = (current_irp_off, next_off) {
                for driver in self.enumerate_driver_objects()? {
                    if let Some(f) = &filter_l
                        && !driver.name.to_ascii_lowercase().contains(f.as_str())
                    {
                        continue;
                    }
                    let mut seen = Vec::new();
                    let mut cur = Some(driver.device_object);
                    for _ in 0..256 {
                        let Some(dev) = cur else { break };
                        if dev.is_zero() || seen.contains(&dev.0) {
                            break;
                        }
                        seen.push(dev.0);
                        let current_irp = read_ptr(dev + cur_off).unwrap_or(VirtAddr(0));
                        if !current_irp.is_zero()
                            && let Some((sc, cl)) = self.plausible_irp(current_irp)
                        {
                            out.push(IrpHit {
                                irp: current_irp,
                                source: "device",
                                stack_count: sc,
                                current_location: cl,
                                pid: None,
                                tid: None,
                                ethread: None,
                                state: None,
                                wait_reason: None,
                                driver: Some(driver.name.clone()),
                                device: Some(dev),
                            });
                        }
                        cur = read_ptr(dev + next_off);
                    }
                }
            }
        }

        Ok(out)
    }

    pub fn enumerate_threads_for_process_info(
        &self,
        process: &ProcessInfo,
    ) -> Result<Vec<ThreadInfo>> {
        let guest = self.guest()?;
        let memory = guest.ntoskrnl.memory();
        let eprocess = guest
            .ntoskrnl
            .types_in(process.dtb)
            .struct_at("_EPROCESS", process.eprocess_va)?;
        let eprocess_layout = guest.ntoskrnl.types().layout("_EPROCESS")?;
        let thread_list_head_offset = eprocess_layout.field_offset("ThreadListHead")?;
        let ethread_layout = guest.ntoskrnl.types().layout("_ETHREAD")?;
        let thread_list_entry_offset = ethread_layout.field_offset("ThreadListEntry")?;
        let head = eprocess.addr() + thread_list_head_offset;

        let mut threads = Vec::new();
        let mut visited = HashSet::new();
        let mut current: VirtAddr = memory.read(head)?;

        for _ in 0..16384 {
            if current.is_zero() || current == head || !visited.insert(current.0) {
                break;
            }

            let ethread = current - thread_list_entry_offset;
            threads.push(self.thread_info_from_ethread_with_hint(ethread, Some(process))?);
            current = memory.read(current)?;
        }

        Ok(threads)
    }

    pub fn enumerate_threads(&self) -> Result<Vec<ThreadInfo>> {
        let processes = self.guest()?.enumerate_processes()?;
        let mut threads = Vec::new();

        for process in &processes {
            let Ok(process_threads) = self.enumerate_threads_for_process_info(process) else {
                continue;
            };
            threads.extend(process_threads);
        }

        Ok(threads)
    }

    pub fn thread_info_from_ethread(&self, ethread: VirtAddr) -> Result<ThreadInfo> {
        self.thread_info_from_ethread_with_hint(ethread, None)
    }

    fn thread_info_from_ethread_with_hint(
        &self,
        ethread: VirtAddr,
        process_hint: Option<&ProcessInfo>,
    ) -> Result<ThreadInfo> {
        let guest = self.guest()?;
        let memory = guest.ntoskrnl.memory();
        let types = guest.ntoskrnl.types();
        let ethread_layout = types.layout("_ETHREAD")?;
        let kthread_layout = types.layout("_KTHREAD")?;
        let tcb_offset = ethread_layout.field_offset("Tcb").unwrap_or(0);
        let kthread = ethread + tcb_offset;

        let cid_base = ethread_layout
            .field_offset("Cid")
            .ok()
            .map(|offset| ethread + offset);
        let client_id_layout = types.layout("_CLIENT_ID").ok();
        let tid = cid_base.and_then(|base| {
            client_id_layout
                .as_ref()
                .and_then(|layout| layout.field_offset("UniqueThread").ok())
                .and_then(|offset| memory.read::<u64>(base + offset).ok())
        });
        let pid = cid_base.and_then(|base| {
            client_id_layout
                .as_ref()
                .and_then(|layout| layout.field_offset("UniqueProcess").ok())
                .and_then(|offset| memory.read::<u64>(base + offset).ok())
        });

        let read_ethread_ptr = |field: &str| -> Option<VirtAddr> {
            ethread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<VirtAddr>(ethread + offset).ok())
                .filter(|addr| !addr.is_zero())
        };
        let read_kthread_ptr = |field: &str| -> Option<VirtAddr> {
            kthread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<VirtAddr>(kthread + offset).ok())
                .filter(|addr| !addr.is_zero())
        };
        let read_kthread_u8 = |field: &str| -> Option<u8> {
            kthread_layout
                .field_offset(field)
                .ok()
                .and_then(|offset| memory.read::<u8>(kthread + offset).ok())
        };

        // KTHREAD.Process is a KPROCESS*, which is the Pcb at offset 0 of the
        // owning EPROCESS; present across modern builds and the most reliable
        // source. ThreadsProcess (older builds) and ProcessFastRef (newest, an
        // EX_FAST_REF that packs the pointer with refcount bits in the low 4)
        // are build-specific fallbacks.
        let eprocess = read_kthread_ptr("Process")
            .or_else(|| read_ethread_ptr("ThreadsProcess"))
            .or_else(|| {
                ethread_layout
                    .field_offset("ProcessFastRef")
                    .ok()
                    .and_then(|offset| memory.read::<u64>(ethread + offset).ok())
                    .map(|raw| VirtAddr(raw & !0xf))
                    .filter(|addr| !addr.is_zero())
            });

        // Bulk enumeration passes the owning process as a hint, so it never
        // walks the process list per thread. Single-thread lookups (break
        // context, `thread_info_from_ethread`) have no hint, so match the
        // thread's pid/EPROCESS against a one-shot process list for the name.
        let owner: Option<ProcessInfo> = match process_hint {
            Some(_) => None,
            None => guest.enumerate_processes().ok().and_then(|processes| {
                processes.into_iter().find(|process| {
                    pid.is_some_and(|pid| process.pid == pid)
                        || eprocess.is_some_and(|eprocess| process.eprocess_va == eprocess)
                })
            }),
        };
        let owner = process_hint.or(owner.as_ref());

        let process_name = owner
            .map(|process| process.name.clone())
            .or_else(|| eprocess.and_then(|eprocess| guest.process_image_name(eprocess)))
            // PID 0 is the System Idle Process, which isn't on PsActiveProcessHead
            // and so never matches above; label its per-CPU idle threads like WinDbg
            .or_else(|| (pid == Some(0)).then(|| "Idle".to_string()));

        Ok(ThreadInfo {
            ethread,
            kthread,
            tid,
            pid: pid.or_else(|| owner.map(|process| process.pid)),
            process_name,
            eprocess: eprocess.or_else(|| owner.map(|process| process.eprocess_va)),
            state: read_kthread_u8("State"),
            wait_reason: read_kthread_u8("WaitReason"),
            priority: read_kthread_u8("Priority"),
            base_priority: read_kthread_u8("BasePriority"),
            wait_irql: read_kthread_u8("WaitIrql"),
            kernel_stack_resident: read_kthread_u8("KernelStackResident").map(|value| value != 0),
            start_address: read_ethread_ptr("StartAddress"),
            win32_start_address: read_ethread_ptr("Win32StartAddress"),
            teb: read_ethread_ptr("Teb"),
            kernel_stack: read_kthread_ptr("KernelStack"),
            stack_base: read_kthread_ptr("StackBase"),
            stack_limit: read_kthread_ptr("StackLimit"),
            trap_frame: read_kthread_ptr("TrapFrame"),
            pending_irps: self.thread_pending_irps(&memory, &ethread_layout, ethread),
        })
    }

    fn thread_pending_irps(
        &self,
        memory: &impl MemoryOps<VirtAddr>,
        ethread_layout: &TypeInfo,
        ethread: VirtAddr,
    ) -> Option<Vec<VirtAddr>> {
        let irp_list_offset = ethread_layout.field_offset("IrpList").ok()?;
        let irp_layout = self.guest.as_ref()?.ntoskrnl.types().layout("_IRP").ok()?;
        let thread_list_entry_offset = irp_layout.field_offset("ThreadListEntry").ok()?;
        let head = ethread + irp_list_offset;
        let mut current: VirtAddr = memory.read(head).ok()?;
        let mut irps = Vec::new();
        let mut visited = HashSet::new();

        for _ in 0..256 {
            if current.is_zero() || current == head || !visited.insert(current.0) {
                break;
            }
            irps.push(current - thread_list_entry_offset);
            current = match memory.read(current) {
                Ok(next) => next,
                Err(_) => break,
            };
        }

        Some(irps)
    }

    pub fn current_windows_thread_for_processor(&self, processor: u16) -> Result<ThreadInfo> {
        let guest = self.guest()?;
        let memory = guest.ntoskrnl.memory();
        let prcb_current_thread_offset = guest
            .ntoskrnl
            .types()
            .layout("_KPRCB")?
            .field_offset("CurrentThread")?;
        let ethread_tcb_offset = guest
            .ntoskrnl
            .types()
            .layout("_ETHREAD")?
            .field_offset("Tcb")
            .unwrap_or(0);
        let processor_block = guest.ntoskrnl.symbol("KiProcessorBlock")?.address();
        let prcb: VirtAddr = memory.read(processor_block + (processor as u64) * 8)?;
        if prcb.is_zero() {
            return Err(Error::DebugInfo(format!(
                "KiProcessorBlock[{}] is null",
                processor
            )));
        }

        let kthread: VirtAddr = memory.read(prcb + prcb_current_thread_offset)?;
        if kthread.is_zero() {
            return Err(Error::DebugInfo(format!(
                "KPRCB.CurrentThread for processor {} is null",
                processor
            )));
        }

        self.thread_info_from_ethread(kthread - ethread_tcb_offset)
    }

    pub fn enumerate_vad_regions_for_process_info(
        &self,
        process: &ProcessInfo,
    ) -> Result<Vec<MemoryRegionInfo>> {
        let guest = self.guest()?;
        let memory = self.address_space(process.dtb);
        let types = guest.ntoskrnl.types_in(process.dtb);
        let eprocess_layout = guest.ntoskrnl.types().layout("_EPROCESS")?;
        let vad_root_base = process.eprocess_va + eprocess_layout.field_offset("VadRoot")?;
        let root = self.read_vad_root(process.dtb, vad_root_base)?;
        if root.is_zero() {
            return Ok(Vec::new());
        }

        let vad_layout = types
            .layout("_MMVAD_SHORT")
            .or_else(|_| types.layout("_MMVAD"))?;
        let vad_node_offset = vad_layout.field_offset("VadNode").unwrap_or(0);
        let node_layout = types.layout("_RTL_BALANCED_NODE")?;
        let left_offset = node_layout.field_offset("Left").unwrap_or(0);
        let right_offset = node_layout.field_offset("Right").unwrap_or(8);
        let flags_layout = types.layout("_MMVAD_FLAGS").ok();
        let modules = guest.process_modules(process).unwrap_or_default();

        let mut regions = Vec::new();
        let mut stack = vec![root];
        let mut visited = HashSet::new();

        while let Some(node) = stack.pop() {
            if node.is_zero() || !visited.insert(node.0) || visited.len() > 65536 {
                continue;
            }

            let left = Self::canonical_vad_link(memory.read::<VirtAddr>(node + left_offset)?);
            let right = Self::canonical_vad_link(memory.read::<VirtAddr>(node + right_offset)?);
            if !right.is_zero() {
                stack.push(right);
            }
            if !left.is_zero() {
                stack.push(left);
            }

            let vad = node - vad_node_offset;
            if let Some(region) =
                self.read_vad_region(&memory, &vad_layout, flags_layout.as_ref(), vad, &modules)
            {
                regions.push(region);
            }
        }

        regions.sort_by_key(|region| region.start.0);
        Ok(regions)
    }

    fn read_vad_root(&self, dtb: Dtb, vad_root_base: VirtAddr) -> Result<VirtAddr> {
        let memory = self.address_space(dtb);
        let types = self.guest()?.ntoskrnl.types_in(dtb);

        if let Ok(tree_layout) = types.layout("_RTL_AVL_TREE")
            && let Ok(root_offset) = tree_layout.field_offset("Root")
        {
            let root: VirtAddr = memory.read(vad_root_base + root_offset)?;
            return Ok(Self::canonical_vad_link(root));
        }

        let root: VirtAddr = memory.read(vad_root_base)?;
        Ok(Self::canonical_vad_link(root))
    }

    fn canonical_vad_link(link: VirtAddr) -> VirtAddr {
        VirtAddr(link.0 & !0xf)
    }

    fn read_integer_field(
        memory: &impl MemoryOps<VirtAddr>,
        layout: &TypeInfo,
        base: VirtAddr,
        field: &str,
    ) -> Option<u64> {
        let info = layout.fields.get(field)?;
        let address = base + info.offset as u64;
        match info.size {
            1 => memory.read::<u8>(address).ok().map(u64::from),
            2 => memory.read::<u16>(address).ok().map(u64::from),
            4 => memory.read::<u32>(address).ok().map(u64::from),
            8 => memory.read::<u64>(address).ok(),
            _ => None,
        }
    }

    fn bitfield_value(layout: &TypeInfo, field: &str, raw: u64) -> Option<u64> {
        let info = layout.fields.get(field)?;
        let ParsedType::Bitfield { pos, len, .. } = info.type_data else {
            return None;
        };
        let mask = if len >= 64 {
            u64::MAX
        } else {
            (1u64 << len) - 1
        };
        Some((raw >> pos) & mask)
    }

    fn vad_flags_base_offset(vad_layout: &TypeInfo) -> Option<u64> {
        vad_layout
            .field_offset("u")
            .or_else(|_| vad_layout.field_offset("u1"))
            .or_else(|_| vad_layout.field_offset("VadFlags"))
            .ok()
    }

    fn read_vad_region(
        &self,
        memory: &impl MemoryOps<VirtAddr>,
        vad_layout: &TypeInfo,
        flags_layout: Option<&TypeInfo>,
        vad: VirtAddr,
        modules: &[ModuleInfo],
    ) -> Option<MemoryRegionInfo> {
        let start_low = Self::read_integer_field(memory, vad_layout, vad, "StartingVpn")?;
        let end_low = Self::read_integer_field(memory, vad_layout, vad, "EndingVpn")?;
        let start_high =
            Self::read_integer_field(memory, vad_layout, vad, "StartingVpnHigh").unwrap_or(0);
        let end_high =
            Self::read_integer_field(memory, vad_layout, vad, "EndingVpnHigh").unwrap_or(0);
        let start_vpn = start_low | (start_high << 32);
        let end_vpn = end_low | (end_high << 32);
        let start = VirtAddr(start_vpn.checked_shl(12)?);
        let end = VirtAddr(end_vpn.checked_add(1)?.checked_shl(12)?);

        let flags = Self::vad_flags_base_offset(vad_layout)
            .and_then(|offset| memory.read::<u32>(vad + offset).ok())
            .map(u64::from);
        let protection = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "Protection", raw));
        let vad_type = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "VadType", raw));
        let private_memory = flags.zip(flags_layout).and_then(|(raw, layout)| {
            Self::bitfield_value(layout, "PrivateMemory", raw).map(|v| v != 0)
        });
        let commit_charge = flags
            .zip(flags_layout)
            .and_then(|(raw, layout)| Self::bitfield_value(layout, "CommitCharge", raw));
        let details = modules
            .iter()
            .find(|module| {
                module.base_address.0 >= start.0 && module.base_address.0 < end.0
                    || start.0 >= module.base_address.0 && start.0 < module.end_address().0
            })
            .map(|module| module.name.clone());

        Some(MemoryRegionInfo {
            start,
            end,
            protection,
            vad_type,
            private_memory,
            commit_charge,
            details,
        })
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

    pub fn pte_traverse(&self, address: VirtAddr) -> Result<PteWalk> {
        // Walk through the current inspection address space so user VAs resolve
        // through the attached process's tables (not the kernel's). MmPteBase is
        // a kernel VA valid in any process context (the recursive PML4 slot).
        let memory = self.current_process()?.memory();
        let dtb = self.current_dtb();

        let pte_base: VirtAddr = self.guest()?.ntoskrnl.symbol("MmPteBase")?.read()?;
        let pde_base = pte_base + (pte_base.0 >> 9 & 0x7FFFFFFFFF);
        let ppe_base = pde_base + (pde_base.0 >> 9 & 0x3FFFFFFF);
        let pxe_base = ppe_base + (ppe_base.0 >> 9 & 0x1FFFFF);

        let pxe_address = VirtAddr(pxe_base.0 + (((address.0 >> 39) & 0x1FF) << 3));
        let ppe_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 30) << 3) + ppe_base.0);

        let pxe_value: PageTableEntry = memory.read(pxe_address)?;
        let ppe_value: PageTableEntry = memory.read(ppe_address)?;

        let pxe = PteLevel {
            name: "PXE".into(),
            address: pxe_address,
            value: pxe_value,
        };
        let ppe = PteLevel {
            name: "PPE".into(),
            address: ppe_address,
            value: ppe_value,
        };

        if ppe_value.is_large_page() {
            return Ok(PteWalk {
                address,
                dtb,
                pxe,
                ppe,
                pde: None,
                pte: None,
            });
        }

        let pde_address = VirtAddr((((address.0 & 0xFFFFFFFFFFFF) >> 21) << 3) + pde_base.0);
        let pde_value: PageTableEntry = memory.read(pde_address)?;
        let pde = PteLevel {
            name: "PDE".into(),
            address: pde_address,
            value: pde_value,
        };

        if pde_value.is_large_page() {
            return Ok(PteWalk {
                address,
                dtb,
                pxe,
                ppe,
                pde: Some(pde),
                pte: None,
            });
        }

        let pte_address = VirtAddr(((address.0 & 0xFFFFFFFFFFFF) >> 12) << 3) + pte_base.0;
        let pte_value: PageTableEntry = memory.read(pte_address)?;
        let pte = PteLevel {
            name: "PTE".into(),
            address: pte_address,
            value: pte_value,
        };

        Ok(PteWalk {
            address,
            dtb,
            pxe,
            ppe,
            pde: Some(pde),
            pte: Some(pte),
        })
    }
}

impl fmt::Display for PteLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = format!("pfn {:<5x} {:>11}", self.value.pfn(), self.value.flags());
        write!(
            f,
            "{} at {:X}\ncontains {:016X}\n{}",
            self.name,
            self.address,
            Value(self.value.0),
            flags
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ListTermination, ObjectNameLayout, ThreadInfo, bounded_list_walk,
        decode_token_privilege_bitmaps, select_object_header_candidate, select_thread_process_dtb,
        thread_owner_matches,
    };
    use crate::guest::ProcessInfo;
    use crate::types::VirtAddr;

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
    fn thread_pseudo_registers_cover_common_windbg_names() {
        let thread = sample_thread();
        assert_eq!(
            thread.pseudo_register_value("thread"),
            Some(thread.ethread.0)
        );
        assert_eq!(
            thread.pseudo_register_value("ethread"),
            Some(thread.ethread.0)
        );
        assert_eq!(
            thread.pseudo_register_value("kthread"),
            Some(thread.kthread.0)
        );
        assert_eq!(thread.pseudo_register_value("tid"), thread.tid);
        assert_eq!(thread.pseudo_register_value("pid"), thread.pid);
        assert_eq!(
            thread.pseudo_register_value("proc"),
            thread.eprocess.map(|addr| addr.0)
        );
        assert_eq!(
            thread.pseudo_register_value("process"),
            thread.eprocess.map(|addr| addr.0)
        );
        assert_eq!(
            thread.pseudo_register_value("teb"),
            thread.teb.map(|addr| addr.0)
        );
        assert_eq!(
            thread.pseudo_register_value("priority"),
            thread.priority.map(u64::from)
        );
        assert_eq!(
            thread.pseudo_register_value("basepriority"),
            thread.base_priority.map(u64::from)
        );
        assert_eq!(
            thread.pseudo_register_value("waitirql"),
            thread.wait_irql.map(u64::from)
        );
        assert_eq!(thread.pseudo_register_value("stackresident"), Some(1));
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
    fn cr3_normalization_strips_pcid_and_reserved_bits() {
        assert_eq!(
            super::Target::normalize_cr3(0xffff_8123_4567_8abc),
            0x000f_8123_4567_8000
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
        };
        let owner = ProcessInfo {
            pid: 0x99,
            name: "sample.exe".into(),
            dtb: 0x2222_0000,
            eprocess_va: thread.eprocess.unwrap(),
        };
        assert!(!thread_owner_matches(&thread, &same_pid_wrong_process));
        assert!(thread_owner_matches(&thread, &owner));
        assert_eq!(owner.dtb, 0x2222_0000);
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
            _ => Err(crate::error::Error::DebugInfo("synthetic bad flink".into())),
        });
        assert_eq!(links, vec![VirtAddr(1), VirtAddr(2)]);
        assert_eq!(
            termination,
            ListTermination::Corrupt("synthetic bad flink".into())
        );
    }
    #[test]
    fn token_privilege_bitmaps_preserve_ids_and_attributes() {
        let privileges =
            decode_token_privilege_bitmaps((1 << 2) | (1 << 20), 1 << 20, (1 << 2) | (1 << 20));
        assert_eq!(
            privileges,
            vec![
                super::PrivilegeInfo {
                    luid: 2,
                    attributes: super::SE_PRIVILEGE_ENABLED_BY_DEFAULT,
                },
                super::PrivilegeInfo {
                    luid: 20,
                    attributes: super::SE_PRIVILEGE_ENABLED_BY_DEFAULT
                        | super::SE_PRIVILEGE_ENABLED,
                },
            ]
        );
    }
    #[test]
    fn direct_object_header_wins_when_only_it_has_a_valid_type() {
        let input = VirtAddr(0x1000);
        assert_eq!(
            select_object_header_candidate(
                input,
                0x30,
                Some(VirtAddr(0x0fd0)),
                Some(input),
                false,
                true,
            ),
            Some((input, VirtAddr(0x1030), "header"))
        );
    }

    #[test]
    fn ambiguous_readable_object_headers_are_rejected() {
        assert_eq!(
            select_object_header_candidate(
                VirtAddr(0x1000),
                0x30,
                Some(VirtAddr(0x0fd0)),
                Some(VirtAddr(0x1000)),
                false,
                false,
            ),
            None
        );
    }

    #[test]
    fn object_name_info_address_accounts_for_creator_info_only() {
        let layout = ObjectNameLayout {
            body_offset: 0x30,
            info_mask_offset: 0x1a,
            creator_info_size: Some(0x20),
            name_info_size: 0x20,
            name_offset: 0x08,
        };
        let header = VirtAddr(0x1000);

        assert_eq!(layout.name_info_address(header, 0x00).unwrap(), None);
        assert_eq!(
            layout.name_info_address(header, 0x02).unwrap(),
            Some(VirtAddr(0x0fe0))
        );
        assert_eq!(
            layout.name_info_address(header, 0x03).unwrap(),
            Some(VirtAddr(0x0fc0))
        );
        assert_eq!(
            layout.name_info_address(header, 0x7e).unwrap(),
            Some(VirtAddr(0x0fe0))
        );
    }

    #[test]
    fn object_name_info_address_requires_present_creator_layout() {
        let layout = ObjectNameLayout {
            body_offset: 0x30,
            info_mask_offset: 0x1a,
            creator_info_size: None,
            name_info_size: 0x20,
            name_offset: 0x08,
        };

        let error = layout
            .name_info_address(VirtAddr(0x1000), 0x03)
            .unwrap_err();
        assert!(matches!(
            &error,
            crate::error::Error::StructNotFound(name)
                if name == "_OBJECT_HEADER_CREATOR_INFO"
        ));
    }
}
