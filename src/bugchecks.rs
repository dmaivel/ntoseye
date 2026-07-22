// Derived from Microsoft Learn Windows driver debugger docs.
// Source: https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-code-reference2
// Audited against all 379 linked code pages on 2026-07-16.

use crate::backend::MemoryOps;
use crate::dbg_backend::BugcheckInfo;
use crate::error::Result;
use crate::target::Target;
use crate::trapframe::{KtrapFrame, read_ktrap_frame};
use crate::types::VirtAddr;
use crate::unwind::{ThreadTraceContext, format_symbol, resolve_thread_trace_context};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BugcheckDescriptor {
    pub name: &'static str,
    pub description: Option<&'static str>,
    /// Code-only fallback meanings. Use [`bugcheck_argument_descriptions`] for
    /// a concrete stop because some parameter schemas depend on parameter 1.
    pub arguments: [&'static str; 4],
}

pub const GENERIC_BUGCHECK_ARGS: [&str; 4] = ["", "", "", ""];

/// Number of u64 slots in `nt!KiBugCheckData` (BugCheckCode + 4 parameters).
pub const BUGCHECK_DATA_SLOTS: usize = 5;

/// A bugcheck argument paired with its documented meaning (empty when the code
/// has no documented arguments).
#[derive(Clone, Debug)]
pub struct BugcheckArg {
    pub value: u64,
    pub description: String,
}

/// The faulting instruction a bugcheck points at, when its parameters carry one.
#[derive(Clone, Debug)]
pub struct BugcheckFault {
    pub ip: u64,
    pub symbol: String,
    pub driver: Option<String>,
}

/// A trap-frame address carried by a bugcheck parameter, with either the
/// decoded `_KTRAP_FRAME` or the reason decoding failed.
#[derive(Clone, Debug)]
pub struct BugcheckTrapFrame {
    pub address: u64,
    pub frame: Option<KtrapFrame>,
    /// Symbol for the frame's `Rip`, when the frame decoded.
    pub rip_symbol: Option<String>,
    /// Decode failure reason; `None` exactly when `frame` is present.
    pub error: Option<String>,
}

/// A decoded, presentation-free bugcheck: the code resolved to a name and
/// per-argument descriptions, the responsible driver (from the KD stream or the
/// fault site), and the fault instruction when derivable. Hosts (REPL/SDK/MCP)
/// render or serialize this; one source of truth for bugcheck analysis.
#[derive(Clone, Debug)]
pub struct BugcheckAnalysis {
    pub code: u32,
    pub name: String,
    pub description: Option<String>,
    pub driver: Option<String>,
    pub args: Vec<BugcheckArg>,
    pub fault: Option<BugcheckFault>,
    /// Trap frames named by the bugcheck parameters, decoded from the guest.
    pub trap_frames: Vec<BugcheckTrapFrame>,
    /// Where the data came from (e.g. an indirection through `nt!KiBugCheckData`).
    pub source: Option<String>,
}

/// Detailed result of resolving the frozen guest's `nt!KiBugCheckData`.
/// Public hosts use [`current_bugcheck`]'s compact `Option`; the REPL also
/// consumes failures so a bugcheck stop can explain missing or malformed data.
pub enum CurrentBugcheckResolution {
    Resolved(BugcheckAnalysis),
    SymbolUnavailable,
    Unresolved(CurrentBugcheckFailure),
}

pub struct CurrentBugcheckFailure {
    pub address: VirtAddr,
    pub slots: Option<[u64; BUGCHECK_DATA_SLOTS]>,
    pub dereferenced_slots: Option<[u64; BUGCHECK_DATA_SLOTS]>,
    pub reason: String,
}

pub fn plausible_bugcheck_code(code: u64) -> bool {
    code != 0 && code <= u32::MAX as u64
}

pub fn looks_like_kernel_pointer(value: u64) -> bool {
    value >= 0xffff_8000_0000_0000
}

/// How close to the current kernel base a stop PC must be to be treated as the
/// *same* kernel image (rather than a reboot into a relocated one). Shared by
/// the reload heuristic ([`crate::session::stop_event_requires_target_reload`])
/// and the REPL's pending-reload rebasing.
pub const CURRENT_KERNEL_RELOAD_WINDOW: u64 = 0x1000_0000;

pub fn read_bugcheck_data<M: MemoryOps<VirtAddr>>(
    mem: &M,
    addr: VirtAddr,
) -> Result<[u64; BUGCHECK_DATA_SLOTS]> {
    let mut data = [0u64; BUGCHECK_DATA_SLOTS];
    for (i, slot) in data.iter_mut().enumerate() {
        *slot = mem.read::<u64>(addr + (i * 8) as u64)?;
    }
    Ok(data)
}

pub fn module_filename(name: &str) -> String {
    name.rsplit(['\\', '/']).next().unwrap_or(name).to_string()
}

pub fn driver_filename_for_address(
    debugger: &Target,
    trace: &ThreadTraceContext,
    address: u64,
) -> Option<String> {
    trace
        .kernel_modules
        .iter()
        .chain(trace.process_modules.iter())
        .find(|module| module.contains_address(VirtAddr(address)))
        .map(|module| module_filename(&module.name))
        .filter(|name| name.to_ascii_lowercase().ends_with(".sys"))
        .or_else(|| {
            debugger
                .symbols
                .find_module_for_address(trace.kernel_dtb, VirtAddr(address))
                .map(|module| module_filename(&module.name))
                .filter(|name| name.to_ascii_lowercase().ends_with(".sys"))
        })
}

pub fn bugcheck_fault_ip(info: &BugcheckInfo) -> Option<u64> {
    let ip = match info.code {
        // The instruction address is parameter 1.
        0x0000_0151 => info.parameters[0],
        // The instruction address is parameter 2.
        0x0000_001e | 0x0000_003b | 0x0000_007e | 0x0000_008e | 0x1000_007e | 0x1000_008e => {
            info.parameters[1]
        }
        // The instruction address is parameter 3, when known.
        0x0000_0050 | 0x0000_00cc | 0x0000_00cd | 0x0000_00ce | 0x0000_00cf | 0x0000_00d5
        | 0x0000_00d6 => info.parameters[2],
        // The instruction address is parameter 4.
        0x0000_000a | 0x0000_002e | 0x0000_00c5 | 0x0000_00d0 | 0x0000_00d1 | 0x0000_00d3
        | 0x0000_00d4 | 0x0000_01ea => info.parameters[3],
        // Other bugchecks may carry addresses, but not necessarily a faulting
        // instruction. For example, 0x4a arg1 is the system-call routine and
        // often resolves to an ntdll syscall stub, not the responsible driver.
        _ => 0,
    };
    (ip != 0).then_some(ip)
}

/// The trap-frame address a bugcheck's parameters carry, per the documented
/// parameter meanings (mirrors the descriptor text in [`bugcheck_descriptor`]).
/// Filtered to kernel pointers so a zeroed/garbage parameter is never chased.
pub fn bugcheck_trap_frame_address(info: &BugcheckInfo) -> Option<u64> {
    let addr = match info.code {
        // PANIC_STACK_SWITCH: parameter 1 is the trap frame.
        0x0000_002b => info.parameters[0],
        // SET_OF_INVALID_CONTEXT: parameter 3 is the trap frame address.
        0x0000_0030 => info.parameters[2],
        // KERNEL_MODE_EXCEPTION_NOT_HANDLED and its minidump alias:
        // parameter 3 is the trap frame.
        0x0000_008e | 0x1000_008e => info.parameters[2],
        // KERNEL_SECURITY_CHECK_FAILURE: parameter 2 is the trap frame address.
        0x0000_0139 => info.parameters[1],
        // UNSUPPORTED_INSTRUCTION_MODE: parameter 2 is the trap frame.
        0x0000_0151 => info.parameters[1],
        _ => return None,
    };
    looks_like_kernel_pointer(addr).then_some(addr)
}

/// Resolve parameter meanings that vary by bugcheck parameter values.
///
/// [`BugcheckDescriptor::arguments`] stays a code-only, conservative fallback;
/// this function provides the precise schema used for a concrete stop.
pub fn bugcheck_argument_descriptions(info: &BugcheckInfo) -> [&'static str; 4] {
    match info.code {
        0x0000_0077 if matches!(info.parameters[0], 0..=2) => [
            "page retrieval result: 0 = page cache; 1 = disk; 2 = disk success with a short transfer",
            "value where the kernel-stack signature should be",
            "zero",
            "address of the kernel-stack signature",
        ],
        0x0000_0077 => [
            "status code",
            "I/O status code",
            "page-file number",
            "offset into the page file",
        ],
        0x0000_007a if matches!(info.parameters[0], 1..=3) && info.parameters[2] == 0 => [
            "lock type held (1, 2, or 3)",
            "error status, usually an I/O status code",
            "current process when parameter 1 is 1; zero when it is 2 or 3",
            "virtual address that could not be paged into memory",
        ],
        0x0000_007a if matches!(info.parameters[0], 3..=4) && info.parameters[2] != 0 => [
            "lock type held (3 or 4)",
            "error status, typically an I/O status code",
            "address of the InPageSupport structure",
            "faulting memory address",
        ],
        0x0000_007a => [
            "address of the page-table entry (PTE)",
            "error status, usually an I/O status code",
            "PTE contents",
            "faulting memory address",
        ],
        0x0000_009f => match info.parameters[0] {
            0x1 => [
                "violation type: device freed with an outstanding power request",
                "device object",
                "reserved",
                "reserved",
            ],
            0x2 => [
                "violation type: power IRP completed without PoStartNextPowerIrp",
                "target device object, if available",
                "device object",
                "driver object, if available",
            ],
            0x3 => [
                "violation type: a device blocked a power IRP for too long",
                "physical device object (PDO) of the stack",
                "nt!_TRIAGE_9F_POWER",
                "blocked IRP",
            ],
            0x4 => [
                "violation type: power transition timed out waiting for PnP synchronization",
                "timeout in seconds",
                "thread holding the Plug-and-Play lock",
                "nt!_TRIAGE_9F_PNP",
            ],
            0x5 => [
                "violation type: directed power transition timed out",
                "physical device object (PDO) of the stack",
                "POP_FX_DEVICE object",
                "reserved (zero)",
            ],
            0x6 => [
                "violation type: directed power transition callback failed",
                "POP_FX_DEVICE object",
                "directed power down (1) or power up (0)",
                "reserved (zero)",
            ],
            0x500 => [
                "violation type: power IRP completed without PoStartNextPowerIrp",
                "reserved",
                "target device object, if available",
                "device object",
            ],
            _ => [
                "power-state violation type",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        },
        0x0000_012b if info.parameters[2] == 0 && info.parameters[3] == 0 => [
            "virtual address mapped to the corrupted page",
            "physical page number",
            "zero",
            "zero",
        ],
        0x0000_012b => [
            "compressed-store failure status",
            "compressed size of the page being read",
            "source buffer",
            "target buffer",
        ],
        0x0000_0131 => match info.parameters[0] {
            0 => [
                "failure type: invalid feature mask or extended processor state is disabled",
                "nonzero if extended state is enabled",
                "low 32 bits of the feature mask",
                "high 32 bits of the feature mask",
            ],
            1 => [
                "failure type: save or restore attempted above DISPATCH_LEVEL",
                "IRQL",
                "reserved",
                "reserved",
            ],
            2 => [
                "failure type: saved state is for an equal or higher level",
                "saved level",
                "current level",
                "reserved",
            ],
            3 => [
                "failure type: saved state is for a different thread",
                "saved thread",
                "current thread",
                "reserved",
            ],
            4 => [
                "failure type: saved state is for a different level",
                "saved level",
                "current level",
                "reserved",
            ],
            _ => [
                "extended-processor-state failure type",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        },
        0x0000_0133 if info.parameters[0] == 0 => [
            "violation type: a single DPC or ISR exceeded its time allotment",
            "DPC time count in ticks",
            "DPC time allotment in ticks",
            "nt!DPC_WATCHDOG_GLOBAL_TRIAGE_BLOCK",
        ],
        0x0000_0133 if info.parameters[0] == 1 => [
            "violation type: cumulative time at DISPATCH_LEVEL or above was excessive",
            "watchdog period",
            "nt!DPC_WATCHDOG_GLOBAL_TRIAGE_BLOCK",
            "reserved",
        ],
        0x0000_0143 if info.parameters[0] == 1 => [
            "failure type: PEP rejected a required notification",
            "PEP runtime notification type",
            "notification message",
            "processor device context issuing the notification",
        ],
        0x0000_0143 if info.parameters[0] == 2 => [
            "failure type: PEP returned an invalid processor idle state",
            "invalid-state subtype",
            "meaning depends on parameter 2",
            "meaning depends on parameter 2",
        ],
        0x0000_0159 if info.parameters[0] & 0xf000 == 0x3000 => [
            "IOMMU vendor disambiguation (0x3xxx)",
            "status",
            "PASID",
            "directory base",
        ],
        0x0000_0159 => [
            "IOMMU vendor disambiguation",
            "fault packet",
            "vendor-specific fault-packet data",
            "vendor-specific fault-packet data",
        ],
        _ => bugcheck_descriptor(info.code)
            .map(|descriptor| descriptor.arguments)
            .unwrap_or(GENERIC_BUGCHECK_ARGS),
    }
}

pub fn bugcheck_site(
    debugger: &Target,
    trace: &ThreadTraceContext,
    info: &BugcheckInfo,
) -> Option<(u64, String, Option<String>)> {
    let ip = bugcheck_fault_ip(info)?;
    let symbol = format_symbol(debugger, trace, ip);
    let driver = driver_filename_for_address(debugger, trace, ip);
    Some((ip, symbol, driver))
}

/// Decode a known [`BugcheckInfo`] into a structured [`BugcheckAnalysis`].
pub fn analyze_bugcheck(debugger: &Target, info: &BugcheckInfo) -> BugcheckAnalysis {
    let trace = resolve_thread_trace_context(debugger, debugger.kernel_dtb());
    let site = bugcheck_site(debugger, &trace, info);
    let descriptor = bugcheck_descriptor(info.code);
    let name = descriptor
        .map(|d| d.name)
        .unwrap_or("UNKNOWN_BUGCHECK")
        .to_string();
    let description = descriptor.and_then(|d| d.description).map(str::to_string);
    let arg_descriptions = bugcheck_argument_descriptions(info);
    let driver = info
        .driver
        .clone()
        .or_else(|| site.as_ref().and_then(|(_, _, driver)| driver.clone()));
    let args = info
        .parameters
        .iter()
        .zip(arg_descriptions)
        .map(|(value, description)| BugcheckArg {
            value: *value,
            description: description.to_string(),
        })
        .collect();
    let fault = site.map(|(ip, symbol, driver)| BugcheckFault { ip, symbol, driver });
    let trap_frames = bugcheck_trap_frame_address(info)
        .map(|address| {
            let (frame, error) = match read_ktrap_frame(debugger, VirtAddr(address)) {
                Ok(frame) => (Some(frame), None),
                Err(error) => (None, Some(error.to_string())),
            };
            let rip_symbol = frame
                .as_ref()
                .map(|frame| format_symbol(debugger, &trace, frame.rip));
            BugcheckTrapFrame {
                address,
                frame,
                rip_symbol,
                error,
            }
        })
        .into_iter()
        .collect();

    BugcheckAnalysis {
        code: info.code,
        name,
        description,
        driver,
        args,
        fault,
        trap_frames,
        source: None,
    }
}

/// Read and resolve `nt!KiBugCheckData` from the frozen guest, following one
/// level of pointer indirection (some builds store the data behind a pointer in
/// the first slot). Unlike [`current_bugcheck`], this preserves diagnostics for
/// the REPL's bugcheck-stop banner.
pub fn resolve_current_bugcheck(debugger: &Target) -> CurrentBugcheckResolution {
    let Some(guest) = debugger.guest.as_ref() else {
        return CurrentBugcheckResolution::SymbolUnavailable;
    };
    let kernel_dtb = guest.ntoskrnl.dtb();
    let Some(address) = debugger
        .symbols
        .find_symbol_across_modules(kernel_dtb, "KiBugCheckData")
    else {
        return CurrentBugcheckResolution::SymbolUnavailable;
    };
    let mem = guest.ntoskrnl.memory();
    let direct = match read_bugcheck_data(&mem, address) {
        Ok(data) => data,
        Err(error) => {
            return CurrentBugcheckResolution::Unresolved(CurrentBugcheckFailure {
                address,
                slots: None,
                dereferenced_slots: None,
                reason: format!("failed to read nt!KiBugCheckData: {error}"),
            });
        }
    };

    let (data, source) = if plausible_bugcheck_code(direct[0]) {
        (direct, None)
    } else if looks_like_kernel_pointer(direct[0]) {
        let indirect_address = VirtAddr(direct[0]);
        match read_bugcheck_data(&mem, indirect_address) {
            Ok(indirect) if plausible_bugcheck_code(indirect[0]) => (
                indirect,
                Some(format!("nt!KiBugCheckData -> {indirect_address:#x}")),
            ),
            Ok(indirect) => {
                return CurrentBugcheckResolution::Unresolved(CurrentBugcheckFailure {
                    address,
                    slots: Some(direct),
                    dereferenced_slots: Some(indirect),
                    reason: format!(
                        "first slot looks like a pointer to {indirect_address:#x}, but dereferenced first slot {:#x} is not a plausible bugcheck code",
                        indirect[0]
                    ),
                });
            }
            Err(error) => {
                return CurrentBugcheckResolution::Unresolved(CurrentBugcheckFailure {
                    address,
                    slots: Some(direct),
                    dereferenced_slots: None,
                    reason: format!(
                        "first slot looks like a pointer to {indirect_address:#x}, but reading that address failed: {error}"
                    ),
                });
            }
        }
    } else {
        return CurrentBugcheckResolution::Unresolved(CurrentBugcheckFailure {
            address,
            slots: Some(direct),
            dereferenced_slots: None,
            reason: format!(
                "first slot {:#x} is not a plausible bugcheck code",
                direct[0]
            ),
        });
    };

    let info = BugcheckInfo {
        code: data[0] as u32,
        parameters: [data[1], data[2], data[3], data[4]],
        driver: None,
    };
    let mut analysis = analyze_bugcheck(debugger, &info);
    analysis.source = source;
    CurrentBugcheckResolution::Resolved(analysis)
}

/// Read `nt!KiBugCheckData` from the frozen guest and decode it. Returns `None`
/// when no plausible bugcheck code is present or the symbol/memory is
/// unavailable.
pub fn current_bugcheck(debugger: &Target) -> Option<BugcheckAnalysis> {
    match resolve_current_bugcheck(debugger) {
        CurrentBugcheckResolution::Resolved(analysis) => Some(analysis),
        CurrentBugcheckResolution::SymbolUnavailable | CurrentBugcheckResolution::Unresolved(_) => {
            None
        }
    }
}

/// Build a [`BugcheckAnalysis`] from the dump header's bugcheck fields when
/// the live-memory path (`current_bugcheck`) is unavailable (e.g. triage dumps
/// that don't include the `KiBugCheckData` memory region).
pub fn bugcheck_from_dump_info(debugger: &Target) -> Option<BugcheckAnalysis> {
    let dmp = debugger.phys.dmp_info()?;
    if !plausible_bugcheck_code(dmp.bug_check_code as u64) {
        return None;
    }
    let info = BugcheckInfo {
        code: dmp.bug_check_code,
        parameters: dmp.bug_check_parameters,
        driver: None,
    };
    let mut analysis = analyze_bugcheck(debugger, &info);
    analysis.source = Some("dump header".into());
    Some(analysis)
}

pub fn bugcheck_descriptor(code: u32) -> Option<BugcheckDescriptor> {
    match code {
        0x00000001 => Some(BugcheckDescriptor {
            name: "APC_INDEX_MISMATCH",
            description: Some(
                "The bug check indicates a mismatch in the asynchronous procedure calls (APC) state index.",
            ),
            arguments: [
                "the address of the system function (system call) or worker routine",
                "the value of the current thread's ApcStateIndex field",
                "the value of current thread's CombinedApcDisable field (SpecialApcDisable and KernelApcDisable)",
                "call type: 0 = system call, 1 = worker routine",
            ],
        }),
        0x00000002 => Some(BugcheckDescriptor {
            name: "DEVICE_QUEUE_NOT_BUSY",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000003 => Some(BugcheckDescriptor {
            name: "INVALID_AFFINITY_SET",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000004 => Some(BugcheckDescriptor {
            name: "INVALID_DATA_ACCESS_TRAP",
            description: Some("It indicates an incorrect data access trap."),
            arguments: ["", "", "", ""],
        }),
        0x00000005 => Some(BugcheckDescriptor {
            name: "INVALID_PROCESS_ATTACH_ATTEMPT",
            description: Some(
                "This generally indicates that the thread was attached to a process in a situation where that is not allowed. For example, this bug check could occur if KeAttachProcess was called when the thread was already attached to a process (which is illegal), or if the thread returned from certain function calls in an attached state (which is invalid),",
            ),
            arguments: [
                "the pointer to the dispatcher object for the target process, or if the thread is already attached, the pointer to the object for the original process",
                "the pointer to the dispatcher object of the process that the current thread is currently attached to",
                "the value of the thread's APC state index",
                "a non-zero value indicates that a DPC is running on the current processor",
            ],
        }),
        0x00000006 => Some(BugcheckDescriptor {
            name: "INVALID_PROCESS_DETACH_ATTEMPT",
            description: Some(
                "This can occur when KeStackAttachProcess is followed by KeUnstackDetachProcess from a load-image notification callback.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000007 => Some(BugcheckDescriptor {
            name: "INVALID_SOFTWARE_INTERRUPT",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000008 => Some(BugcheckDescriptor {
            name: "IRQL_NOT_DISPATCH_LEVEL",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000009 => Some(BugcheckDescriptor {
            name: "IRQL_NOT_GREATER_OR_EQUAL",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000000a => Some(BugcheckDescriptor {
            name: "IRQL_NOT_LESS_OR_EQUAL",
            description: Some(
                "This bug check indicates that Microsoft Windows or a kernel-mode driver accessed paged memory at an invalid address while at a raised interrupt request level (IRQL). The cause is typically a bad pointer or a pageability problem.",
            ),
            arguments: [
                "virtual memory address that could not be accessed",
                "IRQL at time of the fault",
                "operation: bit 0 clear = read, bit 0 set = write, bit 3 set = execute",
                "instruction pointer at time of the fault",
            ],
        }),
        0x0000000b => Some(BugcheckDescriptor {
            name: "NO_EXCEPTION_HANDLING_SUPPORT",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000000c => Some(BugcheckDescriptor {
            name: "MAXIMUM_WAIT_OBJECTS_EXCEEDED",
            description: Some(
                "This indicates that the current thread exceeded the permitted number of wait objects.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000000d => Some(BugcheckDescriptor {
            name: "MUTEX_LEVEL_NUMBER_VIOLATION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000000e => Some(BugcheckDescriptor {
            name: "NO_USER_MODE_CONTEXT",
            description: Some(
                "If control returns from the initial procedure while starting a system thread, this bug check occurs.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000000f => Some(BugcheckDescriptor {
            name: "SPIN_LOCK_ALREADY_OWNED",
            description: Some(
                "This indicates that a request for a spin lock has been initiated when the spin lock was already owned.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000010 => Some(BugcheckDescriptor {
            name: "SPIN_LOCK_NOT_OWNED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000011 => Some(BugcheckDescriptor {
            name: "THREAD_NOT_MUTEX_OWNER",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000012 => Some(BugcheckDescriptor {
            name: "TRAP_CAUSE_UNKNOWN",
            description: Some("This indicates that an unknown exception has occurred."),
            arguments: [
                "type of TRAP_CAUSE_UNKNOWN VALUES 1 - Unexpected interrupt. (Parameter 2 - Interrupt Vector) 2 - Unknown floating point exception. 3 - The enabled and asserted status bits (see processor definition)",
                "dependent on Arg1",
                "reserved",
                "reserved",
            ],
        }),
        0x00000013 => Some(BugcheckDescriptor {
            name: "EMPTY_THREAD_REAPER_LIST",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000014 => Some(BugcheckDescriptor {
            name: "CREATE_DELETE_LOCK_NOT_LOCKED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000015 => Some(BugcheckDescriptor {
            name: "LAST_CHANCE_CALLED_FROM_KMODE",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000016 => Some(BugcheckDescriptor {
            name: "CID_HANDLE_CREATION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000017 => Some(BugcheckDescriptor {
            name: "CID_HANDLE_DELETION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000018 => Some(BugcheckDescriptor {
            name: "REFERENCE_BY_POINTER",
            description: Some(
                "This indicates that the reference count of an object is illegal for the current state of the object.",
            ),
            arguments: [
                "object type of the object whose reference count is being lowered",
                "object whose reference count is being lowered",
                "reserved",
                "reserved",
            ],
        }),
        0x00000019 => Some(BugcheckDescriptor {
            name: "BAD_POOL_HEADER",
            description: Some("This indicates that a pool header is corrupt."),
            arguments: ["", "", "", ""],
        }),
        0x0000001a => Some(BugcheckDescriptor {
            name: "MEMORY_MANAGEMENT",
            description: Some(
                "The bug check indicates that a severe memory management error occurred.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000001b => Some(BugcheckDescriptor {
            name: "PFN_SHARE_COUNT",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000001c => Some(BugcheckDescriptor {
            name: "PFN_REFERENCE_COUNT",
            description: Some(
                "This indicates that a reference count error was detected. It can be caused by counter overflows, underflows, or an object that is used after it has been freed. Examine the stack to determine the fault. Note: This bug check code is used to report multiple types of reference count errors, not necessarily related to Memory Manager Page Frame Numbers (PFNs).",
            ),
            arguments: ["not used", "not used", "not used", "not used"],
        }),
        0x0000001d => Some(BugcheckDescriptor {
            name: "NO_SPIN_LOCK_AVAILABLE",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000001e => Some(BugcheckDescriptor {
            name: "KMODE_EXCEPTION_NOT_HANDLED",
            description: Some(
                "The bug check indicates that a kernel-mode program generated an exception that the error handler didn't catch.",
            ),
            arguments: [
                "the exception code that wasn't handled",
                "the address where the exception occurred",
                "exception information parameter 0 of the exception record",
                "exception information parameter 1 of the exception record",
            ],
        }),
        0x0000001f => Some(BugcheckDescriptor {
            name: "SHARED_RESOURCE_CONV_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000020 => Some(BugcheckDescriptor {
            name: "KERNEL_APC_PENDING_DURING_EXIT",
            description: Some(
                "This indicates that an asynchronous procedure call (APC) was still pending when a thread exited.",
            ),
            arguments: [
                "the address of the APC found pending during exit",
                "the thread's APC disable count",
                "the current IRQL",
                "reserved",
            ],
        }),
        0x00000021 => Some(BugcheckDescriptor {
            name: "QUOTA_UNDERFLOW",
            description: Some(
                "This indicates that quota charges have been mishandled by returning more quota to a particular block than was previously charged.",
            ),
            arguments: [
                "the process that was initially charged, if available",
                "the quota type. For the list of all possible quota type values, see the header file Ps.h in the Windows Driver Kit (WDK)",
                "the initial charged amount of quota to return",
                "the remaining amount of quota that was not returned",
            ],
        }),
        0x00000022 => Some(BugcheckDescriptor {
            name: "FILE_SYSTEM",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000023 => Some(BugcheckDescriptor {
            name: "FAT_FILE_SYSTEM",
            description: Some("This indicates that a problem occurred in the FAT file system."),
            arguments: [
                "specifies source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") identify the source file by its identifier number",
                "if FatExceptionFilter is on the stack, this parameter specifies the address of the exception record",
                "if FatExceptionFilter is on the stack, this parameter specifies the address of the context record",
                "reserved",
            ],
        }),
        0x00000024 => Some(BugcheckDescriptor {
            name: "NTFS_FILE_SYSTEM",
            description: Some(
                "This indicates a problem occurred in ntfs.sys, the driver file that allows the system to read and write to NTFS drives.",
            ),
            arguments: [
                "specifies source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") identify the source file by its identifier number",
                "if NtfsExceptionFilter is on the stack, this parameter specifies the address of the exception record",
                "if NtfsExceptionFilter is on the stack, this parameter specifies the address of the context record",
                "reserved",
            ],
        }),
        0x00000025 => Some(BugcheckDescriptor {
            name: "NPFS_FILE_SYSTEM",
            description: Some("This indicates that a problem occurred in the NPFS file system."),
            arguments: [
                "specifies source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") identify the source file by its identifier number",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x00000026 => Some(BugcheckDescriptor {
            name: "CDFS_FILE_SYSTEM",
            description: Some("This indicates that a problem occurred in the CD file system."),
            arguments: [
                "specifies source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") identify the source file by its identifier number",
                "if CdExceptionFilter is on the stack, this parameter specifies the address of the exception record",
                "if CdExceptionFilter is on the stack, this parameter specifies the address of the context record",
                "reserved",
            ],
        }),
        0x00000027 => Some(BugcheckDescriptor {
            name: "RDR_FILE_SYSTEM",
            description: Some(
                "This indicates that a problem occurred in the SMB redirector file system.",
            ),
            arguments: [
                "the high 16 bits (the first four hexadecimal digits after the \"0x\") identify the type of problem",
                "if RxExceptionFilter is on the stack, this parameter specifies the address of the exception record",
                "if RxExceptionFilter is on the stack, this parameter specifies the address of the context record",
                "reserved",
            ],
        }),
        0x00000028 => Some(BugcheckDescriptor {
            name: "CORRUPT_ACCESS_TOKEN",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000029 => Some(BugcheckDescriptor {
            name: "SECURITY_SYSTEM",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000002a => Some(BugcheckDescriptor {
            name: "INCONSISTENT_IRP",
            description: Some(
                "This indicates that an IRP was found to contain inconsistent information.",
            ),
            arguments: [
                "the address of the IRP that was found to be inconsistent",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x0000002b => Some(BugcheckDescriptor {
            name: "PANIC_STACK_SWITCH",
            description: Some("This indicates that the kernel mode stack was overrun."),
            arguments: ["the trap frame", "reserved", "reserved", "reserved"],
        }),
        0x0000002c => Some(BugcheckDescriptor {
            name: "PORT_DRIVER_INTERNAL",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000002d => Some(BugcheckDescriptor {
            name: "SCSI_DISK_DRIVER_INTERNAL",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000002e => Some(BugcheckDescriptor {
            name: "DATA_BUS_ERROR",
            description: Some(
                "This typically indicates that a parity error in system memory has been detected.",
            ),
            arguments: [
                "virtual address that caused the fault",
                "physical address that caused the fault",
                "processor status register (PSR)",
                "faulting instruction register (FIR)",
            ],
        }),
        0x0000002f => Some(BugcheckDescriptor {
            name: "INSTRUCTION_BUS_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000030 => Some(BugcheckDescriptor {
            name: "SET_OF_INVALID_CONTEXT",
            description: Some(
                "This indicates that the stack pointer in a trap frame had an invalid value.",
            ),
            arguments: [
                "the new stack pointer",
                "the old stack pointer",
                "the trap frame address",
                "0",
            ],
        }),
        0x00000031 => Some(BugcheckDescriptor {
            name: "PHASE0_INITIALIZATION_FAILED",
            description: Some("This indicates that system initialization failed."),
            arguments: ["", "", "", ""],
        }),
        0x00000032 => Some(BugcheckDescriptor {
            name: "PHASE1_INITIALIZATION_FAILED",
            description: Some("This indicates that system initialization failed."),
            arguments: [
                "the NT status code that describes why the system initialization failed",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x00000033 => Some(BugcheckDescriptor {
            name: "UNEXPECTED_INITIALIZATION_CALL",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000034 => Some(BugcheckDescriptor {
            name: "CACHE_MANAGER",
            description: Some(
                "This indicates that a problem occurred in the file system's cache manager.",
            ),
            arguments: [
                "specifies source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") identify the source file by its identifier number",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x00000035 => Some(BugcheckDescriptor {
            name: "NO_MORE_IRP_STACK_LOCATIONS",
            description: Some(
                "This bug check occurs when the IoCallDriver packet has no more stack locations remaining.",
            ),
            arguments: ["address of the IRP", "reserved", "reserved", "reserved"],
        }),
        0x00000036 => Some(BugcheckDescriptor {
            name: "DEVICE_REFERENCE_COUNT_NOT_ZERO",
            description: Some(
                "This indicates that a driver attempted to delete a device object that still had a positive reference count.",
            ),
            arguments: [
                "the address of the device object",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x00000037 => Some(BugcheckDescriptor {
            name: "FLOPPY_INTERNAL_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000038 => Some(BugcheckDescriptor {
            name: "SERIAL_DRIVER_INTERNAL",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000039 => Some(BugcheckDescriptor {
            name: "SYSTEM_EXIT_OWNED_MUTEX",
            description: Some(
                "This indicates that the worker routine returned without releasing the mutex object that it owned.",
            ),
            arguments: [
                "the address of the worker routine that caused the error",
                "the parameter passed to the worker routine",
                "the address of the work item",
                "reserved",
            ],
        }),
        0x0000003a => Some(BugcheckDescriptor {
            name: "SYSTEM_UNWIND_PREVIOUS_USER",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000003b => Some(BugcheckDescriptor {
            name: "SYSTEM_SERVICE_EXCEPTION",
            description: Some("An exception happened while executing a system service routine."),
            arguments: [
                "exception code that caused the bugcheck",
                "address of the instruction which caused the bugcheck",
                "address of the context record for the exception that caused the bugcheck",
                "zero",
            ],
        }),
        0x0000003c => Some(BugcheckDescriptor {
            name: "INTERRUPT_UNWIND_ATTEMPTED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000003d => Some(BugcheckDescriptor {
            name: "INTERRUPT_EXCEPTION_NOT_HANDLED",
            description: Some(
                "This indicates that the exception handler for the kernel interrupt object interrupt management was not able to handle the generated exception.",
            ),
            arguments: [
                "exception Record (When Available)",
                "context Record (When Available)",
                "0",
                "0",
            ],
        }),
        0x0000003e => Some(BugcheckDescriptor {
            name: "MULTIPROCESSOR_CONFIGURATION_NOT_SUPPORTED",
            description: Some(
                "This indicates that the system has multiple processors, but they are asymmetric in relation to one another.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000003f => Some(BugcheckDescriptor {
            name: "NO_MORE_SYSTEM_PTES",
            description: Some(
                "This is the result of a system which has performed too many I/O actions. This has resulted in fragmented system page table entries (PTE).",
            ),
            arguments: [
                "0: system expansion PTE type 1: nonpaged pool expansion PTE type",
                "size of memory request",
                "total free system PTEs",
                "total system PTEs",
            ],
        }),
        0x00000040 => Some(BugcheckDescriptor {
            name: "TARGET_MDL_TOO_SMALL",
            description: Some(
                "This indicates that a driver has improperly used IoBuildPartialMdl.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000041 => Some(BugcheckDescriptor {
            name: "MUST_SUCCEED_POOL_EMPTY",
            description: Some(
                "This indicates that a kernel-mode thread has requested too much must-succeed pool.",
            ),
            arguments: [
                "the size of the request that could not be satisfied",
                "the number of pages used from nonpaged pool",
                "the number of requests from nonpaged pool larger than PAGE_SIZE",
                "the number of pages available",
            ],
        }),
        0x00000042 => Some(BugcheckDescriptor {
            name: "ATDISK_DRIVER_INTERNAL",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000043 => Some(BugcheckDescriptor {
            name: "NO_SUCH_PARTITION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000044 => Some(BugcheckDescriptor {
            name: "MULTIPLE_IRP_COMPLETE_REQUESTS",
            description: Some(
                "This indicates that a driver has tried to request an IRP be completed that is already complete.",
            ),
            arguments: ["the address of the IRP", "reserved", "reserved", "reserved"],
        }),
        0x00000045 => Some(BugcheckDescriptor {
            name: "INSUFFICIENT_SYSTEM_MAP_REGS",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000046 => Some(BugcheckDescriptor {
            name: "DEREF_UNKNOWN_LOGON_SESSION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000047 => Some(BugcheckDescriptor {
            name: "REF_UNKNOWN_LOGON_SESSION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000048 => Some(BugcheckDescriptor {
            name: "CANCEL_STATE_IN_COMPLETED_IRP",
            description: Some(
                "This indicates that an I/O request packet (IRP) was completed, and then was subsequently canceled.",
            ),
            arguments: [
                "a pointer to the IRP",
                "the cancel routine set by the driver",
                "reserved",
                "reserved",
            ],
        }),
        0x00000049 => Some(BugcheckDescriptor {
            name: "PAGE_FAULT_WITH_INTERRUPTS_OFF",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000004a => Some(BugcheckDescriptor {
            name: "IRQL_GT_ZERO_AT_SYSTEM_SERVICE",
            description: Some(
                "This indicates that a thread is returning to user mode from a system call when its IRQL is still above PASSIVE_LEVEL.",
            ),
            arguments: [
                "the address of the system function (system call routine)",
                "the current IRQL",
                "0",
                "0",
            ],
        }),
        0x0000004b => Some(BugcheckDescriptor {
            name: "STREAMS_INTERNAL_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000004c => Some(BugcheckDescriptor {
            name: "FATAL_UNHANDLED_HARD_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000004d => Some(BugcheckDescriptor {
            name: "NO_PAGES_AVAILABLE",
            description: Some(
                "This indicates that no free pages are available to continue operations.",
            ),
            arguments: [
                "the total number of dirty pages",
                "the number of dirty pages destined for the page file",
                "the size of the nonpaged pool available at the time the bug check occurred",
                "the most recent modified write error status",
            ],
        }),
        0x0000004e => Some(BugcheckDescriptor {
            name: "PFN_LIST_CORRUPT",
            description: Some("This indicates that the page frame number (PFN) list is corrupted."),
            arguments: ["", "", "", ""],
        }),
        0x0000004f => Some(BugcheckDescriptor {
            name: "NDIS_INTERNAL_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000050 => Some(BugcheckDescriptor {
            name: "PAGE_FAULT_IN_NONPAGED_AREA",
            description: Some(
                "Invalid system memory was referenced. This cannot be protected by try-except. Typically the address is just plain bad or it is pointing at freed memory.",
            ),
            arguments: [
                "memory address referenced",
                "access type (x64: 0 = read; 1 = legacy write; 2 = modern write; 0x10 = execute)",
                "address that referenced memory, if known",
                "page-fault subtype on newer Windows; reserved on older versions",
            ],
        }),
        0x00000051 => Some(BugcheckDescriptor {
            name: "REGISTRY_ERROR",
            description: Some("This indicates that a severe registry error has occurred."),
            arguments: [
                "reserved",
                "reserved",
                "the pointer to the hive (if available)",
                "if the hive is corrupt, the return code of HvCheckHive (if available)",
            ],
        }),
        0x00000052 => Some(BugcheckDescriptor {
            name: "MAILSLOT_FILE_SYSTEM",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000053 => Some(BugcheckDescriptor {
            name: "NO_BOOT_DEVICE",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000054 => Some(BugcheckDescriptor {
            name: "LM_SERVER_INTERNAL_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000055 => Some(BugcheckDescriptor {
            name: "DATA_COHERENCY_EXCEPTION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000056 => Some(BugcheckDescriptor {
            name: "INSTRUCTION_COHERENCY_EXCEPTION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000057 => Some(BugcheckDescriptor {
            name: "XNS_INTERNAL_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000058 => Some(BugcheckDescriptor {
            name: "FTDISK_INTERNAL_ERROR",
            description: Some(
                "This is issued if the system is booted from the wrong copy of a mirrored partition.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000059 => Some(BugcheckDescriptor {
            name: "PINBALL_FILE_SYSTEM",
            description: Some("This indicates that a problem occurred in the Pinball file system."),
            arguments: [
                "specifies source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") identify the source file by its identifier number",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x0000005a => Some(BugcheckDescriptor {
            name: "CRITICAL_SERVICE_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000005b => Some(BugcheckDescriptor {
            name: "SET_ENV_VAR_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000005c => Some(BugcheckDescriptor {
            name: "HAL_INITIALIZATION_FAILED",
            description: Some(
                "This indicates that initialization of the hardware abstraction layer (HAL) failed.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000005d => Some(BugcheckDescriptor {
            name: "UNSUPPORTED_PROCESSOR",
            description: Some(
                "This indicates that the computer is attempting to run Windows on an unsupported processor.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000005e => Some(BugcheckDescriptor {
            name: "OBJECT_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000005f => Some(BugcheckDescriptor {
            name: "SECURITY_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000060 => Some(BugcheckDescriptor {
            name: "PROCESS_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000061 => Some(BugcheckDescriptor {
            name: "HAL1_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000062 => Some(BugcheckDescriptor {
            name: "OBJECT1_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000063 => Some(BugcheckDescriptor {
            name: "SECURITY1_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000064 => Some(BugcheckDescriptor {
            name: "SYMBOLIC_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000065 => Some(BugcheckDescriptor {
            name: "MEMORY1_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000066 => Some(BugcheckDescriptor {
            name: "CACHE_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000067 => Some(BugcheckDescriptor {
            name: "CONFIG_INITIALIZATION_FAILED",
            description: Some("This bug check indicates that the registry configuration failed."),
            arguments: [
                "reserved",
                "the location selector",
                "the NT status code",
                "reserved",
            ],
        }),
        0x00000068 => Some(BugcheckDescriptor {
            name: "FILE_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000069 => Some(BugcheckDescriptor {
            name: "IO1_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the initialization of the I/O system failed for some reason.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000006a => Some(BugcheckDescriptor {
            name: "LPC_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000006b => Some(BugcheckDescriptor {
            name: "PROCESS1_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the initialization of the Microsoft Windows operating system failed.",
            ),
            arguments: [
                "the NT status code that caused the failure",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x0000006c => Some(BugcheckDescriptor {
            name: "REFMON_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000006d => Some(BugcheckDescriptor {
            name: "SESSION1_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the initialization of the Microsoft Windows operating system failed.",
            ),
            arguments: [
                "the NT status code that caused the initialization failure",
                "0",
                "0",
                "0",
            ],
        }),
        0x0000006e => Some(BugcheckDescriptor {
            name: "SESSION2_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the initialization of the Microsoft Windows operating system failed.",
            ),
            arguments: [
                "the NT status code that caused the Windows operating system to conclude that initialization failed",
                "0",
                "0",
                "0",
            ],
        }),
        0x0000006f => Some(BugcheckDescriptor {
            name: "SESSION3_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the initialization of the Microsoft Windows operating system failed.",
            ),
            arguments: [
                "the NT status code that caused the Windows operating system to conclude that initialization failed",
                "0",
                "0",
                "0",
            ],
        }),
        0x00000070 => Some(BugcheckDescriptor {
            name: "SESSION4_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the initialization of the Microsoft Windows operating system failed.",
            ),
            arguments: [
                "the NT status code that caused the Windows operating system to conclude that initialization failed",
                "0",
                "0",
                "0",
            ],
        }),
        0x00000071 => Some(BugcheckDescriptor {
            name: "SESSION5_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the initialization of the Microsoft Windows operating system failed.",
            ),
            arguments: [
                "the NT status code that caused the Windows operating system to conclude that initialization failed",
                "0",
                "0",
                "0",
            ],
        }),
        0x00000072 => Some(BugcheckDescriptor {
            name: "ASSIGN_DRIVE_LETTERS_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000073 => Some(BugcheckDescriptor {
            name: "CONFIG_LIST_FAILED",
            description: Some(
                "This bug check indicates that one of the top-level registry keys, also known as core system hives, cannot be linked in the registry tree.",
            ),
            arguments: [
                "1",
                "the NT status code that led the Windows operating system to assume that it failed to load the hive",
                "the index of the hive in the hive list",
                "a pointer to a UNICODE_STRING structure that contains the file name of the hive",
            ],
        }),
        0x00000074 => Some(BugcheckDescriptor {
            name: "BAD_SYSTEM_CONFIG_INFO",
            description: Some(
                "Can indicate that the SYSTEM hive loaded by the osloader/NTLDR was corrupt. This is unlikely, since the osloader will check a hive to make sure it isn't corrupt after loading it. It can also indicate that some critical registry keys and values are not present. (i.e. somebody used regedt32 to delete something that they shouldn't have) Booting from LastKnownGood may fix the problem, but if someone is persistent enough in mucking with the registry they will need to reinstall or use the Emergency Repair Disk.",
            ),
            arguments: [
                "(reserved)",
                "(reserved)",
                "(reserved)",
                "usually the NT status code",
            ],
        }),
        0x00000075 => Some(BugcheckDescriptor {
            name: "CANNOT_WRITE_CONFIGURATION",
            description: Some(
                "This bug check indicates that the SYSTEM registry hive file cannot be converted to a mapped file.",
            ),
            arguments: [
                "1",
                "the NT status code that led the Windows operating system to assume that it had failed to convert the hive",
                "reserved",
                "reserved",
            ],
        }),
        0x00000076 => Some(BugcheckDescriptor {
            name: "PROCESS_HAS_LOCKED_PAGES",
            description: Some(
                "This bug check indicates that a driver failed to release locked pages after an I/O operation, or that it attempted to unlock pages that were already unlocked.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000077 => Some(BugcheckDescriptor {
            name: "KERNEL_STACK_INPAGE_ERROR",
            description: Some(
                "This bug check indicates that the requested page of kernel data from the paging file could not be read into memory.",
            ),
            arguments: [
                "page retrieval result or status code",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        }),
        0x00000078 => Some(BugcheckDescriptor {
            name: "PHASE0_EXCEPTION",
            description: Some(
                "This occurs when an unexpected break is encountered during HAL initialization, such as using the /break boot option without enabling kernel debugging.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000079 => Some(BugcheckDescriptor {
            name: "MISMATCHED_HAL",
            description: Some(
                "This bug check indicates that the Hardware Abstraction Layer (HAL) revision level or configuration does not match that of the kernel or the computer.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000007a => Some(BugcheckDescriptor {
            name: "KERNEL_DATA_INPAGE_ERROR",
            description: Some(
                "This bug check indicates that the requested page of kernel data from the paging file couldn't be read into memory.",
            ),
            arguments: [
                "lock type or PTE address; schema also depends on parameter 3",
                "error status",
                "process, InPageSupport address, or PTE contents",
                "faulting memory address or page-file offset",
            ],
        }),
        0x0000007b => Some(BugcheckDescriptor {
            name: "INACCESSIBLE_BOOT_DEVICE",
            description: Some(
                "This bug check indicates that the Microsoft Windows operating system has lost access to the system partition during startup.",
            ),
            arguments: [
                "the address of a UNICODE_STRING structure, or the address of the device object that couldn't be mounted",
                "0",
                "0",
                "0",
            ],
        }),
        0x0000007c => Some(BugcheckDescriptor {
            name: "BUGCODE_NDIS_DRIVER",
            description: Some(
                "This bug check indicates that the operating system detected an error in a networking driver.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000007d => Some(BugcheckDescriptor {
            name: "INSTALL_MORE_MEMORY",
            description: Some(
                "This bug check indicates that there is not enough memory to start up the Microsoft Windows operating system.",
            ),
            arguments: [
                "the number of physical pages that are found",
                "the lowest physical page",
                "the highest physical page",
                "0",
            ],
        }),
        0x0000007e => Some(BugcheckDescriptor {
            name: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
            description: Some(
                "This bug check indicates that a system thread generated an exception that the error handler didn't catch.",
            ),
            arguments: [
                "the exception code that wasn't handled",
                "the address where the exception occurred",
                "the address of the exception record",
                "the address of the context record",
            ],
        }),
        0x0000007f => Some(BugcheckDescriptor {
            name: "UNEXPECTED_KERNEL_MODE_TRAP",
            description: Some(
                "This bug check indicates that the Intel CPU generated a trap and the kernel failed to catch this trap.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000080 => Some(BugcheckDescriptor {
            name: "NMI_HARDWARE_FAILURE",
            description: Some("This bug check indicates that a hardware malfunction has occurred."),
            arguments: ["", "", "", ""],
        }),
        0x00000081 => Some(BugcheckDescriptor {
            name: "SPIN_LOCK_INIT_FAILURE",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000082 => Some(BugcheckDescriptor {
            name: "DFS_FILE_SYSTEM",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000085 => Some(BugcheckDescriptor {
            name: "SETUP_FAILURE",
            description: Some("This bug check indicates that a fatal error occurred during setup."),
            arguments: ["", "", "", ""],
        }),
        0x0000008b => Some(BugcheckDescriptor {
            name: "MBR_CHECKSUM_MISMATCH",
            description: Some(
                "This bug check indicates that a mismatch has occurred in the MBR checksum.",
            ),
            arguments: [
                "the disk signature from MBR",
                "the MBR checksum that the OS Loader calculates",
                "the MBR checksum that the system calculates",
                "reserved",
            ],
        }),
        0x0000008e => Some(BugcheckDescriptor {
            name: "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
            description: Some(
                "This bug check indicates that a kernel-mode application generated an exception that the error handler did not catch.",
            ),
            arguments: [
                "the exception code that was not handled",
                "the address where the exception occurred",
                "the trap frame",
                "reserved",
            ],
        }),
        0x0000008f => Some(BugcheckDescriptor {
            name: "PP0_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the Plug and Play (PnP) manager could not be initialized.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000090 => Some(BugcheckDescriptor {
            name: "PP1_INITIALIZATION_FAILED",
            description: Some(
                "This bug check indicates that the Plug and Play (PnP) manager could not be initialized.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000092 => Some(BugcheckDescriptor {
            name: "UP_DRIVER_ON_MP_SYSTEM",
            description: Some(
                "This bug check indicates that a uniprocessor-only driver has been loaded on a multiprocessor system.",
            ),
            arguments: [
                "the base address of the driver",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x00000093 => Some(BugcheckDescriptor {
            name: "INVALID_KERNEL_HANDLE",
            description: Some(
                "This bug check indicates that an invalid or protected handle was passed to NtClose.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000094 => Some(BugcheckDescriptor {
            name: "KERNEL_STACK_LOCKED_AT_EXIT",
            description: Some(
                "This bug check indicates that a thread exited while its kernel stack was marked as not swappable",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000096 => Some(BugcheckDescriptor {
            name: "INVALID_WORK_QUEUE_ITEM",
            description: Some(
                "This bug check indicates that a queue entry was removed that contained a NULL pointer.",
            ),
            arguments: [
                "the address of the queue entry whose flink or blink field is NULL",
                "the address of the queue that is being referenced. Typically, this queue is an ExWorkerQueue",
                "the base address of the ExWorkerQueue array. (This address helps you determine if the queue in question is indeed an ExWorkerQueue",
                "assuming the queue is an ExWorkerQueue, this value is the address of the worker routine that would have been called if the work item had been valid",
            ],
        }),
        0x00000097 => Some(BugcheckDescriptor {
            name: "BOUND_IMAGE_UNSUPPORTED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000098 => Some(BugcheckDescriptor {
            name: "END_OF_NT_EVALUATION_PERIOD",
            description: Some(
                "This bug check indicates that the trial period for the Microsoft Windows operating system has ended.",
            ),
            arguments: [
                "the low-order 32 bits of the product expiration date",
                "the high-order 32 bits of the product expiration date",
                "reserved",
                "reserved",
            ],
        }),
        0x00000099 => Some(BugcheckDescriptor {
            name: "INVALID_REGION_OR_SEGMENT",
            description: Some(
                "This bug check indicates that ExInitializeRegion or ExInterlockedExtendRegion was called with an invalid set of parameters.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000009a => Some(BugcheckDescriptor {
            name: "SYSTEM_LICENSE_VIOLATION",
            description: Some(
                "This bug check indicates that the software license agreement has been violated.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000009b => Some(BugcheckDescriptor {
            name: "UDFS_FILE_SYSTEM",
            description: Some(
                "This bug check indicates that a problem occurred in the UDF file system.",
            ),
            arguments: [
                "the source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") identify the source file by its identifier number",
                "if UdfExceptionFilter is on the stack, this parameter specifies the address of the exception record",
                "if UdfExceptionFilter is on the stack, this parameter specifies the address of the context record",
                "reserved",
            ],
        }),
        0x0000009c => Some(BugcheckDescriptor {
            name: "MACHINE_CHECK_EXCEPTION",
            description: Some(
                "This bug check indicates that a fatal machine check exception has occurred.",
            ),
            arguments: [
                "MCA bank number",
                "address of the MCA_EXCEPTION structure",
                "high 32 bits of the MCA bank's MCi_STATUS MSR",
                "low 32 bits of the MCA bank's MCi_STATUS MSR",
            ],
        }),
        0x0000009e => Some(BugcheckDescriptor {
            name: "USER_MODE_HEALTH_MONITOR",
            description: Some(
                "This bug check indicates that one or more critical user-mode components failed to satisfy a health check.",
            ),
            arguments: [
                "the process that failed to satisfy a health check in the configured time-out",
                "the health monitoring time-out, in seconds",
                "watchdog source. In combination with process address helps to identify what sub-component has created this watchdog. Values listed below",
                "reserved",
            ],
        }),
        0x0000009f => Some(BugcheckDescriptor {
            name: "DRIVER_POWER_STATE_FAILURE",
            description: Some(
                "A driver has failed to complete a power IRP within a specific time.",
            ),
            arguments: [
                "power-state violation type",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        }),
        0x000000a0 => Some(BugcheckDescriptor {
            name: "INTERNAL_POWER_ERROR",
            description: Some(
                "This bug check indicates that the power policy manager experienced a fatal error.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000a1 => Some(BugcheckDescriptor {
            name: "PCI_BUS_DRIVER_INTERNAL",
            description: Some(
                "This bug check indicates that the PCI Bus driver detected inconsistency problems in its internal structures and could not continue.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000a2 => Some(BugcheckDescriptor {
            name: "MEMORY_IMAGE_CORRUPT",
            description: Some(
                "This bug check indicates that corruption has been detected in the image of an executable file in memory.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000a3 => Some(BugcheckDescriptor {
            name: "ACPI_DRIVER_INTERNAL",
            description: Some(
                "This bug check indicates that the ACPI driver detected an internal inconsistency.",
            ),
            arguments: ["reserved", "reserved", "reserved", "reserved"],
        }),
        0x000000a4 => Some(BugcheckDescriptor {
            name: "CNSS_FILE_SYSTEM_FILTER",
            description: Some(
                "This bug check indicates that a problem occurred in the CNSS file system filter.",
            ),
            arguments: [
                "specifies source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") identify the source file by its identifier number",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x000000a5 => Some(BugcheckDescriptor {
            name: "ACPI_BIOS_ERROR",
            description: Some(
                "This bug check indicates that the Advanced Configuration and Power Interface (ACPI) BIOS of the computer is not fully compliant with the ACPI specification.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000a7 => Some(BugcheckDescriptor {
            name: "BAD_EXHANDLE",
            description: Some(
                "This bug check indicates that the kernel-mode handle table detected an inconsistent handle table entry state.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000ac => Some(BugcheckDescriptor {
            name: "HAL_MEMORY_ALLOCATION",
            description: Some(
                "This bug check indicates that the hardware abstraction layer (HAL) could not obtain sufficient memory.",
            ),
            arguments: [
                "the allocation size",
                "0",
                "a pointer to a string that contains the file name",
                "reserved",
            ],
        }),
        0x000000ad => Some(BugcheckDescriptor {
            name: "VIDEO_DRIVER_DEBUG_REPORT_REQUEST",
            description: Some(
                "This bug check indicates that the video port created a non-fatal minidump on behalf of the video driver during run time.",
            ),
            arguments: [
                "driver-specific",
                "driver-specific",
                "driver-specific",
                "the number of all reports that have been requested since boot time",
            ],
        }),
        0x000000b1 => Some(BugcheckDescriptor {
            name: "BGI_DETECTED_VIOLATION",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x000000b4 => Some(BugcheckDescriptor {
            name: "VIDEO_DRIVER_INIT_FAILURE",
            description: Some("This indicates that Windows was unable to enter graphics mode."),
            arguments: ["", "", "", ""],
        }),
        0x000000b8 => Some(BugcheckDescriptor {
            name: "ATTEMPTED_SWITCH_FROM_DPC",
            description: Some(
                "This indicates that an illegal operation was attempted by a deferred procedure call (DPC) routine.",
            ),
            arguments: [
                "the original thread causing the failure",
                "the new thread",
                "the stack address of the original thread",
                "reserved",
            ],
        }),
        0x000000b9 => Some(BugcheckDescriptor {
            name: "CHIPSET_DETECTED_ERROR",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x000000ba => Some(BugcheckDescriptor {
            name: "SESSION_HAS_VALID_VIEWS_ON_EXIT",
            description: Some(
                "This indicates that a session driver still had mapped views when the session unloaded.",
            ),
            arguments: [
                "the session ID",
                "the number of mapped views that are leaking",
                "the address of this session's mapped views table",
                "the size of this session's mapped views table",
            ],
        }),
        0x000000bb => Some(BugcheckDescriptor {
            name: "NETWORK_BOOT_INITIALIZATION_FAILED",
            description: Some(
                "This indicates that Windows failed to successfully boot off a network.",
            ),
            arguments: [
                "the part of network initialization that failed. Possible values are: 1: Failure while updating the registry. 2: Failure while starting the network stack",
                "the failure status",
                "reserved",
                "reserved",
            ],
        }),
        0x000000bc => Some(BugcheckDescriptor {
            name: "NETWORK_BOOT_DUPLICATE_ADDRESS",
            description: Some(
                "This indicates that a duplicate IP address was assigned to this machine while booting off a network.",
            ),
            arguments: [
                "the IP address, shown as a DWORD. An address of the form aa.bb.cc.dd will appear as 0xDDCCBBAA",
                "the hardware address of the other machine. (For an Ethernet connection, see the following note.)",
                "the hardware address of the other machine. (For an Ethernet connection, see the following note.)",
                "the hardware address of the other machine. (For an Ethernet connection, this will be zero.)",
            ],
        }),
        0x000000bd => Some(BugcheckDescriptor {
            name: "INVALID_HIBERNATED_STATE",
            description: Some(
                "This indicates that the hibernated memory image does not match the current hardware configuration. This bugcheck occurs when a system resumes from hibernate and discovers that the hardware has been changed while the system was hibernated.",
            ),
            arguments: [
                "hardware that was invalid. 1 : Number of installed processors is less than before the hibernation Value in Param 2: Number of processors before hibernation Value in Param 3: Number of processors after hibernation",
                "per Parameter 1",
                "per Parameter 1",
                "reserved",
            ],
        }),
        0x000000be => Some(BugcheckDescriptor {
            name: "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
            description: Some(
                "This is issued if a driver attempts to write to a read-only memory segment.",
            ),
            arguments: [
                "virtual address of attempted write",
                "PTE contents",
                "reserved",
                "reserved",
            ],
        }),
        0x000000bf => Some(BugcheckDescriptor {
            name: "MUTEX_ALREADY_OWNED",
            description: Some(
                "This indicates that a thread attempted to acquire ownership of a mutex it already owned.",
            ),
            arguments: [
                "the address of the mutex",
                "the thread that caused the error",
                "0",
                "reserved",
            ],
        }),
        0x000000c1 => Some(BugcheckDescriptor {
            name: "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION",
            description: Some(
                "This indicates that the driver wrote to an invalid section of the special pool.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000c2 => Some(BugcheckDescriptor {
            name: "BAD_POOL_CALLER",
            description: Some(
                "This indicates that the current thread is making a bad pool request.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000c4 => Some(BugcheckDescriptor {
            name: "DRIVER_VERIFIER_DETECTED_VIOLATION",
            description: Some(
                "This is the general bug check code for fatal errors found by Driver Verifier. For more information, see Handling a Bug Check When Driver Verifier is Enabled.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000c5 => Some(BugcheckDescriptor {
            name: "DRIVER_CORRUPTED_EXPOOL",
            description: Some(
                "This indicates that the system attempted to access invalid memory at a process IRQL that was too high.",
            ),
            arguments: [
                "memory referenced",
                "IRQL at time of reference",
                "0: Read 1: Write",
                "address that referenced memory",
            ],
        }),
        0x000000c6 => Some(BugcheckDescriptor {
            name: "DRIVER_CAUGHT_MODIFYING_FREED_POOL",
            description: Some(
                "This indicates that the driver attempted to access a freed memory pool.",
            ),
            arguments: [
                "memory referenced",
                "0: Read 1: Write",
                "0: Kernel mode 1: User mode",
                "reserved",
            ],
        }),
        0x000000c7 => Some(BugcheckDescriptor {
            name: "TIMER_OR_DPC_INVALID",
            description: Some(
                "This is issued if a kernel timer or deferred procedure call (DPC) is found somewhere in memory where it is not permitted.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000c8 => Some(BugcheckDescriptor {
            name: "IRQL_UNEXPECTED_VALUE",
            description: Some(
                "This indicates that the processor's IRQL is not what it should be at this time.",
            ),
            arguments: [
                "the value of the following bit computation: (Current IRQL << 16) | (Expected IRQL << 8) | UniqueValue",
                "if UniqueValue is 0 or 1: APC->KernelRoutine. If UniqueValue is 2: the callout routine If UniqueValue is 3: the interrupt's ServiceRoutine If UniqueValue is 0xfe: 1 if APCs are disabled",
                "if UniqueValue is 0 or 1: APC If UniqueValue is 2: the callout's parameter If UniqueValue is 3: KINTERRUPT",
                "if UniqueValue is 0 or 1: APC->NormalRoutine",
            ],
        }),
        0x000000c9 => Some(BugcheckDescriptor {
            name: "DRIVER_VERIFIER_IOMANAGER_VIOLATION",
            description: Some(
                "This is the bug check code for all Driver Verifier I/O Verification violations.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000ca => Some(BugcheckDescriptor {
            name: "PNP_DETECTED_FATAL_ERROR",
            description: Some(
                "This indicates that the Plug and Play Manager encountered a severe error, probably as a result of a problematic Plug and Play driver.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000cb => Some(BugcheckDescriptor {
            name: "DRIVER_LEFT_LOCKED_PAGES_IN_PROCESS",
            description: Some(
                "This indicates that a driver or the I/O manager failed to release locked pages after an I/O operation.",
            ),
            arguments: [
                "the address of the internal lock tracking structure",
                "0 (Reserved)",
                "address of the MDL containing the locked pages",
                "number of locked pages",
            ],
        }),
        0x000000cc => Some(BugcheckDescriptor {
            name: "PAGE_FAULT_IN_FREED_SPECIAL_POOL",
            description: Some(
                "This indicates that the system has referenced memory which was earlier freed.",
            ),
            arguments: [
                "memory address referenced",
                "0: Read 1: Write",
                "address that referenced memory (if known)",
                "reserved",
            ],
        }),
        0x000000cd => Some(BugcheckDescriptor {
            name: "PAGE_FAULT_BEYOND_END_OF_ALLOCATION",
            description: Some(
                "This indicates that the system accessed memory beyond the end of some driver's pool allocation.",
            ),
            arguments: [
                "memory address referenced",
                "0: Read 1: Write",
                "address that referenced memory (if known)",
                "reserved",
            ],
        }),
        0x000000ce => Some(BugcheckDescriptor {
            name: "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS",
            description: Some(
                "This indicates that a driver failed to cancel pending operations before unloading.",
            ),
            arguments: [
                "memory address referenced",
                "0: Read 1: Write",
                "address that referenced memory (if known)",
                "reserved",
            ],
        }),
        0x000000cf => Some(BugcheckDescriptor {
            name: "TERMINAL_SERVER_DRIVER_MADE_INCORRECT_MEMORY_REFERENCE",
            description: Some(
                "This indicates that a driver has been incorrectly ported to the terminal server.",
            ),
            arguments: [
                "memory address referenced",
                "0: Read 1: Write",
                "address that referenced memory (if known)",
                "reserved",
            ],
        }),
        0x000000d0 => Some(BugcheckDescriptor {
            name: "DRIVER_CORRUPTED_MMPOOL",
            description: Some(
                "This indicates that the system attempted to access invalid memory at a process IRQL that was too high.",
            ),
            arguments: [
                "memory referenced",
                "IRQL at time of reference",
                "0: Read 1: Write",
                "address that referenced memory",
            ],
        }),
        0x000000d1 => Some(BugcheckDescriptor {
            name: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
            description: Some(
                "An attempt was made to access a pageable (or completely invalid) address at an interrupt request level (IRQL) that is too high. This is usually caused by drivers using improper addresses. If kernel debugger is available get stack backtrace.",
            ),
            arguments: [
                "memory referenced",
                "IRQL",
                "value 0 = read operation, 1 = write operation, 2 or 8 = execute operation",
                "address which referenced memory",
            ],
        }),
        0x000000d2 => Some(BugcheckDescriptor {
            name: "BUGCODE_ID_DRIVER",
            description: Some("This indicates that a problem occurred with an NDIS driver."),
            arguments: ["", "", "", ""],
        }),
        0x000000d3 => Some(BugcheckDescriptor {
            name: "DRIVER_PORTION_MUST_BE_NONPAGED",
            description: Some(
                "This indicates that the system attempted to access pageable memory at a process IRQL that was too high.",
            ),
            arguments: [
                "memory referenced",
                "IRQL at time of reference",
                "0: Read 1: Write",
                "address that referenced memory",
            ],
        }),
        0x000000d4 => Some(BugcheckDescriptor {
            name: "SYSTEM_SCAN_AT_RAISED_IRQL_CAUGHT_IMPROPER_DRIVER_UNLOAD",
            description: Some(
                "This indicates that a driver did not cancel pending operations before unloading.",
            ),
            arguments: [
                "memory referenced",
                "IRQL at time of reference",
                "0: Read 1: Write",
                "address that referenced memory",
            ],
        }),
        0x000000d5 => Some(BugcheckDescriptor {
            name: "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
            description: Some(
                "This indicates that a driver has referenced memory which was earlier freed.",
            ),
            arguments: [
                "memory address referenced",
                "0: Read 1: Write",
                "address that referenced memory (if known)",
                "reserved",
            ],
        }),
        0x000000d6 => Some(BugcheckDescriptor {
            name: "DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION",
            description: Some(
                "This indicates the driver accessed memory beyond the end of its pool allocation.",
            ),
            arguments: [
                "memory address referenced",
                "0: Read 1: Write",
                "address that referenced memory (if known)",
                "reserved",
            ],
        }),
        0x000000d7 => Some(BugcheckDescriptor {
            name: "DRIVER_UNMAPPING_INVALID_VIEW",
            description: Some(
                "This indicates a driver is trying to unmap an address that was not mapped.",
            ),
            arguments: [
                "virtual address to unmap",
                "1: The view is being unmapped 2: The view is being committed",
                "0",
                "0",
            ],
        }),
        0x000000d8 => Some(BugcheckDescriptor {
            name: "DRIVER_USED_EXCESSIVE_PTES",
            description: Some(
                "This indicates that there are no more system page table entries (PTE) remaining.",
            ),
            arguments: [
                "pointer to the name of the driver that caused the error (Unicode string), or zero",
                "number of PTEs used by the driver that caused the error (if Parameter 1 is nonzero)",
                "total free system PTEs",
                "total system PTEs",
            ],
        }),
        0x000000d9 => Some(BugcheckDescriptor {
            name: "LOCKED_PAGES_TRACKER_CORRUPTION",
            description: Some(
                "This indicates that the internal locked-page tracking structures have been corrupted.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000da => Some(BugcheckDescriptor {
            name: "SYSTEM_PTE_MISUSE",
            description: Some(
                "This indicates that a page table entry (PTE) routine has been used in an improper way.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000db => Some(BugcheckDescriptor {
            name: "DRIVER_CORRUPTED_SYSPTES",
            description: Some(
                "This indicates that an attempt was made to touch memory at an invalid IRQL, probably due to corruption of system PTEs.",
            ),
            arguments: [
                "memory referenced",
                "IRQL",
                "0: Read 1: Write",
                "address in code which referenced memory",
            ],
        }),
        0x000000dc => Some(BugcheckDescriptor {
            name: "DRIVER_INVALID_STACK_ACCESS",
            description: Some(
                "This indicates that a driver accessed a stack address that lies below the stack pointer of the stack's thread.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000de => Some(BugcheckDescriptor {
            name: "POOL_CORRUPTION_IN_FILE_AREA",
            description: Some(
                "This indicates that a driver has corrupted pool memory that is used for holding pages destined for disk.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000df => Some(BugcheckDescriptor {
            name: "IMPERSONATING_WORKER_THREAD",
            description: Some(
                "This indicates that a workitem did not disable impersonation before it completed.",
            ),
            arguments: [
                "the worker routine that caused this error",
                "the parameter passed to this worker routine",
                "a pointer to the work item",
                "reserved",
            ],
        }),
        0x000000e0 => Some(BugcheckDescriptor {
            name: "ACPI_BIOS_FATAL_ERROR",
            description: Some("This indicates that one of your computer components is faulty."),
            arguments: ["", "", "", ""],
        }),
        0x000000e1 => Some(BugcheckDescriptor {
            name: "WORKER_THREAD_RETURNED_AT_BAD_IRQL",
            description: Some(
                "This indicates that a worker thread completed and returned with IRQL >= DISPATCH_LEVEL.",
            ),
            arguments: [
                "address of the worker routine",
                "IRQL that the worker thread returned at",
                "work item parameter",
                "work item address",
            ],
        }),
        0x000000e2 => Some(BugcheckDescriptor {
            name: "MANUALLY_INITIATED_CRASH",
            description: Some(
                "This indicates that the user deliberately initiated a crash dump from either the kernel debugger or the keyboard.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000e3 => Some(BugcheckDescriptor {
            name: "RESOURCE_NOT_OWNED",
            description: Some(
                "This indicates that a thread tried to release a resource it did not own.",
            ),
            arguments: [
                "address of resource",
                "address of thread",
                "address of owner table (if it exists)",
                "reserved",
            ],
        }),
        0x000000e4 => Some(BugcheckDescriptor {
            name: "WORKER_INVALID",
            description: Some(
                "This indicates that memory that should not contain an executive work item does contain such an item, or that a currently active work item was queued.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000e6 => Some(BugcheckDescriptor {
            name: "DRIVER_VERIFIER_DMA_VIOLATION",
            description: Some(
                "This is the bug check code for all Driver Verifier DMA Verification violations.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000e7 => Some(BugcheckDescriptor {
            name: "INVALID_FLOATING_POINT_STATE",
            description: Some(
                "This indicates that a thread's saved floating-point state is invalid.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000e8 => Some(BugcheckDescriptor {
            name: "INVALID_CANCEL_OF_FILE_OPEN",
            description: Some(
                "This indicates that an invalid file object was passed to IoCancelFileOpen.",
            ),
            arguments: [
                "the file object passed to IoCancelFileOpen",
                "the device object passed to IoCancelFileOpen",
                "reserved",
                "reserved",
            ],
        }),
        0x000000e9 => Some(BugcheckDescriptor {
            name: "ACTIVE_EX_WORKER_THREAD_TERMINATION",
            description: Some(
                "This indicates that an active executive worker thread is being terminated.",
            ),
            arguments: ["the exiting ETHREAD", "reserved", "reserved", "reserved"],
        }),
        0x000000ea => Some(BugcheckDescriptor {
            name: "THREAD_STUCK_IN_DEVICE_DRIVER",
            description: Some(
                "This indicates that a thread in a device driver is endlessly spinning.",
            ),
            arguments: [
                "a pointer to the stuck thread object",
                "a pointer to the DEFERRED_WATCHDOG object",
                "a pointer to the offending driver name",
                "in the kernel debugger: The number of times the \"intercepted\" bug check 0xEA was hit On the blue screen: 1",
            ],
        }),
        0x000000eb => Some(BugcheckDescriptor {
            name: "DIRTY_MAPPED_PAGES_CONGESTION",
            description: Some(
                "This indicates that no free pages are available to continue operations.",
            ),
            arguments: [
                "the total number of dirty pages",
                "the number of dirty pages destined for the page file",
                "windows Server 2003 only: The size of the nonpaged pool available at the time of the bug check (in pages) Windows Vista and later versions: Reserved",
                "windows Server 2003 only: The number of transition pages that are currently stranded Windows Vista and later versions: The most recent modified write error status",
            ],
        }),
        0x000000ec => Some(BugcheckDescriptor {
            name: "SESSION_HAS_VALID_SPECIAL_POOL_ON_EXIT",
            description: Some(
                "This indicates that a session unload occurred while a session driver still held memory.",
            ),
            arguments: [
                "the session ID",
                "the number of special pool pages that are leaking",
                "reserved",
                "reserved",
            ],
        }),
        0x000000ed => Some(BugcheckDescriptor {
            name: "UNMOUNTABLE_BOOT_VOLUME",
            description: Some(
                "This indicates that the I/O subsystem attempted to mount the boot volume and it failed.",
            ),
            arguments: [
                "the device object of the boot volume",
                "the status code from the file system that describes why it failed to mount the volume",
                "reserved",
                "reserved",
            ],
        }),
        0x000000ef => Some(BugcheckDescriptor {
            name: "CRITICAL_PROCESS_DIED",
            description: Some(
                "This check indicates that a critical system process terminated. A critical process forces the system to bug check if the system terminates. This check happens when the state of the process is corrupted or damaged. When the corruption or damage happens, as these processes are critical to the operation of Windows, a system bug check occurs as the operating system integrity is in question.",
            ),
            arguments: [
                "the process object",
                "if 0, a process terminated. If 1, a thread terminated",
                "reserved",
                "reserved",
            ],
        }),
        0x000000f0 => Some(BugcheckDescriptor {
            name: "STORAGE_MINIPORT_ERROR",
            description: Some(
                "It indicates that a storage Miniport driver failed to complete a SRB request.",
            ),
            arguments: [
                "error Code. See Values below",
                "see Values below",
                "see Values below",
                "see Values below",
            ],
        }),
        0x000000f1 => Some(BugcheckDescriptor {
            name: "SCSI_VERIFIER_DETECTED_VIOLATION",
            description: Some(
                "This is the bug check code for all Driver Verifier SCSI Verification violations.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000f2 => Some(BugcheckDescriptor {
            name: "HARDWARE_INTERRUPT_STORM",
            description: Some("This indicates that the kernel detected an interrupt storm."),
            arguments: [
                "address of the ISR (or first ISR in the chain) connected to the storming interrupt vector",
                "ISR context value",
                "address of the interrupt object for the storming interrupt vector",
                "0x1 if the ISR is not chained, 0x2 if the ISR is chained",
            ],
        }),
        0x000000f3 => Some(BugcheckDescriptor {
            name: "DISORDERLY_SHUTDOWN",
            description: Some(
                "This indicates that Windows was unable to shut down due to lack of memory.",
            ),
            arguments: [
                "the total number of dirty pages",
                "the number of dirty pages destined for the page file",
                "windows Server 2003 only: The size of the nonpaged pool available at the time of the bug check (in pages) Windows Vista and later: Reserved",
                "windows Server 2003 only: The current shut down stage Windows Vista and later: The most recent modified write error status",
            ],
        }),
        0x000000f4 => Some(BugcheckDescriptor {
            name: "CRITICAL_OBJECT_TERMINATION",
            description: Some(
                "This indicates that a process or thread crucial to system operation has unexpectedly exited or been terminated.",
            ),
            arguments: [
                "the terminating object type: 0x3: Process 0x6: Thread",
                "the terminating object",
                "the process image file name",
                "pointer to an ASCII string containing an explanatory message",
            ],
        }),
        0x000000f5 => Some(BugcheckDescriptor {
            name: "FLTMGR_FILE_SYSTEM",
            description: Some(
                "This indicates that an unrecoverable failure occurred in the Filter Manager.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000f6 => Some(BugcheckDescriptor {
            name: "PCI_VERIFIER_DETECTED_VIOLATION",
            description: Some(
                "This indicates that an error occurred in the BIOS or another device being verified by the PCI driver.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000f7 => Some(BugcheckDescriptor {
            name: "DRIVER_OVERRAN_STACK_BUFFER",
            description: Some("This indicates that a driver has overrun a stack-based buffer."),
            arguments: [
                "the actual security check cookie from the stack",
                "the expected security check cookie",
                "the bit-complement of the expected security check cookie",
                "0",
            ],
        }),
        0x000000f8 => Some(BugcheckDescriptor {
            name: "RAMDISK_BOOT_INITIALIZATION_FAILED",
            description: Some(
                "This indicates that an initialization failure occurred while attempting to boot from the RAM disk.",
            ),
            arguments: [
                "indicates the cause of the failure. 1: No LoaderXIPRom descriptor was found in the loader memory list. 2: Unable to open the RAM disk driver (ramdisk.sys or \\Device\\Ramdisk). 3: FSCTL_CREATE_RAM_DISK failed",
                "NTSTATUS code",
                "0",
                "0",
            ],
        }),
        0x000000f9 => Some(BugcheckDescriptor {
            name: "DRIVER_RETURNED_STATUS_REPARSE_FOR_VOLUME_OPEN",
            description: Some(
                "This indicates that a driver returned STATUS_REPARSE to an IRP_MJ_CREATE request with no trailing names.",
            ),
            arguments: [
                "the device object that was opened",
                "the device object to which the IRP_MJ_CREATE request was issued",
                "address of the Unicode string containing the new name of the file (to be reparsed)",
                "information returned by the driver for the IRP_MJ_CREATE request",
            ],
        }),
        0x000000fa => Some(BugcheckDescriptor {
            name: "HTTP_DRIVER_CORRUPTED",
            description: Some(
                "This indicates that the HTTP kernel driver (Http.sys) has reached a corrupted state and cannot recover.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000fc => Some(BugcheckDescriptor {
            name: "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
            description: Some(
                "This indicates that an attempt was made to execute non-executable memory.",
            ),
            arguments: [
                "the virtual address whose execution was attempted",
                "the contents of the page table entry (PTE)",
                "reserved",
                "reserved",
            ],
        }),
        0x000000fd => Some(BugcheckDescriptor {
            name: "DIRTY_NOWRITE_PAGES_CONGESTION",
            description: Some(
                "This indicates that there are no free pages available to continue basic system operations.",
            ),
            arguments: [
                "total number of dirty pages",
                "number of non-writeable dirty pages",
                "reserved",
                "most recently modified write-error status",
            ],
        }),
        0x000000fe => Some(BugcheckDescriptor {
            name: "BUGCODE_USB_DRIVER",
            description: Some(
                "This indicates that an error has occurred in a universal serial bus (USB) driver.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000000ff => Some(BugcheckDescriptor {
            name: "RESERVE_QUEUE_OVERFLOW",
            description: Some(
                "This indicates that an attempt was made to insert a new item into a reserve queue, causing the queue to overflow.",
            ),
            arguments: [
                "the address of the reserve queue",
                "the size of the reserve queue",
                "0",
                "0",
            ],
        }),
        0x00000100 => Some(BugcheckDescriptor {
            name: "LOADER_BLOCK_MISMATCH",
            description: Some(
                "This indicates that either the loader block is invalid, or it does not match the system that is being loaded.",
            ),
            arguments: [
                "3",
                "the size of the loader black extension",
                "the major version of the loader block",
                "the minor version of the loader block",
            ],
        }),
        0x00000101 => Some(BugcheckDescriptor {
            name: "CLOCK_WATCHDOG_TIMEOUT",
            description: Some(
                "This bug check indicates that an expected clock interrupt on a secondary processor, in a multi-processor system, wasn't received within the allocated interval.",
            ),
            arguments: [
                "clock interrupt time-out interval, in nominal clock ticks",
                "0",
                "the address of the processor control block (PRCB) for the unresponsive processor",
                "the index of the hung processor",
            ],
        }),
        0x00000102 => Some(BugcheckDescriptor {
            name: "DPC_WATCHDOG_TIMEOUT",
            description: Some(
                "This indicates that The DPC watchdog routine was not executed within the allocated time interval.",
            ),
            arguments: [
                "DPC watchdog time out interval in nominal clock ticks",
                "the PRCB address of the hung processor",
                "reserved",
                "reserved",
            ],
        }),
        0x00000103 => Some(BugcheckDescriptor {
            name: "MUP_FILE_SYSTEM",
            description: Some(
                "This bug check indicates that the multiple UNC provider (MUP) has encountered invalid or unexpected data. As a result, the MUP cannot channel a remote file system request to a network redirector, the Universal Naming Convention (UNC) provider.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000104 => Some(BugcheckDescriptor {
            name: "AGP_INVALID_ACCESS",
            description: Some(
                "This indicates that the GPU wrote to a range of Accelerated Graphics Port (AGP) memory that had not previously been committed.",
            ),
            arguments: [
                "offset (in ULONG) within the AGP verifier page to the first ULONG data that is corrupted",
                "0",
                "0",
                "0",
            ],
        }),
        0x00000105 => Some(BugcheckDescriptor {
            name: "AGP_GART_CORRUPTION",
            description: Some(
                "This indicates that the Graphics Aperture Remapping Table (GART) is corrupt.",
            ),
            arguments: [
                "the base address (virtual) of the GART",
                "the offset into the GART where the corruption occurred",
                "the base address (virtual) of the GART cache (a copy of the GART)",
                "0",
            ],
        }),
        0x00000106 => Some(BugcheckDescriptor {
            name: "AGP_ILLEGALLY_REPROGRAMMED",
            description: Some(
                "This indicates that the Accelerated Graphics Port (AGP) hardware has been reprogrammed by an unauthorized agent.",
            ),
            arguments: [
                "the originally programmed AGP command register value",
                "the current command register value",
                "0",
                "0",
            ],
        }),
        0x00000108 => Some(BugcheckDescriptor {
            name: "THIRD_PARTY_FILE_SYSTEM_FAILURE",
            description: Some(
                "This indicates that an unrecoverable problem has occurred in a third-party file system or file system filter.",
            ),
            arguments: [
                "identifies the file system that failed. Possible values include: 1: Polyserve (Psfs.sys)",
                "the address of the exception record",
                "the address of the context record",
                "reserved",
            ],
        }),
        0x00000109 => Some(BugcheckDescriptor {
            name: "CRITICAL_STRUCTURE_CORRUPTION",
            description: Some(
                "This indicates that the kernel has detected critical kernel code or data corruption.",
            ),
            arguments: [
                "reserved",
                "reserved",
                "reserved",
                "the type of the corrupted region. (See the following table later on this page.)",
            ],
        }),
        0x0000010a => Some(BugcheckDescriptor {
            name: "APP_TAGGING_INITIALIZATION_FAILED",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000010c => Some(BugcheckDescriptor {
            name: "FSRTL_EXTRA_CREATE_PARAMETER_VIOLATION",
            description: Some(
                "This indicates that a violation was detected in the File system Run-time library (FsRtl) Extra Create Parameter (ECP) package.",
            ),
            arguments: [
                "the type of violation. (See the following table later on this page for more details)",
                "0",
                "the address of the ECP",
                "the starting address of the ECP list",
            ],
        }),
        0x0000010d => Some(BugcheckDescriptor {
            name: "WDF_VIOLATION",
            description: Some(
                "This indicates that Kernel-Mode Driver Framework (KMDF) detected that Windows found an error in a framework-based driver.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000010e => Some(BugcheckDescriptor {
            name: "VIDEO_MEMORY_MANAGEMENT_INTERNAL",
            description: Some(
                "This indicates that the video memory manager has encountered a condition that it is unable to recover from.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000010f => Some(BugcheckDescriptor {
            name: "RESOURCE_MANAGER_EXCEPTION_NOT_HANDLED",
            description: Some(
                "This indicates that the kernel transaction manager detected that a kernel-mode resource manager has raised an exception in response to a direct call-back. The resource manager is in an unexpected and unrecoverable state.",
            ),
            arguments: [
                "the address of the exception record",
                "the address of the context record",
                "the address of the exception code",
                "the address of the resource manager",
            ],
        }),
        0x00000111 => Some(BugcheckDescriptor {
            name: "RECURSIVE_NMI",
            description: Some(
                "This bug check indicates that a non-maskable-interrupt (NMI) occurred while a previous NMI was in progress.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000112 => Some(BugcheckDescriptor {
            name: "MSRPC_STATE_VIOLATION",
            description: Some(
                "This indicates that the Msrpc.sys driver has initiated a bug check.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000113 => Some(BugcheckDescriptor {
            name: "VIDEO_DXGKRNL_FATAL_ERROR",
            description: Some(
                "This indicates that the Microsoft DirectX graphics kernel subsystem has detected a violation.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000114 => Some(BugcheckDescriptor {
            name: "VIDEO_SHADOW_DRIVER_FATAL_ERROR",
            description: Some("This indicates that the shadow driver has detected a violation."),
            arguments: ["", "", "", ""],
        }),
        0x00000115 => Some(BugcheckDescriptor {
            name: "AGP_INTERNAL",
            description: Some(
                "This indicates that the accelerated graphics port (AGP) driver has detected a violation.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000116 => Some(BugcheckDescriptor {
            name: "VIDEO_TDR_FAILURE",
            description: Some(
                "Attempt to reset the display driver and recover from timeout failed.",
            ),
            arguments: [
                "optional pointer to internal TDR recovery context (TDR_RECOVERY_CONTEXT)",
                "the pointer into responsible device driver module (e.g. owner tag)",
                "optional error code (NTSTATUS) of the last failed operation",
                "optional internal context dependent data",
            ],
        }),
        0x00000117 => Some(BugcheckDescriptor {
            name: "VIDEO_TDR_TIMEOUT_DETECTED",
            description: Some(
                "The display driver failed to respond in timely fashion. (This code can never be used for a real bug check; it is used to identify live dumps.)",
            ),
            arguments: [
                "optional pointer to internal TDR recovery context (TDR_RECOVERY_CONTEXT)",
                "the pointer into responsible device driver module (e.g owner tag)",
                "the secondary driver specific bucketing key",
                "optional internal context dependent data",
            ],
        }),
        0x00000119 => Some(BugcheckDescriptor {
            name: "VIDEO_SCHEDULER_INTERNAL_ERROR",
            description: Some(
                "This bug check indicates that the video scheduler has detected a fatal violation.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000011a => Some(BugcheckDescriptor {
            name: "EM_INITIALIZATION_FAILURE",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000011b => Some(BugcheckDescriptor {
            name: "DRIVER_RETURNED_HOLDING_CANCEL_LOCK",
            description: Some(
                "This bug check indicates that a driver has returned from a cancel routine that holds the global cancel lock. This causes all later cancellation calls to fail, and results in either a deadlock or another bug check.",
            ),
            arguments: [
                "the address of the IRP that was canceled (might not be valid)",
                "the address of the cancel routine",
                "",
                "",
            ],
        }),
        0x0000011c => Some(BugcheckDescriptor {
            name: "ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE",
            description: Some(
                "This bug check indicates that an attempt was made to write to the read-only protected storage of the configuration manager.",
            ),
            arguments: [
                "virtual address for the attempted write",
                "PTE contents",
                "reserved",
                "reserved",
            ],
        }),
        0x0000011d => Some(BugcheckDescriptor {
            name: "EVENT_TRACING_FATAL_ERROR",
            description: Some(
                "This bug check indicates that the Event Tracing subsystem has encountered an unexpected fatal error.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000011e => Some(BugcheckDescriptor {
            name: "TOO_MANY_RECURSIVE_FAULTS",
            description: Some(
                "This indicates that a file system has caused too many recursive faults under low resource conditions to be handled.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000011f => Some(BugcheckDescriptor {
            name: "INVALID_DRIVER_HANDLE",
            description: Some(
                "This indicates that someone has closed the initial handle for a driver between inserting the driver object and referencing the handle.",
            ),
            arguments: [
                "the handle value for the driver object",
                "the status returned trying to reference the object",
                "the address of the PDRIVER_OBJECT",
                "reserved",
            ],
        }),
        0x00000120 => Some(BugcheckDescriptor {
            name: "BITLOCKER_FATAL_ERROR",
            description: Some(
                "This indicates that BitLocker drive encryption encountered a problem that it cannot recover from.",
            ),
            arguments: ["type of problem", "reserved", "reserved", "reserved"],
        }),
        0x00000121 => Some(BugcheckDescriptor {
            name: "DRIVER_VIOLATION",
            description: Some("This bug check indicates that a driver has caused a violation."),
            arguments: ["", "", "", ""],
        }),
        0x00000122 => Some(BugcheckDescriptor {
            name: "WHEA_INTERNAL_ERROR",
            description: Some(
                "This bug check indicates that an internal error in the Windows Hardware Error Architecture (WHEA) has occurred. Errors can result from a bug in the implementation of a platform-specific hardware error driver (PSHED) plug-in supplied by a vendor, the firmware implementation of error records, or the firmware implementation of error injection.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000123 => Some(BugcheckDescriptor {
            name: "CRYPTO_SELF_TEST_FAILURE",
            description: Some(
                "This indicates that the cryptographic subsystem failed a mandatory algorithm self-test during bootstrap.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000124 => Some(BugcheckDescriptor {
            name: "WHEA_UNCORRECTABLE_ERROR",
            description: Some(
                "and indicates that a fatal hardware error has occurred. This bug check uses the error data provided by the Windows Hardware Error Architecture (WHEA).",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000125 => Some(BugcheckDescriptor {
            name: "NMR_INVALID_STATE",
            description: Some(
                "This indicates that NMR (network module registrar) has detected an invalid state. See parameter 1 for the state type.",
            ),
            arguments: [
                "the subtype of the bugcheck. 0x0 : Machine Check Exception Parameter 2 - Address of the WHEA_ERROR_RECORD structure. Parameter 3 - High order 32-bits of the MCi_STATUS value",
                "pointer to the NMI Handle",
                "pointer to the expected type, when available",
                "reserved",
            ],
        }),
        0x00000126 => Some(BugcheckDescriptor {
            name: "NETIO_INVALID_POOL_CALLER",
            description: Some(
                "This indicates that an invalid pool request has been made to netio managed memory pool, e.g. FSB and MDL.",
            ),
            arguments: [
                "the subtype of the bugcheck. 0x1 : Invalid pool. Pool is at an invalid state. Parameter 2 - Pointer to memory block or MDL. Parameter 3 - Pointer to page. Parameter 4 - Pointer to CPU pool. 0x2 : Invalid MDL",
                "see parameter 1",
                "see parameter 1",
                "see parameter 1",
            ],
        }),
        0x00000127 => Some(BugcheckDescriptor {
            name: "PAGE_NOT_ZERO",
            description: Some(
                "This bug check indicates that a page that should have been filled with zeros was not. This bug check might occur because of a hardware error or because a privileged component of the operating system modified a page after freeing it.",
            ),
            arguments: [
                "virtual address that maps the corrupted page",
                "physical page number",
                "zero (Reserved)",
                "zero (Reserved)",
            ],
        }),
        0x00000128 => Some(BugcheckDescriptor {
            name: "WORKER_THREAD_RETURNED_WITH_BAD_IO_PRIORITY",
            description: Some(
                "This indicates that a worker threads IOPriority was wrongly modified by the called worker routine.",
            ),
            arguments: [
                "address of worker routine (Use the ln (List Nearest Symbols) command on this address to find the offending driver)",
                "current IoPrioirity value",
                "workitem parameter",
                "workitem address",
            ],
        }),
        0x00000129 => Some(BugcheckDescriptor {
            name: "WORKER_THREAD_RETURNED_WITH_BAD_PAGING_IO_PRIORITY",
            description: Some(
                "This indicates that a worker threads Paging IOPriority was wrongly modified by the called worker routine.",
            ),
            arguments: [
                "address of worker routine Use the ln (List Nearest Symbols) command on this address to find the offending driver",
                "current Paging IoPrioirity value",
                "workitem parameter",
                "workitem address",
            ],
        }),
        0x0000012a => Some(BugcheckDescriptor {
            name: "MUI_NO_VALID_SYSTEM_LANGUAGE",
            description: Some(
                "This indicates that Windows did not find any installed, licensed language packs for the system default UI language.",
            ),
            arguments: [
                "the subtype of the bugcheck 0x1 : Windows did not find any installed language packs during phase I initialization. Parameter 2 - NT status code that describes the reason of failure",
                "see parameter 1",
                "reserved",
                "reserved",
            ],
        }),
        0x0000012b => Some(BugcheckDescriptor {
            name: "FAULTY_HARDWARE_CORRUPTED_PAGE",
            description: Some(
                "This bug check indicates that the Windows memory manager detected corruption. That corruption could only have been caused by a component accessing memory using physical addressing.",
            ),
            arguments: [
                "memory-manager address or compressed-store failure status",
                "physical page number or compressed page size",
                "zero or compressed-store source buffer",
                "zero or compressed-store target buffer",
            ],
        }),
        0x0000012c => Some(BugcheckDescriptor {
            name: "EXFAT_FILE_SYSTEM",
            description: Some(
                "This bug check indicates that a problem occurred in the Extended File Allocation Table (exFAT) file system.",
            ),
            arguments: [
                "specifies source file and line number information. The high 16 bits (the first four hexadecimal digits after the \"0x\") determine the source file by its identifier number",
                "if FppExceptionFilter is on the stack, this parameter specifies the address of the exception record",
                "if FppExceptionFilter is on the stack, this parameter specifies the address of the context record",
                "reserved",
            ],
        }),
        0x0000012d => Some(BugcheckDescriptor {
            name: "VOLSNAP_OVERLAPPED_TABLE_ACCESS",
            description: Some(
                "This indicates that volsnap tried to access a common table from two different threads which may result in table corruption and eventually corrupt the table.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000012e => Some(BugcheckDescriptor {
            name: "INVALID_MDL_RANGE",
            description: Some(
                "This indicates that a driver has called the IoBuildPartialMdl() function and passed it an MDL to map part of a source MDL, but the virtual address range specified is outside the range in the source MDL. This is typically a driver bug.",
            ),
            arguments: ["SourceMdl", "TargetMdl", "VirtualAddress", "length"],
        }),
        0x0000012f => Some(BugcheckDescriptor {
            name: "VHD_BOOT_INITIALIZATION_FAILED",
            description: Some(
                "This indicates that an initialization failure occurred while attempting to boot from a VHD.",
            ),
            arguments: [
                "action that failed 1 : Couldn't extract VHD information from boot device. 2 : Timeout waiting for VHD parent device to surface. 3 : VHD path string memory allocation error. 4 : VHD path construction failed",
                "NT status code",
                "reserved",
                "reserved",
            ],
        }),
        0x00000130 => Some(BugcheckDescriptor {
            name: "DYNAMIC_ADD_PROCESSOR_MISMATCH",
            description: Some(
                "This bugcheck indicates that a new processor added to the system is incompatible with the current configuration.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000131 => Some(BugcheckDescriptor {
            name: "INVALID_EXTENDED_PROCESSOR_STATE",
            description: Some(
                "This indicates that an invalid combination of parameters was detected while saving or restoring extended processor state.",
            ),
            arguments: [
                "extended-processor-state failure type",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        }),
        0x00000132 => Some(BugcheckDescriptor {
            name: "RESOURCE_OWNER_POINTER_INVALID",
            description: Some(
                "This indicates that an invalid resource owner pointer was supplied.",
            ),
            arguments: [
                "resource",
                "resource->OwnerTable",
                "CurrentThread",
                "OwnerPointer",
            ],
        }),
        0x00000133 => Some(BugcheckDescriptor {
            name: "DPC_WATCHDOG_VIOLATION",
            description: Some(
                "The DPC watchdog detected a prolonged run time at an IRQL of DISPATCH_LEVEL or above.",
            ),
            arguments: [
                "watchdog violation type",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        }),
        0x00000134 => Some(BugcheckDescriptor {
            name: "DRIVE_EXTENDER",
            description: Some(
                "This indicates that the drive extender component has experienced a severe internal error that prevents continued system operation.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000135 => Some(BugcheckDescriptor {
            name: "REGISTRY_FILTER_DRIVER_EXCEPTION",
            description: Some(
                "This bugcheck is caused by an unhandled exception in a registry filtering driver.",
            ),
            arguments: [
                "exception Code",
                "address of the context record for the exception that caused the bugcheck",
                "the driver's callback routine address",
                "reserved",
            ],
        }),
        0x00000136 => Some(BugcheckDescriptor {
            name: "VHD_BOOT_HOST_VOLUME_NOT_ENOUGH_SPACE",
            description: Some(
                "This indicates that an initialization failure occurred while attempting to boot from a VHD. The volume that hosts the VHD does not have enough free space to expand the VHD.",
            ),
            arguments: [
                "0 : Unable to expand VHD file to full size",
                "NT Status Code",
                "reserved",
                "reserved",
            ],
        }),
        0x00000137 => Some(BugcheckDescriptor {
            name: "WIN32K_HANDLE_MANAGER",
            description: Some(
                "This indicates that the win32k/ntuser handle manager has detected a fatal error.",
            ),
            arguments: [
                "reserved",
                "address of the object (If available)",
                "reserved",
                "reserved",
            ],
        }),
        0x00000138 => Some(BugcheckDescriptor {
            name: "GPIO_CONTROLLER_DRIVER_ERROR",
            description: Some(
                "This bug check indicates that the GPIO class extension driver encountered a fatal error.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000139 => Some(BugcheckDescriptor {
            name: "KERNEL_SECURITY_CHECK_FAILURE",
            description: Some(
                ", and indicates that the kernel detects the corruption of a critical data structure.",
            ),
            arguments: [
                "the type of corruption. For more information, see the following table",
                "address of the trap frame for the exception that caused the bug check",
                "address of the exception record for the exception that caused the bug check",
                "reserved",
            ],
        }),
        0x0000013a => Some(BugcheckDescriptor {
            name: "KERNEL_MODE_HEAP_CORRUPTION",
            description: Some(
                "This bug check indicates that the kernel mode heap manager has detected corruption in a heap.",
            ),
            arguments: [
                "type of corruption detected - see the following list",
                "address of the heap that reported the corruption",
                "address at which the corruption was detected",
                "reserved",
            ],
        }),
        0x0000013b => Some(BugcheckDescriptor {
            name: "PASSIVE_INTERRUPT_ERROR",
            description: Some(
                "This indicates that the kernel has detected issues with the passive-level interrupt.",
            ),
            arguments: [
                "type of error detected 0x1 : A driver tried to acquire an interrupt spinlock but passed in a passive-level interrupt object",
                "address of the KINTERRUPT object for the passive-level interrupt",
                "reserved",
                "reserved",
            ],
        }),
        0x0000013c => Some(BugcheckDescriptor {
            name: "INVALID_IO_BOOST_STATE",
            description: Some(
                "This indicates that a thread exited with an invalid I/O boost state. This should be zero when a thread exits.",
            ),
            arguments: [
                "pointer to the thread which had the invalid boost state",
                "current boost state or throttle count",
                "reserved",
                "reserved",
            ],
        }),
        0x0000013d => Some(BugcheckDescriptor {
            name: "CRITICAL_INITIALIZATION_FAILURE",
            description: Some("This indicates that early kernel initialization has failed."),
            arguments: ["reserved", "reserved", "reserved", "reserved"],
        }),
        0x00000140 => Some(BugcheckDescriptor {
            name: "STORAGE_DEVICE_ABNORMALITY_DETECTED",
            description: Some(
                "This indicates that the storage driver stack encountered rate of responsiveness violations, exceeding the threshold, or other failures to respond.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000143 => Some(BugcheckDescriptor {
            name: "PROCESSOR_DRIVER_INTERNAL",
            description: Some(
                "This indicates that the Processor Power Management (PPM) driver encountered a fatal error.",
            ),
            arguments: [
                "processor-driver failure type",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        }),
        0x00000144 => Some(BugcheckDescriptor {
            name: "BUGCODE_USB3_DRIVER",
            description: Some(
                "This is the code used for all USB 3 bug checks. Parameter 1 specifies the type of the USB 3 bug check, and the meanings of the other parameters are dependent on Parameter 1.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000145 => Some(BugcheckDescriptor {
            name: "SECURE_BOOT_VIOLATION",
            description: Some(
                "This indicates that the secure Boot policy enforcement could not be started due to an invalid policy or a required operation not being completed.",
            ),
            arguments: [
                "the status code of the failure",
                "address of the Secure Boot policy",
                "size of the Secure Boot policy",
                "reserved",
            ],
        }),
        0x00000147 => Some(BugcheckDescriptor {
            name: "ABNORMAL_RESET_DETECTED",
            description: Some(
                "This indicates that Windows underwent an abnormal reset. No context or exception records were saved, and bugcheck callbacks were not called.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000149 => Some(BugcheckDescriptor {
            name: "REFS_FILE_SYSTEM",
            description: Some("This indicates that a file system error has occurred."),
            arguments: [
                "__LINE__",
                "ExceptionRecord",
                "ContextRecord",
                "ExceptionRecord->ExceptionAddress",
            ],
        }),
        0x0000014a => Some(BugcheckDescriptor {
            name: "KERNEL_WMI_INTERNAL",
            description: Some(
                "This indicates that the internal kernel WMI subsystem has encountered a fatal error.",
            ),
            arguments: [
                "0 : A kernel WMI entry reference count was incremented from 0. Parameter 2: Pointer to the kernel WMI entry. 1 : A kernel WMI datasource was removed prematurely. Parameter 2: Pointer to the kernel WMI datasource",
                "see parameter 1",
                "reserved",
                "reserved",
            ],
        }),
        0x0000014b => Some(BugcheckDescriptor {
            name: "SOC_SUBSYSTEM_FAILURE",
            description: Some("A SOC subsystem has experienced an unrecoverable critical fault."),
            arguments: [
                "nt!SOC_SUBSYSTEM_FAILURE_DETAILS",
                "reserved",
                "reserved",
                "(Optional) address to vendor supplied general purpose data block",
            ],
        }),
        0x0000014c => Some(BugcheckDescriptor {
            name: "FATAL_ABNORMAL_RESET_ERROR",
            description: Some(
                "This indicates that an unrecoverable system error occurred or the system has abnormally reset.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x0000014d => Some(BugcheckDescriptor {
            name: "EXCEPTION_SCOPE_INVALID",
            description: Some(
                "This indicates that an internal inconsistency in exception dispatching has been detected.",
            ),
            arguments: ["reserved", "reserved", "reserved", "reserved"],
        }),
        0x0000014e => Some(BugcheckDescriptor {
            name: "SOC_CRITICAL_DEVICE_REMOVED",
            description: Some(
                "This indicates that a critical SOC device has been unexpectedly removed or failed.",
            ),
            arguments: [
                "when available, indicates the ID of the device which was removed (4 character packed code)",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x0000014f => Some(BugcheckDescriptor {
            name: "PDC_WATCHDOG_TIMEOUT",
            description: Some(
                "This indicates that a system component failed to respond within the allocated time period, preventing the system from exiting connected standby.",
            ),
            arguments: [
                "client ID of the hung component",
                "client type of the hung component. 0x1 : A notification client failed to respond. Parameter 3: Pointer to the notification client (PDC_NOTIFICATION_CLIENT). Parameter 4: Pointer to a pdc!PDC_14F_TRIAGE structure",
                "see parameter 2",
                "see parameter 2",
            ],
        }),
        0x00000150 => Some(BugcheckDescriptor {
            name: "TCPIP_AOAC_NIC_ACTIVE_REFERENCE_LEAK",
            description: Some(
                "This indicates that the NIC active reference should have been released when the send queue was fully drained.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000151 => Some(BugcheckDescriptor {
            name: "UNSUPPORTED_INSTRUCTION_MODE",
            description: Some(
                "This indicates that an attempt was made to execute code using an unsupported processor instruction mode (for example, executing classic Arm instructions instead of ThumbV2 instructions). This is not permitted.",
            ),
            arguments: [
                "program counter when the problem was detected",
                "trap Frame",
                "reserved",
                "reserved",
            ],
        }),
        0x00000152 => Some(BugcheckDescriptor {
            name: "INVALID_PUSH_LOCK_FLAGS",
            description: Some(
                "This indicates that the flags supplied to one of push lock APIs were invalid.",
            ),
            arguments: [
                "the invalid flags supplied by the caller",
                "the address of the push lock",
                "reserved",
                "reserved",
            ],
        }),
        0x00000153 => Some(BugcheckDescriptor {
            name: "KERNEL_LOCK_ENTRY_LEAKED_ON_THREAD_TERMINATION",
            description: Some(
                "This indicates that a thread was terminated before it had freed all its AutoBoost lock entries.",
            ),
            arguments: [
                "the address of the thread",
                "the address of the entry that was not freed",
                "a status code indicating the state of the entry 0x1 : Lock pointer was not NULL 0x2 : Thread pointer reserved bits were set 0x3 : Thread pointer was corrupted 0x4 : The entry had residual IO or CPU boosts left",
                "reserved",
            ],
        }),
        0x00000154 => Some(BugcheckDescriptor {
            name: "UNEXPECTED_STORE_EXCEPTION",
            description: Some(
                "This bug check indicates that the kernel memory store component caught an unexpected exception.",
            ),
            arguments: [
                "pointer to the store context or data manager",
                "exception information",
                "reserved",
                "reserved",
            ],
        }),
        0x00000155 => Some(BugcheckDescriptor {
            name: "OS_DATA_TAMPERING",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x00000157 => Some(BugcheckDescriptor {
            name: "KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION",
            description: Some(
                "This indicates that an illegal operation was attempted on the priority floor of a particular thread.",
            ),
            arguments: [
                "the address of the thread",
                "the target priority value",
                "a status code indicating the nature of the violation 0x1 : The priority counter for the target priority over-flowed 0x2 : The priority counter for the target priority under-flowed 0x3 : The target priority value was i",
                "reserved",
            ],
        }),
        0x00000158 => Some(BugcheckDescriptor {
            name: "ILLEGAL_IOMMU_PAGE_FAULT",
            description: Some(
                "This indicates that the IOMMU has delivered a page fault packet for an invalid ASID. This is not safe since the ASID may have already been reused.",
            ),
            arguments: [
                "the invalid ASID",
                "the number of ASIDs currently in use",
                "the process using this ASID",
                "the ASID's reference count",
            ],
        }),
        0x00000159 => Some(BugcheckDescriptor {
            name: "HAL_ILLEGAL_IOMMU_PAGE_FAULT",
            description: Some(
                "This indicates that the IOMMU has delivered a page fault against an ASID that was in the process of being freed. The driver was responsible for completing any inflight requests before this point in time and this bugcheck indicates a driver in the system did not do so.",
            ),
            arguments: [
                "IOMMU vendor disambiguation",
                "fault packet or status, depending on parameter 1",
                "vendor-specific data or PASID, depending on parameter 1",
                "vendor-specific data or directory base, depending on parameter 1",
            ],
        }),
        0x0000015a => Some(BugcheckDescriptor {
            name: "SDBUS_INTERNAL_ERROR",
            description: Some(
                "This indicates that an unrecoverable hardware failure has occurred on an SD-attached device.",
            ),
            arguments: [
                "pointer to the internal SD work packet that caused the failure",
                "pointer the controller socket information",
                "pointer to the SD request packet sent down to the bus driver",
                "reserved",
            ],
        }),
        0x0000015b => Some(BugcheckDescriptor {
            name: "WORKER_THREAD_RETURNED_WITH_SYSTEM_PAGE_PRIORITY_ACTIVE",
            description: Some(
                "This indicates that a worker thread's system page priority was leaked by the called worker routine.",
            ),
            arguments: [
                "address of worker routine (do ln on this address to find the offending driver)",
                "current system page priority value",
                "WorkItem parameter",
                "WorkItem address",
            ],
        }),
        0x00000160 => Some(BugcheckDescriptor {
            name: "WIN32K_ATOMIC_CHECK_FAILURE",
            description: Some("This indicates that a Win32k function has violated an ATOMICCHECK."),
            arguments: [
                "count of functions on the stack currently inside of an ATOMIC operation",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x00000162 => Some(BugcheckDescriptor {
            name: "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE",
            description: Some(
                "This indicates that a lock tracked by AutoBoost was released by a thread that did not own the lock.",
            ),
            arguments: [
                "the address of the thread",
                "the lock address",
                "the session ID of the thread",
                "reserved",
            ],
        }),
        0x00000163 => Some(BugcheckDescriptor {
            name: "WORKER_THREAD_TEST_CONDITION",
            description: Some(
                "This indicates that a test for kernel worker threads raised a failure.",
            ),
            arguments: [
                "active test flags",
                "flag corresponding to the test that triggered the failure",
                "reserved",
                "reserved",
            ],
        }),
        0x00000164 => Some(BugcheckDescriptor {
            name: "WIN32K_CRITICAL_FAILURE",
            description: Some("This indicates that Win32k has encountered a critical failure."),
            arguments: [
                "1 - Type of the failure. 0x1 : REGION_VALIDATION_FAILURE- Region is out of surface bounds",
                "see parameter 1",
                "see parameter 1",
                "see parameter 1",
            ],
        }),
        0x0000016c => Some(BugcheckDescriptor {
            name: "INVALID_RUNDOWN_PROTECTION_FLAGS",
            description: Some(
                "This indicates that the flags supplied to one of the rundown protection APIs were invalid.",
            ),
            arguments: [
                "the invalid flags supplied by the caller",
                "the address of the rundown ref",
                "reserved",
                "reserved",
            ],
        }),
        0x0000016d => Some(BugcheckDescriptor {
            name: "INVALID_SLOT_ALLOCATOR_FLAGS",
            description: Some(
                "This indicates that the flags supplied to one of the slot allocator APIs were invalid.",
            ),
            arguments: [
                "the invalid flags supplied by the caller",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x0000016e => Some(BugcheckDescriptor {
            name: "ERESOURCE_INVALID_RELEASE",
            description: Some(
                "This indicates that the target thread pointer supplied to ExReleaseResourceForThreadLite was invalid.",
            ),
            arguments: [
                "the resource being released",
                "the current thread",
                "the incorrect target thread that was passed in",
                "reserved",
            ],
        }),
        0x00000170 => Some(BugcheckDescriptor {
            name: "CLUSTER_CSV_CLUSSVC_DISCONNECT_WATCHDOG",
            description: Some(
                "This indicates that Cluster disconnect is not making forward progress.",
            ),
            arguments: [
                "id of the thread that is handling cluster disconnect",
                "timeout in milliseconds",
                "reserved",
                "reserved",
            ],
        }),
        0x00000171 => Some(BugcheckDescriptor {
            name: "CRYPTO_LIBRARY_INTERNAL_ERROR",
            description: Some(
                "It indicates that an internal error in the crypto libraries occurred.",
            ),
            arguments: ["ID of failure", "reserved", "reserved", "reserved"],
        }),
        0x00000173 => Some(BugcheckDescriptor {
            name: "COREMSGCALL_INTERNAL_ERROR",
            description: Some(
                "This indicates that the CoreMessageCall detected an unrecoverable error.",
            ),
            arguments: ["type of the failure", "reserved", "reserved", "reserved"],
        }),
        0x00000174 => Some(BugcheckDescriptor {
            name: "COREMSG_INTERNAL_ERROR",
            description: Some("This indicates that CoreMessaging detected an unrecoverable error."),
            arguments: ["type of the failure", "reserved", "reserved", "reserved"],
        }),
        0x00000178 => Some(BugcheckDescriptor {
            name: "ELAM_DRIVER_DETECTED_FATAL_ERROR",
            description: Some("This indicates that ELAM driver detected a fatal error."),
            arguments: [
                "type of the failure. 0x0 : TPM attestation could not be revoked 2 - Pointer to the BDCB_IMAGE_INFORMATION structure for the driver being inspected 3 - TBS_RESULT failure code 0x10000 : ELAM-vendor defined failure 2 -",
                "see parameter 1",
                "see parameter 1",
                "(Optional) ELAM vendor supplied general purpose data block",
            ],
        }),
        0x0000017b => Some(BugcheckDescriptor {
            name: "PROFILER_CONFIGURATION_ILLEGAL",
            description: None,
            arguments: ["", "", "", ""],
        }),
        0x0000017e => Some(BugcheckDescriptor {
            name: "MICROCODE_REVISION_MISMATCH",
            description: Some(
                "It indicates that one or more processors in the multiprocessor configuration have inconsistent microcode loaded.",
            ),
            arguments: [
                "the processor CPUID signature value of the processor that mismatched",
                "the expected microcode revision for the processor",
                "the actual, reported microcode revision for the processor",
                "the processor index of the mismatching processor",
            ],
        }),
        0x00000187 => Some(BugcheckDescriptor {
            name: "VIDEO_DWMINIT_TIMEOUT_FALLBACK_BDD",
            description: Some(
                "This indicates that video fell back to BDD rather than using the IHV driver. This always generates a live dump.",
            ),
            arguments: [
                "reason Code. 0x1 : DWM failed to initialize after retries, stopping display adapters and falling back to BDD",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x00000189 => Some(BugcheckDescriptor {
            name: "BAD_OBJECT_HEADER",
            description: Some("This indicates that The OBJECT_HEADER has been corrupted."),
            arguments: [
                "pointer to bad OBJECT_HEADER",
                "pointer to the resulting OBJECT_TYPE based on the TypeIndex in the OBJECT_HEADER",
                "type of corruption. 0x0 : The type index is corrupt 0x1 : The object security descriptor is invalid",
                "reserved",
            ],
        }),
        0x0000018b => Some(BugcheckDescriptor {
            name: "SECURE_KERNEL_ERROR",
            description: Some(
                "This indicates that the secure kernel has encountered a fatal error.",
            ),
            arguments: ["reserved", "reserved", "reserved", "reserved"],
        }),
        0x0000018c => Some(BugcheckDescriptor {
            name: "HYPERGUARD_VIOLATION",
            description: Some(
                "This indicates that the kernel has detected that critical kernel code or data have been corrupted.",
            ),
            arguments: [
                "type of corrupted region - values listed below",
                "failure type dependent information",
                "reserved",
                "reserved",
            ],
        }),
        0x0000018d => Some(BugcheckDescriptor {
            name: "SECURE_FAULT_UNHANDLED",
            description: Some(
                "This indicates that a secure fault originating in the secure kernel could not be handled.",
            ),
            arguments: [
                "secure fault code bitmask - values below",
                "secure fault VA (only applicable to certain secure fault types)",
                "exception Record",
                "context Record",
            ],
        }),
        0x0000018e => Some(BugcheckDescriptor {
            name: "KERNEL_PARTITION_REFERENCE_VIOLATION",
            description: Some(
                "This indicates that a partition was improperly dereferenced, usually by a kernel-mode driver, or that serious kernel data corruption occurred.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x00000191 => Some(BugcheckDescriptor {
            name: "PF_DETECTED_CORRUPTION",
            description: None,
            arguments: ["reserved", "reserved", "reserved", "reserved"],
        }),
        0x00000192 => Some(BugcheckDescriptor {
            name: "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL",
            description: Some(
                "This indicates that a lock tracked by AutoBoost was acquired while executing at DISPATCH_LEVEL or above.",
            ),
            arguments: [
                "the address of the thread",
                "the lock address",
                "the IRQL at which the lock was acquired",
                "reserved",
            ],
        }),
        0x00000196 => Some(BugcheckDescriptor {
            name: "LOADER_ROLLBACK_DETECTED",
            description: Some(
                "This indicates that the version of the OS loader does not match the operating system.",
            ),
            arguments: [
                "loader security version",
                "OS security version",
                "reserved",
                "reserved",
            ],
        }),
        0x00000197 => Some(BugcheckDescriptor {
            name: "WIN32K_SECURITY_FAILURE",
            description: Some("This indicates a security failure was detected in win32k."),
            arguments: [
                "failure type 0x1 : An objects handle entry didn't point back to the object. 2 - Pointer to the object type 3 - Pointer to the object handle entry 4 - Expected object",
                "see parameter 1",
                "see parameter 1",
                "see parameter 1",
            ],
        }),
        0x00000199 => Some(BugcheckDescriptor {
            name: "KERNEL_STORAGE_SLOT_IN_USE",
            description: Some(
                "This indicates that the storage slot cannot be freed because there is an object using it.",
            ),
            arguments: [
                "the address of the storage array",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x0000019a => Some(BugcheckDescriptor {
            name: "WORKER_THREAD_RETURNED_WHILE_ATTACHED_TO_SILO",
            description: Some(
                "This indicates that a worker thread attached to a silo and did not detach before returning.",
            ),
            arguments: [
                "address of worker routine",
                "workitem parameter",
                "workitem address",
                "reserved",
            ],
        }),
        0x0000019b => Some(BugcheckDescriptor {
            name: "TTM_FATAL_ERROR",
            description: Some(
                "This indicates that the terminal topology manager experienced a fatal error.",
            ),
            arguments: [
                "failure type 0x1 : An terminal object could not be generated. 2 - The NT status code of the failure 3 - Reserved 4 - Reserved",
                "see parameter 1",
                "see parameter 1",
                "see parameter 1",
            ],
        }),
        0x0000019c => Some(BugcheckDescriptor {
            name: "WIN32K_POWER_WATCHDOG_TIMEOUT",
            description: Some(
                "This indicates that Win32k did not turn the monitor on in a timely manner.",
            ),
            arguments: [
                "win32k power-watchdog failure type",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        }),
        0x000001a0 => Some(BugcheckDescriptor {
            name: "TTM_WATCHDOG_TIMEOUT",
            description: Some(
                "It indicates that the terminal topology manager detected that for the configured timeouts some device specific operations did not complete.",
            ),
            arguments: [
                "failure type - values listed below",
                "pointer to the device",
                "pointer to the worker thread",
                "pointer to the callout routine",
            ],
        }),
        0x000001a2 => Some(BugcheckDescriptor {
            name: "WIN32K_CALLOUT_WATCHDOG_BUGCHECK",
            description: Some("It indicates that a callout to Win32k did not return promptly."),
            arguments: [
                "thread blocking prompt return from a Win32k callout",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x000001aa => Some(BugcheckDescriptor {
            name: "EXCEPTION_ON_INVALID_STACK",
            description: Some(
                "This BugCheck indicates that exception dispatch crossed over into an invalid kernel stack. This might indicate that the kernel stack pointer has become corrupted during exception dispatch or unwind (e.g. due to stack corruption of a frame pointer), or that a driver is executing off of a stack that is not a legal kernel stack.",
            ),
            arguments: [
                "pointer to the current stack",
                "estimated active kernel stack-limit type",
                "context record for the active exception dispatch",
                "exception record for the active exception",
            ],
        }),
        0x000001ab => Some(BugcheckDescriptor {
            name: "UNWIND_ON_INVALID_STACK",
            description: Some(
                "It indicates that an attempt was made to access memory outside of the valid kernel stack range. In particular, this BugCheck indicates that stack unwinding crossed over into an invalid kernel stack. This might indicate that the kernel stack pointer has become corrupted during exception dispatch or unwind (e.g. due to stack corruption of a frame pointer), or that a driver is executing off of a stack that is not a legal kernel stack.",
            ),
            arguments: [
                "pointer to the current stack",
                "estimated active kernel stack-limit type",
                "context record active when the invalid stack was encountered",
                "reserved (zero)",
            ],
        }),
        0x000001c6 => Some(BugcheckDescriptor {
            name: "FAST_ERESOURCE_PRECONDITION_VIOLATION",
            description: Some(
                "It indicates that a current thread is performing an invalid call to a fast resource routine.",
            ),
            arguments: [
                "violation type. See values below",
                "see values below",
                "see values below",
                "see values below",
            ],
        }),
        0x000001c7 => Some(BugcheckDescriptor {
            name: "STORE_DATA_STRUCTURE_CORRUPTION",
            description: Some(
                "It indicates that the store component detected a corruption in its data structures.",
            ),
            arguments: [
                "corruption ID. See values below",
                "see values below",
                "see values below",
                "see values below",
            ],
        }),
        0x000001c8 => Some(BugcheckDescriptor {
            name: "MANUALLY_INITIATED_POWER_BUTTON_HOLD",
            description: Some(
                "The system was configured to initiate a bugcheck when the user holds the power button for a specified length of time. This is a diagnostic bugcheck used to capture a dump when the system is about to be hard reset with a long power button hold.",
            ),
            arguments: [
                "time in milliseconds the power button was held down",
                "pointer to nt!_POP_POWER_BUTTON_TRIAGE_BLOCK",
                "reserved",
                "reserved",
            ],
        }),
        0x000001ca => Some(BugcheckDescriptor {
            name: "SYNTHETIC_WATCHDOG_TIMEOUT",
            description: Some(
                "A system wide watchdog has expired. This indicates that the system is hung and not processing timer ticks.",
            ),
            arguments: [
                "the time since the watchdog was last reset, in interrupt time",
                "the current interrupt time",
                "the current QPC timestamp",
                "the index of the clock processor",
            ],
        }),
        0x000001cb => Some(BugcheckDescriptor {
            name: "INVALID_SILO_DETACH",
            description: Some(
                "It indicates that a thread failed to detach from a silo before exiting.",
            ),
            arguments: [
                "pointer to the attached thread",
                "previously attached silo",
                "pointer to the thread's process",
                "reserved",
            ],
        }),
        0x000001cd => Some(BugcheckDescriptor {
            name: "INVALID_CALLBACK_STACK_ADDRESS",
            description: Some("The callback stack is a user mode address which is illegal."),
            arguments: ["", "", "", ""],
        }),
        0x000001ce => Some(BugcheckDescriptor {
            name: "INVALID_KERNEL_STACK_ADDRESS",
            description: Some(
                "An invalid initial kernel stack address was encountered during the context switch.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x000001cf => Some(BugcheckDescriptor {
            name: "HARDWARE_WATCHDOG_TIMEOUT",
            description: Some(
                "This indicates that the system is hung and not processing timer ticks.",
            ),
            arguments: [
                "the time since the watchdog was last reset, in interrupt time",
                "the current interrupt time",
                "the current QPC timestamp",
                "the index of the clock processor",
            ],
        }),
        0x000001d0 => Some(BugcheckDescriptor {
            name: "ACPI_FIRMWARE_WATCHDOG_TIMEOUT",
            description: Some(
                "ACPI driver failed to complete an operation in expected allotted time.",
            ),
            arguments: [
                "pointer to AMLI Context",
                "pointer to Unicode Name of the Aml Context",
                "pointer to ACPI Device Extension",
                "pointer to ACPI Triage Block",
            ],
        }),
        0x000001d2 => Some(BugcheckDescriptor {
            name: "WORKER_THREAD_INVALID_STATE",
            description: Some(
                "This indicates that an executive worker thread is in an invalid state.",
            ),
            arguments: [
                "type of failure",
                "address of the worker thread",
                "reserved",
                "reserved",
            ],
        }),
        0x000001d3 => Some(BugcheckDescriptor {
            name: "WFP_INVALID_OPERATION",
            description: Some(
                "This indicates that a Windows Filtering Platform callout performed an invalid operation.",
            ),
            arguments: [
                "the subtype of the bugcheck",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x000001d5 => Some(BugcheckDescriptor {
            name: "DRIVER_PNP_WATCHDOG",
            description: Some(
                "This indicates that a driver has failed to complete a PnP operation within a specific time.",
            ),
            arguments: [
                "first few character of the service associated with the devnode",
                "pointer to the nt!TRIAGE_PNP_WATCHDOG on Win10 RS4 and higher",
                "thread responsible for the PnP Watchdog",
                "milliseconds elapsed since the watchdog was armed",
            ],
        }),
        0x000001d6 => Some(BugcheckDescriptor {
            name: "WORKER_THREAD_RETURNED_WITH_NON_DEFAULT_WORKLOAD_CLASS",
            description: Some(
                "It indicates that a worker thread changed its workload class and did not revert it before returning.",
            ),
            arguments: [
                "address of worker routine (use ln on this to find the responsible driver)",
                "current workload class value",
                "WorkItem parameter",
                "WorkItem address",
            ],
        }),
        0x000001d7 => Some(BugcheckDescriptor {
            name: "EFS_FATAL_ERROR",
            description: Some(
                "It indicates that an EFS error condition has occurred such that cannot be handled without data loss or data corruption.",
            ),
            arguments: [
                "bug Check Subclass: 01 - Pre-offloading failure",
                "NTSTATUS return code of the operation",
                "the current IRP at the time of failure",
                "file encryption context at the time of failure",
            ],
        }),
        0x000001d8 => Some(BugcheckDescriptor {
            name: "UCMUCSI_FAILURE",
            description: Some(
                "It indicates that the UCSI class extension has encountered an error.",
            ),
            arguments: [
                "type of failure. VALUES: 0x0 : A UCSI command has timed out because the firmware did not respond to the command in time",
                "the UCSI command value",
                "if non-zero, the pointer to additional information (use dt UcmUcsiCx!UCMUCSICX_TRIAGE)",
                "reserved",
            ],
        }),
        0x000001d9 => Some(BugcheckDescriptor {
            name: "HAL_IOMMU_INTERNAL_ERROR",
            description: Some(
                "This indicates that an internal error was detected in the HAL IOMMU library.",
            ),
            arguments: [
                "indicates the failed operation; see values below",
                "see values below",
                "see values below",
                "see values below",
            ],
        }),
        0x000001da => Some(BugcheckDescriptor {
            name: "HAL_BLOCKED_PROCESSOR_INTERNAL_ERROR",
            description: Some(
                "It indicates that an internal error was detected in the blocked processor library.",
            ),
            arguments: [
                "type of failure - See below",
                "see below",
                "see below",
                "see below",
            ],
        }),
        0x000001db => Some(BugcheckDescriptor {
            name: "IPI_WATCHDOG_TIMEOUT",
            description: Some(
                "It indicates that a processor has been stuck in an IPI loop for more than the allowed time.",
            ),
            arguments: [
                "indicates QPC frequency",
                "indicates the current QPC",
                "indicates the baseline QPC",
                "reserved",
            ],
        }),
        0x000001dc => Some(BugcheckDescriptor {
            name: "DMA_COMMON_BUFFER_VECTOR_ERROR",
            description: Some(
                "It indicates that a driver has misused the DMA vectored common buffer APIs.",
            ),
            arguments: [
                "indicates the type of failure. See values below",
                "see values below",
                "see values below",
                "see values below",
            ],
        }),
        0x000001dd => Some(BugcheckDescriptor {
            name: "BUGCODE_MBBADAPTER_DRIVER",
            description: Some(
                "This indicates that the operating system encountered an error caused by a networking driver managed by MBBCx. MBBCx provides mobile broadband (MBB) media-specific functionality in the form of a KMDF-based MBB client driver for MBB devices. For more information, see Introduction to the Mobile Broadband (MBB) WDF class extension (MBBCx).",
            ),
            arguments: [
                "one of the following failure codes 0 - FailureCode_CorruptedPrivateGlobals 1 - FailureCode_IrqlIsNotPassive 2 - FailureCode_IrqlNotLessOrEqualDispatch 3 - FailureCode_InvalidStructTypeSize 4 - FailureCode_InvalidPower",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x000001de => Some(BugcheckDescriptor {
            name: "BUGCODE_WIFIADAPTER_DRIVER",
            description: Some(
                "This indicates that the operating system encountered an error caused by a networking driver managed by WiFiCx. The Wi-Fi WDF class extensions (WiFiCx) supports KMDF-based Wi-Fi client driver for Wi-Fi devices. For more information, see Introduction to the Wi-Fi WDF class extension (WiFiCx).",
            ),
            arguments: [
                "WiFiCx bugcheck subtype",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "reserved",
            ],
        }),
        0x000001df => Some(BugcheckDescriptor {
            name: "PROCESSOR_START_TIMEOUT",
            description: Some(
                "This indicates a processor failed to start in the allowed time. The processor start occurs very early in the operating system initialization.",
            ),
            arguments: [
                "virtual address of the processor state",
                "reserved",
                "NT processor number",
                "local unit ID for the processor",
            ],
        }),
        0x000001e4 => Some(BugcheckDescriptor {
            name: "VIDEO_DXGKRNL_SYSMM_FATAL_ERROR",
            description: Some(
                "This indicates that the Microsoft DirectX graphics kernel system memory manager has detected a violation.",
            ),
            arguments: [
                "the subcode of the BugCheck 0x1 : Invalid physical object type 0x2 : IOMMU enabled with invalid reason 0x3 : IOMMU disabled with invalid reason 0x4 : ADL is being built against non-locked memory 0x5 : Memory is being",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x000001e9 => Some(BugcheckDescriptor {
            name: "ILLEGAL_ATS_INITIALIZATION",
            description: Some(
                "This indicates that the driver has attempted to illegally enable the Address Translation Service (ATS) on a device which has been already been enabled for Shared Virtual Memory (SVM).",
            ),
            arguments: [
                "the physical device object",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x000001ea => Some(BugcheckDescriptor {
            name: "SECURE_PCI_CONFIG_SPACE_ACCESS_VIOLATION",
            description: Some(
                "This indicates that the access to the PCI config space region from VTL0 by directly mapping the PCI MCFG range is prohibited because secure PCI is enabled.",
            ),
            arguments: [
                "opcode that caused the exception",
                "RID of the device that caused the exception",
                "config space access offset",
                "address of the instruction that caused the exception",
            ],
        }),
        0x000001eb => Some(BugcheckDescriptor {
            name: "DAM_WATCHDOG_TIMEOUT",
            description: Some(
                "This indicates that the Desktop Activity Moderator (DAM) was unable to unfreeze non-exempt user session processes within the allocated time period after the device resumed from modern standby.",
            ),
            arguments: [
                "pointer to the DAM user session delay context",
                "reserved",
                "reserved",
                "reserved",
            ],
        }),
        0x000001ed => Some(BugcheckDescriptor {
            name: "HANDLE_ERROR_ON_CRITICAL_THREAD",
            description: Some(
                "This indicates that an invalid handle access problem was detected in kernel mode on a system-critical thread.",
            ),
            arguments: ["reserved", "reserved", "reserved", "reserved"],
        }),
        0x000001f1 => Some(BugcheckDescriptor {
            name: "KASAN_ENLIGHTENMENT_VIOLATION",
            description: Some(
                "It indicates that KASAN encountered an internal error. This bug check is used to check internal operation of KASAN in Windows. For more information, see Kernel Address Sanitizer (KASAN) and the Microsoft C++ AddressSanitizer (ASAN) documentation.",
            ),
            arguments: [
                "type of operation that led to the internal error",
                "type of the internal error",
                "extra information on the internal error",
                "extra information on the internal error",
            ],
        }),
        0x000001f2 => Some(BugcheckDescriptor {
            name: "KASAN_ILLEGAL_ACCESS",
            description: Some(
                "It indicates that Kernel Address Sanitizer (KASAN) detected an illegal memory access being made.",
            ),
            arguments: [
                "the address being accessed illegally",
                "size of the access",
                "the address of the caller",
                "extra information on the access - memory violation location KASAN shadow code.; Bits [0:7]: The KASAN shadow code. See the table below.; Bit 8: 1 if the access was a write, 0 if it was a read",
            ],
        }),
        0x00000356 => Some(BugcheckDescriptor {
            name: "XBOX_ERACTRL_CS_TIMEOUT",
            description: Some(
                "The eractrl.sys driver could not transition an Xbox console to or from connected standby within the allowed time.",
            ),
            arguments: ["CS exit", "reserved", "reserved", "reserved"],
        }),
        0x00000bfe => Some(BugcheckDescriptor {
            name: "BC_BLUETOOTH_VERIFIER_FAULT",
            description: Some("This indicates that a driver has caused a violation."),
            arguments: [
                "Bluetooth verifier fault subtype",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        }),
        0x00000bff => Some(BugcheckDescriptor {
            name: "BC_BTHMINI_VERIFIER_FAULT",
            description: Some(
                "This indicates that The Bluetooth miniport extensible driver verifier has caught a violation.",
            ),
            arguments: [
                "Bluetooth miniport verifier fault subtype",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
                "meaning depends on parameter 1",
            ],
        }),
        0x00020001 => Some(BugcheckDescriptor {
            name: "HYPERVISOR_ERROR",
            description: Some("This indicates that the hypervisor has encountered a fatal error."),
            arguments: ["reserved", "reserved", "reserved", "reserved"],
        }),
        0x1000007e => Some(BugcheckDescriptor {
            name: "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
            description: Some(
                "This indicates that a system thread generated an exception which the error handler did not catch.",
            ),
            arguments: [
                "the exception code that wasn't handled",
                "the address where the exception occurred",
                "the address of the exception record",
                "the address of the context record",
            ],
        }),
        0x1000007f => Some(BugcheckDescriptor {
            name: "UNEXPECTED_KERNEL_MODE_TRAP_M",
            description: Some(
                "This indicates that a trap was generated by the Intel CPU and the kernel failed to catch this trap.",
            ),
            arguments: ["", "", "", ""],
        }),
        0x1000008e => Some(BugcheckDescriptor {
            name: "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M",
            description: Some(
                "This indicates that a kernel-mode program generated an exception which the error handler did not catch.",
            ),
            arguments: [
                "the exception code that was not handled",
                "the address where the exception occurred",
                "the trap frame",
                "reserved",
            ],
        }),
        0x100000ea => Some(BugcheckDescriptor {
            name: "THREAD_STUCK_IN_DEVICE_DRIVER_M",
            description: Some(
                "This indicates that a thread in a device driver is endlessly spinning.",
            ),
            arguments: [
                "a pointer to the stuck thread object",
                "a pointer to the DEFERRED_WATCHDOG object",
                "a pointer to the offending driver name",
                "in the kernel debugger: The number of times the \"intercepted\" bug check 0xEA was hit On the blue screen: 1",
            ],
        }),
        0x4000008a => Some(BugcheckDescriptor {
            name: "THREAD_TERMINATE_HELD_MUTEX",
            description: Some(
                "This indicates that a driver acquired a mutex on a thread that exited before the mutex could be released. This can be caused by a driver returning to user mode without releasing a mutex or by a driver acquiring a mutex and then causing an exception that results in the thread it is running on, being terminated.",
            ),
            arguments: [
                "the address of the KTHREAD that owns the KMUTEX",
                "the address of the KMUTEX that is owned",
                "reserved",
                "reserved",
            ],
        }),
        0xc0000218 => Some(BugcheckDescriptor {
            name: "STATUS_CANNOT_LOAD_REGISTRY_FILE",
            description: Some("This indicates that a registry file could not be loaded."),
            arguments: [
                "address of the name of the registry hive that could not be loaded",
                "zero (Reserved)",
                "zero (Reserved)",
                "zero (Reserved)",
            ],
        }),
        0xc000021a => Some(BugcheckDescriptor {
            name: "WINLOGON_FATAL_ERROR",
            description: Some("This means that the Winlogon process terminated unexpectedly."),
            arguments: [
                "a string that identifies the problem",
                "the error code",
                "reserved",
                "reserved",
            ],
        }),
        0xc0000221 => Some(BugcheckDescriptor {
            name: "STATUS_IMAGE_CHECKSUM_MISMATCH",
            description: Some(
                "The bug check indicates that a driver or a system DLL is corrupted.",
            ),
            arguments: ["", "", "", ""],
        }),
        0xdeaddead => Some(BugcheckDescriptor {
            name: "MANUALLY_INITIATED_CRASH1",
            description: Some("This indicates that a manually initiated crash occurred."),
            arguments: ["reserved", "reserved", "reserved", "reserved"],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(code: u32, parameters: [u64; 4]) -> BugcheckInfo {
        BugcheckInfo {
            code,
            parameters,
            driver: None,
        }
    }

    #[test]
    fn trap_frame_parameter_mapping_matches_descriptors() {
        let frame = 0xffff_b000_1234_5000u64;
        // PANIC_STACK_SWITCH: arg1.
        assert_eq!(
            bugcheck_trap_frame_address(&info(0x2b, [frame, 0, 0, 0])),
            Some(frame)
        );
        // SET_OF_INVALID_CONTEXT: arg3.
        assert_eq!(
            bugcheck_trap_frame_address(&info(0x30, [1, 2, frame, 0])),
            Some(frame)
        );
        // KERNEL_MODE_EXCEPTION_NOT_HANDLED: arg3.
        assert_eq!(
            bugcheck_trap_frame_address(&info(0x8e, [0xc0000005, 0, frame, 0])),
            Some(frame)
        );
        // KERNEL_SECURITY_CHECK_FAILURE: arg2.
        assert_eq!(
            bugcheck_trap_frame_address(&info(0x139, [3, frame, 0, 0])),
            Some(frame)
        );
        // KERNEL_MODE_EXCEPTION_NOT_HANDLED_M: arg3.
        assert_eq!(
            bugcheck_trap_frame_address(&info(0x1000008e, [0xc0000005, 0, frame, 0])),
            Some(frame)
        );
        // UNSUPPORTED_INSTRUCTION_MODE: arg2.
        assert_eq!(
            bugcheck_trap_frame_address(&info(0x151, [0, frame, 0, 0])),
            Some(frame)
        );
    }

    #[test]
    fn trap_frame_requires_kernel_pointer() {
        // A zeroed or user-mode parameter is not chased.
        assert_eq!(
            bugcheck_trap_frame_address(&info(0x139, [3, 0, 0, 0])),
            None
        );
        assert_eq!(
            bugcheck_trap_frame_address(&info(0x8e, [0xc0000005, 0, 0x7ffe_0000, 0])),
            None
        );
    }

    #[test]
    fn codes_without_documented_trap_frames_yield_none() {
        let kernel_ptr = 0xffff_b000_1234_5000u64;
        for code in [0x0a, 0x1e, 0x3b, 0x50, 0x7e, 0xd1] {
            assert_eq!(
                bugcheck_trap_frame_address(&info(code, [kernel_ptr; 4])),
                None,
                "code {code:#x} must not claim a trap frame"
            );
        }
    }

    #[test]
    fn fault_ip_parameter_mapping_matches_descriptors() {
        let parameters = [0x1111, 0x2222, 0x3333, 0x4444];
        assert_eq!(bugcheck_fault_ip(&info(0x151, parameters)), Some(0x1111));
        for code in [0x1e, 0x3b, 0x7e, 0x8e, 0x1000007e, 0x1000008e] {
            assert_eq!(bugcheck_fault_ip(&info(code, parameters)), Some(0x2222));
        }
        for code in [0x50, 0xcc, 0xcd, 0xce, 0xcf, 0xd5, 0xd6] {
            assert_eq!(bugcheck_fault_ip(&info(code, parameters)), Some(0x3333));
        }
        for code in [0x0a, 0x2e, 0xc5, 0xd0, 0xd1, 0xd3, 0xd4, 0x1ea] {
            assert_eq!(bugcheck_fault_ip(&info(code, parameters)), Some(0x4444));
        }
        assert_eq!(bugcheck_fault_ip(&info(0xdead, parameters)), None);
    }

    #[test]
    fn conditional_argument_descriptions_follow_parameter_values() {
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x77, [1, 0, 0, 0]))[1],
            "value where the kernel-stack signature should be"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x77, [0xc000000e, 0, 0, 0]))[1],
            "I/O status code"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x7a, [3, 0, 0, 0]))[2],
            "current process when parameter 1 is 1; zero when it is 2 or 3"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x7a, [3, 0, 1, 0]))[2],
            "address of the InPageSupport structure"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x7a, [5, 0, 0, 0]))[0],
            "address of the page-table entry (PTE)"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x9f, [4, 0, 0, 0]))[1],
            "timeout in seconds"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x12b, [0, 0, 1, 1]))[0],
            "compressed-store failure status"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x131, [3, 0, 0, 0]))[1],
            "saved thread"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x133, [1, 0, 0, 0]))[1],
            "watchdog period"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x143, [2, 0, 0, 0]))[1],
            "invalid-state subtype"
        );
        assert_eq!(
            bugcheck_argument_descriptions(&info(0x159, [0x3001, 0, 0, 0]))[2],
            "PASID"
        );
    }

    #[test]
    fn minidump_aliases_reuse_base_parameter_schemas() {
        for (alias, base) in [
            (0x1000007e, 0x7e),
            (0x1000007f, 0x7f),
            (0x1000008e, 0x8e),
            (0x100000ea, 0xea),
        ] {
            assert_eq!(
                bugcheck_descriptor(alias).unwrap().arguments,
                bugcheck_descriptor(base).unwrap().arguments
            );
        }
    }

    #[test]
    fn page_fault_descriptor_covers_current_x64_values_and_subtype() {
        let descriptor = bugcheck_descriptor(0x50).unwrap();
        assert!(descriptor.arguments[1].contains("2 = modern write"));
        assert!(descriptor.arguments[1].contains("0x10 = execute"));
        assert!(descriptor.arguments[3].contains("page-fault subtype"));
    }

    #[test]
    fn d1_access_argument_documents_execute_faults() {
        let descriptor = bugcheck_descriptor(0xd1).unwrap();
        assert_eq!(
            descriptor.arguments[2],
            "value 0 = read operation, 1 = write operation, 2 or 8 = execute operation"
        );
    }
}
