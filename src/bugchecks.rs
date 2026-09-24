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
    /// Symbol for the frame's instruction pointer, when the frame decoded.
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
    /// Set only when the data was not where it should have been, naming
    /// where it was instead: `nt!KiBugCheckData` holding a pointer to the
    /// real slots rather than the slots themselves. `None` is the normal
    /// case, including every bugcheck the target reported itself.
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

/// The file name at the end of a Windows or POSIX module path.
pub fn module_filename(name: &str) -> &str {
    name.rsplit(['\\', '/']).next().unwrap_or(name)
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
        .map(|module| module_filename(&module.name).to_owned())
        .filter(|name| name.to_ascii_lowercase().ends_with(".sys"))
        .or_else(|| {
            debugger
                .symbols
                .find_module_for_address(trace.kernel_dtb, VirtAddr(address))
                .map(|module| module_filename(&module.name).to_owned())
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
    const VERIFIER_C4_F6_ARGS: [&str; 4] = [
        "violation type: a kernel handle was referenced as a user-mode handle",
        "handle value",
        "current process",
        "address inside the driver that referenced the handle",
    ];
    const VERIFIER_E6_26_ARGS: [&str; 4] = [
        "violation type: an IOMMU detected a DMA violation",
        "device object of the faulting device",
        "fault information (usually the physical address)",
        "fault type (hardware-specific)",
    ];

    match info.code {
        0x0000_00c4 if info.parameters[0] == 0xf6 => VERIFIER_C4_F6_ARGS,
        0x0000_00e6 if info.parameters[0] == 0x26 => VERIFIER_E6_26_ARGS,
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
                .map(|frame| format_symbol(debugger, &trace, frame.instruction_pointer()));
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
    let address = match debugger
        .symbols
        .find_symbol_across_modules(kernel_dtb, "nt!KiBugCheckData")
    {
        Ok(Some(address)) => address,
        Ok(None) => return CurrentBugcheckResolution::SymbolUnavailable,
        Err(error) => {
            return CurrentBugcheckResolution::Unresolved(CurrentBugcheckFailure {
                address: VirtAddr(0),
                slots: None,
                dereferenced_slots: None,
                reason: error.to_string(),
            });
        }
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

pub use table::bugcheck_descriptor;

mod table;

#[cfg(test)]
mod tests;
