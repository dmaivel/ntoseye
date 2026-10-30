//! Presentation-free crash triage aggregation shared by debugger frontends.

mod blackbox;
pub mod crash_context;
mod culprit;
pub mod hang;
pub mod power;
mod signature;

pub mod user;
mod verifier;
mod whea;

use ntoseye_macros::record;

use crate::base::types::VirtAddr;
use crate::nt::bugchecks::{
    BugcheckAnalysis, bugcheck_trap_frame_on_stack, fault_at_trap_frame, module_filename,
    trap_on_stack_is_the_fault,
};
use crate::nt::dmp::triage::TriagePrcbInfo;
use crate::nt::dmp::{DmpException, DmpInfo, DmpSystemInfo, UnloadedDriver};
use crate::nt::guest::ModuleInfo;
use crate::nt::unwind::{StackTrace, resolve_thread_trace_context};
use crate::session::{RunStatus, Session};
use blackbox::blackbox_findings;
pub use crash_context::TriageCrashInfo;
use culprit::culprit_attribution;
pub use power::{
    POWER_THREAD_STACK_LIMIT, PowerFailureFinding, PowerFailureThread, PowerThreadRole,
    power_failure_finding,
};
use signature::failure_signature;
pub use user::{
    CodeOwner, ExceptionParameter, UserDumpTriage, UserExceptionFinding, UserFrame,
    UserProcessSummary, UserStackSource, UserStackThread,
};
use verifier::verifier_finding;
use whea::{decode_whea_record, whea_without_memory};

/// Canonical crash-code kind used by a failure signature: `bugcheck` or
/// `exception`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCodeKind {
    Bugcheck,
    Exception,
}

/// The source of a failure signature's location: `bugcheck_fault`,
/// `exception_address`, `current_instruction`, `top_frame`,
/// `power_failure_driver` (the driver a 0x9F names),
/// `first_non_system_frame` (on a user-mode minidump, the first frame
/// outside the system modules), or `code_only`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureSignatureSource {
    BugcheckFault,
    ExceptionAddress,
    CurrentInstruction,
    TopFrame,
    /// The driver a DRIVER_POWER_STATE_FAILURE names: the one that holds
    /// the blocked power IRP, or the one whose device or driver object the
    /// parameters give.
    PowerFailureDriver,
    /// On a user-mode minidump, the first frame outside the system modules,
    /// which called the system code that raised the exception.
    FirstNonSystemFrame,
    CodeOnly,
}

/// A deterministic identity for a failure that does not depend on
/// addresses, so you can use it to compare failures.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureSignature {
    pub code_kind: FailureCodeKind,
    /// The bugcheck or exception code.
    #[record(hex)]
    pub code: u32,
    /// The module at the failing location.
    pub module: Option<String>,
    /// The symbol at the failing location.
    pub symbol: Option<String>,
    pub source: FailureSignatureSource,
    /// The ordered parts that make `bucket`.
    pub components: Vec<String>,
    /// The failure bucket.
    pub bucket: String,
}

/// How sure an attribution is: `low`, `medium`, or `high`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CulpritConfidence {
    Low,
    Medium,
    High,
}

/// What an item of culprit evidence is: `recorded_broken_driver`,
/// `recorded_bugcheck_driver`, `bugcheck_fault_address`,
/// `exception_address`, `current_instruction`, `top_frame`,
/// `power_failure_driver`, `pnp_lock_owner_stack`, or
/// `first_non_system_frame`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CulpritEvidenceKind {
    RecordedBrokenDriver,
    RecordedBugcheckDriver,
    BugcheckFaultAddress,
    ExceptionAddress,
    CurrentInstruction,
    TopFrame,
    /// A DRIVER_POWER_STATE_FAILURE names the driver.
    PowerFailureDriver,
    /// The thread that holds the PnP lock in a 0x9F/0x4 runs in the module.
    PnpLockOwnerStack,
    /// On a user-mode minidump, the first frame outside the system modules
    /// on the faulting thread's stack is in the module.
    FirstNonSystemFrame,
}

/// One item of evidence for a culprit attribution.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CulpritEvidence {
    pub kind: CulpritEvidenceKind,
    pub detail: String,
    /// The address that the evidence uses, if the evidence is an address.
    #[record(hex)]
    pub address: Option<u64>,
}

/// What the available evidence identifies as the cause of the crash: a
/// module, or on a user-mode minidump, generated code no module holds.
/// Absence means the evidence was not sufficient to name a non-kernel
/// culprit.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CulpritAttribution {
    pub subject: CulpritSubject,
    pub confidence: CulpritConfidence,
    /// The evidence that points to the culprit.
    pub evidence: Vec<CulpritEvidence>,
}

/// What a culprit attribution names: `kind` `module` (`module`, its name),
/// or `dynamic_code` (`dynamic_code`: JIT-compiled or generated code that a
/// dynamic function table covers, on a user-mode minidump).
#[record(tagged)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CulpritSubject {
    Module(String),
    /// On a user-mode minidump, code no module holds that a dynamic
    /// function table covers: JIT-compiled or otherwise generated code.
    DynamicCode(DynamicCodeCulprit),
}

/// Generated code a culprit attribution names: no module holds it, and a
/// dynamic function table the process registered covers it.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicCodeCulprit {
    /// The blamed frame's address.
    #[record(hex)]
    pub address: u64,
    /// The dynamic function table covering it, `table_start..table_end`.
    #[record(hex)]
    pub table_start: u64,
    #[record(hex)]
    pub table_end: u64,
    /// The first frame further out that a module holds: the module code
    /// that called into the generated code.
    pub caller: Option<UserFrame>,
}

impl CulpritAttribution {
    /// The module the attribution names; `None` for generated code.
    pub fn module(&self) -> Option<&str> {
        match &self.subject {
            CulpritSubject::Module(module) => Some(module),
            CulpritSubject::DynamicCode(_) => None,
        }
    }
}

/// A verifier bugcheck parameter and what it means for the subcode.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierArgument {
    #[record(hex)]
    pub value: u64,
    pub description: String,
}

/// An address in a verifier bugcheck, and its role.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierAddress {
    pub role: String,
    #[record(hex)]
    pub address: u64,
}

/// A Driver Verifier bugcheck, decoded from its subcode.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierFinding {
    #[record(hex)]
    pub bugcheck_code: u32,
    pub bugcheck_name: String,
    /// The verifier subcode (the first bugcheck parameter).
    #[record(hex)]
    pub subcode: u64,
    /// `True` if the decoder recognizes the subcode.
    pub known_subcode: bool,
    /// What the subcode means, or `unknown verifier subcode`.
    pub subcode_description: String,
    /// The bugcheck parameters, with descriptions for the subcode.
    pub arguments: Vec<VerifierArgument>,
    /// The driver that ntoseye attributes the violation to.
    pub associated_driver: Option<String>,
    /// The addresses in the parameters, with their roles.
    pub addresses: Vec<VerifierAddress>,
}

/// What a WHEA section holds: `processor_generic`, `memory`,
/// `pci_express`, `x64_processor`, or `unknown`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WheaSectionKind {
    ProcessorGeneric,
    Memory,
    PciExpress,
    X64Processor,
    Unknown,
}

/// One section of a WHEA error record.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheaSection {
    /// The section's offset in the record, in bytes.
    pub offset: u32,
    /// The section's length in bytes.
    pub length: u32,
    /// The section's error severity.
    pub severity: u32,
    /// The section type GUID.
    pub section_type: String,
    pub kind: WheaSectionKind,
}

/// A decoded WHEA error record.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheaRecord {
    #[record(hex)]
    pub revision: u16,
    /// The record's error severity (`WHEA_ERROR_SEVERITY`).
    pub severity: u32,
    /// The record's length in bytes.
    pub length: u32,
    pub sections: Vec<WheaSection>,
}

/// A WHEA error record, `decoded`, or `unavailable` with the `reason`.
#[record(tagged)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WheaRecordState {
    Decoded(WheaRecord),
    Unavailable { reason: String },
}

/// The WHEA error record of a hardware-error bugcheck.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheaFinding {
    /// The address of the record. `None` if the bugcheck does not give one.
    #[record(hex)]
    pub record_address: Option<u64>,
    pub state: WheaRecordState,
}

/// A blackbox record of a crash dump: `pnp`, `ntfs`, `bsd`, or `winlogon`.
#[record]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlackboxKind {
    Pnp,
    Ntfs,
    Bsd,
    Winlogon,
}

/// What a dump holds of a blackbox: `decoded` (with `summary`, what it holds
/// in one line), `malformed` (with the `reason`), or `absent`.
#[record(tagged)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlackboxState {
    /// The dump has the block, and it decodes; `summary` says what it holds.
    Decoded { summary: String },
    /// The dump has the block, but it does not decode.
    Malformed { reason: String },
    /// The dump has no block for the blackbox.
    Absent,
}

/// A blackbox record (pnp, ntfs, bsd, winlogon) of a crash dump: a block of
/// its tagged data that ntoseye decodes as WinDbg's `!blackbox*` commands do.
#[record]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackboxFinding {
    pub kind: BlackboxKind,
    /// `PnP`, `NTFS`, `BSD`, or `Winlogon`.
    pub name: String,
    /// The command that shows the whole record, such as `!blackboxpnp`.
    pub command: &'static str,
    /// The block's size in bytes. `None` if the dump has no block.
    pub size: Option<u64>,
    pub state: BlackboxState,
}

/// Maximum number of frames collected for a one-shot triage report.
pub const TRIAGE_BACKTRACE_LIMIT: usize = 64;

/// The one-shot crash triage report (`!analyze`), with the run status, the
/// bugcheck or exception, the backtrace, the modules, the dump records, and
/// the findings.
#[record(impl)]
#[derive(Debug, Clone)]
pub struct TriageReport {
    /// The target's run status.
    pub status: RunStatus,
    /// The bugcheck, if the target is in a bugcheck.
    pub bugcheck: Option<BugcheckAnalysis>,
    /// The exception that a dump recorded.
    pub exception: Option<DmpException>,
    /// The system information of the dump.
    pub system_info: Option<DmpSystemInfo>,
    /// The stack of the current thread (see the `backtrace` property).
    #[record(skip)]
    pub backtrace: Option<StackTrace>,
    /// The loaded modules.
    pub modules: Vec<ModuleInfo>,
    /// The drivers the system unloaded recently, as the crash dump records
    /// them.
    pub unloaded_drivers: Vec<UnloadedDriver>,
    /// The process and thread that crashed, as a triage dump recorded them.
    pub crash_context: Option<TriageCrashInfo>,
    /// The processor that crashed, as a triage dump recorded it.
    pub prcb: Option<TriagePrcbInfo>,
    /// The driver that the dump records as broken.
    pub broken_driver: Option<String>,
    /// `True` if the triage data of the dump overflowed. `None` if the
    /// target is not a dump.
    pub triage_overflowed: Option<bool>,
    pub failure_signature: Option<FailureSignature>,
    /// What the evidence identifies as the cause: a module, or on a
    /// user-mode minidump, JIT-compiled code. `None` if the evidence
    /// identifies neither a non-kernel (or, on a user dump, non-system)
    /// module nor generated code.
    pub culprit: Option<CulpritAttribution>,
    /// The Driver Verifier violation of a verifier bugcheck.
    pub verifier: Option<VerifierFinding>,
    /// The hardware error record of a WHEA bugcheck.
    pub whea: Option<WheaFinding>,
    pub blackboxes: Vec<BlackboxFinding>,
    /// The KMDF driver whose In-Flight Recorder log the dump holds.
    pub kmdf_log: Option<KmdfLogFinding>,
    /// What a DRIVER_POWER_STATE_FAILURE names as stuck.
    pub power: Option<PowerFailureFinding>,
    /// What a user-mode minidump adds: the process, the exception decoded,
    /// and the frame the failure is blamed on. `None` for a kernel target.
    pub user: Option<UserDumpTriage>,
    /// Failures in best-effort data collection that did not stop the
    /// report.
    pub warnings: Vec<String>,
}

#[record]
impl TriageReport {
    /// The stack of the current thread. `None` while the target runs or if
    /// the unwind failed (see `warnings`).
    #[record(getter, rename = "backtrace")]
    pub fn backtrace_frames(&self) -> Option<Vec<crate::nt::unwind::StackFrame>> {
        self.backtrace.as_ref().map(|trace| trace.frames.clone())
    }
}

/// The client driver whose In-Flight Recorder log Wdf01000 copied into a
/// crash dump, and how many records it holds (`!wdfkd.wdfcrashdump` shows
/// them).
#[record]
#[derive(Debug, Clone)]
pub struct KmdfLogFinding {
    pub driver: String,
    pub records: usize,
}

impl TriageReport {
    /// Aggregate all data used by the MCP and REPL triage surfaces.
    ///
    /// Enumeration and unwinding are best-effort so a partial or live target
    /// still produces the directly available crash/status data.
    pub fn build(session: &mut Session) -> Self {
        // A user dump has no kernel to read a bugcheck, kernel modules, or
        // any of the kernel findings from.
        if let Some(report) = user::build(session) {
            return report;
        }
        let status = session.run_status();
        let mut bugcheck = session.bugcheck();
        let mut warnings = Vec::new();
        let mut backtrace = if status.running {
            None
        } else {
            match session.backtrace(TRIAGE_BACKTRACE_LIMIT) {
                Ok(trace) => Some(trace),
                Err(error) => {
                    warnings.push(format!("backtrace: {error}"));
                    None
                }
            }
        };
        if bugcheck.is_some()
            && let Some(trace) = backtrace.as_mut()
        {
            trim_bugcheck_callbacks(trace);
        }
        // A bugcheck raised from a trap handler names no trap frame; the stack
        // crossed it on the way to the fault.
        if let (Some(analysis), Some(trace)) = (bugcheck.as_mut(), backtrace.as_ref())
            && analysis.trap_frames.is_empty()
            && let Some(trap_frame) = bugcheck_trap_frame_on_stack(&session.target, trace)
        {
            if trap_on_stack_is_the_fault(analysis.code) && analysis.fault.is_none() {
                let trace =
                    resolve_thread_trace_context(&session.target, session.target.kernel_dtb());
                analysis.fault = fault_at_trap_frame(&session.target, &trace, &trap_frame);
                if analysis.driver.is_none() {
                    analysis.driver = analysis
                        .fault
                        .as_ref()
                        .and_then(|fault| fault.driver.clone());
                }
            }
            analysis.trap_frames.push(trap_frame);
        }
        let modules = match session.target.kernel_modules() {
            Ok(modules) => modules,
            Err(error) => {
                warnings.push(format!("kernel modules: {error}"));
                Vec::new()
            }
        };
        let crash_context = TriageCrashInfo::from_dump(&session.target);

        let mut report = Self::assemble(
            status,
            bugcheck,
            backtrace,
            modules,
            crash_context,
            session.target.phys.dmp_info(),
        );
        report.warnings = warnings;
        report.kmdf_log = session
            .target
            .wdf_crash_log()
            .ok()
            .map(|log| KmdfLogFinding {
                driver: log.driver,
                records: log.entries.len(),
            });
        if let Some(address) = report.whea.as_ref().and_then(|whea| whea.record_address) {
            report.whea = Some(WheaFinding {
                record_address: Some(address),
                state: decode_whea_record(&session.target.context_memory(), address),
            });
        }
        report.power = report.bugcheck.as_ref().and_then(|bugcheck| {
            let parameters: Vec<u64> = bugcheck.args.iter().map(|arg| arg.value).collect();
            power_failure_finding(session, bugcheck.code, &parameters)
        });
        if report.power.is_some() {
            report.failure_signature = failure_signature(&report);
            report.culprit = culprit_attribution(&report);
        }
        report
    }

    fn assemble(
        status: RunStatus,
        bugcheck: Option<BugcheckAnalysis>,
        backtrace: Option<StackTrace>,
        modules: Vec<ModuleInfo>,
        crash_context: Option<TriageCrashInfo>,
        dump: Option<&DmpInfo>,
    ) -> Self {
        let blackboxes = dump
            .map(|d| blackbox_findings(&d.tagged_blocks))
            .unwrap_or_default();
        let mut report = Self {
            status,
            bugcheck,
            exception: dump.and_then(|d| d.exception.clone()),
            system_info: dump.and_then(|d| d.system_info.clone()),
            backtrace,
            modules,
            unloaded_drivers: dump.map(|d| d.unloaded_drivers.clone()).unwrap_or_default(),
            crash_context,
            prcb: dump.and_then(|d| d.triage_prcb_info.clone()),
            broken_driver: dump.and_then(|d| d.broken_driver.clone()),
            triage_overflowed: dump.map(|d| d.triage_overflowed),
            failure_signature: None,
            culprit: None,
            verifier: None,
            whea: None,
            blackboxes,
            kmdf_log: None,
            power: None,
            user: None,
            warnings: Vec::new(),
        };
        report.failure_signature = failure_signature(&report);
        report.culprit = culprit_attribution(&report);
        report.verifier = report.bugcheck.as_ref().and_then(verifier_finding);
        report.whea = report.bugcheck.as_ref().and_then(whea_without_memory);
        report
    }

    /// Whether a loaded module contains a directly recorded fault, exception,
    /// current-instruction, or stack-frame address (or is the recorded broken
    /// driver from a triage dump).
    pub fn loaded_module_is_relevant(&self, module: &ModuleInfo) -> bool {
        self.recorded_address_in(module.base_address.0, module.end_address().0)
            || self
                .broken_driver
                .as_deref()
                .is_some_and(|name| module_name_matches(name, module))
    }

    /// Whether an unloaded-driver range contains a directly recorded address
    /// or its name matches the dump's recorded broken-driver metadata.
    pub fn unloaded_driver_is_relevant(&self, driver: &UnloadedDriver) -> bool {
        self.recorded_address_in(driver.start_address, driver.end_address)
            || self
                .broken_driver
                .as_deref()
                .is_some_and(|name| names_match(name, &driver.name))
    }

    /// The instruction the evidence takes as current: where the target
    /// stopped, unless the backtrace starts at the bugcheck's
    /// `nt!KeBugCheckEx` frame below it (see [`trim_bugcheck_callbacks`]),
    /// where a dump that Windows wrote would have stopped.
    pub(super) fn current_instruction(&self) -> Option<u64> {
        let rip = self.status.rip?;
        match self
            .backtrace
            .as_ref()
            .and_then(|trace| trace.frames.first())
        {
            Some(top)
                if self.bugcheck.is_some()
                    && top.ip != rip
                    && symbol_is_function(&top.symbol, "nt!KeBugCheckEx") =>
            {
                Some(top.ip)
            }
            _ => Some(rip),
        }
    }

    fn recorded_address_in(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return false;
        }
        let contains = |address: u64| address >= start && address < end;

        self.status.rip.is_some_and(contains)
            || self.exception.as_ref().is_some_and(|e| contains(e.address))
            || self
                .bugcheck
                .as_ref()
                .and_then(|b| b.fault.as_ref())
                .is_some_and(|f| contains(f.ip))
            || self
                .backtrace
                .as_ref()
                .is_some_and(|trace| trace.frames.iter().any(|frame| contains(frame.ip)))
    }
}

/// Start a bugcheck's stack at its `nt!KeBugCheckEx` frame, dropping the
/// bugcheck callbacks that `nt!KeBugCheck2` runs above it. A dump that
/// Windows writes holds the context `KeBugCheckEx` captured. A dump that
/// QEMU writes (`dump-guest-memory -w`) holds the registers at dump time,
/// which libvirt takes when pvpanic's callback reports the crash:
/// `pvpanic+0x10cf` <- `nt!KiScanBugCheckCallbackList` <- `nt!KeBugCheck2` <-
/// `nt!KeBugCheckEx`. That callback is not where the crash happened. `k`
/// still walks the whole stack.
fn trim_bugcheck_callbacks(trace: &mut StackTrace) {
    let Some(bugcheck) = trace
        .frames
        .iter()
        .position(|frame| symbol_is_function(&frame.symbol, "nt!KeBugCheckEx"))
    else {
        return;
    };
    if trace.frames[..bugcheck]
        .iter()
        .any(|frame| symbol_is_function(&frame.symbol, "nt!KeBugCheck2"))
    {
        trace.frames.drain(..bugcheck);
    }
}

/// Whether a frame's symbol (`nt!KeBugCheckEx+0x107`) is in `function`.
fn symbol_is_function(symbol: &str, function: &str) -> bool {
    let symbol = symbol.split_whitespace().next().unwrap_or_default();
    let name = symbol.split_once('+').map_or(symbol, |(name, _)| name);
    name.eq_ignore_ascii_case(function)
}

fn evidence_module_for_address(report: &TriageReport, address: u64) -> Option<&str> {
    report
        .modules
        .iter()
        .find(|module| module.contains_address(VirtAddr(address)))
        .map(|module| module.name.as_str())
        .or_else(|| {
            report
                .unloaded_drivers
                .iter()
                .find(|driver| address >= driver.start_address && address < driver.end_address)
                .map(|driver| driver.name.as_str())
        })
}

/// `name`'s file name without a `.sys` or `.exe` extension.
fn module_stem(name: &str) -> &str {
    let filename = module_filename(name);
    filename
        .rsplit_once('.')
        .filter(|(_, extension)| {
            extension.eq_ignore_ascii_case("sys") || extension.eq_ignore_ascii_case("exe")
        })
        .map(|(stem, _)| stem)
        .unwrap_or(filename)
}

fn canonical_module_component(name: &str) -> String {
    module_stem(name).to_ascii_lowercase()
}

fn module_name_matches(recorded: &str, module: &ModuleInfo) -> bool {
    names_match(recorded, &module.name) || names_match(recorded, &module.short_name)
}

fn names_match(left: &str, right: &str) -> bool {
    module_stem(left).eq_ignore_ascii_case(module_stem(right))
}

#[cfg(test)]
mod tests {
    use super::user::UserExceptionKind;
    use super::*;
    use crate::arch::Arch;
    use crate::arch::RegisterFile;
    use crate::base::types::VirtAddr;
    use crate::nt::bugchecks::{BugcheckArg, BugcheckFault};
    use crate::nt::dmp::triage::TriageDriver;
    use crate::nt::guest::ProcessInfo;
    use crate::nt::symbols::CodeFrame;
    use crate::nt::target::power::{DeviceDriver, PowerCulprit, PowerFailure};
    use crate::nt::unwind::{FrameSource, StackFrame};
    use crate::session::RunStatus;

    fn bugcheck(
        code: u32,
        args: [u64; 4],
        fault: Option<(u64, &str, Option<&str>)>,
    ) -> BugcheckAnalysis {
        BugcheckAnalysis {
            code,
            name: format!("BUGCHECK_{code:08X}"),
            description: None,
            driver: fault.and_then(|(_, _, driver)| driver.map(str::to_string)),
            args: args
                .into_iter()
                .map(|value| BugcheckArg {
                    value,
                    description: String::new(),
                })
                .collect(),
            fault: fault.map(|(ip, symbol, driver)| BugcheckFault {
                ip,
                symbol: symbol.into(),
                driver: driver.map(str::to_string),
            }),
            trap_frames: Vec::new(),
            source: Some("synthetic test".into()),
        }
    }

    fn status(running: bool, rip: Option<u64>) -> RunStatus {
        RunStatus {
            running,
            current_thread: "p0.1".into(),
            rip,
            symbol: rip.map(|_| "sample!fault".into()),
            saved_vtl: Vec::new(),
            serving: None,
            running_vp: None,
            attached_process: Some(ProcessInfo {
                pid: 4,
                name: "System".into(),
                dtb: 0x1a_d000,
                eprocess: VirtAddr(0xffff_8000_0000_1000),
                wow64_peb: None,
            }),
            stopped_process: None,
            stopped_thread: None,
            coherent: true,
            kernel_base: 0xffff_f800_0000_0000,
            partition: None,
        }
    }

    fn dump_info() -> DmpInfo {
        DmpInfo {
            directory_table_base: 0x1ad000,
            bug_check_code: 0x50,
            bug_check_parameters: [1, 2, 3, 4],
            context: RegisterFile::empty(Arch::Amd64),
            offset_prcb_context: None,
            number_processors: 2,
            is_triage: true,
            ps_loaded_module_list: 0,
            debugger_data_block: None,
            triage_drivers: vec![TriageDriver {
                name: "sample.sys".into(),
                base: 0xffff_f800_1000_0000,
                size: 0x4000,
                checksum: 0,
                time_date_stamp: 0x1234,
            }],
            exception: Some(DmpException {
                code: 0xc0000005,
                flags: 0,
                address: 0xffff_f800_1000_1234,
                parameters: vec![0, 0xdeadbeef],
            }),
            system_info: Some(DmpSystemInfo {
                major_version: 10,
                minor_version: 22621,
                system_time: 133_000_000_000_000_000,
                system_up_time: 90_000_000,
                product_type: 1,
                suite_mask: 0x110,
                machine_image_type: 0x8664,
                service_pack_build: 42,
            }),
            unloaded_drivers: vec![UnloadedDriver {
                name: "old.sys".into(),
                start_address: 0xffff_f800_2000_0000,
                end_address: 0xffff_f800_2000_3000,
            }],
            triage_process_snapshot: Some(vec![1, 2]),
            triage_thread_snapshot: Some(vec![3, 4]),
            tagged_blocks: Vec::new(),
            triage_prcb_info: Some(TriagePrcbInfo {
                current_thread: 0xffff_8000_1234_0000,
                processor_number: 1,
                mhz: 3600,
                cpu_type: 6,
                vendor_string: "GenuineIntel".into(),
            }),
            broken_driver: Some("sample.sys".into()),
            triage_overflowed: true,
            triage_signature_valid: true,
            kern_base: Some(0xffff_f800_0000_0000),
        }
    }

    #[test]
    fn live_report_has_no_dump_metadata_and_matches_recorded_addresses() {
        let modules = vec![
            ModuleInfo::new("fault.sys".into(), VirtAddr(0x1000), 0x100),
            ModuleInfo::new("other.sys".into(), VirtAddr(0x3000), 0x100),
        ];
        let trace = StackTrace {
            frames: vec![StackFrame {
                sp: 0x8000,
                ip: 0x1040,
                symbol: "fault!dispatch".into(),
                source: FrameSource::Current,
                source_location: None,
                machine_frame: None,
                code: CodeFrame::at(VirtAddr(0x1040)),
                inline: false,
            }],
            truncated: 0,
        };

        let report = TriageReport::assemble(
            status(false, Some(0x1040)),
            None,
            Some(trace),
            modules,
            None,
            None,
        );

        assert!(report.exception.is_none());
        assert!(report.system_info.is_none());
        assert!(report.unloaded_drivers.is_empty());
        assert_eq!(report.triage_overflowed, None);
        assert!(report.loaded_module_is_relevant(&report.modules[0]));
        assert!(!report.loaded_module_is_relevant(&report.modules[1]));
    }

    #[test]
    fn recorded_broken_driver_name_is_directly_relevant() {
        let dump = dump_info();
        let module = ModuleInfo::new(
            "\\SystemRoot\\System32\\drivers\\sample.sys".into(),
            VirtAddr(0x5000),
            0x100,
        );
        let report = TriageReport::assemble(
            status(false, None),
            None,
            None,
            vec![module],
            None,
            Some(&dump),
        );

        assert!(report.loaded_module_is_relevant(&report.modules[0]));
        assert!(!report.unloaded_driver_is_relevant(&report.unloaded_drivers[0]));
    }
    #[test]
    fn failure_signature_is_stable_across_addresses_and_symbol_offsets() {
        let first = TriageReport::assemble(
            status(false, Some(0x1010)),
            Some(bugcheck(
                0x50,
                [0; 4],
                Some((0x1010, "Sample!Dispatch+0x10", Some("sample.sys"))),
            )),
            None,
            vec![ModuleInfo::new(
                "sample.sys".into(),
                VirtAddr(0x1000),
                0x100,
            )],
            None,
            None,
        );
        let second = TriageReport::assemble(
            status(false, Some(0x9010)),
            Some(bugcheck(
                0x50,
                [0; 4],
                Some((0x9010, "sample!dispatch+0x88", Some("sample.sys"))),
            )),
            None,
            vec![ModuleInfo::new(
                "sample.sys".into(),
                VirtAddr(0x9000),
                0x100,
            )],
            None,
            None,
        );

        let first = first.failure_signature.unwrap();
        let second = second.failure_signature.unwrap();
        assert_eq!(first.components, second.components);
        assert_eq!(first.bucket, "bugcheck:00000050|symbol:sample!dispatch");
        assert_eq!(first.bucket, second.bucket);
        assert_eq!(first.source, FailureSignatureSource::BugcheckFault);
    }

    #[test]
    fn failure_signature_buckets_by_fault_module_when_the_driver_has_no_symbols() {
        // A bugcheck stop sits at nt!DbgBreakPointWithStatus; a fault in a
        // driver without a PDB (`myfault+0x1730`) must still bucket by that
        // driver, not by the break-in instruction every crash shares.
        let trace = StackTrace {
            frames: vec![StackFrame {
                sp: 0x8000,
                ip: 0xffff_f800_0010_dfb0,
                symbol: "nt!DbgBreakPointWithStatus".into(),
                source: FrameSource::Current,
                source_location: None,
                machine_frame: None,
                code: CodeFrame::at(VirtAddr(0xffff_f800_0010_dfb0)),
                inline: false,
            }],
            truncated: 0,
        };
        let report = TriageReport::assemble(
            status(false, Some(0xffff_f800_0010_dfb0)),
            Some(bugcheck(
                0xd1,
                [0; 4],
                Some((0xffff_f809_d337_1730, "myfault+0x1730", Some("myfault.sys"))),
            )),
            Some(trace),
            vec![
                ModuleInfo::new(
                    "ntoskrnl.exe".into(),
                    VirtAddr(0xffff_f800_0000_0000),
                    0x100_0000,
                ),
                ModuleInfo::new(
                    "myfault.sys".into(),
                    VirtAddr(0xffff_f809_d337_0000),
                    0xb000,
                ),
            ],
            None,
            None,
        );
        let signature = report.failure_signature.unwrap();
        assert_eq!(signature.bucket, "bugcheck:000000d1|module:myfault");
        assert_eq!(signature.source, FailureSignatureSource::BugcheckFault);
    }

    #[test]
    fn failure_signature_does_not_promote_an_unrelated_deep_non_kernel_frame() {
        let trace = StackTrace {
            frames: vec![
                StackFrame {
                    sp: 0x8000,
                    ip: 0x1040,
                    symbol: "nt!KiPageFault+0x10".into(),
                    source: FrameSource::Current,
                    source_location: None,
                    machine_frame: None,
                    code: CodeFrame::at(VirtAddr(0x1040)),
                    inline: false,
                },
                StackFrame {
                    sp: 0x8100,
                    ip: 0x3040,
                    symbol: "thirdparty!Worker+0x20".into(),
                    source: FrameSource::Unwind,
                    source_location: None,
                    machine_frame: None,
                    code: CodeFrame::at(VirtAddr(0x3040)),
                    inline: false,
                },
            ],
            truncated: 0,
        };
        let report = TriageReport::assemble(
            status(false, Some(0x1040)),
            Some(bugcheck(0x50, [0; 4], None)),
            Some(trace),
            vec![
                ModuleInfo::new("ntoskrnl.exe".into(), VirtAddr(0x1000), 0x100),
                ModuleInfo::new("thirdparty.sys".into(), VirtAddr(0x3000), 0x100),
            ],
            None,
            None,
        );

        let signature = report.failure_signature.unwrap();
        assert_eq!(signature.source, FailureSignatureSource::CurrentInstruction);
        assert_eq!(signature.symbol.as_deref(), Some("nt!kipagefault"));
        assert!(!signature.bucket.contains("thirdparty"));
    }

    fn bugcheck_callback_stack() -> StackTrace {
        StackTrace {
            frames: vec![
                frame(DRIVER_BASE + 0x10cf, "pvpanic+0x10cf"),
                frame(NT_BASE + 0x358643, "nt!KiScanBugCheckCallbackList+0x9b"),
                frame(NT_BASE + 0x357206, "nt!KeBugCheck2+0xd36"),
                frame(NT_BASE + 0x22fc57, "nt!KeBugCheckEx+0x107"),
                frame(NT_BASE + 0x245529, "nt!KiBugCheckDispatch+0x69"),
                frame(NT_BASE + 0x23f5dc, "nt!KiDoubleFaultAbort+0x31c"),
            ],
            truncated: 0,
        }
    }

    #[test]
    fn bugcheck_callbacks_are_trimmed_to_kebugcheckex() {
        let mut trace = bugcheck_callback_stack();
        trim_bugcheck_callbacks(&mut trace);
        let symbols: Vec<&str> = trace.frames.iter().map(|f| f.symbol.as_str()).collect();
        assert_eq!(
            symbols,
            [
                "nt!KeBugCheckEx+0x107",
                "nt!KiBugCheckDispatch+0x69",
                "nt!KiDoubleFaultAbort+0x31c"
            ]
        );

        // A stack that already starts at KeBugCheckEx, as in a dump Windows
        // wrote, or that never entered KeBugCheck2, is kept.
        let mut trace = bugcheck_callback_stack();
        trace.frames.remove(2);
        trim_bugcheck_callbacks(&mut trace);
        assert_eq!(trace.frames.len(), 5);
    }

    #[test]
    fn a_bugcheck_callback_is_neither_the_signature_nor_the_culprit() {
        let mut trace = bugcheck_callback_stack();
        trim_bugcheck_callbacks(&mut trace);
        let report = TriageReport::assemble(
            status(false, Some(DRIVER_BASE + 0x10cf)),
            Some(bugcheck(0x7f, [8, 0, 0, 0], None)),
            Some(trace),
            vec![
                ModuleInfo::new("ntoskrnl.exe".into(), VirtAddr(NT_BASE), 0x100_0000),
                ModuleInfo::new("pvpanic.sys".into(), VirtAddr(DRIVER_BASE), 0x1_0000),
            ],
            None,
            None,
        );

        assert_eq!(report.current_instruction(), Some(NT_BASE + 0x22fc57));
        let signature = report.failure_signature.as_ref().unwrap();
        assert_eq!(signature.bucket, "bugcheck:0000007f|symbol:nt!kebugcheckex");
        assert_eq!(signature.source, FailureSignatureSource::CurrentInstruction);
        assert!(report.culprit.is_none());
    }

    #[test]
    fn recorded_broken_driver_produces_high_confidence_with_explicit_evidence() {
        let dump = dump_info();
        let report = TriageReport::assemble(
            status(false, None),
            None,
            None,
            vec![dump.triage_drivers[0].to_module_info()],
            None,
            Some(&dump),
        );

        let culprit = report.culprit.unwrap();
        assert_eq!(culprit.module(), Some("sample.sys"));
        assert_eq!(culprit.confidence, CulpritConfidence::High);
        assert_eq!(
            culprit.evidence[0].kind,
            CulpritEvidenceKind::RecordedBrokenDriver
        );
    }

    #[test]
    fn kernel_frame_alone_is_not_a_culprit() {
        let trace = StackTrace {
            frames: vec![StackFrame {
                sp: 0x8000,
                ip: 0x1040,
                symbol: "nt!KiPageFault".into(),
                source: FrameSource::Current,
                source_location: None,
                machine_frame: None,
                code: CodeFrame::at(VirtAddr(0x1040)),
                inline: false,
            }],
            truncated: 0,
        };
        let report = TriageReport::assemble(
            status(false, Some(0x1040)),
            Some(bugcheck(
                0x50,
                [0; 4],
                Some((0x1040, "nt!KiPageFault", Some("ntoskrnl.exe"))),
            )),
            Some(trace),
            vec![ModuleInfo::new(
                "ntoskrnl.exe".into(),
                VirtAddr(0x1000),
                0x100,
            )],
            None,
            None,
        );

        assert!(report.culprit.is_none());
    }

    #[test]
    fn verifier_known_and_unknown_subcodes_are_explicit() {
        let known = bugcheck(
            0xc4,
            [0xf6, 0x44, 0xffff_8000_1234_0000, 0xffff_f800_1010_1234],
            None,
        );
        let known = verifier_finding(&known).unwrap();
        assert!(known.known_subcode);
        assert_eq!(known.addresses[0].role, "driver instruction");
        assert_eq!(known.addresses[0].address, 0xffff_f800_1010_1234);

        let unknown = verifier_finding(&bugcheck(0xc4, [0xdead, 1, 2, 3], None)).unwrap();
        assert!(!unknown.known_subcode);
        assert_eq!(
            unknown.subcode_description,
            "unknown verifier subcode 0xdead"
        );
    }

    const NT_BASE: u64 = 0xffff_f800_0000_0000;
    const DRIVER_BASE: u64 = 0xffff_f800_1000_0000;

    fn frame(ip: u64, symbol: &str) -> StackFrame {
        StackFrame {
            sp: 0x8000,
            ip,
            symbol: symbol.into(),
            source: FrameSource::Unwind,
            source_location: None,
            machine_frame: None,
            code: CodeFrame::at(VirtAddr(ip)),
            inline: false,
        }
    }

    fn power_modules() -> Vec<ModuleInfo> {
        vec![
            ModuleInfo::new("ntoskrnl.exe".into(), VirtAddr(NT_BASE), 0x10_0000),
            ModuleInfo::new("stuck.sys".into(), VirtAddr(DRIVER_BASE), 0x1_0000),
        ]
    }

    fn power_failure(subtype: u64, culprit: Option<&str>) -> PowerFailure {
        PowerFailure {
            subtype,
            description: "",
            device: None,
            stack: None,
            blocked_irp: None,
            irps: None,
            workers: None,
            pnp_lock_owner: None,
            timeout_seconds: None,
            culprit: culprit.map(|module| PowerCulprit {
                driver: DeviceDriver {
                    driver_object: VirtAddr(0xffff_9000_0000_2000),
                    name: "\\Driver\\stuck".into(),
                    driver_start: VirtAddr(DRIVER_BASE),
                    module: Some(module.into()),
                },
                device: VirtAddr(0xffff_9000_0000_1000),
                reason: "holds the blocked power IRP".into(),
            }),
            notes: Vec::new(),
        }
    }

    /// A 0x9F report as `build` completes it: the power finding read, then
    /// the signature and culprit worked out again with it.
    fn power_report(subtype: u64, finding: PowerFailureFinding) -> TriageReport {
        let trace = StackTrace {
            frames: vec![
                frame(NT_BASE + 0x100, "nt!KeBugCheckEx"),
                frame(NT_BASE + 0x200, "nt!PopIrpWatchdogBugcheck+0x1f0"),
            ],
            truncated: 0,
        };
        let mut report = TriageReport::assemble(
            status(false, Some(NT_BASE + 0x100)),
            Some(bugcheck(0x9f, [subtype, 0, 0, 0], None)),
            Some(trace),
            power_modules(),
            None,
            None,
        );
        report.power = Some(finding);
        report.failure_signature = failure_signature(&report);
        report.culprit = culprit_attribution(&report);
        report
    }

    #[test]
    fn a_0x9f_is_bucketed_on_the_driver_it_names_not_the_watchdog_stack() {
        let report = power_report(
            3,
            PowerFailureFinding {
                failure: power_failure(3, Some("stuck.sys")),
                threads: Vec::new(),
            },
        );

        let signature = report.failure_signature.unwrap();
        assert_eq!(signature.bucket, "bugcheck:0000009f|subtype:3|module:stuck");
        assert_eq!(signature.source, FailureSignatureSource::PowerFailureDriver);
        let culprit = report.culprit.unwrap();
        assert_eq!(culprit.module(), Some("stuck.sys"));
        assert_eq!(culprit.confidence, CulpritConfidence::High);
        assert_eq!(
            culprit.evidence[0].kind,
            CulpritEvidenceKind::PowerFailureDriver
        );
        assert_eq!(culprit.evidence[0].address, Some(0xffff_9000_0000_1000));
    }

    #[test]
    fn a_0x9f_0x4_suspects_the_first_driver_on_the_pnp_lock_owners_stack() {
        let owner = StackTrace {
            frames: vec![
                frame(NT_BASE + 0x300, "nt!KeWaitForSingleObject+0x846"),
                frame(DRIVER_BASE + 0x1234, "stuck!WaitForDevice+0x40"),
                frame(NT_BASE + 0x400, "nt!IopfCallDriver+0x53"),
            ],
            truncated: 0,
        };
        let report = power_report(
            4,
            PowerFailureFinding {
                failure: power_failure(4, None),
                threads: vec![PowerFailureThread {
                    role: PowerThreadRole::PnpLockOwner,
                    thread: VirtAddr(0xffff_9000_0000_3000),
                    stack: Ok(owner),
                }],
            },
        );

        let culprit = report.culprit.unwrap();
        assert_eq!(culprit.module(), Some("stuck.sys"));
        assert_eq!(culprit.confidence, CulpritConfidence::Medium);
        assert_eq!(
            culprit.evidence[0].kind,
            CulpritEvidenceKind::PnpLockOwnerStack
        );
        assert_eq!(culprit.evidence[0].address, Some(DRIVER_BASE + 0x1234));
        // Only a driver the parameters name buckets the failure.
        assert_eq!(
            report.failure_signature.unwrap().bucket,
            "bugcheck:0000009f|subtype:4|symbol:nt!kebugcheckex"
        );
    }

    const APP_BASE: u64 = 0x1_4000_0000;
    const KERNELBASE_BASE: u64 = 0x7ff9_4000_0000;
    const JIT_TABLE: (u64, u64) = (0x7ff8_9b6c_0020, 0x7ff8_9b74_0000);

    /// A user-dump report whose exception was raised at `frames[0]`, with
    /// the frame analysis `user::build` makes.
    fn user_report(frames: Vec<StackFrame>) -> TriageReport {
        let modules = vec![
            ModuleInfo::new("app.exe".into(), VirtAddr(APP_BASE), 0x10_0000),
            ModuleInfo::new(
                "KERNELBASE.dll".into(),
                VirtAddr(KERNELBASE_BASE),
                0x40_0000,
            ),
        ];
        let owner = |address: u64| match modules
            .iter()
            .find(|module| module.contains_address(VirtAddr(address)))
        {
            Some(module) => CodeOwner::Module {
                name: module.name.clone(),
                system: culprit::is_user_system_module(&module.name),
            },
            None => CodeOwner::DynamicCode {
                table_start: JIT_TABLE.0,
                table_end: JIT_TABLE.1,
            },
        };
        let trace = StackTrace {
            frames,
            truncated: 0,
        };
        let address = trace.frames[0].ip;
        let blamed_frame = user::blamed_frame(&trace, 0, owner);
        let module_caller = blamed_frame
            .as_ref()
            .and_then(|blamed| user::module_caller(&trace, blamed, owner));
        let exception = UserExceptionFinding {
            code: 0xE06D_7363,
            kind: UserExceptionKind::CppException,
            name: "C++ exception",
            flags: 1,
            flag_names: Vec::new(),
            record: 0,
            address,
            symbol: trace.frames[0].symbol.clone(),
            address_owner: owner(address),
            parameters: Vec::new(),
            summary: None,
            thread_id: 0x1a2c,
            thread: "1f40.1a2c".into(),
            thread_name: None,
            faulting_frame: Some(0),
            blamed_frame,
            module_caller,
        };
        let mut report =
            TriageReport::assemble(status(false, None), None, Some(trace), modules, None, None);
        report.user = Some(UserDumpTriage {
            process: UserProcessSummary {
                name: Some("app.exe".into()),
                pid: Some(0x1f40),
                arch: Arch::Amd64,
                major_version: 10,
                minor_version: 0,
                build_number: 26200,
                build_string: None,
                dump_time: 0,
                create_time: None,
                cpu_times: None,
                threads: 1,
                modules: 2,
                unloaded_modules: 0,
                handles: None,
            },
            exception: Some(exception),
            stack_thread: None,
            exception_registers: Vec::new(),
        });
        report.failure_signature = signature::user_failure_signature(&report);
        report.culprit = culprit::user_culprit_attribution(&report);
        report
    }

    fn user_frame(ip: u64, symbol: &str, source: FrameSource) -> StackFrame {
        StackFrame {
            source,
            ..frame(ip, symbol)
        }
    }

    #[test]
    fn a_user_raise_buckets_and_blames_the_caller_outside_the_system_modules() {
        let report = user_report(vec![
            user_frame(
                KERNELBASE_BASE + 0x1000,
                "kernelbase!RaiseException+0x8a",
                FrameSource::Current,
            ),
            user_frame(APP_BASE + 0x2040, "app!Parse+0x40", FrameSource::Unwind),
        ]);

        let signature = report.failure_signature.unwrap();
        assert_eq!(signature.bucket, "exception:e06d7363|symbol:app!parse");
        assert_eq!(
            signature.source,
            FailureSignatureSource::FirstNonSystemFrame
        );
        let culprit = report.culprit.unwrap();
        assert_eq!(culprit.module(), Some("app.exe"));
        assert_eq!(culprit.confidence, CulpritConfidence::Medium);
        assert_eq!(
            culprit.evidence[0].kind,
            CulpritEvidenceKind::FirstNonSystemFrame
        );
        assert_eq!(culprit.evidence[0].address, Some(APP_BASE + 0x2040));
    }

    #[test]
    fn a_user_fault_in_the_application_is_blamed_on_the_exception_address() {
        let report = user_report(vec![user_frame(
            APP_BASE + 0x10,
            "app!Write+0x10",
            FrameSource::Current,
        )]);

        let signature = report.failure_signature.unwrap();
        assert_eq!(signature.bucket, "exception:e06d7363|symbol:app!write");
        assert_eq!(signature.source, FailureSignatureSource::ExceptionAddress);
        let culprit = report.culprit.unwrap();
        assert_eq!(
            culprit.evidence[0].kind,
            CulpritEvidenceKind::ExceptionAddress
        );
    }

    #[test]
    fn a_user_raise_from_jit_code_blames_that_code_and_buckets_on_the_raise() {
        let report = user_report(vec![
            user_frame(
                KERNELBASE_BASE + 0x1000,
                "kernelbase!RaiseException+0x8a",
                FrameSource::Current,
            ),
            user_frame(0x7ff8_9b6c_6a48, "0x7ff89b6c6a48", FrameSource::Unwind),
            user_frame(0x7ff8_9b6c_6914, "0x7ff89b6c6914", FrameSource::Unwind),
            user_frame(APP_BASE + 0x2040, "app!Main+0x40", FrameSource::Unwind),
        ]);

        // The JIT frame is the caller: the application frame further out
        // is not promoted over it, only named as what called into it.
        let culprit = report.culprit.unwrap();
        assert_eq!(culprit.module(), None);
        assert_eq!(culprit.confidence, CulpritConfidence::Low);
        let CulpritSubject::DynamicCode(code) = &culprit.subject else {
            panic!("expected a dynamic-code culprit");
        };
        assert_eq!(code.address, 0x7ff8_9b6c_6a48);
        assert_eq!((code.table_start, code.table_end), JIT_TABLE);
        assert_eq!(code.caller.as_ref().map(|caller| caller.index), Some(3));
        let signature = report.failure_signature.unwrap();
        assert_eq!(
            signature.bucket,
            "exception:e06d7363|symbol:kernelbase!raiseexception"
        );
        assert_eq!(signature.source, FailureSignatureSource::ExceptionAddress);
    }

    #[test]
    fn a_user_culprit_found_by_scanning_has_low_confidence_and_a_symbolless_one_buckets_by_module()
    {
        let report = user_report(vec![
            user_frame(
                KERNELBASE_BASE + 0x1000,
                "kernelbase!RaiseException+0x8a",
                FrameSource::Current,
            ),
            user_frame(APP_BASE + 0x2040, "app+0x2040", FrameSource::Scan),
        ]);

        assert_eq!(report.culprit.unwrap().confidence, CulpritConfidence::Low);
        assert_eq!(
            report.failure_signature.unwrap().bucket,
            "exception:e06d7363|module:app"
        );
    }
}
