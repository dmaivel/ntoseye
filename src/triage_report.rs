//! Presentation-free crash triage aggregation shared by debugger frontends.

use crate::backend::MemoryOps;
use crate::bugchecks::{BugcheckAnalysis, bugcheck_from_dump_info, current_bugcheck};
use crate::dmp::{
    DmpBlackboxStream, DmpException, DmpInfo, DmpSystemInfo, TriageCrashInfo, UnloadedDriver,
};
use crate::guest::ModuleInfo;
use crate::session::{RunStatus, Session};
use crate::triage::TriagePrcbInfo;
use crate::types::VirtAddr;
use crate::unwind::StackTrace;

/// Canonical crash-code kind used by a failure signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCodeKind {
    Bugcheck,
    Exception,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureSignatureSource {
    BugcheckFault,
    ExceptionAddress,
    CurrentInstruction,
    TopFrame,
    CodeOnly,
}

/// Deterministic, address-independent identity for comparing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureSignature {
    pub code_kind: FailureCodeKind,
    pub code: u32,
    pub module: Option<String>,
    pub symbol: Option<String>,
    pub source: FailureSignatureSource,
    /// Ordered, canonical components used to form `bucket`.
    pub components: Vec<String>,
    pub bucket: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CulpritConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CulpritEvidenceKind {
    RecordedBrokenDriver,
    RecordedBugcheckDriver,
    BugcheckFaultAddress,
    ExceptionAddress,
    CurrentInstruction,
    TopFrame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CulpritEvidence {
    pub kind: CulpritEvidenceKind,
    pub detail: String,
    pub address: Option<u64>,
}

/// Evidence-based attribution. Absence means the available evidence was not
/// sufficient to name a non-kernel culprit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CulpritAttribution {
    pub module: String,
    pub confidence: CulpritConfidence,
    pub evidence: Vec<CulpritEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierArgument {
    pub value: u64,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierAddress {
    pub role: String,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierFinding {
    pub bugcheck_code: u32,
    pub bugcheck_name: String,
    pub subcode: u64,
    pub known_subcode: bool,
    /// A decoded meaning, or an explicit `unknown verifier subcode` label.
    pub subcode_description: String,
    pub arguments: Vec<VerifierArgument>,
    pub associated_driver: Option<String>,
    pub addresses: Vec<VerifierAddress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WheaSectionKind {
    ProcessorGeneric,
    Memory,
    PciExpress,
    X64Processor,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheaSection {
    pub offset: u32,
    pub length: u32,
    pub severity: u32,
    pub section_type: String,
    pub kind: WheaSectionKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheaRecord {
    pub revision: u16,
    pub severity: u32,
    pub length: u32,
    pub sections: Vec<WheaSection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WheaRecordState {
    Decoded(WheaRecord),
    Unavailable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheaFinding {
    pub record_address: Option<u64>,
    pub state: WheaRecordState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlackboxKind {
    Pnp,
    Ntfs,
    Bsd,
    Winlogon,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlackboxState {
    /// No stream directory/payload was exposed, so absence cannot be asserted.
    Unavailable { reason: String },
    /// Stream metadata is recorded, but no documented payload parser is
    /// available. Presence and size remain directly recorded facts.
    PresentUnparsed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackboxFinding {
    pub kind: BlackboxKind,
    pub name: String,
    pub size: Option<u64>,
    pub state: BlackboxState,
}

/// Maximum number of frames collected for a one-shot triage report.
pub const TRIAGE_BACKTRACE_LIMIT: usize = 64;

/// A presentation-neutral first-pass debugger report.
///
/// Frontends decide how to format addresses and collection caps. Recorded
/// facts, decoded findings, and explicitly labeled attribution evidence remain
/// in this presentation-neutral model.
#[derive(Debug, Clone)]
pub struct TriageReport {
    pub status: RunStatus,
    pub bugcheck: Option<BugcheckAnalysis>,
    pub exception: Option<DmpException>,
    pub system_info: Option<DmpSystemInfo>,
    pub backtrace: Option<StackTrace>,
    pub modules: Vec<ModuleInfo>,
    pub unloaded_drivers: Vec<UnloadedDriver>,
    pub crash_context: Option<TriageCrashInfo>,
    pub prcb: Option<TriagePrcbInfo>,
    pub broken_driver: Option<String>,
    /// `None` for non-dump targets; otherwise the dump's recorded overflow bit.
    pub triage_overflowed: Option<bool>,
    pub failure_signature: Option<FailureSignature>,
    pub culprit: Option<CulpritAttribution>,
    pub verifier: Option<VerifierFinding>,
    pub whea: Option<WheaFinding>,
    pub blackboxes: Vec<BlackboxFinding>,
    /// Best-effort collection failures that did not prevent the report.
    pub warnings: Vec<String>,
}

impl TriageReport {
    /// Aggregate all data used by the MCP and REPL triage surfaces.
    ///
    /// Enumeration and unwinding are best-effort so a partial or live target
    /// still produces the directly available crash/status data.
    pub fn build(session: &mut Session) -> Self {
        let status = session.run_status();
        let bugcheck =
            current_bugcheck(&session.target).or_else(|| bugcheck_from_dump_info(&session.target));
        let mut warnings = Vec::new();
        let backtrace = if status.running {
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
        let modules = match session.target.kernel_modules() {
            Ok(modules) => modules,
            Err(error) => {
                warnings.push(format!("kernel modules: {error}"));
                Vec::new()
            }
        };
        let crash_context = session.backend.triage_crash_info().cloned();

        let mut report = Self::assemble(
            status,
            bugcheck,
            backtrace,
            modules,
            crash_context,
            session.target.phys.dmp_info(),
        );
        report.warnings = warnings;
        if let Some(address) = report.whea.as_ref().and_then(|whea| whea.record_address) {
            report.whea = Some(WheaFinding {
                record_address: Some(address),
                state: decode_whea_record(&session.target.context_memory(), address),
            });
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
            .map(|d| blackbox_findings(&d.blackbox_streams))
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
fn failure_signature(report: &TriageReport) -> Option<FailureSignature> {
    let (code_kind, code, mut components) = if let Some(bugcheck) = &report.bugcheck {
        (
            FailureCodeKind::Bugcheck,
            bugcheck.code,
            vec![format!("bugcheck:{:08x}", bugcheck.code)],
        )
    } else if let Some(exception) = &report.exception {
        (
            FailureCodeKind::Exception,
            exception.code,
            vec![format!("exception:{:08x}", exception.code)],
        )
    } else {
        return None;
    };

    let bugcheck_symbol = report
        .bugcheck
        .as_ref()
        .and_then(|bugcheck| bugcheck.fault.as_ref())
        .and_then(|fault| stable_symbol(&fault.symbol))
        .map(|symbol| (symbol, FailureSignatureSource::BugcheckFault));
    let exception_symbol = report.exception.as_ref().and_then(|exception| {
        report.backtrace.as_ref().and_then(|trace| {
            trace
                .frames
                .iter()
                .find(|frame| frame.ip == exception.address)
                .and_then(|frame| stable_symbol(&frame.symbol))
                .map(|symbol| (symbol, FailureSignatureSource::ExceptionAddress))
        })
    });
    let current_symbol = report.status.rip.and_then(|rip| {
        report.backtrace.as_ref().and_then(|trace| {
            trace
                .frames
                .iter()
                .find(|frame| frame.ip == rip)
                .and_then(|frame| stable_symbol(&frame.symbol))
                .map(|symbol| (symbol, FailureSignatureSource::CurrentInstruction))
        })
    });
    let top_symbol = report.backtrace.as_ref().and_then(|trace| {
        trace.frames.first().and_then(|frame| {
            stable_symbol(&frame.symbol).map(|symbol| (symbol, FailureSignatureSource::TopFrame))
        })
    });
    let resolved_symbol = bugcheck_symbol
        .or(exception_symbol)
        .or(current_symbol)
        .or(top_symbol);
    let (symbol, module, source) = match resolved_symbol {
        Some((symbol, source)) => {
            let module = symbol.split_once('!').map(|(module, _)| module.to_string());
            (Some(symbol), module, source)
        }
        None => match best_signature_module(report) {
            Some((module, source)) => (None, Some(module), source),
            None => (None, None, FailureSignatureSource::CodeOnly),
        },
    };

    if let Some(symbol) = &symbol {
        components.push(format!("symbol:{symbol}"));
    } else if let Some(module) = &module {
        components.push(format!("module:{module}"));
    }
    let bucket = components.join("|");
    Some(FailureSignature {
        code_kind,
        code,
        module,
        source,
        symbol,
        components,
        bucket,
    })
}

fn stable_symbol(symbol: &str) -> Option<String> {
    let symbol = symbol.split_whitespace().next()?;
    let (module, function) = symbol.split_once('!')?;
    if module.is_empty() || function.is_empty() {
        return None;
    }
    let function = function
        .split_once("+0x")
        .map(|(name, _)| name)
        .or_else(|| function.split_once('+').map(|(name, _)| name))
        .unwrap_or(function);
    if function.is_empty() || function.starts_with("0x") {
        return None;
    }
    Some(format!(
        "{}!{}",
        canonical_module_component(module),
        function.to_ascii_lowercase()
    ))
}

fn best_signature_module(report: &TriageReport) -> Option<(String, FailureSignatureSource)> {
    if let Some(fault) = report
        .bugcheck
        .as_ref()
        .and_then(|bugcheck| bugcheck.fault.as_ref())
    {
        if let Some(driver) = fault.driver.as_deref() {
            return Some((
                canonical_module_component(driver),
                FailureSignatureSource::BugcheckFault,
            ));
        }
        if let Some(module) = evidence_module_for_address(report, fault.ip) {
            return Some((
                canonical_module_component(module),
                FailureSignatureSource::BugcheckFault,
            ));
        }
    }
    if let Some(exception) = &report.exception
        && let Some(module) = evidence_module_for_address(report, exception.address)
    {
        return Some((
            canonical_module_component(module),
            FailureSignatureSource::ExceptionAddress,
        ));
    }
    if let Some(rip) = report.status.rip
        && let Some(module) = evidence_module_for_address(report, rip)
    {
        return Some((
            canonical_module_component(module),
            FailureSignatureSource::CurrentInstruction,
        ));
    }
    let frame = report.backtrace.as_ref()?.frames.first()?;
    evidence_module_for_address(report, frame.ip).map(|module| {
        (
            canonical_module_component(module),
            FailureSignatureSource::TopFrame,
        )
    })
}

#[derive(Debug)]
struct CulpritCandidate {
    module: String,
    confidence: CulpritConfidence,
    evidence: Vec<CulpritEvidence>,
}

fn culprit_attribution(report: &TriageReport) -> Option<CulpritAttribution> {
    let mut candidates = Vec::<CulpritCandidate>::new();
    if let Some(driver) = report.broken_driver.as_deref() {
        add_culprit_evidence(
            &mut candidates,
            driver,
            CulpritConfidence::High,
            CulpritEvidence {
                kind: CulpritEvidenceKind::RecordedBrokenDriver,
                detail: "triage dump records this broken driver".into(),
                address: None,
            },
        );
    }
    if let Some(bugcheck) = &report.bugcheck {
        if let Some(driver) = bugcheck.driver.as_deref() {
            let derived_from_fault = bugcheck
                .fault
                .as_ref()
                .and_then(|fault| fault.driver.as_deref())
                .is_some_and(|fault_driver| names_match(driver, fault_driver));
            if !derived_from_fault {
                add_culprit_evidence(
                    &mut candidates,
                    driver,
                    CulpritConfidence::High,
                    CulpritEvidence {
                        kind: CulpritEvidenceKind::RecordedBugcheckDriver,
                        detail: "bugcheck event records this driver".into(),
                        address: None,
                    },
                );
            }
        }
        if let Some(fault) = &bugcheck.fault
            && let Some(module) = evidence_module_for_address(report, fault.ip)
        {
            add_culprit_evidence(
                &mut candidates,
                module,
                CulpritConfidence::Medium,
                CulpritEvidence {
                    kind: CulpritEvidenceKind::BugcheckFaultAddress,
                    detail: format!("bugcheck fault address resolves to {module}"),
                    address: Some(fault.ip),
                },
            );
        }
    }
    if let Some(exception) = &report.exception
        && let Some(module) = evidence_module_for_address(report, exception.address)
    {
        add_culprit_evidence(
            &mut candidates,
            module,
            CulpritConfidence::Medium,
            CulpritEvidence {
                kind: CulpritEvidenceKind::ExceptionAddress,
                detail: format!("exception address resolves to {module}"),
                address: Some(exception.address),
            },
        );
    }
    if let Some(address) = report.status.rip
        && let Some(module) = evidence_module_for_address(report, address)
    {
        add_culprit_evidence(
            &mut candidates,
            module,
            CulpritConfidence::Low,
            CulpritEvidence {
                kind: CulpritEvidenceKind::CurrentInstruction,
                detail: format!("current instruction is inside {module}"),
                address: Some(address),
            },
        );
    }
    if let Some(frame) = report
        .backtrace
        .as_ref()
        .and_then(|trace| trace.frames.first())
        && let Some(module) = evidence_module_for_address(report, frame.ip)
    {
        add_culprit_evidence(
            &mut candidates,
            module,
            CulpritConfidence::Low,
            CulpritEvidence {
                kind: CulpritEvidenceKind::TopFrame,
                detail: format!("top frame {} is inside {module}", frame.symbol),
                address: Some(frame.ip),
            },
        );
    }

    candidates.sort_by(|left, right| {
        right
            .confidence
            .cmp(&left.confidence)
            .then_with(|| right.evidence.len().cmp(&left.evidence.len()))
            .then_with(|| left.module.cmp(&right.module))
    });
    let candidate = candidates.into_iter().find(|candidate| {
        !is_kernel_module(&candidate.module)
            || (candidate.confidence == CulpritConfidence::High && candidate.evidence.len() > 1)
    })?;
    Some(CulpritAttribution {
        module: candidate.module,
        confidence: candidate.confidence,
        evidence: candidate.evidence,
    })
}

fn add_culprit_evidence(
    candidates: &mut Vec<CulpritCandidate>,
    module: &str,
    confidence: CulpritConfidence,
    evidence: CulpritEvidence,
) {
    let module = module_filename(module);
    let candidate = candidates
        .iter_mut()
        .find(|candidate| names_match(&candidate.module, &module));
    if let Some(candidate) = candidate {
        candidate.confidence = candidate.confidence.max(confidence);
        if !candidate
            .evidence
            .iter()
            .any(|existing| existing.kind == evidence.kind && existing.address == evidence.address)
        {
            candidate.evidence.push(evidence);
        }
    } else {
        candidates.push(CulpritCandidate {
            module,
            confidence,
            evidence: vec![evidence],
        });
    }
}

fn verifier_finding(bugcheck: &BugcheckAnalysis) -> Option<VerifierFinding> {
    if !matches!(
        bugcheck.code,
        0x0000_00c4
            | 0x0000_00c9
            | 0x0000_00e6
            | 0x0000_00f1
            | 0x0000_00f6
            | 0x0000_0bfe
            | 0x0000_0bff
    ) {
        return None;
    }
    let subcode = bugcheck.args.first().map(|arg| arg.value).unwrap_or(0);
    let known_description = match (bugcheck.code, subcode) {
        (0x0000_00c4, 0xf6) => Some("a kernel handle was referenced as a user-mode handle"),
        (0x0000_00e6, 0x26) => Some("an IOMMU detected a DMA violation"),
        _ => None,
    };
    let addresses = match (bugcheck.code, subcode) {
        (0x0000_00c4, 0xf6) => bugcheck
            .args
            .get(3)
            .into_iter()
            .map(|arg| VerifierAddress {
                role: "driver instruction".into(),
                address: arg.value,
            })
            .collect(),
        (0x0000_00e6, 0x26) => bugcheck
            .args
            .get(2)
            .into_iter()
            .map(|arg| VerifierAddress {
                role: "DMA fault information".into(),
                address: arg.value,
            })
            .collect(),
        _ => Vec::new(),
    };
    Some(VerifierFinding {
        bugcheck_code: bugcheck.code,
        bugcheck_name: bugcheck.name.clone(),
        subcode,
        known_subcode: known_description.is_some(),
        subcode_description: known_description
            .map(str::to_string)
            .unwrap_or_else(|| format!("unknown verifier subcode {subcode:#x}")),
        arguments: bugcheck
            .args
            .iter()
            .map(|arg| VerifierArgument {
                value: arg.value,
                description: arg.description.clone(),
            })
            .collect(),
        associated_driver: bugcheck.driver.clone(),
        addresses,
    })
}

fn whea_without_memory(bugcheck: &BugcheckAnalysis) -> Option<WheaFinding> {
    match bugcheck.code {
        0x0000_0124 => {
            let address = bugcheck
                .args
                .get(1)
                .map(|arg| arg.value)
                .filter(|&address| address != 0);
            Some(WheaFinding {
                record_address: address,
                state: WheaRecordState::Unavailable {
                    reason: if address.is_some() {
                        "WHEA_ERROR_RECORD bytes were not read".into()
                    } else {
                        "bugcheck parameter 2 does not contain a WHEA_ERROR_RECORD address".into()
                    },
                },
            })
        }
        0x0000_0122 => Some(WheaFinding {
            record_address: None,
            state: WheaRecordState::Unavailable {
                reason: "WHEA_INTERNAL_ERROR does not record a WHEA_ERROR_RECORD address".into(),
            },
        }),
        _ => None,
    }
}

const WHEA_HEADER_SIZE: usize = 128;
const WHEA_SECTION_DESCRIPTOR_SIZE: usize = 72;
const WHEA_MAX_RECORD_SIZE: usize = 1024 * 1024;
const WHEA_RECORD_SIGNATURE: u32 = 0x5245_5043;
const WHEA_RECORD_SIGNATURE_END: u32 = 0xffff_ffff;
const WHEA_SUPPORTED_REVISION: u16 = 0x0210;

fn decode_whea_record<M: MemoryOps<VirtAddr>>(memory: &M, address: u64) -> WheaRecordState {
    let mut header = [0u8; WHEA_HEADER_SIZE];
    if let Err(error) = memory.read_bytes(VirtAddr(address), &mut header) {
        return WheaRecordState::Unavailable {
            reason: format!("WHEA_ERROR_RECORD header is not captured: {error}"),
        };
    }
    decode_whea_header_and_read(memory, address, &header)
}

fn decode_whea_header_and_read<M: MemoryOps<VirtAddr>>(
    memory: &M,
    address: u64,
    header: &[u8; WHEA_HEADER_SIZE],
) -> WheaRecordState {
    let signature = le_u32(header, 0);
    if signature != WHEA_RECORD_SIGNATURE {
        return whea_malformed(format!("invalid WHEA signature {signature:#010x}"));
    }
    let revision = le_u16(header, 4);
    if revision != WHEA_SUPPORTED_REVISION {
        return whea_malformed(format!("unsupported WHEA record revision {revision:#06x}"));
    }
    let signature_end = le_u32(header, 6);
    if signature_end != WHEA_RECORD_SIGNATURE_END {
        return whea_malformed(format!(
            "invalid WHEA ending signature {signature_end:#010x}"
        ));
    }
    let section_count = le_u16(header, 10) as usize;
    let severity = le_u32(header, 12);
    let length = le_u32(header, 20) as usize;
    let descriptors_end = match section_count
        .checked_mul(WHEA_SECTION_DESCRIPTOR_SIZE)
        .and_then(|bytes| WHEA_HEADER_SIZE.checked_add(bytes))
    {
        Some(end) => end,
        None => return whea_malformed("WHEA section descriptor count overflows".into()),
    };
    if length < descriptors_end {
        return whea_malformed(format!(
            "WHEA length {length:#x} is smaller than the {descriptors_end:#x}-byte header and descriptor table"
        ));
    }
    if length > WHEA_MAX_RECORD_SIZE {
        return whea_malformed(format!(
            "WHEA length {length:#x} exceeds the {WHEA_MAX_RECORD_SIZE:#x}-byte safety cap"
        ));
    }

    let mut record = vec![0u8; length];
    if let Err(error) = memory.read_bytes(VirtAddr(address), &mut record) {
        return WheaRecordState::Unavailable {
            reason: format!("WHEA_ERROR_RECORD is only partially captured: {error}"),
        };
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let descriptor = WHEA_HEADER_SIZE + index * WHEA_SECTION_DESCRIPTOR_SIZE;
        let offset = le_u32(&record, descriptor) as usize;
        let section_length = le_u32(&record, descriptor + 4) as usize;
        let section_end = match offset.checked_add(section_length) {
            Some(end) => end,
            None => {
                return whea_malformed(format!("WHEA section {index} range overflows"));
            }
        };
        if offset < descriptors_end || section_end > length {
            return whea_malformed(format!(
                "WHEA section {index} range {offset:#x}..{section_end:#x} is outside record bounds {descriptors_end:#x}..{length:#x}"
            ));
        }
        let section_type = format_guid(&record[descriptor + 16..descriptor + 32]);
        sections.push(WheaSection {
            offset: offset as u32,
            length: section_length as u32,
            severity: le_u32(&record, descriptor + 48),
            kind: whea_section_kind(&section_type),
            section_type,
        });
    }
    WheaRecordState::Decoded(WheaRecord {
        revision,
        severity,
        length: length as u32,
        sections,
    })
}

fn whea_malformed(reason: String) -> WheaRecordState {
    WheaRecordState::Unavailable {
        reason: format!("malformed WHEA_ERROR_RECORD: {reason}"),
    }
}

fn whea_section_kind(section_type: &str) -> WheaSectionKind {
    match section_type {
        "9876ccad-47b4-4bdb-b65e-16f193c4f3db" => WheaSectionKind::ProcessorGeneric,
        "a5bc1114-6f64-4ede-b863-3e83ed7c83b1" => WheaSectionKind::Memory,
        "d995e954-bbc1-430f-ad91-b44dcb3c6f35" => WheaSectionKind::PciExpress,
        "dc3ea0b0-a144-4797-b95b-53fa242b6e1d" => WheaSectionKind::X64Processor,
        _ => WheaSectionKind::Unknown,
    }
}

fn format_guid(bytes: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        le_u32(bytes, 0),
        le_u16(bytes, 4),
        le_u16(bytes, 6),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn blackbox_findings(streams: &[DmpBlackboxStream]) -> Vec<BlackboxFinding> {
    [
        (BlackboxKind::Pnp, "PnP"),
        (BlackboxKind::Ntfs, "NTFS"),
        (BlackboxKind::Bsd, "BSD"),
        (BlackboxKind::Winlogon, "Winlogon"),
    ]
    .into_iter()
    .map(|(kind, display_name)| {
        let stream = streams.iter().find(|stream| {
            let name = stream.name.to_ascii_lowercase();
            match kind {
                BlackboxKind::Pnp => name.contains("pnp"),
                BlackboxKind::Ntfs => name.contains("ntfs"),
                BlackboxKind::Bsd => name.contains("bsd"),
                BlackboxKind::Winlogon => name.contains("winlogon"),
            }
        });
        match stream {
            Some(stream) => BlackboxFinding {
                kind,
                name: stream.name.clone(),
                size: Some(stream.size),
                state: BlackboxState::PresentUnparsed,
            },
            None => BlackboxFinding {
                kind,
                name: display_name.into(),
                size: None,
                state: BlackboxState::Unavailable {
                    reason: "dump parser exposes no matching blackbox stream metadata".into(),
                },
            },
        }
    })
    .collect()
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

fn module_filename(name: &str) -> String {
    name.rsplit(['\\', '/']).next().unwrap_or(name).to_string()
}

fn canonical_module_component(name: &str) -> String {
    let filename = module_filename(name);
    filename
        .rsplit_once('.')
        .filter(|(_, extension)| {
            extension.eq_ignore_ascii_case("sys") || extension.eq_ignore_ascii_case("exe")
        })
        .map(|(stem, _)| stem)
        .unwrap_or(&filename)
        .to_ascii_lowercase()
}

fn is_kernel_module(name: &str) -> bool {
    matches!(
        canonical_module_component(name).as_str(),
        "nt" | "ntoskrnl" | "ntkrnlmp" | "ntkrnlpa" | "ntkrpamp"
    )
}

/// Stable exception-code label shared by report renderers.
pub fn exception_code_name(code: u32) -> &'static str {
    match code {
        0xC0000005 => "STATUS_ACCESS_VIOLATION",
        0xC000001D => "STATUS_ILLEGAL_INSTRUCTION",
        0xC0000094 => "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC0000095 => "STATUS_INTEGER_OVERFLOW",
        0xC0000096 => "STATUS_PRIVILEGED_INSTRUCTION",
        0xC00000FD => "STATUS_STACK_OVERFLOW",
        0xC0000006 => "STATUS_IN_PAGE_ERROR",
        0x80000003 => "STATUS_BREAKPOINT",
        0x80000004 => "STATUS_SINGLE_STEP",
        0xC000008E => "STATUS_FLOAT_DIVIDE_BY_ZERO",
        0xC0000090 => "STATUS_FLOAT_INVALID_OPERATION",
        0xC0000091 => "STATUS_FLOAT_OVERFLOW",
        0xC000008D => "STATUS_FLOAT_DENORMAL_OPERAND",
        0xC0000092 => "STATUS_FLOAT_STACK_CHECK",
        0xC0000093 => "STATUS_FLOAT_UNDERFLOW",
        0xC000008F => "STATUS_FLOAT_INEXACT_RESULT",
        _ => "unknown",
    }
}

/// Convert a Windows FILETIME value to an ISO-8601 UTC timestamp.
pub fn filetime_to_iso(ft: u64) -> Option<String> {
    // Windows FILETIME: 100-ns intervals since 1601-01-01 UTC.
    const EPOCH_DIFF: i64 = 11_644_473_600;
    let secs = (ft / 10_000_000) as i64 - EPOCH_DIFF;
    if !(0..=253_402_300_799).contains(&secs) {
        return None;
    }
    let s = secs % 60;
    let total_m = secs / 60;
    let m = total_m % 60;
    let total_h = total_m / 60;
    let h = total_h % 24;
    let days = total_h / 24;
    let (y, mo, d) = days_to_ymd(days);
    Some(format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z"))
}

fn days_to_ymd(mut days: i64) -> (i64, i64, i64) {
    // Civil days since 1970-01-01 to (year, month, day).
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn module_name_matches(recorded: &str, module: &ModuleInfo) -> bool {
    names_match(recorded, &module.name) || names_match(recorded, &module.short_name)
}

fn names_match(left: &str, right: &str) -> bool {
    fn basename(name: &str) -> &str {
        let name = name.rsplit(['\\', '/']).next().unwrap_or(name);
        name.get(..name.len().saturating_sub(4))
            .filter(|_| {
                name.get(name.len().saturating_sub(4)..)
                    .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".sys"))
            })
            .unwrap_or(name)
    }

    basename(left).eq_ignore_ascii_case(basename(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bugchecks::{BugcheckArg, BugcheckFault};
    use crate::dmp::DmpContext;
    use crate::error::Result;
    use crate::kd::context::REGISTER_BUFFER_SIZE;
    use crate::session::RunStatus;
    use crate::triage::TriageDriver;
    use crate::types::VirtAddr;
    use crate::unwind::{FrameSource, StackFrame};

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
            process: Some((4, "System".into(), 0xffff_8000_0000_1000)),
            coherent: true,
            kernel_base: 0xffff_f800_0000_0000,
        }
    }

    fn dump_info() -> DmpInfo {
        DmpInfo {
            directory_table_base: 0x1ad000,
            bug_check_code: 0x50,
            bug_check_parameters: [1, 2, 3, 4],
            context: DmpContext::from_bytes(&vec![0; REGISTER_BUFFER_SIZE]),
            offset_prcb_context: None,
            number_processors: 2,
            is_triage: true,
            ps_loaded_module_list: 0,
            ps_active_process_head: 0,
            debugger_data_block: None,
            triage_drivers: vec![TriageDriver {
                name: "sample.sys".into(),
                base: 0xffff_f800_1000_0000,
                entry_point: 0xffff_f800_1000_1000,
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
            blackbox_streams: Vec::new(),
            triage_prcb_info: Some(TriagePrcbInfo {
                current_thread: 0xffff_8000_1234_0000,
                processor_number: 1,
                mhz: 3600,
                cpu_type: 0x8664,
                vendor_string: "GenuineIntel".into(),
            }),
            broken_driver: Some("sample.sys".into()),
            triage_overflowed: true,
            kern_base: Some(0xffff_f800_0000_0000),
        }
    }

    #[test]
    fn assemble_preserves_dump_triage_metadata() {
        let dump = dump_info();
        let crash_context = TriageCrashInfo {
            process_name: Some("System".into()),
            process_id: Some(4),
            parent_process_id: Some(0),
            exit_status: Some(-1),
            create_time: Some(133_000_000_000_000_000),
            thread_id: Some(0x88),
            thread_exit_status: Some(0),
        };
        let modules = vec![dump.triage_drivers[0].to_module_info()];

        let report = TriageReport::assemble(
            status(false, Some(0xffff_f800_1000_1234)),
            None,
            None,
            modules,
            Some(crash_context),
            Some(&dump),
        );

        assert_eq!(report.exception.as_ref().unwrap().code, 0xc0000005);
        assert_eq!(report.system_info.as_ref().unwrap().minor_version, 22621);
        assert_eq!(report.unloaded_drivers[0].name, "old.sys");
        assert_eq!(report.crash_context.as_ref().unwrap().thread_id, Some(0x88));
        assert_eq!(report.prcb.as_ref().unwrap().processor_number, 1);
        assert_eq!(report.broken_driver.as_deref(), Some("sample.sys"));
        assert_eq!(report.triage_overflowed, Some(true));
        assert!(report.loaded_module_is_relevant(&report.modules[0]));
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
    fn failure_signature_does_not_promote_an_unrelated_deep_non_kernel_frame() {
        let trace = StackTrace {
            frames: vec![
                StackFrame {
                    sp: 0x8000,
                    ip: 0x1040,
                    symbol: "nt!KiPageFault+0x10".into(),
                    source: FrameSource::Current,
                    source_location: None,
                },
                StackFrame {
                    sp: 0x8100,
                    ip: 0x3040,
                    symbol: "thirdparty!Worker+0x20".into(),
                    source: FrameSource::Unwind,
                    source_location: None,
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
        assert_eq!(culprit.module, "sample.sys");
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

    struct NoMemory;

    impl MemoryOps<VirtAddr> for NoMemory {
        fn read_bytes(&self, _addr: VirtAddr, _buf: &mut [u8]) -> Result<()> {
            panic!("malformed header must be rejected before a record read")
        }

        fn write_bytes(&self, _addr: VirtAddr, _buf: &[u8]) -> Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn malformed_whea_descriptor_bounds_are_rejected() {
        let mut header = [0u8; WHEA_HEADER_SIZE];
        header[0..4].copy_from_slice(&WHEA_RECORD_SIGNATURE.to_le_bytes());
        header[4..6].copy_from_slice(&WHEA_SUPPORTED_REVISION.to_le_bytes());
        header[6..10].copy_from_slice(&WHEA_RECORD_SIGNATURE_END.to_le_bytes());
        header[10..12].copy_from_slice(&1u16.to_le_bytes());
        header[20..24].copy_from_slice(&(WHEA_HEADER_SIZE as u32).to_le_bytes());

        let state = decode_whea_header_and_read(&NoMemory, 0x1000, &header);
        let WheaRecordState::Unavailable { reason } = state else {
            panic!("malformed record unexpectedly decoded")
        };
        assert!(reason.contains("smaller than"));
    }

    #[test]
    fn blackbox_presence_falls_back_to_recorded_name_and_size() {
        let findings = blackbox_findings(&[DmpBlackboxStream {
            name: "BLACKBOXPNP".into(),
            size: 0x240,
        }]);
        let pnp = findings
            .iter()
            .find(|finding| finding.kind == BlackboxKind::Pnp)
            .unwrap();
        assert_eq!(pnp.name, "BLACKBOXPNP");
        assert_eq!(pnp.size, Some(0x240));
        assert_eq!(pnp.state, BlackboxState::PresentUnparsed);
        assert!(matches!(
            findings
                .iter()
                .find(|finding| finding.kind == BlackboxKind::Ntfs)
                .unwrap()
                .state,
            BlackboxState::Unavailable { .. }
        ));
    }
}
