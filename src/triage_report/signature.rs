//! Failure signatures: the address-independent crash identity used to
//! bucket failures.

use super::{
    CodeOwner, FailureCodeKind, FailureSignature, FailureSignatureSource, TriageReport,
    canonical_module_component, evidence_module_for_address,
};
use crate::guest::ModuleInfo;

pub(super) fn failure_signature(report: &TriageReport) -> Option<FailureSignature> {
    let (code_kind, code, mut components) = if let Some(bugcheck) = &report.bugcheck {
        let mut components = vec![format!("bugcheck:{:08x}", bugcheck.code)];
        // Each 0x9F subtype is a different failure.
        if let Some(power) = &report.power {
            components.push(format!("subtype:{:x}", power.failure.subtype));
        }
        (FailureCodeKind::Bugcheck, bugcheck.code, components)
    } else if let Some(exception) = &report.exception {
        (
            FailureCodeKind::Exception,
            exception.code,
            vec![format!("exception:{:08x}", exception.code)],
        )
    } else {
        return None;
    };

    // The recorded fault always outranks where the target happens to be
    // stopped: on a bugcheck that is DbgBreakPointWithStatus, which would
    // bucket every crash in a driver without symbols identically.
    let bugcheck_fault = report
        .bugcheck
        .as_ref()
        .and_then(|bugcheck| bugcheck.fault.as_ref());
    let bugcheck_symbol = bugcheck_fault
        .and_then(|fault| stable_symbol(&fault.symbol))
        .map(|symbol| (symbol, FailureSignatureSource::BugcheckFault));
    let bugcheck_module = bugcheck_fault.and_then(|fault| {
        fault
            .driver
            .as_deref()
            .or_else(|| evidence_module_for_address(report, fault.ip))
            .map(|module| {
                (
                    canonical_module_component(module),
                    FailureSignatureSource::BugcheckFault,
                )
            })
    });
    // A DRIVER_POWER_STATE_FAILURE names its driver in its parameters
    // rather than a fault address; that outranks the stack, which is the
    // power manager's watchdog.
    let bugcheck_module = bugcheck_module.or_else(|| power_failure_module(report));
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
    let resolved_symbol = bugcheck_symbol.or_else(|| {
        bugcheck_module
            .is_none()
            .then(|| exception_symbol.or(current_symbol).or(top_symbol))
            .flatten()
    });
    let (symbol, module, source) = match (resolved_symbol, bugcheck_module) {
        (Some((symbol, source)), _) => {
            let module = symbol.split_once('!').map(|(module, _)| module.to_string());
            (Some(symbol), module, source)
        }
        (None, Some((module, source))) => (None, Some(module), source),
        (None, None) => match best_signature_module(report) {
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

/// The module of the driver a DRIVER_POWER_STATE_FAILURE names.
fn power_failure_module(report: &TriageReport) -> Option<(String, FailureSignatureSource)> {
    let culprit = report.power.as_ref()?.failure.culprit.as_ref()?;
    culprit.driver.module.as_deref().map(|module| {
        (
            canonical_module_component(module),
            FailureSignatureSource::PowerFailureDriver,
        )
    })
}

fn best_signature_module(report: &TriageReport) -> Option<(String, FailureSignatureSource)> {
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

/// The failure signature of a user-mode minidump's exception: the code,
/// then the function (or, without symbols, the module) of the first frame
/// outside the system modules, so a raise in `kernelbase!RaiseException`
/// buckets by its caller. When that frame is in no module (JIT-compiled
/// code), the exception address's own function stands in: it is the
/// stable evidence there is.
pub fn user_failure_signature(report: &TriageReport) -> Option<FailureSignature> {
    let exception = report.user.as_ref()?.exception.as_ref()?;
    let mut components = vec![format!("exception:{:08x}", exception.code)];
    let module_component = |name: &str| ModuleInfo::derive_short_name(name);
    let blamed = exception
        .blamed_frame
        .as_ref()
        .and_then(|frame| match &frame.owner {
            CodeOwner::Module {
                name,
                system: false,
            } => Some((frame, name)),
            _ => None,
        });
    let (symbol, module, source) = if let Some((frame, name)) = blamed {
        let source = if Some(frame.index) == exception.faulting_frame {
            FailureSignatureSource::ExceptionAddress
        } else {
            FailureSignatureSource::FirstNonSystemFrame
        };
        match stable_symbol(&frame.symbol) {
            Some(symbol) => {
                let module = symbol.split_once('!').map(|(module, _)| module.to_string());
                (Some(symbol), module, source)
            }
            None => (None, Some(module_component(name)), source),
        }
    } else if let Some(symbol) = stable_symbol(&exception.symbol) {
        let module = symbol.split_once('!').map(|(module, _)| module.to_string());
        (
            Some(symbol),
            module,
            FailureSignatureSource::ExceptionAddress,
        )
    } else if let CodeOwner::Module { name, .. } = &exception.address_owner {
        (
            None,
            Some(module_component(name)),
            FailureSignatureSource::ExceptionAddress,
        )
    } else {
        (None, None, FailureSignatureSource::CodeOnly)
    };
    if let Some(symbol) = &symbol {
        components.push(format!("symbol:{symbol}"));
    } else if let Some(module) = &module {
        components.push(format!("module:{module}"));
    }
    let bucket = components.join("|");
    Some(FailureSignature {
        code_kind: FailureCodeKind::Exception,
        code: exception.code,
        module,
        source,
        symbol,
        components,
        bucket,
    })
}
