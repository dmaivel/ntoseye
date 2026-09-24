//! Failure signatures: the address-independent crash identity used to
//! bucket failures.

use super::{
    FailureCodeKind, FailureSignature, FailureSignatureSource, TriageReport,
    canonical_module_component, evidence_module_for_address,
};

pub(super) fn failure_signature(report: &TriageReport) -> Option<FailureSignature> {
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
