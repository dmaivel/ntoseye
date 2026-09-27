//! hardware: [`View`] builders for hang diagnosis (`!qlocks`, `!ipi`) and PCI.

use super::{View, diagnostic};
use crate::target::hang::{
    IpiDetail, IpiProcessor, IpiRequest, ProcessorError, QueuedLock, QueuedLockState,
    QueuedLocksDetail, ipi_frozen_name, ipi_request_type_name,
};

fn processor_error(error: &ProcessorError) -> View {
    View::Object(vec![
        ("processor", View::Num(error.processor.into())),
        ("message", View::Str(error.message.clone())),
    ])
}

fn queued_lock(lock: &QueuedLock) -> View {
    let holders = lock
        .holders
        .iter()
        .map(|holder| {
            let (state, order, reason) = match &holder.state {
                QueuedLockState::Owner => ("owner", None, None),
                QueuedLockState::Waiting(order) => ("waiting", Some(u64::from(*order)), None),
                QueuedLockState::Corrupt(reason) => ("corrupt", None, Some(reason.clone())),
            };
            View::Object(vec![
                ("processor", View::Num(holder.processor.into())),
                ("state", View::Str(state.into())),
                ("wait_order", View::OptNum(order)),
                ("reason", View::OptStr(reason)),
            ])
        })
        .collect();
    View::Object(vec![
        ("number", View::Num(lock.number.into())),
        ("name", View::Str(lock.name.clone())),
        ("lock", View::OptHex(lock.lock.map(|lock| lock.0))),
        ("holders", View::List(holders)),
    ])
}

/// Numbered queued spinlocks; top-level keys: `processors`, `locks`, `errors`.
pub fn queued_locks(detail: &QueuedLocksDetail) -> View {
    View::Object(vec![
        (
            "processors",
            View::List(
                detail
                    .processors
                    .iter()
                    .map(|processor| View::Num((*processor).into()))
                    .collect(),
            ),
        ),
        (
            "locks",
            View::List(detail.locks.iter().map(queued_lock).collect()),
        ),
        (
            "errors",
            View::List(detail.errors.iter().map(processor_error).collect()),
        ),
    ])
}

fn ipi_request(request: &IpiRequest) -> View {
    View::Object(vec![
        ("mailbox", View::Hex(request.mailbox.0)),
        ("sender", View::OptNum(request.sender.map(u64::from))),
        (
            "request_summary",
            diagnostic(&request.request_summary, |summary| View::Hex(*summary)),
        ),
        (
            "request_type",
            diagnostic(&request.request_summary, |summary| {
                View::OptStr(ipi_request_type_name(*summary).map(str::to_string))
            }),
        ),
        (
            "worker_routine",
            diagnostic(&request.worker_routine, |routine| View::Hex(routine.0)),
        ),
        ("worker_symbol", View::OptStr(request.worker_symbol.clone())),
        (
            "parameters",
            diagnostic(&request.parameters, |parameters| {
                View::List(parameters.iter().map(|value| View::Hex(*value)).collect())
            }),
        ),
    ])
}

fn ipi_processor(processor: &IpiProcessor) -> View {
    let frozen = processor
        .fields
        .iter()
        .find(|field| field.name == "IpiFrozen")
        .map(|field| {
            diagnostic(&field.value, |value| {
                View::Str(ipi_frozen_name(*value).into())
            })
        })
        .unwrap_or(View::Null);
    View::Object(vec![
        ("processor", View::Num(processor.processor.into())),
        ("kprcb", View::Hex(processor.kprcb.0)),
        (
            "fields",
            View::Object(
                processor
                    .fields
                    .iter()
                    .map(|field| {
                        (
                            field.name,
                            diagnostic(&field.value, |value| View::Hex(*value)),
                        )
                    })
                    .collect(),
            ),
        ),
        ("frozen_state", frozen),
        (
            "pending",
            diagnostic(&processor.pending, |requests| {
                View::List(requests.iter().map(ipi_request).collect())
            }),
        ),
        ("pending_truncated", View::Bool(processor.pending_truncated)),
        (
            "awaiting",
            View::List(
                processor
                    .awaiting
                    .iter()
                    .map(|processor| View::Num((*processor).into()))
                    .collect(),
            ),
        ),
    ])
}

/// Per-processor IPI state; top-level keys: `processors`, `errors`.
pub fn ipi(detail: &IpiDetail) -> View {
    View::Object(vec![
        (
            "processors",
            View::List(detail.processors.iter().map(ipi_processor).collect()),
        ),
        (
            "errors",
            View::List(detail.errors.iter().map(processor_error).collect()),
        ),
    ])
}
