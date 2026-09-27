//! Hang diagnosis from the processor blocks (`!qlocks`, `!ipi`).

use crate::error::Result;
use crate::expr::Expr;
use crate::repl::*;
use crate::target::DiagnosticValue;
use crate::target::hang::{
    IpiProcessor, QueuedLockState, QueuedLocksDetail, ipi_frozen_name, ipi_request_type_name,
};
use crate::ui;

repl_command! {
    cmd_qlocks;
    names: ["!qlocks", "qlocks"],
    usage: "!qlocks",
    summary: "Show which processors own or wait for each numbered queued spinlock.",
    details: "Reads every processor's _KPRCB.LockQueue entries (one _KSPIN_LOCK_QUEUE per _KSPIN_LOCK_QUEUE_NUMBER lock) and lays them out as WinDbg does: a row per lock, a column per processor, O for the owner, 1-n for the wait order (found by following the queue links from the owner), and C for an entry whose owner/wait bits the links contradict. Only the numbered locks (KeAcquireQueuedSpinLock) appear; in-stack queued spinlocks live on their acquirers' stacks.",
}

repl_command! {
    cmd_ipi;
    names: ["!ipi", "ipi"],
    usage: "!ipi [processor]",
    summary: "Show interprocessor-interrupt state for one processor or all of them.",
    details: "For each processor, the IPI fields its _KPRCB has on this build: IpiFrozen (the freeze state the debugger and KeFreezeExecution drive: Running, Frozen, Freeze owner...), TargetCount and PacketBarrier (as a sender, the targets still to finish its packet), SelfIpiRequestSummary, and IpiFrame (the trap frame of the IPI being serviced). On builds with per-sender mailboxes (Windows 10 and later), also the requests queued to the processor and not yet taken: the sender, the request type (packet, TB or cache flush, from RequestSummary), and a packet's worker routine and parameters; and, as a sender, the processors whose queues still hold its request.",
    completion: Expression,
}

impl ReplState<'_> {
    fn cmd_qlocks(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help(invocation.name));
            return Ok(());
        }
        match self.ctx.target.queued_locks() {
            Ok(detail) => print_queued_locks(&detail),
            Err(error) => error!("failed to read the queued spinlocks: {error}"),
        }
        Ok(())
    }

    fn cmd_ipi(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let processor = match invocation.arg(0) {
            None => None,
            Some(text) => match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
                Ok(value) => match u16::try_from(value.0) {
                    Ok(processor) => Some(processor),
                    Err(_) => {
                        error!("processor index out of range: {:#x}", value.0);
                        return Ok(());
                    }
                },
                Err(error) => {
                    error!("invalid processor '{text}': {error}");
                    return Ok(());
                }
            },
        };
        let detail = match self.ctx.target.ipi_state(processor) {
            Ok(detail) => detail,
            Err(error) => {
                error!("failed to read IPI state: {error}");
                return Ok(());
            }
        };
        for processor in &detail.processors {
            print_ipi_processor(processor);
        }
        for error in &detail.errors {
            outln!(
                "processor {}: <unavailable: {}>",
                error.processor,
                error.message
            );
        }
        Ok(())
    }
}

fn print_queued_locks(detail: &QueuedLocksDetail) {
    outln!("Key: O = Owner, 1-n = Wait order, blank = not owned/waiting, C = Corrupt\n");
    let width = detail
        .locks
        .iter()
        .map(|lock| lock.name.len())
        .max()
        .unwrap_or(0)
        .max(9);
    let columns: String = detail
        .processors
        .iter()
        .map(|processor| format!("{processor:>3}"))
        .collect();
    outln!("    {:width$}  Processor Number", "");
    outln!("    {:width$}{columns}", "Lock Name");
    outln!("");
    for lock in &detail.locks {
        let cells: String = detail
            .processors
            .iter()
            .map(|processor| {
                let cell = lock
                    .holders
                    .iter()
                    .find(|holder| holder.processor == *processor)
                    .map_or_else(String::new, |holder| match &holder.state {
                        QueuedLockState::Owner => "O".to_string(),
                        QueuedLockState::Waiting(order) => order.to_string(),
                        QueuedLockState::Corrupt(_) => "C".to_string(),
                    });
                format!("{cell:>3}")
            })
            .collect();
        outln!("    {:width$}{}", lock.name, cells.trim_end());
    }
    outln!("");
    for lock in &detail.locks {
        for holder in &lock.holders {
            if let QueuedLockState::Corrupt(reason) = &holder.state {
                outln!(
                    "{}: processor {} {reason} (lock {})",
                    lock.name,
                    holder.processor,
                    lock.lock
                        .map_or_else(|| "?".into(), |lock| ui::addr(lock.0))
                );
            }
        }
    }
    for error in &detail.errors {
        outln!(
            "processor {}: <unavailable: {}>",
            error.processor,
            error.message
        );
    }
}

fn print_ipi_processor(processor: &IpiProcessor) {
    outln!(
        "IPI State for Processor {} (KPRCB {})",
        processor.processor,
        ui::addr(processor.kprcb.0)
    );
    let field = |name: &str| processor.fields.iter().find(|field| field.name == name);
    for entry in &processor.fields {
        let value = match (&entry.value, entry.name) {
            (DiagnosticValue::Available(value), "IpiFrozen") => {
                format!("{value:#x} [{}]", ipi_frozen_name(*value))
            }
            (DiagnosticValue::Available(value), "IpiFrame") => ui::addr(*value),
            (DiagnosticValue::Available(value), _) => format!("{value:#x}"),
            (DiagnosticValue::Unavailable(error), _) => format!("<unavailable: {error}>"),
        };
        outln!("    {:<22}{value}", entry.name);
    }
    let outstanding = matches!(
        field("TargetCount").map(|field| &field.value),
        Some(DiagnosticValue::Available(count)) if *count != 0
    );
    if !processor.awaiting.is_empty() {
        let list: Vec<String> = processor.awaiting.iter().map(u16::to_string).collect();
        outln!(
            "    As a sender, awaiting request completion from processor(s) {}",
            list.join(" ")
        );
    } else if outstanding {
        outln!("    As a sender, a packet is outstanding (targets already took the request)");
    }
    match &processor.pending {
        DiagnosticValue::Available(requests) if requests.is_empty() => {
            outln!("    As a receiver, no requests are pending");
        }
        DiagnosticValue::Available(requests) => {
            outln!("    As a receiver, the following requests are pending:");
            for request in requests {
                let sender = request.sender.map_or_else(
                    || "an unknown processor".into(),
                    |sender| format!("processor {sender}"),
                );
                let kind = match &request.request_summary {
                    DiagnosticValue::Available(summary) => format!(
                        "[{}] summary {summary:#x}",
                        ipi_request_type_name(*summary).unwrap_or("unknown type")
                    ),
                    DiagnosticValue::Unavailable(error) => {
                        format!("summary <unavailable: {error}>")
                    }
                };
                outln!(
                    "      from {sender} (mailbox {}): {kind}",
                    ui::addr(request.mailbox.0)
                );
                let is_packet = matches!(&request.request_summary,
                    DiagnosticValue::Available(summary) if ipi_request_type_name(*summary) == Some("packet"));
                if is_packet {
                    let worker = match &request.worker_routine {
                        DiagnosticValue::Available(routine) => match &request.worker_symbol {
                            Some(symbol) => {
                                format!("{} ({})", ui::symbol(symbol), ui::addr(routine.0))
                            }
                            None => ui::addr(routine.0),
                        },
                        DiagnosticValue::Unavailable(error) => format!("<unavailable: {error}>"),
                    };
                    outln!("        Worker Routine: {worker}");
                    if let DiagnosticValue::Available(parameters) = &request.parameters {
                        for (index, parameter) in parameters.iter().enumerate() {
                            outln!("        Parameter[{index}]: {}", ui::addr(*parameter));
                        }
                    }
                }
            }
            if processor.pending_truncated {
                outln!("      (list walk stopped at a repeated or unreadable mailbox)");
            }
        }
        DiagnosticValue::Unavailable(error) => {
            outln!(
                "    {}",
                ui::muted(&format!("pending requests unavailable: {error}"))
            );
        }
    }
    outln!("");
}
