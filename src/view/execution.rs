//! Debugger execution-state [`View`] builders: run status,
//! vCPUs, breakpoints, exception policies, stacks, call traces, and
//! disassembly.

use super::View;
use super::process::{process, thread};
use super::symbols::source_location;
use crate::breakpoints::Breakpoint;
use crate::disasm::DisasmRow;
use crate::exception_policy::{ExceptionPolicy, ExceptionPolicyFinalAction, exception_alias};
use crate::session::{CallTrace, CallTraceEnd, CallTraceFrame, RunStatus, VcpuInfo};
use crate::unwind::StackFrame;

pub fn vcpu(v: &VcpuInfo) -> View {
    View::Object(vec![
        ("id", View::Str(v.id.clone())),
        ("rip", View::OptHex(v.rip)),
        ("context", View::Str(v.context.clone())),
        ("symbol", View::OptStr(v.symbol.clone())),
        (
            "saved_vtl",
            View::List(v.saved_vtl.iter().cloned().map(View::Str).collect()),
        ),
        ("error", View::OptStr(v.error.clone())),
    ])
}

/// One code-breakpoint/data-watchpoint row. `address` is null while a symbolic
/// or source breakpoint is deferred; `resolved` distinguishes that state from a
/// deliberately disabled breakpoint.
pub fn breakpoint(bp: &Breakpoint) -> View {
    View::Object(vec![
        ("id", View::Num(bp.id.into())),
        (
            "address",
            View::OptHex(bp.resolved_address().map(|address| address.0)),
        ),
        ("enabled", View::Bool(bp.enabled)),
        ("resolved", View::Bool(bp.resolved)),
        ("deferred", View::Bool(bp.deferred())),
        (
            "specification",
            View::OptStr(bp.specification().map(str::to_string)),
        ),
        ("symbol", View::OptStr(bp.symbol.clone())),
        ("scope", View::Str(bp.scope.label())),
        (
            "thread",
            View::OptStr(bp.thread.as_ref().map(|thread| thread.label())),
        ),
        ("processor", View::OptNum(bp.processor.map(u64::from))),
        ("condition", View::OptStr(bp.condition.clone())),
        ("pass_count", View::Num(bp.pass_count)),
        ("hit_count", View::Num(bp.hit_count)),
        ("remaining_pass_count", View::Num(bp.remaining_pass_count)),
        ("one_shot", View::Bool(bp.one_shot)),
        ("action", View::OptStr(bp.action.clone())),
        ("temporary", View::Bool(bp.temporary)),
        (
            "watch_access",
            View::OptStr(bp.watch_access_name().map(str::to_string)),
        ),
        (
            "watch_length",
            View::OptNum(bp.watch_length().map(u64::from)),
        ),
    ])
}

pub fn run_status(status: &RunStatus) -> View {
    View::Object(vec![
        ("running", View::Bool(status.running)),
        ("current_thread", View::Str(status.current_thread.clone())),
        ("rip", View::OptHex(status.rip)),
        ("symbol", View::OptStr(status.symbol.clone())),
        (
            "attached_process",
            status.attached_process.as_ref().map_or(View::Null, process),
        ),
        (
            "stopped_process",
            status.stopped_process.as_ref().map_or(View::Null, process),
        ),
        (
            "stopped_thread",
            status
                .stopped_thread
                .as_ref()
                .map_or(View::Null, |t| thread(t, None)),
        ),
        ("coherent", View::Bool(status.coherent)),
        ("kernel_base", View::Hex(status.kernel_base)),
    ])
}

pub fn stack_frame(frame: &StackFrame) -> View {
    View::Object(vec![
        ("ip", View::Hex(frame.ip)),
        ("sp", View::Hex(frame.sp)),
        ("symbol", View::Str(frame.symbol.clone())),
        ("source", View::Str(frame.source.as_str().to_string())),
        (
            "source_location",
            frame
                .source_location
                .as_ref()
                .map_or(View::Null, source_location),
        ),
    ])
}

/// One decoded instruction: bytes, text, and the resolved branch/rip-relative
/// target comment when there is one.
pub fn disasm_row(row: &DisasmRow) -> View {
    View::Object(vec![
        ("ip", View::Hex(row.ip)),
        ("hex", View::Str(row.hex.clone())),
        ("asm", View::Str(row.asm())),
        ("comment", View::OptStr(row.comment.clone())),
    ])
}

/// A `wt` call trace: why it stopped, the instructions it stepped, and the
/// call tree.
pub fn call_trace(trace: &CallTrace) -> View {
    let (end, error) = match &trace.end {
        CallTraceEnd::Returned => ("returned", None),
        CallTraceEnd::Limit => ("limit", None),
        CallTraceEnd::Interrupted => ("interrupted", None),
        CallTraceEnd::Breakpoint => ("breakpoint", None),
        CallTraceEnd::Failed(error) => ("failed", Some(error.clone())),
    };
    View::Object(vec![
        ("end", View::Str(end.to_string())),
        ("error", View::OptStr(error)),
        ("instructions", View::Num(trace.instructions as u64)),
        ("root", call_trace_frame(&trace.root)),
    ])
}

fn call_trace_frame(frame: &CallTraceFrame) -> View {
    View::Object(vec![
        ("name", View::Str(frame.name.clone())),
        ("instructions", View::Num(frame.instructions as u64)),
        (
            "children",
            View::List(frame.children.iter().map(call_trace_frame).collect()),
        ),
    ])
}

/// One exception stop policy (`sx`).
pub fn exception_policy(code: u32, policy: &ExceptionPolicy) -> View {
    let disposition = match policy.final_action {
        Some(ExceptionPolicyFinalAction::Continue(disposition)) => Some(disposition.name()),
        Some(ExceptionPolicyFinalAction::Break) => Some("break"),
        None => None,
    };
    View::Object(vec![
        ("code", View::Hex(u64::from(code))),
        (
            "alias",
            View::OptStr(exception_alias(code).map(str::to_string)),
        ),
        ("mode", View::Str(policy.mode.name().to_string())),
        ("disposition", View::OptStr(disposition.map(str::to_string))),
        ("command", View::OptStr(policy.command.clone())),
    ])
}
