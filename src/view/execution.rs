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
use crate::unwind::{
    Arm64CodeDetail, Arm64UnwindDetail, FunctionEntryDetail, HandlerDetail, StackFrame,
    UnwindDetail,
};

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
            "saved_vtl",
            View::List(status.saved_vtl.iter().cloned().map(View::Str).collect()),
        ),
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
    View::Object(stack_frame_fields(frame))
}

/// [`stack_frame`] with its position in the walked stack first, for a
/// selection of a stack's frames.
pub fn numbered_stack_frame(index: usize, frame: &StackFrame) -> View {
    let mut fields = vec![("index", View::Num(index as u64))];
    fields.extend(stack_frame_fields(frame));
    View::Object(fields)
}

fn stack_frame_fields(frame: &StackFrame) -> Vec<(&'static str, View)> {
    vec![
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
    ]
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

/// `.fnent`: the function-table entry covering an address and its unwind
/// info, then each chained parent's. Addresses are absolute; `*_rva` fields
/// are the raw image-relative values, and `unwind_data` is the entry's raw
/// word: the unwind info's RVA, or ARM64's packed unwind data, for which
/// `unwind_info` is null. `unwind.form` is `amd64`, `packed`, or `xdata`.
pub fn function_entry(detail: &FunctionEntryDetail) -> View {
    let base = detail.image_base;
    let va = |rva: u32| View::Hex(base.wrapping_add(u64::from(rva)));
    let handler = |handler: &Option<HandlerDetail>| {
        handler.as_ref().map_or(View::Null, |handler| {
            View::Object(vec![
                ("address", va(handler.rva)),
                ("symbol", View::Str(handler.symbol.clone())),
                ("data", va(handler.data_rva)),
            ])
        })
    };
    let arm64_codes = |codes: &[Arm64CodeDetail]| {
        View::List(
            codes
                .iter()
                .map(|code| {
                    View::Object(vec![
                        ("index", View::Num(code.index as u64)),
                        (
                            "bytes",
                            View::List(
                                code.bytes
                                    .iter()
                                    .map(|&byte| View::Hex(byte.into()))
                                    .collect(),
                            ),
                        ),
                        ("description", View::Str(code.description.clone())),
                    ])
                })
                .collect(),
        )
    };
    let entries = detail
        .entries
        .iter()
        .map(|entry| {
            let unwind = entry
                .unwind
                .as_ref()
                .map_or(View::Null, |unwind| match unwind {
                    UnwindDetail::Amd64(info) => View::Object(vec![
                        ("form", View::Str("amd64".into())),
                        ("version", View::Num(info.version.into())),
                        ("flags", View::Num(info.flags.into())),
                        ("prolog_size", View::Num(info.prolog_size.into())),
                        ("code_count", View::Num(info.code_count.into())),
                        (
                            "frame_register",
                            View::OptStr(info.frame_register.map(str::to_string)),
                        ),
                        ("frame_offset", View::Num(info.frame_offset.into())),
                        ("size", View::Num(info.size as u64)),
                        (
                            "codes",
                            View::List(
                                info.codes
                                    .iter()
                                    .map(|code| {
                                        View::Object(vec![
                                            ("slot", View::Num(code.slot as u64)),
                                            ("code_offset", View::Num(code.code_offset.into())),
                                            ("op", View::Num(code.op.into())),
                                            ("op_info", View::Num(code.op_info.into())),
                                            ("description", View::Str(code.description.clone())),
                                        ])
                                    })
                                    .collect(),
                            ),
                        ),
                        ("handler", handler(&info.handler)),
                    ]),
                    UnwindDetail::Arm64(Arm64UnwindDetail::Packed {
                        flag,
                        reg_f,
                        reg_i,
                        homes_arguments,
                        cr,
                        frame_size,
                        codes,
                    }) => View::Object(vec![
                        ("form", View::Str("packed".into())),
                        ("flag", View::Num((*flag).into())),
                        ("reg_f", View::Num((*reg_f).into())),
                        ("reg_i", View::Num((*reg_i).into())),
                        ("homes_arguments", View::Bool(*homes_arguments)),
                        ("cr", View::Num((*cr).into())),
                        ("frame_size", View::Num((*frame_size).into())),
                        ("codes", arm64_codes(codes)),
                    ]),
                    UnwindDetail::Arm64(Arm64UnwindDetail::Xdata {
                        version,
                        exception_data,
                        epilog_in_header,
                        epilog_count,
                        code_words,
                        scopes,
                        codes,
                        handler: xdata_handler,
                        size,
                    }) => View::Object(vec![
                        ("form", View::Str("xdata".into())),
                        ("version", View::Num((*version).into())),
                        ("exception_data", View::Bool(*exception_data)),
                        ("epilog_in_header", View::Bool(*epilog_in_header)),
                        ("epilog_count", View::Num((*epilog_count).into())),
                        ("code_words", View::Num((*code_words).into())),
                        (
                            "epilog_scopes",
                            View::List(
                                scopes
                                    .iter()
                                    .map(|(start, first_code)| {
                                        View::Object(vec![
                                            ("start_offset", View::Hex((*start).into())),
                                            ("first_code", View::Num((*first_code).into())),
                                        ])
                                    })
                                    .collect(),
                            ),
                        ),
                        ("size", View::Num(*size as u64)),
                        ("codes", arm64_codes(codes)),
                        ("handler", handler(xdata_handler)),
                    ]),
                });
            let packed = matches!(
                entry.unwind,
                Some(UnwindDetail::Arm64(Arm64UnwindDetail::Packed { .. }))
            );
            View::Object(vec![
                ("begin", va(entry.begin)),
                ("end", va(entry.end)),
                ("begin_rva", View::Hex(entry.begin.into())),
                ("end_rva", View::Hex(entry.end.into())),
                (
                    "unwind_info",
                    if packed {
                        View::Null
                    } else {
                        va(entry.unwind_data)
                    },
                ),
                ("unwind_data", View::Hex(entry.unwind_data.into())),
                ("symbol", View::Str(entry.symbol.clone())),
                ("unwind", unwind),
            ])
        })
        .collect();
    View::Object(vec![
        ("module", View::Str(detail.module.clone())),
        ("image_base", View::Hex(base)),
        ("entries", View::List(entries)),
        ("incomplete", View::OptStr(detail.incomplete.clone())),
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
        CallTraceEnd::Diverted => ("diverted", None),
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
