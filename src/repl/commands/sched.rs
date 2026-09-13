use std::sync::Arc;
use std::sync::atomic::Ordering;

use tabled::builder::Builder;

use crate::cpu_state::{MAX_PROCESSORS, kpcr_for_processor, kprcb_for_processor, processor_count};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::kuser_shared;
use crate::repl::*;
use crate::session::processor_index_from_backend_thread_id;
use crate::symbols::{ParsedType, TypeInfo};
use crate::target::{
    ListCursor, ListTermination, Target, ThreadInfo, kthread_state_name, wait_reason_name,
};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{StackTrace, ThreadTraceContext, format_symbol, resolve_thread_trace_context};

const MAX_LIST_ENTRIES: usize = 4096;
const MAX_RUNNING_STACK_FRAMES: usize = 8;
const MAX_STACK_FRAMES_LEVEL_1: usize = 32;
const MAX_STACK_FRAMES_LEVEL_2: usize = 64;
const READY_PRIORITY_COUNT: usize = 32;
const DPC_QUEUE_COUNT: usize = 2;
const TIMER_BUCKET_COUNT: usize = 256;
const APC_THREAD_DISPLAY_LIMIT: usize = 16_384;
const HUNDRED_NS_PER_MS: u64 = 10_000;
const TIMER_DELTA_DISPLAY_LIMIT: u64 = 1_000_000_000_000;

repl_command! {
    cmd_running;
    names: ["!running", "running"],
    usage: "!running [-i] [-t]",
    summary: "Show the thread running on each processor.",
    details: "-i includes idle threads. -t appends a bounded short kernel stack for each processor.",
    completion: None,
}

repl_command! {
    cmd_ready;
    names: ["!ready", "ready"],
    usage: "!ready [processor]",
    summary: "List bounded dispatcher-ready queues, optionally for one processor.",
    details: "Reads DispatcherReadyListHead (or ReadyListHead on newer builds) from each _KPRCB.",
    completion: Expression,
}

repl_command! {
    cmd_dpcs;
    names: ["!dpcs", "dpcs"],
    usage: "!dpcs",
    summary: "List deferred procedure calls queued on each processor.",
    details: "Walks the two _KPRCB DpcData queues with cycle and entry bounds.",
    completion: None,
}

repl_command! {
    cmd_timer;
    names: ["!timer", "timer"],
    usage: "!timer [address-expression]",
    summary: "List kernel timers or decode one _KTIMER.",
    details: "The list form walks _KPRCB.TimerTable.TimerEntries; the address form decodes one timer and its DPC.",
    completion: Expression,
}

repl_command! {
    cmd_apc;
    names: ["!apc", "apc"],
    usage: "!apc [process|thread]",
    summary: "List kernel and user APCs for the selected thread, process, or all threads.",
    details: "With no argument the current Windows thread is used; * enumerates all threads within a bounded walk.",
    completion: [Expression],
}

repl_command! {
    cmd_stacks;
    names: ["!stacks", "stacks"],
    usage: "!stacks [0|1|2] [filter]",
    summary: "Show every thread's state, wait reason, and top stack symbol.",
    details: "Level 0 shows one frame; levels 1 and 2 append bounded full stacks. The optional filter matches process or stack symbols.",
    completion: [None, Process],
}

fn aggregate_type_name(type_data: &ParsedType) -> Option<&str> {
    match type_data {
        ParsedType::Struct(name) | ParsedType::Union(name) => Some(name.as_str()),
        ParsedType::Pointer(inner) | ParsedType::Array(inner, _) => aggregate_type_name(inner),
        _ => None,
    }
}

fn array_element_type_name(type_data: &ParsedType) -> Option<&str> {
    let ParsedType::Array(inner, _) = type_data else {
        return None;
    };
    aggregate_type_name(inner)
}

fn array_count(type_data: &ParsedType, default: usize) -> usize {
    let mut current = type_data;
    let mut count = 1usize;
    let mut found_array = false;
    while let ParsedType::Array(inner, dimension) = current {
        found_array = true;
        let Ok(dimension) = usize::try_from(*dimension) else {
            return default;
        };
        let Some(product) = count.checked_mul(dimension) else {
            return default;
        };
        count = product;
        current = inner;
    }
    if found_array { count } else { default }
}

fn layout_for(target: &Target, name: &str) -> Result<Arc<TypeInfo>> {
    target.guest()?.ntoskrnl.types().layout(name)
}

fn array_stride(target: &Target, type_data: &ParsedType, field_size: u64, default: usize) -> u64 {
    if let Some(element_name) = array_element_type_name(type_data)
        && let Ok(element) = layout_for(target, element_name)
        && element.size != 0
    {
        return element.size as u64;
    }

    if matches!(type_data, ParsedType::Array(_, _)) && field_size != 0 {
        let count = array_count(type_data, 0);
        if count != 0 {
            return field_size / count as u64;
        }
    }

    if field_size != 0 && !matches!(type_data, ParsedType::Array(_, _)) {
        return field_size;
    }

    default as u64
}

fn link_offset(target: &Target, record_type: &str, candidates: &[&str]) -> Option<u64> {
    let layout = layout_for(target, record_type).ok()?;
    candidates
        .iter()
        .find_map(|candidate| layout.field_offset(*candidate).ok())
}

fn read_list_next(target: &Target, address: VirtAddr) -> Result<VirtAddr> {
    target
        .guest()?
        .ntoskrnl
        .types()
        .struct_at("_LIST_ENTRY", address)?
        .read_field("Flink")
}

fn walk_list_nodes(
    target: &Target,
    head: VirtAddr,
    limit: usize,
) -> (Vec<VirtAddr>, ListTermination) {
    let mut cursor = ListCursor::new(head, limit.min(MAX_LIST_ENTRIES));
    cursor.advance(read_list_next(target, head).map_err(|error| error.to_string()));
    let mut nodes = Vec::new();
    while let Some(current) = cursor.next() {
        nodes.push(current);
        cursor.advance(read_list_next(target, current).map_err(|error| error.to_string()));
    }
    (nodes, cursor.finish())
}

fn processor_indices(target: &Target) -> Result<Vec<u16>> {
    let count = usize::from(processor_count(target)?).clamp(1, usize::from(MAX_PROCESSORS));
    Ok((0..count).map(|index| index as u16).collect())
}

fn selected_processor_indices(state: &ReplState<'_>, argument: Option<&str>) -> Option<Vec<u16>> {
    if let Some(argument) = argument {
        let value = match Expr::eval_with_radix(argument, &state.ctx.target, state.radix) {
            Ok(value) => value.0,
            Err(error) => {
                error!("invalid processor '{}': {}", argument, error);
                return None;
            }
        };
        let Ok(index) = u16::try_from(value) else {
            error!("processor index out of range: {value:#x}");
            return None;
        };
        let count = match processor_count(&state.ctx.target) {
            Ok(count) => count,
            Err(error) => {
                error!("processor count unavailable: {error}");
                return None;
            }
        };
        if index >= count {
            error!("processor index {index} out of range (target has {count} processor(s))");
            return None;
        }
        return Some(vec![index]);
    }

    match processor_indices(&state.ctx.target) {
        Ok(indices) => Some(indices),
        Err(error) => {
            error!("processor count unavailable: {error}");
            None
        }
    }
}

fn is_idle_thread(thread: &ThreadInfo) -> bool {
    thread.pid == Some(0)
        || thread
            .process_name
            .as_deref()
            .is_some_and(|name| name.eq_ignore_ascii_case("idle"))
}

fn thread_tid(thread: &ThreadInfo) -> String {
    thread
        .tid
        .map(|tid| tid.to_string())
        .unwrap_or_else(|| ui::addr(thread.ethread.0).to_string())
}

fn thread_process(thread: &ThreadInfo) -> &str {
    thread.process_name.as_deref().unwrap_or("<unknown>")
}

fn thread_state(thread: &ThreadInfo) -> String {
    thread
        .state
        .map(|state| format!("{} ({state})", kthread_state_name(state)))
        .unwrap_or_else(|| "<unavailable>".to_string())
}

fn thread_wait_reason(thread: &ThreadInfo) -> String {
    thread
        .wait_reason
        .map(|reason| format!("{} ({reason})", wait_reason_name(reason)))
        .unwrap_or_else(|| "<unavailable>".to_string())
}

fn short_stack(state: &ReplState<'_>, thread: &ThreadInfo, limit: usize) -> String {
    match state.ctx.backtrace_thread(thread, limit) {
        Ok(trace) if trace.stacktrace.frames.is_empty() => "<no frames>".to_string(),
        Ok(trace) => trace
            .stacktrace
            .frames
            .iter()
            .take(limit)
            .map(|frame| frame.symbol.as_str())
            .collect::<Vec<_>>()
            .join(" <- "),
        Err(error) => format!("<unavailable: {error}>"),
    }
}

fn kernel_trace(target: &Target) -> ThreadTraceContext {
    resolve_thread_trace_context(target, target.kernel_dtb())
}

fn symbol_for_address(target: &Target, trace: &ThreadTraceContext, address: VirtAddr) -> String {
    format_symbol(target, trace, address.0)
}

fn format_pointer_field(
    target: &Target,
    trace: &ThreadTraceContext,
    type_name: &str,
    base: VirtAddr,
    field: Option<&str>,
    null_label: &str,
) -> String {
    let Some(field) = field else {
        return "<unavailable: field not present>".to_string();
    };
    let value = target.guest().and_then(|guest| {
        guest
            .ntoskrnl
            .types()
            .struct_at(type_name, base)
            .and_then(|cursor| cursor.read_field::<VirtAddr>(field))
    });
    match value {
        Ok(address) if address.is_zero() => null_label.to_string(),
        Ok(address) => symbol_for_address(target, trace, address),
        Err(error) => format!("<unavailable: {error}>"),
    }
}

fn format_context_field(
    target: &Target,
    type_name: &str,
    base: VirtAddr,
    field: Option<&str>,
) -> String {
    let Some(field) = field else {
        return "<unavailable: field not present>".to_string();
    };
    let value = target.guest().and_then(|guest| {
        guest
            .ntoskrnl
            .types()
            .struct_at(type_name, base)
            .and_then(|cursor| cursor.read_field::<VirtAddr>(field))
    });
    match value {
        Ok(address) if address.is_zero() => "0x0".to_string(),
        Ok(address) => ui::addr(address.0),
        Err(error) => format!("<unavailable: {error}>"),
    }
}

impl ReplState<'_> {
    fn cmd_running(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let mut include_idle = false;
        let mut include_stack = false;
        for argument in &invocation.argv {
            match argument.as_ref() {
                "-i" => include_idle = true,
                "-t" => include_stack = true,
                other => {
                    outln!("{}\n", command_help("!running"));
                    error!("unknown !running option '{other}'");
                    return Ok(());
                }
            }
        }

        let processors = match processor_indices(&self.ctx.target) {
            Ok(indices) => indices,
            Err(error) => {
                error!("processor count unavailable: {error}");
                return Ok(());
            }
        };

        let mut builder = Builder::default();
        builder.push_record([
            "CPU", "KPCR", "KPRCB", "KTHREAD", "TID", "Process", "Priority", "Stack",
        ]);
        let mut displayed = 0usize;
        for processor in processors {
            let kpcr = kpcr_for_processor(&self.ctx.target, processor)
                .map(|address| ui::addr(address.0))
                .unwrap_or_else(|error| format!("<unavailable: {error}>"));
            let prcb = match kprcb_for_processor(&self.ctx.target, processor) {
                Ok(address) => address,
                Err(error) => {
                    builder.push_record([
                        format!("{processor}"),
                        kpcr,
                        format!("<unavailable: {error}>"),
                        "-".to_string(),
                        "-".to_string(),
                        "<unavailable>".to_string(),
                        "<unavailable>".to_string(),
                        "-".to_string(),
                    ]);
                    displayed += 1;
                    continue;
                }
            };
            let thread = match self
                .ctx
                .target
                .current_windows_thread_for_processor(processor)
            {
                Ok(thread) => thread,
                Err(error) => {
                    builder.push_record([
                        format!("{processor}"),
                        kpcr,
                        ui::addr(prcb.0),
                        "<unavailable>".to_string(),
                        "-".to_string(),
                        format!("<unavailable: {error}>"),
                        "<unavailable>".to_string(),
                        "-".to_string(),
                    ]);
                    displayed += 1;
                    continue;
                }
            };
            if !include_idle && is_idle_thread(&thread) {
                continue;
            }
            let stack = if include_stack {
                short_stack(self, &thread, MAX_RUNNING_STACK_FRAMES)
            } else {
                "-".to_string()
            };
            builder.push_record([
                format!("{processor}"),
                kpcr,
                ui::addr(prcb.0),
                ui::addr(thread.kthread.0),
                thread_tid(&thread),
                thread_process(&thread).to_string(),
                thread
                    .priority
                    .map(|priority| priority.to_string())
                    .unwrap_or_else(|| "<unavailable>".to_string()),
                stack,
            ]);
            displayed += 1;
        }
        if displayed == 0 {
            outln!("no non-idle running threads\n");
        } else {
            print_padded_table(builder);
        }
        Ok(())
    }

    fn cmd_ready(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let processor_argument = (!invocation.argv.is_empty()).then(|| invocation.join_args(0));
        let processors = match selected_processor_indices(self, processor_argument.as_deref()) {
            Some(indices) => indices,
            None => return Ok(()),
        };
        let prcb_layout = match layout_for(&self.ctx.target, "_KPRCB") {
            Ok(layout) => layout,
            Err(error) => {
                error!("_KPRCB layout unavailable: {error}");
                return Ok(());
            }
        };
        let ready_name = if prcb_layout.fields.contains_key("DispatcherReadyListHead") {
            "DispatcherReadyListHead"
        } else if prcb_layout.fields.contains_key("ReadyListHead") {
            "ReadyListHead"
        } else {
            error!("_KPRCB ready-list head field unavailable");
            return Ok(());
        };
        let Some(ready_field) = prcb_layout.fields.get(ready_name) else {
            error!("_KPRCB ready-list head field unavailable");
            return Ok(());
        };
        let stride = array_stride(
            &self.ctx.target,
            &ready_field.type_data,
            ready_field.size,
            16,
        )
        .max(1);
        let count = array_count(&ready_field.type_data, READY_PRIORITY_COUNT)
            .clamp(1, READY_PRIORITY_COUNT);
        let link_offset = link_offset(
            &self.ctx.target,
            "_KTHREAD",
            &["WaitListEntry", "ReadyListEntry", "QueueListEntry"],
        );
        let ethread_tcb_offset = layout_for(&self.ctx.target, "_ETHREAD")
            .ok()
            .and_then(|layout| layout.field_offset("Tcb").ok())
            .unwrap_or(0);

        let mut builder = Builder::default();
        builder.push_record([
            "CPU",
            "Priority",
            "KTHREAD",
            "TID",
            "Process",
            "ThreadPriority",
            "State",
        ]);
        let mut total = 0usize;
        for processor in processors {
            let prcb = match kprcb_for_processor(&self.ctx.target, processor) {
                Ok(address) => address,
                Err(error) => {
                    outln!("CPU {processor}: <unavailable: {error}>");
                    continue;
                }
            };
            for priority in 0..count {
                if total >= MAX_LIST_ENTRIES {
                    break;
                }
                let head = prcb + u64::from(ready_field.offset) + (priority as u64) * stride;
                let remaining = MAX_LIST_ENTRIES - total;
                let (nodes, stop) = walk_list_nodes(&self.ctx.target, head, remaining);
                for node in nodes {
                    let Some(link_offset) = link_offset else {
                        builder.push_record([
                            processor.to_string(),
                            priority.to_string(),
                            ui::addr(node.0),
                            "<unavailable>".to_string(),
                            "<unavailable: _KTHREAD link field not present>".to_string(),
                            "<unavailable>".to_string(),
                            "<unavailable>".to_string(),
                        ]);
                        total += 1;
                        continue;
                    };
                    let kthread = node - link_offset;
                    let thread = self
                        .ctx
                        .target
                        .thread_info_from_ethread(kthread - ethread_tcb_offset);
                    match thread {
                        Ok(thread) => builder.push_record([
                            processor.to_string(),
                            priority.to_string(),
                            ui::addr(kthread.0).to_string(),
                            thread_tid(&thread),
                            thread_process(&thread).to_string(),
                            thread
                                .priority
                                .map(|value| value.to_string())
                                .unwrap_or_else(|| "<unavailable>".to_string()),
                            thread_state(&thread),
                        ]),
                        Err(error) => builder.push_record([
                            processor.to_string(),
                            priority.to_string(),
                            ui::addr(kthread.0).to_string(),
                            "<unavailable>".to_string(),
                            format!("<unavailable: {error}>"),
                            "<unavailable>".to_string(),
                            "<unavailable>".to_string(),
                        ]),
                    }
                    total += 1;
                    if total >= MAX_LIST_ENTRIES {
                        break;
                    }
                }
                if let Some(stop) = stop.diagnostic() {
                    outln!("CPU {processor} priority {priority}: list walk stopped: {stop}");
                }
            }
            if total >= MAX_LIST_ENTRIES {
                break;
            }
        }
        if total == 0 {
            outln!("ready lists are empty or unavailable\n");
        } else {
            print_padded_table(builder);
        }
        if total >= MAX_LIST_ENTRIES {
            outln!("ready-list output bounded at {MAX_LIST_ENTRIES} entries\n");
        }
        Ok(())
    }

    fn cmd_dpcs(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if !invocation.argv.is_empty() {
            outln!("{}\n", command_help("!dpcs"));
            return Ok(());
        }
        let processors = match processor_indices(&self.ctx.target) {
            Ok(indices) => indices,
            Err(error) => {
                error!("processor count unavailable: {error}");
                return Ok(());
            }
        };
        let prcb_layout = match layout_for(&self.ctx.target, "_KPRCB") {
            Ok(layout) => layout,
            Err(error) => {
                error!("_KPRCB layout unavailable: {error}");
                return Ok(());
            }
        };
        let Some(dpc_data) = prcb_layout.fields.get("DpcData") else {
            error!("_KPRCB.DpcData field unavailable");
            return Ok(());
        };
        let data_count = array_count(&dpc_data.type_data, DPC_QUEUE_COUNT).min(DPC_QUEUE_COUNT);
        let data_stride =
            array_stride(&self.ctx.target, &dpc_data.type_data, dpc_data.size, 0x40).max(1);
        let data_type_name = array_element_type_name(&dpc_data.type_data)
            .or_else(|| aggregate_type_name(&dpc_data.type_data));
        let Some(data_type_name) = data_type_name else {
            error!("_KPRCB.DpcData element type unavailable");
            return Ok(());
        };
        let data_layout = match layout_for(&self.ctx.target, data_type_name) {
            Ok(layout) => layout,
            Err(error) => {
                error!("{data_type_name} layout unavailable: {error}");
                return Ok(());
            }
        };
        let Some(dpc_list) = data_layout.fields.get("DpcList") else {
            error!("{data_type_name}.DpcList field unavailable");
            return Ok(());
        };
        let dpc_list_offset = u64::from(dpc_list.offset);
        let dpc_link_offset = link_offset(
            &self.ctx.target,
            "_KDPC",
            &["DpcListEntry", "ListEntry", "SLink"],
        );
        let dpc_layout = layout_for(&self.ctx.target, "_KDPC").ok();
        let routine_field = dpc_layout.as_ref().and_then(|layout| {
            if layout.fields.contains_key("DeferredRoutine") {
                Some("DeferredRoutine")
            } else if layout.fields.contains_key("DpcRoutine") {
                Some("DpcRoutine")
            } else {
                None
            }
        });
        let context_field = dpc_layout.as_ref().and_then(|layout| {
            if layout.fields.contains_key("DeferredContext") {
                Some("DeferredContext")
            } else if layout.fields.contains_key("Context") {
                Some("Context")
            } else {
                None
            }
        });
        let importance_field = dpc_layout.as_ref().and_then(|layout| {
            layout
                .fields
                .contains_key("Importance")
                .then_some("Importance")
        });
        let trace = kernel_trace(&self.ctx.target);

        let mut builder = Builder::default();
        builder.push_record([
            "CPU",
            "Queue",
            "KDPC",
            "DeferredRoutine",
            "Context",
            "Importance",
        ]);
        let mut total = 0usize;
        for processor in processors {
            let prcb = match kprcb_for_processor(&self.ctx.target, processor) {
                Ok(address) => address,
                Err(error) => {
                    outln!("CPU {processor}: <unavailable: {error}>");
                    continue;
                }
            };
            for queue in 0..data_count {
                if total >= MAX_LIST_ENTRIES {
                    break;
                }
                let data = prcb + u64::from(dpc_data.offset) + (queue as u64) * data_stride;
                let head = data + dpc_list_offset;
                let remaining = MAX_LIST_ENTRIES - total;
                let (nodes, stop) = walk_list_nodes(&self.ctx.target, head, remaining);
                for node in nodes {
                    let dpc = dpc_link_offset.map(|offset| node - offset).unwrap_or(node);
                    let (routine, context, importance) = if dpc_link_offset.is_some() {
                        let routine = format_pointer_field(
                            &self.ctx.target,
                            &trace,
                            "_KDPC",
                            dpc,
                            routine_field,
                            "null",
                        );
                        let context =
                            format_context_field(&self.ctx.target, "_KDPC", dpc, context_field);
                        let importance = importance_field
                            .map(|field| {
                                match self.ctx.target.guest().and_then(|guest| {
                                    guest
                                        .ntoskrnl
                                        .types()
                                        .struct_at("_KDPC", dpc)
                                        .and_then(|cursor| cursor.read_field::<u8>(field))
                                }) {
                                    Ok(value) => value.to_string(),
                                    Err(error) => format!("<unavailable: {error}>"),
                                }
                            })
                            .unwrap_or_else(|| "<unavailable: field not present>".to_string());
                        (routine, context, importance)
                    } else {
                        (
                            "<unavailable: _KDPC link field not present>".to_string(),
                            "<unavailable: _KDPC link field not present>".to_string(),
                            "<unavailable: _KDPC link field not present>".to_string(),
                        )
                    };
                    builder.push_record([
                        processor.to_string(),
                        queue.to_string(),
                        ui::addr(dpc.0),
                        routine,
                        context,
                        importance,
                    ]);
                    total += 1;
                    if total >= MAX_LIST_ENTRIES {
                        break;
                    }
                }
                if let Some(stop) = stop.diagnostic() {
                    outln!("CPU {processor} queue {queue}: list walk stopped: {stop}");
                }
            }
            if total >= MAX_LIST_ENTRIES {
                break;
            }
        }
        if total == 0 {
            outln!("DPC queues are empty or unavailable\n");
        } else {
            print_padded_table(builder);
        }
        if total >= MAX_LIST_ENTRIES {
            outln!("DPC output bounded at {MAX_LIST_ENTRIES} entries\n");
        }
        Ok(())
    }

    fn cmd_timer(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let timer_layout = match layout_for(&self.ctx.target, "_KTIMER") {
            Ok(layout) => layout,
            Err(error) => {
                error!("_KTIMER layout unavailable: {error}");
                return Ok(());
            }
        };
        let trace = kernel_trace(&self.ctx.target);
        let interrupt = kuser_shared::read_interrupt_time(&self.ctx.target)
            .map(|value| (value, "KUSER_SHARED_DATA.InterruptTime"));
        let dpc_keys = timer_dpc_keys(&self.ctx.target);
        if let Some(argument) = invocation.arg(0) {
            let address =
                match Expr::eval_with_radix(&invocation.join_args(0), &self.ctx.target, self.radix)
                {
                    Ok(address) => address,
                    Err(error) => {
                        error!("invalid timer address '{}': {error}", argument);
                        return Ok(());
                    }
                };
            outln!("timer {}", ui::addr(address.0));
            let row = decode_timer(
                &self.ctx.target,
                address,
                &timer_layout,
                &trace,
                interrupt,
                dpc_keys,
            );
            outln!("  DueTime : {}", row.due);
            outln!("  Period  : {}", row.period);
            outln!("  DPC     : {}", row.dpc);
            outln!();
            return Ok(());
        }

        let prcb_layout = match layout_for(&self.ctx.target, "_KPRCB") {
            Ok(layout) => layout,
            Err(error) => {
                error!("_KPRCB layout unavailable: {error}");
                return Ok(());
            }
        };
        let Some(timer_table_field) = prcb_layout.fields.get("TimerTable") else {
            error!("_KPRCB.TimerTable field unavailable");
            return Ok(());
        };
        let table_type = aggregate_type_name(&timer_table_field.type_data)
            .ok_or_else(|| Error::DebugInfo("_KPRCB.TimerTable type unavailable".to_string()));
        let table_layout = match table_type {
            Ok(name) => match layout_for(&self.ctx.target, name) {
                Ok(layout) => layout,
                Err(error) => {
                    error!("{name} layout unavailable: {error}");
                    return Ok(());
                }
            },
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let Some(entries) = table_layout.fields.get("TimerEntries") else {
            error!("_KTIMER_TABLE.TimerEntries field unavailable");
            return Ok(());
        };
        let resolved_entry_count = array_count(&entries.type_data, TIMER_BUCKET_COUNT);
        let entry_type_name = array_element_type_name(&entries.type_data)
            .or_else(|| aggregate_type_name(&entries.type_data));
        let Some(entry_type_name) = entry_type_name else {
            error!("_KTIMER_TABLE entry type unavailable");
            return Ok(());
        };
        let entry_layout = match layout_for(&self.ctx.target, entry_type_name) {
            Ok(layout) => layout,
            Err(error) => {
                error!("{entry_type_name} layout unavailable: {error}");
                return Ok(());
            }
        };
        let entry_stride = entry_layout.size as u64;
        if entry_stride == 0 {
            error!(
                "_KTIMER_TABLE.TimerEntries leaf type {} has no size (field size {:#x})",
                entry_type_name, entries.size,
            );
            return Ok(());
        }
        if entries.size != 0
            && u64::try_from(resolved_entry_count)
                .ok()
                .and_then(|count| count.checked_mul(entry_stride))
                != Some(entries.size)
        {
            error!(
                "_KTIMER_TABLE.TimerEntries dimensions/size mismatch ({} entries * {:#x} != field size {:#x})",
                resolved_entry_count, entry_stride, entries.size
            );
            return Ok(());
        }
        let entry_count = resolved_entry_count.min(MAX_LIST_ENTRIES);
        let entry_name = if entry_layout.fields.contains_key("Entry") {
            "Entry"
        } else if entry_layout.fields.contains_key("TimerListEntry") {
            "TimerListEntry"
        } else {
            error!("{entry_type_name}.Entry field unavailable");
            return Ok(());
        };
        let Some(entry) = entry_layout.fields.get(entry_name) else {
            error!("{entry_type_name}.{entry_name} field unavailable");
            return Ok(());
        };
        let timer_link_offset = link_offset(
            &self.ctx.target,
            "_KTIMER",
            &["TimerListEntry", "TimerList", "ListEntry"],
        );
        outln!(
            "interrupt time {}",
            interrupt
                .map(|(value, source)| format!("{value:#x} [{source}]"))
                .unwrap_or_else(|| "<unavailable>".to_string())
        );

        let mut builder = Builder::default();
        builder.push_record(["CPU", "Bucket", "KTIMER", "DueTime", "Period", "DPC"]);
        let mut total = 0usize;
        let processors = match processor_indices(&self.ctx.target) {
            Ok(processors) => processors,
            Err(error) => {
                error!("processor count unavailable: {error}");
                return Ok(());
            }
        };
        for processor in processors {
            let prcb = match kprcb_for_processor(&self.ctx.target, processor) {
                Ok(address) => address,
                Err(error) => {
                    outln!("CPU {processor}: <unavailable: {error}>");
                    continue;
                }
            };
            let table = if matches!(timer_table_field.type_data, ParsedType::Pointer(_)) {
                let table_result = self.ctx.target.guest().and_then(|guest| {
                    guest
                        .ntoskrnl
                        .types()
                        .struct_at("_KPRCB", prcb)
                        .and_then(|cursor| cursor.read_field::<VirtAddr>("TimerTable"))
                });
                match table_result {
                    Ok(address) if !address.is_zero() => address,
                    Ok(_) => {
                        outln!("CPU {processor}: TimerTable is null");
                        continue;
                    }
                    Err(error) => {
                        outln!("CPU {processor}: TimerTable <unavailable: {error}>");
                        continue;
                    }
                }
            } else {
                prcb + u64::from(timer_table_field.offset)
            };
            for bucket in 0..entry_count {
                if total >= MAX_LIST_ENTRIES {
                    break;
                }
                let head = table
                    + u64::from(entries.offset)
                    + (bucket as u64) * entry_stride
                    + u64::from(entry.offset);
                let remaining = MAX_LIST_ENTRIES - total;
                let (nodes, stop) = walk_list_nodes(&self.ctx.target, head, remaining);
                for node in nodes {
                    let timer = timer_link_offset
                        .map(|offset| node - offset)
                        .unwrap_or(node);
                    let row = if timer_link_offset.is_some() {
                        decode_timer(
                            &self.ctx.target,
                            timer,
                            &timer_layout,
                            &trace,
                            interrupt,
                            dpc_keys,
                        )
                    } else {
                        TimerRow {
                            due: "<unavailable: _KTIMER link field not present>".to_string(),
                            period: "<unavailable: _KTIMER link field not present>".to_string(),
                            dpc: "<unavailable: _KTIMER link field not present>".to_string(),
                        }
                    };
                    builder.push_record([
                        (processor.to_string()),
                        (bucket.to_string()),
                        ui::addr(timer.0),
                        (row.due),
                        (row.period),
                        (row.dpc),
                    ]);
                    total += 1;
                    if total >= MAX_LIST_ENTRIES {
                        break;
                    }
                }
                if let Some(stop) = stop.diagnostic() {
                    outln!("CPU {processor} bucket {bucket}: list walk stopped: {stop}");
                }
            }
            if total >= MAX_LIST_ENTRIES {
                break;
            }
        }
        if total == 0 {
            outln!("timer table is empty or unavailable\n");
        } else {
            print_padded_table(builder);
        }
        if total >= MAX_LIST_ENTRIES {
            outln!("timer output bounded at {MAX_LIST_ENTRIES} entries\n");
        }
        Ok(())
    }

    fn cmd_apc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let thread_argument = (!invocation.argv.is_empty()).then(|| invocation.join_args(0));
        let threads = match apc_scope_threads(self, thread_argument.as_deref()) {
            Ok(threads) => threads,
            Err(error) => {
                error!("failed to select APC threads: {error}");
                return Ok(());
            }
        };
        if threads.is_empty() {
            outln!("no matching Windows threads\n");
            return Ok(());
        }
        let layout = resolve_apc_layout(&self.ctx.target);
        if let Err(error) = &layout {
            outln!("APC layout: <unavailable: {error}>\n");
        }
        let trace = kernel_trace(&self.ctx.target);
        let mut total = 0usize;
        for thread in threads.iter().take(APC_THREAD_DISPLAY_LIMIT) {
            outln!(
                "thread {}  ETHREAD {}  process {}",
                thread_tid(thread),
                ui::addr(thread.ethread.0),
                thread_process(thread)
            );
            let Ok(layout) = &layout else {
                continue;
            };
            let state_base = if layout.state_is_pointer {
                let state_result = self.ctx.target.guest().and_then(|guest| {
                    guest
                        .ntoskrnl
                        .types()
                        .struct_at("_KTHREAD", thread.kthread)
                        .and_then(|cursor| cursor.read_field::<VirtAddr>("ApcState"))
                });
                match state_result {
                    Ok(address) if !address.is_zero() => address,
                    Ok(_) => {
                        outln!("  APC state: <unavailable: null>");
                        continue;
                    }
                    Err(error) => {
                        outln!("  APC state: <unavailable: {error}>");
                        continue;
                    }
                }
            } else {
                thread.kthread + layout.state_offset
            };
            for (index, label) in [(0usize, "kernel"), (1usize, "user")] {
                if total >= MAX_LIST_ENTRIES {
                    break;
                }
                let head = state_base
                    + layout.heads_offset
                    + (index as u64) * layout.head_stride
                    + layout.head_list_offset;
                let remaining = MAX_LIST_ENTRIES - total;
                let (nodes, stop) = walk_list_nodes(&self.ctx.target, head, remaining);
                if nodes.is_empty() && matches!(stop, ListTermination::Head) {
                    continue;
                }
                for node in nodes {
                    let apc = layout
                        .link_offset
                        .map(|offset| node - offset)
                        .unwrap_or(node);
                    let (kernel_routine, normal_routine) = if layout.link_offset.is_some() {
                        (
                            format_pointer_field(
                                &self.ctx.target,
                                &trace,
                                "_KAPC",
                                apc,
                                layout.kernel_routine,
                                "null",
                            ),
                            format_pointer_field(
                                &self.ctx.target,
                                &trace,
                                "_KAPC",
                                apc,
                                layout.normal_routine,
                                "null",
                            ),
                        )
                    } else {
                        (
                            "<unavailable: _KAPC link field not present>".to_string(),
                            "<unavailable: _KAPC link field not present>".to_string(),
                        )
                    };
                    outln!(
                        "  {label:<6} APC {}  KernelRoutine {}  NormalRoutine {}",
                        ui::addr(apc.0),
                        kernel_routine,
                        normal_routine
                    );
                    total += 1;
                    if total >= MAX_LIST_ENTRIES {
                        break;
                    }
                }
                if let Some(stop) = stop.diagnostic() {
                    outln!("  {label} APC list stopped: {stop}");
                }
            }
            if total >= MAX_LIST_ENTRIES {
                break;
            }
        }
        if total >= MAX_LIST_ENTRIES {
            outln!("APC output bounded at {MAX_LIST_ENTRIES} entries\n");
        } else {
            outln!();
        }
        Ok(())
    }

    fn cmd_stacks(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let (level, filter_start) = match invocation.arg(0) {
            None => (0usize, 0usize),
            Some("0") => (0, 1),
            Some("1") => (1, 1),
            Some("2") => (2, 1),
            Some(_) => (0, 0),
        };
        let filter = if invocation.argv.len() > filter_start {
            Some(invocation.join_args(filter_start).to_ascii_lowercase())
        } else {
            None
        };
        let threads = match self.ctx.target.enumerate_threads() {
            Ok(threads) => threads,
            Err(error) => {
                let cached = self.caches.threads.read().unwrap().clone();
                if cached.is_empty() {
                    error!("failed to enumerate threads: {error}");
                    return Ok(());
                }
                outln!("thread enumeration unavailable ({error}); using cached thread metadata");
                cached
            }
        };
        *self.caches.threads.write().unwrap() = threads.clone();
        let frame_limit = match level {
            1 => MAX_STACK_FRAMES_LEVEL_1,
            2 => MAX_STACK_FRAMES_LEVEL_2,
            _ => 1,
        };
        outln!(
            "{} thread(s), level {}, frame bound {}{}",
            threads.len(),
            level,
            frame_limit,
            filter
                .as_deref()
                .map(|value| format!(", filter '{value}'"))
                .unwrap_or_default()
        );
        let mut displayed = 0usize;
        let mut interrupted = INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst);
        for thread in &threads {
            if interrupted || INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst) {
                interrupted = true;
                break;
            }
            let mut stack_error = None;
            let stack = match self.ctx.backtrace_thread(thread, frame_limit) {
                Ok(trace) => trace.stacktrace,
                Err(error) => {
                    stack_error = Some(error.to_string());
                    StackTrace {
                        frames: Vec::new(),
                        truncated: 0,
                    }
                }
            };
            let top = stack
                .frames
                .first()
                .map(|frame| frame.symbol.clone())
                .or_else(|| stack_error.map(|error| format!("<unavailable: {error}>")))
                .unwrap_or_else(|| "<unavailable>".to_string());
            let symbol_match = filter.as_deref().is_none_or(|needle| {
                top.to_ascii_lowercase().contains(needle)
                    || stack
                        .frames
                        .iter()
                        .any(|frame| frame.symbol.to_ascii_lowercase().contains(needle))
            });
            let process_match = filter
                .as_deref()
                .is_none_or(|needle| thread_process(thread).to_ascii_lowercase().contains(needle));
            if !symbol_match && !process_match {
                continue;
            }
            let tid = thread_tid(thread);
            outln!(
                "{}  {:<16}  {:<24}  {:<20}  {}",
                tid,
                thread_process(thread),
                thread_state(thread),
                thread_wait_reason(thread),
                top
            );
            displayed += 1;
            if level > 0 {
                for (index, frame) in stack.frames.iter().enumerate() {
                    outln!("    #{index:<2} {}", frame.symbol);
                }
            }
            if level > 0 && stack.truncated != 0 {
                outln!("    <{} additional frame(s) omitted>", stack.truncated);
            }
        }
        if interrupted {
            outln!("interrupted after {displayed} displayed thread(s)\n");
        }
        if displayed == 0 {
            outln!("no matching thread stacks\n");
        } else {
            outln!();
        }
        Ok(())
    }
}

struct TimerRow {
    due: String,
    period: String,
    dpc: String,
}

fn format_due_time(raw: u64, interrupt: Option<(u64, &'static str)>) -> String {
    let Some((now, _)) = interrupt else {
        return format!("{raw:#x}");
    };
    let (future, delta) = if raw >= now {
        (true, raw - now)
    } else {
        (false, now - raw)
    };
    if delta >= TIMER_DELTA_DISPLAY_LIMIT {
        return format!("{raw:#x}");
    }
    let millis = delta / HUNDRED_NS_PER_MS;
    if future {
        format!("{raw:#x} (+{millis} ms)")
    } else {
        format!("{raw:#x} (-{millis} ms, expired)")
    }
}

#[derive(Clone, Copy)]
struct TimerDpcKeys {
    wait_never: u64,
    wait_always: u64,
}

fn timer_dpc_keys(target: &Target) -> Option<TimerDpcKeys> {
    Some(TimerDpcKeys {
        wait_never: read_kernel_global_u64(target, "KiWaitNever").ok()?,
        wait_always: read_kernel_global_u64(target, "KiWaitAlways").ok()?,
    })
}

fn decode_timer_dpc(encoded: u64, timer: VirtAddr, keys: Option<TimerDpcKeys>) -> Option<VirtAddr> {
    let keys = keys?;
    let rotated = (encoded ^ keys.wait_never).rotate_left((keys.wait_never & 0xff) as u32);
    Some(VirtAddr(
        (rotated ^ timer.0).swap_bytes() ^ keys.wait_always,
    ))
}

fn decode_timer(
    target: &Target,
    timer: VirtAddr,
    timer_layout: &TypeInfo,
    trace: &ThreadTraceContext,
    interrupt: Option<(u64, &'static str)>,
    dpc_keys: Option<TimerDpcKeys>,
) -> TimerRow {
    let cursor = target
        .guest()
        .and_then(|guest| guest.ntoskrnl.types().struct_at("_KTIMER", timer));
    let due = if !timer_layout.fields.contains_key("DueTime") {
        "<unavailable: DueTime field not present>".to_string()
    } else {
        match cursor.as_ref() {
            Ok(cursor) => match cursor.read_field::<u64>("DueTime") {
                Ok(value) => format_due_time(value, interrupt),
                Err(error) => format!("<unavailable: {error}>"),
            },
            Err(error) => format!("<unavailable: {error}>"),
        }
    };
    let period = if !timer_layout.fields.contains_key("Period") {
        "<unavailable: Period field not present>".to_string()
    } else {
        match cursor.as_ref() {
            Ok(cursor) => match cursor.read_field::<u32>("Period") {
                Ok(value) => value.to_string(),
                Err(error) => format!("<unavailable: {error}>"),
            },
            Err(error) => format!("<unavailable: {error}>"),
        }
    };
    let dpc = if !timer_layout.fields.contains_key("Dpc") {
        "<unavailable: Dpc field not present>".to_string()
    } else {
        match cursor.as_ref() {
            Ok(cursor) => match cursor.read_field::<VirtAddr>("Dpc") {
                Ok(encoded) if encoded.is_zero() => "null".to_string(),
                Ok(encoded) => match decode_timer_dpc(encoded.0, timer, dpc_keys) {
                    None => format!("<encoded> {:#x}", encoded.0),
                    Some(address) if address.is_zero() => "null".to_string(),
                    Some(address) => match layout_for(target, "_KDPC") {
                        Ok(layout) => {
                            let routine = if layout.fields.contains_key("DeferredRoutine") {
                                Some("DeferredRoutine")
                            } else if layout.fields.contains_key("DpcRoutine") {
                                Some("DpcRoutine")
                            } else {
                                None
                            };
                            format_pointer_field(target, trace, "_KDPC", address, routine, "null")
                        }
                        Err(error) => format!("<unavailable: {error}>"),
                    },
                },
                Err(error) => format!("<unavailable: {error}>"),
            },
            Err(error) => format!("<unavailable: {error}>"),
        }
    };
    TimerRow { due, period, dpc }
}

fn current_selected_thread(state: &ReplState<'_>) -> Result<ThreadInfo> {
    if let Some(thread) = state.ctx.target.windows_thread_selection.as_ref() {
        return Ok(thread.clone());
    }
    let processor = processor_index_from_backend_thread_id(&state.ctx.current_thread)
        .ok_or_else(|| Error::DebugInfo("current Windows thread is unavailable".to_string()))?;
    state
        .ctx
        .target
        .current_windows_thread_for_processor(processor)
}

fn apc_scope_threads(state: &ReplState<'_>, argument: Option<&str>) -> Result<Vec<ThreadInfo>> {
    match argument {
        None | Some(".") => current_selected_thread(state).map(|thread| vec![thread]),
        Some("*") => state.ctx.target.enumerate_threads(),
        Some(argument) => {
            let threads = state.ctx.target.enumerate_threads()?;
            let address = Expr::eval_with_radix(argument, &state.ctx.target, state.radix)
                .ok()
                .map(|value| value.0);
            let exact: Vec<_> = threads
                .iter()
                .filter(|thread| {
                    address.is_some_and(|value| {
                        value == thread.ethread.0
                            || value == thread.kthread.0
                            || thread.tid == Some(value)
                    })
                })
                .cloned()
                .collect();
            if !exact.is_empty() {
                return Ok(exact);
            }
            let lower = argument.to_ascii_lowercase();
            Ok(threads
                .into_iter()
                .filter(|thread| {
                    address.is_some_and(|value| {
                        thread.pid == Some(value)
                            || thread.eprocess.is_some_and(|eprocess| eprocess.0 == value)
                    }) || thread_process(thread).to_ascii_lowercase().contains(&lower)
                })
                .collect())
        }
    }
}

struct ApcLayout {
    state_offset: u64,
    state_is_pointer: bool,
    heads_offset: u64,
    head_stride: u64,
    head_list_offset: u64,
    link_offset: Option<u64>,
    kernel_routine: Option<&'static str>,
    normal_routine: Option<&'static str>,
}

fn resolve_apc_layout(target: &Target) -> Result<ApcLayout> {
    let kthread = layout_for(target, "_KTHREAD")?;
    let state = kthread
        .fields
        .get("ApcState")
        .ok_or_else(|| Error::FieldNotFound("ApcState".to_string()))?;
    let state_name = aggregate_type_name(&state.type_data)
        .ok_or_else(|| Error::DebugInfo("ApcState type unavailable".to_string()))?;
    let state_layout = layout_for(target, state_name)?;
    let heads = state_layout
        .fields
        .get("ApcListHead")
        .ok_or_else(|| Error::FieldNotFound("ApcListHead".to_string()))?;
    let apc_layout = layout_for(target, "_KAPC").ok();
    let link_offset = link_offset(target, "_KAPC", &["ApcListEntry", "ListEntry"]);
    let head_stride = array_stride(target, &heads.type_data, heads.size, 16).max(1);
    Ok(ApcLayout {
        state_offset: u64::from(state.offset),
        state_is_pointer: matches!(state.type_data, ParsedType::Pointer(_)),
        heads_offset: u64::from(heads.offset),
        head_stride,
        head_list_offset: 0,
        link_offset,
        kernel_routine: apc_layout.as_ref().and_then(|layout| {
            layout
                .fields
                .contains_key("KernelRoutine")
                .then_some("KernelRoutine")
        }),
        normal_routine: apc_layout.as_ref().and_then(|layout| {
            layout
                .fields
                .contains_key("NormalRoutine")
                .then_some("NormalRoutine")
        }),
    })
}
