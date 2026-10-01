use std::collections::HashMap;
use std::time::Duration;

use owo_colors::OwoColorize;

use crate::dbg_backend::{
    BugcheckInfo, ModuleEvent, StopEvent, processor_index_from_backend_thread_id,
};
use crate::error::Result;
use crate::guest::ModuleInfo;
use crate::session::stops::module_event_line;
use crate::session::{ContinueOutcome, Session, StopResolution};
use crate::target::{HYPERVISOR_CONTEXT, Target, ThreadInfo, kthread_state_name};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{
    UNKNOWN_CONTEXT, build_stacktrace_with_register_values, format_symbol,
    resolve_thread_trace_context_at, saved_vtls,
};

use crate::repl::*;

pub const REPL_STOP_POLL: Duration = Duration::from_millis(100);

pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;

pub use crate::session::context::refresh_windows_thread_context_for_backend_thread;

/// One-line summary: `thread Idle  state Running  ethread <addr>  pid 0  tid 0`.
/// The leading `thread` label distinguishes it from the break line above,
/// which names the process context (via CR3), not the thread's owner.
fn format_windows_thread(thread: &ThreadInfo) -> String {
    let process = thread.process_name.as_deref().unwrap_or("unknown");
    let mut line = format!("{} {}", ui::muted("thread"), process);
    if let Some(state) = thread.state {
        line.push_str(&format!(
            "  {} {}",
            ui::muted("state"),
            kthread_state_name(state)
        ));
    }
    line.push_str(&format!(
        "  {} {}",
        ui::muted("ethread"),
        ui::addr(thread.ethread.0)
    ));
    if let Some(pid) = thread.pid {
        line.push_str(&format!("  {} {pid}", ui::muted("pid")));
    }
    if let Some(tid) = thread.tid {
        line.push_str(&format!("  {} {tid}", ui::muted("tid")));
    }
    line
}

/// The exception cause child for a BREAK banner, e.g. `exception 0x80000003
/// at fffff807c0c5a0d0`. `None` when the stop carried no exception code.
pub fn stop_exception_cause(
    exception_code: Option<u32>,
    program_counter: Option<u64>,
) -> Option<String> {
    let code = exception_code?;
    Some(match program_counter {
        Some(pc) => format!("{} {:#x} at {}", ui::muted("exception"), code, ui::addr(pc)),
        None => format!("{} {:#x}", ui::muted("exception"), code),
    })
}

/// Refresh the caches the stop output depends on (vcpus, kernel module symbols),
/// done before any stop notice prints so it reflects the current kernel image.
/// Returns whether the kernel module set changed (a driver/module loaded or
/// unloaded), so the caller can refresh module-dependent caches. Both signals are
/// consulted/cleared: the backend load event (KD) and the per-stop module-list
/// diff (any backend).
pub fn refresh_stop_caches_pre(session: &mut Session, caches: &ReplCaches) -> bool {
    caches.refresh_vcpus(&mut *session.backend);
    let modules_changed = session.refresh_modules_on_stop();
    let report = session.take_module_refresh_report();
    if let Some(report) = report.as_ref().filter(|report| report.loaded != 0) {
        print_module_symbol_report(report);
    }
    if modules_changed {
        caches.refresh_symbol_context(&session.target);
        caches.refresh_breakpoints(&session.breakpoints);
    }
    modules_changed
}

/// Refresh the completion caches derived from debugger state after a stop.
/// Both the async and synchronous stop paths call this, so the set can't
/// drift. Guest lists (processes, drivers) are deliberately not walked here:
/// completions enumerate them on demand, memoized per halt.
pub fn refresh_stop_caches_post(debugger: &Target, caches: &ReplCaches) {
    caches.refresh_expression_context(debugger);
}

/// Render a stop after [`Session::classify_stop_event`] has completed all
/// backend and debugger-state transitions.
pub fn print_async_stop_resolution(
    session: &mut Session,
    caches: &ReplCaches,
    resolution: StopResolution,
) {
    session.target.selected_frame = None;
    refresh_stop_caches_pre(session, caches);
    refresh_stop_caches_post(&session.target, caches);
    refresh_windows_thread_context_for_backend_thread(&mut session.target, &session.current_thread);

    print_stop_separator();
    match resolution {
        StopResolution::Resumed | StopResolution::ModulesChanged => {}
        StopResolution::Breakpoint {
            breakpoint,
            condition_error,
            ..
        } => {
            if let Some(error) = condition_error {
                error!("breakpoint condition failed: {error}");
            }
            let label = if breakpoint.hardware.is_some() {
                "watchpoint"
            } else {
                "breakpoint"
            };
            let mut cause = format!("{} {}", ui::muted(label), ui::bp_id(breakpoint.id));
            if breakpoint.hardware.is_some() {
                cause.push_str(&format!(" at {}", ui::addr(breakpoint.address.0)));
                if let Some(symbol) = breakpoint.symbol.as_deref() {
                    cause.push_str(&format!(" ({})", ui::symbol(symbol)));
                }
            }
            print_break_context_at(session, None, (!breakpoint.temporary).then_some(cause));
        }
        StopResolution::ModuleLoad { module, .. } => {
            print_module_event_stop(session, ModuleEvent::Load, &module)
        }
        StopResolution::ModuleUnload { module, .. } => {
            print_module_event_stop(session, ModuleEvent::Unload, &module)
        }
        StopResolution::Bugcheck { event } => {
            print_bugcheck_summary(&session.target, event.bugcheck.as_ref());
            outln!();
            print_break_context_for_bugcheck(session, event.bugcheck.as_ref());
        }
        StopResolution::TargetReloaded { event, coherent } => {
            caches.clear_threads();
            print_target_reload(
                &session.target,
                &session.current_thread,
                event.program_counter,
                coherent,
            );
        }
        StopResolution::Stopped { event, .. } => {
            let cause = stop_exception_cause(event.exception_code, event.program_counter);
            print_break_context_at(session, None, cause);
        }
    }
}

/// Render a stop the session already classified and parked (see
/// [`Session::take_parked_stop`]) the way the continue loop would have,
/// so a request/response host's stops read like the interactive REPL's.
pub fn print_parked_outcome(session: &mut Session, caches: &ReplCaches, outcome: ContinueOutcome) {
    session.target.selected_frame = None;
    refresh_stop_caches_pre(session, caches);
    refresh_stop_caches_post(&session.target, caches);
    refresh_windows_thread_context_for_backend_thread(&mut session.target, &session.current_thread);

    match outcome {
        ContinueOutcome::Running | ContinueOutcome::Halted { .. } => (),
        ContinueOutcome::Breakpoint {
            id,
            temporary,
            condition_error,
            ..
        } => {
            print_stop_separator();
            if let Some(error) = condition_error {
                error!("breakpoint condition failed: {error}");
            }
            let cause = session.breakpoint(id).map(|breakpoint| {
                let label = if breakpoint.hardware.is_some() {
                    "watchpoint"
                } else {
                    "breakpoint"
                };
                let mut cause = format!("{} {}", ui::muted(label), ui::bp_id(id));
                if breakpoint.hardware.is_some() {
                    cause.push_str(&format!(" at {}", ui::addr(breakpoint.address.0)));
                    if let Some(symbol) = breakpoint.symbol.as_deref() {
                        cause.push_str(&format!(" ({})", ui::symbol(symbol)));
                    }
                }
                cause
            });
            print_break_context_at(session, None, cause.filter(|_| !temporary));
        }
        ContinueOutcome::ModuleLoad { module, .. } => {
            print_stop_separator();
            print_module_event_stop(session, ModuleEvent::Load, &module);
        }
        ContinueOutcome::ModuleUnload { module, .. } => {
            print_stop_separator();
            print_module_event_stop(session, ModuleEvent::Unload, &module);
        }
        ContinueOutcome::Bugcheck { info, .. } => {
            print_stop_separator();
            print_bugcheck_summary(&session.target, info.as_ref());
            outln!();
            print_break_context_for_bugcheck(session, info.as_ref());
        }
        ContinueOutcome::TargetReloaded { rip, coherent, .. } => {
            print_stop_separator();
            caches.clear_threads();
            print_target_reload(&session.target, &session.current_thread, rip, coherent);
        }
        ContinueOutcome::Stopped {
            rip,
            exception_code,
            ..
        } => {
            print_stop_separator();
            let cause = stop_exception_cause(exception_code, Some(rip));
            print_break_context_at(session, None, cause);
        }
        ContinueOutcome::Step { .. } => {
            print_stop_separator();
            print_break_context(session);
        }
    }
}

/// Render a stop at a module load or unload a `sxe ld`/`sxe ud` filter
/// names: WinDbg's `ModLoad:` or `Unload module` line, then the stop context
/// like any other stop.
pub fn print_module_event_stop(session: &mut Session, event: ModuleEvent, module: &ModuleInfo) {
    outln!("{}", module_event_line(event, module));
    let what = match event {
        ModuleEvent::Load => "module load",
        ModuleEvent::Unload => "module unload",
    };
    let cause = format!("{} {}", ui::muted(what), module.name);
    print_break_context_at(session, None, Some(cause));
}

/// Announce a reboot the session has already rebuilt debugger state for, so
/// `pc` symbolizes against the new kernel. Only the kernel is trusted here:
/// the stop may be in early boot, before threads or processes exist to walk.
pub fn print_target_reload(
    debugger: &Target,
    current_thread: &str,
    pc: Option<u64>,
    coherent: bool,
) {
    let location = pc.map_or_else(
        || "unknown".bright_black().to_string(),
        |pc| {
            debugger
                .symbols
                .format_closest_symbol_for_address(debugger.kernel_dtb(), VirtAddr(pc))
                .map_or_else(|| ui::addr(pc), |symbol| ui::symbol(&symbol))
        },
    );
    outln!(
        "{}{}",
        ui::badge("BREAK"),
        ui::plate(&format!(
            " {} kernel at {} ",
            ui::thread_id(current_thread),
            location
        ))
    );
    let message = if coherent {
        "guest rebooted; kernel reloaded"
    } else {
        "guest rebooted; kernel reloaded, module list not available yet (continue to finish)"
    };
    print_event_children(" ", &[ui::muted(message)]);
    outln!();
}

/// Drain one stop the running target has already reported. Returns whether a
/// stop was surfaced to the user; a noise stop that was resumed (or an
/// exception a policy continued) leaves the target running and returns
/// `false`, so callers that want a stop keep going and break in.
pub fn surface_pending_stop(session: &mut Session, caches: &ReplCaches) -> Result<bool> {
    let Some(event) = session.backend.try_wait_for_stop(REPL_STOP_POLL)? else {
        return Ok(false);
    };
    let resolution = session.classify_stop_event(event)?;
    if matches!(
        resolution,
        StopResolution::Resumed | StopResolution::ModulesChanged
    ) {
        return Ok(false);
    }

    if let StopResolution::Stopped { event, .. } = &resolution
        && continue_exception_policy(session, event)?
    {
        return Ok(false);
    }

    print_async_stop_resolution(session, caches, resolution);
    Ok(true)
}

/// Apply a command-free automatic continue for an exception stop.
pub fn continue_exception_policy(session: &mut Session, event: &StopEvent) -> Result<bool> {
    let ExceptionPolicyAction::Continue {
        notify,
        disposition,
        command: None,
    } = session.exception_policies.action_for(event)
    else {
        return Ok(false);
    };
    if notify {
        let chance = match event.first_chance {
            Some(true) => "first chance",
            Some(false) => "second chance",
            None => "unknown chance",
        };
        outln!(
            "Exception {:#010x} ({chance}); continuing",
            event.exception_code.unwrap_or_default()
        );
    }
    session.target.selected_frame = None;
    session
        .backend
        .continue_execution_with_disposition(disposition)?;
    session.record_continuation_disposition(disposition);
    Ok(true)
}

pub use crate::session::stepping::step_one_and_clear_tf;
pub use crate::session::stepping::step_over_current_breakpoint;

pub fn print_break_context(session: &mut Session) {
    print_break_context_at(session, None, None);
}

pub fn print_break_context_for_bugcheck(session: &mut Session, info: Option<&BugcheckInfo>) {
    print_break_context_at(session, info.and_then(bugcheck_fault_ip), None);
}

/// The stop display for the saved VTL0 state selected at a stop in the
/// Windows hypervisor: its registers (the general-purpose ones only when
/// they were recovered), the NT code it left off at, and its stack.
fn print_saved_vtl0_context(session: &Session, saved: &HashMap<String, u64>) {
    let debugger = &session.target;
    print_section("registers (saved VTL0)");
    print_sparse_registers(saved, None, 2);
    let rip = saved.get("rip").copied().unwrap_or(0);
    let cr3 = saved
        .get(debugger.arch().dtb_register())
        .copied()
        .unwrap_or(0);
    let trace = resolve_thread_trace_context_at(debugger, cr3, rip);
    print_disasm_context(session, &trace, rip);
    let stack = build_stacktrace_with_register_values(
        debugger,
        &session.register_map,
        saved,
        BREAK_STACKTRACE_PROBE_LIMIT,
    );
    print_stacktrace_data(
        &stack.into_stacktrace(),
        BREAK_STACKTRACE_DISPLAY_LIMIT,
        true,
    );
}

/// `cause` is an optional pre-styled tree child naming why execution stopped
/// (e.g. `breakpoint #3`), rendered first.
pub fn print_break_context_at(
    session: &mut Session,
    display_rip: Option<u64>,
    cause: Option<String>,
) {
    session.target.selected_frame = None;
    let thread_id = session.current_thread.clone();
    let regs = match session
        .backend
        .set_current_thread(&thread_id)
        .and_then(|()| session.backend.read_registers())
    {
        Ok(r) => r,
        Err(e) => {
            session.target.registers = None;
            outln!(
                "{}{}\n",
                ui::badge("BREAK"),
                ui::plate(&format!(
                    " {} (register context unavailable: {}) ",
                    ui::thread_id(&thread_id),
                    e
                ))
            );
            return;
        }
    };
    let register_map = &session.register_map;
    let debugger = &mut session.target;
    debugger.registers = Some(register_map.to_hashmap(&regs));

    let cr3 = register_map
        .read_u64(debugger.arch().dtb_register(), &regs)
        .unwrap_or(0);
    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
    let windows_thread = refresh_windows_thread_context_for_backend_thread(debugger, &thread_id);
    let trace = resolve_thread_trace_context_at(debugger, cr3, rip);
    let context_rip = display_rip.unwrap_or(rip);
    let symbol = format_symbol(debugger, &trace, context_rip);
    // A vCPU running a guest partition's VP shows that guest's registers.
    let context = (trace.description == UNKNOWN_CONTEXT)
        .then(|| processor_index_from_backend_thread_id(&thread_id))
        .flatten()
        .and_then(|number| debugger.guest_vp_label(number))
        .unwrap_or_else(|| trace.description.clone());

    outln!(
        "{}{}",
        ui::badge("BREAK"),
        ui::plate(&format!(
            " {} {} at {} ",
            ui::thread_id(&thread_id),
            context,
            ui::symbol(&symbol)
        ))
    );

    let mut children: Vec<String> = Vec::new();
    if let Some(cause) = cause {
        children.push(cause);
    }
    // Bugcheck stops park at the break inside KeBugCheck, not at the fault
    // site the banner names.
    if display_rip.is_some_and(|display_rip| display_rip != rip) {
        let stop_symbol = format_symbol(debugger, &trace, rip);
        children.push(format!(
            "{} {}",
            ui::muted("stopped at"),
            ui::symbol(&stop_symbol)
        ));
    }
    if let Some(thread) = windows_thread {
        children.push(format_windows_thread(&thread));
    }
    // At a stop in the Windows hypervisor NT is what is inspected: where it
    // left off becomes the context, `.cxr` returns to the hypervisor's.
    let saved_context = debugger.select_saved_vtl0(&thread_id);
    // Where NT left off on a vCPU the hypervisor holds.
    if trace.description == HYPERVISOR_CONTEXT {
        let processor = processor_index_from_backend_thread_id(&thread_id);
        match saved_vtls(debugger, cr3, rip, processor) {
            Ok(saved) => {
                children.extend(
                    saved
                        .iter()
                        .filter(|saved| saved.summarized())
                        .map(|saved| {
                            let detail = saved
                                .context
                                .exit_detail()
                                .map(|detail| ui::muted(&format!("  {detail}")))
                                .unwrap_or_default();
                            format!(
                                "{} {}{detail}",
                                ui::muted("saved"),
                                ui::symbol(&saved.describe())
                            )
                        }),
                );
                // The note explains why VTL0 is not selected; a stale VTL1
                // is marked on its own line.
                if saved
                    .iter()
                    .any(|saved| saved.context.vtl == 0 && saved.context.may_be_stale)
                {
                    children.push(ui::muted(
                        "stopped on the hypervisor's VM-exit entry: KVM writes the saved state when it \
                         enters the hypervisor, so it may still describe the previous exit and is not \
                         selected (.vtlcxr selects it anyway; a breakpoint on the entry sees the \
                         current exit)",
                    ));
                }
            }
            Err(error) => children.push(ui::muted(&format!("saved VTL state: {error}"))),
        }
        // The guest's VP whose exit the hypervisor handles here, when the
        // processor runs one: what the stop is about, more than the root's.
        if let Some(served) =
            processor.and_then(|number| debugger.served_guest_vp(cr3, rip, number))
        {
            children.push(format!(
                "{} {}  {}",
                ui::muted("serving"),
                served.label(),
                ui::muted(&served.describe())
            ));
        }
        if saved_context {
            children.push(ui::muted(
                "inspecting saved VTL0 (.cxr shows the hypervisor's registers)",
            ));
        }
    }
    print_event_children(" ", &children);

    if saved_context
        && let Some(saved) = debugger
            .selected_frame
            .as_ref()
            .map(|frame| frame.registers.clone())
    {
        print_saved_vtl0_context(session, &saved);
        outln!();
        return;
    }

    print_registers(&session.register_map, &regs, true);
    print_disasm_context(session, &trace, context_rip);
    print_stacktrace(
        &session.target,
        &session.register_map,
        &regs,
        BREAK_STACKTRACE_PROBE_LIMIT,
        BREAK_STACKTRACE_DISPLAY_LIMIT,
        true,
    );
    outln!();
}
