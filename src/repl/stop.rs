use std::time::Duration;

use owo_colors::OwoColorize;

use crate::dbg_backend::{BugcheckInfo, DebugBackend, StopEvent};
use crate::error::Result;
use crate::gdb::{BreakpointManager, RegisterMap};
use crate::session::{ContinueOutcome, Session, StopResolution};
use crate::target::{Target, ThreadInfo, kthread_state_name};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{format_symbol, resolve_thread_trace_context};

use crate::repl::*;

pub const REPL_STOP_POLL: Duration = Duration::from_millis(100);

pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;

pub use crate::session::processor_index_from_backend_thread_id;
pub use crate::session::refresh_windows_thread_context_for_backend_thread;

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
            print_break_context_at(
                &mut *session.backend,
                &session.register_map,
                &mut session.target,
                &session.breakpoints,
                &session.current_thread,
                None,
                (!breakpoint.temporary).then_some(cause),
            );
        }
        StopResolution::Bugcheck { event } => {
            print_bugcheck_summary(&session.target, event.bugcheck.as_ref());
            outln!();
            print_break_context_for_bugcheck(
                &mut *session.backend,
                &session.register_map,
                &mut session.target,
                &session.breakpoints,
                &session.current_thread,
                event.bugcheck.as_ref(),
            );
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
            print_break_context_at(
                &mut *session.backend,
                &session.register_map,
                &mut session.target,
                &session.breakpoints,
                &session.current_thread,
                None,
                cause,
            );
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
            print_break_context_at(
                &mut *session.backend,
                &session.register_map,
                &mut session.target,
                &session.breakpoints,
                &session.current_thread,
                None,
                cause.filter(|_| !temporary),
            );
        }
        ContinueOutcome::Bugcheck { info, .. } => {
            print_stop_separator();
            print_bugcheck_summary(&session.target, info.as_ref());
            outln!();
            print_break_context_for_bugcheck(
                &mut *session.backend,
                &session.register_map,
                &mut session.target,
                &session.breakpoints,
                &session.current_thread,
                info.as_ref(),
            );
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
            print_break_context_at(
                &mut *session.backend,
                &session.register_map,
                &mut session.target,
                &session.breakpoints,
                &session.current_thread,
                None,
                cause,
            );
        }
        ContinueOutcome::Step { .. } => {
            print_stop_separator();
            print_break_context(
                &mut *session.backend,
                &session.register_map,
                &mut session.target,
                &session.breakpoints,
                &session.current_thread,
            );
        }
    }
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

pub use crate::session::step_one_and_clear_tf;
pub use crate::session::step_over_current_breakpoint;

pub fn print_break_context(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &BreakpointManager,
    thread_id: &str,
) {
    print_break_context_at(
        client,
        register_map,
        debugger,
        breakpoints,
        thread_id,
        None,
        None,
    );
}

pub fn print_break_context_for_bugcheck(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &BreakpointManager,
    thread_id: &str,
    info: Option<&BugcheckInfo>,
) {
    print_break_context_at(
        client,
        register_map,
        debugger,
        breakpoints,
        thread_id,
        info.and_then(bugcheck_fault_ip),
        None,
    );
}

/// `cause` is an optional pre-styled tree child naming why execution stopped
/// (e.g. `breakpoint #3`), rendered first.
pub fn print_break_context_at(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &BreakpointManager,
    thread_id: &str,
    display_rip: Option<u64>,
    cause: Option<String>,
) {
    debugger.selected_frame = None;
    let regs = match client
        .set_current_thread(thread_id)
        .and_then(|()| client.read_registers())
    {
        Ok(r) => r,
        Err(e) => {
            debugger.registers = None;
            outln!(
                "{}{}\n",
                ui::badge("BREAK"),
                ui::plate(&format!(
                    " {} (register context unavailable: {}) ",
                    ui::thread_id(thread_id),
                    e
                ))
            );
            return;
        }
    };
    debugger.registers = Some(register_map.to_hashmap(&regs));

    let cr3 = register_map
        .read_u64(debugger.arch().dtb_register(), &regs)
        .unwrap_or(0);
    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
    let windows_thread = refresh_windows_thread_context_for_backend_thread(debugger, thread_id);
    let trace = resolve_thread_trace_context(debugger, cr3);
    let context_rip = display_rip.unwrap_or(rip);
    let symbol = format_symbol(debugger, &trace, context_rip);

    outln!(
        "{}{}",
        ui::badge("BREAK"),
        ui::plate(&format!(
            " {} {} at {} ",
            ui::thread_id(thread_id),
            trace.description,
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
    print_event_children(" ", &children);

    print_registers(register_map, &regs, true);
    print_disasm_context(debugger, breakpoints, &trace, context_rip);
    print_stacktrace(
        debugger,
        register_map,
        &regs,
        BREAK_STACKTRACE_PROBE_LIMIT,
        BREAK_STACKTRACE_DISPLAY_LIMIT,
        true,
    );
    outln!();
}

#[cfg(test)]
mod tests {
    use super::processor_index_from_backend_thread_id;

    #[test]
    fn backend_thread_ids_parse_as_zero_based_processors() {
        assert_eq!(processor_index_from_backend_thread_id("p1.1"), Some(0));
        assert_eq!(processor_index_from_backend_thread_id("p1.a"), Some(9));
        // QEMU pads both fields: `p01.01` is its first vCPU.
        assert_eq!(processor_index_from_backend_thread_id("p01.01"), Some(0));
        assert_eq!(processor_index_from_backend_thread_id("p01.0a"), Some(9));
        assert_eq!(processor_index_from_backend_thread_id("p1.0"), None);
        assert_eq!(processor_index_from_backend_thread_id("bad"), None);
    }
}
