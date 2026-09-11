use std::time::Duration;

use owo_colors::OwoColorize;

use crate::dbg_backend::{BugcheckInfo, DebugBackend, StopEvent};
use crate::error::Result;
use crate::gdb::{BreakpointManager, RegisterMap};
use crate::session::{Session, StopResolution};
use crate::target::{ReloadReport, Target, ThreadInfo, kthread_state_name};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{format_symbol, resolve_thread_trace_context};

use crate::repl::*;

/// Returns whether the kernel module set changed. New modules are loaded and
/// removed symbol registrations are pruned before breakpoint reconciliation.
pub fn refresh_kernel_module_symbols_on_stop(debugger: &Target, caches: &ReplCaches) -> bool {
    let Ok(report) = debugger.refresh_kernel_module_symbols() else {
        return false;
    };
    let changed = report.loaded != 0 || report.unloaded != 0;
    if report.loaded != 0 {
        print_module_symbol_report(&report);
    }
    if changed {
        caches.refresh_symbol_context(debugger);
    }
    changed
}

pub fn print_target_reload_report(report: &ReloadReport) {
    if let Some(startup) = &report.startup {
        println!(
            "{} kernel reloaded: {} -> {}, psmods {}",
            "target:".bright_black(),
            ui::addr(report.previous_base_address.0),
            ui::addr(startup.base_address.0),
            ui::addr_opt(startup.loaded_module_list)
        );
    } else {
        println!(
            "{} kernel reloaded: previous base {}",
            "target:".bright_black(),
            ui::addr(report.previous_base_address.0)
        );
    }

    if let Some(symbol_report) = &report.symbol_report {
        print_module_symbol_report(symbol_report);
    }
    if let Some(err) = &report.symbol_error {
        error!(
            "failed to refresh kernel module symbols after reload: {}",
            err
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetReloadStatus {
    Unchanged,
    Reloaded { loaded_module_list_available: bool },
    PendingRediscovery { kernel_base_hint: Option<VirtAddr> },
}

impl TargetReloadStatus {
    pub fn target_reloaded(self) -> bool {
        matches!(self, Self::Reloaded { .. })
    }

    pub fn pending_rediscovery(self) -> bool {
        matches!(self, Self::PendingRediscovery { .. })
    }

    fn loaded_module_list_available(self) -> bool {
        match self {
            Self::Reloaded {
                loaded_module_list_available,
            } => loaded_module_list_available,
            Self::Unchanged | Self::PendingRediscovery { .. } => false,
        }
    }

    fn kernel_base_hint(self) -> Option<VirtAddr> {
        match self {
            Self::PendingRediscovery { kernel_base_hint } => kernel_base_hint,
            _ => None,
        }
    }
}

pub const REPL_STOP_POLL: Duration = Duration::from_millis(100);

pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;

pub use crate::session::processor_index_from_backend_thread_id;

pub fn refresh_windows_thread_context_for_backend_thread(
    debugger: &mut Target,
    thread_id: &str,
) -> Option<ThreadInfo> {
    let thread = processor_index_from_backend_thread_id(thread_id).and_then(|processor| {
        debugger
            .current_windows_thread_for_processor(processor)
            .ok()
    });
    if let Some(thread) = thread.clone() {
        debugger.set_current_windows_thread_context(thread);
    } else {
        debugger.clear_current_windows_thread_context();
    }
    thread
}

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
pub fn refresh_stop_caches_pre(
    client: &mut dyn DebugBackend,
    debugger: &Target,
    breakpoints: &mut BreakpointManager,
    caches: &ReplCaches,
) -> bool {
    caches.refresh_vcpus(client);
    let symbols_changed = refresh_kernel_module_symbols_on_stop(debugger, caches);
    let event_changed = client.take_modules_changed();
    let modules_changed = symbols_changed || event_changed;
    if modules_changed {
        if let Err(error) = breakpoints.reconcile_symbolic_after_module_refresh(client, debugger) {
            error!("failed to reconcile breakpoints after module refresh: {error}");
        }
        caches.refresh_breakpoints(breakpoints);
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
    refresh_stop_caches_pre(
        &mut *session.backend,
        &session.target,
        &mut session.breakpoints,
        caches,
    );
    refresh_stop_caches_post(&session.target, caches);
    refresh_windows_thread_context_for_backend_thread(&mut session.target, &session.current_thread);

    print_stop_separator();
    match resolution {
        StopResolution::Resumed => {}
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
            println!();
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
            print_target_reload_notification_context(
                &session.target,
                &session.current_thread,
                &event,
                TargetReloadStatus::Reloaded {
                    loaded_module_list_available: coherent,
                },
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

pub fn is_target_reload_load_symbols_stop(
    event: &StopEvent,
    reload_status: TargetReloadStatus,
) -> bool {
    reload_status.target_reloaded()
        && event.exception_code.is_none()
        && event.target_kernel_base_hint.is_some()
}

pub fn print_target_reload_notification_context(
    debugger: &Target,
    current_thread: &str,
    event: &StopEvent,
    reload_status: TargetReloadStatus,
) {
    let pending_status = TargetReloadStatus::PendingRediscovery {
        kernel_base_hint: event.target_kernel_base_hint,
    };
    println!(
        "{}{}",
        ui::badge("BREAK"),
        ui::plate(&format!(
            " {} early boot at {} ",
            ui::thread_id(current_thread),
            pending_reload_location(debugger, event, pending_status, None)
        ))
    );
    let message = if reload_status.loaded_module_list_available() {
        "kernel reloaded; context is limited, continue to resume boot"
    } else {
        "kernel reloaded; module list is not available yet, continue to retry full reload"
    };
    print_event_children(" ", &[ui::muted(message)]);
    println!();
}

pub fn rebase_kernel_symbol_for_pending_reload(
    debugger: &Target,
    pc: u64,
    kernel_base_hint: Option<VirtAddr>,
) -> Option<String> {
    let new_base = kernel_base_hint?;
    let rva = pc.checked_sub(new_base.0)?;
    let guest = debugger.guest.as_ref()?;
    let old_addr = guest.ntoskrnl.base_address.0.checked_add(rva)?;
    let (module, symbol, offset) = debugger
        .symbols
        .find_closest_symbol_for_address(guest.ntoskrnl.dtb(), VirtAddr(old_addr))?;
    if offset > 0x1000 {
        return None;
    }
    Some(if offset == 0 {
        format!("{module}!{symbol}")
    } else {
        format!("{module}!{symbol}+{offset:#x}")
    })
}

pub fn pending_reload_location(
    debugger: &Target,
    event: &StopEvent,
    reload_status: TargetReloadStatus,
    register_kernel_base_hint: Option<VirtAddr>,
) -> String {
    let Some(pc) = event.program_counter else {
        return "unknown".bright_black().to_string();
    };
    let kernel_base_hint = reload_status
        .kernel_base_hint()
        .or(register_kernel_base_hint);
    rebase_kernel_symbol_for_pending_reload(debugger, pc, kernel_base_hint)
        .map(|symbol| ui::symbol(&symbol))
        .unwrap_or_else(|| ui::addr(pc))
}

pub fn pending_reload_register_kernel_base_hint(
    register_map: &RegisterMap,
    regs: &[u8],
    pc: u64,
) -> Option<VirtAddr> {
    let base = register_map.read_u64("r9", regs).ok()?;
    if !looks_like_kernel_pointer(base) {
        return None;
    }
    let rva = pc.checked_sub(base)?;
    (rva < CURRENT_KERNEL_RELOAD_WINDOW).then_some(VirtAddr(base))
}

pub fn surface_pending_stop(
    session: &mut Session,
    caches: &ReplCaches,
    exception_policies: &ExceptionPolicyTable,
) -> Result<bool> {
    let Some(event) = session.backend.try_wait_for_stop(REPL_STOP_POLL)? else {
        return Ok(false);
    };
    let resolution = session.classify_stop_event(event)?;
    if matches!(resolution, StopResolution::Resumed) {
        return Ok(true);
    }

    if let StopResolution::Stopped { event, .. } = &resolution
        && let ExceptionPolicyAction::Continue {
            notify,
            disposition,
            command: None,
        } = exception_policies.action_for(event)
    {
        if notify {
            let code = event.exception_code.unwrap_or_default();
            let chance = match event.first_chance {
                Some(true) => "first chance",
                Some(false) => "second chance",
                None => "unknown chance",
            };
            println!("Exception {code:#010x} ({chance}); continuing");
        }
        session
            .backend
            .continue_execution_with_disposition(disposition)?;
        session.record_continuation_disposition(disposition);
        return Ok(true);
    }

    print_async_stop_resolution(session, caches, resolution);
    Ok(true)
}

pub fn surface_interrupt_stop(session: &mut Session, caches: &ReplCaches) -> Result<()> {
    loop {
        let event = session.backend.interrupt()?;
        let resolution = session.classify_stop_event(event)?;
        if matches!(resolution, StopResolution::Resumed) {
            continue;
        }
        print_async_stop_resolution(session, caches, resolution);
        return Ok(());
    }
}

// In core so the REPL and Python SDK share identical step semantics.
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
    let regs = match client
        .set_current_thread(thread_id)
        .and_then(|()| client.read_registers())
    {
        Ok(r) => r,
        Err(e) => {
            debugger.registers = None;
            println!(
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

    let cr3 = register_map.read_u64("cr3", &regs).unwrap_or(0);
    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
    let windows_thread = refresh_windows_thread_context_for_backend_thread(debugger, thread_id);
    let trace = resolve_thread_trace_context(debugger, cr3);
    let context_rip = display_rip.unwrap_or(rip);
    let symbol = format_symbol(debugger, &trace, context_rip);

    println!(
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
    println!();
}

#[cfg(test)]
mod tests {
    use super::processor_index_from_backend_thread_id;

    #[test]
    fn backend_thread_ids_parse_as_zero_based_processors() {
        assert_eq!(processor_index_from_backend_thread_id("p1.1"), Some(0));
        assert_eq!(processor_index_from_backend_thread_id("p1.a"), Some(9));
        assert_eq!(processor_index_from_backend_thread_id("p1.0"), None);
        assert_eq!(processor_index_from_backend_thread_id("bad"), None);
    }
}
