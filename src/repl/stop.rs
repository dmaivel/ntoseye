use std::cell::Cell;
use std::collections::HashMap;
use std::time::Duration;

use owo_colors::OwoColorize;

use crate::dbg_backend::{
    BugcheckInfo, ContinueDisposition, ModuleEvent, processor_index_from_backend_thread_id,
};
use crate::diagnostics::print_notice;
use crate::error::{Error, Result};
use crate::guest::ModuleInfo;
use crate::repl::commands::display;
use crate::session::stops::module_event_line;
use crate::session::{
    BreakpointHit, Cancel, CancelBehavior, HitKind, Motion, RunOutcome, Session, ShownStop, Stop,
    StopKind,
};
use crate::target::{HYPERVISOR_CONTEXT, Target, ThreadInfo, kthread_state_name};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{
    StackTrace, ThreadTraceContext, UNKNOWN_CONTEXT, build_stacktrace_with_register_values,
    format_symbol, resolve_thread_trace_context_at, saved_vtls,
};

use crate::repl::*;

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
    // A resume left any partition view, and a partition breakpoint's hit
    // shows one.
    caches.refresh_partition(session.partition(), &session.target);
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

/// A stop [`Session::run`] reported: the cause the break banner names, then
/// the stopped context, then what the core noted meanwhile. Every REPL path
/// that surfaces a stop (a run command, a wait, a parked stop, a break-in)
/// renders it here.
impl Render for Stop {
    fn render(&self, repl: &mut ReplState<'_>, (): ()) {
        print_stop(repl.ctx, &repl.caches, self);
        repl.flush_notices();
    }
}

fn print_stop(session: &mut Session, caches: &ReplCaches, stop: &Stop) {
    session.target.selected_frame = None;
    refresh_stop_caches_pre(session, caches);
    refresh_stop_caches_post(&session.target, caches);
    refresh_windows_thread_context_for_backend_thread(&mut session.target, &session.current_thread);

    if let Some(error) = stop
        .breakpoint
        .as_ref()
        .and_then(|hit| hit.condition_error.as_deref())
    {
        error!("breakpoint condition failed: {error}");
    }
    print_stop_separator();
    match stop.kind {
        StopKind::Breakpoint => {
            let cause = stop.breakpoint.as_ref().map(breakpoint_cause);
            print_break_context_at(session, None, cause);
        }
        StopKind::ModuleLoad | StopKind::ModuleUnload => {
            let event = if stop.kind == StopKind::ModuleLoad {
                ModuleEvent::Load
            } else {
                ModuleEvent::Unload
            };
            match &stop.module {
                Some(module) => print_module_event_stop(session, event, module),
                None => print_break_context(session),
            }
        }
        StopKind::Bugcheck => {
            print_bugcheck_summary(&session.target, stop.bugcheck.as_ref());
            outln!();
            print_break_context_for_bugcheck(session, stop.bugcheck.as_ref());
        }
        StopKind::Reload => {
            caches.clear_threads();
            let coherent = stop.reload.is_none_or(|reload| reload.coherent);
            print_target_reload(&session.target, &session.current_thread, stop.rip, coherent);
        }
        StopKind::Exception => {
            let cause = stop
                .exception
                .and_then(|exception| stop_exception_cause(Some(exception.code), stop.rip));
            print_break_context_at(session, None, cause);
        }
        StopKind::Interrupt | StopKind::Step | StopKind::Entry => print_break_context(session),
    }
}

/// The cause a breakpoint hit's banner names: `breakpoint #3`, or what a
/// debug-register breakpoint watches (`hardware breakpoint #2 w8  nt!Foo`).
/// The address it watches is unrelated to `rip` for a data watch, so the
/// cause keeps the watched symbol while the banner shows where execution
/// stopped.
fn breakpoint_cause(hit: &BreakpointHit) -> String {
    let (kind, detail) = match hit.kind {
        HitKind::Code => {
            return format!("{} {}", ui::muted("breakpoint"), ui::bp_id(hit.id));
        }
        // A hypercall or VM-exit breakpoint is named for what it stops on;
        // the stop's children name the caller and its exit.
        HitKind::Hypercall => ("hypercall breakpoint", String::new()),
        HitKind::VmExit => (
            "VM-exit breakpoint",
            hit.exit_reason
                .as_deref()
                .map(|reason| format!(" {reason}"))
                .unwrap_or_default(),
        ),
        HitKind::Hardware | HitKind::Watch => (
            "hardware breakpoint",
            hit.access
                .zip(hit.length)
                .map(|(access, length)| format!(" {}{length}", access.letter()))
                .unwrap_or_default(),
        ),
    };
    format!(
        "{} {}{}{}",
        ui::muted(kind),
        ui::bp_id(hit.id),
        detail.bright_black(),
        hit.symbol
            .as_ref()
            .map(|symbol| format!("  {}", ui::symbol(symbol)))
            .unwrap_or_default()
    )
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
    let symbol = pc.and_then(|pc| {
        debugger
            .symbols
            .format_closest_symbol_for_address(debugger.kernel_dtb(), VirtAddr(pc))
    });
    #[cfg(feature = "cli")]
    native::render(
        || native::stop::reboot_card(current_thread, pc, symbol.as_deref(), coherent),
        || print_target_reload_text(current_thread, pc, symbol.as_deref(), coherent),
    );
    #[cfg(not(feature = "cli"))]
    print_target_reload_text(current_thread, pc, symbol.as_deref(), coherent);
}

fn print_target_reload_text(
    current_thread: &str,
    pc: Option<u64>,
    symbol: Option<&str>,
    coherent: bool,
) {
    let location = match (pc, symbol) {
        (None, _) => "unknown".bright_black().to_string(),
        (Some(_), Some(symbol)) => ui::symbol(symbol),
        (Some(pc), None) => ui::addr(pc),
    };
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
    print_section("registers (saved VTL0)");
    print_sparse_registers(saved, None, 2);
    let (trace, rip, stack) = saved_vtl0_code(session, saved);
    print_disasm_context(session, &trace, rip);
    print_stacktrace_data(&stack, BREAK_STACKTRACE_DISPLAY_LIMIT, true);
}

/// Where the saved VTL0 state left off: its trace context, its `rip` and
/// its stack.
fn saved_vtl0_code(
    session: &Session,
    saved: &HashMap<String, u64>,
) -> (ThreadTraceContext, u64, StackTrace) {
    let debugger = &session.target;
    let rip = saved.get("rip").copied().unwrap_or(0);
    let cr3 = saved
        .get(debugger.arch().dtb_register())
        .copied()
        .unwrap_or(0);
    let trace = resolve_thread_trace_context_at(debugger, cr3, rip);
    let stack = build_stacktrace_with_register_values(
        debugger,
        &session.register_map,
        saved,
        BREAK_STACKTRACE_PROBE_LIMIT,
    );
    (trace, rip, stack.into_stacktrace())
}

/// What a stop shows, gathered once for either renderer.
struct StopContext {
    thread: String,
    context: String,
    symbol: String,
    /// Why it stopped, styled.
    cause: Option<String>,
    /// Where a bugcheck stop parked, when its banner names the fault site.
    stopped_at: Option<String>,
    windows_thread: Option<ThreadInfo>,
    /// The hypervisor's saved state and notes, styled.
    notes: Vec<String>,
    /// The stop card names a bugcheck in its chip.
    #[cfg(feature = "cli")]
    bugcheck: bool,
    regs: Vec<u8>,
    /// The register file of the previous stop on the same thread, when the
    /// display marks what changed since.
    before: Option<Vec<u8>>,
    /// The `display` expressions, evaluated at this stop.
    displays: Vec<display::Shown>,
    /// The saved VTL0 registers a hypervisor stop inspects instead of the
    /// vCPU's.
    saved: Option<HashMap<String, u64>>,
    trace: ThreadTraceContext,
    rip: u64,
    /// How much of it the text renderer draws.
    detail: StopDetail,
}

/// How much of a stop a compact host draws (see [`Session::compact_stops`]).
#[derive(Clone, Copy, PartialEq, Eq)]
enum StopDetail {
    /// The whole card: banner, registers, code and stack.
    Full,
    /// After a stop on the same thread, such as a step: the banner, the
    /// registers that changed, the next few instructions, and the stack
    /// only when the function changed.
    Changes { stack: bool },
    /// The banner alone, for a stop in the middle of a line.
    Banner,
}

/// Instructions a compact stop shows after a step.
const COMPACT_DISASM_INSTRUCTIONS: usize = 3;

/// The function part of a stop's symbol: `nt!NtClose+0x5` is in
/// `nt!NtClose`.
fn function_of(symbol: &str) -> &str {
    symbol
        .rsplit_once('+')
        .map_or(symbol, |(function, _)| function)
}

impl StopContext {
    /// The lines under the banner, as the text renderer lists them.
    fn children(&self) -> Vec<String> {
        let mut children = Vec::new();
        children.extend(self.cause.clone());
        children.extend(self.stopped_at.clone());
        children.extend(self.windows_thread.as_ref().map(format_windows_thread));
        children.extend(self.notes.iter().cloned());
        children
    }
}

fn print_stop_text(session: &Session, stop: &StopContext) {
    outln!(
        "{}{}",
        ui::badge("BREAK"),
        ui::plate(&format!(
            " {} {} at {} ",
            ui::thread_id(&stop.thread),
            stop.context,
            ui::symbol(&stop.symbol)
        ))
    );
    print_event_children(" ", &stop.children());
    match stop.detail {
        StopDetail::Full => {}
        StopDetail::Banner => {
            outln!();
            return;
        }
        StopDetail::Changes { stack } => {
            print_changed_registers(&session.register_map, &stop.regs, stop.before.as_deref());
            print_disasm_lines(session, &stop.trace, stop.rip, COMPACT_DISASM_INSTRUCTIONS);
            if stack {
                print_stacktrace(
                    &session.target,
                    &session.register_map,
                    &stop.regs,
                    BREAK_STACKTRACE_PROBE_LIMIT,
                    BREAK_STACKTRACE_DISPLAY_LIMIT,
                    true,
                );
            }
            print_displays(&stop.displays);
            outln!();
            return;
        }
    }
    if let Some(saved) = &stop.saved {
        print_saved_vtl0_context(session, saved);
        print_displays(&stop.displays);
        outln!();
        return;
    }
    print_registers(
        &session.register_map,
        &stop.regs,
        stop.before.as_deref(),
        true,
    );
    print_disasm_context(session, &stop.trace, stop.rip);
    print_stacktrace(
        &session.target,
        &session.register_map,
        &stop.regs,
        BREAK_STACKTRACE_PROBE_LIMIT,
        BREAK_STACKTRACE_DISPLAY_LIMIT,
        true,
    );
    print_displays(&stop.displays);
    outln!();
}

/// The `display` expressions under a stop, in a section of their own.
fn print_displays(shown: &[display::Shown]) {
    if shown.is_empty() {
        return;
    }
    print_section("display");
    display::print(shown);
}

#[cfg(feature = "cli")]
fn stop_view(session: &Session, stop: &StopContext, tone: tern_sdk::ui::Tone) -> tern_sdk::View {
    let ran = native::take_run();
    let lines: Vec<String> = stop.stopped_at.iter().chain(&stop.notes).cloned().collect();
    let (registers, rows, current, stack) = match &stop.saved {
        Some(saved) => {
            let (trace, rip, stack) = saved_vtl0_code(session, saved);
            let grid = native::styled(|| print_sparse_registers(saved, None, 0));
            (
                (
                    vec![native::span("registers (saved VTL0)", "")],
                    native::block(&grid).into(),
                ),
                disasm_context_rows(session, &trace, rip),
                rip,
                stack,
            )
        }
        None => {
            let map = &session.register_map;
            let read = |name: &str| map.read_u64(name, &stop.regs).ok();
            let changed = |name: &str| {
                read(name).is_some_and(|value| changed(map, name, value, stop.before.as_deref()))
            };
            let grid = native::frames::register_grid(&read, &changed);
            // Folded by default, the section's head names what changed.
            let names = native::frames::changed_registers(&read, &changed);
            let mut head = vec![native::span("registers", "")];
            if !names.is_empty() {
                head.push(native::span(
                    format!("  {} changed", names.join(" ")),
                    native::MUTED,
                ));
            }
            let stack = thread_stacktrace(
                &session.target,
                &session.register_map,
                &stop.regs,
                BREAK_STACKTRACE_PROBE_LIMIT,
            );
            (
                (head, grid.into()),
                disasm_context_rows(session, &stop.trace, stop.rip),
                stop.rip,
                stack,
            )
        }
    };
    native::stop::stop_card(native::stop::Stop {
        thread: &stop.thread,
        context: &stop.context,
        symbol: &stop.symbol,
        tone,
        cause: stop.cause.as_deref(),
        bugcheck: stop.bugcheck,
        windows_thread: stop.windows_thread.as_ref(),
        lines: &lines,
        registers,
        code: rows.as_deref().map_err(|note| note.trim().to_owned()),
        current,
        stack: &stack,
        stack_limit: BREAK_STACKTRACE_DISPLAY_LIMIT,
        ran,
        displays: (!stop.displays.is_empty()).then(|| native::frames::displays(&stop.displays)),
    })
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
    #[cfg(feature = "cli")]
    let tone = native::stop::tone(
        cause.as_deref(),
        display_rip.is_some(),
        trace.description == HYPERVISOR_CONTEXT,
    );

    // Bugcheck stops park at the break inside KeBugCheck, not at the fault
    // site the banner names.
    let stopped_at = display_rip
        .is_some_and(|display_rip| display_rip != rip)
        .then(|| {
            let stop_symbol = format_symbol(debugger, &trace, rip);
            format!("{} {}", ui::muted("stopped at"), ui::symbol(&stop_symbol))
        });
    let mut children: Vec<String> = Vec::new();
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
    let saved = saved_context
        .then(|| {
            debugger
                .selected_frame
                .as_ref()
                .map(|frame| frame.registers.clone())
        })
        .flatten();
    // The previous stop's registers count only on the same vCPU and the
    // same Windows thread: a stop elsewhere would mark nearly everything.
    let ethread = windows_thread.as_ref().map_or(0, |thread| thread.ethread.0);
    let previous = session
        .shown_stop
        .take()
        .filter(|shown| shown.thread == thread_id && shown.ethread == ethread);
    let detail = if !session.compact_stops {
        StopDetail::Full
    } else if session.brief_stops {
        StopDetail::Banner
    } else if let Some(previous) = previous.as_ref().filter(|_| saved.is_none()) {
        StopDetail::Changes {
            stack: function_of(&previous.symbol) != function_of(&symbol),
        }
    } else {
        StopDetail::Full
    };
    let before = previous.map(|shown| shown.regs);
    session.shown_stop = Some(ShownStop {
        thread: thread_id.clone(),
        ethread,
        regs: regs.clone(),
        symbol: symbol.clone(),
    });
    let displays = display::evaluate(session, true);
    let stop = StopContext {
        thread: thread_id,
        context,
        symbol,
        cause,
        stopped_at,
        windows_thread,
        notes: children,
        #[cfg(feature = "cli")]
        bugcheck: display_rip.is_some(),
        regs,
        before,
        displays,
        saved,
        trace,
        rip: context_rip,
        detail,
    };
    #[cfg(feature = "cli")]
    native::render(
        || stop_view(session, &stop, tone),
        || print_stop_text(session, &stop),
    );
    #[cfg(not(feature = "cli"))]
    print_stop_text(session, &stop);
}

/// How long `g` on a running target waits for a stop it already reported.
const PENDING_STOP_POLL: Duration = Duration::from_millis(100);

/// The cancellation of a run a dispatch drives within its stop `budget`: a
/// remote client's budget hands the target back running when it is spent;
/// the interactive prompt (no budget) waits for a stop or Ctrl+C (the
/// session's interrupt request, which halts).
fn budget_cancel<'a>(
    budget: Option<&'a StopWaitBudget>,
    tick: Option<&'a dyn Fn(&mut Session)>,
) -> Cancel<'a> {
    Cancel {
        flag: budget.map(|budget| &*budget.cancel),
        deadline: budget.and_then(|budget| budget.deadline),
        behavior: CancelBehavior::ReturnRunning,
        tick,
    }
}

/// The cancellation a `kind = Run` command that drives its own run (`wt`)
/// gets: Ctrl+C or a remote client's budget ends it, halted where it got to.
pub fn run_cancel(budget: Option<&StopWaitBudget>) -> Cancel<'_> {
    budget_cancel(budget, None).with_behavior(CancelBehavior::Halt)
}

impl ReplState<'_> {
    /// Drive a run command's motion and render where it ended: the REPL
    /// half of `#[command(kind = Run)]`.
    pub fn run_motion(&mut self, motion: Motion) {
        // `.vtl 1` is a memory view, not the vCPU's context: resume from the
        // live context so the stop that follows is rendered as itself.
        self.leave_vtl1();
        // What the operation noted before the run (an unconfirmed `g`
        // site), above the run it is about.
        self.flush_notices();
        match motion {
            Motion::Continue { disposition } => self.resume(disposition),
            Motion::Break => {
                self.clear_selected_frame();
                let outcome = self.ctx.run(Motion::Break, &Cancel::NEVER);
                self.report_run(outcome, "failed to interrupt");
            }
            Motion::Wait => {
                let outcome = self.drive(Motion::Wait, true);
                self.report_run(outcome, "error waiting for stop");
            }
            Motion::Step => {
                let outcome = self.drive(Motion::Step, false);
                self.report_run(outcome, "failed to step");
            }
            Motion::StepOver | Motion::StepOut => {
                let failure = if matches!(motion, Motion::StepOver) {
                    "failed to step over"
                } else {
                    "failed to step out"
                };
                match self.ctx.plan(motion) {
                    Ok(planned) => {
                        let outcome = self.drive(planned, true);
                        self.report_run(outcome, failure);
                    }
                    Err(error) => error!("{error}"),
                }
            }
            Motion::RunTo { address, .. } => {
                let outcome = self.drive(motion, true);
                self.report_run(
                    outcome,
                    &format!("failed to run to {}", ui::addr(address.0)),
                );
            }
            // A walk into or over calls; a remote client's budget ends it
            // where it is.
            Motion::Walk { .. } => match self.drive(motion, false) {
                Err(error @ Error::StepLimit(_)) => {
                    error!("{error}");
                    print_stop_separator();
                    print_break_context(self.ctx);
                }
                outcome => self.report_run(outcome, "failed while stepping"),
            },
        }
    }

    /// Resume (`g`, `gh`, `gn` without an address) and render the stop. On
    /// a running target, a stop it already reported is rendered; otherwise
    /// it keeps the run it is on.
    fn resume(&mut self, disposition: ContinueDisposition) {
        self.clear_selected_frame();
        if self.ctx.backend.is_running() {
            let cancel = Cancel::within(PENDING_STOP_POLL);
            match self.ctx.run(Motion::Wait, &cancel) {
                Ok(RunOutcome::Stopped(stop)) => stop.render(self, ()),
                Ok(RunOutcome::Running) => error!("VM is running"),
                Err(e) => error!("error checking running VM: {e}"),
            }
            return;
        }
        let motion = Motion::Continue { disposition };
        // A remote host's bounded wait for a stop nothing is set to cause
        // only spends its budget; an empty line waits for one anyway, and a
        // wait with no limit waits, ended by Ctrl+C as at the prompt.
        if self.stop_wait_bounded() && !self.stop_is_set() {
            match self.ctx.run(motion, &Cancel::poll()) {
                Ok(RunOutcome::Running) => outln!(
                    "{}",
                    ui::muted(
                        "the target runs on: no breakpoint or event filter is set to stop it, so \
                         this does not wait (an empty line waits for a stop anyway)"
                    )
                ),
                outcome => self.report_run(outcome, "failed to continue"),
            }
            return;
        }
        let outcome = self.drive(motion, true);
        self.report_run(outcome, "failed to continue");
    }

    /// Run `motion` through the session's driver within this dispatch's
    /// stop budget, printing what arrives while it runs: guest prints (for a
    /// backend without KD's stream), notices, and, for a run that waits at
    /// the prompt and `announce`s it, the running indicator. Breakpoint
    /// actions print as they run.
    fn drive(&mut self, motion: Motion, announce: bool) -> Result<RunOutcome> {
        let announce = announce && self.stop_wait.is_none();
        let announced = Cell::new(false);
        let printed = Cell::new(self.printed_debug_seq);
        let interactive = self.context == DispatchContext::Interactive;
        let tick = |session: &mut Session| {
            if announce && !announced.get() && session.backend.is_running() {
                announced.set(true);
                let print = || {
                    outln!(
                        "{}",
                        "VM running, waiting for stop (Ctrl+C to pause)...".bright_black()
                    )
                };
                #[cfg(feature = "cli")]
                native::running(print);
                #[cfg(not(feature = "cli"))]
                print();
            }
            if interactive && !session.backend_streams_debug_output() {
                let page = session.read_debug_output(printed.get());
                printed.set(page.next_seq);
                for line in page.lines {
                    eprintln!("{}", line.text);
                }
            }
            for notice in session.take_notices() {
                print_notice(&notice);
            }
        };
        self.clear_selected_frame();
        let cancel = budget_cancel(self.stop_wait.as_ref(), Some(&tick));
        let outcome = self.ctx.run(motion, &cancel);
        self.printed_debug_seq = printed.get();
        if announced.get() {
            // A wait that ended without a stop (an error, a spent budget)
            // still stops the indicator.
            #[cfg(feature = "cli")]
            native::finish_running();
            // Past the `^C` the terminal echoed.
            if let Ok(RunOutcome::Stopped(stop)) = &outcome
                && stop.kind == StopKind::Interrupt
            {
                outln!();
            }
        }
        outcome
    }

    /// Render what a run ended on: its stop, or that a remote client's
    /// budget handed the target back still running. `failure` names what
    /// failed for an error.
    fn report_run(&mut self, outcome: Result<RunOutcome>, failure: &str) {
        match outcome {
            Ok(RunOutcome::Stopped(stop)) => stop.render(self, ()),
            Ok(RunOutcome::Running) => self.print_still_running(),
            Err(error) => {
                error!("{failure}: {error}");
                if self.ctx.backend.is_running() {
                    outln!(
                        "{}",
                        ui::muted("target still running; use `break` to try again")
                    );
                }
            }
        }
    }

    /// Say that a remote client's stop budget ran out with the target still
    /// running, and how to go on.
    fn print_still_running(&self) {
        let hint = if self.context == DispatchContext::Remote(RemoteClient::Sdk) {
            "target still running; `dbg.wait()` to keep waiting, or `dbg.interrupt()` to \
             break in"
        } else {
            "target still running; call again to keep waiting, or `break` to interrupt"
        };
        outln!("{}", ui::muted(hint));
    }

    /// Collect the next stop for a host that hands control back while the
    /// target runs: a stop the idle servicer already parked is rendered at
    /// once; otherwise wait (within [`ReplState::stop_wait`]) for one and
    /// render it. A halted target with nothing pending returns immediately.
    pub fn collect_stop(&mut self) {
        if self.ctx.backend.is_running() || self.ctx.stop_pending() {
            self.run_motion(Motion::Wait);
        }
    }

    /// The start of a call from a host that hands control back while the
    /// target runs: a stop parked since the last call is rendered first, and
    /// an empty line only waits for the next stop. Returns the flow to report
    /// instead of dispatching `line`; `None` means dispatch it (each command
    /// on it is then admitted by [`ReplState::gate_remote_command`]).
    pub fn begin_remote_line(&mut self, line: &str) -> Option<Flow> {
        self.surface_parked_stop();
        if line.is_empty() {
            self.collect_stop();
            return Some(Flow::Continue);
        }
        None
    }

    /// Admit one resolved command for a remote host, against the target's
    /// state at this point in the line (a `break` earlier on the same line
    /// has already halted it). As WinDbg queues input typed at a running
    /// debuggee, a command that needs the target halted (or would move it)
    /// waits within the stop budget for the halt; nothing runs while the
    /// target is still running. MCP refuses one resume against a stop the
    /// client has not seen; the SDK has no such gate because the stop is
    /// exposed as `dbg.stop`. Returns the flow to report instead of running
    /// the command; `None` means run it now.
    pub fn gate_remote_command(&mut self, spec: &CommandSpec, typed: &str) -> Option<Flow> {
        let client = match self.context {
            DispatchContext::Remote(client)
                if matches!(client, RemoteClient::Mcp | RemoteClient::Sdk) =>
            {
                client
            }
            _ => return None,
        };
        let name = typed;
        let moves = spec.effects.run != RunEffect::None;
        let needs_halt = spec.effects.needs_halt(self.ctx);
        if self.ctx.backend.is_running() && (moves || needs_halt) {
            // Waiting out a time limit for a stop no breakpoint will cause
            // only spends it. The guest can still stop by itself (a
            // bugcheck, a `DbgBreakPoint` over KD), which an empty line
            // waits for, as does a wait with no limit, which a caller ends
            // with Ctrl+C as at the prompt.
            let can_stop = !self.stop_wait_bounded()
                || self.ctx.backend.has_pending_stop()
                || self.stop_is_set();
            if !can_stop {
                outln!(
                    "'{name}' was not run: the target is running and no breakpoint or event \
                     filter is set to stop it. `break` halts it (`break; {name}` on one line), \
                     and an empty line waits for a stop anyway."
                );
                return Some(Flow::Denied);
            }
            self.collect_stop();
            if self.ctx.backend.is_running() {
                outln!("'{name}' was not run.");
                return Some(Flow::Denied);
            }
            self.unseen_stop_rendered = true;
        }
        if client == RemoteClient::Mcp && self.unseen_stop_rendered && moves {
            outln!(
                "the target stopped (above); '{name}' was not run so the stop is not \
                 skipped. Re-issue it to continue."
            );
            return Some(Flow::Denied);
        }
        None
    }

    /// Render a stop the idle servicer parked (or the backend caught) since
    /// the last dispatch, if any, without waiting: its action runs first, and
    /// one that resumes leaves nothing to render. Returns whether one was
    /// rendered; a remote host then refuses to resume past it on this call.
    pub fn surface_parked_stop(&mut self) -> bool {
        if !self.ctx.stop_pending() {
            return false;
        }
        self.clear_selected_frame();
        match self.ctx.run(Motion::Wait, &Cancel::poll()) {
            Ok(RunOutcome::Stopped(stop)) => {
                stop.render(self, ());
                self.unseen_stop_rendered = true;
                true
            }
            Ok(RunOutcome::Running) => {
                self.flush_notices();
                false
            }
            Err(error) => {
                error!("error collecting the stop: {error}");
                false
            }
        }
    }

    /// Whether something the user set will stop the target: an enabled
    /// breakpoint, or a module load or unload filter that breaks (`sxe ld`,
    /// `sxe ud:<module>`). What stops it unasked, a bugcheck or a
    /// `DbgBreakPoint` over KD, does not count.
    fn stop_is_set(&self) -> bool {
        self.ctx
            .breakpoints
            .list()
            .iter()
            .any(|breakpoint| breakpoint.enabled)
            || self
                .ctx
                .exception_policies
                .module_event_entries()
                .any(|policy| policy.mode == ExceptionPolicyMode::Break)
    }

    /// Whether this dispatch's wait for a stop has a time limit: an MCP
    /// call's, or an SDK call given a timeout.
    fn stop_wait_bounded(&self) -> bool {
        self.stop_wait
            .as_ref()
            .is_some_and(|budget| budget.deadline.is_some())
    }
}
