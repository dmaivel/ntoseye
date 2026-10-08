use std::sync::atomic::Ordering;

use owo_colors::OwoColorize;

use crate::breakpoints::Breakpoint;
use crate::breakpoints::StepFrame;
use crate::dbg_backend::{ContinueDisposition, ModuleEvent};
use crate::diagnostics;
use crate::disasm::ControlFlow;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::ModuleInfo;
use crate::session::{
    CallTraceEnd, CallTraceFrame, ContinueOutcome, STEP_UNTIL_LIMIT, StepKind, StepMode, StepStack,
    StopResolution,
};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    continue_vm;
    names: ["g", "continue"],
    usage: "g [address]",
    summary: "Resume VM execution.",
    details: "With an address, g runs to a temporary breakpoint at that address. ntoseye checks that an instruction starts there as bp does: it refuses an address inside an instruction and warns when it cannot check. In secure-kernel code, this breakpoint uses a debug register, and ntoseye never patches the code. The .vtl 1 memory view accepts only g without an address, which leaves the view before it resumes the VM. To stop in VTL1, use `ba e1`.",
    completion: Expression,
    run: Run,
}

repl_command! {
    continue_handled;
    names: ["gh"],
    usage: "gh [address]",
    summary: "Resume and mark the current exception handled.",
    completion: Expression,
    run: Run,
}

repl_command! {
    continue_not_handled;
    names: ["gn"],
    usage: "gn [address]",
    summary: "Resume and pass the current exception to Windows (KD only).",
    completion: Expression,
    run: Run,
}

repl_command! {
    interrupt_running_vm();
    names: ["break"],
    usage: "break",
    summary: "Break in and pause VM execution.",
    run_state: Running,
}

repl_command! {
    single_step();
    names: ["t", "si"],
    usage: "t",
    summary: "Step one instruction (step into).",
    run_state: Halted,
    run: Step,
}

repl_command! {
    cmd_p();
    names: ["p", "ni"],
    usage: "p or ni",
    summary: "Step over the current instruction.",
    details: "If the instruction is a call, p runs to the instruction after the call and stops there only when the thread that you step returns from that call. Other threads that get to the address, and deeper calls of the same code, continue to run.",
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_gu();
    names: ["gu", "finish"],
    usage: "gu or finish",
    summary: "Run until the current function returns.",
    details: "gu stops at the return address only when the thread that you step returns from this call. Other threads that get to the address, and deeper calls of the same function, continue to run.",
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_pa;
    names: ["pa"],
    usage: "pa <address>",
    summary: "Step over repeatedly until execution gets to an address.",
    completion: Expression,
    run: Run,
}

repl_command! {
    cmd_ta;
    names: ["ta"],
    usage: "ta <address>",
    summary: "Step into repeatedly until execution gets to an address.",
    completion: Expression,
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_pc();
    names: ["pc"],
    usage: "pc",
    summary: "Step over until the next call instruction.",
    completion: None,
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_tc();
    names: ["tc"],
    usage: "tc",
    summary: "Step into until the next call instruction.",
    completion: None,
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_pt();
    names: ["pt"],
    usage: "pt",
    summary: "Step over until the next return instruction.",
    completion: None,
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_tt();
    names: ["tt"],
    usage: "tt",
    summary: "Step into until the next return instruction.",
    completion: None,
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_ph();
    names: ["ph"],
    usage: "ph",
    summary: "Step over until the next branch instruction.",
    completion: None,
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_th();
    names: ["th"],
    usage: "th",
    summary: "Step into until the next branch instruction.",
    completion: None,
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_wt;
    names: ["wt"],
    usage: "wt [count]",
    summary: "Watch and trace calls until the current function returns.",
    completion: Expression,
    run_state: Halted,
    run: Run,
}

const WATCH_TRACE_DEFAULT_LIMIT: usize = 10_000;

fn render_trace_frame(frame: &CallTraceFrame, depth: usize) {
    outln!(
        "{}{} ({} instructions)",
        "  ".repeat(depth),
        frame.name,
        frame.instructions
    );
    for child in &frame.children {
        render_trace_frame(child, depth + 1);
    }
}

impl ReplState<'_> {
    /// Collect the next stop for a host that hands control back while the
    /// target runs: a stop the idle servicer already parked is rendered at
    /// once; otherwise wait (within [`ReplState::stop_wait`]) for one and
    /// render it. A halted target with nothing pending returns immediately.
    pub fn collect_stop(&mut self) -> Result<()> {
        if self.surface_parked_stop() {
            return Ok(());
        }
        if self.ctx.backend.is_running() {
            self.clear_selected_frame();
            let waited = self.wait_for_stop_after_resume();
            self.flush_notices();
            return waited;
        }
        Ok(())
    }

    /// The start of a call from a host that hands control back while the
    /// target runs: a stop parked since the last call is rendered first, and
    /// an empty line only waits for the next stop. Returns the flow to report
    /// instead of dispatching `line`; `None` means dispatch it (each command
    /// on it is then admitted by [`ReplState::gate_remote_command`]).
    pub fn begin_remote_line(&mut self, line: &str) -> Result<Option<Flow>> {
        self.surface_parked_stop();
        if line.is_empty() {
            self.collect_stop()?;
            return Ok(Some(Flow::Continue));
        }
        Ok(None)
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
    pub fn gate_remote_command(&mut self, spec: &CommandSpec) -> Result<Option<Flow>> {
        let client = match self.context {
            DispatchContext::Remote(client)
                if matches!(client, RemoteClient::Mcp | RemoteClient::Sdk) =>
            {
                client
            }
            _ => return Ok(None),
        };
        let name = spec.names[0];
        let moves = spec.run != RunEffect::None;
        let needs_halt = crate::repl::command::needs_halt(self, spec);
        if self.ctx.backend.is_running() && (moves || needs_halt) {
            // Waiting out the budget for a stop no breakpoint will cause
            // only spends it. The guest can still stop by itself (a
            // bugcheck, a `DbgBreakPoint` over KD), which an empty line
            // waits for.
            let can_stop = self.ctx.backend.has_pending_stop()
                || self
                    .ctx
                    .breakpoints
                    .list()
                    .iter()
                    .any(|breakpoint| breakpoint.enabled);
            if !can_stop {
                outln!(
                    "'{name}' was not run: the target is running and no breakpoint is set to \
                     stop it. `break` halts it (`break; {name}` on one line), and an empty line \
                     waits for a stop anyway."
                );
                return Ok(Some(Flow::Denied));
            }
            self.collect_stop()?;
            if self.ctx.backend.is_running() {
                outln!("'{name}' was not run.");
                return Ok(Some(Flow::Denied));
            }
            self.unseen_stop_rendered = true;
        }
        if client == RemoteClient::Mcp && self.unseen_stop_rendered && moves {
            outln!(
                "the target stopped (above); '{name}' was not run so the stop is not \
                 skipped. Re-issue it to continue."
            );
            return Ok(Some(Flow::Denied));
        }
        Ok(None)
    }

    /// Render a stop the idle servicer parked since the last dispatch, if
    /// any, without waiting. Returns whether one was rendered; a remote host
    /// then refuses to resume past it on this call.
    pub fn surface_parked_stop(&mut self) -> bool {
        let Some(outcome) = self.ctx.take_parked_stop() else {
            return false;
        };
        self.clear_selected_frame();
        print_parked_outcome(self.ctx, &self.caches, outcome);
        self.flush_notices();
        self.unseen_stop_rendered = true;
        true
    }

    pub fn interrupt_running_vm(&mut self) -> Result<()> {
        self.clear_selected_frame();
        let had_pending_stop = self.ctx.backend.has_pending_stop();
        let mut apply_pending_exception_policy = had_pending_stop;
        let mut outcome = match self.ctx.interrupt_outcome() {
            Ok(outcome) => outcome,
            Err(error) => {
                error!("failed to interrupt: {error}");
                return Ok(());
            }
        };

        // A pending stop whose exception policy continues without a command
        // is continued, then broken into again, so the requested pause still
        // ends on a visible stop.
        if had_pending_stop
            && matches!(&outcome, ContinueOutcome::Stopped { .. })
            && let Some(event) = self.ctx.last_event.as_ref().map(|last| last.stop.clone())
            && continue_exception_policy(self.ctx, &event)?
        {
            apply_pending_exception_policy = false;
            outcome = match self.ctx.interrupt_outcome() {
                Ok(outcome) => outcome,
                Err(error) => {
                    error!("failed to interrupt: {error}");
                    return Ok(());
                }
            };
        }

        let surfaced = !matches!(
            &outcome,
            ContinueOutcome::Running | ContinueOutcome::Halted { .. }
        );
        print_parked_outcome(self.ctx, &self.caches, outcome);

        if apply_pending_exception_policy
            && surfaced
            && let Err(error) = self.apply_buffered_exception_policy()
        {
            error!("failed to apply exception policy: {error}");
        }

        Ok(())
    }

    fn continue_vm(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.resume(invocation, ContinueDisposition::Handled)
    }

    fn continue_handled(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.resume(invocation, ContinueDisposition::Handled)
    }

    fn continue_not_handled(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.resume(invocation, ContinueDisposition::NotHandled)
    }

    fn resume(
        &mut self,
        invocation: CommandInvocation<'_>,
        disposition: ContinueDisposition,
    ) -> Result<()> {
        let expression = invocation.raw_tail.trim();
        // The `.vtl 1` view names addresses in VTL1 but holds no vCPU
        // context to run from; refused before anything leaves the view.
        if !expression.is_empty() && self.ctx.target.in_secure_scope() {
            error!(
                "'{} <address>' is unavailable in the .vtl 1 memory view; set `ba e1 <address>` \
                 and resume with plain {}",
                invocation.name, invocation.name
            );
            return Ok(());
        }
        // `.vtl 1` is a memory view, not the vCPU's context: resume from the
        // live context so the stop that follows is rendered as itself.
        self.leave_vtl1();
        if expression.is_empty() {
            return self.continue_vm_with_disposition(disposition);
        }
        match Expr::eval_with_radix(expression, &self.ctx.target, self.radix) {
            Ok(address) => {
                // Secure-kernel code and a partition's take a debug register
                // for the run, which writes nothing.
                let patched =
                    self.ctx.partition().is_none() && !self.ctx.target.is_secure_address(address);
                let check = patched
                    .then(|| self.check_instruction_start(self.ctx.target.current_dtb(), address));
                match check {
                    Some(Ok(Some(warning))) => diagnostics::print_warning(warning),
                    Some(Err(error)) => {
                        error!("{error}");
                        return Ok(());
                    }
                    Some(Ok(None)) | None => {}
                }
                self.run_to_temporary_code_breakpoint_with_disposition(address, None, disposition)
                    .map(|_| ())
            }
            Err(error) => {
                error!("invalid {} address: {error}", invocation.name);
                Ok(())
            }
        }
    }

    /// Run the `-c` commands of the `sxe ld` or `sxe ud` filter that stopped
    /// at `event` for `module`.
    fn run_module_event_command(&mut self, event: ModuleEvent, module: &ModuleInfo) -> Result<()> {
        let command = self
            .ctx
            .exception_policies
            .module_event_policy(event, &module.name)
            .and_then(|policy| policy.command.clone());
        self.run_exception_policy_command(command.as_deref())
    }

    fn run_exception_policy_command(&mut self, command: Option<&str>) -> Result<()> {
        if let Some(command) = command {
            self.dispatch_exception_command(command)?;
        }
        Ok(())
    }

    /// A pending stop is rendered by the asynchronous stop helper before it can
    /// hand control back here. Commands still run, and an explicit continue
    /// outcome is applied afterward; command-free auto-continues were already
    /// completed by the helper.
    fn apply_buffered_exception_policy(&mut self) -> Result<()> {
        match self.ctx.current_stop().cloned() {
            Some(ContinueOutcome::ModuleLoad { module, .. }) => {
                return self.run_module_event_command(ModuleEvent::Load, &module);
            }
            Some(ContinueOutcome::ModuleUnload { module, .. }) => {
                return self.run_module_event_command(ModuleEvent::Unload, &module);
            }
            _ => {}
        }
        let Some(event) = self.ctx.last_event.as_ref().map(|last| last.stop.clone()) else {
            return Ok(());
        };
        match self.ctx.exception_policies.action_for(&event) {
            ExceptionPolicyAction::Surface {
                command: Some(command),
            } => self.run_exception_policy_command(Some(&command)),
            ExceptionPolicyAction::Continue {
                notify,
                disposition,
                command: Some(command),
            } => {
                self.run_exception_policy_command(Some(&command))?;
                if notify {
                    outln!(
                        "Exception {:#010x}; continuing",
                        event.exception_code.unwrap_or_default()
                    );
                }
                self.ctx
                    .backend
                    .continue_execution_with_disposition(disposition)?;
                self.ctx.record_continuation_disposition(disposition);
                Ok(())
            }
            ExceptionPolicyAction::Surface { command: None }
            | ExceptionPolicyAction::Continue { command: None, .. } => Ok(()),
        }
    }

    fn continue_vm_with_disposition(&mut self, disposition: ContinueDisposition) -> Result<()> {
        self.clear_selected_frame();
        if self.ctx.backend.is_running() {
            match surface_pending_stop(self.ctx, &self.caches) {
                Ok(true) => {
                    if let Err(error) = self.apply_buffered_exception_policy() {
                        error!("failed to apply exception policy: {error}");
                    }
                }
                Ok(false) => error!("VM is running"),
                Err(e) => error!("error checking running VM: {e}"),
            }
            return Ok(());
        }

        if let Err(e) = self.ctx.resume_with_disposition(disposition) {
            error!("failed to continue: {e}");
            return Ok(());
        }

        // A remote host's bounded wait for a stop no breakpoint will cause
        // only spends its budget; an empty line waits for one anyway.
        if self.stop_wait.is_some()
            && !self
                .ctx
                .breakpoints
                .list()
                .iter()
                .any(|breakpoint| breakpoint.enabled)
        {
            outln!(
                "{}",
                ui::muted(
                    "the target runs on: no breakpoint is set to stop it, so this does not wait \
                     (an empty line waits for a stop anyway)"
                )
            );
            return Ok(());
        }
        self.wait_for_stop_after_resume()
    }

    pub fn wait_for_stop_after_resume(&mut self) -> Result<()> {
        if !self.quiet_stops && self.stop_wait.is_none() {
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

        self.ctx.target.interrupt.store(false, Ordering::SeqCst);

        loop {
            let interrupt_requested = self.ctx.target.interrupt.swap(false, Ordering::SeqCst);
            // A Ctrl+C breaks in, and again past any hit a filter declines
            // meanwhile: on code the whole system runs those arrive first,
            // and resuming past one lost the Ctrl+C.
            let stop_result = if interrupt_requested {
                outln!();
                self.ctx
                    .interrupt_classified()
                    .map(|(resolution, _)| Some(Ok(resolution)))
            } else {
                self.ctx
                    .backend
                    .try_wait_for_stop(REPL_STOP_POLL)
                    .map(|event| event.map(|event| self.ctx.classify_stop_event(event)))
            };

            match stop_result {
                Ok(Some(classified)) => {
                    let resolution = match classified {
                        // A stream of absorbed hits (a temporary site other
                        // threads reach) must not outlast the budget either.
                        Ok(StopResolution::Resumed | StopResolution::ModulesChanged) => {
                            // An `sxn ld` line reads as the load happens.
                            self.flush_notices();
                            if self.stop_budget_spent() {
                                break;
                            }
                            continue;
                        }
                        Ok(resolution) => resolution,
                        Err(error) => {
                            error!("failed to classify stop: {error}");
                            break;
                        }
                    };

                    // The thread a run-to waits for changed state: its site
                    // is armed only while the thread is about to run.
                    if let StopResolution::Breakpoint { breakpoint, .. } = &resolution
                        && let Some(watch) = self
                            .follow_watch
                            .as_ref()
                            .filter(|watch| watch.id == breakpoint.id)
                    {
                        if let Err(error) = self.ctx.follow_watch_hit(watch) {
                            error!("{error}");
                            break;
                        }
                        if interrupt_requested {
                            print_stop_separator();
                            print_break_context_at(self.ctx, None, None);
                            break;
                        }
                        if let Err(error) = self
                            .ctx
                            .resume_with_disposition(ContinueDisposition::Handled)
                        {
                            error!("failed to continue: {error}");
                            break;
                        }
                        continue;
                    }

                    refresh_stop_caches_pre(self.ctx, &self.caches);
                    refresh_stop_caches_post(&self.ctx.target, &self.caches);
                    refresh_windows_thread_context_for_backend_thread(
                        &mut self.ctx.target,
                        &self.ctx.current_thread,
                    );

                    match resolution {
                        StopResolution::Resumed | StopResolution::ModulesChanged => {
                            unreachable!("handled above")
                        }
                        StopResolution::Breakpoint {
                            breakpoint,
                            condition_error,
                            ..
                        } => {
                            if let Some(error) = condition_error {
                                error!("breakpoint condition failed: {error}");
                            }
                            if let Some(action) = breakpoint.action.as_deref()
                                && self.dispatch_breakpoint_action(action)?
                                // A Ctrl+C this pass took breaks in at the hit
                                // instead of being lost to the action's resume.
                                && !interrupt_requested
                            {
                                if let Err(error) = self
                                    .ctx
                                    .resume_with_disposition(ContinueDisposition::Handled)
                                {
                                    error!("failed to continue after breakpoint action: {error}");
                                    break;
                                }
                                continue;
                            }

                            // A run-to's own site (`p` over a call, `gu`,
                            // `g <address>`) is no cause to name, whether
                            // patched or a debug register (the secure
                            // kernel's and a guest partition's).
                            if breakpoint.temporary {
                                if !self.quiet_stops {
                                    print_stop_separator();
                                    print_break_context_at(self.ctx, None, None);
                                }
                            } else if breakpoint.hardware.is_some() {
                                self.surface_hardware_breakpoint_hit(&breakpoint);
                            } else {
                                print_stop_separator();
                                let cause = format!(
                                    "{} {}",
                                    ui::muted("breakpoint"),
                                    ui::bp_id(breakpoint.id)
                                );
                                print_break_context_at(self.ctx, None, Some(cause));
                            }
                            break;
                        }
                        StopResolution::ModuleLoad { module, .. } => {
                            print_stop_separator();
                            print_module_event_stop(self.ctx, ModuleEvent::Load, &module);
                            if let Err(error) =
                                self.run_module_event_command(ModuleEvent::Load, &module)
                            {
                                error!("module load command failed: {error}");
                            }
                            break;
                        }
                        StopResolution::ModuleUnload { module, .. } => {
                            print_stop_separator();
                            print_module_event_stop(self.ctx, ModuleEvent::Unload, &module);
                            if let Err(error) =
                                self.run_module_event_command(ModuleEvent::Unload, &module)
                            {
                                error!("module unload command failed: {error}");
                            }
                            break;
                        }
                        StopResolution::Bugcheck { event } => {
                            print_stop_separator();
                            print_bugcheck_summary(&self.ctx.target, event.bugcheck.as_ref());
                            outln!();
                            print_break_context_for_bugcheck(self.ctx, event.bugcheck.as_ref());
                            break;
                        }
                        StopResolution::TargetReloaded { event, coherent } => {
                            print_stop_separator();
                            self.caches.clear_threads();
                            print_target_reload(
                                &self.ctx.target,
                                &self.ctx.current_thread,
                                event.program_counter,
                                coherent,
                            );
                            break;
                        }
                        StopResolution::Stopped { event, .. } => {
                            match self.ctx.exception_policies.action_for(&event) {
                                ExceptionPolicyAction::Surface { command } => {
                                    if let Err(error) =
                                        self.run_exception_policy_command(command.as_deref())
                                    {
                                        error!("exception command failed: {error}");
                                    }
                                }
                                ExceptionPolicyAction::Continue {
                                    notify,
                                    disposition,
                                    command,
                                } => {
                                    if let Err(error) =
                                        self.run_exception_policy_command(command.as_deref())
                                    {
                                        error!("exception command failed: {error}");
                                    } else {
                                        if notify {
                                            let code = event.exception_code.unwrap_or_default();
                                            let address =
                                                event.exception_address.or(event.program_counter);
                                            let chance = match event.first_chance {
                                                Some(true) => "first chance",
                                                Some(false) => "second chance",
                                                None => "unknown chance",
                                            };
                                            let location = address
                                                .map(|address| format!(" at {address:#x}"))
                                                .unwrap_or_default();
                                            outln!(
                                                "Exception {code:#010x} ({chance}){location}; continuing"
                                            );
                                        }
                                        match self
                                            .ctx
                                            .backend
                                            .continue_execution_with_disposition(disposition)
                                        {
                                            Ok(()) => {
                                                self.ctx
                                                    .record_continuation_disposition(disposition);
                                                continue;
                                            }
                                            Err(error) => {
                                                error!(
                                                    "failed to continue after exception: {error}"
                                                );
                                                break;
                                            }
                                        }
                                    }
                                }
                            }

                            print_stop_separator();
                            let cause =
                                stop_exception_cause(event.exception_code, event.program_counter);
                            print_break_context_at(self.ctx, None, cause);
                            break;
                        }
                    }
                }
                Ok(None) => {
                    if self.stop_budget_spent() {
                        break;
                    }
                }
                Err(e) => {
                    error!("error waiting for stop: {e}");
                    if self.ctx.backend.is_running() {
                        outln!(
                            "{}",
                            ui::muted("target still running; use `break` to try again")
                        );
                    }
                    break;
                }
            }
        }
        // A wait that ended without a result (an error, a spent budget)
        // still stops the indicator.
        #[cfg(feature = "cli")]
        native::finish_running();

        Ok(())
    }

    /// Whether a remote client's stop budget has run out, saying so: the
    /// target is left running.
    fn stop_budget_spent(&self) -> bool {
        if !self
            .stop_wait
            .as_ref()
            .is_some_and(StopWaitBudget::exhausted)
        {
            return false;
        }
        let hint = if self.context == DispatchContext::Remote(RemoteClient::Sdk) {
            "target still running; `dbg.wait()` to keep waiting, or `dbg.interrupt()` to \
             break in"
        } else {
            "target still running; call again to keep waiting, or `break` to interrupt"
        };
        outln!("{}", ui::muted(hint));
        true
    }

    /// Print a hardware (DR) breakpoint hit, mirroring the software-breakpoint
    /// `Hit` rendering. The address the breakpoint watches is unrelated to
    /// `rip` for data watches, so the cause child keeps the watched symbol
    /// while the BREAK banner shows where execution actually stopped.
    fn surface_hardware_breakpoint_hit(&mut self, bp: &Breakpoint) {
        print_stop_separator();
        // A hypercall or VM-exit breakpoint is named for what it stops on;
        // the stop's children name the caller and its exit.
        let (kind, access) = match (bp.hypercall, bp.vm_exit) {
            (Some(_), _) => ("hypercall breakpoint", String::new()),
            (None, Some(filter)) => ("VM-exit breakpoint", format!(" {}", filter.label())),
            (None, None) => (
                "hardware breakpoint",
                bp.hardware
                    .map(|hw| format!(" {}{}", hw.access.letter(), hw.len))
                    .unwrap_or_default(),
            ),
        };
        let cause = format!(
            "{} {}{}{}",
            ui::muted(kind),
            ui::bp_id(bp.id),
            access.bright_black(),
            bp.symbol
                .as_ref()
                .map(|s| format!("  {}", ui::symbol(s)))
                .unwrap_or_default()
        );
        print_break_context_at(self.ctx, None, Some(cause));
    }

    fn single_step(&mut self) -> Result<()> {
        if let Err(e) = self.single_step_checked() {
            error!("failed to step: {e}");
        }

        Ok(())
    }

    fn single_step_checked(&mut self) -> Result<()> {
        let outcome = self.ctx.step()?;

        if self.quiet_stops {
            return Ok(());
        }
        if matches!(outcome, ContinueOutcome::Step { .. }) {
            print_stop_separator();
            print_break_context(self.ctx);
        } else {
            print_parked_outcome(self.ctx, &self.caches, outcome);
        }

        Ok(())
    }

    /// Run a step to `address`: stop there only for the stepping thread,
    /// with its stack where `stack` requires.
    fn run_step_to(&mut self, address: VirtAddr, stack: StepStack) -> Result<bool> {
        let frame = self.ctx.step_frame(stack)?;
        self.run_to_temporary_code_breakpoint_with_disposition(
            address,
            frame,
            ContinueDisposition::Handled,
        )
    }

    fn current_ip(&mut self) -> Option<u64> {
        self.ctx.read_registers().ok().and_then(|registers| {
            self.ctx
                .register_map
                .read_u64("rip", &registers)
                .or_else(|_| self.ctx.register_map.read_u64("pc", &registers))
                .ok()
        })
    }

    fn run_to_temporary_code_breakpoint_with_disposition(
        &mut self,
        address: VirtAddr,
        frame: Option<StepFrame>,
        disposition: ContinueDisposition,
    ) -> Result<bool> {
        if self
            .ctx
            .breakpoints
            .enabled_breakpoint_id_for_current_context(&self.ctx.target, address)
            .is_some()
        {
            self.continue_vm_with_disposition(disposition)?;
            return Ok(self.current_ip() == Some(address.0));
        }

        let followed = frame.as_ref().map(|frame| frame.thread.clone());
        let temp_id = match self.ctx.add_temporary_code(address, frame) {
            Ok(id) => id,
            Err(e) => {
                error!(
                    "failed to set temporary breakpoint at {}: {}",
                    ui::addr(address.0),
                    e
                );
                return Ok(false);
            }
        };
        if let Some(stale) = self.follow_watch.take() {
            self.ctx.end_follow_watch(stale);
        }
        // The site is armed only while the stepping thread is about to run.
        // Not for a bounded wait: it hands back a running target, and no
        // stop is left to end the watch at.
        self.follow_watch = followed
            .filter(|_| self.stop_wait.is_none())
            .and_then(|thread| self.ctx.watch_followed(&thread, &[temp_id]));
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);

        let result = self.continue_vm_with_disposition(disposition);

        // A bounded wait that elapsed leaves the target running toward the
        // temporary site; it is consumed by its own hit, so leave it armed
        // (and a watch to the continue loop, which takes its stops).
        if self.ctx.backend.is_running() {
            return result.map(|_| false);
        }
        if let Some(watch) = self.follow_watch.take() {
            self.ctx.end_follow_watch(watch);
        }

        // Temporary sites are removed when the stop is consumed (a one-shot hit
        // clears itself); anything else left in place is a real problem.
        if let Err(e) = self.ctx.remove_breakpoint(temp_id)
            && !matches!(e, Error::BPNotFound(_))
        {
            error!(
                "failed to remove temporary breakpoint at {}: {e}",
                ui::addr(address.0)
            );
        }
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);

        result.map(|_| {
            let reached = self.current_ip() == Some(address.0);
            if reached {
                self.ctx
                    .note_stop(&ContinueOutcome::Step { rip: address.0 });
            }
            reached
        })
    }

    fn cmd_p(&mut self) -> Result<()> {
        if let Err(error) = self.step_over_once() {
            // Stepping *over* needs the instruction decoded to know whether it
            // is a call, and the instruction cannot be read while its page is
            // out. `t` executes the fetch instead of reading it, which is what
            // brings the page in.
            match (&error, self.current_ip()) {
                (Error::BadVirtualAddress(_) | Error::AddressNotInDump(_), Some(ip)) => error!(
                    "the page holding {} is not resident, so the instruction cannot be \
                     decoded to step over it; `t` single-steps through the fetch",
                    ui::addr(ip)
                ),
                _ => error!("failed to decode current instruction: {}", error),
            }
        }
        Ok(())
    }

    fn step_over_once(&mut self) -> Result<bool> {
        match self.ctx.step_over_target()? {
            StepKind::Single => self.single_step_checked().map(|_| true),
            StepKind::RunTo(target) => self.run_step_to(target, StepStack::CallReturn),
        }
    }

    fn required_address(
        &self,
        invocation: &CommandInvocation<'_>,
        command: &str,
    ) -> Option<VirtAddr> {
        let expression = invocation.raw_tail.trim();
        if expression.is_empty() {
            outln!("{}\n", command_help(command));
            return None;
        }
        self.eval_or_report(expression)
    }

    fn step_until(
        &mut self,
        mode: StepMode,
        stop: impl Fn(u64, ControlFlow) -> bool,
    ) -> Result<()> {
        // A remote client's budget ends the walk where it is.
        let remaining = self
            .stop_wait
            .as_ref()
            .and_then(|budget| budget.deadline)
            .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()));
        match self.ctx.step_until(mode, STEP_UNTIL_LIMIT, remaining, stop) {
            Ok(ContinueOutcome::Step { .. }) => self.print_current_stop(),
            Ok(outcome) => print_parked_outcome(self.ctx, &self.caches, outcome),
            Err(error @ Error::StepLimit(_)) => {
                error!("{error}");
                self.print_current_stop();
            }
            Err(error) => error!("failed while stepping: {error}"),
        }
        Ok(())
    }

    fn print_current_stop(&mut self) {
        print_stop_separator();
        print_break_context(self.ctx);
    }

    fn step_until_flow(&mut self, wanted: ControlFlow, mode: StepMode) -> Result<()> {
        self.step_until(mode, move |_, flow| flow == wanted)
    }

    fn cmd_pa(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(address) = self.required_address(&invocation, "pa") {
            self.step_until(StepMode::Over, move |ip, _| ip == address.0)?;
        }
        Ok(())
    }

    fn cmd_ta(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(address) = self.required_address(&invocation, "ta") {
            self.step_until(StepMode::Into, move |ip, _| ip == address.0)?;
        }
        Ok(())
    }

    fn cmd_pc(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Call, StepMode::Over)
    }

    fn cmd_tc(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Call, StepMode::Into)
    }

    fn cmd_pt(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Ret, StepMode::Over)
    }

    fn cmd_tt(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Ret, StepMode::Into)
    }

    fn cmd_ph(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Branch, StepMode::Over)
    }

    fn cmd_th(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Branch, StepMode::Into)
    }

    fn cmd_wt(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let limit = match invocation.arg(0) {
            None => WATCH_TRACE_DEFAULT_LIMIT,
            Some(expression) => match self.eval_or_report(expression) {
                Some(value) => match usize::try_from(value.0) {
                    Ok(count) => count,
                    Err(_) => {
                        error!("watch-trace count is too large");
                        return Ok(());
                    }
                },
                None => return Ok(()),
            },
        };
        self.watch_trace(limit)
    }

    fn watch_trace(&mut self, limit: usize) -> Result<()> {
        let trace = match self.ctx.trace_calls(limit) {
            Ok(trace) => trace,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let count = trace.instructions;
        match &trace.end {
            CallTraceEnd::Returned => {}
            CallTraceEnd::Limit => outln!("wt instruction cap reached after {count} instructions"),
            CallTraceEnd::Interrupted => outln!("wt interrupted after {count} instructions"),
            CallTraceEnd::Breakpoint => error!("watch-trace stopped at a code breakpoint"),
            CallTraceEnd::Diverted => error!(
                "watch-trace stopped after {count} instructions: a step was diverted into an \
                 interrupt handler, and the traced thread is not known to follow"
            ),
            CallTraceEnd::Failed(error) => {
                error!("watch-trace stopped after {count} instructions: {error}")
            }
        }
        #[cfg(feature = "cli")]
        native::render(
            || native::trees::call_tree(&trace.root),
            || render_trace_frame(&trace.root, 0),
        );
        #[cfg(not(feature = "cli"))]
        render_trace_frame(&trace.root, 0);
        Ok(())
    }

    fn cmd_gu(&mut self) -> Result<()> {
        match self.ctx.step_out_target() {
            Ok(target) => self
                .run_step_to(target, StepStack::FunctionReturn)
                .map(|_| ()),
            Err(e) => {
                error!("{}", e);
                Ok(())
            }
        }
    }
}
