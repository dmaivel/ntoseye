use std::cell::Cell;
use std::time::Duration;

use owo_colors::OwoColorize;

use crate::dbg_backend::ContinueDisposition;
use crate::diagnostics;
use crate::diagnostics::print_notice;
use crate::error::{Error, Result};
use crate::exception_policy::ExceptionPolicyMode;
use crate::expr::Expr;
use crate::session::{
    CallTraceEnd, CallTraceFrame, Cancel, CancelBehavior, Motion, RunOutcome, Session, StepMode,
    StopKind, WalkUntil,
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

impl ReplState<'_> {
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
            Ok(RunOutcome::Stopped(stop)) => {
                print_stop(self.ctx, &self.caches, &stop);
                self.flush_notices();
            }
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

    /// Wait for and render the next stop of a target this command set
    /// running (a reboot, a crash).
    pub fn wait_for_stop_after_resume(&mut self) -> Result<()> {
        let outcome = self.drive(Motion::Wait, true);
        self.report_run(outcome, "error waiting for stop");
        Ok(())
    }

    /// Collect the next stop for a host that hands control back while the
    /// target runs: a stop the idle servicer already parked is rendered at
    /// once; otherwise wait (within [`ReplState::stop_wait`]) for one and
    /// render it. A halted target with nothing pending returns immediately.
    pub fn collect_stop(&mut self) -> Result<()> {
        if self.ctx.backend.is_running() || self.ctx.stop_pending() {
            self.wait_for_stop_after_resume()?;
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
    pub fn gate_remote_command(&mut self, spec: &CommandSpec, typed: &str) -> Result<Option<Flow>> {
        let client = match self.context {
            DispatchContext::Remote(client)
                if matches!(client, RemoteClient::Mcp | RemoteClient::Sdk) =>
            {
                client
            }
            _ => return Ok(None),
        };
        let name = typed;
        let moves = spec.run != RunEffect::None;
        let needs_halt = crate::repl::command::needs_halt(self, spec);
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

    /// Render a stop the idle servicer parked (or the backend caught) since
    /// the last dispatch, if any, without waiting: its action runs first, and
    /// one that resumes leaves nothing to render. Returns whether one was
    /// rendered; a remote host then refuses to resume past it on this call.
    pub fn surface_parked_stop(&mut self) -> bool {
        if !self.ctx.stop_pending() {
            return false;
        }
        self.clear_selected_frame();
        let cancel = Cancel::poll();
        match self.ctx.run(Motion::Wait, &cancel) {
            Ok(RunOutcome::Stopped(stop)) => {
                print_stop(self.ctx, &self.caches, &stop);
                self.flush_notices();
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

    pub fn interrupt_running_vm(&mut self) -> Result<()> {
        self.clear_selected_frame();
        let outcome = self.ctx.run(Motion::Break, &Cancel::NEVER);
        self.report_run(outcome, "failed to interrupt");
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
        let address = match Expr::eval_with_radix(expression, &self.ctx.target, self.radix) {
            Ok(address) => address,
            Err(error) => {
                error!("invalid {} address: {error}", invocation.name);
                return Ok(());
            }
        };
        // Secure-kernel code and a partition's take a debug register for the
        // run, which writes nothing.
        let patched = self.ctx.partition().is_none() && !self.ctx.target.is_secure_address(address);
        let check =
            patched.then(|| self.check_instruction_start(self.ctx.target.current_dtb(), address));
        match check {
            Some(Ok(Some(warning))) => diagnostics::print_warning(warning),
            Some(Err(error)) => {
                error!("{error}");
                return Ok(());
            }
            Some(Ok(None)) | None => {}
        }
        if self.ctx.backend.is_running() {
            error!("VM is running");
            return Ok(());
        }
        let motion = Motion::RunTo {
            address,
            frame: None,
            disposition,
        };
        let outcome = self.drive(motion, true);
        self.report_run(
            outcome,
            &format!("failed to run to {}", ui::addr(address.0)),
        );
        Ok(())
    }

    fn continue_vm_with_disposition(&mut self, disposition: ContinueDisposition) -> Result<()> {
        self.clear_selected_frame();
        if self.ctx.backend.is_running() {
            // A stop the target already reported is rendered; otherwise the
            // target keeps the run it is on.
            let cancel = Cancel::within(PENDING_STOP_POLL);
            match self.ctx.run(Motion::Wait, &cancel) {
                Ok(RunOutcome::Stopped(stop)) => {
                    print_stop(self.ctx, &self.caches, &stop);
                    self.flush_notices();
                }
                Ok(RunOutcome::Running) => error!("VM is running"),
                Err(e) => error!("error checking running VM: {e}"),
            }
            return Ok(());
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
            return Ok(());
        }
        let outcome = self.drive(motion, true);
        self.report_run(outcome, "failed to continue");
        Ok(())
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

    fn single_step(&mut self) -> Result<()> {
        let outcome = self.drive(Motion::Step, false);
        self.report_run(outcome, "failed to step");
        Ok(())
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

    fn cmd_p(&mut self) -> Result<()> {
        let motion = match self.ctx.plan(Motion::StepOver) {
            Ok(motion) => motion,
            Err(error) => {
                // Stepping *over* needs the instruction decoded to know
                // whether it is a call, and the instruction cannot be read
                // while its page is out. `t` executes the fetch instead of
                // reading it, which is what brings the page in.
                match (&error, self.current_ip()) {
                    (Error::BadVirtualAddress(_) | Error::AddressNotInDump(_), Some(ip)) => error!(
                        "the page holding {} is not resident, so the instruction cannot be \
                         decoded to step over it; `t` single-steps through the fetch",
                        ui::addr(ip)
                    ),
                    _ => error!("failed to decode current instruction: {}", error),
                }
                return Ok(());
            }
        };
        let outcome = self.drive(motion, true);
        self.report_run(outcome, "failed to step over");
        Ok(())
    }

    fn cmd_gu(&mut self) -> Result<()> {
        let motion = match self.ctx.plan(Motion::StepOut) {
            Ok(motion) => motion,
            Err(error) => {
                error!("{error}");
                return Ok(());
            }
        };
        let outcome = self.drive(motion, true);
        self.report_run(outcome, "failed to step out");
        Ok(())
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

    /// Walk into or over calls until `until` holds; a remote client's budget
    /// ends the walk where it is.
    fn step_until(&mut self, mode: StepMode, until: WalkUntil) -> Result<()> {
        match self.drive(Motion::walk(mode, until), false) {
            Err(error @ Error::StepLimit(_)) => {
                error!("{error}");
                print_stop_separator();
                print_break_context(self.ctx);
            }
            outcome => self.report_run(outcome, "failed while stepping"),
        }
        Ok(())
    }

    fn cmd_pa(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(address) = self.required_address(&invocation, "pa") {
            self.step_until(StepMode::Over, WalkUntil::Address(address))?;
        }
        Ok(())
    }

    fn cmd_ta(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(address) = self.required_address(&invocation, "ta") {
            self.step_until(StepMode::Into, WalkUntil::Address(address))?;
        }
        Ok(())
    }

    fn cmd_pc(&mut self) -> Result<()> {
        self.step_until(StepMode::Over, WalkUntil::Call)
    }

    fn cmd_tc(&mut self) -> Result<()> {
        self.step_until(StepMode::Into, WalkUntil::Call)
    }

    fn cmd_pt(&mut self) -> Result<()> {
        self.step_until(StepMode::Over, WalkUntil::Return)
    }

    fn cmd_tt(&mut self) -> Result<()> {
        self.step_until(StepMode::Into, WalkUntil::Return)
    }

    fn cmd_ph(&mut self) -> Result<()> {
        self.step_until(StepMode::Over, WalkUntil::Branch)
    }

    fn cmd_th(&mut self) -> Result<()> {
        self.step_until(StepMode::Into, WalkUntil::Branch)
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
        // Ctrl+C or a remote client's budget ends `wt`, halted where it got to.
        let cancel =
            budget_cancel(self.stop_wait.as_ref(), None).with_behavior(CancelBehavior::Halt);
        let trace = self.ctx.trace_calls(limit, &cancel);
        let trace = match trace {
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
}
