use std::sync::atomic::Ordering;

use owo_colors::OwoColorize;

use crate::dbg_backend::ContinueDisposition;
use crate::disasm::{ControlFlow, classify};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::gdb::breakpoints::Breakpoint;
use crate::session::{StepKind, StopResolution};
use crate::types::{Arch, VirtAddr};
use crate::ui;
use crate::unwind::{format_symbol, resolve_thread_trace_context};

use crate::repl::*;

repl_command! {
    continue_vm;
    names: ["g", "continue"],
    usage: "g [address]",
    summary: "Resume VM execution.",
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
    summary: "Break/pause VM execution.",
    run_state: Running,
}

repl_command! {
    single_step();
    names: ["t", "si"],
    usage: "t",
    summary: "Single step (step into).",
    run_state: Halted,
    run: Step,
}

repl_command! {
    cmd_p();
    names: ["p", "ni"],
    usage: "p or ni",
    summary: "Step over the current instruction.",
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_gu();
    names: ["gu", "finish"],
    usage: "gu or finish",
    summary: "Run until the current function returns.",
    run_state: Halted,
    run: Run,
}

repl_command! {
    cmd_pa;
    names: ["pa"],
    usage: "pa <address>",
    summary: "Step over repeatedly until an address is reached.",
    completion: Expression,
    run: Run,
}

repl_command! {
    cmd_ta;
    names: ["ta"],
    usage: "ta <address>",
    summary: "Step into repeatedly until an address is reached.",
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

const STEP_UNTIL_LIMIT: usize = 100_000;
const WATCH_TRACE_DEFAULT_LIMIT: usize = 10_000;

struct TraceFrame {
    name: String,
    entry_sp: u64,
    instructions: usize,
    children: Vec<TraceFrame>,
}

struct ExecutionState {
    ip: u64,
    sp: u64,
    dtb: u64,
    flow: ControlFlow,
}

fn format_trace_symbol(target: &crate::target::Target, dtb: u64, ip: u64) -> String {
    let trace = resolve_thread_trace_context(target, dtb);
    format_symbol(target, &trace, ip)
}

fn render_trace_frame(frame: &TraceFrame, depth: usize) {
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
    pub fn interrupt_running_vm(&mut self) -> Result<()> {
        self.clear_selected_frame();
        match surface_pending_stop(self.ctx, &self.caches, &self.exception_policies) {
            Ok(true) => {
                if let Err(error) = self.apply_buffered_exception_policy() {
                    error!("failed to apply exception policy: {error}");
                }
                return Ok(());
            }
            Ok(false) => {}
            Err(e) => {
                error!("error checking running VM: {:?}", e);
                return Ok(());
            }
        }

        if let Err(e) = surface_interrupt_stop(self.ctx, &self.caches) {
            error!("failed to interrupt: {:?}", e);
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
        if expression.is_empty() {
            return self.continue_vm_with_disposition(disposition);
        }
        match Expr::eval_with_radix(expression, &self.ctx.target, self.radix) {
            Ok(address) => self
                .run_to_temporary_code_breakpoint_with_disposition(address, disposition)
                .map(|_| ()),
            Err(error) => {
                error!("invalid {} address: {error}", invocation.name);
                Ok(())
            }
        }
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
        let Some(event) = self.ctx.last_event.as_ref().map(|last| last.stop.clone()) else {
            return Ok(());
        };
        match self.exception_policies.action_for(&event) {
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
            match surface_pending_stop(self.ctx, &self.caches, &self.exception_policies) {
                Ok(true) => {
                    if let Err(error) = self.apply_buffered_exception_policy() {
                        error!("failed to apply exception policy: {error}");
                    }
                }
                Ok(false) => error!("VM is running"),
                Err(e) => error!("error checking running VM: {:?}", e),
            }
            return Ok(());
        }

        if let Err(e) = self.ctx.resume_with_disposition(disposition) {
            error!("failed to continue: {:?}", e);
            return Ok(());
        }

        self.wait_for_stop_after_resume()
    }

    pub(super) fn wait_for_stop_after_resume(&mut self) -> Result<()> {
        if !self.quiet_stops {
            outln!(
                "{}",
                "VM running, waiting for stop (Ctrl+C to pause)...".bright_black()
            );
        }

        INTERRUPT_REQUESTED.store(false, Ordering::SeqCst);

        loop {
            let interrupt_requested = INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst);
            let stop_result = if interrupt_requested {
                outln!();
                match self.ctx.backend.try_wait_for_stop(REPL_STOP_POLL) {
                    Ok(Some(event)) => Ok(Some(event)),
                    Ok(None) => self.ctx.backend.interrupt().map(Some),
                    Err(e) => Err(e),
                }
            } else {
                self.ctx.backend.try_wait_for_stop(REPL_STOP_POLL)
            };

            match stop_result {
                Ok(Some(event)) => {
                    let resolution = match self.ctx.classify_stop_event(event) {
                        Ok(StopResolution::Resumed) => continue,
                        Ok(resolution) => resolution,
                        Err(error) => {
                            error!("failed to classify stop: {error}");
                            break;
                        }
                    };

                    refresh_stop_caches_pre(
                        &mut *self.ctx.backend,
                        &self.ctx.target,
                        &mut self.ctx.breakpoints,
                        &self.caches,
                    );
                    refresh_stop_caches_post(&self.ctx.target, &self.caches);
                    refresh_windows_thread_context_for_backend_thread(
                        &mut self.ctx.target,
                        &self.ctx.current_thread,
                    );

                    match resolution {
                        StopResolution::Resumed => unreachable!("handled above"),
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

                            if breakpoint.hardware.is_some() {
                                self.surface_hardware_breakpoint_hit(&breakpoint);
                            } else if !(self.quiet_stops && breakpoint.temporary) {
                                print_stop_separator();
                                let cause = (!breakpoint.temporary).then(|| {
                                    format!(
                                        "{} {}",
                                        ui::muted("breakpoint"),
                                        ui::bp_id(breakpoint.id)
                                    )
                                });
                                print_break_context_at(
                                    &mut *self.ctx.backend,
                                    &self.ctx.register_map,
                                    &mut self.ctx.target,
                                    &self.ctx.breakpoints,
                                    &self.ctx.current_thread,
                                    None,
                                    cause,
                                );
                            }
                            break;
                        }
                        StopResolution::Bugcheck { event } => {
                            print_stop_separator();
                            print_bugcheck_summary(&self.ctx.target, event.bugcheck.as_ref());
                            outln!();
                            print_break_context_for_bugcheck(
                                &mut *self.ctx.backend,
                                &self.ctx.register_map,
                                &mut self.ctx.target,
                                &self.ctx.breakpoints,
                                &self.ctx.current_thread,
                                event.bugcheck.as_ref(),
                            );
                            break;
                        }
                        StopResolution::TargetReloaded { event, coherent } => {
                            print_stop_separator();
                            self.caches.clear_threads();
                            print_target_reload_notification_context(
                                &self.ctx.target,
                                &self.ctx.current_thread,
                                &event,
                                TargetReloadStatus::Reloaded {
                                    loaded_module_list_available: coherent,
                                },
                            );
                            break;
                        }
                        StopResolution::Stopped { event, .. } => {
                            match self.exception_policies.action_for(&event) {
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
                            print_break_context_at(
                                &mut *self.ctx.backend,
                                &self.ctx.register_map,
                                &mut self.ctx.target,
                                &self.ctx.breakpoints,
                                &self.ctx.current_thread,
                                None,
                                cause,
                            );
                            break;
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    error!("error waiting for stop: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Print a hardware (DR) breakpoint hit, mirroring the software-breakpoint
    /// `Hit` rendering. The address the breakpoint watches is unrelated to
    /// `rip` for data watches, so the cause child keeps the watched symbol
    /// while the BREAK banner shows where execution actually stopped.
    fn surface_hardware_breakpoint_hit(&mut self, bp: &Breakpoint) {
        print_stop_separator();
        let access = bp
            .hardware
            .map(|hw| format!(" {}{}", hw.access.letter(), hw.len))
            .unwrap_or_default();
        let cause = format!(
            "{} {}{}{}",
            ui::muted("hardware breakpoint"),
            ui::bp_id(bp.id),
            access.bright_black(),
            bp.symbol
                .as_ref()
                .map(|s| format!("  {}", ui::symbol(s)))
                .unwrap_or_default()
        );
        print_break_context_at(
            &mut *self.ctx.backend,
            &self.ctx.register_map,
            &mut self.ctx.target,
            &self.ctx.breakpoints,
            &self.ctx.current_thread,
            None,
            Some(cause),
        );
    }

    fn single_step(&mut self) -> Result<()> {
        if let Err(e) = self.single_step_checked() {
            error!("failed to step: {:?}", e);
        }

        Ok(())
    }

    fn single_step_checked(&mut self) -> Result<()> {
        self.clear_selected_frame();
        self.ctx.step()?;

        if self.quiet_stops {
            return Ok(());
        }
        print_stop_separator();
        print_break_context(
            &mut *self.ctx.backend,
            &self.ctx.register_map,
            &mut self.ctx.target,
            &self.ctx.breakpoints,
            &self.ctx.current_thread,
        );

        Ok(())
    }

    fn run_to_temporary_code_breakpoint(&mut self, address: VirtAddr) -> Result<bool> {
        self.run_to_temporary_code_breakpoint_with_disposition(
            address,
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

    fn stopped_at_code_breakpoint(&mut self, previous_ip: u64) -> bool {
        let Some(ip) = self.current_ip() else {
            return false;
        };
        self.stopped_at_code_breakpoint_at(previous_ip, ip)
    }

    fn stopped_at_code_breakpoint_at(&self, previous_ip: u64, ip: u64) -> bool {
        let address = VirtAddr(ip);
        if self
            .ctx
            .breakpoints
            .enabled_breakpoint_id_for_current_context(&self.ctx.target, address)
            .is_some()
        {
            return true;
        }
        let step = u64::from(self.ctx.register_map.breakpoint_step_size());
        let started_on_breakpoint = self
            .ctx
            .breakpoints
            .enabled_breakpoint_id_for_current_context(&self.ctx.target, VirtAddr(previous_ip))
            .is_some();
        !started_on_breakpoint
            && ip >= step
            && self
                .ctx
                .breakpoints
                .enabled_breakpoint_id_for_current_context(&self.ctx.target, VirtAddr(ip - step))
                .is_some()
    }

    fn run_to_temporary_code_breakpoint_with_disposition(
        &mut self,
        address: VirtAddr,
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

        let temp_id = match self.ctx.breakpoints.add_temporary_code(
            &mut *self.ctx.backend,
            &self.ctx.target,
            address,
        ) {
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
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);

        let result = self.continue_vm_with_disposition(disposition);

        // Temporary sites are removed when the stop is consumed (a one-shot hit
        // clears itself); anything else left in place is a real problem.
        if let Err(e) =
            self.ctx
                .breakpoints
                .remove(&mut *self.ctx.backend, &self.ctx.target, temp_id)
            && !matches!(e, Error::BPNotFound(_))
        {
            error!(
                "failed to remove temporary breakpoint at {}: {e}",
                ui::addr(address.0)
            );
        }
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);

        result.map(|_| self.current_ip() == Some(address.0))
    }

    fn cmd_p(&mut self) -> Result<()> {
        if let Err(e) = self.step_over_once() {
            error!("failed to decode current instruction: {}", e);
        }
        Ok(())
    }

    fn step_over_once(&mut self) -> Result<bool> {
        match self.ctx.step_over_target()? {
            StepKind::Single => self.single_step_checked().map(|_| true),
            StepKind::RunTo(target) => self.run_to_temporary_code_breakpoint(target),
        }
    }

    fn required_address(
        &self,
        invocation: &CommandInvocation<'_>,
        command: &str,
    ) -> Result<Option<VirtAddr>> {
        let expression = invocation.raw_tail.trim();
        if expression.is_empty() {
            outln!("{}\n", command_help(command));
            return Ok(None);
        }
        match Expr::eval_with_radix(expression, &self.ctx.target, self.radix) {
            Ok(address) => Ok(Some(address)),
            Err(error) => {
                error!("{}", error);
                Ok(None)
            }
        }
    }

    fn current_execution_state(&mut self) -> Result<ExecutionState> {
        let registers = self.ctx.read_registers()?;
        let ip = self
            .ctx
            .register_map
            .read_u64("rip", &registers)
            .or_else(|_| self.ctx.register_map.read_u64("pc", &registers))?;
        let sp = self
            .ctx
            .register_map
            .read_u64("rsp", &registers)
            .or_else(|_| self.ctx.register_map.read_u64("sp", &registers))?;
        let dtb = self
            .ctx
            .register_map
            .read_u64(self.ctx.target.arch().dtb_register(), &registers)
            .unwrap_or(0);
        let mut bytes = [0u8; 16];
        let length = if self.ctx.target.arch() == Arch::Arm64 {
            4
        } else {
            bytes.len()
        };
        self.ctx.read_masked(VirtAddr(ip), &mut bytes[..length])?;
        Ok(ExecutionState {
            ip,
            sp,
            dtb,
            flow: classify(&bytes[..length], self.ctx.target.arch()),
        })
    }

    fn step_until(&mut self, over: bool, stop: impl Fn(u64, ControlFlow) -> bool) -> Result<()> {
        self.clear_selected_frame();
        let was_quiet = self.quiet_stops;
        self.quiet_stops = true;
        let outcome = self.step_until_quiet(over, stop);
        self.quiet_stops = was_quiet;
        if outcome? {
            self.print_current_stop();
        }
        Ok(())
    }

    /// Render the halted context once, after a multi-step command settles on
    /// its own stop (a real breakpoint or exception already rendered itself).
    fn print_current_stop(&mut self) {
        print_stop_separator();
        print_break_context(
            &mut *self.ctx.backend,
            &self.ctx.register_map,
            &mut self.ctx.target,
            &self.ctx.breakpoints,
            &self.ctx.current_thread,
        );
    }

    /// `Ok(true)` when the loop stopped on its own condition (or limit) and
    /// the caller should render the stop; `Ok(false)` when another stop
    /// surfaced and was already rendered.
    fn step_until_quiet(
        &mut self,
        over: bool,
        stop: impl Fn(u64, ControlFlow) -> bool,
    ) -> Result<bool> {
        for _ in 0..STEP_UNTIL_LIMIT {
            if INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst) {
                outln!();
                return Ok(true);
            }
            let state = match self.current_execution_state() {
                Ok(state) => state,
                Err(error) => {
                    error!("failed to read current instruction: {error}");
                    return Ok(false);
                }
            };
            if stop(state.ip, state.flow) {
                return Ok(true);
            }
            let result = if over {
                self.step_over_once()
            } else {
                self.single_step_checked().map(|_| true)
            };
            match result {
                Ok(reached) if over && !reached => return Ok(false),
                Ok(_) if self.stopped_at_code_breakpoint(state.ip) => return Ok(false),
                Ok(_) => {}
                Err(error) => {
                    error!("failed while stepping: {error}");
                    return Ok(false);
                }
            }
        }
        error!("step-until limit ({STEP_UNTIL_LIMIT}) reached");
        Ok(true)
    }

    fn step_until_flow(&mut self, wanted: ControlFlow, over: bool) -> Result<()> {
        self.step_until(over, move |_, flow| flow == wanted)
    }

    fn cmd_pa(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(address) = self.required_address(&invocation, "pa")? {
            self.step_until(true, move |ip, _| ip == address.0)?;
        }
        Ok(())
    }

    fn cmd_ta(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        if let Some(address) = self.required_address(&invocation, "ta")? {
            self.step_until(false, move |ip, _| ip == address.0)?;
        }
        Ok(())
    }

    fn cmd_pc(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Call, true)
    }

    fn cmd_tc(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Call, false)
    }

    fn cmd_pt(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Ret, true)
    }

    fn cmd_tt(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Ret, false)
    }

    fn cmd_ph(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Branch, true)
    }

    fn cmd_th(&mut self) -> Result<()> {
        self.step_until_flow(ControlFlow::Branch, false)
    }

    fn cmd_wt(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        self.clear_selected_frame();
        let limit = match invocation.arg(0) {
            None => WATCH_TRACE_DEFAULT_LIMIT,
            Some(expression) => {
                match Expr::eval_with_radix(expression, &self.ctx.target, self.radix) {
                    Ok(value) => match usize::try_from(value.0) {
                        Ok(count) => count,
                        Err(_) => {
                            error!("watch-trace count is too large");
                            return Ok(());
                        }
                    },
                    Err(error) => {
                        error!("{}", error);
                        return Ok(());
                    }
                }
            }
        };
        if limit == 0 {
            error!("watch-trace count must be greater than zero");
            return Ok(());
        }

        self.watch_trace(limit)
    }

    fn watch_trace(&mut self, limit: usize) -> Result<()> {
        let mut current = match self.current_execution_state() {
            Ok(state) => state,
            Err(error) => {
                error!("failed to read current instruction: {error}");
                return Ok(());
            }
        };
        let mut stack = vec![TraceFrame {
            name: format_trace_symbol(&self.ctx.target, current.dtb, current.ip),
            entry_sp: current.sp,
            instructions: 0,
            children: Vec::new(),
        }];
        let mut root = None;
        let mut instructions = 0usize;

        while instructions < limit {
            if INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst) {
                outln!("wt interrupted after {instructions} instructions");
                break;
            }
            if let Err(error) = self.ctx.step() {
                error!(
                    "watch-trace stopped after {} instructions: {error}",
                    instructions
                );
                break;
            }
            instructions += 1;
            let next = match self.current_execution_state() {
                Ok(state) => state,
                Err(error) => {
                    error!("watch-trace stopped after {}: {error}", instructions);
                    break;
                }
            };
            if self.stopped_at_code_breakpoint_at(current.ip, next.ip) {
                error!("watch-trace stopped at a code breakpoint");
                break;
            }
            let Some(frame) = stack.last_mut() else {
                break;
            };
            frame.instructions += 1;

            if current.flow == ControlFlow::Call {
                stack.push(TraceFrame {
                    name: format_trace_symbol(&self.ctx.target, next.dtb, next.ip),
                    entry_sp: next.sp,
                    instructions: 0,
                    children: Vec::new(),
                });
            } else if current.flow == ControlFlow::Ret
                && (next.sp > frame.entry_sp
                    || (self.ctx.target.arch() == Arch::Arm64 && next.sp >= frame.entry_sp))
            {
                let completed = stack.pop().expect("trace frame exists");
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(completed);
                } else {
                    root = Some(completed);
                    break;
                }
            }
            current = next;
        }

        if root.is_none() {
            if instructions >= limit {
                outln!("wt instruction cap reached after {instructions} instructions");
            }
            while stack.len() > 1 {
                let completed = stack.pop().expect("trace frame exists");
                stack
                    .last_mut()
                    .expect("root trace frame exists")
                    .children
                    .push(completed);
            }
            root = stack.pop();
        }

        if let Some(root) = root {
            render_trace_frame(&root, 0);
        }
        Ok(())
    }

    fn cmd_gu(&mut self) -> Result<()> {
        self.clear_selected_frame();
        match self.ctx.step_out_target() {
            Ok(target) => self.run_to_temporary_code_breakpoint(target).map(|_| ()),
            Err(e) => {
                error!("{}", e);
                Ok(())
            }
        }
    }
}
