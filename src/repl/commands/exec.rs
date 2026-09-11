use std::sync::atomic::Ordering;

use owo_colors::OwoColorize;

use crate::dbg_backend::ContinueDisposition;
use crate::error::Result;
use crate::gdb::breakpoints::Breakpoint;
use crate::session::{StepKind, StopResolution};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    continue_vm();
    names: ["continue", "g"],
    usage: "continue",
    summary: "Resume VM execution.",
}

repl_command! {
    continue_handled();
    names: ["gh"],
    usage: "gh",
    summary: "Resume and mark the current exception handled.",
}

repl_command! {
    continue_not_handled();
    names: ["gn"],
    usage: "gn",
    summary: "Resume and pass the current exception to Windows (KD only).",
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
    names: ["si", "t"],
    usage: "si",
    summary: "Single step (step into).",
    run_state: Halted,
}

repl_command! {
    cmd_p();
    names: ["p", "ni"],
    usage: "p or ni",
    summary: "Step over the current instruction.",
    run_state: Halted,
}

repl_command! {
    cmd_gu();
    names: ["gu", "finish"],
    usage: "gu or finish",
    summary: "Run until the current function returns.",
    run_state: Halted,
}

impl ReplState<'_> {
    pub fn interrupt_running_vm(&mut self) -> Result<()> {
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

    fn continue_vm(&mut self) -> Result<()> {
        self.continue_vm_with_disposition(ContinueDisposition::Handled)
    }

    fn continue_handled(&mut self) -> Result<()> {
        self.continue_vm_with_disposition(ContinueDisposition::Handled)
    }

    fn continue_not_handled(&mut self) -> Result<()> {
        self.continue_vm_with_disposition(ContinueDisposition::NotHandled)
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
                    println!(
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

        // Step past a breakpoint at RIP, re-arm breakpoints, continue, and drop
        // stale inspection caches; the canonical resume prologue lives in core.
        if let Err(e) = self.ctx.resume_with_disposition(disposition) {
            error!("failed to continue: {:?}", e);
            return Ok(());
        }

        println!(
            "{}",
            "VM running, waiting for stop (Ctrl+C to pause)...".bright_black()
        );

        INTERRUPT_REQUESTED.store(false, Ordering::SeqCst);

        loop {
            let interrupt_requested = INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst);
            let stop_result = if interrupt_requested {
                println!();
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
                            } else {
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
                            println!();
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
                                            println!(
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
                Ok(None) => {
                    // timeout
                }
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
        // The step itself (over-breakpoint dance, trap-flag clear, breakpoint
        // re-arm, thread re-select) is the canonical `Session::step`;
        // the REPL only adds the break-context display.
        if let Err(e) = self.ctx.step() {
            error!("failed to step: {:?}", e);
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

    fn run_to_temporary_code_breakpoint(&mut self, address: VirtAddr) -> Result<()> {
        if self
            .ctx
            .breakpoints
            .enabled_breakpoint_id_for_current_context(&self.ctx.target, address)
            .is_some()
        {
            return self.continue_vm();
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
                return Ok(());
            }
        };
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);

        let result = self.continue_vm();

        let _ = self
            .ctx
            .breakpoints
            .remove(&mut *self.ctx.backend, &self.ctx.target, temp_id);
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);

        result
    }

    fn cmd_p(&mut self) -> Result<()> {
        // The step-over decision (is the current insn a call? where does it
        // return?) is shared with the SDKs; the REPL only differs in *how* it
        // runs to the target, via its rich-display continue loop.
        match self.ctx.step_over_target() {
            Ok(StepKind::Single) => self.single_step(),
            Ok(StepKind::RunTo(target)) => self.run_to_temporary_code_breakpoint(target),
            Err(e) => {
                error!("failed to decode current instruction: {}", e);
                Ok(())
            }
        }
    }

    fn cmd_gu(&mut self) -> Result<()> {
        match self.ctx.step_out_target() {
            Ok(target) => self.run_to_temporary_code_breakpoint(target),
            Err(e) => {
                error!("{}", e);
                Ok(())
            }
        }
    }
}
