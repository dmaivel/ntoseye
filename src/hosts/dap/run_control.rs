//! Run control: continue, pause, and stepping by source line or instruction,
//! and reporting each stop to the client.

use std::result;
use std::sync::atomic::Ordering;

use serde_json::json;

use crate::backend::dbg_backend::{ContinueDisposition, ModuleEvent};
use crate::base::disasm::{fallthrough_run_end, instruction_length};
use crate::base::ntstatus::exception_code_name;
use crate::base::output;
use crate::base::types::VirtAddr;
use crate::nt::guest::ModuleInfo;
use crate::session::stops::module_event_line;
use crate::session::{Cancel, Motion, RunOutcome, StepMode, StepStack, Stop, StopKind};

use super::wire::Request;
use super::{Handled, RunState, Server, StopInfo, arg_i64, arg_str};

/// Bound source stepping when execution does not reach another mapped line.
const STEP_LINE_BUDGET: usize = 4096;
/// Largest source-line range eligible for a temporary endpoint breakpoint.
const MAX_LINE_SPAN: usize = 4096;

impl Server {
    /// Answers its own request, so the entry stop follows the response the
    /// way every other stop follows the run-control request that produced it.
    pub(super) fn on_configuration_done(&mut self, request: &Request) -> Handled {
        self.configured = true;
        if self.user_dump() {
            self.respond(request, Ok(None));
            self.state = RunState::Halted;
            self.report_user_dump_stop();
            return Ok(None);
        }
        // A check that does not wait: a halted target reports the stop it
        // is halted at, a stop already caught surfaces.
        let outcome = self.drive(Motion::Wait, &Cancel::poll());
        self.respond(request, Ok(None));
        match outcome {
            Ok(RunOutcome::Stopped(stop)) => self.report_stop(stop),
            Ok(RunOutcome::Running) => self.state = RunState::Running,
            Err(message) => {
                self.emit_output("stderr", format!("{message}\n"));
                self.state = RunState::Running;
            }
        }
        Ok(None)
    }

    /// Run `motion` on the session, sending what breakpoint actions print to
    /// the Debug Console.
    pub fn drive(
        &mut self,
        motion: Motion,
        cancel: &Cancel<'_>,
    ) -> result::Result<RunOutcome, String> {
        let session = self.session()?;
        let (outcome, text) = output::capture(|| session.run(motion, cancel));
        if !text.is_empty() {
            self.emit_output("stdout", text);
        }
        outcome.map_err(|error| error.to_string())
    }

    pub(super) fn on_continue(&mut self, request: &Request) -> Handled {
        self.refuse_on_dump("continue")?;
        // A step still running becomes this run: its sites would otherwise
        // end the continue as a step.
        self.end_step();
        // Resume and take a stop already waiting; the rest arrive while the
        // loop services the running target.
        let continue_ = Motion::Continue {
            disposition: ContinueDisposition::Handled,
        };
        match self.drive(continue_, &Cancel::poll()) {
            Ok(outcome) => {
                self.invalidate_stop_state();
                self.state = RunState::Running;
                self.respond(request, Ok(Some(json!({"allThreadsContinued": true}))));
                self.send_event(
                    "continued",
                    json!({"threadId": 1, "allThreadsContinued": true}),
                );
                if let RunOutcome::Stopped(stop) = outcome {
                    self.report_stop(stop);
                }
            }
            Err(message) => self.respond(request, Err(message)),
        }
        Ok(None)
    }

    pub(super) fn on_pause(&mut self, request: &Request) -> Handled {
        // The reader raised the flag for this request; it is consumed here.
        self.cancel.store(false, Ordering::Relaxed);
        // The client already holds the stop (a step this pause interrupted
        // reported where it ended), so there is nothing to interrupt.
        if matches!(self.state, RunState::Halted) {
            self.respond(request, Ok(None));
            return Ok(None);
        }
        match self.drive(Motion::Break, &Cancel::NEVER) {
            Ok(outcome) => {
                self.respond(request, Ok(None));
                if let RunOutcome::Stopped(stop) = outcome {
                    self.report_stop(stop);
                }
            }
            Err(message) => self.respond(request, Err(message)),
        }
        Ok(None)
    }

    /// Start a step and answer at once, as `continue` does: the step's runs
    /// go on while the loop services the running target, which answers
    /// other requests meanwhile and lets `pause` or a disconnect end it, and
    /// the stop it ends on is reported when it comes. A client that waited
    /// for the response instead would show the thread stopped, without a
    /// pause, for as long as a step over a long call takes.
    pub(super) fn on_step(&mut self, request: &Request, step: StepRequest) -> Handled {
        self.refuse_on_dump("stepping")?;
        let instruction_granularity =
            arg_str(&request.arguments, "granularity").as_deref() == Some("instruction");
        if let Some(thread) = arg_i64(&request.arguments, "threadId")
            && let Err(message) = self.select_thread(thread)
        {
            self.respond(request, Err(message));
            return Ok(None);
        }
        self.invalidate_stop_state();
        match self.start_step(step, instruction_granularity) {
            Ok(outcome) => {
                self.state = RunState::Running;
                self.respond(request, Ok(None));
                self.send_event(
                    "continued",
                    json!({"threadId": 1, "allThreadsContinued": true}),
                );
                if let RunOutcome::Stopped(stop) = outcome {
                    self.on_stopped(stop);
                }
            }
            Err(message) => {
                self.end_step();
                self.respond(request, Err(message));
                // The step failed with the target still halted where it was,
                // so re-announce that stop to keep the client's view live. A
                // target that reports no pc has no stop to re-announce, and
                // inventing one would park the client at 0x0.
                if let Some(stop) = self
                    .session
                    .as_mut()
                    .and_then(|session| session.halted_stop().ok().flatten())
                    .filter(|stop| stop.rip.is_some())
                {
                    self.report_stop(stop);
                }
            }
        }
        Ok(None)
    }

    /// Start a step by source line, or by instruction when requested or
    /// unmapped, recording it as the step in progress: its first run, and
    /// where that run stopped if it already did.
    pub fn start_step(
        &mut self,
        step: StepRequest,
        instruction_granularity: bool,
    ) -> result::Result<RunOutcome, String> {
        self.step = Some(StepInProgress::default());
        let mode = match step {
            StepRequest::Step(mode) => mode,
            StepRequest::Out => return self.step_motion(Motion::StepOut),
        };

        let (rip, start) = {
            let session = self.session()?;
            let rip = session.run_status().rip;
            let start = rip
                .and_then(|rip| session.target.source_location(VirtAddr(rip)))
                .map(|location| (location.file, location.line));
            (rip.unwrap_or(0), start)
        };
        let Some((file, line)) = start.filter(|_| !instruction_granularity) else {
            return self.step_once(mode);
        };
        if let Some(step) = self.step.as_mut() {
            step.line = Some(LineStep {
                mode,
                file,
                line,
                runs_left: STEP_LINE_BUDGET - 1,
            });
        }
        self.advance_within_line(mode, rip)
    }

    /// A stop the running target reached. One that ends a run of a step by
    /// source line still on its line starts the step's next run; any other
    /// is reported.
    pub(super) fn on_stopped(&mut self, mut stop: Stop) {
        while let Some(line) = self.step.as_mut().and_then(|step| step.line.as_mut()) {
            if !matches!(stop.kind, StopKind::Step)
                || self.cancel.load(Ordering::Relaxed)
                || line.runs_left == 0
            {
                break;
            }
            line.runs_left -= 1;
            let (mode, file, number) = (line.mode, line.file.clone(), line.line);
            let rip = stop.rip.unwrap_or(0);
            let Some(session) = self.session.as_ref() else {
                break;
            };
            match session.target.source_location(VirtAddr(rip)) {
                Some(location) if location.file == file && location.line == number => {}
                // Another line, or code without line records (a call into a
                // module without private symbols): the step ends here rather
                // than running on blindly.
                _ => break,
            }
            match self.advance_within_line(mode, rip) {
                Ok(RunOutcome::Running) => return,
                Ok(RunOutcome::Stopped(next)) => stop = next,
                // The target stays where the last run left it.
                Err(message) => {
                    self.emit_output("stderr", format!("the step stopped early: {message}\n"));
                    break;
                }
            }
        }
        self.report_stop(stop);
    }

    /// Run one motion of the step in progress, handing the target back
    /// running unless it stopped at once, as a continue does. A run to an
    /// address handed back that way leaves its temporary sites armed, for
    /// the wait that ends it; they are the step's to remove
    /// ([`Self::end_step`]).
    fn step_motion(&mut self, motion: Motion) -> result::Result<RunOutcome, String> {
        let armed = self.armed_temporary_sites();
        let outcome = self.drive(motion, &Cancel::poll())?;
        let planted: Vec<(u32, u64)> = self
            .armed_temporary_sites()
            .into_iter()
            .filter(|site| !armed.contains(site))
            .collect();
        if let Some(step) = self.step.as_mut() {
            step.sites.extend(planted);
        }
        Ok(outcome)
    }

    /// The temporary sites the session has armed, by id and serial.
    fn armed_temporary_sites(&self) -> Vec<(u32, u64)> {
        self.session.as_ref().map_or_else(Vec::new, |session| {
            session
                .list_breakpoints()
                .into_iter()
                .filter(|breakpoint| breakpoint.temporary)
                .map(|breakpoint| (breakpoint.id, breakpoint.serial))
                .collect()
        })
    }

    /// End the step in progress, if any, removing the temporary sites its
    /// runs left armed: a stop elsewhere (a breakpoint, an exception, a
    /// `pause`) leaves them, and the next run would stop at one as if the
    /// step had ended there. A site that fired is the stop's own, and the
    /// next resume removes it.
    pub(super) fn end_step(&mut self) {
        let Some(step) = self.step.take() else {
            return;
        };
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let armed: Vec<u32> = step
            .sites
            .into_iter()
            .filter(|&(id, serial)| {
                session
                    .breakpoint(id)
                    .is_some_and(|breakpoint| breakpoint.serial == serial)
            })
            .map(|(id, _)| id)
            .collect();
        if armed.is_empty() {
            return;
        }
        let removed = session.with_target_halted(|session| {
            armed
                .iter()
                .try_for_each(|&id| session.remove_breakpoint(id))
        });
        if let Err(error) = removed {
            self.emit_output(
                "important",
                format!("the step's temporary breakpoint could not be removed: {error}\n"),
            );
        }
    }

    /// Run through a fall-through range, or single-step if no range can be used.
    fn advance_within_line(
        &mut self,
        mode: StepMode,
        rip: u64,
    ) -> result::Result<RunOutcome, String> {
        let Some(end) = self.coalescible_line_end(rip)? else {
            return self.step_once(mode);
        };
        let frame = self
            .session()?
            .step_frame(StepStack::Any)
            .map_err(|error| error.to_string())?;
        let run = Motion::RunTo {
            address: end,
            frame,
            disposition: ContinueDisposition::Handled,
        };
        match self.step_motion(run) {
            Ok(outcome) => Ok(outcome),
            // The temporary breakpoint could not be written (a non-resident or
            // read-only page at that address). Stepping needs no breakpoint.
            Err(_) => self.step_once(mode),
        }
    }

    /// End of a readable fall-through range containing more than one instruction.
    /// `None` requires single-stepping instead.
    pub(super) fn coalescible_line_end(
        &mut self,
        rip: u64,
    ) -> result::Result<Option<VirtAddr>, String> {
        let session = self.session()?;
        let Some(end) = session
            .target
            .source_line_extent(VirtAddr(rip))
            .and_then(|extent| extent.end)
            .filter(|end| end.0 > rip)
        else {
            return Ok(None);
        };
        let Some(span) = usize::try_from(end.0 - rip)
            .ok()
            .filter(|span| *span <= MAX_LINE_SPAN)
        else {
            return Ok(None);
        };
        // Masked: an injected breakpoint byte reads as `int3`, i.e. as control
        // flow, and would defeat the fall-through proof.
        let mut bytes = vec![0u8; span];
        if session.read_masked(VirtAddr(rip), &mut bytes).is_err() {
            return Ok(None);
        }
        let machine = session.target.executing_machine(VirtAddr(rip));
        let Some(run_end) = fallthrough_run_end(&bytes, rip, end.0, machine) else {
            return Ok(None);
        };
        // One instruction: a single-step reaches it in one round trip, a run
        // needs a breakpoint write, a resume and a removal.
        if instruction_length(&bytes, machine) == Some(run_end.saturating_sub(rip) as usize) {
            return Ok(None);
        }
        Ok(Some(VirtAddr(run_end)))
    }

    fn step_once(&mut self, mode: StepMode) -> result::Result<RunOutcome, String> {
        self.step_motion(match mode {
            StepMode::Into => Motion::Step,
            StepMode::Over => Motion::StepOver,
        })
    }

    /// Report where a user-mode minidump stands: at its exception, on the
    /// thread that raised it, when it records one, with the exception's
    /// context selected (`.ecxr`) so that thread's stack, scopes, and
    /// expressions start where the exception was raised; else at the
    /// selected thread's captured context.
    fn report_user_dump_stop(&mut self) {
        self.invalidate_stop_state();
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let selected = session
            .target
            .user_exception()
            .is_some()
            .then(|| session.select_user_exception_context());
        let target = &session.target;
        let stop = match (target.user_exception(), target.user_exception_summary()) {
            (Some(exception), Some(summary)) => {
                let parameters = exception
                    .parameters
                    .iter()
                    .map(|parameter| format!("{parameter:#x}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                StopInfo {
                    reason: "exception",
                    description: format!("exception {summary}"),
                    exception_id: Some(format!("{:#010x}", exception.code)),
                    detail: Some(format!(
                        "exception record: code {:#010x}, flags {:#x}, address {:#x}, parameters [{parameters}]",
                        exception.code, exception.flags, exception.address
                    )),
                    breakpoint_id: None,
                }
            }
            _ => StopInfo {
                reason: "entry",
                description: format!(
                    "user-mode minidump of {}",
                    target
                        .user_dump_info()
                        .map(|info| info.process_label())
                        .unwrap_or_default()
                ),
                exception_id: None,
                detail: None,
                breakpoint_id: None,
            },
        };
        if let Some(Err(error)) = selected {
            self.emit_output(
                "important",
                format!("the exception's context cannot be selected; its thread shows its own: {error}\n"),
            );
        }
        self.publish_stop(stop);
    }

    /// The stop a `sxe ld` or `sxe ud` filter surfaced, with WinDbg's
    /// `ModLoad:` or `Unload module` line echoed to the console.
    fn module_event_stop(&mut self, event: ModuleEvent, module: &ModuleInfo, rip: u64) -> StopInfo {
        let line = module_event_line(event, module);
        self.emit_output("console", format!("{line}\n"));
        let reason = match event {
            ModuleEvent::Load => "module load",
            ModuleEvent::Unload => "module unload",
        };
        StopInfo {
            reason,
            description: format!("{reason} {} at {rip:#x}", module.name),
            exception_id: None,
            detail: Some(line),
            breakpoint_id: None,
        }
    }

    /// The bookkeeping every reported stop starts with: the step in
    /// progress ends, the client's view of the last stop is dropped, and
    /// what arrived meanwhile goes out first.
    fn enter_halted(&mut self) {
        self.end_step();
        self.invalidate_stop_state();
        self.state = RunState::Halted;
        self.cancel.store(false, Ordering::Relaxed);
        self.drain_debug_output();
        self.reconcile_breakpoints();
    }

    /// Report a step that ended before it got where it was going, `why`
    /// (its thread exited), with the target halted wherever that left it:
    /// a `step` stop, as a completed step is, whose description says so.
    pub(super) fn report_ended_step(&mut self, why: &str) {
        self.enter_halted();
        self.publish_stop(StopInfo {
            reason: "step",
            description: format!("step ended: {why}"),
            exception_id: None,
            detail: Some(why.to_string()),
            breakpoint_id: None,
        });
    }

    /// Report a stop to the client: the DAP reason for its kind, a requested
    /// break-in (or a target found halted for a `pause`) as `pause`.
    pub(super) fn report_stop(&mut self, stop: Stop) {
        self.enter_halted();

        let rip = stop.rip.unwrap_or(0);
        let info = match &stop.kind {
            StopKind::Breakpoint { breakpoint: hit } => {
                let id = hit.id;
                if let Some(error) = hit.condition_error.as_deref() {
                    self.emit_output(
                        "important",
                        format!("breakpoint {id} condition failed: {error}\n"),
                    );
                }
                let where_ = hit.symbol.clone().unwrap_or_else(|| format!("{rip:#x}"));
                StopInfo {
                    reason: "breakpoint",
                    description: format!("breakpoint {id} at {where_}"),
                    exception_id: None,
                    detail: Some(format!("address {:#x}", hit.address)),
                    breakpoint_id: Some(id),
                }
            }
            StopKind::Step => StopInfo {
                reason: "step",
                description: format!("step to {rip:#x}"),
                exception_id: None,
                detail: None,
                breakpoint_id: None,
            },
            StopKind::ModuleLoad { module } => {
                self.module_event_stop(ModuleEvent::Load, module, rip)
            }
            StopKind::ModuleUnload { module } => {
                self.module_event_stop(ModuleEvent::Unload, module, rip)
            }
            StopKind::Entry | StopKind::Interrupt => StopInfo {
                reason: if matches!(stop.kind, StopKind::Entry) {
                    "entry"
                } else {
                    "pause"
                },
                description: format!("halted at {rip:#x}"),
                exception_id: None,
                detail: None,
                breakpoint_id: None,
            },
            StopKind::Exception { exception } => {
                let code = exception.code;
                let name = exception_code_name(code);
                let chance = match exception.first_chance {
                    Some(true) => " (first chance)",
                    Some(false) => " (second chance)",
                    None => "",
                };
                StopInfo {
                    reason: "exception",
                    description: format!("{name} ({code:#x}){chance} at {rip:#x}"),
                    exception_id: Some(format!("{code:#010x}")),
                    detail: exception
                        .address
                        .map(|address| format!("exception record address {address:#x}")),
                    breakpoint_id: None,
                }
            }
            StopKind::Bugcheck { bugcheck } => {
                let detail = match bugcheck {
                    Some(info) => format!(
                        "bugcheck {:#x} ({:#x}, {:#x}, {:#x}, {:#x})",
                        info.code,
                        info.parameters[0],
                        info.parameters[1],
                        info.parameters[2],
                        info.parameters[3]
                    ),
                    None => "bugcheck (code unavailable from the transport)".to_string(),
                };
                self.emit_output("important", format!("{detail}\n"));
                self.emit_output(
                    "console",
                    "run `!analyze -v` in the debug console for the full triage\n",
                );
                StopInfo {
                    reason: "exception",
                    description: match stop.rip {
                        Some(rip) => format!("{detail} at {rip:#x}"),
                        None => detail.clone(),
                    },
                    exception_id: Some("bugcheck".to_string()),
                    detail: Some(detail),
                    breakpoint_id: None,
                }
            }
            StopKind::Reload { reload } => {
                let base = reload
                    .kernel_base
                    .map(|base| format!("{base:#x}"))
                    .unwrap_or_else(|| "unknown".to_string());
                self.emit_output(
                    "important",
                    format!(
                        "target rebooted; nt base {base}{}\n",
                        if reload.coherent {
                            ""
                        } else {
                            " (early boot: module and process enumeration not yet available)"
                        }
                    ),
                );
                StopInfo {
                    reason: "entry",
                    description: format!("target rebooted (nt {base})"),
                    exception_id: None,
                    detail: None,
                    breakpoint_id: None,
                }
            }
        };
        self.publish_stop(info);
    }

    /// Tell the client about `stop`, on the current thread.
    fn publish_stop(&mut self, stop: StopInfo) {
        self.sync_threads();
        let thread_id = self
            .session
            .as_ref()
            .map(|session| session.current_thread.clone())
            .map(|id| self.dap_thread_id(&id))
            .unwrap_or(1);
        let mut body = json!({
            "reason": stop.reason,
            "threadId": thread_id,
            "allThreadsStopped": true,
            "description": stop.description,
            "preserveFocusHint": false,
        });
        if stop.reason == "breakpoint"
            && let Some(detail) = &stop.detail
        {
            body["text"] = json!(detail);
        }
        if let Some(id) = stop.breakpoint_id {
            body["hitBreakpointIds"] = json!([id]);
        }
        self.last_stop = Some(stop);
        self.send_event("stopped", body);
    }

    pub(super) fn on_exception_info(&mut self) -> Handled {
        let Some(stop) = self.last_stop.as_ref() else {
            return Err("no stop has been reported yet".to_string());
        };
        let Some(exception_id) = stop.exception_id.clone() else {
            return Err("the last stop was not an exception".to_string());
        };
        let description = stop.description.clone();
        let detail = stop.detail.clone().unwrap_or_else(|| description.clone());
        Ok(Some(json!({
            "exceptionId": exception_id,
            "description": description,
            "breakMode": "always",
            "details": {"message": detail},
        })))
    }
}

/// A DAP step request: `next` and `stepIn` step by line or instruction,
/// `stepOut` runs to the caller.
#[derive(Clone, Copy)]
pub(super) enum StepRequest {
    Step(StepMode),
    Out,
}

/// A step whose runs are under way.
#[derive(Default)]
pub struct StepInProgress {
    /// The temporary sites its runs armed, by id and serial.
    sites: Vec<(u32, u64)>,
    /// For a step by source line, what decides whether a run's stop ends
    /// it.
    line: Option<LineStep>,
}

/// A step by source line: it runs on while its runs stop on the line it
/// started on.
struct LineStep {
    mode: StepMode,
    file: String,
    line: u32,
    /// How many more runs it may take before it stops where it got to, for
    /// a line that execution never leaves.
    runs_left: usize,
}
