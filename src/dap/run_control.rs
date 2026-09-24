//! Run control: continue, pause, and stepping by source line or instruction,
//! and reporting each stop to the client.

use std::result;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde_json::json;

use crate::disasm::{fallthrough_run_end, instruction_length};
use crate::output;
use crate::repl::{DispatchContext, ReplState, ReplStore};
use crate::session::{ContinueOutcome, StepMode};
use crate::triage_report::exception_code_name;
use crate::types::VirtAddr;

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
        let status = self.session()?.run_status();
        let running = status.running;
        let rip = status.rip.unwrap_or(0);
        self.respond(request, Ok(None));
        if running {
            self.state = RunState::Running;
        } else {
            self.state = RunState::Halted;
            self.report_stop(ContinueOutcome::Halted { rip });
        }
        Ok(None)
    }

    pub(super) fn on_continue(&mut self, request: &Request) -> Handled {
        let result = self.session()?.resume().map_err(|error| error.to_string());
        match result {
            Ok(()) => {
                self.invalidate_stop_state();
                self.state = RunState::Running;
                self.respond(request, Ok(Some(json!({"allThreadsContinued": true}))));
                self.send_event(
                    "continued",
                    json!({"threadId": 1, "allThreadsContinued": true}),
                );
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
        let result = self
            .session()?
            .interrupt_outcome()
            .map_err(|error| error.to_string());
        match result {
            Ok(outcome) => {
                self.respond(request, Ok(None));
                // A break-in arrives as `STATUS_BREAKPOINT` and a target found
                // halted has no event; both are the pause the client asked
                // for (the exception detail stays for `exceptionInfo`). A
                // breakpoint, bugcheck, or reboot the break-in raced is
                // reported as itself.
                let forced = matches!(
                    outcome,
                    ContinueOutcome::Stopped { .. } | ContinueOutcome::Halted { .. }
                )
                .then_some("pause");
                self.report_stop_as(outcome, forced);
            }
            Err(message) => self.respond(request, Err(message)),
        }
        Ok(None)
    }

    pub(super) fn on_step(&mut self, request: &Request, step: StepRequest) -> Handled {
        let instruction_granularity =
            arg_str(&request.arguments, "granularity").as_deref() == Some("instruction");
        if let Some(thread) = arg_i64(&request.arguments, "threadId")
            && let Err(message) = self.select_thread(thread)
        {
            self.respond(request, Err(message));
            return Ok(None);
        }
        self.invalidate_stop_state();
        let outcome = self.run_step(step, instruction_granularity);
        match outcome {
            Ok(outcome) => {
                self.respond(request, Ok(None));
                self.report_stop(outcome);
            }
            Err(message) => {
                self.respond(request, Err(message));
                // The step failed with the target still halted where it was,
                // so re-announce that stop to keep the client's view live. A
                // target that reports no pc has no stop to re-announce, and
                // inventing one would park the client at 0x0.
                if let Some(rip) = self
                    .session
                    .as_mut()
                    .and_then(|session| session.run_status().rip)
                {
                    self.report_stop(ContinueOutcome::Halted { rip });
                }
            }
        }
        Ok(None)
    }

    /// Step by source line, or by instruction when requested or unmapped.
    fn run_step(
        &mut self,
        step: StepRequest,
        instruction_granularity: bool,
    ) -> result::Result<ContinueOutcome, String> {
        let mode = match step {
            StepRequest::Step(mode) => mode,
            StepRequest::Out => {
                let cancel = Arc::clone(&self.cancel);
                let session = self.session()?;
                return session.step_out(&cancel).map_err(|error| error.to_string());
            }
        };

        let (mut rip, start) = {
            let session = self.session()?;
            let rip = session.run_status().rip;
            let start = rip
                .and_then(|rip| session.target.source_location(VirtAddr(rip)))
                .map(|location| (location.file, location.line));
            (rip.unwrap_or(0), start)
        };
        if instruction_granularity || start.is_none() {
            return self.step_once(mode);
        }

        for _ in 0..STEP_LINE_BUDGET {
            let outcome = self.advance_within_line(mode, rip)?;
            if !matches!(outcome, ContinueOutcome::Step { .. }) {
                return Ok(outcome);
            }
            if self.cancel.load(Ordering::Relaxed) {
                return Ok(outcome);
            }
            let session = self.session()?;
            rip = session.run_status().rip.unwrap_or(0);
            match session.target.source_location(VirtAddr(rip)) {
                // Left line-mapped code (a call into a module without private
                // symbols): stop here rather than running on blindly.
                None => return Ok(outcome),
                Some(location) => {
                    if start
                        .as_ref()
                        .is_none_or(|(file, line)| location.line != *line || location.file != *file)
                    {
                        return Ok(outcome);
                    }
                }
            }
        }
        Ok(ContinueOutcome::Step { rip })
    }

    /// Run through a fall-through range, or single-step if no range can be used.
    fn advance_within_line(
        &mut self,
        mode: StepMode,
        rip: u64,
    ) -> result::Result<ContinueOutcome, String> {
        let Some(end) = self.coalescible_line_end(rip)? else {
            return self.step_once(mode);
        };
        let cancel = Arc::clone(&self.cancel);
        match self.session()?.run_to(end, None, &cancel) {
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
        let arch = session.target.arch();
        let bitness = session.target.code_bitness(VirtAddr(rip));
        let Some(run_end) = fallthrough_run_end(&bytes, rip, end.0, arch, bitness) else {
            return Ok(None);
        };
        // One instruction: a single-step reaches it in one round trip, a run
        // needs a breakpoint write, a resume and a removal.
        if instruction_length(&bytes, arch, bitness) == Some(run_end.saturating_sub(rip) as usize) {
            return Ok(None);
        }
        Ok(Some(VirtAddr(run_end)))
    }

    fn step_once(&mut self, mode: StepMode) -> result::Result<ContinueOutcome, String> {
        let cancel = Arc::clone(&self.cancel);
        let session = self.session()?;
        match mode {
            StepMode::Into => {
                let rip = session.step().map_err(|error| error.to_string())?;
                Ok(ContinueOutcome::Step { rip })
            }
            StepMode::Over => session
                .step_over(&cancel)
                .map_err(|error| error.to_string()),
        }
    }

    pub(super) fn report_stop(&mut self, outcome: ContinueOutcome) {
        self.report_stop_as(outcome, None);
    }

    /// Report a stop to the client. `forced_reason` overrides the DAP stop
    /// reason without touching the description or exception detail, for stops
    /// whose transport encoding hides the real cause (a break-in is delivered
    /// as a breakpoint exception).
    fn report_stop_as(&mut self, outcome: ContinueOutcome, forced_reason: Option<&'static str>) {
        // A cancelled run: `run_to` halts the target to remove its temporary
        // breakpoint before reporting `Running`, so the client's `pause` has
        // its stop. Only a target still running (the halt failed) stays on
        // its run.
        let (outcome, forced_reason) = match outcome {
            ContinueOutcome::Running => {
                let halted_rip = self
                    .session
                    .as_mut()
                    .filter(|session| !session.backend.is_running())
                    .and_then(|session| session.run_status().rip);
                match halted_rip {
                    Some(rip) => (ContinueOutcome::Halted { rip }, Some("pause")),
                    None => {
                        self.invalidate_stop_state();
                        self.state = RunState::Running;
                        return;
                    }
                }
            }
            outcome => (outcome, forced_reason),
        };
        self.invalidate_stop_state();
        self.state = RunState::Halted;
        self.cancel.store(false, Ordering::Relaxed);
        self.drain_debug_output();
        self.reconcile_breakpoints();

        let mut action = None;
        let stop = match outcome {
            ContinueOutcome::Running => unreachable!("a running target was reported above"),
            ContinueOutcome::Breakpoint {
                id,
                address,
                symbol,
                rip,
                condition_error,
                action: breakpoint_action,
                ..
            } => {
                action = breakpoint_action;
                let where_ = symbol.unwrap_or_else(|| format!("{rip:#x}"));
                if let Some(error) = condition_error {
                    self.emit_output(
                        "important",
                        format!("breakpoint {id} condition failed: {error}\n"),
                    );
                }
                StopInfo {
                    reason: "breakpoint",
                    description: format!("breakpoint {id} at {where_}"),
                    exception_id: None,
                    detail: Some(format!("address {address:#x}")),
                    breakpoint_id: Some(id),
                }
            }
            ContinueOutcome::Step { rip } => StopInfo {
                reason: "step",
                description: format!("step to {rip:#x}"),
                exception_id: None,
                detail: None,
                breakpoint_id: None,
            },
            ContinueOutcome::Halted { rip } => StopInfo {
                reason: "entry",
                description: format!("halted at {rip:#x}"),
                exception_id: None,
                detail: None,
                breakpoint_id: None,
            },
            ContinueOutcome::Stopped {
                rip,
                exception_code,
                first_chance,
                exception_address,
            } => match exception_code {
                Some(code) => {
                    let name = exception_code_name(code);
                    let chance = match first_chance {
                        Some(true) => " (first chance)",
                        Some(false) => " (second chance)",
                        None => "",
                    };
                    StopInfo {
                        reason: "exception",
                        description: format!("{name} ({code:#x}){chance} at {rip:#x}"),
                        exception_id: Some(format!("{code:#010x}")),
                        detail: exception_address
                            .map(|address| format!("exception record address {address:#x}")),
                        breakpoint_id: None,
                    }
                }
                None => StopInfo {
                    reason: "pause",
                    description: format!("halted at {rip:#x}"),
                    exception_id: None,
                    detail: None,
                    breakpoint_id: None,
                },
            },
            ContinueOutcome::Bugcheck { rip, info } => {
                let detail = match &info {
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
                    description: match rip {
                        Some(rip) => format!("{detail} at {rip:#x}"),
                        None => detail.clone(),
                    },
                    exception_id: Some("bugcheck".to_string()),
                    detail: Some(detail),
                    breakpoint_id: None,
                }
            }
            ContinueOutcome::TargetReloaded {
                kernel_base,
                coherent,
                ..
            } => {
                let base = kernel_base
                    .map(|base| format!("{base:#x}"))
                    .unwrap_or_else(|| "unknown".to_string());
                self.emit_output(
                    "important",
                    format!(
                        "target rebooted; nt base {base}{}\n",
                        if coherent {
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

        // A breakpoint command action belongs to the frontend. Running it here
        // keeps `bp ... do "..."` (typed in the console) working, including a
        // trailing `gc` that resumes the target.
        if let Some(action) = action {
            self.run_breakpoint_action(&action);
            if self
                .session
                .as_ref()
                .is_some_and(|session| session.backend.is_running())
            {
                self.state = RunState::Running;
                self.last_stop = Some(stop);
                return;
            }
        }

        self.sync_threads();
        let thread_id = self
            .session
            .as_ref()
            .map(|session| session.current_thread.clone())
            .map(|id| self.dap_thread_id(&id))
            .unwrap_or(1);
        let mut body = json!({
            "reason": forced_reason.unwrap_or(stop.reason),
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

    /// Run the breakpoint command action, sending output to the Debug Console.
    /// A trailing `gc` resumes without reporting a stop.
    fn run_breakpoint_action(&mut self, action: &str) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let store = ReplStore::new(session, DispatchContext::BreakpointAction);
        let mut state = ReplState::attach(session, store);
        state.line = action.to_string();
        let (result, text) = output::capture(|| state.dispatch_breakpoint_action(action));
        drop(state.detach());
        if !text.is_empty() {
            self.emit_output("stdout", text);
        }
        match result {
            // The action asked to resume (`...; gc`). Nothing else will do it:
            // the client was never told the target stopped.
            Ok(true) => {
                if let Some(session) = self.session.as_mut()
                    && let Err(error) = session.resume()
                {
                    self.emit_output(
                        "stderr",
                        format!("breakpoint action could not resume the target: {error}\n"),
                    );
                }
            }
            Ok(false) => {}
            Err(error) => {
                self.emit_output("stderr", format!("breakpoint action failed: {error}\n"));
            }
        }
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
