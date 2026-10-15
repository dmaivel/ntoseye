//! Run control: continue, pause, and stepping by source line or instruction,
//! and reporting each stop to the client.

use std::result;
use std::sync::atomic::Ordering;

use serde_json::json;

use crate::dbg_backend::{ContinueDisposition, ModuleEvent};
use crate::disasm::{fallthrough_run_end, instruction_length};
use crate::guest::ModuleInfo;
use crate::output;
use crate::session::stops::module_event_line;
use crate::session::{
    Cancel, ExceptionStop, Motion, ReloadStop, RunOutcome, StepMode, StepStack, Stop, StopKind,
};
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
        self.refuse_on_user_dump("continue")?;
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

    pub(super) fn on_step(&mut self, request: &Request, step: StepRequest) -> Handled {
        self.refuse_on_user_dump("stepping")?;
        let instruction_granularity =
            arg_str(&request.arguments, "granularity").as_deref() == Some("instruction");
        if let Some(thread) = arg_i64(&request.arguments, "threadId")
            && let Err(message) = self.select_thread(thread)
        {
            self.respond(request, Err(message));
            return Ok(None);
        }
        self.invalidate_stop_state();
        match self.run_step(step, instruction_granularity) {
            Ok(stop) => {
                self.respond(request, Ok(None));
                self.report_stop(stop);
            }
            Err(message) => {
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

    /// Run a step motion to its stop. A step always ends halted: a `pause`
    /// (the session's interrupt request) halts it where it is.
    fn step_motion(&mut self, motion: Motion) -> result::Result<Stop, String> {
        match self.drive(motion, &Cancel::NEVER)? {
            RunOutcome::Stopped(stop) => Ok(stop),
            RunOutcome::Running => Err("the target is still running".to_string()),
        }
    }

    /// Step by source line, or by instruction when requested or unmapped.
    fn run_step(
        &mut self,
        step: StepRequest,
        instruction_granularity: bool,
    ) -> result::Result<Stop, String> {
        let mode = match step {
            StepRequest::Step(mode) => mode,
            StepRequest::Out => return self.step_motion(Motion::StepOut),
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

        let mut last = None;
        for _ in 0..STEP_LINE_BUDGET {
            let stop = self.advance_within_line(mode, rip)?;
            if stop.kind != StopKind::Step || self.cancel.load(Ordering::Relaxed) {
                return Ok(stop);
            }
            rip = stop.rip.unwrap_or(0);
            let session = self.session()?;
            match session.target.source_location(VirtAddr(rip)) {
                // Left line-mapped code (a call into a module without private
                // symbols): stop here rather than running on blindly.
                None => return Ok(stop),
                Some(location) => {
                    if start
                        .as_ref()
                        .is_none_or(|(file, line)| location.line != *line || location.file != *file)
                    {
                        return Ok(stop);
                    }
                }
            }
            last = Some(stop);
        }
        last.ok_or_else(|| "the step budget ran out".to_string())
    }

    /// Run through a fall-through range, or single-step if no range can be used.
    fn advance_within_line(&mut self, mode: StepMode, rip: u64) -> result::Result<Stop, String> {
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
            Ok(stop) => Ok(stop),
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

    fn step_once(&mut self, mode: StepMode) -> result::Result<Stop, String> {
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

    /// Report a stop to the client: the DAP reason for its kind, a requested
    /// break-in (or a target found halted for a `pause`) as `pause`.
    pub(super) fn report_stop(&mut self, stop: Stop) {
        self.invalidate_stop_state();
        self.state = RunState::Halted;
        self.cancel.store(false, Ordering::Relaxed);
        self.drain_debug_output();
        self.reconcile_breakpoints();

        let rip = stop.rip.unwrap_or(0);
        let info = match stop.kind {
            StopKind::Breakpoint => {
                let hit = stop.breakpoint.as_ref();
                let id = hit.map_or(0, |hit| hit.id);
                if let Some(error) = hit.and_then(|hit| hit.condition_error.as_deref()) {
                    self.emit_output(
                        "important",
                        format!("breakpoint {id} condition failed: {error}\n"),
                    );
                }
                let where_ = hit
                    .and_then(|hit| hit.symbol.clone())
                    .unwrap_or_else(|| format!("{rip:#x}"));
                StopInfo {
                    reason: "breakpoint",
                    description: format!("breakpoint {id} at {where_}"),
                    exception_id: None,
                    detail: hit.map(|hit| format!("address {:#x}", hit.address)),
                    breakpoint_id: hit.map(|hit| hit.id),
                }
            }
            StopKind::Step => StopInfo {
                reason: "step",
                description: format!("step to {rip:#x}"),
                exception_id: None,
                detail: None,
                breakpoint_id: None,
            },
            StopKind::ModuleLoad | StopKind::ModuleUnload => {
                let event = if stop.kind == StopKind::ModuleLoad {
                    ModuleEvent::Load
                } else {
                    ModuleEvent::Unload
                };
                match &stop.module {
                    Some(module) => self.module_event_stop(event, module, rip),
                    None => StopInfo {
                        reason: "pause",
                        description: format!("halted at {rip:#x}"),
                        exception_id: None,
                        detail: None,
                        breakpoint_id: None,
                    },
                }
            }
            StopKind::Entry | StopKind::Interrupt => StopInfo {
                reason: if stop.kind == StopKind::Entry {
                    "entry"
                } else {
                    "pause"
                },
                description: format!("halted at {rip:#x}"),
                exception_id: None,
                detail: None,
                breakpoint_id: None,
            },
            StopKind::Exception => {
                let exception = stop.exception.unwrap_or(ExceptionStop {
                    code: 0,
                    first_chance: None,
                    address: None,
                });
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
            StopKind::Bugcheck => {
                let detail = match &stop.bugcheck {
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
            StopKind::Reload => {
                let reload = stop.reload.unwrap_or(ReloadStop {
                    kernel_base: None,
                    coherent: true,
                });
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
