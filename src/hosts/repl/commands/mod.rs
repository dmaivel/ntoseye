use crate::TargetSpec;
use crate::base::diagnostics::{errors_reported, print_notice};
use crate::base::error::Result;
use crate::base::types::VirtAddr;
use crate::hosts::repl::*;
use crate::hosts::ui;
use crate::nt::expr::Expr;
use crate::session::effects::Refusal;
use crate::session::{ActionRunner, Session};

const ALIAS_RECURSION_LIMIT: usize = 16;

/// Open a session for a host: [`Session::open_with_progress`], with the REPL
/// dispatcher installed to run its stops' breakpoint actions and filter
/// commands. Every host opens its sessions here.
pub fn open_session(spec: &TargetSpec, progress: &mut dyn FnMut(&str)) -> Result<Session> {
    let mut session = Session::open_with_progress(spec, progress)?;
    session.set_action_runner(Box::new(ReplActions::default()));
    Ok(session)
}

/// The REPL dispatcher as every session's [`ActionRunner`]: breakpoint `do`
/// actions and filter `-c` commands run in a REPL of their own over the
/// session, with the user's saved aliases and the session's pseudo-registers
/// and radix, whichever host drives the run. Output goes where the host's
/// output goes.
#[derive(Default)]
pub struct ReplActions {
    /// The REPL state the actions run in, made at the first one and kept, so
    /// a log point does not load the saved aliases and build the completion
    /// caches again at every hit.
    store: Option<ReplStore>,
    /// The [`alias_generation`] the store's aliases were loaded at.
    aliases_at: u64,
}

impl ReplActions {
    fn with_state<T>(
        &mut self,
        session: &mut Session,
        line: &str,
        f: impl FnOnce(&mut ReplState) -> T,
    ) -> T {
        let generation = alias_generation();
        let store = match self.store.take() {
            Some(store) => store,
            None => {
                self.aliases_at = generation;
                ReplStore::new(session, DispatchContext::BreakpointAction)
            }
        };
        let mut state = ReplState::attach(session, store);
        // An alias defined or removed since the last hit applies to this one.
        if self.aliases_at != generation {
            state.reload_aliases();
            self.aliases_at = alias_generation();
        }
        // Each hit lists from its own stop: `ls` and `#` without an address
        // do not go on from where the last hit's left off.
        state.source_cursor = None;
        state.disasm_search = DisasmSearch::default();
        state.line = line.to_string();
        let result = f(&mut state);
        self.store = Some(state.detach());
        result
    }
}

impl ActionRunner for ReplActions {
    fn breakpoint_action(&mut self, session: &mut Session, action: &str) -> bool {
        self.with_state(session, action, |state| {
            state.dispatch_breakpoint_action(action)
        })
    }

    fn event_command(&mut self, session: &mut Session, command: &str) {
        self.with_state(session, command, |state| {
            state.dispatch_exception_command(command)
        })
    }
}

pub mod address_space;
pub mod analyze;
mod blackbox;
pub mod breakpoints;
mod cpu;
mod diagnostics;
mod disasm;
pub mod display;
mod dx;
mod dx_model;
mod dx_query;
mod etw;
mod exceptions;
pub mod exec;
mod foreach;
pub mod frames;
mod fs;
mod hardware;
mod heap;
mod image;
mod interrupts;
pub mod memory;
pub mod meta;
pub mod mm;
mod ndis;
mod object;
mod physical;
mod pnp;
pub mod power;
pub mod process;
mod process_objects;
mod rcdr;
mod registry;
mod sched;
mod script;
mod security;
mod shell;
mod storport;
pub mod symbols;
mod target_control;
mod thread;
pub mod types;
mod usermode;
mod verifier;
pub mod virtio;
pub mod vtl;
mod wdf;

pub use meta::{command_reference_json, json_string};

impl ReplState<'_> {
    pub fn dispatch_line(&mut self, line: &str) -> Result<Flow> {
        let flow = self.dispatch_line_inner(line, 0);
        // `.process /p`, `.reload`, a backtrace's lazy frame load, or a
        // background fetch that finished meanwhile may have made a deferred
        // breakpoint resolvable.
        self.ctx.reconcile_breakpoints_if_symbols_changed();
        self.flush_notices();
        flow
    }

    /// Print the notices the core raised since the last boundary, so a
    /// breakpoint that failed to re-arm during a stop is not lost silently.
    pub fn flush_notices(&mut self) {
        for notice in self.ctx.take_notices() {
            print_notice(&notice);
        }
    }

    /// Evaluate a command's expression argument in the current radix. A
    /// failure is reported here, so the command only has to stop on `None`.
    fn eval_or_report(&self, text: &str) -> Option<VirtAddr> {
        match Expr::eval_with_radix(text, &self.ctx.target, self.ctx.radix) {
            Ok(value) => Some(value),
            Err(error) => {
                error!("{error}");
                None
            }
        }
    }

    /// Run a breakpoint action. A WinDbg-style `gc` or plain `g` requests
    /// automatic resume; it ends the action wherever it runs, so
    /// `j (cond) ''; 'g'` resumes too. Returns whether the action resumes.
    pub fn dispatch_breakpoint_action(&mut self, line: &str) -> bool {
        self.dispatch_event_commands(line, DispatchContext::BreakpointAction, |flow| match flow {
            Flow::Jump(Jump::Resume) => Some(true),
            Flow::Quit | Flow::Denied | Flow::Jump(_) => Some(false),
            Flow::Continue => None,
        })
    }

    /// Run a policy-owned exception command without letting its text choose
    /// run control: the caller applies the policy's typed final action
    /// (`break`, `gh`, or `gn`) after this returns.
    pub fn dispatch_exception_command(&mut self, line: &str) {
        self.dispatch_event_commands(line, DispatchContext::ExceptionCommand, |flow| match flow {
            Flow::Denied | Flow::Jump(_) => Some(()),
            Flow::Quit => {
                error!("quit is ignored inside an exception command");
                Some(())
            }
            Flow::Continue => None,
        })
    }

    /// Run an event's command list in `context`, the REPL side of the core's
    /// [`ActionRunner`]. `end` maps a command's flow to the list's result, or
    /// to `None` to go on with the next command; a list that runs out, fails,
    /// or does not parse gives the default.
    fn dispatch_event_commands<T: Default>(
        &mut self,
        line: &str,
        context: DispatchContext,
        mut end: impl FnMut(Flow) -> Option<T>,
    ) -> T {
        let commands = match split_command_list(line) {
            Ok(commands) => commands,
            Err(error) => {
                report_command_parse_error(line, error);
                return T::default();
            }
        };
        self.event_command_depth += 1;
        let outer = std::mem::replace(&mut self.context, context);
        // A loop the stop interrupted is not the event's to break.
        let breakable = std::mem::replace(&mut self.breakable_loop, false);
        let mut result = T::default();
        for command in commands {
            // A failing command is reported and abandons the rest of the
            // list. Propagating would end the session, and a log point whose
            // argument is briefly unreadable must not take the debugger down
            // with it.
            let flow = match self.dispatch_one(command, 0) {
                Ok(flow) => flow,
                Err(error) => {
                    let what = match context {
                        DispatchContext::BreakpointAction => "breakpoint action",
                        _ => "exception command",
                    };
                    error!("{what} failed: {error}");
                    break;
                }
            };
            if let Some(value) = end(flow) {
                result = value;
                break;
            }
            self.caches.refresh_expression_context(&self.ctx.target);
        }
        self.context = outer;
        self.breakable_loop = breakable;
        self.event_command_depth -= 1;
        result
    }

    /// Why the current [`DispatchContext`] refuses `spec`, if it does. Decided
    /// on the resolved command's [`RunEffect`], after alias expansion, so an
    /// alias cannot smuggle a resume into an event command.
    fn run_control_denial(&self, spec: &CommandSpec) -> Option<String> {
        let name = spec.names[0];
        match self.context {
            DispatchContext::Interactive => None,
            DispatchContext::BreakpointAction if spec.effects.run != RunEffect::None => {
                Some(format!(
                    "run-control command '{name}' must not appear inside a breakpoint action; \
                 use 'g' or 'gc' (no address) to continue"
                ))
            }
            DispatchContext::ExceptionCommand
                if spec.effects.run != RunEffect::None
                    || spec.effects.state == RunState::Running =>
            {
                Some(format!(
                    "run-control command '{name}' must not appear inside an exception command; \
                     use the policy's -f break, -f gh, or -f gn"
                ))
            }
            DispatchContext::Remote(RemoteClient::Dap) if spec.effects.run == RunEffect::Run => {
                Some(format!(
                    "'{name}' would block this session until the next stop; use the client's \
                 continue or step controls instead"
                ))
            }
            DispatchContext::Remote(RemoteClient::Mcp) if spec.flow == Flow::Quit => Some(format!(
                "'{name}' ends the interactive REPL; use the close tool to release the session"
            )),
            DispatchContext::Remote(RemoteClient::Sdk) if spec.flow == Flow::Quit => Some(format!(
                "'{name}' ends the interactive REPL; call close() to release the session"
            )),
            DispatchContext::Remote(RemoteClient::Dap) if spec.flow == Flow::Quit => Some(format!(
                "'{name}' ends the interactive REPL; disconnect from the client to end the \
                 debug session"
            )),
            // The client caches registers and memory for the stop it was last
            // told about; only its own resume packets may move the target.
            DispatchContext::Remote(RemoteClient::Gdb) if spec.effects.run != RunEffect::None => {
                Some(format!(
                    "'{name}' would move the target behind the GDB client; use the client's \
                     continue or step controls instead"
                ))
            }
            DispatchContext::Remote(RemoteClient::Gdb) if spec.flow == Flow::Quit => Some(format!(
                "'{name}' ends the interactive REPL; detach from the GDB client to end the \
                 debug session"
            )),
            _ => None,
        }
    }

    fn dispatch_line_inner(&mut self, line: &str, depth: usize) -> Result<Flow> {
        let commands = match split_command_list(line) {
            Ok(commands) => commands,
            Err(err) => {
                report_command_parse_error(line, err);
                return Ok(Flow::Continue);
            }
        };

        // The line the user sent is the outermost list, and a stop in its
        // middle is drawn brief for a compact host (see
        // [`Session::brief_stops`]): the rest of the line carries on from it.
        let outermost = self.line_depth == 0;
        self.line_depth += 1;
        let flow = self.dispatch_commands(&commands, depth, outermost);
        self.line_depth -= 1;
        if outermost {
            self.ctx.brief_stops = false;
        }
        flow
    }

    fn dispatch_commands(
        &mut self,
        commands: &[&str],
        depth: usize,
        outermost: bool,
    ) -> Result<Flow> {
        // A command that reports an error ends the list, as in WinDbg: what
        // follows usually depends on it, as `g` depends on the `bp` before
        // it, and running on would resume a target nothing is set to stop.
        for (index, command) in commands.iter().enumerate() {
            let rest = &commands[index + 1..];
            if outermost {
                self.ctx.brief_stops = !rest.is_empty();
            }
            let errors = errors_reported();
            match self.dispatch_one(command, depth)? {
                Flow::Continue => {}
                flow => return Ok(flow),
            }
            if errors_reported() != errors {
                if !rest.is_empty() {
                    outln!(
                        "{}",
                        ui::muted(&format!("not run after that error: {}", rest.join("; ")))
                    );
                }
                return Ok(Flow::Continue);
            }
            self.caches.refresh_expression_context(&self.ctx.target);
        }
        Ok(Flow::Continue)
    }

    /// Whether the backend runs the target and can never stop it (the
    /// memory backend), where selecting a processor needs no halt.
    fn backend_never_halts(&self) -> bool {
        self.ctx.backend.is_running()
            && !self.ctx.backend.supports(DebugCapability::ExecutionControl)
    }

    /// The per-command policy every dispatch path shares: the context's
    /// refusal of host commands and of run control, then a remote host's
    /// wait for the halt the command needs (against the target's state right
    /// now, so a `break` earlier on the line counts), then the command's
    /// [`Effects`] through [`crate::session::Session::admit`], which the
    /// Python SDK shares. `None` means run it. `typed` is the name as the
    /// user wrote it, which messages repeat (`k`, not the canonical `kn`).
    fn admit(&mut self, spec: &CommandSpec, typed: &str) -> Result<Option<Flow>> {
        if let Some(reason) = self.host_command_denial(spec) {
            error!("{reason}");
            return Ok(Some(Flow::Denied));
        }
        if let Some(reason) = self.run_control_denial(spec) {
            error!("{reason}");
            return Ok(Some(Flow::Denied));
        }
        if let Some(flow) = self.gate_remote_command(spec, typed) {
            return Ok(Some(flow));
        }
        if let Err(refusal) = self.ctx.admit(&spec.effects) {
            // A VTL1 refusal ends a script or event command as a context
            // denial does: what follows was meant for the other VTL.
            // Inside a command loop any refusal ends the loop, since the
            // refused command would be refused on every pass.
            let flow = if matches!(refusal, Refusal::Vtl1(_)) || self.command_loop_depth > 0 {
                Flow::Denied
            } else {
                Flow::Continue
            };
            report_refusal(typed, refusal);
            return Ok(Some(flow));
        }
        Ok(None)
    }

    fn dispatch_one(&mut self, line: &str, depth: usize) -> Result<Flow> {
        // WinDbg processor syntax (`~2s`, `~*k`) is one token with the
        // selector glued on, so it never matches a registered name; a bare
        // `~` is the listing, which is.
        if line.trim_start().starts_with('~') && line.trim() != "~" {
            // Selecting a processor (`~1s`) where the backend never halts
            // (the memory backend) picks whose PRCB state later commands
            // read, which needs no halt; anything else `~` runs does.
            let body = line.trim().trim_start_matches('~');
            let digits = body.trim_end_matches('s');
            let selection = !digits.is_empty()
                && digits.bytes().all(|byte| byte.is_ascii_digit())
                && body.len() <= digits.len() + 1;
            if !(selection && self.backend_never_halts())
                && let Some(spec) = command_registry().get("~")
                && let Some(flow) = self.admit(spec, "~")?
            {
                return Ok(flow);
            }
            return self.cmd_tilde(line.trim());
        }
        // Script files (`$<`, `$$>a<`...) glue the file name on too.
        if let Some((token, operand)) = script_file_token(line.trim_start()) {
            if let Some(spec) = command_registry().get("$<")
                && let Some(flow) = self.admit(spec, token)?
            {
                return Ok(flow);
            }
            return self.run_script_file(token, operand);
        }
        // So do comments: `$$` runs to the next `;`, `*` to the line's end.
        if is_comment(line) {
            return Ok(Flow::Continue);
        }
        let parsed = match parse_command(line) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Ok(Flow::Continue),
            Err(err) => {
                report_command_parse_error(line, err);
                return Ok(Flow::Continue);
            }
        };

        if let Some(spec) = command_registry().get(parsed.name) {
            // WinDbg scripts resume from a breakpoint action with a plain
            // `g` (`"j (cond) 'kb; g' ; 'g'"`): there it is `gc`, which hands
            // the resume to the stop loop that ran the action. `g <address>`
            // stays refused below.
            if self.context == DispatchContext::BreakpointAction
                && spec.names[0] == "g"
                && parsed.raw_tail.trim().is_empty()
            {
                return Ok(Flow::Jump(Jump::Resume));
            }
            // `r $t0 = ...` touches no target state, so it runs whatever the
            // target is doing, unlike the register display `r` otherwise is.
            if spec.names[0] == "r"
                && let Some((slot, value)) = script::pseudo_register_operand(parsed.raw_tail)
            {
                self.cmd_pseudo_register(slot, value);
                return Ok(Flow::Continue);
            }
            // `vcpu N` selects a processor as `~Ns` does, so it needs a halt
            // only where the backend can halt.
            let selection_only = spec.names[0] == "vcpu" && self.backend_never_halts();
            if !selection_only && let Some(flow) = self.admit(spec, parsed.name)? {
                return Ok(flow);
            }
            match spec.handler {
                CommandHandler::Args(handler) => {
                    let Some(invocation) = invocation_or_report(line, &parsed, spec.style) else {
                        return Ok(Flow::Continue);
                    };
                    handler(self, invocation)?;
                }
                CommandHandler::ArgsFlow(handler) => {
                    let Some(invocation) = invocation_or_report(line, &parsed, spec.style) else {
                        return Ok(Flow::Continue);
                    };
                    return handler(self, invocation);
                }
            }
            return Ok(spec.flow);
        }

        let Some(invocation) = invocation_or_report(line, &parsed, CommandStyle::StructuredArgs)
        else {
            return Ok(Flow::Continue);
        };

        match self.aliases.expand(invocation.name, &invocation.argv) {
            Ok(Some(expanded)) => {
                if depth >= ALIAS_RECURSION_LIMIT {
                    error!("alias expansion limit reached");
                    return Ok(Flow::Continue);
                }
                return self.dispatch_line_inner(&expanded, depth + 1);
            }
            Ok(None) => {}
            Err(err) => {
                error!("{}", err);
                return Ok(Flow::Continue);
            }
        }

        if self.ctx.target.in_secure_address_space() {
            error!("custom commands are not VTL1-aware; they need a VTL0 address space");
            return Ok(Flow::Denied);
        }
        self.cmd_user(invocation)?;
        Ok(Flow::Continue)
    }
}

/// `parsed`'s arguments split as `style` says; a malformed line is reported.
fn invocation_or_report<'a>(
    line: &str,
    parsed: &ParsedCommand<'a>,
    style: CommandStyle,
) -> Option<CommandInvocation<'a>> {
    match parsed.invocation(style) {
        Ok(invocation) => Some(invocation),
        Err(err) => {
            report_command_parse_error(line, err);
            None
        }
    }
}
