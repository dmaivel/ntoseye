use crate::diagnostics::{errors_reported, print_warning};
use crate::expr::Expr;
use crate::repl::*;
use crate::types::VirtAddr;
use crate::ui;

const ALIAS_RECURSION_LIMIT: usize = 16;
const BREAKPOINT_ACTION_RECURSION_LIMIT: usize = 4;

pub mod address_space;
pub mod analyze;
pub mod breakpoints;
pub mod browse;
mod cpu;
mod diagnostics;
pub mod display;
mod etw;
mod exceptions;
pub mod exec;
mod foreach;
pub mod frames;
mod fs;
mod hardware;
mod heap;
mod image;
pub mod memory;
pub mod meta;
pub mod mm;
mod object;
mod physical;
mod pnp;
pub mod process;
mod process_objects;
mod sched;
mod script;
mod security;
mod shell;
pub mod symbols;
mod target_control;
mod thread;
pub mod types;
mod usermode;
mod verifier;
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

    /// Print the diagnostics the core raised since the last boundary, so a
    /// breakpoint that failed to re-arm during a stop is not lost silently.
    pub fn flush_notices(&mut self) {
        for notice in self.ctx.take_notices() {
            print_warning(notice);
        }
    }

    /// Evaluate a command's expression argument in the current radix. A
    /// failure is reported here, so the command only has to stop on `None`.
    fn eval_or_report(&self, text: &str) -> Option<VirtAddr> {
        match Expr::eval_with_radix(text, &self.ctx.target, self.radix) {
            Ok(value) => Some(value),
            Err(error) => {
                error!("{error}");
                None
            }
        }
    }

    /// Execute frontend-owned breakpoint commands while keeping the core free
    /// of REPL state. A WinDbg-style `gc` or plain `g` requests automatic
    /// resume; it ends the action wherever it runs, so `j (cond) ''; 'g'`
    /// resumes too.
    /// Recursive actions are bounded even when an alias resumes into another
    /// command breakpoint.
    pub fn dispatch_breakpoint_action(&mut self, line: &str) -> Result<bool> {
        if self.event_command_depth >= BREAKPOINT_ACTION_RECURSION_LIMIT {
            error!("breakpoint action recursion limit reached");
            return Ok(false);
        }
        let commands = match split_command_list(line) {
            Ok(commands) => commands,
            Err(error) => {
                report_command_parse_error(line, error);
                return Ok(false);
            }
        };
        self.event_command_depth += 1;
        let outer = std::mem::replace(&mut self.context, DispatchContext::BreakpointAction);
        // A loop the stop interrupted is not the action's to break.
        let breakable = std::mem::replace(&mut self.breakable_loop, false);
        let result = (|| {
            for command in commands {
                // A failing action command is reported and abandons the rest
                // of the list. Propagating would end the session, and a log
                // point whose argument is briefly unreadable must not take
                // the debugger down with it.
                let flow = match self.dispatch_one(command, 0) {
                    Ok(flow) => flow,
                    Err(error) => {
                        error!("breakpoint action failed: {}", error);
                        return Ok(false);
                    }
                };
                match flow {
                    Flow::Jump(Jump::Resume) => return Ok(true),
                    Flow::Quit | Flow::Denied | Flow::Jump(_) => return Ok(false),
                    Flow::Continue => {}
                }
                self.caches.refresh_expression_context(&self.ctx.target);
            }
            Ok(false)
        })();
        self.context = outer;
        self.breakable_loop = breakable;
        self.event_command_depth -= 1;
        result
    }

    /// Execute a policy-owned exception command without allowing the command
    /// text to choose run control. The policy's typed final action (`break`,
    /// `gh`, or `gn`) is applied by the caller after this returns.
    pub fn dispatch_exception_command(&mut self, line: &str) -> Result<()> {
        if self.event_command_depth >= EXCEPTION_COMMAND_RECURSION_LIMIT {
            error!("exception command recursion limit reached");
            return Ok(());
        }
        let commands = match split_command_list(line) {
            Ok(commands) => commands,
            Err(error) => {
                report_command_parse_error(line, error);
                return Ok(());
            }
        };
        self.event_command_depth += 1;
        let outer = std::mem::replace(&mut self.context, DispatchContext::ExceptionCommand);
        let breakable = std::mem::replace(&mut self.breakable_loop, false);
        let result = (|| {
            for command in commands {
                let flow = match self.dispatch_one(command, 0) {
                    Ok(flow) => flow,
                    Err(error) => {
                        error!("exception command failed: {}", error);
                        return Ok(());
                    }
                };
                match flow {
                    Flow::Denied | Flow::Jump(_) => return Ok(()),
                    Flow::Quit => {
                        error!("quit is ignored inside an exception command");
                        return Ok(());
                    }
                    Flow::Continue => {}
                }
                self.caches.refresh_expression_context(&self.ctx.target);
            }
            Ok(())
        })();
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
            DispatchContext::BreakpointAction if spec.run != RunEffect::None => Some(format!(
                "run-control command '{name}' must not appear inside a breakpoint action; \
                 use 'g' or 'gc' (no address) to continue"
            )),
            DispatchContext::ExceptionCommand
                if spec.run != RunEffect::None || spec.run_state == Some(RunState::Running) =>
            {
                Some(format!(
                    "run-control command '{name}' must not appear inside an exception command; \
                     use the policy's -f break, -f gh, or -f gn"
                ))
            }
            DispatchContext::Remote(RemoteClient::Dap) if spec.run == RunEffect::Run => {
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
            DispatchContext::Remote(RemoteClient::Gdb) if spec.run != RunEffect::None => {
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

    /// The per-command policy every dispatch path shares: the context's
    /// refusal of host commands and of run control, then a remote host's
    /// wait for the halt the command needs (against the target's state right
    /// now, so a `break` earlier on the line counts), then the run-state
    /// check. `None` means run it. `typed` is the name as the user wrote it,
    /// which messages repeat (`k`, not the canonical `kn`).
    fn admit(&mut self, spec: &CommandSpec, typed: &str) -> Result<Option<Flow>> {
        if let Some(reason) = self.host_command_denial(spec) {
            error!("{reason}");
            return Ok(Some(Flow::Denied));
        }
        if let Some(reason) = self.secure_denial(spec) {
            error!("{reason}");
            return Ok(Some(Flow::Denied));
        }
        if let Some(reason) = self.run_control_denial(spec) {
            error!("{reason}");
            return Ok(Some(Flow::Denied));
        }
        if let Some(flow) = self.gate_remote_command(spec, typed)? {
            return Ok(Some(flow));
        }
        if !check_run_state(self, spec) {
            return Ok(Some(Flow::Continue));
        }
        Ok(None)
    }

    fn dispatch_one(&mut self, line: &str, depth: usize) -> Result<Flow> {
        // WinDbg processor syntax (`~`, `~2s`, `~*k`) is one token with the
        // selector glued on, so it never matches a registered name.
        if line.trim_start().starts_with('~') {
            if let Some(spec) = command_registry().get("~")
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
            if let Some(flow) = self.admit(spec, parsed.name)? {
                return Ok(flow);
            }
            match spec.handler {
                CommandHandler::NoArgs(handler) => {
                    if !parsed.raw_tail.trim().is_empty() {
                        outln!("{}\n", command_help(parsed.name));
                        return Ok(Flow::Continue);
                    }
                    handler(self)?;
                }
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
