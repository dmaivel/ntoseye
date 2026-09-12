use crate::repl::*;

const ALIAS_RECURSION_LIMIT: usize = 16;
const BREAKPOINT_ACTION_RECURSION_LIMIT: usize = 4;

mod analyze;
mod breakpoints;
mod cpu;
mod diagnostics;
mod exceptions;
mod exec;
mod frames;
mod inspect;
mod memory;
mod meta;
mod mm;
mod physical;
mod process;
mod sched;
mod security;
mod symbols;
mod target_control;
mod types;
mod usermode;

impl ReplState<'_> {
    pub fn dispatch_line(&mut self, line: &str) -> Result<Flow> {
        self.dispatch_line_inner(line, 0)
    }
    /// Execute frontend-owned breakpoint commands while keeping the core free
    /// of REPL state. A trailing WinDbg-style `gc` requests automatic resume.
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
        let continue_after = commands
            .last()
            .is_some_and(|command| command.trim().eq_ignore_ascii_case("gc"));
        let command_count = commands.len().saturating_sub(usize::from(continue_after));
        self.event_command_depth += 1;
        let outer = std::mem::replace(&mut self.context, DispatchContext::BreakpointAction);
        let result = (|| {
            for command in commands.into_iter().take(command_count) {
                match self.dispatch_one(command, 0)? {
                    Flow::Quit | Flow::Denied => return Ok(false),
                    Flow::Continue => {}
                }
                self.caches.refresh_expression_context(&self.ctx.target);
            }
            Ok(continue_after)
        })();
        self.context = outer;
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
        let result = (|| {
            for command in commands {
                match self.dispatch_one(command, 0)? {
                    Flow::Denied => return Ok(()),
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
                 use trailing 'gc' to continue"
            )),
            DispatchContext::ExceptionCommand
                if spec.run != RunEffect::None || spec.run_state == Some(RunState::Running) =>
            {
                Some(format!(
                    "run-control command '{name}' must not appear inside an exception command; \
                     use the policy's -f break, -f gh, or -f gn"
                ))
            }
            DispatchContext::Remote if spec.run == RunEffect::Run => Some(format!(
                "'{name}' would block this session until the next stop; use the resume tool, \
                 then poll wait_for_stop"
            )),
            DispatchContext::Remote if spec.flow == Flow::Quit => Some(format!(
                "'{name}' ends the interactive REPL; use the close tool to release the session"
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

        for command in commands {
            match self.dispatch_one(command, depth)? {
                Flow::Quit => return Ok(Flow::Quit),
                Flow::Denied => return Ok(Flow::Denied),
                Flow::Continue => {}
            }
            self.caches.refresh_expression_context(&self.ctx.target);
        }
        Ok(Flow::Continue)
    }

    fn dispatch_one(&mut self, line: &str, depth: usize) -> Result<Flow> {
        // WinDbg processor syntax (`~`, `~2s`, `~*k`) is one token with the
        // selector glued on, so it never matches a registered name.
        if line.trim_start().starts_with('~') {
            if let Some(spec) = command_registry().get("~") {
                if let Some(reason) = self.run_control_denial(spec) {
                    error!("{reason}");
                    return Ok(Flow::Denied);
                }
                if !check_run_state(self, spec) {
                    return Ok(Flow::Continue);
                }
            }
            return self.cmd_tilde(line.trim());
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
            if let Some(reason) = self.run_control_denial(spec) {
                error!("{reason}");
                return Ok(Flow::Denied);
            }
            if !check_run_state(self, spec) {
                return Ok(Flow::Continue);
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
                    let invocation = match parsed.invocation(spec.style) {
                        Ok(invocation) => invocation,
                        Err(err) => {
                            report_command_parse_error(line, err);
                            return Ok(Flow::Continue);
                        }
                    };
                    handler(self, invocation)?;
                }
            }
            return Ok(spec.flow);
        }

        let invocation = match parsed.invocation(CommandStyle::StructuredArgs) {
            Ok(invocation) => invocation,
            Err(err) => {
                report_command_parse_error(line, err);
                return Ok(Flow::Continue);
            }
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

        self.cmd_user(invocation)?;
        Ok(Flow::Continue)
    }
}
