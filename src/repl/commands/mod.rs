use crate::repl::*;

const ALIAS_RECURSION_LIMIT: usize = 16;
const BREAKPOINT_ACTION_RECURSION_LIMIT: usize = 4;

mod breakpoints;
mod diagnostics;
mod exceptions;
mod exec;
mod inspect;
mod memory;
mod meta;
mod process;
mod symbols;

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
        let result = (|| {
            for command in commands.into_iter().take(command_count) {
                let name = command
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if matches!(
                    name.as_str(),
                    "g" | "continue" | "gh" | "gn" | "p" | "step" | "t" | "gu" | "finish"
                ) {
                    error!(
                        "run-control command '{name}' must not appear inside a breakpoint action; use trailing 'gc' to continue"
                    );
                    return Ok(false);
                }
                if self.dispatch_one(command, 0)? == Flow::Quit {
                    return Ok(false);
                }
                self.caches.refresh_expression_context(&self.ctx.target);
            }
            Ok(continue_after)
        })();
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
        let result = (|| {
            for command in commands {
                let name = command
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if matches!(
                    name.as_str(),
                    "g" | "continue"
                        | "gh"
                        | "gn"
                        | "break"
                        | "si"
                        | "t"
                        | "p"
                        | "ni"
                        | "gu"
                        | "finish"
                        | "gc"
                        | "quit"
                        | "q"
                ) {
                    error!(
                        "run-control command '{name}' must not appear inside an exception command; use the policy's -f break, -f gh, or -f gn"
                    );
                    return Ok(());
                }
                if self.dispatch_one(command, 0)? == Flow::Quit {
                    error!("quit is ignored inside an exception command");
                    return Ok(());
                }
                self.caches.refresh_expression_context(&self.ctx.target);
            }
            Ok(())
        })();
        self.event_command_depth -= 1;
        result
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
                Flow::Continue => {}
            }
            self.caches.refresh_expression_context(&self.ctx.target);
        }
        Ok(Flow::Continue)
    }

    fn dispatch_one(&mut self, line: &str, depth: usize) -> Result<Flow> {
        let parsed = match parse_command(line) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => return Ok(Flow::Continue),
            Err(err) => {
                report_command_parse_error(line, err);
                return Ok(Flow::Continue);
            }
        };

        if let Some(spec) = command_registry().get(parsed.name) {
            if !check_run_state(self, spec) {
                return Ok(Flow::Continue);
            }
            match spec.handler {
                CommandHandler::NoArgs(handler) => {
                    if !parsed.raw_tail.trim().is_empty() {
                        println!("{}\n", command_help(parsed.name));
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
