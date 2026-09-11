use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::OnceLock;

use linkme::distributed_slice;

use crate::error::Result;
use crate::repl::{CompletionStrategy, Flow, ReplState, error};

#[distributed_slice]
pub static COMMANDS: [CommandSpec];

pub struct CommandSpec {
    pub names: &'static [&'static str],
    pub usage: &'static str,
    pub summary: &'static str,
    pub details: Option<&'static str>,
    pub completion: CompletionSpec,
    pub run_state: Option<RunState>,
    pub style: CommandStyle,
    pub flow: Flow,
    pub handler: CommandHandler,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Halted,
    Running,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStyle {
    StructuredArgs,
    RawTail,
    ExpressionTail,
}

#[derive(Clone, Copy)]
pub enum CompletionSpec {
    None,
    All(CompletionStrategy),
    PerArg(&'static [CompletionStrategy]),
}

impl CompletionSpec {
    pub fn strategy_for_arg(self, index: usize) -> CompletionStrategy {
        match self {
            Self::None => CompletionStrategy::None,
            Self::All(strategy) => strategy,
            Self::PerArg(strategies) => strategies
                .get(index)
                .copied()
                .unwrap_or(CompletionStrategy::None),
        }
    }
}

#[derive(Clone, Copy)]
pub enum CommandHandler {
    Args(fn(&mut ReplState<'_>, CommandInvocation<'_>) -> Result<()>),
    NoArgs(fn(&mut ReplState<'_>) -> Result<()>),
}

pub struct CommandInvocation<'a> {
    pub name: &'a str,
    pub argv: Vec<Cow<'a, str>>,
    pub raw_tail: &'a str,
}

impl<'a> CommandInvocation<'a> {
    pub fn arg(&self, index: usize) -> Option<&str> {
        self.argv.get(index).map(|arg| arg.as_ref())
    }

    pub fn join_args(&self, start: usize) -> String {
        self.argv
            .get(start..)
            .unwrap_or(&[])
            .iter()
            .map(|arg| arg.as_ref())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub struct CommandRegistry {
    by_name: HashMap<&'static str, &'static CommandSpec>,
}

impl CommandRegistry {
    pub fn get(&self, name: &str) -> Option<&'static CommandSpec> {
        self.by_name.get(name).copied()
    }

    pub fn command_names(&self) -> Vec<(&'static str, &'static CommandSpec)> {
        let mut names: Vec<_> = self
            .by_name
            .iter()
            .map(|(name, spec)| (*name, *spec))
            .collect();
        names.sort_by_key(|(name, _)| *name);
        names
    }
}

pub fn command_registry() -> &'static CommandRegistry {
    static REGISTRY: OnceLock<CommandRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        assert!(
            !COMMANDS.is_empty(),
            "REPL command registry is empty; command modules may have been dropped"
        );

        let mut by_name = HashMap::new();
        for spec in COMMANDS {
            assert!(!spec.names.is_empty(), "REPL command spec has no names");
            for &name in spec.names {
                let old = by_name.insert(name, spec);
                assert!(old.is_none(), "duplicate REPL command name: {name}");
            }
        }

        CommandRegistry { by_name }
    })
}

pub fn command_help(name: &str) -> String {
    let Some(spec) = command_registry().get(name) else {
        return "invalid usage".to_string();
    };

    let mut help = format!("{}\n(usage: {})", spec.summary, spec.usage);
    if let Some(detail) = spec.details {
        help.push('\n');
        help.push_str(detail);
    }
    help
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandParseError {
    span: Range<usize>,
    message: String,
}

impl CommandParseError {
    fn new(span: Range<usize>, message: impl Into<String>) -> Self {
        Self {
            span,
            message: message.into(),
        }
    }
}

pub struct ParsedCommand<'a> {
    pub name: &'a str,
    pub raw_tail: &'a str,
    args_start: usize,
}

impl<'a> ParsedCommand<'a> {
    pub fn invocation(
        &self,
        style: CommandStyle,
    ) -> std::result::Result<CommandInvocation<'a>, CommandParseError> {
        let argv = match style {
            CommandStyle::StructuredArgs => parse_args(self.raw_tail, self.args_start)?,
            CommandStyle::RawTail | CommandStyle::ExpressionTail => Vec::new(),
        };
        Ok(CommandInvocation {
            name: self.name,
            argv,
            raw_tail: self.raw_tail.trim(),
        })
    }
}

pub fn parse_command(
    line: &str,
) -> std::result::Result<Option<ParsedCommand<'_>>, CommandParseError> {
    let start = skip_ws(line, 0);
    if start >= line.len() {
        return Ok(None);
    }

    let name_end = line[start..]
        .find(char::is_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(line.len());
    let args_start = skip_ws(line, name_end);
    Ok(Some(ParsedCommand {
        name: &line[start..name_end],
        raw_tail: &line[args_start..],
        args_start,
    }))
}

pub fn split_command_list(line: &str) -> std::result::Result<Vec<&str>, CommandParseError> {
    let mut commands = Vec::new();
    let mut start = 0;

    loop {
        start = skip_ws(line, start);
        if start >= line.len() {
            return Ok(commands);
        }

        if command_style_at(&line[start..]) == Some(CommandStyle::RawTail) {
            commands.push(line[start..].trim());
            return Ok(commands);
        }

        let mut depth = 0usize;
        let mut quote = None;
        let mut quote_start = 0;
        let mut escaped = false;
        let mut split = None;

        for (offset, ch) in line[start..].char_indices() {
            let idx = start + offset;
            if let Some(active_quote) = quote {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == active_quote {
                    quote = None;
                }
                continue;
            }

            match ch {
                '"' | '\'' => {
                    quote = Some(ch);
                    quote_start = idx;
                }
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ';' if depth == 0 => {
                    split = Some(idx);
                    break;
                }
                _ => {}
            }
        }

        if quote.is_some() {
            return Err(CommandParseError::new(
                quote_start..quote_start + 1,
                "unterminated quoted argument",
            ));
        }

        let end = split.unwrap_or(line.len());
        let command = line[start..end].trim();
        if !command.is_empty() {
            commands.push(command);
        }

        let Some(split) = split else {
            return Ok(commands);
        };
        start = split + 1;
    }
}

fn command_style_at(line: &str) -> Option<CommandStyle> {
    let start = skip_ws(line, 0);
    if start >= line.len() {
        return None;
    }
    let end = line[start..]
        .find(char::is_whitespace)
        .map(|offset| start + offset)
        .unwrap_or(line.len());
    command_registry()
        .get(&line[start..end])
        .map(|spec| spec.style)
}

fn parse_args(
    line: &str,
    base: usize,
) -> std::result::Result<Vec<Cow<'_, str>>, CommandParseError> {
    let mut args = Vec::new();
    let mut pos = 0;
    while pos < line.len() {
        pos = skip_ws(line, pos);
        if pos >= line.len() {
            break;
        }

        let start = pos;
        let Some(quote) = line[pos..]
            .chars()
            .next()
            .filter(|ch| *ch == '"' || *ch == '\'')
        else {
            let end = line[pos..]
                .find(char::is_whitespace)
                .map(|offset| pos + offset)
                .unwrap_or(line.len());
            args.push(Cow::Borrowed(&line[start..end]));
            pos = end;
            continue;
        };

        pos += quote.len_utf8();
        let mut text = String::new();
        let mut escaped = false;
        let mut closed = false;
        while let Some(ch) = line[pos..].chars().next() {
            pos += ch.len_utf8();
            if escaped {
                text.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                closed = true;
                break;
            } else {
                text.push(ch);
            }
        }
        if !closed {
            return Err(CommandParseError::new(
                base + start..base + start + quote.len_utf8(),
                "unterminated quoted argument",
            ));
        }
        args.push(Cow::Owned(text));
    }
    Ok(args)
}

fn skip_ws(s: &str, pos: usize) -> usize {
    s[pos..]
        .char_indices()
        .find_map(|(offset, ch)| (!ch.is_whitespace()).then_some(pos + offset))
        .unwrap_or(s.len())
}

pub fn report_command_parse_error(line: &str, err: CommandParseError) {
    let start = err.span.start.min(line.len());
    let end = err.span.end.min(line.len()).max(start + 1);
    outln!("{line}");
    outln!(
        "{}{} {}",
        " ".repeat(start),
        "^".repeat(end - start),
        err.message
    );
}

pub fn check_run_state(state: &ReplState<'_>, spec: &CommandSpec) -> bool {
    match spec.run_state {
        Some(RunState::Halted) if state.ctx.backend.is_running() => {
            error!("VM is running");
            return false;
        }
        Some(RunState::Running) if !state.ctx.backend.is_running() => {
            error!("VM is already paused");
            return false;
        }
        _ => {}
    }

    true
}

#[macro_export]
macro_rules! repl_command {
    (
        $method:ident();
        $($body:tt)*
    ) => {
        $crate::repl_command! {
            @register
            $crate::repl::CommandHandler::NoArgs(|state| state.$method());
            $($body)*
        }
    };

    (
        $method:ident;
        $($body:tt)*
    ) => {
        $crate::repl_command! {
            @register
            $crate::repl::CommandHandler::Args(|state, invocation| state.$method(invocation));
            $($body)*
        }
    };

    (
        names: [$($name:expr),+ $(,)?],
        usage: $usage:expr,
        summary: $summary:expr
        $(, details: $details:expr)?
        $(, completion: $completion:tt)?
        $(, run_state: $run_state:ident)?
        $(, style: $style:ident)?
        , flow: $flow:ident
        $(,)?
    ) => {
        $crate::repl_command! {
            @register
            $crate::repl::CommandHandler::NoArgs(|_state| Ok(()));
            names: [$($name),+],
            usage: $usage,
            summary: $summary
            $(, details: $details)?
            $(, completion: $completion)?
            $(, run_state: $run_state)?
            $(, style: $style)?
            , flow: $flow,
        }
    };

    (
        @register
        $handler:expr;
        names: [$($name:expr),+ $(,)?],
        usage: $usage:expr,
        summary: $summary:expr
        $(, details: $details:expr)?
        $(, completion: $completion:tt)?
        $(, run_state: $run_state:ident)?
        $(, style: $style:ident)?
        $(, flow: $flow:ident)?
        $(,)?
    ) => {
        const _: () = {
            #[linkme::distributed_slice($crate::repl::COMMANDS)]
            static COMMAND: $crate::repl::CommandSpec = $crate::repl::CommandSpec {
                names: &[$($name),+],
                usage: $usage,
                summary: $summary,
                details: $crate::repl_command!(@details $($details)?),
                completion: $crate::repl_command!(@completion $($completion)?),
                run_state: $crate::repl_command!(@run_state $($run_state)?),
                style: $crate::repl_command!(@style $($style)?),
                flow: $crate::repl_command!(@flow $($flow)?),
                handler: $handler,
            };
        };
    };

    (@completion) => { $crate::repl::CompletionSpec::None };
    (@completion None) => { $crate::repl::CompletionSpec::None };
    (@completion [$($completion:ident),+ $(,)?]) => {
        $crate::repl::CompletionSpec::PerArg(&[
            $($crate::repl_command!(@completion_strategy $completion)),+
        ])
    };
    (@completion $completion:ident) => {
        $crate::repl::CompletionSpec::All($crate::repl_command!(@completion_strategy $completion))
    };

    (@completion_strategy None) => { $crate::repl::CompletionStrategy::None };
    (@completion_strategy Symbol) => { $crate::repl::CompletionStrategy::Symbol };
    (@completion_strategy Expression) => { $crate::repl::CompletionStrategy::Expression };
    (@completion_strategy Type) => { $crate::repl::CompletionStrategy::Type };
    (@completion_strategy Process) => { $crate::repl::CompletionStrategy::Process };
    (@completion_strategy Thread) => { $crate::repl::CompletionStrategy::Thread };
    (@completion_strategy Vcpu) => { $crate::repl::CompletionStrategy::Vcpu };
    (@completion_strategy Breakpoint) => { $crate::repl::CompletionStrategy::Breakpoint };
    (@completion_strategy Driver) => { $crate::repl::CompletionStrategy::Driver };
    (@completion_strategy Alias) => { $crate::repl::CompletionStrategy::Alias };

    (@details) => { None };
    (@details $details:expr) => { Some($details) };

    (@run_state) => { None };
    (@run_state Halted) => { Some($crate::repl::RunState::Halted) };
    (@run_state Running) => { Some($crate::repl::RunState::Running) };

    (@style) => { $crate::repl::CommandStyle::StructuredArgs };
    (@style StructuredArgs) => { $crate::repl::CommandStyle::StructuredArgs };
    (@style RawTail) => { $crate::repl::CommandStyle::RawTail };
    (@style ExpressionTail) => { $crate::repl::CommandStyle::ExpressionTail };

    (@flow) => { $crate::repl::Flow::Continue };
    (@flow Continue) => { $crate::repl::Flow::Continue };
    (@flow Quit) => { $crate::repl::Flow::Quit };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_registry_is_populated() {
        assert!(!COMMANDS.is_empty());
        assert!(command_registry().get("continue").is_some());
    }

    #[test]
    fn builtin_aliases_resolve_to_command_specs() {
        let registry = command_registry();
        assert_eq!(registry.get("g").unwrap().names[0], "continue");
        assert_eq!(registry.get("t").unwrap().names[0], "si");
        assert_eq!(registry.get("u").unwrap().names[0], "disasm");
        assert_eq!(registry.get("r").unwrap().names[0], "registers");
        assert_eq!(registry.get("q").unwrap().names[0], "quit");
        assert_eq!(registry.get("q").unwrap().flow, Flow::Quit);
        assert_eq!(registry.get("?").unwrap().names[0], "ev");
        for (alias, canonical) in [
            ("!pte", "pte"),
            ("!pool", "pool"),
            ("!irp", "irp"),
            ("!drvobj", "drvobj"),
            ("!devobj", "devobj"),
            ("!object", "object"),
            ("!analyze", "analyze"),
        ] {
            assert_eq!(registry.get(alias).unwrap().names[0], canonical);
        }
        for stack_variant in ["kb", "kp", "kv"] {
            assert_eq!(registry.get(stack_variant).unwrap().names[0], "k");
        }
        for command in [
            "uf",
            "lmv",
            ".reload",
            ".sympath",
            ".symfix",
            "ld",
            "gh",
            "gn",
            "sxe",
            "sxd",
            "sxn",
            "sxi",
            "n",
            "reload-scripts",
        ] {
            assert!(
                registry.get(command).is_some(),
                "{command} is not registered"
            );
        }
        assert_eq!(
            registry.get("?").unwrap().style,
            CommandStyle::ExpressionTail
        );
    }

    #[test]
    fn per_arg_completion_is_command_metadata() {
        let registry = command_registry();

        let completion = registry.get("dt").unwrap().completion;
        assert!(matches!(
            completion.strategy_for_arg(0),
            CompletionStrategy::Type
        ));
        assert!(matches!(
            completion.strategy_for_arg(1),
            CompletionStrategy::Expression
        ));
        assert!(matches!(
            completion.strategy_for_arg(2),
            CompletionStrategy::None
        ));

        let completion = registry.get("f").unwrap().completion;
        assert!(matches!(
            completion.strategy_for_arg(0),
            CompletionStrategy::Expression
        ));
        assert!(matches!(
            completion.strategy_for_arg(1),
            CompletionStrategy::None
        ));
        assert!(matches!(
            completion.strategy_for_arg(2),
            CompletionStrategy::Expression
        ));

        let completion = registry.get("s").unwrap().completion;
        assert!(matches!(
            completion.strategy_for_arg(0),
            CompletionStrategy::Expression
        ));
        assert!(matches!(
            completion.strategy_for_arg(1),
            CompletionStrategy::None
        ));
        assert!(matches!(
            completion.strategy_for_arg(2),
            CompletionStrategy::Expression
        ));

        let completion = registry.get("thread").unwrap().completion;
        assert!(matches!(
            completion.strategy_for_arg(0),
            CompletionStrategy::Thread
        ));
        assert!(matches!(
            completion.strategy_for_arg(1),
            CompletionStrategy::None
        ));

        let completion = registry.get("set").unwrap().completion;
        assert!(matches!(
            completion.strategy_for_arg(0),
            CompletionStrategy::None
        ));
        assert!(matches!(
            completion.strategy_for_arg(1),
            CompletionStrategy::Expression
        ));
    }

    #[test]
    fn parses_quoted_arguments() {
        let parsed = parse_command(r#"x "nt!Ke Bug" plain"#).unwrap().unwrap();
        let invocation = parsed.invocation(CommandStyle::StructuredArgs).unwrap();
        assert_eq!(invocation.name, "x");
        assert_eq!(invocation.argv[0].as_ref(), "nt!Ke Bug");
        assert_eq!(invocation.argv[1].as_ref(), "plain");
    }

    #[test]
    fn splits_semicolons_outside_quotes_and_grouping() {
        assert_eq!(
            split_command_list(r#"bp "a;b"; ev poi(rax;rbx); g"#).unwrap(),
            vec![r#"bp "a;b""#, "ev poi(rax;rbx)", "g"]
        );
    }

    #[test]
    fn raw_tail_command_keeps_semicolons() {
        assert_eq!(
            split_command_list("alias ubp bp ${1}; g").unwrap(),
            vec!["alias ubp bp ${1}; g"]
        );
    }

    #[test]
    fn expression_tail_keeps_unsplit_expression() {
        let parsed = parse_command("? rax + rbx").unwrap().unwrap();
        let invocation = parsed.invocation(CommandStyle::ExpressionTail).unwrap();
        assert_eq!(invocation.name, "?");
        assert!(invocation.argv.is_empty());
        assert_eq!(invocation.raw_tail, "rax + rbx");
    }

    #[test]
    fn command_help_includes_details() {
        assert!(command_help("x").contains("operators:"));
    }
}
