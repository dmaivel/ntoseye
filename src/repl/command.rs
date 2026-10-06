use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::OnceLock;

use linkme::distributed_slice;

use crate::dbg_backend::halt_unreachable_reason;
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
    pub run: RunEffect,
    pub style: CommandStyle,
    pub flow: Flow,
    pub handler: CommandHandler,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunState {
    Halted,
    /// Halted, unless the context is a parked Windows thread (`.thread`)
    /// and no vCPU's registers: its stack, frames, and their recovered
    /// registers are read from memory, which a running target (and the
    /// memory backend, which always runs) serves live.
    HaltedOrParkedThread,
    Running,
}

/// What a command does to target execution, so dispatch contexts that must
/// not let a command move the target (breakpoint actions, exception
/// commands, a remote host with its own run-control) can refuse it by
/// metadata rather than by a name list that aliases can bypass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunEffect {
    /// Leaves execution state alone (or only pauses it).
    None,
    /// Executes one instruction and returns promptly.
    Step,
    /// Resumes until the next stop; may block indefinitely.
    Run,
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
    /// A command that dispatches other commands (`.foreach`, `!list -x`) and
    /// passes on how they ended, so a refusal inside it abandons the rest of
    /// the line and reaches the host as one typed directly would.
    ArgsFlow(fn(&mut ReplState<'_>, CommandInvocation<'_>) -> Result<Flow>),
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
    spec_help(spec)
}

/// A command's summary, usage and details as text.
pub fn spec_help(spec: &CommandSpec) -> String {
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

    let name_end = command_name_end(line, start);
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
        let scan = scan_unquoted(&line[start..], |_, ch| {
            match ch {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth = depth.saturating_sub(1),
                ';' if depth == 0 => return true,
                _ => {}
            }
            false
        });
        let split = match scan {
            Unquoted::Stopped(offset) => Some(start + offset),
            Unquoted::End => None,
            Unquoted::OpenQuote(offset) => {
                let quote_start = start + offset;
                return Err(CommandParseError::new(
                    quote_start..quote_start + 1,
                    "unterminated quoted argument",
                ));
            }
        };

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
    let text = &line[start..];
    // `*` comments out the rest of the line, and `$<`/`$><` take it as the
    // file name, `;` included.
    if (is_comment(text) && !text.starts_with("$$"))
        || matches!(script_file_token(text), Some(("$<" | "$><", _)))
    {
        return Some(CommandStyle::RawTail);
    }
    let end = command_name_end(line, start);
    command_registry()
        .get(&line[start..end])
        .map(|spec| spec.style)
}

/// Where the command name starting at `start` ends: at whitespace, or for a
/// dot command also at `(` or `{`, which WinDbg's control-flow tokens take
/// glued on (`.if(x){...}`, `.block{...}`).
fn command_name_end(line: &str, start: usize) -> usize {
    let dot = line[start..].starts_with('.');
    line[start..]
        .find(|ch: char| ch.is_whitespace() || (dot && matches!(ch, '(' | '{')))
        .map(|offset| start + offset)
        .unwrap_or(line.len())
}

/// Whether `text` is a WinDbg comment: `*` (to the end of the line) or `$$`
/// (to the next `;`), but not the script-file tokens `$$<` and `$$>`.
pub fn is_comment(text: &str) -> bool {
    let text = text.trim_start();
    text.starts_with('*')
        || text
            .strip_prefix("$$")
            .is_some_and(|rest| !rest.starts_with(['<', '>']))
}

/// The script-file token (`$<`, `$><`, `$$<`, `$$><`, `$$>a<`) that opens
/// `text`, and the file name and arguments glued on after it.
pub fn script_file_token(text: &str) -> Option<(&'static str, &str)> {
    ["$$>a<", "$$><", "$$<", "$><", "$<"]
        .into_iter()
        .find_map(|token| text.strip_prefix(token).map(|rest| (token, rest)))
}

/// Where [`scan_unquoted`] stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum Unquoted {
    /// The visitor stopped at this byte offset.
    Stopped(usize),
    /// The text ended with every quote closed.
    End,
    /// The quote opened at this byte offset is never closed.
    OpenQuote(usize),
}

/// Call `visit` with each character of `text` outside quoted strings and its
/// byte offset, until it returns `true`. Quote characters are not visited.
/// Inside quotes a backslash escapes the next character, so `"a\"b"` is one
/// string. A `$$` comment where a command starts (at the start of `text`, or
/// after `;` or `{`) opens no quotes up to its `;`, so `{ $$ don't ; k }` is
/// one block. The command-list splitter and the block scanners share this, so
/// they agree on where a quoted string ends.
pub fn scan_unquoted(text: &str, mut visit: impl FnMut(usize, char) -> bool) -> Unquoted {
    let mut quote = None;
    let mut escaped = false;
    let mut command_start = true;
    let mut comment = false;
    for (offset, ch) in text.char_indices() {
        if let Some((active, _)) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        if command_start && !ch.is_whitespace() {
            command_start = false;
            comment = text[offset..].starts_with("$$") && is_comment(&text[offset..]);
        }
        match ch {
            ';' => (command_start, comment) = (true, false),
            '{' if !comment => command_start = true,
            _ => {}
        }
        if matches!(ch, '"' | '\'') && !comment {
            quote = Some((ch, offset));
        } else if visit(offset, ch) {
            return Unquoted::Stopped(offset);
        }
    }
    match quote {
        Some((_, offset)) => Unquoted::OpenQuote(offset),
        None => Unquoted::End,
    }
}

/// `text` split at each `sep` outside quotes and brackets, parts trimmed;
/// `None` for an unterminated quote.
pub fn split_top_level(text: &str, sep: char) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let scan = scan_unquoted(text, |offset, ch| {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ if ch == sep && depth == 0 => {
                parts.push(text[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
        false
    });
    if let Unquoted::OpenQuote(_) = scan {
        return None;
    }
    parts.push(text[start..].trim());
    Some(parts)
}

/// The quoted string that opens `text`, unescaped, and the text after its
/// closing quote; `None` when `text` does not open with a quote or the quote
/// is never closed. A backslash only escapes the quote or another backslash.
/// Every other sequence is passed through intact, because the command that
/// receives it owns its own escapes: `.printf` needs to see `\n`, and a
/// Windows path keeps its separators.
pub fn take_quoted(text: &str) -> Option<(String, &str)> {
    let mut chars = text.char_indices();
    let (_, quote @ ('"' | '\'')) = chars.next()? else {
        return None;
    };
    let mut value = String::new();
    let mut escaped = false;
    for (offset, ch) in chars {
        if escaped {
            if ch != quote && ch != '\\' {
                value.push('\\');
            }
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            return Some((value, &text[offset + ch.len_utf8()..]));
        } else {
            value.push(ch);
        }
    }
    None
}

pub fn parse_args(
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
        if !line[pos..].starts_with(['"', '\'']) {
            let end = line[pos..]
                .find(char::is_whitespace)
                .map(|offset| pos + offset)
                .unwrap_or(line.len());
            args.push(Cow::Borrowed(&line[start..end]));
            pos = end;
            continue;
        }
        let Some((text, rest)) = take_quoted(&line[pos..]) else {
            return Err(CommandParseError::new(
                base + start..base + start + 1,
                "unterminated quoted argument",
            ));
        };
        pos = line.len() - rest.len();
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

/// Whether `spec` needs the target halted now, given the selected context.
pub fn needs_halt(state: &ReplState<'_>, spec: &CommandSpec) -> bool {
    match spec.run_state {
        Some(RunState::Halted) => true,
        Some(RunState::HaltedOrParkedThread) => state.ctx.parked_windows_thread().is_none(),
        Some(RunState::Running) | None => false,
    }
}

pub fn check_run_state(state: &ReplState<'_>, spec: &CommandSpec) -> bool {
    match spec.run_state {
        _ if needs_halt(state, spec) && state.ctx.backend.is_running() => {
            let or_thread = if spec.run_state == Some(RunState::HaltedOrParkedThread) {
                ", or a thread selected with `.thread`"
            } else {
                ""
            };
            match halt_unreachable_reason(&*state.ctx.backend) {
                Some(reason) => error!("this command needs a halted target{or_thread}; {reason}"),
                None => error!("VM is running; this command needs a halted target{or_thread}"),
            }
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
        $method:ident -> Flow;
        $($body:tt)*
    ) => {
        $crate::repl_command! {
            @register
            $crate::repl::CommandHandler::ArgsFlow(|state, invocation| state.$method(invocation));
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
        $(, run: $run:ident)?
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
            $(, run: $run)?
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
        $(, run: $run:ident)?
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
                run: $crate::repl_command!(@run $($run)?),
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
    (@run_state HaltedOrParkedThread) => { Some($crate::repl::RunState::HaltedOrParkedThread) };
    (@run_state Running) => { Some($crate::repl::RunState::Running) };

    (@run) => { $crate::repl::RunEffect::None };
    (@run Step) => { $crate::repl::RunEffect::Step };
    (@run Run) => { $crate::repl::RunEffect::Run };

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
}
